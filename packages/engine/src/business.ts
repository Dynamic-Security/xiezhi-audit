// Business-logic detection: business-sensitive index rules (rules/*/business, rule ids
// `*.business.*`), per-entry logic review batches, and "未排除的假设" (hypotheses neither proven nor refuted).
// the logic review is part of risk-hypothesis-first; old `logicReview` strategies are migrated.
import { newId, type AuditStrategy, type EntryPoint, type HypothesisDraft, type StructIndex } from '@xiezhi/contracts';
import { graphqlStateOrById } from '@xiezhi/context';
import { fromJson, type Store } from '@xiezhi/store';
import type { AuditRuntime } from './runtime.js';
import { addRevision, createVulnerability, type CanonicalFinding } from './vulns.js';

export const isBusinessRule = (ruleId: string | null | undefined): boolean => !!ruleId && ruleId.includes('.business.');
/**
 * Business-sensitive sinks join candidates and coverage with risk-hypothesis-first (formerly with
 * the separate logic review, migrated into it).
 */
export const businessRulesOn = (s: AuditStrategy): boolean => s.stages.threatHypotheses === true;

/** The index an audit works with: business-sensitive sinks only with risk-hypothesis-first. */
export function effectiveIndex(index: StructIndex, s: AuditStrategy): StructIndex {
  if (businessRulesOn(s)) return index;
  return { ...index, sinks: index.sinks.filter((x) => !isBusinessRule(x.ruleId)) };
}

const STATE_CHANGING = /^(POST|PUT|PATCH|DELETE|ANY)\b/i;

/**
 * Entries the threat model must consider one by one (the former per-entry logic review): state-
 * changing methods or an object id in the path, GraphQL mutations or id arguments, at most `limit`,
 * optionally only the given entry ids.
 */
export function logicEntries(idx: StructIndex | undefined, limit: number, only?: ReadonlySet<string>): EntryPoint[] {
  return ((idx?.entrypoints ?? []) as EntryPoint[])
    .filter((e) => !only || only.has(e.entryId))
    .filter((e) => (e.entryKey.startsWith('rpc:graphql:')
      ? graphqlStateOrById(e.entryKey, e.pathTemplate)
      : STATE_CHANGING.test(e.entryKey.split(':').pop() ?? e.entryKey) || /\{|:\w/.test(e.pathTemplate ?? '')))
    .slice(0, limit);
}

/** Persist hypotheses of a hunt submission (open and refuted; proven ones are findings). */
export function insertHypotheses(rt: AuditRuntime, stepId: string, hs: HypothesisDraft[]): number {
  let n = 0;
  for (const h of hs) {
    const repo = rt.repoByName(h.location.repo) ?? rt.targetRepo;
    const view = rt.views.get(repo.name);
    if (!view) continue;
    const loc = { repo: repo.name, path: view.guard(h.location.path), startLine: h.location.startLine, endLine: h.location.endLine };
    const id = newId('hypothesis');
    rt.store.insert('hypothesis', {
      id, audit_id: rt.auditId, step_id: stepId, project_id: rt.audit.project_id, repository_id: repo.id, category: h.category,
      statement: h.statement, location: loc, entry_key: h.entry ?? null, attempts: h.attempts, status: h.status,
    });
    rt.event('judgement.made', { kind: 'hypothesis', hypothesis_id: id, status: h.status, category: h.category, statement: h.statement.slice(0, 300) }, stepId);
    n++;
  }
  return n;
}

export interface HypothesisRow {
  id: string; audit_id: string; step_id: string | null; project_id: string; repository_id: string; category: string; statement: string;
  /** Null while a threat-model hypothesis is `proposed` (not verified yet). */
  location: string | null; entry_key: string | null; attempts: string;
  status: 'proposed' | 'confirmed' | 'open' | 'refuted' | 'converted' | 'dismissed';
  vulnerability_id: string | null; decided_by: string | null; decided_reason: string | null; created_at: number; updated_at: number;
  /** `threat_model` hypotheses come from the threat-model step (risk-hypothesis-first). */
  origin: 'hunt' | 'threat_model'; priority: number | null; basis: string | null; related: string;
  finding_id: string | null; verify_step_id: string | null; verified_at: number | null;
  /** per-model verdicts (JSON `HypothesisVote[]`). */
  votes?: string;
}

/** Hypotheses of these audits (an audit and its supplements), threat-model ones by priority first. */
export function listHypotheses(store: Store, auditId: string | string[], status?: HypothesisRow['status'][]): HypothesisRow[] {
  const ids = Array.isArray(auditId) ? auditId : [auditId];
  const rows = store.all<HypothesisRow>(
    `SELECT * FROM hypothesis WHERE audit_id IN (${ids.map(() => '?').join(',')}) ORDER BY origin DESC, COALESCE(priority, 0) DESC, created_at, id`, ...ids);
  return status?.length ? rows.filter((r) => status.includes(r.status)) : rows;
}

export class HypothesisError extends Error {
  constructor(readonly code: 'NOT_FOUND' | 'STATE_CONFLICT', message: string) { super(message); }
}

/**
 * A reviewer's decision on an open hypothesis: `dismiss` (not a problem, with a reason) or `convert` — a human
 * finding (source ai: the statement is the model's) and a pending vulnerability (evidence incomplete: only the hypothesis
 * location, unverified chain); the conversion itself is a `human` revision.
 */
export function decideHypothesis(store: Store, id: string, action: 'dismiss' | 'convert', opts: { reason: string; actor: string; severity?: string }): { status: HypothesisRow['status']; vulnerabilityId: string | null; displayNo: number | null } {
  const h = store.get<HypothesisRow>('SELECT * FROM hypothesis WHERE id = ?', id);
  if (!h) throw new HypothesisError('NOT_FOUND', `hypothesis ${id} not found`);
  // A reviewer may also set aside a threat-model hypothesis nobody verified yet: dismiss only.
  const decidable = h.status === 'open' || (h.status === 'proposed' && action === 'dismiss');
  if (!decidable) throw new HypothesisError('STATE_CONFLICT', `hypothesis is ${h.status}; only open hypotheses can be decided (proposed ones can be dismissed)`);
  if (action === 'dismiss') {
    store.update('hypothesis', { id }, { status: 'dismissed', decided_by: opts.actor, decided_reason: opts.reason });
    return { status: 'dismissed', vulnerabilityId: null, displayNo: null };
  }
  const loc = fromJson<{ repo: string; path: string; startLine: number; endLine: number }>(h.location, { repo: '', path: '', startLine: 1, endLine: 1 });
  let result = { id: '', displayNo: 0 };
  store.tx(() => {
    const findingId = newId('finding');
    const displayNo = (store.get<{ m: number | null }>('SELECT MAX(display_no) AS m FROM finding WHERE audit_id = ?', h.audit_id)?.m ?? 0) + 1;
    const detailRef = store.artifacts.putJson({
      evidence: [], chain: [], reasoning: `由“未排除的假设”转为漏洞（人工）：${h.statement}\n\n已尝试的反驳：${h.attempts}\n\n转换理由：${opts.reason}`,
      counterCheck: h.attempts, exploitConditions: [], remediation: { approach: '待人工确认漏洞成立后补充修复方案' },
    });
    store.insert('finding', {
      id: findingId, audit_id: h.audit_id, step_id: h.step_id, lineage_id: `HYP-${h.id.slice(-6)}`, repository_id: h.repository_id, display_no: displayNo,
      category: h.category, cwe: null, title: h.statement.slice(0, 200), severity: opts.severity ?? 'medium', confidence: 'low', confidence_score: 0.4,
      module: null, sink_symbol: null, sink_api: null, entry_keys: h.entry_key ? [h.entry_key] : [], root_cause: h.statement, location: loc,
      fp_sink: null, fp_entry: null, detail_ref: detailRef,
      // The statement came from the model (finding.source is rule | ai); the human decision is the `human` revision below.
      source: 'ai', model: h.step_id ? store.get<{ model: string | null }>('SELECT model FROM step WHERE id = ?', h.step_id)?.model ?? null : null, state: 'canonical', confirmation: 'pending',
    });
    store.insert('evidence', {
      id: newId('evidence'), owner_kind: 'finding', owner_id: findingId, kind: 'code_range',
      snapshot_id: store.get<{ snapshot_id: string | null }>('SELECT snapshot_id FROM audit_repository WHERE audit_id = ? AND repository_id = ?', h.audit_id, h.repository_id)?.snapshot_id ?? null, path: loc.path,
      start_line: loc.startLine, end_line: loc.endLine, content_hash: null, verified: 0, step_id: h.step_id, note: '假设所在位置（人工转为漏洞，未经证据核实）', ord: 0, origin_label: 'sink',
    });
    const f = store.get<CanonicalFinding>('SELECT * FROM finding WHERE id = ?', findingId)!;
    const v = createVulnerability(store, f, { projectId: h.project_id, auditId: h.audit_id, actor: opts.actor });
    addRevision(store, v.id, { dimension: 'confirm', source: 'human', actor: opts.actor, from: null, to: 'pending', reason: `由未排除的假设转为漏洞：${opts.reason}`, auditId: h.audit_id });
    store.update('hypothesis', { id }, { status: 'converted', vulnerability_id: v.id, decided_by: opts.actor, decided_reason: opts.reason });
    result = { id: v.id, displayNo: v.displayNo };
  });
  return { status: 'converted', vulnerabilityId: result.id, displayNo: result.displayNo };
}
