// Vulnerability matching and cross-audit lifecycle. Matching is planned before
// the reconcile transaction (exact fingerprint → rename following → suspected judgement by the merge
// model) and applied inside it; humans settle "suspected same" links afterwards (confirm or
// separate).
import { join } from 'node:path';
import {
  AppError, newId, normalizePending, sameCategoryFamily, SubmitSuspectedMatches, type Lifecycle, type PendingCondition, type Presence, type SnapshotManifest, type StructIndex,
} from '@xiezhi/contracts';
import { buildIndex, diffSymbols, SnapshotView } from '@xiezhi/context';
import type { AuditTool } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import { fpSink } from './identity.js';
import { attributeSplitHit } from './identity-ops.js';
import type { AuditRuntime } from './runtime.js';
import { sessionError, type AttemptContext } from './step-runner.js';
import { P } from '@xiezhi/knowledge';

export interface CanonicalFinding {
  id: string; display_no: number; repository_id: string; category: string; cwe: string | null; title: string; severity: string;
  confidence: string; module: string | null; sink_symbol: string | null; sink_api: string | null; entry_keys: string;
  root_cause: string | null; fp_sink: string | null; detail_ref: string; confirmation: string; location?: string; audit_id?: string;
}

/** Revision dimensions a conversation revision card proposes, by its `to` / `from` keys. */
const REVIEWED_KEY: Record<string, string> = { confirm: 'confirmStatus', handling: 'handlingStatus', severity: 'severity' };

/** Where a revision card stands against its vulnerability now. */
export interface RevisionCardProgress {
  /** Dimensions whose value already is the proposed one (done elsewhere or by this card). */
  done: string[];
  /** Dimensions still at the card's base value: applying the card changes them. */
  open: string[];
  /** Dimensions changed elsewhere to a third value: the card cannot apply until they are back. */
  conflict: string[];
  /** The vulnerability is gone (merged, deleted). */
  gone: boolean;
}

export function revisionCardProgress(store: Store, card: { target_id: string | null; data: string }, pending: Record<string, unknown> = {}): RevisionCardProgress {
  const v = card.target_id ? store.get<{ confirm_status: string; handling_status: string; severity: string; status: string }>(
    'SELECT confirm_status, handling_status, severity, status FROM vulnerability WHERE id = ?', card.target_id) : undefined;
  const d = fromJson<{ from?: Record<string, unknown>; to?: Record<string, unknown> }>(card.data, {});
  const now: Record<string, unknown> = { confirmStatus: v?.confirm_status, handlingStatus: v?.handling_status, severity: v?.severity, ...pending };
  const out: RevisionCardProgress = { done: [], open: [], conflict: [], gone: !v || v.status !== 'active' };
  for (const [k, to] of Object.entries(d.to ?? {})) {
    if (to === undefined) continue;
    if (now[k] === to) out.done.push(k);
    else if (now[k] === d.from?.[k]) out.open.push(k);
    else out.conflict.push(k);
  }
  return out;
}

/**
 * Settle the pending revision cards (`propose_revision`) of a vulnerability — every one without `vulnId` (start-up
 * repair of older data) — once it changed elsewhere (a card stayed “待你确认” and counted in the sidebar
 * after the vulnerability was confirmed in its panel). Every proposed value already holds → applied by the system
 * (“已在别处处理”); the vulnerability is gone → expired. A card with values still open or in conflict stays pending
 * (a conflict may be set back); counts and the card read its progress live. `pending` holds values being
 * written in the same transaction. The card's proposed revisions are left to the review that changed the value.
 * Returns the conversations whose cards changed.
 */
export function settleRevisionCards(store: Store, vulnId?: string, pending: Record<string, unknown> = {}): string[] {
  const cards = store.all<{ id: string; conversation_id: string; target_id: string; data: string }>(
    `SELECT id, conversation_id, target_id, data FROM conversation_card WHERE state = 'pending' AND tool = 'propose_revision' AND target_kind = 'vuln'${vulnId ? ' AND target_id = ?' : ''}`,
    ...(vulnId ? [vulnId] : []));
  const changed = new Set<string>();
  for (const c of cards) {
    const p = revisionCardProgress(store, c, c.target_id === vulnId ? pending : {});
    if (!p.gone && (p.open.length || p.conflict.length || !p.done.length)) continue;
    store.update('conversation_card', { id: c.id }, p.gone
      ? { state: 'expired', decided_by: 'system', decided_at: Date.now(), result: { reason: 'vulnerability_gone' } }
      : { state: 'applied', decided_by: 'system', decided_at: Date.now(), result: { vulnId: c.target_id, via: 'elsewhere' } });
    changed.add(c.conversation_id);
  }
  return [...changed];
}

export function addRevision(store: Store, vulnId: string, r: {
  dimension: string; source: 'rule' | 'ai' | 'human'; actor: string; from: unknown; to: unknown; reason: string; evidenceIds?: string[];
  auditId?: string; conversationId?: string; state?: 'applied' | 'proposed';
}): string {
  const seq = (store.get<{ m: number | null }>('SELECT MAX(seq) AS m FROM revision WHERE vulnerability_id = ?', vulnId)?.m ?? 0) + 1;
  const id = newId('revision');
  store.insert('revision', {
    id, vulnerability_id: vulnId, seq, dimension: r.dimension, source: r.source, actor: r.actor,
    from_value: r.from === undefined || r.from === null ? null : JSON.stringify(r.from),
    to_value: r.to === undefined || r.to === null ? null : JSON.stringify(r.to), reason: r.reason,
    evidence_ids: r.evidenceIds ?? [], audit_id: r.auditId ?? null, conversation_id: r.conversationId ?? null, state: r.state ?? 'applied',
  });
  if ((r.state ?? 'applied') === 'applied') {
    // A dimension changed elsewhere (detail panel, batch, audit, another card): cards it completes are settled.
    const key = REVIEWED_KEY[r.dimension];
    if (key) settleRevisionCards(store, vulnId, { [key]: r.to });
    const sources = store.all<{ source: string }>(`SELECT DISTINCT source FROM revision WHERE vulnerability_id = ? AND state = 'applied' ORDER BY source`, vulnId).map((x) => x.source);
    store.update('vulnerability', { id: vulnId }, { sources });
    // Any applied revision changes the reviewable resource (optimistic concurrency).
    store.db.run('UPDATE vulnerability SET rev = rev + 1 WHERE id = ?', vulnId);
  }
  return id;
}

/** evidence_complete: verified sink range, known entries, fully verified chain, no missing context. */
/** The pending condition of a finding / vulnerability detail, in either stored shape. */
export function pendingOf(detail: { pendingCondition?: unknown; missingContext?: unknown } | null | undefined): PendingCondition | null {
  return normalizePending(detail?.pendingCondition) ?? normalizePending(detail?.missingContext);
}

export function evidenceComplete(store: Store, f: CanonicalFinding): boolean {
  const ev = store.all<{ kind: string; verified: number; ord: number }>('SELECT kind, verified, ord FROM evidence WHERE owner_kind = ? AND owner_id = ?', 'finding', f.id);
  const sink = ev.find((e) => e.ord === 0 && e.kind === 'code_range' && e.verified === 1);
  const chain = ev.filter((e) => e.kind === 'call_chain_segment');
  const detail = store.artifacts.getJson<Record<string, unknown>>(f.detail_ref);
  return !!sink && fromJson<string[]>(f.entry_keys, []).length > 0 && chain.length > 0 && chain.every((c) => c.verified === 1)
    && !pendingOf(detail) && f.confirmation !== 'pending';
}

function copyEvidence(store: Store, findingId: string, vulnId: string): string[] {
  const rows = store.all<Record<string, unknown>>('SELECT * FROM evidence WHERE owner_kind = ? AND owner_id = ? ORDER BY ord', 'finding', findingId);
  return rows.map((r) => {
    const id = newId('evidence');
    const { created_at: _c, updated_at: _u, ...rest } = r;
    store.insert('evidence', { ...rest, id, owner_kind: 'vulnerability', owner_id: vulnId });
    return id;
  });
}

/**
 * Create a vulnerability from a canonical finding ("未匹配的发现创建新漏洞"): next display
 * number, anchor fingerprint, entries, evidence copy, `found` occurrence, confirm/lifecycle revisions.
 */
export function createVulnerability(store: Store, f: CanonicalFinding, opts: { projectId: string; auditId: string; actor: string }): { id: string; displayNo: number; confirmed: boolean } {
  const entries = fromJson<string[]>(f.entry_keys, []);
  const complete = evidenceComplete(store, f);
  const confirmed = complete && f.confidence === 'high';
  const pending = pendingOf(store.artifacts.getJson<Record<string, unknown>>(f.detail_ref));
  const project = store.get<{ next_vuln_no: number }>('SELECT next_vuln_no FROM project WHERE id = ?', opts.projectId)!;
  const vulnId = newId('vulnerability');
  store.update('project', { id: opts.projectId }, { next_vuln_no: project.next_vuln_no + 1 });
  store.insert('vulnerability', {
    id: vulnId, project_id: opts.projectId, display_no: project.next_vuln_no, repository_id: f.repository_id, module: f.module,
    category: f.category, cwe: f.cwe, title: f.title, severity: f.severity, confidence: f.confidence, sink_symbol: f.sink_symbol,
    sink_api: f.sink_api, root_cause: f.root_cause, confirm_status: confirmed ? 'confirmed' : 'pending', handling_status: 'open',
    // Missing context only with a stated condition: a pending verdict without one (adversarial review refuted it)
    // is a dispute about the evidence, shown as insufficient evidence.
    lifecycle: 'new', pending_kind: confirmed ? null : pending ? 'missing_context' : 'insufficient_evidence',
    missing_context: pending, sources: [], evidence_complete: complete ? 1 : 0, detail_ref: f.detail_ref,
    first_seen_audit_id: opts.auditId, last_seen_audit_id: opts.auditId,
  });
  if (f.fp_sink && !store.get('SELECT 1 FROM vuln_fingerprint WHERE project_id = ? AND fp = ? AND active = 1', opts.projectId, f.fp_sink)) {
    store.insert('vuln_fingerprint', { vulnerability_id: vulnId, project_id: opts.projectId, fp: f.fp_sink, kind: 'anchor', since_audit_id: opts.auditId, active: 1 });
  }
  for (const e of entries) store.insert('vuln_entry', { vulnerability_id: vulnId, entry_key: e, repository_id: f.repository_id, first_seen_audit_id: opts.auditId, last_seen_audit_id: opts.auditId, state: 'active' });
  const evidenceIds = copyEvidence(store, f.id, vulnId);
  store.insert('vuln_occurrence', {
    id: newId('occurrence'), vulnerability_id: vulnId, audit_id: opts.auditId, finding_id: f.id, match_level: null,
    match_basis: { created: true }, presence: 'found', lifecycle_before: null, lifecycle_after: 'new',
  });
  addRevision(store, vulnId, { dimension: 'confirm', source: 'ai', actor: opts.actor, from: null, to: confirmed ? 'confirmed' : 'pending', reason: confirmed ? 'complete evidence, high confidence' : 'evidence incomplete or pending context', evidenceIds, auditId: opts.auditId });
  addRevision(store, vulnId, { dimension: 'lifecycle', source: 'rule', actor: 'engine', from: null, to: 'new', reason: 'first seen', auditId: opts.auditId });
  return { id: vulnId, displayNo: project.next_vuln_no, confirmed };
}

// ---- planning (before the reconcile transaction) --------------------------------

export type MatchPlan =
  | { level: 'exact'; vulnId: string }
  | { level: 'rename'; vulnId: string; from: string; to: string }
  | { level: 'suspected'; vulnId: string; reason: string; candidates: string[] };

interface ActiveVuln {
  id: string; display_no: number; repository_id: string; category: string; sink_symbol: string | null; sink_api: string | null;
  root_cause: string | null; title: string; last_seen_audit_id: string | null; detail_ref: string;
}

/** Snapshot of `repositoryId` reviewed by `auditId` (where a vulnerability was last seen). */
function auditSnapshot(store: Store, auditId: string, repositoryId: string): { id: string; root_hash: string; manifest_ref: string; name: string } | undefined {
  return store.get(
    `SELECT s.id, s.root_hash, s.manifest_ref, r.name FROM audit_repository ar JOIN snapshot s ON s.id = ar.snapshot_id JOIN repository r ON r.id = ar.repository_id
     WHERE ar.audit_id = ? AND ar.repository_id = ?`, auditId, repositoryId);
}

/**
 * Rename maps (base qualified name → current) between the snapshot a vulnerability was last seen in
 * and this audit's snapshot: function-body hash comparison of the two indexes.
 */
class RenameResolver {
  private cache = new Map<string, Map<string, string>>();
  constructor(private readonly rt: AuditRuntime) {}

  async map(fromSnapshotRoot: string, fromManifestRef: string, repoName: string): Promise<Map<string, string>> {
    const key = `${repoName}|${fromSnapshotRoot}`;
    const hit = this.cache.get(key);
    if (hit) return hit;
    const out = new Map<string, string>();
    this.cache.set(key, out);
    const head = this.rt.views.get(repoName);
    const headIndex = this.rt.identityIndex(repoName);
    const rules = this.rt.rules;
    if (!head || !headIndex || !rules || fromSnapshotRoot === head.rootHash) return out;
    let baseIndex: StructIndex;
    const baseView = new SnapshotView(repoName, join(this.rt.store.paths.snapshots, fromSnapshotRoot), this.rt.store.artifacts.getJson<SnapshotManifest>(fromManifestRef));
    try {
      baseIndex = (await buildIndex(baseView, rules, { indexesDir: this.rt.store.paths.indexes, ...this.rt.indexLanguages(repoName, baseView) })).index;
    } catch {
      return out;
    }
    for (const r of diffSymbols(baseIndex, baseView, headIndex, head).renames) out.set(r.from, r.to);
    return out;
  }
}

/** Code excerpt for the suspected-match projection (never more than 20 lines). */
function excerpt(store: Store, snapshotId: string | null, path: string | null, start: number | null, end: number | null): string {
  if (!snapshotId || !path || !start) return '';
  const snap = store.get<{ root_hash: string; manifest_ref: string }>('SELECT root_hash, manifest_ref FROM snapshot WHERE id = ?', snapshotId);
  if (!snap) return '';
  try {
    const v = new SnapshotView('x', join(store.paths.snapshots, snap.root_hash), store.artifacts.getJson<SnapshotManifest>(snap.manifest_ref));
    return v.lines(path).slice(start - 1, Math.min(end ?? start, start + 19)).join('\n');
  } catch {
    return '';
  }
}

const MAX_SUSPECT_CANDIDATES = 5;

/**
 * Decide, for each canonical finding, whether it continues a tracked vulnerability: exact fingerprint,
 * then rename following, then (merge model configured and allowed) suspected judgement. Findings
 * without a plan become new vulnerabilities.
 */
export async function planMatches(rt: AuditRuntime, findings: CanonicalFinding[], ctx: AttemptContext, llmAllowed: boolean): Promise<Map<string, MatchPlan>> {
  const store = rt.store;
  const projectId = rt.audit.project_id;
  const plans = new Map<string, MatchPlan>();
  const taken = new Set<string>();
  // 1. exact
  for (const f of findings) {
    if (!f.fp_sink) continue;
    const hit = store.get<{ vulnerability_id: string }>(
      `SELECT vf.vulnerability_id FROM vuln_fingerprint vf JOIN vulnerability v ON v.id = vf.vulnerability_id
       WHERE vf.project_id = ? AND vf.fp = ? AND vf.active = 1 AND v.status = 'active'`, projectId, f.fp_sink);
    if (!hit) continue;
    // A sink split by entries: attribute by entry ownership; unowned entries → human.
    const who = attributeSplitHit(store, projectId, f.fp_sink, hit.vulnerability_id, fromJson<string[]>(f.entry_keys, []));
    plans.set(f.id, who.suspected
      ? { level: 'suspected', vulnId: who.vulnId, reason: '同一危险点已被人工按入口拆分，本次发现包含未归属的入口，需要人工判断', candidates: [who.vulnId] }
      : { level: 'exact', vulnId: who.vulnId });
    taken.add(who.vulnId);
  }
  const active = store.all<ActiveVuln>(`SELECT id, display_no, repository_id, category, sink_symbol, sink_api, root_cause, title, last_seen_audit_id, detail_ref FROM vulnerability WHERE project_id = ? AND status = 'active' ORDER BY display_no`, projectId);
  // 2. rename following
  const resolver = new RenameResolver(rt);
  for (const f of findings) {
    if (plans.has(f.id) || !f.fp_sink || !f.sink_symbol) continue;
    const repo = rt.repos.find((r) => r.id === f.repository_id);
    if (!repo) continue;
    for (const v of active) {
      if (taken.has(v.id) || v.repository_id !== f.repository_id || v.category !== f.category || !v.sink_symbol || !v.last_seen_audit_id) continue;
      const snap = auditSnapshot(store, v.last_seen_audit_id, v.repository_id);
      if (!snap) continue;
      const to = (await resolver.map(snap.root_hash, snap.manifest_ref, repo.name)).get(v.sink_symbol);
      if (to && fpSink(v.category, v.repository_id, to, v.sink_api) === f.fp_sink) {
        plans.set(f.id, { level: 'rename', vulnId: v.id, from: v.sink_symbol, to });
        taken.add(v.id);
        break;
      }
    }
  }
  // 3. suspected: same category family and repository, and the same sensitive API or overlapping entries.
  const model = rt.strategy.models.merge;
  const pending = findings.filter((f) => !plans.has(f.id));
  if (!model || !llmAllowed || pending.length === 0) return plans;
  const entriesOf = (vId: string) => store.all<{ entry_key: string }>('SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ?', vId).map((e) => e.entry_key);
  const candidatesOf = new Map<string, ActiveVuln[]>();
  for (const f of pending) {
    const fe = new Set(fromJson<string[]>(f.entry_keys, []));
    const cands = active.filter((v) => !taken.has(v.id) && v.repository_id === f.repository_id && sameCategoryFamily(v.category, f.category)
      && ((!!v.sink_api && v.sink_api === f.sink_api) || entriesOf(v.id).some((e) => fe.has(e)))).slice(0, MAX_SUSPECT_CANDIDATES);
    if (cands.length) candidatesOf.set(f.id, cands);
  }
  if (candidatesOf.size === 0) return plans;
  const fLabel = new Map([...candidatesOf.keys()].map((id, i) => [`F${i + 1}`, id]));
  const vIds = [...new Set([...candidatesOf.values()].flat().map((v) => v.id))];
  const vLabel = new Map(vIds.map((id, i) => [`V${i + 1}`, id]));
  const labelOfV = new Map([...vLabel].map(([l, id]) => [id, l]));
  const byId = new Map(active.map((v) => [v.id, v]));
  const vulnBlock = (v: ActiveVuln) => {
    const ev = store.get<{ snapshot_id: string | null; path: string | null; start_line: number | null; end_line: number | null }>(
      `SELECT snapshot_id, path, start_line, end_line FROM evidence WHERE owner_kind = 'vulnerability' AND owner_id = ? ORDER BY ord LIMIT 1`, v.id);
    return [
      `${labelOfV.get(v.id)} | ${v.category} | 危险点=${v.sink_symbol ?? '?'} | API=${v.sink_api ?? '?'} | 入口=${entriesOf(v.id).join(', ') || '?'}`,
      `  根因：${v.root_cause ?? ''}`, '  代码：', excerpt(store, ev?.snapshot_id ?? null, ev?.path ?? null, ev?.start_line ?? null, ev?.end_line ?? null).replace(/^/gm, '    '),
    ].join('\n');
  };
  const findingBlock = (label: string, f: CanonicalFinding) => {
    const loc = fromJson<{ path: string; startLine: number; endLine: number }>(f.location, { path: '', startLine: 1, endLine: 1 });
    const repo = rt.repos.find((r) => r.id === f.repository_id);
    let code = '';
    try { code = rt.views.get(repo?.name ?? '')?.lines(loc.path).slice(loc.startLine - 1, Math.min(loc.endLine, loc.startLine + 19)).join('\n') ?? ''; } catch { /* missing */ }
    return [
      `${label} | ${f.category} | 危险点=${f.sink_symbol ?? '?'} | API=${f.sink_api ?? '?'} | 入口=${fromJson<string[]>(f.entry_keys, []).join(', ') || '?'}`,
      `  根因：${f.root_cause ?? ''}`, '  代码：', code.replace(/^/gm, '    '),
      `  候选：${candidatesOf.get(f.id)!.map((v) => labelOfV.get(v.id)).join(', ')}`,
    ].join('\n');
  };
  const projection = [
    '## 本次发现（未能按危险点确定匹配）', ...[...fLabel].map(([l, id]) => findingBlock(l, findings.find((f) => f.id === id)!)),
    '', '## 已追踪的漏洞', ...vIds.map((id) => vulnBlock(byId.get(id)!)),
  ].join('\n');
  const submit: AuditTool = {
    name: 'submit_suspected_matches', kind: 'submit', parameters: SubmitSuspectedMatches,
    description: P('tool.submit_suspected_matches'),
    validate: (a: { decisions: { finding: string; vulnerability: string | null }[] }) => {
      const issues: string[] = [];
      for (const l of fLabel.keys()) if (a.decisions.filter((d) => d.finding === l).length !== 1) issues.push(P('feedback.suspected_match.decide_once', { finding: l }));
      for (const d of a.decisions) {
        const fid = fLabel.get(d.finding);
        if (!fid) { issues.push(P('feedback.suspected_match.unknown_finding', { finding: d.finding })); continue; }
        if (d.vulnerability !== null && !candidatesOf.get(fid)!.some((v) => labelOfV.get(v.id) === d.vulnerability)) issues.push(P('feedback.suspected_match.not_candidate', { vulnerability: d.vulnerability, finding: d.finding }));
      }
      return issues;
    },
    run: () => ({ text: 'accepted' }),
  };
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'reconcile', phase: 'reconcile', model, signal: ctx.signal, withIndex: false, submitOnly: true,
    prompt: [
      P('suspected_match.task'),
      '', projection,
    ].join('\n'),
    submitTools: [submit], requiredSubmits: ['submit_suspected_matches'], maxTurns: 6,
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const res = (outcome.submissions.submit_suspected_matches as SubmitSuspectedMatches[]).at(-1)!;
  for (const d of res.decisions) {
    const fid = fLabel.get(d.finding)!;
    const vid = d.vulnerability ? vLabel.get(d.vulnerability) : undefined;
    if (!vid || taken.has(vid)) continue;
    plans.set(fid, { level: 'suspected', vulnId: vid, reason: d.reason, candidates: candidatesOf.get(fid)!.map((v) => v.id) });
    taken.add(vid);
  }
  return plans;
}

// ---- apply (inside the reconcile transaction) --------------------------------------

export function matchVulnerabilities(rt: AuditRuntime, canonical: CanonicalFinding[], stepId: string, plans: Map<string, MatchPlan>): void {
  const store = rt.store;
  const projectId = rt.audit.project_id;
  const touched = new Set<string>();
  for (const f of canonical) {
    const plan = plans.get(f.id);
    const entries = fromJson<string[]>(f.entry_keys, []);
    if (plan) {
      const v = store.get<{ id: string; lifecycle: Lifecycle; display_no: number; sink_symbol: string | null }>('SELECT id, lifecycle, display_no, sink_symbol FROM vulnerability WHERE id = ?', plan.vulnId);
      if (v) {
        // Suspected links only advance to persisting (never regressed) until a human confirms.
        const next: Lifecycle = plan.level === 'suspected' ? 'persisting' : v.lifecycle === 'fixed_verified' ? 'regressed' : 'persisting';
        const basis = plan.level === 'exact' ? { fp_sink: f.fp_sink }
          : plan.level === 'rename' ? { fp_sink: f.fp_sink, rename: { from: plan.from, to: plan.to } }
            : { reason: plan.reason, candidates: plan.candidates, fp_sink: f.fp_sink };
        store.insert('vuln_occurrence', {
          id: newId('occurrence'), vulnerability_id: v.id, audit_id: rt.auditId, finding_id: f.id, match_level: plan.level === 'suspected' ? 'suspected' : 'exact',
          match_basis: basis, presence: 'found', lifecycle_before: v.lifecycle, lifecycle_after: next,
        });
        store.update('vulnerability', { id: v.id }, { lifecycle: next, last_seen_audit_id: rt.auditId, ...(plan.level === 'suspected' ? { suspected_link: 1 } : {}) });
        if (next !== v.lifecycle) addRevision(store, v.id, { dimension: 'lifecycle', source: 'rule', actor: 'engine', from: v.lifecycle, to: next, reason: plan.level === 'suspected' ? 'suspected match in audit' : 'matched in audit', auditId: rt.auditId });
        if (plan.level === 'rename') {
          // Follow the sink to its new name: add the renamed fingerprint and show the current symbol.
          if (f.fp_sink && !store.get('SELECT 1 FROM vuln_fingerprint WHERE project_id = ? AND fp = ? AND active = 1', projectId, f.fp_sink)) {
            store.insert('vuln_fingerprint', { vulnerability_id: v.id, project_id: projectId, fp: f.fp_sink, kind: 'rename', since_audit_id: rt.auditId, active: 1 });
          }
          store.update('vulnerability', { id: v.id }, { sink_symbol: plan.to });
          addRevision(store, v.id, { dimension: 'identity', source: 'rule', actor: 'engine', from: plan.from, to: plan.to, reason: 'sink function renamed or moved (body unchanged)', auditId: rt.auditId });
        }
        if (plan.level !== 'suspected') {
          const known = new Set(store.all<{ entry_key: string }>('SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ?', v.id).map((e) => e.entry_key));
          const added = entries.filter((e) => !known.has(e));
          for (const e of added) store.insert('vuln_entry', { vulnerability_id: v.id, entry_key: e, repository_id: f.repository_id, first_seen_audit_id: rt.auditId, last_seen_audit_id: rt.auditId, state: 'active' });
          if (added.length) {
            addRevision(store, v.id, { dimension: 'entries', source: 'rule', actor: 'engine', from: [...known], to: [...known, ...added], reason: 'new entry reaches the same sink', auditId: rt.auditId });
            rt.event('vuln.impact_changed', { vulnerability_id: v.id, added_entries: added }, stepId);
          }
        }
        rt.event('vuln.matched', { vulnerability_id: v.id, display_no: v.display_no, finding_id: f.id, match_level: plan.level === 'suspected' ? 'suspected' : 'exact', ...(plan.level === 'rename' ? { rename: { from: plan.from, to: plan.to } } : {}) }, stepId);
        touched.add(v.id);
        continue;
      }
    }
    const created = createVulnerability(store, f, { projectId, auditId: rt.auditId, actor: rt.strategy.models.audit.model });
    rt.event('vuln.created', { vulnerability_id: created.id, display_no: created.displayNo, finding_id: f.id, confirm_status: created.confirmed ? 'confirmed' : 'pending' }, stepId);
    touched.add(created.id);
  }
  // Active vulnerabilities of this repository not seen in this audit.
  const repoIds = rt.repos.map((r) => r.id);
  const others = store.all<{ id: string; lifecycle: string; repository_id: string; sink_symbol: string | null; sink_api: string | null; category: string }>(
    `SELECT id, lifecycle, repository_id, sink_symbol, sink_api, category FROM vulnerability WHERE project_id = ? AND status = 'active'`, projectId)
    .filter((v) => !touched.has(v.id) && repoIds.includes(v.repository_id));
  for (const v of others) {
    const presence: Presence = isCovered(rt, v) ? 'not_found_unverified' : 'not_covered';
    store.insert('vuln_occurrence', {
      id: newId('occurrence'), vulnerability_id: v.id, audit_id: rt.auditId, finding_id: null, match_level: null,
      match_basis: {}, presence, lifecycle_before: v.lifecycle, lifecycle_after: v.lifecycle,
    });
  }
}

function isCovered(rt: AuditRuntime, v: { id: string; repository_id: string; sink_symbol: string | null; sink_api: string | null }): boolean {
  const store = rt.store;
  const sinkItems = store.all<{ status: string; item_key: string }>(`SELECT status, item_key FROM coverage_item WHERE audit_id = ? AND repository_id = ? AND kind = 'sink'`, rt.auditId, v.repository_id);
  const idx = [...rt.indexes.values()];
  const symbols = new Map(idx.flatMap((i) => i.symbols.map((s) => [s.qualifiedName, s.symbolId] as const)));
  const sinkSymbolId = v.sink_symbol ? symbols.get(v.sink_symbol) ?? v.sink_symbol : null;
  const sinkOk = !!sinkSymbolId && sinkItems.some((i) => i.status === 'concluded' && i.item_key.startsWith(`${sinkSymbolId}|`));
  if (!sinkOk) return false;
  const entries = store.all<{ entry_key: string }>(`SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ? AND state = 'active'`, v.id);
  return entries.every((e) => !!store.get(`SELECT 1 FROM coverage_item WHERE audit_id = ? AND kind = 'entry' AND item_key = ? AND status = 'concluded'`, rt.auditId, e.entry_key));
}

// ---- human decision on a "suspected same" link ----------------

function refreshSuspectedFlag(store: Store, vulnId: string): void {
  const open = store.get('SELECT 1 FROM vuln_occurrence WHERE vulnerability_id = ? AND match_level = ? LIMIT 1', vulnId, 'suspected');
  store.update('vulnerability', { id: vulnId }, { suspected_link: open ? 1 : 0 });
}

/**
 * confirm: the linked finding is this vulnerability — the link becomes `manual`, its fingerprint and
 * entries are adopted, and a previously verified-fixed vulnerability becomes regressed.
 * separate: the finding is a different problem — it becomes a new vulnerability and this one's
 * lifecycle change from the link is undone.
 */
export function decideSuspectedMatch(store: Store, vulnId: string, occurrenceId: string, decision: 'confirm' | 'separate', opts: { reason?: string; actor: string }): { created: { id: string; displayNo: number } | null } {
  let created: { id: string; displayNo: number } | null = null;
  store.tx(() => {
    const occ = store.get<{ id: string; vulnerability_id: string; audit_id: string; finding_id: string | null; match_level: string | null; lifecycle_before: Lifecycle | null; lifecycle_after: Lifecycle | null }>(
      'SELECT * FROM vuln_occurrence WHERE id = ?', occurrenceId);
    if (!occ || occ.vulnerability_id !== vulnId || occ.match_level !== 'suspected' || !occ.finding_id) throw new AppError('COMMON_NOT_FOUND', 'no pending suspected link with this id on the vulnerability');
    const v = store.get<{ id: string; project_id: string; lifecycle: Lifecycle; last_seen_audit_id: string | null }>('SELECT id, project_id, lifecycle, last_seen_audit_id FROM vulnerability WHERE id = ?', vulnId)!;
    const f = store.get<CanonicalFinding & { audit_id: string }>('SELECT * FROM finding WHERE id = ?', occ.finding_id)!;
    const reason = opts.reason?.trim() || (decision === 'confirm' ? 'confirmed as the same vulnerability' : 'separated: a different vulnerability');
    if (decision === 'confirm') {
      const next: Lifecycle = occ.lifecycle_before === 'fixed_verified' ? 'regressed' : (occ.lifecycle_after ?? v.lifecycle);
      store.update('vuln_occurrence', { id: occ.id }, { match_level: 'manual', lifecycle_after: next });
      if (f.fp_sink && !store.get('SELECT 1 FROM vuln_fingerprint WHERE project_id = ? AND fp = ? AND active = 1', v.project_id, f.fp_sink)) {
        store.insert('vuln_fingerprint', { vulnerability_id: vulnId, project_id: v.project_id, fp: f.fp_sink, kind: 'manual', since_audit_id: occ.audit_id, active: 1 });
      }
      const known = new Set(store.all<{ entry_key: string }>('SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ?', vulnId).map((e) => e.entry_key));
      const added = fromJson<string[]>(f.entry_keys, []).filter((e) => !known.has(e));
      for (const e of added) store.insert('vuln_entry', { vulnerability_id: vulnId, entry_key: e, repository_id: f.repository_id, first_seen_audit_id: occ.audit_id, last_seen_audit_id: occ.audit_id, state: 'active' });
      if (added.length) addRevision(store, vulnId, { dimension: 'entries', source: 'human', actor: opts.actor, from: [...known], to: [...known, ...added], reason, auditId: occ.audit_id });
      if (v.last_seen_audit_id === occ.audit_id && next !== v.lifecycle) {
        store.update('vulnerability', { id: vulnId }, { lifecycle: next });
        addRevision(store, vulnId, { dimension: 'lifecycle', source: 'human', actor: opts.actor, from: v.lifecycle, to: next, reason: 'suspected match confirmed', auditId: occ.audit_id });
      }
      addRevision(store, vulnId, { dimension: 'identity', source: 'human', actor: opts.actor, from: { suspected: f.id }, to: { confirmed: f.id }, reason, auditId: occ.audit_id });
    } else {
      // Detach the finding from this vulnerability; it was not seen here after all.
      store.update('vuln_occurrence', { id: occ.id }, { finding_id: null, match_level: null, presence: 'not_covered', lifecycle_after: occ.lifecycle_before, match_basis: { separated: f.id } });
      if (v.last_seen_audit_id === occ.audit_id && occ.lifecycle_before && v.lifecycle === occ.lifecycle_after && v.lifecycle !== occ.lifecycle_before) {
        store.update('vulnerability', { id: vulnId }, { lifecycle: occ.lifecycle_before });
        addRevision(store, vulnId, { dimension: 'lifecycle', source: 'human', actor: opts.actor, from: v.lifecycle, to: occ.lifecycle_before, reason: 'suspected match separated', auditId: occ.audit_id });
      }
      const n = createVulnerability(store, f, { projectId: v.project_id, auditId: occ.audit_id, actor: opts.actor });
      created = { id: n.id, displayNo: n.displayNo };
      addRevision(store, vulnId, { dimension: 'identity', source: 'human', actor: opts.actor, from: { suspected: f.id }, to: { separated: n.id }, reason, auditId: occ.audit_id });
      addRevision(store, n.id, { dimension: 'identity', source: 'human', actor: opts.actor, from: { suspectedOf: vulnId }, to: { separated: n.id }, reason, auditId: occ.audit_id });
    }
    refreshSuspectedFlag(store, vulnId);
  });
  return { created };
}
