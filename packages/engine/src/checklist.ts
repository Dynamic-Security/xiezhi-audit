// Checklist check (20): after the exploration, the checklist items the audit's knowledge carries are
// settled one by one in small sessions of their own — never in the lead or an exploring session, whose context is
// fullest then. The engine picks the items deterministically (`applies_to`, focus), registers them as obligations
// (`checklist`), checks them in batches per vulnerability class against an evidence index from the ledger (the
// conclusions and finding locations of that class, which the session may verify by reading code), and hands the
// uncovered ones to a fill session (a hunt over those items). An item still open or uncovered is a coverage gap.
import { Type } from 'typebox';
import { CodeRef, type ObligationStatus } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import type { ChecklistItem } from '@xiezhi/knowledge';
import { fromJson } from '@xiezhi/store';
import type { AuditRuntime } from './runtime.js';
import { addObligation, settleObligation } from './obligations.js';
import { sessionError, type AttemptContext, type StepResult } from './step-runner.js';
import { validateCodeRef } from './steps/hunt.js';
import type { Candidate } from './steps/triage.js';
import { backfillScope } from './steps/coverage-gap.js';
import { supplementScope } from './threat.js';
import { P } from '@xiezhi/knowledge';

/** Items per check session (one vulnerability class per batch). */
export const CHECK_BATCH = 8;
/** Uncovered items per fill session. */
export const FILL_BATCH = 4;
/** Evidence-index lines per class: conclusions and findings. */
const EVIDENCE_LINES = 30;
/** Classes whose units are entry points (authorization, session, cross-site, business rules) rather than sinks. */
const ENTRY_CLASSES: ReadonlySet<string> = new Set(['authz_object', 'authz_function', 'authn', 'csrf', 'cors', 'business_logic', 'race_condition']);

export interface ChecklistRow { key: string; title: string; category: string; status: ObligationStatus; detail: { skill: string; id: string; check: string; startFiles?: string[] } }

/** The check runs in full audits (not incremental ones, which stay on the change; not backfills or supplements). */
export function checklistOn(rt: AuditRuntime): boolean {
  return rt.audit.scene === 'full' && !backfillScope(rt) && !supplementScope(rt);
}

function dimOk(declared: string[] | undefined, task: string[]): boolean {
  if (!declared?.length || !task.length) return true;
  const t = new Set(task.map((x) => x.toLowerCase()));
  return declared.some((d) => t.has(d.toLowerCase()));
}

/** The items that apply to this audit, in skill-name then file order: skill scenes / languages / frameworks, then the item's own. */
export function selectChecklist(rt: AuditRuntime): { skill: string; item: ChecklistItem }[] {
  const facts = rt.taskFacts('hunt');
  const focus = rt.strategy.focus.categories;
  const out: { skill: string; item: ChecklistItem }[] = [];
  for (const s of [...rt.knowledge.skills].sort((a, b) => a.name.localeCompare(b.name))) {
    if (!s.checklist?.length || s.category === 'push_guide' || facts.exclude.includes(s.name)) continue;
    if (!dimOk(s.appliesTo.scenes, [facts.scene]) || !dimOk(s.appliesTo.languages, facts.languages) || !dimOk(s.appliesTo.frameworks, facts.frameworks)) continue;
    for (const item of s.checklist) {
      if (!dimOk(item.appliesTo.languages, facts.languages) || !dimOk(item.appliesTo.frameworks, facts.frameworks)) continue;
      if (focus.length && !focus.includes(item.vulnClass)) continue;
      out.push({ skill: s.name, item });
    }
  }
  return out;
}

/** Register the selected items as `checklist` obligations (kept when they exist: resumes do not reset them). */
export function registerChecklist(rt: AuditRuntime): void {
  rt.store.tx(() => {
    for (const { skill, item } of selectChecklist(rt)) {
      addObligation(rt, { kind: 'checklist', itemKey: `${skill}:${item.id}`, source: 'checklist', title: item.title, category: item.vulnClass, detail: { skill, id: item.id, check: item.check } });
    }
  });
}

export function checklistRows(rt: Pick<AuditRuntime, 'store' | 'auditId'>): ChecklistRow[] {
  return rt.store.all<{ item_key: string; title: string; category: string; status: ObligationStatus; detail: string }>(
    `SELECT item_key, title, category, status, detail FROM obligation WHERE audit_id = ? AND kind = 'checklist' ORDER BY rowid`, rt.auditId)
    .map((r) => ({ key: r.item_key, title: r.title, category: r.category, status: r.status, detail: fromJson(r.detail, { skill: '', id: '', check: '' }) }));
}

/** Check batches: per class in first-seen order, at most CHECK_BATCH items; fixed by the registered rows (stable on resume). */
export function checkBatches(rows: ChecklistRow[]): { vulnClass: string; keys: string[] }[] {
  const byClass = new Map<string, string[]>();
  for (const r of rows) byClass.set(r.category, [...(byClass.get(r.category) ?? []), r.key]);
  return [...byClass.entries()].flatMap(([vulnClass, keys]) => Array.from({ length: Math.ceil(keys.length / CHECK_BATCH) }, (_, i) => ({ vulnClass, keys: keys.slice(i * CHECK_BATCH, (i + 1) * CHECK_BATCH) })));
}

/**
 * The evidence index of a class: findings of the class and concluded ledger units (sinks of the class; entry points for
 * the entry classes) with their verdict and location. Data the session may verify — not the exploration history.
 */
export function evidenceIndex(rt: AuditRuntime, vulnClass: string): string[] {
  const findings = rt.store.all<{ lineage_id: string | null; title: string; location: string }>(
    `SELECT lineage_id, title, location FROM finding WHERE audit_id = ? AND category = ? AND state != 'dropped' ORDER BY created_at LIMIT ?`, rt.auditId, vulnClass, EVIDENCE_LINES);
  const units = rt.store.all<{ kind: string; path: string; start_line: number; verdict: string | null }>(
    `SELECT kind, path, start_line, verdict FROM coverage_item WHERE audit_id = ? AND status = 'concluded' AND (category = ? OR (kind = 'entry' AND ?)) ORDER BY path, start_line LIMIT ?`,
    rt.auditId, vulnClass, ENTRY_CLASSES.has(vulnClass) ? 1 : 0, EVIDENCE_LINES);
  const loc = (l: string) => { const x = fromJson<{ path?: string; startLine?: number }>(l, {}); return x.path ? `${x.path}:${x.startLine ?? 1}` : '（位置未知）'; };
  return [
    ...findings.map((f) => `- 发现 ${f.lineage_id ?? ''}「${f.title.slice(0, 80)}」：${loc(f.location)}`),
    ...units.map((u) => `- ${u.kind === 'entry' ? '入口' : '危险点'} ${u.path}:${u.start_line}：${(u.verdict ?? '已结论').slice(0, 120)}`),
  ];
}

const SubmitChecklist = Type.Object({
  items: Type.Array(Type.Object({
    itemId: Type.String({ maxLength: 200 }),
    status: Type.Union([Type.Literal('covered'), Type.Literal('not_applicable'), Type.Literal('uncovered')]),
    reason: Type.String({ minLength: 4, maxLength: 800 }),
    evidence: Type.Optional(Type.Array(CodeRef, { maxItems: 6 })),
    startFiles: Type.Optional(Type.Array(Type.String({ maxLength: 500 }), { maxItems: 5 })),
  }, { additionalProperties: false }), { minItems: 1, maxItems: CHECK_BATCH }),
}, { additionalProperties: false });
type ChecklistVerdict = { itemId: string; status: 'covered' | 'not_applicable' | 'uncovered'; reason: string; evidence?: CodeRef[]; startFiles?: string[] };

export function checkPrompt(rt: AuditRuntime, vulnClass: string, rows: ChecklistRow[]): string {
  const ev = evidenceIndex(rt, vulnClass);
  return [
    P('checklist.intro', { n: rows.length, vulnClass }),
    '',
    P('checklist.items_heading'),
    ...rows.map((r) => `- itemId=\`${r.key}\` 「${r.title}」：${r.detail.check}`),
    '',
    P('checklist.evidence_heading'),
    ...(ev.length ? ev : [P('checklist.no_evidence')]),
    '',
    P('checklist.how', { n: rows.length }),
  ].join('\n');
}

export async function checklistCheckStep(rt: AuditRuntime, ctx: AttemptContext, vulnClass: string, keys: string[]): Promise<StepResult> {
  const all = new Map(checklistRows(rt).map((r) => [r.key, r]));
  const rows = keys.map((k) => all.get(k)).filter((r): r is ChecklistRow => !!r);
  const isFile = (f: string) => !!startFile(rt, f);
  const submit: AuditTool = {
    name: 'submit_checklist', kind: 'submit', parameters: SubmitChecklist,
    description: P('tool.submit_checklist'),
    validate: (a: { items: ChecklistVerdict[] }) => {
      const issues: string[] = [];
      const seen = new Set<string>();
      for (const [i, v] of a.items.entries()) {
        if (!all.has(v.itemId) || !keys.includes(v.itemId)) { issues.push(P('feedback.checklist.not_in_batch', { i, id: v.itemId })); continue; }
        if (seen.has(v.itemId)) issues.push(P('feedback.checklist.duplicate', { i, id: v.itemId }));
        seen.add(v.itemId);
        if (v.status === 'covered') {
          if (!v.evidence?.length) issues.push(P('feedback.checklist.covered_evidence', { i }));
          for (const [j, e] of (v.evidence ?? []).entries()) issues.push(...validateCodeRef(rt, e, `items[${i}].evidence[${j}]`, true));
        }
        if (v.status === 'uncovered') {
          if (!v.startFiles?.length) issues.push(P('feedback.checklist.uncovered_start', { i }));
          for (const f of v.startFiles ?? []) if (!isFile(f)) issues.push(P('feedback.checklist.start_not_file', { i, file: f }));
        }
      }
      const missing = keys.filter((k) => !seen.has(k));
      if (missing.length) issues.push(P('feedback.checklist.missing', { ids: missing.join(', ') }));
      return issues.slice(0, 30);
    },
    run: () => ({ text: 'recorded' }),
  };
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'coverage-gap', phase: 'hunt', model: rt.strategy.models.audit, signal: ctx.signal,
    prompt: checkPrompt(rt, vulnClass, rows), submitTools: [submit], requiredSubmits: ['submit_checklist'], maxTurns: rt.strategy.limits.maxTurnsPerStep,
    extraTools: [], threatModel: false, vulnClasses: [vulnClass],
  });
  const err = sessionError(outcome);
  if (err) throw err;
  // Start files as `repo:path` in a multi-repository audit (the fill session starts in that repository).
  const verdicts = (outcome.submissions.submit_checklist as { items: ChecklistVerdict[] }[]).at(-1)!.items.map((v) => (v.startFiles?.length
    ? { ...v, startFiles: v.startFiles.map((f) => { const r = startFile(rt, f)!; return rt.views.size > 1 ? `${r.repo}:${r.path}` : r.path; }) } : v));
  return {
    outputRef: rt.store.artifacts.putJson({ vulnClass, verdicts }),
    apply: () => {
      for (const v of verdicts) {
        settleObligation(rt, 'checklist', v.itemId, v.status, v.reason, ctx.stepId);
        const d = all.get(v.itemId)!.detail;
        rt.store.db.run(`UPDATE obligation SET detail = ? WHERE audit_id = ? AND kind = 'checklist' AND item_key = ?`,
          JSON.stringify({ ...d, ...(v.evidence?.length ? { evidence: v.evidence } : {}), ...(v.startFiles?.length ? { startFiles: v.startFiles } : {}) }), rt.auditId, v.itemId);
      }
      rt.event('judgement.made', { kind: 'checklist_checked', vulnClass, ...Object.fromEntries(['covered', 'not_applicable', 'uncovered'].map((s) => [s, verdicts.filter((v) => v.status === s).length])) }, ctx.stepId);
    },
  };
}

/** Fill batches over the uncovered items, in ledger order. */
export function fillBatches(rows: ChecklistRow[]): string[][] {
  const open = rows.filter((r) => r.status === 'uncovered').map((r) => r.key);
  return Array.from({ length: Math.ceil(open.length / FILL_BATCH) }, (_, i) => open.slice(i * FILL_BATCH, (i + 1) * FILL_BATCH));
}

/**
 * A start file of an uncovered item in any target repository (only the first one was looked at, so in a
 * multi-repository audit every file of the others was rejected and the check failed): `repo:path`, `repo/path`, or a
 * path of one repository (the first target's first).
 */
export function startFile(rt: Pick<AuditRuntime, 'views' | 'targetRepo'>, f: string): { repo: string; path: string } | null {
  const tryIn = (repo: string, path: string) => {
    const v = rt.views.get(repo);
    if (!v) return null;
    try { return { repo, path: v.guard(path) }; } catch { return null; }
  };
  const sep = /^([^:/\\]+)[:/](.+)$/.exec(f);
  if (sep && rt.views.has(sep[1]!)) {
    const hit = tryIn(sep[1]!, sep[2]!);
    if (hit) return hit;
  }
  const order = [rt.targetRepo.name, ...[...rt.views.keys()].filter((r) => r !== rt.targetRepo.name)];
  for (const repo of order) { const hit = tryIn(repo, f); if (hit) return hit; }
  return null;
}

/** A fill target: the item, starting at the first file the check named (`checklist:` ids are not ledger units). */
export function fillCandidate(rt: AuditRuntime, r: ChecklistRow): Candidate {
  const first = r.detail.startFiles?.[0];
  const at = first ? startFile(rt, first) : null;
  const path = at?.path ?? first ?? '.';
  return { id: `checklist:${r.key}`, kind: 'change', repo: at?.repo ?? rt.targetRepo.name, path, line: 1, label: `[checklist] ${r.title}：${r.detail.check.slice(0, 300)}`, score: 1 };
}
