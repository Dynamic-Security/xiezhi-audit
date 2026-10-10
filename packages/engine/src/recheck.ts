// Conclusion recheck: "no issue" conclusions are the cheapest place for a model to be wrong and the
// hardest to notice. Before ⑨ the engine picks (1) conclusions that contradict a fact of the structure index — a sink
// whose call takes a request value or a concatenated string, an entry point with no authentication signal that reaches
// an object by id — and (2) a sample of the other "no issue" conclusions weighted by triage score, and has an
// independent model look at each unit again. A unit it disagrees on is reopened, so ⑨ (or the gate) picks it up.
import { createHash } from 'node:crypto';
import { Type } from 'typebox';
import { CodeRef, type ModelRef } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import type { AuditRuntime } from './runtime.js';
import { sessionError, type AttemptContext, type StepResult } from './step-runner.js';
import { validateCodeRef } from './steps/hunt.js';
import { heuristicLlmScore, type Candidate } from './steps/triage.js';
import { P } from '@xiezhi/knowledge';

/** Share of the remaining "no issue" conclusions sampled (10–20%), at least one, at most SAMPLE_MAX. */
export const SAMPLE_SHARE = 0.15;
export const SAMPLE_MAX = 20;
/** Units per recheck session. */
export const RECHECK_BATCH = 5;
/** Sinks whose index hint says a request value or a concatenated string reaches the call. */
const TAINTED = new Set(['request_string', 'string_concat']);
const STATE_CHANGING = /^(POST|PUT|PATCH|DELETE)\b/i;

export interface RecheckUnit { targetId: string; kind: 'entry' | 'sink'; path: string; line: number; verdict: string; reason: 'index_fact' | 'sample'; fact?: string }

const isNoIssue = (v: string | null) => !!v && (v === 'no_issue' || v.startsWith('ruled_out'));

/** The units to recheck: index-fact contradictions first, then the weighted sample; deterministic for an audit. */
export function recheckUnits(rt: AuditRuntime, candidates: Candidate[]): RecheckUnit[] {
  const rows = rt.store.all<{ kind: 'entry' | 'sink'; target_id: string; path: string; start_line: number; verdict: string | null }>(
    `SELECT kind, target_id, path, start_line, verdict FROM coverage_item WHERE audit_id = ? AND status = 'concluded' ORDER BY kind, target_id`, rt.auditId)
    .filter((r) => isNoIssue(r.verdict));
  const sinks = new Map<string, { taintHint?: string; category: string; api: string }>();
  const entries = new Map<string, { entryKey: string; authSignals: string[]; pathTemplate?: string }>();
  for (const idx of rt.indexes.values()) {
    for (const s of idx.sinks) sinks.set(s.sinkId, s as { taintHint?: string; category: string; api: string });
    for (const e of idx.entrypoints) entries.set(e.entryId, e);
  }
  const out: RecheckUnit[] = [];
  const rest: typeof rows = [];
  for (const r of rows) {
    const base = { targetId: r.target_id, kind: r.kind, path: r.path, line: r.start_line, verdict: r.verdict! };
    const s = r.kind === 'sink' ? sinks.get(r.target_id) : undefined;
    const e = r.kind === 'entry' ? entries.get(r.target_id) : undefined;
    if (s?.taintHint && TAINTED.has(s.taintHint)) {
      out.push({ ...base, reason: 'index_fact', fact: `结构索引提示：危险调用 ${s.api}（${s.category}）的参数${s.taintHint === 'request_string' ? '直接来自请求' : '由字符串拼接而成'}` });
    } else if (e && !e.authSignals.length && /[{:]/.test(e.pathTemplate ?? e.entryKey) && (STATE_CHANGING.test(e.entryKey) || /\{[^}]*id[^}]*\}|:\w*id\b/i.test(e.pathTemplate ?? e.entryKey))) {
      out.push({ ...base, reason: 'index_fact', fact: `结构索引提示：入口 ${e.entryKey} 没有识别到认证信号，并按路径参数访问对象` });
    } else rest.push(r);
  }
  // Weighted sample without replacement (Efraimidis–Spirakis), keyed by the audit so a resume picks the same units.
  const score = new Map(candidates.map((c) => [c.id, c.llmScore ?? heuristicLlmScore(c.score)]));
  const k = rest.length ? Math.min(SAMPLE_MAX, Math.max(1, Math.round(rest.length * SAMPLE_SHARE))) : 0;
  const keyed = rest.map((r) => {
    const u = (parseInt(createHash('sha256').update(`${rt.auditId}:${r.target_id}`).digest('hex').slice(0, 12), 16) + 1) / (2 ** 48 + 2);
    const w = Math.max(0.5, score.get(r.target_id) ?? 1);
    return { r, key: Math.log(u) / w };
  }).sort((a, b) => b.key - a.key || a.r.target_id.localeCompare(b.r.target_id)).slice(0, k);
  for (const { r } of keyed) out.push({ targetId: r.target_id, kind: r.kind, path: r.path, line: r.start_line, verdict: r.verdict!, reason: 'sample' });
  return out;
}

export function recheckBatches(units: RecheckUnit[]): RecheckUnit[][] {
  return Array.from({ length: Math.ceil(units.length / RECHECK_BATCH) }, (_, i) => units.slice(i * RECHECK_BATCH, (i + 1) * RECHECK_BATCH));
}

const SubmitRecheck = Type.Object({
  items: Type.Array(Type.Object({
    targetId: Type.String({ maxLength: 500 }),
    agree: Type.Boolean({ description: 'true when the earlier "no issue" conclusion holds' }),
    reason: Type.String({ minLength: 4, maxLength: 800 }),
    evidence: Type.Optional(Type.Array(CodeRef, { maxItems: 6 })),
  }, { additionalProperties: false }), { minItems: 1, maxItems: RECHECK_BATCH }),
}, { additionalProperties: false });
type RecheckVerdict = { targetId: string; agree: boolean; reason: string; evidence?: CodeRef[] };

export function recheckPrompt(units: RecheckUnit[]): string {
  return [
    P('recheck.intro', { n: units.length }),
    '',
    P('recheck.units_heading'),
    ...units.map((u) => `- targetId=\`${u.targetId}\`（${u.kind === 'entry' ? '入口' : '危险点'}，${u.path}:${u.line}）原结论：${u.verdict.slice(0, 240)}${u.fact ? `\n  ${u.fact}` : '（抽检）'}`),
    '',
    P('recheck.how', { n: units.length }),
  ].join('\n');
}

export async function recheckStep(rt: AuditRuntime, ctx: AttemptContext, units: RecheckUnit[], model: ModelRef): Promise<StepResult> {
  const ids = units.map((u) => u.targetId);
  const submit: AuditTool = {
    name: 'submit_recheck', kind: 'submit', parameters: SubmitRecheck,
    description: P('tool.submit_recheck'),
    validate: (a: { items: RecheckVerdict[] }) => {
      const issues: string[] = [];
      const seen = new Set<string>();
      for (const [i, v] of a.items.entries()) {
        if (!ids.includes(v.targetId)) { issues.push(P('feedback.recheck.not_in_batch', { i, id: v.targetId })); continue; }
        if (seen.has(v.targetId)) issues.push(P('feedback.recheck.duplicate', { i, id: v.targetId }));
        seen.add(v.targetId);
        if (!v.agree && !v.evidence?.length) issues.push(P('feedback.recheck.disagree_evidence', { i }));
        for (const [j, e] of (v.evidence ?? []).entries()) issues.push(...validateCodeRef(rt, e, `items[${i}].evidence[${j}]`, true));
      }
      const missing = ids.filter((x) => !seen.has(x));
      if (missing.length) issues.push(P('feedback.recheck.missing', { ids: missing.join(', ') }));
      return issues.slice(0, 30);
    },
    run: () => ({ text: 'recorded' }),
  };
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'coverage-gap', phase: 'hunt', model, signal: ctx.signal,
    prompt: recheckPrompt(units), submitTools: [submit], requiredSubmits: ['submit_recheck'], maxTurns: rt.strategy.limits.maxTurnsPerStep,
    extraTools: [], threatModel: false,
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const verdicts = (outcome.submissions.submit_recheck as { items: RecheckVerdict[] }[]).at(-1)!.items;
  return {
    outputRef: rt.store.artifacts.putJson({ units, verdicts }),
    apply: () => {
      const reopened: string[] = [];
      for (const v of verdicts) {
        if (v.agree) continue;
        const u = units.find((x) => x.targetId === v.targetId)!;
        // No verdict: the coverage finalize would otherwise conclude a read unit with a verdict again. The reason is in the
        // step output and the event.
        rt.store.db.run(`UPDATE coverage_item SET status = 'read', verdict = NULL, concluded_by_step = NULL, updated_at = ? WHERE audit_id = ? AND kind = ? AND target_id = ? AND status = 'concluded'`,
          Date.now(), rt.auditId, u.kind, u.targetId);
        reopened.push(u.targetId);
      }
      rt.event('judgement.made', {
        kind: 'conclusion_recheck', units: units.length, indexFacts: units.filter((u) => u.reason === 'index_fact').length,
        agreed: verdicts.filter((v) => v.agree).length, reopened: reopened.length, ids: reopened.slice(0, 20),
      }, ctx.stepId);
    },
  };
}
