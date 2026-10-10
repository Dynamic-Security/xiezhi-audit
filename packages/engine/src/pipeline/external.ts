// The external-results stage: after the exploration, the imported SAST / SCA results are settled.
// Deterministic first: a result whose file is not in the snapshot is not applicable; one that matches a finding of this
// audit (same file, within LINE_SLACK lines, same category family or CWE) is covered as its duplicate. Then triage batches
// (EXT-B*) of an independent session decide the rest — false positive with a reason (not applicable), or true positive
// (uncovered) — and fill batches (EXT-F-B*) investigate the true positives with a hunt that writes proper findings.
import { Type } from 'typebox';
import { CodeRef, sameCategoryFamily } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import { P } from '@xiezhi/knowledge';
import { fromJson } from '@xiezhi/store';
import { estimateStep } from '../estimates.js';
import { settleObligation } from '../obligations.js';
import { pool } from '../pool.js';
import type { AuditRuntime } from '../runtime.js';
import type { StepRow } from '../state.js';
import { ensureStep, sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { huntStep, validateCodeRef } from '../steps/hunt.js';
import type { Candidate } from '../steps/triage.js';
import type { ExternalResult } from '../sarif.js';
import type { PipelineRun, RunResult } from './context.js';

export const TRIAGE_BATCH = 10;
export const FILL_BATCH = 4;
const LINE_SLACK = 3;

interface ExternalRow { key: string; status: string; detail: ExternalResult }

function rows(rt: AuditRuntime): ExternalRow[] {
  return rt.store.all<{ item_key: string; status: string; detail: string }>(`SELECT item_key, status, detail FROM obligation WHERE audit_id = ? AND kind = 'external' ORDER BY rowid`, rt.auditId)
    .map((r) => ({ key: r.item_key, status: r.status, detail: fromJson<ExternalResult>(r.detail, {} as ExternalResult) }));
}

/** The repository of the audit's targets that has the file (the SARIF paths are relative to a repository root). */
function repoFor(rt: AuditRuntime, path: string): { repo: string; path: string } | null {
  for (const t of rt.targets) {
    const view = rt.views.get(t.name);
    if (!view) continue;
    for (const candidate of [path, path.replace(new RegExp(`^${t.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/`), '')]) {
      try { view.guard(candidate); return { repo: t.name, path: candidate }; } catch { /* not this one */ }
    }
  }
  return null;
}

/** Deterministic settling: outside the snapshot → not applicable; a duplicate of an own finding → covered. */
export function settleExternalDeterministic(rt: AuditRuntime): { notApplicable: number; duplicates: number } {
  const findings = rt.store.all<{ display_no: number | null; lineage_id: string | null; category: string; cwe: string | null; location: string; repository_id: string }>(
    `SELECT display_no, lineage_id, category, cwe, location, repository_id FROM finding WHERE audit_id = ? AND state IN ('submitted','canonical')`, rt.auditId);
  let notApplicable = 0;
  let duplicates = 0;
  for (const r of rows(rt).filter((x) => x.status === 'open')) {
    const at = repoFor(rt, r.detail.uri);
    if (!at) { settleObligation(rt, 'external', r.key, 'not_applicable', `文件 ${r.detail.uri} 不在本次审计的快照中`, null); notApplicable++; continue; }
    const repoId = rt.repos.find((x) => x.name === at.repo)?.id;
    const dup = findings.find((f) => {
      const loc = fromJson<{ path: string; startLine: number; endLine: number }>(f.location, { path: '', startLine: 0, endLine: 0 });
      if (f.repository_id !== repoId || loc.path !== at.path) return false;
      if (r.detail.line < loc.startLine - LINE_SLACK || r.detail.line > loc.endLine + LINE_SLACK) return false;
      return (!!r.detail.cwe && f.cwe === r.detail.cwe) || sameCategoryFamily(f.category, r.detail.category);
    });
    if (dup) { settleObligation(rt, 'external', r.key, 'covered', `与本次审计的发现 ${dup.display_no ? `F-${dup.display_no}` : dup.lineage_id ?? ''} 重复（同一位置、同类问题）`, null); duplicates++; }
  }
  return { notApplicable, duplicates };
}

const SubmitExternalTriage = Type.Object({
  items: Type.Array(Type.Object({
    itemId: Type.String({ maxLength: 500 }),
    verdict: Type.Union([Type.Literal('true_positive'), Type.Literal('false_positive')]),
    reason: Type.String({ minLength: 4, maxLength: 800 }),
    evidence: Type.Optional(Type.Array(CodeRef, { maxItems: 6 })),
  }, { additionalProperties: false }), { minItems: 1, maxItems: TRIAGE_BATCH }),
}, { additionalProperties: false });
type Verdict = { itemId: string; verdict: 'true_positive' | 'false_positive'; reason: string; evidence?: CodeRef[] };

export async function externalTriageStep(rt: AuditRuntime, ctx: AttemptContext, keys: string[]): Promise<StepResult> {
  const all = new Map(rows(rt).map((r) => [r.key, r]));
  const batch = keys.map((k) => all.get(k)!).filter(Boolean);
  const submit: AuditTool = {
    name: 'submit_external_triage', kind: 'submit', parameters: SubmitExternalTriage, description: P('tool.submit_external_triage'),
    validate: (a: { items: Verdict[] }) => {
      const issues: string[] = [];
      const seen = new Set<string>();
      for (const [i, v] of a.items.entries()) {
        if (!keys.includes(v.itemId)) { issues.push(`items[${i}]: ${v.itemId} is not a result of this batch`); continue; }
        seen.add(v.itemId);
        if (v.verdict === 'false_positive' && !v.evidence?.length) issues.push(`items[${i}]: false_positive needs evidence (the code you read that shows it is not exploitable)`);
        for (const [j, e] of (v.evidence ?? []).entries()) issues.push(...validateCodeRef(rt, e, `items[${i}].evidence[${j}]`, true));
      }
      const missing = keys.filter((k) => !seen.has(k));
      if (missing.length) issues.push(`every result needs a verdict; missing: ${missing.join(', ')}`);
      return issues.slice(0, 30);
    },
    run: () => ({ text: 'recorded' }),
  };
  const prompt = [
    P('external.triage', { n: batch.length }),
    '',
    ...batch.map((r) => {
      const at = repoFor(rt, r.detail.uri);
      return `- itemId=\`${r.key}\`  ${at ? `${at.repo}:${at.path}` : r.detail.uri}:${r.detail.line}  [${r.detail.tool} ${r.detail.ruleId}${r.detail.cwe ? ` · ${r.detail.cwe}` : ''} · ${r.detail.level}] ${r.detail.message.slice(0, 400)}`;
    }),
  ].join('\n');
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'coverage-gap', phase: 'hunt', model: rt.strategy.models.challenge ?? rt.strategy.models.audit, signal: ctx.signal,
    prompt, submitTools: [submit], requiredSubmits: ['submit_external_triage'], maxTurns: rt.strategy.limits.maxTurnsPerStep, extraTools: [], threatModel: false,
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const verdicts = (outcome.submissions.submit_external_triage as { items: Verdict[] }[]).at(-1)!.items;
  return {
    outputRef: rt.store.artifacts.putJson({ verdicts }),
    apply: () => {
      for (const v of verdicts) settleObligation(rt, 'external', v.itemId, v.verdict === 'false_positive' ? 'not_applicable' : 'uncovered', `${v.verdict === 'false_positive' ? '误报' : '成立，待补审'}：${v.reason}`, ctx.stepId);
      rt.event('judgement.made', { kind: 'external_triage', true_positive: verdicts.filter((v) => v.verdict === 'true_positive').length, false_positive: verdicts.filter((v) => v.verdict === 'false_positive').length }, ctx.stepId);
    },
  };
}

export async function externalStage(p: PipelineRun): Promise<RunResult | null> {
  const { rt, store, auditId, s } = p;
  if (!rows(rt).length || !p.llmAllowed()) return null;
  const det = settleExternalDeterministic(rt);
  if (det.notApplicable || det.duplicates) rt.event('judgement.made', { kind: 'external_settled', not_applicable: det.notApplicable, duplicates: det.duplicates });
  const blocked: StepRow[] = [];
  const run = async (stepRows: StepRow[], body: (row: StepRow, i: number) => Parameters<PipelineRun['step']>[1]) => {
    await pool(stepRows, p.parallel, async (row, i) => {
      if (p.halting() || blocked.length) return;
      if (!p.llmAllowed()) { p.skipUnrun(row); return; }
      const r = await p.step(row, body(row, i));
      if (r === 'blocked_budget') blocked.push(row);
    });
    if (p.halting()) return p.interrupted();
    if (blocked.length) return p.blocked(p.unfinished('coverage-gap'));
    return null;
  };
  const open = rows(rt).filter((r) => r.status === 'open').map((r) => r.key);
  const triage = Array.from({ length: Math.ceil(open.length / TRIAGE_BATCH) }, (_, i) => open.slice(i * TRIAGE_BATCH, (i + 1) * TRIAGE_BATCH));
  const triageRows = triage.map((keys, i) => ensureStep(store, auditId, {
    kind: 'coverage-gap', identity: { external: keys }, lineage: `EXT-B${i + 1}`, model: s.models.challenge ?? s.models.audit, input: { keys }, estimateTokens: estimateStep('hunt', Math.ceil(keys.length / 2)),
  }));
  let stop = await run(triageRows, (_row, i) => (ctx) => externalTriageStep(rt, ctx, triage[i]!));
  if (stop) return stop;
  const after = rows(rt);
  const tp = after.filter((r) => r.status === 'uncovered');
  const fills = Array.from({ length: Math.ceil(tp.length / FILL_BATCH) }, (_, i) => tp.slice(i * FILL_BATCH, (i + 1) * FILL_BATCH));
  const fillRows = fills.map((batch, i) => ensureStep(store, auditId, {
    kind: 'coverage-gap', identity: { externalFill: batch.map((b) => b.key) }, lineage: `EXT-F-B${i + 1}`, model: s.models.audit, input: { keys: batch.map((b) => b.key) }, estimateTokens: estimateStep('hunt', batch.length),
  }));
  stop = await run(fillRows, (row, i) => async (ctx) => {
    const batch = fills[i]!;
    const cands: Candidate[] = batch.flatMap((r) => {
      const at = repoFor(rt, r.detail.uri);
      return at ? [{ id: `external:${r.key}`, kind: 'change' as const, repo: at.repo, path: at.path, line: r.detail.line, label: `[external · ${r.detail.tool} ${r.detail.ruleId}${r.detail.cwe ? ` · ${r.detail.cwe}` : ''}] ${r.detail.message.slice(0, 300)}`, score: 1 }] : [];
    });
    const res = await huntStep(rt, cands, row.lineage_id ?? 'EXT-F', ctx, { kind: 'coverage-gap' });
    return {
      outputRef: res.outputRef,
      apply: () => {
        res.apply?.();
        const scope = (store.artifacts.getJson<{ scopeReviewed?: string[] }>(res.outputRef).scopeReviewed ?? []).join(', ').slice(0, 600);
        for (const r of batch) settleObligation(rt, 'external', r.key, 'concluded', `补审：${scope || '已检查'}`, ctx.stepId);
      },
    };
  });
  return stop;
}
