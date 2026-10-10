// The checklist check stage: after the exploration and before ⑨, check batches (CHK-B*) settle each
// applicable checklist item; fill batches (CHK-F-B*) investigate the uncovered ones.
import { checkBatches, checklistCheckStep, checklistOn, checklistRows, fillBatches, fillCandidate, registerChecklist } from '../checklist.js';
import { estimateStep } from '../estimates.js';
import { settleObligation } from '../obligations.js';
import { pool } from '../pool.js';
import type { StepRow } from '../state.js';
import { ensureStep } from '../step-runner.js';
import { huntStep } from '../steps/hunt.js';
import type { PipelineRun, RunResult } from './context.js';

export async function checklistStage(p: PipelineRun): Promise<RunResult | null> {
  const { rt, store, auditId, s } = p;
  if (!checklistOn(rt) || !p.llmAllowed()) return null;
  registerChecklist(rt);
  const rows = checklistRows(rt);
  if (!rows.length) return null;
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
  // Check: one small session per batch of one class; its input is the items and the evidence index, not the exploration.
  const checks = checkBatches(rows);
  const checkRows = checks.map((b, i) => ensureStep(store, auditId, {
    kind: 'coverage-gap', identity: { checklist: b.keys }, lineage: `CHK-B${i + 1}`, model: s.models.audit,
    input: { vulnClass: b.vulnClass, keys: b.keys }, estimateTokens: estimateStep('hunt', Math.ceil(b.keys.length / 2)),
  }));
  let stop = await run(checkRows, (_row, i) => (ctx) => checklistCheckStep(rt, ctx, checks[i]!.vulnClass, checks[i]!.keys));
  if (stop) return stop;
  // Fill: the uncovered items, a hunt each batch starting from the files the check named; settled as concluded.
  const after = checklistRows(rt);
  const fills = fillBatches(after);
  if (!fills.length) return null;
  const byKey = new Map(after.map((r) => [r.key, r]));
  const fillRows = fills.map((keys, i) => ensureStep(store, auditId, {
    kind: 'coverage-gap', identity: { checklistFill: keys }, lineage: `CHK-F-B${i + 1}`, model: s.models.audit,
    input: { keys }, estimateTokens: estimateStep('hunt', keys.length),
  }));
  stop = await run(fillRows, (row, i) => async (ctx) => {
    const keys = fills[i]!;
    const r = await huntStep(rt, keys.map((k) => fillCandidate(rt, byKey.get(k)!)), row.lineage_id ?? 'CHK-F', ctx, { kind: 'coverage-gap' });
    return {
      outputRef: r.outputRef,
      apply: () => {
        r.apply?.();
        const scope = (store.artifacts.getJson<{ scopeReviewed?: string[] }>(r.outputRef).scopeReviewed ?? []).join(', ').slice(0, 600);
        for (const k of keys) settleObligation(rt, 'checklist', k, 'concluded', `补审：${scope || '已检查'}`, ctx.stepId);
      },
    };
  });
  return stop;
}
