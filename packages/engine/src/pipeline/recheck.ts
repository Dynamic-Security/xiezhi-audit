// The conclusion recheck stage: before ⑨, RCK-B* sessions of an independent model look again at the
// "no issue" conclusions that contradict an index fact and at a weighted sample of the rest; a unit they disagree on is
// reopened for ⑨.
import { recheckBatches, recheckStep, recheckUnits } from '../recheck.js';
import { estimateStep } from '../estimates.js';
import { pool } from '../pool.js';
import type { StepRow } from '../state.js';
import { ensureStep } from '../step-runner.js';
import { backfillScope } from '../steps/coverage-gap.js';
import type { Candidate } from '../steps/triage.js';
import { supplementScope } from '../threat.js';
import type { PipelineRun, RunResult } from './context.js';

export async function recheckStage(p: PipelineRun, candidates: Candidate[]): Promise<RunResult | null> {
  const { rt, store, auditId, s } = p;
  if (!['full', 'incremental'].includes(rt.audit.scene) || backfillScope(rt) || supplementScope(rt) || !p.llmAllowed()) return null;
  // The units are chosen once (the first time the stage runs) and kept in the step identities, so a resume — after
  // which some units may be concluded again — runs the same batches.
  const batches = recheckBatches(recheckUnits(rt, candidates));
  if (!batches.length) return null;
  const model = s.models.challenge ?? s.models.audit;
  const rows = batches.map((units, i) => ensureStep(store, auditId, {
    kind: 'coverage-gap', identity: { recheck: units.map((u) => u.targetId) }, lineage: `RCK-B${i + 1}`, model,
    input: { units }, estimateTokens: estimateStep('hunt', Math.ceil(units.length / 2)),
  }));
  const blocked: StepRow[] = [];
  await pool(rows, p.parallel, async (row, i) => {
    if (p.halting() || blocked.length) return;
    if (!p.llmAllowed()) { p.skipUnrun(row); return; }
    const r = await p.step(row, (ctx) => recheckStep(rt, ctx, batches[i]!, model));
    if (r === 'blocked_budget') blocked.push(row);
  });
  if (p.halting()) return p.interrupted();
  if (blocked.length) return p.blocked(p.unfinished('coverage-gap'));
  return null;
}
