// Report (completion gate + deterministic rendering) and finalize — the end of every pipeline.
import { refreshHunt } from '../hunt.js';
import { huntScope } from '../steps/risk.js';
import { reportStep, type GateResult } from '../steps/finalize.js';
import { ensureStep } from '../step-runner.js';
import { durationExceeded } from '../budget.js';
import { listSteps, NOT_RUN_MARK, NOT_STARTED, transitionAudit, transitionStep } from '../state.js';
import type { PipelineRun, RunResult } from './context.js';

export async function finish(p: PipelineRun, overflow: string[]): Promise<RunResult> {
  const { store, auditId, rt } = p;
  // Cross lanes the content filter refused while the other models went on, still undecided: skipped, so the
  // report says the task has only the other models' results.
  for (const id of rt.filteredLanes) transitionStep(store, id, 'skipped', {}, 'content filtered; the other cross models covered the task');
  // Steps still waiting when the pipeline ends (pending, waiting for budget, interrupted) never run
  // any more: skipped, so the overview no longer shows an ended audit's stages as running and the gate can tell them.
  const why = p.declined ? 'budget declined' : durationExceeded(rt.audit) ? 'duration exhausted' : 'audit ended';
  for (const s of listSteps(store, auditId)) {
    if (s.kind !== 'report' && s.kind !== 'finalize' && NOT_STARTED.includes(s.status)) transitionStep(store, s.id, 'skipped', { error_summary: `${NOT_RUN_MARK}${why}` }, why);
  }
  // The report step may run twice; rendering failures of one format no longer fail it (reportStep).
  const reportRow = ensureStep(store, auditId, { kind: 'report', identity: { audit: auditId }, required: true, maxAttempts: 2 });
  const out = await p.step(reportRow, async (ctx) => reportStep(rt, ctx, [...p.carried], overflow));
  if (out === 'interrupted') return p.interrupted();
  const gate: GateResult | null = rt.audit.gate_ref ? store.artifacts.getJson<GateResult>(rt.audit.gate_ref) : null;
  const finalRow = ensureStep(store, auditId, { kind: 'finalize', identity: { audit: auditId }, required: true, maxAttempts: 1 });
  const status = out !== 'succeeded' || !gate ? 'failed' : gate.status;
  const reasons = gate?.partialReasons ?? [];
  await p.step(finalRow, async () => ({
    outputRef: store.artifacts.putJson({ status, partialReasons: reasons }),
    apply: () => transitionAudit(store, auditId, status, {
      reason: 'completion gate', partialReasons: reasons, ...(status === 'failed' ? { errorClass: out !== 'succeeded' ? 'INTERNAL' as const : 'OUTPUT_CONTRACT' as const } : {}),
    }),
  }));
  // language servers are reclaimed when the audit ends (other audits of the same snapshot restart them).
  await p.host.closeLsp(rt.repos.map((r) => r.rootHash));
  const hunt = rt.audit.scene === 'risk_hunt' ? huntScope(rt) : null;
  if (hunt) refreshHunt(store, hunt.id);
  return { status, partialReasons: reasons };
}
