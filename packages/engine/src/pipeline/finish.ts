// Report (completion gate + deterministic rendering) and finalize — the end of every pipeline.
import { refreshHunt } from '../hunt.js';
import { huntScope } from '../steps/risk.js';
import { reportStep, type GateResult } from '../steps/finalize.js';
import { ensureStep } from '../step-runner.js';
import { transitionAudit } from '../state.js';
import type { PipelineRun, RunResult } from './context.js';

export async function finish(p: PipelineRun, overflow: string[]): Promise<RunResult> {
  const { store, auditId, rt } = p;
  // The report step may run twice; rendering failures of one format do not fail it (reportStep).
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
