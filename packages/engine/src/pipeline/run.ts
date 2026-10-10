// The audit pipeline. Steps are checkpoints: every stage may stop the run (pause, cancel, budget), and a
// later run continues from the steps already settled. Every scene runs the catalog's stages through the orchestrator
// (full / incremental, risk hunt and reverification).
import type { Scene } from '@xiezhi/contracts';
import type { AuditRuntime } from '../runtime.js';
import { PipelineRun, type PipelineHost, type RunResult } from './context.js';
import { FULL_STAGES } from './full.js';
import { REVERIFY_STAGES, RISK_HUNT_STAGES } from './scenes.js';
import { runStages } from './stage.js';

export async function runPipeline(host: PipelineHost, rt: AuditRuntime, signal: AbortSignal): Promise<RunResult> {
  const p = new PipelineRun(host, rt, signal);
  const scene = rt.audit.scene as Scene;
  return runStages(p, scene, scene === 'risk_hunt' ? RISK_HUNT_STAGES : scene === 'reverify' ? REVERIFY_STAGES : FULL_STAGES);
}
