// The orchestrator: runs a scene's stages in the catalog's order. Stages of one group run in
// parallel and are settled after all of them joined; every other stage settles itself (it returns its RunResult) or
// returns null to go on. Only ordered batches and stop conditions — no dependency graph, no stages added at run time.
import { sceneStages, type Scene, type StageId } from '@xiezhi/contracts';
import type { HuntStage } from './hunts.js';
import type { LocateResult } from '@xiezhi/context';
import type { StepRow } from '../state.js';
import type { TriageOutput } from '../steps/triage.js';
import type { PipelineRun, RunResult, Stop } from './context.js';

/** What a stage hands the next ones (typed fields instead of local variables of one long function). */
export interface StageBag {
  /** ⑥ candidate selection as it came back (before the profile's added entry points and sinks). */
  selected?: TriageOutput;
  /** The selection with the profile's surface: what the hunts work on. */
  triage?: TriageOutput;
  /** ⑦–⑨ hunt state: run after the lead, completed by ⑨. */
  hunts?: HuntStage;
  /** Risk hunt: the located candidates and the judge step of each repository. */
  risk?: { basis: string; located: LocateResult; judges: { repo: string; cands: LocateResult['candidates']; row: StepRow }[] };
}

/**
 * A stage's result: a settled run (stop here, or the final result of `finish`), a stop to settle (stages of a
 * parallel group return these, so two branches never both change the audit state), or null to go on.
 */
export type StageOutcome = RunResult | Stop | null;

export interface StageImpl {
  readonly id: StageId;
  run(p: PipelineRun, bag: StageBag): Promise<StageOutcome>;
}

const isRunResult = (o: RunResult | Stop): o is RunResult => 'status' in o;

/** The stages of a scene must all have an implementation. */
export function checkImplementations(scene: Scene, impls: ReadonlyMap<StageId, StageImpl>): void {
  const missing = sceneStages(scene).filter((s) => !impls.has(s.id)).map((s) => s.id);
  if (missing.length) throw new Error(`stages without implementation for ${scene}: ${missing.join(', ')}`);
}

export async function runStages(p: PipelineRun, scene: Scene, impls: ReadonlyMap<StageId, StageImpl>): Promise<RunResult> {
  checkImplementations(scene, impls);
  const stages = sceneStages(scene);
  const bag: StageBag = {};
  for (let i = 0; i < stages.length;) {
    const group = stages[i]!.group;
    let j = i + 1;
    while (group && j < stages.length && stages[j]!.group === group) j++;
    const batch = stages.slice(i, j).map((s) => impls.get(s.id)!);
    i = j;
    if (batch.length === 1) {
      const o = await batch[0]!.run(p, bag);
      if (o) return isRunResult(o) ? o : p.settle(o);
      continue;
    }
    // A parallel group (④⑤ alongside ⑥): join, then the first stop in catalog order settles the run.
    const outcomes = await Promise.all(batch.map((s) => s.run(p, bag)));
    if (p.halting()) return p.interrupted();
    const o = outcomes.find((x): x is RunResult | Stop => !!x);
    if (o) return isRunResult(o) ? o : p.settle(o);
  }
  throw new Error(`pipeline for ${scene} ended without a result`);
}
