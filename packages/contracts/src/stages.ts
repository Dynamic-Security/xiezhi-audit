// The stage catalog: what a pipeline stage is, in one place. Each stage lists the step roles it creates;
// a role says which model stage a step uses (model and fallback), which budget stage it charges, and
// where the execution overview shows it (phase and segment). The engine's stage implementations,
// the orchestrator, the estimates and the execution overview read this catalog instead of classifying steps themselves.
import type { EXECUTION_PHASES, EXECUTION_SEGMENTS } from './api.js';
import type { Scene, StepKind } from './enums.js';
import type { BudgetStage, ModelStageKey } from './strategy.js';

export const STAGE_IDS = [
  'setup', 'gateway', 'understand', 'triage', 'surface', 'lead', 'hunt', 'external', 'checklist', 'recheck', 'gap',
  'locate', 'judge', 'reconcile', 'explore', 'review', 'publish', 'verify', 'finish',
] as const;
export type StageId = (typeof STAGE_IDS)[number];

export type ExecPhase = (typeof EXECUTION_PHASES)[number];
export type ExecSegment = (typeof EXECUTION_SEGMENTS)[number];

/** A kind of step a stage creates; `lineage` narrows the kind by the step's lineage id (first matching role wins). */
export interface StepRole {
  kind: StepKind;
  lineage?: RegExp;
  stage: StageId;
  model: ModelStageKey | null;
  budget: BudgetStage | null;
  phase: ExecPhase;
  segment: ExecSegment;
}

export interface StageMeta {
  id: StageId;
  /** Display name (Chinese, like the rest of the UI). */
  label: string;
  /** Scenes that run the stage, in this catalog's order. `setup` runs before the pipeline (snapshot, index, plan). */
  scenes: readonly Scene[];
  /** Deterministic stages never call a model. */
  kind: 'deterministic' | 'model' | 'mixed';
  /** Stages of the same group in one scene run in parallel and are settled after all of them joined. */
  group?: string;
  /** The strategy switch (`strategy.stages.<key>`) that turns the stage off, when it has one. */
  switch?: 'adversarialReview' | 'deepExplore' | 'threatHypotheses';
  /**
   * the stage also runs on demand while its switch keeps the scene default (⑪ explores the experts' open
   * directions); only an explicit `false` from a layer turns it off.
   */
  onDemand?: boolean;
}

const FULL_INC = ['full', 'incremental'] as const;

/** Stages in execution order; a scene runs its own stages in this order (risk hunt: locate → judge → reconcile). */
export const STAGE_CATALOG: readonly StageMeta[] = [
  { id: 'setup', label: '快照、索引与计划', scenes: ['full', 'incremental', 'risk_hunt', 'reverify'], kind: 'mixed' },
  { id: 'gateway', label: '网关鉴权事实', scenes: FULL_INC, kind: 'deterministic' },
  { id: 'understand', label: '系统理解', scenes: FULL_INC, kind: 'model', group: 'prepare' },
  { id: 'triage', label: '初筛', scenes: FULL_INC, kind: 'mixed', group: 'prepare' },
  { id: 'surface', label: '补齐入口与危险点', scenes: FULL_INC, kind: 'deterministic' },
  { id: 'lead', label: '主控探索', scenes: FULL_INC, kind: 'model' },
  { id: 'hunt', label: '假设复查与追查', scenes: FULL_INC, kind: 'model' },
  { id: 'external', label: '外部结果分诊', scenes: FULL_INC, kind: 'model' },
  { id: 'checklist', label: '清单核对', scenes: ['full'], kind: 'model' },
  { id: 'recheck', label: '结论复查', scenes: FULL_INC, kind: 'model' },
  { id: 'gap', label: '覆盖补齐', scenes: FULL_INC, kind: 'model' },
  { id: 'locate', label: '定位', scenes: ['risk_hunt'], kind: 'model' },
  { id: 'judge', label: '研判', scenes: ['risk_hunt'], kind: 'model' },
  { id: 'reconcile', label: '归并', scenes: ['full', 'incremental', 'risk_hunt'], kind: 'mixed' },
  { id: 'explore', label: '深度探索', scenes: FULL_INC, kind: 'model', switch: 'deepExplore', onDemand: true },
  { id: 'review', label: '对抗复核', scenes: FULL_INC, kind: 'model', switch: 'adversarialReview' },
  { id: 'publish', label: '发布', scenes: FULL_INC, kind: 'deterministic' },
  { id: 'verify', label: '修复验证', scenes: ['reverify'], kind: 'model' },
  { id: 'finish', label: '报告与收尾', scenes: ['full', 'incremental', 'risk_hunt', 'reverify'], kind: 'deterministic' },
];

/**
 * Step roles, first match wins. The checklist check (CHK-*), the conclusion recheck (RCK-*) and the external triage
 * (EXT-*) reuse the `coverage-gap` kind and charge the coverage-completion quota (`gap`); the recheck and
 * the external triage run on the adversarial review model (`models.challenge ?? models.audit`), so their model stage
 * is `challenge` (before, they were classified as `hunt` and fell back like hunt steps).
 */
export const STEP_ROLES: readonly StepRole[] = [
  { kind: 'snapshot', stage: 'setup', model: null, budget: null, phase: 'prepare', segment: 'snapshot' },
  { kind: 'index', stage: 'setup', model: null, budget: null, phase: 'prepare', segment: 'index' },
  { kind: 'plan', stage: 'setup', model: 'profile', budget: 'prepare', phase: 'prepare', segment: 'plan' },
  { kind: 'scope', stage: 'understand', model: 'scope', budget: 'prepare', phase: 'prepare', segment: 'scope' },
  { kind: 'profile', stage: 'understand', model: 'profile', budget: 'prepare', phase: 'prepare', segment: 'profile' },
  { kind: 'threat-model', stage: 'understand', model: 'logic', budget: 'hypotheses', phase: 'prepare', segment: 'threat' },
  { kind: 'triage', stage: 'triage', model: 'triage', budget: 'triage', phase: 'triage', segment: 'triage' },
  { kind: 'hunt', lineage: /^LOGIC/, stage: 'hunt', model: 'logic', budget: 'hunt', phase: 'hunt', segment: 'hunt' },
  { kind: 'hunt', lineage: /^HYP/, stage: 'hunt', model: 'logic', budget: 'hypotheses', phase: 'hunt', segment: 'hunt' },
  { kind: 'hunt', lineage: /^GAP/, stage: 'gap', model: 'hunt', budget: 'gap', phase: 'hunt', segment: 'hunt' },
  { kind: 'hunt', lineage: /^R\d/, stage: 'explore', model: 'explore', budget: 'explore', phase: 'explore', segment: 'explore' },
  { kind: 'hunt', lineage: /^(LEAD|DOM-)/, stage: 'lead', model: 'hunt', budget: 'hunt', phase: 'hunt', segment: 'hunt' },
  { kind: 'hunt', stage: 'hunt', model: 'hunt', budget: 'hunt', phase: 'hunt', segment: 'hunt' },
  { kind: 'coverage-gap', lineage: /^CHK-/, stage: 'checklist', model: 'hunt', budget: 'gap', phase: 'hunt', segment: 'checklist' },
  { kind: 'coverage-gap', lineage: /^RCK-/, stage: 'recheck', model: 'challenge', budget: 'gap', phase: 'hunt', segment: 'recheck' },
  { kind: 'coverage-gap', lineage: /^EXT-F/, stage: 'external', model: 'hunt', budget: 'gap', phase: 'hunt', segment: 'external' },
  { kind: 'coverage-gap', lineage: /^EXT-/, stage: 'external', model: 'challenge', budget: 'gap', phase: 'hunt', segment: 'external' },
  { kind: 'coverage-gap', stage: 'gap', model: 'hunt', budget: 'gap', phase: 'hunt', segment: 'hunt' },
  { kind: 'decide', stage: 'explore', model: 'explore', budget: 'explore', phase: 'explore', segment: 'explore' },
  { kind: 'challenge', stage: 'review', model: 'challenge', budget: 'review', phase: 'challenge', segment: 'challenge' },
  { kind: 'review', stage: 'review', model: 'challenge', budget: 'review', phase: 'challenge', segment: 'challenge' },
  { kind: 'reconcile', stage: 'reconcile', model: 'merge', budget: 'merge', phase: 'finalize', segment: 'finalize' },
  { kind: 'hunt-risk', lineage: /^LOCATE$/, stage: 'locate', model: 'verify', budget: 'hunt', phase: 'risk', segment: 'locate' },
  { kind: 'hunt-risk', stage: 'judge', model: 'verify', budget: 'hunt', phase: 'risk', segment: 'judge' },
  { kind: 'verify-fix', stage: 'verify', model: 'verify', budget: 'verify', phase: 'verify', segment: 'verify' },
  { kind: 'report', stage: 'finish', model: null, budget: null, phase: 'finalize', segment: 'finalize' },
  { kind: 'finalize', stage: 'finish', model: null, budget: null, phase: 'finalize', segment: 'finalize' },
];

/** The role of a step; null for a kind the catalog does not know (treated as a preparation step without a model). */
export function stepRole(kind: string, lineage: string | null | undefined): StepRole | null {
  for (const r of STEP_ROLES) {
    if (r.kind !== kind) continue;
    if (r.lineage && !r.lineage.test(lineage ?? '')) continue;
    return r;
  }
  return null;
}

/** The catalog entry of a stage. */
export function stageMeta(id: StageId): StageMeta {
  const m = STAGE_CATALOG.find((x) => x.id === id);
  if (!m) throw new Error(`unknown stage ${id}`);
  return m;
}

/** The stages a scene runs, in order (without `setup`, which runs before the pipeline). */
export function sceneStages(scene: Scene): StageMeta[] {
  return STAGE_CATALOG.filter((s) => s.id !== 'setup' && s.scenes.includes(scene));
}
