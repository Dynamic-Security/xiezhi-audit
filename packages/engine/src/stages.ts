// Which model stage and which budget stage a step belongs to — read from the stage catalog, which
// replaced the separate model-stage and budget-stage classifications.
import { stepRole, type BudgetStage, type ModelStageKey } from '@xiezhi/contracts';

/** The model stage of a step: it decides the step's model and its fallback; null for steps without a model. */
export function stepStage(kind: string, lineage: string | null): ModelStageKey | null {
  return stepRole(kind, lineage)?.model ?? null;
}

/** Which budget stage a step charges; null = no stage quota (no model or no tokens). */
export function budgetStage(kind: string, lineage: string | null): BudgetStage | null {
  return stepRole(kind, lineage)?.budget ?? null;
}
