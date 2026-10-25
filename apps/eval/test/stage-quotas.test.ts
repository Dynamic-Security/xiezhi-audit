// Eval runs measure quality under the total budget: stage quotas are off unless an experiment
// sets them, because the runner declines every budget wait.
import { describe, expect, it } from 'vitest';
import { auditBudget, BUDGET_STAGES, mergeStrategy, sceneDefaults } from '@xiezhi/contracts';
import { evalStrategyOverride } from '../src/runner.js';

const M = { defaultModel: { provider: 'gw', model: 'm1' } };

describe('eval strategy override', () => {
  it('turns stage quotas off by default and keeps the other overrides', () => {
    const o = evalStrategyOverride({ budget: { tokens: 5_000_000 }, limits: { maxCandidates: 300 } });
    expect(o.limits).toEqual({ maxCandidates: 300 });
    expect((o.budget as { tokens: number }).tokens).toBe(5_000_000);
    expect(Object.keys((o.budget as { stages: object }).stages)).toEqual([...BUDGET_STAGES]);
    const s = mergeStrategy(sceneDefaults('full', M), undefined, o).strategy;
    expect(auditBudget(s).stages).toBeUndefined();
    expect(auditBudget(s).tokens).toBe(5_000_000);
    expect(auditBudget(mergeStrategy(sceneDefaults('full', M), undefined, evalStrategyOverride(undefined)).strategy).stages).toBeUndefined();
  });

  it('leaves an experiment that sets stage quotas as it is', () => {
    const o = { budget: { stages: { hunt: 0.5 } } };
    expect(evalStrategyOverride(o)).toBe(o);
    const s = mergeStrategy(sceneDefaults('full', M), undefined, o).strategy;
    expect(auditBudget(s).stages!.hunt).toBe(6_000_000);
  });
});
