// One stage vocabulary and order for the model table, the stage quotas and the status bar; every stage has an ⓘ.
import { describe, expect, it } from 'vitest';
import { BUDGET_STAGES, EXECUTION_SEGMENTS } from '@xiezhi/contracts';
import { BUDGET_STAGE, stepLabel } from '../src/shared/format/messages';
import { SEGMENT_LABEL } from '../src/features/audits/StatusBar';
import { STAGE_LABEL } from '../src/features/audits/StageModels';
import { BUDGET_INFO, SEGMENT_INFO } from '../src/features/audits/stageInfo';

describe('stage alignment', () => {
  it('the hunt stage is 领域审计 everywhere', () => {
    expect([STAGE_LABEL.hunt, BUDGET_STAGE.hunt, SEGMENT_LABEL.hunt, stepLabel('hunt', 'DOM-D1-R1')]).toEqual(['领域审计', '领域审计', '领域审计', '领域审计']);
  });

  it('quotas follow 计划与画像 → 风险假设 → 初筛 → 领域审计 → 覆盖补齐 → 归并 → 深度探索 → 对抗复核', () => {
    expect(BUDGET_STAGES.map((k) => BUDGET_STAGE[k])).toEqual(['计划与画像', '风险假设', '初筛', '领域审计', '覆盖补齐', '归并', '深度探索', '对抗复核', '复验']);
    expect(Object.keys(BUDGET_STAGE)).toEqual([...BUDGET_STAGES]);
  });

  it('hunt steps are labelled by lineage', () => {
    expect(stepLabel('hunt', 'GAP-B2')).toBe('覆盖补审');
    expect(stepLabel('hunt', 'R3-direction')).toBe('深度探索');
    expect(stepLabel('hunt', 'HYP-R-B1')).toBe('风险假设验证');
    expect(stepLabel('hunt', null)).toBe('领域审计');
    expect(stepLabel('triage', null)).toBe('初筛');
  });

  it('every quota and every status-bar segment has an explanation', () => {
    expect(BUDGET_STAGES.filter((k) => !BUDGET_INFO[k])).toEqual([]);
    expect(EXECUTION_SEGMENTS.filter((k) => !SEGMENT_INFO[k])).toEqual([]);
  });
});
