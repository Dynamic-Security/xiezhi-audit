// The optional stages are switched in the “审计流程与模型” table; each row says what its state does.
import { describe, expect, it } from 'vitest';
import { switchHint, type StageSwitchesProps } from '../src/features/audits/StageModels';

const sw = (value: Partial<StageSwitchesProps['value']>, extra: Partial<StageSwitchesProps> = {}): StageSwitchesProps => ({
  value: { logic: true, explore: false, challenge: true, ...value }, onChange: () => undefined, maxCandidates: 500, rounds: 30, ...extra,
});

describe('stage switch hints', () => {
  it('风险假设先行 and 对抗复核', () => {
    expect(switchHint('logic', sw({}))).toBe('开启：列出风险假设（最多 500 条）并逐条验证');
    expect(switchHint('logic', sw({ logic: false }))).toBe('关闭：威胁建模只划分风险领域');
    expect(switchHint('challenge', sw({ challenge: false }))).toBe('关闭：不复核正式发现');
  });

  it('深度探索: checked is the full mode, unchecked the on-demand runs', () => {
    expect(switchHint('explore', sw({ explore: true }))).toBe('完整：每轮选一个不确定的方向调查，最多 30 轮');
    expect(switchHint('explore', sw({}))).toBe('按需：追查领域专家留下的全部方向');
    expect(switchHint('explore', sw({}, { rounds: 0 }))).toMatch(/不能开启完整模式$/);
    expect(switchHint('explore', sw({}, { exploreBaseOn: true }))).toBe('本次不运行');
  });
});
