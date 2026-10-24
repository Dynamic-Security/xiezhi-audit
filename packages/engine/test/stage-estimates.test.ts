// The plan estimate is the sum of the stage estimates. The golden file was recorded with the
// estimate function of the stage catalog (UPDATE_STAGE_GOLDEN=1); every strategy / option combination must give the same
// numbers, and the per-stage view must add up to the entries it groups.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { sceneDefaults, sceneStages, type AuditStrategy } from '@xiezhi/contracts';
import { estimatePipeline } from '../src/estimates.js';

const GOLDEN = join(__dirname, 'stage-estimates.golden.json');
const UPDATE = process.env.UPDATE_STAGE_GOLDEN === '1';
const M = { provider: 'gw', model: 'm1' };
const M2 = { provider: 'gw', model: 'm2' };

function variants(): Record<string, [AuditStrategy, number, number, Parameters<typeof estimatePipeline>[5]]> {
  const full = sceneDefaults('full', { defaultModel: M });
  const inc = sceneDefaults('incremental', { defaultModel: M });
  const cross: AuditStrategy = { ...full, multiModel: { ...full.multiModel, enabled: true, models: [M, M2] } };
  const lean: AuditStrategy = { ...full, models: { ...full.models, triage: null, merge: null }, stages: { ...full.stages, adversarialReview: false }, tools: { ...full.tools, coverageCompare: false } };
  const hyp: AuditStrategy = { ...full, stages: { ...full.stages, threatHypotheses: true, tieredReview: false } };
  return {
    'full default': [full, 120, 30, {}],
    'full lead + gap + M18 stages': [full, 120, 30, { domainHunt: true, gapFill: true, checklist: true, recheck: true, external: 12 }],
    'full crossed lead': [cross, 300, 75, { domainHunt: true, gapFill: true, checklist: true, recheck: true }],
    'full lean': [lean, 40, 10, {}],
    'full hypotheses, untiered review': [hyp, 80, 20, { domainHunt: false }],
    'full hypotheses with lead': [hyp, 80, 20, { domainHunt: true }],
    'incremental lead': [inc, 9, 3, { domainHunt: true, incremental: true, recheck: true }],
    'incremental generalist': [inc, 9, 3, { incremental: true }],
  };
}

const ratio = (kind: string) => (kind === 'hunt' ? 1.7 : kind === 'challenge' ? 0.8 : 1);

describe('stage estimates', () => {
  it('give the same plan estimate as before, with and without calibration', () => {
    const got: Record<string, unknown> = {};
    for (const [name, [s, n, f, opts]] of Object.entries(variants())) {
      for (const [tag, r] of [['plain', undefined], ['calibrated', ratio]] as const) {
        const e = estimatePipeline(s, n, f, { input: 1, output: 4, currency: 'USD' }, r, opts);
        got[`${name} · ${tag}`] = { tokens: e.tokens, durationSec: e.durationSec, cost: e.cost, byStep: e.byStep };
      }
    }
    if (UPDATE || !existsSync(GOLDEN)) {
      writeFileSync(GOLDEN, `${JSON.stringify(got, null, 2)}\n`);
      return;
    }
    expect(got).toEqual(JSON.parse(readFileSync(GOLDEN, 'utf8')));
  });

  it('groups the entries per catalog stage, in catalog order, adding up to the same total', () => {
    for (const [name, [s, n, f, opts]] of Object.entries(variants())) {
      const e = estimatePipeline(s, n, f, undefined, ratio, opts);
      const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);
      expect(sum(Object.values(e.byStep)), name).toBeGreaterThan(0);
      // Shares of the median: they add up to p50 (rounded per stage).
      expect(Math.abs(sum(e.byStage!.map((x) => x.tokens)) - e.tokens.p50), name).toBeLessThanOrEqual(e.byStage!.length);
      const order = sceneStages(opts?.incremental ? 'incremental' : 'full').map((x) => x.id);
      const idx = e.byStage!.map((x) => order.indexOf(x.stage));
      expect(idx.every((v, i) => v >= 0 && (i === 0 || v > idx[i - 1]!)), name).toBe(true);
    }
    const full = estimatePipeline(sceneDefaults('full', { defaultModel: M }), 120, 30, undefined, undefined, { domainHunt: true, gapFill: true, checklist: true, recheck: true });
    expect(full.byStage!.map((x) => x.stage)).toEqual(['understand', 'triage', 'lead', 'checklist', 'recheck', 'gap', 'reconcile', 'review']);
  });

  it('estimates the deep exploration: on-demand directions and the full loop', () => {
    const s = sceneDefaults('full', { defaultModel: M });
    const off = estimatePipeline(s, 120, 30, undefined, undefined, { domainHunt: true });
    const onDemand = estimatePipeline(s, 120, 30, undefined, undefined, { domainHunt: true, explore: 'directions' });
    const full = estimatePipeline({ ...s, stages: { ...s.stages, deepExplore: true } }, 120, 30, undefined, undefined, { domainHunt: true, explore: 'full' });
    expect(off.byStage!.map((x) => x.stage)).not.toContain('explore');
    // Directions: at most 5, one single-candidate investigation each, no decide session.
    expect(onDemand.byStep).toMatchObject({ explore: 5 * 18_000 });
    expect(onDemand.byStep.decide).toBeUndefined();
    expect(full.byStep).toMatchObject({ decide: s.limits.maxRounds * 12_000, explore: s.limits.maxRounds * 18_000 });
    expect(onDemand.byStage!.find((x) => x.stage === 'explore')!.tokens).toBe(Math.round(5 * 18_000 * 1.15 * 0.7));
    expect(onDemand.tokens.p50).toBeGreaterThan(off.tokens.p50);
  });
});
