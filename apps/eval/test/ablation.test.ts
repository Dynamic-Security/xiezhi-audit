// `xiezhi eval ablation` writes an experiment with one variant per catalog stage that has a strategy
// switch, its scene default flipped; the experiment passes the control rules of `experiment` (one field per variant).
import { describe, expect, it } from 'vitest';
import { ablationExperiment, planExperiment } from '../src/experiment.js';
import { Experiment } from '../src/schema.js';
import { validated } from '../src/util.js';

const ctx = { benchVersion: '0.9.0', defaultModel: null, cheapModel: null, pi: '0.87.1' };

describe('ablation experiment', () => {
  it('full: turns the deep exploration and the adversarial review off, one field each (exploration runs on demand)', () => {
    const exp = ablationExperiment({ benchVersion: '0.9.0', scene: 'full', partition: 'dev', filter: { sample: ['photoview-vuln'], scene: ['full'] } });
    expect(exp.variants).toEqual([
      { name: 'no-explore', patch: { 'stages.deepExplore': false } },
      { name: 'no-review', patch: { 'stages.adversarialReview': false } },
    ]);
    expect(exp.repeats).toBe(3);
    expect(exp.bench.filter).toEqual({ sample: ['photoview-vuln'] });
    validated(Experiment, exp, 'experiment');
    const plan = planExperiment(exp, ctx);
    expect(plan.arms.map((a) => [a.name, a.variable])).toEqual([['baseline', null], ['no-explore', 'stages.deepExplore'], ['no-review', 'stages.adversarialReview']]);
    expect(plan.arms[2]!.override).toEqual({ stages: { adversarialReview: false } });
  });

  it('a chosen subset; a stage without a switch is refused', () => {
    expect(ablationExperiment({ benchVersion: '0.9.0', scene: 'incremental', partition: 'dev', stages: ['review'], repeats: 5 }).variants.map((v) => v.name)).toEqual(['with-review']); // incremental: review off by default
    expect(() => ablationExperiment({ benchVersion: '0.9.0', scene: 'full', partition: 'dev', stages: ['checklist'] })).toThrow(/checklist/);
  });
});
