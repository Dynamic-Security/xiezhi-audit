// Strategy comparison: control-variable enforcement, seeded bootstrap, McNemar and the
// "样本不足" rule — all deterministic.
import { describe, expect, it } from 'vitest';
import { compareScores, patchVariables, planExperiment, toOverride, MIN_LABELS } from '../src/experiment.js';
import { erfc, mcnemar, pairedBootstrap, percentile, prng } from '../src/stats.js';
import { renderExperiment } from '../src/report.js';
import type { Experiment } from '../src/schema.js';
import type { RunScore, ScoreResult } from '../src/score.js';
import { EvalError } from '../src/util.js';

const exp = (over: Partial<Experiment> = {}): Experiment => ({
  experiment: 'exp-ast', bench: { version: '0.1.0', partition: 'dev' }, baseline: { strategy_from: 'scene_default:full', overrides: {} },
  variants: [{ name: 'ast_off', patch: { 'tools.ast': false } }], repeats: 3, decision: { primary: 'f1', guard: ['precision'] }, ...over,
});
const ctx = { benchVersion: '0.1.0', defaultModel: 'gw/m1', cheapModel: null, pi: '0.87.1' };

function problems(e: Experiment): string[] {
  try {
    planExperiment(e, ctx);
    return [];
  } catch (err) {
    expect(err).toBeInstanceOf(EvalError);
    return (err as EvalError).details;
  }
}

describe('experiment control rules', () => {
  it('accepts one field per variant and builds nested overrides', () => {
    const plan = planExperiment(exp({ baseline: { strategy_from: 'scene_default:full', overrides: { 'stages.challenge': true } } }), ctx);
    expect(plan.arms.map((a) => [a.name, a.variable])).toEqual([['baseline', null], ['ast_off', 'tools.ast']]);
    expect(plan.arms[1]!.override).toEqual({ stages: { challenge: true }, tools: { ast: false } });
    expect(plan.filter.scene).toEqual(['full']);
  });

  it('rejects a variant that changes two fields, but treats the model combination as one', () => {
    expect(problems(exp({ variants: [{ name: 'two', patch: { tools: { ast: false, lsp: true } } }] })).join()).toContain('改动了 2 个字段');
    expect(patchVariables({ 'models.audit': { provider: 'gw', model: 'm2' }, 'models.challenge': { provider: 'gw', model: 'm3' } })).toEqual(['models']);
    expect(problems(exp({ variants: [{ name: 'combo', patch: { models: { audit: { provider: 'gw', model: 'm2' }, challenge: null } } }] }))).toEqual([]);
  });

  it('rejects unknown fields, too few repeats, a different manifest version and unpinned models', () => {
    const p = problems(exp({ variants: [{ name: 'x', patch: { 'tools.magic': true } }], repeats: 2, bench: { version: '9.9.9', partition: 'dev' }, pins: { models: { audit: 'gw/other' } } })).join('\n');
    expect(p).toContain('AuditStrategy 中没有字段 tools.magic');
    expect(p).toContain('repeats 至少为 3');
    expect(p).toContain('bench.version 9.9.9');
    expect(p).toContain('pins.models.audit = gw/other');
  });

  it('toOverride does not mutate the baseline', () => {
    const base = { tools: { ast: true } };
    expect(toOverride(base, { 'tools.lsp': true })).toEqual({ tools: { ast: true, lsp: true } });
    expect(base).toEqual({ tools: { ast: true } });
  });
});

describe('statistics', () => {
  it('seeded PRNG is reproducible', () => {
    const a = prng(42), b = prng(42);
    const xs = Array.from({ length: 5 }, () => a());
    expect(xs).toEqual(Array.from({ length: 5 }, () => b()));
    expect(xs.every((x) => x >= 0 && x < 1)).toBe(true);
    expect(percentile([1, 2, 3, 4], 0.5)).toBe(2.5);
  });

  it('paired bootstrap: identical inputs give identical intervals; a clear shift is significant', () => {
    const base = Array.from({ length: 30 }, (_, i) => ({ v: 0.4 + (i % 5) * 0.02 }));
    const better = base.map((u) => ({ v: u.v + 0.2 }));
    const mean = (us: { v: number }[]) => us.reduce((s, u) => s + u.v, 0) / us.length;
    const r1 = pairedBootstrap(base, better, mean, { resamples: 1000, seed: 7 })!;
    const r2 = pairedBootstrap(base, better, mean, { resamples: 1000, seed: 7 })!;
    expect(r1).toEqual(r2);
    expect(r1.diff).toBeCloseTo(0.2, 10);
    expect(r1.significant).toBe(true);
    expect(r1.low).toBeCloseTo(0.2, 6);
    const noisy = base.map((u, i) => ({ v: u.v + (i % 2 ? 0.05 : -0.05) }));
    const r3 = pairedBootstrap(base, noisy, mean, { resamples: 1000, seed: 7 })!;
    expect(r3.low).toBeLessThan(0);
    expect(r3.high).toBeGreaterThan(0);
    expect(r3.significant).toBe(false);
  });

  it('McNemar: exact binomial for few discordant pairs, χ² with continuity correction otherwise', () => {
    expect(mcnemar(0, 0)).toMatchObject({ method: 'none', p: null });
    expect(mcnemar(1, 5).method).toBe('exact');
    expect(mcnemar(1, 5).p).toBeCloseTo(0.21875, 10); // 2 × P(X ≤ 1 | n = 6)
    expect(mcnemar(0, 6).p).toBeCloseTo(0.03125, 10);
    const big = mcnemar(10, 30);
    expect(big.method).toBe('chi2_cc');
    expect(big.statistic).toBeCloseTo(9.025, 10);
    expect(big.p!).toBeCloseTo(0.002663, 5);
    expect(erfc(0)).toBeCloseTo(1, 6);
    expect(erfc(1)).toBeCloseTo(0.157299, 6);
  });
});

function fakeScore(hits: (sample: number) => number, fp: number, labels: number): ScoreResult {
  const runs: RunScore[] = [];
  for (let s = 0; s < labels; s++) {
    for (let r = 1; r <= 3; r++) {
      const hit = hits(s) >= r ? 1 : 0;
      runs.push({
        sample_id: `s${String(s).padStart(2, '0')}`, repeat: r, kind: 'vuln', language: 'java', dataset: 'self-built', project: 'p', status: 'completed', completed: true,
        labels: [{ label_id: `L${s}`, category: 'sqli', depth: 'cross_file', hit: !!hit, hit_status: hit ? 'confirmed' : null, finding_id: null, expected_verdict: 'confirmed', verdict_ok: !!hit, severity_ok: null, entries_hit: 0, entries_total: 0 }],
        findings: [], label_policy: 'complete', counts: { tp: hit, duplicate: 0, fp: s < fp ? 1 : 0, queue: 0, pending: 0, pending_hit: 0, pending_fp: 0, adj_tp: 0, adj_fp: 0, labels_total: 1, labels_hit: hit },
        category_aligned: { n: 0, correct: 0 }, localization: { n: 0, correct: 0 }, guard: null,
      });
    }
  }
  const tp = runs.reduce((n, r) => n + r.counts.tp, 0);
  const lab = runs.filter((r) => r.labels[0]!.hit).length;
  return {
    runs,
    quality: { counts: { tp }, by_category: { sqli: { labels, hit: lab / 3, recall: lab / (labels * 3), recall_mixed: lab / (labels * 3) } } },
    cost: { total: { known: { USD: tp * 0.01 }, unknown_calls: 0 } },
    stability: { mean_jaccard: 1 }, availability: { completion_rate: 1 },
  } as unknown as ScoreResult;
}

describe('comparison conclusions', () => {
  it('reports only the direction below the minimum label count', () => {
    const base = fakeScore(() => 1, 0, 10);
    const variant = fakeScore(() => 3, 0, 10);
    const c = compareScores(base, variant, exp());
    expect(c.labels).toBe(10);
    expect(c.primary.conclusion).toBe('样本不足');
    expect(c.primary.direction).toBe('提升');
    expect(c.recommendation).toContain('样本不足');
    expect(c.by_category.sqli!.conclusion).toBe('样本不足');
  });

  it('declares a significant improvement with enough labels, lists flips and marginal cost', () => {
    const base = fakeScore((s) => (s % 2 ? 3 : 0), 0, MIN_LABELS + 4);
    const variant = fakeScore(() => 3, 0, MIN_LABELS + 4);
    const c = compareScores(base, variant, exp());
    expect(c.primary.conclusion).toBe('显著提升');
    expect(c.primary.ci95![0]).toBeGreaterThan(0);
    expect(c.mcnemar).toMatchObject({ b: 0, c: 12, method: 'exact' });
    expect(c.mcnemar.flips.every((f) => f.change === 'gained')).toBe(true);
    expect(c.paired.losses).toEqual([]);
    expect(c.cost.marginal_usd_per_new_tp).toBeCloseTo(0.01, 6);
    // Same inputs → same bytes.
    const doc = { format: 'x', identity: { experiment: 'e', config_sha256: 'a'.repeat(64), code: { revision: 'r', dirty: false }, bench_version: '0.1.0', partition: 'dev', pi_version: '0', models: { default: 'gw/m1', cheap: null }, repeats: 3, bootstrap: { resamples: 2000, seed: 1 } },
      arms: [], comparisons: [{ variant: 'v', variable: 'tools.ast', ...c }], cost_limit: null, spent_usd: 0 };
    expect(renderExperiment(doc as never)).toBe(renderExperiment(JSON.parse(JSON.stringify(doc))));
  });

  it('counts per-category labels once each, like the overall count, not labels × repeats', () => {
    // 8 labels × 3 repeats: the scorer's by_category.labels counts 24 label outcomes, which used to pass the
    // 20-label rule per category while the overall count (8) did not.
    const base = fakeScore((s) => (s % 2 ? 3 : 0), 0, 8);
    const variant = fakeScore(() => 3, 0, 8);
    (base.quality.by_category as Record<string, { labels: number }>).sqli!.labels = 24;
    const c = compareScores(base, variant, exp());
    expect(c.labels).toBe(8);
    expect(c.by_category.sqli).toMatchObject({ labels: 8, conclusion: '样本不足' });
    // With enough distinct labels both agree.
    const big = compareScores(fakeScore((s) => (s % 2 ? 3 : 0), 0, MIN_LABELS), fakeScore(() => 3, 0, MIN_LABELS), exp());
    expect(big.labels).toBe(MIN_LABELS);
    expect(big.by_category.sqli).toMatchObject({ labels: MIN_LABELS, conclusion: '见总体检验' });
  });
});
