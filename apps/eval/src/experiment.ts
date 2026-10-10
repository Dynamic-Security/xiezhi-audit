// Strategy comparison experiments: one AuditStrategy field per variant (the model
// combination counts as one), same manifest / partition / snapshots / config, ≥ 3 repeats, fresh
// data-dirs; paired bootstrap 95% CI per sample, McNemar per label, "样本不足" below 20 labels.
import { join, resolve } from 'node:path';
import { AuditStrategy, canonicalJson, configStageModel, sceneDefaults, sceneStages, sha256Hex } from '@xiezhi/contracts';
import { piVersion, type ModelMode } from '@xiezhi/agent';
import { loadBench } from './bench.js';
import { runBench, loadEvalConfig, type SampleFilter } from './runner.js';
import { COUNT_KEYS, emptyCounts, qualityMetrics, scoreRunDir, type QualityCounts, type QualityMetrics, type RunScore, type ScoreResult } from './score.js';
import { Experiment, type Partition } from './schema.js';
import type { RemoteOptions } from './trees.js';
import { mcnemar, pairedBootstrap, type BootstrapResult, type McNemarResult } from './stats.js';
import { byString, EvalError, readYamlFile, round, validated, writeJson } from './util.js';
import { renderExperiment } from './report.js';
import { writeFileSync } from 'node:fs';

export const EXPERIMENT_FORMAT = 'xiezhi-eval-experiment/1';
/** Fewer labels than this → report the direction only. */
export const MIN_LABELS = 20;
export const MIN_REPEATS = 3;
const QUALITY_KEYS = ['precision', 'recall', 'f1', 'recall_mixed', 'f1_mixed'] as const;
type MetricKey = (typeof QUALITY_KEYS)[number];

export function loadExperiment(path: string): Experiment {
  try {
    return validated(Experiment, readYamlFile(path), 'experiment');
  } catch (e) {
    if (e instanceof EvalError) throw new EvalError('EXPERIMENT_INVALID', e.message, e.details);
    throw e;
  }
}

function isPlain(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Dotted leaf paths of a patch; everything under `models` is one composite variable. */
export function patchFields(patch: Record<string, unknown>): string[] {
  const out: string[] = [];
  const walk = (prefix: string, v: unknown) => {
    if (prefix === 'models' || prefix.startsWith('models.')) { out.push(prefix); return; }
    if (isPlain(v) && Object.keys(v).length) for (const [k, x] of Object.entries(v)) walk(prefix ? `${prefix}.${k}` : k, x);
    else out.push(prefix);
  };
  for (const [k, v] of Object.entries(patch)) walk(k, v);
  return out;
}

/** The variables a patch changes: leaf fields, with the model combination collapsed to `models`. */
export function patchVariables(patch: Record<string, unknown>): string[] {
  return [...new Set(patchFields(patch).map((f) => (f === 'models' || f.startsWith('models.') ? 'models' : f)))].sort(byString);
}

function schemaHas(path: string): boolean {
  let node: any = AuditStrategy;
  for (const seg of path.split('.')) {
    const props = node?.properties;
    if (!props || !(seg in props)) return false;
    node = props[seg];
  }
  return true;
}

function deepSet(target: Record<string, unknown>, path: string, value: unknown): void {
  const segs = path.split('.');
  let o = target;
  for (const s of segs.slice(0, -1)) {
    if (!isPlain(o[s])) o[s] = {};
    o = o[s] as Record<string, unknown>;
  }
  o[segs[segs.length - 1]!] = value;
}

function leafValues(patch: Record<string, unknown>): [string, unknown][] {
  const out: [string, unknown][] = [];
  const walk = (prefix: string, v: unknown) => {
    if (isPlain(v) && Object.keys(v).length && !(prefix === 'models' || prefix.startsWith('models.'))) for (const [k, x] of Object.entries(v)) walk(prefix ? `${prefix}.${k}` : k, x);
    else out.push([prefix, v]);
  };
  for (const [k, v] of Object.entries(patch)) walk(k, v);
  return out;
}

export function toOverride(base: Record<string, unknown>, patch: Record<string, unknown>): Record<string, unknown> {
  const out = JSON.parse(JSON.stringify(base)) as Record<string, unknown>;
  for (const [path, v] of leafValues(patch)) deepSet(out, path, v);
  return out;
}

/** Control rules; returns the arms to run. Throws on any violation. */
export function planExperiment(exp: Experiment, ctx: { benchVersion: string; defaultModel: string | null; cheapModel: string | null; pi: string }) {
  const problems: string[] = [];
  if (exp.bench.version !== ctx.benchVersion) problems.push(`bench.version ${exp.bench.version} 与 manifest ${ctx.benchVersion} 不一致`);
  if (exp.repeats < MIN_REPEATS) problems.push(`repeats 至少为 ${MIN_REPEATS}`);
  const names = new Set<string>(['baseline']);
  for (const v of exp.variants) {
    if (names.has(v.name)) problems.push(`变体名重复或与 baseline 冲突：${v.name}`);
    names.add(v.name);
    const vars = patchVariables(v.patch);
    if (vars.length !== 1) problems.push(`变体 ${v.name} 改动了 ${vars.length} 个字段（${vars.join(', ') || '无'}）；每个变体只允许改一个字段，模型组合整体算一个`);
    for (const f of patchFields(v.patch)) if (!schemaHas(f)) problems.push(`变体 ${v.name}：AuditStrategy 中没有字段 ${f}`);
  }
  for (const f of patchFields(exp.baseline.overrides)) if (!schemaHas(f)) problems.push(`baseline.overrides：AuditStrategy 中没有字段 ${f}`);
  const pinned = exp.pins?.models ?? {};
  for (const [stage, want] of Object.entries(pinned)) {
    const have = stage === 'audit' ? ctx.defaultModel : ctx.cheapModel;
    if (want !== have) problems.push(`pins.models.${stage} = ${want}，但配置中是 ${have ?? '（未配置）'}`);
  }
  if (exp.pins?.pi && !exp.pins.pi.startsWith('<') && exp.pins.pi !== ctx.pi) problems.push(`pins.pi = ${exp.pins.pi}，当前 pi 为 ${ctx.pi}`);
  const scene = exp.baseline.strategy_from.split(':')[1]!;
  const filter: SampleFilter = Object.fromEntries(Object.entries(exp.bench.filter ?? {}).map(([k, v]) => [k, Array.isArray(v) ? v : [v]]));
  if (filter.scene && !filter.scene.every((x) => x === scene)) problems.push(`filter.scene 与 strategy_from（${scene}）不一致`);
  filter.scene = [scene];
  if (problems.length) throw new EvalError('EXPERIMENT_INVALID', '实验配置不满足控制变量要求，拒绝运行', problems);
  return {
    filter,
    arms: [
      { name: 'baseline', override: toOverride({}, exp.baseline.overrides), variable: null as string | null },
      ...exp.variants.map((v) => ({ name: v.name, override: toOverride(toOverride({}, exp.baseline.overrides), v.patch), variable: patchVariables(v.patch)[0]! })),
    ],
  };
}

/**
 * An ablation experiment from the stage catalog — one variant per stage with a strategy switch, its
 * scene default flipped (a stage on by default is turned off, one off by default turned on; a stage that runs
 * on demand at the default counts as on). Run it with
 * `xiezhi eval experiment`; its comparison per variant is the stage's contribution.
 */
export function ablationExperiment(o: {
  benchVersion: string; scene: 'full' | 'incremental'; partition: Partition; stages?: string[]; repeats?: number;
  filter?: SampleFilter; name?: string;
}): Experiment {
  const defaults = sceneDefaults(o.scene, { defaultModel: { provider: 'placeholder', model: 'placeholder' } });
  const switchable = sceneStages(o.scene).filter((st) => st.switch);
  const unknown = (o.stages ?? []).filter((id) => !switchable.some((st) => st.id === id));
  if (unknown.length) throw new EvalError('USAGE', `这些阶段没有策略开关，不能做消融：${unknown.join(', ')}（可选：${switchable.map((st) => st.id).join(', ')}）`);
  const chosen = o.stages?.length ? switchable.filter((st) => o.stages!.includes(st.id)) : switchable;
  if (!chosen.length) throw new EvalError('USAGE', `${o.scene} 场景没有带策略开关的阶段`);
  const variants = chosen.map((st) => {
    // A stage that runs on demand at the default (deep exploration) is ablated by turning it off explicitly.
    const on = !!defaults.stages[st.switch!] || !!st.onDemand;
    return { name: `${on ? 'no' : 'with'}-${st.id}`, patch: { [`stages.${st.switch}`]: !on } };
  });
  const filter = Object.fromEntries(Object.entries(o.filter ?? {}).filter(([k]) => k !== 'scene'));
  return {
    experiment: o.name ?? `ablation-${o.scene}-${chosen.map((st) => st.id).join('-')}`,
    bench: { version: o.benchVersion, partition: o.partition, ...(Object.keys(filter).length ? { filter } : {}) },
    baseline: { strategy_from: `scene_default:${o.scene}`, overrides: {} },
    variants,
    repeats: o.repeats ?? MIN_REPEATS,
    decision: { primary: 'recall', guard: ['precision'] },
  };
}

// ---- comparison --------------------------------------------------------------------------------

/** Distinct labels (sample, label) of a category in the quality runs, however many repeats ran. */
export function distinctLabels(runs: RunScore[], category: string): number {
  const keys = new Set<string>();
  for (const r of runs) {
    if (!['vuln', 'fixed', 'negative'].includes(r.kind)) continue;
    for (const l of r.labels) if (l.category === category) keys.add(`${r.sample_id}\u0000${l.label_id}`);
  }
  return keys.size;
}

interface Unit { sample_id: string; counts: QualityCounts; labels: Map<string, number> }

/** Per-sample units averaged over repeats (the bootstrap resamples samples). */
export function sampleUnits(runs: RunScore[]): Map<string, Unit> {
  const out = new Map<string, Unit>();
  const quality = runs.filter((r) => ['vuln', 'fixed', 'negative'].includes(r.kind));
  for (const sid of [...new Set(quality.map((r) => r.sample_id))].sort(byString)) {
    const rs = quality.filter((r) => r.sample_id === sid);
    const c = emptyCounts();
    for (const r of rs) {
      c.labels_total_all += r.counts.labels_total / rs.length;
      if (!r.completed) continue;
      c.runs += 1 / rs.length;
      for (const k of COUNT_KEYS) c[k] += (r.counts[k] ?? 0) / rs.length;
    }
    const done = rs.filter((r) => r.completed);
    const labels = new Map<string, number>();
    for (const l of new Set(rs.flatMap((r) => r.labels.map((x) => x.label_id)))) {
      labels.set(l, done.length ? done.filter((r) => r.labels.some((x) => x.label_id === l && x.hit)).length / done.length : 0);
    }
    out.set(sid, { sample_id: sid, counts: c, labels });
  }
  return out;
}

function metricOf(units: Unit[], key: MetricKey): number | null {
  const c = emptyCounts();
  for (const u of units) for (const k of Object.keys(c) as (keyof QualityCounts)[]) c[k] += u.counts[k];
  return (qualityMetrics(c) as QualityMetrics)[key];
}

export type Conclusion = '显著提升' | '无显著差异' | '显著下降' | '样本不足';

function direction(diff: number | null): string {
  if (diff === null || Math.abs(diff) < 1e-12) return '持平';
  return diff > 0 ? '提升' : '下降';
}

function conclude(b: BootstrapResult | null, labels: number): { conclusion: Conclusion; direction: string } {
  if (!b) return { conclusion: '样本不足', direction: '无法计算' };
  if (labels < MIN_LABELS) return { conclusion: '样本不足', direction: direction(b.diff) };
  if (!b.significant) return { conclusion: '无显著差异', direction: direction(b.diff) };
  return { conclusion: b.diff > 0 ? '显著提升' : '显著下降', direction: direction(b.diff) };
}

export function compareScores(base: ScoreResult, variant: ScoreResult, exp: Experiment) {
  const boot = { resamples: exp.bootstrap?.resamples ?? 2000, seed: exp.bootstrap?.seed ?? 20260927 };
  const ub = sampleUnits(base.runs);
  const uv = sampleUnits(variant.runs);
  const shared = [...ub.keys()].filter((k) => uv.has(k)).sort(byString);
  const B = shared.map((k) => ub.get(k)!);
  const V = shared.map((k) => uv.get(k)!);
  const labelCount = B.reduce((n, u) => n + u.labels.size, 0);
  const metric = (key: MetricKey) => {
    const bs = pairedBootstrap(B, V, (us) => metricOf(us, key), boot);
    const bv = metricOf(B, key), vv = metricOf(V, key);
    return { baseline: bv, variant: vv, diff: bs ? round(bs.diff) : null, ci95: bs ? [round(bs.low), round(bs.high)] : null, ...conclude(bs, labelCount) };
  };
  const primary = metric(exp.decision.primary as MetricKey);
  const guards = Object.fromEntries(exp.decision.guard.map((g) => [g, metric(g as MetricKey)]));

  // Per-sample paired outcome: +hits −false positives −duplicates (means over repeats); adjudicated findings
  // of known_only samples count as hits / false positives.
  const paired = shared.map((sid, i) => {
    const b = B[i]!.counts, v = V[i]!.counts;
    const delta = round((v.labels_hit + v.adj_tp - b.labels_hit - b.adj_tp) - (v.fp + v.adj_fp - b.fp - b.adj_fp) - (v.duplicate - b.duplicate));
    return { sample_id: sid, delta, result: delta > 0 ? 'win' : delta < 0 ? 'loss' : 'tie' };
  });
  // McNemar on labels detected in at least half of the completed repeats.
  let bOnly = 0, vOnly = 0;
  const flips: { sample_id: string; label_id: string; change: 'lost' | 'gained' }[] = [];
  shared.forEach((sid, i) => {
    for (const [l, rate] of B[i]!.labels) {
      const bd = rate >= 0.5, vd = (V[i]!.labels.get(l) ?? 0) >= 0.5;
      if (bd && !vd) { bOnly++; flips.push({ sample_id: sid, label_id: l, change: 'lost' }); }
      if (!bd && vd) { vOnly++; flips.push({ sample_id: sid, label_id: l, change: 'gained' }); }
    }
  });
  const mc: McNemarResult = mcnemar(bOnly, vOnly);

  // Per-category recall direction (significance only with ≥ MIN_LABELS labels in the category). Labels are
  // counted like the overall count above: once each, over the shared samples, not once per repeat.
  type CatQ = { recall: number | null };
  const sharedSet = new Set(shared);
  const sharedRuns = base.runs.filter((r) => sharedSet.has(r.sample_id));
  const cats = new Set([...Object.keys(base.quality.by_category), ...Object.keys(variant.quality.by_category)]);
  const byCategory = Object.fromEntries([...cats].sort(byString).map((c) => {
    const bq = (base.quality.by_category as Record<string, CatQ>)[c];
    const vq = (variant.quality.by_category as Record<string, CatQ>)[c];
    const diff = bq?.recall != null && vq?.recall != null ? round(vq.recall - bq.recall) : null;
    const labels = distinctLabels(sharedRuns, c);
    return [c, { labels, baseline: bq?.recall ?? null, variant: vq?.recall ?? null, diff, conclusion: labels < MIN_LABELS ? '样本不足' : '见总体检验', direction: direction(diff) }];
  }));

  const usd = (s: ScoreResult) => s.cost.total.known.USD ?? null;
  const costDiff = usd(base) !== null && usd(variant) !== null ? round(usd(variant)! - usd(base)!, 6) : null;
  const tpDiff = round(variant.quality.counts.tp - base.quality.counts.tp);
  const unknownPrices = base.cost.total.unknown_calls + variant.cost.total.unknown_calls > 0;

  // Recommendation.
  const guardDown = Object.values(guards).some((g) => g.conclusion === '显著下降');
  let recommendation: string;
  if (primary.conclusion === '样本不足') recommendation = `样本不足（${labelCount} 条标注 < ${MIN_LABELS}），只报告方向：主指标${primary.direction}，不下结论`;
  else if (primary.conclusion === '显著提升' && !guardDown) recommendation = '主指标显著提升且守护指标未显著下降：可设为该场景默认开启（需确认边际成本可接受）';
  else if (primary.conclusion === '显著提升') recommendation = '主指标显著提升但守护指标显著下降：保持可选，不设为默认';
  else if (primary.conclusion === '显著下降') recommendation = '显著下降：默认关闭；若是 skill 或规则，建议调整或下线';
  else recommendation = '无显著差异：默认关闭（简单的事不复杂化），节省成本';

  return {
    samples: shared.length, labels: labelCount,
    primary: { metric: exp.decision.primary, ...primary }, guards,
    paired: { wins: paired.filter((p) => p.result === 'win').map((p) => p.sample_id), losses: paired.filter((p) => p.result === 'loss'), ties: paired.filter((p) => p.result === 'tie').map((p) => p.sample_id) },
    mcnemar: { ...mc, p: mc.p === null ? null : round(mc.p, 6), statistic: mc.statistic === null ? null : round(mc.statistic, 6), flips },
    by_category: byCategory,
    cost: {
      baseline_usd: usd(base), variant_usd: usd(variant), diff_usd: costDiff, unknown_prices: unknownPrices, tp_diff: tpDiff,
      marginal_usd_per_new_tp: costDiff !== null && tpDiff > 0 ? round(costDiff / tpDiff, 6) : null,
    },
    stability: { baseline_jaccard: base.stability.mean_jaccard, variant_jaccard: variant.stability.mean_jaccard },
    availability: { baseline_completion: base.availability.completion_rate, variant_completion: variant.availability.completion_rate },
    recommendation,
  };
}

export interface ExperimentOptions {
  experimentPath: string;
  benchRoot: string;
  configPath: string;
  out: string;
  knowledgeDir?: string;
  allowHoldout?: boolean;
  mode?: ModelMode;
  skipPreflight?: boolean;
  runner?: { retryBackoffMs?: number; rateLimitBackoffMs?: number };
  log?: (line: string) => void;
  /** Result cache shared by all arms (and experiments): an unchanged baseline arm is reused. */
  cacheDir?: string;
  trees?: RemoteOptions;
  codeId?: string;
}

export async function runExperiment(opts: ExperimentOptions) {
  const exp = loadExperiment(opts.experimentPath);
  const bench = loadBench(opts.benchRoot);
  const cfg = loadEvalConfig(opts.configPath);
  const ref = (m?: { provider: string; model: string }) => (m ? `${m.provider}/${m.model}` : null);
  const plan = planExperiment(exp, { benchVersion: bench.manifest.bench_version, defaultModel: ref(cfg.defaultModel), cheapModel: ref(configStageModel(cfg, 'triage') ?? undefined), pi: piVersion() });
  const out = resolve(opts.out);
  const tracker = { usd: 0 };
  const scores = new Map<string, ScoreResult>();
  for (const arm of plan.arms) {
    opts.log?.(`== ${arm.name}${arm.variable ? `（${arm.variable}）` : ''} ==`);
    const dir = join(out, arm.name);
    await runBench({
      bench, configPath: opts.configPath, out: dir, partition: exp.bench.partition as Partition, filter: plan.filter, repeats: exp.repeats,
      strategyOverride: arm.override, name: arm.name, costTracker: tracker,
      ...(exp.limits?.max_parallel ? { maxParallel: exp.limits.max_parallel } : {}), ...(exp.limits?.max_cost_usd !== undefined ? { maxCostUsd: exp.limits.max_cost_usd } : {}),
      ...(opts.knowledgeDir ? { knowledgeDir: opts.knowledgeDir } : {}), ...(opts.allowHoldout ? { allowHoldout: true } : {}),
      ...(opts.mode ? { mode: opts.mode } : {}), ...(opts.skipPreflight ? { skipPreflight: true } : {}), ...(opts.runner ? { runner: opts.runner } : {}), ...(opts.log ? { log: opts.log } : {}),
      ...(opts.cacheDir ? { cacheDir: opts.cacheDir } : {}), ...(opts.trees ? { trees: opts.trees } : {}), ...(opts.codeId ? { codeId: opts.codeId } : {}),
    });
    const score = await scoreRunDir(dir, bench.root, opts.trees ? { trees: opts.trees } : {});
    writeJson(join(dir, 'score.json'), score);
    scores.set(arm.name, score);
  }
  const base = scores.get('baseline')!;
  const result = {
    format: EXPERIMENT_FORMAT,
    identity: {
      experiment: exp.experiment, config_sha256: sha256Hex(canonicalJson(exp)), code: base.run.code, bench_version: bench.manifest.bench_version,
      partition: exp.bench.partition, pi_version: base.run.pi_version, models: base.run.models, repeats: exp.repeats,
      bootstrap: { resamples: exp.bootstrap?.resamples ?? 2000, seed: exp.bootstrap?.seed ?? 20260927 },
    },
    arms: plan.arms.map((a) => ({
      name: a.name, variable: a.variable, override: a.override,
      // Precision may be withheld (null) for low adjudication coverage; the bounds go with it.
      metrics: Object.fromEntries([...QUALITY_KEYS, 'precision_low', 'precision_high', 'adjudication_coverage'].map((k) => [k, (scores.get(a.name)!.quality as Record<string, unknown>)[k] ?? null])) as Record<string, number | null>,
      completion_rate: scores.get(a.name)!.availability.completion_rate, cost_usd: scores.get(a.name)!.cost.total.known.USD ?? null, unknown_price_calls: scores.get(a.name)!.cost.total.unknown_calls,
      skipped: scores.get(a.name)!.skipped, stopped_reason: scores.get(a.name)!.stopped_reason,
    })),
    comparisons: plan.arms.filter((a) => a.name !== 'baseline').map((a) => ({ variant: a.name, variable: a.variable, ...compareScores(base, scores.get(a.name)!, exp) })),
    cost_limit: exp.limits?.max_cost_usd ?? null, spent_usd: round(tracker.usd, 6),
  };
  writeJson(join(out, 'experiment.json'), result);
  writeFileSync(join(out, 'experiment.md'), renderExperiment(result));
  return result;
}

export type ExperimentResult = Awaited<ReturnType<typeof runExperiment>>;
