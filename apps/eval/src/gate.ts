// Regression gate: before a change to prompts, pipeline or defaults moves on, a
// candidate run is compared with a baseline run of the same samples (each ≥ 3 completed repeats). The verdict is
// “不降” (no regression), “下降” (regression) or “样本不足” (not enough evidence), with recall and precision from the
// paired bootstrap of the experiment framework, per-sample strict hits (median and range), cost, time and the stage
// telemetry (input tokens, peak context, compactions) side by side.
import type { Experiment } from './schema.js';
import { compareScores, MIN_LABELS, MIN_REPEATS } from './experiment.js';
import type { ScoreResult } from './score.js';
import { byString, round } from './util.js';

export const GATE_FORMAT = 'xiezhi-eval-gate/1';
/** Fewer shared samples than this: the paired bootstrap is not used for the verdict (see gateScores). */
export const MIN_BOOTSTRAP_SAMPLES = 5;
export type GateVerdict = '不降' | '下降' | '样本不足';

export interface GateSample {
  sample_id: string;
  baseline: { runs: number; median: number | null; min: number | null; max: number | null };
  candidate: { runs: number; median: number | null; min: number | null; max: number | null };
  labels: number;
  /** The candidate's median strict hits fall below the baseline's minimum: outside the baseline's own spread. */
  below_baseline_range: boolean;
}

export interface GateSide { usd: number | null; unknown_price_calls: number; /** Mean wall time per run (all runs). */ wall_minutes_per_run: number | null; tokens_in: number; peak_context_max: number | null; compactions: number }

export interface GateResult {
  format: typeof GATE_FORMAT;
  verdict: GateVerdict;
  reasons: string[];
  baseline: { name: string | null; code: string | null };
  candidate: { name: string | null; code: string | null };
  min_repeats: number;
  samples: GateSample[];
  recall: { baseline: number | null; candidate: number | null; diff: number | null; ci95: number[] | null; conclusion: string };
  precision: { baseline: number | null; candidate: number | null; diff: number | null; ci95: number[] | null; conclusion: string };
  labels: number;
  cost: { baseline: GateSide; candidate: GateSide };
}

function side(s: ScoreResult): GateSide {
  const stages = Object.values(s.stages?.by_stage ?? {});
  const peaks = stages.map((x) => x.peak_context_max).filter((x): x is number => x !== null);
  return {
    usd: s.cost.total.known.USD ?? null,
    unknown_price_calls: s.cost.total.unknown_calls,
    wall_minutes_per_run: s.runs.length ? round(s.cost.total.wall_ms / s.runs.length / 60000, 1) : null,
    tokens_in: s.cost.total.tokens_in,
    peak_context_max: peaks.length ? Math.max(...peaks) : null,
    compactions: stages.reduce((n, x) => n + x.compactions, 0),
  };
}

export function gateScores(base: ScoreResult, cand: ScoreResult, opts: { minRepeats?: number } = {}): GateResult {
  const minRepeats = opts.minRepeats ?? MIN_REPEATS;
  const bh = base.quality.by_sample_hits ?? {};
  const ch = cand.quality.by_sample_hits ?? {};
  const ids = [...new Set([...Object.keys(bh), ...Object.keys(ch)])].sort(byString);
  const reasons: string[] = [];
  const samples: GateSample[] = ids.map((id) => {
    const b = bh[id], c = ch[id];
    const below = !!b && !!c && c.strict.median !== null && b.strict.min !== null && c.strict.median < b.strict.min;
    return {
      sample_id: id, labels: (b ?? c)!.labels,
      baseline: { runs: b?.runs ?? 0, median: b?.strict.median ?? null, min: b?.strict.min ?? null, max: b?.strict.max ?? null },
      candidate: { runs: c?.runs ?? 0, median: c?.strict.median ?? null, min: c?.strict.min ?? null, max: c?.strict.max ?? null },
      below_baseline_range: below,
    };
  });
  for (const s of samples) {
    if (s.baseline.runs < minRepeats || s.candidate.runs < minRepeats) reasons.push(`${s.sample_id}：完成的运行不足 ${minRepeats} 次（基线 ${s.baseline.runs}，候选 ${s.candidate.runs}）`);
  }
  // The experiment framework's paired comparison, recall as the primary metric and precision as the guard.
  const exp = { decision: { primary: 'recall', guard: ['precision'] } } as unknown as Experiment;
  const cmp = compareScores(base, cand, exp);
  const pick = (m: { baseline: number | null; variant: number | null; diff: number | null; ci95: number[] | null; conclusion: string }) => ({ baseline: m.baseline, candidate: m.variant, diff: m.diff, ci95: m.ci95, conclusion: m.conclusion });
  const recall = pick(cmp.primary);
  const precision = pick(cmp.guards.precision!);
  if (!samples.length || !cmp.samples) reasons.push('两组运行没有共同的已完成样本');
  if (cmp.labels < MIN_LABELS) reasons.push(`共同样本的标注 ${cmp.labels} 条，少于 ${MIN_LABELS} 条`);
  const insufficient = reasons.length > 0;
  const down: string[] = [];
  // The bootstrap resamples samples: with one or a few samples every resample is (almost) the same set, so any small
  // difference looks significant. Below MIN_BOOTSTRAP_SAMPLES only the per-sample range rule decides.
  const bootstrapUsable = cmp.samples >= MIN_BOOTSTRAP_SAMPLES;
  if (!bootstrapUsable) recall.conclusion = `只看方向（共同样本 ${cmp.samples} 个，少于 ${MIN_BOOTSTRAP_SAMPLES} 个）`;
  if (!bootstrapUsable) precision.conclusion = `只看方向（共同样本 ${cmp.samples} 个，少于 ${MIN_BOOTSTRAP_SAMPLES} 个）`;
  if (bootstrapUsable && recall.conclusion === '显著下降') down.push(`Recall 显著下降（${recall.baseline} → ${recall.candidate}，95% CI ${JSON.stringify(recall.ci95)}）`);
  for (const s of samples.filter((x) => x.below_baseline_range)) down.push(`${s.sample_id}：候选命中中位数 ${s.candidate.median} 低于基线最小值 ${s.baseline.min}`);
  const verdict: GateVerdict = down.length ? '下降' : insufficient ? '样本不足' : '不降';
  return {
    format: 'xiezhi-eval-gate/1', verdict, reasons: [...down, ...reasons],
    baseline: { name: base.run.name, code: base.run.code.revision }, candidate: { name: cand.run.name, code: cand.run.code.revision },
    min_repeats: minRepeats, samples, recall, precision, labels: cmp.labels,
    cost: { baseline: side(base), candidate: side(cand) },
  };
}

export function renderGate(g: GateResult): string {
  const pct = (x: number | null) => (x === null ? '-' : `${(x * 100).toFixed(1)}%`);
  const spread = (x: GateSample['baseline']) => (x.runs ? `${x.median}（${x.min}–${x.max}，${x.runs} 次）` : '-');
  const n = (x: number | null) => (x === null ? '-' : String(x));
  const lines = [
    `# 回归门禁：${g.verdict}`, '',
    `基线 ${g.baseline.name ?? '-'}（${g.baseline.code ?? '未知'}） → 候选 ${g.candidate.name ?? '-'}（${g.candidate.code ?? '未知'}）；每个样本至少 ${g.min_repeats} 次完成的运行；共同样本标注 ${g.labels} 条。`, '',
    ...(g.reasons.length ? ['原因：', '', ...g.reasons.map((r) => `- ${r}`), ''] : []),
    '| 指标 | 基线 | 候选 | 差值 | 95% CI | 结论 |', '| --- | --- | --- | --- | --- | --- |',
    `| Recall | ${pct(g.recall.baseline)} | ${pct(g.recall.candidate)} | ${n(g.recall.diff)} | ${g.recall.ci95 ? g.recall.ci95.join(' ~ ') : '-'} | ${g.recall.conclusion} |`,
    `| Precision | ${pct(g.precision.baseline)} | ${pct(g.precision.candidate)} | ${n(g.precision.diff)} | ${g.precision.ci95 ? g.precision.ci95.join(' ~ ') : '-'} | ${g.precision.conclusion} |`,
    '', '各样本严格命中（中位数，最小–最大）：', '',
    '| 样本 | 标注 | 基线 | 候选 | 低于基线范围 |', '| --- | --- | --- | --- | --- |',
    ...g.samples.map((s) => `| ${s.sample_id} | ${s.labels} | ${spread(s.baseline)} | ${spread(s.candidate)} | ${s.below_baseline_range ? '是' : '否'} |`),
    '', '| 成本与上下文 | 基线 | 候选 |', '| --- | --- | --- |',
    `| 费用 USD（无单价调用） | ${n(g.cost.baseline.usd)}（${g.cost.baseline.unknown_price_calls}） | ${n(g.cost.candidate.usd)}（${g.cost.candidate.unknown_price_calls}） |`,
    `| 每次运行墙钟（分） | ${n(g.cost.baseline.wall_minutes_per_run)} | ${n(g.cost.candidate.wall_minutes_per_run)} |`,
    `| 输入 tokens | ${g.cost.baseline.tokens_in} | ${g.cost.candidate.tokens_in} |`,
    `| 最大峰值上下文 | ${n(g.cost.baseline.peak_context_max)} | ${n(g.cost.candidate.peak_context_max)} |`,
    `| 自动压缩次数 | ${g.cost.baseline.compactions} | ${g.cost.candidate.compactions} |`, '',
  ];
  return lines.join('\n');
}
