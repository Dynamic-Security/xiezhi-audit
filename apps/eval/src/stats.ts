// Statistics for strategy comparisons: seeded PRNG, paired bootstrap over samples,
// McNemar on per-label detection. Everything is deterministic for a given seed.

/** mulberry32: small, fast, good enough for resampling; deterministic across platforms. */
export function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Percentile with linear interpolation (p in [0, 1]) of a sorted array. */
export function percentile(sorted: number[], p: number): number {
  if (!sorted.length) return NaN;
  const idx = (sorted.length - 1) * p;
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  return sorted[lo]! + (sorted[hi]! - sorted[lo]!) * (idx - lo);
}

export interface BootstrapResult { diff: number; low: number; high: number; resamples: number; significant: boolean }

/**
 * Paired bootstrap: resample sample indices with replacement; the statistic is computed on the
 * resampled baseline and variant units (same indices) and the difference variant − baseline kept.
 * `stat` receives the per-sample units (each already averaged over repeats).
 */
export function pairedBootstrap<U>(base: U[], variant: U[], stat: (units: U[]) => number | null, opts: { resamples: number; seed: number }): BootstrapResult | null {
  if (base.length !== variant.length) throw new Error('paired bootstrap needs the same samples on both sides');
  const n = base.length;
  const b0 = stat(base);
  const v0 = stat(variant);
  if (n === 0 || b0 === null || v0 === null) return null;
  const rnd = prng(opts.seed);
  const diffs: number[] = [];
  for (let k = 0; k < opts.resamples; k++) {
    const bs: U[] = [];
    const vs: U[] = [];
    for (let i = 0; i < n; i++) {
      const j = Math.floor(rnd() * n);
      bs.push(base[j]!);
      vs.push(variant[j]!);
    }
    const b = stat(bs);
    const v = stat(vs);
    if (b !== null && v !== null) diffs.push(v - b);
  }
  diffs.sort((a, b) => a - b);
  const low = percentile(diffs, 0.025);
  const high = percentile(diffs, 0.975);
  return { diff: v0 - b0, low, high, resamples: diffs.length, significant: diffs.length > 0 && (low > 0 || high < 0) };
}

/** log(n choose k) via log-gamma-free summation (n is small here). */
function logChoose(n: number, k: number): number {
  let s = 0;
  for (let i = 1; i <= k; i++) s += Math.log(n - k + i) - Math.log(i);
  return s;
}

/** Complementary error function (Numerical Recipes erfcc, |ε| < 1.2e-7). */
export function erfc(x: number): number {
  const z = Math.abs(x);
  const t = 1 / (1 + 0.5 * z);
  const r = t * Math.exp(-z * z - 1.26551223 + t * (1.00002368 + t * (0.37409196 + t * (0.09678418 + t * (-0.18628806
    + t * (0.27886807 + t * (-1.13520398 + t * (1.48851587 + t * (-0.82215223 + t * 0.17087277)))))))));
  return x >= 0 ? r : 2 - r;
}

export interface McNemarResult { b: number; c: number; method: 'exact' | 'chi2_cc' | 'none'; statistic: number | null; p: number | null }

/**
 * McNemar on discordant pairs: b = detected by baseline only, c = detected by the variant only.
 * Exact two-sided binomial when b + c ≤ 25, otherwise χ² with continuity correction (1 df).
 */
export function mcnemar(b: number, c: number): McNemarResult {
  const n = b + c;
  if (n === 0) return { b, c, method: 'none', statistic: null, p: null };
  if (n <= 25) {
    const k = Math.min(b, c);
    let tail = 0;
    for (let i = 0; i <= k; i++) tail += Math.exp(logChoose(n, i) - n * Math.LN2);
    return { b, c, method: 'exact', statistic: k, p: Math.min(1, 2 * tail) };
  }
  const x2 = (Math.abs(b - c) - 1) ** 2 / n;
  return { b, c, method: 'chi2_cc', statistic: x2, p: erfc(Math.sqrt(x2 / 2)) };
}
