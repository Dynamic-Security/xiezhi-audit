// Estimate calibration from this data directory's history: the cold-start constants in
// estimates.ts run 1.5–6× low. Each estimate is the constant × the median ratio of actual usage to the uncalibrated
// estimate (`estimate_base`) over the latest finished steps of the same kind and model — of the same kind when the model
// has too few, the constant alone when the kind has too few. Usage counts what the budget counts: input, output and
// cache reads.
import type { ModelRef, StepKind } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';

/** Latest steps per group; fewer than MIN_SAMPLES falls back to the coarser group. */
export const CALIBRATION_SAMPLES = 20;
export const CALIBRATION_MIN_SAMPLES = 3;
/** A ratio outside this range is clamped (one runaway or empty step must not skew every estimate). */
export const CALIBRATION_RANGE: readonly [number, number] = [0.5, 8];
const TTL_MS = 60_000;

type Ratios = { byModel: Map<string, number>; byKind: Map<string, number> };
const cache = new WeakMap<Store, { at: number; ratios: Ratios }>();

const median = (xs: number[]): number => {
  const v = [...xs].sort((a, b) => a - b);
  const m = v.length >> 1;
  return v.length % 2 ? v[m]! : (v[m - 1]! + v[m]!) / 2;
};
const clamp = (r: number) => Math.min(CALIBRATION_RANGE[1], Math.max(CALIBRATION_RANGE[0], r));

function load(store: Store): Ratios {
  const rows = store.all<{ kind: string; provider: string | null; model: string | null; used: number; base: number }>(
    `SELECT kind, provider, model, tokens_in + tokens_out + tokens_cached AS used, estimate_base AS base FROM step
     WHERE status = 'succeeded' AND estimate_base > 0 AND reused_from IS NULL AND tokens_in + tokens_out > 0
     ORDER BY ended_at DESC LIMIT 5000`);
  const groups = { byModel: new Map<string, number[]>(), byKind: new Map<string, number[]>() };
  for (const r of rows) {
    const ratio = r.used / r.base;
    const add = (m: Map<string, number[]>, k: string) => {
      const list = m.get(k) ?? [];
      if (list.length < CALIBRATION_SAMPLES) list.push(ratio);
      m.set(k, list);
    };
    add(groups.byKind, r.kind);
    if (r.provider && r.model) add(groups.byModel, `${r.kind}|${r.provider}/${r.model}`);
  }
  const reduce = (m: Map<string, number[]>) => new Map([...m].filter(([, v]) => v.length >= CALIBRATION_MIN_SAMPLES).map(([k, v]) => [k, clamp(median(v))]));
  return { byModel: reduce(groups.byModel), byKind: reduce(groups.byKind) };
}

function ratios(store: Store): Ratios {
  const hit = cache.get(store);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.ratios;
  const r = load(store);
  cache.set(store, { at: Date.now(), ratios: r });
  return r;
}

/** Calibration factor for a step kind (and model): 1 without enough history. */
export function calibrationRatio(store: Store, kind: StepKind | string, model?: ModelRef | null): number {
  const r = ratios(store);
  return (model && r.byModel.get(`${kind}|${model.provider}/${model.model}`)) ?? r.byKind.get(kind) ?? 1;
}

/** A calibrated estimate from an uncalibrated one. */
export function calibrated(store: Store, base: number, kind: StepKind | string, model?: ModelRef | null): number {
  return base > 0 ? Math.ceil(base * calibrationRatio(store, kind, model)) : 0;
}

/** Forget cached ratios (tests, or after a run that should count at once). */
export function resetCalibration(store: Store): void {
  cache.delete(store);
}
