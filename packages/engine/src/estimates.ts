// Deterministic cost estimates. Baselines are cold-start constants; estimates are
// calibrated from this data directory's history (calibration.ts) — `ratio` below.
import { auditBudget, crossModels, sceneStages, stageModel, type AuditStrategy, type BudgetStage, type CrossStage, type ModelRef, type Pricing, type StageId, type StepKind } from '@xiezhi/contracts';

/** Calibration factor of a step kind for a model (1 = the constant as it is). */
export type EstimateRatio = (kind: StepKind, model: ModelRef | null) => number;
const ONE: EstimateRatio = () => 1;

export const BASELINE_TOKENS: Partial<Record<StepKind, number>> = {
  plan: 30_000,
  profile: 25_000,
  'threat-model': 40_000,
  'verify-fix': 40_000,
  triage: 15_000,
  hunt: 18_000, // per candidate
  challenge: 20_000,
  review: 20_000,
  decide: 12_000,
  reconcile: 8_000,
};

export const RETRY_MARGIN = 1.15;

export function estimateStep(kind: StepKind, size = 1): number {
  const base = BASELINE_TOKENS[kind] ?? 0;
  return Math.ceil(base * (kind === 'hunt' || kind === 'triage' ? Math.max(1, size) : 1));
}

export interface PlanEstimate {
  tokens: { p50: number; p90: number };
  durationSec: { p50: number; p90: number };
  cost: { p50: number; p90: number; currency: string } | null;
  byStep: Record<string, number>;
  /** each catalog stage's share of the median `tokens.p50` (absent in plans of other scenes and of older audits). */
  byStage?: { stage: StageId; tokens: number }[];
}

/** Domains assumed before the threat model has planned them, and the expert planning estimate. */
export const PLANNED_DOMAINS = 6;
export const DOMAIN_EXPERT_TOKENS = 600_000;
/** share of the findings expected to be critical / high and not pending, and a light review's cost. */
const FULL_REVIEW_SHARE = 0.4;
const LIGHT_REVIEW_COST = 0.4;
/** Share of the candidates ⑨ is expected to complete after the experts (they concluded about half in test runs). */
const GAP_SHARE = 0.5;
/** one lead session per hunt model (dispatch only, context below LEAD_CONTEXT_CAP; summed input over its turns). */
const LEAD_SESSION_TOKENS = 150_000;

/** Smallest planning estimate of one expert of an incremental audit (the engine's floor of a domain's share). */
const MIN_INCREMENTAL_EXPERT = 50_000;

/**
 * the stages after the exploration, missing from the estimate before. Cold-start constants from the
 * Measured runs (step counts; tokens are calibrated like every `coverage-gap` step): the checklist check ran 6 batches of
 * one class each plus at most one fill batch; the recheck samples SAMPLE_SHARE of the units (recheck.ts), batches of
 * RECHECK_BATCH; the external triage batches TRIAGE_BATCH results and fills about half of them in FILL_BATCH.
 */
const CHECKLIST_BATCHES = 6;
const CHECKLIST_UNITS_PER_BATCH = 4; // CHECK_BATCH (8) items, estimated as half a candidate each like the step itself
const CHECKLIST_FILL_UNITS = 4;
const RECHECK_SHARE = 0.15;
const RECHECK_MAX = 20;
const RECHECK_BATCH = 5;
const EXTERNAL_TRIAGE_BATCH = 10;
const EXTERNAL_FILL_BATCH = 4;
const EXTERNAL_FILL_SHARE = 0.5;

/** Tokens of the checklist check, the conclusion recheck and the external triage (exported for the stage estimates). */
export function postExplorationEstimates(candidates: number, opts: { checklist?: boolean; recheck?: boolean; external?: number }): { checklist?: number; recheck?: number; external?: number } {
  const out: { checklist?: number; recheck?: number; external?: number } = {};
  if (opts.checklist) out.checklist = CHECKLIST_BATCHES * estimateStep('hunt', CHECKLIST_UNITS_PER_BATCH) + estimateStep('hunt', CHECKLIST_FILL_UNITS);
  if (opts.recheck) {
    const units = Math.min(RECHECK_MAX, Math.max(1, Math.round(candidates * RECHECK_SHARE)));
    out.recheck = Math.ceil(units / RECHECK_BATCH) * estimateStep('hunt', Math.ceil(RECHECK_BATCH / 2));
  }
  if (opts.external) {
    const triage = Math.ceil(opts.external / EXTERNAL_TRIAGE_BATCH) * estimateStep('hunt', Math.ceil(EXTERNAL_TRIAGE_BATCH / 2));
    const fills = Math.ceil(opts.external * EXTERNAL_FILL_SHARE / EXTERNAL_FILL_BATCH) * estimateStep('hunt', EXTERNAL_FILL_BATCH);
    out.external = triage + fills;
  }
  return out;
}

/** Options of the plan estimate: which optional parts run (decided by the plan step from the audit). */
export interface EstimateOptions {
  domainHunt?: boolean; gapFill?: boolean; incremental?: boolean; checklist?: boolean; recheck?: boolean; external?: number;
  /** how ⑪ may run (`plannedExploreMode`): the full decide loop, the on-demand directions, or not at all. */
  explore?: 'full' | 'directions' | null;
}

/** Rounds of the on-demand exploration at most (explore.ts `AUTO_EXPLORE_ROUNDS` is this constant). */
export const EXPLORE_DIRECTION_ROUNDS = 5;

interface EstimateContext {
  strategy: AuditStrategy;
  /** Candidates within the limit. */
  n: number;
  expectedFindings: number;
  opts: EstimateOptions;
  times: (stage: CrossStage) => number;
  /** One domain expert's planning estimate (full: the constant; incremental: from the change set). */
  expert: number;
  lead: number;
}

/**
 * each catalog stage estimates its own steps (entries keyed like `byStep`, before calibration).
 * Stages without an entry (deterministic stages, deep exploration) add nothing.
 */
const NONE: Record<string, number> = {};
const STAGE_ESTIMATORS: Partial<Record<StageId, (c: EstimateContext) => Record<string, number>>> = {
  understand: ({ strategy, opts, times }) => ({
    // profile runs in the full pipeline unless it is the minimal one (a cache hit costs nothing; the estimate stays conservative).
    ...(strategy.models.triage || strategy.stages.adversarialReview || strategy.tools.coverageCompare ? { profile: estimateStep('profile') } : {}),
    // risk-hypothesis-first (one threat model); the domain hunt plans from the threat model too.
    ...(opts.domainHunt || strategy.stages.threatHypotheses ? { 'threat-model': estimateStep('threat-model') * times('threat') } : {}),
  }),
  triage: ({ strategy, n }) => (strategy.models.triage ? { triage: estimateStep('triage', Math.ceil(n / 50)) } : NONE),
  // One expert per planned domain and model, plus the lead that dispatches their subtasks.
  lead: ({ opts, expert, lead, times }) => (opts.domainHunt ? { hunt: (PLANNED_DOMAINS * expert + lead) * times('hunt') } : NONE),
  hunt: ({ strategy, n, opts, times }) => ({
    // × multi-model copies (every model hunts the same batches); × the cross models.
    ...(opts.domainHunt ? {} : { hunt: estimateStep('hunt', n) * times('hunt') }),
    // verification of the hypotheses (≈ 40 before the list exists), per verify model.
    // with the domain hunt the experts verify them (charged to hunt); only HYP-R retries are left.
    ...(strategy.stages.threatHypotheses && !opts.domainHunt ? { hypotheses: estimateStep('hunt', Math.min(strategy.limits.maxCandidates, 40)) * times('verify') } : {}),
  }),
  external: ({ n, opts }) => postExplorationEstimates(n, { external: opts.external ?? 0 }),
  checklist: ({ n, opts }) => postExplorationEstimates(n, { checklist: !!opts.checklist }),
  recheck: ({ n, opts }) => postExplorationEstimates(n, { recheck: !!opts.recheck }),
  // ⑨ completes what the experts left uncovered (on by default in the domain hunt).
  gap: ({ n, opts }) => (opts.domainHunt && opts.gapFill ? { gap: estimateStep('hunt', Math.ceil(n * GAP_SHARE)) } : NONE),
  // ⑪ — the on-demand directions investigate each open direction once without a decide session, at
  // most EXPLORE_DIRECTION_ROUNDS; the full loop runs one decide and one single-candidate investigation per round, up
  // to `limits.maxRounds` (it may stop earlier on stagnation, so this is an upper bound).
  explore: ({ strategy, opts }) => {
    if (opts.explore === 'directions') return { explore: EXPLORE_DIRECTION_ROUNDS * estimateStep('hunt', 1) };
    if (opts.explore === 'full') return { decide: strategy.limits.maxRounds * estimateStep('decide'), explore: strategy.limits.maxRounds * estimateStep('hunt', 1) };
    return NONE;
  },
  // one adversarial review per canonical finding (per review model when crossed). Tiered:
  // about FULL_REVIEW_SHARE of the findings get the full review by every review model, the rest a light one.
  review: ({ strategy, expectedFindings, times }) => (!strategy.stages.adversarialReview ? NONE : {
    challenge: strategy.stages.tieredReview === false
      ? estimateStep('challenge') * expectedFindings * times('review')
      : Math.ceil(estimateStep('challenge') * expectedFindings * (FULL_REVIEW_SHARE * times('review') + (1 - FULL_REVIEW_SHARE) * LIGHT_REVIEW_COST)),
  }),
  reconcile: ({ strategy }) => (strategy.models.merge ? { reconcile: estimateStep('reconcile') } : NONE),
};

export function estimatePipeline(strategy: AuditStrategy, candidates: number, expectedFindings: number, pricing: Pricing | undefined, ratio: EstimateRatio = ONE, opts: EstimateOptions = {}): PlanEstimate {
  const n = Math.min(candidates, strategy.limits.maxCandidates);
  const times = (stage: CrossStage) => crossModels(strategy, stage)?.length ?? 1;
  // an incremental audit's experts read the change set, not the repository — per expert the
  // calibrated per-candidate estimate of the changed units, between the domain floor and the full-audit constant (a
  // 3-file change was planned at 3.1–5.7M and used 0.5M).
  const expert = opts.incremental
    ? Math.min(DOMAIN_EXPERT_TOKENS, Math.max(MIN_INCREMENTAL_EXPERT, Math.ceil(estimateStep('hunt', n) * ratio('hunt', strategy.models.audit))))
    : DOMAIN_EXPERT_TOKENS;
  const lead = opts.incremental ? Math.min(LEAD_SESSION_TOKENS, expert) : LEAD_SESSION_TOKENS;
  const ctx: EstimateContext = { strategy, n, expectedFindings, opts, times, expert, lead };
  const byStep: Record<string, number> = {};
  const stageOfEntry: Record<string, StageId> = {};
  for (const st of sceneStages(opts.incremental ? 'incremental' : 'full')) {
    for (const [k, v] of Object.entries(STAGE_ESTIMATORS[st.id]?.(ctx) ?? {})) {
      byStep[k] = (byStep[k] ?? 0) + v;
      stageOfEntry[k] = st.id;
    }
  }
  // Each entry calibrated with its stage's model.
  const models: Record<string, [StepKind, ModelRef | null]> = {
    profile: ['profile', stageModel(strategy, 'profile')], triage: ['triage', strategy.models.triage], hunt: ['hunt', strategy.models.audit], gap: ['coverage-gap', strategy.models.audit],
    'threat-model': ['threat-model', stageModel(strategy, 'logic')], hypotheses: ['hunt', stageModel(strategy, 'logic')],
    challenge: ['challenge', stageModel(strategy, 'challenge')], reconcile: ['reconcile', strategy.models.merge],
    checklist: ['coverage-gap', strategy.models.audit], recheck: ['coverage-gap', stageModel(strategy, 'challenge')], external: ['coverage-gap', stageModel(strategy, 'challenge')],
    decide: ['decide', stageModel(strategy, 'explore')], explore: ['hunt', stageModel(strategy, 'explore')],
  };
  // The expert constant is not a per-candidate estimate and the expert sessions are not calibrated
  // (`calibrate: false`); the per-candidate hunt ratio (3–10× on real models) would inflate it as much.
  if (opts.domainHunt) delete models.hunt;
  for (const [k, v] of Object.entries(byStep)) {
    const m = models[k];
    if (m) byStep[k] = Math.ceil(v * ratio(m[0], m[1]));
  }
  // Per stage, in catalog order: each stage's share of the median (calibrated, with the retry margin like the total).
  const byStage: { stage: StageId; tokens: number }[] = [];
  for (const [k, v] of Object.entries(byStep)) {
    const st = stageOfEntry[k]!;
    const at = byStage.find((x) => x.stage === st);
    if (at) at.tokens += v; else byStage.push({ stage: st, tokens: v });
  }
  for (const x of byStage) x.tokens = Math.round(x.tokens * RETRY_MARGIN * 0.7);
  const total = Object.values(byStep).reduce((a, b) => a + b, 0) * RETRY_MARGIN;
  const p50 = Math.ceil(total * 0.7);
  const p90 = Math.ceil(total * 1.3);
  const parallel = Math.max(1, strategy.concurrency.sessions);
  const dur = Math.ceil((n / 8) * 180 / parallel + expectedFindings * 60 / parallel + 60);
  const cost = pricing
    ? { p50: (p50 * 0.8 * pricing.input + p50 * 0.2 * pricing.output) / 1e6, p90: (p90 * 0.8 * pricing.input + p90 * 0.2 * pricing.output) / 1e6, currency: pricing.currency }
    : null;
  return { tokens: { p50, p90 }, durationSec: { p50: dur, p90: Math.ceil(dur * 1.8) }, cost, byStep, byStage };
}

/** Cost in micro-units of the pricing currency; null when the price is unknown. */
export function costMicros(pricing: Pricing | undefined, u: { input: number; output: number; cacheRead: number }): number | null {
  if (!pricing) return null;
  return Math.round(u.input * pricing.input + u.output * pricing.output + u.cacheRead * (pricing.cacheRead ?? pricing.input));
}

/** Which budget stage each `estimatePipeline` entry charges. */
const ESTIMATE_STAGE: Record<string, BudgetStage> = {
  profile: 'prepare', triage: 'triage', hunt: 'hunt', gap: 'gap', 'threat-model': 'hypotheses', hypotheses: 'hypotheses', challenge: 'review', reconcile: 'merge',
  // these steps charge the coverage-completion quota (catalog step roles), so their estimate does too.
  checklist: 'gap', recheck: 'gap', external: 'gap',
  decide: 'explore', explore: 'explore',
};

/**
 * Stages whose estimate does not fit their quota: the plan says so up front instead of the audit
 * pausing later. Hunt also needs room for the batches reserved while running (`sessions` × one full batch).
 */
export function stageShortfalls(strategy: AuditStrategy, estimate: PlanEstimate, ratio: EstimateRatio = ONE, targets = 1): { stage: BudgetStage; need: number; limit: number }[] {
  const quotas = auditBudget(strategy, { targets }).stages;
  if (!quotas) return [];
  const need = new Map<BudgetStage, number>();
  for (const [k, v] of Object.entries(estimate.byStep)) {
    const st = ESTIMATE_STAGE[k];
    if (st) need.set(st, (need.get(st) ?? 0) + v);
  }
  if (need.has('hunt')) need.set('hunt', need.get('hunt')! + Math.ceil(strategy.concurrency.sessions * estimateStep('hunt', 8) * ratio('hunt', strategy.models.audit)));
  return [...need].flatMap(([stage, n]) => {
    const limit = quotas[stage];
    return limit !== undefined && n > limit ? [{ stage, need: n, limit }] : [];
  });
}
