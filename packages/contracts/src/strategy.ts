// AuditStrategy. Authoritative parameter model; frozen at plan confirmation.
import { Type, type Static, type TOptional } from 'typebox';
import { closedSet, type Scene } from './enums.js';
import { sha256Hex, canonicalJson } from './hash.js';

/**
 * Stages whose model can be chosen separately, in pipeline order. `hunt` is `models.audit`,
 * `profile` covers plan and profile, `verify` covers reverification and risk judging.
 */
/** threat modeling, bottom-up hunt, top-down verification, adversarial review. */
export const CROSS_STAGES = ['threat', 'hunt', 'verify', 'review'] as const;
export const MODEL_STAGE_KEYS = ['profile', 'scope', 'triage', 'hunt', 'logic', 'explore', 'challenge', 'merge', 'verify', 'report'] as const;
export type ModelStageKey = (typeof MODEL_STAGE_KEYS)[number];
/** Stages that can run without a model (deterministic heuristics / grouping). */
export const NO_MODEL_STAGES = ['triage', 'merge'] as const;

export const ModelRef = Type.Object({
  provider: Type.String({ minLength: 1 }),
  model: Type.String({ minLength: 1 }),
  thinking: Type.Optional(closedSet(['off', 'low', 'medium', 'high'] as const)),
}, { additionalProperties: false });
export type ModelRef = Static<typeof ModelRef>;

const NullableModel = Type.Union([ModelRef, Type.Null()]);
const Ratio = Type.Number({ minimum: 0, maximum: 1 });

/**
 * Budget stages: the steps of one stage share a token quota, a share of the total budget. A
 * stage that uses up its quota waits for a top-up like the total budget. `prepare` = plan, scope and
 * profile; `hypotheses` = threat modeling and hypothesis verification; `verify` = reverification.
 */
export const BUDGET_STAGES = ['prepare', 'triage', 'hunt', 'gap', 'hypotheses', 'explore', 'merge', 'review', 'verify'] as const;
export type BudgetStage = (typeof BUDGET_STAGES)[number];
/**
 * Default shares of the total for full audits. They may add up to more than 1: a stage that is off uses
 * nothing, and the total stays the overall limit.
 */
export const DEFAULT_BUDGET_SHARES: Readonly<Record<BudgetStage, number>> = {
  // hunt 65% → 85%; 500 candidates × 18k = 9M plus 4 reserved batches (≈ 0.6M) must fit in 12M × share.
  prepare: 0.05, triage: 0.1, hunt: 0.85, gap: 0.2, hypotheses: 0.2, explore: 0.15, merge: 0.03, review: 0.15, verify: 0.15,
};
const BudgetShares = Type.Object(
  Object.fromEntries(BUDGET_STAGES.map((k) => [k, Type.Optional(Ratio)])) as Record<BudgetStage, TOptional<typeof Ratio>>,
  { additionalProperties: false },
);

/** Call-edge confidence order for impact traversal. */
export const EDGE_CONFIDENCES = ['resolved', 'heuristic', 'unresolved'] as const;
export type EdgeConfidence = (typeof EDGE_CONFIDENCES)[number];

/** Incremental impact analysis parameters (part of the strategy). */
export const ImpactParams = Type.Object({
  /** Reverse-call BFS depth limit. */
  maxDepth: Type.Integer({ minimum: 0, maximum: 32 }),
  /** Weakest call-edge confidence followed by the BFS. */
  minConfidence: closedSet(['resolved', 'heuristic'] as const),
  /** Changed indexable files above this share of all indexable files → full scan. */
  maxChangedRatio: Ratio,
  /** Diff-seeded variant search over the whole repository. */
  variantSearch: Type.Boolean(),
}, { additionalProperties: false });
export type ImpactParams = Static<typeof ImpactParams>;
export const DEFAULT_IMPACT: ImpactParams = { maxDepth: 6, minConfidence: 'heuristic', maxChangedRatio: 0.3, variantSearch: false };

export const AuditStrategy = Type.Object({
  version: Type.Literal(1),
  tools: Type.Object({
    grep: Type.Literal(true),
    read: Type.Literal(true),
    ast: Type.Boolean(),
    lsp: Type.Boolean(),
    coverageCompare: Type.Boolean(),
    /** `git_log` over the repository's local git data (default on for incremental). */
    gitHistory: Type.Optional(Type.Boolean()),
    /**
     * The profile also lists entry points and dangerous operations the index rules did not
     * recognize; validated ones join the index, the candidates and the coverage ledger (rule `model.surface`).
     * Absent = on in full audits; false = off.
     */
    surfaceDiscovery: Type.Optional(Type.Boolean()),
  }, { additionalProperties: false }),
  models: Type.Object({
    triage: NullableModel,
    audit: ModelRef,
    challenge: NullableModel,
    merge: NullableModel,
    report: NullableModel,
    /** profile and plan; null / absent = `audit`. */
    profile: Type.Optional(NullableModel),
    /** incremental impact analysis, per-entry logic review, deep exploration, reverify and risk
     * judging; null / absent = `audit`. `report` drives the AI report; null = `audit`. */
    scope: Type.Optional(NullableModel),
    logic: Type.Optional(NullableModel),
    explore: Type.Optional(NullableModel),
    verify: Type.Optional(NullableModel),
  }, { additionalProperties: false }),
  /**
   * Per-stage fallback model: used once per step on model errors; absent = the global fallback.
   * Deprecated: only the global fallback is configurable; kept for strategies frozen before.
   */
  modelFallbacks: Type.Optional(Type.Object(Object.fromEntries(MODEL_STAGE_KEYS.map((k) => [k, Type.Optional(ModelRef)])) as Record<(typeof MODEL_STAGE_KEYS)[number], TOptional<typeof ModelRef>>, { additionalProperties: false })),
  /**
   * Multi-model cross-checking: one group of 2–4 models. Every stage that can run
   * crossed has its own switch, off unless chosen — threat modeling, bottom-up hunt, top-down verification,
   * adversarial review. Absent `stages` (older strategies) = the old cross review: hunt + verification.
   */
  multiModel: Type.Object({
    enabled: Type.Boolean(),
    models: Type.Array(ModelRef, { maxItems: 4 }),
    stages: Type.Optional(Type.Object({
      threat: Type.Optional(Type.Boolean()), hunt: Type.Optional(Type.Boolean()), verify: Type.Optional(Type.Boolean()), review: Type.Optional(Type.Boolean()),
    }, { additionalProperties: false })),
  }, { additionalProperties: false }),
  stages: Type.Object({
    /**
     * 对抗复核: after reconcile, one fresh session per canonical finding argues against it with
     * the counter-evidence of the audit; maintain / pending / refuted (never deletes). Also reviews “已修复” in
     * reverification and “受影响” in risk hunts. Replaces `challenge` and `independentReview`.
     */
    adversarialReview: Type.Boolean(),
    /**
     * 分级复核: critical / high findings not pending get the full adversarial review (every review
     * model); the others a light one (first review model, fewer turns, checking the evidence chain and the
     * counter-evidence). Absent = on; false = every finding gets the full review.
     */
    tieredReview: Type.Optional(Type.Boolean()),
    /** Deprecated: read as adversarialReview (see migrateStages). */
    challenge: Type.Optional(Type.Boolean()),
    /** Deprecated: read as adversarialReview (see migrateStages). */
    independentReview: Type.Optional(Type.Boolean()),
    deepExplore: Type.Boolean(),
    /**
     * Deprecated (4, 18): full and incremental audits always explore with the lead; the switch between
     * domain experts and the generalist hunt is gone. Still accepted so old strategies and saved defaults load; dropped on
     * read (see migrateStages).
     */
    domainHunt: Type.Optional(Type.Boolean()),
    /** Deprecated: merged into threatHypotheses (see migrateStages). */
    logicReview: Type.Optional(Type.Boolean()),
    /**
     * 风险假设先行: a `threat-model` step lists the risks the repository may face (at most
     * `limits.maxCandidates`), then `HYP-B*` batches verify each one (confirmed → finding, refuted, open) with a
     * reason; the hypotheses are a third coverage dimension. Absent = off. Full and incremental.
     * includes the per-entry logic review — state-changing / by-id entries are a required source
     * of the threat model, and business-sensitive index rules join candidates and coverage.
     */
    threatHypotheses: Type.Optional(Type.Boolean()),
  }, { additionalProperties: false }),
  concurrency: Type.Object({ sessions: Type.Integer({ minimum: 1, maximum: 16 }) }, { additionalProperties: false }),
  budget: Type.Object({
    tokens: Type.Integer({ minimum: 1 }),
    durationSec: Type.Integer({ minimum: 1 }),
    /**
     * Deprecated: the cost cap was removed — budgets are tokens only. Still accepted so old strategies
     * and saved defaults load; dropped on read (`upgradeStrategy`, override layers) and never enforced.
     */
    costCap: Type.Optional(Type.Union([
      Type.Object({ amount: Type.Number({ minimum: 0 }), currency: Type.String({ minLength: 3, maxLength: 3 }) }, { additionalProperties: false }),
      Type.Null(),
    ])),
    /** per-stage quota as a share of `tokens`; absent (older strategies) = no stage quota. */
    stages: Type.Optional(BudgetShares),
    /**
     * The switch for the stage quotas. `false` = no stage quota, only `tokens` limits
     * the audit (the shares are kept for when it is switched on); absent (frozen strategies from before the switch) = on.
     */
    stageLimits: Type.Optional(Type.Boolean()),
  }, { additionalProperties: false }),
  limits: Type.Object({
    maxRounds: Type.Integer({ minimum: 0 }),
    maxTurnsPerStep: Type.Integer({ minimum: 1 }),
    maxCandidates: Type.Integer({ minimum: 1 }),
    /**
     * Triage cutoff: candidates the triage model scored below this (1–5) are not hunted and
     * are declared as coverage gaps like over-limit candidates. 0 / absent = off; unscored candidates are kept.
     */
    minTriageScore: Type.Optional(Type.Integer({ minimum: 0, maximum: 5 })),
  }, { additionalProperties: false }),
  coverageTarget: Type.Object({
    entry: Ratio,
    sink: Ratio,
    onShortfall: closedSet(['declare', 'gap_fill'] as const),
  }, { additionalProperties: false }),
  minConfidence: Ratio,
  knowledge: Type.Object({
    include: Type.Array(Type.String()),
    exclude: Type.Array(Type.String()),
  }, { additionalProperties: false }),
  focus: Type.Object({
    categories: Type.Array(Type.String()),
    modules: Type.Array(Type.String()),
    text: Type.Optional(Type.String({ maxLength: 4000 })),
  }, { additionalProperties: false }),
  scope: Type.Object({
    include: Type.Array(Type.String()),
    exclude: Type.Array(Type.String()),
  }, { additionalProperties: false }),
  impact: ImpactParams,
  /** Context connectors the Agent may query in this task (按任务授权); default: the project bindings. */
  connectors: Type.Array(Type.String({ maxLength: 64 }), { maxItems: 20 }),
  /** Requirement threat models this audit references; absent or empty: none. */
  threatModels: Type.Optional(Type.Array(Type.String({ maxLength: 64 }), { maxItems: 10 })),
}, { additionalProperties: false });
export type AuditStrategy = Static<typeof AuditStrategy>;

/** Deep partial used for settings-level and task-level overrides. */
export type StrategyOverride = { [K in keyof AuditStrategy]?: AuditStrategy[K] extends object ? Partial<AuditStrategy[K]> | unknown : AuditStrategy[K] } & Record<string, unknown>;

export interface ModelDefaults {
  /** Settings “默认模型”. Required. */
  defaultModel: ModelRef;
  /**
   * Settings per-stage models: a model, `null` = no model (triage / merge only), absent = the
   * default model. Every scene uses the same table (the scene layer has no models).
   */
  stageModels?: Partial<Record<ModelStageKey, ModelRef | null>>;
}

/** The model of a stage in new strategies: the settings table, else the default model. */
function defaultStageModel(m: ModelDefaults, stage: ModelStageKey): ModelRef | null {
  const v = m.stageModels?.[stage];
  if (v === null && (NO_MODEL_STAGES as readonly string[]).includes(stage)) return null;
  return v ?? m.defaultModel;
}

/**
 * Built-in scene defaults. Values marked "按评测校准" there are initial values.
 * `tools.lsp` is on for full audits (“按需”): servers start only when definition / references is
 * called, and an unavailable server falls back to tree-sitter.
 */
export function sceneDefaults(scene: Scene, m: ModelDefaults): AuditStrategy {
  const r = (k: ModelStageKey) => defaultStageModel(m, k);
  const base: AuditStrategy = {
    version: 1,
    tools: { grep: true, read: true, ast: false, lsp: false, coverageCompare: false, gitHistory: false },
    // every stage is explicit, so a frozen strategy says which model each stage used.
    models: {
      triage: r('triage'), audit: r('hunt')!, challenge: r('challenge'), merge: r('merge'), report: r('report'),
      profile: r('profile'), scope: r('scope'), logic: r('logic'), explore: r('explore'), verify: r('verify'),
    },
    multiModel: { enabled: false, models: [] },
    stages: { adversarialReview: false, deepExplore: false },
    concurrency: { sessions: 4 },
    budget: { tokens: 400_000, durationSec: 900 },
    limits: { maxRounds: 0, maxTurnsPerStep: 40, maxCandidates: 100 },
    coverageTarget: { entry: 0, sink: 0, onShortfall: 'declare' },
    minConfidence: 0,
    knowledge: { include: [], exclude: [] },
    focus: { categories: [], modules: [] },
    scope: { include: [], exclude: [] },
    impact: { ...DEFAULT_IMPACT },
    connectors: [],
  };
  switch (scene) {
    case 'full':
      return {
        ...base,
        tools: { ...base.tools, ast: true, lsp: true, coverageCompare: true },
        stages: { adversarialReview: true, deepExplore: false },
        concurrency: { sessions: 4 },
        // 3M was exhausted by triage at real scale.
        // Stage quotas stopped too many real audits — off by default, shares kept for the switch.
        budget: { tokens: 12_000_000, durationSec: 14_400, stages: { ...DEFAULT_BUDGET_SHARES }, stageLimits: false },
        // 200 left every repository with more than ~250 candidates short of the coverage target.
        limits: { maxRounds: 30, maxTurnsPerStep: 80, maxCandidates: 500 },
        coverageTarget: { entry: 0.9, sink: 0.8, onShortfall: 'declare' },
        minConfidence: 0.6,
      };
    case 'incremental':
      return {
        ...base,
        tools: { ...base.tools, gitHistory: true },
        concurrency: { sessions: 2 },
        // no stage quotas by default. 300k did not cover the threat model
        // the lead needs; a 4-file real-model increment used about 3M (cache reads included).
        budget: { tokens: 3_000_000, durationSec: 1_800 },
        limits: { maxRounds: 0, maxTurnsPerStep: 60, maxCandidates: 200 },
        coverageTarget: { entry: 1, sink: 0, onShortfall: 'declare' },
        minConfidence: 0.8,
      };
    case 'risk_hunt':
      return base;
    case 'reverify':
      return { ...base, budget: { tokens: 60_000, durationSec: 660 } };
  }
}

/**
 * Strategies stored before a field existed (e.g. `impact`) lack it; frozen strategies are
 * immutable, so readers fill system defaults for missing fields instead of migrating rows. The stored
 * hash stays the hash of what was frozen.
 */
export function upgradeStrategy(raw: unknown): AuditStrategy {
  const s = raw as AuditStrategy & { impact?: ImpactParams; connectors?: string[] };
  return { ...s, budget: withoutCostCap(s.budget), stages: migrateStages(s.stages) as AuditStrategy['stages'], impact: s.impact ?? { ...DEFAULT_IMPACT }, connectors: s.connectors ?? [] };
}

/** the removed cost cap is dropped wherever a budget is read. */
function withoutCostCap<T>(budget: T): T {
  if (!isPlainObject(budget) || !('costCap' in budget)) return budget;
  const { costCap: _dropped, ...rest } = budget;
  return rest as T;
}

/**
 * `stages.challenge` and `stages.independentReview` became `stages.adversarialReview`. A layer
 * (or an old frozen strategy) that sets either of them and not the new switch turns adversarial review on when
 * either was on; the old keys are dropped. Applied per override layer before merging and to frozen strategies.
 */
export function migrateStages<T extends Record<string, unknown> | undefined>(stages: T): T {
  if (!stages || typeof stages !== 'object') return stages;
  let st = stages as Record<string, unknown>;
  if ('challenge' in st || 'independentReview' in st) {
    const { challenge, independentReview, ...rest } = st;
    st = 'adversarialReview' in rest ? rest : { ...rest, adversarialReview: challenge === true || independentReview === true };
  }
  // the per-entry logic review is part of risk-hypothesis-first.
  if ('logicReview' in st) {
    const { logicReview, ...rest } = st;
    st = logicReview === true ? { ...rest, threatHypotheses: true } : rest;
  }
  // the lead replaced the domain-expert switch.
  if ('domainHunt' in st) {
    const { domainHunt: _dropped, ...rest } = st;
    st = rest;
  }
  return st as T;
}

/** Stages that can run crossed by several models. */
export type CrossStage = (typeof CROSS_STAGES)[number];

/**
 * The models a stage runs with under multi-model cross-checking, or null when it runs with one model. Strategies
 * from before per-stage switches (no `multiModel.stages`) crossed the hunt and the logic review, now the verification.
 */
/**
 * The key of slot `j` of a cross-check group (the same model may be chosen more than once; it then
 * simply runs more than once). `provider/model` when the model appears once — the identity steps had before — and
 * `provider/model#<j+1>` for a model that appears more than once, so its runs stay separate steps and separate votes.
 */
export function crossKey(models: readonly Pick<ModelRef, 'provider' | 'model'>[], j: number): string {
  const m = models[j]!;
  const name = `${m.provider}/${m.model}`;
  return models.filter((x) => x.provider === m.provider && x.model === m.model).length > 1 ? `${name}#${j + 1}` : name;
}

export function crossKeys(models: readonly Pick<ModelRef, 'provider' | 'model'>[]): string[] {
  return models.map((_, j) => crossKey(models, j));
}

export function crossModels(s: Pick<AuditStrategy, 'multiModel'>, stage: CrossStage): ModelRef[] | null {
  const mm = s.multiModel;
  if (!mm.enabled || mm.models.length < 2) return null;
  const on = mm.stages ?? { hunt: true, verify: true };
  return on[stage] ? mm.models : null;
}

function migrateLayer(layer: Record<string, unknown> | undefined): Record<string, unknown> | undefined {
  if (!layer) return layer;
  let out = layer;
  if (isPlainObject(out.stages)) out = { ...out, stages: migrateStages(out.stages) };
  if (isPlainObject(out.budget) && 'costCap' in out.budget) out = { ...out, budget: withoutCostCap(out.budget) };
  if (isPlainObject(out.budget) && customShares(out.budget.stages) && out.budget.stageLimits === undefined) out = { ...out, budget: { ...out.budget, stageLimits: true } };
  return out;
}

/**
 * A layer saved before the stage-quota switch that set shares of its own (not the built-in defaults, which the
 * settings page saved as they were) keeps its quotas: the switch is on for it. Default shares follow the new default, off.
 */
function customShares(stages: unknown): boolean {
  if (!isPlainObject(stages)) return false;
  return Object.entries(stages).some(([k, r]) => r !== undefined && r !== DEFAULT_BUDGET_SHARES[k as BudgetStage]);
}

function withoutKeys(layer: Record<string, unknown> | undefined, keys: string[]): Record<string, unknown> | undefined {
  if (!layer || !keys.some((k) => k in layer)) return layer;
  return Object.fromEntries(Object.entries(layer).filter(([k]) => !keys.includes(k)));
}

export type StrategyLayer = 'system' | 'settings' | 'task';
export interface MergedStrategy {
  strategy: AuditStrategy;
  /** Source layer per leaf path, e.g. `budget.tokens` → 'task'. */
  sources: Record<string, StrategyLayer>;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Paths whose array values are unioned across layers instead of replaced. */
const UNION_ARRAY_PATHS = new Set(['scope.exclude']);
/** Object-valued leaves that are replaced wholesale rather than deep-merged. */
const ATOMIC_OBJECT_PATHS = new Set([
  'models.triage', 'models.audit', 'models.challenge', 'models.merge', 'models.report', 'models.profile',
  // a model chosen in a later layer replaces the earlier one whole (its thinking level included).
  'models.scope', 'models.logic', 'models.explore', 'models.verify', ...MODEL_STAGE_KEYS.map((k) => `modelFallbacks.${k}`),
]);

function applyLayer(target: Record<string, unknown>, layer: Record<string, unknown>, name: StrategyLayer, sources: Record<string, StrategyLayer>, prefix = ''): void {
  for (const [key, value] of Object.entries(layer)) {
    if (value === undefined) continue;
    const path = prefix ? `${prefix}.${key}` : key;
    const current = target[key];
    if (isPlainObject(value) && isPlainObject(current) && !ATOMIC_OBJECT_PATHS.has(path)) {
      applyLayer(current, value, name, sources, path);
      continue;
    }
    if (Array.isArray(value) && Array.isArray(current) && UNION_ARRAY_PATHS.has(path)) {
      target[key] = [...new Set([...current, ...value])];
    } else {
      target[key] = structuredClone(value);
    }
    markSources(target[key], path, name, sources);
  }
}

function markSources(value: unknown, path: string, name: StrategyLayer, sources: Record<string, StrategyLayer>): void {
  if (isPlainObject(value) && !ATOMIC_OBJECT_PATHS.has(path)) {
    for (const [k, v] of Object.entries(value)) markSources(v, `${path}.${k}`, name, sources);
  } else {
    sources[path] = name;
  }
}

/** Merge order: system < settings scene defaults < task override. */
export function mergeStrategy(system: AuditStrategy, settings: Record<string, unknown> | undefined, task: Record<string, unknown> | undefined): MergedStrategy {
  const result = structuredClone(system) as unknown as Record<string, unknown>;
  const sources: Record<string, StrategyLayer> = {};
  for (const [k, v] of Object.entries(result)) markSources(v, k, 'system', sources);
  // stage models come from settings → 模型 (built into `system`); a scene layer no longer
  // sets models, and per-stage fallbacks are gone (one global fallback). Values saved before are ignored.
  const st = withoutKeys(migrateLayer(settings), ['models', 'modelFallbacks']);
  const tk = withoutKeys(migrateLayer(task), ['modelFallbacks']);
  if (st) applyLayer(result, st, 'settings', sources);
  if (tk) applyLayer(result, tk, 'task', sources);
  return { strategy: result as unknown as AuditStrategy, sources };
}

export interface StrategyIssue { path: string; message: string }

/**
 * Cross-field consistency plus capability limits. `knownModels`
 * is the set of `provider/model` ids configured in settings.
 */
export function checkStrategy(s: AuditStrategy, scene: Scene, knownModels: ReadonlySet<string>): StrategyIssue[] {
  const issues: StrategyIssue[] = [];
  if (s.tools.coverageCompare && !s.tools.ast) issues.push({ path: 'tools.coverageCompare', message: 'coverageCompare requires tools.ast=true' });
  if (s.multiModel.enabled && s.multiModel.models.length < 2) issues.push({ path: 'multiModel.models', message: 'multiModel requires 2–4 models' });
  if (s.stages.deepExplore && s.limits.maxRounds < 1) issues.push({ path: 'limits.maxRounds', message: 'deepExplore requires maxRounds ≥ 1' });
  // the optional analyses run in full and incremental audits; the logic review works on indexed entries.
  for (const k of ['logicReview', 'threatHypotheses'] as const) {
    if (s.stages[k] && scene !== 'full' && scene !== 'incremental') issues.push({ path: `stages.${k}`, message: `${k} applies to full and incremental audits` });
  }
  const refs: [string, ModelRef | null][] = [
    ['models.audit', s.models.audit], ['models.triage', s.models.triage], ['models.challenge', s.models.challenge], ['models.profile', s.models.profile ?? null],
    ['models.merge', s.models.merge], ['models.report', s.models.report],
    // the new stage models and the per-stage fallbacks must be configured models too.
    ...(['scope', 'logic', 'explore', 'verify'] as const).map((k): [string, ModelRef | null] => [`models.${k}`, s.models[k] ?? null]),
    ...Object.entries(s.modelFallbacks ?? {}).map(([k, m]): [string, ModelRef | null] => [`modelFallbacks.${k}`, m ?? null]),
    ...s.multiModel.models.map((m, i): [string, ModelRef] => [`multiModel.models.${i}`, m]),
  ];
  for (const [path, ref] of refs) {
    if (ref && !knownModels.has(`${ref.provider}/${ref.model}`)) issues.push({ path, message: `model ${ref.provider}/${ref.model} is not configured` });
  }
  return issues;
}

/** An audit's budget record; `stages` holds each stage quota in tokens. */
export interface AuditBudget { tokens: number; durationMs: number; costMicros: number | null; stages?: Partial<Record<BudgetStage, number>> }

/** The prepare quota grows with the target repositories up to this share (or the configured one, if larger). */
export const PREPARE_SHARE_CAP = 0.3;

/**
 * The budget an audit starts with, from its frozen strategy. `targets`: the audit's target repositories — each one
 * runs its own system understanding, so the plan-and-profile quota is the share per repository.
 * A crossed stage runs once per model — adversarial review (each finding by each review model), risk hypotheses (the
 * threat model and the verification by each model) — so its quota is the share per model (also for
 * hypotheses); the total budget still caps them all.
 */
export function auditBudget(s: Pick<AuditStrategy, 'budget'> & Partial<Pick<AuditStrategy, 'multiModel'>>, opts: { targets?: number } = {}): AuditBudget {
  const b = s.budget;
  const n = Math.max(1, opts.targets ?? 1);
  const crossed = (st: CrossStage) => (s.multiModel ? crossModels({ multiModel: s.multiModel }, st)?.length ?? 1 : 1);
  // Crossed stages run once per model — review (each finding), hypotheses (threat model, verification).
  const times: Partial<Record<string, number>> = { review: crossed('review'), hypotheses: Math.max(crossed('threat'), crossed('verify')) };
  const share = (k: string, r: number) => (k === 'prepare' && n > 1 ? Math.min(r * n, Math.max(r, PREPARE_SHARE_CAP))
    : (times[k] ?? 1) > 1 ? Math.min(r * times[k]!, 1) : r);
  // a share of 1 (100%) means no stage quota — only the total limits it, also after top-ups.
  // The switch off means no stage quota at all.
  const kept = b.stageLimits === false ? [] : Object.entries(b.stages ?? {}).filter(([, r]) => r !== undefined && r < 1);
  const stages = kept.length ? Object.fromEntries(kept.map(([k, r]) => [k, Math.floor(share(k, r!) * b.tokens)])) : undefined;
  // `costMicros` stays in the record (no longer a cap) so budgets of older audits keep their shape.
  return { tokens: b.tokens, durationMs: b.durationSec * 1000, costMicros: null, ...(stages ? { stages } : {}) };
}

export function strategyHash(s: AuditStrategy): string {
  return sha256Hex(canonicalJson(s));
}

/**
 * The model a stage uses: its own setting, else what it follows — triage and merge have no model when
 * unset (heuristics / deterministic merge), every other stage follows the hunt model (`models.audit`).
 */
export function stageModel(s: Pick<AuditStrategy, 'models'>, stage: ModelStageKey): ModelRef | null {
  const m = s.models;
  switch (stage) {
    case 'hunt': return m.audit;
    case 'triage': return m.triage;
    case 'merge': return m.merge;
    case 'challenge': return m.challenge ?? m.audit;
    default: return m[stage] ?? m.audit;
  }
}

/** The fallback of a stage: its own, else the global fallback role; never the model it replaces. */
export function stageFallback(s: Pick<AuditStrategy, 'modelFallbacks'>, stage: ModelStageKey, global: ModelRef | null | undefined, current: ModelRef): ModelRef | null {
  const f = s.modelFallbacks?.[stage] ?? global ?? null;
  return f && !(f.provider === current.provider && f.model === current.model) ? f : null;
}
