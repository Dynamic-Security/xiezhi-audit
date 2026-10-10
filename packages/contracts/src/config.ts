// config.json schema. Credentials live only in this file.
import { Type, type Static, type TOptional } from 'typebox';
import { closedSet, SCENES } from './enums.js';
import { MODEL_STAGE_KEYS, ModelRef, NO_MODEL_STAGES } from './strategy.js';

export const MODEL_APIS = ['openai-completions', 'openai-responses', 'anthropic-messages'] as const;
export type ModelApi = (typeof MODEL_APIS)[number];

export const ModelProviderConfig = Type.Object({
  id: Type.String({ pattern: '^[a-z0-9][a-z0-9_-]{0,63}$' }),
  api: closedSet(MODEL_APIS),
  baseUrl: Type.String({ minLength: 1 }),
  /** Secret. Bound to (id, origin(baseUrl)); changing baseUrl clears it. */
  apiKey: Type.Optional(Type.String()),
  apiKeyOrigin: Type.Optional(Type.String()),
  headers: Type.Optional(Type.Record(Type.String(), Type.String())),
  models: Type.Array(Type.Object({
    id: Type.String({ minLength: 1 }),
    name: Type.Optional(Type.String()),
    contextWindow: Type.Optional(Type.Integer({ minimum: 1024 })),
    maxTokens: Type.Optional(Type.Integer({ minimum: 256 })),
    reasoning: Type.Optional(Type.Boolean()),
  }, { additionalProperties: false })),
}, { additionalProperties: false });
export type ModelProviderConfig = Static<typeof ModelProviderConfig>;

/** HTTPS credential for one Git host. `token` is a secret. */
export const GitCredentialConfig = Type.Object({
  host: Type.String({ pattern: '^[a-z0-9.-]+(:[0-9]{1,5})?$', maxLength: 255 }),
  username: Type.String({ minLength: 1, maxLength: 200 }),
  token: Type.Optional(Type.String({ maxLength: 4096 })),
}, { additionalProperties: false });
export type GitCredentialConfig = Static<typeof GitCredentialConfig>;

export const Pricing = Type.Object({
  currency: Type.String({ minLength: 3, maxLength: 3 }),
  /** Price per million tokens. */
  input: Type.Number({ minimum: 0 }),
  output: Type.Number({ minimum: 0 }),
  cacheRead: Type.Optional(Type.Number({ minimum: 0 })),
}, { additionalProperties: false });
export type Pricing = Static<typeof Pricing>;

/**
 * Stages whose model is chosen in settings: the audit stages plus `chat` (conversations,
 * knowledge drafting, push parameters, architecture import).
 */
export const CONFIG_MODEL_STAGES = [...MODEL_STAGE_KEYS, 'chat'] as const;
export type ConfigModelStage = (typeof CONFIG_MODEL_STAGES)[number];

/** Per stage: a model, `null` = no model (only triage and merge: deterministic processing), absent = the default model. */
const StageModel = Type.Union([ModelRef, Type.Null()]);
export const StageModelsConfig = Type.Object(
  Object.fromEntries(CONFIG_MODEL_STAGES.map((k) => [k, Type.Optional(StageModel)])) as Record<ConfigModelStage, TOptional<typeof StageModel>>,
  { additionalProperties: false },
);
export type StageModelsConfig = Static<typeof StageModelsConfig>;

export const AppConfig = Type.Object({
  modelProviders: Type.Array(ModelProviderConfig),
  /** “默认模型”: every stage without its own model uses it. */
  defaultModel: Type.Optional(ModelRef),
  /** per-stage models; see StageModelsConfig. */
  stageModels: Type.Optional(StageModelsConfig),
  /** Deprecated: read once by `upgradeConfig` into `stageModels.triage` / `merge`; never written. */
  cheapModel: Type.Optional(ModelRef),
  /** Deprecated: read once by `upgradeConfig` into `stageModels.chat`; never written. */
  chatModel: Type.Optional(ModelRef),
  /** “备用模型”: used when a stage's model is unavailable (the only fallback). */
  fallbackModel: Type.Optional(ModelRef),
  /**
   * the models (`provider/model`) that may receive enterprise facts marked confidential; sessions on
   * other models never see them (withheld and recorded). Absent / empty = no model receives them.
   */
  confidentialModels: Type.Optional(Type.Array(Type.String({ maxLength: 300 }), { maxItems: 50 })),
  /** Keyed by `provider/model`. */
  pricing: Type.Record(Type.String(), Pricing),
  sceneDefaults: Type.Partial(Type.Record(closedSet(SCENES), Type.Record(Type.String(), Type.Unknown()))),
  concurrency: Type.Object({
    audits: Type.Integer({ minimum: 1, maximum: 8 }),
    modelRequests: Type.Integer({ minimum: 1, maximum: 64 }),
    indexWorkers: Type.Optional(Type.Integer({ minimum: 1, maximum: 16 })),
  }, { additionalProperties: false }),
  engine: Type.Object({
    pauseGraceSec: Type.Integer({ minimum: 0 }),
    budgetTolerance: Type.Number({ minimum: 0, maximum: 1 }),
    /** Connector write calls one audit step or one reply may run (default 20). */
    connectorWritesPerStep: Type.Optional(Type.Integer({ minimum: 1, maximum: 1000 })),
  }, { additionalProperties: false }),
  gitCredentials: Type.Optional(Type.Array(GitCredentialConfig, { maxItems: 100 })),
  /** Connector credentials by connector id, referenced from connector configuration as `${secret:key}`. */
  connectorSecrets: Type.Optional(Type.Record(Type.String({ maxLength: 64 }), Type.Record(Type.String({ pattern: '^[A-Za-z0-9_.-]{1,64}$' }), Type.String({ maxLength: 8192 })))),
  tools: Type.Object({
    rgPath: Type.Optional(Type.String()),
    gitPath: Type.Optional(Type.String()),
    /** Language servers: absolute paths; when absent they are looked up in the usual places. */
    goplsPath: Type.Optional(Type.String()),
    jdtlsPath: Type.Optional(Type.String()),
    /** The Go toolchain gopls uses (`go` binary). */
    goPath: Type.Optional(Type.String()),
    /** `pyright-langserver` and `typescript-language-server`; both need `node` (nodePath or PATH). */
    pyrightPath: Type.Optional(Type.String()),
    tsLspPath: Type.Optional(Type.String()),
    nodePath: Type.Optional(Type.String()),
  }, { additionalProperties: false }),
  export: Type.Object({
    snippets: Type.Boolean(),
    localRoots: Type.Boolean(),
    /** Default report skill for exports; its `template.md`, if any, orders and titles sections. */
    reportSkill: Type.Optional(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' })),
  }, { additionalProperties: false }),
  log: Type.Object({
    level: closedSet(['debug', 'info', 'warn', 'error'] as const),
    retentionDays: Type.Integer({ minimum: 1 }),
  }, { additionalProperties: false }),
}, { additionalProperties: false });
export type AppConfig = Static<typeof AppConfig>;

export function defaultAppConfig(): AppConfig {
  return {
    modelProviders: [],
    stageModels: {},
    pricing: {},
    sceneDefaults: {},
    concurrency: { audits: 1, modelRequests: 4 },
    engine: { pauseGraceSec: 120, budgetTolerance: 0.1 },
    tools: {},
    export: { snippets: true, localRoots: true },
    log: { level: 'info', retentionDays: 14 },
  };
}

/** Secret-bearing leaf paths inside AppConfig; used by redaction and masked display. */
export function collectSecrets(cfg: AppConfig): string[] {
  return [
    ...cfg.modelProviders.map((p) => p.apiKey), ...(cfg.gitCredentials ?? []).map((c) => c.token),
    ...Object.values(cfg.connectorSecrets ?? {}).flatMap((m) => Object.values(m)),
  ]
    .filter((k): k is string => !!k && k.length >= 4);
}

export function maskSecret(value: string | undefined): { configured: boolean; hint?: string } {
  if (!value) return { configured: false };
  if (value.length < 12) return { configured: true };
  return { configured: true, hint: `${value.slice(0, 3)}…${value.slice(-4)}` };
}

export function originOf(url: string): string {
  const u = new URL(url);
  return `${u.protocol}//${u.host}`.toLowerCase();
}

/**
 * the light model and the chat model became stages of `stageModels`. A light model the user
 * chose stays on triage and merge; without one they follow the default model like every other stage
 * (their default is the default model too). The chat model becomes the `chat` stage. The deprecated keys
 * are dropped. Applied when reading and saving.
 */
export function upgradeConfig<T extends Record<string, unknown>>(raw: T): T {
  const { cheapModel, chatModel, ...rest } = raw as Record<string, unknown>;
  const sm: Record<string, unknown> = { ...((rest.stageModels as Record<string, unknown> | undefined) ?? {}) };
  if (cheapModel) for (const k of NO_MODEL_STAGES) if (!(k in sm)) sm[k] = cheapModel;
  if (chatModel && !('chat' in sm)) sm.chat = chatModel;
  return { ...rest, stageModels: sm } as unknown as T;
}

/** The model a settings stage resolves to: its own, `null` = none (triage / merge only), else the default. */
export function configStageModel(c: Pick<AppConfig, 'defaultModel' | 'stageModels'>, stage: ConfigModelStage): ModelRef | null {
  const v = c.stageModels?.[stage];
  if (v === null && (NO_MODEL_STAGES as readonly string[]).includes(stage)) return null;
  return v ?? c.defaultModel ?? null;
}
