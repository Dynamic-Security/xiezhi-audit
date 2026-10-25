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
    /** Accepts image input (conversation attachments); absent means yes. */
    images: Type.Optional(Type.Boolean()),
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

/** External tools: absolute paths; when absent they are looked up on PATH and in the usual places. */
export const ToolsConfig = Type.Object({
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
}, { additionalProperties: false });
export type ToolsConfig = Static<typeof ToolsConfig>;
/** Keys of `tools` in schema order: settable from the CLI (`tools.<key>`) and the general settings page. */
export const TOOL_PATH_KEYS = Object.keys(ToolsConfig.properties) as (keyof ToolsConfig)[];

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
  tools: ToolsConfig,
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

const PROVIDER_REF_STAGE_LABEL: Record<ConfigModelStage, string> = {
  profile: '计划与画像', scope: '影响范围', triage: '初筛', hunt: '领域审计', logic: '风险假设', explore: '深度探索',
  challenge: '对抗复核', merge: '归并', verify: '复验与风险研判', report: '报告', chat: '对话',
};
const PROVIDER_REF_SCENE_LABEL: Record<(typeof SCENES)[number], string> = { full: '全量审计', incremental: '增量审计', risk_hunt: '风险排查', reverify: '漏洞复验' };

/** One setting that names a model of a provider: `setting` is its config path, `label` what the page calls it. */
export interface ProviderReference { setting: string; label: string; model: string }

const refOf = (v: unknown, id: string): string | null => {
  const m = v as Partial<ModelRef> | null | undefined;
  return m && typeof m === 'object' && m.provider === id && typeof m.model === 'string' ? `${m.provider}/${m.model}` : null;
};

/**
 * The settings that point at provider `id`: default, fallback and per-stage models, the confidential-fact
 * models, and the scene defaults' cross-check group (plus per-stage models an older scene layer may still hold).
 */
export function providerReferences(cfg: AppConfig, id: string): ProviderReference[] {
  const out: ProviderReference[] = [];
  const add = (setting: string, label: string, v: unknown) => { const model = refOf(v, id); if (model) out.push({ setting, label, model }); };
  add('defaultModel', '默认模型', cfg.defaultModel);
  add('fallbackModel', '备用模型', cfg.fallbackModel);
  for (const k of CONFIG_MODEL_STAGES) add(`stageModels.${k}`, `各阶段模型 · ${PROVIDER_REF_STAGE_LABEL[k]}`, cfg.stageModels?.[k]);
  for (const k of cfg.confidentialModels ?? []) if (k.startsWith(`${id}/`)) out.push({ setting: 'confidentialModels', label: '可接收机密事实（模型标签）', model: k });
  for (const scene of SCENES) {
    const layer = (cfg.sceneDefaults as Record<string, Record<string, unknown> | undefined>)[scene];
    if (!layer) continue;
    const label = `任务创建默认值 · ${PROVIDER_REF_SCENE_LABEL[scene]}`;
    for (const key of ['models', 'modelFallbacks'] as const) {
      for (const [k, v] of Object.entries((layer[key] as Record<string, unknown> | undefined) ?? {})) add(`sceneDefaults.${scene}.${key}.${k}`, label, v);
    }
    const mm = layer.multiModel as { models?: unknown[] } | undefined;
    for (const v of mm?.models ?? []) add(`sceneDefaults.${scene}.multiModel`, `${label} · 多模型交叉`, v);
  }
  return out;
}

/**
 * The config without provider `id` and without every reference `providerReferences` finds: the default and
 * fallback models are unset, stages follow the default model again, the provider's models leave the confidential list
 * and the cross-check groups (a group left with fewer than 2 models is switched off). Pricing entries stay.
 */
export function withoutProvider(cfg: AppConfig, id: string): AppConfig {
  const hit = (v: unknown) => refOf(v, id) !== null;
  const { defaultModel, fallbackModel, confidentialModels, ...rest } = cfg;
  const stageModels = Object.fromEntries(Object.entries(cfg.stageModels ?? {}).filter(([, v]) => !hit(v))) as StageModelsConfig;
  const confidential = (confidentialModels ?? []).filter((k) => !k.startsWith(`${id}/`));
  const sceneDefaults: Record<string, Record<string, unknown>> = {};
  for (const [scene, layer] of Object.entries(cfg.sceneDefaults as Record<string, Record<string, unknown> | undefined>)) {
    if (!layer) continue;
    const next: Record<string, unknown> = { ...layer };
    for (const key of ['models', 'modelFallbacks'] as const) {
      if (layer[key] && typeof layer[key] === 'object') next[key] = Object.fromEntries(Object.entries(layer[key] as Record<string, unknown>).filter(([, v]) => !hit(v)));
    }
    const mm = layer.multiModel as { enabled?: boolean; models?: unknown[] } | undefined;
    if (mm?.models?.some(hit)) {
      const models = mm.models.filter((v) => !hit(v));
      next.multiModel = { ...mm, models, ...(mm.enabled && models.length < 2 ? { enabled: false } : {}) };
    }
    sceneDefaults[scene] = next;
  }
  return {
    ...rest,
    modelProviders: cfg.modelProviders.filter((p) => p.id !== id),
    ...(defaultModel && !hit(defaultModel) ? { defaultModel } : {}),
    ...(fallbackModel && !hit(fallbackModel) ? { fallbackModel } : {}),
    stageModels,
    ...(confidential.length ? { confidentialModels: confidential } : {}),
    sceneDefaults: sceneDefaults as AppConfig['sceneDefaults'],
  };
}
