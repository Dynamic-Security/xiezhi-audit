// Request body schemas: one object per route, used both by the handler's validation
// (parseBody) and by the route schema from which openapi.json is generated — no drift possible.
import { Type } from 'typebox';
import { THREAT_RISK_STATUSES, THREAT_SOURCE_MAX_BYTES, VULN_CATEGORIES,
  AuditPlanRequest, BUDGET_STAGES, StageModelsConfig, TOOL_PATH_KEYS, CONFIRM_STATUSES, EXPORT_FORMATS, HANDLING_STATUSES, INTERVENTION_KINDS, MATCH_DECISIONS, MODEL_APIS, ModelRef, Pricing, SEVERITIES,
  TOP_UP_TOKENS_MAX, TOP_UP_TOKENS_MIN,
} from '@xiezhi/contracts';

const NullableModel = Type.Union([ModelRef, Type.Null()]);

export const ModelEntry = Type.Object({
  id: Type.String({ minLength: 1, maxLength: 200 }), name: Type.Optional(Type.String({ maxLength: 200 })),
  contextWindow: Type.Optional(Type.Integer({ minimum: 1024 })), maxTokens: Type.Optional(Type.Integer({ minimum: 256 })), reasoning: Type.Optional(Type.Boolean()), images: Type.Optional(Type.Boolean()),
  /** May receive facts marked confidential: stored in the global `confidentialModels` list, not on the model. */
  confidential: Type.Optional(Type.Boolean()),
}, { additionalProperties: false });

export const ProviderCreate = Type.Object({
  id: Type.String({ pattern: '^[a-z0-9][a-z0-9_-]{0,63}$' }), api: Type.Enum(MODEL_APIS), baseUrl: Type.String({ minLength: 1, maxLength: 500 }),
  apiKey: Type.Optional(Type.String({ maxLength: 4096 })), models: Type.Array(ModelEntry, { minItems: 1, maxItems: 100 }),
}, { additionalProperties: false });
/** An unsaved provider form to probe or check: `id` names a saved provider whose key may be reused. */
export const ProviderProbeBody = Type.Object({
  id: Type.Optional(Type.String({ pattern: '^[a-z0-9][a-z0-9_-]{0,63}$' })), api: Type.Enum(MODEL_APIS), baseUrl: Type.String({ minLength: 1, maxLength: 500 }),
  apiKey: Type.Optional(Type.String({ maxLength: 4096 })),
}, { additionalProperties: false });
export const ProviderCheckBody = Type.Object({
  ...ProviderProbeBody.properties,
  models: Type.Array(Type.String({ minLength: 1, maxLength: 200 }), { maxItems: 100 }),
}, { additionalProperties: false });
export const ProviderPatch = Type.Object({
  api: Type.Optional(Type.Enum(MODEL_APIS)), baseUrl: Type.Optional(Type.String({ minLength: 1, maxLength: 500 })),
  apiKey: Type.Optional(Type.String({ maxLength: 4096 })), models: Type.Optional(Type.Array(ModelEntry, { minItems: 1, maxItems: 100 })),
}, { additionalProperties: false });


export const PostSessionBootstrapBody = Type.Object({ code: Type.String({ minLength: 10, maxLength: 200 }) }, { additionalProperties: false });
export const PutSettingsModelsBody = Type.Object({ defaultModel: NullableModel, stageModels: StageModelsConfig, fallbackModel: NullableModel, confidentialModels: Type.Optional(Type.Array(Type.String({ maxLength: 300 }), { maxItems: 50 })), revision: Type.String() }, { additionalProperties: false });
export const PutSettingsSceneDefaultsSceneBody = Type.Object({ override: Type.Record(Type.String(), Type.Unknown()), revision: Type.String() }, { additionalProperties: false });
export const PatchSettingsGeneralBody = Type.Object({
      revision: Type.String(),
      concurrency: Type.Optional(Type.Object({ audits: Type.Optional(Type.Integer({ minimum: 1, maximum: 8 })), modelRequests: Type.Optional(Type.Integer({ minimum: 1, maximum: 64 })) }, { additionalProperties: false })),
      engine: Type.Optional(Type.Object({ pauseGraceSec: Type.Optional(Type.Integer({ minimum: 0, maximum: 3600 })), budgetTolerance: Type.Optional(Type.Number({ minimum: 0, maximum: 1 })) }, { additionalProperties: false })),
      export: Type.Optional(Type.Object({ snippets: Type.Optional(Type.Boolean()), localRoots: Type.Optional(Type.Boolean()), reportSkill: Type.Optional(Type.Union([Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' }), Type.Null()])) }, { additionalProperties: false })),
      log: Type.Optional(Type.Object({ level: Type.Optional(Type.Enum(['debug', 'info', 'warn', 'error'] as const)), retentionDays: Type.Optional(Type.Integer({ minimum: 1, maximum: 365 })) }, { additionalProperties: false })),
      pricing: Type.Optional(Type.Record(Type.String(), Pricing)),
      /** External tool paths: an absolute path sets one, null clears it (looked up on PATH again). */
      tools: Type.Optional(Type.Object(Object.fromEntries(TOOL_PATH_KEYS.map((k) => [k, Type.Optional(Type.Union([Type.String({ minLength: 1, maxLength: 1024, pattern: '^/' }), Type.Null()]))])), { additionalProperties: false })),
    }, { additionalProperties: false });
export const PostProjectsBody = Type.Object({ name: Type.String({ minLength: 1, maxLength: 100 }) }, { additionalProperties: false });
export const PatchProjectsPidBody = Type.Object({
  name: Type.Optional(Type.String({ minLength: 1, maxLength: 100 })), status: Type.Optional(Type.Enum(['active', 'archived'] as const)),
  /** the internal-trust setting; null = infer from the topology. */
  internalTrust: Type.Optional(Type.Union([Type.Enum(['zero_trust', 'gateway_boundary', 'trusted_network'] as const), Type.Null()])),
}, { additionalProperties: false });
const SourceFields = {
  path: Type.Optional(Type.String({ minLength: 1, maxLength: 4096, description: '本地目录（服务所在机器的绝对路径）' })),
  git: Type.Optional(Type.String({ minLength: 1, maxLength: 2000, description: 'Git 地址：https://… 或 ssh / git@host:path；不得内嵌凭证' })),
  uploadId: Type.Optional(Type.String({ pattern: '^upl_[0-9a-f]{24}$', description: 'POST /uploads 返回的上传 ID' })),
};
/** Exactly one of path / git / uploadId (checked by the handler). */
export const PostRepoProbesBody = Type.Object(SourceFields, { additionalProperties: false });
export const PostProjectsPidReposBody = Type.Object({
      repos: Type.Array(Type.Object({ ...SourceFields, name: Type.Optional(Type.String({ maxLength: 100 })), ref: Type.Optional(Type.String({ maxLength: 250 })) }, { additionalProperties: false }), { minItems: 1, maxItems: 20 }),
    }, { additionalProperties: false });
export const PutSettingsGitCredentialsHostBody = Type.Object({
  username: Type.String({ minLength: 1, maxLength: 200 }),
  /** Empty / omitted keeps the stored token. */
  token: Type.Optional(Type.String({ maxLength: 4096 })),
}, { additionalProperties: false });
export const PatchReposRidBody = Type.Object({
  defaultRef: Type.Optional(Type.Union([Type.String({ maxLength: 250 }), Type.Null()])), role: Type.Optional(Type.String({ maxLength: 40 })),
  /** true = auditable, false = context only, 'auto' = follow the automatic judgement again. */
  auditable: Type.Optional(Type.Union([Type.Boolean(), Type.Literal('auto')])),
}, { additionalProperties: false });
/** Shared with the conversation's propose_audit_plan: both entries build the same plan. */
/** The audit form request plus `autoStart`: the conversation tool's AuditPlanRequest stays unchanged. */
export const PostAuditPlansBody = Type.Object({ ...AuditPlanRequest.properties, autoStart: Type.Optional(Type.Boolean({ description: '计划生成后直接开始（网页表单默认开启）' })) }, { additionalProperties: false });
export const PatchAuditPlansIdBody = Type.Object({ revision: Type.Optional(Type.Integer()), strategyOverride: Type.Record(Type.String(), Type.Unknown()), title: Type.Optional(Type.String({ minLength: 1, maxLength: 200 })) }, { additionalProperties: false });
/** Steps a content filter refused start afresh instead of retrying their conversation as it is. */
export const PostAuditsAidResumeBody = Type.Object({
  restartFiltered: Type.Optional(Type.Boolean()), switchModel: Type.Optional(ModelRef),
  /** `later` also moves every later step that would run on a refused model; default `filtered` (the refused steps only). */
  switchScope: Type.Optional(Type.Union([Type.Literal('filtered'), Type.Literal('later')])),
}, { additionalProperties: false });
export const PostAuditsAidBudgetGrantsBody = Type.Object({
  tokens: Type.Optional(Type.Integer({ minimum: TOP_UP_TOKENS_MIN, maximum: TOP_UP_TOKENS_MAX })), durationSec: Type.Optional(Type.Integer({ minimum: 1, maximum: 7 * 86400 })),
  /** Add the tokens to this stage quota (and to the total). */
  stage: Type.Optional(Type.Enum(BUDGET_STAGES)),
  /** drop the audit's stage quotas — only the total limits it from then on. */
  liftStageQuotas: Type.Optional(Type.Literal(true)),
}, { additionalProperties: false });
export const PostQuestionsQidAnswerBody = Type.Object({ answer: Type.String({ minLength: 1, maxLength: 8000 }) }, { additionalProperties: false });
export const PostAuditsAidInterventionsBody = Type.Object({ kind: Type.Enum(INTERVENTION_KINDS), text: Type.String({ maxLength: 8000 }), target: Type.Optional(Type.String({ maxLength: 100 })) }, { additionalProperties: false });
export const PostExportsBody = Type.Object({
      scope: Type.Literal('audit'), ids: Type.Array(Type.String(), { minItems: 1, maxItems: 1 }), format: Type.Enum(EXPORT_FORMATS),
      snippets: Type.Optional(Type.Boolean()), localRoots: Type.Optional(Type.Boolean()),
      /** Report skill (category report) whose template orders and titles the Markdown sections; default from settings. */
      reportSkill: Type.Optional(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' })),
      /** only the findings of these vulnerabilities of the audit. */
      vulnIds: Type.Optional(Type.Array(Type.String({ maxLength: 64 }), { minItems: 1, maxItems: 500 })),
      /** false leaves out pending and insufficient-evidence findings (default true). */
      includePending: Type.Optional(Type.Boolean()),
      /** append a per-step trajectory summary (Markdown / HTML / JSON). */
      trajectory: Type.Optional(Type.Boolean()),
      /** `ai` = the report model writes the report (md / html only) in the background; default `template`. */
      mode: Type.Optional(Type.Enum(['template', 'ai'] as const)),
      /** the model for this AI report only; default the audit's report stage. */
      model: Type.Optional(ModelRef),
    }, { additionalProperties: false });
/** G1: client-measured review time; longer than 24 h is clamped by the engine. */
const ReviewMs = Type.Optional(Type.Integer({ minimum: 0, maximum: 2_147_483_647, description: '复核耗时（毫秒）：单条为打开详情到作出判定；批量为选择到应用，服务端按实际改动的条数平分' }));
export const PatchVulnerabilitiesVidBody = Type.Object({
      revision: Type.Optional(Type.Integer()), confirmStatus: Type.Optional(Type.Enum(CONFIRM_STATUSES)), handlingStatus: Type.Optional(Type.Enum(HANDLING_STATUSES)),
      severity: Type.Optional(Type.Enum(SEVERITIES)), reason: Type.Optional(Type.String({ maxLength: 2000 })), reviewMs: ReviewMs,
    }, { additionalProperties: false });
/** a reviewer adds a risk hypothesis to the audit's list, also while it runs. */
export const PostAuditsAidHypothesesBody = Type.Object({
      statement: Type.String({ minLength: 4, maxLength: 1000 }), category: Type.Enum(VULN_CATEGORIES),
      basis: Type.Optional(Type.String({ maxLength: 1000 })), entries: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 300 }), { maxItems: 10 })),
      files: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 500 }), { maxItems: 10 })), priority: Type.Optional(Type.Integer({ minimum: 1, maximum: 5 })),
      repo: Type.Optional(Type.String({ minLength: 1, maxLength: 200 })),
    }, { additionalProperties: false });
export const PostHypothesesHidDecisionBody = Type.Object({
      action: Type.Union([Type.Literal('convert'), Type.Literal('dismiss')]), reason: Type.String({ minLength: 1, maxLength: 2000 }),
      severity: Type.Optional(Type.Union([Type.Literal('critical'), Type.Literal('high'), Type.Literal('medium'), Type.Literal('low')])),
    }, { additionalProperties: false });
export const PostVulnerabilitiesVidMatchDecisionBody = Type.Object({
      revision: Type.Optional(Type.Integer()), occurrenceId: Type.String({ minLength: 1, maxLength: 100 }),
      decision: Type.Enum(MATCH_DECISIONS), reason: Type.Optional(Type.String({ maxLength: 2000 })),
    }, { additionalProperties: false });
export const PostAuditsAidCoverageBackfillsBody = Type.Object({
      itemIds: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 100 }), { minItems: 1, maxItems: 500 })), all: Type.Optional(Type.Boolean()),
    }, { additionalProperties: false });
/** 追加执行: an optional analysis on a finished audit; hypothesisIds = verify these unverified hypotheses only. */
export const PostAuditsAidSupplementsBody = Type.Object({
      kind: Type.Union([Type.Literal('logic_review'), Type.Literal('threat_hypotheses'), Type.Literal('domains')], { description: 'threat_hypotheses = 风险假设先行；logic_review（已并入风险假设先行）按 threat_hypotheses 执行；domains = 专家阶段结束后新增的风险领域' }),
      hypothesisIds: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 100 }), { minItems: 1, maxItems: 500 })),
      domainIds: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 20 }), { minItems: 1, maxItems: 20 })),
    }, { additionalProperties: false });
export const PostReverificationsBody = Type.Object({
      vulnIds: Type.Array(Type.String({ minLength: 1, maxLength: 100 }), { minItems: 1, maxItems: 100 }),
      /** Version per repository id; default: the repository's default audit version. */
      refs: Type.Optional(Type.Record(Type.String(), Type.String({ minLength: 1, maxLength: 250 }))),
      /** Information the user supplies for pending vulnerabilities (answers to the condition). */
      note: Type.Optional(Type.String({ minLength: 1, maxLength: 4000 })),
    }, { additionalProperties: false });
export const PostVulnerabilitiesMergeBody = Type.Object({
      revision: Type.Optional(Type.Integer()), sourceIds: Type.Array(Type.String({ minLength: 1, maxLength: 100 }), { minItems: 1, maxItems: 50 }),
      targetId: Type.String({ minLength: 1, maxLength: 100 }), reason: Type.String({ minLength: 1, maxLength: 2000 }),
    }, { additionalProperties: false });
export const PostVulnerabilitiesVidSplitBody = Type.Object({
      revision: Type.Optional(Type.Integer()), entryKeys: Type.Optional(Type.Array(Type.String({ maxLength: 300 }), { maxItems: 100 })),
      fingerprints: Type.Optional(Type.Array(Type.String({ pattern: '^[0-9a-f]{64}$' }), { maxItems: 20 })), reason: Type.String({ minLength: 1, maxLength: 2000 }),
    }, { additionalProperties: false });
export const PostVulnerabilitiesVidIdentityUndoBody = Type.Object({
      revision: Type.Optional(Type.Integer()), revisionId: Type.String({ minLength: 1, maxLength: 100 }), reason: Type.Optional(Type.String({ maxLength: 2000 })),
    }, { additionalProperties: false });
export const PostVulnerabilitiesBatchUpdatesBody = Type.Object({
      items: Type.Array(Type.Object({ id: Type.String(), revision: Type.Integer() }, { additionalProperties: false }), { minItems: 1, maxItems: 200 }),
      /** batch confirm / false positive; at least one of confirmStatus and handlingStatus. */
      confirmStatus: Type.Optional(Type.Enum(CONFIRM_STATUSES)), handlingStatus: Type.Optional(Type.Enum(HANDLING_STATUSES)),
      reason: Type.Optional(Type.String({ maxLength: 2000, description: '整批共用的原因（误报、接受风险必填）' })), reviewMs: ReviewMs,
    }, { additionalProperties: false });

export const PatchProjectsPidTopologyBody = Type.Object({
  revision: Type.Optional(Type.Integer()),
  addNodes: Type.Optional(Type.Array(Type.Object({ name: Type.String({ minLength: 1, maxLength: 100 }), kind: Type.Enum(['external_service', 'service'] as const) }, { additionalProperties: false }), { maxItems: 50 })),
  addEdges: Type.Optional(Type.Array(Type.Object({
    from: Type.String({ minLength: 1, maxLength: 120, description: '节点 id，或同一请求中新增节点的 `new:<name>`' }), to: Type.String({ minLength: 1, maxLength: 120 }),
    kind: Type.Enum(['contract', 'client_call', 'message', 'shared_lib', 'frontend_api'] as const), protocol: Type.Enum(['http', 'grpc', 'dubbo', 'mq', 'gateway_route', 'shared_lib'] as const),
  }, { additionalProperties: false }), { maxItems: 100 })),
  removeEdges: Type.Optional(Type.Array(Type.String({ maxLength: 60 }), { maxItems: 200 })),
  restoreEdges: Type.Optional(Type.Array(Type.String({ maxLength: 60 }), { maxItems: 200 })),
}, { additionalProperties: false });
export const PostHuntBasesBody = Type.Object({
  kind: Type.Enum(['skill', 'prompt', 'intel'] as const, { description: 'report（V1.1）与 ticket（V1.2）暂不支持' }),
  skill: Type.Optional(Type.String({ minLength: 1, maxLength: 120 })), text: Type.Optional(Type.String({ minLength: 1, maxLength: 30_000 })),
}, { additionalProperties: false });
export const PatchHuntBasesBidBody = Type.Object({ revision: Type.Optional(Type.Integer()), basis: Type.Unknown({ description: 'HuntBasis（完整对象）' }) }, { additionalProperties: false });
export const PostHuntBasesBidSaveAsSkillBody = Type.Object({ name: Type.Optional(Type.String({ minLength: 2, maxLength: 64 })), category: Type.Enum(['vuln_case', 'audit_method'] as const) }, { additionalProperties: false });
export const PostHuntsBody = Type.Object({
  basisId: Type.String({ minLength: 1, maxLength: 60 }), projectIds: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 120 }), { maxItems: 200 })),
  allProjects: Type.Optional(Type.Boolean()), title: Type.Optional(Type.String({ minLength: 1, maxLength: 200 })),
}, { additionalProperties: false });
export const PostAuditConcurrencyBody = Type.Object({ sessions: Type.Integer({ minimum: 1, maximum: 16 }) }, { additionalProperties: false });
export const PatchHuntsHidBody = Type.Object({ title: Type.String({ minLength: 1, maxLength: 200 }) }, { additionalProperties: false });
export const PatchHuntTargetsTidBody = Type.Object({ verdict: Type.Enum(['affected', 'not_affected', 'pending'] as const), reason: Type.String({ minLength: 1, maxLength: 1000 }) }, { additionalProperties: false });

// Knowledge. The content hash the editor started from goes in `baseSha256` (or If-Match);
// null creates a new skill / sub-file.
const Sha = Type.String({ pattern: '^[0-9a-f]{64}$' });
export const PutSkillBody = Type.Object({
  text: Type.String({ maxLength: 256 * 1024 }), baseSha256: Type.Optional(Type.Union([Sha, Type.Null()])),
  form: Type.Optional(Type.Union([Type.Literal('file'), Type.Literal('dir')])),
}, { additionalProperties: false });
export const PutSkillFileBody = Type.Object({ text: Type.String({ maxLength: 256 * 1024 }), baseSha256: Type.Optional(Type.Union([Sha, Type.Null()])) }, { additionalProperties: false });
export const PutKnowledgeOverrideBody = Type.Object({ disabled: Type.Boolean() }, { additionalProperties: false });
export const PostKnowledgeDraftsBody = Type.Object({
  layer: Type.Union([Type.Literal('global'), Type.Literal('project')]), projectId: Type.Optional(Type.String({ maxLength: 100 })),
  kind: Type.Optional(Type.Union([Type.Literal('skill'), Type.Literal('case')])),
  /** Text to organize, or a complete skill file when `organize` is false. Omit with `questionId`. */
  text: Type.Optional(Type.String({ maxLength: 200_000 })),
  organize: Type.Optional(Type.Boolean()), name: Type.Optional(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' })),
  category: Type.Optional(Type.Union(['vuln_case', 'audit_method', 'report', 'business', 'architecture', 'push_guide', 'security_spec'].map((c) => Type.Literal(c)))),
  source: Type.Optional(Type.Object({
    kind: Type.Union([Type.Literal('manual'), Type.Literal('text'), Type.Literal('upload'), Type.Literal('connector'), Type.Literal('conversation')]), label: Type.Optional(Type.String({ maxLength: 200 })),
    /** connector: `<connectorId>:<operation>` (“从连接器存入”); conversation: the message id (会话回答). */
    ref: Type.Optional(Type.String({ maxLength: 300 })),
  }, { additionalProperties: false })),
  /** An answered Agent question (“从提问一键存草稿”). */
  questionId: Type.Optional(Type.String({ maxLength: 100 })),
}, { additionalProperties: false });
export const PutKnowledgeDraftBody = Type.Object({ text: Type.String({ maxLength: 256 * 1024 }), name: Type.Optional(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' })), revision: Type.Integer({ minimum: 1 }) }, { additionalProperties: false });
export const PostKnowledgeDraftApproveBody = Type.Object({ replace: Type.Optional(Type.Boolean()), afterMove: Type.Optional(Type.Union([Type.Literal('delete'), Type.Literal('keep')])) }, { additionalProperties: false });
export const PostDistillCaseBody = Type.Object({ layer: Type.Union([Type.Literal('global'), Type.Literal('project')]) }, { additionalProperties: false });
export const PostMoveToGlobalBody = Type.Object({ confirm: Type.Optional(Type.Boolean()), text: Type.Optional(Type.String({ maxLength: 256 * 1024 })) }, { additionalProperties: false });

// Connectors. Credentials are never part of the configuration: reference them as
// `${secret:name}` and set the values through `secrets` (write-only).
const ConnectorConfigBody = Type.Object({
  command: Type.Optional(Type.Object({
    path: Type.String({ minLength: 1, maxLength: 1024 }), args: Type.Array(Type.String({ maxLength: 2048 }), { maxItems: 50 }),
    env: Type.Record(Type.String({ maxLength: 128 }), Type.String({ maxLength: 4096 })),
  }, { additionalProperties: false })),
  url: Type.Optional(Type.String({ maxLength: 2048 })),
  headers: Type.Optional(Type.Record(Type.String({ maxLength: 128 }), Type.String({ maxLength: 4096 }))),
  concurrency: Type.Optional(Type.Integer({ minimum: 1, maximum: 8 })),
  timeouts: Type.Optional(Type.Object({ callMs: Type.Optional(Type.Integer({ minimum: 1000, maximum: 300_000 })) }, { additionalProperties: false })),
  pack: Type.Optional(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' })), base_url: Type.Optional(Type.String({ maxLength: 500 })),
  variables: Type.Optional(Type.Record(Type.String({ maxLength: 64 }), Type.String({ maxLength: 500 }))), interpreter_path: Type.Optional(Type.String({ maxLength: 1024 })), program_path: Type.Optional(Type.String({ maxLength: 1024 })),
}, { additionalProperties: false });
export const PostConnectorsBody = Type.Object({
  name: Type.String({ minLength: 1, maxLength: 100 }), protocol: Type.Union([Type.Literal('mcp_stdio'), Type.Literal('mcp_http'), Type.Literal('http')]),
  config: ConnectorConfigBody, authoritative: Type.Optional(Type.Boolean()), purpose: Type.Optional(Type.Union([Type.Literal('context'), Type.Literal('sync')], { description: '已废弃：读写由工具声明决定，忽略' })), allowWrite: Type.Optional(Type.Boolean({ description: '已废弃：忽略' })),
}, { additionalProperties: false });
export const PatchConnectorsIdBody = Type.Object({
  name: Type.Optional(Type.String({ minLength: 1, maxLength: 100 })), purpose: Type.Optional(Type.Union([Type.Literal('context'), Type.Literal('sync')], { description: '已废弃：读写由工具声明决定，忽略' })),
  config: Type.Optional(ConnectorConfigBody), allowWrite: Type.Optional(Type.Boolean({ description: '已废弃：忽略' })), authoritative: Type.Optional(Type.Boolean()), enabled: Type.Optional(Type.Boolean()),
  /** Write-only: a value sets the secret, null removes it. */
  secrets: Type.Optional(Type.Record(Type.String({ pattern: '^[A-Za-z0-9_.-]{1,64}$' }), Type.Union([Type.String({ maxLength: 8192 }), Type.Null()]))),
  /** Connector packs: offer a read operation to the Agent (MCP connectors offer every tool). */
  tools: Type.Optional(Type.Array(Type.Object({ name: Type.String({ maxLength: 128 }), exposed: Type.Boolean() }, { additionalProperties: false }), { maxItems: 500 })),
}, { additionalProperties: false });
export const PostConnectorsIdConfirmCommandBody = Type.Object({ commandHash: Type.String({ pattern: '^[0-9a-f]{64}$' }) }, { additionalProperties: false });
/** approve or reject a held connector call; the note is kept with the decision. */
export const PostConnectorWritesIdDecisionBody = Type.Object({ note: Type.Optional(Type.String({ maxLength: 500 })) }, { additionalProperties: false });
export const PostConnectorsIdQueryBody = Type.Object({
  tool: Type.String({ maxLength: 128 }), args: Type.Record(Type.String(), Type.Unknown()),
  /** Context of the query (a pending vulnerability), for the call log. */
  vulnId: Type.Optional(Type.String({ maxLength: 100 })),
}, { additionalProperties: false });
export const PutProjectsPidConnectorsBody = Type.Object({ connectorIds: Type.Array(Type.String({ maxLength: 64 }), { maxItems: 50 }) }, { additionalProperties: false });
export const PostProjectsPidArchitectureImportsBody = Type.Object({
  text: Type.String({ minLength: 1, maxLength: 200_000 }), label: Type.Optional(Type.String({ maxLength: 200 })),
}, { additionalProperties: false });
export const PutConnectorPackFileBody = Type.Object({ text: Type.String({ maxLength: 256 * 1024 }), baseSha256: Type.Union([Type.String({ pattern: '^[0-9a-f]{64}$' }), Type.Null()]) }, { additionalProperties: false });
export const PostConnectorPackDraftsBody = Type.Object({
  openapi: Type.String({ minLength: 1, maxLength: 500_000 }), name: Type.Optional(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' })), focus: Type.Optional(Type.String({ maxLength: 500 })),
}, { additionalProperties: false });
export const PostProjectsPidPushesBody = Type.Object({
  skill: Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' }), vulnIds: Type.Array(Type.String({ maxLength: 64 }), { minItems: 1, maxItems: 50 }),
  /** Always return a preview to confirm, even when the guide would push at once. */
  preview: Type.Optional(Type.Boolean()),
}, { additionalProperties: false });
/** link a vulnerability to an existing external record. */
export const PutVulnerabilitiesVidSyncBody = Type.Object({
  connectorId: Type.String({ maxLength: 64 }), externalId: Type.String({ minLength: 1, maxLength: 200 }), externalUrl: Type.Optional(Type.Union([Type.String({ maxLength: 1000 }), Type.Null()])),
}, { additionalProperties: false });
export const PostPushesIdConfirmBody = Type.Object({ token: Type.String({ pattern: '^[0-9a-f]{48}$' }), payloadHash: Type.String({ pattern: '^[0-9a-f]{64}$' }) }, { additionalProperties: false });

// Conversations.
export { PostConversationsBody, PatchConversationBody, PostMessagesBody, EditMessageBody, PostCardApplyBody } from '@xiezhi/contracts';

// ---- requirement threat models ----
export const PostThreatModelBody = Type.Object({ title: Type.String({ minLength: 1, maxLength: 200 }) }, { additionalProperties: false });
export const PatchThreatModelBody = Type.Object({
  title: Type.Optional(Type.String({ minLength: 1, maxLength: 200 })),
  clarified: Type.Optional(Type.Boolean({ description: 'true: a person confirmed the clarification; false: back to unconfirmed' })),
}, { additionalProperties: false });
/** One source; uploads are read in the browser and sent as text (Markdown / plain text only). */
export const PostThreatSourceBody = Type.Union([
  Type.Object({ kind: Type.Literal('upload'), title: Type.String({ minLength: 1, maxLength: 200 }), content: Type.String({ maxLength: THREAT_SOURCE_MAX_BYTES }), note: Type.Optional(Type.String({ maxLength: 1000 })) }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal('text'), title: Type.Optional(Type.String({ maxLength: 200 })), text: Type.String({ maxLength: THREAT_SOURCE_MAX_BYTES }), note: Type.Optional(Type.String({ maxLength: 1000 })) }, { additionalProperties: false }),
  Type.Object({ kind: Type.Literal('online'), title: Type.String({ minLength: 1, maxLength: 200 }), connectorId: Type.String({ minLength: 1, maxLength: 100 }), docRef: Type.String({ minLength: 1, maxLength: 2000 }), note: Type.Optional(Type.String({ maxLength: 1000 })) }, { additionalProperties: false }),
]);
export const PatchThreatSourceBody = Type.Object({
  title: Type.Optional(Type.String({ minLength: 1, maxLength: 200 })), note: Type.Optional(Type.Union([Type.String({ maxLength: 1000 }), Type.Null()])),
  text: Type.Optional(Type.String({ maxLength: THREAT_SOURCE_MAX_BYTES })), connectorId: Type.Optional(Type.String({ minLength: 1, maxLength: 100 })),
  docRef: Type.Optional(Type.String({ minLength: 1, maxLength: 2000 })), injectionAck: Type.Optional(Type.Literal(true)),
}, { additionalProperties: false });
export const PutThreatSourceOrderBody = Type.Object({ ids: Type.Array(Type.String({ minLength: 1, maxLength: 100 }), { maxItems: 10_000 }) }, { additionalProperties: false });
export const PostThreatGenerateBody = Type.Object({
  model: Type.Optional(ModelRef), tokenLimit: Type.Optional(Type.Integer({ minimum: 10_000, maximum: 5_000_000 })),
}, { additionalProperties: false });
export const PatchThreatRiskBody = Type.Object({
  status: Type.Enum(THREAT_RISK_STATUSES), reason: Type.Optional(Type.Union([Type.String({ maxLength: 2000 }), Type.Null()])),
}, { additionalProperties: false });
export const PatchThreatRisksBody = Type.Object({
  ids: Type.Array(Type.String({ minLength: 1, maxLength: 100 }), { minItems: 1, maxItems: 500 }), status: Type.Enum(THREAT_RISK_STATUSES),
  reason: Type.Optional(Type.Union([Type.String({ maxLength: 2000 }), Type.Null()])),
}, { additionalProperties: false });
export const PostThreatSyncBody = Type.Object({
  skill: Type.Optional(Type.String({ minLength: 1, maxLength: 64 })),
  /** write into this existing document (link or ID) instead of creating one. */
  document: Type.Optional(Type.String({ minLength: 1, maxLength: 2000 })),
}, { additionalProperties: false });
export const PostThreatSyncConfirmBody = Type.Object({ token: Type.String({ minLength: 1, maxLength: 200 }), payloadHash: Type.String({ minLength: 1, maxLength: 200 }) }, { additionalProperties: false });
/** import an MCP server configured in another tool. */
export const PostConnectorImportsBody = Type.Object({
  candidate: Type.String({ minLength: 1, maxLength: 300 }), name: Type.Optional(Type.String({ minLength: 1, maxLength: 100 })),
  purpose: Type.Optional(Type.Union([Type.Literal('context'), Type.Literal('sync')], { description: '已废弃：读写由工具声明决定，忽略' })), allowWrite: Type.Optional(Type.Boolean({ description: '已废弃：忽略' })),
  secrets: Type.Optional(Type.Record(Type.String({ pattern: '^[A-Za-z0-9_.-]{1,64}$' }), Type.Union([Type.Literal('import'), Type.Literal('blank'), Type.Literal('drop')]))),
  extraArgs: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 2000 }), { maxItems: 20 })),
}, { additionalProperties: false });

/** one edit of an audit's domain plan. */
export { DomainPlanEditBody as PostAuditsAidDomainPlanEditsBody } from '@xiezhi/contracts';

/** a SARIF 2.1.0 log (text). */
export const PostExternalResultsBody = Type.Object({ sarif: Type.String({ minLength: 2, maxLength: 32 * 1024 * 1024 }) }, { additionalProperties: false });
