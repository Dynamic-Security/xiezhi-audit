// HTTP API contract. Error-code → status mapping and the TypeBox schemas of every
// request/response DTO. The server attaches these as Fastify route schemas: responses are serialized
// through them (only declared fields leave the process) and `openapi.json` is generated
// from them. Web and CLI use the Static types (web: `import type` only).
import { Type, type Static, type TSchema } from 'typebox';
import type { ErrorCode } from './errors.js';
import {
  AUDIT_STATUSES, CONFIDENCES, CONFIRM_STATUSES, HANDLING_STATUSES, LIFECYCLES, PARTIAL_REASONS,
  SCENES, SEVERITIES, STEP_STATUSES, THREAT_FETCH_STATUSES, THREAT_MODEL_STATUSES, THREAT_RISK_LEVELS,
  THREAT_RISK_STATUSES, THREAT_SOURCE_KINDS, FACT_TOPICS, FACT_SOURCES, FACT_TRUST, FACT_SENSITIVITY, FACT_STATUSES, closedSet, type AuditStatus, type StepStatus,
} from './enums.js';
import { EVENT_TYPES, type EventType } from './events.js';
import { AuditStrategy, BUDGET_STAGES, ModelRef } from './strategy.js';
import { RepoSignals } from './context.js';
import { StageModelsConfig, ToolsConfig } from './config.js';
import { PendingCondition } from './submit.js';
import { HuntBasis } from './hunt.js';
import { VULN_CATEGORIES } from './categories.js';
import { STAGE_IDS } from './stages.js';

export const API_PREFIX = '/api/v1';

/** HTTP status per error code. */
export const ERROR_HTTP_STATUS: Record<ErrorCode, number> = {
  CONFIG_INVALID: 422, STRATEGY_INVALID: 422, PROJECT_NOT_FOUND: 404, PROJECT_EXISTS: 409, REPOSITORY_NOT_FOUND: 404,
  REPOSITORY_EXISTS: 409, AUDIT_NOT_FOUND: 404, AUDIT_NOT_RESUMABLE: 409, AUDIT_TERMINAL: 409, INVALID_TRANSITION: 409,
  SNAPSHOT_FAILED: 422, LOCK_HELD: 409, MODEL_NOT_CONFIGURED: 422, CREDENTIAL_BINDING_MISMATCH: 422, SECRET_ON_COMMAND_LINE: 400,
  ARTIFACT_CORRUPT: 500, EXPORT_FAILED: 500, INTERNAL: 500,
  COMMON_VALIDATION: 400, COMMON_NOT_FOUND: 404, COMMON_REVISION_CONFLICT: 412, COMMON_IDEMPOTENCY_KEY_REUSED: 422,
  COMMON_PRECONDITION_REQUIRED: 428, AUTH_SESSION_REQUIRED: 401, AUTH_ORIGIN_REJECTED: 403, AUTH_HOST_REJECTED: 421,
  AUTH_BOOTSTRAP_EXPIRED: 401, AUTH_CSRF_INVALID: 403, AUDIT_INVALID_TRANSITION: 409, AUDIT_PLAN_NOT_READY: 409,
  QUESTION_NOT_FOUND: 404, QUESTION_CLOSED: 409, VULN_NOT_FOUND: 404, VULN_EVIDENCE_INCOMPLETE: 409, VULN_REASON_REQUIRED: 422,
  SOURCE_NOT_IN_MANIFEST: 404, EXPORT_FORMAT_UNSUPPORTED: 400, EXPORT_NOT_FOUND: 404, MODEL_UNREACHABLE: 502,
  PROVIDER_NOT_FOUND: 404, REPO_REF_NOT_FOUND: 422, SERVER_NOT_RUNNING: 503, AUDIT_BASELINE_UNAVAILABLE: 422, VULN_MERGE_CROSS_PROJECT: 422,
  REPO_UNREACHABLE: 422, REPO_AUTH_FAILED: 422, UPLOAD_NOT_FOUND: 404, UPLOAD_TOO_LARGE: 413, ARCHIVE_REJECTED: 422,
  KNOWLEDGE_INVALID: 422, KNOWLEDGE_EXISTS: 409, KNOWLEDGE_PATH_INVALID: 400,
  CONVERSATION_NOT_FOUND: 404, MESSAGE_NOT_FOUND: 404, MESSAGE_BUSY: 409, CARD_NOT_FOUND: 404, CARD_NOT_PENDING: 409, HYPOTHESIS_NOT_FOUND: 404, HYPOTHESIS_DECIDED: 409,
  THREAT_MODEL_NOT_FOUND: 404, THREAT_MODEL_BUSY: 409, THREAT_SOURCE_NOT_FOUND: 404, THREAT_RISK_NOT_FOUND: 404, THREAT_REASON_REQUIRED: 422,
  PROVIDER_IN_USE: 409,
};

const O = <P extends Record<string, TSchema>>(props: P) => Type.Object(props, { additionalProperties: false });
const Nullable = <S extends TSchema>(s: S) => Type.Union([s, Type.Null()]);
const Str = Type.String();
const NStr = Nullable(Type.String());
const Int = Type.Integer();
const Num = Type.Number();
const Bool = Type.Boolean();
const Iso = Type.String({ description: 'ISO 8601 UTC timestamp' });
const NIso = Nullable(Iso);
const StrRecord = Type.Record(Type.String(), Type.String());
const NumRecord = Type.Record(Type.String(), Type.Number());
const AnyRecord = Type.Record(Type.String(), Type.Unknown());

export const ApiErrorBody = O({
  error: O({ code: Str, message: Str, hint: Type.Optional(Str), details: Type.Optional(AnyRecord), requestId: Str }),
});
export type ApiErrorBody = { error: { code: ErrorCode; message: string; hint?: string; details?: Record<string, unknown>; requestId: string } };

export interface Page<T> { items: T[]; nextCursor: string | null; totalEstimate: number }
export const PageOf = <S extends TSchema>(item: S) => O({ items: Type.Array(item), nextCursor: NStr, totalEstimate: Int });

// ---- session ------------------------------------------------------------------------------------------
export const SessionInfo = O({ authenticated: Bool, csrfToken: NStr, version: Str, dataDir: Str });
export type SessionInfo = Static<typeof SessionInfo>;
export const HealthInfo = O({ status: Type.Literal('ok'), version: Str, dataDirWritable: Bool, lockHolder: Nullable(O({ pid: Int, role: Str })), piVersion: Str });
export type HealthInfo = Static<typeof HealthInfo>;
/** `<data-dir>/run/api.json` — a file, not an HTTP response. */
export interface ServiceDiscovery { port: number; pid: number; token: string; startedAt: number; version: string }

// ---- projects / repos --------------------------------------------------------------------------------------
export const SeverityCounts = O(Object.fromEntries(SEVERITIES.map((s) => [s, Int])) as Record<(typeof SEVERITIES)[number], typeof Int>);
export type SeverityCounts = Static<typeof SeverityCounts>;
export const ProjectDto = O({
  id: Str, name: Str, status: closedSet(['active', 'archived'] as const), createdAt: Iso, repoCount: Int, openVulns: SeverityCounts,
  lastAudit: Nullable(O({ id: Str, status: closedSet(AUDIT_STATUSES), endedAt: NIso })),
  /** 项目风险概况“覆盖是否完整”: the latest finished audit with coverage comparison (backfills merged). */
  coverage: Nullable(O({ auditId: Str, entry: O({ total: Int, reviewed: Int }), sink: O({ total: Int, reviewed: Int }), complete: Bool })),
  /** how far the project's services trust each other — the setting (null = inferred) and what is in force. */
  internalTrust: O({ setting: Nullable(closedSet(['zero_trust', 'gateway_boundary', 'trusted_network'] as const)), effective: closedSet(['zero_trust', 'gateway_boundary', 'trusted_network', 'monolith'] as const), reason: Str }),
});
export type ProjectDto = Static<typeof ProjectDto>;
export const RepoDto = O({
  id: Str, projectId: Str, name: Str, sourceKind: closedSet(['local', 'git', 'archive'] as const), locator: Str, defaultRef: NStr,
  languages: Type.Array(Str), role: Str, auditable: Bool, createdAt: Iso,
  lastSnapshot: Nullable(O({ commit: NStr, ref: NStr, worktree: Bool, auditId: Str })),
  /** Archive: file name, root hash of its fixed snapshot, embedded HEAD (display only). Remote: default branch. */
  sourceDetail: O({ fileName: NStr, rootHash: NStr, headCommit: NStr, defaultBranch: NStr }),
  roleSource: closedSet(['ai', 'user'] as const),
  /**
   * `auditable` is the effective value; `auditableSource` says whether it follows the automatic
   * judgement (`auto`) or a user setting (`user`); `auditableAuto` / `auditableReason` are the automatic judgement and,
   * when it is “context only”, why (e.g. a JS / TS repository without a server-side framework dependency).
   */
  auditableSource: closedSet(['auto', 'user'] as const),
  auditableAuto: Bool,
  auditableReason: NStr,
  /** Roles from the latest AI analysis, most confident first; empty until analyzed. */
  aiRoles: Type.Array(O({ role: Str, confidence: Type.Number() })),
});
export type RepoDto = Static<typeof RepoDto>;
export const RefDto = O({ kind: closedSet(['branch', 'tag', 'commit'] as const), name: Str, commit: Str, subject: Str, author: Str, date: NStr });
export type RefDto = Static<typeof RefDto>;
/**
 * Native folder picker: the service opens the system dialog on its own machine. `unavailable` =
 * no dialog there (no desktop session, or Linux without zenity / kdialog); `reason` says why.
 */
export const DirectoryPickDto = O({ status: closedSet(['picked', 'cancelled', 'unavailable'] as const), path: NStr, reason: NStr });
export type DirectoryPickDto = Static<typeof DirectoryPickDto>;
/**
 * Pre-add probe (`/repo-probes`). `ok` = the source can be added. Local directories fill
 * exists/isDirectory/hasGit/…; remote Git fills `remote`; uploaded archives fill `archive`.
 */
export const RepoProbeDto = O({
  sourceKind: closedSet(['local', 'git', 'archive'] as const), ok: Bool,
  path: Str, exists: Bool, isDirectory: Bool, hasGit: Bool, currentBranch: NStr, headCommit: NStr, dirty: Nullable(Bool),
  languages: NumRecord, auditable: Bool, suggestedName: Str, problems: Type.Array(Str), refs: Type.Array(RefDto),
  remote: Nullable(O({ url: Str, defaultBranch: NStr, refs: Type.Array(RefDto), errorCode: NStr, suggestions: Type.Array(Str) })),
  archive: Nullable(O({ uploadId: Str, fileName: Str, format: Str, fileCount: Int, totalBytes: Int })),
});
export type RepoProbeDto = Static<typeof RepoProbeDto>;
export const UploadDto = O({ uploadId: Str, fileName: Str, size: Int, expiresAt: Iso });
export type UploadDto = Static<typeof UploadDto>;
export const AddReposResult = O({
  results: Type.Array(O({ ok: Bool, repo: Type.Optional(RepoDto), path: Type.Optional(Str), error: Type.Optional(O({ code: Str, hint: NStr })) })),
});
const RoleEvidence = O({ signal: Str, path: Type.Optional(Str), count: Type.Optional(Int) });
export const RepoAnalysisDto = O({
  repositoryId: Str, name: Str, status: closedSet(['succeeded', 'reused', 'skipped', 'failed'] as const), rootHash: NStr, error: NStr,
  roles: Type.Array(O({ role: Str, confidence: Type.Number(), evidence: Type.Array(RoleEvidence) })), rationale: NStr,
  signals: Nullable(RepoSignals),
});
export type RepoAnalysisDto = Static<typeof RepoAnalysisDto>;
/** Project analysis run (`/projects/{pid}/analyze`: repository roles). */
export const AnalysisDto = O({
  id: Str, status: closedSet(['running', 'succeeded', 'partial', 'failed', 'interrupted'] as const), reason: NStr, model: NStr,
  startedAt: Iso, endedAt: NIso, tokens: O({ input: Int, output: Int }), costMicros: Nullable(Int), repos: Type.Array(RepoAnalysisDto),
});
export type AnalysisDto = Static<typeof AnalysisDto>;
export const ProjectAnalysisDto = O({ analysis: Nullable(AnalysisDto) });
// ---- topology ----
const EdgeSite = O({ repo: Str, path: Str, line: Int, ruleId: Str, key: Type.Record(Str, Type.Union([Str, Int])) });
export const TopologyNodeDto = O({
  id: Str, kind: closedSet(['repo', 'service', 'external_service', 'gateway', 'mq_topic'] as const), name: Str, repositoryId: NStr, role: NStr,
  origin: closedSet(['ai', 'imported', 'user'] as const),
});
export const TopologyEdgeDto = O({
  id: Str, from: Str, to: Str, kind: closedSet(['contract', 'client_call', 'message', 'shared_lib', 'frontend_api'] as const),
  protocol: closedSet(['http', 'grpc', 'dubbo', 'mq', 'gateway_route', 'shared_lib'] as const), origin: closedSet(['ai', 'imported', 'user'] as const),
  confidence: closedSet(['confirmed', 'inferred'] as const), removed: Bool,
  evidence: Type.Array(O({ consumer: Nullable(EdgeSite), provider: Nullable(EdgeSite), confidence: Str, reason: Str, source: Type.Optional(Str) })),
});
export const TopologyDto = O({ projectId: Str, revision: Int, nodes: Type.Array(TopologyNodeDto), edges: Type.Array(TopologyEdgeDto) });
export type TopologyDto = Static<typeof TopologyDto>;
export type TopologyEdgeDto = Static<typeof TopologyEdgeDto>;
export type TopologyNodeDto = Static<typeof TopologyNodeDto>;
export const GitCredentialDto = O({ host: Str, username: Str, token: O({ configured: Bool, hint: Type.Optional(Str) }) });
export type GitCredentialDto = Static<typeof GitCredentialDto>;

// ---- audits -------------------------------------------------------------------------------------------------
export const AUDIT_PHASES = ['planning', 'awaiting_confirm', 'queued', 'preparing', 'analyzing', 'verifying', 'reporting', 'done'] as const;
/** Display phase derived from status + steps; never a fake percentage. */
export type AuditPhase = (typeof AUDIT_PHASES)[number];
export const BudgetDto = O({ tokens: Int, durationMs: Int, costMicros: Nullable(Int) });
export type BudgetDto = Static<typeof BudgetDto>;
const ROLE_IN_AUDIT = closedSet(['target', 'related', 'context'] as const);
const AuditRepoRef = O({ id: Str, name: Str, ref: NStr, commit: NStr, worktree: Bool, roleInAudit: ROLE_IN_AUDIT });
const auditSummaryProps = {
  id: Str, projectId: Str, projectName: Str, title: Str, scene: closedSet(SCENES), mode: closedSet(['single', 'multi'] as const),
  status: closedSet(AUDIT_STATUSES), phase: closedSet(AUDIT_PHASES), partialReasons: Type.Array(closedSet(PARTIAL_REASONS)), errorClass: NStr, origin: Str,
  createdAt: Iso, startedAt: NIso, endedAt: NIso,
  budget: O({
    effective: BudgetDto, consumed: BudgetDto,
    /** stage quotas and their usage in tokens; absent for audits without stage quotas. */
    /**
     * `stopped`: a step of this stage waits because the stage quota cannot hold it; `suggestedTopUp`: what
     * that stage needs to finish its steps not run yet.
     */
    stages: Type.Optional(Type.Array(O({ stage: closedSet(BUDGET_STAGES), limit: Int, consumed: Int, stopped: Bool, suggestedTopUp: Type.Optional(Int) }))),
    /** While waiting for budget: the tokens to add so the audit can finish. */
    suggestedTopUp: Type.Optional(Int),
  }),
  repos: Type.Array(AuditRepoRef), findingCount: Int, openQuestions: Int,
  /** The conversation the audit lives in; null until one is needed. */
  conversationId: NStr,
};
export const AuditSummaryDto = O(auditSummaryProps);
export type AuditSummaryDto = Static<typeof AuditSummaryDto>;
export const StepDto = O({
  id: Str, seq: Int, kind: Str, lineage: NStr, status: closedSet(STEP_STATUSES), attempt: Int, maxAttempts: Int, model: NStr,
  tokensIn: Int, tokensOut: Int, costMicros: Nullable(Int), errorClass: NStr, errorSummary: NStr, startedAt: NIso, endedAt: NIso,
});
export type StepDto = Static<typeof StepDto>;
/** What a content filter refused — the step's model, the provider's reply and the last messages sent before it. */
export const FilteredStepDto = O({
  stepId: Str, lineage: NStr, model: NStr, attempt: Int, error: NStr,
  reply: Nullable(O({ text: Str, model: NStr, stopReason: NStr, errorMessage: NStr })),
  /** Oldest first; `text` is cut, `chars` is the full length. */
  request: Type.Array(O({ role: Str, text: Str, chars: Int })),
});
export type FilteredStepDto = Static<typeof FilteredStepDto>;
// ---- execution overview ----
/** Phases of the overview, in display order. */
export const EXECUTION_PHASES = ['prepare', 'triage', 'hunt', 'explore', 'challenge', 'verify', 'risk', 'finalize'] as const;
/** Finer job segments of the trajectory status bar, in pipeline order. */
export const EXECUTION_SEGMENTS = ['snapshot', 'index', 'plan', 'profile', 'scope', 'threat', 'triage', 'hunt', 'external', 'checklist', 'recheck', 'explore', 'challenge', 'verify', 'locate', 'judge', 'finalize'] as const;
export const CANDIDATE_STATUSES = ['pending', 'investigating', 'finding', 'suspicious', 'no_issue', 'ruled_out', 'unreviewed'] as const;
export const ExecCandidateDto = O({
  id: Str, kind: Str, repo: Str, path: Str, line: Int, label: Str, reason: NStr, score: Nullable(Num),
  /** Settled verdict once the step's submission was accepted; before that the Agent's last mark (`preliminary`). */
  status: closedSet(CANDIDATE_STATUSES), preliminary: Bool, note: NStr, changedFrom: NStr,
});
export type ExecCandidateDto = Static<typeof ExecCandidateDto>;
export const ExecAgentDto = O({
  id: Str, role: closedSet(['main', 'task'] as const), parent: NStr, goal: NStr,
  status: closedSet(['running', 'completed', 'failed', 'interrupted'] as const),
  /** What a running agent waits for: a session slot of the audit, the global model gate, or the user's answer. */
  waiting: Nullable(closedSet(['slot', 'model', 'question'] as const)),
  lastTool: Nullable(O({ tool: Str, args: Type.Unknown(), at: Iso })),
  turns: Int, tokens: Int, startedAt: Iso, endedAt: NIso,
});
export type ExecAgentDto = Static<typeof ExecAgentDto>;
export const ExecStepDto = O({
  id: Str, kind: Str, lineage: NStr, status: closedSet(STEP_STATUSES), startedAt: NIso, endedAt: NIso, tokens: Int, repo: NStr,
  /** What a step without candidates works on: the finding challenged or reviewed, the vulnerability reverified. */
  subject: NStr,
  /** The job segment of the status bar the step belongs to. */
  segment: closedSet(EXECUTION_SEGMENTS),
  /** The model the step runs with (`provider/model`, after a fallback switch) and the switch, if any. */
  model: NStr,
  /**
   * `manual`: the user chose the model (“切换模型重试”) rather than the configured fallback; `later`: the
   * step was not refused itself — it would have run on a refused model and the user chose another for every later step.
   */
  fallback: Nullable(O({ from: Str, reason: Str, degraded: Bool, manual: Bool, later: Bool })),
  candidates: Type.Array(ExecCandidateDto), agents: Type.Array(ExecAgentDto),
});
export type ExecStepDto = Static<typeof ExecStepDto>;
export const ExecutionDto = O({
  auditId: Str, status: Str,
  phases: Type.Array(O({ key: closedSet(EXECUTION_PHASES), steps: Type.Array(ExecStepDto) })),
  concurrency: O({
    /** Agent sessions of this audit (sub-agents included) against its limit; sessions waiting for a slot. */
    sessions: O({ running: Int, limit: Int, queued: Int }),
    /** Model requests of the whole process against `concurrency.modelRequests` (live values). */
    model: O({ active: Int, queued: Int, capacity: Int }),
  }),
  counts: O({ running: Int, waiting: Int, done: Int, total: Int }),
  /** Segments this audit goes through (scene and strategy; ones already run included), in order. */
  segments: Type.Array(closedSet(EXECUTION_SEGMENTS)),
  /** The plan's median estimate, for overall progress and the remaining time (null without a plan estimate). */
  estimate: O({ tokens: Nullable(Int), durationSec: Nullable(Int) }),
});
export type ExecutionDto = Static<typeof ExecutionDto>;

const CoverageCount = O({ total: Int, reviewed: Int });
export const GateDto = O({
  status: closedSet(['completed', 'partial', 'failed'] as const), partialReasons: Type.Array(closedSet(PARTIAL_REASONS)),
  checks: Type.Array(O({ name: Str, ok: Bool, detail: Str })), coverage: Nullable(O({ entry: CoverageCount, sink: CoverageCount })),
  /** problems that no longer make the audit partial (a few failed reviews, failed deep exploration, LSP fallback). */
  notices: Type.Optional(Type.Array(Str)),
});
export type GateDto = Static<typeof GateDto>;
/** One target of a reverification audit and its verdict; null verdict = not reached yet. */
export const ReverifyItemDto = O({
  vulnId: Str, displayNo: Int, title: Str, severity: closedSet(SEVERITIES), category: Str,
  verdict: Nullable(closedSet(['fixed', 'still_present', 'partially_fixed', 'undetermined'] as const)),
  lifecycleBefore: Nullable(closedSet(LIFECYCLES)), lifecycleAfter: Nullable(closedSet(LIFECYCLES)), reasoning: NStr,
});
export type ReverifyItemDto = Static<typeof ReverifyItemDto>;
export const AuditDetailDto = O({
  ...auditSummaryProps, strategyHash: NStr, steps: Type.Array(StepDto), gate: Nullable(GateDto), lastEventSeq: Int,
  /** Reverification audits: targets and verdicts; null for other scenes. */
  reverify: Nullable(Type.Array(ReverifyItemDto)),
  exports: O({ md: Bool, json: Bool, sarif: Bool }),
  /** Every model (`provider/model`) a content filter refused in this audit, a refused fallback model included. */
  filteredModels: Type.Array(Str),
  /** “切换模型重试 · 之后所有步骤” — later steps that would run on `from` run on `to`. */
  modelSwitches: Type.Array(O({ from: Str, to: ModelRef })),
});
export type AuditDetailDto = Static<typeof AuditDetailDto>;
const Range2 = O({ p50: Num, p90: Num });
/** Incremental audits: baseline and change summary shown with the plan. */
const IncrementalBase = O({ auditId: NStr, ref: NStr, commit: NStr, rootHash: Str, worktree: Bool });
const incrementalChange = {
  mode: closedSet(['precise', 'heuristic', 'full_scan'] as const),
  fallbackReasons: Type.Array(Str),
  changedFiles: O({ added: Int, modified: Int, deleted: Int, renamed: Int }),
  changedSymbols: Int, affectedEntrypoints: Int, affectedSinks: Int,
};
/**
 * Multi-repository incremental audits: the top level sums the targets (mode = the least precise, base = the
 * first target with a baseline) and `repos` has each target; `base` is null for a target audited in full without one.
 */
export const IncrementalSummaryDto = O({
  base: IncrementalBase,
  ...incrementalChange,
  repos: Type.Optional(Type.Array(O({ repo: Str, base: Nullable(IncrementalBase), ...incrementalChange }))),
});
export type IncrementalSummaryDto = Static<typeof IncrementalSummaryDto>;
export const PlanDto = O({
  auditId: Str, status: closedSet(AUDIT_STATUSES), revision: Int, scene: closedSet(SCENES),
  plan: Nullable(O({
    summary: Str, focusDirections: Type.Array(O({ direction: Str, reason: Str })), plannedKnowledge: Type.Array(O({ skill: Str, reason: Str })),
    contextNeeded: Type.Array(Str), limitations: Type.Array(Str),
    scale: O({ files: Int, byLang: NumRecord, entrypoints: Int, sinks: Int, candidates: Int, sinksByCategory: NumRecord }),
    estimate: O({
      tokens: Range2, durationSec: Range2, cost: Nullable(O({ p50: Num, p90: Num, currency: Str })),
      /** each stage's share of the median tokens, in pipeline order; `switch` names the strategy switch that turns it off. */
      stages: Type.Optional(Type.Array(O({ stage: closedSet(STAGE_IDS), label: Str, tokens: Int, switch: NStr }))),
    }),
    knowledge: Type.Array(Str),
    incremental: Nullable(IncrementalSummaryDto),
  })),
  strategy: AuditStrategy, strategySources: StrRecord,
  mode: closedSet(['single', 'multi'] as const),
  /** `dirty`: the working-tree version had uncommitted changes (a hint; absent when unknown). */
  repos: Type.Array(O({ id: Str, name: Str, ref: NStr, commit: NStr, worktree: Bool, rootHash: NStr, roleInAudit: ROLE_IN_AUDIT, dirty: Type.Optional(Bool) })),
});
export type PlanDto = Static<typeof PlanDto>;
export const PlanCreated = O({ auditId: Str, planId: Str, status: Type.Literal('planning') });
export const QuestionDto = O({
  id: Str, auditId: Str, text: Str, blocking: Bool, status: closedSet(['open', 'answered', 'dismissed', 'expired'] as const), answer: NStr,
  /** an answered question can be saved as project knowledge (offered → saved / declined). */
  saveAsSkill: closedSet(['none', 'offered', 'saved', 'declined'] as const),
  /** a plan-context question — its answer becomes an enterprise fact of the project. */
  asFact: Bool,
  /** Suggested answers the agent offered with the question (empty for none and for older questions). */
  options: Type.Array(Str),
  createdAt: Iso, answeredAt: NIso,
});
export type QuestionDto = Static<typeof QuestionDto>;
export const INTERVENTION_KINDS = ['supplement', 'refocus', 'skip', 'deep_dive'] as const;
export type InterventionKind = (typeof INTERVENTION_KINDS)[number];
export const InterventionResult = O({ applied: Type.Array(Str) });
/**
 * The answer the “让 Agent 自行查询” chip sends (the web keeps the same literal): the agent is told to find out itself;
 * it is no statement, so it never becomes an enterprise fact or a confirmed fact of the audit.
 */
export const DEFER_TO_AGENT_ANSWER = '不确定，请 Agent 自行查询代码与配置后判断';
export const isDeferAnswer = (answer: string | null | undefined): boolean => (answer ?? '').trim() === DEFER_TO_AGENT_ANSWER;
export const AnswerResult = O({ routed: closedSet(['steer', 'state', 'closed_audit'] as const), question: QuestionDto, factId: Type.Optional(Str) });
export const EventDtoSchema = O({ seq: Int, type: closedSet(EVENT_TYPES), stepId: NStr, ts: Iso, payload: AnyRecord });
export type EventDto = { seq: number; type: EventType; stepId: string | null; ts: string; payload: Record<string, unknown> };
export const TrajectoryPage = O({ items: Type.Array(EventDtoSchema), nextAfter: Int, hasMore: Bool });
export const EventPoll = O({ resync: Bool, events: Type.Array(EventDtoSchema), lastSeq: Int, status: closedSet(AUDIT_STATUSES) });
/** `tokensCached`: input read from the prompt cache, not in `tokensIn`; the three add up to what the budget counts. */
export const UsageRow = O({ key: Str, tokensIn: Int, tokensOut: Int, tokensCached: Int, costMicros: Nullable(Int), unknownCostCalls: Int, calls: Int });
export type UsageRow = Static<typeof UsageRow>;

// ---- findings / vulnerabilities ----------------------------------------------------------------------------------
export const CodeLocDto = O({ repo: Str, path: Str, startLine: Int, endLine: Int, note: Type.Optional(Str) });
export type CodeLocDto = Static<typeof CodeLocDto>;
export const FindingDto = O({
  id: Str, displayNo: Nullable(Int), auditId: Str, title: Str, category: Str, cwe: NStr, severity: closedSet(SEVERITIES),
  confidence: closedSet(CONFIDENCES), state: Str, repo: Str, location: CodeLocDto, vulnId: NStr, vulnDisplayNo: Nullable(Int),
  confirmStatus: Nullable(closedSet(CONFIRM_STATUSES)), lifecycle: Nullable(closedSet(LIFECYCLES)), stepId: Str,
});
export type FindingDto = Static<typeof FindingDto>;
const vulnSummaryProps = {
  id: Str, projectId: Str, displayNo: Int, title: Str, category: Str, cwe: NStr, severity: closedSet(SEVERITIES),
  severityOriginal: Nullable(closedSet(SEVERITIES)), confidence: closedSet(CONFIDENCES), confirmStatus: closedSet(CONFIRM_STATUSES),
  handlingStatus: closedSet(HANDLING_STATUSES), lifecycle: closedSet(LIFECYCLES), pendingKind: NStr, sources: Type.Array(Str), repo: Str,
  module: NStr, evidenceComplete: Bool,
  /** own-service defect / relies on an upstream guarantee / cross-service risk; null for findings recorded before this was judged. */
  boundary: Nullable(closedSet(['own', 'upstream', 'cross_service'] as const)),
  /** Confirmed by a person without complete evidence, with a reason. */
  confirmOverride: Bool,
  entryCount: Int, firstSeenAuditId: NStr, lastSeenAuditId: NStr, updatedAt: Iso, revision: Int,
  /** A finding was linked as "suspected same" and awaits a human decision. */
  suspectedLink: Bool,
  /** Last audit covered it and did not find it, but nothing verified the fix ("建议复验"). */
  reverifySuggested: Bool,
  /** `merged`: folded into another vulnerability; read through the target. */
  status: closedSet(['active', 'merged'] as const), mergedIntoId: NStr, mergedIntoNo: Nullable(Int),
  /** the requirement risk its finding named, with that risk's decision when the audit ran. */
  threatRisk: Nullable(O({ riskId: Str, code: Str, threatModelId: Str, title: Str, status: Str })),
};
/** A proposed (not yet applied) revision, e.g. a reverification suggesting a handling status. */
export const ProposalDto = O({ revisionId: Str, dimension: Str, to: Type.Unknown(), reason: NStr, auditId: NStr, createdAt: Iso });
export type ProposalDto = Static<typeof ProposalDto>;
/** A pending "suspected same" link: the finding, where it was seen, and why the model linked it. */
export const SuspectedMatchDto = O({
  occurrenceId: Str, auditId: Str, auditTitle: Str, findingId: Str, findingNo: Nullable(Int), findingTitle: Str,
  location: CodeLocDto, sinkSymbol: NStr, sinkApi: NStr, entries: Type.Array(Str), rootCause: NStr, reason: Str, createdAt: Iso,
});
export type SuspectedMatchDto = Static<typeof SuspectedMatchDto>;
export const VulnSummaryDto = O(vulnSummaryProps);
export type VulnSummaryDto = Static<typeof VulnSummaryDto>;
export const VulnDetailDto = O({
  ...vulnSummaryProps,
  sinkSymbol: NStr, sinkApi: NStr, rootCause: NStr, handlingReason: NStr,
  pendingCondition: Nullable(PendingCondition),
  entries: Type.Array(O({ key: Str, state: Str })),
  suspectedMatches: Type.Array(SuspectedMatchDto),
  proposals: Type.Array(ProposalDto),
  /** Identity fingerprints (sink anchors), for splitting. `active=false`: history or a split marker. */
  fingerprints: Type.Array(O({ fp: Str, kind: Str, active: Bool })),
  /** Vulnerabilities merged into this one. */
  mergedFrom: Type.Array(O({ id: Str, displayNo: Int, title: Str })),
  layers: O({
    evidence: Type.Array(O({ kind: Str, repo: NStr, path: NStr, startLine: Nullable(Int), endLine: Nullable(Int), verified: Bool, note: NStr, snapshotId: NStr, auditId: NStr })),
    reasoning: O({
      chain: Type.Array(CodeLocDto), reasoning: Str, counterCheck: Str, challenge: Nullable(O({ verdict: Str, reason: Str, confidenceDelta: Num, against: NStr, affirm: NStr })),
      /** Cross review: the models that hunted, the ones that found it, the ones that ruled it out, the cross models that could not run. */
      consensus: Nullable(O({ models: Type.Array(Str), support: Type.Array(Str), conflicts: Type.Array(O({ model: Str, verdict: Str, reason: Str })), unavailable: Type.Array(Str) })),
    }),
    exploit: Type.Array(O({ condition: Str, status: Str, source: Str })),
    /** attack path and impact; null for findings submitted before it was recorded. */
    attack: Nullable(O({ path: Str, impact: Str })),
    fix: O({ approach: Str, suggestion: Type.Optional(Str), verification: Type.Optional(Str) }),
  }),
});
export type VulnDetailDto = Static<typeof VulnDetailDto>;
export const MATCH_DECISIONS = ['confirm', 'separate'] as const;
export type MatchDecision = (typeof MATCH_DECISIONS)[number];
export const SplitResult = O({ vulnerability: VulnDetailDto, created: O({ id: Str, displayNo: Int }) });
export const MatchDecisionResult = O({ vulnerability: VulnDetailDto, created: Nullable(O({ id: Str, displayNo: Int })) });
export type MatchDecisionResult = Static<typeof MatchDecisionResult>;
/**
 * a hypothesis a hunt could neither prove nor refute (`open`), or refuted / decided ones.
 * Hypotheses from the threat model (`origin: threat_model`) are listed before verification
 * (`proposed`, no location yet) and may end `confirmed` with the finding that proves them; `reason` is the
 * verification's reason (排查理由). Hypotheses of supplement audits are listed with the audit they extend.
 */
export const HYPOTHESIS_STATUSES = ['proposed', 'confirmed', 'open', 'refuted', 'converted', 'dismissed'] as const;
export const HypothesisDto = O({
  id: Str, auditId: Str, repo: Str, category: Str, statement: Str, attempts: Str, entry: NStr,
  location: Nullable(O({ repo: Str, path: Str, startLine: Int, endLine: Int })),
  status: closedSet(HYPOTHESIS_STATUSES), vulnerabilityId: NStr, decidedReason: NStr, createdAt: Iso,
  origin: closedSet(['hunt', 'threat_model'] as const), priority: Nullable(Int), basis: NStr,
  relatedEntries: Type.Array(Str), relatedFiles: Type.Array(Str), findingId: NStr, verifiedAt: Nullable(Iso),
  /** State of the proving finding after reconcile / challenge (canonical, insufficient, dropped …; merged ones resolve to their target). */
  findingState: NStr,
  /** a requirement risk verified as a hypothesis. */
  threatRiskId: NStr,
});
export type HypothesisDto = Static<typeof HypothesisDto>;
export const HypothesisList = O({ items: Type.Array(HypothesisDto), counts: O({ proposed: Int, confirmed: Int, open: Int, refuted: Int, converted: Int, dismissed: Int }) });
export type HypothesisList = Static<typeof HypothesisList>;
export const HypothesisDecisionResult = O({ hypothesis: HypothesisDto, vulnerability: Nullable(O({ id: Str, displayNo: Int })) });
export type HypothesisDecisionResult = Static<typeof HypothesisDecisionResult>;
export const RevisionDto = O({
  id: Str, seq: Int, dimension: Str, source: Str, actor: Str, from: Type.Unknown(), to: Type.Unknown(), reason: NStr, state: Str, auditId: NStr, createdAt: Iso,
  /** A merge or split that is still the latest identity change of everything involved. */
  undoable: Bool,
  /** Review time of the human decision that wrote this revision (first revision of a decision only). */
  reviewMs: Nullable(Int),
  /** Batch size when the decision was a batch action (reviewMs is then the per-item share); null for a single item. */
  reviewBatch: Nullable(Int),
});
export type RevisionDto = Static<typeof RevisionDto>;
export const VulnPatch = O({
  revision: Type.Optional(Int), confirmStatus: Type.Optional(closedSet(CONFIRM_STATUSES)), handlingStatus: Type.Optional(closedSet(HANDLING_STATUSES)),
  severity: Type.Optional(closedSet(SEVERITIES)), reason: Type.Optional(Type.String({ maxLength: 2000 })),
});
export type VulnPatch = Static<typeof VulnPatch>;
export const BatchUpdateResult = O({
  results: Type.Array(O({
    id: Str, ok: Bool, revision: Type.Optional(Int),
    /** Why the item was skipped (e.g. VULN_EVIDENCE_INCOMPLETE, VULN_REASON_REQUIRED, COMMON_REVISION_CONFLICT). */
    code: Type.Optional(Str),
    /** The item already had the requested value; nothing was written. */
    unchanged: Type.Optional(Bool),
  })),
});
const ReviewTiming = O({ count: Int, medianMs: Nullable(Int), meanMs: Nullable(Int) });
/** Online metric: client-measured human review time of a project's decisions. */
export const ReviewStatsDto = O({
  single: ReviewTiming,
  batch: O({ count: Int, medianMs: Nullable(Int), meanMs: Nullable(Int), batches: Int }),
  decisions: O({ confirmed: Int, falsePositive: Int }),
});
export type ReviewStatsDto = Static<typeof ReviewStatsDto>;
export const TrajectoryLink = O({ auditId: Str, auditTitle: Str, findingId: Str, findingNo: Nullable(Int), stepId: Str, presence: Str });

// ---- coverage / source / export ---------------------------------------------------------------------------------
const CovCount3 = O({ total: Int, reviewed: Int, readOnly: Int });
/** optional analyses that can also run afterwards on a finished audit (追加执行). */
export const SUPPLEMENT_KINDS = ['logic_review', 'threat_hypotheses', 'domains'] as const;
export const CovHypothesis = O({ total: Int, reviewed: Int, confirmed: Int, refuted: Int, open: Int, proposed: Int });
export const CoverageDto = O({
  enabled: Bool,
  repos: Type.Array(O({
    repoId: Str, repo: Str, entry: CovCount3, sink: CovCount3, reading: O({ totalLines: Int, readLines: Int }),
    /** indexable source lines, reading per module, index status and gaps. */
    sourceLines: Int, byModule: Type.Array(O({ module: Str, totalLines: Int, readLines: Int })),
    indexStatus: NStr, gaps: Type.Array(O({ path: Str, reason: Str, detail: Str })),
    /**
     * risk hypotheses from the threat model (this audit and its supplements). `reviewed` = verified
     * (confirmed + refuted + open) or decided by a reviewer; `proposed` = not verified yet (a coverage gap).
     */
    hypothesis: CovHypothesis,
  })),
  /** Backfill audits started from this audit's uncovered targets. */
  backfills: Type.Array(O({ auditId: Str, title: Str, status: closedSet(AUDIT_STATUSES), targets: Int, concluded: Int })),
  /** which optional analyses this audit ran (strategy), and supplements started from it afterwards. */
  analyses: O({ logicReview: Bool, threatHypotheses: Bool }),
  /** Whether supplements can be started: a finished full / incremental audit that is not itself a backfill or supplement. */
  supplementable: Bool,
  supplements: Type.Array(O({ auditId: Str, title: Str, status: closedSet(AUDIT_STATUSES), kind: closedSet(SUPPLEMENT_KINDS), hypotheses: Int })),
});
export type CoverageDto = Static<typeof CoverageDto>;
/**
 * What a coverage item is: an entry as an external interface (source) — method, route, handler, middleware and
 * auth signals; a sink as a risky function (sink) — the call, its line, the tainted argument hint and the enclosing
 * function. From the structure index; null when neither the item nor the cached index has it.
 */
export const CoverageItemDetail = Type.Union([
  O({
    /** `entryKind`: http / rpc / socket / message / schedule / cli; `protocol`: grpc, websocket, kafka, cron… */
    type: Type.Literal('entry'), entryKind: Str, protocol: Str, framework: Str, method: NStr, route: NStr,
    /** Handler function name (`Class.method`); null for file-level code (a PHP script). */
    handler: NStr, line: Int, middlewares: Type.Array(Str), auth: Type.Array(Str),
  }),
  O({ type: Type.Literal('sink'), api: Str, line: Int, column: Type.Union([Int, Type.Null()]), taintHint: NStr, function: NStr }),
]);
export type CoverageItemDetail = Static<typeof CoverageItemDetail>;
export const CoverageItemDto = O({
  id: Str, kind: closedSet(['entry', 'sink'] as const), repo: Str, targetId: Str, category: NStr, path: Str, startLine: Int, endLine: Int, status: Str, verdict: NStr,
  /** the entry / sink itself; `startLine`–`endLine` stay the range that must be read. */
  detail: Type.Union([CoverageItemDetail, Type.Null()]),
  /** The canonical finding the item concluded with, if any. */
  findingId: NStr,
});
export type CoverageItemDto = Static<typeof CoverageItemDto>;
const CompareVulnDto = O({ vulnId: Str, displayNo: Int, title: Str, severity: closedSet(SEVERITIES), category: Str, lifecycle: closedSet(LIFECYCLES) });
/** Two audits of a project compared: appeared, disappeared (with how), changed. */
export const AuditCompareDto = O({
  base: O({ id: Str, title: Str, createdAt: Iso }), target: O({ id: Str, title: Str, createdAt: Iso }),
  added: Type.Array(CompareVulnDto),
  removed: Type.Array(O({ ...CompareVulnDto.properties, presence: Str })),
  changed: Type.Array(O({ ...CompareVulnDto.properties, changes: Type.Array(Str) })),
  unchanged: Int,
});
export type AuditCompareDto = Static<typeof AuditCompareDto>;
export const SourceDto = O({ repo: Str, path: Str, from: Int, to: Int, totalLines: Int, lines: Type.Array(Str), rootHash: Str });
export type SourceDto = Static<typeof SourceDto>;
export const TreeEntryDto = O({ name: Str, path: Str, kind: closedSet(['dir', 'file'] as const), lines: Type.Optional(Int), lang: Type.Optional(NStr) });
export type TreeEntryDto = Static<typeof TreeEntryDto>;
export const EXPORT_FORMATS = ['md', 'html', 'json', 'sarif'] as const;
export type ExportFormatApi = (typeof EXPORT_FORMATS)[number];
export const ExportRequest = O({
  scope: Type.Literal('audit'), ids: Type.Array(Str, { minItems: 1, maxItems: 1 }), format: Type.String(),
  snippets: Type.Optional(Bool), localRoots: Type.Optional(Bool),
});
export type ExportRequest = Static<typeof ExportRequest>;
export const EXPORT_MODES = ['template', 'ai'] as const;
export const AI_REPORT_PHASES = ['generating', 'verifying', 'repairing'] as const;
export const ExportDto = O({
  id: Str, auditId: Str, format: closedSet(EXPORT_FORMATS), status: closedSet(['running', 'succeeded', 'failed'] as const), bytes: Int, createdAt: Iso, fileName: Str, warning: NStr,
  /** `template` = deterministic rendering (with a report skill's section template), `ai` = written by the report model. */
  mode: closedSet(EXPORT_MODES),
  /** AI reports: the model that wrote it (`provider/model`, the fallback after a switch), tokens, the phase while running. */
  model: NStr, tokens: Int, progress: Nullable(closedSet(AI_REPORT_PHASES)), reportSkill: NStr, error: NStr,
  /** AI reports: the check against the recorded conclusions (after the repair round, if one ran). */
  verification: Nullable(O({ ok: Bool, rounds: Int, issues: Type.Array(Str), firstIssues: Type.Array(Str), fallbackFrom: NStr })),
});
/** The AI report defaults of an audit: report-stage model, where it comes from, its fallback, a token estimate. */
export const AiReportDefaultsDto = O({
  model: ModelRef, source: closedSet(['report_stage', 'hunt'] as const), fallback: Nullable(ModelRef), estimate: O({ tokens: Int, conclusions: Int }),
});
export type AiReportDefaultsDto = Static<typeof AiReportDefaultsDto>;
export const ExportPreviewDto = O({ markdown: Str });
export type ExportPreviewDto = Static<typeof ExportPreviewDto>;
export type ExportDto = Static<typeof ExportDto>;

// ---- settings / diagnostics / home --------------------------------------------------------------------------
/** `confidential`: listed in `confidentialModels` (may receive facts marked confidential). */
const ModelEntry = O({ id: Str, name: Type.Optional(Str), contextWindow: Type.Optional(Int), maxTokens: Type.Optional(Int), reasoning: Type.Optional(Bool), confidential: Type.Optional(Bool), images: Type.Optional(Bool) });
export const ProviderDto = O({
  id: Str, api: Str, baseUrl: Str, apiKey: O({ configured: Bool, hint: Type.Optional(Str) }), models: Type.Array(ModelEntry),
  lastTest: Nullable(O({ ok: Bool, at: Iso, detail: Str })),
  /** The model settings that name this provider; deleting it clears them only when asked to. */
  references: Type.Array(O({ setting: Str, label: Str, model: Str })),
});
export type ProviderDto = Static<typeof ProviderDto>;
/** DELETE of a provider: the settings that pointed at it and were cleared with it. */
export const ProviderDeleted = O({ cleared: Type.Array(O({ setting: Str, label: Str, model: Str })) });
export type ProviderDeleted = Static<typeof ProviderDeleted>;
export const ProviderPatched = O({ ...ProviderDto.properties, keyCleared: Bool });
export const ProviderTestResult = O({ ok: Bool, at: Iso, detail: Str, models: Type.Array(Str) });
/** Model list of an unsaved provider form; `limits`: the models whose listing entry reported a context window or output cap. */
export const ProviderProbeResult = O({
  ok: Bool, detail: Str, models: Type.Array(Str),
  limits: Type.Optional(Type.Record(Str, O({ contextWindow: Type.Optional(Int), maxTokens: Type.Optional(Int) }))),
});
export type ProviderProbeResult = Static<typeof ProviderProbeResult>;
/** Connectivity of an unsaved form: the model list, then one minimal request per selected model. */
export const ProviderCheckResult = O({
  ok: Bool, detail: Str, list: O({ ok: Bool, detail: Str, count: Int }),
  models: Type.Array(O({ id: Str, ok: Bool, ms: Int, detail: Str })),
  /** More models were selected than one check covers (only the first ones were tried). */
  truncated: Bool,
});
export type ProviderCheckResult = Static<typeof ProviderCheckResult>;
/** the default model, per-stage models (absent = the default; `null` = no model, triage / merge only) and the one fallback. */
/** confidentialModels: `provider/model` keys allowed to receive facts marked confidential. */
export const ModelSettingsDto = O({ defaultModel: Nullable(ModelRef), stageModels: StageModelsConfig, fallbackModel: Nullable(ModelRef), confidentialModels: Type.Array(Str), revision: Str });
export type ModelSettingsDto = Static<typeof ModelSettingsDto>;
export const SceneDefaultsDto = O({ scene: closedSet(SCENES), override: AnyRecord, effective: Nullable(AuditStrategy), revision: Str, runnable: Bool });
export type SceneDefaultsDto = Static<typeof SceneDefaultsDto>;
const PricingDto = O({ currency: Str, input: Num, output: Num, cacheRead: Type.Optional(Num) });
export const GeneralSettingsDto = O({
  concurrency: O({ audits: Int, modelRequests: Int }), engine: O({ pauseGraceSec: Int, budgetTolerance: Num }),
  export: O({ snippets: Bool, localRoots: Bool, reportSkill: Type.Optional(Str) }), log: O({ level: Str, retentionDays: Int }),
  pricing: Type.Record(Type.String(), PricingDto),
  /** External tool paths as configured (unset keys absent; the service looks those up on PATH). */
  tools: ToolsConfig, revision: Str,
});
export type GeneralSettingsDto = Static<typeof GeneralSettingsDto>;
export const DoctorCheckDto = O({ name: Str, level: closedSet(['ok', 'fatal', 'block', 'warn', 'info'] as const), detail: Str, impact: Type.Optional(Str), fix: Type.Optional(Str) });
export type DoctorCheckDto = Static<typeof DoctorCheckDto>;
export const DiagnosticsDto = O({
  checks: Type.Array(DoctorCheckDto), checkedAt: Iso, storage: NumRecord,
  runtime: O({ version: Str, piVersion: Str, pid: Int, uptimeSec: Int, queued: Int, running: Int }),
  recentErrors: Type.Array(O({ ts: Iso, requestId: Str, code: Str, message: Str })),
});
export type DiagnosticsDto = Static<typeof DiagnosticsDto>;
/** A connector call the Agent made that carries instructions from the audited code, held for (or after) the user's decision. */
export const ConnectorWriteDto = O({
  id: Str, connectorId: Str, connector: Str, tool: Str, toolDescription: NStr, args: Type.Unknown(), reason: NStr,
  source: closedSet(['audit', 'conversation', 'push'] as const), auditId: NStr, auditTitle: NStr, conversationId: NStr, conversationTitle: NStr,
  status: closedSet(['pending', 'executed', 'failed', 'rejected'] as const),
  /** Suspected injected instructions found in the arguments. */
  signals: Type.Array(Str), result: NStr, error: NStr, decisionNote: NStr, decidedAt: NStr, createdAt: Str,
});
export type ConnectorWriteDto = Static<typeof ConnectorWriteDto>;
export const InboxDto = O({
  questions: Type.Array(O({ ...QuestionDto.properties, auditTitle: Str, projectName: Str })),
  waitingBudget: Type.Array(AuditSummaryDto), interrupted: Type.Array(AuditSummaryDto), awaitingConfirm: Type.Array(AuditSummaryDto),
  /** Pending confirmation per project; `missing` lists what the pending conditions ask for. */
  pendingVulns: Type.Array(O({ projectId: Str, projectName: Str, count: Int, missing: Type.Array(Str) })),
  proposals: Type.Array(O({ vulnId: Str, displayNo: Int, projectId: Str, projectName: Str, title: Str, dimension: Str, to: Type.Unknown(), reason: NStr, conversationId: NStr })),
  /** connector calls held for approval (instructions from the audited code). */
  connectorWrites: Type.Array(ConnectorWriteDto),
});
export type InboxDto = Static<typeof InboxDto>;
export const DashboardDto = O({ inbox: InboxDto, running: Type.Array(AuditSummaryDto), projects: Type.Array(ProjectDto) });
export type DashboardDto = Static<typeof DashboardDto>;
/** Knowledge listing row: effective and hidden skills with why they are hidden. */
export const SkillDto = O({
  name: Str, layer: closedSet(['global', 'project'] as const), valid: Bool, errors: Type.Array(Str), warnings: Type.Array(Str),
  category: NStr, description: NStr, load: NStr, verified: Nullable(Bool), path: Str, updatedAt: NStr,
  disabled: Bool, disabledBy: Type.Array(closedSet(['global', 'project_name', 'project_category'] as const)),
  overridesGlobal: Bool, overriddenBy: Type.Array(Str),
});
export type SkillDto = Static<typeof SkillDto>;
/** what one model session sent to which provider. */
export const EgressDto = O({
  id: Str, kind: Str, auditId: NStr, step: NStr, conversationId: NStr, ref: NStr, provider: Str, model: Str, endpoint: NStr, status: Str, turns: Int,
  tokens: O({ input: Int, output: Int, cached: Int }), files: Type.Array(O({ repo: Type.Optional(Str), path: Str })), facts: Type.Array(Str), withheldFacts: Int,
  tools: Type.Record(Type.String(), Type.Integer()), startedAt: Iso, endedAt: Iso,
});
export type EgressDto = Static<typeof EgressDto>;

/** a service's responsibility card. */
export const ServiceCardDto = O({
  service: Str, names: Type.Array(Str), trust: O({ value: Str, source: Str, reason: Str }),
  inbound: O({ exposed: Type.Array(O({ entryKey: Str, routes: Type.Array(O({ gateway: Str, pathTemplate: Str, auth: NStr })) })), internal: Type.Array(Str), channels: Type.Record(Type.String(), Type.Integer()) }),
  guarantees: Type.Array(O({ id: Str, statement: Str, trust: Str, source: Str })), outbound: Type.Array(O({ to: Str, kind: Str, protocol: Str })),
});
export type ServiceCardDto = Static<typeof ServiceCardDto>;

/** what the project's gateways do before forwarding (from their configuration). */
export const GatewayAuthDto = O({ kind: Str, mechanism: Str, path: Str, line: Int });
export const GatewayRouteDto = O({ pathTemplate: Str, upstream: NStr, stripPrefix: Int, auth: Nullable(GatewayAuthDto), effectiveAuth: Nullable(GatewayAuthDto), setHeaders: Type.Array(Str), removeHeaders: Type.Array(Str), path: Str, line: Int });
export const GatewayExposureDto = O({ gateways: Type.Array(O({ gateway: Str, global: Type.Array(GatewayAuthDto), routes: Type.Array(GatewayRouteDto) })) });
export type GatewayExposureDto = Static<typeof GatewayExposureDto>;

/** an enterprise fact version, with the vulnerabilities that rely on its key. */
export const FactScopeDto = O({ repos: Type.Optional(Type.Array(Str)), services: Type.Optional(Type.Array(Str)), paths: Type.Optional(Type.Array(Str)) });
export const FactDto = O({
  id: Str, projectId: Str, key: Str, version: Int, topic: closedSet(FACT_TOPICS), statement: Str, scope: FactScopeDto,
  sourceKind: closedSet(FACT_SOURCES), sourceRef: NStr, trust: closedSet(FACT_TRUST), sensitivity: closedSet(FACT_SENSITIVITY),
  status: closedSet(FACT_STATUSES), createdBy: Str, reason: NStr, createdAt: Iso, updatedAt: Iso,
  /** Vulnerabilities whose findings rely on this key; `stale`: on a version no longer in force (reverify them). */
  affected: O({ vulns: Int, stale: Int }),
});
export type FactDto = Static<typeof FactDto>;
export const FactImpactDto = O({ vulnerabilityId: Str, displayNo: Int, title: Str, auditId: Str, version: Int, stale: Bool });
export const FactDetailDto = O({ fact: FactDto, versions: Type.Array(FactDto), impact: Type.Array(FactImpactDto) });
export type FactDetailDto = Static<typeof FactDetailDto>;
export const PostFactBody = O({
  topic: closedSet(FACT_TOPICS), statement: Type.String({ minLength: 1, maxLength: 4000 }), scope: Type.Optional(FactScopeDto),
  trust: Type.Optional(closedSet(['verified', 'unverified'] as const)), sensitivity: Type.Optional(closedSet(FACT_SENSITIVITY)),
  /** `review`: saved from a review ruling of the vulnerability `sourceRef`. */
  sourceKind: Type.Optional(closedSet(['user', 'review'] as const)), sourceRef: Type.Optional(Str), reason: Type.Optional(Str),
});
export type PostFactBody = Static<typeof PostFactBody>;
export const PutFactBody = O({
  topic: Type.Optional(closedSet(FACT_TOPICS)), statement: Type.Optional(Type.String({ minLength: 1, maxLength: 4000 })), scope: Type.Optional(FactScopeDto),
  trust: Type.Optional(closedSet(['verified', 'unverified'] as const)), sensitivity: Type.Optional(closedSet(FACT_SENSITIVITY)), reason: Type.Optional(Str),
});
export const RetractFactBody = O({ reason: Type.String({ minLength: 1, maxLength: 1000 }) });
export const FactImportDto = O({ added: Int, updated: Int, unchanged: Int, kept: Int });

/** one pipeline prompt of the knowledge base with its default and the overrides of the layers. */
export const PROMPT_GROUPS_DTO = ['role_rules', 'step_task', 'standalone', 'conversation', 'nudge', 'data_note', 'tool'] as const;
export const PromptLayerDto = O({ text: Str, updatedAt: NStr, valid: Bool, issues: Type.Array(Str), defaultChanged: Bool });
export type PromptLayerDto = Static<typeof PromptLayerDto>;
export const PromptDto = O({
  id: Str, group: closedSet(PROMPT_GROUPS_DTO), title: Str, description: Str, editable: Bool, readonlyReason: NStr,
  variables: Type.Array(Str), locked: Type.Array(Str), defaultText: Str,
  global: Nullable(PromptLayerDto), project: Nullable(PromptLayerDto),
  effectiveLayer: closedSet(['default', 'global', 'project'] as const), effectiveText: Str,
});
export type PromptDto = Static<typeof PromptDto>;
export const PromptListDto = O({ items: Type.Array(PromptDto), hash: Str, overrides: Int, invalid: Int });
export type PromptListDto = Static<typeof PromptListDto>;
export const PutPromptBody = O({ text: Type.String({ minLength: 1, maxLength: 20000 }), projectId: Type.Optional(Str) });
export type PutPromptBody = Static<typeof PutPromptBody>;
export const SkillFileInfoDto = O({ path: Str, size: Int, sha256: Str });
/** One skill with its entry file text (`body`) and hashes for If-Match. */
export const SkillBodyDto = O({
  name: Str, layer: closedSet(['global', 'project'] as const), form: closedSet(['file', 'dir'] as const), valid: Bool, errors: Type.Array(Str), warnings: Type.Array(Str),
  category: NStr, description: NStr, load: NStr, verified: Nullable(Bool), source: NStr, sha256: NStr,
  entryFile: Str, body: Str, entrySha256: Str, files: Type.Array(SkillFileInfoDto), updatedAt: Str,
});
export type SkillBodyDto = Static<typeof SkillBodyDto>;
export const SkillFileDto = O({ path: Str, text: Str, sha256: Str });
export type SkillFileDto = Static<typeof SkillFileDto>;
export const KnowledgeOverrideDto = O({ disabled: Type.Array(Str), disabledCategories: Type.Array(Str) });
export type KnowledgeOverrideDto = Static<typeof KnowledgeOverrideDto>;
/** Knowledge draft for review. */
export const KnowledgeDraftDto = O({
  id: Str, layer: closedSet(['global', 'project'] as const), projectId: NStr,
  status: closedSet(['organizing', 'ready', 'failed', 'approved', 'rejected'] as const), revision: Int,
  kind: closedSet(['skill', 'case'] as const), name: NStr, library: NStr, text: Str, inputPreview: Str,
  source: O({ kind: Str, ref: NStr, label: Str }),
  checks: O({
    errors: Type.Array(Str), warnings: Type.Array(Str),
    injection: Type.Array(O({ signal: Str, line: Int, excerpt: Str })),
    sameName: Nullable(O({ layer: Str, name: Str, file: NStr })), overridesGlobal: Bool,
    similar: Type.Array(O({ layer: Str, name: Str, file: NStr, score: Num })),
    conflicts: Type.Array(O({ layer: Str, name: Str, file: NStr, points: Type.Array(Str), suggestion: Str, merged: NStr })),
  }),
  model: NStr, tokens: Int, error: NStr, moveFrom: Nullable(O({ projectId: Str, name: Str })), createdAt: Str, updatedAt: Str, decidedAt: NStr,
});
export type KnowledgeDraftDto = Static<typeof KnowledgeDraftDto>;
export const DraftApprovedDto = O({ draft: KnowledgeDraftDto, name: Str, file: NStr });
export const MoveToGlobalPreviewDto = O({ text: Str, hints: Type.Array(O({ kind: Str, text: Str, line: Int })), globalExists: Bool });
export type MoveToGlobalPreviewDto = Static<typeof MoveToGlobalPreviewDto>;

/** Connector: no credential values, only whether each referenced secret is set. */
export const ConnectorConfigDto = O({
  command: Type.Optional(O({ path: Str, args: Type.Array(Str), env: Type.Record(Str, Str) })), url: Type.Optional(Str), headers: Type.Optional(Type.Record(Str, Str)),
  concurrency: Type.Optional(Int), timeouts: Type.Optional(O({ callMs: Type.Optional(Int) })),
  pack: Type.Optional(Str), base_url: Type.Optional(Str), variables: Type.Optional(Type.Record(Str, Str)), interpreter_path: Type.Optional(Str),
  /** absolute path of a pack's program (CLI). */
  program_path: Type.Optional(Str),
});
export const ConnectorDto = O({
  id: Str, name: Str, protocol: closedSet(['mcp_stdio', 'mcp_http', 'http'] as const),
  /** no purpose / allow-write settings — what a connector can do is what its tools declare. */
  enabled: Bool, status: closedSet(['needs_confirmation', 'untested', 'failed', 'ready'] as const),
  /** Connector whose results may support conclusions. */
  authoritative: Bool,
  config: ConnectorConfigDto, commandLine: NStr, commandHash: NStr,
  secrets: Type.Array(O({ name: Str, configured: Bool, hint: Type.Optional(Str) })),
  tools: Type.Array(O({
    name: Str, title: Type.Optional(Str), description: Type.Optional(Str), readOnlyHint: Nullable(Bool), destructiveHint: Nullable(Bool), exposed: Bool,
  })),
  lastTest: Nullable(O({ ok: Bool, at: Str, server: Nullable(O({ name: Str, version: Str, protocolVersion: Str })), error: NStr, toolCount: Int })),
  breaker: O({ state: Str, failures: Int }), createdAt: Str, updatedAt: Str,
});
export type ConnectorDto = Static<typeof ConnectorDto>;
export const ConnectorQueryResultDto = O({ text: Str, isError: Bool, bytes: Int, authoritative: Bool, injection: Type.Array(O({ signal: Str, line: Int, excerpt: Str })) });
export type ConnectorQueryResultDto = Static<typeof ConnectorQueryResultDto>;
export const ProjectConnectorDto = O({ connectorId: Str, name: Str, scope: closedSet(['project', 'global'] as const), status: Str, enabled: Bool });
export type ProjectConnectorDto = Static<typeof ProjectConnectorDto>;
/** Connector pack. */
export const ConnectorPackDto = O({
  name: Str, valid: Bool, errors: Type.Array(Str), description: NStr, hash: NStr, operations: Type.Array(O({ name: Str, kind: Str })),
  scripts: Type.Array(Str), interpreter: NStr, secrets: Type.Array(Str), baseUrl: NStr,
});
export type ConnectorPackDto = Static<typeof ConnectorPackDto>;
export const ConnectorPackFileDto = O({ path: Str, text: Str, sha256: Type.Optional(Str) });
export const ConnectorPackDraftDto = O({
  id: Str, status: Str, name: NStr, error: NStr, model: NStr, tokens: Int, createdAt: Str, files: Type.Array(Str), errors: Type.Array(Str),
});
export type ConnectorPackDraftDto = Static<typeof ConnectorPackDraftDto>;
export const ConnectorCallDto = O({ id: Str, operation: Str, kind: Str, status: Str, durationMs: Int, responseBytes: Int, error: NStr, auditId: NStr, createdAt: Str });
export type ConnectorCallDto = Static<typeof ConnectorCallDto>;

/** Push guides and pushes. */
export const PushGuideDto = O({
  name: Str, description: Str, layer: Str, connector: Str, operation: Str, updateOperation: NStr, confirm: Bool, template: Bool,
  connectorId: NStr, available: Bool, reason: NStr,
});
export type PushGuideDto = Static<typeof PushGuideDto>;
export const PushItemDto = O({
  vulnId: Str, displayNo: Int, title: Str, action: closedSet(['create', 'update', 'skip'] as const), operation: NStr,
  args: Type.Record(Type.String(), Type.Unknown()), skipReason: NStr, reasons: Type.Array(Str),
  existing: Nullable(O({ externalId: Str, externalUrl: NStr })),
  result: Nullable(O({ ok: Bool, externalId: NStr, externalUrl: NStr, error: NStr })),
  /** a re-push may run several operations in order (comment, fields, state); each with its own result. */
  steps: Type.Array(O({ operation: Str, args: Type.Record(Type.String(), Type.Unknown()), ok: Nullable(Bool), error: NStr })),
});
export type PushItemDto = Static<typeof PushItemDto>;
export const PushDto = O({
  id: Str, projectId: Str, skill: Str, connectorId: Str, connectorName: Str, status: closedSet(['awaiting_confirm', 'done', 'expired'] as const),
  confirmRequired: Bool, confirmReasons: Type.Array(Str), payloadHash: Str, token: NStr, expiresAt: Str, tokens: Int, items: Type.Array(PushItemDto),
});
export type PushDto = Static<typeof PushDto>;
export const SyncRecordDto = O({ connectorId: Str, connectorName: Str, externalId: Str, externalUrl: NStr, updatedAt: Str });
export type SyncRecordDto = Static<typeof SyncRecordDto>;

/** Architecture material import (`/projects/{pid}/architecture-imports`). */
export const ArchitectureImportDto = O({
  id: Str, projectId: Str, label: Str, status: closedSet(['running', 'done', 'failed'] as const),
  result: Nullable(O({ nodesAdded: Int, edgesAdded: Int, aliases: Int, skipped: Type.Array(Str), summary: Str })),
  draftId: NStr, error: NStr, model: NStr, tokens: Int, createdAt: Str, updatedAt: Str,
});
export type ArchitectureImportDto = Static<typeof ArchitectureImportDto>;

/** Knowledge used by an audit (审计结果汇总). */
export const KnowledgeUsageDto = O({
  items: Type.Array(O({ name: Str, layer: Str, maxLevel: Str, reads: Int, steps: Int, tokens: Int, citedBy: Int })),
  knowledgeTokens: Int, totalTokens: Int, citedShare: Nullable(Num),
});
export type KnowledgeUsageDto = Static<typeof KnowledgeUsageDto>;

/** Pushed on the global event stream when a knowledge layer changed on disk. */
export const KnowledgeChangedDto = O({ layer: closedSet(['global', 'project'] as const), projectId: NStr });
export type KnowledgeChangedDto = Static<typeof KnowledgeChangedDto>;
export const BootstrapUrl = O({ url: Str, expiresInSec: Int });

export const CACHE_HANDLINGS = ['patch_audit', 'append_trajectory', 'invalidate_results', 'invalidate_coverage', 'invalidate_questions'] as const;
export type CacheHandling = (typeof CACHE_HANDLINGS)[number];

/**
 * Event → client cache handling. Every event type must declare one. Literal-typed so the
 * web client's mirror (it may only import types) is checked against it by the compiler.
 */
export const EVENT_CACHE_HANDLING = {
  'audit.status_changed': 'patch_audit', 'step.status_changed': 'patch_audit', 'step.attempt_started': 'append_trajectory',
  'plan.generated': 'patch_audit', 'plan.confirmed': 'patch_audit',
  'session.started': 'append_trajectory', 'session.turn': 'append_trajectory', 'session.compacted': 'append_trajectory', 'session.ended': 'append_trajectory',
  'agent.note': 'append_trajectory',
  'session.queued': 'append_trajectory', 'session.dequeued': 'append_trajectory', 'session.paused': 'append_trajectory', 'session.resumed': 'append_trajectory', 'task.started': 'append_trajectory', 'task.finished': 'append_trajectory',
  'candidate.marked': 'append_trajectory', 'candidate.settled': 'append_trajectory',
  'model.fallback': 'append_trajectory',
  'tool.called': 'append_trajectory', 'tool.result': 'append_trajectory', 'file.read': 'append_trajectory', 'cross_repo.traced': 'append_trajectory',
  'knowledge.loaded': 'append_trajectory', 'knowledge.changed': 'append_trajectory', 'connector.queried': 'append_trajectory', 'connector.write_requested': 'append_trajectory', 'connector.write_decided': 'append_trajectory',
  'hypothesis.proposed': 'append_trajectory', 'hypothesis.retired': 'append_trajectory', 'state.updated': 'append_trajectory', 'decide.chosen': 'append_trajectory',
  'question.asked': 'invalidate_questions', 'question.answered': 'invalidate_questions', 'intervention.received': 'append_trajectory', 'intervention.applied': 'append_trajectory',
  'judgement.made': 'append_trajectory', 'finding.submitted': 'invalidate_results', 'finding.challenged': 'invalidate_results', 'finding.reconciled': 'invalidate_results',
  'vuln.created': 'invalidate_results', 'vuln.matched': 'invalidate_results', 'vuln.impact_changed': 'invalidate_results',
  'contract.violation': 'append_trajectory', 'security.blocked': 'append_trajectory', 'injection_suspected': 'append_trajectory',
  'budget.reserved': 'patch_audit', 'budget.charged': 'patch_audit', 'budget.exhausted': 'patch_audit', 'budget.topped_up': 'patch_audit',
  'coverage.updated': 'invalidate_coverage', 'gate.evaluated': 'patch_audit', 'error': 'append_trajectory',
} as const satisfies Record<EventType, CacheHandling>;

/** Trajectory filter groups (`GET /audits/{aid}/trajectory?type=`), in display order. */
export const TRAJECTORY_GROUPS = {
  note: ['agent.note'],
  plan: ['plan.generated', 'plan.confirmed'],
  read: ['file.read'],
  tool: ['tool.called', 'tool.result', 'task.started', 'task.finished'],
  knowledge: ['knowledge.loaded', 'knowledge.changed'],
  question: ['question.asked', 'question.answered', 'connector.write_requested', 'connector.write_decided'],
  intervention: ['intervention.received', 'intervention.applied'],
  judgement: ['candidate.marked', 'candidate.settled', 'judgement.made', 'finding.submitted', 'finding.challenged', 'finding.reconciled', 'hypothesis.proposed', 'hypothesis.retired', 'state.updated'],
  vuln: ['vuln.created', 'vuln.matched', 'vuln.impact_changed'],
  budget: ['budget.exhausted', 'budget.topped_up'],
  step: ['audit.status_changed', 'step.status_changed', 'session.started', 'session.ended', 'session.queued', 'session.dequeued', 'session.paused', 'session.resumed', 'model.fallback', 'gate.evaluated', 'coverage.updated'],
  security: ['contract.violation', 'security.blocked', 'injection_suspected', 'error'],
} as const satisfies Record<string, readonly EventType[]>;
export type TrajectoryGroup = keyof typeof TRAJECTORY_GROUPS;
export const TRAJECTORY_GROUP_NAMES = Object.keys(TRAJECTORY_GROUPS) as TrajectoryGroup[];
/** High-volume bookkeeping events hidden from the default (unfiltered) trajectory view. */
export const TRAJECTORY_NOISE = ['budget.reserved', 'budget.charged', 'session.turn', 'step.attempt_started'] as const satisfies readonly EventType[];

/** Phase shown for an audit, from the kind of its current step (AuditHeader). */
export const PHASE_OF_KIND = {
  snapshot: 'preparing', index: 'preparing', plan: 'planning', triage: 'analyzing', hunt: 'analyzing', scope: 'analyzing', profile: 'analyzing',
  challenge: 'verifying', review: 'verifying', reconcile: 'verifying', report: 'reporting', finalize: 'reporting',
} as const satisfies Record<string, AuditPhase>;

export function derivePhase(status: AuditStatus, steps: readonly { kind: string; status: StepStatus }[]): AuditPhase {
  if (['completed', 'partial', 'failed', 'cancelled'].includes(status)) return 'done';
  if (status === 'planning') return steps.some((s) => s.kind === 'plan' && s.status === 'running') ? 'planning' : steps.some((s) => s.status === 'running') ? 'preparing' : 'planning';
  if (status === 'awaiting_confirm') return 'awaiting_confirm';
  if (status === 'queued') return 'queued';
  const running = steps.filter((s) => s.status === 'running').at(-1);
  const last = running ?? [...steps].reverse().find((s) => s.status !== 'pending' && s.kind !== 'plan' && s.kind !== 'snapshot' && s.kind !== 'index');
  return last ? (PHASE_OF_KIND as Record<string, AuditPhase>)[last.kind] ?? 'analyzing' : 'analyzing';
}

// ---- risk hunts ----
export const HuntBasisDto = O({
  id: Str, kind: closedSet(['skill', 'prompt', 'intel', 'report', 'ticket'] as const), title: Str, status: closedSet(['drafting', 'ready', 'failed'] as const),
  error: NStr, revision: Int, basis: Nullable(HuntBasis), skillName: NStr, model: NStr, createdAt: Iso,
});
export type HuntBasisDto = Static<typeof HuntBasisDto>;
const HuntSummaryDto = O({ projects: Int, repositories: Int, affected: Int, notAffected: Int, pending: Int, unfinished: Int, hits: Int, projectVerdicts: StrRecord });
export const HuntDto = O({
  id: Str, title: Str, status: closedSet(['planned', 'running', 'completed', 'partial', 'failed', 'cancelled'] as const), basisId: NStr,
  basisKind: Str, skillName: NStr, scope: O({ all: Bool, projectIds: Type.Array(Str) }), rerunOfId: NStr, summary: HuntSummaryDto,
  createdAt: Iso, startedAt: NIso, endedAt: NIso, basis: HuntBasis,
  plan: Nullable(O({
    projects: Type.Array(O({ id: Str, name: Str, repos: Type.Array(O({ id: Str, name: Str, auditable: Bool, ref: NStr })) })),
    estimate: O({
      repositories: Int, tokens: Range2, durationSec: Range2,
      /** Deterministic locate before confirmation: repositories needing AI judgement vs settled by rule. */
      precheck: O({
        status: closedSet(['none', 'running', 'done', 'failed'] as const), judged: Int, cleared: Int,
        repos: Type.Array(O({ project: Str, name: Str, candidates: Int, error: NStr })),
      }),
    }),
  })),
  auditIds: Type.Array(Str),
});
export type HuntDto = Static<typeof HuntDto>;
const HuntEvidence = O({ kind: Str, repo: NStr, path: NStr, startLine: Nullable(Int), endLine: Nullable(Int), note: NStr, verified: Bool });
export const HuntTargetDto = O({
  id: Str, projectId: Str, projectName: Str, repositoryId: NStr, repoName: NStr, auditId: NStr, auditStatus: NStr,
  verdict: Nullable(closedSet(['affected', 'not_affected', 'pending'] as const)), reason: NStr, verdictSource: NStr, delta: NStr, hits: Int,
  evidence: Type.Array(HuntEvidence), pendingCondition: Nullable(PendingCondition),
});
export const HuntHitDto = O({
  id: Str, projectId: Str, projectName: Str, repoName: Str, auditId: Str, title: Str, severity: Str, category: Str, confidence: Str,
  location: O({ path: Str, startLine: Int, endLine: Int }), reasoning: Str, exploitConditions: Type.Array(O({ condition: Str, status: Str, source: Str })),
  evidence: Type.Array(HuntEvidence), promotedVulnId: NStr, promotedDisplayNo: Nullable(Int),
});
export const HuntResultsDto = O({ hunt: HuntDto, targets: Type.Array(HuntTargetDto), hits: Type.Array(HuntHitDto) });
export type HuntResultsDto = Static<typeof HuntResultsDto>;
export type HuntTargetDto = Static<typeof HuntTargetDto>;
export type HuntHitDto = Static<typeof HuntHitDto>;
export const HuntCompareDto = O({ items: Type.Array(O({ projectName: Str, repoName: NStr, before: NStr, after: NStr, change: Str })) });

// ---- requirement threat models ---------------------------------------------------------------------
export const ThreatSourceDto = O({
  id: Str, threatModelId: Str,
  /** S1, S2 … in the order the sources were added; never reused. */
  no: Int, ord: Int, kind: closedSet(THREAT_SOURCE_KINDS), title: Str, note: NStr,
  connectorId: NStr, docRef: NStr, bytes: Int, contentHash: NStr,
  fetchStatus: Nullable(closedSet(THREAT_FETCH_STATUSES)), fetchError: NStr, fetchedAt: NIso,
  /** Injection signals found in the text; a source with signals is used for generation only after `injectionAck`. */
  injection: Type.Array(O({ signal: Str, line: Int, excerpt: Str })), injectionAck: Bool,
  createdAt: Iso, updatedAt: Iso,
});
export type ThreatSourceDto = Static<typeof ThreatSourceDto>;
export const ThreatRiskHistoryEntry = O({ at: Iso, actor: Str, from: closedSet(THREAT_RISK_STATUSES), to: closedSet(THREAT_RISK_STATUSES), reason: NStr });
export type ThreatRiskHistoryEntry = Static<typeof ThreatRiskHistoryEntry>;
export const ThreatRiskDto = O({
  id: Str, threatModelId: Str, no: Int, code: Str, category: Str, level: Nullable(closedSet(THREAT_RISK_LEVELS)),
  statement: Str, impact: NStr, mitigation: NStr, features: Type.Array(Str),
  /** Source numbers the risk rests on (S1 …). */
  sources: Type.Array(Int),
  status: closedSet(THREAT_RISK_STATUSES), reason: NStr, decidedBy: NStr, decidedAt: NIso,
  /** A triaged risk the latest generation did not propose again (kept). */
  stale: Bool, history: Type.Array(ThreatRiskHistoryEntry), createdAt: Iso, updatedAt: Iso,
  /** what audits that referenced the threat model concluded on this risk (newest first; a suggestion only). */
  verifications: Type.Array(O({ auditId: Str, auditTitle: Str, status: Str, reason: NStr, findingId: NStr, verifiedAt: NIso })),
  /** vulnerabilities whose findings named this risk. */
  vulnerabilities: Type.Array(O({ id: Str, displayNo: Int, title: Str, confirmStatus: Str, handlingStatus: Str })),
});
export type ThreatRiskDto = Static<typeof ThreatRiskDto>;
export const ThreatRiskCounts = O(Object.fromEntries(THREAT_RISK_STATUSES.map((s) => [s, Int])) as Record<(typeof THREAT_RISK_STATUSES)[number], typeof Int>);
export type ThreatRiskCounts = Static<typeof ThreatRiskCounts>;
export const ThreatModelSummaryDto = O({
  id: Str, projectId: Str, title: Str, status: closedSet(THREAT_MODEL_STATUSES), sourceCount: Int, riskCounts: ThreatRiskCounts,
  generatedAt: NIso,
  /** Sources were added, changed or removed after the last generation. */
  sourcesChanged: Bool, createdAt: Iso, updatedAt: Iso,
});
export type ThreatModelSummaryDto = Static<typeof ThreatModelSummaryDto>;
export const ThreatModelDto = O({
  ...ThreatModelSummaryDto.properties,
  /** Markdown of the clarification (功能澄清), null before the first generation. */
  clarification: NStr, clarifiedAt: NIso, model: NStr, tokensIn: Int, tokensOut: Int, costMicros: Nullable(Int), error: NStr,
  sources: Type.Array(ThreatSourceDto), risks: Type.Array(ThreatRiskDto),
  /** Online documents it was synced to. */
  syncs: Type.Array(O({ connectorId: Str, connectorName: Str, externalId: Str, externalUrl: NStr, updatedAt: Iso })),
});
export type ThreatModelDto = Static<typeof ThreatModelDto>;
export const ThreatSyncRecordDto = O({ connectorId: Str, connectorName: Str, externalId: Str, externalUrl: NStr, updatedAt: Iso });
export type ThreatSyncRecordDto = Static<typeof ThreatSyncRecordDto>;
/** A threat-model sync to an online document: always previewed, then confirmed with the token. */
export const ThreatSyncDto = O({
  id: Str, threatModelId: Str, skill: Str, connectorId: Str, connectorName: Str, status: closedSet(['awaiting_confirm', 'done'] as const),
  action: closedSet(['create', 'update', 'skip'] as const), skipReason: NStr, reasons: Type.Array(Str),
  existing: Nullable(O({ externalId: Str, externalUrl: NStr })),
  steps: Type.Array(O({ operation: Str, args: Type.Record(Type.String(), Type.Unknown()), ok: Nullable(Bool), error: NStr })),
  payloadHash: Str, token: NStr, expiresAt: Iso, tokens: Int,
  result: Nullable(O({ ok: Bool, externalId: NStr, externalUrl: NStr, error: NStr })),
});
export type ThreatSyncDto = Static<typeof ThreatSyncDto>;
/** An MCP server configured in another tool on this machine; credentials are masked. */
export const McpImportCandidateDto = O({
  id: Str, source: Str, sourceLabel: Str, sourcePath: Str, name: Str, protocol: closedSet(['mcp_stdio', 'mcp_http'] as const),
  command: NStr, resolvedPath: NStr, args: Type.Array(Str), envKeys: Type.Array(Str), url: NStr, headerKeys: Type.Array(Str),
  secrets: Type.Array(O({ name: Str, where: closedSet(['arg', 'env', 'header', 'query'] as const), key: Str, masked: Str })),
  issues: Type.Array(Str),
});
export type McpImportCandidateDto = Static<typeof McpImportCandidateDto>;

// ---- domain plan ------------------------------------------------------------------------------
/**
 * The risk domains of a domain-hunt audit with the expert rounds run so far. `phase`: not_planned (the threat model has
 * not run yet), experts (edits reach the running stage), done (the expert phase ended: an added domain is `late` and
 * runs in a supplement once the audit is finished — `supplementable`).
 */
export const DomainPlanDto = O({
  planned: Bool,
  phase: closedSet(['not_planned', 'experts', 'done'] as const),
  editable: Bool,
  supplementable: Bool,
  domains: Type.Array(O({
    id: Str, name: Str, focus: Str, userFocus: Type.Array(Str), categories: Type.Array(Str),
    source: closedSet(['threat_model', 'fallback', 'completion', 'user'] as const),
    removed: Bool, late: Bool, supplementAuditId: NStr,
    /** `model`: the model of a crossed hunt's round (each model has its own rounds); absent otherwise. */
    rounds: Type.Array(O({ round: Int, status: Str, findings: Int, model: Type.Optional(Str) })),
  })),
});
export type DomainPlanDto = Static<typeof DomainPlanDto>;
/** One edit: add a domain (name, focus, categories), remove one, or add focus to one (domainId, text). */
export const DomainPlanEditBody = Type.Object({
  op: closedSet(['add', 'remove', 'focus'] as const),
  name: Type.Optional(Type.String({ minLength: 1, maxLength: 60 })),
  focus: Type.Optional(Type.String({ minLength: 1, maxLength: 800 })),
  categories: Type.Optional(Type.Array(closedSet(VULN_CATEGORIES), { minItems: 1, maxItems: VULN_CATEGORIES.length })),
  domainId: Type.Optional(Type.String({ minLength: 1, maxLength: 20 })),
  text: Type.Optional(Type.String({ minLength: 1, maxLength: 800 })),
}, { additionalProperties: false });
export type DomainPlanEditBody = Static<typeof DomainPlanEditBody>;

// ---- project rules from confirmed vulnerabilities ----
export const PROJECT_RULE_STATUSES = ['drafting', 'proposed', 'approved', 'rejected', 'retired', 'failed'] as const;
export const PROJECT_RULE_MATCHERS = ['tree_sitter', 'regex'] as const;
export const ProjectRuleValidationDto = O({
  originHit: Bool, hits: Int, files: Int, truncated: Bool, error: NStr,
  sample: Type.Array(O({ path: Str, startLine: Int, text: Str })),
});
export type ProjectRuleValidationDto = Static<typeof ProjectRuleValidationDto>;
export const ProjectRuleDto = O({
  id: Str, projectId: Str, vulnerabilityId: NStr, vulnDisplayNo: Nullable(Int), lang: Str, matcher: closedSet(PROJECT_RULE_MATCHERS), pattern: Str,
  category: Str, cwe: NStr, title: Str, rationale: NStr, status: closedSet(PROJECT_RULE_STATUSES), source: closedSet(['ai', 'user'] as const),
  origin: Nullable(O({ repo: Str, path: Str, startLine: Int, endLine: Int })), validation: Nullable(ProjectRuleValidationDto),
  model: NStr, tokens: Int, error: NStr, decidedAt: Nullable(Iso), createdAt: Iso, updatedAt: Iso,
});
export type ProjectRuleDto = Static<typeof ProjectRuleDto>;
/** `mode: 'ai'` drafts with the chat model (202); otherwise `matcher` + `pattern` is the user's own rule (validated now). */
export const PostProjectRuleBody = O({
  mode: Type.Optional(Type.Literal('ai')), matcher: Type.Optional(closedSet(PROJECT_RULE_MATCHERS)), pattern: Type.Optional(Type.String({ minLength: 1, maxLength: 4000 })),
  title: Type.Optional(Type.String({ maxLength: 200 })), rationale: Type.Optional(Type.String({ maxLength: 1500 })),
});
export const TestProjectRuleBody = O({ matcher: closedSet(PROJECT_RULE_MATCHERS), pattern: Type.String({ minLength: 1, maxLength: 4000 }) });
export const ProjectRuleDecisionBody = O({ decision: closedSet(['approve', 'reject', 'retire'] as const) });

// ---- verification cases; fix suggestions ----
export const VERIFICATION_OUTCOMES = ['reproduced', 'not_reproduced', 'inconclusive'] as const;
export const VerificationCaseDto = O({
  id: Str, projectId: Str, vulnerabilityId: Str, status: closedSet(['drafting', 'ready', 'failed'] as const), source: closedSet(['ai', 'user'] as const),
  preconditions: Type.Array(Str), steps: Type.Array(O({ kind: closedSet(['http', 'test', 'manual'] as const), title: Str, content: Str, lang: NStr })),
  expected: Nullable(O({ vulnerable: Str, fixed: Str })), notes: NStr, model: NStr, tokens: Int, error: NStr,
  outcome: Nullable(closedSet(VERIFICATION_OUTCOMES)), outcomeNote: NStr, outcomeAt: Nullable(Iso), createdAt: Iso, updatedAt: Iso,
});
export type VerificationCaseDto = Static<typeof VerificationCaseDto>;
export const PostCaseResultBody = O({ outcome: closedSet(VERIFICATION_OUTCOMES), note: Type.Optional(Type.String({ maxLength: 2000 })) });
export const FixSuggestionDto = O({
  id: Str, projectId: Str, vulnerabilityId: Str, status: closedSet(['drafting', 'ready', 'failed'] as const), summary: NStr,
  patches: Type.Array(O({ path: Str, diff: Str })), verify: NStr, notes: NStr, model: NStr, tokens: Int, error: NStr,
  /** The reverification started from the suggestion and its verdict on the vulnerability. */
  reverify: Nullable(O({ auditId: Str, status: Str, verdict: closedSet(['running', 'fixed', 'still_present', 'unknown'] as const) })),
  createdAt: Iso, updatedAt: Iso,
});
export type FixSuggestionDto = Static<typeof FixSuggestionDto>;
