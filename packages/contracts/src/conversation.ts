// AI conversations: closed sets, the card-producing
// tools the conversation agent may call (they never change data — the user applies a card), the audit
// plan request shared with `POST /audit-plans` (both entries build the same plan), and DTOs.
import { Type, type Static, type TSchema } from 'typebox';
import { CONFIRM_STATUSES, HANDLING_STATUSES, SEVERITIES, THREAT_SOURCE_MAX_BYTES, closedSet } from './enums.js';
import { CodeRef } from './submit.js';

export const CONVERSATION_STATUSES = ['active', 'archived'] as const;
export const MESSAGE_ROLES = ['user', 'assistant'] as const;
export const MESSAGE_STATUSES = ['streaming', 'complete', 'interrupted'] as const;
export type MessageStatus = (typeof MESSAGE_STATUSES)[number];
/** Card kinds, including `connector_draft` (配置草稿卡片). */
export const CARD_KINDS = ['audit_plan', 'audit_status', 'investigation', 'revision_suggestion', 'tool_call', 'connector_draft'] as const;
export type CardKind = (typeof CARD_KINDS)[number];
export const CARD_STATES = ['pending', 'applied', 'dismissed', 'expired', 'info'] as const;
export type CardState = (typeof CARD_STATES)[number];
export const MENTION_KINDS = ['project', 'repo', 'audit', 'vuln', 'skill'] as const;
export type MentionKind = (typeof MENTION_KINDS)[number];
export const FINISH_REASONS = ['stop', 'user_stopped', 'max_turns', 'no_subscriber', 'error', 'interrupted'] as const;
export type FinishReason = (typeof FINISH_REASONS)[number];
/** Reply stream events. */
export const MESSAGE_EVENT_TYPES = ['message_start', 'delta', 'tool_call', 'card', 'done', 'error'] as const;
export type MessageEventType = (typeof MESSAGE_EVENT_TYPES)[number];

/**
 * Files added to a user message: pasted or chosen images go to the model as images (when its entry
 * allows them, `ModelProviderConfig.models[].images`); text files, also from an added folder, as data blocks of the
 * message. Other files are refused. Stored as artifacts; later turns see only their names.
 */
export const ATTACHMENT_KINDS = ['image', 'text'] as const;
export type AttachmentKind = (typeof ATTACHMENT_KINDS)[number];
export const IMAGE_MIME_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'] as const;
export const ATTACHMENT_LIMITS = {
  files: 100, images: 5, imageBytes: 5 * 1024 * 1024, textBytes: 512 * 1024, totalTextBytes: 1024 * 1024,
} as const;

const Str = (max: number, min = 1) => Type.String({ minLength: min, maxLength: max });
const Id = Str(120);
/** A vulnerability: its id, or its number `V-n` within the conversation's projects. */
const VulnRef = Type.String({ minLength: 1, maxLength: 120, description: 'Vulnerability id, or its number V-n' });

const O = <P extends Record<string, TSchema>>(props: P, description?: string) => Type.Object(props, { additionalProperties: false, ...(description ? { description } : {}) });

export const Mention = O({ kind: closedSet(MENTION_KINDS), id: Id });
export type Mention = { kind: MentionKind; id: string };

/**
 * The audit plan request: body of `POST /audit-plans` and parameters of `propose_audit_plan` (the
 * conversation entry produces the very same plan as the form).
 */
export const AuditPlanRequest = O({
  projectId: Type.String({ minLength: 1 }), repository: Type.Optional(Type.String()), ref: Type.Optional(Type.String({ maxLength: 250 })),
  mode: Type.Optional(Type.Enum(['single', 'multi'] as const)),
  related: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 120 }), { maxItems: 50, description: '单仓库模式的关联仓库（只作证据）' })),
  repositories: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 120 }), { maxItems: 50, description: '多仓库合并审计（全量或增量）的目标仓库；省略 = 全部可审计仓库' })),
  refs: Type.Optional(Type.Record(Type.String(), Type.String({ minLength: 1, maxLength: 250 }), { description: '按仓库（名称或 id）指定版本' })),
  title: Type.Optional(Type.String({ maxLength: 200 })), scene: Type.Optional(Type.Union([Type.Literal('full'), Type.Literal('incremental')])),
  baseRef: Type.Optional(Type.String({ minLength: 1, maxLength: 250 })), baseAuditId: Type.Optional(Type.String({ minLength: 1, maxLength: 100 })),
  baseRefs: Type.Optional(Type.Record(Type.String(), Type.String({ minLength: 1, maxLength: 250 }), { description: '多仓库增量审计：按仓库（名称或 id）指定对比基线；省略的仓库用其上次审计的版本，没有则按全量审计' })),
  strategyOverride: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
});
export type AuditPlanRequest = Static<typeof AuditPlanRequest>;

// ---- conversation tools (card producers) -------------------------------------------------------

export const ReportInvestigation = O({
  title: Str(200),
  conclusion: Str(4000),
  /** Code locations read in this reply (validated like audit evidence). */
  evidence: Type.Array(CodeRef, { maxItems: 20 }),
  vulnId: Type.Optional(VulnRef),
  knowledgeRefs: Type.Optional(Type.Array(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}(/[^\\s]{1,200})?$' }), { maxItems: 10 })),
  connectorRefs: Type.Optional(Type.Array(Type.String({ pattern: '^ccl_[0-9A-Z]{26}$' }), { maxItems: 10 })),
}, 'An investigation result shown as a card; it changes nothing by itself.');
export type ReportInvestigation = Static<typeof ReportInvestigation>;

export const ProposeRevision = O({
  vulnId: VulnRef,
  confirmStatus: Type.Optional(closedSet(CONFIRM_STATUSES)),
  handlingStatus: Type.Optional(closedSet(HANDLING_STATUSES)),
  severity: Type.Optional(closedSet(SEVERITIES)),
  reason: Str(2000),
  evidence: Type.Array(CodeRef, { maxItems: 20 }),
  connectorRefs: Type.Optional(Type.Array(Type.String({ pattern: '^ccl_[0-9A-Z]{26}$' }), { maxItems: 10 })),
}, 'Suggest changing a vulnerability (at least one of confirmStatus / handlingStatus / severity). The user decides.');
export type ProposeRevision = Static<typeof ProposeRevision>;

export const ProposeAuditPlan = O({ request: AuditPlanRequest, rationale: Str(2000), recommended: Type.Optional(Type.Array(Str(300), { maxItems: 10 })) },
  'Propose starting an audit. `request` is exactly what the audit form sends; the user reviews the card and generates the plan.');
export type ProposeAuditPlan = Static<typeof ProposeAuditPlan>;

export const ProposeReverify = O({
  vulnIds: Type.Array(VulnRef, { minItems: 1, maxItems: 100 }),
  note: Type.Optional(Str(4000)),
  rationale: Str(2000),
}, 'Propose reverifying vulnerabilities.');
export type ProposeReverify = Static<typeof ProposeReverify>;

export const ProposeHunt = O({
  basis: Type.Union([
    O({ kind: Type.Literal('skill'), skill: Str(120) }),
    O({ kind: Type.Enum(['prompt', 'intel'] as const), text: Str(30_000) }),
  ]),
  projectIds: Type.Optional(Type.Array(Id, { maxItems: 200 })),
  allProjects: Type.Optional(Type.Boolean()),
  title: Type.Optional(Str(200)),
  rationale: Str(2000),
}, 'Propose a risk hunt: a basis plus the project scope.');
export type ProposeHunt = Static<typeof ProposeHunt>;

export const ProposeMerge = O({ targetId: VulnRef, sourceIds: Type.Array(VulnRef, { minItems: 1, maxItems: 50 }), reason: Str(2000) },
  'Suggest merging vulnerabilities that are the same issue (same sink and root cause) into targetId.');
export type ProposeMerge = Static<typeof ProposeMerge>;

export const ProposeSplit = O({
  vulnId: VulnRef, entryKeys: Type.Optional(Type.Array(Str(300), { maxItems: 100 })), fingerprints: Type.Optional(Type.Array(Type.String({ pattern: '^[0-9a-f]{64}$' }), { maxItems: 20 })),
  reason: Str(2000),
}, 'Suggest splitting entries or fingerprints off a vulnerability that mixes different issues.');
export type ProposeSplit = Static<typeof ProposeSplit>;

export const DraftConnector = O({
  name: Type.String({ pattern: '^[a-z0-9][a-z0-9_-]{1,63}$' }),
  protocol: Type.Enum(['mcp_stdio', 'mcp_http'] as const),
  purpose: Type.Enum(['context', 'sync'] as const),
  /** Non-secret configuration only; credentials are referenced as `${secret:name}` and entered in the settings form. */
  config: Type.Record(Type.String(), Type.Unknown()),
  secrets: Type.Optional(Type.Array(Type.String({ pattern: '^[a-z0-9_]{1,40}$' }), { maxItems: 10 })),
  notes: Type.Optional(Str(2000)),
}, 'A connector configuration draft. Never put credentials in config; name them in secrets.');
export type DraftConnector = Static<typeof DraftConnector>;

// Projects, threat models and per-vulnerability drafts from the conversation — still cards the user applies.

/** A repository to add: a local directory or a Git URL (uploads go through the form). */
const RepoSource = O({
  path: Type.Optional(Type.String({ minLength: 1, maxLength: 4096, description: '本地目录（服务所在机器的绝对路径）' })),
  git: Type.Optional(Type.String({ minLength: 1, maxLength: 2000, description: 'Git 地址：https://… 或 ssh / git@host:path；不得内嵌凭证' })),
  name: Type.Optional(Str(100)), ref: Type.Optional(Str(250)),
});

export const ProposeProject = O({
  name: Type.String({ minLength: 1, maxLength: 100, description: '字母、数字开头，可含空格、点、横线、下划线' }),
  repos: Type.Array(RepoSource, { maxItems: 20, description: '每项给出 path 或 git 之一' }),
  /** After the repositories are added: analyze repository roles, and/or start a full audit (single repository, or multi when several are auditable). */
  analyze: Type.Optional(Type.Boolean()),
  audit: Type.Optional(O({ title: Type.Optional(Str(200)), strategyOverride: Type.Optional(Type.Record(Type.String(), Type.Unknown())) })),
  rationale: Str(2000),
}, 'Propose creating a project with its repositories; optionally analyze repository roles and start a full audit right after.');
export type ProposeProject = Static<typeof ProposeProject>;

export const ThreatSourceProposal = Type.Union([
  O({ kind: Type.Literal('user_message'), title: Str(200) }, 'The text of the user message this reply answers, taken verbatim (do not copy it into a text source).'),
  O({ kind: Type.Literal('text'), title: Type.Optional(Str(200)), text: Str(THREAT_SOURCE_MAX_BYTES) }),
  O({ kind: Type.Literal('online'), title: Str(200), connectorId: Id, docRef: Str(2000) }),
]);
export type ThreatSourceProposal = Static<typeof ThreatSourceProposal>;

export const ProposeThreatModel = O({
  projectId: Id, title: Str(200),
  sources: Type.Array(ThreatSourceProposal, { minItems: 1, maxItems: 20 }),
  /** Start generating once created (default true). */
  generate: Type.Optional(Type.Boolean()),
  rationale: Str(2000),
}, 'Propose a requirement threat model: the project, the requirement sources, and whether to generate right away.');
export type ProposeThreatModel = Static<typeof ProposeThreatModel>;

export const VULN_DRAFT_KINDS = ['fix', 'case', 'rule'] as const;
export const ProposeVulnDrafts = O({
  vulnId: VulnRef, kinds: Type.Array(Type.Enum(VULN_DRAFT_KINDS), { minItems: 1, maxItems: 3, uniqueItems: true }), rationale: Str(2000),
}, 'Propose AI drafts for a vulnerability: fix = patch suggestion, case = verification case, rule = project rule against recurrence.');
export type ProposeVulnDrafts = Static<typeof ProposeVulnDrafts>;

export const ProposeAnalysis = O({ projectId: Id, rationale: Str(2000) }, 'Propose analyzing the repository roles and relations of a project (project analysis).');
export type ProposeAnalysis = Static<typeof ProposeAnalysis>;

/** Tool name → card kind. */
export const CONVERSATION_TOOLS = {
  report_investigation: 'investigation', propose_revision: 'revision_suggestion', propose_audit_plan: 'audit_plan',
  propose_reverify: 'audit_plan', propose_hunt: 'audit_plan', propose_merge: 'revision_suggestion', propose_split: 'revision_suggestion',
  draft_connector: 'connector_draft',
  propose_project: 'audit_plan', propose_threat_model: 'audit_plan', propose_vuln_drafts: 'audit_plan', propose_analysis: 'audit_plan',
} as const satisfies Record<string, CardKind>;

// ---- DTOs --------------------------------------------------------------------------------------

const N = <S extends TSchema>(s: S) => Type.Union([s, Type.Null()]);
const S = Type.String();

export const MentionDto = O({ kind: closedSet(MENTION_KINDS), id: S, label: S, valid: Type.Boolean() });
export type MentionDto = Static<typeof MentionDto>;
export const ConversationDto = O({
  id: S, title: S, model: N(S), status: closedSet(CONVERSATION_STATUSES), mentions: Type.Array(MentionDto),
  lastMessageAt: N(S), streaming: Type.Boolean(), pendingCards: Type.Integer(), createdAt: S, updatedAt: S,
  /** Pinned conversations are listed first. */
  pinned: Type.Boolean(),
  /**
   * The project the conversation is about: the first of its mentioned projects, repositories, audits and
   * vulnerabilities (engine `mentionedProjects`); “存为知识” drafts go to that project's layer.
   */
  projectId: Type.Optional(N(S)),
});
export type ConversationDto = Static<typeof ConversationDto>;
export const CardDto = O({
  id: S, conversationId: S, messageId: S, kind: closedSet(CARD_KINDS), state: closedSet(CARD_STATES),
  /** What the card shows (per kind); `result` once applied (e.g. the created audit). */
  data: Type.Record(Type.String(), Type.Unknown()), result: N(Type.Record(Type.String(), Type.Unknown())),
  /** For revision cards: the vulnerability revision the suggestion was made against. */
  targetRevision: N(Type.Integer()), decidedAt: N(S), createdAt: S,
  /**
   * A pending revision card against its vulnerability now: dimensions already at the proposed value
   * (`done`), still to change (`open`), or changed elsewhere to a third value (`conflict`: cannot apply until set back).
   * A card applied by the system because every value was set elsewhere has `result.via = 'elsewhere'`.
   */
  progress: Type.Optional(O({ done: Type.Array(S), open: Type.Array(S), conflict: Type.Array(S) })),
  /** Length of the reply text when the card appeared: cards are shown at that point of the text. */
  textOffset: Type.Optional(N(Type.Integer())),
});
export type CardDto = Static<typeof CardDto>;
export const ToolCallDto = O({
  callId: S, name: S, argsSummary: S, phase: Type.Enum(['started', 'finished'] as const), ok: N(Type.Boolean()), resultPreview: N(S),
  /** Length of the reply text when the call started (null for replies recorded before it was tracked). */
  textOffset: Type.Optional(N(Type.Integer())),
});
export type ToolCallDto = Static<typeof ToolCallDto>;
export const AttachmentDto = O({
  /** sha256 of the bytes; served at `GET /messages/{mid}/attachments/{id}`. */
  id: S, kind: closedSet(ATTACHMENT_KINDS), name: S, mimeType: S, size: Type.Integer(),
});
export type AttachmentDto = Static<typeof AttachmentDto>;
export const MessageDto = O({
  id: S, conversationId: S, seq: Type.Integer(), role: closedSet(MESSAGE_ROLES), content: S, mentions: Type.Array(MentionDto),
  attachments: Type.Array(AttachmentDto),
  status: closedSet(MESSAGE_STATUSES), finishReason: N(closedSet(FINISH_REASONS)), model: N(S), tokens: Type.Integer(),
  toolCalls: Type.Array(ToolCallDto), cards: Type.Array(CardDto), error: N(S), clientMessageId: N(S), createdAt: S,
});
export type MessageDto = Static<typeof MessageDto>;
export const MessagePageDto = O({ items: Type.Array(MessageDto), nextCursor: N(S) });
export type MessagePageDto = Static<typeof MessagePageDto>;
export const PostMessageResultDto = O({ userMessageId: S, assistantMessageId: S });
export type PostMessageResultDto = Static<typeof PostMessageResultDto>;
export const MentionCandidateDto = O({ kind: closedSet(MENTION_KINDS), id: S, label: S, detail: N(S) });
export type MentionCandidateDto = Static<typeof MentionCandidateDto>;

// ---- request bodies (shared with the server routes) ---------------------------------------------

export const PostConversationsBody = O({
  title: Type.Optional(Str(200)), model: Type.Optional(O({ provider: Str(64), model: Str(200) })),
  mentions: Type.Optional(Type.Array(Mention, { maxItems: 20 })),
});
export const PatchConversationBody = O({
  title: Type.Optional(Str(200)), status: Type.Optional(closedSet(CONVERSATION_STATUSES)), pinned: Type.Optional(Type.Boolean()),
  model: Type.Optional(N(O({ provider: Str(64), model: Str(200) }))),
});
/** A file as sent: base64 bytes; `name` is the path within an added folder. Kind and limits are checked by the engine. */
export const AttachmentInput = O({
  name: Str(500), mimeType: Type.String({ maxLength: 200 }),
  data: Type.String({ maxLength: Math.ceil(ATTACHMENT_LIMITS.imageBytes / 3) * 4, pattern: '^[A-Za-z0-9+/]*={0,2}$' }),
});
export type AttachmentInput = Static<typeof AttachmentInput>;
export const PostMessagesBody = O({
  /** Idempotency key: resending the same client id returns the same pair. */
  clientMessageId: Type.String({ pattern: '^[A-Za-z0-9_-]{8,64}$' }),
  /** May be empty when files are attached. */
  content: Str(20_000, 0),
  mentions: Type.Optional(Type.Array(Mention, { maxItems: 20 })),
  attachments: Type.Optional(Type.Array(AttachmentInput, { maxItems: ATTACHMENT_LIMITS.files })),
});
/** Edit the last user message and answer it again. */
export const EditMessageBody = O({ clientMessageId: Type.String({ pattern: '^[A-Za-z0-9_-]{8,64}$' }), content: Str(20_000) });
export const PostCardApplyBody = O({ revision: Type.Optional(Type.Integer()) });

