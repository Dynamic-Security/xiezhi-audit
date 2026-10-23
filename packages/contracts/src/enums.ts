// Closed sets shared across all packages. Security- and
// state-related fields are always closed sets; DB CHECK constraints are generated from these.
import { Type } from 'typebox';
import { AUDIT_LANGUAGE_INFO, AUDIT_LANGUAGES } from './languages.js';

/** Closed-set schema (`{enum: [...]}`) with a precise static type. */
export function closedSet<const T extends readonly string[]>(values: T) {
  return Type.Enum(values);
}

export const SCENES = ['full', 'incremental', 'risk_hunt', 'reverify'] as const;
export type Scene = (typeof SCENES)[number];

export const MODES = ['single', 'multi'] as const;
export type Mode = (typeof MODES)[number];

// Audit lifecycle
export const AUDIT_STATUSES = [
  'planning', 'awaiting_confirm', 'queued', 'running', 'waiting_budget', 'paused',
  'cancelling', 'interrupted', 'completed', 'partial', 'failed', 'cancelled',
] as const;
export type AuditStatus = (typeof AUDIT_STATUSES)[number];
export const TERMINAL_AUDIT_STATUSES: readonly AuditStatus[] = ['completed', 'partial', 'failed', 'cancelled'];
export const RESUMABLE_AUDIT_STATUSES: readonly AuditStatus[] = ['interrupted', 'paused', 'waiting_budget'];

// Step lifecycle
export const STEP_STATUSES = [
  'pending', 'ready', 'blocked_budget', 'running', 'retry_wait', 'succeeded',
  'failed', 'skipped', 'cancelled', 'interrupted',
] as const;
export type StepStatus = (typeof STEP_STATUSES)[number];

// Step kinds
export const STEP_KINDS = [
  'plan', 'snapshot', 'index', 'scope', 'profile', 'triage', 'hunt', 'challenge', 'review',
  'reconcile', 'verify-fix', 'coverage-gap', 'hunt-risk', 'decide', 'report', 'finalize',
  // risk hypotheses from the threat model (stages.threatHypotheses)
  'threat-model',
] as const;
export type StepKind = (typeof STEP_KINDS)[number];

export const MODEL_STAGES = ['triage', 'audit', 'challenge', 'merge', 'report'] as const;
export type ModelStage = (typeof MODEL_STAGES)[number];

// Error classes
export const ERROR_CLASSES = [
  'PROVIDER_TRANSIENT', 'RATE_LIMITED', 'STEP_TIMEOUT', 'CONTEXT_OVERFLOW', 'OUTPUT_CONTRACT',
  'TOOL_FAILURE', 'INTERNAL', 'AUTH_INVALID', 'MODEL_NOT_FOUND', 'CONFIG_INVALID',
  'SNAPSHOT_UNAVAILABLE', 'SECURITY_VIOLATION', 'BUDGET_EXHAUSTED', 'CANCELLED',
  // the provider's content filter refused the request (not transient: the same conversation is refused again).
  'CONTENT_FILTERED',
  // 402 / balance or quota used up — retrying cannot help; the audit pauses for a person.
  'PROVIDER_QUOTA',
] as const;
export type ErrorClass = (typeof ERROR_CLASSES)[number];
// CONTEXT_OVERFLOW is not retried: the same prompt overflows the same window again (hunt batches are split instead).
export const RETRYABLE_ERROR_CLASSES: readonly ErrorClass[] = [
  'PROVIDER_TRANSIENT', 'RATE_LIMITED', 'STEP_TIMEOUT', 'OUTPUT_CONTRACT', 'TOOL_FAILURE', 'INTERNAL',
];

// array order IS the display priority (authoritative over any other
// lowercase list).
export const PARTIAL_REASONS = [
  // COST_CAP_REACHED: no longer produced (cost cap removed); kept for audits that ended with it.
  'BUDGET_EXHAUSTED', 'DURATION_EXHAUSTED', 'COST_CAP_REACHED', 'STEP_FAILED', 'OUTPUT_CONTRACT_FAILED',
  'MODEL_UNAVAILABLE', 'ROUND_LIMIT_REACHED', 'CONTEXT_REPO_MISSING', 'INDEX_DEGRADED',
  'PENDING_QUESTIONS', 'USER_SKIPPED', 'COVERAGE_GAP',
] as const;
export type PartialReason = (typeof PARTIAL_REASONS)[number];
export function sortPartialReasons(reasons: Iterable<PartialReason>): PartialReason[] {
  const set = new Set(reasons);
  return PARTIAL_REASONS.filter((r) => set.has(r));
}

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;
export type Severity = (typeof SEVERITIES)[number];
export const CONFIDENCES = ['low', 'medium', 'high'] as const;
export type Confidence = (typeof CONFIDENCES)[number];

export const FINDING_STATES = ['submitted', 'canonical', 'merged', 'dropped', 'insufficient'] as const;
export type FindingState = (typeof FINDING_STATES)[number];
export const DROP_REASONS = ['duplicate_of', 'out_of_scope'] as const;

export const CONFIRM_STATUSES = ['pending', 'confirmed', 'false_positive'] as const;
export type ConfirmStatus = (typeof CONFIRM_STATUSES)[number];
export const HANDLING_STATUSES = ['open', 'fixing', 'fixed', 'risk_accepted'] as const;
export type HandlingStatus = (typeof HANDLING_STATUSES)[number];
export const LIFECYCLES = ['new', 'persisting', 'fixed_verified', 'regressed'] as const;
export type Lifecycle = (typeof LIFECYCLES)[number];
export const PENDING_KINDS = ['insufficient_evidence', 'missing_context'] as const;
export const DECISION_SOURCES = ['rule', 'ai', 'human'] as const;
export type DecisionSource = (typeof DECISION_SOURCES)[number];
export const MATCH_LEVELS = ['exact', 'suspected', 'manual'] as const;
export const PRESENCES = ['found', 'not_found_verified', 'not_found_unverified', 'not_covered'] as const;
export type Presence = (typeof PRESENCES)[number];
export const REVISION_DIMENSIONS = ['confirm', 'handling', 'lifecycle', 'severity', 'identity', 'entries'] as const;
export const REVISION_STATES = ['applied', 'proposed', 'rejected'] as const;
export const EVIDENCE_KINDS = [
  'code_range', 'call_chain_segment', 'tool_output', 'context_ref', 'connector', 'knowledge', 'user_answer',
] as const;
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

export const SOURCE_KINDS = ['local', 'git', 'archive'] as const;
export const REPO_ROLES = ['gateway', 'auth', 'business', 'api_def', 'frontend', 'shared_lib', 'unknown'] as const;
/** Controlled vocabularies for skill `applies_to`: the ids the prefilter matches against. */
export const KNOWLEDGE_LANGUAGES = AUDIT_LANGUAGES;
export const KNOWLEDGE_FRAMEWORKS = [...new Set(AUDIT_LANGUAGES.flatMap((l) => AUDIT_LANGUAGE_INFO[l].frameworks))];
export const ROLE_IN_AUDIT = ['target', 'related', 'context'] as const;
export const COVERAGE_KINDS = ['entry', 'sink'] as const;
export const COVERAGE_STATUSES = ['uncovered', 'read', 'concluded', 'excluded', 'failed'] as const;
/**
 * what an audit must settle. entry / sink: the coverage ledger; hypothesis: risk hypotheses to verify;
 * access: access-policy differences; checklist / external: the `obligation` table (checklist items, external scanners).
 */
export const OBLIGATION_KINDS = ['entry', 'sink', 'hypothesis', 'access', 'checklist', 'external'] as const;
export type ObligationKind = (typeof OBLIGATION_KINDS)[number];
/**
 * enterprise facts — what the enterprise is like (knowledge says how to audit). Topic, where it came
 * from, how far it can be trusted (authoritative source / confirmed by a person or by configuration / unverified), how
 * sensitive it is, whether it is in force.
 */
export const FACT_TOPICS = ['gateway', 'auth', 'deployment', 'network', 'business_rule', 'architecture', 'data', 'integration', 'other'] as const;
export type FactTopic = (typeof FACT_TOPICS)[number];
export const FACT_SOURCES = ['user', 'knowledge', 'architecture_import', 'topology', 'question', 'requirement_risk', 'profile', 'review', 'gateway_config'] as const;
export type FactSource = (typeof FACT_SOURCES)[number];
export const FACT_TRUST = ['authoritative', 'verified', 'unverified'] as const;
export type FactTrust = (typeof FACT_TRUST)[number];
export const FACT_SENSITIVITY = ['public', 'internal', 'confidential'] as const;
export type FactSensitivity = (typeof FACT_SENSITIVITY)[number];
export const FACT_STATUSES = ['active', 'superseded', 'retracted'] as const;
export type FactStatus = (typeof FACT_STATUSES)[number];
/** States of an `obligation` row: open (not assessed), covered / not_applicable / concluded (settled), uncovered (needs a review). */
export const OBLIGATION_STATUSES = ['open', 'covered', 'not_applicable', 'uncovered', 'concluded'] as const;
export type ObligationStatus = (typeof OBLIGATION_STATUSES)[number];
export const QUESTION_STATUSES = ['open', 'answered', 'dismissed', 'expired'] as const;
export const AUDIT_ORIGINS = ['ui', 'cli', 'conversation'] as const;
/** Knowledge categories, including `push_guide` (推送指引) and `security_spec`. */
export const SKILL_CATEGORIES = ['vuln_case', 'audit_method', 'report', 'business', 'architecture', 'push_guide', 'security_spec'] as const;
export type SkillCategory = (typeof SKILL_CATEGORIES)[number];
export const SKILL_LAYERS = ['global', 'project'] as const;
export const SKILL_LOAD_LEVELS = ['index', 'body', 'file'] as const;
export const SKILL_TRIGGERS = ['on_demand', 'always', 'phase', 'user_pinned', 'knowledge_need'] as const;
export type SkillTrigger = (typeof SKILL_TRIGGERS)[number];

// Requirement threat models. Migration 30 has the same lists.
export const THREAT_MODEL_STATUSES = ['draft', 'generating', 'ready', 'partial', 'failed'] as const;
export type ThreatModelStatus = (typeof THREAT_MODEL_STATUSES)[number];
export const THREAT_SOURCE_KINDS = ['upload', 'online', 'text'] as const;
export type ThreatSourceKind = (typeof THREAT_SOURCE_KINDS)[number];
export const THREAT_FETCH_STATUSES = ['pending', 'ok', 'failed'] as const;
/** 待研判 / 需规避 / 已规避 / 接受风险 / 误报·不适用. */
export const THREAT_RISK_STATUSES = ['pending', 'to_mitigate', 'mitigated', 'accepted', 'false_positive'] as const;
export type ThreatRiskStatus = (typeof THREAT_RISK_STATUSES)[number];
export const THREAT_RISK_LEVELS = ['high', 'medium', 'low'] as const;
/** One source's text, as for a knowledge file; the number of sources is not limited. */
export const THREAT_SOURCE_MAX_BYTES = 256 * 1024;
/** Risk categories of a requirement threat model: STRIDE plus business logic and abuse (skill threat-modeling-method). */
export const THREAT_RISK_CATEGORIES = [
  'spoofing', 'tampering', 'repudiation', 'information_disclosure', 'denial_of_service', 'elevation_of_privilege', 'business_logic', 'abuse',
] as const;
