// Schema migrations. A shipped migration's SQL never changes: its checksum is stored in every
// database it ran on, and db.ts#migrate refuses a database whose stored checksum it does not recognise. CHECK lists
// therefore come from the closed-set values frozen below (the contracts values as of migration 26), not from the live
// contracts sets. Adding a value to a contracts closed set that a CHECK uses takes a new migration that rebuilds the
// table (migrations 19, 23, 26) with its own literal list; a test compares the final schema with contracts.
// migration 1 used to interpolate the live sets, so STEP_KINDS and ERROR_CLASSES
// changed its SQL and older data directories stopped opening; those historical checksums are accepted below.
import { sha256Hex } from '@xiezhi/contracts';

/** Closed-set values used by migrations 1–26, frozen. Never edit: add a migration instead. */
const FROZEN = {
  AUDIT_STATUSES: ['planning', 'awaiting_confirm', 'queued', 'running', 'waiting_budget', 'paused', 'cancelling', 'interrupted', 'completed', 'partial', 'failed', 'cancelled'],
  AUDIT_ORIGINS: ['ui', 'cli', 'conversation'],
  CONFIDENCES: ['low', 'medium', 'high'],
  CONFIRM_STATUSES: ['pending', 'confirmed', 'false_positive'],
  COVERAGE_KINDS: ['entry', 'sink'],
  COVERAGE_STATUSES: ['uncovered', 'read', 'concluded', 'excluded', 'failed'],
  DECISION_SOURCES: ['rule', 'ai', 'human'],
  EVIDENCE_KINDS: ['code_range', 'call_chain_segment', 'tool_output', 'context_ref', 'connector', 'knowledge', 'user_answer'],
  ERROR_CLASSES: ['PROVIDER_TRANSIENT', 'RATE_LIMITED', 'STEP_TIMEOUT', 'CONTEXT_OVERFLOW', 'OUTPUT_CONTRACT', 'TOOL_FAILURE', 'INTERNAL', 'AUTH_INVALID', 'MODEL_NOT_FOUND', 'CONFIG_INVALID', 'SNAPSHOT_UNAVAILABLE', 'SECURITY_VIOLATION', 'BUDGET_EXHAUSTED', 'CANCELLED', 'CONTENT_FILTERED'],
  FINDING_STATES: ['submitted', 'canonical', 'merged', 'dropped', 'insufficient'],
  HANDLING_STATUSES: ['open', 'fixing', 'fixed', 'risk_accepted'],
  LIFECYCLES: ['new', 'persisting', 'fixed_verified', 'regressed'],
  MATCH_LEVELS: ['exact', 'suspected', 'manual'],
  MODES: ['single', 'multi'],
  PENDING_KINDS: ['insufficient_evidence', 'missing_context'],
  PRESENCES: ['found', 'not_found_verified', 'not_found_unverified', 'not_covered'],
  QUESTION_STATUSES: ['open', 'answered', 'dismissed', 'expired'],
  REPO_ROLES: ['gateway', 'auth', 'business', 'api_def', 'frontend', 'shared_lib', 'unknown'],
  REVISION_DIMENSIONS: ['confirm', 'handling', 'lifecycle', 'severity', 'identity', 'entries'],
  REVISION_STATES: ['applied', 'proposed', 'rejected'],
  ROLE_IN_AUDIT: ['target', 'related', 'context'],
  SCENES: ['full', 'incremental', 'risk_hunt', 'reverify'],
  SEVERITIES: ['info', 'low', 'medium', 'high', 'critical'],
  SKILL_LAYERS: ['global', 'project'],
  SKILL_LOAD_LEVELS: ['index', 'body', 'file'],
  SKILL_TRIGGERS: ['on_demand', 'always', 'phase', 'user_pinned', 'knowledge_need'],
  SOURCE_KINDS: ['local', 'git', 'archive'],
  STEP_KINDS: ['plan', 'snapshot', 'index', 'scope', 'profile', 'triage', 'hunt', 'challenge', 'review', 'reconcile', 'verify-fix', 'coverage-gap', 'hunt-risk', 'decide', 'report', 'finalize', 'threat-model'],
  STEP_STATUSES: ['pending', 'ready', 'blocked_budget', 'running', 'retry_wait', 'succeeded', 'failed', 'skipped', 'cancelled', 'interrupted'],
  CARD_KINDS: ['audit_plan', 'audit_status', 'investigation', 'revision_suggestion', 'tool_call', 'connector_draft'],
  CARD_STATES: ['pending', 'applied', 'dismissed', 'expired', 'info'],
  CONVERSATION_STATUSES: ['active', 'archived'],
  FINISH_REASONS: ['stop', 'user_stopped', 'max_turns', 'no_subscriber', 'error', 'interrupted'],
  MESSAGE_EVENT_TYPES: ['message_start', 'delta', 'tool_call', 'card', 'done', 'error'],
  MESSAGE_ROLES: ['user', 'assistant'],
  MESSAGE_STATUSES: ['streaming', 'complete', 'interrupted'],
} as const;
const {
  AUDIT_STATUSES, AUDIT_ORIGINS, CONFIDENCES, CONFIRM_STATUSES, COVERAGE_KINDS, COVERAGE_STATUSES, DECISION_SOURCES,
  EVIDENCE_KINDS, ERROR_CLASSES, FINDING_STATES, HANDLING_STATUSES, LIFECYCLES, MATCH_LEVELS, MODES, PENDING_KINDS,
  PRESENCES, QUESTION_STATUSES, REPO_ROLES, REVISION_DIMENSIONS, REVISION_STATES, ROLE_IN_AUDIT, SCENES,
  SEVERITIES, SKILL_LAYERS, SKILL_LOAD_LEVELS, SKILL_TRIGGERS, SOURCE_KINDS, STEP_KINDS, STEP_STATUSES, CARD_KINDS,
  CARD_STATES, CONVERSATION_STATUSES, FINISH_REASONS, MESSAGE_EVENT_TYPES, MESSAGE_ROLES, MESSAGE_STATUSES,
} = FROZEN;

const q = (vals: readonly string[]) => vals.map((v) => `'${v}'`).join(',');
const inSet = (col: string, vals: readonly string[], nullable = false) =>
  nullable ? `CHECK(${col} IS NULL OR ${col} IN (${q(vals)}))` : `CHECK(${col} IN (${q(vals)}))`;
const json = (col: string, nullable = false) => nullable ? `CHECK(${col} IS NULL OR json_valid(${col}))` : `CHECK(json_valid(${col}))`;
const TS = 'created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL';

const M001 = `
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL ${json('value')}, schema_version INTEGER NOT NULL DEFAULT 1, ${TS});

CREATE TABLE project (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'active' ${inSet('status', ['active', 'archived'])},
  next_vuln_no INTEGER NOT NULL DEFAULT 1, ${TS});

CREATE TABLE repository (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  name TEXT NOT NULL, source_kind TEXT NOT NULL ${inSet('source_kind', SOURCE_KINDS)}, source_uri TEXT NOT NULL,
  default_ref TEXT, languages TEXT NOT NULL DEFAULT '[]' ${json('languages')}, modules TEXT NOT NULL DEFAULT '[]' ${json('modules')},
  is_auditable INTEGER NOT NULL DEFAULT 1 CHECK(is_auditable IN (0,1)),
  role TEXT NOT NULL DEFAULT 'unknown' ${inSet('role', REPO_ROLES)},
  role_source TEXT NOT NULL DEFAULT 'user' ${inSet('role_source', ['ai', 'user'])},
  removed_at INTEGER, ${TS}, UNIQUE(project_id, name));
CREATE INDEX idx_repository_project ON repository(project_id);

CREATE TABLE snapshot (
  id TEXT PRIMARY KEY, repository_id TEXT NOT NULL REFERENCES repository(id) ON DELETE CASCADE,
  root_hash TEXT NOT NULL, manifest_ref TEXT NOT NULL, requested_ref TEXT, resolved_ref_name TEXT, resolved_commit TEXT,
  is_worktree INTEGER NOT NULL DEFAULT 0, file_count INTEGER NOT NULL, bytes INTEGER NOT NULL, ${TS},
  UNIQUE(repository_id, root_hash));
CREATE INDEX idx_snapshot_root ON snapshot(root_hash);

CREATE TABLE audit (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  scene TEXT NOT NULL ${inSet('scene', SCENES)}, mode TEXT NOT NULL ${inSet('mode', MODES)}, title TEXT NOT NULL,
  status TEXT NOT NULL ${inSet('status', AUDIT_STATUSES)}, phase TEXT,
  strategy_draft TEXT NOT NULL ${json('strategy_draft')}, strategy_sources TEXT NOT NULL ${json('strategy_sources')},
  strategy_frozen TEXT ${json('strategy_frozen', true)}, strategy_hash TEXT, plan_ref TEXT, knowledge_ref TEXT, gate_ref TEXT,
  running_since INTEGER,
  scope TEXT NOT NULL DEFAULT '{}' ${json('scope')}, base_audit_id TEXT REFERENCES audit(id) ON DELETE SET NULL,
  partial_reasons TEXT NOT NULL DEFAULT '[]' ${json('partial_reasons')},
  budget_initial TEXT NOT NULL ${json('budget_initial')}, budget_effective TEXT NOT NULL ${json('budget_effective')},
  budget_consumed TEXT NOT NULL ${json('budget_consumed')}, budget_reserved TEXT NOT NULL DEFAULT '{"tokens":0}' ${json('budget_reserved')},
  report_refs TEXT NOT NULL DEFAULT '{}' ${json('report_refs')},
  origin TEXT NOT NULL ${inSet('origin', AUDIT_ORIGINS)}, conversation_id TEXT,
  lease_owner TEXT, lease_expires_at INTEGER, last_event_seq INTEGER NOT NULL DEFAULT 0,
  error_class TEXT ${inSet('error_class', ERROR_CLASSES, true)}, queued_at INTEGER, started_at INTEGER, ended_at INTEGER, ${TS});
CREATE INDEX idx_audit_project ON audit(project_id, created_at);
CREATE INDEX idx_audit_status ON audit(status);
CREATE TRIGGER audit_strategy_frozen_immutable BEFORE UPDATE OF strategy_frozen ON audit
  WHEN OLD.strategy_frozen IS NOT NULL AND NEW.strategy_frozen IS NOT OLD.strategy_frozen
  BEGIN SELECT RAISE(ABORT, 'strategy_frozen is immutable'); END;

CREATE TABLE audit_repository (
  audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  repository_id TEXT NOT NULL REFERENCES repository(id),
  snapshot_id TEXT REFERENCES snapshot(id), base_snapshot_id TEXT REFERENCES snapshot(id),
  requested_ref TEXT,
  role_in_audit TEXT NOT NULL ${inSet('role_in_audit', ROLE_IN_AUDIT)}, ${TS},
  PRIMARY KEY(audit_id, repository_id));
CREATE INDEX idx_audit_repository_snapshot ON audit_repository(snapshot_id);

CREATE TABLE budget_adjustment (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  idempotency_key TEXT NOT NULL, delta TEXT NOT NULL ${json('delta')}, reason TEXT,
  actor TEXT NOT NULL ${inSet('actor', ['user', 'cli'])}, ${TS}, UNIQUE(audit_id, idempotency_key));

CREATE TABLE step (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  parent_step_id TEXT, seq INTEGER NOT NULL, kind TEXT NOT NULL ${inSet('kind', STEP_KINDS)}, lineage_id TEXT,
  status TEXT NOT NULL ${inSet('status', STEP_STATUSES)}, required INTEGER NOT NULL DEFAULT 0,
  attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 2,
  idempotency_key TEXT NOT NULL, depends_on TEXT NOT NULL DEFAULT '[]' ${json('depends_on')},
  input TEXT NOT NULL DEFAULT '{}' ${json('input')}, input_ref TEXT, output_ref TEXT, reused_from TEXT,
  model TEXT, provider TEXT, tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0,
  tokens_cached INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER, estimated_usage INTEGER NOT NULL DEFAULT 0,
  estimate_tokens INTEGER NOT NULL DEFAULT 0, retry_at INTEGER,
  error_class TEXT ${inSet('error_class', ERROR_CLASSES, true)}, error_ref TEXT, error_summary TEXT,
  started_at INTEGER, ended_at INTEGER, ${TS}, UNIQUE(audit_id, idempotency_key), UNIQUE(audit_id, seq));
CREATE INDEX idx_step_audit_status ON step(audit_id, status);

CREATE TABLE step_attempt (
  step_id TEXT NOT NULL REFERENCES step(id) ON DELETE CASCADE, attempt INTEGER NOT NULL,
  outcome TEXT ${inSet('outcome', ['succeeded', 'failed', 'aborted', 'interrupted', 'cancelled'], true)},
  error_class TEXT ${inSet('error_class', ERROR_CLASSES, true)}, tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0, tokens_cached INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER,
  submitted_ref TEXT, started_at INTEGER NOT NULL, ended_at INTEGER, ${TS}, PRIMARY KEY(step_id, attempt));

CREATE TABLE event (
  audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, seq INTEGER NOT NULL, type TEXT NOT NULL,
  step_id TEXT, ts INTEGER NOT NULL, payload TEXT NOT NULL ${json('payload')}, payload_ref TEXT,
  PRIMARY KEY(audit_id, seq));
CREATE INDEX idx_event_type ON event(audit_id, type);

CREATE TABLE question (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, step_id TEXT,
  work_item_id TEXT, text TEXT NOT NULL, context_ref TEXT, blocking INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL ${inSet('status', QUESTION_STATUSES)}, answer TEXT, answered_at INTEGER,
  save_as_skill TEXT NOT NULL DEFAULT 'none' ${inSet('save_as_skill', ['none', 'offered', 'saved', 'declined'])}, ${TS});
CREATE INDEX idx_question_status ON question(status);

CREATE TABLE cognitive_state (
  audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, version INTEGER NOT NULL, step_id TEXT,
  confirmed_facts TEXT NOT NULL ${json('confirmed_facts')}, active_hypotheses TEXT NOT NULL ${json('active_hypotheses')},
  pending_questions TEXT NOT NULL ${json('pending_questions')}, ruled_out_directions TEXT NOT NULL ${json('ruled_out_directions')},
  explored_nodes TEXT NOT NULL ${json('explored_nodes')}, knowledge_needs TEXT NOT NULL ${json('knowledge_needs')},
  ${TS}, PRIMARY KEY(audit_id, version));

CREATE TABLE finding (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, step_id TEXT NOT NULL,
  lineage_id TEXT, repository_id TEXT NOT NULL, display_no INTEGER, category TEXT NOT NULL, cwe TEXT, title TEXT NOT NULL,
  severity TEXT NOT NULL ${inSet('severity', SEVERITIES)}, confidence TEXT NOT NULL ${inSet('confidence', CONFIDENCES)},
  confidence_score REAL NOT NULL, module TEXT, sink_symbol TEXT, sink_api TEXT, entry_keys TEXT NOT NULL DEFAULT '[]' ${json('entry_keys')},
  root_cause TEXT, location TEXT NOT NULL ${json('location')}, fp_sink TEXT, fp_entry TEXT, detail_ref TEXT NOT NULL,
  source TEXT NOT NULL ${inSet('source', ['rule', 'ai'])}, model TEXT,
  state TEXT NOT NULL ${inSet('state', FINDING_STATES)}, drop_reason TEXT, confirmation TEXT NOT NULL DEFAULT 'maintain'
  ${inSet('confirmation', ['maintain', 'pending'])}, challenge_ref TEXT, ${TS}, UNIQUE(audit_id, display_no));
CREATE INDEX idx_finding_audit_state ON finding(audit_id, state);
CREATE INDEX idx_finding_fp_sink ON finding(fp_sink);

CREATE TABLE finding_merge (
  audit_id TEXT NOT NULL, source_finding_id TEXT PRIMARY KEY REFERENCES finding(id) ON DELETE CASCADE,
  target_finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  method TEXT NOT NULL ${inSet('method', ['deterministic', 'semantic'])}, group_label TEXT, reason TEXT, ${TS});

CREATE TABLE vulnerability (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE, display_no INTEGER NOT NULL,
  repository_id TEXT NOT NULL, module TEXT, category TEXT NOT NULL, cwe TEXT, title TEXT NOT NULL,
  severity TEXT NOT NULL ${inSet('severity', SEVERITIES)}, severity_original TEXT ${inSet('severity_original', SEVERITIES, true)},
  confidence TEXT NOT NULL ${inSet('confidence', CONFIDENCES)}, sink_symbol TEXT, sink_api TEXT, root_cause TEXT,
  confirm_status TEXT NOT NULL ${inSet('confirm_status', CONFIRM_STATUSES)},
  handling_status TEXT NOT NULL DEFAULT 'open' ${inSet('handling_status', HANDLING_STATUSES)},
  lifecycle TEXT NOT NULL ${inSet('lifecycle', LIFECYCLES)}, pending_kind TEXT ${inSet('pending_kind', PENDING_KINDS, true)},
  missing_context TEXT ${json('missing_context', true)}, handling_reason TEXT,
  sources TEXT NOT NULL DEFAULT '[]' ${json('sources')}, evidence_complete INTEGER NOT NULL DEFAULT 0 CHECK(evidence_complete IN (0,1)),
  suspected_link INTEGER NOT NULL DEFAULT 0, detail_ref TEXT NOT NULL,
  first_seen_audit_id TEXT, last_seen_audit_id TEXT, last_verified_audit_id TEXT,
  status TEXT NOT NULL DEFAULT 'active' ${inSet('status', ['active', 'merged'])}, merged_into_id TEXT, ${TS},
  UNIQUE(project_id, display_no));
CREATE INDEX idx_vuln_lifecycle ON vulnerability(project_id, lifecycle);
CREATE INDEX idx_vuln_confirm ON vulnerability(project_id, confirm_status);
CREATE TRIGGER vuln_confirm_requires_evidence BEFORE UPDATE OF confirm_status ON vulnerability
  WHEN NEW.confirm_status = 'confirmed' AND NEW.evidence_complete = 0
  BEGIN SELECT RAISE(ABORT, 'confirmed requires evidence_complete=1'); END;
CREATE TRIGGER vuln_confirm_requires_evidence_insert BEFORE INSERT ON vulnerability
  WHEN NEW.confirm_status = 'confirmed' AND NEW.evidence_complete = 0
  BEGIN SELECT RAISE(ABORT, 'confirmed requires evidence_complete=1'); END;

CREATE TABLE vuln_fingerprint (
  vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE, project_id TEXT NOT NULL, fp TEXT NOT NULL,
  kind TEXT NOT NULL ${inSet('kind', ['anchor', 'rename', 'merged', 'manual'])}, since_audit_id TEXT, active INTEGER NOT NULL DEFAULT 1, ${TS});
CREATE UNIQUE INDEX idx_vuln_fp_active ON vuln_fingerprint(project_id, fp) WHERE active = 1;

CREATE TABLE vuln_occurrence (
  id TEXT PRIMARY KEY, vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
  audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, finding_id TEXT,
  match_level TEXT ${inSet('match_level', MATCH_LEVELS, true)}, match_basis TEXT NOT NULL DEFAULT '{}' ${json('match_basis')},
  presence TEXT NOT NULL ${inSet('presence', PRESENCES)}, reverify_verdict TEXT,
  lifecycle_before TEXT, lifecycle_after TEXT, ${TS}, UNIQUE(vulnerability_id, audit_id, finding_id));
CREATE INDEX idx_occurrence_audit ON vuln_occurrence(audit_id);

CREATE TABLE vuln_entry (
  vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE, entry_key TEXT NOT NULL,
  repository_id TEXT NOT NULL, first_seen_audit_id TEXT, last_seen_audit_id TEXT,
  state TEXT NOT NULL DEFAULT 'active' ${inSet('state', ['active', 'fixed', 'unknown'])}, ${TS}, PRIMARY KEY(vulnerability_id, entry_key));

CREATE TABLE evidence (
  id TEXT PRIMARY KEY, owner_kind TEXT NOT NULL ${inSet('owner_kind', ['finding', 'vulnerability', 'risk_hunt_target', 'revision'])},
  owner_id TEXT NOT NULL, kind TEXT NOT NULL ${inSet('kind', EVIDENCE_KINDS)}, snapshot_id TEXT, path TEXT,
  start_line INTEGER, end_line INTEGER, content_hash TEXT, artifact_ref TEXT, origin_label TEXT,
  verified INTEGER NOT NULL DEFAULT 0, step_id TEXT, note TEXT, ord INTEGER NOT NULL DEFAULT 0, ${TS});
CREATE INDEX idx_evidence_owner ON evidence(owner_kind, owner_id);

CREATE TABLE revision (
  id TEXT PRIMARY KEY, vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE, seq INTEGER NOT NULL,
  dimension TEXT NOT NULL ${inSet('dimension', REVISION_DIMENSIONS)}, source TEXT NOT NULL ${inSet('source', DECISION_SOURCES)},
  actor TEXT NOT NULL, from_value TEXT ${json('from_value', true)}, to_value TEXT ${json('to_value', true)}, reason TEXT,
  evidence_ids TEXT NOT NULL DEFAULT '[]' ${json('evidence_ids')}, audit_id TEXT, conversation_id TEXT,
  state TEXT NOT NULL ${inSet('state', REVISION_STATES)}, ${TS}, UNIQUE(vulnerability_id, seq));
CREATE INDEX idx_revision_state ON revision(state);

CREATE TABLE coverage_item (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, repository_id TEXT NOT NULL,
  snapshot_id TEXT NOT NULL, kind TEXT NOT NULL ${inSet('kind', COVERAGE_KINDS)}, item_key TEXT NOT NULL, target_id TEXT NOT NULL,
  category TEXT, rule_id TEXT, path TEXT NOT NULL, start_line INTEGER NOT NULL, end_line INTEGER NOT NULL,
  status TEXT NOT NULL ${inSet('status', COVERAGE_STATUSES)}, verdict TEXT, concluded_by_step TEXT, finding_id TEXT,
  ${TS}, UNIQUE(audit_id, kind, target_id));
CREATE INDEX idx_coverage_status ON coverage_item(audit_id, kind, status);

CREATE TABLE read_coverage (
  audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, repository_id TEXT NOT NULL, path TEXT NOT NULL,
  ranges TEXT NOT NULL ${json('ranges')}, lines_read INTEGER NOT NULL, file_lines INTEGER NOT NULL, last_step_id TEXT,
  PRIMARY KEY(audit_id, repository_id, path));

CREATE TABLE skill_usage (
  id TEXT PRIMARY KEY, audit_id TEXT, conversation_id TEXT, step_id TEXT, skill_name TEXT NOT NULL,
  layer TEXT NOT NULL ${inSet('layer', SKILL_LAYERS)}, skill_hash TEXT NOT NULL, level TEXT NOT NULL ${inSet('level', SKILL_LOAD_LEVELS)},
  trigger TEXT NOT NULL ${inSet('trigger', SKILL_TRIGGERS)}, reason TEXT, tokens INTEGER NOT NULL DEFAULT 0, ${TS});
CREATE INDEX idx_skill_usage_audit ON skill_usage(audit_id);

CREATE TABLE artifact (sha256 TEXT PRIMARY KEY, size INTEGER NOT NULL, media_type TEXT NOT NULL, last_marked_at INTEGER, ${TS});
`;

// optimistic-concurrency counters, API idempotency records, export jobs.
const M002 = `
ALTER TABLE vulnerability ADD COLUMN rev INTEGER NOT NULL DEFAULT 1;
ALTER TABLE audit ADD COLUMN draft_rev INTEGER NOT NULL DEFAULT 1;

CREATE TABLE idempotency_record (
  key TEXT NOT NULL, route TEXT NOT NULL, body_hash TEXT NOT NULL, status INTEGER NOT NULL,
  response TEXT NOT NULL ${json('response')}, expires_at INTEGER NOT NULL, ${TS}, PRIMARY KEY(key, route));
CREATE INDEX idx_idempotency_expires ON idempotency_record(expires_at);

CREATE TABLE export_job (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  format TEXT NOT NULL ${inSet('format', ['md', 'html', 'json', 'sarif'])}, options TEXT NOT NULL ${json('options')},
  status TEXT NOT NULL ${inSet('status', ['succeeded', 'failed'])}, artifact_ref TEXT, bytes INTEGER NOT NULL DEFAULT 0, error TEXT, ${TS});
CREATE INDEX idx_export_audit ON export_job(audit_id);
`;

// the baseline ref requested for an incremental audit (the baseline
// snapshot itself is audit_repository.base_snapshot_id, present since migration 1).
const M003 = `
ALTER TABLE audit_repository ADD COLUMN base_requested_ref TEXT;
`;

// source details that are not the locator — archive file name, root hash
// of its fixed snapshot and embedded HEAD commit; remote default branch.
const M004 = `
ALTER TABLE repository ADD COLUMN source_meta TEXT NOT NULL DEFAULT '{}' CHECK(json_valid(source_meta));
`;

// project analysis runs (manual) and per-repository role results, cached
// by (signals, model, prompt version).
const M005 = `
CREATE TABLE project_analysis (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  status TEXT NOT NULL ${inSet('status', ['running', 'succeeded', 'partial', 'failed', 'interrupted'])},
  model TEXT, reason TEXT, tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER,
  started_at INTEGER NOT NULL, ended_at INTEGER, ${TS});
CREATE INDEX idx_project_analysis_project ON project_analysis(project_id, started_at);
CREATE TABLE repo_analysis (
  id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES project_analysis(id) ON DELETE CASCADE,
  repository_id TEXT NOT NULL REFERENCES repository(id) ON DELETE CASCADE, root_hash TEXT,
  status TEXT NOT NULL ${inSet('status', ['succeeded', 'reused', 'skipped', 'failed'])},
  signals_ref TEXT, result_ref TEXT, cache_key TEXT, error TEXT, tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0, ${TS});
CREATE INDEX idx_repo_analysis_repo ON repo_analysis(repository_id, created_at);
CREATE INDEX idx_repo_analysis_cache ON repo_analysis(cache_key);
`;

// connection points per repository analysis, matches per
// project analysis, and the project topology (AI edges rebuilt per analysis; user edges and user
// deletions survive). An audit freezes the topology it started with (audit.topology_ref).
const M006 = `
ALTER TABLE repo_analysis ADD COLUMN connections_ref TEXT;
ALTER TABLE project_analysis ADD COLUMN matches_ref TEXT;
ALTER TABLE project ADD COLUMN topology_revision INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit ADD COLUMN topology_ref TEXT;
CREATE TABLE topology_node (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  kind TEXT NOT NULL ${inSet('kind', ['repo', 'service', 'external_service', 'gateway', 'mq_topic'])},
  repository_id TEXT REFERENCES repository(id) ON DELETE CASCADE, name TEXT NOT NULL,
  origin TEXT NOT NULL ${inSet('origin', ['ai', 'imported', 'user'])}, attrs TEXT NOT NULL DEFAULT '{}' ${json('attrs')}, ${TS});
CREATE INDEX idx_topology_node_project ON topology_node(project_id);
CREATE TABLE topology_edge (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  from_node TEXT NOT NULL REFERENCES topology_node(id) ON DELETE CASCADE, to_node TEXT NOT NULL REFERENCES topology_node(id) ON DELETE CASCADE,
  kind TEXT NOT NULL ${inSet('kind', ['contract', 'client_call', 'message', 'shared_lib', 'frontend_api'])},
  protocol TEXT NOT NULL ${inSet('protocol', ['http', 'grpc', 'dubbo', 'mq', 'gateway_route', 'shared_lib'])},
  origin TEXT NOT NULL ${inSet('origin', ['ai', 'imported', 'user'])},
  confidence TEXT NOT NULL ${inSet('confidence', ['confirmed', 'inferred'])},
  evidence TEXT NOT NULL DEFAULT '[]' ${json('evidence')}, removed INTEGER NOT NULL DEFAULT 0 CHECK(removed IN (0,1)),
  derived_analysis_id TEXT, ${TS});
CREATE INDEX idx_topology_edge_project ON topology_edge(project_id);
`;

// risk_hunt / risk_hunt_target: risk hunt bases (drafted by AI,
// confirmed by the user), hunts over one or more projects, and per-repository verdicts. Each project
// of a hunt runs as one scene=risk_hunt audit.
const M007 = `
CREATE TABLE hunt_basis (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL ${inSet('kind', ['skill', 'prompt', 'intel', 'report', 'ticket'])},
  title TEXT NOT NULL, input_ref TEXT NOT NULL, basis_ref TEXT, skill_name TEXT,
  status TEXT NOT NULL ${inSet('status', ['drafting', 'ready', 'failed'])}, error TEXT, revision INTEGER NOT NULL DEFAULT 1,
  model TEXT, tokens INTEGER NOT NULL DEFAULT 0, ${TS});
CREATE TABLE risk_hunt (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, basis_id TEXT REFERENCES hunt_basis(id) ON DELETE SET NULL,
  basis_kind TEXT NOT NULL ${inSet('basis_kind', ['skill', 'prompt', 'intel', 'report', 'ticket'])}, basis_ref TEXT NOT NULL, basis_hash TEXT NOT NULL,
  skill_name TEXT, scope TEXT NOT NULL ${json('scope')}, rerun_of_id TEXT REFERENCES risk_hunt(id) ON DELETE SET NULL,
  status TEXT NOT NULL ${inSet('status', ['planned', 'running', 'completed', 'partial', 'failed', 'cancelled'])},
  summary TEXT NOT NULL DEFAULT '{}' ${json('summary')}, started_at INTEGER, ended_at INTEGER, ${TS});
CREATE INDEX idx_risk_hunt_basis ON risk_hunt(basis_hash);
CREATE TABLE risk_hunt_target (
  id TEXT PRIMARY KEY, risk_hunt_id TEXT NOT NULL REFERENCES risk_hunt(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE, repository_id TEXT REFERENCES repository(id) ON DELETE CASCADE,
  audit_id TEXT REFERENCES audit(id) ON DELETE SET NULL,
  verdict TEXT ${inSet('verdict', ['affected', 'not_affected', 'pending'], true)}, reason TEXT, verdict_source TEXT ${inSet('verdict_source', ['rule', 'ai', 'human'], true)},
  pending_condition TEXT ${json('pending_condition', true)},
  delta_vs_previous TEXT ${inSet('delta_vs_previous', ['new_affected', 'cleared', 'unchanged', 'new'], true)}, ${TS},
  UNIQUE(risk_hunt_id, project_id, repository_id));
CREATE INDEX idx_risk_hunt_target_hunt ON risk_hunt_target(risk_hunt_id);
ALTER TABLE finding ADD COLUMN promoted_vulnerability_id TEXT;
`;

// M008 (real-model smoke): a verdict change that is neither into `affected` nor to
// `not_affected` (e.g. affected → pending) is `changed`, not `cleared`. SQLite needs a rebuild to widen
// the CHECK; nothing references risk_hunt_target by foreign key (evidence ownership is polymorphic).
const M008 = `
CREATE TABLE risk_hunt_target_new (
  id TEXT PRIMARY KEY, risk_hunt_id TEXT NOT NULL REFERENCES risk_hunt(id) ON DELETE CASCADE,
  project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE, repository_id TEXT REFERENCES repository(id) ON DELETE CASCADE,
  audit_id TEXT REFERENCES audit(id) ON DELETE SET NULL,
  verdict TEXT ${inSet('verdict', ['affected', 'not_affected', 'pending'], true)}, reason TEXT, verdict_source TEXT ${inSet('verdict_source', ['rule', 'ai', 'human'], true)},
  pending_condition TEXT ${json('pending_condition', true)},
  delta_vs_previous TEXT ${inSet('delta_vs_previous', ['new_affected', 'cleared', 'changed', 'unchanged', 'new'], true)}, ${TS},
  UNIQUE(risk_hunt_id, project_id, repository_id));
INSERT INTO risk_hunt_target_new SELECT id, risk_hunt_id, project_id, repository_id, audit_id, verdict, reason, verdict_source, pending_condition, delta_vs_previous, created_at, updated_at FROM risk_hunt_target;
DROP TABLE risk_hunt_target;
ALTER TABLE risk_hunt_target_new RENAME TO risk_hunt_target;
CREATE INDEX idx_risk_hunt_target_hunt ON risk_hunt_target(risk_hunt_id);
`;

// M009: the hunt plan's deterministic precheck (locate per repository before confirmation).
const M009 = `
ALTER TABLE risk_hunt ADD COLUMN precheck TEXT ${json('precheck', true)};
`;

// M010: connectors (connector / connector_binding / sync_record).
// Credentials never live here: `${secret:x}` references resolve from config.json.
const M010 = `
CREATE TABLE connector (
  id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  protocol TEXT NOT NULL ${inSet('protocol', ['mcp_stdio', 'mcp_http', 'http'])}, purpose TEXT NOT NULL ${inSet('purpose', ['context', 'sync'])},
  config TEXT NOT NULL ${json('config')}, allow_write INTEGER NOT NULL DEFAULT 0 CHECK(allow_write IN (0,1)), enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
  confirmed_command_hash TEXT, tested_spec_hash TEXT, last_test TEXT ${json('last_test', true)}, tools TEXT NOT NULL DEFAULT '[]' ${json('tools')},
  breaker_state TEXT ${json('breaker_state', true)}, ${TS});
CREATE TABLE connector_binding (
  id TEXT PRIMARY KEY, connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE, project_id TEXT REFERENCES project(id) ON DELETE CASCADE,
  direction TEXT NOT NULL ${inSet('direction', ['pull', 'push', 'bidirectional'])}, mapping TEXT NOT NULL DEFAULT '{}' ${json('mapping')}, ${TS},
  UNIQUE(connector_id, project_id));
CREATE TABLE sync_record (
  id TEXT PRIMARY KEY, connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE,
  local_kind TEXT NOT NULL ${inSet('local_kind', ['vulnerability', 'risk_hunt_target'])}, local_id TEXT NOT NULL,
  external_id TEXT NOT NULL, external_url TEXT, last_pushed_hash TEXT, last_external_status TEXT, last_pulled_at INTEGER, ${TS},
  UNIQUE(connector_id, local_kind, local_id), UNIQUE(connector_id, external_id));
CREATE TABLE connector_call (
  id TEXT PRIMARY KEY, connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE,
  audit_id TEXT REFERENCES audit(id) ON DELETE SET NULL, step_id TEXT, operation TEXT NOT NULL,
  kind TEXT NOT NULL ${inSet('kind', ['read', 'write', 'test'])},
  status TEXT NOT NULL ${inSet('status', ['ok', 'error', 'unavailable', 'timeout', 'blocked', 'refused'])},
  duration_ms INTEGER NOT NULL DEFAULT 0, request_hash TEXT, response_bytes INTEGER NOT NULL DEFAULT 0, error TEXT, confirmed_by TEXT, ${TS});
CREATE INDEX idx_connector_call_connector ON connector_call(connector_id, created_at);
CREATE INDEX idx_connector_call_audit ON connector_call(audit_id);
`;

// M012: authoritative context connectors: results of such connectors may support
// conclusions; each call keeps whether it counted as authoritative and the response it returned.
const M012 = `
ALTER TABLE connector ADD COLUMN authoritative INTEGER NOT NULL DEFAULT 0 CHECK(authoritative IN (0,1));
ALTER TABLE connector_call ADD COLUMN authoritative INTEGER NOT NULL DEFAULT 0 CHECK(authoritative IN (0,1));
ALTER TABLE connector_call ADD COLUMN response_hash TEXT;
ALTER TABLE connector_call ADD COLUMN response_ref TEXT;
`;

// M011: architecture material imports.
const M011 = `
CREATE TABLE architecture_import (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE, label TEXT NOT NULL,
  status TEXT NOT NULL ${inSet('status', ['running', 'done', 'failed'])}, input_ref TEXT NOT NULL,
  result TEXT ${json('result', true)}, draft_id TEXT, error TEXT, model TEXT, tokens INTEGER NOT NULL DEFAULT 0, ${TS});
CREATE INDEX idx_architecture_import_project ON architecture_import(project_id, created_at);
`;

// M013: AI conversations. Cards get their own table
// (state + apply); non-delta reply events are kept per message for stream resume.
const M013 = `
CREATE TABLE conversation (
  id TEXT PRIMARY KEY, title TEXT NOT NULL, model TEXT ${json('model', true)},
  status TEXT NOT NULL DEFAULT 'active' ${inSet('status', CONVERSATION_STATUSES)},
  mentions TEXT NOT NULL DEFAULT '[]' ${json('mentions')}, last_message_at INTEGER, ${TS});
CREATE INDEX idx_conversation_status ON conversation(status, updated_at);
CREATE TABLE message (
  id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversation(id) ON DELETE CASCADE, seq INTEGER NOT NULL,
  role TEXT NOT NULL ${inSet('role', MESSAGE_ROLES)}, content TEXT NOT NULL DEFAULT '', content_ref TEXT,
  refs TEXT NOT NULL DEFAULT '[]' ${json('refs')}, cards TEXT NOT NULL DEFAULT '[]' ${json('cards')},
  status TEXT NOT NULL ${inSet('status', MESSAGE_STATUSES)}, finish_reason TEXT ${inSet('finish_reason', FINISH_REASONS, true)},
  model TEXT, tokens INTEGER NOT NULL DEFAULT 0, usage TEXT ${json('usage', true)}, error TEXT,
  client_message_id TEXT, reply_to TEXT, last_event_seq INTEGER NOT NULL DEFAULT 0, ${TS},
  UNIQUE(conversation_id, seq), UNIQUE(conversation_id, client_message_id));
CREATE TABLE message_event (
  message_id TEXT NOT NULL REFERENCES message(id) ON DELETE CASCADE, seq INTEGER NOT NULL,
  type TEXT NOT NULL ${inSet('type', MESSAGE_EVENT_TYPES)}, payload TEXT NOT NULL ${json('payload')}, ${TS},
  PRIMARY KEY(message_id, seq));
CREATE TABLE conversation_card (
  id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
  message_id TEXT NOT NULL REFERENCES message(id) ON DELETE CASCADE, kind TEXT NOT NULL ${inSet('kind', CARD_KINDS)},
  state TEXT NOT NULL ${inSet('state', CARD_STATES)}, tool TEXT, data TEXT NOT NULL ${json('data')}, result TEXT ${json('result', true)},
  target_kind TEXT, target_id TEXT, target_revision INTEGER, revision_ids TEXT NOT NULL DEFAULT '[]' ${json('revision_ids')},
  decided_by TEXT, decided_at INTEGER, ${TS});
CREATE INDEX idx_card_conversation ON conversation_card(conversation_id, created_at);
CREATE INDEX idx_card_state ON conversation_card(state);
ALTER TABLE connector_call ADD COLUMN conversation_id TEXT;
`;

// M014: deep-explore task pools; the basis drafting usage split
// (input / output / cached) so its cost can be priced.
const M014 = `
CREATE TABLE work_item (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  pool TEXT NOT NULL ${inSet('pool', ['todo', 'leads', 'done'])}, kind TEXT NOT NULL ${inSet('kind', ['entry', 'sink', 'candidate', 'hypothesis', 'question', 'user', 'direction'])},
  lineage_id TEXT NOT NULL, parent_id TEXT, title TEXT NOT NULL, target TEXT NOT NULL DEFAULT '{}' ${json('target')},
  priority INTEGER NOT NULL DEFAULT 0, round INTEGER NOT NULL DEFAULT 0, created_by_step TEXT, closed_by_step TEXT, outcome TEXT, ${TS});
CREATE INDEX idx_work_item_pool ON work_item(audit_id, pool, priority DESC);
ALTER TABLE hunt_basis ADD COLUMN usage TEXT CHECK(usage IS NULL OR json_valid(usage));
`;

// audits bound to a conversation (existing conversation_id, now also for form audits),
// and audits that start as soon as their plan is ready.
const M015 = `
ALTER TABLE audit ADD COLUMN auto_start INTEGER NOT NULL DEFAULT 0 CHECK(auto_start IN (0,1));
CREATE INDEX idx_audit_conversation ON audit(conversation_id);
`;

// pinned conversations stay at the top of the sidebar and the list.
const M016 = `
ALTER TABLE conversation ADD COLUMN pinned_at INTEGER;
`;

// time a person spent on a review decision, recorded
// by the client (panel opened → decision; a batch's elapsed time split evenly over the items it changed).
// Only on the first revision a decision writes; review_batch is the batch size (NULL = single item).
const M017 = `
ALTER TABLE revision ADD COLUMN review_ms INTEGER CHECK(review_ms IS NULL OR review_ms >= 0);
ALTER TABLE revision ADD COLUMN review_batch INTEGER CHECK(review_batch IS NULL OR review_batch >= 1);
`;

// hypotheses a hunt could neither prove nor refute, and refuted ones (kept for the record).
const M018 = `
CREATE TABLE hypothesis (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audit(id),
  step_id TEXT REFERENCES step(id),
  project_id TEXT NOT NULL REFERENCES project(id),
  repository_id TEXT NOT NULL REFERENCES repository(id),
  category TEXT NOT NULL,
  statement TEXT NOT NULL,
  location TEXT NOT NULL,
  entry_key TEXT,
  attempts TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open','refuted','converted','dismissed')),
  vulnerability_id TEXT REFERENCES vulnerability(id),
  decided_by TEXT,
  decided_reason TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX idx_hypothesis_audit ON hypothesis(audit_id, status);
`;

// AI reports run in the background — a `running` status, the generation mode, the model that
// wrote it, token use, the verification result, the phase shown while it runs. SQLite cannot widen a CHECK in place,
// so the table is rebuilt (nothing references export_job).
const M019 = `
CREATE TABLE export_job_new (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  format TEXT NOT NULL ${inSet('format', ['md', 'html', 'json', 'sarif'])}, options TEXT NOT NULL ${json('options')},
  status TEXT NOT NULL ${inSet('status', ['running', 'succeeded', 'failed'])}, artifact_ref TEXT, bytes INTEGER NOT NULL DEFAULT 0, error TEXT,
  mode TEXT NOT NULL DEFAULT 'template' ${inSet('mode', ['template', 'ai'])}, model TEXT, tokens INTEGER NOT NULL DEFAULT 0,
  verification TEXT ${json('verification', true)}, progress TEXT, markdown_ref TEXT, ${TS});
INSERT INTO export_job_new (id, audit_id, format, options, status, artifact_ref, bytes, error, created_at, updated_at)
  SELECT id, audit_id, format, options, status, artifact_ref, bytes, error, created_at, updated_at FROM export_job;
DROP TABLE export_job;
ALTER TABLE export_job_new RENAME TO export_job;
CREATE INDEX idx_export_audit ON export_job(audit_id);
`;

// risk hypotheses from the threat model. Listed before verification (`proposed`, no
// location yet), verified by a hypothesis batch (`confirmed` with its finding, `refuted`, `open`). SQLite cannot
// change a CHECK constraint or NOT NULL in place, so the table is rebuilt (nothing references it).
const M021 = `
CREATE TABLE hypothesis_v2 (
  id TEXT PRIMARY KEY,
  audit_id TEXT NOT NULL REFERENCES audit(id),
  step_id TEXT REFERENCES step(id),
  project_id TEXT NOT NULL REFERENCES project(id),
  repository_id TEXT NOT NULL REFERENCES repository(id),
  category TEXT NOT NULL,
  statement TEXT NOT NULL,
  location TEXT,
  entry_key TEXT,
  attempts TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL CHECK (status IN ('proposed','confirmed','open','refuted','converted','dismissed')),
  vulnerability_id TEXT REFERENCES vulnerability(id),
  decided_by TEXT,
  decided_reason TEXT,
  origin TEXT NOT NULL DEFAULT 'hunt' CHECK (origin IN ('hunt','threat_model')),
  priority INTEGER,
  basis TEXT,
  related TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(related)),
  finding_id TEXT REFERENCES finding(id),
  verify_step_id TEXT REFERENCES step(id),
  verified_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
INSERT INTO hypothesis_v2 (id, audit_id, step_id, project_id, repository_id, category, statement, location, entry_key, attempts, status,
  vulnerability_id, decided_by, decided_reason, created_at, updated_at)
  SELECT id, audit_id, step_id, project_id, repository_id, category, statement, location, entry_key, attempts, status,
  vulnerability_id, decided_by, decided_reason, created_at, updated_at FROM hypothesis;
DROP TABLE hypothesis;
ALTER TABLE hypothesis_v2 RENAME TO hypothesis;
CREATE INDEX idx_hypothesis_audit ON hypothesis(audit_id, status);
`;

// under multi-model cross-checking each model verifies a hypothesis; the votes are kept
// ([{model, status, reason, location, findingId?}]) and the hypothesis status is combined from them.
const M022 = `
ALTER TABLE hypothesis ADD COLUMN votes TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(votes));
`;

// deep exploration works on uncertain items — open hypotheses and uncertain findings (model
// conflicts, single source, pending) — so work_item gets the kind `finding`. CHECK cannot change in place: rebuild.
const M023 = `
CREATE TABLE work_item_v2 (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  pool TEXT NOT NULL ${inSet('pool', ['todo', 'leads', 'done'])}, kind TEXT NOT NULL ${inSet('kind', ['entry', 'sink', 'candidate', 'hypothesis', 'question', 'user', 'direction', 'finding'])},
  lineage_id TEXT NOT NULL, parent_id TEXT, title TEXT NOT NULL, target TEXT NOT NULL DEFAULT '{}' ${json('target')},
  priority INTEGER NOT NULL DEFAULT 0, round INTEGER NOT NULL DEFAULT 0, created_by_step TEXT, closed_by_step TEXT, outcome TEXT, ${TS});
INSERT INTO work_item_v2 SELECT id, audit_id, pool, kind, lineage_id, parent_id, title, target, priority, round, created_by_step, closed_by_step, outcome, created_at, updated_at FROM work_item;
DROP TABLE work_item;
ALTER TABLE work_item_v2 RENAME TO work_item;
CREATE INDEX idx_work_item_pool ON work_item(audit_id, pool, priority DESC);
`;

// MCP tools are offered to the Agent and run directly, except calls carrying instructions from the
// audited code (suspected injection in the arguments, or read by the session): those wait for the user's approval.
const M024 = `
CREATE TABLE connector_write_request (
  id TEXT PRIMARY KEY, connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE,
  tool TEXT NOT NULL, args TEXT NOT NULL ${json('args')}, reason TEXT,
  source TEXT NOT NULL ${inSet('source', ['audit', 'conversation', 'push'])},
  audit_id TEXT REFERENCES audit(id) ON DELETE SET NULL, step_id TEXT, conversation_id TEXT, message_id TEXT,
  status TEXT NOT NULL ${inSet('status', ['pending', 'executed', 'failed', 'rejected'])},
  signals TEXT NOT NULL DEFAULT '[]' ${json('signals')},
  result TEXT, error TEXT, call_id TEXT, decision_note TEXT, decided_at INTEGER, ${TS});
CREATE INDEX idx_connector_write_status ON connector_write_request(status, created_at);
`;

// connector tools start offered to the Agent, read or write; existing connectors switch every tool on once
// (packs only offered read operations the user picked, and write operations could not be offered before).
const M025 = `
UPDATE connector SET tools = (SELECT json_group_array(json_set(value, '$.exposed', json('true'))) FROM json_each(connector.tools))
WHERE json_array_length(tools) > 0;
`;

// databases created by older builds carry migration 1's CHECK lists from their build — step.kind
// without 'threat-model', error_class without 'CONTENT_FILTERED' — so audit, step and step_attempt are rebuilt with
// the current lists (same columns, same order; idempotent on databases that already have them). Every other table
// references audit or step, so the rebuild runs with foreign keys off (migration flag `foreignKeysOff`, the SQLite
// 12-step procedure): with them on, DROP TABLE audit would cascade-delete every child row.
const M026 = `
CREATE TABLE audit_v2 (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  scene TEXT NOT NULL ${inSet('scene', SCENES)}, mode TEXT NOT NULL ${inSet('mode', MODES)}, title TEXT NOT NULL,
  status TEXT NOT NULL ${inSet('status', AUDIT_STATUSES)}, phase TEXT,
  strategy_draft TEXT NOT NULL ${json('strategy_draft')}, strategy_sources TEXT NOT NULL ${json('strategy_sources')},
  strategy_frozen TEXT ${json('strategy_frozen', true)}, strategy_hash TEXT, plan_ref TEXT, knowledge_ref TEXT, gate_ref TEXT,
  running_since INTEGER,
  scope TEXT NOT NULL DEFAULT '{}' ${json('scope')}, base_audit_id TEXT REFERENCES audit(id) ON DELETE SET NULL,
  partial_reasons TEXT NOT NULL DEFAULT '[]' ${json('partial_reasons')},
  budget_initial TEXT NOT NULL ${json('budget_initial')}, budget_effective TEXT NOT NULL ${json('budget_effective')},
  budget_consumed TEXT NOT NULL ${json('budget_consumed')}, budget_reserved TEXT NOT NULL DEFAULT '{"tokens":0}' ${json('budget_reserved')},
  report_refs TEXT NOT NULL DEFAULT '{}' ${json('report_refs')},
  origin TEXT NOT NULL ${inSet('origin', AUDIT_ORIGINS)}, conversation_id TEXT,
  lease_owner TEXT, lease_expires_at INTEGER, last_event_seq INTEGER NOT NULL DEFAULT 0,
  error_class TEXT ${inSet('error_class', ERROR_CLASSES, true)}, queued_at INTEGER, started_at INTEGER, ended_at INTEGER, ${TS},
  draft_rev INTEGER NOT NULL DEFAULT 1, topology_ref TEXT, auto_start INTEGER NOT NULL DEFAULT 0 CHECK(auto_start IN (0,1)));
INSERT INTO audit_v2 (id, project_id, scene, mode, title, status, phase, strategy_draft, strategy_sources, strategy_frozen,
  strategy_hash, plan_ref, knowledge_ref, gate_ref, running_since, scope, base_audit_id, partial_reasons, budget_initial,
  budget_effective, budget_consumed, budget_reserved, report_refs, origin, conversation_id, lease_owner, lease_expires_at,
  last_event_seq, error_class, queued_at, started_at, ended_at, created_at, updated_at, draft_rev, topology_ref, auto_start)
  SELECT id, project_id, scene, mode, title, status, phase, strategy_draft, strategy_sources, strategy_frozen,
  strategy_hash, plan_ref, knowledge_ref, gate_ref, running_since, scope, base_audit_id, partial_reasons, budget_initial,
  budget_effective, budget_consumed, budget_reserved, report_refs, origin, conversation_id, lease_owner, lease_expires_at,
  last_event_seq, error_class, queued_at, started_at, ended_at, created_at, updated_at, draft_rev, topology_ref, auto_start FROM audit;
DROP TABLE audit;
ALTER TABLE audit_v2 RENAME TO audit;
CREATE INDEX idx_audit_project ON audit(project_id, created_at);
CREATE INDEX idx_audit_status ON audit(status);
CREATE INDEX idx_audit_conversation ON audit(conversation_id);
CREATE TRIGGER audit_strategy_frozen_immutable BEFORE UPDATE OF strategy_frozen ON audit
  WHEN OLD.strategy_frozen IS NOT NULL AND NEW.strategy_frozen IS NOT OLD.strategy_frozen
  BEGIN SELECT RAISE(ABORT, 'strategy_frozen is immutable'); END;

CREATE TABLE step_v2 (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  parent_step_id TEXT, seq INTEGER NOT NULL, kind TEXT NOT NULL ${inSet('kind', STEP_KINDS)}, lineage_id TEXT,
  status TEXT NOT NULL ${inSet('status', STEP_STATUSES)}, required INTEGER NOT NULL DEFAULT 0,
  attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 2,
  idempotency_key TEXT NOT NULL, depends_on TEXT NOT NULL DEFAULT '[]' ${json('depends_on')},
  input TEXT NOT NULL DEFAULT '{}' ${json('input')}, input_ref TEXT, output_ref TEXT, reused_from TEXT,
  model TEXT, provider TEXT, tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0,
  tokens_cached INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER, estimated_usage INTEGER NOT NULL DEFAULT 0,
  estimate_tokens INTEGER NOT NULL DEFAULT 0, retry_at INTEGER,
  error_class TEXT ${inSet('error_class', ERROR_CLASSES, true)}, error_ref TEXT, error_summary TEXT,
  started_at INTEGER, ended_at INTEGER, ${TS}, UNIQUE(audit_id, idempotency_key), UNIQUE(audit_id, seq));
INSERT INTO step_v2 (id, audit_id, parent_step_id, seq, kind, lineage_id, status, required, attempt, max_attempts,
  idempotency_key, depends_on, input, input_ref, output_ref, reused_from, model, provider, tokens_in, tokens_out,
  tokens_cached, cost_micros, estimated_usage, estimate_tokens, retry_at, error_class, error_ref, error_summary,
  started_at, ended_at, created_at, updated_at)
  SELECT id, audit_id, parent_step_id, seq, kind, lineage_id, status, required, attempt, max_attempts,
  idempotency_key, depends_on, input, input_ref, output_ref, reused_from, model, provider, tokens_in, tokens_out,
  tokens_cached, cost_micros, estimated_usage, estimate_tokens, retry_at, error_class, error_ref, error_summary,
  started_at, ended_at, created_at, updated_at FROM step;
DROP TABLE step;
ALTER TABLE step_v2 RENAME TO step;
CREATE INDEX idx_step_audit_status ON step(audit_id, status);

CREATE TABLE step_attempt_v2 (
  step_id TEXT NOT NULL REFERENCES step(id) ON DELETE CASCADE, attempt INTEGER NOT NULL,
  outcome TEXT ${inSet('outcome', ['succeeded', 'failed', 'aborted', 'interrupted', 'cancelled'], true)},
  error_class TEXT ${inSet('error_class', ERROR_CLASSES, true)}, tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0, tokens_cached INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER,
  submitted_ref TEXT, started_at INTEGER NOT NULL, ended_at INTEGER, ${TS}, PRIMARY KEY(step_id, attempt));
INSERT INTO step_attempt_v2 (step_id, attempt, outcome, error_class, tokens_in, tokens_out, tokens_cached, cost_micros,
  submitted_ref, started_at, ended_at, created_at, updated_at)
  SELECT step_id, attempt, outcome, error_class, tokens_in, tokens_out, tokens_cached, cost_micros,
  submitted_ref, started_at, ended_at, created_at, updated_at FROM step_attempt;
DROP TABLE step_attempt;
ALTER TABLE step_attempt_v2 RENAME TO step_attempt;
`;

// audit, step and step_attempt are rebuilt again (as in migration 26) for the error class PROVIDER_QUOTA
// (402 / balance or quota used up: pause the audit, not retried), and step gets `estimate_base` — the estimate
// before calibration, so calibration compares actual usage with the constants and not with itself (existing
// steps were never calibrated: their estimate is the base). connector_call keeps the full request of a write call
// (`request_ref`) and marks a write answered from an earlier identical call (`replayed_from`).
const ERROR_CLASSES_27 = [...ERROR_CLASSES, 'PROVIDER_QUOTA'] as const;
const M027 = `
CREATE TABLE audit_v2 (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  scene TEXT NOT NULL ${inSet('scene', SCENES)}, mode TEXT NOT NULL ${inSet('mode', MODES)}, title TEXT NOT NULL,
  status TEXT NOT NULL ${inSet('status', AUDIT_STATUSES)}, phase TEXT,
  strategy_draft TEXT NOT NULL ${json('strategy_draft')}, strategy_sources TEXT NOT NULL ${json('strategy_sources')},
  strategy_frozen TEXT ${json('strategy_frozen', true)}, strategy_hash TEXT, plan_ref TEXT, knowledge_ref TEXT, gate_ref TEXT,
  running_since INTEGER,
  scope TEXT NOT NULL DEFAULT '{}' ${json('scope')}, base_audit_id TEXT REFERENCES audit(id) ON DELETE SET NULL,
  partial_reasons TEXT NOT NULL DEFAULT '[]' ${json('partial_reasons')},
  budget_initial TEXT NOT NULL ${json('budget_initial')}, budget_effective TEXT NOT NULL ${json('budget_effective')},
  budget_consumed TEXT NOT NULL ${json('budget_consumed')}, budget_reserved TEXT NOT NULL DEFAULT '{"tokens":0}' ${json('budget_reserved')},
  report_refs TEXT NOT NULL DEFAULT '{}' ${json('report_refs')},
  origin TEXT NOT NULL ${inSet('origin', AUDIT_ORIGINS)}, conversation_id TEXT,
  lease_owner TEXT, lease_expires_at INTEGER, last_event_seq INTEGER NOT NULL DEFAULT 0,
  error_class TEXT ${inSet('error_class', ERROR_CLASSES_27, true)}, queued_at INTEGER, started_at INTEGER, ended_at INTEGER, ${TS},
  draft_rev INTEGER NOT NULL DEFAULT 1, topology_ref TEXT, auto_start INTEGER NOT NULL DEFAULT 0 CHECK(auto_start IN (0,1)));
INSERT INTO audit_v2 (id, project_id, scene, mode, title, status, phase, strategy_draft, strategy_sources, strategy_frozen,
  strategy_hash, plan_ref, knowledge_ref, gate_ref, running_since, scope, base_audit_id, partial_reasons, budget_initial,
  budget_effective, budget_consumed, budget_reserved, report_refs, origin, conversation_id, lease_owner, lease_expires_at,
  last_event_seq, error_class, queued_at, started_at, ended_at, created_at, updated_at, draft_rev, topology_ref, auto_start)
  SELECT id, project_id, scene, mode, title, status, phase, strategy_draft, strategy_sources, strategy_frozen,
  strategy_hash, plan_ref, knowledge_ref, gate_ref, running_since, scope, base_audit_id, partial_reasons, budget_initial,
  budget_effective, budget_consumed, budget_reserved, report_refs, origin, conversation_id, lease_owner, lease_expires_at,
  last_event_seq, error_class, queued_at, started_at, ended_at, created_at, updated_at, draft_rev, topology_ref, auto_start FROM audit;
DROP TABLE audit;
ALTER TABLE audit_v2 RENAME TO audit;
CREATE INDEX idx_audit_project ON audit(project_id, created_at);
CREATE INDEX idx_audit_status ON audit(status);
CREATE INDEX idx_audit_conversation ON audit(conversation_id);
CREATE TRIGGER audit_strategy_frozen_immutable BEFORE UPDATE OF strategy_frozen ON audit
  WHEN OLD.strategy_frozen IS NOT NULL AND NEW.strategy_frozen IS NOT OLD.strategy_frozen
  BEGIN SELECT RAISE(ABORT, 'strategy_frozen is immutable'); END;

CREATE TABLE step_v2 (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  parent_step_id TEXT, seq INTEGER NOT NULL, kind TEXT NOT NULL ${inSet('kind', STEP_KINDS)}, lineage_id TEXT,
  status TEXT NOT NULL ${inSet('status', STEP_STATUSES)}, required INTEGER NOT NULL DEFAULT 0,
  attempt INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 2,
  idempotency_key TEXT NOT NULL, depends_on TEXT NOT NULL DEFAULT '[]' ${json('depends_on')},
  input TEXT NOT NULL DEFAULT '{}' ${json('input')}, input_ref TEXT, output_ref TEXT, reused_from TEXT,
  model TEXT, provider TEXT, tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0,
  tokens_cached INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER, estimated_usage INTEGER NOT NULL DEFAULT 0,
  estimate_tokens INTEGER NOT NULL DEFAULT 0, estimate_base INTEGER NOT NULL DEFAULT 0, retry_at INTEGER,
  error_class TEXT ${inSet('error_class', ERROR_CLASSES_27, true)}, error_ref TEXT, error_summary TEXT,
  started_at INTEGER, ended_at INTEGER, ${TS}, UNIQUE(audit_id, idempotency_key), UNIQUE(audit_id, seq));
INSERT INTO step_v2 (id, audit_id, parent_step_id, seq, kind, lineage_id, status, required, attempt, max_attempts,
  idempotency_key, depends_on, input, input_ref, output_ref, reused_from, model, provider, tokens_in, tokens_out,
  tokens_cached, cost_micros, estimated_usage, estimate_tokens, estimate_base, retry_at, error_class, error_ref, error_summary,
  started_at, ended_at, created_at, updated_at)
  SELECT id, audit_id, parent_step_id, seq, kind, lineage_id, status, required, attempt, max_attempts,
  idempotency_key, depends_on, input, input_ref, output_ref, reused_from, model, provider, tokens_in, tokens_out,
  tokens_cached, cost_micros, estimated_usage, estimate_tokens, estimate_tokens, retry_at, error_class, error_ref, error_summary,
  started_at, ended_at, created_at, updated_at FROM step;
DROP TABLE step;
ALTER TABLE step_v2 RENAME TO step;
CREATE INDEX idx_step_audit_status ON step(audit_id, status);

CREATE TABLE step_attempt_v2 (
  step_id TEXT NOT NULL REFERENCES step(id) ON DELETE CASCADE, attempt INTEGER NOT NULL,
  outcome TEXT ${inSet('outcome', ['succeeded', 'failed', 'aborted', 'interrupted', 'cancelled'], true)},
  error_class TEXT ${inSet('error_class', ERROR_CLASSES_27, true)}, tokens_in INTEGER NOT NULL DEFAULT 0,
  tokens_out INTEGER NOT NULL DEFAULT 0, tokens_cached INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER,
  submitted_ref TEXT, started_at INTEGER NOT NULL, ended_at INTEGER, ${TS}, PRIMARY KEY(step_id, attempt));
INSERT INTO step_attempt_v2 (step_id, attempt, outcome, error_class, tokens_in, tokens_out, tokens_cached, cost_micros,
  submitted_ref, started_at, ended_at, created_at, updated_at)
  SELECT step_id, attempt, outcome, error_class, tokens_in, tokens_out, tokens_cached, cost_micros,
  submitted_ref, started_at, ended_at, created_at, updated_at FROM step_attempt;
DROP TABLE step_attempt;
ALTER TABLE step_attempt_v2 RENAME TO step_attempt;

ALTER TABLE connector_call ADD COLUMN request_ref TEXT;
ALTER TABLE connector_call ADD COLUMN replayed_from TEXT;
CREATE INDEX idx_connector_call_step ON connector_call(step_id, request_hash);
`;

// a coverage item keeps what its target is — the external interface of an entry, the risky call of a sink
// (`CoverageItemDetail`). Earlier items have none; the API fills them from the cached structure index or the target id.
const M028 = `
ALTER TABLE coverage_item ADD COLUMN detail TEXT ${json('detail', true)};
`;

// a person may confirm a vulnerability whose evidence is incomplete when they give a reason
// (e.g. adversarial review refuted it and the finding stays pending). confirm_override marks such a
// confirmation; the confirmed-needs-evidence triggers let it through and still refuse everything else.
const M029 = `
ALTER TABLE vulnerability ADD COLUMN confirm_override INTEGER NOT NULL DEFAULT 0 CHECK(confirm_override IN (0,1));
DROP TRIGGER vuln_confirm_requires_evidence;
DROP TRIGGER vuln_confirm_requires_evidence_insert;
CREATE TRIGGER vuln_confirm_requires_evidence BEFORE UPDATE OF confirm_status ON vulnerability
  WHEN NEW.confirm_status = 'confirmed' AND NEW.evidence_complete = 0 AND NEW.confirm_override = 0
  BEGIN SELECT RAISE(ABORT, 'confirmed requires evidence_complete=1 or a human override'); END;
CREATE TRIGGER vuln_confirm_requires_evidence_insert BEFORE INSERT ON vulnerability
  WHEN NEW.confirm_status = 'confirmed' AND NEW.evidence_complete = 0 AND NEW.confirm_override = 0
  BEGIN SELECT RAISE(ABORT, 'confirmed requires evidence_complete=1 or a human override'); END;
`;

// requirement threat models. A threat model belongs to a project and has any number of input sources
// (upload / online document / text, numbered S1… in the order they were added, `ord` for display) and risks (R1…,
// numbers never reused) that a person triages into five states; a state other than pending needs a reason.
const M030 = `
CREATE TABLE threat_model (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE, title TEXT NOT NULL,
  status TEXT NOT NULL ${inSet('status', ['draft', 'generating', 'ready', 'partial', 'failed'])},
  clarification_ref TEXT, report_ref TEXT, clarified_at INTEGER, model TEXT,
  tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0, cost_micros INTEGER, error TEXT,
  generated_at INTEGER, sources_updated_at INTEGER,
  next_source_no INTEGER NOT NULL DEFAULT 1, next_risk_no INTEGER NOT NULL DEFAULT 1, ${TS});
CREATE INDEX idx_threat_model_project ON threat_model(project_id, created_at);
CREATE TABLE threat_model_source (
  id TEXT PRIMARY KEY, threat_model_id TEXT NOT NULL REFERENCES threat_model(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL, ord INTEGER NOT NULL, kind TEXT NOT NULL ${inSet('kind', ['upload', 'online', 'text'])},
  title TEXT NOT NULL, note TEXT, connector_id TEXT REFERENCES connector(id) ON DELETE SET NULL, doc_ref TEXT,
  content_ref TEXT, content_hash TEXT, bytes INTEGER NOT NULL DEFAULT 0,
  fetch_status TEXT ${inSet('fetch_status', ['pending', 'ok', 'failed'], true)}, fetch_error TEXT, fetched_at INTEGER,
  injection TEXT NOT NULL DEFAULT '[]' ${json('injection')}, injection_ack INTEGER NOT NULL DEFAULT 0 CHECK(injection_ack IN (0,1)),
  ${TS}, UNIQUE(threat_model_id, seq),
  CHECK(kind != 'online' OR doc_ref IS NOT NULL));
CREATE TABLE threat_risk (
  id TEXT PRIMARY KEY, threat_model_id TEXT NOT NULL REFERENCES threat_model(id) ON DELETE CASCADE,
  no INTEGER NOT NULL, category TEXT NOT NULL, level TEXT ${inSet('level', ['high', 'medium', 'low'], true)},
  statement TEXT NOT NULL, impact TEXT, mitigation TEXT,
  features TEXT NOT NULL DEFAULT '[]' ${json('features')}, sources TEXT NOT NULL DEFAULT '[]' ${json('sources')},
  status TEXT NOT NULL DEFAULT 'pending' ${inSet('status', ['pending', 'to_mitigate', 'mitigated', 'accepted', 'false_positive'])},
  reason TEXT, decided_by TEXT, decided_at INTEGER, stale INTEGER NOT NULL DEFAULT 0 CHECK(stale IN (0,1)),
  history TEXT NOT NULL DEFAULT '[]' ${json('history')}, ${TS}, UNIQUE(threat_model_id, no),
  CHECK(status = 'pending' OR (reason IS NOT NULL AND length(trim(reason)) > 0)));
`;

// a threat model synced to an online document has its own sync_record kind. SQLite needs a
// rebuild to widen the CHECK; nothing references sync_record by foreign key.
const M031 = `
CREATE TABLE sync_record_new (
  id TEXT PRIMARY KEY, connector_id TEXT NOT NULL REFERENCES connector(id) ON DELETE CASCADE,
  local_kind TEXT NOT NULL ${inSet('local_kind', ['vulnerability', 'risk_hunt_target', 'threat_model'])}, local_id TEXT NOT NULL,
  external_id TEXT NOT NULL, external_url TEXT, last_pushed_hash TEXT, last_external_status TEXT, last_pulled_at INTEGER, ${TS},
  UNIQUE(connector_id, local_kind, local_id), UNIQUE(connector_id, external_id));
INSERT INTO sync_record_new SELECT id, connector_id, local_kind, local_id, external_id, external_url, last_pushed_hash, last_external_status, last_pulled_at, created_at, updated_at FROM sync_record;
DROP TABLE sync_record;
ALTER TABLE sync_record_new RENAME TO sync_record;
`;

// audits that reference requirement threat models. A risk to verify is an ordinary
// threat-model hypothesis with its risk (no CHECK change); a finding names the risk it relates to; a vulnerability set
// by the rule from a person's decision on a risk keeps that risk.
const M032 = `
ALTER TABLE hypothesis ADD COLUMN threat_risk_id TEXT;
ALTER TABLE finding ADD COLUMN related_risk TEXT;
ALTER TABLE vulnerability ADD COLUMN threat_risk TEXT ${json('threat_risk', true)};
`;

// obligations that have no state of their own elsewhere — checklist items and results of
// external scanners. Entry points, sinks, hypotheses and access-policy differences keep their own tables; the
// engine settles all of them together. Values are literal so the checksum never follows later enum edits.
const M033 = `
CREATE TABLE obligation (
  id TEXT PRIMARY KEY, audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK(kind IN ('checklist','external')), item_key TEXT NOT NULL,
  source TEXT NOT NULL, title TEXT NOT NULL, category TEXT,
  repository_id TEXT, path TEXT, start_line INTEGER,
  status TEXT NOT NULL CHECK(status IN ('open','covered','not_applicable','uncovered','concluded')),
  reason TEXT, step_id TEXT, detail TEXT NOT NULL DEFAULT '{}' ${json('detail')},
  ${TS}, UNIQUE(audit_id, kind, item_key));
CREATE INDEX idx_obligation_status ON obligation(audit_id, kind, status);
`;

// enterprise facts, versioned per key; the findings that rely on a fact (stale once the fact changes);
// plan questions whose answers become facts.
const M034 = `
CREATE TABLE fact (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  fact_key TEXT NOT NULL, version INTEGER NOT NULL CHECK(version >= 1),
  topic TEXT NOT NULL ${inSet('topic', ['gateway', 'auth', 'deployment', 'network', 'business_rule', 'architecture', 'data', 'integration', 'other'])}, statement TEXT NOT NULL CHECK(length(trim(statement)) > 0),
  scope TEXT NOT NULL DEFAULT '{}' ${json('scope')},
  source_kind TEXT NOT NULL ${inSet('source_kind', ['user', 'knowledge', 'architecture_import', 'topology', 'question', 'requirement_risk', 'profile', 'review', 'gateway_config'])}, source_ref TEXT,
  trust TEXT NOT NULL ${inSet('trust', ['authoritative', 'verified', 'unverified'])}, sensitivity TEXT NOT NULL DEFAULT 'internal' ${inSet('sensitivity', ['public', 'internal', 'confidential'])},
  status TEXT NOT NULL ${inSet('status', ['active', 'superseded', 'retracted'])}, created_by TEXT NOT NULL, reason TEXT,
  ${TS}, UNIQUE(project_id, fact_key, version));
CREATE INDEX idx_fact_project ON fact(project_id, status);
CREATE TABLE fact_ref (
  id TEXT PRIMARY KEY, fact_id TEXT NOT NULL REFERENCES fact(id) ON DELETE CASCADE,
  audit_id TEXT NOT NULL REFERENCES audit(id) ON DELETE CASCADE, finding_id TEXT NOT NULL REFERENCES finding(id) ON DELETE CASCADE,
  stale INTEGER NOT NULL DEFAULT 0 CHECK(stale IN (0,1)), ${TS}, UNIQUE(fact_id, finding_id));
CREATE INDEX idx_fact_ref_fact ON fact_ref(fact_id);
ALTER TABLE question ADD COLUMN as_fact INTEGER NOT NULL DEFAULT 0 CHECK(as_fact IN (0,1));
`;

// the project's internal-trust setting (null = inferred from the topology), and the boundary
// class of findings and vulnerabilities (own-service defect / relies on an upstream guarantee / cross-service risk) with
// what the trust setting did to it.
const M035 = `
ALTER TABLE project ADD COLUMN internal_trust TEXT CHECK(internal_trust IS NULL OR internal_trust IN ('zero_trust','gateway_boundary','trusted_network'));
ALTER TABLE finding ADD COLUMN boundary TEXT CHECK(boundary IS NULL OR boundary IN ('own','upstream','cross_service'));
ALTER TABLE finding ADD COLUMN boundary_note TEXT;
ALTER TABLE vulnerability ADD COLUMN boundary TEXT CHECK(boundary IS NULL OR boundary IN ('own','upstream','cross_service'));
`;

// what each model session sent to which provider (files, facts, tools, tokens), and how many confidential
// facts it was not allowed to see.
const M036 = `
CREATE TABLE egress_record (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, audit_id TEXT REFERENCES audit(id) ON DELETE CASCADE, step_id TEXT,
  conversation_id TEXT, project_id TEXT, ref TEXT, provider TEXT NOT NULL, model TEXT NOT NULL, endpoint TEXT,
  status TEXT NOT NULL, turns INTEGER NOT NULL DEFAULT 0, tokens_in INTEGER NOT NULL DEFAULT 0, tokens_out INTEGER NOT NULL DEFAULT 0,
  tokens_cached INTEGER NOT NULL DEFAULT 0, files TEXT NOT NULL DEFAULT '[]' ${json('files')}, facts TEXT NOT NULL DEFAULT '[]' ${json('facts')},
  withheld_facts INTEGER NOT NULL DEFAULT 0, tools TEXT NOT NULL DEFAULT '{}' ${json('tools')}, started_at INTEGER NOT NULL, ended_at INTEGER NOT NULL, ${TS});
CREATE INDEX idx_egress_audit ON egress_record(audit_id);
CREATE INDEX idx_egress_project ON egress_record(project_id);
`;

// a confirmed vulnerability solidified into a project rule (tree-sitter query or line regex). The
// engine checks it hits the original place; approved rules are frozen with the audit's knowledge and run as sinks.
const M037 = `
CREATE TABLE project_rule (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  vulnerability_id TEXT REFERENCES vulnerability(id) ON DELETE SET NULL, repository_id TEXT,
  lang TEXT NOT NULL, matcher TEXT NOT NULL CHECK(matcher IN ('tree_sitter','regex')), pattern TEXT NOT NULL,
  category TEXT NOT NULL, cwe TEXT, title TEXT NOT NULL, rationale TEXT,
  status TEXT NOT NULL CHECK(status IN ('drafting','proposed','approved','rejected','retired','failed')),
  source TEXT NOT NULL CHECK(source IN ('ai','user')), origin TEXT ${json('origin', true)}, validation TEXT ${json('validation', true)},
  model TEXT, tokens INTEGER NOT NULL DEFAULT 0, error TEXT, decided_by TEXT, decided_at INTEGER, ${TS});
CREATE INDEX idx_project_rule ON project_rule(project_id, status);
`;

// verification cases the user runs in their own environment (the engine never executes them), with
// the result the user records.
const M038 = `
CREATE TABLE verification_case (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('drafting','ready','failed')), source TEXT NOT NULL CHECK(source IN ('ai','user')),
  preconditions TEXT ${json('preconditions', true)}, steps TEXT ${json('steps', true)}, expected TEXT ${json('expected', true)}, notes TEXT,
  model TEXT, tokens INTEGER NOT NULL DEFAULT 0, error TEXT,
  outcome TEXT CHECK(outcome IS NULL OR outcome IN ('reproduced','not_reproduced','inconclusive')), outcome_note TEXT, outcome_by TEXT, outcome_at INTEGER, ${TS});
CREATE INDEX idx_verification_case_vuln ON verification_case(vulnerability_id);
`;

// fix suggestions (unified diffs checked against the snapshot, never written to the repository) and the
// reverification started from one.
const M039 = `
CREATE TABLE fix_suggestion (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
  vulnerability_id TEXT NOT NULL REFERENCES vulnerability(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('drafting','ready','failed')), summary TEXT, patches TEXT ${json('patches', true)}, verify TEXT, notes TEXT,
  model TEXT, tokens INTEGER NOT NULL DEFAULT 0, error TEXT, reverify_audit_id TEXT REFERENCES audit(id) ON DELETE SET NULL, ${TS});
CREATE INDEX idx_fix_suggestion_vuln ON fix_suggestion(vulnerability_id);
`;

/**
 * `accepts`: checksums of earlier texts of this migration that shipped in a build and left the same schema once the
 * later migrations ran. `foreignKeysOff`: the migration rebuilds a referenced table, so it runs with
 * foreign keys off and is checked with `PRAGMA foreign_key_check` before it commits.
 */
export interface Migration { version: number; name: string; sql: string; accepts?: readonly string[]; foreignKeysOff?: boolean }

// the user can set a repository to auditable / context-only. is_auditable stays the
// effective value; auditable_auto is the latest automatic judgement (with its reason), auditable_source
// says which one is in force ('auto' follows the judgement, 'user' keeps the manual setting).
// Numbered 20: migration 19 was taken by another change merged first.
const M020 = `
ALTER TABLE repository ADD COLUMN auditable_source TEXT NOT NULL DEFAULT 'auto' CHECK(auditable_source IN ('auto','user'));
ALTER TABLE repository ADD COLUMN auditable_auto INTEGER CHECK(auditable_auto IS NULL OR auditable_auto IN (0,1));
ALTER TABLE repository ADD COLUMN auditable_reason TEXT;
UPDATE repository SET auditable_auto = is_auditable;
`;

export const MIGRATIONS: Migration[] = [
  {
    version: 1, name: 'm1_core', sql: M001,
    // Older builds: before 'threat-model' joined STEP_KINDS, and before 'CONTENT_FILTERED' joined ERROR_CLASSES.
    // Only CHECK lists differ; migration 26 brings them up to date.
    accepts: [
      '043cfad35fa8673ccef69ddff864f4ef9ca3003e67c80375f6f9fcd7d2aadcbb',
      'bb9fb93934f571483e49baa8f951e5d2f29ef4a8103a0154e400b15c5fffc380',
    ],
  },
  { version: 2, name: 'm2_api', sql: M002 },
  { version: 3, name: 'm3_incremental', sql: M003 },
  { version: 4, name: 'm4_sources', sql: M004 },
  { version: 5, name: 'm4_analysis', sql: M005 },
  { version: 6, name: 'm4_topology', sql: M006 },
  { version: 7, name: 'm5_risk_hunt', sql: M007 },
  { version: 8, name: 'm5_hunt_delta_changed', sql: M008 },
  { version: 9, name: 'm5_hunt_precheck', sql: M009 },
  { version: 10, name: 'm6_connectors', sql: M010 },
  { version: 11, name: 'm6_architecture_import', sql: M011 },
  { version: 12, name: 'm6_authoritative_connectors', sql: M012 },
  { version: 13, name: 'm7_conversations', sql: M013 },
  { version: 14, name: 'm7_work_items', sql: M014 },
  { version: 15, name: 'm8_audit_conversation', sql: M015 },
  { version: 16, name: 'm8_conversation_pin', sql: M016 },
  { version: 17, name: 'm9_review_duration', sql: M017 },
  { version: 18, name: 'm9_hypotheses', sql: M018 },
  { version: 19, name: 'm10_ai_report', sql: M019 },
  { version: 20, name: 'm11_auditable_override', sql: M020 },
  { version: 21, name: 'm10_threat_hypotheses', sql: M021 },
  { version: 22, name: 'm12_hypothesis_votes', sql: M022 },
  { version: 23, name: 'm12_explore_uncertain', sql: M023 },
  { version: 24, name: 'm10_connector_writes', sql: M024 },
  { version: 25, name: 'm10_connector_tools_open', sql: M025 },
  { version: 26, name: 'm13_closed_set_checks', sql: M026, foreignKeysOff: true },
  { version: 27, name: 'm12_quota_estimates_write_replay', sql: M027, foreignKeysOff: true },
  { version: 28, name: 'm10_coverage_detail', sql: M028 },
  { version: 29, name: 'm12_confirm_override', sql: M029 },
  { version: 30, name: 'm15_threat_models', sql: M030 },
  { version: 31, name: 'm15_threat_model_sync', sql: M031 },
  { version: 32, name: 'm15_audit_threat_models', sql: M032 },
  { version: 33, name: 'm18_obligations', sql: M033 },
  { version: 34, name: 'm18_facts', sql: M034 },
  { version: 35, name: 'm18_internal_trust', sql: M035 },
  { version: 36, name: 'm18_egress', sql: M036 },
  { version: 37, name: 'm18_project_rules', sql: M037 },
  { version: 38, name: 'm18_verification_cases', sql: M038 },
  { version: 39, name: 'm18_fix_suggestions', sql: M039 },
];

export function migrationChecksum(m: Migration): string {
  return sha256Hex(m.sql);
}
