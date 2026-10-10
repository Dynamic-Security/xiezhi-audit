// Read queries on audits, their questions, findings, coverage and exports, and the home page lists, for the API and
// the CLI: the applications shape responses; the SQL lives here.
import type { AuditStatus } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import type { AuditRow } from '../state.js';

const ACTIVE = `('planning','queued','running','cancelling')`;

export interface AuditRepoRow { id: string; name: string; requested_ref: string | null; resolved_commit: string | null; is_worktree: number | null; root_hash: string | null; manifest_ref?: string | null; role_in_audit: 'target' | 'related' | 'context' }

/** Whether a working-tree snapshot had uncommitted changes (from its manifest; undefined when unknown). */
export function snapshotDirty(store: Store, r: Pick<AuditRepoRow, 'is_worktree' | 'manifest_ref'>): boolean | undefined {
  if (!r.is_worktree || !r.manifest_ref) return undefined;
  try { return store.artifacts.getJson<{ source?: { dirty?: boolean } }>(r.manifest_ref).source?.dirty; } catch { return undefined; }
}

/** The repositories of an audit with their snapshots: targets first, then related, then context. */
export function auditRepos(store: Store, auditId: string): AuditRepoRow[] {
  return store.all<AuditRepoRow>(
    `SELECT r.id, r.name, ar.requested_ref, s.resolved_commit, s.is_worktree, s.root_hash, s.manifest_ref, ar.role_in_audit FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id
     LEFT JOIN snapshot s ON s.id = ar.snapshot_id WHERE ar.audit_id = ? ORDER BY CASE ar.role_in_audit WHEN 'target' THEN 0 WHEN 'related' THEN 1 ELSE 2 END, r.name`, auditId);
}

/** The snapshot of one repository of an audit (by id or name), for browsing its source. */
export function auditRepoSnapshot(store: Store, auditId: string, repo: string): { name: string; root_hash: string; manifest_ref: string } | undefined {
  return store.get<{ name: string; root_hash: string; manifest_ref: string }>(
    `SELECT r.name, s.root_hash, s.manifest_ref FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id JOIN snapshot s ON s.id = ar.snapshot_id
     WHERE ar.audit_id = ? AND (ar.repository_id = ? OR r.name = ?)`, auditId, repo, repo);
}

/** Audits, newest first, filtered by project, scene and statuses. */
export function listAudits(store: Store, filter: { projectId?: string; scene?: string; statuses?: string[] } = {}): AuditRow[] {
  const where: string[] = [];
  const params: string[] = [];
  if (filter.projectId) { where.push('project_id = ?'); params.push(filter.projectId); }
  if (filter.scene) { where.push('scene = ?'); params.push(filter.scene); }
  if (filter.statuses?.length) { where.push(`status IN (${filter.statuses.map(() => '?').join(',')})`); params.push(...filter.statuses); }
  return store.all<AuditRow>(`SELECT * FROM audit ${where.length ? `WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at DESC`, ...params);
}

/** Audits of a project (by name or id), oldest first; all audits without a project (CLI list). */
export function auditList(store: Store, project?: string): { id: string; title: string; status: string; created_at: number }[] {
  return project
    ? store.all('SELECT a.id, a.title, a.status, a.created_at FROM audit a JOIN project p ON p.id = a.project_id WHERE p.name = ? OR p.id = ? ORDER BY a.created_at', project, project)
    : store.all('SELECT id, title, status, created_at FROM audit ORDER BY created_at');
}

/** Planning, queued, running or cancelling audits, newest first. */
export function activeAudits(store: Store): AuditRow[] {
  return store.all<AuditRow>(`SELECT * FROM audit WHERE status IN ${ACTIVE} ORDER BY created_at DESC`);
}

export function hasActiveAudit(store: Store, projectId: string): boolean {
  return !!store.get(`SELECT 1 FROM audit WHERE project_id = ? AND status IN ${ACTIVE}`, projectId);
}

/** The latest audits in one status (home page lists). */
export function recentAuditsIn(store: Store, status: AuditStatus, limit = 20): AuditRow[] {
  return store.all<AuditRow>('SELECT * FROM audit WHERE status = ? ORDER BY created_at DESC LIMIT ?', status, limit);
}

export function countAuditsIn(store: Store, status: AuditStatus): number {
  return store.get<{ n: number }>('SELECT COUNT(*) AS n FROM audit WHERE status = ?', status)!.n;
}

/** The next queued audit in FIFO order, skipping the ones given. */
export function nextQueuedAudit(store: Store, skip: string[] = []): string | undefined {
  return store.get<{ id: string }>(
    `SELECT id FROM audit WHERE status = 'queued' ${skip.length ? `AND id NOT IN (${skip.map(() => '?').join(',')})` : ''} ORDER BY queued_at, id LIMIT 1`, ...skip)?.id;
}

export function auditStatus(store: Store, auditId: string): AuditStatus | undefined {
  return store.get<{ status: AuditStatus }>('SELECT status FROM audit WHERE id = ?', auditId)?.status;
}

export function auditTitle(store: Store, auditId: string): string | undefined {
  return store.get<{ title: string }>('SELECT title FROM audit WHERE id = ?', auditId)?.title;
}

export function canonicalFindingCount(store: Store, auditId: string): number {
  return store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM finding WHERE audit_id = ? AND state = 'canonical'`, auditId)!.n;
}

export function openQuestionCount(store: Store, auditId: string): number {
  return store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM question WHERE audit_id = ? AND status = 'open'`, auditId)!.n;
}

export function conversationExists(store: Store, conversationId: string): boolean {
  return !!store.get('SELECT 1 FROM conversation WHERE id = ?', conversationId);
}

export function lastEventSeq(store: Store, auditId: string): number {
  return store.get<{ last_event_seq: number }>('SELECT last_event_seq FROM audit WHERE id = ?', auditId)!.last_event_seq;
}

/** The verdict a reverification audit reached on a vulnerability, if any. */
export function reverifyOccurrence(store: Store, auditId: string, vulnId: string): { reverify_verdict: string; lifecycle_before: string | null; lifecycle_after: string | null; match_basis: string } | undefined {
  return store.get<{ reverify_verdict: string; lifecycle_before: string | null; lifecycle_after: string | null; match_basis: string }>(
    'SELECT reverify_verdict, lifecycle_before, lifecycle_after, match_basis FROM vuln_occurrence WHERE audit_id = ? AND vulnerability_id = ? AND reverify_verdict IS NOT NULL', auditId, vulnId);
}

export function stepOutputRef(store: Store, stepId: string): string | null | undefined {
  return store.get<{ output_ref: string | null }>('SELECT output_ref FROM step WHERE id = ?', stepId)?.output_ref;
}

// ---- questions ----

export function auditQuestions<T = Record<string, unknown>>(store: Store, auditId: string): T[] {
  return store.all<T>('SELECT * FROM question WHERE audit_id = ? ORDER BY created_at', auditId);
}

export function getQuestion<T = Record<string, unknown>>(store: Store, questionId: string): T | undefined {
  return store.get<T>('SELECT * FROM question WHERE id = ?', questionId);
}

/** Open questions of all audits with the audit and project names, newest first. */
export function openQuestions<T = Record<string, unknown>>(store: Store, limit = 50): T[] {
  return store.all<T>(`SELECT q.*, a.title AS audit_title, p.name AS project_name FROM question q JOIN audit a ON a.id = q.audit_id JOIN project p ON p.id = a.project_id WHERE q.status = 'open' ORDER BY q.created_at DESC LIMIT ?`, limit);
}

// ---- findings and coverage ----

/** Findings of an audit by display number (raw rows). */
export function auditFindings<T = Record<string, unknown>>(store: Store, auditId: string): T[] {
  return store.all<T>(`SELECT * FROM finding WHERE audit_id = ? ORDER BY display_no IS NULL, display_no, id`, auditId);
}

/** Audits started from this one (backfills and supplements). */
export function childAudits(store: Store, baseAuditId: string): { id: string; title: string; status: string; scope: string }[] {
  return store.all<{ id: string; title: string; status: string; scope: string }>(`SELECT id, title, status, scope FROM audit WHERE base_audit_id = ? ORDER BY created_at`, baseAuditId);
}

export function concludedCoverageCount(store: Store, auditId: string): number {
  return store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM coverage_item WHERE audit_id = ? AND status = 'concluded'`, auditId)!.n;
}

/** Threat-model hypotheses an audit listed or verified. */
export function threatHypothesisCount(store: Store, auditId: string): number {
  return store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM hypothesis WHERE origin = 'threat_model' AND (audit_id = ? OR verify_step_id IN (SELECT id FROM step WHERE audit_id = ?))`, auditId, auditId)!.n;
}

export interface CoverageItemRow {
  id: string; kind: string; repo: string; repository_id: string; target_id: string; category: string; path: string; start_line: number; end_line: number; status: string; verdict: string | null;
  finding_id: string | null; snapshot_id: string; root_hash: string | null; detail: string | null;
}

/** Coverage items of an audit with the repository name; `uncovered` keeps only the ones neither concluded nor excluded. */
export function coverageItems(store: Store, auditId: string, uncovered = false): CoverageItemRow[] {
  return store.all<CoverageItemRow>(
    `SELECT c.*, r.name AS repo, s.root_hash FROM coverage_item c JOIN repository r ON r.id = c.repository_id LEFT JOIN snapshot s ON s.id = c.snapshot_id
     WHERE c.audit_id = ?${uncovered ? ` AND c.status NOT IN ('concluded','excluded')` : ''} ORDER BY c.kind, c.path, c.start_line`, auditId);
}

// ---- home page ----

/** Projects with vulnerabilities awaiting confirmation, by project name. */
export function pendingVulnsByProject(store: Store): { project_id: string; name: string; n: number }[] {
  return store.all<{ project_id: string; name: string; n: number }>(
    `SELECT v.project_id, p.name, COUNT(*) AS n FROM vulnerability v JOIN project p ON p.id = v.project_id WHERE v.status = 'active' AND v.confirm_status = 'pending' GROUP BY v.project_id ORDER BY p.name`);
}

/** The missing context (JSON) of a project's vulnerabilities awaiting confirmation. */
export function pendingMissingContexts(store: Store, projectId: string): string[] {
  return store.all<{ missing_context: string }>(`SELECT missing_context FROM vulnerability WHERE project_id = ? AND status = 'active' AND confirm_status = 'pending' AND missing_context IS NOT NULL`, projectId)
    .map((v) => v.missing_context);
}

export interface ProposedRevisionRow { vid: string; display_no: number; project_id: string; project_name: string; title: string; dimension: string; to_value: string | null; reason: string | null; conversation_id: string | null }

/** Revisions proposed on active vulnerabilities, newest first. */
export function proposedRevisions(store: Store, limit = 50): ProposedRevisionRow[] {
  return store.all<ProposedRevisionRow>(
    `SELECT v.id AS vid, v.display_no, v.project_id, p.name AS project_name, v.title, r.dimension, r.to_value, r.reason, r.conversation_id FROM revision r
     JOIN vulnerability v ON v.id = r.vulnerability_id JOIN project p ON p.id = v.project_id WHERE r.state = 'proposed' AND v.status = 'active'
     ORDER BY r.created_at DESC LIMIT ?`, limit);
}
