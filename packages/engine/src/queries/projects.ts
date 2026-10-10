// Read queries on projects, repositories and project analyses for the API and the CLI:
// the applications shape responses; the SQL lives here.
import type { AuditStatus, Severity } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import type { RepoRoleOutput } from '../analyze.js';

export function repoCount(store: Store, projectId: string): number {
  return store.get<{ n: number }>('SELECT COUNT(*) AS n FROM repository WHERE project_id = ? AND removed_at IS NULL', projectId)!.n;
}

/** Open vulnerabilities by severity: active, not a false positive, still to handle, not verified fixed. */
export function openVulnCounts(store: Store, projectId: string): { severity: Severity; n: number }[] {
  return store.all<{ severity: Severity; n: number }>(
    `SELECT severity, COUNT(*) AS n FROM vulnerability WHERE project_id = ? AND status = 'active' AND confirm_status != 'false_positive'
     AND handling_status IN ('open','fixing') AND lifecycle != 'fixed_verified' GROUP BY severity`, projectId);
}

export function lastAudit(store: Store, projectId: string): { id: string; status: AuditStatus; ended_at: number | null } | undefined {
  return store.get<{ id: string; status: AuditStatus; ended_at: number | null }>('SELECT id, status, ended_at FROM audit WHERE project_id = ? ORDER BY created_at DESC LIMIT 1', projectId);
}

/** The latest finished full audit that compared coverage (覆盖是否完整). */
export function latestCoverageAudit(store: Store, projectId: string): { id: string; strategy_frozen: string | null } | undefined {
  return store.get<{ id: string; strategy_frozen: string | null }>(
    `SELECT id, strategy_frozen FROM audit WHERE project_id = ? AND status IN ('completed','partial') AND scene = 'full' AND json_extract(strategy_frozen, '$.tools.coverageCompare') = 1
     ORDER BY created_at DESC LIMIT 1`, projectId);
}

/** Coverage items of an audit of one kind (excluded ones not counted), optionally of one status. */
export function coverageCount(store: Store, auditId: string, kind: string, status?: string): number {
  return store.get<{ n: number }>(
    `SELECT COUNT(*) AS n FROM coverage_item WHERE audit_id = ? AND kind = ? AND status != 'excluded'${status ? ' AND status = ?' : ''}`, ...(status ? [auditId, kind, status] : [auditId, kind]))!.n;
}

/** The snapshot the repository was last audited at. */
export function lastRepoSnapshot(store: Store, repositoryId: string): { resolved_commit: string | null; requested_ref: string | null; is_worktree: number; audit_id: string } | undefined {
  return store.get<{ resolved_commit: string | null; requested_ref: string | null; is_worktree: number; audit_id: string }>(
    `SELECT s.resolved_commit, s.requested_ref, s.is_worktree, ar.audit_id FROM audit_repository ar JOIN snapshot s ON s.id = ar.snapshot_id
     WHERE ar.repository_id = ? ORDER BY ar.created_at DESC LIMIT 1`, repositoryId);
}

/** Latest AI role judgement of a repository, or null. */
export function latestRoleResult(store: Store, repositoryId: string): RepoRoleOutput | null {
  const row = store.get<{ result_ref: string }>(
    `SELECT result_ref FROM repo_analysis WHERE repository_id = ? AND result_ref IS NOT NULL ORDER BY created_at DESC, rowid DESC LIMIT 1`, repositoryId);
  return row ? store.artifacts.getJson<RepoRoleOutput>(row.result_ref) : null;
}

export interface RepoAnalysisRow { repository_id: string; name: string; status: string; root_hash: string | null; error: string | null; result_ref: string | null; signals_ref: string | null }

/** The repositories of a project analysis, by name. */
export function analysisRepos(store: Store, analysisId: string): RepoAnalysisRow[] {
  return store.all<RepoAnalysisRow>(
    `SELECT ra.repository_id, r.name, ra.status, ra.root_hash, ra.error, ra.result_ref, ra.signals_ref FROM repo_analysis ra JOIN repository r ON r.id = ra.repository_id
     WHERE ra.analysis_id = ? ORDER BY r.name`, analysisId);
}

export function projectName(store: Store, projectId: string): string | undefined {
  return store.get<{ name: string }>('SELECT name FROM project WHERE id = ?', projectId)?.name;
}

export function repositoryName(store: Store, repositoryId: string): string | undefined {
  return store.get<{ name: string }>('SELECT name FROM repository WHERE id = ?', repositoryId)?.name;
}

/** Active projects by name (raw rows). */
export function activeProjects<T = Record<string, unknown>>(store: Store): T[] {
  return store.all<T>(`SELECT * FROM project WHERE status = 'active' ORDER BY name`);
}

/** A repository that has not been removed (raw row). */
export function liveRepository<T = Record<string, unknown>>(store: Store, repositoryId: string): T | undefined {
  return store.get<T>('SELECT * FROM repository WHERE id = ? AND removed_at IS NULL', repositoryId);
}

/** The latest analysis of a project (raw row). */
export function latestProjectAnalysis<T = Record<string, unknown>>(store: Store, projectId: string): T | undefined {
  return store.get<T>('SELECT * FROM project_analysis WHERE project_id = ? ORDER BY started_at DESC, rowid DESC LIMIT 1', projectId);
}

export interface ProjectAnalysisRow { status: string; reason: string | null; model: string | null; tokens_in: number; tokens_out: number }

export function projectAnalysis(store: Store, analysisId: string): ProjectAnalysisRow | undefined {
  return store.get<ProjectAnalysisRow>('SELECT status, reason, model, tokens_in, tokens_out FROM project_analysis WHERE id = ?', analysisId);
}

/** Repositories of an analysis with their role (CLI summary). */
export function analysisRoleRows(store: Store, analysisId: string): { name: string; status: string; role: string; role_source: string; error: string | null }[] {
  return store.all<{ name: string; status: string; role: string; role_source: string; error: string | null }>(
    `SELECT r.name, ra.status, r.role, r.role_source, ra.error FROM repo_analysis ra JOIN repository r ON r.id = ra.repository_id WHERE ra.analysis_id = ? ORDER BY r.name`, analysisId);
}
