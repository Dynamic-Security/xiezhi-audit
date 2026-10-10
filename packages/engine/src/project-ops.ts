// Changes to projects and repositories requested through the API: the
// rules that were in the server routes — name checks, no deletion while audits are active, role and auditable
// overrides, soft removal.
import { AppError } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { primaryRole } from './analyze.js';
import { latestRoleResult, liveRepository } from './queries/projects.js';
import type { ProjectRow, RepositoryRow } from './services.js';
import { getProject } from './services.js';

const PROJECT_NAME = /^[\p{L}\p{N}][\p{L}\p{N}._ -]{0,99}$/u;
const REPO_ROLES = ['gateway', 'auth', 'business', 'api_def', 'frontend', 'shared_lib', 'unknown'];
const ACTIVE_AUDIT = `SELECT 1 FROM audit WHERE project_id = ? AND status IN ('planning','queued','running','cancelling')`;

export function updateProject(store: Store, projectId: string, patch: { name?: string; status?: 'active' | 'archived' }): ProjectRow {
  const p = getProject(store, projectId);
  if (patch.name && patch.name !== p.name) {
    if (!PROJECT_NAME.test(patch.name)) throw new AppError('COMMON_VALIDATION', 'invalid project name');
    if (store.get('SELECT 1 FROM project WHERE name = ? AND id != ?', patch.name, p.id)) throw new AppError('PROJECT_EXISTS', patch.name);
  }
  store.update('project', { id: p.id }, { ...(patch.name ? { name: patch.name } : {}), ...(patch.status ? { status: patch.status } : {}) });
  return getProject(store, p.id);
}

/** Delete a project with no active audit; `confirmName` must repeat its name (ConfirmDialog). */
export function deleteProject(store: Store, projectId: string, confirmName: string | undefined): void {
  const p = getProject(store, projectId);
  if (confirmName !== p.name) throw new AppError('COMMON_VALIDATION', 'confirmName must equal the project name');
  if (store.get(ACTIVE_AUDIT, p.id)) throw new AppError('AUDIT_INVALID_TRANSITION', 'project has active audits; cancel them first');
  store.tx(() => {
    store.db.run('DELETE FROM audit_repository WHERE audit_id IN (SELECT id FROM audit WHERE project_id = ?)', p.id);
    // Hypothesis (migration 21) references audit, project, repository, step, finding and
    // vulnerability without ON DELETE, so its rows would block the cascade.
    store.db.run('DELETE FROM hypothesis WHERE project_id = ? OR audit_id IN (SELECT id FROM audit WHERE project_id = ?)', p.id, p.id);
    store.db.run('DELETE FROM project WHERE id = ?', p.id);
  });
}

/** A repository that has not been removed, or REPOSITORY_NOT_FOUND. */
export function getLiveRepository<T = RepositoryRow>(store: Store, repositoryId: string): T {
  const r = liveRepository<T>(store, repositoryId);
  if (!r) throw new AppError('REPOSITORY_NOT_FOUND', repositoryId);
  return r;
}

/**
 * Change a repository's default ref, role or auditable setting. `role: 'auto'` drops the user's correction and returns
 * to the latest AI judgement (unknown when never analyzed); `auditable: 'auto'` follows the judgement again;
 * a manual setting survives later analyses.
 */
export function updateRepository(store: Store, repositoryId: string, patch: { defaultRef?: string | null; role?: string; auditable?: boolean | 'auto' }): void {
  const r = getLiveRepository<{ id: string; is_auditable: number; auditable_auto: number | null }>(store, repositoryId);
  if (patch.defaultRef && (patch.defaultRef.startsWith('-') || /[\s\0]/.test(patch.defaultRef))) throw new AppError('COMMON_VALIDATION', 'invalid ref');
  if (patch.role && patch.role !== 'auto' && !REPO_ROLES.includes(patch.role)) throw new AppError('COMMON_VALIDATION', 'role');
  const latest = patch.role === 'auto' ? latestRoleResult(store, r.id) : null;
  const role = patch.role === 'auto' ? { role: latest ? primaryRole(latest.judgement) : 'unknown', role_source: 'ai' } : patch.role ? { role: patch.role, role_source: 'user' } : {};
  const auditable = patch.auditable === undefined ? {}
    : patch.auditable === 'auto' ? { auditable_source: 'auto', is_auditable: r.auditable_auto ?? r.is_auditable }
      : { auditable_source: 'user', is_auditable: patch.auditable ? 1 : 0 };
  store.update('repository', { id: r.id }, { ...(patch.defaultRef !== undefined ? { default_ref: patch.defaultRef || null } : {}), ...role, ...auditable });
}

/** Soft remove: finished audits keep referring to the repository. */
export function removeRepository(store: Store, repositoryId: string): void {
  const r = getLiveRepository<{ id: string }>(store, repositoryId);
  store.update('repository', { id: r.id }, { removed_at: Date.now() });
}
