// Snapshot a repository from its source (local directory, remote Git, uploaded archive) — shared by the
// audit snapshot step and project analysis.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { newId, type SnapshotManifest } from '@xiezhi/contracts';
import { createSnapshot, SnapshotError, type Executor, type SnapshotResult, type SnapshotSource } from '@xiezhi/context';
import type { Store } from '@xiezhi/store';
import { parseRemote, remoteAuth, type SourceMeta } from './services.js';

export interface SourceRow { id: string; source_kind: string; source_uri: string; source_meta: string }

/** Archive repositories reuse the snapshot taken when the archive was added. */
function archiveSnapshot(store: Store, repo: SourceRow, ref: string | null): SnapshotResult {
  if (ref) throw new SnapshotError('an uploaded archive has no branches or commits; upload a new archive for another version');
  const meta = JSON.parse(repo.source_meta) as SourceMeta;
  const snap = meta.rootHash ? store.get<{ manifest_ref: string }>('SELECT manifest_ref FROM snapshot WHERE repository_id = ? AND root_hash = ?', repo.id, meta.rootHash) : undefined;
  const root = meta.rootHash ? join(store.paths.snapshots, meta.rootHash) : '';
  if (!snap || !existsSync(root)) throw new SnapshotError('the snapshot of this archive is missing; upload the archive again');
  return { manifest: store.artifacts.getJson<SnapshotManifest>(snap.manifest_ref), root, reused: true };
}

/** Throws SnapshotError (or AppError for an invalid stored URL). */
export async function snapshotSource(store: Store, executor: Executor, repo: SourceRow, ref: string | null, opts: { allowFileRemotes?: boolean; signal?: AbortSignal } = {}): Promise<SnapshotResult> {
  if (repo.source_kind === 'archive') return archiveSnapshot(store, repo, ref);
  const r = ref ? { ref } : {};
  let source: SnapshotSource;
  if (repo.source_kind === 'git') {
    const remote = parseRemote(repo.source_uri, opts.allowFileRemotes);
    source = { kind: 'remote', remote, cacheRoot: store.paths.gitCache, auth: remoteAuth(store.config, remote, opts.allowFileRemotes), ...r };
  } else source = { kind: 'local', path: repo.source_uri, ...r };
  return createSnapshot({ source, snapshotsDir: store.paths.snapshots, tmpDir: store.paths.tmp, executor, ...(opts.signal ? { signal: opts.signal } : {}) });
}

/** The snapshot row for (repository, rootHash), created on first use. Call inside a transaction. */
export function recordSnapshot(store: Store, repositoryId: string, m: SnapshotManifest, manifestRef: string): string {
  const snap = store.get<{ id: string }>('SELECT id FROM snapshot WHERE repository_id = ? AND root_hash = ?', repositoryId, m.rootHash);
  if (snap) return snap.id;
  const id = newId('snapshot');
  store.insert('snapshot', {
    id, repository_id: repositoryId, root_hash: m.rootHash, manifest_ref: manifestRef, requested_ref: m.source.ref ?? null,
    resolved_ref_name: m.source.ref ?? null, resolved_commit: m.source.kind === 'archive' ? null : m.source.commit ?? null, is_worktree: m.source.worktree ? 1 : 0,
    file_count: m.stats.fileCount, bytes: m.stats.totalBytes,
  });
  return id;
}
