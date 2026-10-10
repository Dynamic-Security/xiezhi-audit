// snapshot / index steps (deterministic).
import type { SnapshotManifest } from '@xiezhi/contracts';
import { buildIndex, SnapshotError, SnapshotView, type RuleSet, type SnapshotResult } from '@xiezhi/context';
import type { AuditRuntime } from '../runtime.js';
import { effectiveIndex } from '../business.js';
import { recordSnapshot, snapshotSource } from '../sources.js';
import { StepError, type AttemptContext, type StepResult } from '../step-runner.js';

/** `base`: snapshot the incremental baseline (`base_requested_ref`) into `base_snapshot_id`. */
export async function snapshotStep(rt: AuditRuntime, repositoryId: string, ctx: AttemptContext, opts: { base?: boolean } = {}): Promise<StepResult> {
  const store = rt.store;
  const found = store.get<{ name: string; source_kind: string; source_uri: string; source_meta: string; requested_ref: string | null; base_requested_ref: string | null }>(
    `SELECT r.name, r.source_kind, r.source_uri, r.source_meta, ar.requested_ref, ar.base_requested_ref FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id
     WHERE ar.audit_id = ? AND ar.repository_id = ?`, rt.auditId, repositoryId);
  if (!found) throw new StepError('SNAPSHOT_UNAVAILABLE', 'repository not attached to audit');
  const row = { ...found, requested_ref: opts.base ? found.base_requested_ref : found.requested_ref };
  if (opts.base && !row.requested_ref) throw new StepError('SNAPSHOT_UNAVAILABLE', 'no baseline ref requested');
  let result: SnapshotResult;
  try {
    result = await snapshotSource(store, rt.executor, { id: repositoryId, source_kind: row.source_kind, source_uri: row.source_uri, source_meta: row.source_meta }, row.requested_ref, { allowFileRemotes: rt.allowFileRemotes, signal: ctx.signal });
  } catch (e) {
    if (e instanceof SnapshotError) throw new StepError(ctx.signal.aborted ? 'CANCELLED' : 'SNAPSHOT_UNAVAILABLE', e.message);
    throw new StepError('SNAPSHOT_UNAVAILABLE', (e as Error).message);
  }
  const m = result.manifest;
  const manifestRef = store.artifacts.putJson(m);
  const outputRef = store.artifacts.putJson({ repositoryId, rootHash: m.rootHash, manifestRef });
  return {
    outputRef,
    apply: () => {
      const snap = { id: recordSnapshot(store, repositoryId, m, manifestRef) };
      if (opts.base) {
        store.update('audit_repository', { audit_id: rt.auditId, repository_id: repositoryId }, { base_snapshot_id: snap.id });
        return;
      }
      store.update('audit_repository', { audit_id: rt.auditId, repository_id: repositoryId }, { snapshot_id: snap.id });
      store.update('repository', { id: repositoryId }, { languages: Object.keys(m.stats.byLang).sort() });
      for (const e of m.excluded.filter((x) => x.reason === 'agent_control')) {
        rt.event('injection_suspected', { repo: row.name, path: e.path, signal: 'excluded_control_file' }, ctx.stepId);
      }
    },
  };
}

export async function indexStep(rt: AuditRuntime, rules: RuleSet, repoName: string, ctx: AttemptContext): Promise<StepResult> {
  const view = rt.views.get(repoName);
  if (!view) throw new StepError('SNAPSHOT_UNAVAILABLE', `no snapshot for ${repoName}`);
  let r;
  try {
    r = await buildIndex(view, rules, { indexesDir: rt.store.paths.indexes, signal: ctx.signal, ...rt.indexLanguages(repoName, view) });
  } catch (e) {
    throw new StepError(ctx.signal.aborted ? 'CANCELLED' : 'TOOL_FAILURE', (e as Error).message);
  }
  rt.indexes.set(repoName, effectiveIndex(r.index, rt.strategy));
  const summary = {
    repo: repoName, rootHash: view.rootHash, cacheKey: r.cacheKey, cached: r.cached, status: r.status,
    counts: { symbols: r.index.symbols.length, entrypoints: r.index.entrypoints.length, sinks: r.index.sinks.length, edges: r.index.callEdges.length },
    gaps: r.index.gaps.slice(0, 50),
  };
  return { outputRef: rt.store.artifacts.putJson(summary) };
}

export function manifestOf(rt: AuditRuntime, repoName: string): SnapshotManifest | undefined {
  return rt.views.get(repoName)?.manifest;
}

export type { SnapshotView };
