// Auditable vs context-only repositories (migration 20). The automatic judgement comes from the
// snapshot's languages; the user may override it. `is_auditable` is the effective value, `auditable_auto` /
// `auditable_reason` the latest automatic judgement, `auditable_source` which of the two is in force.
import { auditLanguagesOfView, type SnapshotView } from '@xiezhi/context';
import { presentAuditLanguages, type AuditLanguage } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { auditableFrom } from './services.js';

export interface AuditableJudgement { auditable: boolean; reason: string | null }

/** Automatic judgement from a snapshot (JS / TS backend marker and minor-language share included). */
export function autoAuditable(view: SnapshotView): AuditableJudgement {
  if (auditLanguagesOfView(view).length) return { auditable: true, reason: null };
  // Not auditable: JS / TS present means the backend marker was missing (a known `false`, not unknown).
  const { note } = auditableFrom(view.manifest.stats.byLang, false, false);
  return { auditable: false, reason: note };
}

/** Record an automatic judgement; the effective value follows it only while the user has not set one. */
export function recordAutoAuditable(store: Store, repositoryId: string, j: AuditableJudgement): void {
  const row = store.get<{ auditable_source: string }>('SELECT auditable_source FROM repository WHERE id = ?', repositoryId);
  if (!row) return;
  store.update('repository', { id: repositoryId }, {
    auditable_auto: j.auditable ? 1 : 0, auditable_reason: j.reason,
    ...(row.auditable_source === 'auto' ? { is_auditable: j.auditable ? 1 : 0 } : {}),
  });
}

/**
 * Languages the index parses for a repository: a user-set “auditable” repository gets every audit language it
 * has files of (otherwise a misjudged JS backend would still index nothing); everything else the default.
 */
export function indexLanguagesFor(store: Store, repositoryId: string | undefined, view: SnapshotView): AuditLanguage[] | undefined {
  if (!repositoryId) return undefined;
  const r = store.get<{ is_auditable: number; auditable_source: string }>('SELECT is_auditable, auditable_source FROM repository WHERE id = ?', repositoryId);
  return r?.auditable_source === 'user' && r.is_auditable ? presentAuditLanguages(view.manifest.stats.byLang) : undefined;
}
