// Rerun and compare: a rerun is a new audit with the source's
// configuration (scene, repository and version, frozen strategy, baseline or targets); the source stays
// unchanged. Compare lists the vulnerabilities that appeared, disappeared or changed between two audits.
import { AppError, upgradeStrategy } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { createAudit, createReverifyAudit } from './services.js';

interface AuditRow {
  id: string; project_id: string; scene: string; mode: string | null; title: string; status: string; scope: string; strategy_frozen: string | null; strategy_draft: string;
  base_audit_id: string | null; auto_start: number;
}

/** New audit with the configuration of `sourceId` (the source is recorded in `scope.rerunOf`). */
export function rerunAudit(store: Store, knownModels: Set<string>, sourceId: string, origin: 'cli' | 'ui' | 'conversation'): string {
  const src = store.get<AuditRow>('SELECT * FROM audit WHERE id = ?', sourceId);
  if (!src) throw new AppError('AUDIT_NOT_FOUND', sourceId);
  if (!['completed', 'partial', 'failed', 'cancelled'].includes(src.status)) throw new AppError('AUDIT_INVALID_TRANSITION', 'only finished audits can be rerun');
  const scope = fromJson<{ backfill?: unknown; reverify?: string[] }>(src.scope, {});
  if (scope.backfill) throw new AppError('COMMON_VALIDATION', 'a backfill is rerun from the coverage of its source audit');
  const repo = store.get<{ repository_id: string; requested_ref: string | null; base_snapshot_id: string | null; base_requested_ref: string | null }>(
    `SELECT repository_id, requested_ref, base_snapshot_id, base_requested_ref FROM audit_repository WHERE audit_id = ? AND role_in_audit = 'target'`, src.id);
  if (!repo) throw new AppError('REPOSITORY_NOT_FOUND', 'source audit has no target repository');
  let id: string;
  if (src.scene === 'reverify') {
    const active = (scope.reverify ?? []).filter((v) => store.get(`SELECT 1 FROM vulnerability WHERE id = ? AND status = 'active'`, v));
    id = createReverifyAudit(store, knownModels, { vulnIds: active, origin, ...(repo.requested_ref ? { refs: { [repo.repository_id]: repo.requested_ref } } : {}) });
  } else {
    const strategy = upgradeStrategy(JSON.parse(src.strategy_frozen ?? src.strategy_draft)) as unknown as Record<string, unknown>;
    const incremental = src.scene === 'incremental';
    // every repository of the source, not only its first target (a multi-repository audit was rerun on
    // one repository); each keeps its version.
    const rows = store.all<{ repository_id: string; requested_ref: string | null; role_in_audit: string }>(
      `SELECT repository_id, requested_ref, role_in_audit FROM audit_repository WHERE audit_id = ? AND role_in_audit IN ('target', 'related')`, src.id);
    const targets = rows.filter((r) => r.role_in_audit === 'target').map((r) => r.repository_id);
    const related = rows.filter((r) => r.role_in_audit === 'related').map((r) => r.repository_id);
    const refs = Object.fromEntries(rows.filter((r) => r.requested_ref).map((r) => [r.repository_id, r.requested_ref!]));
    const multi = src.mode === 'multi' && !incremental;
    id = createAudit(store, knownModels, {
      projectId: src.project_id, scene: incremental ? 'incremental' : 'full', origin,
      ...(multi ? { mode: 'multi' as const, repositories: targets } : { repository: repo.repository_id, ...(related.length ? { related } : {}) }),
      ...(Object.keys(refs).length ? { refs } : {}),
      title: `${src.title.replace(/（重新审计）$/, '')}（重新审计）`, strategyOverride: strategy,
      // The source started right after its plan unless it asked to confirm the plan first; the rerun does the same.
      ...(src.auto_start ? { autoStart: true } : {}),
      // `ref` is the single target's (in a multi-repository audit it would apply to every target; `refs` has each).
      ...(!multi && repo.requested_ref ? { ref: repo.requested_ref } : {}),
      // Same baseline as the source: the same ref, or the same baseline audit.
      ...(incremental && repo.base_requested_ref ? { baseRef: repo.base_requested_ref } : {}),
      ...(incremental && !repo.base_requested_ref && src.base_audit_id ? { baseAuditId: src.base_audit_id } : {}),
    });
    if (!incremental) store.update('audit', { id }, { base_audit_id: src.id });
  }
  const a = store.get<{ scope: string }>('SELECT scope FROM audit WHERE id = ?', id)!;
  store.update('audit', { id }, { scope: { ...fromJson<Record<string, unknown>>(a.scope, {}), rerunOf: src.id } });
  return id;
}

export interface CompareVuln { vulnId: string; displayNo: number; title: string; severity: string; category: string; lifecycle: string }
export interface AuditComparison {
  base: { id: string; title: string; createdAt: number };
  target: { id: string; title: string; createdAt: number };
  added: CompareVuln[];
  /** Found in the base, not in the target: `presence` says whether it was verified fixed, only not found, or not covered. */
  removed: (CompareVuln & { presence: string })[];
  changed: (CompareVuln & { changes: string[] })[];
  unchanged: number;
}

/** Follow merges so both audits speak about the same (surviving) vulnerability. */
function root(store: Store, id: string): string {
  let cur = id;
  for (let i = 0; i < 20; i++) {
    const v = store.get<{ merged_into_id: string | null; status: string }>('SELECT merged_into_id, status FROM vulnerability WHERE id = ?', cur);
    if (!v || v.status !== 'merged' || !v.merged_into_id) return cur;
    cur = v.merged_into_id;
  }
  return cur;
}

export function compareAudits(store: Store, targetId: string, baseId: string): AuditComparison {
  const t = store.get<{ id: string; title: string; created_at: number; project_id: string }>('SELECT id, title, created_at, project_id FROM audit WHERE id = ?', targetId);
  const b = store.get<{ id: string; title: string; created_at: number; project_id: string }>('SELECT id, title, created_at, project_id FROM audit WHERE id = ?', baseId);
  if (!t) throw new AppError('AUDIT_NOT_FOUND', targetId);
  if (!b) throw new AppError('AUDIT_NOT_FOUND', baseId);
  if (t.project_id !== b.project_id) throw new AppError('COMMON_VALIDATION', 'audits belong to different projects');
  const seen = (auditId: string) => {
    const m = new Map<string, { severity: string; lifecycle: string | null; entries: string }>();
    for (const o of store.all<{ vulnerability_id: string; lifecycle_after: string | null; severity: string | null; entry_keys: string | null }>(
      `SELECT o.vulnerability_id, o.lifecycle_after, f.severity, f.entry_keys FROM vuln_occurrence o LEFT JOIN finding f ON f.id = o.finding_id
       WHERE o.audit_id = ? AND o.presence = 'found'`, auditId)) {
      m.set(root(store, o.vulnerability_id), { severity: o.severity ?? '', lifecycle: o.lifecycle_after, entries: o.entry_keys ?? '[]' });
    }
    return m;
  };
  const inT = seen(t.id);
  const inB = seen(b.id);
  const vuln = (id: string): CompareVuln => {
    const v = store.get<{ display_no: number; title: string; severity: string; category: string; lifecycle: string }>('SELECT display_no, title, severity, category, lifecycle FROM vulnerability WHERE id = ?', id)!;
    return { vulnId: id, displayNo: v.display_no, title: v.title, severity: v.severity, category: v.category, lifecycle: v.lifecycle };
  };
  const presenceIn = (auditId: string, vid: string) => store.get<{ presence: string }>(
    `SELECT presence FROM vuln_occurrence WHERE audit_id = ? AND (vulnerability_id = ? OR vulnerability_id IN (SELECT id FROM vulnerability WHERE merged_into_id = ?)) ORDER BY presence = 'not_found_verified' DESC LIMIT 1`, auditId, vid, vid)?.presence ?? 'absent';
  const added = [...inT.keys()].filter((id) => !inB.has(id)).map(vuln);
  const removed = [...inB.keys()].filter((id) => !inT.has(id)).map((id) => ({ ...vuln(id), presence: presenceIn(t.id, id) }));
  const changed: AuditComparison['changed'] = [];
  let unchanged = 0;
  for (const [id, x] of inT) {
    const y = inB.get(id);
    if (!y) continue;
    const changes: string[] = [];
    if (x.severity && y.severity && x.severity !== y.severity) changes.push(`severity:${y.severity}→${x.severity}`);
    const ex = new Set(fromJson<string[]>(x.entries, []));
    const ey = new Set(fromJson<string[]>(y.entries, []));
    const plus = [...ex].filter((e) => !ey.has(e));
    const minus = [...ey].filter((e) => !ex.has(e));
    if (plus.length) changes.push(`entries+:${plus.join(',')}`);
    if (minus.length) changes.push(`entries-:${minus.join(',')}`);
    if (x.lifecycle === 'regressed' && y.lifecycle !== 'regressed') changes.push('regressed');
    if (changes.length) changed.push({ ...vuln(id), changes }); else unchanged++;
  }
  const order = (a: CompareVuln, c: CompareVuln) => a.displayNo - c.displayNo;
  return {
    base: { id: b.id, title: b.title, createdAt: b.created_at }, target: { id: t.id, title: t.title, createdAt: t.created_at },
    added: added.sort(order), removed: removed.sort(order), changed: changed.sort(order), unchanged,
  };
}
