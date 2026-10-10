// Manual identity corrections: merge B → A, split A → A + C, and undo. Each
// operation is one transaction and one `identity` revision per vulnerability involved; the revision's
// `to` value records exactly what moved, so undo can restore it.
import { AppError, newId, type Lifecycle } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { addRevision } from './vulns.js';

interface VulnRow {
  id: string; project_id: string; display_no: number; status: string; merged_into_id: string | null; lifecycle: Lifecycle; rev: number;
  repository_id: string; module: string | null; category: string; cwe: string | null; title: string; severity: string; severity_original: string | null;
  confidence: string; sink_symbol: string | null; sink_api: string | null; root_cause: string | null; confirm_status: string; handling_status: string;
  handling_reason: string | null; pending_kind: string | null; missing_context: string | null; evidence_complete: number; detail_ref: string;
  first_seen_audit_id: string | null; last_seen_audit_id: string | null; last_verified_audit_id: string | null;
}

/** What an identity operation did, stored in the revision (`to_value`) for display and undo. */
export type IdentityOp =
  | { op: 'merge'; source: string; target: string; fingerprints: string[]; entries: string[]; lifecycle: { from: Lifecycle; to: Lifecycle } }
  | { op: 'split'; source: string; created: string; fingerprints: string[]; entries: string[]; sharedFingerprints: string[] }
  | { op: 'undo'; of: string };

function vuln(store: Store, id: string): VulnRow {
  const v = store.get<VulnRow>('SELECT * FROM vulnerability WHERE id = ?', id);
  if (!v) throw new AppError('VULN_NOT_FOUND', id);
  return v;
}

function checkRev(v: VulnRow, expected: number | undefined): void {
  if (expected !== undefined && v.rev !== expected) throw new AppError('COMMON_REVISION_CONFLICT', `V-${v.display_no}: current revision ${v.rev}`, { revision: v.rev });
}

/** Lifecycle after the latest occurrence across a set of vulnerabilities ("按合并后的出现记录重算"). */
function lifecycleFromOccurrences(store: Store, ids: string[], fallback: Lifecycle): Lifecycle {
  const row = store.get<{ lifecycle_after: Lifecycle | null }>(
    `SELECT lifecycle_after FROM vuln_occurrence WHERE vulnerability_id IN (${ids.map(() => '?').join(',')}) AND lifecycle_after IS NOT NULL
     ORDER BY created_at DESC, (presence = 'found') DESC LIMIT 1`, ...ids);
  return row?.lifecycle_after ?? fallback;
}

/**
 * Merge sources into target: each source becomes `merged` into the target, its active
 * fingerprints are re-issued on the target as `kind=merged` (later audits hitting them land on the
 * target), entries are unioned; source occurrences, evidence and revisions stay where they are and are
 * read through `merged_into_id`.
 */
export function mergeVulnerabilities(store: Store, input: { sourceIds: string[]; targetId: string; reason: string; actor: string; targetRevision?: number }): void {
  const reason = input.reason.trim();
  if (!reason) throw new AppError('VULN_REASON_REQUIRED', 'merging needs a reason');
  const sources = [...new Set(input.sourceIds)];
  if (sources.length === 0) throw new AppError('COMMON_VALIDATION', 'no source vulnerabilities');
  if (sources.includes(input.targetId)) throw new AppError('COMMON_VALIDATION', 'a vulnerability cannot be merged into itself');
  store.tx(() => {
    const target = vuln(store, input.targetId);
    checkRev(target, input.targetRevision);
    if (target.status !== 'active') throw new AppError('COMMON_VALIDATION', `V-${target.display_no} is not active`);
    for (const sid of sources) {
      const s = vuln(store, sid);
      if (s.project_id !== target.project_id) throw new AppError('VULN_MERGE_CROSS_PROJECT');
      if (s.status !== 'active') throw new AppError('COMMON_VALIDATION', `V-${s.display_no} is not active`);
      const fps = store.all<{ fp: string }>('SELECT fp FROM vuln_fingerprint WHERE vulnerability_id = ? AND active = 1', s.id).map((f) => f.fp);
      store.db.run('UPDATE vuln_fingerprint SET active = 0 WHERE vulnerability_id = ? AND active = 1', s.id);
      for (const fp of fps) store.insert('vuln_fingerprint', { vulnerability_id: target.id, project_id: target.project_id, fp, kind: 'merged', since_audit_id: null, active: 1 });
      const known = new Set(store.all<{ entry_key: string }>('SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ?', target.id).map((e) => e.entry_key));
      const moved = store.all<{ entry_key: string; repository_id: string; first_seen_audit_id: string | null; last_seen_audit_id: string | null; state: string }>(
        'SELECT entry_key, repository_id, first_seen_audit_id, last_seen_audit_id, state FROM vuln_entry WHERE vulnerability_id = ?', s.id).filter((e) => !known.has(e.entry_key));
      for (const e of moved) store.insert('vuln_entry', { vulnerability_id: target.id, ...e });
      store.update('vulnerability', { id: s.id }, { status: 'merged', merged_into_id: target.id, suspected_link: 0 });
      const before = vuln(store, target.id).lifecycle;
      const after = lifecycleFromOccurrences(store, [target.id, s.id, ...mergedChildren(store, target.id)], before);
      if (after !== before) store.update('vulnerability', { id: target.id }, { lifecycle: after });
      const op: IdentityOp = { op: 'merge', source: s.id, target: target.id, fingerprints: fps, entries: moved.map((e) => e.entry_key), lifecycle: { from: before, to: after } };
      addRevision(store, target.id, { dimension: 'identity', source: 'human', actor: input.actor, from: null, to: op, reason: `合并 V-${s.display_no} → V-${target.display_no}：${reason}` });
      addRevision(store, s.id, { dimension: 'identity', source: 'human', actor: input.actor, from: null, to: op, reason: `已合并到 V-${target.display_no}：${reason}` });
    }
  });
}

/** Vulnerabilities merged (directly) into this one. */
export function mergedChildren(store: Store, id: string): string[] {
  return store.all<{ id: string }>(`SELECT id FROM vulnerability WHERE merged_into_id = ? AND status = 'merged'`, id).map((r) => r.id);
}

/**
 * Split A → A + C (entries/fingerprints chosen by the user). C is a
 * new vulnerability (next number) with A's description; the chosen fingerprints and entries move to C.
 * Entries alone on a shared sink fingerprint (same sink, two root causes): C records the shared
 * fingerprint as an inactive `manual` marker and later hits are attributed by entry ownership.
 */
export function splitVulnerability(store: Store, input: { vulnId: string; entryKeys: string[]; fingerprints: string[]; reason: string; actor: string; revision?: number }): { id: string; displayNo: number } {
  const reason = input.reason.trim();
  if (!reason) throw new AppError('VULN_REASON_REQUIRED', 'splitting needs a reason');
  const entryKeys = [...new Set(input.entryKeys)];
  const fps = [...new Set(input.fingerprints)];
  if (!entryKeys.length && !fps.length) throw new AppError('COMMON_VALIDATION', 'choose entries or fingerprints to move');
  let created = { id: '', displayNo: 0 };
  store.tx(() => {
    const a = vuln(store, input.vulnId);
    checkRev(a, input.revision);
    if (a.status !== 'active') throw new AppError('COMMON_VALIDATION', `V-${a.display_no} is not active`);
    const ownFps = store.all<{ fp: string }>('SELECT fp FROM vuln_fingerprint WHERE vulnerability_id = ? AND active = 1', a.id).map((f) => f.fp);
    const ownEntries = store.all<{ entry_key: string }>('SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ?', a.id).map((e) => e.entry_key);
    for (const f of fps) if (!ownFps.includes(f)) throw new AppError('COMMON_VALIDATION', `fingerprint ${f.slice(0, 12)}… is not active on V-${a.display_no}`);
    for (const e of entryKeys) if (!ownEntries.includes(e)) throw new AppError('COMMON_VALIDATION', `entry ${e} is not on V-${a.display_no}`);
    if (fps.length === ownFps.length && fps.length > 0 && entryKeys.length === ownEntries.length) throw new AppError('COMMON_VALIDATION', 'nothing would remain on the original vulnerability');
    if (!fps.length && entryKeys.length === ownEntries.length) throw new AppError('COMMON_VALIDATION', 'keep at least one entry on the original vulnerability');
    const project = store.get<{ next_vuln_no: number }>('SELECT next_vuln_no FROM project WHERE id = ?', a.project_id)!;
    const id = newId('vulnerability');
    store.update('project', { id: a.project_id }, { next_vuln_no: project.next_vuln_no + 1 });
    store.insert('vulnerability', {
      id, project_id: a.project_id, display_no: project.next_vuln_no, repository_id: a.repository_id, module: a.module, category: a.category, cwe: a.cwe,
      title: a.title, severity: a.severity, severity_original: a.severity_original, confidence: a.confidence, sink_symbol: a.sink_symbol, sink_api: a.sink_api,
      root_cause: a.root_cause, confirm_status: a.confirm_status, handling_status: 'open', lifecycle: a.lifecycle, pending_kind: a.pending_kind,
      missing_context: a.missing_context === null ? null : fromJson(a.missing_context, null), sources: [], evidence_complete: a.evidence_complete, detail_ref: a.detail_ref,
      first_seen_audit_id: a.first_seen_audit_id, last_seen_audit_id: a.last_seen_audit_id, last_verified_audit_id: a.last_verified_audit_id,
    });
    for (const r of store.all<Record<string, unknown>>(`SELECT * FROM evidence WHERE owner_kind = 'vulnerability' AND owner_id = ? ORDER BY ord`, a.id)) {
      const { created_at: _c, updated_at: _u, ...rest } = r;
      store.insert('evidence', { ...rest, id: newId('evidence'), owner_id: id });
    }
    for (const fp of fps) {
      store.db.run('UPDATE vuln_fingerprint SET active = 0 WHERE vulnerability_id = ? AND fp = ? AND active = 1', a.id, fp);
      store.insert('vuln_fingerprint', { vulnerability_id: id, project_id: a.project_id, fp, kind: 'manual', since_audit_id: null, active: 1 });
    }
    // Same sink kept by A: remember it on C (inactive marker) so later hits can be attributed by entry.
    const shared = fps.length ? [] : ownFps;
    for (const fp of shared) store.insert('vuln_fingerprint', { vulnerability_id: id, project_id: a.project_id, fp, kind: 'manual', since_audit_id: null, active: 0 });
    for (const e of entryKeys) store.db.run('UPDATE vuln_entry SET vulnerability_id = ? WHERE vulnerability_id = ? AND entry_key = ?', id, a.id, e);
    // "拆分前历史"：C references A's history instead of copying occurrences.
    const op: IdentityOp = { op: 'split', source: a.id, created: id, fingerprints: fps, entries: entryKeys, sharedFingerprints: shared };
    addRevision(store, a.id, { dimension: 'identity', source: 'human', actor: input.actor, from: null, to: op, reason: `拆出 V-${project.next_vuln_no}：${reason}` });
    addRevision(store, id, { dimension: 'identity', source: 'human', actor: input.actor, from: { splitFrom: a.id, history: `V-${a.display_no}` }, to: op, reason: `从 V-${a.display_no} 拆出：${reason}` });
    addRevision(store, id, { dimension: 'lifecycle', source: 'human', actor: input.actor, from: null, to: a.lifecycle, reason: `沿用 V-${a.display_no} 拆分前的跨审计状态` });
    created = { id, displayNo: project.next_vuln_no };
  });
  return created;
}

/** Undo a merge or split while it is still the latest identity change of the vulnerabilities involved. */
export function undoIdentityOp(store: Store, input: { vulnId: string; revisionId: string; reason?: string; actor: string; revision?: number }): void {
  store.tx(() => {
    const r = store.get<{ id: string; vulnerability_id: string; dimension: string; to_value: string | null; seq: number }>('SELECT * FROM revision WHERE id = ?', input.revisionId);
    if (!r || r.vulnerability_id !== input.vulnId || r.dimension !== 'identity') throw new AppError('COMMON_NOT_FOUND', 'no identity change with this id on the vulnerability');
    const op = fromJson<IdentityOp | null>(r.to_value, null);
    if (!op || (op.op !== 'merge' && op.op !== 'split')) throw new AppError('COMMON_VALIDATION', 'only merges and splits can be undone');
    checkRev(vuln(store, input.vulnId), input.revision);
    const involved = op.op === 'merge' ? [op.source, op.target] : [op.source, op.created];
    // Only the latest identity change of every vulnerability involved can be undone (later ones built on it).
    for (const vid of involved) {
      const latest = store.get<{ to_value: string | null }>(`SELECT to_value FROM revision WHERE vulnerability_id = ? AND dimension = 'identity' ORDER BY seq DESC LIMIT 1`, vid);
      const l = fromJson<IdentityOp | null>(latest?.to_value ?? null, null);
      if (!l || JSON.stringify(l) !== JSON.stringify(op)) throw new AppError('AUDIT_INVALID_TRANSITION', 'a later identity change exists; undo that first');
    }
    const reason = input.reason?.trim() || '撤销';
    const undo: IdentityOp = { op: 'undo', of: input.revisionId };
    if (op.op === 'merge') {
      const t = vuln(store, op.target);
      const s = vuln(store, op.source);
      for (const fp of op.fingerprints) {
        store.db.run(`UPDATE vuln_fingerprint SET active = 0 WHERE vulnerability_id = ? AND fp = ? AND kind = 'merged' AND active = 1`, t.id, fp);
        store.db.run('UPDATE vuln_fingerprint SET active = 1 WHERE rowid = (SELECT rowid FROM vuln_fingerprint WHERE vulnerability_id = ? AND fp = ? AND active = 0 ORDER BY created_at DESC LIMIT 1)', s.id, fp);
      }
      for (const e of op.entries) store.db.run('DELETE FROM vuln_entry WHERE vulnerability_id = ? AND entry_key = ?', t.id, e);
      store.update('vulnerability', { id: s.id }, { status: 'active', merged_into_id: null });
      if (t.lifecycle === op.lifecycle.to && op.lifecycle.to !== op.lifecycle.from) store.update('vulnerability', { id: t.id }, { lifecycle: op.lifecycle.from });
      addRevision(store, t.id, { dimension: 'identity', source: 'human', actor: input.actor, from: op, to: undo, reason: `撤销合并 V-${s.display_no}：${reason}` });
      addRevision(store, s.id, { dimension: 'identity', source: 'human', actor: input.actor, from: op, to: undo, reason: `撤销合并到 V-${t.display_no}：${reason}` });
    } else {
      const a = vuln(store, op.source);
      const c = vuln(store, op.created);
      for (const fp of op.fingerprints) {
        store.db.run('UPDATE vuln_fingerprint SET active = 0 WHERE vulnerability_id = ? AND fp = ? AND active = 1', c.id, fp);
        store.db.run('UPDATE vuln_fingerprint SET active = 1 WHERE rowid = (SELECT rowid FROM vuln_fingerprint WHERE vulnerability_id = ? AND fp = ? AND active = 0 ORDER BY created_at DESC LIMIT 1)', a.id, fp);
      }
      store.db.run(`DELETE FROM vuln_fingerprint WHERE vulnerability_id = ? AND active = 0 AND kind = 'manual'`, c.id);
      // Entries return to A; ones A already has again (seen by later audits) are dropped from C.
      store.db.run('UPDATE OR IGNORE vuln_entry SET vulnerability_id = ? WHERE vulnerability_id = ?', a.id, c.id);
      store.db.run('DELETE FROM vuln_entry WHERE vulnerability_id = ?', c.id);
      // C disappears into A; its occurrences since the split stay readable through merged_into_id.
      store.update('vulnerability', { id: c.id }, { status: 'merged', merged_into_id: a.id, suspected_link: 0 });
      addRevision(store, a.id, { dimension: 'identity', source: 'human', actor: input.actor, from: op, to: undo, reason: `撤销拆分 V-${c.display_no}：${reason}` });
      addRevision(store, c.id, { dimension: 'identity', source: 'human', actor: input.actor, from: op, to: undo, reason: `撤销拆分，并回 V-${a.display_no}：${reason}` });
    }
  });
}

/**
 * Attribution of an exact fingerprint hit when the sink was split by entries: the owner
 * whose entries cover the finding's entries; entries owned by nobody → a suspected link for a human.
 */
export function attributeSplitHit(store: Store, projectId: string, fp: string, owner: string, findingEntries: string[]): { vulnId: string; suspected: boolean } {
  const siblings = store.all<{ vulnerability_id: string }>(
    `SELECT vf.vulnerability_id FROM vuln_fingerprint vf JOIN vulnerability v ON v.id = vf.vulnerability_id
     WHERE vf.project_id = ? AND vf.fp = ? AND vf.active = 0 AND vf.kind = 'manual' AND v.status = 'active' AND v.id != ?`, projectId, fp, owner).map((r) => r.vulnerability_id);
  if (!siblings.length || !findingEntries.length) return { vulnId: owner, suspected: false };
  const owners = [owner, ...siblings];
  const entriesOf = new Map(owners.map((id) => [id, new Set(store.all<{ entry_key: string }>('SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ?', id).map((e) => e.entry_key))]));
  const covering = owners.filter((id) => findingEntries.every((e) => entriesOf.get(id)!.has(e)));
  if (covering.length === 1) return { vulnId: covering[0]!, suspected: false };
  const best = [...owners].sort((x, y) => findingEntries.filter((e) => entriesOf.get(y)!.has(e)).length - findingEntries.filter((e) => entriesOf.get(x)!.has(e)).length)[0]!;
  return { vulnId: best, suspected: true };
}

