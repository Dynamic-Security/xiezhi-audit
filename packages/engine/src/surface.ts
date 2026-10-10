// Attack-surface completion: the profile lists entry points and dangerous operations (sinks) the
// index rules did not recognize. Validated ones become index entries and sinks (rule `model.surface`), so they are
// triage candidates, hunt targets and coverage items like rule-found ones; the ledger tells them apart by the rule id.
import { canonicalJson, newId, sha256Hex, VULN_CATEGORIES, type EntryPoint, type IndexSymbol, type Sink, type StructIndex, type SurfaceItem } from '@xiezhi/contracts';
import { coverageTargets } from '@xiezhi/context';
import type { AuditRuntime, RepoInfo } from './runtime.js';
import type { ProfileOutput } from './steps/profile.js';
import { validateCodeRef } from './steps/hunt.js';
import { buildCandidates, makeBatches, rankCandidates, scopePredicate, type TriageOutput } from './steps/triage.js';
import { P } from '@xiezhi/knowledge';

export const SURFACE_RULE = 'model.surface';

/** On in full audits unless `tools.surfaceDiscovery` is false. */
export const surfaceOn = (rt: AuditRuntime): boolean => rt.strategy.tools.surfaceDiscovery !== false && rt.audit.scene === 'full';

/** Submit-time checks: the location is in this repository, exists and was read; a sink names its category and call. */
export function validateSurface(rt: AuditRuntime, repo: RepoInfo, items: SurfaceItem[] | undefined): string[] {
  const issues: string[] = [];
  (items ?? []).forEach((it, i) => {
    if (it.location.repo && it.location.repo !== repo.name) issues.push(P('feedback.surface.other_repo', { i, repo: repo.name }));
    else issues.push(...validateCodeRef(rt, { ...it.location, repo: repo.name }, `surface[${i}].location`, true));
    if (it.kind === 'sink' && (!it.category || !it.api)) issues.push(P('feedback.surface.sink_fields', { i, categories: VULN_CATEGORIES.join(' / ') }));
  });
  return issues.slice(0, 30);
}

/** The smallest function of the index containing the line: the range to read, and the sink's symbol. */
function enclosing(idx: StructIndex | undefined, path: string, line: number): IndexSymbol | undefined {
  return (idx?.symbols ?? []).filter((s) => (s.kind === 'method' || s.kind === 'func') && s.path === path && s.range.startLine <= line && line <= s.range.endLine)
    .sort((a, b) => (a.range.endLine - a.range.startLine) - (b.range.endLine - b.range.startLine))[0];
}

const overlaps = (a: { path: string; range: { startLine: number; endLine: number } }, path: string, start: number, end: number) =>
  a.path === path && a.range.startLine <= end && start <= a.range.endLine;

const surfaceId = (repo: string, path: string, line: number, key: string) => `surf-${sha256Hex(canonicalJson([repo, path, line, key])).slice(0, 16)}`;

/**
 * The entry points and sinks a profile added, as index items. Entries that overlap an index entry, and sinks that
 * overlap an index sink of the same category, are dropped; so are duplicates within the list.
 */
export function surfaceItems(out: ProfileOutput, repoName: string, idx: StructIndex | undefined): { entries: EntryPoint[]; sinks: Sink[] } {
  const seen = new Set<string>();
  const entries: EntryPoint[] = [];
  const sinks: Sink[] = [];
  for (const it of out.profile.surface ?? []) {
    const { path, startLine, endLine } = it.location;
    const fn = enclosing(idx, path, startLine);
    if (it.kind === 'entry') {
      if ((idx?.entrypoints ?? []).some((e) => overlaps(e, path, startLine, endLine))) continue;
      const key = `model:${(it.access ?? it.name).trim()}`;
      if (seen.has(`e|${key}`)) continue;
      seen.add(`e|${key}`);
      entries.push({
        entryId: surfaceId(repoName, path, startLine, key), entryKey: key, kind: 'internal', framework: 'model', handler: it.name, path,
        range: fn ? { ...fn.range } : { startLine, endLine: Math.max(startLine, endLine) }, middlewares: [], authSignals: [], ruleId: SURFACE_RULE,
      });
    } else {
      const category = it.category ?? 'other';
      if ((idx?.sinks ?? []).some((s) => s.category === category && overlaps(s, path, startLine, endLine))) continue;
      const key = `${category}|${path}|${startLine}`;
      if (seen.has(`s|${key}`)) continue;
      seen.add(`s|${key}`);
      sinks.push({
        sinkId: surfaceId(repoName, path, startLine, key), category, symbolId: fn?.symbolId ?? null, path,
        range: { startLine, endLine: Math.max(startLine, endLine) }, api: (it.api ?? it.name).slice(0, 300), ruleId: SURFACE_RULE,
      });
    }
  }
  return { entries, sinks };
}

/**
 * Merge the entry points and sinks of this audit's profiles into the runtime indexes and the coverage ledger.
 * Idempotent: runs after every `prepare` (also on resume, where the index is loaded again without them). Returns the
 * number of items added.
 */
export function applySurface(rt: AuditRuntime): number {
  if (!surfaceOn(rt)) return 0;
  const inScope = scopePredicate(rt.strategy.scope.include, rt.strategy.scope.exclude);
  let entriesAdded = 0, sinksAdded = 0;
  for (const repo of rt.targets) {
    const row = rt.store.get<{ output_ref: string }>(
      `SELECT output_ref FROM step WHERE audit_id = ? AND kind = 'profile' AND status IN ('succeeded','skipped') AND output_ref IS NOT NULL
       AND json_extract(input, '$.repo') = ? ORDER BY seq DESC LIMIT 1`, rt.auditId, repo.name);
    const idx = rt.indexes.get(repo.name);
    if (!row || !idx) continue;
    const out = rt.store.artifacts.getJson<ProfileOutput>(row.output_ref);
    const found = surfaceItems(out, repo.name, idx);
    const entries = found.entries.filter((e) => inScope(e.path) && !idx.entrypoints.some((x) => x.entryId === e.entryId));
    const sinks = found.sinks.filter((s) => inScope(s.path) && !idx.sinks.some((x) => x.sinkId === s.sinkId));
    if (!entries.length && !sinks.length) continue;
    const merged: StructIndex = { ...idx, entrypoints: [...idx.entrypoints, ...entries], sinks: [...idx.sinks, ...sinks] };
    rt.indexes.set(repo.name, merged);
    const ids = new Set([...entries.map((e) => e.entryId), ...sinks.map((s) => s.sinkId)]);
    rt.store.tx(() => {
      for (const t of coverageTargets(merged, inScope)) {
        if (!ids.has(t.targetId)) continue;
        rt.store.db.run(
          `INSERT OR IGNORE INTO coverage_item(id, audit_id, repository_id, snapshot_id, kind, item_key, target_id, category, rule_id, path, start_line, end_line, status, detail, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          newId('coverage'), rt.auditId, repo.id, repo.snapshotId, t.kind, t.itemKey, t.targetId, t.category ?? null, t.ruleId, t.path,
          t.readRange.startLine, t.readRange.endLine, 'uncovered', JSON.stringify(t.detail), Date.now(), Date.now(),
        );
      }
    });
    entriesAdded += entries.length;
    sinksAdded += sinks.length;
  }
  if (entriesAdded || sinksAdded) rt.event('judgement.made', { kind: 'surface_added', entries: entriesAdded, sinks: sinksAdded });
  return entriesAdded + sinksAdded;
}

/** At most this many profile-added items are hunted (they are not ranked by the triage model). */
export const MAX_SURFACE_CANDIDATES = 100;

/**
 * The triage output with the profile-added items (already merged into the index by `applySurface`) appended as
 * candidates and batches of their own, in the heuristic order. Deterministic, so a resumed run gets the same batches.
 */
export function withSurface(rt: AuditRuntime, triage: TriageOutput): TriageOutput {
  if (!surfaceOn(rt)) return triage;
  const known = new Set(triage.candidates.map((c) => c.id));
  const added = rankCandidates(buildCandidates(rt).filter((c) => !known.has(c.id) && (
    rt.indexes.get(c.repo)?.entrypoints.some((e) => e.entryId === c.id && e.ruleId === SURFACE_RULE)
    || rt.indexes.get(c.repo)?.sinks.some((x) => x.sinkId === c.id && x.ruleId === SURFACE_RULE)
  ))).slice(0, MAX_SURFACE_CANDIDATES);
  if (!added.length) return triage;
  return {
    ...triage,
    candidates: [...triage.candidates, ...added],
    selected: [...triage.selected, ...added.map((c) => c.id)],
    batches: [...triage.batches, ...makeBatches(added)],
  };
}
