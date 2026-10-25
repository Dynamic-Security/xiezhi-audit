// Coverage persistence: items are created from the index at pipeline start;
// "concluded" requires the target range to be read ≥ 60% AND a submitted conclusion. The model cannot
// self-certify coverage: a conclusion without reading is recorded but not counted.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { newId, type CoverageItemDetail, type EntryPoint, type IndexSymbol, type Sink, type StructIndex } from '@xiezhi/contracts';
import { fromJson } from '@xiezhi/store';
import { coverageTargets, entryDetail, overlapRatio, READ_THRESHOLD, sinkDetail } from '@xiezhi/context';
import type { AuditRuntime } from './runtime.js';
import { scopePredicate } from './steps/triage.js';
import { hypothesisAuditIds } from './threat.js';

interface ItemRow { id: string; kind: 'entry' | 'sink'; target_id: string; repository_id: string; path: string; start_line: number; end_line: number; status: string; verdict: string | null; finding_id?: string | null }

/** `only`: restrict items to these target ids (incremental impact set). */
export function ensureCoverageItems(rt: AuditRuntime, only?: ReadonlySet<string>): number {
  const store = rt.store;
  if (store.get('SELECT 1 FROM coverage_item WHERE audit_id = ? LIMIT 1', rt.auditId)) return 0;
  const inScope = scopePredicate(rt.strategy.scope.include, rt.strategy.scope.exclude);
  let n = 0;
  store.tx(() => {
    // coverage is about the target repositories only (related ones are indexed for tracing, not audited).
    for (const repo of rt.targets) {
      const idx = rt.indexes.get(repo.name);
      if (!idx) continue;
      for (const t of coverageTargets(idx, inScope)) {
        if (only && !only.has(t.targetId)) continue;
        store.db.run(
          `INSERT OR IGNORE INTO coverage_item(id, audit_id, repository_id, snapshot_id, kind, item_key, target_id, category, rule_id, path, start_line, end_line, status, detail, created_at, updated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
          newId('coverage'), rt.auditId, repo.id, repo.snapshotId, t.kind, t.itemKey, t.targetId, t.category ?? null, t.ruleId, t.path,
          t.readRange.startLine, t.readRange.endLine, 'uncovered', JSON.stringify(t.detail), Date.now(), Date.now(),
        );
        n++;
      }
    }
  });
  return n;
}

/**
 * Incremental: only the impact set is in scope for coverage; outside it everything is not_covered.
 * A full-scan fallback covers its repository like a full audit (per target); undefined = everything.
 */
export function incrementalCoverageTargets(rt: AuditRuntime): Set<string> | undefined {
  const impacts = rt.impacts();
  if (rt.targets.every((t) => impacts.get(t.name)?.mode === 'full_scan')) return undefined;
  const inScope = scopePredicate(rt.strategy.scope.include, rt.strategy.scope.exclude);
  const out = new Set<string>();
  for (const t of rt.targets) {
    const impact = impacts.get(t.name);
    if (!impact) continue;
    const idx = rt.indexes.get(t.name);
    if (impact.mode !== 'full_scan') for (const id of [...impact.affectedEntrypoints, ...impact.affectedSinks]) out.add(id);
    else if (idx) for (const c of coverageTargets(idx, inScope)) out.add(c.targetId);
  }
  return out;
}

function readEnough(rt: AuditRuntime, item: ItemRow): boolean {
  const repo = rt.repos.find((r) => r.id === item.repository_id);
  if (!repo) return false;
  return overlapRatio(rt.readRanges(repo.name, item.path), { startLine: item.start_line, endLine: item.end_line }) >= READ_THRESHOLD;
}

export function markConcluded(rt: AuditRuntime, kind: 'entry' | 'sink', targetId: string, stepId: string, verdict: string, findingId?: string): void {
  const item = rt.store.get<ItemRow>('SELECT * FROM coverage_item WHERE audit_id = ? AND kind = ? AND target_id = ?', rt.auditId, kind, targetId);
  if (!item) return;
  // A unit a finding concluded keeps that conclusion. A later ruled_out (“already submitted as F1”) replaced
  // it, the recheck then reopened the unit as a wrong exclusion, and the finding no longer covered it.
  if (item.finding_id && item.verdict === 'finding' && verdict !== 'finding') return;
  if (readEnough(rt, item)) {
    rt.store.update('coverage_item', { id: item.id }, { status: 'concluded', verdict, concluded_by_step: stepId, ...(findingId ? { finding_id: findingId } : {}) });
  } else {
    rt.store.update('coverage_item', { id: item.id }, { verdict, ...(findingId ? { finding_id: findingId } : {}) });
    rt.event('coverage.updated', { warning: 'concluded_without_reading', kind, target_id: targetId }, stepId);
  }
}

export interface CoverageTotals { entry: { total: number; reviewed: number }; sink: { total: number; reviewed: number } }

/** Final pass: re-check conclusions against all reads; mark read-only items. */
export function finalizeCoverage(rt: AuditRuntime, stepId: string): CoverageTotals {
  const store = rt.store;
  const items = store.all<ItemRow>('SELECT * FROM coverage_item WHERE audit_id = ?', rt.auditId);
  store.tx(() => {
    for (const it of items) {
      if (it.status === 'concluded' || it.status === 'excluded') continue;
      const read = readEnough(rt, it);
      const status = read && it.verdict ? 'concluded' : read ? 'read' : 'uncovered';
      if (status !== it.status) store.update('coverage_item', { id: it.id }, { status, ...(status === 'concluded' ? { concluded_by_step: stepId } : {}) });
    }
  });
  const count = (kind: string, status?: string) => store.get<{ n: number }>(
    `SELECT COUNT(*) AS n FROM coverage_item WHERE audit_id = ? AND kind = ? AND status != 'excluded'${status ? ' AND status = ?' : ''}`,
    ...(status ? [rt.auditId, kind, status] : [rt.auditId, kind]))!.n;
  const totals = {
    entry: { total: count('entry'), reviewed: count('entry', 'concluded') },
    sink: { total: count('sink'), reviewed: count('sink', 'concluded') },
  };
  rt.event('coverage.updated', { entry: totals.entry, sink: totals.sink }, stepId);
  return totals;
}

/**
 * Why an item has no conclusion, first match wins: a verdict without enough reading; a batch
 * listed it and got no verdict even after being asked (`candidate.settled` = unreviewed); read but no verdict; not
 * selected by triage (over `maxCandidates` or below `minTriageScore`); never handed to a session.
 */
export const UNCONCLUDED_REASONS = ['concluded_without_reading', 'assigned_no_verdict', 'read_no_verdict', 'not_selected', 'not_assigned'] as const;
export type UnconcludedReason = (typeof UNCONCLUDED_REASONS)[number];
export interface UnconcludedSummary {
  total: number;
  byReason: Record<UnconcludedReason, number>;
  /** At most UNCONCLUDED_LISTED items, in reason order. */
  items: { kind: string; targetId: string; status: string; reason: UnconcludedReason }[];
}
const UNCONCLUDED_LISTED = 500;

/** every item without a conclusion and why — written at the gate whether or not coverage targets are set. */
export function unconcludedSummary(rt: AuditRuntime, overflow: string[]): UnconcludedSummary {
  const store = rt.store;
  const open = store.all<{ kind: string; target_id: string; status: string; verdict: string | null }>(
    `SELECT kind, target_id, status, verdict FROM coverage_item WHERE audit_id = ? AND status NOT IN ('concluded', 'excluded') ORDER BY kind, target_id`, rt.auditId);
  const unreviewed = new Set(store.listEvents(rt.auditId, 0, ['candidate.settled']).filter((e) => e.payload.status === 'unreviewed').map((e) => String(e.payload.candidate)));
  const notSelected = new Set(overflow);
  const reasonOf = (i: (typeof open)[number]): UnconcludedReason => (i.verdict ? 'concluded_without_reading'
    : unreviewed.has(i.target_id) ? 'assigned_no_verdict' : i.status === 'read' ? 'read_no_verdict' : notSelected.has(i.target_id) ? 'not_selected' : 'not_assigned');
  const items = open.map((i) => ({ kind: i.kind, targetId: i.target_id, status: i.status, reason: reasonOf(i) }))
    .sort((a, b) => UNCONCLUDED_REASONS.indexOf(a.reason) - UNCONCLUDED_REASONS.indexOf(b.reason));
  const byReason = Object.fromEntries(UNCONCLUDED_REASONS.map((r) => [r, items.filter((i) => i.reason === r).length])) as Record<UnconcludedReason, number>;
  return { total: items.length, byReason, items: items.slice(0, UNCONCLUDED_LISTED) };
}

// ---- reporting -----------------------------------------------------------------------

export interface RepoCoverage {
  repoId: string; repo: string;
  /** `fromModel`: items the profile added outside the index rules, included in `total`. */
  entry: { total: number; reviewed: number; readOnly: number; fromModel?: number };
  sink: { total: number; reviewed: number; readOnly: number; fromModel?: number };
  reading: { totalLines: number; readLines: number };
  /** Lines of indexable source in the snapshot (the reading denominator for the whole repository). */
  sourceLines: number;
  byModule: { module: string; totalLines: number; readLines: number }[];
  indexStatus: string | null;
  gaps: { path: string; reason: string; detail: string }[];
  /** threat-model risk hypotheses of this repository (the audit and its supplements). */
  hypothesis: HypothesisCoverage;
}

export interface HypothesisCoverage { total: number; reviewed: number; confirmed: number; refuted: number; open: number; proposed: number }

/** The third coverage dimension: verified (or reviewer-decided) threat-model hypotheses. */
export function hypothesisCoverage(store: import('@xiezhi/store').Store, auditIds: string[], repoId: string): HypothesisCoverage {
  const rows = store.all<{ status: string; n: number }>(
    `SELECT status, COUNT(*) AS n FROM hypothesis WHERE origin = 'threat_model' AND repository_id = ? AND audit_id IN (${auditIds.map(() => '?').join(',')}) GROUP BY status`, repoId, ...auditIds);
  const n = (st: string) => rows.find((r) => r.status === st)?.n ?? 0;
  const total = rows.reduce((a, r) => a + r.n, 0);
  // A converted / dismissed hypothesis was open (or set aside while proposed) and then decided by a reviewer.
  return { total, reviewed: total - n('proposed'), confirmed: n('confirmed') + n('converted'), refuted: n('refuted') + n('dismissed'), open: n('open'), proposed: n('proposed') };
}

/**
 * The module a file belongs to (`reading.byModule`): the Maven module when the repository
 * declares modules, otherwise the source package directory (Java / Kotlin below src/main/java|kotlin, other languages
 * their directory).
 */
export function moduleOf(path: string, mavenModules: string[]): string {
  const first = path.split('/')[0]!;
  if (mavenModules.includes(first)) return first;
  const java = /(?:^|\/)src\/main\/(?:java|kotlin)\/(.+)\/[^/]+$/.exec(path);
  if (java) return java[1]!.replace(/\//g, '.');
  const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '.';
  return dir;
}

export function auditCoverage(store: import('@xiezhi/store').Store, auditId: string): RepoCoverage[] {
  const hypAudits = hypothesisAuditIds(store, auditId);
  const repos = store.all<{ id: string; name: string; modules: string; manifest_ref: string | null }>(
    `SELECT r.id, r.name, r.modules, s.manifest_ref FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id LEFT JOIN snapshot s ON s.id = ar.snapshot_id
     WHERE ar.audit_id = ? ORDER BY r.name`, auditId);
  const indexOut = new Map(store.all<{ output_ref: string }>(`SELECT output_ref FROM step WHERE audit_id = ? AND kind = 'index' AND status = 'succeeded' AND output_ref IS NOT NULL`, auditId)
    .map((r) => store.artifacts.getJson<{ repo: string; status: string; gaps?: { path: string; reason: string; detail: string }[] }>(r.output_ref)).map((o) => [o.repo, o]));
  return repos.map((r) => {
    const items = store.all<{ kind: string; status: string; rule_id: string | null }>('SELECT kind, status, rule_id FROM coverage_item WHERE audit_id = ? AND repository_id = ?', auditId, r.id);
    const fromModel = (k: string) => items.filter((i) => i.kind === k && i.status !== 'excluded' && i.rule_id === 'model.surface').length;
    const withModel = <T extends object>(k: string, x: T) => (fromModel(k) ? { ...x, fromModel: fromModel(k) } : x);
    const sum = (k: string) => ({
      total: items.filter((i) => i.kind === k && i.status !== 'excluded').length,
      reviewed: items.filter((i) => i.kind === k && i.status === 'concluded').length,
      readOnly: items.filter((i) => i.kind === k && i.status === 'read').length,
    });
    const reads = store.all<{ path: string; lines_read: number; file_lines: number }>('SELECT path, lines_read, file_lines FROM read_coverage WHERE audit_id = ? AND repository_id = ?', auditId, r.id);
    const readBy = new Map(reads.map((x) => [x.path, x.lines_read]));
    const modules = fromJson<string[]>(r.modules, []);
    const mod = new Map<string, { totalLines: number; readLines: number }>();
    let sourceLines = 0;
    const manifest = r.manifest_ref ? store.artifacts.getJson<import('@xiezhi/contracts').SnapshotManifest>(r.manifest_ref) : null;
    for (const f of manifest?.files ?? []) {
      if (!f.indexable) continue;
      sourceLines += f.lines;
      const m = moduleOf(f.path, modules);
      const e = mod.get(m) ?? { totalLines: 0, readLines: 0 };
      e.totalLines += f.lines;
      e.readLines += Math.min(f.lines, readBy.get(f.path) ?? 0);
      mod.set(m, e);
    }
    const idx = indexOut.get(r.name);
    return {
      repoId: r.id, repo: r.name, entry: withModel('entry', sum('entry')), sink: withModel('sink', sum('sink')),
      reading: { totalLines: reads.reduce((a, x) => a + x.file_lines, 0), readLines: reads.reduce((a, x) => a + x.lines_read, 0) },
      sourceLines,
      byModule: [...mod.entries()].map(([module, v]) => ({ module, ...v })).sort((a, b) => b.totalLines - a.totalLines).slice(0, 100),
      indexStatus: idx?.status ?? null, gaps: (idx?.gaps ?? []).slice(0, 50),
      hypothesis: hypothesisCoverage(store, hypAudits, r.id),
    };
  });
}

/**
 * A finished backfill (“一键补审”) merges into the audit it was started from: targets it
 * concluded count as concluded there too, with the backfill named as the source.
 */
export function mergeBackfill(rt: AuditRuntime, stepId: string): number {
  // A logic-review supplement (追加执行) merges its concluded entries back the same way.
  const scope = fromJson<{ backfill?: { auditId: string }; supplement?: { auditId: string; kind: string } }>(rt.audit.scope, {});
  const bf = scope.backfill ?? (scope.supplement?.kind === 'logic_review' ? scope.supplement : undefined);
  if (!bf) return 0;
  const store = rt.store;
  const done = store.all<{ kind: string; target_id: string; verdict: string | null; finding_id: string | null }>(
    `SELECT kind, target_id, verdict, finding_id FROM coverage_item WHERE audit_id = ? AND status = 'concluded'`, rt.auditId);
  let merged = 0;
  store.tx(() => {
    for (const d of done) {
      merged += store.db.run(
        `UPDATE coverage_item SET status = 'concluded', verdict = ?, concluded_by_step = ?, finding_id = COALESCE(?, finding_id), updated_at = ?
         WHERE audit_id = ? AND kind = ? AND target_id = ? AND status NOT IN ('concluded', 'excluded')`,
        `${scope.backfill ? '补审' : '追加逻辑审查'} ${rt.auditId}：${d.verdict ?? ''}`.slice(0, 500), stepId, d.finding_id, Date.now(), bf.auditId, d.kind, d.target_id).changes;
    }
    if (merged) store.appendEvent(bf.auditId, 'coverage.updated', { backfill: rt.auditId, merged });
  });
  return merged;
}

// ---- item detail -------------------------------------------------------------------------------------------

type DetailMaps = { entries: Map<string, EntryPoint>; sinks: Map<string, Sink>; symbols: Map<string, IndexSymbol> };
/** Structure indexes read for items created before details were stored with them, by `rootHash|repo` (a few, the latest used). */
const indexCache = new Map<string, DetailMaps | null>();

/** The cached structure index of a snapshot (`<indexes>/<rootHash>/<cacheKey>/index.json`), or null. */
function cachedIndex(indexesDir: string, rootHash: string, repo: string): DetailMaps | null {
  const key = `${rootHash}|${repo}`;
  if (indexCache.has(key)) return indexCache.get(key)!;
  let maps: DetailMaps | null = null;
  const dir = join(indexesDir, rootHash);
  for (const k of existsSync(dir) ? readdirSync(dir) : []) {
    const file = join(dir, k, 'index.json');
    if (!existsSync(file)) continue;
    try {
      const idx = JSON.parse(readFileSync(file, 'utf8')) as StructIndex;
      if (idx.repo !== repo) continue;
      maps = {
        entries: new Map(idx.entrypoints.map((e) => [e.entryId, e])), sinks: new Map(idx.sinks.map((x) => [x.sinkId, x])),
        symbols: new Map(idx.symbols.map((x) => [x.symbolId, x])),
      };
      break;
    } catch { /* a damaged cache file: try the next one */ }
  }
  indexCache.set(key, maps);
  while (indexCache.size > 4) indexCache.delete(indexCache.keys().next().value!);
  return maps;
}

/** What the target id itself says: `repo:METHOD /route` for an entry, `repo:path#L<line>:<col>:<category>` for a sink. */
function detailFromId(kind: string, targetId: string, repo: string): CoverageItemDetail | null {
  const id = targetId.startsWith(`${repo}:`) ? targetId.slice(repo.length + 1) : targetId;
  if (kind === 'sink') {
    const m = /#L(\d+):(\d+):/.exec(id);
    return m ? { type: 'sink', api: '', line: Number(m[1]), column: Number(m[2]), taintHint: null, function: null } : null;
  }
  const key = id.replace(/#\d+$/, '');
  const base = { type: 'entry' as const, framework: '', method: null, handler: null, line: 0, middlewares: [], auth: [] };
  if (key.startsWith('rpc:')) {
    const svc = key.slice(4);
    return { ...base, entryKind: 'rpc', protocol: /^(graphql|signalr|thrift|dubbo):/.exec(svc)?.[1] ?? 'grpc', route: svc.replace(/^(graphql|signalr|thrift|dubbo):/, '') };
  }
  // Channel keys: ws: / socketio: / stomp: (socket), mq:<broker>: (message), cron: (schedule), cli: (command).
  const ch = /^(ws|socketio|stomp|mq|cron|cli):(.*)$/.exec(key);
  if (ch) {
    const [, p, rest] = ch as unknown as [string, string, string];
    const kind = p === 'mq' ? 'message' : p === 'cron' ? 'schedule' : p === 'cli' ? 'cli' : 'socket';
    const broker = p === 'mq' ? /^([^:]+):(.*)$/.exec(rest) : null;
    return { ...base, entryKind: kind, protocol: broker ? broker[1]! : p === 'ws' ? 'websocket' : p, route: broker ? broker[2]! : rest };
  }
  const m = /^([A-Z]+) (\S.*)$/.exec(key);
  return m ? { ...base, entryKind: 'http', protocol: 'http', method: m[1] === 'ANY' ? null : m[1]!, route: m[2]! } : null;
}

/**
 * The detail of each coverage item: stored with the item; for earlier items from the cached
 * structure index of the snapshot, else what the target id says.
 */
export function coverageItemDetail(indexesDir: string, item: { kind: string; target_id: string; repo: string; root_hash: string | null; detail: string | null }): CoverageItemDetail | null {
  const stored = fromJson<CoverageItemDetail | null>(item.detail, null);
  if (stored) return stored;
  const maps = item.root_hash ? cachedIndex(indexesDir, item.root_hash, item.repo) : null;
  if (maps) {
    const e = item.kind === 'entry' ? maps.entries.get(item.target_id) : undefined;
    if (e) return entryDetail(e, maps.symbols);
    const s = item.kind === 'sink' ? maps.sinks.get(item.target_id) : undefined;
    if (s) return sinkDetail(s, maps.symbols);
  }
  return detailFromId(item.kind, item.target_id, item.repo);
}
