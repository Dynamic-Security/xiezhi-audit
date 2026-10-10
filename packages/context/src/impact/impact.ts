// Incremental impact analysis: base + head snapshots → changed files and hunks →
// changed symbols → reverse-call BFS → affected entrypoints and sinks, with an honest mode
// (precise / heuristic / full_scan) and the reasons for any fallback.
import type {
  CallEdge, DiffHunk, EdgeConfidence, ImpactFallbackReason, ImpactMode, ImpactParams, ImpactSet, SnapshotManifest, StructIndex,
} from '@xiezhi/contracts';
import { diffManifests, lineHunks } from './diff.js';
import { diffSymbols, type TextSource } from './symbols.js';

export interface ImpactSide {
  manifest: SnapshotManifest;
  src: TextSource;
  /** Absent when AST is disabled or the index could not be built. */
  index?: StructIndex;
}

export interface ImpactInput {
  base: ImpactSide;
  head: ImpactSide;
  params: ImpactParams;
  ast: boolean;
}

/** Parse gaps in more than this share of changed files make the result a full scan. */
const MAX_GAP_RATIO = 0.2;
const RANK: Record<EdgeConfidence, number> = { resolved: 2, heuristic: 1, unresolved: 0 };
/** Closed-set strings from the index (typed as string by the schema). */
const rank = (c: string) => RANK[c as EdgeConfidence] ?? 0;

const overlaps = (a: { startLine: number; endLine: number }, start: number, count: number) =>
  count === 0 ? a.startLine <= start + 1 && a.endLine >= start : a.startLine <= start + count - 1 && a.endLine >= start;

export function computeImpact(input: ImpactInput): ImpactSet {
  const { base, head, params } = input;
  const changedFiles = diffManifests(base.manifest, head.manifest);
  const indexable = new Set(head.manifest.files.filter((f) => f.indexable).map((f) => f.path));
  const hunks: DiffHunk[] = [];
  for (const p of changedFiles.modified) {
    try {
      hunks.push(...lineHunks(p, base.src.lines(p), head.src.lines(p)));
    } catch { /* unreadable file: listed as modified without hunks */ }
  }
  const changedPaths = [...changedFiles.added, ...changedFiles.modified, ...changedFiles.renamed.map((r) => r.to)];
  const changedIndexable = changedPaths.filter((p) => indexable.has(p));
  const stats = { indexableFiles: indexable.size, changedIndexableFiles: changedIndexable.length, unresolvedCallers: 0, resolvedCallers: 0 };
  const empty = { affectedSymbols: [], affectedEntrypoints: [], affectedSinks: [] };

  if (!input.ast) {
    // grep/read only — the diff is the whole input; callers are found by the Agent with grep.
    return { mode: 'heuristic', fallbackReasons: ['ast_disabled'], changedFiles, hunks, changedSymbols: [], renames: [], ...empty, stats };
  }
  if (!base.index || !head.index) {
    return { mode: 'full_scan', fallbackReasons: ['no_baseline_index'], changedFiles, hunks, changedSymbols: [], renames: [], ...empty, stats };
  }

  const symDiff = diffSymbols(base.index, base.src, head.index, head.src);
  const reasons: ImpactFallbackReason[] = [];
  if (indexable.size > 0 && changedIndexable.length / indexable.size > params.maxChangedRatio) reasons.push('too_many_changes');
  const gapPaths = new Set(head.index.gaps.map((g) => g.path));
  const gapped = changedIndexable.filter((p) => gapPaths.has(p));
  const gapRatio = changedIndexable.length ? gapped.length / changedIndexable.length : 0;
  if (gapRatio > MAX_GAP_RATIO) reasons.push('parse_gap_in_changed_files');

  // Seeds: changed/added/renamed functions, plus head functions overlapping a changed hunk (catches
  // edits the symbol hash comparison cannot attribute, e.g. in files whose functions were renamed).
  const headFns = head.index.symbols.filter((s) => s.kind === 'method' || s.kind === 'func');
  const seeds = new Set(symDiff.changes.filter((c) => c.change !== 'deleted').map((c) => c.symbolId));
  for (const h of hunks) for (const s of headFns) if (s.path === h.path && overlaps(s.range, h.headStart, h.headCount)) seeds.add(s.symbolId);
  for (const p of changedFiles.added) for (const s of headFns) if (s.path === p) seeds.add(s.symbolId);

  // Callers we could not resolve by edge but that call a changed name: when they outnumber resolved
  // callers the call graph cannot be trusted for this change.
  const byId = new Map(head.index.symbols.map((s) => [s.symbolId, s]));
  const seedNames = new Set([...seeds].map((id) => byId.get(id)?.name).filter((n): n is string => !!n));
  const callersOf = new Map<string, CallEdge[]>();
  for (const e of head.index.callEdges) {
    if (e.to) callersOf.set(e.to, [...(callersOf.get(e.to) ?? []), e]);
    else if (seedNames.has(e.calleeText.split(/[.:]/).pop() ?? '')) stats.unresolvedCallers++;
  }
  for (const id of seeds) stats.resolvedCallers += (callersOf.get(id) ?? []).length;
  if (stats.unresolvedCallers > stats.resolvedCallers && stats.unresolvedCallers > 0) reasons.push('unresolved_edges_dominant');

  // Reverse BFS over callers.
  const min = rank(params.minConfidence);
  const dist = new Map<string, { distance: number; via: EdgeConfidence }>();
  let queue = [...seeds];
  for (const id of queue) dist.set(id, { distance: 0, via: 'resolved' });
  let usedHeuristic = false;
  for (let depth = 1; depth <= params.maxDepth && queue.length; depth++) {
    const next: string[] = [];
    for (const id of queue) {
      for (const e of callersOf.get(id) ?? []) {
        if (rank(e.confidence) < min || dist.has(e.from)) continue;
        if (e.confidence !== 'resolved') usedHeuristic = true;
        const via: EdgeConfidence = rank(e.confidence) < rank(dist.get(id)!.via) ? (e.confidence as EdgeConfidence) : dist.get(id)!.via;
        dist.set(e.from, { distance: depth, via });
        next.push(e.from);
      }
    }
    queue = next;
  }
  const affected = new Set(dist.keys());
  // An entry whose middleware / auth set changed (e.g. `api.Use(AuthRequired())` removed in the router
  // file, or a global auth configuration edited) is affected even when neither its handler nor its range changed.
  const guardOf = (e: { middlewares: string[]; authSignals: string[] }) => JSON.stringify([[...e.middlewares].sort(), [...e.authSignals].sort()]);
  const baseGuards = new Map<string, Set<string>>();
  for (const e of base.index.entrypoints) baseGuards.set(e.entryKey, (baseGuards.get(e.entryKey) ?? new Set<string>()).add(guardOf(e)));
  const changedSet = new Set(changedPaths);
  const affectedEntrypoints = head.index.entrypoints
    .filter((e) => affected.has(e.handler) || !baseGuards.get(e.entryKey)?.has(guardOf(e))
      || (changedSet.has(e.path) && hunks.some((h) => h.path === e.path && overlaps(e.range, h.headStart, h.headCount))))
    .map((e) => e.entryId).sort();
  const affectedSinks = head.index.sinks.filter((s) => (s.symbolId && affected.has(s.symbolId)) || changedFiles.added.includes(s.path)).map((s) => s.sinkId).sort();

  const fullScan = reasons.includes('too_many_changes') || reasons.includes('parse_gap_in_changed_files') || reasons.includes('unresolved_edges_dominant');
  const mode: ImpactMode = fullScan ? 'full_scan' : usedHeuristic || gapped.length > 0 ? 'heuristic' : 'precise';
  return {
    mode, fallbackReasons: reasons, changedFiles, hunks, changedSymbols: symDiff.changes, renames: symDiff.renames,
    affectedSymbols: [...dist].map(([symbolId, d]) => ({ symbolId, distance: d.distance, viaEdgeConfidence: d.via })).sort((a, b) => a.distance - b.distance || a.symbolId.localeCompare(b.symbolId)),
    affectedEntrypoints, affectedSinks, stats,
  };
}
