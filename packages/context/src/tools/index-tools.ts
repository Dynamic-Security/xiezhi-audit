// Structure tools over the tree-sitter index: entrypoints, dangerous_sinks,
// symbol_lookup, find_refs, callgraph. Oversized results are offloaded like other tools.
import type { CallEdge, EntryPoint, IndexSymbol, Sink, StructIndex } from '@xiezhi/contracts';
import { OUTPUT_INLINE_LIMIT, ToolInputError, type Offloaded, type ToolContext } from './tools.js';

export type IndexMap = ReadonlyMap<string, StructIndex>;

function indexes(idx: IndexMap, repo?: string): StructIndex[] {
  if (repo) {
    const i = idx.get(repo);
    if (!i) throw new ToolInputError(`no structural index for repo "${repo}"`);
    return [i];
  }
  return [...idx.values()];
}

function limitList<T>(ctx: ToolContext, items: T[], max: number, render: (t: T) => string): { items: T[]; total: number; truncated: boolean; offloaded?: Offloaded } {
  const total = items.length;
  if (total <= max && Buffer.byteLength(JSON.stringify(items)) <= OUTPUT_INLINE_LIMIT) return { items, total, truncated: false };
  const full = items.map(render).join('\n');
  const artifactId = ctx.artifacts.put(full, 'text/plain');
  ctx.auditArtifacts.add(artifactId);
  return {
    items: items.slice(0, Math.min(max, 50)), total, truncated: true,
    offloaded: { preview: full.slice(0, 8192), artifactId, totalItems: total, totalBytes: Buffer.byteLength(full), hint: 'Use read_artifact to page, or narrow with pathPrefix/category.' },
  };
}

/**
 * When a filter value matches nothing, names the values the index does have: a model that guessed a name
 * (`sql` for `sqli`, `spring` for `spring-mvc`) would otherwise read the empty list as “none in this repository”.
 */
function unmatchedNote(field: string, asked: string | undefined, present: string[]): string | undefined {
  if (!asked || present.includes(asked)) return undefined;
  const counts = new Map<string, number>();
  for (const v of present) counts.set(v, (counts.get(v) ?? 0) + 1);
  const known = [...counts].map(([v, n]) => `${v} (${n})`).join(', ');
  return `no ${field} "${asked}" in the index; ${field} values present: ${known || 'none'}`;
}

export function toolEntrypoints(ctx: ToolContext, idx: IndexMap, args: { repo?: string; framework?: string; pathPrefix?: string }) {
  const all = indexes(idx, args.repo).flatMap((i) => i.entrypoints);
  const items = all.filter((e) => (!args.framework || e.framework === args.framework) && (!args.pathPrefix || (e.pathTemplate ?? '').startsWith(args.pathPrefix) || e.path.startsWith(args.pathPrefix)));
  const note = unmatchedNote('framework', args.framework, all.map((e) => e.framework));
  return { ...limitList(ctx, items, 300, (e: EntryPoint) => `${e.entryId}\t${e.handler}\t${e.path}:${e.range.startLine}\tmw=${e.middlewares.join(',')}\tauth=${e.authSignals.join(',')}`), ...(note ? { note } : {}) };
}

export function toolDangerousSinks(ctx: ToolContext, idx: IndexMap, args: { repo?: string; category?: string; pathPrefix?: string }) {
  const all = indexes(idx, args.repo).flatMap((i) => i.sinks);
  const items = all.filter((s) => (!args.category || s.category === args.category) && (!args.pathPrefix || s.path.startsWith(args.pathPrefix)));
  const note = unmatchedNote('category', args.category, all.map((s) => s.category));
  return { ...limitList(ctx, items, 300, (s: Sink) => `${s.sinkId}\t${s.api}\t${s.symbolId ?? '-'}\t${s.taintHint ?? ''}`), ...(note ? { note } : {}) };
}

export function toolSymbolLookup(idx: IndexMap, args: { repo?: string; name: string; kind?: string; container?: string }) {
  const name = args.name.trim();
  if (!name) throw new ToolInputError('name is required');
  const items = indexes(idx, args.repo).flatMap((i) => i.symbols)
    .filter((s) => (s.name === name || s.qualifiedName === name || s.symbolId === name) && (!args.kind || s.kind === args.kind) && (!args.container || s.container.includes(args.container)))
    .slice(0, 50)
    .map((s: IndexSymbol) => ({ symbolId: s.symbolId, kind: s.kind, path: s.path, range: s.range, signature: s.signature, qualifiedName: s.qualifiedName, source: 'ts' as const }));
  return { symbols: items };
}

export function toolFindRefs(ctx: ToolContext, idx: IndexMap, args: { repo?: string; symbolId: string }) {
  const edges = indexes(idx, args.repo).flatMap((i) => i.callEdges).filter((e) => e.to === args.symbolId);
  return limitList(ctx, edges.map((e) => ({ path: e.site.path, line: e.site.line, from: e.from, confidence: e.confidence })), 200,
    (r) => `${r.path}:${r.line}\t${r.from}\t${r.confidence}`);
}

const CONF_RANK: Record<CallEdge['confidence'], number> = { resolved: 3, heuristic: 2, unresolved: 1 };

export function toolCallgraph(ctx: ToolContext, idx: IndexMap, args: { symbolId: string; direction: 'callers' | 'callees'; depth?: number; minConfidence?: CallEdge['confidence'] }) {
  const all = [...idx.values()].flatMap((i) => i.callEdges);
  const depth = Math.min(4, Math.max(1, Math.floor(args.depth ?? 2)));
  const min: number = CONF_RANK[args.minConfidence ?? 'heuristic'] ?? 2;
  const out: CallEdge[] = [];
  let frontier = new Set([args.symbolId]);
  const seen = new Set(frontier);
  for (let d = 0; d < depth && frontier.size; d++) {
    const next = new Set<string>();
    for (const e of all) {
      if ((CONF_RANK[e.confidence] ?? 0) < min) continue;
      const hit = args.direction === 'callers' ? e.to && frontier.has(e.to) : frontier.has(e.from);
      if (!hit) continue;
      out.push(e);
      const nxt = args.direction === 'callers' ? e.from : e.to;
      if (nxt && !seen.has(nxt)) { seen.add(nxt); next.add(nxt); }
    }
    frontier = next;
  }
  return limitList(ctx, out, 300, (e) => `${e.from} -> ${e.to ?? e.calleeText}\t${e.site.path}:${e.site.line}\t${e.confidence}`);
}
