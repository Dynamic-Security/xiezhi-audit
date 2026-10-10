// Coverage: reading coverage from `read` ranges only; entry/sink "reviewed" requires
// (1) the handler / enclosing function range was read ≥ 60% and (2) a conclusion was submitted.
import type { CoverageItemDetail, EntryPoint, IndexSymbol, LineRange, Sink, StructIndex } from '@xiezhi/contracts';

export type Range = [number, number];

export function mergeRanges(ranges: Range[]): Range[] {
  const sorted = ranges.filter(([a, b]) => b >= a).sort((x, y) => x[0] - y[0]);
  const out: Range[] = [];
  for (const [a, b] of sorted) {
    const last = out[out.length - 1];
    if (last && a <= last[1] + 1) last[1] = Math.max(last[1], b);
    else out.push([a, b]);
  }
  return out;
}

export function linesCovered(ranges: Range[]): number {
  return mergeRanges(ranges).reduce((n, [a, b]) => n + (b - a + 1), 0);
}

export function overlapRatio(read: Range[], target: LineRange): number {
  const size = target.endLine - target.startLine + 1;
  if (size <= 0) return 0;
  let covered = 0;
  for (const [a, b] of mergeRanges(read)) {
    const lo = Math.max(a, target.startLine);
    const hi = Math.min(b, target.endLine);
    if (hi >= lo) covered += hi - lo + 1;
  }
  return covered / size;
}

export const READ_THRESHOLD = 0.6;

export interface CoverageTarget {
  kind: 'entry' | 'sink';
  targetId: string;
  itemKey: string;
  repo: string;
  path: string;
  /** Range that must be read: handler range (entry) or enclosing function (sink). */
  readRange: LineRange;
  category?: string;
  ruleId: string;
  /** What the target is: the external interface of an entry, the risky call of a sink. */
  detail: CoverageItemDetail;
}

/** `Class.method` of a symbol; null for file-level code (`<main>`, a PHP script) or an unresolved handler. */
function symbolLabel(sym: IndexSymbol | undefined): string | null {
  if (!sym || sym.name.startsWith('<')) return null;
  const owner = sym.container.split(/[.\\/]/).filter(Boolean).at(-1);
  return owner && owner !== sym.name ? `${owner}.${sym.name}` : sym.name;
}

export function entryDetail(e: EntryPoint, symbols: Map<string, IndexSymbol>): CoverageItemDetail {
  const unresolved = /#<unresolved:(.*)>$/.exec(e.handler)?.[1];
  return {
    type: 'entry', entryKind: e.kind, protocol: e.protocol ?? (e.kind === 'rpc' ? 'grpc' : 'http'), framework: e.framework,
    method: e.httpMethod && e.httpMethod !== 'ANY' ? e.httpMethod : null,
    route: e.pathTemplate ?? (e.entryKey.startsWith('rpc:') ? e.entryKey.slice(4) : null),
    handler: symbolLabel(symbols.get(e.handler)) ?? (unresolved && unresolved !== 'anonymous' ? unresolved : null),
    line: e.range.startLine, middlewares: e.middlewares.slice(0, 10), auth: e.authSignals.slice(0, 10),
  };
}

export function sinkDetail(s: Sink, symbols: Map<string, IndexSymbol>): CoverageItemDetail {
  const column = Number(/#L\d+:(\d+):/.exec(s.sinkId)?.[1]);
  return {
    type: 'sink', api: s.api, line: s.range.startLine, column: Number.isFinite(column) ? column : null,
    taintHint: s.taintHint ?? null, function: symbolLabel(s.symbolId ? symbols.get(s.symbolId) : undefined),
  };
}

/**
 * An entry whose named handler could not be resolved because several functions / methods of the
 * repository carry that name (`h.GetUser` with `UserHandler.GetUser` and `AdminHandler.GetUser`) only has the
 * registration line as its range. Reading the route file must not count as reading the handler, so its read range
 * is empty (never satisfied): the entry stays uncovered. A handler outside the repository (no same-named function)
 * keeps the registration line, which is all there is to read.
 */
function entryReadRange(e: EntryPoint, sameNamed: (name: string) => number): LineRange {
  const ref = /#<unresolved:(.*)>$/.exec(e.handler)?.[1];
  if (!ref || ref === 'anonymous') return e.range;
  const name = ref.split(/[.:@\\/]/).filter(Boolean).pop() ?? '';
  return name && sameNamed(name) >= 2 ? { startLine: e.range.startLine, endLine: e.range.startLine - 1 } : e.range;
}

/** Derive coverage targets (denominators) from an index, restricted to an optional path filter. */
export function coverageTargets(index: StructIndex, inScope: (path: string) => boolean = () => true): CoverageTarget[] {
  const symbols = new Map(index.symbols.map((s) => [s.symbolId, s]));
  const out: CoverageTarget[] = [];
  let callableNames: Map<string, number> | null = null;
  const sameNamed = (name: string) => {
    if (!callableNames) {
      callableNames = new Map();
      for (const s of index.symbols) if (s.kind === 'method' || s.kind === 'func') callableNames.set(s.name, (callableNames.get(s.name) ?? 0) + 1);
    }
    return callableNames.get(name) ?? 0;
  };
  for (const e of index.entrypoints) {
    if (!inScope(e.path)) continue;
    out.push({ kind: 'entry', targetId: e.entryId, itemKey: e.entryKey, repo: index.repo, path: e.path, readRange: entryReadRange(e, sameNamed), ruleId: e.ruleId, detail: entryDetail(e, symbols) });
  }
  for (const s of index.sinks) {
    if (!inScope(s.path)) continue;
    const fn = s.symbolId ? symbols.get(s.symbolId) : undefined;
    const readRange = fn && fn.path === s.path ? fn.range : s.range;
    out.push({ kind: 'sink', targetId: s.sinkId, itemKey: `${s.symbolId ?? s.path}|${s.api}`, repo: index.repo, path: s.path, readRange, category: s.category, ruleId: s.ruleId, detail: sinkDetail(s, symbols) });
  }
  return out;
}

export type TargetState = 'reviewed' | 'read_only' | 'untouched';

export function targetState(read: Range[] | undefined, target: CoverageTarget, concluded: boolean): TargetState {
  const isRead = !!read && overlapRatio(read, target.readRange) >= READ_THRESHOLD;
  if (isRead && concluded) return 'reviewed';
  if (isRead) return 'read_only';
  return 'untouched';
}
