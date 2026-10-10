// Symbol-level changes between two indexed snapshots and rename/move mapping for
// vulnerability identity: functions are compared by qualified name and by a hash
// of their body, so a moved or renamed function with the same body is followed rather than lost.
import { createHash } from 'node:crypto';
import type { IndexSymbol, StructIndex, SymbolChange } from '@xiezhi/contracts';

export interface TextSource {
  lines(relPath: string): string[];
}

const FUNCTION_KINDS = new Set(['method', 'func']);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');
const norm = (lines: string[]) => lines.map((l) => l.replace(/\s+/g, '')).filter(Boolean).join('\n');

export interface SymbolHashes {
  /** Whole range, whitespace-insensitive: detects any change to the function. */
  full: string;
  /** Range without its declaration line: equal for a moved/renamed function with an unchanged body. */
  body: string;
}

export function hashSymbol(src: TextSource, s: IndexSymbol): SymbolHashes {
  let lines: string[];
  try {
    lines = src.lines(s.path).slice(s.range.startLine - 1, s.range.endLine);
  } catch {
    lines = [];
  }
  const body = lines.length > 1 ? lines.slice(1) : lines;
  return { full: sha(norm(lines)), body: sha(`${s.kind}|${norm(body)}`) };
}

function functions(index: StructIndex): IndexSymbol[] {
  return index.symbols.filter((s) => FUNCTION_KINDS.has(s.kind));
}

export interface SymbolDiff {
  changes: SymbolChange[];
  /** base qualified name → head qualified name. */
  renames: { from: string; to: string }[];
}

/**
 * Compare the functions of two indexes. Same qualified name + different content → modified; a base
 * function missing from head whose body hash matches exactly one new head function (and vice versa)
 * → renamed (moved/renamed with an unchanged body); otherwise added / deleted.
 */
export function diffSymbols(base: StructIndex, baseSrc: TextSource, head: StructIndex, headSrc: TextSource): SymbolDiff {
  const bFns = functions(base);
  const hFns = functions(head);
  const bByName = new Map(bFns.map((s) => [s.qualifiedName, s]));
  const hByName = new Map(hFns.map((s) => [s.qualifiedName, s]));
  const changes: SymbolChange[] = [];
  const bHash = new Map(bFns.map((s) => [s.symbolId, hashSymbol(baseSrc, s)]));
  const hHash = new Map(hFns.map((s) => [s.symbolId, hashSymbol(headSrc, s)]));

  for (const h of hFns) {
    const b = bByName.get(h.qualifiedName);
    if (b && bHash.get(b.symbolId)!.full !== hHash.get(h.symbolId)!.full) {
      changes.push({ symbolId: h.symbolId, qualifiedName: h.qualifiedName, change: 'modified', path: h.path });
    }
  }
  const gone = bFns.filter((s) => !hByName.has(s.qualifiedName));
  const fresh = hFns.filter((s) => !bByName.has(s.qualifiedName));
  const byBody = <T extends IndexSymbol>(xs: T[], hashes: Map<string, SymbolHashes>) => {
    const m = new Map<string, T[]>();
    for (const x of xs) {
      const k = hashes.get(x.symbolId)!.body;
      m.set(k, [...(m.get(k) ?? []), x]);
    }
    return m;
  };
  const goneByBody = byBody(gone, bHash);
  const freshByBody = byBody(fresh, hHash);
  const renames: { from: string; to: string }[] = [];
  const matchedGone = new Set<string>();
  const matchedFresh = new Set<string>();
  for (const [k, olds] of goneByBody) {
    const news = freshByBody.get(k);
    // Only unambiguous 1:1 matches: two identical bodies cannot tell which is which.
    if (olds.length !== 1 || news?.length !== 1) continue;
    const from = olds[0]!;
    const to = news[0]!;
    renames.push({ from: from.qualifiedName, to: to.qualifiedName });
    matchedGone.add(from.symbolId);
    matchedFresh.add(to.symbolId);
    changes.push({ symbolId: to.symbolId, qualifiedName: to.qualifiedName, change: 'renamed', fromQualifiedName: from.qualifiedName, path: to.path });
  }
  for (const s of fresh) if (!matchedFresh.has(s.symbolId)) changes.push({ symbolId: s.symbolId, qualifiedName: s.qualifiedName, change: 'added', path: s.path });
  for (const s of gone) if (!matchedGone.has(s.symbolId)) changes.push({ symbolId: s.symbolId, qualifiedName: s.qualifiedName, change: 'deleted', path: s.path });
  changes.sort((x, y) => x.qualifiedName.localeCompare(y.qualifiedName) || x.change.localeCompare(y.change));
  renames.sort((x, y) => x.from.localeCompare(y.from));
  return { changes, renames };
}
