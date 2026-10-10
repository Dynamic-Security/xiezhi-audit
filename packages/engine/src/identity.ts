// Vulnerability identity: code owns identity; fingerprints anchor on the sink.
import { resolveCategory, sha256Hex, type CodeRef, type HitDraft, type StructIndex, type VulnCategory } from '@xiezhi/contracts';
import { entryKey, normalizeRoute, type SnapshotView } from '@xiezhi/context';

export const FP_VERSION = 'v1';

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/** Remove whitespace and line numbers; keep the qualified form. */
export function normSymbol(s: string | null | undefined): string {
  if (!s) return '';
  return s.replace(/\s+/g, '').replace(/:\d+(-\d+)?$/, '').replace(/#L\d+.*$/, '');
}

export function fpSink(category: string, repositoryId: string, sinkSymbol: string | null, sinkApi: string | null): string | null {
  const sym = normSymbol(sinkSymbol);
  if (!sym) return null;
  return sha256Hex(`${FP_VERSION}|sink|${esc(category)}|${esc(repositoryId)}|${esc(sym)}|${esc(normSymbol(sinkApi))}`);
}

export function fpEntry(category: string, repositoryId: string, entry: string | null): string | null {
  if (!entry) return null;
  return sha256Hex(`${FP_VERSION}|entry|${esc(category)}|${esc(repositoryId)}|${esc(entry)}`);
}

export function confidenceTier(score: number): 'low' | 'medium' | 'high' {
  return score >= 0.8 ? 'high' : score >= 0.5 ? 'medium' : 'low';
}

export interface EnrichedFinding {
  category: VulnCategory;
  cwe: string | null;
  sinkSymbol: string | null;
  sinkApi: string | null;
  sinkId: string | null;
  entryKeys: string[];
  fpSink: string | null;
  fpEntry: string | null;
  module: string | null;
}

/**
 * Deterministic enrichment (reconcile "enrich"): anchor the finding to an index sink when possible
 * (explicit sinkId, or an indexed sink inside the reported location), map entries to entry keys.
 */
export function enrichFinding(d: HitDraft, repositoryId: string, index: StructIndex | undefined): EnrichedFinding {
  const category = resolveCategory(d.category, d.cwe);
  const symbols = new Map((index?.symbols ?? []).map((s) => [s.symbolId, s]));
  let sink = d.sink?.sinkId ? index?.sinks.find((s) => s.sinkId === d.sink!.sinkId) : undefined;
  if (!sink && index) {
    const inLoc = index.sinks.filter((s) => s.path === d.location.path && s.range.startLine <= d.location.endLine && s.range.endLine >= d.location.startLine);
    sink = inLoc.find((s) => s.category === category) ?? (inLoc.length === 1 ? inLoc[0] : undefined);
  }
  if (!sink && index) {
    // The cited lines miss the sink (e.g. the concatenation line instead of the call). Anchor to
    // the sink of the same category in the enclosing function, so the fingerprint does not depend on which lines the
    // model happened to cite. Only an unambiguous match is taken.
    const fn = enclosingFunction(index, d.location);
    const inFn = fn ? index.sinks.filter((s) => s.path === d.location.path && s.symbolId === fn.symbolId && s.category === category) : [];
    if (inFn.length === 1) sink = inFn[0];
  }
  let sinkSymbol: string | null = null;
  let sinkApi: string | null = d.sink?.api ?? null;
  if (sink) {
    const fn = sink.symbolId ? symbols.get(sink.symbolId) : undefined;
    sinkSymbol = fn?.qualifiedName ?? sink.symbolId;
    sinkApi = sink.api;
  } else if (d.sink?.symbol && index) {
    const s = index.symbols.find((x) => x.qualifiedName === d.sink!.symbol || x.symbolId === d.sink!.symbol);
    sinkSymbol = s?.qualifiedName ?? null;
  }
  if (!sinkSymbol && index) {
    // Fall back to the function enclosing the reported location (still code-derived, stable under line shifts).
    const enclosing = enclosingFunction(index, d.location);
    if (enclosing) sinkSymbol = enclosing.qualifiedName;
  }
  const entryKeys = [...new Set(d.entries.map((e) => {
    const hit = index?.entrypoints.find((x) => x.entryId === e || x.entryKey === e || `${index.repo}:${x.entryKey}` === e);
    if (hit) return hit.entryKey;
    const m = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|ANY)\s+(\S+)$/i.exec(e.trim());
    return m ? entryKey(m[1]!, m[2]!) : e.trim();
  }))].sort();
  const module = d.location.path.includes('/') ? d.location.path.slice(0, d.location.path.lastIndexOf('/')) : null;
  return {
    category, cwe: d.cwe ?? null, sinkSymbol, sinkApi, sinkId: sink?.sinkId ?? null, entryKeys,
    // Without an index sink the api is the model's own wording, which changes from run
    // to run; it is kept for display but not used in the fingerprint (the enclosing function is).
    // a sink the profile added (rule model.surface) carries the model's wording as its api, too.
    fpSink: fpSink(category, repositoryId, sinkSymbol, sink && sink.ruleId !== 'model.surface' ? sinkApi : null),
    fpEntry: fpEntry(category, repositoryId, entryKeys[0] ?? null),
    module,
  };
}

export { normalizeRoute };

/** The smallest method / function that contains the location. */
function enclosingFunction(index: StructIndex, loc: { path: string; startLine: number; endLine: number }) {
  return index.symbols
    .filter((s) => (s.kind === 'method' || s.kind === 'func') && s.path === loc.path && s.range.startLine <= loc.startLine && s.range.endLine >= loc.endLine)
    .sort((a, b) => (a.range.endLine - a.range.startLine) - (b.range.endLine - b.range.startLine))[0];
}

/** Verified code evidence: file in manifest, valid range, content hash of the cited lines. */
export function verifyCodeRef(view: SnapshotView | undefined, ref: CodeRef): { verified: boolean; contentHash: string | null; reason?: string } {
  if (!view) return { verified: false, contentHash: null, reason: 'unknown repo' };
  let rel: string;
  try {
    rel = view.guard(ref.path);
  } catch (e) {
    return { verified: false, contentHash: null, reason: (e as Error).message };
  }
  if (!view.validRange(rel, ref.startLine, ref.endLine)) return { verified: false, contentHash: null, reason: `invalid line range ${ref.startLine}-${ref.endLine}` };
  const lines = view.lines(rel).slice(ref.startLine - 1, ref.endLine).join('\n');
  return { verified: true, contentHash: sha256Hex(lines) };
}
