// Evidence chains: what the engine can check about a finding's claim. Each step of the call chain
// (entry → … → dangerous operation) is matched to the index call graph; a finding about a missing check says where
// the check belongs. Nothing is refused here: the result goes with the finding to the adversarial review, which
// refutes item by item and turns a claim it cannot back into “待确认”.
import type { CodeRef, IndexSymbol, StructIndex } from '@xiezhi/contracts';
import { P } from '@xiezhi/knowledge';

/** Categories whose vulnerability is a check that is not there: the finding should say where it belongs. */
export const MISSING_CHECK_CATEGORIES: readonly string[] = ['authz_object', 'authz_function', 'authn', 'csrf', 'business_logic', 'race_condition'];

export type EdgeLink = 'same_function' | 'resolved' | 'heuristic' | 'not_in_index' | 'unknown';

export interface EvidenceCheck {
  /** Consecutive chain steps (chain refs, then the finding location). */
  edges: { from: string; to: string; link: EdgeLink }[];
  missingCheck: 'given' | 'absent' | 'not_needed';
  /** Short Chinese lines for the review prompt; empty when nothing is missing. */
  gaps: string[];
}

function enclosing(idx: StructIndex | undefined, ref: CodeRef): IndexSymbol | undefined {
  return (idx?.symbols ?? [])
    .filter((s) => (s.kind === 'method' || s.kind === 'func') && s.path === ref.path && s.range.startLine <= ref.startLine && ref.startLine <= s.range.endLine)
    .sort((a, b) => (a.range.endLine - a.range.startLine) - (b.range.endLine - b.range.startLine))[0];
}

const label = (r: CodeRef, s: IndexSymbol | undefined) => `${s?.qualifiedName ?? r.path}:${r.startLine}`;

export function checkEvidence(
  d: { category: string; chain: CodeRef[]; location: CodeRef; missingCheck?: { location: CodeRef; expected: string } | undefined },
  idx: StructIndex | undefined, repo: string,
): EvidenceCheck {
  const steps = [...d.chain, d.location].filter((r) => !r.repo || r.repo === repo);
  const edges: EvidenceCheck['edges'] = [];
  for (let i = 1; i < steps.length; i++) {
    const a = steps[i - 1]!, b = steps[i]!;
    const sa = enclosing(idx, a), sb = enclosing(idx, b);
    let link: EdgeLink;
    if (!sa || !sb) link = 'unknown';
    else if (sa.symbolId === sb.symbolId) link = 'same_function';
    else {
      const e = (idx?.callEdges ?? []).filter((x) => x.from === sa.symbolId && x.to === sb.symbolId);
      link = e.some((x) => x.confidence === 'resolved') ? 'resolved' : e.length ? 'heuristic' : 'not_in_index';
    }
    edges.push({ from: label(a, sa), to: label(b, sb), link });
  }
  const needs = MISSING_CHECK_CATEGORIES.includes(d.category);
  const missingCheck = d.missingCheck ? 'given' : needs ? 'absent' : 'not_needed';
  const gaps = [
    ...edges.filter((e) => e.link === 'not_in_index').map((e) => P('evidence.gap_no_edge', { from: e.from, to: e.to })),
    ...(missingCheck === 'absent' ? [P('evidence.gap_missing_check')] : []),
  ];
  return { edges, missingCheck, gaps };
}
