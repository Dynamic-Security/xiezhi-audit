// triage: candidates are AST entry points and sinks; deterministic ordering, optional
// LLM 1–5 scoring (models.triage). Candidates beyond maxCandidates are declared as coverage gaps.
import picomatch from 'picomatch';
import { SubmitTriage, type EntryPoint, type Sink } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import { graphqlStateOrById } from '@xiezhi/context';
import { canonicalJson, isTestPath, sha256Hex } from '@xiezhi/contracts';
import type { AuditRuntime } from '../runtime.js';
import { getStep, transitionStep, type StepRow } from '../state.js';
import { sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { P } from '@xiezhi/knowledge';
import { entryExposure, entryPathOf, projectGateways, serviceNames } from '../gateway.js';

/** Bump when the triage prompt, scoring or candidate construction changes: cached triage is then not reused. */
export const TRIAGE_VERSION = 2;

/**
 * Content identity of a triage (triage is cacheable by rootHash, focus and model): the
 * indexed trees, everything in the strategy that changes candidates or their order, and the model.
 */
export function triageIdentity(rt: AuditRuntime) {
  const s = rt.strategy;
  const roots = [...rt.indexes.keys()].sort().map((name) => `${name}:${rt.views.get(name)?.manifest.rootHash ?? ''}`);
  const m = s.models.triage;
  return {
    triage: sha256Hex(canonicalJson({
      roots, focus: s.focus.categories, scope: s.scope, maxCandidates: s.limits.maxCandidates, minScore: s.limits.minTriageScore ?? 0, logic: s.stages.threatHypotheses === true,
      model: m ? `${m.provider}/${m.model}` : null, v: TRIAGE_VERSION,
    })),
  };
}

/** Reuse a succeeded triage of another audit with the same content identity (settled as `skipped`, no model call). */
export function reuseTriage(rt: AuditRuntime, row: StepRow): boolean {
  const hit = rt.store.get<{ id: string; output_ref: string }>(
    `SELECT id, output_ref FROM step WHERE kind = 'triage' AND idempotency_key = ? AND audit_id != ? AND status IN ('succeeded','skipped') AND output_ref IS NOT NULL
     ORDER BY created_at DESC LIMIT 1`, row.idempotency_key, rt.auditId);
  if (!hit) return false;
  if (!['pending', 'ready'].includes(getStep(rt.store, row.id).status)) return false;
  rt.store.tx(() => {
    transitionStep(rt.store, row.id, 'skipped', { output_ref: hit.output_ref, reused_from: hit.id, error_summary: 'reused cached triage' }, 'cache hit');
  });
  return true;
}

export interface Candidate {
  id: string;
  /**
   * `change`: a changed file in an incremental audit that no indexed candidate represents. `hypothesis`: a
   * threat-model hypothesis in a verification batch (only for progress marks and the step input).
   */
  kind: 'entry' | 'sink' | 'change' | 'hypothesis';
  repo: string;
  path: string;
  line: number;
  label: string;
  score: number;
  llmScore?: number;
  reason?: string;
}

const SINK_WEIGHT: Record<string, number> = {
  cmdi: 5, deserialization: 5, sqli: 5, code_injection: 5, expression_injection: 5, ssrf: 4, path_traversal: 4, xxe: 4,
  ssti: 4, file_upload: 4, nosqli: 4, ldapi: 4, open_redirect: 3, xss: 3,
};

const TEST_PATH = /(^|\/)(src\/test|test|tests|__tests__|testdata|mock|mocks)\/|_test\.go$|Test\.java$|Tests\.java$/;

export function scopePredicate(include: string[], exclude: string[]): (path: string) => boolean {
  const inc = include.length ? picomatch(include, { dot: true }) : null;
  const exc = exclude.length ? picomatch(exclude, { dot: true }) : null;
  return (p) => !TEST_PATH.test(p) && !isTestPath(p) && (!inc || inc(p)) && !(exc && exc(p));
}

/** Heuristic score of an entry candidate (before the triage model). */
export function entryScore(e: EntryPoint, focus: ReadonlySet<string>): number {
  let score = 2;
  // Object id in the path (or a GraphQL id argument / mutation) → IDOR candidate.
  if (e.entryKey.startsWith('rpc:graphql:') ? graphqlStateOrById(e.entryKey, e.pathTemplate) : (e.pathTemplate ?? '').includes('{')) score += 2;
  if (e.authSignals.length === 0) score += 1;
  if (focus.has('authz_object') || focus.has('authz_function')) score += 2;
  return score;
}

export function buildCandidates(rt: AuditRuntime): Candidate[] {
  const inScope = scopePredicate(rt.strategy.scope.include, rt.strategy.scope.exclude);
  const focus = new Set(rt.strategy.focus.categories);
  const out: Candidate[] = [];
  // only the audit's target repositories produce candidates; related / context repositories are indexed for
  // cross-repository tracing, and findings may not land in them.
  const targets = new Set(rt.targets.map((r) => r.name));
  // with gateways in the project, entries the gateways expose come first and internal-only ones
  // after (the trust setting decides how much an internal-only finding counts).
  const gateways = rt.audit.scene === 'full' || rt.audit.scene === 'incremental' ? projectGateways(rt.store, rt.audit.project_id, rt.views) : [];
  for (const [repo, idx] of rt.indexes) {
    if (!targets.has(repo)) continue;
    const names = gateways.length ? serviceNames(rt.store, rt.audit.project_id, repo) : null;
    const exposure = (e: EntryPoint): number => {
      if (!names) return 0;
      const path = entryPathOf(e);
      if (!path) return 0;
      return entryExposure(gateways, names, path).routes.length ? 1 : -1;
    };
    for (const s of idx.sinks as Sink[]) {
      if (!inScope(s.path)) continue;
      let score = SINK_WEIGHT[s.category] ?? 2;
      if (s.taintHint === 'string_concat') score += 1;
      if (s.taintHint === 'request_string') score += 2; // request value straight into the call (GORM conditions)
      if (s.taintHint === 'constant') score -= 2;
      if (focus.has(s.category)) score += 2;
      out.push({ id: s.sinkId, kind: 'sink', repo, path: s.path, line: s.range.startLine, label: `[sink:${s.category}] ${s.api}${s.taintHint ? ` (${s.taintHint})` : ''}`, score });
    }
    for (const e of idx.entrypoints as EntryPoint[]) {
      if (!inScope(e.path)) continue;
      const graphql = e.entryKey.startsWith('rpc:graphql:');
      const score = entryScore(e, focus) + exposure(e);
      out.push({
        id: e.entryId, kind: 'entry', repo, path: e.path, line: e.range.startLine,
        label: `[entry] ${e.entryKey}${graphql && e.pathTemplate ? ` ${e.pathTemplate}` : ''} → ${e.handler}${e.middlewares.length ? ` mw=[${e.middlewares.join(', ')}]` : ''}${e.authSignals.length ? ` auth=[${e.authSignals.join(', ')}]` : ' auth=[]'}`,
        score,
      });
    }
  }
  return out;
}

/** A heuristic score on the model's 1–5 scale (heuristic scores run from about 0 to 9). */
export function heuristicLlmScore(score: number): number {
  return Math.min(5, Math.max(1, Math.round(score / 2)));
}

/**
 * Candidates by model score, then heuristic score. `shownUnscored` (triage): candidates the model was shown but
 * did not score rank by their heuristic score on the model's scale instead of after every scored one; other unscored
 * candidates (not shown, or ⑨ ordering) follow the scored ones.
 */
export function rankCandidates(c: Candidate[], opts: { shownUnscored?: ReadonlySet<string> } = {}): Candidate[] {
  const eff = (x: Candidate) => x.llmScore ?? (opts.shownUnscored?.has(x.id) ? heuristicLlmScore(x.score) : 0);
  return [...c].sort((a, b) => eff(b) - eff(a) || b.score - a.score || a.path.localeCompare(b.path) || a.line - b.line || a.id.localeCompare(b.id));
}

export interface TriageOutput {
  candidates: Candidate[]; selected: string[]; overflow: string[]; batches: string[][];
  /** Formerly: entry batches of the separate logic review; no longer produced. */
  logicBatches?: string[][];
}

export const BATCH_SIZE = 8;

/** Group selected candidates into hunt batches (≤ 8), keeping same-file candidates together. */
export function makeBatches(selected: Candidate[]): string[][] {
  const byFile = new Map<string, Candidate[]>();
  for (const c of selected) (byFile.get(`${c.repo}:${c.path}`) ?? byFile.set(`${c.repo}:${c.path}`, []).get(`${c.repo}:${c.path}`)!).push(c);
  const batches: string[][] = [];
  let cur: string[] = [];
  for (const group of byFile.values()) {
    for (const c of group) {
      if (cur.length >= BATCH_SIZE) { batches.push(cur); cur = []; }
      cur.push(c.id);
    }
  }
  if (cur.length) batches.push(cur);
  return batches;
}

/**
 * Cheap triage models often copy more or less than the id from a listing line (`id | repo:path:line | label`):
 * the id with the location appended, or only the location. Resolve to a listed id: exact, the part before the
 * first " | ", or a location naming exactly one listed candidate.
 */
export function candidateResolver(listed: Candidate[]): (raw: string) => string | null {
  const ids = new Set(listed.map((c) => c.id));
  const byLoc = new Map<string, string[]>();
  for (const c of listed) for (const k of [`${c.repo}:${c.path}:${c.line}`, `${c.path}:${c.line}`]) byLoc.set(k, [...(byLoc.get(k) ?? []), c.id]);
  return (raw) => {
    const t = raw.trim();
    if (ids.has(t)) return t;
    const parts = t.split(' | ').map((x) => x.trim());
    if (ids.has(parts[0]!)) return parts[0]!;
    for (const p of parts) { const hit = byLoc.get(p); if (hit?.length === 1) return hit[0]!; }
    return null;
  };
}

/**
 * `heuristicOnly`: the deterministic ordering without the triage model — the fallback when the model
 * failed, identical to a strategy without `models.triage`.
 */
export async function triageStep(rt: AuditRuntime, ctx: AttemptContext, opts: { heuristicOnly?: boolean } = {}): Promise<StepResult> {
  let candidates = buildCandidates(rt);
  const model = opts.heuristicOnly ? null : rt.strategy.models.triage;
  let shownUnscored = new Set<string>();
  if (model && candidates.length > 0) {
    const shortlist = rankCandidates(candidates).slice(0, Math.ceil(rt.strategy.limits.maxCandidates * 1.5));
    const listing = shortlist.map((c) => `- ${c.id} | ${c.repo}:${c.path}:${c.line} | ${c.label}`).join('\n');
    const resolve = candidateResolver(shortlist);
    const submit: AuditTool = {
      name: 'submit_triage', kind: 'submit', parameters: SubmitTriage, description: P('tool.submit_triage'),
      validate: (a: { scores: { candidateId: string }[] }) => {
        const unknown = a.scores.filter((s) => !resolve(s.candidateId)).map((s) => s.candidateId);
        return unknown.length ? [P('feedback.triage.unknown_candidate', { ids: unknown.slice(0, 5).join(', ') })] : [];
      },
      run: () => ({ text: 'accepted' }),
    };
    const outcome = await rt.session({
      stepId: ctx.stepId, attempt: ctx.attempt, kind: 'triage', phase: 'hunt', model, signal: ctx.signal,
      prompt: `${P('triage.intro')}\n\n${listing}`,
      submitTools: [submit], requiredSubmits: ['submit_triage'], maxTurns: Math.min(30, rt.strategy.limits.maxTurnsPerStep),
    });
    const err = sessionError(outcome);
    if (err) throw err;
    const scores = new Map<string, { score: number; reason: string }>();
    for (const sub of outcome.submissions.submit_triage as { scores: { candidateId: string; score: number; reason: string }[] }[]) {
      for (const s of sub.scores) { const id = resolve(s.candidateId); if (id) scores.set(id, { score: s.score, reason: s.reason }); }
    }
    candidates = candidates.map((c) => (scores.has(c.id) ? { ...c, llmScore: scores.get(c.id)!.score, reason: scores.get(c.id)!.reason } : c));
    shownUnscored = new Set(shortlist.filter((c) => !scores.has(c.id)).map((c) => c.id));
  }
  // Candidates the model left unscored rank by their heuristic score, not after every scored one.
  const ranked = rankCandidates(candidates, { shownUnscored });
  const max = rt.strategy.limits.maxCandidates;
  // Triage cutoff: only candidates the model scored below the threshold are dropped.
  const min = model ? rt.strategy.limits.minTriageScore ?? 0 : 0;
  const kept = min > 0 ? ranked.filter((c) => c.llmScore === undefined || c.llmScore >= min) : ranked;
  const selected = kept.slice(0, max);
  const chosen = new Set(selected.map((c) => c.id));
  const out: TriageOutput = {
    candidates: ranked, selected: selected.map((c) => c.id), overflow: ranked.filter((c) => !chosen.has(c.id)).map((c) => c.id), batches: makeBatches(selected),
  };
  return { outputRef: rt.store.artifacts.putJson(out) };
}
