// After the hunts: ⑩ reconcile, ⑪ deep exploration on what is uncertain, ⑫ adversarial
// review once per canonical finding, and publishing the vulnerabilities.
import { crossKey, crossModels, stageModel } from '@xiezhi/contracts';
import { estimateStep } from '../estimates.js';
import { closeItem, decideStep, exploreCandidate, exploreMode, findingCandidate, progress, seedDirections, seedPools, STAGNATION_ROUNDS, syncLeads, type DecideOutput, type WorkTarget } from '../explore.js';
import { fromJson } from '@xiezhi/store';
import { pool } from '../pool.js';
import { getStep, type StepRow } from '../state.js';
import { ensureStep } from '../step-runner.js';
import { challengeStep, combineReviews, reviewTier } from '../steps/challenge.js';
import { huntStep } from '../steps/hunt.js';
import { publishStep, reconcileStep } from '../steps/reconcile.js';
import type { Candidate, TriageOutput } from '../steps/triage.js';
import { candidateInput, type PipelineRun, type RunResult } from './context.js';

/** ⑩ reconcile (required; semantic grouping only when a merge model is configured). `round` names a later pass. */
export async function reconcile(p: PipelineRun, round?: 'explore'): Promise<RunResult | null> {
  const { store, auditId, rt } = p;
  const merge = rt.strategy.models.merge;
  let row = ensureStep(store, auditId, { kind: 'reconcile', identity: round ? { audit: auditId, round } : { audit: auditId }, required: true, model: merge, estimateTokens: merge ? estimateStep('reconcile') : 0 });
  // The row may have been created with the merge model's estimate before the user declined a top-up (the merge
  // model is dropped then): it now runs without a model and needs no budget, or it is refused again and the audit
  // returns to waiting_budget for ever.
  if (!merge && row.estimate_tokens > 0 && row.status !== 'succeeded') {
    store.update('step', { id: row.id }, { estimate_tokens: 0, estimate_base: 0, model: null, provider: null });
    row = getStep(store, row.id);
  }
  const r = await p.step(row, (ctx) => reconcileStep(rt, ctx));
  if (r === 'failed' && merge) return deterministicFallback(p, row, { audit: auditId, ...(round ? { round } : {}) }, (ctx) => reconcileStep(rt, ctx, { deterministic: true }));
  return p.stopFor(r, row);
}

/**
 * The merge model failed (e.g. the output contract twice). The same step runs again without
 * the model and supersedes the failed one, like the deterministic triage fallback: the audit keeps a
 * reconciled finding set and a report instead of failing with nothing.
 */
async function deterministicFallback(
  p: PipelineRun, failed: StepRow, identity: Record<string, unknown>,
  body: Parameters<PipelineRun['step']>[1],
): Promise<RunResult | null> {
  const { store, auditId, rt } = p;
  const row = ensureStep(store, auditId, { kind: 'reconcile', identity: { ...identity, deterministic: true }, input: { ...inputOf(failed), supersedes: failed.id, deterministic: true }, required: true, model: null, estimateTokens: 0 });
  rt.event('judgement.made', { kind: 'reconcile_fallback', failed_step: failed.id, summary: '汇总模型失败，改用确定性规则（指纹与位置）完成' }, row.id);
  return p.stopFor(await p.step(row, body), row);
}

function inputOf(row: StepRow): Record<string, unknown> {
  try { return JSON.parse(row.input || '{}') as Record<string, unknown>; } catch { return {}; }
}

/**
 * Rounds without progress in a row. A replayed round (it succeeded before a pause or restart)
 * leaves the count as it is: replaying adds nothing new by design, which is not stagnation.
 */
export function nextQuiet(quiet: number, replayed: boolean, progressed: boolean): number {
  if (replayed) return quiet;
  return progressed ? 0 : quiet + 1;
}

/**
 * ⑪ deep exploration: after reconcile, only on what is uncertain — undetermined
 * hypotheses, cross-model conflicts, single-source and pending findings, cognitive leads. decide → one derived
 * investigation per round, until the round limit, the budget, a decision to stop, or STAGNATION_ROUNDS rounds
 * without progress. New findings are reconciled before the adversarial review.
 */
export async function explore(p: PipelineRun, triage: TriageOutput, byId: Map<string, Candidate>, backfill: boolean): Promise<RunResult | null> {
  const { store, auditId, rt, s } = p;
  if (backfill) return null;
  const mode = exploreMode(rt);
  if (mode === 'directions') return exploreDirections(p);
  if (mode !== 'full') return null;
  seedPools(rt, triage);
  let quiet = 0;
  let stopped = false;
  for (let round = 1; round <= s.limits.maxRounds; round++) {
    if (p.halting() || !p.llmAllowed()) { stopped = true; break; }
    const before = progress(rt);
    const decideRow = ensureStep(store, auditId, { kind: 'decide', identity: { round }, lineage: `R${round}`, model: stageModel(s, 'explore')!, estimateTokens: estimateStep('decide') });
    // A round that already ran before a pause or restart is replayed from its saved results: it adds nothing new,
    // so it must not count towards stagnation.
    const replayed = getStep(store, decideRow.id).status === 'succeeded';
    const dr = await p.step(decideRow, (ctx) => decideStep(rt, round, ctx));
    if (dr === 'interrupted' || p.halting()) return p.interrupted();
    if (dr === 'blocked_budget') return p.blocked([decideRow]);
    if (dr !== 'succeeded') { p.carried.add('STEP_FAILED'); stopped = true; break; }
    const d = store.artifacts.getJson<DecideOutput>(getStep(store, decideRow.id).output_ref!);
    if (d.decision.stop) { stopped = true; break; }
    let outcomeText: string;
    let derivedId: string | null = null;
    // A `challenge` decision (older prompt) investigates the finding's place: every finding is reviewed later anyway.
    const cand = exploreCandidate(rt, d, byId) ?? (d.target.findingId ? findingCandidate(rt, d) : null);
    if (cand) {
      const row = ensureStep(store, auditId, { kind: 'hunt', identity: { explore: round, batch: [cand.id] }, lineage: `R${round}-C1`, model: stageModel(s, 'explore')!, estimateTokens: estimateStep('hunt', 1), input: candidateInput([cand]) });
      const r = await p.step(row, (ctx) => huntStep(rt, [cand], row.lineage_id ?? `R${round}-C1`, ctx, { stageModel: stageModel(s, 'explore')! }));
      const stop = p.stopFor(r, row);
      if (stop) return stop;
      derivedId = row.id;
      const n = store.get<{ n: number }>('SELECT COUNT(*) AS n FROM finding WHERE step_id = ?', row.id)!.n;
      outcomeText = r === 'succeeded' ? (n ? `提交 ${n} 条发现` : '未发现问题') : `调查失败（${r}）`;
    } else {
      outcomeText = '方向没有可调查的位置';
    }
    closeItem(rt, d.itemId, derivedId, outcomeText);
    syncLeads(rt, round, derivedId);
    quiet = nextQuiet(quiet, replayed, progress(rt) !== before);
    rt.event('judgement.made', { kind: 'explore_round', round, outcome: outcomeText, quiet }, derivedId ?? decideRow.id);
    if (quiet >= STAGNATION_ROUNDS) { stopped = true; break; }
  }
  if (!stopped) p.carried.add('ROUND_LIMIT_REACHED');
  return null;
}

/** Estimate of a light review against a full one. */
export const LIGHT_REVIEW_SHARE = 0.4;

/**
 * ⑪ on demand: deep exploration is off by default, but the domain experts left directions open —
 * each of them (at most AUTO_EXPLORE_ROUNDS) is investigated once, without a decide session: the direction is the
 * decision. Same lineage (`R<n>-C1`) and budget stage (explore) as the decide loop.
 */
async function exploreDirections(p: PipelineRun): Promise<RunResult | null> {
  const { store, auditId, rt, s } = p;
  const items = seedDirections(rt);
  if (items.length) rt.event('judgement.made', { kind: 'explore_on_demand', directions: items.length });
  // The directions are independent, so they run side by side in the audit's session slots. Rounds keep
  // their index (`R<n>-C1`) so a resumed audit finds the same steps.
  let stopped: RunResult | null = null;
  await pool([...items.entries()], p.parallel, async ([i, item]) => {
    if (stopped || p.halting() || !p.llmAllowed()) return;
    if (item.pool === 'done') return;
    const round = i + 1;
    const t = fromJson<WorkTarget>(item.target, {});
    if (!t.path) {
      closeItem(rt, item.id, null, '方向没有可调查的位置');
      return;
    }
    const repo = t.repo ?? rt.targetRepo.name;
    const cand: Candidate = { id: `explore:R${round}:${repo}:${t.path}#L${t.line ?? 1}`, kind: 'change', repo, path: t.path, line: t.line ?? 1, label: `[explore] ${item.title}`, score: 1 };
    const row = ensureStep(store, auditId, { kind: 'hunt', identity: { explore: round, batch: [cand.id], direction: item.id }, lineage: `R${round}-C1`, model: stageModel(s, 'explore')!, estimateTokens: estimateStep('hunt', 1), input: candidateInput([cand]) });
    const r = await p.step(row, (ctx) => huntStep(rt, [cand], row.lineage_id ?? `R${round}-C1`, ctx, { stageModel: stageModel(s, 'explore')! }));
    const stop = p.stopFor(r, row);
    if (stop) {
      stopped ??= stop;
      return;
    }
    const n = store.get<{ n: number }>('SELECT COUNT(*) AS n FROM finding WHERE step_id = ?', row.id)!.n;
    const outcomeText = r === 'succeeded' ? (n ? `提交 ${n} 条发现` : '未发现问题') : `调查失败（${r}）`;
    closeItem(rt, item.id, row.id, outcomeText);
    rt.event('judgement.made', { kind: 'explore_round', round, outcome: outcomeText, on_demand: true }, row.id);
  });
  if (p.halting()) return p.interrupted();
  return stopped;
}

/**
 * ⑫ adversarial review: once per canonical finding, after reconcile, with the counter-evidence of
 * the audit. Idempotent per finding: a later round only reviews what is new. Tiered (by
 * dispute): a light review — the first review model only, fewer turns — for medium / low findings the hunt
 * models did not disagree on.
 */
export async function adversarialReview(p: PipelineRun): Promise<RunResult | null> {
  const { store, auditId, rt, s } = p;
  if (!s.stages.adversarialReview) return null;
  // a finding the hunt models disagreed on (cross-check conflicts) gets the full review too.
  const findings = store.all<{ id: string; severity: string; confirmation: string | null; detail_ref: string }>(`SELECT id, severity, confirmation, detail_ref FROM finding WHERE audit_id = ? AND state = 'canonical' ORDER BY display_no`, auditId)
    .map((f) => ({ ...f, conflicted: (store.artifacts.getJson<{ consensus?: { conflicts?: unknown[] } }>(f.detail_ref).consensus?.conflicts?.length ?? 0) > 0 }));
  // with cross-checking every review model reviews every finding; the votes are combined.
  const reviewModels = crossModels(s, 'review') ?? [stageModel(s, 'challenge')!];
  const crossReview = reviewModels.length > 1;
  // A light review is one session with the first review model, so it is never a vote. Its identity names the tier:
  // a finding reviewed before tiering keeps its full review on resume.
  const tierOf = new Map(findings.map((f) => [f.id, reviewTier(s, f)]));
  const full = findings.filter((f) => tierOf.get(f.id) === 'full');
  const rows = findings.flatMap((f) => (tierOf.get(f.id) === 'full' ? reviewModels : reviewModels.slice(0, 1)).map((m, j) => {
    const light = tierOf.get(f.id) === 'light';
    const vote = crossReview && !light;
    return { f, m, light, vote, row: ensureStep(store, auditId, {
      kind: 'challenge', identity: light ? { finding: f.id, adversarial: true, light: true } : vote ? { finding: f.id, adversarial: true, model: crossKey(reviewModels, j) } : { finding: f.id, adversarial: true },
      input: light ? { findingId: f.id, light: true } : vote ? { findingId: f.id, vote: true } : { findingId: f.id }, model: m,
      estimateTokens: light ? Math.ceil(estimateStep('challenge') * LIGHT_REVIEW_SHARE) : estimateStep('challenge'), ...(light ? { calibrate: false } : {}),
    }) };
  }));
  const blockedRv: StepRow[] = [];
  await pool(rows, p.parallel, async ({ f, m, light, vote, row }) => {
    if (p.halting() || blockedRv.length) return;
    if (!p.llmAllowed()) {
      p.skipUnrun(row);
      return;
    }
    const r = await p.step(row, (ctx) => challengeStep(rt, f.id, ctx, { model: m, vote, light }));
    if (r === 'blocked_budget') blockedRv.push(row);
  });
  if (p.halting()) return p.interrupted();
  if (blockedRv.length) return p.blocked(p.unfinished('challenge'));
  if (crossReview) {
    for (const f of full) {
      const row = ensureStep(store, auditId, { kind: 'challenge', identity: { finding: f.id, adversarial: true, combine: true }, input: { findingId: f.id, combine: true }, model: null, estimateTokens: 0 });
      const r = await p.step(row, async (ctx) => combineReviews(rt, f.id, ctx));
      if (r === 'interrupted') return p.interrupted();
    }
  }
  return null;
}

/** Publish: vulnerabilities are created / matched once, after the review (and after a gap round). */
export async function publish(p: PipelineRun): Promise<RunResult | null> {
  const { store, auditId, rt } = p;
  // With a merge model the suspected-match judgement may run; reserve one session for it.
  const row = ensureStep(store, auditId, { kind: 'reconcile', identity: { audit: auditId, publish: true }, input: { publish: true }, required: true, model: rt.strategy.models.merge, estimateTokens: rt.strategy.models.merge ? estimateStep('reconcile') : 0 });
  const r = await p.step(row, (ctx) => publishStep(rt, ctx));
  // Without the suspected-match judgement the vulnerabilities are still published (exact and rename matches only).
  if (r === 'failed' && rt.strategy.models.merge) return deterministicFallback(p, row, { audit: auditId, publish: true }, (ctx) => publishStep(rt, ctx, { deterministic: true }));
  return p.stopFor(r, row);
}
