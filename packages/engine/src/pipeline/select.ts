// ④⑤ profile and threat model (`prepare`) run in parallel with ⑥ candidate selection (`select`):
// neither depends on the other; the threat model needs the profile, the hunts need both.
import { crossKey, crossModels, stageModel } from '@xiezhi/contracts';
import { estimateStep } from '../estimates.js';
import { pool } from '../pool.js';
import { getStep, type StepRow } from '../state.js';
import { ensureStep, type StepOutcome } from '../step-runner.js';
import { backfillScope, gapSelection } from '../steps/coverage-gap.js';
import { profileIdentity, profileStep, reuseProfile, SYSTEM_LINEAGE, systemIdentity, systemModelStep, type ProfileOutput } from '../steps/profile.js';
import { scaleSummary } from '../steps/plan.js';
import { incrementalSelection } from '../steps/scope.js';
import { reuseTriage, triageIdentity, triageStep, type TriageOutput } from '../steps/triage.js';
import { supplementSelection } from '../supplement.js';
import { hypothesisModel, supplementScope, threatFromUnderstanding, threatHypothesesOn, threatIdentity, threatModelStep } from '../threat.js';
import { seedRequirementHypotheses } from '../threat-model-audit.js';
import { domainHuntOn } from '../domains.js';
import type { PipelineRun, Stop } from './context.js';

/** Minimal pipeline (one model + one prompt): no triage model, no review, no coverage compare. */
export function minimalPipeline(p: PipelineRun): boolean {
  return !p.s.models.triage && !p.s.stages.adversarialReview && !p.s.tools.coverageCompare;
}

export async function prepare(p: PipelineRun): Promise<Stop | null> {
  const { store, auditId, rt, s } = p;
  // profile: full scene, except the minimal pipeline. Cached by rootHash across audits; a failure only
  // loses the threat-model section.
  // The repositories' profiles are independent and run side by side; the threat models (which read
  // the profiles) start after all of them.
  // when the threat model will run with the profile's model, one system-understanding session per
  // repository writes both (the profile step), and the repository's first threat-model step applies its result.
  const supplementEarly = supplementScope(rt);
  const threatRuns = (threatHypothesesOn(s) || domainHuntOn(rt)) && ['full', 'incremental'].includes(rt.audit.scene) && !backfillScope(rt) && !supplementEarly?.hypothesisIds?.length;
  const firstThreatModel = (crossModels(s, 'threat') ?? [hypothesisModel(rt)])[0]!;
  const profileModel = stageModel(s, 'profile')!;
  const understand = threatRuns && profileModel.provider === firstThreatModel.provider && profileModel.model === firstThreatModel.model;
  const profileRowOf = new Map<string, string>();
  if (rt.audit.scene === 'full' && !minimalPipeline(p)) {
    const profRows = rt.targets.map((repo) => ({ repo, row: ensureStep(store, auditId, {
      kind: 'profile', identity: profileIdentity(rt, repo), input: { repo: repo.name }, model: stageModel(s, 'profile')!, estimateTokens: estimateStep('profile'), maxAttempts: 2,
    }) }));
    const blockedP: StepRow[] = [];
    let interrupted = false;
    await pool(profRows, p.parallel, async ({ repo, row }) => {
      if (interrupted || p.halting() || blockedP.length) return;
      profileRowOf.set(repo.id, row.id);
      if (!reuseProfile(rt, row) && p.llmAllowed()) {
        const pr = await p.step(row, (ctx) => profileStep(rt, ctx, repo, understand ? { understand: firstThreatModel } : {}));
        if (pr === 'interrupted') interrupted = true;
        if (pr === 'blocked_budget') blockedP.push(row);
      } else p.skipUnrun(row);
    });
    if (interrupted || p.halting()) return { kind: 'interrupted' };
    if (blockedP.length) return { kind: 'blocked', rows: blockedP };
    // The profiles above stayed inside their repositories; one system session then writes the calls and trust
    // boundaries between them (a profile step with lineage SYSTEM, cached by the profiles it read). A failure only loses
    // the system section.
    if (rt.targets.length > 1) {
      const outs = profRows.flatMap(({ row }) => {
        const r = getStep(store, row.id);
        return ['succeeded', 'skipped'].includes(r.status) && r.output_ref ? [{ ref: r.output_ref, out: store.artifacts.getJson<ProfileOutput>(r.output_ref) }] : [];
      });
      if (outs.length > 1) {
        const sysRow = ensureStep(store, auditId, {
          kind: 'profile', lineage: SYSTEM_LINEAGE, identity: systemIdentity(rt, outs.map((o) => o.ref)), input: { system: true },
          model: stageModel(s, 'profile')!, estimateTokens: estimateStep('profile'), calibrate: false, maxAttempts: 2,
        });
        if (!reuseProfile(rt, sysRow) && p.llmAllowed()) {
          const so = await p.step(sysRow, (ctx) => systemModelStep(rt, ctx, outs.map((o) => o.out)));
          if (so === 'interrupted' || p.halting()) return { kind: 'interrupted' };
          if (so === 'blocked_budget') return { kind: 'blocked', rows: [sysRow] };
        } else p.skipUnrun(sysRow);
      }
    }
  }
  // threat model: per target repository the list of risk hypotheses the HYP-B* batches verify. Not when a
  // supplement only verifies hypotheses an audit already listed. With cross-checking per model, merged.
  const supplement = supplementScope(rt);
  // risks of the referenced requirement threat models to verify (a person decided to mitigate them).
  if (['full', 'incremental'].includes(rt.audit.scene) && !backfillScope(rt) && !supplement) seedRequirementHypotheses(rt);
  // The domain hunt needs the threat model's risk domains, with or without 风险假设先行.
  if ((threatHypothesesOn(s) || domainHuntOn(rt)) && ['full', 'incremental'].includes(rt.audit.scene) && !backfillScope(rt) && !supplement?.hypothesisIds?.length) {
    const threatModels = crossModels(s, 'threat') ?? [hypothesisModel(rt)];
    const crossThreat = threatModels.length > 1;
    // One threat model per repository × model, side by side.
    const jobs = rt.targets.flatMap((repo) => threatModels.map((m, j) => ({ repo, m, j, row: ensureStep(store, auditId, {
      kind: 'threat-model', identity: threatIdentity(rt, repo, m, crossThreat ? crossKey(threatModels, j) : undefined), input: { repo: repo.name }, lineage: `THREAT${crossThreat ? `-M${j + 1}` : ''}-${repo.name}`, model: m, estimateTokens: estimateStep('threat-model'), maxAttempts: 2,
    }) })));
    const blockedT: StepRow[] = [];
    let stoppedT = false;
    await pool(jobs, p.parallel, async ({ repo, m, row, j }) => {
      if (stoppedT || p.halting() || blockedT.length) return;
      // the understanding session of this audit already wrote this repository's threat model.
      const prof = j === 0 && understand ? profileRowOf.get(repo.id) : undefined;
      const profRow = prof ? getStep(store, prof) : null;
      const understood = profRow?.status === 'succeeded' && !profRow.reused_from && profRow.output_ref
        ? store.artifacts.getJson<ProfileOutput>(profRow.output_ref).understanding : undefined;
      if (understood) {
        const tr = await p.step(row, async (ctx) => threatFromUnderstanding(rt, ctx, repo, m, understood.submissions));
        if (tr === 'interrupted') stoppedT = true;
        if (tr === 'blocked_budget') blockedT.push(row);
      } else if (p.llmAllowed()) {
        const tr = await p.step(row, (ctx) => threatModelStep(rt, ctx, repo, m));
        if (tr === 'interrupted') stoppedT = true;
        if (tr === 'blocked_budget') blockedT.push(row);
      } else p.skipUnrun(row);
    });
    if (stoppedT || p.halting()) return { kind: 'interrupted' };
    if (blockedT.length) return { kind: 'blocked', rows: blockedT };
  }
  return null;
}

/**
 * ⑥ candidates: triage (full), the impact slice computed by scope during planning (incremental,
 * `scope → hunt → report`; a full-scan fallback uses the full candidate set), or the targets of a backfill or supplement.
 */
export async function select(p: PipelineRun): Promise<TriageOutput | Stop> {
  const { store, auditId, rt, s } = p;
  const backfill = backfillScope(rt);
  if (backfill) {
    const statusOf = new Map(store.all<{ target_id: string; status: string }>('SELECT target_id, status FROM coverage_item WHERE audit_id = ?', backfill.auditId).map((i) => [i.target_id, i.status]));
    return gapSelection(rt, new Set(backfill.targets), statusOf);
  }
  const supplement = supplementScope(rt);
  if (supplement) return supplementSelection(rt, supplement);
  if (rt.audit.scene === 'incremental') {
    const impact = rt.impact();
    return impact ? incrementalSelection(rt, impact) : { kind: 'failed', reason: 'impact analysis missing' };
  }
  // Content identity: an unchanged tree, strategy and model reuse an earlier audit's triage.
  let triageRow = ensureStep(store, auditId, {
    kind: 'triage', identity: triageIdentity(rt), required: true, model: s.models.triage,
    // sized like the plan's estimate (15k per 50 candidates), not one flat 15k.
    estimateTokens: s.models.triage ? estimateStep('triage', Math.ceil(Math.min(scaleSummary(rt).candidates, s.limits.maxCandidates) / 50)) : 0,
  });
  // A triage reused earlier (settled `skipped` with an output) counts as done on resume.
  const settled = getStep(store, triageRow.id);
  const done = (settled.status === 'skipped' && !!settled.output_ref) || settled.status === 'succeeded' || reuseTriage(rt, triageRow);
  // After a declined top-up (or with the running time used up) the triage model may not run: the deterministic
  // order below takes over instead of asking for budget again.
  if (!done && s.models.triage && !p.llmAllowed()) p.skipUnrun(triageRow);
  let o: StepOutcome = done ? 'succeeded' : s.models.triage && !p.llmAllowed() ? 'skipped' : await p.step(triageRow, (ctx) => triageStep(rt, ctx));
  if (o === 'interrupted' || p.halting()) return { kind: 'interrupted' };
  if (o === 'blocked_budget') return { kind: 'blocked', rows: [triageRow] };
  if (o !== 'succeeded' && s.models.triage) {
    // The triage model only orders candidates: fall back to the deterministic order instead of
    // failing the audit; the failed model step stays in the trajectory and is superseded by the fallback.
    const failedId = triageRow.id;
    triageRow = ensureStep(store, auditId, { kind: 'triage', identity: { ...triageIdentity(rt), fallback: true }, input: { supersedes: failedId }, required: true, model: null, estimateTokens: 0 });
    rt.event('judgement.made', { kind: 'triage_fallback', reason: 'triage model failed; deterministic candidate order used' }, failedId);
    o = await p.step(triageRow, (ctx) => triageStep(rt, ctx, { heuristicOnly: true }));
    if (o === 'interrupted' || p.halting()) return { kind: 'interrupted' };
  }
  if (o !== 'succeeded') return { kind: 'failed', reason: 'triage failed' };
  return store.artifacts.getJson<TriageOutput>(getStep(store, triageRow.id).output_ref!);
}
