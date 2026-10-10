// The two short pipelines: risk hunt (`hunt-risk (locate + judge) → reconcile → report`) and
// reverification (`verify-fix × N → report`). Their steps are catalog stages run by the orchestrator.
import { stageModel, type StageId } from '@xiezhi/contracts';
import { estimateStep } from '../estimates.js';
import { pool } from '../pool.js';
import { getStep, transitionStep, type StepRow } from '../state.js';
import { ensureStep } from '../step-runner.js';
import { reconcileStep } from '../steps/reconcile.js';
import { basisHash, huntBasis, locateOutput, riskJudgeStep, riskLocateStep, settleRiskTargets, type JudgeOutput } from '../steps/risk.js';
import { applyReverify, reverifyTargets, verifyFixStep, verifyIdentity, type VerifyFixOutput } from '../steps/verify-fix.js';
import { candidateInput, type PipelineRun } from './context.js';
import { finish } from './finish.js';
import type { StageImpl } from './stage.js';

const RISK_IMPLS: StageImpl[] = [
  {
    // hunt-risk (locate): one step over every target repository, keyed by the hunt basis.
    id: 'locate',
    async run(p, bag) {
      const { store, auditId, rt } = p;
      const bh = basisHash(huntBasis(rt));
      const locRow = ensureStep(store, auditId, { kind: 'hunt-risk', identity: { phase: 'locate', roots: rt.targets.map((t) => t.rootHash), basis: bh }, lineage: 'LOCATE', required: true, maxAttempts: 1 });
      const o = await p.step(locRow, (ctx) => riskLocateStep(rt, ctx));
      if (o === 'interrupted') return p.interrupted();
      const located = getStep(store, locRow.id).output_ref;
      if (!located) return finish(p, []);
      bag.risk = { basis: bh, located: locateOutput(rt, located), judges: [] };
      return null;
    },
  },
  {
    // hunt-risk (judge): one step per repository with its located candidates.
    id: 'judge',
    async run(p, bag) {
      const { store, auditId, rt, s } = p;
      const risk = bag.risk!;
      const loc = risk.located;
      risk.judges = rt.targets.map((t) => {
        const cands = loc.candidates.filter((c) => c.repo === t.name);
        return {
          repo: t.name, cands,
          row: ensureStep(store, auditId, {
            kind: 'hunt-risk', identity: { phase: 'judge', repo: t.id, root: t.rootHash, basis: risk.basis }, lineage: `JUDGE-${t.name}`, input: { repo: t.name, ...candidateInput(cands) },
            ...(cands.length ? { model: stageModel(s, 'verify')!, estimateTokens: estimateStep('hunt', cands.length) } : { estimateTokens: 0 }),
          }),
        };
      });
      const blockedR: StepRow[] = [];
      await pool(risk.judges, p.parallel, async (j) => {
        if (p.halting() || blockedR.length) return;
        if (j.cands.length && !p.llmAllowed()) {
          p.skipUnrun(j.row);
          return;
        }
        const r = await p.step(j.row, (ctx) => riskJudgeStep(rt, j.repo, j.cands, loc.checks, j.row.lineage_id ?? `JUDGE-${j.repo}`, ctx));
        if (r === 'blocked_budget') blockedR.push(j.row);
      });
      if (p.halting()) return p.interrupted();
      if (blockedR.length) return p.blocked(blockedR);
      return null;
    },
  },
  {
    // reconcile, then the targets the judges settled.
    id: 'reconcile',
    async run(p, bag) {
      const { store, auditId, rt } = p;
      const recRow = ensureStep(store, auditId, { kind: 'reconcile', identity: { audit: auditId }, required: true, model: null, estimateTokens: 0 });
      const o = await p.step(recRow, (ctx) => reconcileStep(rt, ctx));
      if (o === 'interrupted') return p.interrupted();
      const outputs = bag.risk!.judges.map((j) => getStep(store, j.row.id)).filter((x) => x.status === 'succeeded' && x.output_ref).map((x) => store.artifacts.getJson<JudgeOutput>(x.output_ref!));
      settleRiskTargets(rt, outputs);
      return null;
    },
  },
  { id: 'finish', run: (p) => finish(p, []) },
];

/** Risk hunt: `hunt-risk (locate + judge) → reconcile → report` (stages of the catalog). */
export const RISK_HUNT_STAGES: ReadonlyMap<StageId, StageImpl> = new Map(RISK_IMPLS.map((x) => [x.id, x]));

const REVERIFY_IMPLS: StageImpl[] = [
  {
    // Reverification: one targeted session per vulnerability.
    id: 'verify',
    async run(p) {
      const { store, auditId, rt, s } = p;
      const rows = reverifyTargets(rt).map((vid) => ensureStep(store, auditId, {
        kind: 'verify-fix', identity: verifyIdentity(rt, vid), input: { vulnId: vid }, model: stageModel(s, 'verify')!, estimateTokens: estimateStep('verify-fix'),
      }));
      const blockedV: StepRow[] = [];
      await pool(rows, p.parallel, async (row) => {
        if (p.halting() || blockedV.length) return;
        const vid = (JSON.parse(row.input) as { vulnId: string }).vulnId;
        if (reuseVerdict(p, row)) return;
        if (!p.llmAllowed()) {
          p.skipUnrun(row);
          return;
        }
        const r = await p.step(row, (ctx) => verifyFixStep(rt, vid, ctx));
        if (r === 'blocked_budget') blockedV.push(row);
      });
      if (p.halting()) return p.interrupted();
      if (blockedV.length) return p.blocked(p.unfinished('verify-fix'));
      return null;
    },
  },
  { id: 'finish', run: (p) => finish(p, []) },
];

/** Reverification: `verify-fix × N → report`. */
export const REVERIFY_STAGES: ReadonlyMap<StageId, StageImpl> = new Map(REVERIFY_IMPLS.map((x) => [x.id, x]));

/**
 * Reuse a verdict for the same vulnerability on the same code (verify-fix is cacheable by
 * (vulnId, new rootHash)): the step is `skipped` with `reused_from`, and the write-back is applied
 * for this audit.
 */
function reuseVerdict(p: PipelineRun, row: StepRow): boolean {
  const { store, rt } = p;
  const hit = store.get<{ id: string; output_ref: string }>(
    `SELECT id, output_ref FROM step WHERE kind = 'verify-fix' AND idempotency_key = ? AND audit_id != ? AND status IN ('succeeded','skipped') AND output_ref IS NOT NULL
     ORDER BY created_at DESC LIMIT 1`, row.idempotency_key, rt.auditId);
  if (!hit || !['pending', 'ready', 'interrupted'].includes(getStep(store, row.id).status)) return false;
  const out = store.artifacts.getJson<VerifyFixOutput>(hit.output_ref);
  store.tx(() => {
    transitionStep(store, row.id, 'skipped', { output_ref: hit.output_ref, reused_from: hit.id, error_summary: 'reused verdict for the same code' }, 'cache hit');
    applyReverify(rt, out, row.id, hit.output_ref);
  });
  return true;
}
