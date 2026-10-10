// Stage implementations of full and incremental audits: one entry per catalog stage,
// each calling the stage function it always called. The order and the parallel group come from the catalog
// (contracts/src/stages.ts).
import type { StageId } from '@xiezhi/contracts';
import { USER_SKIPPED_MARK, listSteps } from '../state.js';
import { backfillScope } from '../steps/coverage-gap.js';
import { applySurface, withSurface } from '../surface.js';
import { applyRiskDecisions } from '../threat-model-audit.js';
import { supplementScope } from '../threat.js';
import { projectGateways, syncGatewayFacts } from '../gateway.js';
import { domainHuntOn } from '../domains.js';
import { checklistStage } from './checklist.js';
import { DomainStage } from './domains.js';
import { externalStage } from './external.js';
import { finish } from './finish.js';
import { HuntStage } from './hunts.js';
import { recheckStage } from './recheck.js';
import { adversarialReview, explore, publish, reconcile } from './review.js';
import { prepare, select } from './select.js';
import type { StageBag, StageImpl } from './stage.js';

const need = <K extends keyof StageBag>(bag: StageBag, k: K, stage: StageId): NonNullable<StageBag[K]> => {
  const v = bag[k];
  if (!v) throw new Error(`stage ${stage} needs ${k}, which no earlier stage produced`);
  return v as NonNullable<StageBag[K]>;
};

const IMPLS: StageImpl[] = [
  {
    // the gateways' authentication, read from their configuration, as verified facts of the project.
    id: 'gateway',
    async run({ rt }) {
      const gateways = projectGateways(rt.store, rt.audit.project_id, rt.views);
      if (gateways.length) {
        const r = syncGatewayFacts(rt.store, rt.audit.project_id, gateways);
        rt.event('judgement.made', { kind: 'gateway_auth', gateways: gateways.map((g) => g.gateway), routes: gateways.reduce((n, g) => n + g.report.routes.length, 0), global: gateways.reduce((n, g) => n + g.report.global.length, 0), facts_added: r.added, facts_updated: r.updated });
      }
      return null;
    },
  },
  // ④⑤ profile / threat model alongside ⑥ candidate selection (group `prepare`).
  { id: 'understand', run: (p) => prepare(p) },
  {
    id: 'triage',
    async run(p, bag) {
      const selected = await select(p);
      if ('kind' in selected) return selected;
      bag.selected = selected;
      return null;
    },
  },
  {
    // The entry points and sinks the profile added join the index and the ledger, and get batches
    // of their own after the triaged ones (triage ran alongside the profile and did not see them).
    id: 'surface',
    async run(p, bag) {
      applySurface(p.rt);
      bag.triage = withSurface(p.rt, need(bag, 'selected', 'surface'));
      return null;
    },
  },
  {
    // ⑦ — the lead dispatches the domain subtasks (DomainStage); a supplement for the
    // domains a person added after the source audit's expert phase; without them the generalist hunt.
    id: 'lead',
    async run(p, bag) {
      const triage = need(bag, 'triage', 'lead');
      const sup = supplementScope(p.rt);
      if (sup?.kind === 'domains') {
        const stop = await new DomainStage(p, triage, { supplement: { auditId: sup.auditId, domainIds: sup.domainIds ?? [] } }).run();
        if (stop) return stop;
        bag.hunts = new HuntStage(p, triage, { afterExperts: true });
      } else if (domainHuntOn(p.rt)) {
        const stop = await new DomainStage(p, triage).run();
        if (stop) return stop;
        bag.hunts = new HuntStage(p, triage, { afterExperts: true });
      } else bag.hunts = new HuntStage(p, triage);
      return null;
    },
  },
  // ⑦ generalist batches / ⑧ hypothesis verification (after the experts: only the HYP-R retries).
  { id: 'hunt', run: (_p, bag) => need(bag, 'hunts', 'hunt').run() },
  // imported external scanner results, settled after the exploration (duplicates of its findings).
  { id: 'external', run: (p) => externalStage(p) },
  // the checklist check, after the exploration and before ⑨.
  { id: 'checklist', run: (p) => checklistStage(p) },
  // independent recheck of "no issue" conclusions; reopened units go to ⑨.
  { id: 'recheck', run: (p, bag) => recheckStage(p, need(bag, 'triage', 'recheck').candidates) },
  // ⑨ coverage completion (every uncovered unit, highest triage score first).
  { id: 'gap', run: (_p, bag) => need(bag, 'hunts', 'gap').complete() },
  {
    // ⑩ reconcile: without a model allowed, the merge model is dropped (deterministic grouping only).
    id: 'reconcile',
    async run(p) {
      if (p.halting()) return p.interrupted();
      if (listSteps(p.store, p.auditId).some((x) => x.status === 'skipped' && x.error_summary === USER_SKIPPED_MARK)) p.carried.add('USER_SKIPPED');
      if (!p.llmAllowed() && p.s.models.merge) p.rt.strategy = { ...p.rt.strategy, models: { ...p.rt.strategy.models, merge: null } };
      return reconcile(p);
    },
  },
  {
    // ⑪ deep exploration; its findings join the set (F-numbers continue) and are reconciled again.
    id: 'explore',
    async run(p, bag) {
      const stop = await explore(p, need(bag, 'triage', 'explore'), need(bag, 'hunts', 'explore').byId, !!backfillScope(p.rt));
      if (stop) return stop;
      if (p.store.get('SELECT 1 FROM finding WHERE audit_id = ? AND state = \'submitted\' LIMIT 1', p.auditId)) return reconcile(p, 'explore');
      return null;
    },
  },
  // ⑫ adversarial review.
  { id: 'review', run: (p) => adversarialReview(p) },
  {
    id: 'publish',
    async run(p) {
      const stop = await publish(p);
      if (stop) return stop;
      // new vulnerabilities related to a requirement risk a person accepted or ruled out get that decision.
      applyRiskDecisions(p.rt);
      return null;
    },
  },
  {
    // ⑬⑭ report and completion gate.
    id: 'finish',
    async run(p, bag) {
      const hunts = need(bag, 'hunts', 'finish');
      const overflow = need(bag, 'triage', 'finish').overflow;
      if (!hunts.gapRan) return finish(p, overflow);
      // Over-limit candidates the gap round concluded are no longer a gap.
      const concluded = new Set(p.store.all<{ target_id: string }>(`SELECT target_id FROM coverage_item WHERE audit_id = ? AND status = 'concluded'`, p.auditId).map((r) => r.target_id));
      return finish(p, overflow.filter((id) => !concluded.has(id)));
    },
  },
];

/** Implementations of the full and incremental audit stages, by catalog id. */
export const FULL_STAGES: ReadonlyMap<StageId, StageImpl> = new Map(IMPLS.map((s) => [s.id, s]));
