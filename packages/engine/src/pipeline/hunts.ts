// ⑦ bottom-up hunt, ⑧ verification of the risk hypotheses and ⑨ coverage completion.
// Hunt steps run in a bounded pool; a batch that overflowed the context is split and retried.
import { crossKey, crossModels, type ModelRef } from '@xiezhi/contracts';
import { fromJson } from '@xiezhi/store';
import { listHypotheses, type HypothesisRow } from '../business.js';
import { estimateStep } from '../estimates.js';
import { finalizeCoverage } from '../coverage.js';
import { pool } from '../pool.js';
import { getStep, listSteps, NOT_STARTED, transitionStep, type StepRow } from '../state.js';
import { ensureStep, type StepOutcome } from '../step-runner.js';
import { backfillScope, gapPreface, gapSelection } from '../steps/coverage-gap.js';
import { huntStep } from '../steps/hunt.js';
import type { Candidate, TriageOutput } from '../steps/triage.js';
import { supplementScope, hypothesisBatches, hypothesisModel, priorConclusions, threatHypothesesOn, verificationTargets } from '../threat.js';
import { requirementRisksOn } from '../threat-model-audit.js';
import { gapFillOn } from '../domains.js';
import { candidateInput, type PipelineRun, type RunResult } from './context.js';

/** One hunt step to run: a candidate batch, or a batch of hypotheses (`hyp`), for one model. */
interface HuntJob { batch: string[]; model: ModelRef; modelIndex: number; lineage: string; logic?: boolean; hyp?: boolean }

export class HuntStage {
  /** `coverage-gap` in a backfill audit, else `hunt`. */
  readonly kind: 'hunt' | 'coverage-gap';
  readonly byId: Map<string, Candidate>;
  private readonly backfill: ReturnType<typeof backfillScope>;
  /** Multi-model cross-checking (per stage): every model hunts the same batches in its own sessions. */
  private readonly huntModels: ModelRef[];
  private readonly multi: boolean;
  private readonly verifyModels: ModelRef[];
  private readonly crossVerify: boolean;
  private readonly hypById = new Map<string, HypothesisRow>();
  private readonly jobs: HuntJob[];
  private readonly rows: StepRow[];
  /** Steps refused for budget: the stage stops dispatching once one is. */
  private readonly blockedRows: StepRow[] = [];
  /** A coverage-completion round ran (⑨): over-limit candidates it concluded are no longer a gap. */
  gapRan = false;

  /**
   * After the domain experts — they hunted and verified the hypotheses, so this stage has no
   * hunt or ⑧ batches of its own; it only runs ⑨ and the HYP-R retry of what the experts left without a verdict.
   */
  private readonly afterExperts: boolean;

  constructor(private readonly p: PipelineRun, triage: TriageOutput, opts: { afterExperts?: boolean } = {}) {
    this.afterExperts = !!opts.afterExperts;
    const { s, rt } = p;
    this.backfill = backfillScope(rt);
    this.kind = this.backfill ? 'coverage-gap' : 'hunt';
    this.byId = new Map(triage.candidates.map((c) => [c.id, c]));
    this.huntModels = (!this.backfill && crossModels(s, 'hunt')) || [s.models.audit];
    this.multi = this.huntModels.length > 1;
    this.jobs = this.afterExperts ? [] : this.huntModels.flatMap((m, j) => triage.batches.map((batch, i) => ({ batch, model: m, modelIndex: j, lineage: `${this.backfill ? 'GAP' : 'HUNT'}${this.multi ? `-M${j + 1}` : ''}-B${i + 1}` })));
    // Risk-hypothesis verification: the threat model's hypotheses in batches with the 风险假设 stage's model;
    // with cross-checking every verify model checks every batch and the hypothesis keeps each model's vote.
    this.verifyModels = crossModels(s, 'verify') ?? [hypothesisModel(rt)];
    this.crossVerify = this.verifyModels.length > 1;
    if (!this.backfill && !this.afterExperts && (threatHypothesesOn(s) || requirementRisksOn(rt))) {
      const targets = verificationTargets(rt);
      for (const h of targets) this.hypById.set(h.id, h);
      const batches = hypothesisBatches(targets);
      this.verifyModels.forEach((m, j) => batches.forEach((batch, i) => this.jobs.push({ batch, model: m, modelIndex: j, lineage: `HYP${this.crossVerify ? `-M${j + 1}` : ''}-B${i + 1}`, hyp: true })));
    }
    this.rows = this.jobs.map((job) => ensureStep(p.store, p.auditId, {
      kind: this.kind, identity: this.identity(job), lineage: job.lineage, model: job.model,
      input: this.jobInput(job),
      estimateTokens: estimateStep('hunt', job.batch.length),
    }));
  }

  /** The job's cross-check slot (`provider/model`, `#n` when the group repeats a model). */
  private slotKey(job: Pick<HuntJob, 'hyp' | 'modelIndex'>): string {
    return crossKey(job.hyp ? this.verifyModels : this.huntModels, job.modelIndex);
  }

  private identity(job: HuntJob): Record<string, unknown> {
    if (job.hyp) return this.crossVerify ? { hyp: job.batch, model: this.slotKey(job) } : { hyp: job.batch };
    if (job.logic) return this.multi ? { logic: job.batch, model: this.slotKey(job) } : { logic: job.batch };
    return this.multi ? { batch: job.batch, model: this.slotKey(job) } : { batch: job.batch };
  }

  /** Hypotheses of a batch still to verify (re-read: a reviewer may set some aside while the audit runs). */
  private hypRows(ids: string[]): HypothesisRow[] {
    const fresh = new Map(listHypotheses(this.p.store, [...new Set(ids.map((id) => this.hypById.get(id)?.audit_id).filter((x): x is string => !!x))]).map((h) => [h.id, h]));
    return ids.map((id) => fresh.get(id)).filter((h): h is HypothesisRow => !!h && h.status !== 'dismissed' && h.status !== 'converted');
  }

  private jobInput(job: HuntJob) {
    return job.hyp
      ? candidateInput(job.batch.map((id) => this.hypById.get(id)).filter((h): h is HypothesisRow => !!h).map((h) => ({ id: h.id, kind: 'hypothesis', repo: '', path: '', line: 0, label: `[hyp:${h.category}] ${h.statement}`, ...(h.basis ? { reason: h.basis } : {}) })))
      : candidateInput(job.batch.map((id) => this.byId.get(id)).filter((c): c is Candidate => !!c));
  }

  private async runHunt(row: StepRow, job: HuntJob): Promise<StepOutcome> {
    const { p } = this;
    const { rt } = p;
    const batch = job.hyp ? [] : job.batch.map((id) => this.byId.get(id)!).filter(Boolean);
    // hypotheses a reviewer set aside while the audit ran are not verified; an empty batch is skipped.
    if (job.hyp && !this.hypRows(job.batch).length && NOT_STARTED.includes(getStep(p.store, row.id).status)) {
      transitionStep(p.store, row.id, 'skipped', {}, 'all hypotheses of the batch were set aside by a reviewer');
      return 'skipped';
    }
    const r = await p.step(row, (ctx) => {
      if (job.hyp) {
        // ⑧ reuses what ⑦ concluded on the same places; per model under cross-checking.
        const hs = this.hypRows(job.batch);
        const slot = this.slotKey(job);
        const huntCrossed = this.multi && this.huntModels.some((_, j) => crossKey(this.huntModels, j) === slot);
        return huntStep(rt, batch, row.lineage_id ?? 'HYP', ctx, {
          hypotheses: hs, prior: priorConclusions(rt, hs, huntCrossed ? slot : undefined),
          ...(this.crossVerify ? { model: job.model, modelKey: slot, statePrefix: `HYP-M${job.modelIndex + 1}-` } : { stageModel: job.model }),
        });
      }
      return huntStep(rt, batch, row.lineage_id ?? 'HUNT', ctx,
        this.backfill ? { kind: 'coverage-gap', preface: gapPreface(rt, this.backfill.auditId, batch) }
          : this.multi ? { model: job.model, modelKey: this.slotKey(job), statePrefix: `HUNT-M${job.modelIndex + 1}-` } : {});
    });
    if (r === 'blocked_budget') this.blockedRows.push(row);
    return r;
  }

  /**
   * One phase of hunt steps in the bounded pool, with the context-overflow retry: a batch that
   * did not fit is split in halves and retried, down to single candidates. The failed step stays in the trajectory;
   * the gate ignores it once every part succeeded.
   */
  private async runPhase(rows: StepRow[], jobs: HuntJob[]): Promise<void> {
    const { p } = this;
    await pool(rows, p.parallel, async (row) => {
      if (p.halting() || this.blockedRows.length) return;
      if (getStep(p.store, row.id).status === 'skipped') return;
      if (!p.llmAllowed()) {
        p.skipUnrun(row);
        return;
      }
      await this.runHunt(row, jobs[rows.indexOf(row)]!);
    });
    let overflowed = rows.map((row, i) => ({ row, job: jobs[i]! }));
    for (let depth = 0; depth < 6 && !p.halting() && !this.blockedRows.length; depth++) {
      overflowed = overflowed.filter(({ row }) => { const st = getStep(p.store, row.id); return st.status === 'failed' && st.error_class === 'CONTEXT_OVERFLOW'; });
      const parts = overflowed.flatMap(({ row, job }) => {
        const ids = job.batch;
        if (ids.length < 2) return [];
        const mid = Math.ceil(ids.length / 2);
        return [ids.slice(0, mid), ids.slice(mid)].map((half, k) => ({
          job: { ...job, batch: half },
          row: ensureStep(p.store, p.auditId, {
            kind: this.kind, identity: job.hyp ? { hyp: half, split: row.id, ...(this.crossVerify ? { model: this.slotKey(job) } : {}) } : this.multi ? { batch: half, model: this.slotKey(job), split: row.id } : { batch: half, split: row.id },
            input: { splitFrom: row.id }, lineage: `${row.lineage_id ?? 'HUNT'}-S${k + 1}`, model: job.model, estimateTokens: estimateStep('hunt', half.length),
          }),
        }));
      });
      if (!parts.length) break;
      p.rt.event('judgement.made', { kind: 'batch_split', reason: 'context overflow', parts: parts.length }, overflowed[0]!.row.id);
      await pool(parts, p.parallel, async ({ row, job }) => {
        if (p.halting() || this.blockedRows.length || !p.llmAllowed()) return;
        await this.runHunt(row, job);
      });
      overflowed = parts;
    }
  }

  /** What a stopped phase settles to, or null to go on. */
  private stopped(): RunResult | null {
    if (this.p.halting()) return this.p.interrupted();
    if (this.blockedRows.length) return this.p.blocked(this.p.unfinished(this.kind));
    return null;
  }

  /**
   * ⑦ bottom-up hunt (and the per-entry logic batches), then ⑧ top-down verification of the hypotheses, which
   * reuses ⑦'s conclusions: the verification batches start only after ⑦ has finished.
   */
  async run(): Promise<RunResult | null> {
    for (const hyp of [false, true]) {
      const items = this.jobs.map((job, i) => ({ job, row: this.rows[i]! })).filter((x) => !!x.job.hyp === hyp);
      if (!items.length) continue;
      await this.runPhase(items.map((x) => x.row), items.map((x) => x.job));
      const stop = this.stopped();
      if (stop) return stop;
    }
    return null;
  }

  /**
   * ⑨ coverage completion: breadth closes before reconcile — the uncovered candidates
   * (`coverageTarget.onShortfall = gap_fill`) and the risk hypotheses still unverified (a failed batch, or added by
   * a reviewer while the audit ran).
   */
  async complete(): Promise<RunResult | null> {
    const { p } = this;
    const { store, auditId, rt, s } = p;
    if (!this.backfill && !supplementScope(rt) && s.tools.coverageCompare && gapFillOn(rt) && p.llmAllowed()) {
      const last = listSteps(store, auditId).at(-1)!;
      finalizeCoverage(rt, last.id);
      const pending = store.all<{ target_id: string; status: string }>(`SELECT target_id, status FROM coverage_item WHERE audit_id = ? AND status NOT IN ('concluded','excluded')`, auditId);
      if (pending.length) {
        this.gapRan = true;
        // highest triage score first, so a budget stop leaves the least promising open.
        const gap = gapSelection(rt, new Set(pending.map((x) => x.target_id)), new Map(pending.map((x) => [x.target_id, x.status])), this.byId);
        const gapById = new Map(gap.candidates.map((c) => [c.id, c]));
        const gapRows = gap.batches.map((batch, i) => ensureStep(store, auditId, {
          kind: 'coverage-gap', identity: { gap: batch }, lineage: `GAP-B${i + 1}`, model: s.models.audit, estimateTokens: estimateStep('hunt', batch.length),
        }));
        const blockedGap: StepRow[] = [];
        await pool(gapRows, p.parallel, async (row) => {
          if (p.halting() || blockedGap.length) return;
          if (!p.llmAllowed()) {
            p.skipUnrun(row);
            return;
          }
          const batch = (gap.batches[gapRows.indexOf(row)] ?? []).map((id) => gapById.get(id)!).filter(Boolean);
          const r = await p.step(row, (ctx) => huntStep(rt, batch, row.lineage_id ?? 'GAP', ctx, { kind: 'coverage-gap', preface: gapPreface(rt, auditId, batch) }));
          if (r === 'blocked_budget') blockedGap.push(row);
        });
        if (p.halting()) return p.interrupted();
        if (blockedGap.length) return p.blocked(p.unfinished('coverage-gap'));
      }
    }
    // HYP-R: after the experts also for linked requirement risks — they no longer get ⑧ batches of their own.
    if (!this.backfill && (threatHypothesesOn(s) || (this.afterExperts && requirementRisksOn(rt))) && p.llmAllowed()) {
      // Each verification model retries the hypotheses it has not voted on yet — with cross-checking, one
      // model's vote does not take the hypothesis out of `proposed` for the others. The current rows are read once
      // per audit instead of once per hypothesis.
      const targets = verificationTargets(rt);
      // first the HYP-R batches an earlier pass left unfinished (a budget pause, a restart) — resumed where
      // they stopped. They were re-batched before: the stopped one stayed “interrupted” with its context thrown away
      // and a new batch reused its number.
      const series = /^HYP-R(-M\d+)?-B\d+$/;
      const leftover = listSteps(store, auditId).filter((r) => r.kind === this.kind && series.test(r.lineage_id ?? '') && NOT_STARTED.includes(r.status));
      if (leftover.length) {
        for (const h of targets) this.hypById.set(h.id, h);
        const jobs = leftover.map((r): HuntJob => {
          const j = this.crossVerify ? Number(/-M(\d+)-/.exec(r.lineage_id!)?.[1] ?? 1) - 1 : 0;
          return { batch: fromJson<{ batch?: string[] }>(r.input, {}).batch ?? [], model: this.verifyModels[j] ?? this.verifyModels[0]!, modelIndex: j, lineage: r.lineage_id!, hyp: true };
        });
        await this.runPhase(leftover, jobs);
        const stop = this.stopped();
        if (stop) return stop;
      }
      const rows = new Map(listHypotheses(store, [...new Set(targets.map((h) => h.audit_id))]).map((x) => [x.id, x as HypothesisRow & { votes?: string }]));
      const owed = (j: number) => targets.filter((h) => {
        const row = rows.get(h.id);
        // Without cross-checking there is one vote per hypothesis: only an unanswered one is retried.
        if (!this.crossVerify) return row?.status === 'proposed';
        if (!row || !['proposed', 'open', 'refuted'].includes(row.status)) return false;
        return !fromJson<{ model: string }[]>(row.votes, []).some((v) => v.model === this.slotKey({ hyp: true, modelIndex: j }));
      });
      const perModel = this.verifyModels.map((_, j) => owed(j));
      if (perModel.some((l) => l.length)) {
        for (const h of perModel.flat()) this.hypById.set(h.id, h);
        // Numbers continue after the batches of an earlier pass (two steps were both “HYP-R-M2-B2”).
        const taken = (j: number) => listSteps(store, auditId).filter((r) => r.kind === this.kind && (r.lineage_id ?? '').startsWith(`HYP-R${this.crossVerify ? `-M${j + 1}` : ''}-B`)).length;
        const retryJobs = this.verifyModels.flatMap((m, j) => { const base = taken(j); return hypothesisBatches(perModel[j]!).map((batch, i) => ({ batch, model: m, modelIndex: j, lineage: `HYP-R${this.crossVerify ? `-M${j + 1}` : ''}-B${base + i + 1}`, hyp: true })); });
        const retryRows = retryJobs.map((job) => ensureStep(store, auditId, {
          kind: this.kind, identity: { hyp: job.batch, retry: true, ...(this.crossVerify ? { model: this.slotKey(job) } : {}) }, lineage: job.lineage, model: job.model,
          input: this.jobInput(job), estimateTokens: estimateStep('hunt', job.batch.length),
        }));
        await this.runPhase(retryRows, retryJobs);
        const stop = this.stopped();
        if (stop) return stop;
      }
    }
    return null;
  }
}
