// ⑦ as 多领域专家漏洞狩猎: one expert per risk domain (× hunt model) explores on its own for up to
// three rounds within an equal share of the expert pool, and gives the verdicts on the threat-model hypotheses of its
// categories (⑧ merged into the experts). What the experts leave uncovered goes to ⑨.
// the plan is read again before every round, so a person's edits reach the running stage — an added
// domain gets an expert, a removed one gets no further round, added focus shows from the next round on.
import { crossKey, crossModels, type ModelRef } from '@xiezhi/contracts';
import { fromJson } from '@xiezhi/store';
import type { HypothesisRow } from '../business.js';
import { EXPERTS_DONE } from '../domain-plan.js';
import {
  DOMAIN_ROUNDS, HYPOTHESES_PER_ROUND, NEXT_ROUND_MIN_LEFT, domainExpertStep, domainGaps, domainLeads, domainUsed, expertPool, gapsEmpty, planDomains, planDomainsOf,
  type DomainGaps, type DomainOutput, type OpenLead, type PlannedDomain,
} from '../domains.js';
import { pool } from '../pool.js';
import { getStep, NOT_STARTED, type StepRow } from '../state.js';
import { accessChecks, type AccessCheck } from '../access.js';
import { dependencyCheck, type DependencyHit } from '../dependencies.js';
import { ensureStep } from '../step-runner.js';
import type { Candidate, TriageOutput } from '../steps/triage.js';
import { priorConclusions, supplementScope, threatHypothesesOn, verificationTargets } from '../threat.js';
import { requirementRisksOn } from '../threat-model-audit.js';
import type { PipelineRun, RunResult } from './context.js';
import { LEAD_CONTEXT_CAP, MAX_LEAD_SESSIONS, leadStep, type LeadOutput, type LeadTask } from '../lead.js';
import { obligationSummary } from '../obligations.js';
import { P } from '@xiezhi/knowledge';

/** subtasks one domain may get from the leads of one model (the cost bound the fixed rounds had). */
const MAX_SUBTASKS = 6;

/** One expert: a domain explored by one model, round after round. */
interface Expert {
  domain: PlannedDomain; model: ModelRef; modelIndex: number; stepIds: string[]; previous?: { openLeads: OpenLead[]; findings: string[]; gaps?: DomainGaps }; done: boolean;
  /** what the last round left (for the lead's ledger and the floor). */
  lastGaps?: DomainGaps; lastOut?: DomainOutput | null;
  /**
   * The round in flight for this expert, if any: a lead may send two dispatch calls in one reply that
   * both name a domain; the later one waits, so its round is the next one rather than the same step run twice.
   */
  busy?: Promise<unknown>;
}

/** Smallest share a domain gets, so a tiny budget still lets every expert start. */
const MIN_DOMAIN_CAP = 50_000;
/** Passes over the experts at most: every domain's rounds, plus room for domains added while the stage runs. */
const MAX_PASSES = DOMAIN_ROUNDS * 3;

export interface DomainStageOptions {
  /**
   * a supplement (追加执行) for domains added after the source audit's expert phase — the plan is the source
   * audit's and only these domain ids run; no plan event, no hypotheses, no “experts done” mark.
   */
  supplement?: { auditId: string; domainIds: string[] };
}

export class DomainStage {
  domains: PlannedDomain[];
  private leads: Map<string, Candidate[]>;
  private readonly candidates: Candidate[];
  /** access-policy differences, computed once from the threat models (deterministic). */
  private readonly access: AccessCheck[];
  private readonly models: ModelRef[];
  private readonly multi: boolean;
  private readonly blockedRows: StepRow[] = [];

  constructor(private readonly p: PipelineRun, triage: TriageOutput, private readonly opts: DomainStageOptions = {}) {
    const { s } = p;
    // incremental change candidates (changed files, variant hits) are leads too.
    this.candidates = triage.candidates.filter((c) => c.kind === 'entry' || c.kind === 'sink' || c.kind === 'change');
    this.models = crossModels(s, 'hunt') ?? [s.models.audit];
    this.multi = this.models.length > 1;
    this.domains = [];
    this.leads = new Map();
    this.access = opts.supplement ? [] : accessChecks(p.rt);
    this.refresh();
    if (this.access.length && !p.store.listEvents(p.auditId, 0, ['judgement.made']).some((e) => e.payload.kind === 'access_policy')) {
      p.rt.event('judgement.made', { kind: 'access_policy', checks: this.access.map((c) => ({ entryId: c.entryId, entryKey: c.entryKey, level: c.level, ...(c.role ? { role: c.role } : {}), category: c.category, scope: c.scope, why: c.why })) });
    }
  }

  /** the domain that gets the OSV hits — the first covering deserialization, else “other”, else the first. */
  private dependencyOwner(): string | undefined {
    const r = this.runnable();
    return (r.find((d) => d.categories.includes('deserialization')) ?? r.find((d) => d.categories.includes('other')) ?? r[0])?.id;
  }

  /** the first runnable domain covering a check's category owns it. */
  private accessFor(domainId: string): AccessCheck[] {
    const owner = (cat: string) => this.runnable().find((d) => d.categories.includes(cat))?.id;
    const open = new Set(this.p.store.all<{ target_id: string }>(`SELECT target_id FROM coverage_item WHERE audit_id = ? AND status != 'concluded' AND status != 'excluded'`, this.p.auditId).map((r) => r.target_id));
    return this.access.filter((c) => owner(c.category) === domainId && open.has(c.entryId));
  }

  /** Read the plan (with a person's edits) and route the leads again; deterministic for the same plan. */
  private refresh(): void {
    const { rt } = this.p;
    const sup = this.opts.supplement;
    this.domains = sup ? planDomainsOf({ store: rt.store, auditId: sup.auditId, repos: rt.repos }) : planDomains(rt);
    this.leads = domainLeads(this.domains.filter((d) => !d.removed), this.candidates, rt.indexes);
    // an owner's access-check entries lead its list, so the gap report asks for them first.
    for (const d of this.domains) {
      const ids = new Set(this.access.filter((c) => d.categories.includes(c.category)).map((c) => c.entryId));
      if (!ids.size) continue;
      const first = this.candidates.filter((c) => ids.has(c.id));
      this.leads.set(d.id, [...first, ...(this.leads.get(d.id) ?? []).filter((c) => !ids.has(c.id))]);
    }
  }

  /** Domains whose experts run in this audit: not removed; late ones only in their supplement. */
  private runnable(): PlannedDomain[] {
    const sup = this.opts.supplement;
    return this.domains.filter((d) => !d.removed && (sup ? sup.domainIds.includes(d.id) : !d.late));
  }

  /** The expert's cross-check slot (`provider/model`, `#n` when the group repeats a model). */
  private slotKey(e: Pick<Expert, 'modelIndex'>): string {
    return crossKey(this.models, e.modelIndex);
  }

  /** Rebuild each expert's finished rounds from its steps, then run again the round a stop left unfinished. */
  private async resumeRounds(experts: Map<string, Expert>): Promise<RunResult | null> {
    const { store, auditId } = this.p;
    const unfinished: Expert[] = [];
    for (const e of experts.values()) {
      if (e.stepIds.length) continue;
      for (let round = 1; round <= MAX_SUBTASKS; round++) {
        const row = store.get<{ id: string; status: string }>('SELECT id, status FROM step WHERE audit_id = ? AND lineage_id = ?', auditId, this.lineage(e, round));
        if (!row) break;
        if (NOT_STARTED.includes(row.status)) { unfinished.push(e); break; }
        e.stepIds.push(row.id);
      }
    }
    return unfinished.length ? this.runRounds(unfinished.map((e) => ({ e }))) : null;
  }

  private lineage(e: Expert, round: number): string {
    return `DOM${this.multi ? `-M${e.modelIndex + 1}` : ''}-${e.domain.id}-R${round}`;
  }

  /** The plan, recorded once per audit (a resumed run plans the same domains). */
  private recordPlan(): void {
    const { rt, store, auditId } = this.p;
    if (this.opts.supplement) return;
    if (store.listEvents(auditId, 0, ['judgement.made']).some((e) => e.payload.kind === 'domain_plan')) return;
    rt.event('judgement.made', {
      kind: 'domain_plan', source: this.domains[0]?.source ?? 'fallback',
      domains: this.domains.map((d) => ({ id: d.id, name: d.name, categories: d.categories, mechanisms: d.mechanisms.length, leads: d.leads.length, indexLeads: this.leads.get(d.id)?.length ?? 0, source: d.source })),
    });
  }

  /**
   * The hypotheses an expert still has to answer: the audit's threat-model hypotheses (and linked
   * requirement risks) whose category the domain owns — the first runnable domain covering it, so each goes to one
   * expert per model — that a reviewer has not set aside and this model has not voted on yet. Priority order, at most
   * HYPOTHESES_PER_ROUND; the rest wait for the next round, and what is left after the last goes to HYP-R.
   */
  private pendingHypotheses(e: Expert): HypothesisRow[] {
    const { rt, s } = this.p;
    if (this.opts.supplement || supplementScope(rt)) return [];
    if (!threatHypothesesOn(s) && !requirementRisksOn(rt)) return [];
    const model = this.slotKey(e);
    const runnable = this.runnable();
    const owner = (cat: string) => runnable.find((d) => d.categories.includes(cat))?.id;
    return verificationTargets(rt)
      .filter((h) => owner(h.category) === e.domain.id && (h.status === 'proposed' || (this.multi && h.status !== 'dismissed' && h.status !== 'converted'))
        && !fromJson<{ model: string }[]>((h as HypothesisRow & { votes?: string }).votes, []).some((v) => v.model === model))
      .slice(0, HYPOTHESES_PER_ROUND);
  }

  /** Experts for every runnable domain and model (new ones for added domains); removed domains stop. */
  private sync(experts: Map<string, Expert>): void {
    this.refresh();
    const runnable = this.runnable();
    this.models.forEach((model, j) => runnable.forEach((domain) => {
      const key = `${j}:${domain.id}`;
      const e = experts.get(key);
      if (e) e.domain = domain;
      else experts.set(key, { domain, model, modelIndex: j, stepIds: [], done: false });
    }));
    const live = new Set(runnable.map((d) => d.id));
    for (const e of experts.values()) if (!live.has(e.domain.id)) e.done = true;
  }

  /**
   * Close the expert phase in one transaction with the plan edits: a domain added before this point still
   * gets its expert (false: run another pass), one added after it is late.
   */
  private close(experts: Map<string, Expert>): boolean {
    const { rt, store } = this.p;
    if (this.opts.supplement) return true;
    return store.tx(() => {
      this.sync(experts);
      if ([...experts.values()].some((e) => !e.done)) return false;
      rt.event('judgement.made', { kind: EXPERTS_DONE, domains: this.runnable().length });
      return true;
    });
  }

  /** Shared inputs of every round, fixed when the stage starts. */
  private ctx!: { share: number; depOwner: string | undefined; depHits: DependencyHit[] };
  /** experts whose floor round (after the lead) already ran. */
  private readonly floored = new Set<string>();

  private expertKey(e: Pick<Expert, 'modelIndex' | 'domain'>): string {
    return `${e.modelIndex}:${e.domain.id}`;
  }

  /**
   * One round for each given expert, side by side (an expert at most once per call): the step, the session, then what
   * the round left — gaps, open directions, earlier findings — for the next one. Null to go on, or how a stop settles.
   */
  private async runRounds(items: { e: Expert; task?: LeadTask }[]): Promise<RunResult | null> {
    const { p } = this;
    const { rt, store, auditId } = p;
    const { share, depOwner, depHits } = this.ctx;
    const names = this.runnable().map((d) => d.name);
    const rows = items.map(({ e }) => {
      const round = e.stepIds.length + 1;
      const used = domainUsed(rt, e.stepIds);
      const cap = (e.stepIds.length ? JSON.parse(getStep(store, e.stepIds[0]!).input || '{}').share as number | undefined : undefined) ?? share;
      return ensureStep(store, auditId, {
        kind: 'hunt', identity: { domain: e.domain.name, round, ...(this.multi ? { model: this.slotKey(e) } : {}) },
        lineage: this.lineage(e, round), model: e.model,
        input: { domain: { id: e.domain.id, name: e.domain.name }, round, share: cap },
        estimateTokens: Math.max(MIN_DOMAIN_CAP, cap - used), calibrate: false,
      });
    });
    await pool(rows, p.parallel, async (row) => {
      if (p.halting() || this.blockedRows.length) return;
      if (getStep(store, row.id).status === 'skipped') return;
      if (!p.llmAllowed()) {
        p.skipUnrun(row);
        return;
      }
      const { e, task } = items[rows.indexOf(row)]!;
      const round = e.stepIds.length + 1;
      const cap = (JSON.parse(getStep(store, row.id).input || '{}').share as number | undefined) ?? share;
      const left = Math.max(MIN_DOMAIN_CAP, cap - domainUsed(rt, e.stepIds));
      const r = await p.step(row, (ctx) => {
        // Read per attempt: a retried round skips what an earlier attempt already answered.
        const hyps = this.pendingHypotheses(e);
        return domainExpertStep(rt, e.domain, round, this.leads.get(e.domain.id) ?? [], row.lineage_id ?? this.lineage(e, round), ctx, {
          ...(this.multi ? { model: e.model, modelKey: this.slotKey(e), statePrefix: `DOM-M${e.modelIndex + 1}-` } : {}),
          tokenCap: domainUsed(rt, [row.id]) + left, others: names.filter((n) => n !== e.domain.name), hypotheses: hyps, access: this.accessFor(e.domain.id),
          ...(round === 1 && e.domain.id === depOwner && depHits.length ? { dependencies: depHits } : {}),
          ...(hyps.length ? { prior: priorConclusions(rt, hyps, this.multi ? this.slotKey(e) : undefined) } : {}),
          ...(e.previous ? { previous: e.previous } : {}),
          ...(task ? { task: { goal: task.goal, ...(task.files?.length ? { files: task.files } : {}) } } : {}),
        });
      });
      if (r === 'blocked_budget') this.blockedRows.push(row);
    });
    if (p.halting()) return p.interrupted();
    if (this.blockedRows.length) return p.blocked(p.unfinished('hunt'));
    // What each round left: directions, gaps, the findings so far — the next round's input. The
    // fixed-round policy (supplements) also decides here whether the expert goes on.
    items.forEach(({ e }, i) => {
      const row = getStep(store, rows[i]!.id);
      e.stepIds.push(row.id);
      const cap = (JSON.parse(getStep(store, e.stepIds[0]!).input || '{}').share as number | undefined) ?? share;
      const out = row.status === 'succeeded' && row.output_ref ? store.artifacts.getJson<DomainOutput>(row.output_ref) : null;
      const gaps = out ? domainGaps(rt, e.domain, this.leads.get(e.domain.id) ?? [], e.stepIds) : undefined;
      if (out && !gapsEmpty(gaps)) {
        rt.event('judgement.made', { kind: 'domain_gaps', phase: 'found', domain: e.domain.name, round: e.stepIds.length, mechanisms: gaps!.mechanisms.map((m) => m.name), leads: gaps!.leads.length, ids: gaps!.leads.slice(0, 20).map((c) => c.id) }, row.id);
      }
      e.lastGaps = gaps;
      e.lastOut = out;
      if (!out || e.stepIds.length >= DOMAIN_ROUNDS || (!out.openLeads.length && !this.pendingHypotheses(e).length && gapsEmpty(gaps)) || domainUsed(rt, e.stepIds) > cap * (1 - NEXT_ROUND_MIN_LEFT)) {
        e.done = true;
      }
      const titles = store.all<{ lineage_id: string; title: string }>(
        `SELECT lineage_id, title FROM finding WHERE step_id IN (${e.stepIds.map(() => '?').join(',')}) ORDER BY lineage_id`, ...e.stepIds).map((f) => `${f.lineage_id}：${f.title}`);
      e.previous = { openLeads: out?.openLeads ?? [], findings: titles, ...(gapsEmpty(gaps) ? {} : { gaps: gaps! }) };
    });
    return null;
  }

  /** the lead's view of the stage — per domain the subtasks run, findings, directions, gaps, must-answers, budget. */
  private ledgerText(experts: Map<string, Expert>, modelIndex: number): string {
    const { rt, store, auditId } = this.p;
    const lines: string[] = [];
    for (const d of this.runnable()) {
      const e = experts.get(`${modelIndex}:${d.id}`);
      if (!e) continue;
      const findings = e.stepIds.length ? store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM finding WHERE step_id IN (${e.stepIds.map(() => '?').join(',')})`, ...e.stepIds)!.n : 0;
      const cap = (e.stepIds.length ? JSON.parse(getStep(store, e.stepIds[0]!).input || '{}').share as number | undefined : undefined) ?? this.ctx.share;
      const used = domainUsed(rt, e.stepIds);
      const leads = this.leads.get(d.id) ?? [];
      const open = new Set(store.all<{ target_id: string }>(`SELECT target_id FROM coverage_item WHERE audit_id = ? AND status != 'concluded' AND status != 'excluded'`, auditId).map((r) => r.target_id));
      const gaps = e.lastGaps;
      lines.push(`- ${d.id}「${d.name}」：子任务 ${e.stepIds.length} 个；发现 ${findings} 条；线索 ${leads.length} 个，其中未结论 ${leads.filter((c) => open.has(c.id)).length} 个；`
        + `必答假设 ${this.pendingHypotheses(e).length} 条、访问差异 ${this.accessFor(d.id).length} 条；`
        + `${gaps && !gapsEmpty(gaps) ? `缺口：机制 ${gaps.mechanisms.length}、线索 ${gaps.leads.length}；` : ''}`
        + `${e.previous?.openLeads.length ? `留下方向 ${e.previous.openLeads.length} 条（${e.previous.openLeads.slice(0, 3).map((l) => l.direction.slice(0, 60)).join('；')}）；` : ''}`
        + `额度已用 ${Math.round((used / Math.max(1, cap)) * 100)}%`);
    }
    const o = obligationSummary(this.p.rt);
    lines.push('', `义务：${o.settled}/${o.total} 已结论（${Object.entries(o.byKind).map(([k, v]) => `${k} ${v!.settled}/${v!.total}`).join('，')}）`);
    return lines.join('\n');
  }

  /** the subtasks of one dispatch call — per domain in order, different domains side by side; a receipt each. */
  private async dispatch(experts: Map<string, Expert>, modelIndex: number, tasks: LeadTask[]): Promise<string[]> {
    const { store } = this.p;
    const receipts: string[] = [];
    const queue = new Map<string, LeadTask[]>();
    for (const t of tasks) queue.set(t.domainId, [...(queue.get(t.domainId) ?? []), t]);
    for (let wave = 0; [...queue.values()].some((q) => q.length > wave); wave++) {
      const items = [...queue.entries()].flatMap(([id, q]) => {
        const e = experts.get(`${modelIndex}:${id}`);
        const t = q[wave];
        if (!t) return [];
        if (!e || !this.runnable().some((d) => d.id === id)) { receipts.push(`- ${id}：${P('lead.receipt.unknown_domain')}`); return []; }
        if (e.stepIds.length >= MAX_SUBTASKS) { receipts.push(`- ${id}：${P('lead.receipt.subtask_cap', { n: e.stepIds.length, goal: t.goal.slice(0, 40) })}`); return []; }
        return [{ e, task: t }];
      });
      if (!items.length) continue;
      const prior = items.map(({ e }) => e.busy).filter(Boolean);
      const run = (prior.length ? Promise.allSettled(prior) : Promise.resolve()).then(() => this.runRounds(items));
      for (const { e } of items) e.busy = run.catch(() => undefined);
      const stop = await run;
      for (const { e, task } of items) {
        const row = getStep(store, e.stepIds.at(-1)!);
        const n = store.get<{ n: number }>('SELECT COUNT(*) AS n FROM finding WHERE step_id = ?', row.id)!.n;
        const out = e.lastOut;
        receipts.push(`- ${e.domain.id} 子任务「${task!.goal.slice(0, 60)}」：${row.status === 'succeeded' ? `提交发现 ${n} 条，下结论的单元 ${(out?.reviewedTargets.length ?? 0) + (out?.ruledOut.length ?? 0)} 个，留下方向 ${out?.openLeads.length ?? 0} 条` : `未完成（${row.status}）`}`);
      }
      if (stop) { receipts.push(`- ${P('lead.receipt.stopped')}`); break; }
    }
    return receipts;
  }

  /** Runs the stage: the lead and its floor, or the fixed rounds of a supplement; null to go on. */
  async run(): Promise<RunResult | null> {
    const { p } = this;
    const { rt, store, auditId } = p;
    this.recordPlan();
    // dependencies (and OSV hits when an OSV connector is enabled for the audit), once per audit, full scans only.
    let depHits: DependencyHit[] = [];
    if (!this.opts.supplement && rt.audit.scene === 'full') {
      try { depHits = (await dependencyCheck(rt, p.signal)).hits; } catch (e) { rt.event('judgement.made', { kind: 'dependencies_failed', reason: (e as Error).message.slice(0, 300) }); }
    }
    // An equal share of the expert pool per domain and model, from the plan as it started; fixed in each
    // expert's first-round input (an added domain gets the same share).
    const share = Math.max(MIN_DOMAIN_CAP, Math.floor(expertPool(rt) / Math.max(1, this.runnable().length * this.models.length)));
    this.ctx = { share, depOwner: this.dependencyOwner(), depHits };
    const experts = new Map<string, Expert>();
    if (this.opts.supplement) {
      // Supplements keep the fixed rounds: every expert until it is done.
      for (let pass = 0; pass < MAX_PASSES; pass++) {
        this.sync(experts);
        const active = [...experts.values()].filter((e) => !e.done);
        if (!active.length) break;
        const stop = await this.runRounds(active.map((e) => ({ e })));
        if (stop) return stop;
      }
      return null;
    }
    this.sync(experts);
    // a resumed run (service restart, budget pause) knows the rounds already run, and first finishes a round
    // that was stopped mid-way — before, every expert restarted with no rounds, the stopped round stayed “interrupted”
    // with its work thrown away, and the lead's ledger said no subtask had run.
    const resumeStop = await this.resumeRounds(experts);
    if (resumeStop) return resumeStop;
    // An incremental audit whose change touches nothing auditable has nothing to explore (as the generalist had no batch).
    if (rt.audit.scene === 'incremental' && !this.candidates.length) {
      for (const e of experts.values()) e.done = true;
      this.close(experts);
      return null;
    }
    // One lead per hunt model dispatches the subtasks; a lead whose context reached the cap hands
    // over to a fresh session.
    const leadStops: RunResult[] = [];
    await Promise.all(this.models.map(async (model, j) => {
      let handoff: string | null = null;
      for (let session = 1; session <= MAX_LEAD_SESSIONS; session++) {
        if (p.halting() || this.blockedRows.length || !p.llmAllowed()) return;
        const row = ensureStep(store, auditId, {
          kind: 'hunt', identity: { lead: this.multi ? crossKey(this.models, j) : true, session }, lineage: `LEAD${this.multi ? `-M${j + 1}` : ''}-${session}`, model,
          input: { session }, estimateTokens: LEAD_CONTEXT_CAP * 4, calibrate: false,
        });
        const r = await p.step(row, (ctx) => leadStep(rt, ctx, { model, domains: this.runnable(), session, handoff, ...(this.multi ? { statePrefix: `DOM-M${j + 1}-` } : {}) }, {
          ledger: () => { this.sync(experts); return this.ledgerText(experts, j); },
          dispatch: (tasks) => { this.sync(experts); return this.dispatch(experts, j, tasks); },
        }));
        const stop = p.stopFor(r, row);
        if (stop) { leadStops.push(stop); return; }
        const out = getStep(store, row.id);
        if (out.status !== 'succeeded' || !out.output_ref) return;
        const lo = store.artifacts.getJson<LeadOutput>(out.output_ref);
        if (lo.done) return;
        handoff = lo.handoff ?? lo.summary;
      }
    }));
    if (p.halting()) return p.interrupted();
    if (this.blockedRows.length) return p.blocked(p.unfinished('hunt'));
    if (leadStops.length) return leadStops[0]!;
    // Floor (deterministic): a domain the lead never dispatched, or one still owing must-answers (hypotheses,
    // access differences, gaps of its last round), gets one more round; then the stage closes.
    for (let pass = 0; pass < MAX_PASSES; pass++) {
      this.sync(experts);
      const owed = [...experts.values()].filter((e) => !this.floored.has(this.expertKey(e)) && this.runnable().some((d) => d.id === e.domain.id)
        && (e.stepIds.length === 0 || this.pendingHypotheses(e).length > 0 || this.accessFor(e.domain.id).length > 0 || !gapsEmpty(e.lastGaps)));
      if (!owed.length) {
        for (const e of experts.values()) e.done = true;
        if (this.close(experts)) break;
        continue;
      }
      for (const e of owed) this.floored.add(this.expertKey(e));
      if (owed.length) rt.event('judgement.made', { kind: 'lead_floor', domains: owed.map((e) => e.domain.id) });
      const stop = await this.runRounds(owed.map((e) => ({ e })));
      if (stop) return stop;
    }
    return null;
  }
}
