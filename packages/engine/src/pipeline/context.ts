// What every stage of one pipeline run shares: the runtime, the stop signal, the
// partial reasons carried to the report, and the checks and settlements every stage uses — may a model step still run,
// is the run stopping, and how a stop settles the audit (interrupted, waiting for budget, failed).
import type { AuditStrategy, PartialReason } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { budgetSuggestion, durationExceeded } from '../budget.js';
import type { AuditRuntime } from '../runtime.js';
import { getStep, isStepTerminal, listSteps, NOT_RUN_MARK, NOT_STARTED, transitionAudit, transitionStep, type AuditRow, type StepRow } from '../state.js';
import { runStep, type AttemptContext, type RunnerOptions, type StepOutcome, type StepResult } from '../step-runner.js';

export type RunResult = { status: AuditRow['status']; partialReasons: PartialReason[]; suggestedTopUp?: number };

/** `audit.phase` after the user declined a top-up: the run finishes with what it has (BUDGET_EXHAUSTED). */
export const FLAG_BUDGET_DECLINED = 'budget_declined';

/** What the engine lends a pipeline run. */
export interface PipelineHost {
  readonly store: Store;
  readonly runner: RunnerOptions;
  /** Settle a stopped run according to why it stopped (pause / cancel / shutdown). */
  halt(auditId: string, signal: AbortSignal): RunResult;
  /** A pause was asked for (by the user, or by the engine after a content filter refusal). */
  pauseRequested(auditId: string): boolean;
  /** Reclaim the language servers of these snapshot roots. */
  closeLsp(roots: string[]): Promise<void>;
}

/** A reason to stop, settled after parallel work has joined (two branches must not both change the audit state). */
export type Stop = { kind: 'interrupted' } | { kind: 'blocked'; rows: StepRow[] } | { kind: 'failed'; reason: string };

/**
 * What a step works on, readable while it runs and after the audit (execution overview): the candidate
 * ids plus a short description of each (location, label, triage reason). Not part of the step's idempotency key.
 */
export function candidateInput(cands: { id: string; kind: string; repo: string; path: string; line: number; label: string; reason?: string; llmScore?: number; detail?: string }[]) {
  return {
    batch: cands.map((c) => c.id),
    candidates: cands.map((c) => ({
      id: c.id, kind: c.kind, repo: c.repo, path: c.path, line: c.line, label: c.label.slice(0, 200),
      ...(c.reason ? { reason: c.reason.slice(0, 200) } : c.detail ? { reason: c.detail.slice(0, 200) } : {}),
      ...(c.llmScore !== undefined ? { score: c.llmScore } : {}),
    })),
  };
}

export class PipelineRun {
  readonly store: Store;
  readonly auditId: string;
  /** The strategy as the run started; `rt.strategy` may change while it runs (session limit, merge model dropped). */
  readonly s: AuditStrategy;
  /** Partial reasons found on the way, handed to the report. */
  readonly carried = new Set<PartialReason>();
  /** The user declined a top-up: no model step runs any more. */
  readonly declined: boolean;

  constructor(readonly host: PipelineHost, readonly rt: AuditRuntime, readonly signal: AbortSignal) {
    this.store = host.store;
    this.auditId = rt.auditId;
    this.s = rt.strategy;
    this.declined = rt.audit.phase === FLAG_BUDGET_DECLINED;
    if (this.declined) this.carried.add('BUDGET_EXHAUSTED');
  }

  /** Whether model steps may still start: not after a declined top-up, not once the running time is used. */
  llmAllowed(): boolean {
    if (this.declined) return false;
    if (durationExceeded(this.rt.audit)) { this.carried.add('DURATION_EXHAUSTED'); return false; }
    return true;
  }

  /** A step that may not run (budget declined, running time used up) and has not started is skipped. */
  skipUnrun(row: StepRow): void {
    const why = this.declined ? 'budget declined' : 'duration exhausted';
    if (NOT_STARTED.includes(getStep(this.store, row.id).status)) transitionStep(this.store, row.id, 'skipped', { error_summary: `${NOT_RUN_MARK}${why}` }, why);
  }

  /** Steps of a kind that have not finished: what a budget stop still has to run. */
  unfinished(kind: string): StepRow[] {
    return listSteps(this.store, this.auditId).filter((x) => x.kind === kind && !isStepTerminal(x.status));
  }

  /** Session slots bound the audit's parallel sessions; read live, the limit can change while the audit runs. */
  readonly parallel = (): number => this.rt.strategy.concurrency.sessions;

  halting(): boolean {
    return this.signal.aborted || this.host.pauseRequested(this.auditId);
  }

  interrupted(): RunResult {
    return this.host.halt(this.auditId, this.signal);
  }

  step(row: StepRow, body: (ctx: AttemptContext) => Promise<StepResult>): Promise<StepOutcome> {
    return runStep(this.rt, row, this.signal, this.host.runner, body);
  }

  requeue(reason: string): RunResult {
    transitionAudit(this.store, this.auditId, 'queued', { reason });
    return { status: 'queued', partialReasons: [] };
  }

  /** Steps were refused for budget: wait for a top-up, or run again when nothing is short. */
  blocked(pending: StepRow[]): RunResult {
    // a suggestion covers the usage past the limit and every step not run yet (all branches,
    // not only the step that was refused), so following it does not stop the audit again at once.
    const sug = budgetSuggestion(this.store, this.auditId);
    // nothing missing on paper (a step was refused only because running steps had reserved their
    // estimates): run again instead of waiting for a top-up nobody needs.
    if (!sug.short) return this.requeue('budget suffices; continuing');
    this.store.tx(() => {
      this.store.appendEvent(this.auditId, 'budget.exhausted', {
        suggested_top_up_tokens: sug.tokens, remaining_steps: pending.length,
        ...(sug.stages.length ? { stages: sug.stages.map((x) => ({ stage: x.stage, suggested_top_up_tokens: x.tokens })) } : {}),
      });
      transitionAudit(this.store, this.auditId, 'waiting_budget', { reason: 'budget insufficient' });
    });
    return { status: 'waiting_budget', partialReasons: [], suggestedTopUp: sug.tokens };
  }

  settle(x: Stop): RunResult {
    if (x.kind === 'blocked') return this.blocked(x.rows);
    if (x.kind === 'failed') {
      transitionAudit(this.store, this.auditId, 'failed', { reason: x.reason, errorClass: 'INTERNAL' });
      return { status: 'failed', partialReasons: [] };
    }
    return this.interrupted();
  }

  /** The common end of a step run: interrupted, or blocked for budget (`rows`, default the step itself). */
  stopFor(outcome: StepOutcome, row: StepRow): RunResult | null {
    if (outcome === 'interrupted') return this.interrupted();
    if (outcome === 'blocked_budget') return this.blocked([row]);
    return null;
  }
}
