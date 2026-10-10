// Continuing step sessions from their saved transcripts. The main sessions of a step attempt are
// written to `<data-dir>/sessions/<audit>/<step>/a<attempt>-s<n>/`; when an attempt stops between turns (pause, used-up
// stage quota) or is cut off (shutdown, crash), the next attempt continues its transcript instead of starting over.
import { existsSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { findTranscript } from '@xiezhi/agent';
import type { Store } from '@xiezhi/store';
import type { StepRow } from './state.js';

export const sessionsDir = (store: Store, auditId: string): string => join(store.paths.sessions, auditId);

export const transcriptDir = (store: Store, auditId: string, stepId: string, attempt: number, seq: number): string =>
  join(sessionsDir(store, auditId), stepId, `a${attempt}-s${seq}`);

/**
 * Provider errors after which the session's transcript is kept and may go on: transient errors, and a content
 * filter refusal — a fallback model, or a person choosing to retry as it is, continues it; a person choosing
 * to start the step afresh removes it (`Engine.resume` with `restartFiltered`) — and a used-up balance or quota
 *: the conversation goes on once it is topped up.
 */
export const TRANSIENT_SESSION_ERRORS: readonly string[] = ['PROVIDER_TRANSIENT', 'RATE_LIMITED', 'CONTENT_FILTERED', 'PROVIDER_QUOTA'];

/**
 * Whether an attempt stopped in a way its session may continue: paused or out of stage / cost budget (between turns),
 * cut off by a shutdown, never settled (the process died), or failed on a transient provider error. Any other
 * failure (output contract, context overflow, …) starts afresh.
 */
function continuable(store: Store, stepId: string, attempt: number): boolean {
  const a = store.get<{ outcome: string | null; error_class: string | null }>('SELECT outcome, error_class FROM step_attempt WHERE step_id = ? AND attempt = ?', stepId, attempt);
  return !!a && (a.outcome === null || a.outcome === 'interrupted' || a.outcome === 'cancelled' || a.error_class === 'BUDGET_EXHAUSTED'
    || (a.outcome === 'failed' && TRANSIENT_SESSION_ERRORS.includes(a.error_class ?? '')));
}

/**
 * The newest transcript of main session `seq` to continue, looking back from `attempt`: an attempt that stopped
 * before it opened its own transcript (a pause, a shutdown or a provider error right at the start) passes on the one
 * before it; the first attempt that cannot be continued ends the search.
 */
export function resumableTranscript(store: Store, auditId: string, stepId: string, attempt: number, seq: number): string | null {
  for (let k = attempt; k >= 1; k--) {
    if (!continuable(store, stepId, k)) return null;
    const t = findTranscript(transcriptDir(store, auditId, stepId, k, seq));
    if (t) return t;
  }
  return null;
}

/** Whether the step has a session to continue (any main session, looking back like `resumableTranscript`). */
export function hasResumable(store: Store, auditId: string, step: StepRow): boolean {
  const dir = join(sessionsDir(store, auditId), step.id);
  if (!existsSync(dir)) return false;
  const seqs = [...new Set(readdirSync(dir).map((d) => /^a\d+-s(\d+)$/.exec(d)?.[1]).filter((x): x is string => !!x).map(Number))];
  return seqs.some((seq) => resumableTranscript(store, auditId, step.id, step.attempt, seq) !== null);
}

/** Tokens the latest attempt of a step used (input + output + cache reads, as charged). */
export function attemptTokens(store: Store, step: StepRow): number {
  return store.get<{ n: number }>('SELECT COALESCE(tokens_in + tokens_out + tokens_cached, 0) AS n FROM step_attempt WHERE step_id = ? AND attempt = ?', step.id, step.attempt)?.n ?? 0;
}

/** Tokens a step used over all its attempts — a continued session carries the earlier attempts' conversation. */
function stepTokens(store: Store, step: StepRow): number {
  return store.get<{ n: number }>('SELECT COALESCE(SUM(tokens_in + tokens_out + tokens_cached), 0) AS n FROM step_attempt WHERE step_id = ?', step.id)?.n ?? 0;
}

/**
 * What a step still needs before it can start: a step continuing its session needs the rest of
 * its estimate, at least half of what it used so far over all attempts (a step past its estimate is assumed to need
 * about half as much again; each turn re-sends the growing conversation, so the attempts' total is the measure); a step
 * stopped by the budget that starts over needs at least what its last attempt used; otherwise its estimate.
 */
export function remainingNeed(store: Store, auditId: string, step: StepRow): number {
  const estimate = Math.max(step.estimate_tokens, observedTokens(store, auditId, step));
  if (step.status !== 'interrupted' && step.status !== 'ready' && step.status !== 'blocked_budget') return estimate;
  const used = attemptTokens(store, step);
  if (hasResumable(store, auditId, step)) {
    const total = stepTokens(store, step);
    return Math.max(estimate - total, Math.ceil(total / 2));
  }
  if (step.error_class === 'BUDGET_EXHAUSTED') return Math.max(estimate, used);
  return estimate;
}

/** Steps whose estimate does not depend on a batch size, so finished ones of the same kind measure the others. */
const PER_STEP_KINDS = new Set(['plan', 'profile', 'threat-model', 'verify-fix', 'challenge', 'review', 'decide', 'reconcile']);

/**
 * What finished steps of the same kind used in this audit, on average (0 when none). The estimate of a step is fixed
 * when its row is made — a cold-start constant before any history: real runs saw profile steps estimated at 25k use
 * 280–390k each, and the suggested top-up was used up long before the remaining steps finished.
 */
function observedTokens(store: Store, auditId: string, step: StepRow): number {
  if (!PER_STEP_KINDS.has(step.kind)) return batchObserved(store, auditId, step);
  const r = store.get<{ n: number | null }>(
    `SELECT AVG(t) AS n FROM (SELECT SUM(a.tokens_in + a.tokens_out + a.tokens_cached) AS t FROM step s JOIN step_attempt a ON a.step_id = s.id
      WHERE s.audit_id = ? AND s.kind = ? AND s.status = 'succeeded' AND s.id != ? GROUP BY s.id)`, auditId, step.kind, step.id);
  return Math.ceil(r?.n ?? 0);
}

/**
 * A batch step (`HYP-R-M2-B3`, `GAP-B2`, …) scaled by how its finished siblings of the same series used their own
 * estimates in this audit (haiku's hypothesis batches estimated at 90k used 180–480k each, and the suggested
 * top-up stopped the audit again). 0 without such siblings or for steps that are not batches.
 */
function batchObserved(store: Store, auditId: string, step: StepRow): number {
  const series = /^(.*-)B\d+$/.exec(step.lineage_id ?? '')?.[1];
  if (!series || step.estimate_tokens <= 0) return 0;
  const r = store.get<{ n: number | null }>(
    `SELECT AVG(t * 1.0 / e) AS n FROM (SELECT s.estimate_tokens AS e, SUM(a.tokens_in + a.tokens_out + a.tokens_cached) AS t FROM step s JOIN step_attempt a ON a.step_id = s.id
      WHERE s.audit_id = ? AND s.kind = ? AND s.status = 'succeeded' AND s.id != ? AND s.lineage_id LIKE ? AND s.estimate_tokens > 0 GROUP BY s.id)`,
    auditId, step.kind, step.id, `${series}B%`);
  return r?.n ? Math.ceil(step.estimate_tokens * r.n) : 0;
}

/** Remove saved transcripts: of one step (it ended), or of the whole audit (it reached a final state). */
export function clearSessions(store: Store, auditId: string, stepId?: string): void {
  rmSync(stepId ? join(sessionsDir(store, auditId), stepId) : sessionsDir(store, auditId), { recursive: true, force: true });
}
