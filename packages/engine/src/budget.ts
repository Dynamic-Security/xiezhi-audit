// Budget accounting of an audit: which stage quotas stopped steps,
// what is missing to finish, the top-up to suggest, and the running-time checkpoint.
import type { BudgetStage } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { remainingNeed } from './resume.js';
import { budgetStage } from './stages.js';
import { getAudit, listSteps, NOT_STARTED, runningDelta, type AuditRow, type StepRow } from './state.js';

/** A step stopped by the budget: blocked before it started, or stopped while running. */
const waitsForBudget = (s: StepRow): boolean => s.status === 'blocked_budget' || (s.status === 'interrupted' && s.error_class === 'BUDGET_EXHAUSTED');

/** The stages whose quota is used up for a step waiting for budget. */
export function budgetStoppedStages(store: Store, auditId: string): BudgetStage[] {
  const a = getAudit(store, auditId);
  const eff = JSON.parse(a.budget_effective) as { stages?: Partial<Record<BudgetStage, number>> };
  const used = (JSON.parse(a.budget_consumed) as { stages?: Partial<Record<BudgetStage, number>> }).stages ?? {};
  const out = new Set<BudgetStage>();
  for (const s of listSteps(store, auditId).filter(waitsForBudget)) {
    const st = budgetStage(s.kind, s.lineage_id);
    const limit = st ? eff.stages?.[st] : undefined;
    // a session stopped on a used-up quota (`used ≥ limit`) waits for that stage too.
    if (st && limit !== undefined && ((used[st] ?? 0) >= limit || (used[st] ?? 0) + remainingNeed(store, auditId, s) > limit)) out.add(st);
  }
  return [...out];
}

/**
 * What is missing to finish: for the total and for each stage that stopped a step, the usage
 * past the limit plus what the unfinished steps still need (`remainingNeed`), less what is still free. A total-only top-up
 * also goes to every stopped stage, so the suggestion is the largest of these.
 */
export function budgetNeeds(store: Store, auditId: string): { total: number; stages: { stage: BudgetStage; need: number }[]; largestOpen: number } {
  const a = getAudit(store, auditId);
  const eff = JSON.parse(a.budget_effective) as { tokens: number; stages?: Partial<Record<BudgetStage, number>> };
  const con = JSON.parse(a.budget_consumed) as { tokens: number; stages?: Partial<Record<BudgetStage, number>> };
  const open = listSteps(store, auditId).filter((s) => NOT_STARTED.includes(s.status)).map((s) => ({ s, need: remainingNeed(store, auditId, s) }));
  const total = Math.max(0, con.tokens + open.reduce((n, x) => n + x.need, 0) - eff.tokens);
  const stages = budgetStoppedStages(store, auditId).map((stage) => {
    const left = open.filter((x) => budgetStage(x.s.kind, x.s.lineage_id) === stage).reduce((n, x) => n + x.need, 0);
    return { stage, need: Math.max(0, (con.stages?.[stage] ?? 0) + left - (eff.stages?.[stage] ?? 0)) };
  });
  return { total, stages, largestOpen: Math.max(0, ...open.map((x) => x.need)) };
}

/**
 * The top-up to suggest: 1.2 × the largest gap, per stopped stage likewise; `short` is false when
 * nothing is missing on paper (then the largest unfinished step, so a suggestion is never a token or two). Shared by
 * the engine's `budget.exhausted` event and the API, so both show the same amount.
 */
export function budgetSuggestion(store: Store, auditId: string): { tokens: number; stages: { stage: BudgetStage; tokens: number }[]; short: boolean } {
  const { total, stages, largestOpen } = budgetNeeds(store, auditId);
  const top = Math.max(total, ...stages.map((x) => x.need));
  const round = (n: number) => Math.ceil(n * 1.2);
  return {
    tokens: round(top || largestOpen || 10_000), short: top > 0,
    stages: stages.map((x) => ({ stage: x.stage, tokens: round(x.need || largestOpen || 10_000) })),
  };
}

/**
 * Charge the running time since `running_since` and restart the clock (only `running` time counts). At most
 * `MAX_DURATION_CHARGE_MS` per call: after the machine slept, the first beat does not charge the sleep.
 */
export function checkpointDuration(store: Store, auditId: string, now = Date.now()): void {
  store.tx(() => {
    const a = getAudit(store, auditId);
    if (a.status !== 'running' || !a.running_since) return;
    const consumed = JSON.parse(a.budget_consumed) as { durationMs?: number };
    store.update('audit', { id: auditId }, { budget_consumed: { ...consumed, durationMs: (consumed.durationMs ?? 0) + runningDelta(now, a.running_since) }, running_since: now });
  });
}

/** Whether the audit has used its running time, counting the time since the last checkpoint. */
export function durationExceeded(a: AuditRow): boolean {
  const eff = JSON.parse(a.budget_effective) as { durationMs: number };
  const used = (JSON.parse(a.budget_consumed) as { durationMs?: number }).durationMs ?? 0;
  return used + (a.running_since ? runningDelta(Date.now(), a.running_since) : 0) > eff.durationMs;
}
