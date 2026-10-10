// Audit and step state machines. Every transition and its
// event are written in the same transaction; illegal transitions throw.
import { AppError, type AuditStatus, type ErrorClass, type PartialReason, type StepStatus } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';

export const AUDIT_TRANSITIONS: Record<AuditStatus, readonly AuditStatus[]> = {
  planning: ['awaiting_confirm', 'queued', 'failed', 'cancelled', 'interrupted'],
  awaiting_confirm: ['queued', 'cancelled'],
  queued: ['running', 'cancelled'],
  // running → queued: the run ends to start again at once — budget suffices again, or a decline finalizes.
  running: ['waiting_budget', 'queued', 'paused', 'cancelling', 'interrupted', 'completed', 'partial', 'failed'],
  waiting_budget: ['queued', 'running', 'partial', 'cancelling', 'cancelled'],
  paused: ['queued', 'cancelling', 'cancelled'],
  cancelling: ['cancelled'],
  interrupted: ['queued', 'cancelled'],
  completed: [], partial: [], failed: [], cancelled: [],
};

export const STEP_TRANSITIONS: Record<StepStatus, readonly StepStatus[]> = {
  // Allowed step transitions.
  pending: ['ready', 'skipped', 'cancelled', 'succeeded'],
  ready: ['running', 'blocked_budget', 'skipped', 'cancelled'],
  blocked_budget: ['ready', 'skipped', 'cancelled'],
  running: ['succeeded', 'retry_wait', 'failed', 'cancelled', 'interrupted'],
  retry_wait: ['ready', 'skipped', 'cancelled'],
  succeeded: [], failed: [], skipped: [], cancelled: [],
  interrupted: ['ready', 'skipped', 'cancelled'],
};

export interface AuditRow {
  id: string; project_id: string; scene: string; mode: string; title: string; status: AuditStatus; phase: string | null;
  strategy_draft: string; strategy_sources: string; strategy_frozen: string | null; strategy_hash: string | null; topology_ref: string | null;
  plan_ref: string | null; knowledge_ref: string | null; gate_ref: string | null; scope: string; partial_reasons: string; base_audit_id: string | null;
  budget_initial: string; budget_effective: string; budget_consumed: string; report_refs: string; origin: string;
  /** The conversation the audit lives in: the one it was started from, or one created for it. */
  conversation_id: string | null;
  /** Start as soon as the plan is ready instead of waiting for a confirmation. */
  auto_start: number;
  error_class: ErrorClass | null; queued_at: number | null; started_at: number | null; ended_at: number | null; running_since: number | null;
  created_at: number;
}

export interface StepRow {
  id: string; audit_id: string; seq: number; kind: string; lineage_id: string | null; status: StepStatus; required: number;
  attempt: number; max_attempts: number; idempotency_key: string; depends_on: string; input: string; output_ref: string | null;
  reused_from: string | null; model: string | null; provider: string | null; tokens_in: number; tokens_out: number; tokens_cached: number;
  cost_micros: number | null; estimate_tokens: number; retry_at: number | null; error_class: ErrorClass | null; error_summary: string | null;
  started_at: number | null; ended_at: number | null;
}

export function getAudit(store: Store, id: string): AuditRow {
  const a = store.get<AuditRow>('SELECT * FROM audit WHERE id = ?', id);
  if (!a) throw new AppError('AUDIT_NOT_FOUND', id);
  return a;
}

export function getStep(store: Store, id: string): StepRow {
  const s = store.get<StepRow>('SELECT * FROM step WHERE id = ?', id);
  if (!s) throw new Error(`step ${id} not found`);
  return s;
}

export function listSteps(store: Store, auditId: string): StepRow[] {
  return store.all<StepRow>('SELECT * FROM step WHERE audit_id = ? ORDER BY seq', auditId);
}

export interface TransitionExtra {
  reason?: string;
  partialReasons?: PartialReason[];
  errorClass?: ErrorClass | null;
  patch?: Record<string, unknown>;
}

const TERMINAL = new Set<AuditStatus>(['completed', 'partial', 'failed', 'cancelled']);

/** How often a running audit's wall-clock time is written to its budget. */
export const DURATION_CHECKPOINT_MS = 30_000;
/**
 * The most one settlement of running time may charge. Settlements come every
 * `DURATION_CHECKPOINT_MS` while the process is awake; a longer gap means the machine slept (the timer did not fire),
 * so the gap is not running time.
 */
export const MAX_DURATION_CHARGE_MS = 2 * DURATION_CHECKPOINT_MS;

/** Running time to charge for the span since `running_since`, capped at `MAX_DURATION_CHARGE_MS`. */
export function runningDelta(now: number, since: number): number {
  return Math.min(Math.max(0, now - since), MAX_DURATION_CHARGE_MS);
}

export function transitionAudit(store: Store, id: string, to: AuditStatus, extra: TransitionExtra = {}): void {
  store.tx(() => {
    const a = getAudit(store, id);
    if (a.status === to) return;
    if (!AUDIT_TRANSITIONS[a.status].includes(to)) throw new AppError('INVALID_TRANSITION', `audit ${a.status} → ${to}`);
    const now = Date.now();
    const patch: Record<string, unknown> = { status: to, ...extra.patch };
    // Duration accounting: only wall-clock time in `running` counts.
    if (a.status === 'running' && a.running_since) {
      const consumed = JSON.parse(a.budget_consumed) as { durationMs?: number };
      patch.budget_consumed = { ...consumed, durationMs: (consumed.durationMs ?? 0) + runningDelta(now, a.running_since) };
      patch.running_since = null;
    }
    if (to === 'running') {
      patch.running_since = now;
      if (!a.started_at) patch.started_at = now;
    }
    if (to === 'queued') patch.queued_at = now;
    if (TERMINAL.has(to)) patch.ended_at = now;
    if (extra.partialReasons) patch.partial_reasons = extra.partialReasons;
    if (extra.errorClass !== undefined) patch.error_class = extra.errorClass;
    store.update('audit', { id }, patch);
    store.appendEvent(id, 'audit.status_changed', {
      from: a.status, to, ...(extra.reason ? { reason: extra.reason } : {}),
      ...(extra.partialReasons ? { partial_reasons: extra.partialReasons } : {}),
      ...(extra.errorClass ? { error_class: extra.errorClass } : {}),
    });
  });
}

export function transitionStep(store: Store, stepId: string, to: StepStatus, patch: Record<string, unknown> = {}, reason?: string): void {
  store.tx(() => {
    const s = getStep(store, stepId);
    if (s.status === to && Object.keys(patch).length === 0) return;
    if (s.status !== to && !STEP_TRANSITIONS[s.status].includes(to)) throw new AppError('INVALID_TRANSITION', `step ${s.kind} ${s.status} → ${to}`);
    store.update('step', { id: stepId }, { status: to, ...patch });
    if (s.status !== to) {
      store.appendEvent(s.audit_id, 'step.status_changed', {
        kind: s.kind, from: s.status, to, attempt: (patch.attempt as number | undefined) ?? s.attempt,
        ...(reason ? { reason } : {}),
        ...(patch.error_class ? { error_class: patch.error_class } : {}),
        ...(TERMINAL_STEP.has(to) ? { tokens_in: s.tokens_in, tokens_out: s.tokens_out, cost_micros: s.cost_micros } : {}),
      }, stepId);
    }
  });
}

/** Step states that have not started an attempt and may be skipped. */
export const NOT_STARTED: readonly string[] = ['pending', 'ready', 'blocked_budget', 'retry_wait', 'interrupted'];

/** error_summary marker for steps skipped by a user intervention (→ USER_SKIPPED). */
export const USER_SKIPPED_MARK = 'skipped by user';

const TERMINAL_STEP = new Set<StepStatus>(['succeeded', 'failed', 'skipped', 'cancelled']);
export function isStepTerminal(s: StepStatus): boolean {
  return TERMINAL_STEP.has(s);
}

/**
 * The audit's session limit: the frozen (or draft) strategy's `concurrency.sessions`, unless the user
 * changed it while the audit ran. The frozen strategy is immutable, so the change lives in the trajectory as a
 * `concurrency` intervention and is re-applied from there (the latest one wins).
 */
export function sessionLimit(store: Store, auditId: string, fromStrategy: number): number {
  const last = store.get<{ payload: string }>(
    `SELECT payload FROM event WHERE audit_id = ? AND type = 'intervention.received' AND json_extract(payload, '$.kind') = 'concurrency' ORDER BY seq DESC LIMIT 1`, auditId);
  const to = last ? Number((JSON.parse(last.payload) as { to?: number }).to) : NaN;
  return Number.isInteger(to) && to >= 1 ? to : fromStrategy;
}
