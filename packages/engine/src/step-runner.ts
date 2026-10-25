// Generic step execution: idempotent creation, attempts, error-class retry,
// budget reservation, checkpoint at step boundary (output + derived rows in one transaction).
import { ModelNotConfiguredError } from '@xiezhi/agent';
import { DEFAULT_PROMPTS_HASH, withPrompts, type FrozenKnowledge } from '@xiezhi/knowledge';
import { canonicalJson, newId, RETRYABLE_ERROR_CLASSES, sha256Hex, type ErrorClass, type ModelRef, type StepKind } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import type { AuditRuntime } from './runtime.js';
import { calibrated } from './calibration.js';
import { getStep, transitionStep, type StepRow } from './state.js';
import { remainingNeed } from './resume.js';

export class StepError extends Error {
  constructor(readonly errorClass: ErrorClass, message: string) {
    super(message);
    this.name = 'StepError';
  }
}

export interface StepSpec {
  kind: StepKind;
  /** Stable identity parts; hashed into the idempotency key. */
  identity: unknown;
  input?: Record<string, unknown>;
  required?: boolean;
  maxAttempts?: number;
  estimateTokens?: number;
  /** false = reserve `estimateTokens` as given and keep the step out of estimate calibration. */
  calibrate?: boolean;
  lineage?: string;
  model?: { provider: string; model: string } | null;
}

/** the frozen prompt-set hash of an audit (`default` without overrides), cached once the knowledge is frozen. */
const promptHashes = new Map<string, string>();
function auditPromptsHash(store: Store, auditId: string): string {
  const cached = promptHashes.get(auditId);
  if (cached) return cached;
  const ref = store.get<{ knowledge_ref: string | null }>('SELECT knowledge_ref FROM audit WHERE id = ?', auditId)?.knowledge_ref;
  if (!ref) return DEFAULT_PROMPTS_HASH;
  const hash = store.artifacts.getJson<FrozenKnowledge>(ref).prompts?.hash ?? DEFAULT_PROMPTS_HASH;
  promptHashes.set(auditId, hash);
  return hash;
}

export function ensureStep(store: Store, auditId: string, spec: StepSpec): StepRow {
  // with prompt overrides in effect the prompt version is part of the step identity, so a step is
  // never reused across audits that ran under different prompts. Without overrides the key is unchanged.
  const prompts = auditPromptsHash(store, auditId);
  const key = sha256Hex(canonicalJson({ kind: spec.kind, identity: spec.identity, ...(prompts !== DEFAULT_PROMPTS_HASH ? { prompts } : {}) }));
  const existing = store.get<StepRow>('SELECT * FROM step WHERE audit_id = ? AND idempotency_key = ?', auditId, key);
  if (existing) return existing;
  const id = newId('step');
  store.tx(() => {
    const seq = (store.get<{ m: number | null }>('SELECT MAX(seq) AS m FROM step WHERE audit_id = ?', auditId)?.m ?? 0) + 1;
    store.insert('step', {
      id, audit_id: auditId, seq, kind: spec.kind, lineage_id: spec.lineage ?? null, status: 'pending', required: spec.required ? 1 : 0,
      attempt: 0, max_attempts: spec.maxAttempts ?? 2, idempotency_key: key, input: spec.input ?? {},
      // The reservation is calibrated from history; the constant-based estimate is kept to calibrate against.
      estimate_tokens: spec.calibrate === false ? spec.estimateTokens ?? 0 : calibrated(store, spec.estimateTokens ?? 0, spec.kind, spec.model ?? null),
      estimate_base: spec.calibrate === false ? 0 : spec.estimateTokens ?? 0,
      model: spec.model?.model ?? null, provider: spec.model?.provider ?? null,
    });
  });
  return getStep(store, id);
}

export interface AttemptContext { attempt: number; signal: AbortSignal; stepId: string }

export interface StepResult {
  /** Content-addressed output (already written). */
  outputRef: string;
  /** Derived writes committed atomically with `succeeded`. */
  apply?: () => void;
}

export type StepOutcome = 'succeeded' | 'failed' | 'blocked_budget' | 'cancelled' | 'interrupted' | 'skipped';

/** Consecutive service failures (attempts without any model reply, across steps) that trip the breaker. */
export const SERVICE_BREAKER_FAILURES = 3;

export interface RunnerOptions {
  retryBackoffMs: number;
  rateLimitBackoffMs: number;
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const t = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => { clearTimeout(t); resolve(); }, { once: true });
  });
}

export async function runStep(
  rt: AuditRuntime, step: StepRow, signal: AbortSignal, opts: RunnerOptions,
  body: (ctx: AttemptContext) => Promise<StepResult>,
): Promise<StepOutcome> {
  const store = rt.store;
  let current = getStep(store, step.id);
  if (current.status === 'succeeded') return 'succeeded';
  if (current.status === 'failed' || current.status === 'skipped' || current.status === 'cancelled') return current.status === 'failed' ? 'failed' : current.status === 'skipped' ? 'skipped' : 'cancelled';
  // A refused cross lane waits for a person for the rest of this run; it is not tried again here.
  if (current.status === 'interrupted' && rt.filteredLanes.has(step.id)) return 'failed';
  if (current.status === 'interrupted' || current.status === 'retry_wait' || current.status === 'blocked_budget') transitionStep(store, step.id, 'ready');
  // The user chose another model for every later step that would run on a refused one — recorded like the
  // manual switch, so the trajectory shows it and a resumed run keeps it.
  const later = rt.fallbacks.has(step.id) ? null : rt.laterSwitch(current);
  if (later) {
    rt.fallbacks.set(step.id, later.to);
    store.update('step', { id: step.id }, { model: later.to.model, provider: later.to.provider });
    rt.event('model.fallback', { from: later.from, to: later.to, reason: 'CONTENT_FILTERED', manual: true, later: true }, step.id);
  }

  while (true) {
    current = getStep(store, step.id);
    // The user may skip a step while it waits for its retry.
    if (current.status === 'skipped' || current.status === 'cancelled') return current.status;
    if (signal.aborted) return 'interrupted';
    // pending → ready → running.
    if (current.status === 'pending') transitionStep(store, step.id, 'ready');
    // Budget pre-check / reservation. A step continuing its saved session needs only the rest.
    const estimate = current.estimate_tokens > 0 ? remainingNeed(store, rt.auditId, current) : 0;
    if (estimate > 0 && rt.remainingTokens() < estimate) {
      transitionStep(store, step.id, 'blocked_budget', {}, 'estimate exceeds remaining budget');
      return 'blocked_budget';
    }
    // the step's stage quota is checked the same way as the total, except that the first step of
    // a stage may always start (an estimate can exceed a small quota); its actual usage is still capped by `charge`.
    const stage = rt.stageOf(step.id);
    if (estimate > 0 && rt.stageStarted(stage) && rt.stageRemaining(stage) < estimate) {
      transitionStep(store, step.id, 'blocked_budget', {}, 'estimate exceeds remaining stage quota');
      return 'blocked_budget';
    }
    const attempt = current.attempt + 1;
    const now = Date.now();
    store.tx(() => {
      transitionStep(store, step.id, 'running', { attempt, started_at: now, error_class: null, error_summary: null });
      const model = rt.stepModel(current);
      store.insert('step_attempt', { step_id: step.id, attempt, started_at: now, model: model ? `${model.provider}/${model.model}` : null });
      store.appendEvent(rt.auditId, 'step.attempt_started', { kind: current.kind, attempt, model: current.model }, step.id);
    });
    if (estimate > 0) rt.reserve(step.id, estimate);
    let errorClass: ErrorClass;
    let message: string;
    let stack: string | undefined;
    try {
      // the step's prompts come from the audit's frozen set.
      const result = await withPrompts(rt.prompts, () => body({ attempt, signal, stepId: step.id }));
      if (signal.aborted) throw new StepError('CANCELLED', 'aborted');
      store.tx(() => {
        // derived writes may render catalog text (evidence gaps) — with the audit's prompts too.
        withPrompts(rt.prompts, () => result.apply?.());
        store.db.run('UPDATE step_attempt SET outcome = ?, ended_at = ?, submitted_ref = ? WHERE step_id = ? AND attempt = ?', 'succeeded', Date.now(), result.outputRef, step.id, attempt);
        transitionStep(store, step.id, 'succeeded', { output_ref: result.outputRef, ended_at: Date.now() });
      });
      return 'succeeded';
    } catch (e) {
      // A model the configuration no longer has is a model error (fallback, “模型不可用”), not a defect.
      errorClass = e instanceof StepError ? e.errorClass : e instanceof ModelNotConfiguredError ? 'MODEL_NOT_FOUND' : 'INTERNAL';
      message = (e as Error).message;
      // An internal error is a defect: keep where it happened (11 steps failed with only “Cannot read
      // properties of undefined (reading 'length')” and nothing to locate it).
      if (errorClass === 'INTERNAL' && (e as Error).stack) stack = (e as Error).stack!.split('\n').slice(0, 8).join('\n');
    } finally {
      if (estimate > 0) rt.release(estimate, step.id);
    }
    const outcome = errorClass === 'CANCELLED' ? (signal.aborted ? 'interrupted' : 'cancelled') : 'failed';
    store.db.run('UPDATE step_attempt SET outcome = ?, error_class = ?, ended_at = ? WHERE step_id = ? AND attempt = ?',
      outcome === 'interrupted' ? 'interrupted' : outcome === 'cancelled' ? 'cancelled' : 'failed', errorClass, Date.now(), step.id, attempt);
    if (errorClass === 'CANCELLED' || signal.aborted) {
      transitionStep(store, step.id, 'interrupted', { ended_at: Date.now(), error_summary: message.slice(0, 500) }, 'aborted');
      return 'interrupted';
    }
    if (errorClass === 'BUDGET_EXHAUSTED') {
      // Re-runnable after a top-up: a new attempt starts from scratch (usage already charged).
      transitionStep(store, step.id, 'interrupted', { ended_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) }, 'budget exhausted');
      return 'blocked_budget';
    }
    // Fallback model: a model that does not exist or is not authorized switches at once; rate
    // limits, exhausted quota and transient provider errors switch once their retries are used up. Once per step.
    // attempts that stopped between turns (pause, stage quota) or were cut off are not failures — only failed
    // attempts count against `max_attempts`, so a step paused four times still gets its retry.
    // a content filter refusal is not retried as it is — the same conversation is refused again. A configured
    // fallback model continues the conversation; without one the audit pauses for a person to decide (start the step
    // afresh, or retry as it is), and the step waits.
    // A model service outage — consecutive service failures, across steps, with no model reply in between
    // (any reply resets the count, `AuditRuntime.charge`) — pauses the audit instead of failing batch after batch; the
    // engine probes the service and continues the audit when it answers again. While the breaker is open, other steps
    // hit by the outage are interrupted, not failed. An attempt that got replies before the outage counts too (in one
    // run both batches were mid-session when the service went down).
    // A step has fewer attempts (2) than the breaker needs failures (3), so a step running
    // alone (profile, merge, decide, one session) failed on an outage before the breaker tripped. Now the breaker is
    // checked when the count reaches 3 and also when a step's last attempt fails with no fallback model left. Either
    // way one ping decides (`serviceCheck`): no answer → the service is down, trip the breaker; an answer → the fault
    // is the steps' own, they retry or fail as before, and the answer counts as a reply (no pause–probe loop).
    if (errorClass === 'PROVIDER_TRANSIENT') {
      rt.serviceFailures++;
      const model = rt.stepModel(current);
      let trip = rt.serviceDown;
      if (!trip && (rt.serviceFailures >= SERVICE_BREAKER_FAILURES
        || (failedTries(store, step.id, attempt) >= current.max_attempts && !fallbackLeft(rt, step.id, current)))) {
        trip = model && rt.servicePing ? !(await serviceCheck(rt, model, step.id)) : rt.serviceFailures >= SERVICE_BREAKER_FAILURES;
      }
      if (trip) {
        store.db.run(`UPDATE step_attempt SET outcome = 'interrupted' WHERE step_id = ? AND attempt = ?`, step.id, attempt);
        transitionStep(store, step.id, 'interrupted', { ended_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) }, 'model service unavailable');
        if (!rt.serviceDown) {
          rt.serviceDown = true;
          rt.event('judgement.made', { kind: 'service_breaker', failures: rt.serviceFailures, model, summary: message.slice(0, 300) }, step.id);
          rt.requestPause?.('model service unavailable', { kind: 'service', model });
        }
        return 'interrupted';
      }
    }
    // No balance or quota left — retrying cannot help. A fallback model of another provider takes over;
    // otherwise the audit pauses until a person tops up the account and continues it (the conversation is kept).
    if (errorClass === 'PROVIDER_QUOTA') {
      const fb = rt.fallbacks.has(step.id) ? null : rt.fallbackFor(current);
      const from = current.provider && current.model ? `${current.provider}/${current.model}` : null;
      if (fb && !fb.degraded && fb.to.provider !== current.provider) {
        rt.fallbacks.set(step.id, fb.to);
        rt.event('error', { error_class: errorClass, step_kind: current.kind, attempt, summary: message.slice(0, 500), retrying: true, ...(stack ? { stack } : {}) }, step.id);
        rt.event('model.fallback', { from, to: fb.to, reason: errorClass, attempt, summary: message.slice(0, 300) }, step.id);
        store.update('step', { id: step.id }, { model: fb.to.model, provider: fb.to.provider, max_attempts: current.max_attempts + 1 });
        transitionStep(store, step.id, 'retry_wait', { retry_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) });
        transitionStep(store, step.id, 'ready');
        continue;
      }
      rt.event('error', { error_class: errorClass, step_kind: current.kind, attempt, summary: message.slice(0, 500), retrying: false, needs_user: true, ...(stack ? { stack } : {}) }, step.id);
      store.db.run(`UPDATE step_attempt SET outcome = 'interrupted' WHERE step_id = ? AND attempt = ?`, step.id, attempt);
      transitionStep(store, step.id, 'interrupted', { ended_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) }, 'model provider quota used up');
      rt.requestPause?.('model provider quota used up', { kind: 'quota', model: current.provider && current.model ? { provider: current.provider, model: current.model } : null });
      return 'interrupted';
    }
    if (errorClass === 'CONTENT_FILTERED') {
      const fb = rt.fallbacks.has(step.id) ? null : rt.fallbackFor(current);
      const refused = rt.stepModel(current);
      const from = refused ? `${refused.provider}/${refused.model}` : null;
      if (fb && !fb.degraded) {
        rt.fallbacks.set(step.id, fb.to);
        rt.event('error', { error_class: errorClass, step_kind: current.kind, attempt, summary: message.slice(0, 500), retrying: true, ...(stack ? { stack } : {}) }, step.id);
        rt.event('model.fallback', { from, to: fb.to, reason: errorClass, attempt, summary: message.slice(0, 300) }, step.id);
        store.update('step', { id: step.id }, { model: fb.to.model, provider: fb.to.provider, max_attempts: current.max_attempts + 1 });
        transitionStep(store, step.id, 'retry_wait', { retry_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) });
        transitionStep(store, step.id, 'ready');
        continue;
      }
      // A cross-checked lane goes on without a pause while another lane of the same task is not refused —
      // the stage continues with that lane's result and the refused one waits for a person (a later run tries it
      // again; at the end it is skipped). Only when every lane of the task was refused does the audit pause.
      // The strategy may ask to pause at the first refused lane instead (`multiModel.onFiltered: 'pause'`).
      const lanes = crossLanes(store, current);
      if (lanes && !(lanes.length && lanes.every(isFilteredLane)) && rt.strategy.multiModel.onFiltered !== 'pause') {
        rt.event('error', { error_class: errorClass, step_kind: current.kind, attempt, summary: message.slice(0, 500), retrying: false, cross_lane: true, ...(stack ? { stack } : {}) }, step.id);
        transitionStep(store, step.id, 'interrupted', { ended_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) }, 'content filtered; the other cross models go on');
        rt.filteredLanes.add(step.id);
        return 'failed';
      }
      rt.event('error', { error_class: errorClass, step_kind: current.kind, attempt, summary: message.slice(0, 500), retrying: false, needs_user: true, ...(stack ? { stack } : {}) }, step.id);
      transitionStep(store, step.id, 'interrupted', { ended_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) }, 'content filtered; waiting for the user');
      rt.requestPause?.('content filtered', { kind: 'content_filter' });
      return 'interrupted';
    }
    const tries = failedTries(store, step.id, attempt);
    const modelError = errorClass === 'AUTH_INVALID' || errorClass === 'MODEL_NOT_FOUND'
      || ((errorClass === 'PROVIDER_TRANSIENT' || errorClass === 'RATE_LIMITED') && tries >= current.max_attempts);
    if (modelError && !rt.fallbacks.has(step.id)) {
      const fb = rt.fallbackFor(current);
      const from = current.provider && current.model ? `${current.provider}/${current.model}` : null;
      if (fb?.degraded) {
        rt.event('model.fallback', { from, to: fb.to, reason: errorClass, attempt, degraded: true }, step.id);
      } else if (fb) {
        rt.fallbacks.set(step.id, fb.to);
        rt.event('error', { error_class: errorClass, step_kind: current.kind, attempt, summary: message.slice(0, 500), retrying: true, ...(stack ? { stack } : {}) }, step.id);
        rt.event('model.fallback', { from, to: fb.to, reason: errorClass, attempt, summary: message.slice(0, 300) }, step.id);
        store.update('step', { id: step.id }, { model: fb.to.model, provider: fb.to.provider, max_attempts: Math.max(current.max_attempts, tries + 1) });
        transitionStep(store, step.id, 'retry_wait', { retry_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) });
        transitionStep(store, step.id, 'ready');
        continue;
      }
    }
    const retryable = RETRYABLE_ERROR_CLASSES.includes(errorClass) && tries < current.max_attempts;
    rt.event('error', { error_class: errorClass, step_kind: current.kind, attempt, summary: message.slice(0, 500), retrying: retryable, ...(stack ? { stack } : {}) }, step.id);
    if (!retryable) {
      transitionStep(store, step.id, 'failed', { ended_at: Date.now(), error_class: errorClass, error_summary: message.slice(0, 500) });
      return 'failed';
    }
    const backoff = errorClass === 'RATE_LIMITED' ? opts.rateLimitBackoffMs : opts.retryBackoffMs;
    transitionStep(store, step.id, 'retry_wait', { retry_at: Date.now() + backoff, error_class: errorClass, error_summary: message.slice(0, 500) });
    await sleep(backoff, signal);
    // Re-read: a step skipped or cancelled during the backoff is final and must not move back to ready.
    const waited = getStep(store, step.id);
    if (waited.status === 'skipped' || waited.status === 'cancelled') return waited.status;
    transitionStep(store, step.id, 'ready');
  }
}

/** Failed attempts that count against `max_attempts` (pauses, stage stops and cut-offs do not). */
function failedTries(store: Store, stepId: string, attempt: number): number {
  return store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM step_attempt WHERE step_id = ? AND outcome = 'failed' AND COALESCE(error_class, '') <> 'BUDGET_EXHAUSTED'`, stepId)?.n ?? attempt;
}

/**
 * Ping the model service once; steps failing at the same time share the request. True when it answered: the
 * failure count restarts. Recorded as a `service_check` judgement.
 */
async function serviceCheck(rt: AuditRuntime, model: ModelRef, stepId: string): Promise<boolean> {
  rt.serviceChecking ??= (async () => {
    let r: { ok: boolean; detail: string };
    try {
      r = await rt.servicePing!(model);
    } catch (e) {
      r = { ok: false, detail: (e as Error).message };
    }
    rt.event('judgement.made', { kind: 'service_check', ok: r.ok, detail: r.detail.slice(0, 300), model, failures: rt.serviceFailures }, stepId);
    if (r.ok) rt.serviceFailures = 0;
    return r.ok;
  })().finally(() => { rt.serviceChecking = null; });
  return rt.serviceChecking;
}

/**
 * The other lanes of a cross-checked task: the same task on the other cross models — lineage `…-M<n>-…`
 * (threat model, hunt batch, domain round, lead session, hypothesis batch), or a review vote on the same finding.
 * Lanes not created yet are missing (their model has not started the task). Null when the step is not a cross lane.
 */
export function crossLanes(store: Store, step: StepRow): StepRow[] | null {
  const m = /^(.*)-M(\d+)-(.*)$/.exec(step.lineage_id ?? '');
  if (m) {
    const same = new RegExp(`^${escapeRe(m[1]!)}-M\\d+-${escapeRe(m[3]!)}$`);
    return store.all<StepRow>('SELECT * FROM step WHERE audit_id = ? AND kind = ? AND id <> ?', step.audit_id, step.kind, step.id).filter((r) => same.test(r.lineage_id ?? ''));
  }
  const input = JSON.parse(step.input || '{}') as { findingId?: string; vote?: boolean };
  if (step.kind === 'challenge' && input.vote && input.findingId) {
    return store.all<StepRow>(`SELECT * FROM step WHERE audit_id = ? AND kind = 'challenge' AND id <> ? AND json_extract(input, '$.findingId') = ? AND json_extract(input, '$.vote') = 1`, step.audit_id, step.id, input.findingId);
  }
  return null;
}

/** A lane the content filter refused and that waits for a person. */
export function isFilteredLane(s: Pick<StepRow, 'status' | 'error_class'>): boolean {
  return s.status === 'interrupted' && s.error_class === 'CONTENT_FILTERED';
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** A fallback model the step can still switch to (once per step; a degraded one does not replace the model). */
function fallbackLeft(rt: AuditRuntime, stepId: string, step: StepRow): boolean {
  if (rt.fallbacks.has(stepId)) return false;
  const fb = rt.fallbackFor(step);
  return !!fb && !fb.degraded;
}

/** Map a session outcome to a step error (null when the session completed). */
export function sessionError(o: { status: string; errorClass: ErrorClass | null; errorMessage?: string }): StepError | null {
  if (o.status === 'completed') return null;
  const cls: ErrorClass = o.status === 'contract_failed' ? 'OUTPUT_CONTRACT'
    : o.status === 'max_turns' ? 'STEP_TIMEOUT'
      : o.status === 'aborted' ? 'CANCELLED'
        : o.status === 'budget_stopped' ? 'BUDGET_EXHAUSTED'
          : o.errorClass ?? 'PROVIDER_TRANSIENT';
  return new StepError(cls, o.errorMessage ?? o.status);
}
