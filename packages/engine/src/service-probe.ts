// Model service probe: an audit the service breaker paused is probed at growing intervals
// (1, 2, 4, 8, then every 10 minutes, for at most a day) with one minimal model request; when the service answers,
// the audit is queued again and continues where its steps stopped. A person can still continue or cancel it at any time.
import type { ModelRef } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { getAudit, transitionAudit } from './state.js';

export const PROBE_DELAYS_MS = [1, 2, 4, 8, 10].map((m) => m * 60_000);
export const PROBE_GIVE_UP_MS = 24 * 3600_000;

/** Transition reasons of a service pause and of the automatic continuation. */
export const SERVICE_PAUSE_REASON = 'model service unavailable';
export const SERVICE_RESTORED_REASON = 'model service restored';

export type ServicePing = (model: ModelRef) => Promise<{ ok: boolean; detail: string }>;

export interface ProbeDeps {
  store: Store;
  ping: ServicePing;
  delays?: readonly number[];
  /** The audit was queued again: the caller starts it (the service scheduler kicks its queue). */
  resumed: (auditId: string) => void;
}

export class ServiceProbes {
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private stopped = false;

  constructor(private readonly d: ProbeDeps) {}

  /** Start probing for a paused audit (replaces a probe already running for it). */
  watch(auditId: string, model: ModelRef): void {
    this.cancel(auditId);
    this.schedule(auditId, model, 0, Date.now());
  }

  isWatching(auditId: string): boolean {
    return this.timers.has(auditId);
  }

  cancel(auditId: string): void {
    const t = this.timers.get(auditId);
    if (t) clearTimeout(t);
    this.timers.delete(auditId);
  }

  stopAll(): void {
    this.stopped = true;
    for (const t of this.timers.values()) clearTimeout(t);
    this.timers.clear();
  }

  private schedule(auditId: string, model: ModelRef, n: number, since: number): void {
    if (this.stopped) return;
    const delays = this.d.delays ?? PROBE_DELAYS_MS;
    const delay = delays[Math.min(n, delays.length - 1)]!;
    if (Date.now() + delay - since > PROBE_GIVE_UP_MS) {
      this.d.store.appendEvent(auditId, 'judgement.made', { kind: 'service_probe', ok: false, gave_up: true, attempts: n });
      return;
    }
    const t = setTimeout(() => void this.probe(auditId, model, n, since), delay);
    t.unref?.();
    this.timers.set(auditId, t);
  }

  private async probe(auditId: string, model: ModelRef, n: number, since: number): Promise<void> {
    this.timers.delete(auditId);
    if (this.stopped || getAudit(this.d.store, auditId).status !== 'paused') return;
    let r: { ok: boolean; detail: string };
    try {
      r = await this.d.ping(model);
    } catch (e) {
      r = { ok: false, detail: (e as Error).message };
    }
    if (this.stopped) return;
    // The audit may have been continued or cancelled by hand while the probe ran.
    if (getAudit(this.d.store, auditId).status !== 'paused') return;
    this.d.store.appendEvent(auditId, 'judgement.made', { kind: 'service_probe', ok: r.ok, detail: r.detail.slice(0, 300), attempt: n + 1, model });
    if (!r.ok) return this.schedule(auditId, model, n + 1, since);
    transitionAudit(this.d.store, auditId, 'queued', { reason: SERVICE_RESTORED_REASON });
    this.d.resumed(auditId);
  }
}
