// Background scheduling inside the service process: planning runs as soon as
// a plan is requested; confirmed audits run FIFO with `concurrency.audits` slots. HTTP handlers only
// enqueue — closing a browser never affects a run.
import { getAudit, type Engine, queries as Q } from '@xiezhi/engine';

export class Scheduler {
  private readonly shutdown = new AbortController();
  private readonly running = new Map<string, Promise<unknown>>();
  private readonly planning = new Map<string, Promise<unknown>>();
  private kicking = false;

  constructor(private readonly engine: Engine, private readonly log: (msg: string, extra?: Record<string, unknown>) => void) {
    // the model service probe queued a paused audit again.
    engine.onAutoResume(() => this.kick());
  }

  get runningIds(): string[] {
    return [...this.running.keys()];
  }

  isBusy(auditId: string): boolean {
    return this.running.has(auditId) || this.planning.has(auditId);
  }

  plan(auditId: string): void {
    if (this.planning.has(auditId)) return;
    const p = this.engine.plan(auditId, this.shutdown.signal)
      // Reverification confirms itself after planning: start it.
      .then(() => { if (getAudit(this.engine.store, auditId).status === 'queued') this.kick(); })
      .catch((e) => this.log('plan failed', { auditId, error: String((e as Error).message) }))
      .finally(() => this.planning.delete(auditId));
    this.planning.set(auditId, p);
  }

  /** Start queued audits while slots are free. */
  kick(): void {
    if (this.kicking || this.shutdown.signal.aborted) return;
    this.kicking = true;
    try {
      const limit = this.engine.store.config.concurrency.audits;
      while (this.running.size < limit) {
        const busy = [...this.running.keys()];
        const id = Q.nextQueuedAudit(this.engine.store, busy);
        if (!id) break;
        const p = this.engine.run(id, this.shutdown.signal)
          .catch((e) => this.log('run failed', { auditId: id, error: String((e as Error).message) }))
          .finally(() => {
            this.running.delete(id);
            setImmediate(() => this.kick());
          });
        this.running.set(id, p);
      }
    } finally {
      this.kicking = false;
    }
  }

  /** After a resume the audit may need planning again (interrupted before confirmation). */
  afterResume(auditId: string): void {
    if (getAudit(this.engine.store, auditId).status === 'planning') this.plan(auditId);
    else this.kick();
  }

  async stop(): Promise<void> {
    this.shutdown.abort('shutdown');
    await Promise.allSettled([...this.running.values(), ...this.planning.values()]);
  }
}
