// Global model-request limit (`concurrency.modelRequests`): every model request of the
// process — audits, conversations, repository analysis, knowledge drafting — passes one priority gate.
// Conversation replies (a person is waiting) go before queued background work. The capacity is read on
// every acquire/release, so a settings change applies at once.
import { AsyncLocalStorage } from 'node:async_hooks';

export type ModelPriority = 'interactive' | 'background';

/** Who is asking: set around a session so the provider wrapper knows the priority and whom to tell about waits. */
export interface ModelCallContext {
  priority: ModelPriority;
  /** Called when a request has to wait for a free slot, and when it gets one (waited ms). */
  onQueued?: () => void;
  onDequeued?: (waitedMs: number) => void;
}

export const modelCallContext = new AsyncLocalStorage<ModelCallContext>();

interface Waiter { high: boolean; grant: (release: () => void) => void }

/** A counting gate with two priorities; also used for an audit's session slots. */
export class PriorityGate {
  private active = 0;
  private readonly queue: Waiter[] = [];

  constructor(private capacity: () => number) {}

  setCapacity(capacity: () => number): void {
    this.capacity = capacity;
    this.pump();
  }

  stats(): { active: number; queued: number; capacity: number } {
    return { active: this.active, queued: this.queue.length, capacity: this.limit() };
  }

  /**
   * Wait for a slot (`high` goes before queued normal requests); the returned release is idempotent.
   * `onQueued` runs when the request has to wait.
   * Rejects with the signal's reason when aborted while queued.
   */
  acquire(opts: { high?: boolean; signal?: AbortSignal; onQueued?: () => void } = {}): Promise<{ release: () => void; waited: boolean }> {
    const { signal } = opts;
    if (signal?.aborted) return Promise.reject(signal.reason ?? new Error('aborted'));
    if (this.active < this.limit() && !this.queue.length) {
      this.active++;
      return Promise.resolve({ release: this.releaser(), waited: false });
    }
    return new Promise((resolve, reject) => {
      const w: Waiter = {
        high: !!opts.high,
        grant: (release) => { signal?.removeEventListener('abort', onAbort); resolve({ release, waited: true }); },
      };
      const onAbort = () => {
        const i = this.queue.indexOf(w);
        if (i >= 0) this.queue.splice(i, 1);
        reject(signal?.reason ?? new Error('aborted'));
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.queue.push(w);
      opts.onQueued?.();
      this.pump();
    });
  }

  private limit(): number {
    return Math.max(1, Math.floor(this.capacity()) || 1);
  }

  private releaser(): () => void {
    let done = false;
    return () => {
      if (done) return;
      done = true;
      this.active--;
      this.pump();
    };
  }

  private pump(): void {
    while (this.active < this.limit() && this.queue.length) {
      const i = this.queue.findIndex((w) => w.high);
      const [w] = this.queue.splice(i >= 0 ? i : 0, 1);
      this.active++;
      w!.grant(this.releaser());
    }
  }
}

/** The process-wide gate; the engine points its capacity at the live config. */
export const modelGate = new PriorityGate(() => 4);
