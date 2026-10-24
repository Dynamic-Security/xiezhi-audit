// Global model gate: capacity, interactive first, abort while queued, live capacity.
import { describe, expect, it } from 'vitest';
import { PriorityGate } from '../src/gate.js';

const tick = () => new Promise((r) => setTimeout(r, 0));

describe('PriorityGate', () => {
  it('admits up to the capacity and hands freed slots to high-priority waiters first', async () => {
    const gate = new PriorityGate(() => 1);
    const a = await gate.acquire();
    expect(a.waited).toBe(false);
    const order: string[] = [];
    const queued: string[] = [];
    const low = gate.acquire({ onQueued: () => queued.push('low') }).then((s) => { order.push('low'); return s; });
    const high = gate.acquire({ high: true, onQueued: () => queued.push('high') }).then((s) => { order.push('high'); return s; });
    await tick();
    expect(gate.stats()).toEqual({ active: 1, queued: 2, capacity: 1 });
    expect(queued).toEqual(['low', 'high']);
    a.release();
    a.release(); // idempotent
    const h = await high;
    expect(h.waited).toBe(true);
    expect(order).toEqual(['high']);
    h.release();
    (await low).release();
    expect(order).toEqual(['high', 'low']);
    expect(gate.stats().active).toBe(0);
  });

  it('drops a waiter whose signal aborts, and applies a new capacity at once', async () => {
    let cap = 1;
    const gate = new PriorityGate(() => cap);
    const held = await gate.acquire();
    const ac = new AbortController();
    const aborted = gate.acquire({ signal: ac.signal });
    const waiting = gate.acquire();
    ac.abort(new Error('stop'));
    await expect(aborted).rejects.toThrow('stop');
    expect(gate.stats().queued).toBe(1);
    cap = 2;
    gate.setCapacity(() => cap);
    (await waiting).release();
    held.release();
    expect(gate.stats()).toEqual({ active: 0, queued: 0, capacity: 2 });
  });
});
