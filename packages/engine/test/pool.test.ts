// pool with a live limit: a lowered limit holds new items back, a raised one starts more.
import { describe, expect, it } from 'vitest';
import { pool } from '../src/pool.js';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe('pool', () => {
  it('keeps at most the (live) limit in flight and takes items in order', async () => {
    let limit = 2;
    let active = 0;
    const peaks: number[] = [];
    const started: number[] = [];
    const run = pool(Array.from({ length: 8 }, (_, i) => i), () => limit, async (i) => {
      started.push(i);
      active++;
      peaks.push(active);
      await sleep(i < 2 ? 700 : 40);
      active--;
    });
    await sleep(100);
    expect(Math.max(...peaks)).toBe(2);
    limit = 4;
    await sleep(650);
    expect(Math.max(...peaks)).toBe(4);
    await run;
    expect(started).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });

  it('rejects with the first error after the items in flight settle', async () => {
    const done: number[] = [];
    await expect(pool([1, 2, 3, 4], 2, async (i) => {
      if (i === 1) throw new Error('boom');
      await sleep(20);
      done.push(i);
    })).rejects.toThrow('boom');
    expect(done).toContain(2);
  });
});
