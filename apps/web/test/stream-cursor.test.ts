// The audit page is reused across audits; the event cursor must not carry over.
import { describe, expect, it } from 'vitest';
import { advanceCursor, cursorFor } from '../src/shared/stream/cache';

describe('per-audit event cursor', () => {
  it('switching audits starts the new subscription from seq 0', () => {
    const a = cursorFor(null, 'aud_A');
    for (const seq of [1, 2, 3000]) expect(advanceCursor(a, seq)).toBe(true);
    expect(a.seq).toBe(3000);
    // Same audit (re-render, enabled toggled, reconnect): the cursor is kept, so nothing is replayed twice.
    expect(cursorFor(a, 'aud_A')).toBe(a);
    // Audit B on the same page: a fresh cursor, and B's early events are accepted.
    const b = cursorFor(a, 'aud_B');
    expect(b).not.toBe(a);
    expect(b).toEqual({ aid: 'aud_B', seq: 0 });
    expect(advanceCursor(b, 1)).toBe(true);
    expect(advanceCursor(b, 2)).toBe(true);
    // A late event of A's subscription only moves A's cursor.
    expect(advanceCursor(a, 3001)).toBe(true);
    expect(b.seq).toBe(2);
    // Back to A: a fresh cursor again (the subscription resubscribes from the start; cache writes are idempotent by seq).
    expect(cursorFor(b, 'aud_A').seq).toBe(0);
  });

  it('drops duplicates and older events', () => {
    const c = cursorFor(null, 'aud_A');
    expect(advanceCursor(c, 5)).toBe(true);
    expect(advanceCursor(c, 5)).toBe(false);
    expect(advanceCursor(c, 4)).toBe(false);
    expect(advanceCursor(c, 6)).toBe(true);
    expect(c.seq).toBe(6);
  });
});

describe('engine `error` events on the audit stream', () => {
  it('a server event named error carries data; EventSource’s own error does not', async () => {
    const { isEngineEvent } = await import('../src/shared/stream/streams');
    expect(isEngineEvent(new MessageEvent('error', { data: '{"seq":3,"type":"error"}' }))).toBe(true);
    expect(isEngineEvent(new Event('error'))).toBe(false);
  });
});
