// CLI event following: SSE parsing, resume by seq, degradation to JSON polling,
// and ignoring replayed status transitions older than the wait.
import { describe, expect, it, vi } from 'vitest';
import type { AuditDetailDto, EventDto } from '@xiezhi/contracts';
import { SseParser, type SseMessage } from '../src/sse.js';
import { follow, type Remote } from '../src/remote.js';

describe('SseParser', () => {
  it('assembles messages across chunks, CRLF, comments and multi-line data', () => {
    const p = new SseParser();
    expect(p.push('retry: 3000\n\n: ping\n\nid: 7\nevent: step.status')).toEqual([]);
    expect(p.push('_changed\r\ndata: {"a":\r\ndata: 1}\r\n\r\nevent: end\ndata: {}\n')).toEqual([
      { id: '7', event: 'step.status_changed', data: '{"a":\n1}' },
    ]);
    expect(p.push('\n')).toEqual([{ id: '7', event: 'end', data: '{}' }]);
  });
});

const ev = (seq: number, type: string, payload: Record<string, unknown> = {}): EventDto => ({ seq, type: type as EventDto['type'], stepId: null, ts: '2026-09-27T00:00:00.000Z', payload });
const frame = (e: EventDto): SseMessage => ({ id: String(e.seq), event: e.type, data: JSON.stringify(e) });
const detail = (status: string, lastEventSeq: number) => ({ id: 'aud_1', status, lastEventSeq }) as unknown as AuditDetailDto;
const FAST = { pollMs: 5, sseRetryMs: 1000, reconnectMs: 1 };

function fakeRemote(opts: { details: AuditDetailDto[]; stream: (path: string, on: (m: SseMessage) => boolean | void) => Promise<void>; poll?: (path: string) => unknown }): Remote & { paths: string[] } {
  const paths: string[] = [];
  let d = 0;
  return {
    base: 'http://127.0.0.1:1', paths,
    get: async <T>(p: string) => {
      paths.push(`GET ${p}`);
      if (p.includes('/events')) return opts.poll!(p) as T;
      return opts.details[Math.min(d++, opts.details.length - 1)] as T;
    },
    post: async () => { throw new Error('unused'); },
    raw: async () => { throw new Error('unused'); },
    stream: async (p, on) => { paths.push(`SSE ${p}`); return opts.stream(p, on); },
  };
}

describe('follow', () => {
  it('streams over SSE and stops at `end`', async () => {
    const r = fakeRemote({
      details: [detail('running', 3), detail('completed', 6)],
      stream: async (_p, on) => {
        for (const e of [ev(1, 'audit.status_changed', { to: 'queued' }), ev(4, 'step.status_changed', { kind: 'hunt', to: 'running' }), ev(6, 'audit.status_changed', { to: 'completed' })]) {
          if (on(frame(e)) === false) return;
        }
        on({ id: null, event: 'end', data: '{}' });
      },
    });
    const log = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const a = await follow(r, 'aud_1', (s) => ['completed', 'partial', 'failed', 'cancelled'].includes(s), FAST);
    log.mockRestore();
    expect(a.status).toBe('completed');
    expect(r.paths.filter((p) => p.startsWith('SSE'))).toEqual(['SSE /audits/aud_1/events?after=0']);
  });

  it('ignores replayed transitions older than the wait and resumes by seq after a drop', async () => {
    let call = 0;
    const r = fakeRemote({
      details: [detail('running', 5), detail('paused', 9)],
      stream: async (_p, on) => {
        call++;
        if (call === 1) {
          // History: an earlier pause (seq 2) must not end a wait that started at seq 5. Then the connection drops.
          on(frame(ev(2, 'audit.status_changed', { to: 'paused' })));
          on(frame(ev(3, 'audit.status_changed', { to: 'running' })));
          on(frame(ev(7, 'step.status_changed', { kind: 'hunt', to: 'running' })));
          return;
        }
        on(frame(ev(7, 'step.status_changed', { kind: 'hunt', to: 'running' })));
        on(frame(ev(9, 'audit.status_changed', { to: 'paused' })));
      },
    });
    const log = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const a = await follow(r, 'aud_1', (s) => s === 'paused', FAST);
    log.mockRestore();
    expect(a.status).toBe('paused');
    expect(r.paths.filter((p) => p.startsWith('SSE'))).toEqual(['SSE /audits/aud_1/events?after=0', 'SSE /audits/aud_1/events?after=7']);
  });

  it('falls back to JSON polling after three failed connections', async () => {
    let polls = 0;
    const r = fakeRemote({
      details: [detail('running', 1), detail('partial', 4)],
      stream: async () => { throw new Error('HTTP 502'); },
      poll: () => (++polls < 3
        ? { resync: false, events: [ev(polls + 1, 'step.status_changed', { kind: 'hunt', to: 'running' })], lastSeq: polls + 1, status: 'running' }
        : { resync: false, events: [ev(4, 'audit.status_changed', { to: 'partial' })], lastSeq: 4, status: 'partial' }),
    });
    const log = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const a = await follow(r, 'aud_1', (s) => s === 'partial', FAST);
    log.mockRestore();
    expect(a.status).toBe('partial');
    expect(r.paths.filter((p) => p.startsWith('SSE'))).toHaveLength(3);
    expect(r.paths.filter((p) => p.includes('/events?after=')).at(-1)).toBe('GET /audits/aud_1/events?after=3');
  });

  it('does not repeat events already printed by an earlier follow', async () => {
    const r = fakeRemote({
      details: [detail('queued', 9), detail('completed', 12)],
      stream: async (p, on) => {
        expect(p).toBe('/audits/aud_1/events?after=9');
        on(frame(ev(11, 'step.status_changed', { kind: 'hunt', to: 'running' })));
        on(frame(ev(12, 'audit.status_changed', { to: 'completed' })));
      },
    });
    const lines: string[] = [];
    const log = vi.spyOn(process.stdout, 'write').mockImplementation((s) => { lines.push(String(s)); return true; });
    await follow(r, 'aud_1', (s) => s === 'completed', FAST, 9);
    log.mockRestore();
    expect(lines.join('')).toContain('hunt running');
  });
});
