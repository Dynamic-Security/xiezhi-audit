// Trajectory labels — a sub-agent that got no session slot showed “（目标未记录）” and “进行中” for the rest of the
// audit; a call whose arguments were too large for the event had no name.
import { describe, expect, it } from 'vitest';
import type { EventDto } from '@xiezhi/contracts';
import { addSubEvent, subGoal, subNoSlot, type SubNode } from '../src/features/audits/subagent';

const ev = (seq: number, type: string, payload: Record<string, unknown>): EventDto =>
  ({ seq, type, payload: { ...payload, session: { id: 'ses_1', role: 'task' } }, stepId: 'stp_1', ts: '2026-10-11T08:00:00Z' }) as unknown as EventDto;
const node = (): SubNode => ({ kind: 'sub', id: 'ses_1', started: null, finished: null, events: [] });

describe('sub-agent node of the trajectory', () => {
  it('a gave-up slot wait ends the node; its goal comes from the wait events', () => {
    const n = node();
    addSubEvent(n, ev(1, 'session.queued', { wait: 'slot', goal: '阅读 Program.cs' }));
    expect(n.finished).toBeNull();
    addSubEvent(n, ev(2, 'session.dequeued', { wait: 'slot', ms: 20_000, gaveUp: true, goal: '阅读 Program.cs' }));
    expect(n.finished?.seq).toBe(2);
    expect(subNoSlot(n)).toBe(true);
    expect(subGoal(n)).toBe('阅读 Program.cs');
  });

  it('a sub-agent that waited and then ran keeps task.started / task.finished as its header', () => {
    const n = node();
    addSubEvent(n, ev(1, 'session.queued', { wait: 'slot', goal: '追踪 search' }));
    addSubEvent(n, ev(2, 'session.dequeued', { wait: 'slot', ms: 900 }));
    addSubEvent(n, ev(3, 'task.started', { goal: '追踪 search' }));
    expect(n.finished).toBeNull();
    addSubEvent(n, ev(4, 'task.finished', { status: 'completed', turns: 3 }));
    expect(subNoSlot(n)).toBe(false);
    expect(subGoal(n)).toBe('追踪 search');
    expect(n.events.map((e) => e.seq)).toEqual([1, 2]);
  });
});

describe('tool arguments too large for the event', () => {
  it('names the call from the preview’s first string field', async () => {
    const { toolArgs } = await import('../src/shared/format/messages');
    expect(toolArgs('submit_risk_domain', { truncated: true, preview: '{"name":"服务端请求、文件、XML 与反序列化","focus":"四个…' })).toBe('服务端请求、文件、XML 与反序列化');
    expect(toolArgs('submit_findings', { truncated: true, preview: '{"findings":[{"title":"x"' })).toBe('');
    expect(toolArgs('submit_risk_domain', { name: '认证与令牌' })).toBe('认证与令牌');
  });
});
