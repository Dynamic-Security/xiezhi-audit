// Saved session transcripts: repair on resume and what a continued session already did.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SessionManager } from '@earendil-works/pi-coding-agent';
import { findTranscript, openTranscript, REPAIRED_RESULT, restoredState } from '../src/transcript.js';
import { classifyProviderError, prepareToolArguments, type AuditTool } from '../src/session.js';
import { Type } from 'typebox';
import { check } from '@xiezhi/contracts';

const usage = { input: 100, output: 20, cacheRead: 0, cacheWrite: 0, totalTokens: 120, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
const assistant = (content: unknown[], stopReason = 'toolUse') =>
  ({ role: 'assistant', content, api: 'openai-completions', provider: 'gw', model: 'm1', usage, stopReason, timestamp: Date.now() }) as never;

function saved(build: (sm: SessionManager) => void): string {
  const dir = mkdtempSync(join(tmpdir(), 'ca-transcript-'));
  const sm = SessionManager.create(dir, dir);
  sm.appendMessage({ role: 'user', content: '审计任务', timestamp: Date.now() } as never);
  build(sm);
  return findTranscript(dir)!;
}

describe('session transcripts', () => {
  it('a tool call cut off by a pause gets a result that warns it may have run', () => {
    const file = saved((sm) => {
      sm.appendMessage(assistant([{ type: 'toolCall', id: 'c1', name: 'read', arguments: { path: 'a.java' } }]));
      sm.appendMessage({ role: 'toolResult', toolCallId: 'c1', toolName: 'read', content: [{ type: 'text', text: 'code' }], isError: false, timestamp: Date.now() } as never);
      sm.appendMessage(assistant([{ type: 'toolCall', id: 'c2', name: 'connector_query', arguments: { tool: 'create_issue' } }]));
    });
    const dir = mkdtempSync(join(tmpdir(), 'ca-transcript-'));
    const { sm, resumed } = openTranscript(dir, { dir, resumeFrom: file });
    expect(resumed).toMatchObject({ repaired: 1 });
    const last = sm.buildSessionContext().messages.at(-1) as { role: string; toolCallId: string; isError: boolean; content: { text: string }[] };
    expect(last).toMatchObject({ role: 'toolResult', toolCallId: 'c2', isError: true });
    expect(last.content[0]!.text).toBe(REPAIRED_RESULT);
    expect(REPAIRED_RESULT).toMatch(/可能已经执行/);
  });

  it('a last reply that was aborted is dropped; accepted submissions and turns are restored', () => {
    const file = saved((sm) => {
      sm.appendMessage(assistant([{ type: 'toolCall', id: 's1', name: 'submit_findings', arguments: { findings: [] } }]));
      sm.appendMessage({ role: 'toolResult', toolCallId: 's1', toolName: 'submit_findings', content: [{ type: 'text', text: 'ok' }], isError: false, timestamp: Date.now() } as never);
      sm.appendMessage(assistant([{ type: 'toolCall', id: 's2', name: 'submit_findings', arguments: { findings: ['x'] } }]));
      sm.appendMessage({ role: 'toolResult', toolCallId: 's2', toolName: 'submit_findings', content: [{ type: 'text', text: 'rejected' }], isError: true, timestamp: Date.now() } as never);
      sm.appendMessage(assistant([{ type: 'text', text: '…' }], 'aborted'));
    });
    const dir = mkdtempSync(join(tmpdir(), 'ca-transcript-'));
    const { sm, resumed } = openTranscript(dir, { dir, resumeFrom: file });
    expect(resumed).toMatchObject({ repaired: 0 });
    expect((sm.buildSessionContext().messages.at(-1) as { role: string }).role).toBe('toolResult');
    const r = restoredState(sm, new Set(['submit_findings']));
    expect(r.submissions.submit_findings).toEqual([{ findings: [] }]);
    expect(r.turns).toBe(2);
  });
});

describe('restored submissions are what was accepted, not the raw arguments', () => {
  it('a submission accepted after repair comes back repaired; one that cannot pass the schema is dropped', () => {
    const tool: AuditTool = {
      name: 'submit_profile', kind: 'submit', description: 'd', run: () => ({ text: 'ok' }),
      parameters: Type.Object({ authModel: Type.String(), trustBoundaries: Type.Array(Type.String()) }, { additionalProperties: false }),
    };
    const file = saved((sm) => {
      sm.appendMessage(assistant([{ type: 'toolCall', id: 'p1', name: 'submit_profile', arguments: { authModel: '无鉴权，</authModel>\n<parameter name="trustBoundaries">["网关→服务"]' } }]));
      sm.appendMessage({ role: 'toolResult', toolCallId: 'p1', toolName: 'submit_profile', content: [{ type: 'text', text: 'ok' }], isError: false, timestamp: Date.now() } as never);
      sm.appendMessage(assistant([{ type: 'toolCall', id: 'p2', name: 'submit_profile', arguments: { authModel: 5, trustBoundaries: [] } }]));
      sm.appendMessage({ role: 'toolResult', toolCallId: 'p2', toolName: 'submit_profile', content: [{ type: 'text', text: 'ok' }], isError: false, timestamp: Date.now() } as never);
    });
    const dir = mkdtempSync(join(tmpdir(), 'ca-transcript-'));
    const { sm } = openTranscript(dir, { dir, resumeFrom: file });
    const accept = (_n: string, raw: unknown) => { const a = prepareToolArguments(tool, raw).args; return check(tool.parameters, a).ok ? a : null; };
    expect(restoredState(sm, new Set(['submit_profile']), accept).submissions.submit_profile).toEqual([{ authModel: '无鉴权，', trustBoundaries: ['网关→服务'] }]);
    // Without the preparation the raw arguments came back (the defect).
    expect(restoredState(sm, new Set(['submit_profile'])).submissions.submit_profile![0]).not.toHaveProperty('trustBoundaries');
  });
});

describe('content filter refusals', () => {
  it('a broken stream after a filter notice is CONTENT_FILTERED, not a transient error', () => {
    const notice = "This request was blocked by Gemini's filters. They can occasionally trigger by mistake on safe coding, security, or biology-related queries.";
    expect(classifyProviderError('upstream stream ended without a terminal signal — possible truncation', notice)).toBe('CONTENT_FILTERED');
    expect(classifyProviderError('400 The response was filtered due to the prompt triggering content_filter policy')).toBe('CONTENT_FILTERED');
    expect(classifyProviderError('upstream stream ended without a terminal signal — possible truncation')).toBe('PROVIDER_TRANSIENT');
    expect(classifyProviderError('upstream stream ended', 'Here is the analysis of the SQL injection in OrderDao.')).toBe('PROVIDER_TRANSIENT');
  });
});


describe('tool arguments the repair or the prune could not handle', () => {
  const params = Type.Object({ a: Type.String(), b: Type.Number(), items: Type.Optional(Type.Array(Type.Object({ id: Type.String() }))) }, { additionalProperties: false });
  it('a value split out in one form that leaks again in the other is split too', async () => {
    const { repairLeakedParameters } = await import('../src/repair.js');
    expect(repairLeakedParameters({ focus: 'x</focus>\n<parameter name="affirm">a</affirm>\n<confirmation>maintain</confirmation>' }))
      .toEqual({ focus: 'x', affirm: 'a', confirmation: 'maintain' });
  });
  it('keys the split made up are dropped when the tool does not declare them', () => {
    const tool: AuditTool = { name: 't', kind: 'submit', description: 'd', run: () => ({ text: 'ok' }), parameters: params };
    expect(prepareToolArguments(tool, { a: 'x</a>\n<parameter name="b">2</parameter>\n<parameter name="zz">junk' }).args).toEqual({ a: 'x', b: 2 });
  });
  it('a prune that throws refuses the call instead of failing the session', () => {
    const tool: AuditTool = {
      name: 't', kind: 'submit', description: 'd', run: () => ({ text: 'ok' }), parameters: params,
      prune: (raw: { items: { id: string }[] }) => ({ args: { ...raw, items: raw.items.filter((i) => i.id) }, note: 'n' }),
    };
    const raw = { a: 'x', b: 1, items: '[{"id":1}' };
    expect(() => prepareToolArguments(tool, raw)).not.toThrow();
    expect(prepareToolArguments(tool, raw).args).toBe(raw);
  });
});
