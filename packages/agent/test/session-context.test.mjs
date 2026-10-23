// A session whose context leaves no room for the answer ends as CONTEXT_OVERFLOW at once instead of spending its turns
// on 1-token replies. The model is pi's faux provider (replay mode) answering with scripted messages; it reports its own
// usage (about chars / 4), so the context is made large through the prompt.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Type } from 'typebox';
import { ModelHub, runSession } from '../dist/index.js';

const usage = (input, output) => ({ input, output, cacheRead: 0, cacheWrite: 0, totalTokens: input + output, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } });

/** A session against one faux model; `respond(n)` is the n-th reply (0-based). */
async function session(limits, respond, { maxTurns = 30, prompt = 'score the candidates' } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'xiezhi-session-'));
  try {
    let n = 0;
    const replayer = { next: () => ({ role: 'assistant', api: 'faux', provider: 'p', model: 'm', timestamp: Date.now(), ...respond(n++) }) };
    const config = { modelProviders: [{ id: 'p', api: 'openai-completions', baseUrl: 'http://127.0.0.1:9', models: [{ id: 'm', ...limits }] }] };
    const hub = await ModelHub.create(config, join(dir, 'agent'), { kind: 'replay', replayer });
    const events = [];
    const submit = { name: 'submit_triage', kind: 'submit', description: 'submit', parameters: Type.Object({ ok: Type.Boolean() }), run: () => ({ text: 'accepted' }) };
    const outcome = await runSession({
      hub, model: { provider: 'p', model: 'm' }, cwd: dir, agentDir: join(dir, 'agent'), systemPrompt: 'You review code.', prompt,
      tools: [submit], requiredSubmits: ['submit_triage'], maxTurns, onEvent: (e) => events.push(e),
    });
    return { outcome, requests: n, turns: events.filter((e) => e.type === 'session.turn') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A candidate listing of ~140k estimated tokens, the size of the failing triage prompt. */
const LISTING = Array.from({ length: 5_500 }, (_, i) => `- cand-${i} | repo:src/module${i % 97}/handler.ts:${i} | [entry] POST /api/v1/items/{id} → handler${i} auth=[]`).join('\n');

test('a context larger than the window ends the session instead of sending max_tokens=1 requests', async () => {
  // on a model registered at 128k, pi would send every request of this prompt with max_tokens=1.
  const { outcome, requests } = await session({ contextWindow: 128_000, maxTokens: 8_192 }, () => ({ content: [{ type: 'text', text: 'ok' }], usage: usage(1, 1), stopReason: 'stop' }), { prompt: LISTING });
  assert.equal(outcome.status, 'error');
  assert.equal(outcome.errorClass, 'CONTEXT_OVERFLOW');
  assert.match(outcome.errorMessage, /context too large: the conversation leaves 0 output tokens of the model's 128000-token context window/);
  // stopped before the request went out; without the check the session ran to its 30-turn limit.
  assert.equal(requests, 0);
  assert.ok(outcome.turns <= 1, `turns ${outcome.turns}`);
});

test('the same conversation on a model registered with its real window goes on', async () => {
  const { outcome } = await session({ contextWindow: 400_000, maxTokens: 8_192 }, (n) => (n === 0
    ? { content: [{ type: 'text', text: 'reading' }], usage: usage(136_000, 50), stopReason: 'stop' }
    : { content: [{ type: 'toolCall', id: `c${n}`, name: 'submit_triage', arguments: { ok: true } }], usage: usage(136_100, 30), stopReason: 'toolUse' }), { prompt: LISTING });
  assert.equal(outcome.status, 'completed');
  assert.equal(outcome.errorClass, null);
});

test('replies cut at the output limit with no output end the session as CONTEXT_OVERFLOW', async () => {
  // a provider that clamps on its own (the estimate sees room): only the empty truncated replies tell.
  const { outcome, turns } = await session({ contextWindow: 1_000_000, maxTokens: 8_192 }, () => ({ content: [{ type: 'text', text: '' }], usage: usage(2_000, 1), stopReason: 'length' }));
  assert.equal(outcome.errorClass, 'CONTEXT_OVERFLOW');
  assert.match(outcome.errorMessage, /3 replies in a row were cut at the output limit/);
  assert.ok(turns.length <= 4, `turns ${turns.length}`);
});
