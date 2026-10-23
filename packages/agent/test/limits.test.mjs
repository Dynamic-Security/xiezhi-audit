// Model limits from a provider's model listing, and the output room left under pi-ai's max_tokens clamp.
// Runs against the build: pnpm build && pnpm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { contextTooLarge, modelLimitsOf, modelListingOf, outputRoom, withProbedLimits } from '../dist/index.js';

test('limits of OpenAI-compatible gateway entries (magpie / OpenRouter / vLLM)', () => {
  assert.deepEqual(modelLimitsOf({ id: 'claude-haiku-5-5', object: 'model', context_length: 200000, max_output_tokens: 64000 }), { contextWindow: 200000, maxTokens: 64000 });
  assert.deepEqual(modelLimitsOf({ id: 'x', context_window: '1000000', max_completion_tokens: '65536' }), { contextWindow: 1000000, maxTokens: 65536 });
  assert.deepEqual(modelLimitsOf({ id: 'or/x', context_length: 131072, top_provider: { context_length: 131072, max_completion_tokens: 16384 } }), { contextWindow: 131072, maxTokens: 16384 });
  assert.deepEqual(modelLimitsOf({ id: 'qwen', max_model_len: 32768 }), { contextWindow: 32768 });
});

test('limits of Anthropic /v1/models entries', () => {
  assert.deepEqual(modelLimitsOf({ id: 'claude-opus-5-5', type: 'model', max_input_tokens: 200000, max_tokens: 128000 }), { contextWindow: 200000, maxTokens: 128000 });
});

test('entries without usable limits give none; the output cap never exceeds the window', () => {
  assert.deepEqual(modelLimitsOf({ id: 'gpt', object: 'model', owned_by: 'openai' }), {});
  assert.deepEqual(modelLimitsOf({ id: 'x', context_length: 0, max_output_tokens: -1 }), {});
  assert.deepEqual(modelLimitsOf({ id: 'x', context_length: 512, max_output_tokens: 100 }), {});
  assert.deepEqual(modelLimitsOf({ id: 'x', context_length: 'lots' }), {});
  assert.deepEqual(modelLimitsOf({ id: 'x', context_length: 4096, max_output_tokens: 8192 }), { contextWindow: 4096, maxTokens: 4096 });
  assert.deepEqual(modelLimitsOf(null), {});
});

test('a probe response yields ids and the limits it reports', () => {
  const r = modelListingOf({
    object: 'list',
    data: [
      { id: 'claude-sonnet-5-5', context_length: 200000, max_output_tokens: 64000 },
      { id: 'gpt-5', context_window: 400000 },
      { id: 'embedding-3' },
      { object: 'model' },
    ],
  });
  assert.deepEqual(r.models, ['claude-sonnet-5-5', 'gpt-5', 'embedding-3']);
  assert.deepEqual(r.limits, { 'claude-sonnet-5-5': { contextWindow: 200000, maxTokens: 64000 }, 'gpt-5': { contextWindow: 400000 } });
  assert.match(r.detail, /3 个模型（2 个附带上下文/);
  assert.deepEqual(modelListingOf([{ id: 'a', context_length: 8192 }]).limits, { a: { contextWindow: 8192 } });
  assert.deepEqual(modelListingOf(null), { detail: '可连通', models: [], limits: {} });
});

test('probed limits fill only what the configuration leaves unset', () => {
  const { models, updated } = withProbedLimits(
    [{ id: 'a' }, { id: 'b', contextWindow: 100000 }, { id: 'c', contextWindow: 50000, maxTokens: 4000 }, { id: 'd' }],
    { a: { contextWindow: 200000, maxTokens: 64000 }, b: { contextWindow: 200000, maxTokens: 64000 }, c: { contextWindow: 1, maxTokens: 1 } },
  );
  assert.deepEqual(models, [
    { id: 'a', contextWindow: 200000, maxTokens: 64000 },
    { id: 'b', contextWindow: 100000, maxTokens: 64000 },
    { id: 'c', contextWindow: 50000, maxTokens: 4000 },
    { id: 'd' },
  ]);
  assert.deepEqual(updated, ['a', 'b']);
});

const usage = (input, output = 1, cacheRead = 0) => ({ input, output, cacheRead, cacheWrite: 0, totalTokens: input + output + cacheRead, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } });
const user = (text) => ({ role: 'user', content: [{ type: 'text', text }], timestamp: 1 });
const reply = (u, stopReason = 'stop') => ({ role: 'assistant', content: [{ type: 'text', text: '' }], usage: u, stopReason, timestamp: 2 });

test('the clamp of the failing triage: 136k tokens on a model registered at 128k leaves no output room', () => {
  const model = { contextWindow: 128_000, maxTokens: 8_192 };
  const messages = [user('x'.repeat(255_000)), reply(usage(4_000, 1, 132_000)), user('请调用 submit_triage')];
  const room = outputRoom(model, messages);
  assert.ok(room < 1, `room ${room}`);
  assert.match(contextTooLarge(model, room), /context too large: the conversation leaves 0 output tokens of the model's 128000-token context window/);
  // registered with its real window, the same conversation fits.
  const real = { contextWindow: 200_000, maxTokens: 8_192 };
  assert.equal(outputRoom(real, messages), 8_192);
  assert.equal(contextTooLarge(real, outputRoom(real, messages)), null);
});

test('output room: estimate before any reply, failed replies ignored, small output caps, no window', () => {
  const model = { contextWindow: 128_000, maxTokens: 8_192 };
  // no reply yet: chars / 4 (255k chars ≈ 64k tokens) leaves the full cap.
  assert.equal(outputRoom(model, [user('x'.repeat(255_000))]), 8_192);
  // an errored reply's usage does not count; the earlier valid one does.
  const msgs = [user('a'), reply(usage(120_000)), user('b'), reply(usage(1), 'error')];
  assert.equal(outputRoom(model, msgs), 128_000 - 120_001 - 1 - 4096);
  assert.equal(contextTooLarge(model, outputRoom(model, msgs)), null);
  // a model whose output cap is under the floor is judged by its cap.
  const small = { contextWindow: 8_192, maxTokens: 512 };
  assert.equal(contextTooLarge(small, 512), null);
  assert.notEqual(contextTooLarge(small, 300), null);
  assert.equal(outputRoom({ contextWindow: 0, maxTokens: 8_192 }, msgs), Infinity);
  assert.equal(contextTooLarge(model, 1023) !== null, true);
  assert.equal(contextTooLarge(model, 1024), null);
});
