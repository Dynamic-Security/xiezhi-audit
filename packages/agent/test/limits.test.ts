// Model limits from a provider's model listing, and the output room left under pi-ai's max_tokens clamp.
import { describe, expect, it } from 'vitest';
import { contextTooLarge, modelLimitsOf, modelListingOf, outputRoom, withProbedLimits } from '@xiezhi/agent';

describe('model limits and output room', () => {
  it('limits of OpenAI-compatible gateway entries (magpie / OpenRouter / vLLM)', () => {
    expect(modelLimitsOf({ id: 'claude-haiku-5-5', object: 'model', context_length: 200000, max_output_tokens: 64000 })).toEqual({ contextWindow: 200000, maxTokens: 64000 });
    expect(modelLimitsOf({ id: 'x', context_window: '1000000', max_completion_tokens: '65536' })).toEqual({ contextWindow: 1000000, maxTokens: 65536 });
    expect(modelLimitsOf({ id: 'or/x', context_length: 131072, top_provider: { context_length: 131072, max_completion_tokens: 16384 } })).toEqual({ contextWindow: 131072, maxTokens: 16384 });
    expect(modelLimitsOf({ id: 'qwen', max_model_len: 32768 })).toEqual({ contextWindow: 32768 });
  });

  it('limits of Anthropic /v1/models entries', () => {
    expect(modelLimitsOf({ id: 'claude-opus-5-5', type: 'model', max_input_tokens: 200000, max_tokens: 128000 })).toEqual({ contextWindow: 200000, maxTokens: 128000 });
  });

  it('entries without usable limits give none; the output cap never exceeds the window', () => {
    expect(modelLimitsOf({ id: 'gpt', object: 'model', owned_by: 'openai' })).toEqual({});
    expect(modelLimitsOf({ id: 'x', context_length: 0, max_output_tokens: -1 })).toEqual({});
    expect(modelLimitsOf({ id: 'x', context_length: 512, max_output_tokens: 100 })).toEqual({});
    expect(modelLimitsOf({ id: 'x', context_length: 'lots' })).toEqual({});
    expect(modelLimitsOf({ id: 'x', context_length: 4096, max_output_tokens: 8192 })).toEqual({ contextWindow: 4096, maxTokens: 4096 });
    expect(modelLimitsOf(null)).toEqual({});
  });

  it('a probe response yields ids and the limits it reports', () => {
    const r = modelListingOf({
      object: 'list',
      data: [
        { id: 'claude-sonnet-5-5', context_length: 200000, max_output_tokens: 64000 },
        { id: 'gpt-5', context_window: 400000 },
        { id: 'embedding-3' },
        { object: 'model' },
      ],
    });
    expect(r.models).toEqual(['claude-sonnet-5-5', 'gpt-5', 'embedding-3']);
    expect(r.limits).toEqual({ 'claude-sonnet-5-5': { contextWindow: 200000, maxTokens: 64000 }, 'gpt-5': { contextWindow: 400000 } });
    expect(r.detail).toMatch(/3 个模型（2 个附带上下文/);
    expect(modelListingOf([{ id: 'a', context_length: 8192 }]).limits).toEqual({ a: { contextWindow: 8192 } });
    expect(modelListingOf(null)).toEqual({ detail: '可连通', models: [], limits: {} });
  });

  it('probed limits fill only what the configuration leaves unset', () => {
    const { models, updated } = withProbedLimits(
      [{ id: 'a' }, { id: 'b', contextWindow: 100000 }, { id: 'c', contextWindow: 50000, maxTokens: 4000 }, { id: 'd' }],
      { a: { contextWindow: 200000, maxTokens: 64000 }, b: { contextWindow: 200000, maxTokens: 64000 }, c: { contextWindow: 1, maxTokens: 1 } },
    );
    expect(models).toEqual([
      { id: 'a', contextWindow: 200000, maxTokens: 64000 },
      { id: 'b', contextWindow: 100000, maxTokens: 64000 },
      { id: 'c', contextWindow: 50000, maxTokens: 4000 },
      { id: 'd' },
    ]);
    expect(updated).toEqual(['a', 'b']);
  });

  const usage = (input, output = 1, cacheRead = 0) => ({ input, output, cacheRead, cacheWrite: 0, totalTokens: input + output + cacheRead, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } });
  const user = (text) => ({ role: 'user', content: [{ type: 'text', text }], timestamp: 1 });
  const reply = (u, stopReason = 'stop') => ({ role: 'assistant', content: [{ type: 'text', text: '' }], usage: u, stopReason, timestamp: 2 });

  it('the clamp of the failing triage: 136k tokens on a model registered at 128k leaves no output room', () => {
    const model = { contextWindow: 128_000, maxTokens: 8_192 };
    const messages = [user('x'.repeat(255_000)), reply(usage(4_000, 1, 132_000)), user('请调用 submit_triage')];
    const room = outputRoom(model, messages);
    expect(room < 1, `room ${room}`).toBe(true);
    expect(contextTooLarge(model, room)).toMatch(/context too large: the conversation leaves 0 output tokens of the model's 128000-token context window/);
    // registered with its real window, the same conversation fits.
    const real = { contextWindow: 200_000, maxTokens: 8_192 };
    expect(outputRoom(real, messages)).toBe(8_192);
    expect(contextTooLarge(real, outputRoom(real, messages))).toBe(null);
  });

  it('output room: estimate before any reply, failed replies ignored, small output caps, no window', () => {
    const model = { contextWindow: 128_000, maxTokens: 8_192 };
    // no reply yet: chars / 4 (255k chars ≈ 64k tokens) leaves the full cap.
    expect(outputRoom(model, [user('x'.repeat(255_000))])).toBe(8_192);
    // an errored reply's usage does not count; the earlier valid one does.
    const msgs = [user('a'), reply(usage(120_000)), user('b'), reply(usage(1), 'error')];
    expect(outputRoom(model, msgs)).toBe(128_000 - 120_001 - 1 - 4096);
    expect(contextTooLarge(model, outputRoom(model, msgs))).toBe(null);
    // a model whose output cap is under the floor is judged by its cap.
    const small = { contextWindow: 8_192, maxTokens: 512 };
    expect(contextTooLarge(small, 512)).toBe(null);
    expect(contextTooLarge(small, 300)).not.toBe(null);
    expect(outputRoom({ contextWindow: 0, maxTokens: 8_192 }, msgs)).toBe(Infinity);
    expect(contextTooLarge(model, 1023) !== null).toBe(true);
    expect(contextTooLarge(model, 1024)).toBe(null);
  });
});
