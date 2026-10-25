// Model access through pi's ModelRuntime. Providers come only from config.json; keys are
// set as runtime keys so pi never interprets them (`$ENV` / `!command` interpolation is avoided).
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { ModelRuntime } from '@earendil-works/pi-coding-agent';
import { createAssistantMessageEventStream, createProvider, fauxProvider, type AssistantMessage, type AssistantMessageEventStream, type Model } from '@earendil-works/pi-ai';
import type { AppConfig, ModelRef } from '@xiezhi/contracts';
import { Recorder, Replayer } from './replay.js';
import { modelCallContext, modelGate } from './gate.js';
import { DEFAULT_CONTEXT_WINDOW, DEFAULT_MAX_TOKENS } from './limits.js';

export type ModelMode = { kind: 'live' } | { kind: 'replay'; replayer: Replayer } | { kind: 'record'; recorder: Recorder };

export class ModelNotConfiguredError extends Error {
  constructor(ref: ModelRef) {
    super(`model ${ref.provider}/${ref.model} is not configured`);
    this.name = 'ModelNotConfiguredError';
  }
}

export function piVersion(): string {
  let dir = dirname(fileURLToPath(import.meta.resolve('@earendil-works/pi-coding-agent')));
  for (let i = 0; i < 4; i++) {
    const p = join(dir, 'package.json');
    if (existsSync(p)) return (JSON.parse(readFileSync(p, 'utf8')) as { version: string }).version;
    dir = dirname(dir);
  }
  return 'unknown';
}

/** Sent as the key of a provider configured without one; such gateways ignore it. */
export const NO_KEY = 'no-key';

export class ModelHub {
  private constructor(readonly runtime: ModelRuntime, private readonly config: AppConfig, readonly mode: ModelMode) {}

  /** `agentDir` is a private directory inside the data-dir; no user-level pi configuration is read. */
  static async create(config: AppConfig, agentDir: string, mode: ModelMode = { kind: 'live' }): Promise<ModelHub> {
    const runtime = await ModelRuntime.create({ authPath: join(agentDir, 'auth.json'), modelsPath: null, refreshOnCreate: false, allowModelNetwork: false });
    const hub = new ModelHub(runtime, config, mode);
    await hub.register();
    return hub;
  }

  private async register(): Promise<void> {
    for (const p of this.config.modelProviders) {
      const models = p.models.map((m) => ({
        id: m.id, name: m.name ?? m.id, reasoning: m.reasoning ?? false, input: m.images === false ? ['text' as const] : ['text' as const, 'image' as const],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: m.contextWindow ?? DEFAULT_CONTEXT_WINDOW, maxTokens: m.maxTokens ?? DEFAULT_MAX_TOKENS,
      }));
      if (this.mode.kind === 'replay') {
        const replayer = this.mode.replayer;
        const faux = fauxProvider({ provider: p.id, models: models.map((m) => ({ id: m.id, input: m.input, contextWindow: m.contextWindow, maxTokens: m.maxTokens })) });
        const respond = (ctx: { messages?: unknown[] }) => {
          try {
            return replayer.next(ctx) as AssistantMessage;
          } catch (e) {
            return errorMessage(p.id, (e as Error).message);
          }
        };
        faux.setResponses(Array.from({ length: 10_000 }, () => respond));
        this.runtime.registerNativeProvider(faux.provider);
        await this.runtime.setRuntimeApiKey(p.id, 'replay');
        continue;
      }
      this.runtime.registerProvider(p.id, { name: p.id, baseUrl: p.baseUrl, api: p.api, ...(p.headers ? { headers: p.headers } : {}), models });
      // A provider saved without a key (local gateways such as Ollama or an internal proxy need none) still needs a
      // runtime key, or pi refuses every request with "No API key found" while the settings check passes.
      await this.runtime.setRuntimeApiKey(p.id, p.apiKey || NO_KEY);
      if (this.mode.kind === 'record') this.wrapForRecording(p.id);
      this.wrapForGate(p.id);
    }
  }

  /**
   * Every request of a live provider waits for the global gate. The stream is returned at once and
   * filled once a slot is free; a request aborted while queued ends with an `aborted` error like any other.
   */
  private wrapForGate(providerId: string): void {
    const real = this.runtime.getProvider(providerId);
    if (!real) return;
    type Call = (model: never, ctx: never, opts: never) => AssistantMessageEventStream;
    const gated = (call: Call): Call => (model, ctx, opts) => {
      const out = createAssistantMessageEventStream();
      const who = modelCallContext.getStore();
      const signal = (opts as { signal?: AbortSignal } | undefined)?.signal;
      const started = Date.now();
      void (async () => {
        let release: (() => void) | null = null;
        try {
          const slot = await modelGate.acquire({ high: who?.priority === 'interactive', ...(signal ? { signal } : {}), ...(who?.onQueued ? { onQueued: who.onQueued } : {}) });
          release = slot.release;
          if (slot.waited) who?.onDequeued?.(Date.now() - started);
          const s = call(model, ctx, opts);
          for await (const ev of s) out.push(ev);
          out.end(await s.result());
        } catch (e) {
          const aborted = !!signal?.aborted;
          out.push({ type: 'error', reason: aborted ? 'aborted' : 'error', error: { ...errorMessage(providerId, aborted ? 'aborted' : (e as Error).message), stopReason: aborted ? 'aborted' : 'error' } as AssistantMessage });
          out.end();
        } finally {
          release?.();
        }
      })();
      return out;
    };
    const wrapped = createProvider({
      id: real.id, name: real.name, auth: real.auth,
      models: [...real.getModels()],
      api: { stream: gated((m, c, o) => real.stream(m, c, o)), streamSimple: gated((m, c, o) => real.streamSimple(m, c, o)) },
    } as never);
    this.runtime.registerNativeProvider(wrapped);
  }

  private wrapForRecording(providerId: string): void {
    const real = this.runtime.getProvider(providerId);
    const recorder = (this.mode as { recorder: Recorder }).recorder;
    if (!real) return;
    const wrapped = createProvider({
      id: real.id, name: real.name, auth: real.auth,
      models: [...real.getModels()],
      api: {
        stream: (model: never, ctx: never, opts: never) => real.stream(model, ctx, opts),
        streamSimple: (model: never, ctx: never, opts: never) => {
          const s = real.streamSimple(model, ctx, opts);
          void s.result().then((msg) => recorder.record(ctx as never, msg)).catch(() => undefined);
          return s;
        },
      },
    } as never);
    this.runtime.registerNativeProvider(wrapped);
  }

  resolve(ref: ModelRef): Model<never> {
    const m = this.runtime.getModel(ref.provider, ref.model);
    if (!m) throw new ModelNotConfiguredError(ref);
    return m as Model<never>;
  }

  knownModels(): Set<string> {
    return new Set(this.config.modelProviders.flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`)));
  }
}

function errorMessage(provider: string, message: string): AssistantMessage {
  return {
    role: 'assistant', content: [], api: 'faux', provider, model: 'replay',
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
    stopReason: 'error', errorMessage: message, timestamp: Date.now(),
  } as AssistantMessage;
}
