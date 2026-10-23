// Model limits: what a provider's model listing says about a model's context window and output cap, and how much
// room for the answer a request still has under pi's clamp.
import { calculateContextTokens, estimateTokens } from '@earendil-works/pi-coding-agent';
import type { AppConfig } from '@xiezhi/contracts';

/**
 * The context window a model is registered with when its configuration names none. Provider configs usually carry
 * only model ids; 128k is the window nearly every current chat model has at least (GPT-4o/4.1, DeepSeek, Qwen, Llama 3:
 * 128k; Claude: 200k; Gemini: 1M). A larger default would send prompts past the real window of 128k models; a smaller
 * one makes pi clamp `max_tokens` on models that have room. Sessions that outgrow it end as CONTEXT_OVERFLOW
 * (see `outputRoom`), and probing the provider stores the real window.
 */
export const DEFAULT_CONTEXT_WINDOW = 128_000;
export const DEFAULT_MAX_TOKENS = 8_192;

/** pi-ai's `clampMaxTokensToContext` keeps this much of the window free. */
const CONTEXT_SAFETY_TOKENS = 4096;

/**
 * A request whose clamped `max_tokens` falls below this cannot carry a tool call: the model answers with a token or
 * two, is told to submit, and does so again until the turn limit (seen with a 136k-token triage prompt on a model
 * registered at 128k: max_tokens=1 for 60 turns).
 */
export const MIN_OUTPUT_TOKENS = 1024;

export interface ModelLimits { contextWindow?: number; maxTokens?: number }

type Msg = Parameters<typeof estimateTokens>[0];

/**
 * The `max_tokens` pi-ai would send for the next request of `messages` (its `clampMaxTokensToContext`): the model's
 * output cap, cut to what the window leaves after the context (the last reply's reported usage plus an estimate of
 * what came after it) and the safety margin. Infinity for a model without a window.
 */
export function outputRoom(model: { contextWindow: number; maxTokens: number }, messages: readonly Msg[]): number {
  if (!(model.contextWindow > 0)) return Infinity;
  let used = 0;
  let from = 0;
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i] as { role?: string; stopReason?: string; usage?: Parameters<typeof calculateContextTokens>[0] };
    if (m.role !== 'assistant' || !m.usage || m.stopReason === 'aborted' || m.stopReason === 'error') continue;
    const t = calculateContextTokens(m.usage);
    if (t > 0) { used = t; from = i + 1; break; }
  }
  for (let i = from; i < messages.length; i++) used += estimateTokens(messages[i]!);
  return Math.min(model.maxTokens, model.contextWindow - used - CONTEXT_SAFETY_TOKENS);
}

const num = (v: unknown): number | undefined => {
  const n = typeof v === 'string' && /^\d+$/.test(v.trim()) ? Number(v) : v;
  return typeof n === 'number' && Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
};
const first = (...vs: unknown[]): number | undefined => vs.map(num).find((v) => v !== undefined);

/**
 * Limits of one entry of a `/models` listing, where the service reports them. OpenAI-compatible gateways name them
 * differently: `context_length` (OpenRouter, magpie), `context_window`, `max_model_len` (vLLM), `max_context_length`,
 * `max_output_tokens` / `max_completion_tokens`, OpenRouter's `top_provider`; Anthropic lists `max_input_tokens` and
 * `max_tokens`. Values below the config minimums (1024 / 256) are dropped; the output cap never exceeds the window.
 */
export function modelLimitsOf(entry: unknown): ModelLimits {
  if (!entry || typeof entry !== 'object') return {};
  const e = entry as Record<string, unknown>;
  const top = (e.top_provider && typeof e.top_provider === 'object' ? e.top_provider : {}) as Record<string, unknown>;
  const lim = (e.limits && typeof e.limits === 'object' ? e.limits : {}) as Record<string, unknown>;
  const cw = first(e.context_length, e.context_window, e.max_context_length, e.max_model_len, e.max_input_tokens, e.input_token_limit, top.context_length, lim.context_window, lim.context_length);
  const out = first(e.max_output_tokens, e.max_completion_tokens, e.output_token_limit, e.max_tokens, top.max_completion_tokens, lim.max_output_tokens, lim.max_tokens);
  const r: ModelLimits = {};
  if (cw !== undefined && cw >= 1024) r.contextWindow = cw;
  if (out !== undefined && out >= 256) r.maxTokens = r.contextWindow ? Math.min(out, r.contextWindow) : out;
  return r;
}

export interface ModelListing { ok: boolean; detail: string; models?: string[]; limits?: Record<string, ModelLimits> }

/**
 * A provider's model listing (`/models`, Anthropic: `/v1/models`) with the stored key; never follows redirects.
 * `limits` holds the models whose entry reported a context window or output cap.
 */
export async function listModels(p: AppConfig['modelProviders'][number]): Promise<ModelListing> {
  const headers: Record<string, string> = { accept: 'application/json', ...(p.headers ?? {}) };
  let url = `${p.baseUrl}/models`;
  if (p.api === 'anthropic-messages') {
    url = `${p.baseUrl.replace(/\/v1$/, '')}/v1/models`;
    if (p.apiKey) headers['x-api-key'] = p.apiKey;
    headers['anthropic-version'] = '2023-06-01';
  } else if (p.apiKey) headers.authorization = `Bearer ${p.apiKey}`;
  try {
    const res = await fetch(url, { headers, redirect: 'manual', signal: AbortSignal.timeout(15_000) });
    if (res.status >= 300 && res.status < 400) return { ok: false, detail: `HTTP ${res.status}：服务返回重定向，已拒绝跟随` };
    if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
    const body = await res.json().catch(() => null) as { data?: unknown } | null;
    return { ok: true, ...modelListingOf(body) };
  } catch (e) {
    return { ok: false, detail: `无法连接：${(e as Error).name === 'TimeoutError' ? '超时' : (e as Error).message}` };
  }
}

/** The ids and limits of a `/models` response body (`{ data: [...] }`, or a bare list). */
export function modelListingOf(body: unknown): { detail: string; models: string[]; limits: Record<string, ModelLimits> } {
  const data = Array.isArray(body) ? body : Array.isArray((body as { data?: unknown } | null)?.data) ? (body as { data: unknown[] }).data : [];
  const models: string[] = [];
  const limits: Record<string, ModelLimits> = {};
  for (const m of data.slice(0, 500)) {
    const id = String((m as { id?: unknown } | null)?.id ?? '');
    if (!id) continue;
    models.push(id);
    const l = modelLimitsOf(m);
    if (l.contextWindow || l.maxTokens) limits[id] = l;
  }
  const withLimits = Object.keys(limits).length;
  return { detail: models.length ? `可连通，服务端列出 ${models.length} 个模型${withLimits ? `（${withLimits} 个附带上下文 / 输出上限）` : ''}` : '可连通', models, limits };
}

/**
 * Models with probed limits filled in where the configuration has none: a value set by hand is kept.
 * Returns the merged list and the ids that changed.
 */
export function withProbedLimits<M extends { id: string } & ModelLimits>(models: M[], limits: Record<string, ModelLimits>): { models: M[]; updated: string[] } {
  const updated: string[] = [];
  const out = models.map((m) => {
    const l = limits[m.id];
    if (!l) return m;
    const next = { ...m, ...(m.contextWindow ? {} : l.contextWindow ? { contextWindow: l.contextWindow } : {}), ...(m.maxTokens ? {} : l.maxTokens ? { maxTokens: l.maxTokens } : {}) };
    if (next.contextWindow !== m.contextWindow || next.maxTokens !== m.maxTokens) updated.push(m.id);
    return next;
  });
  return { models: out, updated };
}
