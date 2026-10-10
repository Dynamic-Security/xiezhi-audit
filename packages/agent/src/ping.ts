// Model service ping: used by the settings check and by the engine's service probe after an outage.
import type { AppConfig } from '@xiezhi/contracts';

/**
 * One minimal request to one model: a single-word prompt with at most one output token, in the
 * provider's protocol; never follows redirects. Reports the HTTP outcome and the provider's error message.
 */
export async function pingModel(p: AppConfig['modelProviders'][number], model: string): Promise<{ ok: boolean; ms: number; detail: string }> {
  const headers: Record<string, string> = { 'content-type': 'application/json', accept: 'application/json', ...(p.headers ?? {}) };
  let url: string;
  let body: unknown;
  if (p.api === 'anthropic-messages') {
    url = `${p.baseUrl.replace(/\/v1$/, '')}/v1/messages`;
    if (p.apiKey) headers['x-api-key'] = p.apiKey;
    headers['anthropic-version'] = '2023-06-01';
    body = { model, max_tokens: 1, messages: [{ role: 'user', content: 'ping' }] };
  } else {
    if (p.apiKey) headers.authorization = `Bearer ${p.apiKey}`;
    if (p.api === 'openai-responses') {
      url = `${p.baseUrl}/responses`;
      body = { model, input: 'ping', max_output_tokens: 16 };
    } else {
      url = `${p.baseUrl}/chat/completions`;
      body = { model, messages: [{ role: 'user', content: 'ping' }], max_tokens: 1, stream: false };
    }
  }
  const t0 = Date.now();
  try {
    const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), redirect: 'manual', signal: AbortSignal.timeout(30_000) });
    const ms = Date.now() - t0;
    const text = await res.text().catch(() => '');
    if (res.status >= 300 && res.status < 400) return { ok: false, ms, detail: `HTTP ${res.status}：服务返回重定向，已拒绝跟随` };
    if (!res.ok) {
      let msg = '';
      try {
        const j = JSON.parse(text) as { error?: { message?: string } | string; message?: string };
        msg = typeof j.error === 'string' ? j.error : j.error?.message ?? j.message ?? '';
      } catch { msg = text.slice(0, 200); }
      return { ok: false, ms, detail: `HTTP ${res.status}${msg ? `：${msg.slice(0, 200)}` : ''}` };
    }
    return { ok: true, ms, detail: `可用 · ${ms} ms` };
  } catch (e) {
    return { ok: false, ms: Date.now() - t0, detail: `无法连接：${(e as Error).name === 'TimeoutError' ? '超时' : (e as Error).message}` };
  }
}
