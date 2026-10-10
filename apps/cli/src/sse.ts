// Minimal server-sent-events reader over fetch for `--wait` / `--follow`; no
// dependency. Handles `id`/`event`/`data` fields, comments (heartbeats) and multi-line data.

export interface SseMessage {
  id: string | null;
  event: string;
  data: string;
}

/** Incremental parser: feed decoded text, get complete messages back. */
export class SseParser {
  private buf = '';
  private id: string | null = null;
  private event = '';
  private data: string[] = [];

  push(text: string): SseMessage[] {
    this.buf += text;
    const out: SseMessage[] = [];
    let nl: number;
    while ((nl = this.buf.search(/\r\n|\r|\n/)) !== -1) {
      const line = this.buf.slice(0, nl);
      this.buf = this.buf.slice(nl + (this.buf.startsWith('\r\n', nl) ? 2 : 1));
      if (line === '') {
        if (this.data.length || this.event) out.push({ id: this.id, event: this.event || 'message', data: this.data.join('\n') });
        this.event = '';
        this.data = [];
        continue;
      }
      if (line.startsWith(':')) continue;
      const colon = line.indexOf(':');
      const field = colon === -1 ? line : line.slice(0, colon);
      const value = colon === -1 ? '' : line.slice(colon + 1).replace(/^ /, '');
      if (field === 'data') this.data.push(value);
      else if (field === 'event') this.event = value;
      else if (field === 'id') this.id = value;
    }
    return out;
  }
}

/**
 * Read one SSE response until the server closes it or `signal` aborts. Calls `onMessage` per message;
 * returns normally when the stream ends, throws on HTTP or network errors.
 */
export async function readSse(url: string, headers: Record<string, string>, onMessage: (m: SseMessage) => boolean | void, signal?: AbortSignal): Promise<void> {
  const res = await fetch(url, { headers: { ...headers, accept: 'text/event-stream' }, ...(signal ? { signal } : {}) });
  if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
  if (!(res.headers.get('content-type') ?? '').startsWith('text/event-stream')) throw new Error('not an event stream');
  const parser = new SseParser();
  const decoder = new TextDecoder();
  const reader = res.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      for (const m of parser.push(decoder.decode(value, { stream: true }))) {
        if (onMessage(m) === false) return;
      }
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}
