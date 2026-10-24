// Minimal OpenAI-compatible chat.completions server for tests (streaming SSE).
import { createServer, type IncomingMessage, type Server } from 'node:http';

export interface ScriptedReply {
  text?: string; toolCalls?: { name: string; args: unknown }[]; status?: number; error?: string; /** Respond after this many ms. */ delayMs?: number;
  /** Fault injection: cut the stream after the first chunk (connection destroyed mid-response). */
  truncate?: boolean;
  /** Fault injection: send these raw strings as tool-call arguments (e.g. invalid JSON). */
  rawArgs?: string[];
  /** Prompt tokens to report for this response (default 100), e.g. to reach a session's context cap. */
  promptTokens?: number;
  /** finish_reason to report, e.g. `length` for a reply cut at the output limit. */
  finish?: string;
}

export interface FakeServer {
  url: string;
  requests: { headers: IncomingMessage['headers']; body: any }[];
  /** Requests currently being answered, and the most seen at once since the last reset (concurrency tests). */
  inFlight(): number;
  maxInFlight(): number;
  push(...r: ScriptedReply[]): void;
  reset(): void;
  close(): Promise<void>;
}

/** `models`: served at GET …/models; chat requests naming another model get 404 (provider checks). */
export async function startFakeOpenAI(fallback?: (body: any) => ScriptedReply, opts: { models?: string[] } = {}): Promise<FakeServer> {
  const queue: ScriptedReply[] = [];
  const requests: FakeServer['requests'] = [];
  let callSeq = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  const server: Server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    let counted = true;
    inFlight++;
    maxInFlight = Math.max(maxInFlight, inFlight);
    const done = () => { if (counted) { counted = false; inFlight--; } };
    res.on('close', done);
    req.on('end', () => {
      if (req.method === 'GET' && /\/models$/.test(req.url ?? '')) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ object: 'list', data: (opts.models ?? []).map((id) => ({ id, object: 'model' })) }));
        return;
      }
      const body = raw ? JSON.parse(raw) : {};
      requests.push({ headers: req.headers, body });
      if (opts.models && body.model && !opts.models.includes(body.model)) {
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { message: `model ${body.model} does not exist`, type: 'invalid_request_error' } }));
        return;
      }
      const reply = queue.shift() ?? fallback?.(body) ?? { text: 'done' };
      if (reply.delayMs) {
        const { delayMs: _d, ...rest } = reply;
        setTimeout(() => respond(rest, body), reply.delayMs);
      } else respond(reply, body);
    });
    const respond = (reply: ScriptedReply, body: any) => {
      if (res.writableEnded || res.destroyed) return;
      if (reply.status && reply.status >= 400) {
        res.writeHead(reply.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { message: reply.error ?? 'error', type: 'error' } }));
        return;
      }
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' });
      const chunk = (delta: unknown, finish: string | null, usage?: unknown) =>
        `data: ${JSON.stringify({ id: 'c1', object: 'chat.completion.chunk', created: 1, model: body.model, choices: [{ index: 0, delta, finish_reason: finish }], ...(usage ? { usage } : {}) })}\n\n`;
      let out = chunk({ role: 'assistant' }, null);
      if (reply.truncate) { res.write(out); res.destroy(); return; }
      if (reply.text) out += chunk({ content: reply.text }, null);
      (reply.toolCalls ?? []).forEach((tc, index) => {
        out += chunk({ tool_calls: [{ index, id: `call_${++callSeq}`, type: 'function', function: { name: tc.name, arguments: reply.rawArgs?.[index] ?? JSON.stringify(tc.args) } }] }, null);
      });
      out += chunk({}, reply.finish ?? (reply.toolCalls?.length ? 'tool_calls' : 'stop'), { prompt_tokens: reply.promptTokens ?? 100, completion_tokens: 20, total_tokens: (reply.promptTokens ?? 100) + 20 });
      out += 'data: [DONE]\n\n';
      res.end(out);
    };
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const port = (server.address() as { port: number }).port;
  return {
    url: `http://127.0.0.1:${port}/v1`,
    requests,
    inFlight: () => inFlight,
    maxInFlight: () => maxInFlight,
    push: (...r) => queue.push(...r),
    reset: () => { queue.length = 0; requests.length = 0; maxInFlight = inFlight; },
    close: () => new Promise((r) => server.close(() => r())),
  };
}
