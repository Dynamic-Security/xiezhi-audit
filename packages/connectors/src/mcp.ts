// Minimal MCP client: JSON-RPC 2.0 with `initialize`, `notifications/initialized`, paginated
// `tools/list`, `tools/call`, and cancellation — over stdio (a process started by the executor and
// handed in through `StdioLauncher`) or streamable HTTP (through the checked outbound client).
import { OutboundError, outbound, type OutboundPolicy } from './outbound.js';
import { appVersion } from '@xiezhi/contracts';

export const MCP_PROTOCOL_VERSION = '2025-06-18';
export const MCP_SUPPORTED_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const MAX_MESSAGE_BYTES = 8 * 1024 * 1024;

export type JsonRpcId = number | string;
export interface JsonRpcMessage {
  jsonrpc: '2.0';
  id?: JsonRpcId;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export class McpError extends Error {
  constructor(readonly code: 'protocol' | 'timeout' | 'closed' | 'rpc' | 'transport', message: string, readonly rpcCode?: number) {
    super(message);
    this.name = 'McpError';
  }
}

export interface McpTransport {
  start(onMessage: (m: JsonRpcMessage) => void, onClose: (reason: string) => void): Promise<void>;
  send(m: JsonRpcMessage, signal?: AbortSignal): Promise<void>;
  close(): Promise<void>;
}

// ---- stdio ------------------------------------------------------------------------------------------------

/** A long-running child process with line-delimited stdout (started by the executor). */
export interface StdioProcess {
  write(line: string): void;
  onLine(cb: (line: string) => void): void;
  onExit(cb: (reason: string) => void): void;
  close(): Promise<void>;
}
export interface StdioSpec { file: string; args: string[]; env: Record<string, string>; cwd: string }
export type StdioLauncher = (spec: StdioSpec) => StdioProcess;

export class StdioTransport implements McpTransport {
  private proc: StdioProcess | null = null;
  constructor(private readonly launch: StdioLauncher, private readonly spec: StdioSpec) {}

  async start(onMessage: (m: JsonRpcMessage) => void, onClose: (reason: string) => void): Promise<void> {
    this.proc = this.launch(this.spec);
    this.proc.onLine((line) => {
      if (!line.trim() || line.length > MAX_MESSAGE_BYTES) return;
      try { onMessage(JSON.parse(line) as JsonRpcMessage); } catch { /* servers may log non-JSON lines to stdout; ignore */ }
    });
    this.proc.onExit(onClose);
  }

  async send(m: JsonRpcMessage): Promise<void> {
    if (!this.proc) throw new McpError('closed', 'transport not started');
    this.proc.write(JSON.stringify(m));
  }

  async close(): Promise<void> {
    await this.proc?.close();
    this.proc = null;
  }
}

// ---- streamable HTTP --------------------------------------------------------------------------------------

/** Parse a `text/event-stream` body into JSON-RPC messages. */
export async function* sseMessages(chunks: AsyncIterable<Buffer>): AsyncIterable<JsonRpcMessage> {
  let buf = '';
  for await (const c of chunks) {
    buf += c.toString('utf8');
    let idx: number;
    while ((idx = buf.search(/\r?\n\r?\n/)) >= 0) {
      const block = buf.slice(0, idx);
      buf = buf.slice(buf.slice(idx).match(/^\r?\n\r?\n/)![0].length + idx);
      const data = block.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).replace(/^ /, '')).join('\n');
      if (!data) continue;
      try { yield JSON.parse(data) as JsonRpcMessage; } catch { /* ignore malformed events */ }
    }
  }
}

export class HttpTransport implements McpTransport {
  private onMessage: ((m: JsonRpcMessage) => void) | null = null;
  private session: string | null = null;
  private negotiated: string | null = null;
  constructor(private readonly url: string, private readonly headers: Record<string, string>, private readonly policy: OutboundPolicy, private readonly timeoutMs: number) {}

  async start(onMessage: (m: JsonRpcMessage) => void): Promise<void> {
    this.onMessage = onMessage;
  }

  setProtocolVersion(v: string): void {
    this.negotiated = v;
  }

  async send(m: JsonRpcMessage, signal?: AbortSignal): Promise<void> {
    const res = await outbound({
      url: this.url, method: 'POST', policy: this.policy, timeoutMs: this.timeoutMs, ...(signal ? { signal } : {}),
      headers: {
        'content-type': 'application/json', accept: 'application/json, text/event-stream', ...this.headers,
        ...(this.session ? { 'mcp-session-id': this.session } : {}), ...(this.negotiated ? { 'mcp-protocol-version': this.negotiated } : {}),
      },
      body: JSON.stringify(m),
    });
    const sid = res.headers['mcp-session-id'];
    if (sid && !this.session) this.session = sid;
    if (res.status === 202 || res.status === 204) { await res.text(); return; }
    if (res.status === 404 && this.session) throw new McpError('transport', 'MCP session expired');
    if (res.status >= 400) {
      const body = (await res.text()).slice(0, 300);
      throw new McpError('transport', `HTTP ${res.status}${body ? `: ${body}` : ''}`);
    }
    const type = res.headers['content-type'] ?? '';
    if (type.includes('text/event-stream')) {
      for await (const msg of sseMessages(res.chunks)) this.onMessage?.(msg);
      return;
    }
    const text = await res.text();
    if (!text.trim()) return;
    const parsed = JSON.parse(text) as JsonRpcMessage | JsonRpcMessage[];
    for (const msg of Array.isArray(parsed) ? parsed : [parsed]) this.onMessage?.(msg);
  }

  async close(): Promise<void> {
    if (!this.session) return;
    try {
      const r = await outbound({ url: this.url, method: 'DELETE', policy: this.policy, timeoutMs: 5000, headers: { ...this.headers, 'mcp-session-id': this.session } });
      await r.text();
    } catch { /* best effort */ }
    this.session = null;
  }
}

// ---- client -----------------------------------------------------------------------------------------------

export interface McpToolInfo {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: { readOnlyHint?: boolean; destructiveHint?: boolean; idempotentHint?: boolean; openWorldHint?: boolean; title?: string };
}
export interface McpServerInfo { protocolVersion: string; serverName: string; serverVersion: string; instructions: string | null; hasTools: boolean }
export interface McpCallResult { text: string; isError: boolean; structured: unknown }

export class McpClient {
  private nextId = 1;
  private readonly pending = new Map<JsonRpcId, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private closed: string | null = null;

  constructor(private readonly transport: McpTransport, private readonly opts: { timeoutMs: number; clientName?: string; clientVersion?: string }) {}

  private onMessage = (m: JsonRpcMessage) => {
    if (m.id === undefined || m.method) return; // server requests / notifications are not supported (no sampling, roots, elicitation)
    const p = this.pending.get(m.id);
    if (!p) return;
    this.pending.delete(m.id);
    clearTimeout(p.timer);
    if (m.error) p.reject(new McpError('rpc', m.error.message?.slice(0, 500) ?? 'error', m.error.code));
    else p.resolve(m.result);
  };

  private onClose = (reason: string) => {
    this.closed = reason || 'closed';
    for (const [, p] of this.pending) { clearTimeout(p.timer); p.reject(new McpError('closed', `connection closed: ${this.closed}`)); }
    this.pending.clear();
  };

  async request<T>(method: string, params: unknown, signal?: AbortSignal): Promise<T> {
    if (this.closed) throw new McpError('closed', `connection closed: ${this.closed}`);
    const id = this.nextId++;
    const done = new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        void this.transport.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason: 'timeout' } }).catch(() => undefined);
        reject(new McpError('timeout', `${method} timed out after ${this.opts.timeoutMs} ms`));
      }, this.opts.timeoutMs);
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, timer });
      signal?.addEventListener('abort', () => {
        const p = this.pending.get(id);
        if (!p) return;
        this.pending.delete(id);
        clearTimeout(p.timer);
        void this.transport.send({ jsonrpc: '2.0', method: 'notifications/cancelled', params: { requestId: id, reason: 'aborted' } }).catch(() => undefined);
        reject(new McpError('closed', 'aborted'));
      }, { once: true });
    });
    // Over HTTP the result arrives in the POST response, so the transport and the request timer can fire
    // together: whichever settles first wins, the other is ignored.
    done.catch(() => undefined);
    try {
      await this.transport.send({ jsonrpc: '2.0', id, method, params }, signal);
    } catch (e) {
      const p = this.pending.get(id);
      if (p) { clearTimeout(p.timer); this.pending.delete(id); }
      if (e instanceof McpError) throw e;
      if (e instanceof OutboundError && e.code === 'timeout') throw new McpError('timeout', `${method} timed out after ${this.opts.timeoutMs} ms`);
      if (e instanceof OutboundError) throw e;
      throw new McpError('transport', (e as Error).message);
    }
    return done;
  }

  async connect(signal?: AbortSignal): Promise<McpServerInfo> {
    await this.transport.start(this.onMessage, this.onClose);
    const r = await this.request<{ protocolVersion?: string; capabilities?: { tools?: unknown }; serverInfo?: { name?: string; version?: string }; instructions?: string }>('initialize', {
      protocolVersion: MCP_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: this.opts.clientName ?? 'xiezhi', version: this.opts.clientVersion ?? appVersion() },
    }, signal);
    const version = r.protocolVersion ?? '';
    if (!MCP_SUPPORTED_VERSIONS.includes(version)) throw new McpError('protocol', `unsupported MCP protocol version ${version || '(none)'}`);
    if (this.transport instanceof HttpTransport) this.transport.setProtocolVersion(version);
    await this.transport.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    return {
      protocolVersion: version, serverName: String(r.serverInfo?.name ?? ''), serverVersion: String(r.serverInfo?.version ?? ''),
      instructions: typeof r.instructions === 'string' ? r.instructions.slice(0, 2000) : null, hasTools: !!r.capabilities?.tools,
    };
  }

  async listTools(signal?: AbortSignal): Promise<McpToolInfo[]> {
    const out: McpToolInfo[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < 20; page++) {
      const r = await this.request<{ tools?: McpToolInfo[]; nextCursor?: string }>('tools/list', cursor ? { cursor } : {}, signal);
      out.push(...(r.tools ?? []).filter((t) => typeof t?.name === 'string'));
      if (!r.nextCursor) break;
      cursor = r.nextCursor;
    }
    return out;
  }

  async callTool(name: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<McpCallResult> {
    const r = await this.request<{ content?: { type: string; text?: string; resource?: { text?: string; uri?: string } }[]; isError?: boolean; structuredContent?: unknown }>('tools/call', { name, arguments: args }, signal);
    const text = (r.content ?? []).map((c) => (c.type === 'text' ? c.text ?? '' : c.type === 'resource' && c.resource?.text ? c.resource.text : `[${c.type} omitted]`)).join('\n');
    return { text, isError: !!r.isError, structured: r.structuredContent ?? null };
  }

  async close(): Promise<void> {
    this.onClose('closed by client');
    await this.transport.close();
  }
}
