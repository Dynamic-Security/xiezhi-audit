// Connector runtime: one live MCP session per connector (closed after idle),
// per-connector concurrency, circuit breaker, tools/list cache, `${secret:x}` substitution at the edge, and
// the stdio command hash that the user confirmed.
import { join } from 'node:path';
import { mkdirSync } from 'node:fs';
import { canonicalJson, sha256Hex } from '@xiezhi/contracts';
import { HttpTransport, McpClient, McpError, StdioTransport, type McpCallResult, type McpServerInfo, type McpToolInfo, type StdioLauncher } from './mcp.js';
import { PackClient, PackError, loadPack, packCommandsHash, packScriptsHash, type CommandRun, type Pack, type ScriptRun } from './pack.js';
import { OutboundError } from './outbound.js';

export const DEFAULT_CONNECT_MS = 5000;
export const DEFAULT_CALL_MS = 30_000;
export const DEFAULT_CONCURRENCY = 2;
export const BREAKER_FAILURES = 3;
export const BREAKER_COOLDOWN_MS = 60_000;
export const TOOLS_TTL_MS = 5 * 60_000;
export const IDLE_CLOSE_MS = 5 * 60_000;
/** Tool descriptions are untrusted: truncated before anyone (UI or model) sees them. */
export const TOOL_DESCRIPTION_MAX = 1024;

export interface ConnectorSpec {
  id: string;
  name: string;
  protocol: 'mcp_stdio' | 'mcp_http' | 'http';
  /** stdio: absolute command path, arguments, explicit environment (values may reference `${secret:x}`). */
  command?: { path: string; args: string[]; env: Record<string, string> } | undefined;
  /** mcp_http: endpoint and headers (values, and the endpoint's query, may reference `${secret:x}`). */
  url?: string | undefined;
  headers?: Record<string, string> | undefined;
  timeouts?: { connectMs?: number | undefined; callMs?: number | undefined } | undefined;
  concurrency?: number | undefined;
  /** http: a connector pack; `hash` is the pack content hash, so any file change needs a new test. */
  pack?: { dir: string; name: string; hash: string; baseUrl?: string | undefined; variables: Record<string, string>; interpreterPath?: string | undefined; programPath?: string | undefined } | undefined;
}

export class ConnectorError extends Error {
  constructor(readonly code: 'unavailable' | 'not_confirmed' | 'config' | 'call' | 'timeout' | 'blocked', message: string) {
    super(message);
    this.name = 'ConnectorError';
  }
}

const SECRET_RE = /\$\{secret:([A-Za-z0-9_.-]{1,64})\}/g;

export function secretRefs(spec: ConnectorSpec): string[] {
  // the endpoint may carry a credential in its query (`?token=${secret:token}`).
  const vals = [...Object.values(spec.command?.env ?? {}), ...Object.values(spec.headers ?? {}), ...(spec.command?.args ?? []), ...(spec.url ? [spec.url] : [])];
  return [...new Set(vals.flatMap((v) => [...v.matchAll(SECRET_RE)].map((m) => m[1]!)))].sort();
}

export function substituteSecrets(value: string, secrets: Record<string, string>): string {
  return value.replace(SECRET_RE, (_, k: string) => {
    const v = secrets[k];
    if (v === undefined) throw new ConnectorError('config', `secret ${k} is not configured`);
    return v;
  });
}

/** Hash of what will run: path, args and env with secret references unexpanded. */
export function commandHash(cmd: NonNullable<ConnectorSpec['command']>): string {
  return sha256Hex(canonicalJson({ path: cmd.path, args: cmd.args, env: Object.entries(cmd.env).sort(([a], [b]) => a.localeCompare(b)) }));
}

/** Hash of the connection-relevant configuration: a change sends the connector back to “untested”. */
export function specHash(spec: ConnectorSpec): string {
  return sha256Hex(canonicalJson({ p: spec.protocol, c: spec.command ?? null, u: spec.url ?? null, h: spec.headers ?? null, k: spec.pack ?? null }));
}

export interface BreakerState { state: 'closed' | 'open' | 'half_open'; failures: number; openedAt: number | null }

class Limiter {
  private running = 0;
  private readonly queue: (() => void)[] = [];
  constructor(private readonly limit: number) {}
  async run<T>(fn: () => Promise<T>, waitMs: number): Promise<T> {
    if (this.running >= this.limit) {
      await new Promise<void>((resolve, reject) => {
        const t = setTimeout(() => { const i = this.queue.indexOf(go); if (i >= 0) this.queue.splice(i, 1); reject(new ConnectorError('timeout', 'waited too long for a free connector slot')); }, waitMs);
        const go = () => { clearTimeout(t); resolve(); };
        this.queue.push(go);
      });
    }
    this.running++;
    try { return await fn(); } finally {
      this.running--;
      this.queue.shift()?.();
    }
  }
}

/** What the pool needs from a client: an MCP session or a connector pack. */
interface ClientLike {
  connect(signal?: AbortSignal): Promise<McpServerInfo>;
  listTools(signal?: AbortSignal): Promise<McpToolInfo[]>;
  callTool(name: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<McpCallResult>;
  close(): Promise<void>;
}

interface Live { client: ClientLike; hash: string; idle: NodeJS.Timeout | null; server: McpServerInfo }

export interface PoolDeps {
  launcher: StdioLauncher;
  /** `<data-dir>/tmp/connectors`: each stdio connector gets a private empty cwd below it. */
  connectorsDir: string;
  secrets: (connectorId: string) => Record<string, string>;
  /** Hash the user confirmed for the stdio command or the pack scripts; null = not confirmed. */
  confirmedCommand: (connectorId: string) => string | null;
  /** Runs pack scripts through the executor. */
  runScript?: ScriptRun;
  /** Runs pack commands through the executor. */
  runCommand?: CommandRun;
  now?: () => number;
}

export class ConnectorPool {
  private readonly live = new Map<string, Live>();
  private readonly limiters = new Map<string, Limiter>();
  private readonly breakers = new Map<string, BreakerState>();
  private readonly toolCache = new Map<string, { hash: string; at: number; tools: McpToolInfo[] }>();
  private readonly now: () => number;

  constructor(private readonly deps: PoolDeps) {
    this.now = deps.now ?? Date.now;
  }

  breaker(id: string): BreakerState {
    return this.breakers.get(id) ?? { state: 'closed', failures: 0, openedAt: null };
  }

  /** Drop cached tools and the live session (configuration changed or connector removed). */
  async invalidate(id: string): Promise<void> {
    this.toolCache.delete(id);
    this.breakers.delete(id);
    const l = this.live.get(id);
    this.live.delete(id);
    if (l) { if (l.idle) clearTimeout(l.idle); await l.client.close().catch(() => undefined); }
  }

  async closeAll(): Promise<void> {
    await Promise.all([...this.live.keys()].map((id) => this.invalidate(id)));
  }

  private client(spec: ConnectorSpec): ClientLike {
    const callMs = spec.timeouts?.callMs ?? DEFAULT_CALL_MS;
    const secrets = this.deps.secrets(spec.id);
    if (spec.protocol === 'mcp_stdio') {
      if (!spec.command) throw new ConnectorError('config', 'command is required for mcp_stdio');
      const confirmed = this.deps.confirmedCommand(spec.id);
      if (!confirmed || confirmed !== commandHash(spec.command)) throw new ConnectorError('not_confirmed', 'the command line changed or was never confirmed; confirm it in settings first');
      const cwd = join(this.deps.connectorsDir, spec.id.replace(/[^A-Za-z0-9_-]/g, '_'));
      mkdirSync(cwd, { recursive: true, mode: 0o700 });
      const env = Object.fromEntries(Object.entries(spec.command.env).map(([k, v]) => [k, substituteSecrets(v, secrets)]));
      return new McpClient(new StdioTransport(this.deps.launcher, { file: spec.command.path, args: spec.command.args.map((a) => substituteSecrets(a, secrets)), env, cwd }), { timeoutMs: callMs });
    }
    if (spec.protocol === 'mcp_http') {
      if (!spec.url) throw new ConnectorError('config', 'url is required for mcp_http');
      const host = new URL(spec.url).hostname;
      const headers = Object.fromEntries(Object.entries(spec.headers ?? {}).map(([k, v]) => [k, substituteSecrets(v, secrets)]));
      return new McpClient(new HttpTransport(substituteSecrets(spec.url, secrets), headers, { configuredHosts: [host] }, callMs), { timeoutMs: callMs });
    }
    if (spec.protocol === 'http') {
      if (!spec.pack) throw new ConnectorError('config', 'a connector pack is required for http connectors');
      let pack: Pack;
      try { pack = loadPack(spec.pack.dir, spec.pack.name); } catch (e) { throw new ConnectorError('config', (e as Error).message); }
      if (pack.hash !== spec.pack.hash) throw new ConnectorError('config', 'the connector pack changed; run the connectivity test again');
      const interpreterPath = spec.pack.interpreterPath ?? null;
      const programPath = spec.pack.programPath ?? null;
      if (pack.program) {
        if (!programPath) throw new ConnectorError('config', `the pack runs ${pack.program.name}: it was not found; configure its absolute path`);
        if (pack.scripts.length && !interpreterPath) throw new ConnectorError('config', 'the pack has scripts: configure the interpreter path');
        const confirmed = this.deps.confirmedCommand(spec.id);
        if (!confirmed || confirmed !== packCommandsHash(pack, programPath, interpreterPath)) throw new ConnectorError('not_confirmed', 'the pack commands changed or were never confirmed; review and confirm them in settings first');
      } else if (pack.scripts.length) {
        if (!interpreterPath) throw new ConnectorError('config', 'the pack has scripts: configure the interpreter path');
        const confirmed = this.deps.confirmedCommand(spec.id);
        if (!confirmed || confirmed !== packScriptsHash(pack, interpreterPath)) throw new ConnectorError('not_confirmed', 'the pack scripts changed or were never confirmed; review and confirm them in settings first');
      }
      const cwd = join(this.deps.connectorsDir, spec.id.replace(/[^A-Za-z0-9_-]/g, '_'));
      mkdirSync(cwd, { recursive: true, mode: 0o700 });
      return new PackClient(pack, {
        dir: spec.pack.dir, baseUrl: spec.pack.baseUrl ?? null, variables: spec.pack.variables, secrets, interpreterPath,
        runScript: pack.scripts.length ? this.deps.runScript ?? null : null, cwd, timeoutMs: callMs,
        ...(pack.program ? { programPath, runCommand: this.deps.runCommand ?? null } : {}),
      });
    }
    throw new ConnectorError('config', `protocol ${spec.protocol} is not supported`);
  }

  private async session(spec: ConnectorSpec): Promise<Live> {
    const hash = specHash(spec);
    const cur = this.live.get(spec.id);
    if (cur && cur.hash === hash) {
      if (cur.idle) clearTimeout(cur.idle);
      cur.idle = setTimeout(() => void this.invalidate(spec.id), IDLE_CLOSE_MS);
      cur.idle.unref();
      return cur;
    }
    if (cur) await this.invalidate(spec.id);
    const client = this.client(spec);
    const server = await client.connect();
    const l: Live = { client, hash, idle: setTimeout(() => void this.invalidate(spec.id), IDLE_CLOSE_MS), server };
    l.idle!.unref();
    this.live.set(spec.id, l);
    return l;
  }

  /** Breaker: 3 consecutive failures open it for 60 s, then one probe decides. */
  private async guarded<T>(spec: ConnectorSpec, fn: () => Promise<T>): Promise<T> {
    const b = this.breaker(spec.id);
    if (b.state === 'open') {
      if (this.now() - (b.openedAt ?? 0) < BREAKER_COOLDOWN_MS) throw new ConnectorError('unavailable', 'connector temporarily unavailable (circuit open)');
      b.state = 'half_open';
    }
    const limiter = this.limiters.get(spec.id) ?? new Limiter(spec.concurrency ?? DEFAULT_CONCURRENCY);
    this.limiters.set(spec.id, limiter);
    try {
      const r = await limiter.run(fn, spec.timeouts?.callMs ?? DEFAULT_CALL_MS);
      this.breakers.set(spec.id, { state: 'closed', failures: 0, openedAt: null });
      return r;
    } catch (e) {
      const failures = b.failures + 1;
      const open = b.state === 'half_open' || failures >= BREAKER_FAILURES;
      this.breakers.set(spec.id, { state: open ? 'open' : 'closed', failures, openedAt: open ? this.now() : null });
      // A broken session is not reused.
      await this.invalidateSession(spec.id);
      throw normalize(e);
    }
  }

  private async invalidateSession(id: string): Promise<void> {
    const l = this.live.get(id);
    this.live.delete(id);
    if (l) { if (l.idle) clearTimeout(l.idle); await l.client.close().catch(() => undefined); }
  }

  /**
   * Connectivity test: a fresh connection, `initialize` + `tools/list`, closed afterwards.
   * Never a call to any tool.
   */
  async test(spec: ConnectorSpec): Promise<{ server: McpServerInfo; tools: McpToolInfo[] }> {
    const client = this.client(spec);
    try {
      const server = await client.connect();
      const tools = server.hasTools ? await client.listTools() : [];
      return { server, tools: tools.map(sanitizeTool) };
    } catch (e) {
      throw normalize(e);
    } finally {
      await client.close().catch(() => undefined);
    }
  }

  /** tools/list, cached per connector for 5 minutes (invalidated when the configuration changes). */
  async tools(spec: ConnectorSpec): Promise<McpToolInfo[]> {
    const hash = specHash(spec);
    const c = this.toolCache.get(spec.id);
    if (c && c.hash === hash && this.now() - c.at < TOOLS_TTL_MS) return c.tools;
    const tools = await this.guarded(spec, async () => (await this.session(spec)).client.listTools());
    const clean = tools.map(sanitizeTool);
    this.toolCache.set(spec.id, { hash, at: this.now(), tools: clean });
    return clean;
  }

  async call(spec: ConnectorSpec, tool: string, args: Record<string, unknown>, signal?: AbortSignal): Promise<McpCallResult> {
    return this.guarded(spec, async () => (await this.session(spec)).client.callTool(tool, args, signal));
  }
}

function sanitizeTool(t: McpToolInfo): McpToolInfo {
  return {
    name: t.name.slice(0, 128), ...(t.title ? { title: String(t.title).slice(0, 200) } : {}),
    ...(t.description ? { description: String(t.description).slice(0, TOOL_DESCRIPTION_MAX) } : {}),
    ...(t.inputSchema ? { inputSchema: t.inputSchema } : {}), ...(t.annotations ? { annotations: t.annotations } : {}),
  };
}

function normalize(e: unknown): ConnectorError {
  if (e instanceof ConnectorError) return e;
  if (e instanceof OutboundError) return new ConnectorError(e.code === 'blocked_address' || e.code === 'scheme' || e.code === 'redirect' ? 'blocked' : e.code === 'timeout' ? 'timeout' : 'call', e.message);
  if (e instanceof McpError) return new ConnectorError(e.code === 'timeout' ? 'timeout' : 'call', e.message);
  if (e instanceof PackError) return new ConnectorError('call', e.message);
  return new ConnectorError('call', (e as Error)?.message ?? String(e));
}
