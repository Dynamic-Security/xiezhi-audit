// Connector management: configuration without
// credentials in the database, `${secret:x}` values in config.json, stdio command confirmation,
// connectivity test (initialize + tools/list, never a tool call), which read-only tools are exposed,
// and the status rule “enabled only when the tested configuration is the current one”.
import { AppError, canonicalJson, newId, sha256Hex } from '@xiezhi/contracts';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { resolveCommand } from './command-path.js';
import { commandHash, loadPack, packCommandsHash, packScriptsHash, secretRefs, specHash, type ConnectorPool, type ConnectorSpec, type McpToolInfo, type Pack } from '@xiezhi/connectors';
import { fromJson, type Store } from '@xiezhi/store';
import { detectInjection } from '@xiezhi/agent';

export type ConnectorProtocol = 'mcp_stdio' | 'mcp_http' | 'http';
export interface ConnectorConfig {
  command?: { path: string; args: string[]; env: Record<string, string> };
  url?: string;
  headers?: Record<string, string>;
  concurrency?: number;
  timeouts?: { callMs?: number };
  /** http: connector pack name under `<data-dir>/connectors/`. */
  pack?: string;
  /** http: site address overriding the pack's `base_url`. */
  base_url?: string;
  /** http: non-secret pack variables. */
  variables?: Record<string, string>;
  /** http: absolute interpreter for pack scripts (default for `node` packs: the service's own Node). */
  interpreter_path?: string;
  /** http: absolute path of the pack's program (default: found in PATH and the usual install directories). */
  program_path?: string;
}
export interface ConnectorTool {
  name: string;
  title?: string;
  description?: string;
  readOnlyHint: boolean | null;
  destructiveHint: boolean | null;
  /** Offered to the Agent through `connector_query` (every tool, read or write, starts offered; the user may turn one off). */
  exposed: boolean;
  /** Parameter summary from the input schema (`name: type`), for the operation list. */
  params?: string;
}

/** MCP connector (tools from the server) vs connector pack (operations declared read / write); both offer every tool to the Agent by default. */
export function isMcp(r: Pick<ConnectorRow, 'protocol'>): boolean {
  return r.protocol === 'mcp_http' || r.protocol === 'mcp_stdio';
}
export interface ConnectorTest { ok: boolean; at: number; specHash: string; server: { name: string; version: string; protocolVersion: string } | null; error: string | null; toolCount: number }
export interface ConnectorRow {
  id: string; name: string; protocol: ConnectorProtocol; purpose: 'context' | 'sync'; config: string; allow_write: number; enabled: number;
  /** the user declared this context system's data authoritative — its results may support conclusions. */
  authoritative: number;
  confirmed_command_hash: string | null; tested_spec_hash: string | null; last_test: string | null; tools: string; breaker_state: string | null;
  created_at: number; updated_at: number;
}
export type ConnectorStatus = 'needs_confirmation' | 'untested' | 'failed' | 'ready';

const CREDENTIAL_NAME = /(token|secret|password|passwd|api[-_]?key|apikey|credential|authorization|cookie|session)/i;

export function getConnector(store: Store, id: string): ConnectorRow {
  const r = store.get<ConnectorRow>('SELECT * FROM connector WHERE id = ?', id);
  if (!r) throw new AppError('COMMON_NOT_FOUND', `connector ${id}`);
  return r;
}

/** Interpreter used for a pack's scripts: configured, or this process's Node for `node` packs. */
function interpreterFor(pack: Pack, c: ConnectorConfig): string | null {
  if (!pack.scripts.length) return null;
  return c.interpreter_path ?? (pack.interpreter === 'node' ? process.execPath : null);
}

/** Runtime spec. `packsRoot` (`store.paths.connectorPacks`) is needed for http (pack) connectors. */
export function connectorSpec(r: ConnectorRow, packsRoot?: string): ConnectorSpec {
  const c = fromJson<ConnectorConfig>(r.config, {});
  let pack: ConnectorSpec['pack'];
  if (r.protocol === 'http' && c.pack && packsRoot) {
    const dir = join(packsRoot, c.pack);
    let hash = 'invalid';
    let interpreterPath: string | undefined;
    let programPath: string | undefined;
    try {
      const p = loadPack(dir, c.pack);
      hash = p.hash;
      interpreterPath = interpreterFor(p, c) ?? undefined;
      if (p.program) programPath = c.program_path ?? resolveCommand(p.program.name) ?? undefined;
    } catch { /* invalid pack: the test reports the errors */ }
    pack = { dir, name: c.pack, hash, variables: c.variables ?? {}, ...(c.base_url ? { baseUrl: c.base_url } : {}), ...(interpreterPath ? { interpreterPath } : {}), ...(programPath ? { programPath } : {}) };
  }
  return {
    id: r.id, name: r.name, protocol: r.protocol, command: c.command, url: c.url, headers: c.headers,
    ...(c.concurrency ? { concurrency: c.concurrency } : {}), ...(c.timeouts ? { timeouts: c.timeouts } : {}), ...(pack ? { pack } : {}),
  };
}

/**
 * The hash the user confirms: the stdio command line, or a pack's scripts with their
 * interpreter. Null when nothing needs confirming.
 */
export function confirmationHash(r: ConnectorRow, packsRoot?: string): string | null {
  const spec = connectorSpec(r, packsRoot);
  if (r.protocol === 'mcp_stdio') return spec.command ? commandHash(spec.command) : null;
  if (r.protocol === 'http' && spec.pack && spec.pack.hash !== 'invalid') {
    try {
      const p = loadPack(spec.pack.dir, spec.pack.name);
      if (p.program) return spec.pack.programPath ? packCommandsHash(p, spec.pack.programPath, spec.pack.interpreterPath ?? null) : null;
      return p.scripts.length && spec.pack.interpreterPath ? packScriptsHash(p, spec.pack.interpreterPath) : null;
    } catch { return null; }
  }
  return null;
}

/** Secret names the configuration references: `${secret:x}` in env / headers / args, plus a pack's secrets. */
export function connectorSecretNames(r: ConnectorRow, packsRoot?: string): string[] {
  const spec = connectorSpec(r, packsRoot);
  const names = new Set(secretRefs(spec));
  if (spec.pack) { try { for (const s of loadPack(spec.pack.dir, spec.pack.name).secrets) names.add(s); } catch { /* invalid pack */ } }
  return [...names].sort();
}

/** usable only when the tested configuration equals the current one (and commands / scripts are confirmed). */
export function connectorStatus(r: ConnectorRow, packsRoot?: string): ConnectorStatus {
  const spec = connectorSpec(r, packsRoot);
  if (r.protocol === 'mcp_stdio' && (!spec.command || r.confirmed_command_hash !== commandHash(spec.command))) return 'needs_confirmation';
  if (r.protocol === 'http') {
    const h = confirmationHash(r, packsRoot);
    if (h && r.confirmed_command_hash !== h) return 'needs_confirmation';
  }
  const t = fromJson<ConnectorTest | null>(r.last_test, null);
  if (!t || r.tested_spec_hash !== specHash(spec)) return 'untested';
  return t.ok ? 'ready' : 'failed';
}

/**
 * Configuration rules: absolute stdio command, bounded arguments, credentials only as `${secret:x}`
 * (environment variables and headers whose names look like credentials must reference a secret).
 */
export function validateConnectorConfig(protocol: ConnectorProtocol, c: ConnectorConfig): string[] {
  const errors: string[] = [];
  if (protocol === 'http') {
    if (!c.pack) errors.push('pack is required for http connectors');
    else if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(c.pack)) errors.push('invalid pack name');
    if (c.base_url) { try { const u = new URL(c.base_url); if (!/^https?:$/.test(u.protocol) || u.username || u.password) errors.push('base_url must be http(s) without credentials'); } catch { errors.push('invalid base_url'); } }
    if (c.interpreter_path && !c.interpreter_path.startsWith('/')) errors.push('interpreter_path must be absolute');
    if (c.program_path && !c.program_path.startsWith('/')) errors.push('program_path must be absolute');
    for (const [k, v] of Object.entries(c.variables ?? {})) if (!/^[A-Za-z0-9_.-]{1,64}$/.test(k) || v.length > 500) errors.push(`invalid variable ${k}`);
  }
  if (protocol === 'mcp_stdio') {
    if (!c.command) errors.push('command is required');
    else {
      if (!/^\//.test(c.command.path) && !/^[A-Za-z]:\\/.test(c.command.path)) errors.push('command path must be absolute');
      if (c.command.args.length > 50) errors.push('at most 50 arguments');
      for (const [k, v] of Object.entries(c.command.env)) {
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) errors.push(`invalid environment variable name ${k}`);
        if (CREDENTIAL_NAME.test(k) && !/\$\{secret:[A-Za-z0-9_.-]+\}/.test(v)) errors.push(`environment variable ${k} looks like a credential: use \${secret:name} and set the value in the secret fields`);
      }
      for (const a of c.command.args) if (/(--?(token|password|api[-_]?key)=)[^$]/i.test(a)) errors.push('credentials in arguments must use ${secret:name}');
    }
  }
  if (protocol === 'mcp_http') {
    if (!c.url) errors.push('url is required');
    else {
      try {
        const u = new URL(c.url);
        if (u.protocol !== 'https:' && u.protocol !== 'http:') errors.push('url must be http(s)');
        if (u.username || u.password) errors.push('credentials in the URL are not allowed; use a header with ${secret:name}');
        // a credential in the query must be a secret reference (`?token=${secret:token}`).
        for (const [k, v] of u.searchParams) if (CREDENTIAL_NAME.test(k) && !/\$\{secret:[A-Za-z0-9_.-]+\}/.test(v)) errors.push(`query parameter ${k} looks like a credential: use \${secret:name}`);
      } catch { errors.push('invalid url'); }
    }
    for (const [k, v] of Object.entries(c.headers ?? {})) {
      if (CREDENTIAL_NAME.test(k) && !/\$\{secret:[A-Za-z0-9_.-]+\}/.test(v)) errors.push(`header ${k} looks like a credential: use \${secret:name}`);
    }
  }
  if (c.concurrency !== undefined && (c.concurrency < 1 || c.concurrency > 8)) errors.push('concurrency must be 1–8');
  if (c.timeouts?.callMs !== undefined && (c.timeouts.callMs < 1000 || c.timeouts.callMs > 300_000)) errors.push('call timeout must be 1–300 s');
  return errors;
}

/**
 * what a connector can do is what its tools declare (read-only or not); there is no separate
 * purpose (context / sync) or “allow writes” setting any more. `purpose` / `allowWrite` are accepted and ignored; the
 * columns keep their defaults.
 */
export interface ConnectorInput { name: string; protocol: ConnectorProtocol; config: ConnectorConfig; authoritative?: boolean; purpose?: 'context' | 'sync'; allowWrite?: boolean }

export function createConnector(store: Store, input: ConnectorInput): ConnectorRow {
  const errors = validateConnectorConfig(input.protocol, input.config);
  if (input.protocol === 'http' && input.config.pack && !existsSync(join(store.paths.connectorPacks, input.config.pack))) errors.push(`connector pack ${input.config.pack} does not exist`);
  if (errors.length) throw new AppError('COMMON_VALIDATION', errors.join('; '), { issues: errors.map((message) => ({ path: 'config', message })) });
  if (store.get('SELECT 1 FROM connector WHERE name = ?', input.name)) throw new AppError('COMMON_VALIDATION', `connector ${input.name} already exists`);
  const id = newId('connector');
  store.insert('connector', { id, name: input.name, protocol: input.protocol, purpose: 'context', config: input.config, allow_write: 0, authoritative: input.authoritative ? 1 : 0 });
  return getConnector(store, id);
}

export async function updateConnector(store: Store, pool: ConnectorPool, id: string, patch: Partial<ConnectorInput> & { enabled?: boolean }): Promise<ConnectorRow> {
  const cur = getConnector(store, id);
  const config = patch.config ?? fromJson<ConnectorConfig>(cur.config, {});
  const errors = validateConnectorConfig(cur.protocol, config);
  if (errors.length) throw new AppError('COMMON_VALIDATION', errors.join('; '), { issues: errors.map((message) => ({ path: 'config', message })) });
  if (patch.name && patch.name !== cur.name && store.get('SELECT 1 FROM connector WHERE name = ?', patch.name)) throw new AppError('COMMON_VALIDATION', `connector ${patch.name} already exists`);
  const authoritative = patch.authoritative !== undefined ? (patch.authoritative ? 1 : 0) : cur.authoritative;
  store.update('connector', { id }, {
    ...(patch.name ? { name: patch.name } : {}), config, authoritative,
    ...(patch.enabled !== undefined ? { enabled: patch.enabled ? 1 : 0 } : {}),
  });
  if (patch.config) await pool.invalidate(id);
  return getConnector(store, id);
}

export async function deleteConnector(store: Store, pool: ConnectorPool, id: string): Promise<void> {
  getConnector(store, id);
  await pool.invalidate(id);
  store.db.run('DELETE FROM connector WHERE id = ?', id);
  const secrets = { ...(store.config.connectorSecrets ?? {}) };
  if (secrets[id]) { delete secrets[id]; store.saveConfig({ ...store.config, connectorSecrets: secrets }); }
}

/** Write-only secrets: a value sets, null removes; only referenced names are accepted. */
export async function setConnectorSecrets(store: Store, pool: ConnectorPool, id: string, values: Record<string, string | null>): Promise<void> {
  const r = getConnector(store, id);
  const refs = new Set(connectorSecretNames(r, store.paths.connectorPacks));
  const unknown = Object.keys(values).filter((k) => !refs.has(k));
  if (unknown.length) throw new AppError('COMMON_VALIDATION', `not referenced by the configuration: ${unknown.join(', ')}`);
  const all = { ...(store.config.connectorSecrets ?? {}) };
  const mine = { ...(all[id] ?? {}) };
  for (const [k, v] of Object.entries(values)) if (v === null || v === '') delete mine[k]; else mine[k] = v;
  all[id] = mine;
  store.saveConfig({ ...store.config, connectorSecrets: all });
  await pool.invalidate(id);
}

/** The user saw the full command line (or the pack scripts) and confirmed this exact hash. */
export function confirmConnectorCommand(store: Store, id: string, hash: string): ConnectorRow {
  const r = getConnector(store, id);
  const expected = confirmationHash(r, store.paths.connectorPacks);
  if (!expected) throw new AppError('COMMON_VALIDATION', 'this connector has no command or scripts to confirm');
  if (expected !== hash) throw new AppError('COMMON_REVISION_CONFLICT', 'the command or scripts changed since they were shown; review them again');
  store.update('connector', { id }, { confirmed_command_hash: hash });
  return getConnector(store, id);
}

export function commandLine(r: ConnectorRow, packsRoot?: string): string | null {
  const spec = connectorSpec(r, packsRoot);
  if (spec.pack) {
    try {
      const p = loadPack(spec.pack.dir, spec.pack.name);
      const scripts = p.scripts.map((sc) => `${spec.pack!.interpreterPath ?? '（未配置解释器）'} ${join(spec.pack!.dir, ...sc.split('/'))}`);
      // what each command operation runs (templates unexpanded), with the HOME it gets.
      const commands = p.program ? p.operations.filter((o) => o.command).map((o) => `[${o.kind}] ${o.name}: ${spec.pack!.programPath ?? `（未找到 ${p.program!.name}）`} ${o.command!.join(' ')}${o.stdin ? ' < {stdin}' : ''}`) : [];
      const head = p.program ? [`# ${p.program.home === 'user' ? '使用你的 HOME（读取该命令自己的登录信息）' : '使用私有 HOME'}${Object.keys(p.program.env).length ? `；环境变量 ${Object.entries(p.program.env).map(([k, v]) => `${k}=${v}`).join(' ')}` : ''}`] : [];
      const lines = [...head, ...commands, ...scripts];
      return lines.length ? lines.join('\n') : null;
    } catch { return null; }
  }
  const cmd = spec.command;
  if (!cmd) return null;
  const q = (s: string) => (/^[\w./:=@%+-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`);
  const env = Object.entries(cmd.env).map(([k, v]) => `${k}=${q(v)}`);
  return [...env, q(cmd.path), ...cmd.args.map(q)].join(' ');
}

function logCall(store: Store, connectorId: string, row: {
  operation: string; kind: 'read' | 'write' | 'test'; status: string; durationMs: number; request?: unknown; bytes?: number; error?: string | null; auditId?: string | null; stepId?: string | null;
  confirmedBy?: 'auto' | 'user' | null; authoritative?: boolean; responseHash?: string | null; responseRef?: string | null; conversationId?: string | null;
  /** the full request of a write call, and the earlier call a replayed write was answered from. */
  requestRef?: string | null; replayedFrom?: string | null;
}): string {
  const id = newId('connectorCall');
  store.insert('connector_call', {
    id, connector_id: connectorId, authoritative: row.authoritative ? 1 : 0, response_hash: row.responseHash ?? null, response_ref: row.responseRef ?? null, audit_id: row.auditId ?? null, conversation_id: row.conversationId ?? null, step_id: row.stepId ?? null, operation: row.operation.slice(0, 200),
    kind: row.kind, status: row.status, duration_ms: row.durationMs, request_hash: row.request === undefined ? null : sha256Hex(canonicalJson(row.request)),
    response_bytes: row.bytes ?? 0, error: row.error ? row.error.slice(0, 500) : null, confirmed_by: row.confirmedBy ?? null,
    request_ref: row.requestRef ?? null, replayed_from: row.replayedFrom ?? null,
  });
  return id;
}

/**
 * Connectivity test: initialize + tools/list with the current configuration. Tools keep their
 * exposure choice by name; new tools start offered.
 */
export async function testConnector(store: Store, pool: ConnectorPool, id: string): Promise<ConnectorRow> {
  const r = getConnector(store, id);
  const spec = connectorSpec(r, store.paths.connectorPacks);
  const started = Date.now();
  const prev = new Map(fromJson<ConnectorTool[]>(r.tools, []).map((t) => [t.name, t]));
  try {
    const t = await pool.test(spec);
    const tools: ConnectorTool[] = t.tools.map((x: McpToolInfo) => ({
      name: x.name, ...(x.title ? { title: x.title } : {}), ...(x.description ? { description: x.description } : {}),
      params: paramSummary(x.inputSchema),
      readOnlyHint: typeof x.annotations?.readOnlyHint === 'boolean' ? x.annotations.readOnlyHint : null,
      destructiveHint: typeof x.annotations?.destructiveHint === 'boolean' ? x.annotations.destructiveHint : null,
      // read and write tools alike start offered; a tool the user turned off stays off.
      exposed: prev.get(x.name)?.exposed ?? true,
    }));
    const test: ConnectorTest = { ok: true, at: Date.now(), specHash: specHash(spec), server: { name: t.server.serverName, version: t.server.serverVersion, protocolVersion: t.server.protocolVersion }, error: null, toolCount: tools.length };
    store.tx(() => {
      store.update('connector', { id }, { last_test: test, tested_spec_hash: test.specHash, tools });
      logCall(store, id, { operation: 'test', kind: 'test', status: 'ok', durationMs: Date.now() - started });
    });
  } catch (e) {
    const err = e as { code?: string; message: string };
    const test: ConnectorTest = { ok: false, at: Date.now(), specHash: specHash(spec), server: null, error: err.message.slice(0, 500), toolCount: 0 };
    store.tx(() => {
      store.update('connector', { id }, { last_test: test, tested_spec_hash: test.specHash });
      logCall(store, id, { operation: 'test', kind: 'test', status: err.code === 'not_confirmed' ? 'refused' : err.code === 'blocked' ? 'blocked' : err.code === 'timeout' ? 'timeout' : 'error', durationMs: Date.now() - started, error: err.message });
    });
  }
  return getConnector(store, id);
}

function paramSummary(schema: unknown): string {
  const props = (schema as { properties?: Record<string, { type?: unknown }>; required?: string[] } | undefined)?.properties ?? {};
  const req = new Set((schema as { required?: string[] } | undefined)?.required ?? []);
  return Object.entries(props).slice(0, 12).map(([k, v]) => `${k}${req.has(k) ? '' : '?'}: ${typeof v?.type === 'string' ? v.type : 'any'}`).join(', ').slice(0, 300);
}

// ---- project bindings ----------------------------------------------------------------------

/** Context connectors bound to a project (or to all projects); default authorization of its audits. */
export function boundContextConnectors(store: Store, projectId: string): string[] {
  return store.all<{ id: string }>(
    `SELECT DISTINCT c.id FROM connector_binding b JOIN connector c ON c.id = b.connector_id
     WHERE (b.project_id = ? OR b.project_id IS NULL) AND c.enabled = 1 AND b.direction IN ('pull', 'bidirectional') ORDER BY c.name`, projectId).map((r) => r.id);
}

export function projectConnectors(store: Store, projectId: string): { connectorId: string; scope: 'project' | 'global' }[] {
  return store.all<{ connector_id: string; project_id: string | null }>('SELECT connector_id, project_id FROM connector_binding WHERE project_id = ? OR project_id IS NULL', projectId)
    .map((r) => ({ connectorId: r.connector_id, scope: r.project_id ? 'project' as const : 'global' as const }));
}

/** Replace the project's own context bindings (global bindings stay). */
export function setProjectConnectors(store: Store, projectId: string, connectorIds: string[]): void {
  for (const id of connectorIds) getConnector(store, id);
  store.tx(() => {
    store.db.run('DELETE FROM connector_binding WHERE project_id = ?', projectId);
    for (const id of [...new Set(connectorIds)]) store.insert('connector_binding', { id: newId('connectorBinding'), connector_id: id, project_id: projectId, direction: 'pull', mapping: {} });
  });
}

/**
 * Turn tools offered to the Agent on or off: any tool of any connector, read or write; all start on.
 */
export function setToolExposure(store: Store, id: string, exposure: { name: string; exposed: boolean }[]): ConnectorRow {
  const r = getConnector(store, id);
  const tools = fromJson<ConnectorTool[]>(r.tools, []);
  for (const e of exposure) {
    const t = tools.find((x) => x.name === e.name);
    if (!t) throw new AppError('COMMON_VALIDATION', `unknown tool ${e.name}; run the connectivity test first`);
    t.exposed = e.exposed;
  }
  store.update('connector', { id }, { tools });
  return getConnector(store, id);
}

/**
 * A read-only query started by the user (“通过连接器查询”): only tools the server marks read-only,
 * on a ready, enabled connector; logged like Agent queries. The result is unverified external data.
 */
export async function userConnectorQuery(store: Store, pool: ConnectorPool, id: string, tool: string, args: Record<string, unknown>, opts: { auditId?: string | null } = {}): Promise<{ text: string; isError: boolean; bytes: number; authoritative: boolean }> {
  const r = getConnector(store, id);
  const status = connectorStatus(r, store.paths.connectorPacks);
  if (!r.enabled || status !== 'ready') throw new AppError('COMMON_VALIDATION', `connector ${r.name} is not ready (${status})`);
  const t = fromJson<ConnectorTool[]>(r.tools, []).find((x) => x.name === tool);
  if (!t || (!isMcp(r) && t.readOnlyHint !== true)) throw new AppError('COMMON_VALIDATION', `tool ${tool} is not a read operation of ${r.name}`);
  const started = Date.now();
  try {
    const res = await pool.call(connectorSpec(r, store.paths.connectorPacks), tool, args);
    const bytes = Buffer.byteLength(res.text);
    // Same rule as in analysis: authoritative only if marked, successful and free of injection signals.
    const authoritative = !!r.authoritative && !res.isError && detectInjection(res.text).length === 0;
    logCall(store, id, { operation: tool, kind: t.readOnlyHint === true ? 'read' : 'write', ...(t.readOnlyHint === true ? {} : { confirmedBy: 'user' as const }), status: res.isError ? 'error' : 'ok', durationMs: Date.now() - started, request: args, bytes, auditId: opts.auditId ?? null, authoritative, responseHash: authoritative ? sha256Hex(res.text) : null });
    return { text: res.text.length > 64 * 1024 ? `${res.text.slice(0, 64 * 1024)}\n…（已截断，共 ${bytes} 字节）` : res.text, isError: res.isError, bytes, authoritative };
  } catch (e) {
    const err = e as { code?: string; message: string };
    logCall(store, id, { operation: tool, kind: t.readOnlyHint === true ? 'read' : 'write', status: err.code === 'unavailable' ? 'unavailable' : err.code === 'timeout' ? 'timeout' : err.code === 'blocked' ? 'blocked' : 'error', durationMs: Date.now() - started, request: args, error: err.message });
    throw new AppError('COMMON_VALIDATION', `connector query failed: ${err.message.slice(0, 300)}`);
  }
}

export { logCall as logConnectorCall };

// ---- write requests ---------------------------------------------------------------------

export interface WriteRequestRow {
  id: string; connector_id: string; tool: string; args: string; reason: string | null; source: 'audit' | 'conversation' | 'push';
  audit_id: string | null; step_id: string | null; conversation_id: string | null; message_id: string | null;
  status: 'pending' | 'executed' | 'failed' | 'rejected'; signals: string; result: string | null; error: string | null; call_id: string | null;
  decision_note: string | null; decided_at: number | null; created_at: number; updated_at: number;
}

/**
 * File a call the Agent asked for that carries instructions from the audited code: it runs only after the user
 * approves it. `signals`: suspected injected instructions in the arguments.
 */
export function requestConnectorWrite(store: Store, r: {
  connectorId: string; tool: string; args: Record<string, unknown>; reason: string; source: WriteRequestRow['source'];
  auditId?: string | null; stepId?: string | null; conversationId?: string | null; messageId?: string | null;
}): WriteRequestRow {
  const id = newId('connectorWrite');
  const signals = [...new Set(detectInjection(JSON.stringify(r.args)).map((x) => x.signal))];
  store.insert('connector_write_request', {
    id, connector_id: r.connectorId, tool: r.tool, args: r.args, reason: r.reason.slice(0, 500), source: r.source,
    audit_id: r.auditId ?? null, step_id: r.stepId ?? null, conversation_id: r.conversationId ?? null, message_id: r.messageId ?? null,
    status: 'pending', signals,
  });
  return getWriteRequest(store, id);
}

export function getWriteRequest(store: Store, id: string): WriteRequestRow {
  const r = store.get<WriteRequestRow>('SELECT * FROM connector_write_request WHERE id = ?', id);
  if (!r) throw new AppError('COMMON_NOT_FOUND', `write request ${id}`);
  return r;
}

export function listWriteRequests(store: Store, status?: WriteRequestRow['status']): WriteRequestRow[] {
  return status
    ? store.all<WriteRequestRow>('SELECT * FROM connector_write_request WHERE status = ? ORDER BY created_at DESC LIMIT 200', status)
    : store.all<WriteRequestRow>('SELECT * FROM connector_write_request ORDER BY created_at DESC LIMIT 200');
}

/**
 * The user's decision on a held call. Approve: the connector must still be ready and enabled; the call runs and is
 * logged with `confirmed_by: user`. Reject: nothing runs. Either way the audit trajectory gets `connector.write_decided`
 * when the request came from an audit.
 */
export async function decideWriteRequest(store: Store, pool: ConnectorPool, id: string, decision: 'approve' | 'reject', note?: string): Promise<WriteRequestRow> {
  const w = getWriteRequest(store, id);
  if (w.status !== 'pending') throw new AppError('COMMON_VALIDATION', `write request ${id} was already decided (${w.status})`);
  const c = getConnector(store, w.connector_id);
  const record = (patch: Record<string, unknown>, payload: Record<string, unknown>) => store.tx(() => {
    store.update('connector_write_request', { id }, { ...patch, decided_at: Date.now(), decision_note: note?.slice(0, 500) ?? null });
    if (w.audit_id) store.appendEvent(w.audit_id, 'connector.write_decided', { request_id: id, connector: c.name, operation: w.tool, ...payload }, w.step_id);
  });
  if (decision === 'reject') {
    record({ status: 'rejected' }, { decision: 'rejected', ...(note ? { note: note.slice(0, 300) } : {}) });
    return getWriteRequest(store, id);
  }
  const status = connectorStatus(c, store.paths.connectorPacks);
  if (!c.enabled || status !== 'ready') throw new AppError('COMMON_VALIDATION', `connector ${c.name} is not ready (${status})`);
  const started = Date.now();
  try {
    const res = await pool.call(connectorSpec(c, store.paths.connectorPacks), w.tool, fromJson<Record<string, unknown>>(w.args, {}));
    const callId = logCall(store, c.id, {
      operation: w.tool, kind: 'write', status: res.isError ? 'error' : 'ok', durationMs: Date.now() - started, request: fromJson(w.args, {}), bytes: Buffer.byteLength(res.text), auditId: w.audit_id, stepId: w.step_id, conversationId: w.conversation_id, confirmedBy: 'user',
      // Kept in full, so an identical later call is answered from it.
      requestRef: store.artifacts.putJson(fromJson(w.args, {})), responseRef: store.artifacts.put(res.text, 'text/plain'),
    });
    record({ status: res.isError ? 'failed' : 'executed', result: res.text.slice(0, 64 * 1024), call_id: callId, ...(res.isError ? { error: res.text.slice(0, 500) } : {}) },
      { decision: 'approved', status: res.isError ? 'error' : 'ok', call_id: callId });
  } catch (e) {
    const msg = (e as Error).message.slice(0, 500);
    const callId = logCall(store, c.id, { operation: w.tool, kind: 'write', status: 'error', durationMs: Date.now() - started, request: fromJson(w.args, {}), error: msg, auditId: w.audit_id, stepId: w.step_id, conversationId: w.conversation_id, confirmedBy: 'user' });
    record({ status: 'failed', error: msg, call_id: callId }, { decision: 'approved', status: 'error', error: msg.slice(0, 300) });
  }
  return getWriteRequest(store, id);
}
