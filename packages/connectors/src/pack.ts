// Connector packs (declarative HTTP): a directory with `CONNECTOR.md` (frontmatter: base
// URL, auth, secrets, variables, interpreter) and `operations.yaml` (declarative operations, read / write),
// plus optional `scripts/` for authentication (e.g. signing, token exchange) or a whole operation. A pack is
// served through `PackClient`, which has the MCP client's shape, so tests, exposure, `connector_query` and
// the call log treat packs and MCP servers alike. Scripts only run through the injected runner (executor)
// after the user confirmed their hash.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { canonicalJson, sha256Hex } from '@xiezhi/contracts';
import { parse as parseYaml } from 'yaml';
import { outbound } from './outbound.js';
import type { McpCallResult, McpServerInfo, McpToolInfo } from './mcp.js';

export const PACK_NAME = /^[a-z0-9][a-z0-9-]{1,63}$/;
const MAX_PACK_FILE = 256 * 1024;
const MAX_PACK_FILES = 100;
export const PACK_RESPONSE_MAX = 32 * 1024;
/** An operation may raise its cap (`response.max_bytes`) up to this, e.g. reading a whole document. */
export const PACK_RESPONSE_MAX_LARGE = 256 * 1024;

export type ParamSpec = { type: 'string' | 'integer' | 'number' | 'boolean' | 'array'; description?: string; enum?: (string | number)[]; pattern?: string; maxLength?: number; minimum?: number; maximum?: number; default?: unknown; required?: boolean; items?: { type: 'string' | 'integer' } };

export interface PackOperation {
  name: string;
  kind: 'read' | 'write';
  description: string;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path?: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: unknown;
  /** Alternative to method/path: a script under `scripts/` that receives the arguments on stdin. */
  script?: string;
  /**
   * Alternative: arguments of the pack's `program` (a CLI), each a literal or a `{param}` template; an item
   * that is exactly `{param}` with no value is left out together with the flag before it. `stdin`: a template fed on
   * standard input (large content, e.g. a document body passed as `--content -`).
   */
  command?: string[];
  stdin?: string;
  params: Record<string, ParamSpec>;
  response?: { extract?: string; max_bytes?: number };
}

export interface Pack {
  name: string;
  description: string;
  baseUrl: string | null;
  auth: { type: 'none' } | { type: 'header'; name: string; value: string } | { type: 'script'; script: string };
  secrets: string[];
  variables: string[];
  interpreter: string | null;
  /** the CLI the `command` operations run, and whether it runs with the user's HOME (its own login). */
  program: { name: string; home: 'user' | 'private'; env: Record<string, string> } | null;
  notes: string;
  operations: PackOperation[];
  /** Relative path → sha256 of every file. */
  files: Record<string, string>;
  hash: string;
  scripts: string[];
}

export class PackError extends Error {
  constructor(message: string, readonly errors: string[] = [message]) {
    super(message);
    this.name = 'PackError';
  }
}

function walk(dir: string): string[] {
  const out: string[] = [];
  const rec = (d: string) => {
    for (const n of readdirSync(d).sort()) {
      if (n.startsWith('.') || n.startsWith('_')) continue;
      const p = join(d, n);
      if (statSync(p).isDirectory()) rec(p);
      else out.push(p);
    }
  };
  rec(dir);
  return out;
}

function frontmatter(text: string): { meta: Record<string, unknown>; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) throw new PackError('CONNECTOR.md has no frontmatter');
  return { meta: (parseYaml(m[1]!) ?? {}) as Record<string, unknown>, body: text.slice(m[0].length) };
}

const TYPES = ['string', 'integer', 'number', 'boolean', 'array'];

/** Load and validate a pack directory. Errors list every problem found. */
export function loadPack(dir: string, expectedName?: string): Pack {
  const errors: string[] = [];
  if (!existsSync(join(dir, 'CONNECTOR.md'))) throw new PackError('missing CONNECTOR.md');
  if (!existsSync(join(dir, 'operations.yaml'))) throw new PackError('missing operations.yaml');
  const all = walk(dir);
  if (all.length > MAX_PACK_FILES) errors.push(`too many files (${all.length} > ${MAX_PACK_FILES})`);
  const files: Record<string, string> = {};
  for (const f of all) {
    if (statSync(f).size > MAX_PACK_FILE) errors.push(`${relative(dir, f)} exceeds 256 KB`);
    files[relative(dir, f).split(sep).join('/')] = sha256Hex(readFileSync(f));
  }
  const { meta, body } = frontmatter(readFileSync(join(dir, 'CONNECTOR.md'), 'utf8'));
  const name = String(meta.name ?? '');
  if (!PACK_NAME.test(name)) errors.push('name must match ^[a-z0-9][a-z0-9-]{1,63}$');
  if (expectedName && name !== expectedName) errors.push(`name "${name}" must equal the directory name "${expectedName}"`);
  const description = String(meta.description ?? '');
  if (description.length < 10 || description.length > 400) errors.push('description must be 10–400 characters');
  const baseUrl = meta.base_url === undefined || meta.base_url === null ? null : String(meta.base_url);
  if (baseUrl && !/^https?:\/\//.test(baseUrl)) errors.push('base_url must be http(s)');
  const a = (meta.auth ?? { type: 'none' }) as Record<string, unknown>;
  let auth: Pack['auth'] = { type: 'none' };
  if (a.type === 'header') {
    auth = { type: 'header', name: String(a.name ?? 'Authorization'), value: String(a.value ?? '') };
    if (!/\$\{secret:[A-Za-z0-9_.-]+\}/.test(auth.value)) errors.push('auth.value must reference a secret (${secret:name})');
  } else if (a.type === 'script') {
    auth = { type: 'script', script: String(a.script ?? '') };
  } else if (a.type !== 'none' && a.type !== undefined) errors.push(`unknown auth type ${String(a.type)}`);
  const secrets = Array.isArray(meta.secrets) ? meta.secrets.map(String) : [];
  const variables = Array.isArray(meta.variables) ? meta.variables.map(String) : [];
  for (const s of [...secrets, ...variables]) if (!/^[A-Za-z0-9_.-]{1,64}$/.test(s)) errors.push(`invalid secret / variable name ${s}`);
  const interpreter = meta.interpreter ? String(meta.interpreter) : null;
  let program: Pack['program'] = null;
  if (meta.program !== undefined) {
    const pr = (typeof meta.program === 'string' ? { name: meta.program } : meta.program) as Record<string, unknown>;
    const pname = String(pr.name ?? '');
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(pname)) errors.push('program.name must be a command name (no path)');
    const home = pr.home === undefined ? 'private' : String(pr.home);
    if (home !== 'user' && home !== 'private') errors.push('program.home must be user or private');
    const env = (pr.env ?? {}) as Record<string, unknown>;
    for (const [k, v] of Object.entries(env)) if (!/^[A-Z_][A-Z0-9_]{0,63}$/.test(k) || typeof v !== 'string' || /secret:/.test(v)) errors.push(`program.env.${k} must be a plain string`);
    program = { name: pname, home: home as 'user' | 'private', env: env as Record<string, string> };
  }
  let ops: unknown;
  try { ops = (parseYaml(readFileSync(join(dir, 'operations.yaml'), 'utf8')) as { operations?: unknown } | null)?.operations; } catch (e) { errors.push(`operations.yaml: ${(e as Error).message.split('\n')[0]}`); }
  const operations: PackOperation[] = [];
  if (!Array.isArray(ops) || !ops.length) errors.push('operations.yaml must list operations');
  for (const [i, raw] of (Array.isArray(ops) ? ops : []).entries()) {
    const o = raw as Record<string, unknown>;
    const where = `operations[${i}]`;
    const op: PackOperation = {
      name: String(o.name ?? ''), kind: (o.kind ?? (String(o.method ?? 'GET').toUpperCase() === 'GET' ? 'read' : 'write')) as 'read' | 'write',
      description: String(o.description ?? ''), params: (o.params ?? {}) as Record<string, ParamSpec>,
      ...(o.method ? { method: String(o.method).toUpperCase() as PackOperation['method'] } : {}), ...(o.path ? { path: String(o.path) } : {}),
      ...(o.query ? { query: o.query as Record<string, string> } : {}), ...(o.headers ? { headers: o.headers as Record<string, string> } : {}),
      ...(o.body !== undefined ? { body: o.body } : {}), ...(o.script ? { script: String(o.script) } : {}),
      ...(Array.isArray(o.command) ? { command: o.command.map(String) } : {}), ...(o.stdin !== undefined ? { stdin: String(o.stdin) } : {}),
      ...(o.response ? { response: o.response as PackOperation['response'] } : {}),
    };
    if (!/^[a-z][a-z0-9_]{1,63}$/.test(op.name)) errors.push(`${where}: name must be snake_case`);
    if (op.kind !== 'read' && op.kind !== 'write') errors.push(`${where}: kind must be read or write`);
    if (!op.description) errors.push(`${where}: description is required`);
    if (op.script) {
      if (!files[op.script] || !op.script.startsWith('scripts/')) errors.push(`${where}: script must be a file under scripts/`);
    } else if (op.command) {
      if (!program) errors.push(`${where}: command operations need a program in CONNECTOR.md`);
      if (!op.command.length || op.command.length > 60) errors.push(`${where}: command must list 1–60 arguments`);
      if (op.command.some((a) => /[\0\n\r]/.test(a))) errors.push(`${where}: command arguments must be single-line`);
    } else {
      if (!op.method || !['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(op.method)) errors.push(`${where}: method is required`);
      if (!op.path || !op.path.startsWith('/')) errors.push(`${where}: path must start with /`);
      if (!baseUrl) errors.push(`${where}: base_url is required for HTTP operations`);
      if (op.method === 'GET' && op.kind === 'write') errors.push(`${where}: GET operations must be read`);
    }
    for (const [k, p] of Object.entries(op.params)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) errors.push(`${where}: invalid parameter name ${k}`);
      if (!TYPES.includes(p?.type)) errors.push(`${where}.params.${k}: type must be one of ${TYPES.join(', ')}`);
    }
    for (const ref of templateRefs([op.path ?? '', op.query ?? {}, op.headers ?? {}, op.body ?? null, op.command ?? [], op.stdin ?? ''])) {
      if (!(ref in op.params)) errors.push(`${where}: template refers to unknown parameter {${ref}}`);
    }
    operations.push(op);
  }
  if (auth.type === 'script' && (!files[auth.script] || !auth.script.startsWith('scripts/'))) errors.push('auth.script must be a file under scripts/');
  const scripts = [...new Set([...(auth.type === 'script' ? [auth.script] : []), ...operations.flatMap((o) => (o.script ? [o.script] : []))])];
  if (scripts.length && !interpreter) errors.push('interpreter is required when the pack has scripts (node or python3)');
  if (errors.length) throw new PackError(`invalid connector pack: ${errors[0]}`, errors);
  return {
    name, description, baseUrl, auth, secrets, variables, interpreter, program, notes: body.trim(), operations, files, scripts,
    hash: sha256Hex(canonicalJson(Object.entries(files).sort(([x], [y]) => x.localeCompare(y)))),
  };
}

/**
 * What the user confirms for a pack with a program: the program's path, its HOME mode and fixed environment,
 * every command template, and the scripts with their interpreter (if any).
 */
export function packCommandsHash(pack: Pack, programPath: string, interpreterPath: string | null): string {
  return sha256Hex(canonicalJson({
    program: programPath, home: pack.program?.home ?? 'private', env: Object.entries(pack.program?.env ?? {}).sort(([a], [b]) => a.localeCompare(b)),
    commands: pack.operations.filter((o) => o.command).map((o) => [o.name, o.kind, o.command, o.stdin ?? null]),
    ...(pack.scripts.length ? { interpreter: interpreterPath, scripts: pack.scripts.map((sc) => [sc, pack.files[sc]]) } : {}),
  }));
}

/** Arguments of a command operation: `{param}` items without a value are dropped with the flag before them. */
export function fillCommand(t: string[], args: Record<string, unknown>): string[] {
  const out: string[] = [];
  for (const item of t) {
    const whole = /^\{([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(item);
    if (whole && (args[whole[1]!] === undefined || args[whole[1]!] === '')) {
      if (out.length && out[out.length - 1]!.startsWith('-')) out.pop();
      continue;
    }
    const v = fillString(item, args);
    if (/[\0\n\r]/.test(v)) throw new PackError('command arguments must be single-line; pass long text through stdin');
    out.push(v);
  }
  return out;
}

/** Hash the user confirms before any script of the pack runs: interpreter path + script contents. */
export function packScriptsHash(pack: Pack, interpreterPath: string): string {
  return sha256Hex(canonicalJson({ interpreter: interpreterPath, scripts: pack.scripts.map((s) => [s, pack.files[s]]) }));
}

// ---- templates ---------------------------------------------------------------------------------------------

function templateRefs(v: unknown): string[] {
  if (typeof v === 'string') return [...v.matchAll(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g)].map((m) => m[1]!);
  if (Array.isArray(v)) return v.flatMap(templateRefs);
  if (v && typeof v === 'object') return Object.values(v).flatMap(templateRefs);
  return [];
}

/** Check arguments against the parameter subset and fill defaults. */
export function checkArgs(op: PackOperation, args: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const errors: string[] = [];
  for (const k of Object.keys(args)) if (!(k in op.params)) errors.push(`unknown parameter ${k}`);
  for (const [k, p] of Object.entries(op.params)) {
    let v = args[k];
    if (v === undefined || v === null || v === '') {
      if (p.default !== undefined) v = p.default;
      else if (p.required) { errors.push(`${k} is required`); continue; } else continue;
    }
    if (p.type === 'integer' || p.type === 'number') {
      const n = typeof v === 'string' && v.trim() !== '' ? Number(v) : v;
      if (typeof n !== 'number' || Number.isNaN(n) || (p.type === 'integer' && !Number.isInteger(n))) { errors.push(`${k} must be ${p.type === 'integer' ? 'an integer' : 'a number'}`); continue; }
      if (p.minimum !== undefined && n < p.minimum) errors.push(`${k} must be ≥ ${p.minimum}`);
      if (p.maximum !== undefined && n > p.maximum) errors.push(`${k} must be ≤ ${p.maximum}`);
      v = n;
    } else if (p.type === 'boolean') {
      if (typeof v !== 'boolean') { errors.push(`${k} must be a boolean`); continue; }
    } else if (p.type === 'array') {
      if (!Array.isArray(v) || v.length > 50) { errors.push(`${k} must be an array (≤ 50 items)`); continue; }
    } else {
      v = String(v);
      if (p.maxLength !== undefined && (v as string).length > p.maxLength) errors.push(`${k} exceeds ${p.maxLength} characters`);
      if (p.pattern && !new RegExp(p.pattern).test(v as string)) errors.push(`${k} does not match ${p.pattern}`);
    }
    if (p.enum && !p.enum.includes(v as string | number)) errors.push(`${k} must be one of ${p.enum.join(', ')}`);
    out[k] = v;
  }
  if (errors.length) throw new PackError(`invalid arguments: ${errors.join('; ')}`, errors);
  return out;
}

/** String template: `{param}` replaced by the value (as text). */
function fillString(t: string, args: Record<string, unknown>): string {
  return t.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, k: string) => (args[k] === undefined ? '' : String(args[k])));
}

/**
 * JSON body template: a string that is exactly `{param}` becomes the typed value (numbers, arrays stay typed);
 * other strings get text substitution inside the string. Never string concatenation of JSON.
 */
export function fillBody(t: unknown, args: Record<string, unknown>): unknown {
  if (typeof t === 'string') {
    const whole = /^\{([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(t);
    if (whole) return args[whole[1]!] ?? null;
    return fillString(t, args);
  }
  if (Array.isArray(t)) return t.map((x) => fillBody(x, args));
  if (t && typeof t === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(t)) {
      const filled = fillBody(v, args);
      if (filled !== null && filled !== undefined) out[k] = filled;
    }
    return out;
  }
  return t;
}

/** Path parameters are URL-encoded and may not carry `/` or `..`. */
export function fillPath(t: string, args: Record<string, unknown>): string {
  return t.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, k: string) => {
    const v = String(args[k] ?? '');
    if (!v || v.includes('/') || v.includes('..')) throw new PackError(`path parameter ${k} must be a non-empty value without "/" or ".."`);
    return encodeURIComponent(v);
  });
}

// ---- response extraction (a small JSONPath subset) -----------------------------------------------------

function getPath(v: unknown, path: string): unknown {
  let cur = v;
  for (const seg of path.split('.').filter(Boolean)) {
    if (cur === null || cur === undefined) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

function project(v: unknown, fields: string[]): unknown {
  const out: Record<string, unknown> = {};
  for (const f of fields) out[f] = getPath(v, f);
  return out;
}

/**
 * `$.a.b`, `$.a[*]`, `$.a[*].{x,y.z}`, `$.{x,y}`. Anything else returns the whole value (and the caller
 * still truncates by size).
 */
export function extract(v: unknown, expr: string | undefined): unknown {
  if (!expr || expr === '$') return v;
  const m = /^\$(?:\.([\w.]+?))?(\[\*\])?(?:\.\{([\w.,\s]+)\})?$/.exec(expr.trim());
  if (!m) return v;
  let cur = m[1] ? getPath(v, m[1]) : v;
  const fields = m[3]?.split(',').map((f) => f.trim()).filter(Boolean);
  if (m[2]) {
    const arr = Array.isArray(cur) ? cur : [];
    cur = fields ? arr.map((x) => project(x, fields)) : arr;
  } else if (fields) cur = project(cur, fields);
  return cur;
}

// ---- client ---------------------------------------------------------------------------------------------

export interface ScriptRun {
  (spec: { interpreter: string; script: string; cwd: string; env: Record<string, string>; input: string; timeoutMs: number }): Promise<{ ok: boolean; stdout: string; error: string | null }>;
}

/** Runs a pack command through the executor. */
export type CommandRun = (req: { program: string; args: string[]; cwd: string; env: Record<string, string>; input: string; timeoutMs: number; home: 'user' | 'private' }) => Promise<{ ok: boolean; stdout: string; error: string | null }>;

export interface PackRuntime {
  dir: string;
  baseUrl: string | null;
  variables: Record<string, string>;
  secrets: Record<string, string>;
  interpreterPath: string | null;
  runScript: ScriptRun | null;
  programPath?: string | null;
  runCommand?: CommandRun | null;
  cwd: string;
  timeoutMs: number;
}

/** Parameter subset → JSON schema (for the tool list and the Agent's operation list). */
export function paramsSchema(op: PackOperation): { type: 'object'; properties: Record<string, unknown>; required: string[] } {
  const properties: Record<string, unknown> = {};
  for (const [k, p] of Object.entries(op.params)) properties[k] = { type: p.type, ...(p.description ? { description: p.description } : {}), ...(p.enum ? { enum: p.enum } : {}) };
  return { type: 'object', properties, required: Object.entries(op.params).filter(([, p]) => p.required).map(([k]) => k) };
}

const envName = (prefix: string, k: string) => `${prefix}${k.toUpperCase().replace(/[^A-Z0-9]/g, '_')}`;

export class PackClient {
  private authCache: { headers: Record<string, string>; until: number } | null = null;
  constructor(private readonly pack: Pack, private readonly rt: PackRuntime) {}

  async connect(): Promise<McpServerInfo> {
    return { protocolVersion: 'connector-pack/1', serverName: this.pack.name, serverVersion: this.pack.hash.slice(0, 12), instructions: null, hasTools: true };
  }

  async listTools(): Promise<McpToolInfo[]> {
    return this.pack.operations.map((o) => ({ name: o.name, description: o.description, inputSchema: paramsSchema(o), annotations: { readOnlyHint: o.kind === 'read', destructiveHint: o.kind === 'write' && o.method === 'DELETE' } }));
  }

  private scriptEnv(): Record<string, string> {
    return {
      ...Object.fromEntries(this.pack.variables.map((v) => [envName('CA_VAR_', v), this.rt.variables[v] ?? ''])),
      ...Object.fromEntries(this.pack.secrets.map((s) => [envName('CA_SECRET_', s), this.rt.secrets[s] ?? ''])),
      ...(this.rt.baseUrl ?? this.pack.baseUrl ? { CA_BASE_URL: (this.rt.baseUrl ?? this.pack.baseUrl)! } : {}),
    };
  }

  private async script(rel: string, input: unknown): Promise<unknown> {
    if (!this.rt.runScript || !this.rt.interpreterPath) throw new PackError('scripts are not available (interpreter not configured or not confirmed)');
    const r = await this.rt.runScript({ interpreter: this.rt.interpreterPath, script: join(this.rt.dir, ...rel.split('/')), cwd: this.rt.cwd, env: this.scriptEnv(), input: JSON.stringify(input), timeoutMs: this.rt.timeoutMs });
    if (!r.ok) throw new PackError(`script ${rel} failed: ${(r.error ?? '').slice(0, 300)}`);
    try { return JSON.parse(r.stdout); } catch { throw new PackError(`script ${rel} did not print JSON`); }
  }

  private async authHeaders(): Promise<Record<string, string>> {
    const a = this.pack.auth;
    if (a.type === 'none') return {};
    if (a.type === 'header') {
      const value = a.value.replace(/\$\{secret:([A-Za-z0-9_.-]+)\}/g, (_, k: string) => {
        const v = this.rt.secrets[k];
        if (v === undefined) throw new PackError(`secret ${k} is not configured`);
        return v;
      });
      return { [a.name]: value };
    }
    if (this.authCache && this.authCache.until > Date.now()) return this.authCache.headers;
    const out = await this.script(a.script, { purpose: 'auth' }) as { headers?: Record<string, string>; expiresIn?: number };
    const headers = Object.fromEntries(Object.entries(out.headers ?? {}).map(([k, v]) => [k, String(v)]));
    this.authCache = { headers, until: Date.now() + Math.min(3600, Math.max(0, out.expiresIn ?? 0)) * 1000 };
    return headers;
  }

  async callTool(name: string, rawArgs: Record<string, unknown>, signal?: AbortSignal): Promise<McpCallResult> {
    const op = this.pack.operations.find((o) => o.name === name);
    if (!op) throw new PackError(`unknown operation ${name}`);
    const args = checkArgs(op, rawArgs);
    const max = Math.min(op.response?.max_bytes ?? PACK_RESPONSE_MAX, PACK_RESPONSE_MAX_LARGE);
    let value: unknown;
    if (op.script) {
      value = await this.script(op.script, { operation: op.name, args });
    } else if (op.command) {
      if (!this.rt.runCommand || !this.rt.programPath || !this.pack.program) throw new PackError('commands are not available (program not found or not confirmed)');
      const r = await this.rt.runCommand({
        program: this.rt.programPath, args: fillCommand(op.command, args), cwd: this.rt.cwd, env: { ...this.pack.program.env, ...this.scriptEnv() },
        input: op.stdin !== undefined ? fillString(op.stdin, args) : '', timeoutMs: this.rt.timeoutMs, home: this.pack.program.home,
      });
      let json: unknown = r.stdout;
      try { json = r.stdout.trim() ? JSON.parse(r.stdout) : null; } catch { /* keep text */ }
      if (!r.ok) return { text: `${(r.error ?? 'failed').slice(0, 1000)}${r.stdout.trim() ? `\n${r.stdout.slice(0, 2000)}` : ''}`, isError: true, structured: null };
      value = json;
    } else {
      const base = (this.rt.baseUrl ?? this.pack.baseUrl)!.replace(/\/+$/, '');
      const url = new URL(`${base}${fillPath(op.path!, args)}`);
      for (const [k, t] of Object.entries(op.query ?? {})) {
        const v = fillString(t, args);
        if (v !== '') url.searchParams.set(k, v);
      }
      const headers: Record<string, string> = { accept: 'application/json', ...Object.fromEntries(Object.entries(op.headers ?? {}).map(([k, t]) => [k, fillString(t, args)])), ...(await this.authHeaders()) };
      const body = op.body !== undefined ? JSON.stringify(fillBody(op.body, args)) : undefined;
      if (body !== undefined) headers['content-type'] = 'application/json';
      const res = await outbound({
        url: url.toString(), method: op.method!, headers,
        ...(body !== undefined ? { body } : {}), policy: { configuredHosts: [new URL(base).hostname] }, timeoutMs: this.rt.timeoutMs, maxBytes: 4 * 1024 * 1024, ...(signal ? { signal } : {}),
      });
      const text = await res.text();
      let json: unknown = text;
      try { json = text ? JSON.parse(text) : null; } catch { /* keep text */ }
      if (res.status >= 400) return { text: `HTTP ${res.status}: ${(typeof json === 'string' ? json : JSON.stringify(json)).slice(0, 2000)}`, isError: true, structured: null };
      value = json;
    }
    const extracted = extract(value, op.response?.extract);
    let out = typeof extracted === 'string' ? extracted : JSON.stringify(extracted, null, 1);
    if (Buffer.byteLength(out) > max) out = `${Buffer.from(out).subarray(0, max).toString('utf8')}\n…（已截断）`;
    return { text: out, isError: false, structured: typeof extracted === 'object' ? extracted : null };
  }

  async close(): Promise<void> {
    this.authCache = null;
  }
}
