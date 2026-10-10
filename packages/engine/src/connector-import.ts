// Import MCP servers already configured in other tools: Cursor, Claude Code, Claude
// Desktop, Gemini CLI, Windsurf. The configuration becomes an ordinary connector — the command is confirmed and
// tested as usual — and credentials found in it become `${secret:…}` references. Secret values are never returned
// by discovery; a person chooses per credential to copy it into the local secret store, leave it to fill in, or drop
// the argument (e.g. an expired user token).
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AppError } from '@xiezhi/contracts';
import type { ConnectorPool } from '@xiezhi/connectors';
import type { Store } from '@xiezhi/store';
import { resolveCommand } from './command-path.js';
import { createConnector, setConnectorSecrets, type ConnectorRow } from './connectors.js';

export { resolveCommand };

export const MCP_IMPORT_SOURCES = {
  cursor: { label: 'Cursor', file: ['.cursor', 'mcp.json'] },
  claude_code: { label: 'Claude Code', file: ['.claude.json'] },
  claude_desktop: { label: 'Claude Desktop', file: ['Library', 'Application Support', 'Claude', 'claude_desktop_config.json'] },
  gemini: { label: 'Gemini CLI', file: ['.gemini', 'settings.json'] },
  windsurf: { label: 'Windsurf', file: ['.codeium', 'windsurf', 'mcp_config.json'] },
} as const;
export type McpImportSource = keyof typeof MCP_IMPORT_SOURCES;

/** A credential found in a configuration: where it is and the secret name it would get. */
export interface McpImportSecret { name: string; where: 'arg' | 'env' | 'header' | 'query'; key: string; masked: string }
export interface McpImportCandidate {
  id: string; source: McpImportSource; sourceLabel: string; sourcePath: string; name: string; protocol: 'mcp_stdio' | 'mcp_http';
  /** stdio: the command as configured and its absolute path when found; args with credentials shown as `<密钥>`. */
  command: string | null; resolvedPath: string | null; args: string[]; envKeys: string[];
  url: string | null; headerKeys: string[]; secrets: McpImportSecret[];
  /** What would stop the import or needs attention (unsupported transport, command not found …). */
  issues: string[];
}

interface RawServer { command?: unknown; args?: unknown; env?: unknown; url?: unknown; serverUrl?: unknown; httpUrl?: unknown; headers?: unknown; type?: unknown; transport?: unknown; disabled?: unknown }
interface Parsed { candidate: McpImportCandidate; raw: { args: string[]; env: Record<string, string>; headers: Record<string, string>; url: string | null } }

const SECRET_WORD = /(secret|token|password|passwd|api[-_]?key|access[-_]?key|private[-_]?key|credential|auth)/i;
/** Short flags commonly carrying credentials (`-s` app secret, `-u` user token, `-k` key). */
const SECRET_SHORT = new Set(['-s', '-u', '-k']);
const MASK = '<密钥>';

const mask = (v: string) => (v.length <= 8 ? '•••' : `•••${v.slice(-2)}`);
const secretName = (key: string) => key.replace(/^-+/, '').replace(/[^A-Za-z0-9_.-]+/g, '_').toLowerCase().slice(0, 64) || 'secret';
const strings = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
const record = (v: unknown): Record<string, string> => (v && typeof v === 'object' && !Array.isArray(v)
  ? Object.fromEntries(Object.entries(v as Record<string, unknown>).filter((e): e is [string, string] => typeof e[1] === 'string')) : {});

/** Credentials in args: `--app-secret X`, `--token=X`, `-s X`; values that are already `${…}` references are left alone. */
function argSecrets(args: string[]): { index: number; key: string; value: string }[] {
  const out: { index: number; key: string; value: string }[] = [];
  args.forEach((a, i) => {
    const eq = /^(--?[A-Za-z][\w-]*)=(.+)$/.exec(a);
    if (eq && SECRET_WORD.test(eq[1]!) && !eq[2]!.startsWith('${')) out.push({ index: i, key: eq[1]!, value: eq[2]! });
    else if ((SECRET_SHORT.has(a) || (/^--[A-Za-z]/.test(a) && SECRET_WORD.test(a))) && i + 1 < args.length && !args[i + 1]!.startsWith('-') && !args[i + 1]!.startsWith('${')) {
      out.push({ index: i + 1, key: a, value: args[i + 1]! });
    }
  });
  return out;
}


function parseServer(source: McpImportSource, sourcePath: string, name: string, s: RawServer, pathDirs: string[]): Parsed {
  const issues: string[] = [];
  const url = typeof s.url === 'string' ? s.url : typeof s.serverUrl === 'string' ? s.serverUrl : typeof s.httpUrl === 'string' ? s.httpUrl : null;
  const transport = String(s.type ?? s.transport ?? '').toLowerCase();
  const protocol: 'mcp_stdio' | 'mcp_http' = typeof s.command === 'string' ? 'mcp_stdio' : 'mcp_http';
  const args = strings(s.args);
  const env = record(s.env);
  const headers = record(s.headers);
  const secrets: McpImportSecret[] = [];
  const shownArgs = [...args];
  for (const x of argSecrets(args)) {
    secrets.push({ name: secretName(x.key), where: 'arg', key: x.key, masked: mask(x.value) });
    shownArgs[x.index] = shownArgs[x.index]!.includes('=') && shownArgs[x.index]!.startsWith('-') ? `${x.key}=${MASK}` : MASK;
  }
  for (const [k, v] of Object.entries(env)) if (SECRET_WORD.test(k) && !v.startsWith('${')) secrets.push({ name: secretName(k), where: 'env', key: k, masked: mask(v) });
  for (const [k, v] of Object.entries(headers)) if ((/^authorization$/i.test(k) || SECRET_WORD.test(k)) && !v.startsWith('${')) secrets.push({ name: secretName(k), where: 'header', key: k, masked: mask(v) });
  // A credential in the endpoint's query (`?token=…`) is masked as well.
  let shownUrl = url;
  if (url) {
    try {
      const u = new URL(url);
      for (const [k, v] of u.searchParams) if (SECRET_WORD.test(k) && !v.startsWith('${')) { secrets.push({ name: secretName(k), where: 'query', key: k, masked: mask(v) }); u.searchParams.set(k, MASK); }
      shownUrl = u.toString().replace(encodeURIComponent(MASK), MASK);
    } catch { issues.push('地址无效'); }
  }
  // Two credentials with the same name (e.g. two `-s`) get a suffix.
  const seen = new Map<string, number>();
  for (const x of secrets) { const n = (seen.get(x.name) ?? 0) + 1; seen.set(x.name, n); if (n > 1) x.name = `${x.name}_${n}`; }
  let resolvedPath: string | null = null;
  if (protocol === 'mcp_stdio') {
    resolvedPath = resolveCommand(String(s.command), pathDirs);
    if (!resolvedPath) issues.push(`找不到命令 ${String(s.command)}：导入后在编辑中填写它的绝对路径`);
  } else if (!url) issues.push('没有命令也没有地址，无法导入');
  else if (transport === 'sse') issues.push('SSE 传输不受支持（只支持 stdio 与 streamable HTTP）');
  if (s.disabled === true) issues.push('在原工具中已停用');
  return {
    candidate: {
      id: `${source}:${name}`, source, sourceLabel: MCP_IMPORT_SOURCES[source].label, sourcePath, name, protocol,
      command: typeof s.command === 'string' ? s.command : null, resolvedPath, args: shownArgs, envKeys: Object.keys(env),
      url: shownUrl, headerKeys: Object.keys(headers), secrets, issues,
    },
    raw: { args, env, headers, url },
  };
}

function readServers(home: string): { source: McpImportSource; path: string; servers: Record<string, RawServer> }[] {
  const out: { source: McpImportSource; path: string; servers: Record<string, RawServer> }[] = [];
  for (const [source, def] of Object.entries(MCP_IMPORT_SOURCES) as [McpImportSource, (typeof MCP_IMPORT_SOURCES)[McpImportSource]][]) {
    const path = join(home, ...def.file);
    if (!existsSync(path)) continue;
    try {
      const d = JSON.parse(readFileSync(path, 'utf8')) as { mcpServers?: Record<string, RawServer> };
      if (d.mcpServers && typeof d.mcpServers === 'object') out.push({ source, path, servers: d.mcpServers });
    } catch { /* an unreadable file is skipped */ }
  }
  return out;
}

function parseAll(home: string, pathDirs: string[]): Parsed[] {
  return readServers(home).flatMap(({ source, path, servers }) => Object.entries(servers)
    .filter(([, s]) => s && typeof s === 'object').map(([name, s]) => parseServer(source, path, name, s, pathDirs)));
}

/** MCP servers configured in other tools on this machine, credentials masked. */
export function discoverMcpConfigs(opts: { home?: string; pathDirs?: string[] } = {}): McpImportCandidate[] {
  return parseAll(opts.home ?? homedir(), opts.pathDirs ?? []).map((p) => p.candidate);
}

export interface McpImportInput {
  candidate: string; name?: string;
  /** Per secret name: copy the value into the local secret store, leave it empty to fill in, or drop the argument. */
  secrets?: Record<string, 'import' | 'blank' | 'drop'>;
  /** Arguments appended after the imported ones (e.g. `-t` to choose tools). */
  extraArgs?: string[];
  home?: string; pathDirs?: string[];
}

/** Create a connector from a discovered configuration; the command still has to be confirmed and tested. */
export async function importMcpConfig(store: Store, pool: ConnectorPool, input: McpImportInput): Promise<ConnectorRow> {
  const found = parseAll(input.home ?? homedir(), input.pathDirs ?? []).find((p) => p.candidate.id === input.candidate);
  if (!found) throw new AppError('COMMON_NOT_FOUND', `MCP configuration ${input.candidate} not found`);
  const { candidate: c, raw } = found;
  if (c.protocol === 'mcp_stdio' && !c.resolvedPath) throw new AppError('COMMON_VALIDATION', `command ${c.command} not found; add the connector by hand with its absolute path`);
  if (c.protocol === 'mcp_http' && (!raw.url || c.issues.some((x) => x.startsWith('SSE')))) throw new AppError('COMMON_VALIDATION', c.issues.join('; ') || 'no url');
  const choice = (n: string) => input.secrets?.[n] ?? 'blank';
  const values: Record<string, string> = {};
  // Arguments: credentials become ${secret:…} (or are dropped with their flag).
  const args = [...raw.args];
  const drop = new Set<number>();
  const argHits = argSecrets(raw.args);
  c.secrets.filter((x) => x.where === 'arg').forEach((x, k) => {
    const hit = argHits[k]!;
    if (choice(x.name) === 'drop') {
      drop.add(hit.index);
      if (!/=/.test(raw.args[hit.index]!)) drop.add(hit.index - 1);
      return;
    }
    if (choice(x.name) === 'import') values[x.name] = hit.value;
    args[hit.index] = raw.args[hit.index]!.startsWith('-') && raw.args[hit.index]!.includes('=') ? `${hit.key}=\${secret:${x.name}}` : `\${secret:${x.name}}`;
  });
  const finalArgs = [...args.filter((_, i) => !drop.has(i)), ...(input.extraArgs ?? []).filter((a) => typeof a === 'string' && a.length)];
  const env = { ...raw.env };
  const headers = { ...raw.headers };
  let endpoint = raw.url;
  for (const x of c.secrets.filter((s) => s.where === 'query')) {
    const u = new URL(endpoint!);
    if (choice(x.name) === 'import') values[x.name] = u.searchParams.get(x.key) ?? '';
    if (choice(x.name) === 'drop') { u.searchParams.delete(x.key); endpoint = u.toString(); continue; }
    u.searchParams.set(x.key, `__SECRET_${x.name}__`);
    endpoint = u.toString().replace(`__SECRET_${x.name}__`, `\${secret:${x.name}}`);
  }
  for (const x of c.secrets.filter((s) => s.where === 'env' || s.where === 'header')) {
    const bag = x.where === 'env' ? env : headers;
    if (choice(x.name) === 'drop') { delete bag[x.key]; continue; }
    if (choice(x.name) === 'import') values[x.name] = bag[x.key]!;
    const bearer = x.where === 'header' && /^bearer\s+/i.test(bag[x.key]!);
    bag[x.key] = bearer ? `Bearer \${secret:${x.name}}` : `\${secret:${x.name}}`;
    if (bearer && values[x.name]) values[x.name] = values[x.name]!.replace(/^bearer\s+/i, '');
  }
  // A connector runs with a private HOME: package runners would download the server again on every start and
  // miss the 30 s initialize timeout; point them at this user's caches (measured 57 s → 2.7 s for lark-mcp).
  const runner = c.command ? c.command.split('/').at(-1)! : '';
  const home = input.home ?? homedir();
  if (['npx', 'npm', 'pnpm', 'bunx'].includes(runner) && !env.npm_config_cache) env.npm_config_cache = join(home, '.npm');
  if (runner === 'uvx' && !env.UV_CACHE_DIR) env.UV_CACHE_DIR = join(home, '.cache', 'uv');
  const name = (input.name ?? c.name).trim();
  const row = createConnector(store, {
    name, protocol: c.protocol,
    config: c.protocol === 'mcp_stdio'
      ? { command: { path: c.resolvedPath!, args: finalArgs, env } }
      : { url: endpoint!, ...(Object.keys(headers).length ? { headers } : {}) },
  });
  if (Object.keys(values).length) await setConnectorSecrets(store, pool, row.id, values);
  return row;
}

