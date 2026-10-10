// cross_repo_trace: from a caller site (or a route / provider) find the peer across
// repositories via matched connection points, and return bounded snippets — the handler, its route
// middleware and auth signals, the gateway route in between, the contract definition. Snippets do not
// count as reading coverage; the agent reads full context with `read` before concluding.
import type { Connection, ConnectionMatch, StructIndex } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';
import { comparePaths } from './match.js';

export const TRACE_SNIPPET_LINES = 200;
const MAX_PEERS = 5;

export interface CrossRepoData {
  connections: Connection[];
  matches: ConnectionMatch[];
  indexes: ReadonlyMap<string, StructIndex>;
  /** User-declared topology edges between repositories (no code evidence). */
  userEdges: { from: string; to: string; kind: string; protocol: string }[];
  /** Repositories whose connection points were cut at the file limit. */
  limits?: { repo: string; limit: number; skipped: number; firstSkipped: string }[];
}

export interface TraceInput { repo?: string; path?: string; line?: number; method?: string; pathTemplate?: string; direction?: 'callee' | 'caller' }

export interface TraceSnippet { repo: string; path: string; startLine: number; endLine: number; text: string; why: string }
export interface TracePeer { repo: string; confidence: string; via: string; connection: string; snippets: TraceSnippet[]; authSignals: string[] }
export interface TraceResult {
  start: string[];
  peers: TracePeer[];
  unresolved?: { reason: string; missing: string[] };
  userEdges: string[];
  /** Connection points of these repositories are incomplete: a missing peer is not evidence of no call. */
  incomplete?: string[];
}

function describe(c: Connection): string {
  const k = c.key;
  const what = k.pathTemplate ? `${k.method ?? '*'} ${k.pathTemplate}` : k.topic ? `topic ${k.topic}` : k.service ? `service ${k.service}${k.rpc ? `/${k.rpc}` : ''}` : k.interface ? `interface ${k.interface}` : k.module ?? '';
  return `${c.repo} ${c.side} ${c.kind} ${what}${c.serviceHint ? ` (→ ${c.serviceHint})` : ''} @ ${c.site.path || '(build file)'}${c.site.line ? `:${c.site.line}` : ''}`;
}

function snippet(views: ReadonlyMap<string, SnapshotView>, repo: string, path: string, from: number, to: number, why: string): TraceSnippet | null {
  const v = views.get(repo);
  if (!v || !path || !v.hasFile(path) || v.isExcluded(path)) return null;
  const lines = v.lines(path);
  const start = Math.max(1, from);
  const end = Math.min(lines.length, to, start + TRACE_SNIPPET_LINES - 1);
  if (end < start) return null;
  return { repo, path, startLine: start, endLine: end, text: lines.slice(start - 1, end).map((l, i) => `${String(start + i).padStart(5)}  ${l}`).join('\n'), why };
}

/** Snippets that show how a provider handles the call. */
function providerSnippets(views: ReadonlyMap<string, SnapshotView>, data: CrossRepoData, p: Connection): { snippets: TraceSnippet[]; auth: string[] } {
  const out: TraceSnippet[] = [];
  const auth: string[] = [];
  const idx = data.indexes.get(p.repo);
  if (p.ruleId.startsWith('index.') && idx) {
    const e = idx.entrypoints.find((x) => x.path === p.site.path && x.range.startLine === p.site.line);
    if (e) {
      const sym = idx.symbols.find((s) => s.symbolId === e.handler || (s.path === e.path && s.range.startLine <= e.range.startLine && s.range.endLine >= e.range.endLine && s.kind !== 'class'));
      const range = sym ? sym.range : e.range;
      const s = snippet(views, p.repo, e.path, range.startLine - 3, range.endLine + 1, `handler ${e.handler} of ${e.entryKey}`);
      if (s) out.push(s);
      auth.push(...e.middlewares.map((m) => `middleware ${m}`), ...e.authSignals.map((a) => `auth ${a}`));
      for (const a of idx.authSignals) if (a.kind === 'filter' || a.kind === 'security_config' || a.kind === 'interceptor') auth.push(`${a.kind} ${a.target}: ${a.detail}`.slice(0, 200));
    }
  } else if (p.ruleId.startsWith('gateway.')) {
    const s = snippet(views, p.repo, p.site.path, 1, TRACE_SNIPPET_LINES, 'gateway route configuration');
    if (s) out.push(s);
    // Gateway-wide auth lives in filters / security config: include the first few as
    // bounded snippets so the chain's auth can be judged without guessing; list the rest.
    const v = views.get(p.repo);
    const filters = (v?.listFiles() ?? []).filter((f) => /(Filter|Auth|Security|Interceptor|Guard)[^/]*\.(java|go|kt|ts|js|lua|py|php|cs)$/.test(f.path));
    filters.forEach((f, i) => {
      const sn = i < 3 ? snippet(views, p.repo, f.path, 1, 120, 'gateway filter / auth code') : null;
      if (sn) out.push(sn);
      else auth.push(`gateway file ${f.path}`);
    });
    if (filters.length) auth.push(`gateway auth files: ${filters.map((f) => f.path).join(', ')}`);
  } else {
    const line = p.site.line || 1;
    const s = snippet(views, p.repo, p.site.path, line - 10, line + 30, `${p.ruleId} definition`);
    if (s) out.push(s);
  }
  return { snippets: out, auth: [...new Set(auth)].slice(0, 30) };
}

export function crossRepoTrace(views: ReadonlyMap<string, SnapshotView>, defaultRepo: string, data: CrossRepoData, input: TraceInput): TraceResult {
  const repo = input.repo ?? defaultRepo;
  const direction = input.direction ?? 'callee';
  const byId = new Map(data.connections.map((c) => [c.connId, c]));
  const side = direction === 'callee' ? 'consumes' : 'provides';
  let starts = data.connections.filter((c) => c.repo === repo && c.side === side && c.kind !== 'shared_lib');
  if (input.path) starts = starts.filter((c) => c.site.path === input.path && (input.line === undefined || Math.abs(c.site.line - input.line) <= 6));
  if (input.pathTemplate) starts = starts.filter((c) => c.key.pathTemplate && comparePaths(input.pathTemplate!, c.key.pathTemplate) !== null && (!input.method || !c.key.method || c.key.method === input.method.toUpperCase()));
  if (!input.path && !input.pathTemplate) starts = starts.slice(0, 20);
  const userEdges = data.userEdges.filter((e) => e.from === repo || e.to === repo).map((e) => `${e.from} → ${e.to}（${e.kind}/${e.protocol}，用户声明，无代码证据）`);
  const incomplete = data.limits?.length
    ? { incomplete: data.limits.map((l) => `${l.repo}: connection points from the first ${l.limit} files only; ${l.skipped} files not read (from ${l.firstSkipped})`) }
    : {};
  if (!starts.length) {
    return {
      start: [], peers: [], userEdges, ...incomplete,
      unresolved: { reason: `no ${side === 'consumes' ? 'outgoing call' : 'provided route'} recognized in ${repo}${input.path ? ` at ${input.path}${input.line ? `:${input.line}` : ''}` : ''}${input.pathTemplate ? ` for ${input.pathTemplate}` : ''}`, missing: [] },
    };
  }
  const peers: TracePeer[] = [];
  const missing = new Set<string>();
  for (const s of starts) {
    const ms = direction === 'callee' ? data.matches.filter((m) => m.consumer === s.connId) : data.matches.filter((m) => m.provider === s.connId);
    if (direction === 'callee' && ms.every((m) => !m.provider && !m.providerRepo)) missing.add(s.serviceHint ?? `provider of ${s.key.method ?? ''} ${s.key.pathTemplate ?? s.key.service ?? s.key.interface ?? ''}`.trim());
    for (const m of ms) {
      if (peers.length >= MAX_PEERS) break;
      if (direction === 'caller') {
        const c = byId.get(m.consumer);
        if (!c) continue;
        const sn = snippet(views, c.repo, c.site.path, c.site.line - 10, c.site.line + 10, `caller (${c.ruleId})`);
        peers.push({ repo: c.repo, confidence: m.confidence, via: m.reason, connection: describe(c), snippets: sn ? [sn] : [], authSignals: [] });
        continue;
      }
      const p = m.provider ? byId.get(m.provider) ?? null : null;
      if (!p) {
        if (m.providerRepo) peers.push({ repo: m.providerRepo, confidence: m.confidence, via: m.reason, connection: `repository ${m.providerRepo} (no matching route recognized)`, snippets: [], authSignals: [] });
        continue;
      }
      const main = providerSnippets(views, data, p);
      // Through a gateway: follow its route to the upstream service as well.
      if (p.ruleId.endsWith('.expose')) {
        const routes = data.connections.filter((r) => r.repo === p.repo && r.kind === 'gateway_route' && r.key.pathTemplate === p.key.pathTemplate);
        for (const r of routes) {
          for (const up of data.matches.filter((x) => x.consumer === r.connId)) {
            const target = up.provider ? byId.get(up.provider) : null;
            const upstream = target ? providerSnippets(views, data, target) : { snippets: [], auth: [] };
            peers.push({
              repo: `${p.repo} → ${target?.repo ?? up.providerRepo ?? r.serviceHint ?? '?'}`, confidence: m.confidence === 'confirmed' && up.confidence === 'confirmed' ? 'confirmed' : 'inferred',
              via: `${m.reason}; ${up.reason}`, connection: `${describe(p)} ⇒ ${target ? describe(target) : r.serviceHint ?? ''}`,
              snippets: [...main.snippets, ...upstream.snippets], authSignals: [...main.auth, ...upstream.auth],
            });
            if (!target && !up.providerRepo && r.serviceHint) missing.add(r.serviceHint);
          }
          if (!data.matches.some((x) => x.consumer === r.connId) && r.serviceHint) missing.add(r.serviceHint);
        }
        if (!routes.length) peers.push({ repo: p.repo, confidence: m.confidence, via: m.reason, connection: describe(p), snippets: main.snippets, authSignals: main.auth });
        continue;
      }
      peers.push({ repo: p.repo, confidence: m.confidence, via: m.reason, connection: describe(p), snippets: main.snippets, authSignals: main.auth });
    }
  }
  return {
    start: starts.map(describe), peers, userEdges, ...incomplete,
    ...(peers.length === 0 || missing.size ? { unresolved: { reason: peers.length ? 'part of the chain leaves the project' : 'the peer is not in this audit / project', missing: [...missing] } } : {}),
  };
}
