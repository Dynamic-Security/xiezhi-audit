// Connection matching: path template normalization, service → repository mapping with
// its source, and pairing consumers with providers as `confirmed` or `inferred`. Consumers nobody in
// the project provides stay unmatched (provider null): they become external services in the topology.
import type { Connection, ConnectionMatch, ServiceMapping } from '@xiezhi/contracts';

/** `{id}`, `:id`, `<id>`, `*` → `{}`; `**` → `{**}`; unknown parts keep `{?}`; host, query, doubled and trailing `/` removed. */
export function normalizePath(p: string): string {
  // `{?}` (unknown part) must survive stripping the query string.
  const MARK = '\u0001';
  let s = p.split('{?}').join(MARK).replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '').split(/[?#]/)[0]!.split(MARK).join('{?}');
  s = s.replace(/\$\{[^}]*\}/g, '{?}');
  const segs = s.split('/').filter(Boolean).map((seg) => {
    if (seg === '**') return '{**}';
    if (seg === '{?}') return '{?}';
    if (seg.includes('{?}')) return '{?}';
    if (/^\{[^}]*\}$/.test(seg) || /^:[\w]+$/.test(seg) || /^<[^>]+>$/.test(seg) || seg === '*') return '{}';
    return seg;
  });
  return `/${segs.join('/')}`;
}

type Strength = 'exact' | 'weak' | null;

/** Compare a consumer path with a provider template (a provider ending in `{**}` matches any longer path). */
export function comparePaths(consumer: string, provider: string): Strength {
  const c = normalizePath(consumer).split('/').filter(Boolean);
  const p = normalizePath(provider).split('/').filter(Boolean);
  const prefix = p[p.length - 1] === '{**}';
  const body = prefix ? p.slice(0, -1) : p;
  if (prefix ? c.length < body.length : c.length !== body.length) {
    // A consumer path with an unknown tail (`/api/{?}`) may still hit a longer provider: weak.
    if (c[c.length - 1] === '{?}' && c.length <= body.length && c.slice(0, -1).every((x, i) => x === body[i] || x === '{?}')) return 'weak';
    return null;
  }
  let weak = false;
  for (let i = 0; i < body.length; i++) {
    const a = c[i]!;
    const b = body[i]!;
    if (a === b) continue;
    if (a === '{?}' || b === '{?}') { weak = true; continue; }
    if (b === '{}' && a !== '{}') continue; // concrete value in a template slot
    if (a === '{}' && b !== '{}') { weak = true; continue; }
    return null;
  }
  return weak ? 'weak' : 'exact';
}

const stripSuffix = (n: string) => n.toLowerCase().replace(/[-_.](service|svc|server|api|app|backend|web)$/, '').replace(/[^a-z0-9]/g, '');

export interface RepoNames { repo: string; appNames: string[] }

/**
 * Map a service hint (Feign name, upstream, URL host) to a repository. Priority: user > imported >
 * application name > repository name similarity.
 */
export function resolveService(hint: string, repos: RepoNames[], explicit: ServiceMapping[] = []): ServiceMapping | null {
  const h = hint.toLowerCase();
  for (const src of ['user', 'imported'] as const) {
    const m = explicit.find((x) => x.source === src && x.service.toLowerCase() === h);
    if (m) return m;
  }
  const byApp = repos.filter((r) => r.appNames.some((a) => a.toLowerCase() === h));
  if (byApp.length === 1) return { service: hint, repo: byApp[0]!.repo, source: 'app_name' };
  const hs = stripSuffix(h);
  if (!hs) return null;
  const byName = repos.filter((r) => [r.repo, ...r.appNames].some((n) => stripSuffix(n) === hs));
  if (byName.length === 1) return { service: hint, repo: byName[0]!.repo, source: 'repo_name' };
  return null;
}

export interface MatchResult { matches: ConnectionMatch[]; mappings: ServiceMapping[] }

export function matchConnections(conns: Connection[], repos: RepoNames[], explicit: ServiceMapping[] = []): MatchResult {
  const matches: ConnectionMatch[] = [];
  const mappings = new Map<string, ServiceMapping>();
  const resolve = (hint: string | undefined): ServiceMapping | null => {
    if (!hint) return null;
    const m = resolveService(hint, repos, explicit);
    if (m) mappings.set(m.service.toLowerCase(), m);
    return m;
  };
  const provides = conns.filter((c) => c.side === 'provides');
  const strongSource = (m: ServiceMapping | null) => !!m && m.source !== 'repo_name';
  const add = (c: Connection, provider: Connection | null, providerRepo: string | null, confidence: ConnectionMatch['confidence'], reason: string) =>
    matches.push({ consumer: c.connId, provider: provider?.connId ?? null, providerRepo: provider?.repo ?? providerRepo, confidence, reason });

  for (const c of conns) {
    if (c.side !== 'consumes') continue;
    switch (c.kind) {
      case 'http': {
        const target = resolve(c.serviceHint);
        const cands = provides.filter((p) => p.kind === 'http' && p.repo !== c.repo && (!target || p.repo === target.repo));
        let hits = cands
          .map((p) => ({ p, s: comparePaths(c.key.pathTemplate ?? '/', p.key.pathTemplate ?? '/'), m: !c.key.method || !p.key.method || c.key.method === p.key.method }))
          .filter((x) => x.s && x.m);
        // A call without a host that a gateway route exposes goes through the gateway, not straight to the service.
        if (!c.serviceHint && hits.some((h) => h.p.ruleId.endsWith('.expose'))) hits = hits.filter((h) => h.p.ruleId.endsWith('.expose'));
        // The most specific route wins: `/api/user/me` does not also call `/api/user/{id}`.
        if (hits.length > 1) {
          const spec = (tpl: string) => normalizePath(tpl).split('/').filter((x) => x && !x.startsWith('{')).length;
          const best = Math.max(...hits.filter((h) => h.s === 'exact').map((h) => spec(h.p.key.pathTemplate ?? '/')), -1);
          if (best >= 0) hits = hits.filter((h) => h.s !== 'exact' || spec(h.p.key.pathTemplate ?? '/') === best);
        }
        if (!hits.length) {
          add(c, null, target?.repo ?? null, target ? (strongSource(target) ? 'confirmed' : 'inferred') : 'inferred', target ? `service ${c.serviceHint} → ${target.repo} (${target.source}); no matching route` : 'no provider in the project');
          break;
        }
        const repoCount = new Set(hits.map((h) => h.p.repo)).size;
        for (const h of hits) {
          const exact = h.s === 'exact' && !!c.key.method && !!h.p.key.method && c.extraction !== 'partial';
          const unique = repoCount === 1;
          const conf = exact && unique && (!c.serviceHint || strongSource(target)) ? 'confirmed' : 'inferred';
          add(c, h.p, null, conf, `${h.s} path match${target ? ` via ${target.source}` : ''}${unique ? '' : '; several providers'}`);
        }
        break;
      }
      case 'gateway_route': {
        const target = resolve(c.serviceHint);
        if (!target) { add(c, null, null, 'inferred', `upstream ${c.serviceHint ?? '?'} not in the project`); break; }
        const segs = normalizePath(c.key.pathTemplate ?? '/').split('/').filter(Boolean);
        const forwarded = `/${segs.slice(c.key.stripPrefix ?? 0).join('/')}`;
        const hits = provides.filter((p) => p.kind === 'http' && p.repo === target.repo && comparePaths(p.key.pathTemplate ?? '/', forwarded) !== null);
        const conf = strongSource(target) ? 'confirmed' : 'inferred';
        if (!hits.length) add(c, null, target.repo, conf, `upstream ${c.serviceHint} → ${target.repo} (${target.source})`);
        for (const h of hits) add(c, h, null, conf, `route ${c.key.pathTemplate} → ${target.repo}${h.key.pathTemplate} (${target.source})`);
        break;
      }
      case 'grpc': {
        const svc = (c.key.service ?? '').split('.').pop()!;
        const hits = provides.filter((p) => p.kind === 'grpc' && p.repo !== c.repo && (p.key.service ?? '').split('.').pop() === svc);
        if (!hits.length) add(c, null, null, 'inferred', `gRPC ${svc} not provided in the project`);
        const repoCount = new Set(hits.map((h) => h.repo)).size;
        for (const h of hits) add(c, h, null, repoCount === 1 ? 'confirmed' : 'inferred', `gRPC service ${svc}`);
        break;
      }
      case 'dubbo': {
        const hits = provides.filter((p) => p.kind === 'dubbo' && p.repo !== c.repo && p.key.interface === c.key.interface);
        if (!hits.length) add(c, null, null, 'inferred', `Dubbo ${c.key.interface} not provided in the project`);
        for (const h of hits) add(c, h, null, hits.length === 1 ? 'confirmed' : 'inferred', `Dubbo interface ${c.key.interface}`);
        break;
      }
      case 'mq': {
        // Messages flow producer → consumer: the listener consumes the producer's topic.
        const hits = provides.filter((p) => p.kind === 'mq' && p.repo !== c.repo && p.key.topic === c.key.topic);
        for (const h of hits) add(c, h, null, c.extraction === 'partial' ? 'inferred' : 'confirmed', `topic ${c.key.topic}`);
        break;
      }
      case 'shared_lib': {
        // Only dependencies on modules of this project count; external libraries are not topology.
        const hits = provides.filter((p) => p.kind === 'shared_lib' && p.repo !== c.repo && p.key.module === c.key.module);
        for (const h of hits) add(c, h, null, 'confirmed', `depends on ${c.key.module}`);
        break;
      }
    }
  }
  return { matches, mappings: [...mappings.values()] };
}
