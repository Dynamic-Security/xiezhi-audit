// Gateway authentication and request rewriting: deterministic, from the gateway's own
// configuration — Spring Cloud Gateway (routes, default filters, GlobalFilter / security config classes), Zuul (routes and
// pre filters), Kong declarative config (plugins), APISIX (route and global plugins), Nginx (`auth_request` / `auth_basic`
// / `auth_jwt`, `proxy_set_header`) and Kubernetes Ingress annotations. The result says, per route the gateway exposes,
// whether a request is authenticated before it is forwarded, by what, which identity headers the gateway sets or strips,
// and which upstream gets it. The engine turns it into gateway facts and uses it in the access-policy check.
import { parse as parseYaml, parseAllDocuments } from 'yaml';
import type { SnapshotView } from '../snapshot/view.js';

export type GatewayAuthKind = 'jwt' | 'oauth2' | 'key' | 'basic' | 'external' | 'custom' | 'off';
export interface GatewayAuth { kind: GatewayAuthKind; mechanism: string; site: { path: string; line: number } }
export interface GatewayRoute {
  /** The path the gateway exposes (`/api/order/**`). */
  pathTemplate: string;
  upstream: string | null;
  /** Leading path segments the gateway strips before forwarding (`StripPrefix=2`, Zuul / Kong prefix stripping). */
  stripPrefix: number;
  /** Route-level authentication; null = none at the route (the global one may still apply). */
  auth: GatewayAuth | null;
  /** Headers the gateway sets (`X-User-Id`) or removes before forwarding — identity it passes or strips. */
  setHeaders: string[];
  removeHeaders: string[];
  ruleId: string;
  site: { path: string; line: number };
}
export interface GatewayAuthReport {
  /** Authentication applied to every route (default filters, global filters, global plugins, server-level auth). */
  global: GatewayAuth[];
  routes: GatewayRoute[];
}

const MAX_FILE_BYTES = 512 * 1024;
const AUTH_NAME = /auth|jwt|token|oauth|login|sso|session|security|permission|acl|sign/i;

const lineOf = (text: string, needle: string): number => {
  const i = text.indexOf(needle);
  return i < 0 ? 1 : text.slice(0, i).split('\n').length;
};
const norm = (p: string) => `/${p.split('/').filter(Boolean).join('/')}`.replace(/\/\*$/, '/**');
const upstreamOf = (uri: string) => uri.replace(/^lb:\/\//, '').replace(/^[a-z]+:\/\//i, '').replace(/[:/].*$/, '') || null;
const get = (o: unknown, keys: string[]) => keys.reduce<unknown>((c, k) => (c && typeof c === 'object' ? (c as Record<string, unknown>)[k] : undefined), o);

/** Kind of a Spring Cloud Gateway filter / Zuul filter / class name by its name. */
function kindOfName(name: string): GatewayAuthKind {
  if (/tokenrelay|oauth2|oidc/i.test(name)) return 'oauth2';
  if (/jwt/i.test(name)) return 'jwt';
  if (/basic/i.test(name)) return 'basic';
  if (/apikey|api-key|key-auth|keyauth/i.test(name)) return 'key';
  return 'custom';
}

const KONG_AUTH: Record<string, GatewayAuthKind> = { jwt: 'jwt', 'key-auth': 'key', 'key-auth-enc': 'key', oauth2: 'oauth2', 'openid-connect': 'oauth2', 'basic-auth': 'basic', 'hmac-auth': 'key', 'ldap-auth': 'basic', 'ldap-auth-advanced': 'basic', 'jwt-signer': 'jwt' };
const APISIX_AUTH: Record<string, GatewayAuthKind> = { 'jwt-auth': 'jwt', 'key-auth': 'key', 'basic-auth': 'basic', 'openid-connect': 'oauth2', 'authz-keycloak': 'oauth2', 'authz-casdoor': 'oauth2', 'forward-auth': 'external', 'wolf-rbac': 'custom', 'hmac-auth': 'key', 'ldap-auth': 'basic', 'cas-auth': 'external' };

function headerArgs(filters: string[], name: RegExp): string[] {
  return filters.flatMap((f) => { const m = new RegExp(`^(?:${name.source})\\s*=\\s*([^,\\s]+)`, 'i').exec(f); return m ? [m[1]!] : []; });
}

function scg(d: unknown, text: string, path: string, out: GatewayAuthReport): boolean {
  const gw = get(d, ['spring', 'cloud', 'gateway']);
  if (!gw || typeof gw !== 'object') return false;
  const site = (needle: string) => ({ path, line: lineOf(text, needle) });
  const defaults = ((get(gw, ['default-filters']) ?? get(gw, ['defaultFilters'])) as unknown[] | undefined ?? []).map((f) => (typeof f === 'string' ? f : String((f as { name?: string }).name ?? '')));
  for (const f of defaults) {
    const name = f.split('=')[0]!.trim();
    if (AUTH_NAME.test(name) && !/^(Add|Set|Remove)Request/i.test(name)) out.global.push({ kind: kindOfName(name), mechanism: `Spring Cloud Gateway default-filters：${name}`, site: site(name) });
  }
  for (const r of (get(gw, ['routes']) as Record<string, unknown>[] | undefined) ?? []) {
    const filters = ((r.filters as unknown[] | undefined) ?? []).map((f) => (typeof f === 'string' ? f : `${String((f as { name?: string }).name ?? '')}=${Object.values(((f as { args?: Record<string, unknown> }).args) ?? {}).join(',')}`));
    const authF = filters.map((f) => f.split('=')[0]!.trim()).find((n) => AUTH_NAME.test(n) && !/^(Add|Set|Remove)Request/i.test(n));
    for (const p of ((r.predicates as unknown[] | undefined) ?? []).map(String)) {
      const m = /^Path\s*=\s*(.+)$/.exec(p);
      if (!m) continue;
      for (const pat of m[1]!.split(',')) {
        out.routes.push({
          pathTemplate: norm(pat.trim()), upstream: upstreamOf(String(r.uri ?? '')), stripPrefix: Number(/StripPrefix\s*=\s*(\d+)/.exec(filters.join(','))?.[1] ?? 0),
          auth: authF ? { kind: kindOfName(authF), mechanism: `Spring Cloud Gateway 路由过滤器：${authF}`, site: site(authF) } : null,
          setHeaders: headerArgs(filters, /AddRequestHeader|SetRequestHeader/), removeHeaders: headerArgs(filters, /RemoveRequestHeader/),
          ruleId: 'gateway.scg', site: site(pat.trim()),
        });
      }
    }
  }
  return true;
}

function zuul(d: unknown, text: string, path: string, out: GatewayAuthReport): boolean {
  const routes = get(d, ['zuul', 'routes']);
  if (!routes || typeof routes !== 'object') return false;
  const sensitive = get(d, ['zuul', 'sensitive-headers']) ?? get(d, ['zuul', 'sensitiveHeaders']);
  for (const [name, r] of Object.entries(routes as Record<string, Record<string, unknown>>)) {
    const pat = typeof r?.path === 'string' ? r.path : `/${name}/**`;
    out.routes.push({
      pathTemplate: norm(pat), upstream: r?.serviceId ? String(r.serviceId) : r?.url ? upstreamOf(String(r.url)) : name, auth: null, setHeaders: [],
      stripPrefix: r?.stripPrefix === false ? 0 : pat.replace(/\/\*\*?$/, '').split('/').filter(Boolean).length,
      removeHeaders: typeof sensitive === 'string' ? sensitive.split(',').map((s) => s.trim()).filter(Boolean) : [], ruleId: 'gateway.zuul', site: { path, line: lineOf(text, pat) },
    });
  }
  return true;
}

function kong(d: unknown, text: string, path: string, out: GatewayAuthReport): boolean {
  if (!d || typeof d !== 'object' || !('_format_version' in (d as object))) return false;
  const site = (needle: string) => ({ path, line: lineOf(text, needle) });
  const authOf = (plugins: unknown, where: string): GatewayAuth | null => {
    for (const p of (plugins as { name?: string; enabled?: boolean }[] | undefined) ?? []) {
      if (p?.enabled === false || !p.name) continue;
      const k = KONG_AUTH[p.name];
      if (k) return { kind: k, mechanism: `Kong 插件 ${p.name}（${where}）`, site: site(`name: ${p.name}`) };
    }
    return null;
  };
  const headersOf = (plugins: unknown) => {
    const t = ((plugins as { name?: string; config?: Record<string, unknown> }[] | undefined) ?? []).find((p) => p?.name === 'request-transformer');
    const names = (x: unknown) => ((x as string[] | undefined) ?? []).map((h) => String(h).split(':')[0]!.trim());
    return { set: [...names(get(t?.config, ['add', 'headers'])), ...names(get(t?.config, ['replace', 'headers']))], remove: names(get(t?.config, ['remove', 'headers'])) };
  };
  const doc = d as Record<string, unknown>;
  const g = authOf(doc.plugins, '全局');
  if (g) out.global.push(g);
  for (const s of (doc.services as Record<string, unknown>[] | undefined) ?? []) {
    const svcAuth = authOf(s.plugins, `服务 ${String(s.name ?? '')}`);
    const svc = s.host ? String(s.host) : s.url ? upstreamOf(String(s.url)) : String(s.name ?? '') || null;
    for (const r of (s.routes as Record<string, unknown>[] | undefined) ?? []) {
      const h = headersOf([...((s.plugins as unknown[]) ?? []), ...((r.plugins as unknown[]) ?? [])]);
      for (const p of (r.paths as string[] | undefined) ?? []) {
        out.routes.push({ pathTemplate: norm(`${p.replace(/\/$/, '')}/**`), upstream: svc, stripPrefix: r.strip_path === false ? 0 : p.split('/').filter(Boolean).length, auth: authOf(r.plugins, `路由 ${String(r.name ?? p)}`) ?? svcAuth, setHeaders: h.set, removeHeaders: h.remove, ruleId: 'gateway.kong', site: site(p) });
      }
    }
  }
  return true;
}

function apisix(d: unknown, text: string, path: string, out: GatewayAuthReport): boolean {
  const routes = get(d, ['routes']);
  const globals = get(d, ['global_rules']);
  if (!Array.isArray(routes) && !Array.isArray(globals)) return false;
  const site = (needle: string) => ({ path, line: lineOf(text, needle) });
  const authOf = (plugins: unknown, where: string): GatewayAuth | null => {
    for (const name of Object.keys((plugins as Record<string, unknown> | undefined) ?? {})) {
      const k = APISIX_AUTH[name];
      if (k) return { kind: k, mechanism: `APISIX 插件 ${name}（${where}）`, site: site(name) };
    }
    return null;
  };
  for (const g of (globals as Record<string, unknown>[] | undefined) ?? []) { const a = authOf(g.plugins, '全局规则'); if (a) out.global.push(a); }
  for (const r of (routes as Record<string, unknown>[] | undefined) ?? []) {
    const nodes = get(r, ['upstream', 'nodes']);
    const host = nodes && typeof nodes === 'object' ? upstreamOf(Array.isArray(nodes) ? String((nodes[0] as Record<string, unknown>)?.host ?? '') : Object.keys(nodes)[0] ?? '') : (r.service_id ?? r.upstream_id) ? String(r.service_id ?? r.upstream_id) : null;
    const rw = get(r, ['plugins', 'proxy-rewrite', 'headers']) as Record<string, unknown> | undefined;
    const set = rw ? Object.keys((rw.set as object | undefined) ?? (rw.add as object | undefined) ?? (Array.isArray(rw) ? {} : rw)).filter((k) => !['set', 'add', 'remove'].includes(k)) : [];
    const remove = rw && Array.isArray(rw.remove) ? (rw.remove as string[]) : [];
    const uris = [r.uri, ...((r.uris as unknown[] | undefined) ?? [])].filter((x): x is string => typeof x === 'string');
    for (const u of uris) out.routes.push({ pathTemplate: norm(u.replace(/\*$/, '**')), upstream: host, stripPrefix: 0, auth: authOf(r.plugins, `路由 ${String(r.name ?? r.id ?? u)}`), setHeaders: set, removeHeaders: remove, ruleId: 'gateway.apisix', site: site(u) });
  }
  return true;
}

function ingress(text: string, path: string, out: GatewayAuthReport): boolean {
  let found = false;
  for (const docu of parseAllDocuments(text)) {
    const d = docu.toJSON() as Record<string, unknown> | null;
    if (!d || d.kind !== 'Ingress') continue;
    found = true;
    const ann = (get(d, ['metadata', 'annotations']) as Record<string, string> | undefined) ?? {};
    let auth: GatewayAuth | null = null;
    const at = (key: string) => ({ path, line: lineOf(text, key) });
    if (ann['nginx.ingress.kubernetes.io/auth-url']) auth = { kind: 'external', mechanism: `Ingress 外部鉴权 auth-url=${ann['nginx.ingress.kubernetes.io/auth-url']}`, site: at('auth-url') };
    else if (ann['nginx.ingress.kubernetes.io/auth-type']) auth = { kind: 'basic', mechanism: `Ingress auth-type=${ann['nginx.ingress.kubernetes.io/auth-type']}`, site: at('auth-type') };
    else if (ann['konghq.com/plugins'] && /auth|jwt|oauth|oidc|key/i.test(ann['konghq.com/plugins'])) auth = { kind: kindOfName(ann['konghq.com/plugins']), mechanism: `Ingress Kong 插件 ${ann['konghq.com/plugins']}`, site: at('konghq.com/plugins') };
    else if (ann['traefik.ingress.kubernetes.io/router.middlewares'] && AUTH_NAME.test(ann['traefik.ingress.kubernetes.io/router.middlewares'])) auth = { kind: 'custom', mechanism: `Ingress Traefik 中间件 ${ann['traefik.ingress.kubernetes.io/router.middlewares']}`, site: at('router.middlewares') };
    const setHeaders = (ann['nginx.ingress.kubernetes.io/auth-response-headers'] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    for (const rule of (get(d, ['spec', 'rules']) as Record<string, unknown>[] | undefined) ?? []) {
      for (const p of (get(rule, ['http', 'paths']) as Record<string, unknown>[] | undefined) ?? []) {
        const svc = (get(p, ['backend', 'service', 'name']) ?? get(p, ['backend', 'serviceName'])) as string | undefined;
        const pp = String(p.path ?? '/');
        out.routes.push({ pathTemplate: norm(`${pp.replace(/\(.*$/, '').replace(/\/$/, '')}/**`), upstream: svc ?? null, stripPrefix: 0, auth, setHeaders, removeHeaders: [], ruleId: 'gateway.ingress', site: at(pp) });
      }
    }
  }
  return found;
}

function nginx(text: string, path: string, out: GatewayAuthReport): void {
  const clean = text.replace(/#[^\n]*/g, '');
  const authIn = (block: string, where: string, line: number): GatewayAuth | null | 'off' => {
    if (/\bauth_request\s+off\s*;/.test(block) || /\bauth_basic\s+off\s*;/.test(block)) return 'off';
    const ar = /\bauth_request\s+([^;\s]+)\s*;/.exec(block);
    if (ar) return { kind: 'external', mechanism: `Nginx auth_request ${ar[1]}（${where}）`, site: { path, line } };
    const jwt = /\bauth_jwt\s+[^;]+;/.exec(block);
    if (jwt) return { kind: 'jwt', mechanism: `Nginx auth_jwt（${where}）`, site: { path, line } };
    const basic = /\bauth_basic\s+[^;]+;/.exec(block);
    if (basic) return { kind: 'basic', mechanism: `Nginx auth_basic（${where}）`, site: { path, line } };
    return null;
  };
  // Server-level directives (outside location blocks) apply to every location without its own setting.
  const outside = clean.replace(/\blocation\s+[^{]*\{[^{}]*\}/g, '');
  const serverAuth = authIn(outside, 'server', lineOf(text, 'auth_'));
  if (serverAuth && serverAuth !== 'off') out.global.push(serverAuth);
  for (const m of clean.matchAll(/\blocation\s+(?:[=~^*]+\s*)?([^\s{]+)\s*\{([^{}]*)\}/g)) {
    const pp = /\bproxy_pass\s+([^;\s]+)\s*;/.exec(m[2]!);
    if (!pp) continue;
    const line = lineOf(text, `location ${m[1]}`);
    const a = authIn(m[2]!, `location ${m[1]}`, line);
    const setHeaders = [...m[2]!.matchAll(/\bproxy_set_header\s+([\w-]+)\s+([^;]+);/g)].filter((h) => !/^\s*""\s*$/.test(h[2]!)).map((h) => h[1]!);
    const removeHeaders = [...m[2]!.matchAll(/\bproxy_set_header\s+([\w-]+)\s+""\s*;/g)].map((h) => h[1]!);
    out.routes.push({
      pathTemplate: norm(`${m[1]!.replace(/\/$/, '')}/**`), upstream: upstreamOf(pp[1]!),
      // `proxy_pass http://up/` (with a path) replaces the location prefix.
      stripPrefix: /^[a-z]+:\/\/[^/]+\/./i.test(pp[1]!) || /^[a-z]+:\/\/[^/]+\/$/i.test(pp[1]!) ? m[1]!.split('/').filter(Boolean).length : 0,
      auth: a === 'off' ? { kind: 'off', mechanism: `Nginx 在 location ${m[1]} 关闭了鉴权`, site: { path, line } } : a, setHeaders, removeHeaders, ruleId: 'gateway.nginx', site: { path, line },
    });
  }
}

/** Java classes of a Spring Cloud Gateway / Zuul / WebFlux security setup that authenticate every request. */
function javaGlobal(text: string, path: string, out: GatewayAuthReport): void {
  const cls = /class\s+(\w+)/.exec(text)?.[1] ?? path;
  if (/implements\s+[\w<>,\s]*\bGlobalFilter\b/.test(text) && AUTH_NAME.test(cls)) out.global.push({ kind: kindOfName(cls), mechanism: `Spring Cloud Gateway 全局过滤器 ${cls}`, site: { path, line: lineOf(text, 'GlobalFilter') } });
  else if (/extends\s+ZuulFilter\b/.test(text) && /"pre"|FilterConstants\.PRE_TYPE/.test(text) && AUTH_NAME.test(cls)) out.global.push({ kind: kindOfName(cls), mechanism: `Zuul 前置过滤器 ${cls}`, site: { path, line: lineOf(text, 'ZuulFilter') } });
  else if (/SecurityWebFilterChain/.test(text) && /\.authenticated\(\)|anyExchange\(\)\.authenticated|oauth2ResourceServer/.test(text)) out.global.push({ kind: /oauth2ResourceServer|jwt\(/.test(text) ? 'jwt' : 'custom', mechanism: `Spring WebFlux 安全配置 ${cls}（anyExchange().authenticated()）`, site: { path, line: lineOf(text, 'SecurityWebFilterChain') } });
}

/** Read the gateway configuration of a repository snapshot. */
export function extractGatewayAuth(view: SnapshotView): GatewayAuthReport {
  const out: GatewayAuthReport = { global: [], routes: [] };
  for (const f of view.listFiles()) {
    if (f.size > MAX_FILE_BYTES || f.path.includes('node_modules/')) continue;
    const base = f.path.split('/').pop()!.toLowerCase();
    const isYaml = /\.ya?ml$/.test(base);
    const isConf = base.endsWith('.conf');
    const isJava = base.endsWith('.java') || base.endsWith('.kt');
    const isProps = base.endsWith('.properties');
    if (!isYaml && !isConf && !isJava && !isProps && !base.endsWith('.json')) continue;
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    if (isJava) {
      if (/GlobalFilter|ZuulFilter|SecurityWebFilterChain/.test(text)) javaGlobal(text, f.path, out);
      continue;
    }
    if (isConf) { if (/\bproxy_pass\b/.test(text)) nginx(text, f.path, out); continue; }
    if (isProps) {
      // spring.cloud.gateway.default-filters[n]=Name / routes[n].filters[m]=Name
      for (const m of text.matchAll(/^spring\.cloud\.gateway\.default-filters\[\d+\]\s*=\s*([^\s,=]+)/gm)) {
        if (AUTH_NAME.test(m[1]!)) out.global.push({ kind: kindOfName(m[1]!), mechanism: `Spring Cloud Gateway default-filters：${m[1]}`, site: { path: f.path, line: lineOf(text, m[0]) } });
      }
      continue;
    }
    if (isYaml && /\bkind:\s*Ingress\b/.test(text)) { try { if (ingress(text, f.path, out)) continue; } catch { /* not YAML we read */ } }
    let d: unknown;
    try { d = base.endsWith('.json') ? JSON.parse(text) : parseYaml(text); } catch { continue; }
    if (scg(d, text, f.path, out) || zuul(d, text, f.path, out) || kong(d, text, f.path, out)) continue;
    apisix(d, text, f.path, out);
  }
  return out;
}

/**
 * Whether a request to `path` (as the gateway exposes it) is authenticated before it is forwarded: the most specific
 * route wins; a route without its own auth inherits the global one unless it turned auth off.
 */
export function gatewayAuthFor(report: GatewayAuthReport, path: string): { route: GatewayRoute | null; auth: GatewayAuth | null } {
  const p = path.replace(/\/+$/, '') || '/';
  const matches = report.routes.filter((r) => {
    const base = r.pathTemplate.replace(/\/\*\*$/, '');
    return p === base || p.startsWith(`${base}/`) || base === '' || r.pathTemplate === '/**';
  }).sort((a, b) => b.pathTemplate.length - a.pathTemplate.length);
  const route = matches[0] ?? null;
  if (route?.auth?.kind === 'off') return { route, auth: null };
  return { route, auth: route?.auth ?? (route ? report.global[0] ?? null : null) };
}
