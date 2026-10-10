// Gateway authentication in the audit (37): the gateways' own configuration — read deterministically
// from the latest snapshot of every repository of the project — says which routes are authenticated before they reach a
// service. That gives the entry-exposure map (per service entry: the gateway routes that reach it and whether each
// authenticates), the gateway facts of the project (`gateway_config`, verified), and the access-policy check: an entry
// that every reaching route authenticates no longer raises an authentication difference; one reachable by a route
// without authentication says which route.
import { join } from 'node:path';
import type { EntryPoint, SnapshotManifest } from '@xiezhi/contracts';
import { SnapshotView, extractGatewayAuth, type GatewayAuth, type GatewayAuthReport, type GatewayRoute } from '@xiezhi/context';
import type { Store } from '@xiezhi/store';
import { addFact, type FactRow } from './facts.js';

export interface GatewayReport { gateway: string; repositoryId: string; rootHash: string; report: GatewayAuthReport }

const cache = new Map<string, GatewayAuthReport>();

/** Gateway reports of the project's repositories (latest snapshot each; repositories without gateway config are left out). */
export function projectGateways(store: Store, projectId: string, views?: ReadonlyMap<string, SnapshotView>): GatewayReport[] {
  const repos = store.all<{ id: string; name: string }>('SELECT id, name FROM repository WHERE project_id = ? AND removed_at IS NULL ORDER BY name', projectId);
  const out: GatewayReport[] = [];
  for (const r of repos) {
    let view = views?.get(r.name);
    if (!view) {
      const snap = store.get<{ root_hash: string; manifest_ref: string }>('SELECT root_hash, manifest_ref FROM snapshot WHERE repository_id = ? ORDER BY created_at DESC LIMIT 1', r.id);
      if (!snap) continue;
      try { view = new SnapshotView(r.name, join(store.paths.snapshots, snap.root_hash), store.artifacts.getJson<SnapshotManifest>(snap.manifest_ref)); } catch { continue; }
    }
    const key = view.rootHash;
    let report = cache.get(key);
    if (!report) {
      try { report = extractGatewayAuth(view); } catch { continue; }
      cache.set(key, report);
    }
    if (report.routes.length || report.global.length) out.push({ gateway: r.name, repositoryId: r.id, rootHash: key, report });
  }
  return out;
}

/** Names a service is known by: the repository name and the topology service nodes bound to it. */
export function serviceNames(store: Store, projectId: string, repo: string): Set<string> {
  const names = new Set([repo.toLowerCase()]);
  for (const n of store.all<{ name: string }>(
    `SELECT n.name FROM topology_node n JOIN repository r ON r.id = n.repository_id WHERE n.project_id = ? AND r.name = ?`, projectId, repo)) names.add(n.name.toLowerCase());
  return names;
}

export interface ExposureRoute { gateway: string; pathTemplate: string; upstreamBase: string; auth: GatewayAuth | null; setHeaders: string[] }
export interface EntryExposure { routes: ExposureRoute[]; covered: boolean; open: ExposureRoute[] }

const segs = (p: string) => p.replace(/\/\*\*$/, '').split('/').filter(Boolean);

/** The gateway routes that forward to `entryPath` of a service, and whether all of them authenticate. */
export function entryExposure(gateways: GatewayReport[], names: Set<string>, entryPath: string): EntryExposure {
  const routes: ExposureRoute[] = [];
  const path = `/${segs(entryPath).join('/')}`;
  for (const g of gateways) {
    for (const r of g.report.routes) {
      if (!r.upstream || !names.has(r.upstream.toLowerCase())) continue;
      const upstreamBase = `/${segs(r.pathTemplate).slice(r.stripPrefix).join('/')}`;
      const reaches = upstreamBase === '/' || path === upstreamBase || path.startsWith(`${upstreamBase}/`) || path.replace(/\{[^}]*\}/g, 'x').startsWith(`${upstreamBase}/`);
      if (!reaches) continue;
      const auth = r.auth?.kind === 'off' ? null : r.auth ?? g.report.global[0] ?? null;
      routes.push({ gateway: g.gateway, pathTemplate: r.pathTemplate, upstreamBase, auth, setHeaders: r.setHeaders });
    }
  }
  const open = routes.filter((r) => !r.auth);
  return { routes, covered: routes.length > 0 && open.length === 0, open };
}

export function entryPathOf(e: EntryPoint): string | null {
  if (e.kind !== 'http') return null;
  return e.pathTemplate ?? (e.entryKey.replace(/^\S+\s+/, '') || null);
}

const KIND: Record<string, string> = { jwt: 'JWT', oauth2: 'OAuth2 / OIDC', key: 'API Key', basic: 'Basic', external: '外部鉴权服务', custom: '自定义鉴权', off: '关闭' };

function routeStatement(g: GatewayReport, r: GatewayRoute): string {
  const auth = r.auth?.kind === 'off' ? null : r.auth ?? g.report.global[0] ?? null;
  return [
    `网关 ${g.gateway} 的路由 ${r.pathTemplate}${r.upstream ? ` 转发到 ${r.upstream}` : ''}${r.stripPrefix ? `（去掉前 ${r.stripPrefix} 段路径）` : ''}：`,
    auth ? `转发前经过鉴权——${KIND[auth.kind] ?? auth.kind}，${auth.mechanism}（${auth.site.path}:${auth.site.line}）` : r.auth?.kind === 'off' ? `该路由显式关闭了鉴权，请求不经鉴权直接转发` : '网关配置中没有识别到鉴权，请求不经鉴权直接转发',
    r.setHeaders.length ? `；转发时设置请求头 ${r.setHeaders.join('、')}` : '',
    r.removeHeaders.length ? `；移除请求头 ${r.removeHeaders.join('、')}` : '',
    '。（由网关配置确定性提取；只说明网关做了什么，不代表服务内可以省略校验。）',
  ].join('');
}

/**
 * Write the gateway facts of a project from its gateways' configuration: one per route (and the global mechanisms),
 * verified, keyed by gateway and route. Unchanged ones are kept; a fact a person edited or retracted is left alone.
 */
export function syncGatewayFacts(store: Store, projectId: string, gateways: GatewayReport[]): { added: number; updated: number } {
  let added = 0;
  let updated = 0;
  const put = (key: string, topic: 'gateway' | 'auth', statement: string, scope: { repos: string[]; services?: string[]; paths?: string[] }, ref: string) => {
    const prev = store.get<FactRow>(`SELECT * FROM fact WHERE project_id = ? AND fact_key = ? ORDER BY version DESC LIMIT 1`, projectId, key);
    if (prev && (prev.status === 'retracted' || prev.created_by !== 'gateway_config')) return;
    if (prev && prev.statement === statement) return;
    addFact(store, projectId, { topic, statement, scope, sourceKind: 'gateway_config', sourceRef: ref, trust: 'verified', key }, 'gateway_config');
    if (prev) updated++; else added++;
  };
  for (const g of gateways) {
    for (const a of g.report.global) {
      put(`gateway_config:${g.gateway}:global:${a.mechanism}`, 'auth', `网关 ${g.gateway} 对所有路由统一鉴权：${KIND[a.kind] ?? a.kind}，${a.mechanism}（${a.site.path}:${a.site.line}）。路由可以单独关闭。`, { repos: [g.gateway] }, `${a.site.path}:${a.site.line}`);
    }
    for (const r of g.report.routes) {
      put(`gateway_config:${g.gateway}:${r.pathTemplate}`, 'gateway', routeStatement(g, r), { repos: [g.gateway], ...(r.upstream ? { services: [r.upstream] } : {}), paths: [r.pathTemplate] }, `${r.site.path}:${r.site.line}`);
    }
  }
  return { added, updated };
}
