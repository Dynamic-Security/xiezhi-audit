// Service responsibility boundaries (23, 37). A project's internal-trust setting says how far its
// services trust each other: zero trust (every service checks for itself), the gateway as the boundary (behind it a
// request counts as authenticated), or a trusted internal network. Unset, it is inferred from the topology: a gateway
// in the project → the gateway is the boundary, otherwise the project is treated as a monolith (no service boundaries).
// Each finding is classed as an own-service defect, one that relies on an upstream guarantee (its pending condition is
// about the gateway or another repository), or a cross-service risk (it is reached only from inside: an internal entry
// no gateway route forwards to, or an RPC / message entry). What the setting does at publication: zero trust publishes
// everything; with the gateway as the boundary a cross-service risk is published one severity lower; on a trusted
// internal network it is a hint (listed in the report, not published as a vulnerability).
import type { EntryPoint, Severity, StructIndex } from '@xiezhi/contracts';
import { AppError } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { activeFacts } from './facts.js';
import { entryExposure, entryPathOf, projectGateways, serviceNames, type GatewayReport } from './gateway.js';
import { getProject } from './services.js';

export const INTERNAL_TRUST = ['zero_trust', 'gateway_boundary', 'trusted_network'] as const;
export type InternalTrust = (typeof INTERNAL_TRUST)[number];
export type EffectiveTrust = InternalTrust | 'monolith';
export type Boundary = 'own' | 'upstream' | 'cross_service';

export const TRUST_LABEL: Record<EffectiveTrust, string> = { zero_trust: '零信任', gateway_boundary: '网关为边界', trusted_network: '内网可信', monolith: '单体（不区分服务边界）' };

export function effectiveTrust(store: Store, projectId: string, gateways?: GatewayReport[]): { value: EffectiveTrust; source: 'user' | 'auto'; reason: string } {
  const p = store.get<{ internal_trust: InternalTrust | null }>('SELECT internal_trust FROM project WHERE id = ?', projectId);
  if (!p) throw new AppError('PROJECT_NOT_FOUND', projectId);
  if (p.internal_trust) return { value: p.internal_trust, source: 'user', reason: '项目设置' };
  // Cheap signals first (repository role, gateway facts); the configuration itself only when the caller has it read.
  const gwRole = store.get<{ name: string }>(`SELECT name FROM repository WHERE project_id = ? AND removed_at IS NULL AND role = 'gateway' LIMIT 1`, projectId);
  const gwFact = store.get<{ scope: string }>(`SELECT scope FROM fact WHERE project_id = ? AND status = 'active' AND source_kind = 'gateway_config' LIMIT 1`, projectId);
  const gwName = gwRole?.name ?? (gwFact ? fromJson<{ repos?: string[] }>(gwFact.scope, {}).repos?.[0] : undefined) ?? gateways?.[0]?.gateway;
  if (gwName) return { value: 'gateway_boundary', source: 'auto', reason: `项目中有网关（${gwName}），按“网关为边界”推断` };
  return { value: 'monolith', source: 'auto', reason: '项目中没有网关，按单体处理' };
}

export function setInternalTrust(store: Store, projectId: string, value: InternalTrust | null): void {
  getProject(store, projectId);
  if (value !== null && !(INTERNAL_TRUST as readonly string[]).includes(value)) throw new AppError('COMMON_VALIDATION', `internal trust must be one of ${INTERNAL_TRUST.join(', ')}`);
  store.update('project', { id: projectId }, { internal_trust: value });
}

const INTERNAL_KINDS = new Set(['rpc', 'message']);

/** The class of a finding (the model's own claim wins when it gave one). */
export function classifyFinding(
  f: { entry_keys: string; detail: { boundary?: string; pendingCondition?: { missing?: { kind: string }[] } } },
  ctx: { index: StructIndex | undefined; gateways: GatewayReport[]; names: Set<string>; trust: EffectiveTrust },
): Boundary {
  if (f.detail.boundary === 'own' || f.detail.boundary === 'upstream' || f.detail.boundary === 'cross_service') return f.detail.boundary;
  if ((f.detail.pendingCondition?.missing ?? []).some((m) => m.kind === 'gateway_policy' || m.kind === 'repo' || m.kind === 'external_service')) return 'upstream';
  if (ctx.trust === 'monolith' || !ctx.index) return 'own';
  const keys = fromJson<string[]>(f.entry_keys, []);
  const entries = (ctx.index.entrypoints as EntryPoint[]).filter((e) => keys.includes(e.entryKey) || keys.includes(e.entryId));
  if (!entries.length) return 'own';
  const internal = entries.every((e) => {
    if (INTERNAL_KINDS.has(e.kind)) return true;
    if (!ctx.gateways.length) return false;
    const path = entryPathOf(e);
    return !!path && entryExposure(ctx.gateways, ctx.names, path).routes.length === 0;
  });
  return internal ? 'cross_service' : 'own';
}

const LOWER: Record<string, Severity> = { critical: 'high', high: 'medium', medium: 'low', low: 'low', info: 'info' };

/** What the trust setting does to a finding of a class: publish as is, publish one level lower, or keep as a hint. */
export function trustAction(boundary: Boundary, trust: EffectiveTrust): 'publish' | 'lower' | 'hint' {
  if (boundary !== 'cross_service') return 'publish';
  if (trust === 'trusted_network') return 'hint';
  if (trust === 'gateway_boundary') return 'lower';
  return 'publish';
}

export interface BoundaryResult { hints: string[]; lowered: string[]; classes: Record<string, Boundary>; trust: EffectiveTrust; commit: () => void }

/**
 * Class the findings about to be published and plan what the trust setting does; `commit` (in the publish step's apply)
 * stores the class on each finding, lowers the severity of the lowered ones with a note, and notes the hints.
 */
export function planBoundaries(
  store: Store, projectId: string, findings: { id: string; repository_id: string; entry_keys: string; severity: string; detail_ref: string }[],
  indexes: ReadonlyMap<string, StructIndex>, repos: { id: string; name: string }[], gateways: GatewayReport[],
): BoundaryResult {
  const trust = effectiveTrust(store, projectId, gateways).value;
  const writes: [string, Record<string, unknown>][] = [];
  const out: BoundaryResult = { hints: [], lowered: [], classes: {}, trust, commit: () => { for (const [id, patch] of writes) store.update('finding', { id }, patch); } };
  for (const f of findings) {
    const repo = repos.find((r) => r.id === f.repository_id);
    const detail = store.artifacts.getJson<{ boundary?: string; pendingCondition?: { missing?: { kind: string }[] } }>(f.detail_ref);
    const b = classifyFinding({ entry_keys: f.entry_keys, detail }, { index: repo ? indexes.get(repo.name) : undefined, gateways, names: repo ? serviceNames(store, projectId, repo.name) : new Set(), trust });
    out.classes[f.id] = b;
    const action = trustAction(b, trust);
    if (action === 'hint') {
      out.hints.push(f.id);
      writes.push([f.id, { boundary: b, boundary_note: `内部信任为“${TRUST_LABEL[trust]}”：服务间风险作为提示列出，不发布为漏洞` }]);
    } else if (action === 'lower' && LOWER[f.severity] !== f.severity) {
      out.lowered.push(f.id);
      writes.push([f.id, { boundary: b, severity: LOWER[f.severity], boundary_note: `内部信任为“${TRUST_LABEL[trust]}”：只能从内部到达的服务间风险，严重度由 ${f.severity} 降为 ${LOWER[f.severity]}` }]);
    } else writes.push([f.id, { boundary: b }]);
  }
  return out;
}

// ---- responsibility card -------------------------------------------------------------------------------------------

export interface ResponsibilityCard {
  service: string;
  names: string[];
  trust: { value: EffectiveTrust; source: 'user' | 'auto'; reason: string };
  inbound: {
    /** Entries the gateways forward to, with how they authenticate. */
    exposed: { entryKey: string; routes: { gateway: string; pathTemplate: string; auth: string | null }[] }[];
    /** Entries no gateway forwards to (or RPC / message entries): reached only from inside. */
    internal: string[];
    channels: Record<string, number>;
  };
  /** Facts in force about the service, or the project's gateways: the guarantees it may rely on. */
  guarantees: { id: string; statement: string; trust: string; source: string }[];
  outbound: { to: string; kind: string; protocol: string }[];
}

const MAX_CARD_ENTRIES = 40;

export function responsibilityCard(store: Store, projectId: string, repo: string, index: StructIndex | undefined, gateways?: GatewayReport[], opts: { confidential?: boolean } = {}): ResponsibilityCard {
  const gws = gateways ?? projectGateways(store, projectId);
  const names = serviceNames(store, projectId, repo);
  const exposed: ResponsibilityCard['inbound']['exposed'] = [];
  const internal: string[] = [];
  const channels: Record<string, number> = {};
  for (const e of (index?.entrypoints ?? []) as EntryPoint[]) {
    channels[e.kind] = (channels[e.kind] ?? 0) + 1;
    const path = entryPathOf(e);
    const ex = path && gws.length ? entryExposure(gws, names, path) : null;
    if (ex?.routes.length) exposed.push({ entryKey: e.entryKey, routes: ex.routes.map((r) => ({ gateway: r.gateway, pathTemplate: r.pathTemplate, auth: r.auth ? r.auth.mechanism : null })) });
    else if (INTERNAL_KINDS.has(e.kind) || (gws.length && e.kind === 'http')) internal.push(e.entryKey);
  }
  const lower = [...names];
  // confidential facts only when the reader may see them (a session on a model that may not, does not).
  const guarantees = activeFacts(store, projectId).filter((f) => opts.confidential !== false || f.sensitivity !== 'confidential').filter((f) => {
    const sc = fromJson<{ repos?: string[]; services?: string[] }>(f.scope, {});
    const scoped = [...(sc.repos ?? []), ...(sc.services ?? [])].map((x) => x.toLowerCase());
    return scoped.some((x) => lower.includes(x)) || (f.source_kind === 'gateway_config' && f.topic === 'auth') || (!scoped.length && (f.topic === 'gateway' || f.topic === 'auth' || f.topic === 'network'));
  }).map((f) => ({ id: f.id, statement: f.statement, trust: f.trust, source: f.source_kind }));
  const outbound = store.all<{ to: string; kind: string; protocol: string }>(
    `SELECT t.name AS "to", e.kind, e.protocol FROM topology_edge e JOIN topology_node f ON f.id = e.from_node JOIN topology_node t ON t.id = e.to_node
     WHERE e.project_id = ? AND e.removed = 0 AND (lower(f.name) IN (${lower.map(() => '?').join(',')})) ORDER BY t.name`, projectId, ...lower);
  return {
    service: repo, names: [...names], trust: effectiveTrust(store, projectId, gws),
    inbound: { exposed: exposed.slice(0, MAX_CARD_ENTRIES), internal: internal.slice(0, MAX_CARD_ENTRIES), channels }, guarantees, outbound,
  };
}

/** The card as prompt text (data), compact. */
export function cardText(c: ResponsibilityCard): string {
  const AUTH = (a: string | null) => (a ? `经鉴权（${a}）` : '不经鉴权');
  return [
    `服务 ${c.service}（内部信任：${TRUST_LABEL[c.trust.value]}，${c.trust.source === 'user' ? '项目设置' : c.trust.reason}）`,
    `入站：${Object.entries(c.inbound.channels).map(([k, n]) => `${k} ${n}`).join('、') || '（未识别到入口）'}`,
    ...(c.inbound.exposed.length ? ['经网关暴露的入口：', ...c.inbound.exposed.slice(0, 15).map((x) => `- ${x.entryKey} ← ${x.routes.map((r) => `${r.gateway} ${r.pathTemplate} ${AUTH(r.auth)}`).join('；')}`)] : []),
    ...(c.inbound.internal.length ? [`只能从内部到达的入口（${c.inbound.internal.length}）：${c.inbound.internal.slice(0, 15).join('、')}`] : []),
    ...(c.guarantees.length ? ['上游保证（企业事实）：', ...c.guarantees.slice(0, 10).map((g) => `- [${g.trust}] ${g.statement.slice(0, 300)}`)] : ['上游保证：没有登记']),
    ...(c.outbound.length ? [`出站：${c.outbound.map((o) => `${o.to}（${o.protocol}）`).join('、')}`] : []),
  ].join('\n');
}
