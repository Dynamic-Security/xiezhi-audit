// access-policy check. The threat model states, per group of entries (route prefix or
// controller), who should be able to call them; the engine compares that with the auth signals the index found on
// each entry and in the repository, deterministically, and turns the differences into must-answer items for the
// domain experts that own the category. Only differences are listed — a full matrix would be too long to answer.
import type { AccessLevel, AccessPolicyDraft, EntryPoint, StructIndex } from '@xiezhi/contracts';
import { logicEntries } from './business.js';
import type { AuditRuntime } from './runtime.js';
import { P } from '@xiezhi/knowledge';
import { entryExposure, entryPathOf, projectGateways, serviceNames } from './gateway.js';

export interface AccessGroup extends AccessPolicyDraft { repo: string }

export interface AccessCheck {
  entryId: string;
  repo: string;
  entryKey: string;
  level: AccessLevel;
  role?: string;
  /** The policy's reason for the level. */
  reason: string;
  /** What the engine saw that does not obviously meet the level. */
  why: string;
  category: 'authn' | 'authz_function' | 'authz_object';
  scope: string;
}

/** At most this many checks per audit (the most specific groups first). */
export const MAX_ACCESS_CHECKS = 60;
/** Auth signal text that looks like a role / permission check rather than login only. */
const ROLE_SIGNAL = /role|admin|perm|authori[sz]|preauthorize|secured|rolesallowed|requires|hasany|hasrole|scope|policy|acl|rbac/i;
/** Entry kinds with callers outside the system (schedules and CLIs are not reached by users). */
const REACHABLE = new Set(['http', 'rpc', 'socket', 'message']);

/** The access policies the audit's threat models submitted (one group per call). */
export function accessGroups(rt: Pick<AuditRuntime, 'store' | 'auditId' | 'repos'>): AccessGroup[] {
  const rows = rt.store.all<{ output_ref: string }>(
    `SELECT output_ref FROM step WHERE audit_id = ? AND kind = 'threat-model' AND status = 'succeeded' AND output_ref IS NOT NULL ORDER BY seq`, rt.auditId);
  const out: AccessGroup[] = [];
  for (const r of rows) {
    const o = rt.store.artifacts.getJson<{ repositoryId: string; accessPolicy?: AccessPolicyDraft[] }>(r.output_ref);
    const repo = rt.repos.find((x) => x.id === o.repositoryId);
    if (!repo) continue;
    for (const g of o.accessPolicy ?? []) if (!out.some((x) => x.repo === repo.name && x.scope === g.scope)) out.push({ ...g, repo: repo.name });
  }
  return out;
}

const normPath = (p: string) => p.replace(/\{[^}]*\}|:\w+/g, '{}').replace(/\/+$/, '').toLowerCase();

/** The most specific group of an entry: the longest route prefix, else a controller / handler name it contains. */
export function groupOf(e: EntryPoint, groups: AccessGroup[]): AccessGroup | null {
  const path = normPath(e.pathTemplate ?? e.entryKey.replace(/^\S+\s+/, ''));
  const byRoute = groups.filter((g) => g.scope.startsWith('/') && (path === normPath(g.scope) || path.startsWith(`${normPath(g.scope)}/`)))
    .sort((a, b) => b.scope.length - a.scope.length)[0];
  if (byRoute) return byRoute;
  const handler = e.handler.toLowerCase();
  return groups.filter((g) => !g.scope.startsWith('/') && handler.includes(g.scope.toLowerCase())).sort((a, b) => b.scope.length - a.scope.length)[0] ?? null;
}

/** Whether the repository has a global auth mechanism the index recognises (filter, security config, middleware). */
function globalAuth(idx: StructIndex): boolean {
  return idx.authSignals.some((s) => s.kind === 'filter' || s.kind === 'security_config' || s.kind === 'interceptor' || s.kind === 'middleware');
}

/**
 * Differences between the policy and the index (deterministic):
 * - `role` with no role / permission signal on the entry → authz_function;
 * - `owner` on a state-changing or by-id entry → authz_object (ownership is never visible in signals: always asked);
 * - any non-public level with no signal on the entry and no global mechanism in the repository → authn.
 */
export function accessChecks(rt: Pick<AuditRuntime, 'store' | 'auditId' | 'repos' | 'indexes'> & Partial<Pick<AuditRuntime, 'views' | 'audit'>>): AccessCheck[] {
  const groups = accessGroups(rt);
  if (!groups.length) return [];
  // the project's gateways — an entry every reaching route authenticates has no authentication difference.
  const projectId = rt.audit?.project_id;
  const gateways = projectId ? projectGateways(rt.store, projectId, rt.views) : [];
  const out: AccessCheck[] = [];
  for (const [repo, idx] of rt.indexes) {
    const mine = groups.filter((g) => g.repo === repo);
    if (!mine.length) continue;
    const byId = new Set(logicEntries(idx, Number.MAX_SAFE_INTEGER).map((e) => e.entryId));
    const global = globalAuth(idx);
    for (const e of idx.entrypoints as EntryPoint[]) {
      if (!REACHABLE.has(e.kind)) continue;
      const g = groupOf(e, mine);
      if (!g || g.level === 'public') continue;
      const signals = [...e.authSignals, ...e.middlewares];
      const base = { entryId: e.entryId, repo, entryKey: e.entryKey, level: g.level as AccessLevel, ...(g.role ? { role: g.role } : {}), reason: g.reason, scope: g.scope };
      if (!signals.length && !global) {
        const path = gateways.length ? entryPathOf(e) : null;
        const ex = path ? entryExposure(gateways, serviceNames(rt.store, projectId!, repo), path) : null;
        if (ex?.covered) continue;
        out.push({ ...base, category: 'authn', why: ex?.open.length
          ? `入口上与仓库全局都没有识别到鉴权信号，且网关路由 ${ex.open.map((r) => `${r.gateway} ${r.pathTemplate}`).join('、')} 不经鉴权就转发到这里`
          : '入口上与仓库全局都没有识别到鉴权信号' });
      }
      else if (g.level === 'role' && !signals.some((s) => ROLE_SIGNAL.test(s))) out.push({ ...base, category: 'authz_function', why: signals.length ? `入口上只有 ${signals.slice(0, 3).join('、')}，没有识别到角色或权限检查` : '入口上没有识别到角色或权限检查（可能只有全局登录校验）' });
      else if (g.level === 'owner' && byId.has(e.entryId)) out.push({ ...base, category: 'authz_object', why: '按 id 访问或改变状态，归属校验在鉴权信号中不可见，需要读代码确认' });
    }
  }
  const rank = (c: AccessCheck) => ({ authn: 0, authz_function: 1, authz_object: 2 })[c.category];
  return out.sort((a, b) => rank(a) - rank(b) || b.scope.length - a.scope.length).slice(0, MAX_ACCESS_CHECKS);
}

/** The must-answer section of a domain expert's prompt. */
export function accessLines(checks: AccessCheck[]): string[] {
  if (!checks.length) return [];
  const LEVEL: Record<AccessLevel, string> = { public: '公开', authenticated: '需要登录', role: '需要角色', owner: '只能访问本人的资源' };
  return [
    '', P('domains.access', { n: checks.length }),
    ...checks.map((c) => `- id=\`${c.entryId}\`  ${c.entryKey}\n  应为：${LEVEL[c.level]}${c.role ? `（${c.role}）` : ''}——${c.reason}\n  引擎看到：${c.why}`),
  ];
}
