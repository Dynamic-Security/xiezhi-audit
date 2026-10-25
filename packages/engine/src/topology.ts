// System topology: built from connection matches after each project
// analysis. AI edges are replaced on every rebuild; user edges stay, and an AI edge the user removed
// stays removed when the same edge is derived again. Audits freeze the topology they start with.
import { AppError, newId, type Connection, type ConnectionMatch } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';

export const EDGE_KINDS = ['contract', 'client_call', 'message', 'shared_lib', 'frontend_api'] as const;
export const EDGE_PROTOCOLS = ['http', 'grpc', 'dubbo', 'mq', 'gateway_route', 'shared_lib'] as const;
export type EdgeKind = (typeof EDGE_KINDS)[number];
export type EdgeProtocol = (typeof EDGE_PROTOCOLS)[number];

export interface EdgeEvidence {
  /** Null for imported edges: their evidence is a statement of the architecture material (`source`). */
  consumer: { repo: string; path: string; line: number; ruleId: string; key: Connection['key'] } | null;
  provider: { repo: string; path: string; line: number; ruleId: string; key: Connection['key'] } | null;
  confidence: 'confirmed' | 'inferred';
  reason: string;
  /** `doc:<label>` for architecture imports. */
  source?: string;
}

export interface TopologyNode { id: string; kind: string; name: string; repositoryId: string | null; role: string | null; origin: string; attrs: Record<string, unknown> }
export interface TopologyEdge { id: string; from: string; to: string; kind: EdgeKind; protocol: EdgeProtocol; origin: string; confidence: 'confirmed' | 'inferred'; evidence: EdgeEvidence[]; removed: boolean }
export interface Topology { projectId: string; revision: number; nodes: TopologyNode[]; edges: TopologyEdge[] }

const MAX_EVIDENCE = 20;

function edgeKind(c: Connection, provider: Connection | null, consumerRole: string): EdgeKind {
  if (c.kind === 'mq') return 'message';
  if (c.kind === 'shared_lib') return 'shared_lib';
  if (c.kind === 'http' && (consumerRole === 'frontend' || c.ruleId.startsWith('js.'))) return 'frontend_api';
  if (provider && (provider.ruleId.startsWith('openapi.') || provider.ruleId.startsWith('proto.'))) return 'contract';
  return 'client_call';
}

function site(c: Connection) {
  return { repo: c.repo, path: c.site.path, line: c.site.line, ruleId: c.ruleId, key: c.key };
}

/** The external-service node for calls whose target the analysis could not tell. */
export const UNKNOWN_EXTERNAL_SERVICE = '未识别的外部服务';

/** Rebuild the AI part of the project topology from one analysis. Runs in a transaction. */
export function rebuildTopology(store: Store, projectId: string, analysisId: string, conns: Connection[], matches: ConnectionMatch[]): void {
  const byId = new Map(conns.map((c) => [c.connId, c]));
  const repos = store.all<{ id: string; name: string; role: string }>('SELECT id, name, role FROM repository WHERE project_id = ? AND removed_at IS NULL', projectId);
  const repoByName = new Map(repos.map((r) => [r.name, r]));
  store.tx(() => {
    const nodes = store.all<{ id: string; kind: string; name: string; repository_id: string | null; origin: string }>('SELECT id, kind, name, repository_id, origin FROM topology_node WHERE project_id = ?', projectId);
    const nodeFor = (repoName: string | null, external: string | null): string => {
      if (repoName) {
        const r = repoByName.get(repoName)!;
        const kind = r.role === 'gateway' ? 'gateway' : 'repo';
        let n = nodes.find((x) => x.repository_id === r.id);
        if (!n) {
          n = { id: newId('topologyNode'), kind, name: r.name, repository_id: r.id, origin: 'ai' };
          store.insert('topology_node', { id: n.id, project_id: projectId, kind, name: r.name, repository_id: r.id, origin: 'ai' });
          nodes.push(n);
        } else if (n.kind !== kind && n.origin === 'ai') {
          store.update('topology_node', { id: n.id }, { kind });
          n.kind = kind;
        }
        return n.id;
      }
      const name = external ?? UNKNOWN_EXTERNAL_SERVICE;
      let n = nodes.find((x) => !x.repository_id && x.name.toLowerCase() === name.toLowerCase());
      if (!n) {
        n = { id: newId('topologyNode'), kind: 'external_service', name, repository_id: null, origin: 'ai' };
        store.insert('topology_node', { id: n.id, project_id: projectId, kind: 'external_service', name, repository_id: null, origin: 'ai' });
        nodes.push(n);
      }
      return n.id;
    };
    // Remember AI edges the user removed, by signature.
    const old = store.all<{ from_node: string; to_node: string; kind: string; protocol: string; removed: number }>(`SELECT from_node, to_node, kind, protocol, removed FROM topology_edge WHERE project_id = ? AND origin = 'ai'`, projectId);
    const removedSig = new Set(old.filter((e) => e.removed).map((e) => `${e.from_node}|${e.to_node}|${e.kind}|${e.protocol}`));
    store.db.run(`DELETE FROM topology_edge WHERE project_id = ? AND origin = 'ai'`, projectId);

    const edges = new Map<string, { from: string; to: string; kind: EdgeKind; protocol: EdgeProtocol; confidence: 'confirmed' | 'inferred'; evidence: EdgeEvidence[] }>();
    for (const m of matches) {
      const c = byId.get(m.consumer);
      if (!c || !repoByName.has(c.repo)) continue;
      const p = m.provider ? byId.get(m.provider) ?? null : null;
      const toRepo = p?.repo ?? m.providerRepo;
      if (toRepo === c.repo) continue;
      const from = nodeFor(c.repo, null);
      const to = toRepo && repoByName.has(toRepo) ? nodeFor(toRepo, null) : nodeFor(null, c.serviceHint ?? null);
      const kind = edgeKind(c, p, repoByName.get(c.repo)!.role);
      // Messages flow from producer to consumer.
      const [a, b] = c.kind === 'mq' ? [to, from] : [from, to];
      const protocol = c.kind as EdgeProtocol;
      const sig = `${a}|${b}|${kind}|${protocol}`;
      const e = edges.get(sig) ?? { from: a, to: b, kind, protocol, confidence: 'inferred' as 'confirmed' | 'inferred', evidence: [] as EdgeEvidence[] };
      if (m.confidence === 'confirmed') e.confidence = 'confirmed';
      if (e.evidence.length < MAX_EVIDENCE) e.evidence.push({ consumer: site(c), provider: p ? site(p) : null, confidence: m.confidence as 'confirmed' | 'inferred', reason: m.reason });
      edges.set(sig, e);
    }
    for (const [sig, e] of edges) {
      store.insert('topology_edge', {
        id: newId('topologyEdge'), project_id: projectId, from_node: e.from, to_node: e.to, kind: e.kind, protocol: e.protocol, origin: 'ai',
        confidence: e.confidence, evidence: e.evidence, removed: removedSig.has(sig) ? 1 : 0, derived_analysis_id: analysisId,
      });
    }
    // Every repository has a node, even without connections; drop AI external nodes nothing points to.
    for (const r of repos) nodeFor(r.name, null);
    store.db.run(`DELETE FROM topology_node WHERE project_id = ? AND origin = 'ai' AND repository_id IS NULL
      AND id NOT IN (SELECT from_node FROM topology_edge WHERE project_id = ?) AND id NOT IN (SELECT to_node FROM topology_edge WHERE project_id = ?)`, projectId, projectId, projectId);
    store.db.run('UPDATE project SET topology_revision = topology_revision + 1 WHERE id = ?', projectId);
  });
}

/** Service nodes bound to a repository are name mappings (see `serviceMappings`), not drawn as nodes. */
export function getTopology(store: Store, projectId: string): Topology {
  const rev = store.get<{ topology_revision: number }>('SELECT topology_revision FROM project WHERE id = ?', projectId);
  if (!rev) throw new AppError('PROJECT_NOT_FOUND', projectId);
  const nodes = store.all<{ id: string; kind: string; name: string; repository_id: string | null; origin: string; attrs: string; role: string | null }>(
    `SELECT n.id, n.kind, n.name, n.repository_id, n.origin, n.attrs, r.role FROM topology_node n LEFT JOIN repository r ON r.id = n.repository_id
     WHERE n.project_id = ? AND (n.repository_id IS NULL OR r.removed_at IS NULL)
       AND NOT (n.kind = 'service' AND n.repository_id IS NOT NULL) ORDER BY n.kind, n.name`, projectId);
  const ids = new Set(nodes.map((n) => n.id));
  const edges = store.all<{ id: string; from_node: string; to_node: string; kind: EdgeKind; protocol: EdgeProtocol; origin: string; confidence: 'confirmed' | 'inferred'; evidence: string; removed: number }>(
    'SELECT * FROM topology_edge WHERE project_id = ? ORDER BY created_at, id', projectId);
  return {
    projectId, revision: rev.topology_revision,
    nodes: nodes.map((n) => ({ id: n.id, kind: n.kind, name: n.name, repositoryId: n.repository_id, role: n.role, origin: n.origin, attrs: JSON.parse(n.attrs) as Record<string, unknown> })),
    edges: edges.filter((e) => ids.has(e.from_node) && ids.has(e.to_node)).map((e) => ({
      id: e.id, from: e.from_node, to: e.to_node, kind: e.kind, protocol: e.protocol, origin: e.origin, confidence: e.confidence,
      evidence: JSON.parse(e.evidence) as EdgeEvidence[], removed: !!e.removed,
    })),
  };
}

export interface TopologyEdit {
  addNodes?: { name: string; kind: 'external_service' | 'service' }[];
  addEdges?: { from: string; to: string; kind: EdgeKind; protocol: EdgeProtocol }[];
  removeEdges?: string[];
  restoreEdges?: string[];
}

/**
 * User edits (If-Match): new nodes/edges are `origin=user, confidence=confirmed`;
 * removing a user edge deletes it, removing an AI edge hides it (kept across rebuilds).
 */
export function editTopology(store: Store, projectId: string, revision: number, edit: TopologyEdit): Topology {
  store.tx(() => {
    const cur = store.get<{ topology_revision: number }>('SELECT topology_revision FROM project WHERE id = ?', projectId);
    if (!cur) throw new AppError('PROJECT_NOT_FOUND', projectId);
    if (cur.topology_revision !== revision) throw new AppError('COMMON_REVISION_CONFLICT', `topology revision is ${cur.topology_revision}`);
    const nodeIds = new Set(store.all<{ id: string }>('SELECT id FROM topology_node WHERE project_id = ?', projectId).map((n) => n.id));
    const created = new Map<string, string>();
    for (const n of edit.addNodes ?? []) {
      const name = n.name.trim();
      if (!name || name.length > 100) throw new AppError('COMMON_VALIDATION', 'node name must be 1–100 characters');
      const id = newId('topologyNode');
      store.insert('topology_node', { id, project_id: projectId, kind: n.kind, name, repository_id: null, origin: 'user' });
      nodeIds.add(id);
      created.set(`new:${name}`, id);
    }
    for (const e of edit.addEdges ?? []) {
      const from = created.get(e.from) ?? e.from;
      const to = created.get(e.to) ?? e.to;
      if (!nodeIds.has(from) || !nodeIds.has(to) || from === to) throw new AppError('COMMON_VALIDATION', 'edge endpoints must be two different nodes of this project');
      if (!EDGE_KINDS.includes(e.kind) || !EDGE_PROTOCOLS.includes(e.protocol)) throw new AppError('COMMON_VALIDATION', 'edge kind / protocol');
      store.insert('topology_edge', { id: newId('topologyEdge'), project_id: projectId, from_node: from, to_node: to, kind: e.kind, protocol: e.protocol, origin: 'user', confidence: 'confirmed', evidence: [] });
    }
    for (const id of edit.removeEdges ?? []) {
      const e = store.get<{ origin: string }>('SELECT origin FROM topology_edge WHERE id = ? AND project_id = ?', id, projectId);
      if (!e) throw new AppError('COMMON_NOT_FOUND', id);
      if (e.origin === 'user') store.db.run('DELETE FROM topology_edge WHERE id = ?', id);
      else store.update('topology_edge', { id }, { removed: 1 });
    }
    for (const id of edit.restoreEdges ?? []) {
      if (!store.get('SELECT 1 FROM topology_edge WHERE id = ? AND project_id = ?', id, projectId)) throw new AppError('COMMON_NOT_FOUND', id);
      store.update('topology_edge', { id }, { removed: 0 });
    }
    // A user node whose last edge was removed goes too.
    if (edit.removeEdges?.length) {
      store.db.run(`DELETE FROM topology_node WHERE project_id = ? AND origin = 'user' AND repository_id IS NULL
        AND id NOT IN (SELECT from_node FROM topology_edge) AND id NOT IN (SELECT to_node FROM topology_edge)`, projectId);
    }
    store.db.run('UPDATE project SET topology_revision = topology_revision + 1 WHERE id = ?', projectId);
  });
  return getTopology(store, projectId);
}

/** Frozen copy for an audit: removed edges are left out. */
export function freezeTopology(store: Store, projectId: string): string {
  const t = getTopology(store, projectId);
  return store.artifacts.putJson({ ...t, edges: t.edges.filter((e) => !e.removed) });
}

/**
 * Service-name → repository mappings from the topology: user and imported service
 * nodes bound to a repository. Used before application names and name similarity when matching.
 */
export function serviceMappings(store: Store, projectId: string): { service: string; repo: string; source: 'user' | 'imported' }[] {
  return store.all<{ name: string; repo: string; origin: 'user' | 'imported' }>(
    `SELECT n.name, r.name AS repo, n.origin FROM topology_node n JOIN repository r ON r.id = n.repository_id
     WHERE n.project_id = ? AND n.kind = 'service' AND n.origin IN ('user', 'imported') AND r.removed_at IS NULL`, projectId)
    .map((m) => ({ service: m.name, repo: m.repo, source: m.origin }));
}
