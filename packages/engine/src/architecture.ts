// Architecture material import. The
// chat model (no repository access) reads the pasted or uploaded material and proposes services,
// connections and service → repository names. They enter the topology as `origin = imported`,
// `confidence = inferred`, with the stated sentence as evidence; imported service names feed connection
// matching. The same material becomes an unverified project “system architecture” knowledge draft.
import { AppError, ArchitectureImportSubmit, newId, type ModelRef } from '@xiezhi/contracts';
import { boundaryDeclaration, newNonce, startSession, wrapUntrusted, type AuditTool, type ModelHub } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import { chatModelOf, getProject, listRepositories } from './services.js';
import { EDGE_KINDS, EDGE_PROTOCOLS, type EdgeEvidence } from './topology.js';
import { P } from '@xiezhi/knowledge';
import { withLivePrompts } from './prompts.js';

export interface ArchitectureImportRow {
  id: string; project_id: string; label: string; status: 'running' | 'done' | 'failed'; input_ref: string; result: string | null;
  draft_id: string | null; error: string | null; model: string | null; tokens: number; created_at: number; updated_at: number;
}
export interface ArchitectureImportResult { nodesAdded: number; edgesAdded: number; aliases: number; skipped: string[]; summary: string }

const MAX_TEXT = 200_000;

export function getArchitectureImport(store: Store, id: string): ArchitectureImportRow {
  const r = store.get<ArchitectureImportRow>('SELECT * FROM architecture_import WHERE id = ?', id);
  if (!r) throw new AppError('COMMON_NOT_FOUND', `architecture import ${id}`);
  return r;
}

export function createArchitectureImport(store: Store, projectId: string, input: { text: string; label: string }): string {
  getProject(store, projectId);
  if (!input.text.trim()) throw new AppError('COMMON_VALIDATION', 'text is empty');
  if (input.text.length > MAX_TEXT) throw new AppError('COMMON_VALIDATION', `text exceeds ${MAX_TEXT} characters`);
  const id = newId('architectureImport');
  store.insert('architecture_import', { id, project_id: projectId, label: input.label.slice(0, 200) || '架构资料', status: 'running', input_ref: store.artifacts.put(input.text, 'text/plain') });
  return id;
}

/**
 * Run an import: extract with the chat model, apply to the topology, then hand the material to the
 * knowledge pipeline as a project architecture draft (`startDraft` is the engine's draft starter).
 */
async function runArchitectureImportInner(
  deps: { store: Store; hub: ModelHub; startDraft: (input: { layer: 'project'; projectId: string; kind: 'skill'; text: string; organize: true; category: 'architecture'; source: { kind: 'upload'; ref: null; label: string } }) => { id: string } },
  id: string, signal: AbortSignal,
): Promise<void> {
  const { store } = deps;
  const row = getArchitectureImport(store, id);
  const usage = { total: 0 };
  try {
    let model: ModelRef;
    try { model = chatModelOf(store.config); } catch { throw new AppError('MODEL_NOT_CONFIGURED', 'architecture import needs a chat or default model'); }
    const text = store.artifacts.getText(row.input_ref);
    const repos = listRepositories(store, row.project_id);
    const nonce = newNonce();
    const tool: AuditTool = { name: 'submit_architecture', kind: 'submit', parameters: ArchitectureImportSubmit, description: P('tool.submit_architecture'), run: () => ({ text: 'recorded' }) };
    const outcome = await startSession({
      hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
      systemPrompt: [P('role.architecture_import'), boundaryDeclaration(nonce)].join('\n\n'),
      prompt: [P('architecture.guide'), '', `本项目仓库：${repos.map((r) => `${r.name}${r.role ? `（${r.role}）` : ''}`).join('、') || '（无）'}`, wrapUntrusted(nonce, 'user_upload', `architecture:${row.label}`, text)].join('\n'),
      tools: [tool], requiredSubmits: ['submit_architecture'], maxTurns: 4, signal,
      onUsage: (u) => { usage.total += u.total; return 'continue'; },
    }).outcome;
    const sub = (outcome.submissions.submit_architecture as ArchitectureImportSubmit[] | undefined)?.at(-1);
    if (!sub) throw new Error(`the model did not submit (${outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
    const result = applyArchitecture(store, row.project_id, row.label, sub);
    const draft = deps.startDraft({
      layer: 'project', projectId: row.project_id, kind: 'skill', organize: true, category: 'architecture', text,
      source: { kind: 'upload', ref: null, label: `架构资料「${row.label}」` },
    });
    store.update('architecture_import', { id }, { status: 'done', result, draft_id: draft.id, model: `${model.provider}/${model.model}`, tokens: usage.total, error: null });
  } catch (e) {
    store.update('architecture_import', { id }, { status: 'failed', error: (e as Error).message.slice(0, 500), tokens: usage.total });
  }
}

/**
 * Apply the proposals (one transaction, one topology revision): service nodes by name (a named repository
 * binds the service name to it — an imported service mapping), edges between known nodes as
 * `imported` / `inferred` with the statement as evidence. An edge equal to an existing one of any origin
 * only gains evidence; user-removed edges are not revived.
 */
export function applyArchitecture(store: Store, projectId: string, label: string, sub: ArchitectureImportSubmit): ArchitectureImportResult {
  const repos = listRepositories(store, projectId);
  const skipped: string[] = [];
  let nodesAdded = 0;
  let edgesAdded = 0;
  let aliases = 0;
  store.tx(() => {
    const nodes = store.all<{ id: string; kind: string; name: string; repository_id: string | null }>('SELECT id, kind, name, repository_id FROM topology_node WHERE project_id = ?', projectId);
    const byName = new Map<string, string>();
    for (const n of nodes) byName.set(n.name.toLowerCase(), n.id);
    const repoNode = (repoName: string): string | null => {
      const r = repos.find((x) => x.name.toLowerCase() === repoName.toLowerCase());
      if (!r) return null;
      const n = nodes.find((x) => x.repository_id === r.id && x.kind !== 'service');
      if (n) return n.id;
      const nid = newId('topologyNode');
      store.insert('topology_node', { id: nid, project_id: projectId, kind: 'repo', name: r.name, repository_id: r.id, origin: 'imported' });
      nodes.push({ id: nid, kind: 'repo', name: r.name, repository_id: r.id });
      nodesAdded++;
      return nid;
    };
    // Services: bound to a repository → the repository node (plus an imported alias); else a named node.
    const resolved = new Map<string, string>();
    for (const s of sub.services) {
      const key = s.name.toLowerCase();
      if (s.repo) {
        const rid = repoNode(s.repo);
        if (!rid) { skipped.push(`服务 ${s.name} 指向的仓库 ${s.repo} 不在本项目中`); continue; }
        resolved.set(key, rid);
        const r = repos.find((x) => x.name.toLowerCase() === s.repo!.toLowerCase())!;
        if (key !== r.name.toLowerCase() && !nodes.some((n) => n.kind === 'service' && n.name.toLowerCase() === key && n.repository_id === r.id)) {
          store.insert('topology_node', { id: newId('topologyNode'), project_id: projectId, kind: 'service', name: s.name, repository_id: r.id, origin: 'imported', attrs: { source: `doc:${label}` } });
          aliases++;
        }
        continue;
      }
      const repoMatch = repos.find((x) => x.name.toLowerCase() === key);
      if (repoMatch) { resolved.set(key, repoNode(repoMatch.name)!); continue; }
      const existing = byName.get(key);
      if (existing) { resolved.set(key, existing); continue; }
      const nid = newId('topologyNode');
      const kind = s.kind === 'service' ? 'external_service' : s.kind;
      store.insert('topology_node', { id: nid, project_id: projectId, kind, name: s.name.slice(0, 100), repository_id: null, origin: 'imported', attrs: { source: `doc:${label}`, ...(s.description ? { description: s.description } : {}) } });
      byName.set(key, nid);
      resolved.set(key, nid);
      nodesAdded++;
    }
    const nodeOf = (name: string) => resolved.get(name.toLowerCase()) ?? byName.get(name.toLowerCase()) ?? (repos.some((r) => r.name.toLowerCase() === name.toLowerCase()) ? repoNode(name) : null);
    for (const e of sub.edges) {
      const from = nodeOf(e.from);
      const to = nodeOf(e.to);
      if (!from || !to || from === to) { skipped.push(`连接 ${e.from} → ${e.to}：端点不在服务清单中`); continue; }
      if (!(EDGE_KINDS as readonly string[]).includes(e.kind) || !(EDGE_PROTOCOLS as readonly string[]).includes(e.protocol)) { skipped.push(`连接 ${e.from} → ${e.to}：类型无效`); continue; }
      const ev: EdgeEvidence = { consumer: null, provider: null, confidence: 'inferred', reason: e.statement.slice(0, 400), source: `doc:${label}` };
      const same = store.get<{ id: string; evidence: string; removed: number }>('SELECT id, evidence, removed FROM topology_edge WHERE project_id = ? AND from_node = ? AND to_node = ? AND kind = ? AND protocol = ?', projectId, from, to, e.kind, e.protocol);
      if (same) {
        const list = fromJson<EdgeEvidence[]>(same.evidence, []);
        if (!list.some((x) => x.source === ev.source && x.reason === ev.reason) && list.length < 20) store.update('topology_edge', { id: same.id }, { evidence: [...list, ev] });
        continue;
      }
      store.insert('topology_edge', { id: newId('topologyEdge'), project_id: projectId, from_node: from, to_node: to, kind: e.kind, protocol: e.protocol, origin: 'imported', confidence: 'inferred', evidence: [ev] });
      edgesAdded++;
    }
    store.db.run('UPDATE project SET topology_revision = topology_revision + 1 WHERE id = ?', projectId);
  });
  return { nodesAdded, edgesAdded, aliases, skipped: skipped.slice(0, 50), summary: sub.summary.slice(0, 2000) };
}

/** with the prompt overrides of the project. */
export async function runArchitectureImport(
  deps: Parameters<typeof runArchitectureImportInner>[0], id: string, signal: AbortSignal,
): Promise<void> {
  return withLivePrompts(deps.store, getArchitectureImport(deps.store, id).project_id, () => runArchitectureImportInner(deps, id, signal), 'architecture_import', id);
}
