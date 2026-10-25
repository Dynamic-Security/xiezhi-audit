// Project analysis: started by the user, never automatically.
// For each repository: snapshot its default version, compute the deterministic signal summary (and the
// structure index for the audit languages), then ask the light model for its roles. Results are cached by
// (signals, model, prompt version); a role the user corrected is never overwritten.
import { AppError, canonicalJson, configStageModel, newId, sha256Hex, SubmitRepoRole, type Connection, type ModelRef, type RepoSignals, type StructIndex, type SubmitRepoRole as RoleJudgement } from '@xiezhi/contracts';
import { auditLanguagesOfView, buildIndex, computeRepoSignals, CONNECT_VERSION, extractConnections, type ConnectLimit, linkReferences, matchConnections, SnapshotView, type Executor, type RuleSet } from '@xiezhi/context';
import { boundaryDeclaration, newNonce, startSession, wrapUntrusted, type AuditTool, type ModelHub, type UsageDelta } from '@xiezhi/agent';
import type { Store } from '@xiezhi/store';
import { autoAuditable, indexLanguagesFor, recordAutoAuditable } from './auditable.js';
import { costMicros } from './estimates.js';
import { languagesBySize, listRepositories, type RepositoryRow } from './services.js';
import { recordSnapshot, snapshotSource } from './sources.js';
import { rebuildTopology, serviceMappings } from './topology.js';
import { P } from '@xiezhi/knowledge';
import { withLivePrompts } from './prompts.js';
import { DEFAULT_PROMPTS_HASH, currentPrompts } from '@xiezhi/knowledge';

/** Bump when the role prompt or schema changes: cached judgements are then not reused. */
export const ROLE_PROMPT_VERSION = 1;
/** Below this confidence the primary role stays `unknown`. */
export const ROLE_MIN_CONFIDENCE = 0.4;

export interface AnalysisDeps {
  store: Store;
  executor: Executor;
  hub: ModelHub;
  rules: RuleSet;
  allowFileRemotes: boolean;
}

export interface RepoRoleOutput {
  repositoryId: string;
  rootHash: string;
  model: string;
  judgement: RoleJudgement;
}

/**
 * The model for role recognition: the light model, which is the “初筛” stage model (a quick
 * classification like triage), else the default model.
 */
export function roleModel(store: Store, hub: ModelHub): ModelRef | null {
  const known = hub.knownModels();
  for (const m of [configStageModel(store.config, 'triage'), store.config.defaultModel]) {
    if (m && known.has(`${m.provider}/${m.model}`)) return m;
  }
  return null;
}

function roleTool(): AuditTool {
  return {
    name: 'submit_repo_role', kind: 'submit', parameters: SubmitRepoRole,
    description: P('tool.submit_repo_role'),
    run: () => ({ text: 'roles recorded' }),
  };
}

async function judge(deps: AnalysisDeps, model: ModelRef, name: string, signals: RepoSignals, root: string, signal: AbortSignal, usage: UsageDelta): Promise<RoleJudgement> {
  const nonce = newNonce();
  const systemPrompt = [
    P('role.repo_role'),
    boundaryDeclaration(nonce),
  ].join('\n\n');
  const prompt = [
    P('analyze.role_guide'), '',
    P('analyze.signals_intro', { repo: name.replace(/[^A-Za-z0-9._-]/g, '_') }),
    wrapUntrusted(nonce, 'tool_output', 'repo_signals', JSON.stringify(signals, null, 1)),
  ].join('\n');
  const outcome = await startSession({
    hub: deps.hub, model, cwd: root, agentDir: deps.store.paths.agent, systemPrompt, prompt, tools: [roleTool()], requiredSubmits: ['submit_repo_role'],
    maxTurns: 4, signal,
    onUsage: (u) => {
      for (const k of ['input', 'output', 'cacheRead', 'cacheWrite', 'total', 'cost'] as const) usage[k] += u[k];
      return 'continue';
    },
  }).outcome;
  const out = (outcome.submissions.submit_repo_role as RoleJudgement[] | undefined)?.at(-1);
  if (!out) {
    // A model service error (key, model name, quota, network) is the user's to fix, not an internal one.
    const provider = ['AUTH_INVALID', 'MODEL_NOT_FOUND', 'PROVIDER_QUOTA', 'RATE_LIMITED', 'PROVIDER_TRANSIENT'].includes(outcome.errorClass ?? '');
    throw new AppError(provider ? 'MODEL_UNREACHABLE' : 'INTERNAL', `role recognition did not submit (${outcome.errorClass ?? outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
  }
  return out;
}

/** Primary role for `repository.role`: the most confident one above the threshold. */
export function primaryRole(j: RoleJudgement): string {
  const best = [...j.roles].sort((a, b) => b.confidence - a.confidence)[0];
  return best && best.confidence >= ROLE_MIN_CONFIDENCE ? best.role : 'unknown';
}

interface Prepared { repo: RepositoryRow; rootHash: string; root: string; signals: RepoSignals; signalsRef?: string; connections: Connection[]; connectionsRef: string }

/** Create a running analysis row; the caller runs `runAnalysis` with its id. */
export function createAnalysis(store: Store, projectId: string): string {
  const running = store.get<{ id: string }>(`SELECT id FROM project_analysis WHERE project_id = ? AND status = 'running'`, projectId);
  if (running) throw new AppError('AUDIT_INVALID_TRANSITION', `an analysis of this project is already running (${running.id})`);
  const id = newId('analysis');
  store.insert('project_analysis', { id, project_id: projectId, status: 'running', started_at: Date.now() });
  return id;
}

async function runAnalysisInner(deps: AnalysisDeps, projectId: string, analysisId: string, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const repos = listRepositories(store, projectId);
  const prepared: Prepared[] = [];
  const results = new Map<string, 'succeeded' | 'reused' | 'skipped' | 'failed'>();
  const fail = (repo: RepositoryRow, rootHash: string | null, message: string) => {
    results.set(repo.id, 'failed');
    store.insert('repo_analysis', { id: newId('repoAnalysis'), analysis_id: analysisId, repository_id: repo.id, root_hash: rootHash, status: 'failed', error: message.slice(0, 500) });
  };
  try {
    // 1. Deterministic part: snapshot, index (audit languages), signals; languages / modules / auditable.
    for (const repo of repos) {
      if (signal.aborted) break;
      try {
        const snap = await snapshotSource(store, deps.executor, repo, repo.default_ref, { allowFileRemotes: deps.allowFileRemotes, signal });
        const m = snap.manifest;
        const manifestRef = store.artifacts.putJson(m);
        store.tx(() => recordSnapshot(store, repo.id, m, manifestRef));
        const view = new SnapshotView(repo.name, snap.root, m);
        let index: StructIndex | null = null;
        let indexStatus: RepoSignals['indexStatus'] = 'skipped';
        const auditLangs = indexLanguagesFor(store, repo.id, view) ?? auditLanguagesOfView(view);
        if (auditLangs.length) {
          try {
            const r = await buildIndex(view, deps.rules, { indexesDir: store.paths.indexes, signal, languages: auditLangs });
            index = r.index;
            indexStatus = r.status;
          } catch {
            indexStatus = 'failed';
          }
        }
        const signals = computeRepoSignals(view, index, indexStatus);
        // Connection points, cached per snapshot and extractor version.
        const cached = store.get<{ connections_ref: string }>(
          `SELECT connections_ref FROM repo_analysis WHERE repository_id = ? AND root_hash = ? AND connections_ref IS NOT NULL ORDER BY created_at DESC LIMIT 1`, repo.id, m.rootHash);
        const hit = cached ? store.artifacts.getJson<{ v: number; indexStatus: string; connections: Connection[] }>(cached.connections_ref) : null;
        let connectionsRef: string;
        let connections: Connection[];
        if (hit && hit.v === CONNECT_VERSION && hit.indexStatus === indexStatus) {
          connectionsRef = cached!.connections_ref;
          connections = hit.connections;
        } else {
          let limit: ConnectLimit | undefined;
          connections = await extractConnections(view, index, signals, { signal, onLimit: (l) => { limit = l; } });
          // A cut at the file limit is kept with the connections and shown by cross_repo_trace.
          connectionsRef = store.artifacts.putJson({ v: CONNECT_VERSION, indexStatus, connections, ...(limit ? { limit } : {}) });
        }
        prepared.push({ repo, rootHash: m.rootHash, root: snap.root, signals, connections, connectionsRef });
        store.update('repository', { id: repo.id }, {
          languages: languagesBySize(m.stats.byLang), modules: signals.modules,
        });
        recordAutoAuditable(store, repo.id, autoAuditable(view));
      } catch (e) {
        fail(repo, null, (e as Error).message);
      }
    }
    linkReferences(prepared.map((p) => ({ name: p.repo.name, signals: p.signals })));
    for (const p of prepared) p.signalsRef = store.artifacts.putJson(p.signals);
    // Matching and topology are deterministic: they run with or without a model.
    if (!signal.aborted) {
      const conns = prepared.flatMap((p) => p.connections);
      const { matches, mappings } = matchConnections(conns, prepared.map((p) => ({ repo: p.repo.name, appNames: p.signals.appNames })), serviceMappings(store, projectId));
      store.update('project_analysis', { id: analysisId }, { matches_ref: store.artifacts.putJson({ matches, mappings }) });
      rebuildTopology(store, projectId, analysisId, conns, matches);
    }

    // 2. Model part (light model, cached).
    const model = signal.aborted ? null : roleModel(store, deps.hub);
    const modelKey = model ? `${model.provider}/${model.model}` : null;
    const usage: UsageDelta = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0, cost: 0 };
    let reason: string | null = model ? null : signal.aborted ? 'cancelled' : 'model_not_configured';
    const addUsage = (u: UsageDelta) => { for (const k of ['input', 'output', 'cacheRead', 'cacheWrite', 'total', 'cost'] as const) usage[k] += u[k]; };
    const judgeOne = async (p: Prepared): Promise<void> => {
      const base = { analysis_id: analysisId, repository_id: p.repo.id, root_hash: p.rootHash, signals_ref: p.signalsRef, connections_ref: p.connectionsRef };
      if (!model || signal.aborted) {
        results.set(p.repo.id, 'skipped');
        store.insert('repo_analysis', { id: newId('repoAnalysis'), ...base, status: 'skipped', error: reason });
        return;
      }
      // a role judged under prompt overrides is not reused under other prompts (defaults keep the old keys).
      const prompts = currentPrompts().hash;
      const cacheKey = sha256Hex(canonicalJson({ signals: p.signals, model: modelKey, v: ROLE_PROMPT_VERSION, ...(prompts !== DEFAULT_PROMPTS_HASH ? { prompts } : {}) }));
      const hit = store.get<{ result_ref: string }>(`SELECT result_ref FROM repo_analysis WHERE cache_key = ? AND status IN ('succeeded','reused') AND result_ref IS NOT NULL ORDER BY created_at DESC LIMIT 1`, cacheKey);
      let resultRef: string;
      let status: 'succeeded' | 'reused';
      const mine: UsageDelta = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0, cost: 0 };
      if (hit) {
        resultRef = hit.result_ref;
        status = 'reused';
      } else {
        try {
          const judgement = await judge(deps, model, p.repo.name, p.signals, p.root, signal, mine);
          const out: RepoRoleOutput = { repositoryId: p.repo.id, rootHash: p.rootHash, model: modelKey!, judgement };
          resultRef = store.artifacts.putJson(out);
          status = 'succeeded';
        } catch (e) {
          results.set(p.repo.id, 'failed');
          store.insert('repo_analysis', { id: newId('repoAnalysis'), ...base, status: 'failed', cache_key: cacheKey, error: (e as Error).message.slice(0, 500), tokens_in: mine.input, tokens_out: mine.output });
          addUsage(mine);
          return;
        }
      }
      addUsage(mine);
      const out = store.artifacts.getJson<RepoRoleOutput>(resultRef);
      results.set(p.repo.id, status);
      store.tx(() => {
        store.insert('repo_analysis', { id: newId('repoAnalysis'), ...base, status, result_ref: resultRef, cache_key: cacheKey, tokens_in: mine.input, tokens_out: mine.output });
        // A role the user set stays (user correction overrides AI).
        const cur = store.get<{ role_source: string; role: string }>('SELECT role_source, role FROM repository WHERE id = ?', p.repo.id)!;
        if (!(cur.role_source === 'user' && cur.role !== 'unknown')) store.update('repository', { id: p.repo.id }, { role: primaryRole(out.judgement), role_source: 'ai' });
      });
    };
    // Judgements are independent: run them concurrently within the configured model concurrency.
    const queue = [...prepared];
    const workers = Array.from({ length: Math.max(1, Math.min(store.config.concurrency.modelRequests, queue.length)) }, async () => {
      for (let p = queue.shift(); p; p = queue.shift()) await judgeOne(p);
    });
    await Promise.all(workers);
    if (signal.aborted) reason = 'cancelled';
    const states = [...results.values()];
    const status = signal.aborted ? 'interrupted' : states.length > 0 && states.every((s) => s === 'failed') ? 'failed' : states.every((s) => s === 'succeeded' || s === 'reused') ? 'succeeded' : 'partial';
    const cost = model ? costMicros(store.config.pricing[modelKey!], usage) : 0;
    store.update('project_analysis', { id: analysisId }, {
      status, model: modelKey, reason, tokens_in: usage.input, tokens_out: usage.output, cost_micros: usage.total > 0 ? cost : 0, ended_at: Date.now(),
    });
  } catch (e) {
    store.update('project_analysis', { id: analysisId }, { status: 'failed', reason: (e as Error).message.slice(0, 500), ended_at: Date.now() });
  }
}

/** with the prompt overrides of the project. */
export async function runAnalysis(deps: AnalysisDeps, projectId: string, analysisId: string, signal: AbortSignal): Promise<void> {
  return withLivePrompts(deps.store, projectId, () => runAnalysisInner(deps, projectId, analysisId, signal), 'repo_analysis', analysisId);
}
