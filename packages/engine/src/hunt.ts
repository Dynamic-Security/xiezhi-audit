// Risk hunts (risk_hunt / risk_hunt_target). A basis is drafted
// by AI from a skill, a prompt or 1Day/CVE intel and confirmed by the user; a hunt covers one or more
// projects (or all), and runs as one scene=risk_hunt audit per project. Verdicts are per repository and
// summed per project and per hunt; a rerun on the same basis is compared with the previous hunt.
import {
  auditBudget, AppError, auditLanguageLabels, basisPatternIssues, AuditStrategy, canonicalJson, check, checkStrategy, HuntBasis, mergeStrategy, newId, sceneDefaults, sha256Hex, type HuntBasisKind, type ModelRef,
} from '@xiezhi/contracts';
import { boundaryDeclaration, newNonce, startSession, wrapUntrusted, type AuditTool, type ModelHub } from '@xiezhi/agent';
import { locateRiskCandidates, SnapshotView, type Executor } from '@xiezhi/context';
import { scanLayer } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';
import { listRepositories, modelDefaults, withConnectors } from './services.js';
import { pool } from './pool.js';
import { recordSnapshot, snapshotSource } from './sources.js';
import { P } from '@xiezhi/knowledge';
import { withLivePrompts } from './prompts.js';

export type BasisInput = { kind: 'skill'; skill: string } | { kind: 'prompt'; text: string } | { kind: 'intel'; text: string };

export interface BasisRow { id: string; kind: HuntBasisKind; title: string; input_ref: string; basis_ref: string | null; skill_name: string | null; status: string; error: string | null; revision: number; model: string | null; tokens: number; usage?: string | null; created_at: number; updated_at: number }

export function getBasis(store: Store, id: string): BasisRow {
  const b = store.get<BasisRow>('SELECT * FROM hunt_basis WHERE id = ?', id);
  if (!b) throw new AppError('COMMON_NOT_FOUND', `basis ${id}`);
  return b;
}

/** Create a basis draft; `draftBasis` organizes it with the audit model. */
export function createBasis(store: Store, input: BasisInput): string {
  let title: string;
  let skillName: string | null = null;
  let raw: Record<string, unknown>;
  if (input.kind === 'skill') {
    const skill = scanLayer(store.paths.knowledgeGlobal, 'global').skills.find((s) => s.name === input.skill);
    if (!skill) throw new AppError('COMMON_NOT_FOUND', `skill ${input.skill}`);
    title = skill.description.slice(0, 120) || skill.name;
    skillName = skill.name;
    raw = { kind: 'skill', name: skill.name, description: skill.description, category: skill.category, body: skill.body.slice(0, 20_000) };
  } else {
    const text = input.text.trim();
    if (!text) throw new AppError('COMMON_VALIDATION', 'basis text is empty');
    if (text.length > 30_000) throw new AppError('COMMON_VALIDATION', 'basis text is longer than 30000 characters');
    title = text.split('\n')[0]!.slice(0, 120);
    raw = { kind: input.kind, text };
  }
  const id = newId('huntBasis');
  store.insert('hunt_basis', { id, kind: input.kind, title, input_ref: store.artifacts.putJson(raw), skill_name: skillName, status: 'drafting' });
  return id;
}

/** Organize a basis draft with the audit model (BasisSource.fetch). No network fetch of links. */
async function draftBasisInner(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const b = getBasis(store, id);
  let model: ModelRef;
  try {
    model = modelDefaults(store.config).defaultModel;
  } catch (e) {
    store.update('hunt_basis', { id }, { status: 'failed', error: (e as Error).message.slice(0, 500) });
    return;
  }
  const raw = store.artifacts.getJson<Record<string, unknown>>(b.input_ref);
  const nonce = newNonce();
  const tool: AuditTool = { name: 'submit_hunt_basis', kind: 'submit', parameters: HuntBasis, description: P('tool.submit_hunt_basis'), validate: (a: HuntBasis) => basisPatternIssues(a), run: () => ({ text: 'basis recorded' }) };
  const source = raw.kind === 'skill' ? `知识库 skill「${String(raw.name)}」（${String(raw.category)}）` : raw.kind === 'intel' ? P('hunt_basis.source_intel') : '用户描述的风险';
  const usage = { total: 0, input: 0, output: 0, cacheRead: 0 };
  try {
    const outcome = await startSession({
      hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
      systemPrompt: [P('role.hunt_basis'), boundaryDeclaration(nonce)].join('\n\n'),
      prompt: [P('hunt_basis.guide'), '', `来源：${source}`, wrapUntrusted(nonce, 'user_upload', `basis:${raw.kind}`, JSON.stringify(raw, null, 1))].join('\n'),
      tools: [tool], requiredSubmits: ['submit_hunt_basis'], maxTurns: 4, signal,
      onUsage: (u) => { usage.total += u.total; usage.input += u.input; usage.output += u.output; usage.cacheRead += u.cacheRead; return 'continue'; },
    }).outcome;
    const basis = (outcome.submissions.submit_hunt_basis as HuntBasis[] | undefined)?.at(-1);
    if (!basis) throw new Error(`the model did not submit a basis (${outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
    store.update('hunt_basis', { id }, { status: 'ready', basis_ref: store.artifacts.putJson(basis), title: basis.title, model: `${model.provider}/${model.model}`, tokens: usage.total, usage: { input: usage.input, output: usage.output, cacheRead: usage.cacheRead }, error: null });
  } catch (e) {
    store.update('hunt_basis', { id }, { status: 'failed', error: (e as Error).message.slice(0, 500), tokens: usage.total, usage: { input: usage.input, output: usage.output, cacheRead: usage.cacheRead } });
  }
}

/** User edit of the organized basis (optimistic revision). */
export function updateBasis(store: Store, id: string, revision: number, basis: unknown): BasisRow {
  const b = getBasis(store, id);
  if (b.revision !== revision) throw new AppError('COMMON_REVISION_CONFLICT', `basis revision is ${b.revision}`);
  const r = check(HuntBasis, basis);
  if (!r.ok) throw new AppError('COMMON_VALIDATION', r.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; '));
  const broad = basisPatternIssues(r.value as HuntBasis);
  if (broad.length) throw new AppError('COMMON_VALIDATION', broad.slice(0, 3).join('; '));
  store.update('hunt_basis', { id }, { basis_ref: store.artifacts.putJson(r.value), title: (r.value as HuntBasis).title, status: 'ready', revision: b.revision + 1, error: null });
  return getBasis(store, id);
}

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
}

/**
 * The skill text for a basis (后续动作): vuln_case or audit_method with the features and
 * conditions as the body. It becomes a global knowledge draft that the user approves.
 */
export function basisSkillText(store: Store, id: string, opts: { name?: string; category: 'vuln_case' | 'audit_method' }): { name: string; text: string; title: string } {
  const b = getBasis(store, id);
  if (!b.basis_ref) throw new AppError('COMMON_VALIDATION', 'the basis is not ready');
  const basis = store.artifacts.getJson<HuntBasis>(b.basis_ref);
  const name = opts.name ? slug(opts.name) : `hunt-${slug(basis.title) || b.id.slice(-8).toLowerCase()}`;
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(name)) throw new AppError('COMMON_VALIDATION', 'skill name must be lowercase letters, digits and dashes');
  const f = basis.features;
  const yamlStr = (s: string) => JSON.stringify(s.replace(/\n/g, ' ').slice(0, 300));
  const text = [
    '---', `name: ${name}`, `description: ${yamlStr(`${basis.title}：${basis.summary}`)}`, `category: ${opts.category}`, 'scope: global',
    ...(basis.category ? ['applies_to:', `  vuln_classes: [${basis.category}]`] : []), `source: ${yamlStr(`hunt-basis:${b.id}`)}`, '---',
    `# ${basis.title}`, '', basis.summary, '',
    ...(f.dependencies.length ? ['## 受影响组件', ...f.dependencies.map((d) => `- ${d.ecosystem} \`${d.name}\` ${d.affectedVersions}${d.fixedVersion ? `（修复版本 ${d.fixedVersion}）` : ''}`), ''] : []),
    ...(f.apis.length ? ['## 危险 API', ...f.apis.map((a) => `- \`${a.pattern}\`：${a.description}`), ''] : []),
    ...(f.codePatterns.length ? ['## 代码特征', ...f.codePatterns.map((p) => `- ${p.description}${p.grep ? `（grep: \`${p.grep}\`）` : ''}`), ''] : []),
    '## 成立条件', ...basis.affectedIf.map((x) => `- ${x}`), '', '## 不成立条件', ...basis.notAffectedIf.map((x) => `- ${x}`), '',
    '## 修复方式', basis.remediation, '', ...(basis.references.length ? ['## 参考', ...basis.references.map((r) => `- ${r}`), ''] : []),
  ].join('\n');
  return { name, text, title: basis.title };
}

// ---- hunts ------------------------------------------------------------------------------------------------

export interface HuntRow { id: string; title: string; basis_id: string | null; basis_kind: HuntBasisKind; basis_ref: string; basis_hash: string; skill_name: string | null; scope: string; rerun_of_id: string | null; status: string; summary: string; precheck: string | null; started_at: number | null; ended_at: number | null; created_at: number; updated_at: number }
export interface HuntScopeSpec { projectIds?: string[]; all?: boolean }

export function getHunt(store: Store, id: string): HuntRow {
  const h = store.get<HuntRow>('SELECT * FROM risk_hunt WHERE id = ?', id);
  if (!h) throw new AppError('COMMON_NOT_FOUND', `hunt ${id}`);
  return h;
}

function scopeProjects(store: Store, scope: HuntScopeSpec): { id: string; name: string }[] {
  const active = store.all<{ id: string; name: string }>(`SELECT id, name FROM project WHERE status = 'active' ORDER BY name`);
  if (scope.all) return active;
  const ids = [...new Set(scope.projectIds ?? [])];
  if (!ids.length) throw new AppError('COMMON_VALIDATION', 'choose at least one project, or all projects');
  return ids.map((id) => {
    const p = active.find((x) => x.id === id || x.name === id);
    if (!p) throw new AppError('PROJECT_NOT_FOUND', id);
    return p;
  });
}

export function createHunt(store: Store, input: { basisId: string; scope: HuntScopeSpec; title?: string; rerunOf?: string }): string {
  const b = getBasis(store, input.basisId);
  if (b.status !== 'ready' || !b.basis_ref) throw new AppError('COMMON_VALIDATION', 'the basis is not ready; wait for the draft or fix it first');
  scopeProjects(store, input.scope);
  const basis = store.artifacts.getJson<HuntBasis>(b.basis_ref);
  const id = newId('riskHunt');
  store.insert('risk_hunt', {
    id, title: input.title ?? basis.title, basis_id: b.id, basis_kind: b.kind, basis_ref: b.basis_ref, basis_hash: sha256Hex(canonicalJson(basis)),
    skill_name: b.skill_name, scope: input.scope, rerun_of_id: input.rerunOf ?? null, status: 'planned',
  });
  return id;
}

/** Repositories snapshotted and located at the same time during a precheck. */
const PRECHECK_CONCURRENCY = 4;

export interface PrecheckRepo { projectId: string; projectName: string; repoId: string; name: string; candidates: number; truncated: boolean; error: string | null }
export interface HuntPrecheck { status: 'running' | 'done' | 'failed'; repos: PrecheckRepo[]; error?: string }

/** Tokens of one repository judged by AI (real-model hunts: 22k–54k per judged repository). */
const PER_JUDGED = { p50: 25_000, p90: 60_000 };

/** The hunt plan: features, conditions, projects and repositories, estimate. */
export function huntPlan(store: Store, id: string) {
  const h = getHunt(store, id);
  const basis = store.artifacts.getJson<HuntBasis>(h.basis_ref);
  const projects = scopeProjects(store, fromJson<HuntScopeSpec>(h.scope, {})).map((p) => {
    const repos = listRepositories(store, p.id).map((r) => ({ id: r.id, name: r.name, auditable: !!r.is_auditable, ref: r.default_ref }));
    return { id: p.id, name: p.name, repos };
  });
  const repoCount = projects.reduce((n, p) => n + p.repos.filter((r) => r.auditable).length, 0);
  // Repositories without candidates are settled by rule (no model); only the rest cost tokens.
  // Before the precheck has finished the range spans “all cleared by rule” to “all judged”.
  const pre = fromJson<HuntPrecheck | null>(h.precheck, null);
  const judgedRepos = pre?.status === 'done' ? pre.repos.filter((r) => r.candidates > 0 || r.error) : null;
  const judged = judgedRepos?.length ?? repoCount;
  const tokens = judgedRepos ? { p50: PER_JUDGED.p50 * judged, p90: PER_JUDGED.p90 * judged } : { p50: 0, p90: PER_JUDGED.p90 * repoCount };
  return {
    basis, projects,
    estimate: {
      repositories: repoCount, tokens,
      durationSec: { p50: 20 + (judgedRepos ? 45 * judged : 0), p90: 60 + 150 * judged },
      precheck: {
        status: pre?.status ?? 'none', judged: judgedRepos ? judged : 0, cleared: judgedRepos ? repoCount - judged : 0,
        repos: (pre?.repos ?? []).map((r) => ({ project: r.projectName, name: r.name, candidates: r.candidates, error: r.error })),
      },
    },
  };
}

/**
 * Deterministic precheck before confirmation: snapshot each auditable repository at its
 * default ref and run the same locate as the hunt, so the plan says how many repositories need an AI
 * judgement. No model is called; the hunt itself locates again on the snapshots it pins.
 */
export async function precheckHunt(deps: { store: Store; executor: Executor; allowFileRemotes?: boolean }, id: string, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const h = getHunt(store, id);
  const basis = store.artifacts.getJson<HuntBasis>(h.basis_ref);
  const work = scopeProjects(store, fromJson<HuntScopeSpec>(h.scope, {})).flatMap((p) => listRepositories(store, p.id).filter((r) => r.is_auditable).map((repo) => ({ p, repo })));
  // Repositories finish out of order; progress is saved in scope order.
  const finished: (PrecheckRepo | undefined)[] = [];
  const save = (status: HuntPrecheck['status'], error?: string) => {
    const repos = finished.filter((r): r is PrecheckRepo => !!r);
    store.update('risk_hunt', { id }, { precheck: { status, repos, ...(error ? { error } : {}) } satisfies HuntPrecheck });
  };
  save('running');
  // Anything that escapes the per-repository catch ends the precheck as failed, never left at `running`.
  try {
    await pool(work, PRECHECK_CONCURRENCY, async ({ p, repo }, index) => {
      if (signal.aborted) return;
      const row: PrecheckRepo = { projectId: p.id, projectName: p.name, repoId: repo.id, name: repo.name, candidates: 0, truncated: false, error: null };
      try {
        const snap = await snapshotSource(store, deps.executor, repo, repo.default_ref, { allowFileRemotes: !!deps.allowFileRemotes, signal });
        const manifestRef = store.artifacts.putJson(snap.manifest);
        store.tx(() => recordSnapshot(store, repo.id, snap.manifest, manifestRef));
        const view = new SnapshotView(repo.name, snap.root, snap.manifest);
        const r = await locateRiskCandidates({ views: new Map([[repo.name, view]]), defaultRepo: repo.name, executor: deps.executor, artifacts: store.artifacts, auditArtifacts: new Set(), signal }, [repo.name], basis);
        row.candidates = r.candidates.length;
        row.truncated = r.truncated;
      } catch (e) {
        row.error = (e as Error).message.slice(0, 200);
      }
      if (signal.aborted) return;
      finished[index] = row;
      save('running');
    });
  } catch (e) {
    save('failed', (e as Error).message.slice(0, 200));
    return;
  }
  if (signal.aborted) save('failed', 'stopped');
  else save('done');
}

/** Confirm (`/hunts/{hid}/confirm`): one scene=risk_hunt audit per project with auditable repositories. */
export function confirmHunt(store: Store, knownModels: Set<string>, id: string, origin: 'cli' | 'ui' | 'conversation'): string[] {
  const h = getHunt(store, id);
  if (h.status !== 'planned') {
    return store.all<{ audit_id: string }>('SELECT DISTINCT audit_id FROM risk_hunt_target WHERE risk_hunt_id = ? AND audit_id IS NOT NULL', id).map((r) => r.audit_id);
  }
  const models = modelDefaults(store.config);
  const basis = store.artifacts.getJson<HuntBasis>(h.basis_ref);
  const system = sceneDefaults('risk_hunt', models);
  const settingsLayer = (store.config.sceneDefaults as Record<string, Record<string, unknown> | undefined>).risk_hunt;
  const merged = mergeStrategy(system, settingsLayer, h.skill_name ? { knowledge: { include: [h.skill_name], exclude: [] } } : undefined);
  const schema = check(AuditStrategy, merged.strategy);
  if (!schema.ok) throw new AppError('STRATEGY_INVALID', schema.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; '));
  const issues = checkStrategy(merged.strategy, 'risk_hunt', knownModels);
  if (issues.length) throw new AppError('STRATEGY_INVALID', issues.map((i) => `${i.path}: ${i.message}`).join('; '));
  const s = merged.strategy;
  const budget = auditBudget(s);
  const auditIds: string[] = [];
  store.tx(() => {
    for (const p of scopeProjects(store, fromJson<HuntScopeSpec>(h.scope, {}))) {
      const repos = listRepositories(store, p.id);
      const auditable = repos.filter((r) => r.is_auditable);
      if (!auditable.length) {
        // Nothing to hunt in: recorded as not affected by rule (no source in an audit language).
        store.insert('risk_hunt_target', { id: newId('huntTarget'), risk_hunt_id: id, project_id: p.id, repository_id: null, audit_id: null, verdict: 'not_affected', reason: `项目中没有可审计（${auditLanguageLabels()}）的仓库`, verdict_source: 'rule' });
        continue;
      }
      const aid = newId('audit');
      store.insert('audit', {
        id: aid, project_id: p.id, scene: 'risk_hunt', mode: auditable.length > 1 ? 'multi' : 'single', title: `风险排查：${basis.title}`.slice(0, 200),
        status: 'planning', strategy_draft: withConnectors(store, p.id, s, undefined), strategy_sources: merged.sources,
        scope: { include: s.scope.include, exclude: s.scope.exclude, focus: s.focus, hunt: { id, basisRef: h.basis_ref } },
        budget_initial: budget, budget_effective: budget, budget_consumed: { tokens: 0, durationMs: 0, costMicros: 0 }, origin,
      });
      for (const r of repos) {
        store.insert('audit_repository', { audit_id: aid, repository_id: r.id, role_in_audit: r.is_auditable ? 'target' : 'context', requested_ref: r.default_ref });
        if (r.is_auditable) store.insert('risk_hunt_target', { id: newId('huntTarget'), risk_hunt_id: id, project_id: p.id, repository_id: r.id, audit_id: aid });
      }
      store.appendEvent(aid, 'audit.status_changed', { from: null, to: 'planning', reason: `risk hunt ${id}` });
      auditIds.push(aid);
    }
    store.update('risk_hunt', { id }, { status: auditIds.length ? 'running' : 'completed', started_at: Date.now(), ...(auditIds.length ? {} : { ended_at: Date.now() }) });
  });
  refreshHunt(store, id);
  return auditIds;
}

export interface HuntTargetView {
  id: string; projectId: string; projectName: string; repositoryId: string | null; repoName: string | null; auditId: string | null; auditStatus: string | null;
  verdict: 'affected' | 'not_affected' | 'pending' | null; reason: string | null; verdictSource: string | null; delta: string | null; hits: number;
}

export interface HuntSummary { projects: number; repositories: number; affected: number; notAffected: number; pending: number; unfinished: number; projectVerdicts: Record<string, string>; hits: number }

export function huntTargets(store: Store, id: string): HuntTargetView[] {
  return store.all<{ id: string; project_id: string; project_name: string; repository_id: string | null; repo_name: string | null; audit_id: string | null; audit_status: string | null; verdict: HuntTargetView['verdict']; reason: string | null; verdict_source: string | null; delta_vs_previous: string | null }>(
    `SELECT t.id, t.project_id, p.name AS project_name, t.repository_id, r.name AS repo_name, t.audit_id, a.status AS audit_status, t.verdict, t.reason, t.verdict_source, t.delta_vs_previous
     FROM risk_hunt_target t JOIN project p ON p.id = t.project_id LEFT JOIN repository r ON r.id = t.repository_id LEFT JOIN audit a ON a.id = t.audit_id
     WHERE t.risk_hunt_id = ? ORDER BY p.name, r.name`, id).map((t) => ({
    id: t.id, projectId: t.project_id, projectName: t.project_name, repositoryId: t.repository_id, repoName: t.repo_name, auditId: t.audit_id, auditStatus: t.audit_status,
    verdict: t.verdict, reason: t.reason, verdictSource: t.verdict_source, delta: t.delta_vs_previous,
    hits: t.audit_id && t.repository_id ? store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM finding WHERE audit_id = ? AND repository_id = ? AND state = 'canonical'`, t.audit_id, t.repository_id)!.n : 0,
  }));
}

const TERMINAL = ['completed', 'partial', 'failed', 'cancelled'];

/**
 * Verdict change between two hunts: `cleared` only when the risk is now ruled out,
 * `new_affected` on any move into `affected`, `changed` for other moves (e.g. affected → pending).
 */
export function verdictDelta(before: string | null | undefined, after: string | null): 'new' | 'new_affected' | 'cleared' | 'changed' | 'unchanged' {
  if (before === undefined) return 'new';
  if (before === after) return 'unchanged';
  if (after === 'affected') return 'new_affected';
  if (after === 'not_affected' && (before === 'affected' || before === 'pending')) return 'cleared';
  return 'changed';
}

/** Recompute status, summary and the delta against the previous hunt on the same basis. */
export function refreshHunt(store: Store, id: string): HuntSummary {
  const h = getHunt(store, id);
  const targets = huntTargets(store, id);
  // Targets of audits that ended without a verdict (failed / cancelled / declined budget) are pending.
  for (const t of targets) {
    if (!t.verdict && t.auditStatus && TERMINAL.includes(t.auditStatus)) {
      store.update('risk_hunt_target', { id: t.id }, { verdict: 'pending', reason: `排查未完成（审计 ${t.auditStatus}）`, verdict_source: 'rule' });
      t.verdict = 'pending';
    }
  }
  const projectVerdicts: Record<string, string> = {};
  for (const t of targets) {
    const cur = projectVerdicts[t.projectId];
    const v = t.verdict ?? 'unfinished';
    const rank = { affected: 3, pending: 2, unfinished: 1, not_affected: 0 } as Record<string, number>;
    if (cur === undefined || (rank[v] ?? 0) > (rank[cur] ?? 0)) projectVerdicts[t.projectId] = v;
  }
  const summary: HuntSummary = {
    projects: new Set(targets.map((t) => t.projectId)).size, repositories: targets.filter((t) => t.repositoryId).length,
    affected: targets.filter((t) => t.verdict === 'affected').length, notAffected: targets.filter((t) => t.verdict === 'not_affected').length,
    pending: targets.filter((t) => t.verdict === 'pending').length, unfinished: targets.filter((t) => !t.verdict).length, projectVerdicts,
    hits: targets.reduce((n, t) => n + t.hits, 0),
  };
  const audits = [...new Set(targets.map((t) => t.auditId).filter((x): x is string => !!x))].map((aid) => store.get<{ status: string }>('SELECT status FROM audit WHERE id = ?', aid)!.status);
  let status = h.status;
  if (h.status === 'running' && audits.every((s) => TERMINAL.includes(s))) {
    status = audits.every((s) => s === 'completed') ? 'completed' : audits.every((s) => s === 'cancelled') ? 'cancelled' : audits.some((s) => s === 'completed' || s === 'partial') ? 'partial' : 'failed';
  }
  // Delta vs the previous hunt (排查记录): new_affected / cleared / unchanged / new.
  if (h.rerun_of_id && summary.unfinished === 0) {
    const prev = new Map(huntTargets(store, h.rerun_of_id).map((t) => [`${t.projectId}|${t.repositoryId ?? ''}`, t.verdict]));
    for (const t of targets) {
      const before = prev.get(`${t.projectId}|${t.repositoryId ?? ''}`);
      const delta = verdictDelta(before, t.verdict);
      if (t.delta !== delta) store.update('risk_hunt_target', { id: t.id }, { delta_vs_previous: delta });
    }
  }
  store.update('risk_hunt', { id }, { summary, status, ...(status !== h.status && TERMINAL.includes(status) ? { ended_at: Date.now() } : {}) });
  return summary;
}

/** Same basis and scope again (e.g. after fixes); compared with this one when it ends. */
export function rerunHunt(store: Store, id: string): string {
  const h = getHunt(store, id);
  if (!h.basis_id) throw new AppError('COMMON_VALIDATION', 'the basis of this hunt was deleted');
  return createHunt(store, { basisId: h.basis_id, scope: fromJson<HuntScopeSpec>(h.scope, {}), title: h.title, rerunOf: id });
}

/** Rename a hunt (sidebar menu). */
export function renameHunt(store: Store, id: string, title: string): HuntRow {
  getHunt(store, id);
  const t = title.trim();
  if (!t) throw new AppError('COMMON_VALIDATION', '标题不能为空');
  store.update('risk_hunt', { id }, { title: t.slice(0, 200) });
  return getHunt(store, id);
}

/**
 * Delete a hunt record: the hunt, its per-repository verdicts with their evidence and push records.
 * The scene=risk_hunt audits it ran in each project and vulnerabilities promoted from its hits stay: they are
 * ordinary audit / vulnerability history. A running hunt must end (or be cancelled) first.
 */
export function deleteHunt(store: Store, id: string): void {
  refreshHunt(store, id);
  const h = getHunt(store, id);
  if (h.status === 'running') throw new AppError('INVALID_TRANSITION', '排查进行中，结束或取消后才能删除');
  store.tx(() => {
    store.db.run(`DELETE FROM evidence WHERE owner_kind = 'risk_hunt_target' AND owner_id IN (SELECT id FROM risk_hunt_target WHERE risk_hunt_id = ?)`, id);
    store.db.run(`DELETE FROM sync_record WHERE local_kind = 'risk_hunt_target' AND local_id IN (SELECT id FROM risk_hunt_target WHERE risk_hunt_id = ?)`, id);
    store.db.run('DELETE FROM risk_hunt WHERE id = ?', id);
  });
}

export function compareHunts(store: Store, id: string, withId: string) {
  const a = new Map(huntTargets(store, withId).map((t) => [`${t.projectId}|${t.repositoryId ?? ''}`, t]));
  return huntTargets(store, id).map((t) => {
    const before = a.get(`${t.projectId}|${t.repositoryId ?? ''}`);
    return { projectName: t.projectName, repoName: t.repoName, before: before?.verdict ?? null, after: t.verdict, change: verdictDelta(before ? before.verdict : undefined, t.verdict) };
  });
}

/** Human override of a repository verdict (人工可改判). */
export function overrideHuntTarget(store: Store, targetId: string, verdict: 'affected' | 'not_affected' | 'pending', reason: string): void {
  const t = store.get<{ risk_hunt_id: string; audit_id: string | null }>('SELECT risk_hunt_id, audit_id FROM risk_hunt_target WHERE id = ?', targetId);
  if (!t) throw new AppError('COMMON_NOT_FOUND', targetId);
  if (!reason.trim()) throw new AppError('VULN_REASON_REQUIRED', 'a reason is required to change a verdict');
  store.update('risk_hunt_target', { id: targetId }, { verdict, reason: reason.slice(0, 1000), verdict_source: 'human' });
  if (t.audit_id) store.appendEvent(t.audit_id, 'judgement.made', { kind: 'risk_verdict_override', target: targetId, verdict, reason: reason.slice(0, 300) });
  refreshHunt(store, t.risk_hunt_id);
}

/** risk-hunt bases span projects — the global prompt overrides. */
export async function draftBasis(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  return withLivePrompts(deps.store, null, () => draftBasisInner(deps, id, signal), 'risk_basis', id);
}
