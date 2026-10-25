// profile: project profile + threat model for the target repository. Cacheable by
// rootHash through the step idempotency key (a key hit on a succeeded step of another
// audit is reused as `skipped`, no model call). On a new version of a repository that was profiled
// before, the previous profile and the changed files are given to the model to update it.
import { stageModel, SubmitProfile, SubmitSystemModel, type SnapshotManifest, type SubmitProfile as Profile } from '@xiezhi/contracts';
import { diffManifests } from '@xiezhi/context';
import type { AuditTool } from '@xiezhi/agent';
import type { AuditRuntime, RepoInfo } from '../runtime.js';
import { getStep, transitionStep, type StepRow } from '../state.js';
import { sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { surfaceOn, validateSurface } from '../surface.js';
import { P } from '@xiezhi/knowledge';

/** Bump when the profile prompt or schema changes: old cached profiles are then not reused. */
// 2: with several targets the session stays in its own repository (earlier profiles traced all).
// 3: the profile is its own session with its own role (no longer combined with the threat model).
export const PROFILE_PROMPT_VERSION = 3;

export interface ProfileOutput {
  repositoryId: string;
  rootHash: string;
  profile: Profile;
  /** Set when this profile updated an earlier one of the same repository. */
  updatedFrom?: { rootHash: string; changedFiles: number };
}

/**
 * The cross-repository system model of a multi-repository audit — a `profile` step with lineage SYSTEM (no new
 * step kind), written once after the per-repository profiles. Cached by the profiles it read.
 */
export interface SystemModelOutput {
  system: true;
  repositoryIds: string[];
  model: SubmitSystemModel;
}

export const SYSTEM_LINEAGE = 'SYSTEM';
/** Bump when the system prompt or schema changes. */
export const SYSTEM_PROMPT_VERSION = 1;

export const isSystemModel = (o: unknown): o is SystemModelOutput => !!o && typeof o === 'object' && (o as { system?: unknown }).system === true;

export function systemIdentity(rt: AuditRuntime, profileRefs: string[]) {
  const m = stageModel(rt.strategy, 'profile')!;
  return { system: true, repos: rt.targets.map((r) => r.id), profiles: profileRefs, model: `${m.provider}/${m.model}`, v: SYSTEM_PROMPT_VERSION };
}

/** The system session: reads every repository's profile, traces the calls between them and submits the system model. */
export async function systemModelStep(rt: AuditRuntime, ctx: AttemptContext, profiles: ProfileOutput[]): Promise<StepResult> {
  const submit: AuditTool = {
    name: 'submit_system_model', kind: 'submit', parameters: SubmitSystemModel,
    description: P('tool.submit_system_model'),
    run: () => ({ text: 'system model recorded' }),
  };
  const nameOf = (id: string) => rt.repos.find((r) => r.id === id)?.name ?? id;
  const lines = [
    P('system.intro'),
    '',
    `目标仓库：${rt.targets.map((r) => r.name).join('、')}。`,
    ...profiles.flatMap((o) => ['', `### 仓库 ${nameOf(o.repositoryId)} 的画像`, renderThreatModel(o.profile, 3000)]),
    '',
    P('system.submit'),
  ];
  const model = stageModel(rt.strategy, 'profile')!;
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'profile', phase: 'profile', model, signal: ctx.signal,
    prompt: lines.join('\n'), submitTools: [submit], requiredSubmits: ['submit_system_model'], serviceCards: true,
    maxTurns: Math.min(40, rt.strategy.limits.maxTurnsPerStep),
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const out: SystemModelOutput = { system: true, repositoryIds: rt.targets.map((r) => r.id), model: (outcome.submissions.submit_system_model as SubmitSystemModel[]).at(-1)! };
  return { outputRef: rt.store.artifacts.putJson(out) };
}

/** This audit's cross-repository system model, or null (single repository, or the system session failed). */
export function auditSystemModel(rt: Pick<AuditRuntime, 'store' | 'auditId'>): SubmitSystemModel | null {
  const row = rt.store.get<{ output_ref: string }>(
    `SELECT output_ref FROM step WHERE audit_id = ? AND kind = 'profile' AND lineage_id = ? AND status IN ('succeeded','skipped') AND output_ref IS NOT NULL ORDER BY seq DESC LIMIT 1`, rt.auditId, SYSTEM_LINEAGE);
  const out = row ? rt.store.artifacts.getJson<unknown>(row.output_ref) : null;
  return isSystemModel(out) ? out.model : null;
}

/** The system model for the system prompt, once (not per repository). */
export function renderSystemModel(m: SubmitSystemModel, nameOf: (repo: string) => string = (r) => r, maxChars = 3000): string {
  const text = [
    m.summary,
    ...(m.flows?.length ? ['**服务间调用**', ...m.flows.map((f) => `- ${nameOf(f.from)} → ${nameOf(f.to)}（${f.via}）：携带 ${f.carries}；校验：${f.check}`)] : []),
    ...(m.trustBoundaries?.length ? ['**服务间信任边界**', ...m.trustBoundaries.map((b) => `- ${b.name}（${b.repos.join('、')}）：${b.description}`)] : []),
    ...(m.risks?.length ? ['**跨服务风险线索（未经验证）**', ...m.risks.map((r) => `- ${r.title}（${r.repos.join('、')}）：${r.statement}`)] : []),
    ...(m.assumptions?.length ? ['**前提假设（未经代码核实）**', ...m.assumptions.map((a) => `- ${a}`)] : []),
  ].filter(Boolean).join('\n');
  return text.length > maxChars ? `${text.slice(0, maxChars)}\n…（已截断）` : text;
}

export function profileIdentity(rt: AuditRuntime, repo: RepoInfo = rt.targetRepo) {
  const m = stageModel(rt.strategy, 'profile')!;
  // a profile asked for the attack surface is a different output; the others are not reused for it.
  return { repo: repo.id, root: repo.rootHash, model: `${m.provider}/${m.model}`, v: PROFILE_PROMPT_VERSION, ...(surfaceOn(rt) ? { surface: true } : {}) };
}

/**
 * Reuse a succeeded profile step of another audit with the same idempotency key. Returns true when
 * this audit's step was settled as `skipped` with `reused_from`.
 */
export function reuseProfile(rt: AuditRuntime, row: StepRow): boolean {
  const hit = rt.store.get<{ id: string; output_ref: string }>(
    `SELECT id, output_ref FROM step WHERE kind = 'profile' AND idempotency_key = ? AND audit_id != ? AND status IN ('succeeded','skipped') AND output_ref IS NOT NULL
     ORDER BY created_at DESC LIMIT 1`, row.idempotency_key, rt.auditId);
  if (!hit) return false;
  const current = getStep(rt.store, row.id);
  if (!['pending', 'ready'].includes(current.status)) return false;
  rt.store.tx(() => {
    transitionStep(rt.store, row.id, 'skipped', { output_ref: hit.output_ref, reused_from: hit.id, error_summary: 'reused cached profile' }, 'cache hit');
  });
  return true;
}

/** Latest profile of the same repository at another version, for an incremental update. */
function previousProfile(rt: AuditRuntime, repo: RepoInfo): { out: ProfileOutput; manifest: SnapshotManifest } | null {
  const rows = rt.store.all<{ output_ref: string }>(
    `SELECT output_ref FROM step WHERE kind = 'profile' AND status IN ('succeeded','skipped') AND output_ref IS NOT NULL AND audit_id != ? ORDER BY created_at DESC LIMIT 20`, rt.auditId);
  for (const r of rows) {
    const out = rt.store.artifacts.getJson<ProfileOutput>(r.output_ref);
    if (isSystemModel(out) || out.repositoryId !== repo.id || out.rootHash === repo.rootHash) continue;
    const snap = rt.store.get<{ manifest_ref: string }>('SELECT manifest_ref FROM snapshot WHERE repository_id = ? AND root_hash = ?', out.repositoryId, out.rootHash);
    if (!snap) continue;
    return { out, manifest: rt.store.artifacts.getJson<SnapshotManifest>(snap.manifest_ref) };
  }
  return null;
}

/**
 * `understand`: one system-understanding session writes the profile and the threat model of the
 * repository with the given threat model — a coordinator that does not read code itself (no read / grep) but hands
 * reading to `task` sub-agents and then submits.
 */
export async function profileStep(rt: AuditRuntime, ctx: AttemptContext, repo: RepoInfo = rt.targetRepo): Promise<StepResult> {
  const view = rt.views.get(repo.name)!;
  const idx = rt.indexes.get(repo.name);
  const prev = previousProfile(rt, repo);
  const submit: AuditTool = {
    name: 'submit_profile', kind: 'submit', parameters: SubmitProfile,
    description: P('tool.submit_profile'),
    run: () => ({ text: 'profile recorded' }),
    ...(surfaceOn(rt) ? { validate: (a: Profile) => validateSurface(rt, repo, a.surface) } : {}),
  };
  const lines = [
    P('profile.intro'),
    `仓库：${repo.name}；文件 ${view.manifest.stats.fileCount} 个；语言 ${JSON.stringify(view.manifest.stats.byLang)}。`,
  ];
  if (idx) lines.push(`结构索引：入口 ${idx.entrypoints.length} 个，危险点 ${idx.sinks.length} 个，鉴权信号 ${idx.authSignals.length} 个。`);
  let updatedFrom: ProfileOutput['updatedFrom'];
  if (prev) {
    const c = diffManifests(prev.manifest, view.manifest);
    const changed = [...c.added, ...c.modified, ...c.renamed.map((r) => r.to)];
    updatedFrom = { rootHash: prev.out.rootHash, changedFiles: changed.length + c.deleted.length };
    lines.push(
      '', P('profile.update'),
      `变更文件（${changed.length} 个新增/修改，${c.deleted.length} 个删除）：${changed.slice(0, 80).join('、') || '（无）'}${changed.length > 80 ? ' …' : ''}`,
      '```json', JSON.stringify(prev.out.profile).slice(0, 12_000), '```',
    );
  }
  if (surfaceOn(rt) && idx) {
    // the rules only know some frameworks and APIs; the model fills in what they miss.
    lines.push(
      '', P('profile.surface'),
    );
  }
  lines.push(P('profile.submit'));
  const model = stageModel(rt.strategy, 'profile')!;
  // Tools default to this repository (not the audit's first target); with several targets the
  // session and its sub-agents stay in it — the system session after the profiles spans the repositories.
  const scope = { repo: repo.name, ownRepoOnly: rt.targets.length > 1 };
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'profile', phase: 'profile', model, signal: ctx.signal,
    prompt: lines.join('\n'), submitTools: [submit], requiredSubmits: ['submit_profile'],
    maxTurns: Math.min(surfaceOn(rt) ? 40 : 30, rt.strategy.limits.maxTurnsPerStep),
    ...scope,
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const profile = (outcome.submissions.submit_profile as Profile[]).at(-1)!;
  const out: ProfileOutput = { repositoryId: repo.id, rootHash: repo.rootHash, profile, ...(updatedFrom ? { updatedFrom } : {}) };
  return { outputRef: rt.store.artifacts.putJson(out) };
}

/** Compact text for the system prompt's threat-model section. */
export function renderThreatModel(p: Profile, maxChars = 4000): string {
  // Tolerates profiles stored by older versions without a list (one crashed every later session of its audit).
  const list = <T>(title: string, xs: T[] | undefined, f: (x: T) => string) => (xs?.length ? [`**${title}**`, ...xs.map((x) => `- ${f(x)}`)] : []);
  const text = [
    p.summary,
    p.techStack?.length ? `技术栈：${p.techStack.join('、')}` : '',
    `鉴权模型：${p.authModel}`,
    ...list('信任边界', p.trustBoundaries, (b) => `${b.name}：${b.description}`),
    ...list('资产', p.assets, (a) => `${a.name}（敏感度 ${a.sensitivity}）：${a.description}`),
    ...list('角色', p.roles, (r) => `${r.name}：${r.description}`),
    ...list('外部依赖', p.externalDependencies, (d) => `${d.name}：${d.description}`),
    ...list('前提假设（未经代码核实）', p.assumptions, (a) => a),
  ].filter(Boolean).join('\n');
  return text.length > maxChars ? `${text.slice(0, maxChars)}\n…（已截断）` : text;
}
