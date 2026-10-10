// Project / repository / audit creation services shared by CLI (and later the server).
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import {
  createSnapshot, detectLang, SnapshotView, listRemoteTree, lsRemote, parseGitUrl, RemoteGitError, resolveRemoteRef, SnapshotError, type Executor, type GitCredential, type RemoteAuth, type RemoteUrl,
} from '@xiezhi/context';
import {
  auditBudget, AppError, auditLanguageLabels, auditLanguagesOf, cargoDependencyNames, check, FULLSTACK_DEPENDENCIES, isRustBackend, isFullstackServerPath, isJsBackend, USE_SERVER_DIRECTIVE_RE, normalizePending, AuditStrategy, checkStrategy, mergeStrategy, newId, sceneDefaults, upgradeStrategy, configStageModel, type AppConfig, type ModelDefaults, type ModelRef, type Scene,
} from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { autoAuditable } from './auditable.js';
import { boundContextConnectors } from './connectors.js';
import { checkAuditThreatModels } from './threat-model-audit.js';
import { calibrated } from './calibration.js';
import { estimateStep, RETRY_MARGIN } from './estimates.js';

export interface ProjectRow { id: string; name: string; status: string; next_vuln_no: number; created_at: number }
export interface RepositoryRow { id: string; project_id: string; name: string; source_kind: string; source_uri: string; default_ref: string | null; role: string; role_source: string; is_auditable: number; auditable_source: string; auditable_auto: number | null; auditable_reason: string | null; source_meta: string }
/** repository.source_meta. */
export interface SourceMeta { fileName?: string; rootHash?: string; headCommit?: string; defaultBranch?: string }

export function createProject(store: Store, name: string): ProjectRow {
  if (!/^[\p{L}\p{N}][\p{L}\p{N}._ -]{0,99}$/u.test(name)) throw new AppError('CONFIG_INVALID', 'project name must be 1–100 letters, digits, space, dot, dash or underscore');
  if (store.get('SELECT id FROM project WHERE name = ?', name)) throw new AppError('PROJECT_EXISTS', name);
  const id = newId('project');
  store.insert('project', { id, name, status: 'active' });
  return getProject(store, id);
}

export function getProject(store: Store, idOrName: string): ProjectRow {
  const p = store.get<ProjectRow>('SELECT * FROM project WHERE id = ? OR name = ?', idOrName, idOrName);
  if (!p) throw new AppError('PROJECT_NOT_FOUND', idOrName);
  return p;
}

export function listProjects(store: Store): ProjectRow[] {
  return store.all<ProjectRow>('SELECT * FROM project ORDER BY name');
}

export function listRepositories(store: Store, projectId: string): RepositoryRow[] {
  return store.all<RepositoryRow>('SELECT * FROM repository WHERE project_id = ? AND removed_at IS NULL ORDER BY name', projectId);
}

const REPO_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

function checkNewRepo(store: Store, projectId: string, name: string, ref: string | undefined): void {
  if (!REPO_NAME.test(name)) throw new AppError('CONFIG_INVALID', 'repository name must match [A-Za-z0-9._-]');
  if (store.get('SELECT id FROM repository WHERE project_id = ? AND name = ? AND removed_at IS NULL', projectId, name)) throw new AppError('REPOSITORY_EXISTS', name);
  if (ref !== undefined && (ref.startsWith('-') || /[\s\0]/.test(ref))) throw new AppError('CONFIG_INVALID', 'invalid ref');
}

/** Validate a remote Git URL; AppError with the reason when it is not acceptable. */
export function parseRemote(url: string, allowFile = false): RemoteUrl {
  try {
    return parseGitUrl(url, { allowFile });
  } catch (e) {
    if (e instanceof RemoteGitError) throw new AppError('CONFIG_INVALID', e.message);
    throw e;
  }
}

/** HTTPS credential configured for a host (config.json `gitCredentials[]`). */
export function gitCredentialFor(cfg: AppConfig, host: string): GitCredential | undefined {
  const c = (cfg.gitCredentials ?? []).find((x) => x.host === host.toLowerCase());
  return c?.token ? { username: c.username, token: c.token } : undefined;
}

/** Credentials and transport switches for a remote source. */
export function remoteAuth(cfg: AppConfig, remote: RemoteUrl, allowFileRemotes = false): RemoteAuth {
  return {
    credential: remote.kind === 'https' ? gitCredentialFor(cfg, remote.host) : undefined,
    sshAuthSock: remote.kind === 'ssh' ? process.env.SSH_AUTH_SOCK : undefined,
    allowFileProtocol: allowFileRemotes,
  };
}

export interface AddRepositoryInput {
  /** Local directory (exactly one of path / git). */
  path?: string;
  /** Remote Git URL. */
  git?: string;
  ref?: string;
  name?: string;
  /** From the probe; the first snapshot refreshes languages. */
  auditable?: boolean;
  /** Why the automatic judgement made it a context repository. */
  auditableReason?: string | null;
  languages?: string[];
  defaultBranch?: string | null;
  allowFileRemotes?: boolean;
}

const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', 'target', 'build', 'dist', '.idea', '.gradle', '__pycache__', '.venv', 'venv', 'obj']);

/** Quick language census of a local directory (bounded), for callers that did not probe first. */
export function scanLocalLanguages(root: string, cap = 5000): Record<string, number> {
  const out: Record<string, number> = {};
  let n = 0;
  const walk = (d: string, depth: number) => {
    if (depth > 12 || n > cap) return;
    let entries: import('node:fs').Dirent[];
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (n > cap) return;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(join(d, e.name), depth + 1); continue; }
      n++;
      const lang = detectLang(e.name);
      if (lang) out[lang] = (out[lang] ?? 0) + 1;
    }
  };
  walk(root, 0);
  return out;
}

/**
 * Whether a local directory declares a JS / TS server-side framework in a package.json (bounded walk); a
 * Next.js / Nuxt app counts only with server code (same rule as `auditLanguagesOfView`).
 */
export function scanLocalJsBackend(root: string, cap = 50): boolean {
  const fullstack = { declared: false };
  if (scanPackageJsons(root, cap, fullstack)) return true;
  return fullstack.declared && scanFullstackServerCode(root);
}

function scanFullstackServerCode(root: string, cap = 5000): boolean {
  let found = false;
  let n = 0;
  const walk = (d: string, rel: string, depth: number) => {
    if (found || depth > 10 || n > cap) return;
    let entries: import('node:fs').Dirent[];
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (found) return;
      if (e.isSymbolicLink()) continue;
      const p = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(join(d, e.name), p, depth + 1); continue; }
      if (!/\.[cm]?[jt]sx?$/.test(e.name)) continue;
      n++;
      if (isFullstackServerPath(p)) { found = true; return; }
      try { if (USE_SERVER_DIRECTIVE_RE.test(readFileSync(join(d, e.name), 'utf8').slice(0, 2048))) found = true; } catch { /* unreadable */ }
    }
  };
  walk(root, '', 0);
  return found;
}

function scanPackageJsons(root: string, cap: number, fullstack: { declared: boolean }): boolean {
  let found = false;
  let n = 0;
  const walk = (d: string, depth: number) => {
    if (found || depth > 4 || n > cap) return;
    let entries: import('node:fs').Dirent[];
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (found) return;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(join(d, e.name), depth + 1); continue; }
      if (e.name !== 'package.json') continue;
      n++;
      try {
        const j = JSON.parse(readFileSync(join(d, e.name), 'utf8')) as Record<string, Record<string, unknown> | undefined>;
        const deps = [...Object.keys(j.dependencies ?? {}), ...Object.keys(j.devDependencies ?? {}), ...Object.keys(j.peerDependencies ?? {})];
        found = isJsBackend(deps);
        if (deps.some((d) => (FULLSTACK_DEPENDENCIES as readonly string[]).includes(d))) fullstack.declared = true;
      } catch { /* not JSON */ }
    }
  };
  walk(root, 0);
  return found;
}

/** whether a local directory has a Cargo.toml declaring a Rust server framework (bounded walk). */
export function scanLocalRustBackend(root: string, cap = 50): boolean {
  let found = false;
  let n = 0;
  const walk = (d: string, depth: number) => {
    if (found || depth > 4 || n > cap) return;
    let entries: import('node:fs').Dirent[];
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (found) return;
      if (e.isSymbolicLink()) continue;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(join(d, e.name), depth + 1); continue; }
      if (e.name !== 'Cargo.toml') continue;
      n++;
      try { found = isRustBackend(cargoDependencyNames(readFileSync(join(d, e.name), 'utf8'))); } catch { /* unreadable */ }
    }
  };
  walk(root, 0);
  return found;
}

/**
 * Auditable or context repository from a language census. `jsBackend` / `rustBackend` null = unknown
 * (remote / archive listings have no file contents): a JS / TS- or Rust-only repository stays context until the first
 * analysis decides from package.json / Cargo.toml.
 */
export function auditableFrom(languages: Record<string, number>, jsBackend: boolean | null, rustBackend: boolean | null = null): { auditable: boolean; note: string | null } {
  if (auditLanguagesOf(languages, !!jsBackend, !!rustBackend).length) return { auditable: true, note: null };
  const rust = (languages.rust ?? 0) > 0;
  if (rust && rustBackend === null) return { auditable: false, note: '发现 Rust 源码：是否为服务端将在首次分析时按 Cargo.toml 判定，暂作为上下文仓库' };
  if (rust && !(languages.javascript ?? 0) && !(languages.typescript ?? 0)) return { auditable: false, note: 'Rust 仓库未声明服务端框架依赖（axum、actix-web、Rocket、warp、tonic 等）：按命令行工具或库作为上下文仓库' };
  const js = (languages.javascript ?? 0) + (languages.typescript ?? 0) > 0;
  if (js && jsBackend === null) return { auditable: false, note: '只发现 JavaScript/TypeScript 源码：是否为服务端将在首次分析时按 package.json 判定，暂作为上下文仓库' };
  if (js) return { auditable: false, note: 'JavaScript/TypeScript 仓库未声明服务端框架依赖（express、koa、NestJS、fastify 等），也没有 Next.js / Nuxt 服务端代码：按前端作为上下文仓库' };
  return { auditable: false, note: `未发现可完整审计的源码（${auditLanguageLabels()}）：将作为上下文仓库` };
}

export function addRepository(store: Store, projectId: string, opts: AddRepositoryInput): RepositoryRow {
  if (!!opts.path === !!opts.git) throw new AppError('COMMON_VALIDATION', 'give exactly one of a local path or a Git URL');
  let kind: 'local' | 'git';
  let uri: string;
  let name: string;
  const meta: SourceMeta = {};
  if (opts.path) {
    const abs = resolve(opts.path);
    if (!existsSync(abs) || !statSync(abs).isDirectory()) throw new AppError('REPOSITORY_NOT_FOUND', `not a directory: ${opts.path}`);
    kind = 'local';
    uri = realpathSync(abs);
    name = opts.name ?? basename(uri);
    if (opts.auditable === undefined) {
      const langs = scanLocalLanguages(uri);
      const a = auditableFrom(langs, scanLocalJsBackend(uri), scanLocalRustBackend(uri));
      opts = { ...opts, auditable: a.auditable, auditableReason: a.note, languages: Object.keys(langs).sort() };
    } else if (opts.auditable === false && opts.auditableReason === undefined) {
      // From a probe (server): the probe's verdict stands; record why for the repository list.
      opts = { ...opts, auditableReason: auditableFrom(scanLocalLanguages(uri), scanLocalJsBackend(uri), scanLocalRustBackend(uri)).note };
    }
  } else {
    const remote = parseRemote(opts.git!, opts.allowFileRemotes);
    kind = 'git';
    uri = remote.url;
    name = opts.name ?? remote.suggestedName;
    if (opts.defaultBranch) meta.defaultBranch = opts.defaultBranch;
  }
  checkNewRepo(store, projectId, name, opts.ref);
  const id = newId('repository');
  store.insert('repository', {
    id, project_id: projectId, name, source_kind: kind, source_uri: uri, default_ref: opts.ref ?? null, role: 'unknown', role_source: 'ai',
    auditable_reason: opts.auditableReason ?? null, is_auditable: opts.auditable === false ? 0 : 1, auditable_auto: opts.auditable === false ? 0 : 1, languages: opts.languages ?? [], source_meta: meta,
  });
  return store.get<RepositoryRow>('SELECT * FROM repository WHERE id = ?', id)!;
}

/** User-facing reason for a remote failure (cause plus how to fix it). */
export function remoteProblem(e: RemoteGitError): string {
  switch (e.code) {
    case 'auth': return 'Git 认证失败：HTTPS 地址请在“设置 › Git 凭证”中为该域名配置用户名和 token；SSH 地址请确认本机密钥或 ssh-agent 可用';
    case 'not_found': return '远程仓库不存在，或当前凭证无权访问';
    case 'unreachable': return `无法连接远程仓库：${e.message}`;
    case 'ref_not_found': return `分支、标签或提交不存在（${e.message}）${e.suggestions.length ? `；相近的有：${e.suggestions.join('、')}` : ''}`;
    default: return e.message;
  }
}

export function remoteAppError(e: RemoteGitError): AppError {
  const code = e.code === 'auth' ? 'REPO_AUTH_FAILED' : e.code === 'ref_not_found' ? 'REPO_REF_NOT_FOUND' : e.code === 'invalid_url' ? 'CONFIG_INVALID' : 'REPO_UNREACHABLE';
  return new AppError(code, remoteProblem(e), e.suggestions.length ? { suggestions: e.suggestions } : undefined);
}

export function countLanguages(paths: Iterable<string>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const p of paths) {
    const lang = detectLang(p.split('/').pop()!);
    if (lang) out[lang] = (out[lang] ?? 0) + 1;
  }
  return out;
}

/**
 * Add a remote Git repository: the remote must answer and the ref (if any) must exist now; branches
 * are resolved to a commit again when an audit starts. Languages come from a blob-less
 * listing of that commit; when it cannot be read they are filled by the first snapshot.
 */
export async function addGitRepository(store: Store, executor: Executor, projectId: string, opts: { url: string; ref?: string; name?: string; allowFileRemotes?: boolean; signal?: AbortSignal }): Promise<RepositoryRow> {
  const remote = parseRemote(opts.url, opts.allowFileRemotes);
  checkNewRepo(store, projectId, opts.name ?? remote.suggestedName, opts.ref);
  const auth = remoteAuth(store.config, remote, opts.allowFileRemotes);
  let defaultBranch: string | null;
  let languages: Record<string, number> | null = null;
  try {
    const listing = await lsRemote(executor, remote, auth, opts.signal);
    defaultBranch = listing.defaultBranch;
    const head = resolveRemoteRef(listing, opts.ref);
    try { languages = countLanguages(await listRemoteTree(executor, remote, head.commit, auth, opts.signal)); } catch { /* unknown until the first snapshot */ }
  } catch (e) {
    if (e instanceof RemoteGitError) throw remoteAppError(e);
    throw e;
  }
  return addRepository(store, projectId, {
    git: remote.url, ...(opts.allowFileRemotes ? { allowFileRemotes: true } : {}), defaultBranch, ...(opts.ref ? { ref: opts.ref } : {}), ...(opts.name ? { name: opts.name } : {}),
    ...(languages ? (() => { const a = auditableFrom(languages!, null); return { languages: Object.keys(languages!).sort(), auditable: a.auditable, auditableReason: a.note }; })() : {}),
  });
}

/** Display name of an uploaded file: base name, no control characters, at most 200 characters. */
export function cleanFileName(name: string): string {
  // eslint-disable-next-line no-control-regex -- stripping control characters is the point
  return basename(name.replace(/\\/g, '/')).replace(/[\0-\x1f\x7f]/g, '').slice(0, 200) || 'archive';
}

/**
 * Add an uploaded archive: its content is fixed, so the snapshot is taken now and every
 * audit of this repository reuses it; the upload itself may then expire.
 */
export async function addArchiveRepository(store: Store, executor: Executor, projectId: string, opts: { file: string; fileName: string; name?: string; signal?: AbortSignal }): Promise<RepositoryRow> {
  const fileName = cleanFileName(opts.fileName);
  const name = opts.name ?? (fileName.replace(/\.(zip|tar|tgz|tar\.gz)$/i, '').replace(/[^A-Za-z0-9._-]/g, '-').replace(/^[^A-Za-z0-9]+/, '').slice(0, 100) || 'archive');
  checkNewRepo(store, projectId, name, undefined);
  let result;
  try {
    result = await createSnapshot({ source: { kind: 'archive', file: opts.file, fileName }, snapshotsDir: store.paths.snapshots, tmpDir: store.paths.tmp, executor, ...(opts.signal ? { signal: opts.signal } : {}) });
  } catch (e) {
    if (e instanceof SnapshotError) throw new AppError('ARCHIVE_REJECTED', e.message);
    throw e;
  }
  const m = result.manifest;
  const manifestRef = store.artifacts.putJson(m);
  const langs = Object.keys(m.stats.byLang).sort();
  const judged = autoAuditable(new SnapshotView(name, result.root, m));
  const meta: SourceMeta = { fileName, rootHash: m.rootHash, ...(m.source.commit ? { headCommit: m.source.commit } : {}) };
  const id = newId('repository');
  store.tx(() => {
    store.insert('repository', {
      id, project_id: projectId, name, source_kind: 'archive', source_uri: fileName, default_ref: null, role: 'unknown', role_source: 'ai',
      is_auditable: judged.auditable ? 1 : 0, auditable_auto: judged.auditable ? 1 : 0, auditable_reason: judged.reason, languages: langs, source_meta: meta,
    });
    store.insert('snapshot', {
      id: newId('snapshot'), repository_id: id, root_hash: m.rootHash, manifest_ref: manifestRef, requested_ref: null, resolved_ref_name: null,
      resolved_commit: null, is_worktree: 0, file_count: m.stats.fileCount, bytes: m.stats.totalBytes,
    });
  });
  return store.get<RepositoryRow>('SELECT * FROM repository WHERE id = ?', id)!;
}

export function modelDefaults(cfg: AppConfig): ModelDefaults {
  const first = cfg.modelProviders[0];
  const defaultModel = cfg.defaultModel ?? (first?.models[0] ? { provider: first.id, model: first.models[0].id } : null);
  if (!defaultModel) throw new AppError('MODEL_NOT_CONFIGURED', 'configure modelProviders and defaultModel in config.json');
  return { defaultModel, stageModels: cfg.stageModels ?? {} };
}

/** The model of a non-audit settings stage: `chat` — conversations, knowledge / pack drafting, push, architecture import. */
export function chatModelOf(cfg: AppConfig): ModelRef {
  return configStageModel(cfg, 'chat') ?? modelDefaults(cfg).defaultModel;
}

/**
 * Connectors authorized for a new audit: the task override when it names them (they must
 * exist and be context connectors), otherwise the project's context bindings.
 */
export function withConnectors(store: Store, projectId: string, strategy: AuditStrategy, override: Record<string, unknown> | undefined): AuditStrategy {
  if (override && Array.isArray(override.connectors)) {
    for (const ref of override.connectors as string[]) {
      if (!store.get('SELECT 1 FROM connector WHERE id = ? OR name = ?', ref, ref)) throw new AppError('STRATEGY_INVALID', `connectors: unknown connector ${ref}`);
    }
    return strategy;
  }
  return { ...strategy, connectors: boundContextConnectors(store, projectId) };
}

export interface CreateAuditInput {
  projectId: string;
  scene: Scene;
  /** 审计模式: single (one target, optional related repositories as evidence) or multi (equal targets). */
  mode?: 'single' | 'multi';
  /** single: the target repository (name or id). */
  repository?: string;
  /** single: related repositories (evidence only). */
  related?: string[];
  /** multi: target repositories; default all auditable repositories of the project. */
  repositories?: string[];
  /** Version per repository (name or id) other than the target's `ref`. */
  refs?: Record<string, string>;
  ref?: string;
  title?: string;
  strategyOverride?: Record<string, unknown>;
  origin: 'cli' | 'ui' | 'conversation';
  /** origin=conversation: the conversation the audit was started from (audit.conversation_id). */
  conversationId?: string;
  /** Incremental: compare against this ref of the repository (snapshotted during planning). */
  baseRef?: string;
  /** Incremental: compare against the version this earlier audit reviewed. Default: the latest finished audit. */
  baseAuditId?: string;
  /** Start as soon as the plan is ready (form default and conversation cards); otherwise wait for confirmation. */
  autoStart?: boolean;
}

/**
 * Problems a task strategy override would cause when the audit is created: the same merge and schema
 * check as createAudit, so a conversation card is refused while the model can still fix it, not when the user
 * confirms it. Model availability is left to creation (it may change before confirmation).
 */
export function strategyOverrideIssues(store: Store, scene: Scene, override: Record<string, unknown> | undefined): string[] {
  if (!override) return [];
  try {
    const merged = mergeStrategy(sceneDefaults(scene, modelDefaults(store.config)), (store.config.sceneDefaults as Record<string, Record<string, unknown> | undefined>)[scene], override);
    const schema = check(AuditStrategy, merged.strategy);
    return schema.ok ? [] : schema.issues.slice(0, 5).map((i) => `strategyOverride${i.path.replace(/^\$/, '')} ${i.message}`);
  } catch (e) {
    return [`strategyOverride: ${(e as Error).message}`];
  }
}

/** Latest finished full/incremental audit of the repository in the project (default incremental baseline). */
export function latestBaseline(store: Store, projectId: string, repositoryId: string, exceptAuditId?: string): { auditId: string; snapshotId: string } | null {
  const row = store.get<{ id: string; snapshot_id: string }>(
    `SELECT a.id, ar.snapshot_id FROM audit a JOIN audit_repository ar ON ar.audit_id = a.id
     WHERE a.project_id = ? AND ar.repository_id = ? AND ar.snapshot_id IS NOT NULL AND a.scene IN ('full','incremental')
       AND a.status IN ('completed','partial') AND a.id != ? ORDER BY a.ended_at DESC, a.created_at DESC LIMIT 1`,
    projectId, repositoryId, exceptAuditId ?? '');
  return row ? { auditId: row.id, snapshotId: row.snapshot_id } : null;
}

export interface CreateReverifyInput {
  vulnIds: string[];
  /** Version to verify per repository id; default: the repository's default audit version. */
  refs?: Record<string, string>;
  origin: 'cli' | 'ui' | 'conversation';
  conversationId?: string;
  strategyOverride?: Record<string, unknown>;
  /** User-supplied information for pending vulnerabilities (回答问题). */
  note?: string;
}

/**
 * Reverification: one `scene=reverify` audit for the selected tracked
 * vulnerabilities, targets in `audit.scope.reverify`. Budget scales per vulnerability (
 * 60k tokens each, 600 s + 60 s × N). All targets must be in one repository.
 */
export function createReverifyAudit(store: Store, knownModels: Set<string>, input: CreateReverifyInput): string {
  const ids = [...new Set(input.vulnIds)];
  if (ids.length === 0) throw new AppError('COMMON_VALIDATION', 'no vulnerabilities selected');
  const vulns = ids.map((id) => {
    const v = store.get<{ id: string; project_id: string; repository_id: string; status: string; display_no: number; confirm_status: string; missing_context: string | null }>(
      'SELECT id, project_id, repository_id, status, display_no, confirm_status, missing_context FROM vulnerability WHERE id = ?', id);
    if (!v) throw new AppError('VULN_NOT_FOUND', id);
    if (v.status !== 'active') throw new AppError('COMMON_VALIDATION', `V-${v.display_no} was merged into another vulnerability`);
    return v;
  });
  const projects = new Set(vulns.map((v) => v.project_id));
  const repos = new Set(vulns.map((v) => v.repository_id));
  if (projects.size > 1) throw new AppError('COMMON_VALIDATION', 'vulnerabilities belong to different projects');
  const projectId = vulns[0]!.project_id;
  // One reverification may span repositories: each involved repository is a target.
  const repoRows = [...repos].map((rid) => {
    const repo = store.get<RepositoryRow & { removed_at: number | null }>('SELECT * FROM repository WHERE id = ?', rid)!;
    if (repo.removed_at) throw new AppError('REPOSITORY_NOT_FOUND', repo.name);
    const ref = input.refs?.[repo.id];
    if (ref !== undefined && (ref.startsWith('-') || /[\s\0]/.test(ref) || !ref)) throw new AppError('CONFIG_INVALID', 'invalid ref');
    return { repo, ref };
  });
  const models = modelDefaults(store.config);
  const system = sceneDefaults('reverify', models);
  const n = ids.length;
  system.budget = { ...system.budget, tokens: system.budget.tokens * n, durationSec: Math.max(60, system.budget.durationSec - 60) + 60 * n };
  const settingsLayer = (store.config.sceneDefaults as Record<string, Record<string, unknown> | undefined>).reverify;
  const merged = mergeStrategy(system, settingsLayer, input.strategyOverride);
  merged.strategy = withConnectors(store, projectId, merged.strategy, input.strategyOverride);
  const schema = check(AuditStrategy, merged.strategy);
  if (!schema.ok) throw new AppError('STRATEGY_INVALID', schema.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; '));
  const issues = checkStrategy(merged.strategy, 'reverify', knownModels);
  if (issues.length) throw new AppError('STRATEGY_INVALID', issues.map((i) => `${i.path}: ${i.message}`).join('; '));
  const s = merged.strategy;
  const id = newId('audit');
  const budget = auditBudget(s);
  const nos = vulns.map((v) => v.display_no).sort((a, b) => a - b);
  const title = nos.length <= 5 ? `复验 ${nos.map((x) => `V-${x}`).join('、')}` : `复验 ${nos.length} 条漏洞`;
  store.tx(() => {
    store.insert('audit', {
      id, project_id: projectId, scene: 'reverify', mode: repoRows.length > 1 ? 'multi' : 'single', title, status: 'planning', strategy_draft: s, strategy_sources: merged.sources,
      scope: { include: s.scope.include, exclude: s.scope.exclude, focus: s.focus, reverify: vulns.map((v) => v.id), ...(input.note?.trim() ? { reverifyNote: input.note.trim().slice(0, 4000) } : {}) }, budget_initial: budget, budget_effective: budget,
      budget_consumed: { tokens: 0, durationMs: 0, costMicros: 0 }, origin: input.origin, conversation_id: (input as { conversationId?: string }).conversationId ?? null,
    });
    for (const { repo, ref } of repoRows) store.insert('audit_repository', { audit_id: id, repository_id: repo.id, role_in_audit: 'target', requested_ref: ref ?? repo.default_ref });
    for (const r of pendingEvidenceRepos(store, projectId, vulns, new Set(repoRows.map((x) => x.repo.id)))) {
      store.insert('audit_repository', { audit_id: id, repository_id: r.id, role_in_audit: r.is_auditable ? 'related' : 'context', requested_ref: input.refs?.[r.id] ?? r.default_ref });
    }
    store.appendEvent(id, 'audit.status_changed', { from: null, to: 'planning', reason: 'created' });
  });
  return id;
}

const normName = (n: string) => n.toLowerCase().replace(/[-_.](service|svc|server|api|app)$/, '').replace(/[^a-z0-9]/g, '');

/**
 * Targeted reverification of pending vulnerabilities: the repositories the
 * condition names (once added to the project) and the vulnerability repository's topology neighbours
 * join as related (evidence-only) repositories.
 */
export function pendingEvidenceRepos(store: Store, projectId: string, vulns: { repository_id: string; confirm_status: string; missing_context: string | null }[], exclude: Set<string>): RepositoryRow[] {
  const pendingVulns = vulns.filter((v) => v.confirm_status === 'pending' && v.missing_context);
  if (!pendingVulns.length) return [];
  const repos = listRepositories(store, projectId);
  const out = new Map<string, RepositoryRow>();
  for (const v of pendingVulns) {
    const cond = normalizePending(JSON.parse(v.missing_context!));
    for (const m of cond?.missing ?? []) {
      const want = normName(m.ref);
      if (want.length < 3) continue;
      for (const r of repos) {
        const have = normName(r.name);
        if (have === want || (have.length >= 4 && (want.includes(have) || have.includes(want)))) out.set(r.id, r);
      }
    }
    const node = store.get<{ id: string }>('SELECT id FROM topology_node WHERE project_id = ? AND repository_id = ?', projectId, v.repository_id);
    if (node) {
      for (const n of store.all<{ repository_id: string }>(
        `SELECT DISTINCT n.repository_id FROM topology_edge e JOIN topology_node n ON n.id = CASE WHEN e.from_node = ? THEN e.to_node ELSE e.from_node END
         WHERE e.project_id = ? AND e.removed = 0 AND (e.from_node = ? OR e.to_node = ?) AND n.repository_id IS NOT NULL`, node.id, projectId, node.id, node.id)) {
        const r = repos.find((x) => x.id === n.repository_id);
        if (r) out.set(r.id, r);
      }
    }
  }
  return [...out.values()].filter((r) => !exclude.has(r.id));
}

export interface CreateBackfillInput {
  auditId: string;
  /** coverage_item ids of the source audit; omitted with `all` = every uncovered item. */
  itemIds?: string[];
  all?: boolean;
  origin: 'cli' | 'ui' | 'conversation';
}

/**
 * Backfill ("一键补审"): a scope-limited audit of the chosen uncovered targets
 * of a finished audit, on the same snapshot (no new snapshot), with the source audit's frozen strategy
 * and a budget sized to the targets. The source audit is `base_audit_id`; its artifacts are not changed.
 */
export function createBackfillAudit(store: Store, knownModels: Set<string>, input: CreateBackfillInput): string {
  const src = store.get<{ id: string; project_id: string; title: string; status: string; scene: string; strategy_frozen: string | null; strategy_sources: string; mode: string }>(
    'SELECT id, project_id, title, status, scene, strategy_frozen, strategy_sources, mode FROM audit WHERE id = ?', input.auditId);
  if (!src) throw new AppError('AUDIT_NOT_FOUND', input.auditId);
  if (!['completed', 'partial'].includes(src.status) || !src.strategy_frozen) throw new AppError('AUDIT_INVALID_TRANSITION', 'only finished audits can be backfilled');
  const items = store.all<{ id: string; target_id: string; status: string }>(
    `SELECT id, target_id, status FROM coverage_item WHERE audit_id = ? AND status NOT IN ('concluded','excluded')`, src.id);
  const chosen = input.all ? items : items.filter((i) => input.itemIds?.includes(i.id));
  if (!input.all && (input.itemIds ?? []).some((id) => !items.some((i) => i.id === id))) throw new AppError('COMMON_VALIDATION', 'some items are not uncovered items of this audit');
  if (chosen.length === 0) throw new AppError('COMMON_VALIDATION', 'no uncovered items to backfill');
  const base = upgradeStrategy(JSON.parse(src.strategy_frozen));
  const n = chosen.length;
  // A backfill only hunts the chosen items, so its budget has no stage quotas.
  const { stages: _stages, ...baseBudget } = base.budget;
  // Sized like the steps it runs — the calibrated coverage-gap estimate (the engine gives the step the
  // same one) plus the closing steps; the constant alone paused every real-model backfill on its first step.
  const steps = calibrated(store, estimateStep('hunt', n), 'coverage-gap', base.models.audit)
    + calibrated(store, estimateStep('reconcile'), 'reconcile', base.models.audit);
  const strategy = {
    ...base,
    budget: { ...baseBudget, tokens: Math.max(60_000, 20_000 * n, Math.ceil(steps * RETRY_MARGIN)), durationSec: 600 + 90 * n },
    coverageTarget: { ...base.coverageTarget, onShortfall: 'declare' as const },
  };
  const issues = checkStrategy(strategy, 'full', knownModels);
  if (issues.length) throw new AppError('STRATEGY_INVALID', issues.map((i) => `${i.path}: ${i.message}`).join('; '));
  const id = newId('audit');
  const budget = auditBudget(strategy);
  const repos = store.all<{ repository_id: string; snapshot_id: string | null; requested_ref: string | null; role_in_audit: string }>(
    'SELECT repository_id, snapshot_id, requested_ref, role_in_audit FROM audit_repository WHERE audit_id = ?', src.id);
  store.tx(() => {
    store.insert('audit', {
      id, project_id: src.project_id, scene: 'full', mode: src.mode, title: `补审：${src.title}`, status: 'planning', strategy_draft: strategy,
      strategy_sources: fromJson(src.strategy_sources, {}), base_audit_id: src.id,
      scope: { include: strategy.scope.include, exclude: strategy.scope.exclude, focus: strategy.focus, backfill: { auditId: src.id, targets: chosen.map((c) => c.target_id) } },
      budget_initial: budget, budget_effective: budget, budget_consumed: { tokens: 0, durationMs: 0, costMicros: 0 }, origin: input.origin, conversation_id: (input as { conversationId?: string }).conversationId ?? null,
    });
    // Same snapshot as the source audit: planning does not re-snapshot pre-attached repositories.
    for (const r of repos) store.insert('audit_repository', { audit_id: id, repository_id: r.repository_id, snapshot_id: r.snapshot_id, requested_ref: r.requested_ref, role_in_audit: r.role_in_audit });
    store.appendEvent(id, 'audit.status_changed', { from: null, to: 'planning', reason: `backfill of ${src.id}` });
  });
  return id;
}

export function createAudit(store: Store, knownModels: Set<string>, input: CreateAuditInput): string {
  if (input.scene === 'reverify') throw new AppError('CONFIG_INVALID', 'reverification is started from vulnerabilities (createReverifyAudit / POST /reverifications)');
  const project = getProject(store, input.projectId);
  const all = listRepositories(store, project.id);
  const repos = all.filter((r) => r.is_auditable);
  if (repos.length === 0) throw new AppError('REPOSITORY_NOT_FOUND', `project has no auditable repositories; add a repository with ${auditLanguageLabels()} sources first`);
  const find = (key: string, pool: RepositoryRow[]) => {
    const hit = pool.find((r) => r.name === key || r.id === key);
    if (!hit) throw new AppError('REPOSITORY_NOT_FOUND', key);
    return hit;
  };
  const mode = input.mode ?? 'single';
  // Repositories of the audit and their role in it.
  const attached: { repo: RepositoryRow; role: 'target' | 'related' | 'context' }[] = [];
  let target: RepositoryRow;
  if (mode === 'multi') {
    if (input.scene !== 'full') throw new AppError('CONFIG_INVALID', 'multi-repository audits are full audits; incremental audits take one target repository (plus related repositories)');
    const targets = input.repositories?.length ? [...new Set(input.repositories)].map((k) => find(k, repos)) : repos;
    if (targets.length < 2) throw new AppError('CONFIG_INVALID', 'a multi-repository audit needs at least two auditable repositories; use a single-repository audit');
    for (const r of targets) attached.push({ repo: r, role: 'target' });
    // Context repositories (no audit-language sources) join as contract sources.
    for (const r of all) if (!r.is_auditable) attached.push({ repo: r, role: 'context' });
    target = targets[0]!;
  } else {
    if (input.repository) target = find(input.repository, repos);
    else if (repos.length === 1) target = repos[0]!;
    else throw new AppError('CONFIG_INVALID', `project has ${repos.length} repositories; choose the target repository (--repo) or a multi-repository audit (--mode multi)`);
    attached.push({ repo: target, role: 'target' });
    for (const k of [...new Set(input.related ?? [])]) {
      const r = find(k, all);
      if (r.id === target.id) continue;
      attached.push({ repo: r, role: r.is_auditable ? 'related' : 'context' });
    }
  }
  for (const [k, v] of Object.entries(input.refs ?? {})) {
    if (v.startsWith('-') || /[\s\0]/.test(v) || !v) throw new AppError('CONFIG_INVALID', `invalid ref for ${k}`);
    const r = find(k, all);
    if (!attached.some((a) => a.repo.id === r.id)) throw new AppError('CONFIG_INVALID', `${k} is not part of this audit`);
    if (r.source_kind === 'archive') throw new AppError('CONFIG_INVALID', `${r.name} is an uploaded archive and has no branches or commits`);
  }
  if (input.ref !== undefined && (input.ref.startsWith('-') || /[\s\0]/.test(input.ref))) throw new AppError('CONFIG_INVALID', 'invalid ref');
  if (target.source_kind === 'archive' && (input.ref || input.baseRef)) throw new AppError('CONFIG_INVALID', 'an uploaded archive has no branches or commits; choose the baseline by audit instead');
  if (input.baseRef !== undefined && (input.baseRef.startsWith('-') || /[\s\0]/.test(input.baseRef) || !input.baseRef)) throw new AppError('CONFIG_INVALID', 'invalid base ref');

  // Incremental baseline: an explicit ref, an explicit earlier audit, or by
  // default the version the latest finished audit of this repository reviewed.
  let base: { auditId: string | null; snapshotId: string | null; ref: string | null } | null = null;
  if (input.scene === 'incremental') {
    if (input.baseRef) base = { auditId: null, snapshotId: null, ref: input.baseRef };
    else if (input.baseAuditId) {
      const b = store.get<{ snapshot_id: string | null; status: string }>(
        `SELECT ar.snapshot_id, a.status FROM audit a JOIN audit_repository ar ON ar.audit_id = a.id WHERE a.id = ? AND a.project_id = ? AND ar.repository_id = ?`,
        input.baseAuditId, project.id, target.id);
      if (!b?.snapshot_id) throw new AppError('AUDIT_BASELINE_UNAVAILABLE', 'the baseline audit did not snapshot this repository');
      base = { auditId: input.baseAuditId, snapshotId: b.snapshot_id, ref: null };
    } else {
      const latest = latestBaseline(store, project.id, target.id);
      if (!latest) throw new AppError('AUDIT_BASELINE_UNAVAILABLE', 'no finished audit of this repository yet; run a full audit first or specify a base ref');
      base = { auditId: latest.auditId, snapshotId: latest.snapshotId, ref: null };
    }
  } else if (input.baseRef || input.baseAuditId) {
    throw new AppError('CONFIG_INVALID', 'a baseline only applies to incremental audits');
  }

  const models = modelDefaults(store.config);
  const system = sceneDefaults(input.scene, models);
  const settingsLayer = (store.config.sceneDefaults as Record<string, Record<string, unknown> | undefined>)[input.scene];
  const merged = mergeStrategy(system, settingsLayer, input.strategyOverride);
  merged.strategy = withConnectors(store, project.id, merged.strategy, input.strategyOverride);
  const schema = check(AuditStrategy, merged.strategy);
  if (!schema.ok) throw new AppError('STRATEGY_INVALID', schema.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; '));
  const issues = checkStrategy(merged.strategy, input.scene, knownModels);
  if (issues.length) throw new AppError('STRATEGY_INVALID', issues.map((i) => `${i.path}: ${i.message}`).join('; '));
  checkAuditThreatModels(store, project.id, input.scene, merged.strategy.threatModels);

  const id = newId('audit');
  const s = merged.strategy;
  const budget = auditBudget(s, { targets: attached.filter((a) => a.role === 'target').length });
  store.tx(() => {
    store.insert('audit', {
      id, project_id: project.id, scene: input.scene, mode, title: input.title ?? `${input.scene === 'incremental' ? '增量审计' : '全量审计'} · ${attached.filter((a) => a.role === 'target').map((a) => a.repo.name).join(', ')}`,
      status: 'planning', strategy_draft: s, strategy_sources: merged.sources,
      scope: { include: s.scope.include, exclude: s.scope.exclude, focus: s.focus }, budget_initial: budget, budget_effective: budget,
      budget_consumed: { tokens: 0, durationMs: 0, costMicros: 0 }, origin: input.origin, conversation_id: (input as { conversationId?: string }).conversationId ?? null, base_audit_id: base?.auditId ?? null,
      auto_start: input.autoStart ? 1 : 0,
    });
    const refOf = (r: RepositoryRow) => Object.entries(input.refs ?? {}).find(([k]) => k === r.name || k === r.id)?.[1];
    for (const a of attached) {
      const isTarget = a.repo.id === target.id;
      store.insert('audit_repository', {
        audit_id: id, repository_id: a.repo.id, role_in_audit: a.role,
        requested_ref: (isTarget ? input.ref : undefined) ?? refOf(a.repo) ?? a.repo.default_ref,
        base_snapshot_id: isTarget ? base?.snapshotId ?? null : null, base_requested_ref: isTarget ? base?.ref ?? null : null,
      });
    }
    store.appendEvent(id, 'audit.status_changed', { from: null, to: 'planning', reason: 'created' });
  });
  return id;
}
