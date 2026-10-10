// Projects and repositories. Sources: local directories, remote Git (https / ssh) and
// uploaded archives.
import { existsSync, realpathSync, statSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import type { Readable } from 'node:stream';
import type { FastifyInstance } from 'fastify';
import { AppError, type DirectoryPickDto, type RefDto, type RepoProbeDto } from '@xiezhi/contracts';
import { ArchiveError, listRemoteTree, lsRemote, pickFolder, RemoteGitError, runGit, scanArchive, worktreeDirty, type RemoteListing, type RemoteUrl } from '@xiezhi/context';
import {
  addArchiveRepository, addGitRepository, addRepository, countLanguages, createProject, editTopology, getTopology, getProject, listProjects, listRepositories, parseRemote, remoteAppError,
  remoteAuth, remoteProblem, scanLocalLanguages, scanLocalJsBackend, scanLocalRustBackend, auditableFrom, deleteProject, getLiveRepository, queries as Q, removeRepository, updateProject, updateRepository,
  setInternalTrust,
} from '@xiezhi/engine';
import * as B from '../bodies.js';
import type { AppContext } from '../context.js';
import { analysisDto, projectDto, repoDto } from '../dto.js';
import { etag, expectedRevision, parseBody } from '../http.js';

async function gitText(ctx: AppContext, repo: string, sub: string, args: string[]): Promise<string | null> {
  const r = await runGit(ctx.engine.executor, repo, sub, args, { collectStdout: true, timeoutMs: 15_000 });
  return r.status === 'ok' ? r.stdoutData!.toString('utf8') : null;
}

function blankProbe(sourceKind: RepoProbeDto['sourceKind'], path: string, suggestedName: string): RepoProbeDto {
  return {
    sourceKind, ok: false, path, exists: false, isDirectory: false, hasGit: false, currentBranch: null, headCommit: null, dirty: null, languages: {}, auditable: false,
    suggestedName, problems: [], remote: null, archive: null,
  };
}

async function probeRemote(ctx: AppContext, url: string): Promise<RepoProbeDto> {
  let remote: RemoteUrl;
  try {
    remote = parseRemote(url, ctx.engine.allowFileRemotes);
  } catch (e) {
    const out = blankProbe('git', url.trim(), 'repo');
    out.problems.push((e as AppError).hint ?? 'Git 地址无效');
    out.remote = { url: url.trim(), defaultBranch: null, refs: [], errorCode: 'invalid_url', suggestions: [] };
    return out;
  }
  const out = blankProbe('git', remote.url, remote.suggestedName);
  const auth = remoteAuth(ctx.store.config, remote, ctx.engine.allowFileRemotes);
  let listing: RemoteListing;
  try {
    listing = await lsRemote(ctx.engine.executor, remote, auth);
  } catch (e) {
    if (!(e instanceof RemoteGitError)) throw e;
    out.problems.push(remoteProblem(e));
    out.remote = { url: remote.url, defaultBranch: null, refs: [], errorCode: e.code, suggestions: [] };
    return out;
  }
  Object.assign(out, { ok: true, exists: true, hasGit: true, currentBranch: listing.defaultBranch, headCommit: listing.headCommit });
  out.remote = { url: remote.url, defaultBranch: listing.defaultBranch, refs: listing.refs.map(remoteRefDto), errorCode: null, suggestions: [] };
  if (!listing.headCommit) {
    out.problems.push('远程仓库没有默认分支：添加时请指定分支、标签或提交');
    out.auditable = true;
    return out;
  }
  try {
    out.languages = countLanguages(await listRemoteTree(ctx.engine.executor, remote, listing.headCommit, auth));
    const a = auditableFrom(out.languages, null);
    out.auditable = a.auditable;
    if (a.note) out.problems.push(a.note);
  } catch {
    out.auditable = true;
    out.problems.push('未能读取默认分支的文件列表：语言与是否可审计将在首次审计时识别');
  }
  return out;
}

function remoteRefDto(r: { kind: 'branch' | 'tag'; name: string; commit: string }): RefDto {
  return { kind: r.kind, name: r.name, commit: r.commit, subject: '', author: '', date: null };
}

async function probeUpload(ctx: AppContext, uploadId: string): Promise<RepoProbeDto> {
  const up = ctx.uploads.get(uploadId);
  const name = up.fileName.replace(/\.(zip|tar|tgz|tar\.gz)$/i, '').replace(/[^A-Za-z0-9._-]/g, '-').replace(/^[^A-Za-z0-9]+/, '').slice(0, 100) || 'archive';
  const out = blankProbe('archive', up.fileName, name);
  try {
    const scan = await scanArchive(up.file);
    Object.assign(out, { ok: true, exists: true, hasGit: !!scan.headCommit, headCommit: scan.headCommit });
    out.archive = { uploadId, fileName: up.fileName, format: scan.format, fileCount: scan.fileCount, totalBytes: scan.totalBytes };
    out.languages = countLanguages(scan.files);
    const a = auditableFrom(out.languages, null);
    out.auditable = a.auditable;
    if (a.note) out.problems.push(a.note);
    if (scan.headCommit) out.problems.push('包内带 Git 信息：Commit 仅作展示，审计以包内文件内容为准');
  } catch (e) {
    if (!(e instanceof ArchiveError)) throw e;
    out.problems.push(`压缩包不符合安全限制：${e.message}`);
    out.archive = { uploadId, fileName: up.fileName, format: '', fileCount: 0, totalBytes: 0 };
  }
  return out;
}

export async function probeSource(ctx: AppContext, b: { path?: string | undefined; git?: string | undefined; uploadId?: string | undefined }): Promise<RepoProbeDto> {
  const given = [b.path, b.git, b.uploadId].filter((x) => x !== undefined).length;
  if (given !== 1) throw new AppError('COMMON_VALIDATION', 'give exactly one of path, git or uploadId');
  if (b.git !== undefined) return probeRemote(ctx, b.git);
  if (b.uploadId !== undefined) return probeUpload(ctx, b.uploadId);
  return probeRepo(ctx, b.path!);
}

export async function probeRepo(ctx: AppContext, input: string): Promise<RepoProbeDto> {
  const abs = resolve(input);
  const exists = existsSync(abs);
  const isDirectory = exists && statSync(abs).isDirectory();
  const out: RepoProbeDto = {
    ...blankProbe('local', abs, basename(abs).replace(/[^A-Za-z0-9._-]/g, '-').replace(/^[^A-Za-z0-9]+/, '').slice(0, 100) || 'repo'),
    exists, isDirectory, ok: isDirectory,
  };
  const problems = out.problems;
  if (!exists) { problems.push('路径不存在'); return out; }
  if (!isDirectory) { problems.push('不是目录'); return out; }
  const real = realpathSync(abs);
  out.path = real;
  out.hasGit = existsSync(join(real, '.git'));
  if (out.hasGit) {
    out.currentBranch = (await gitText(ctx, real, 'rev-parse', ['--abbrev-ref', 'HEAD']))?.trim() ?? null;
    out.headCommit = (await gitText(ctx, real, 'rev-parse', ['HEAD']))?.trim() ?? null;
    // No `git status` on the user's repository (it runs repository-configured clean filters).
    out.dirty = await worktreeDirty(ctx.engine.executor, real, { timeoutMs: 15_000 });
    if (out.dirty) problems.push('工作区有未提交改动：审计将标注为“工作区版本”');
  }
  out.languages = scanLocalLanguages(real);
  const a = auditableFrom(out.languages, scanLocalJsBackend(real), scanLocalRustBackend(real));
  out.auditable = a.auditable;
  if (a.note) problems.push(a.note);
  return out;
}

async function remoteRefs(ctx: AppContext, url: string, kind: string | undefined, q: string | undefined): Promise<RefDto[]> {
  if (kind === 'commit') return [];
  const remote = parseRemote(url, ctx.engine.allowFileRemotes);
  let listing: RemoteListing;
  try {
    listing = await lsRemote(ctx.engine.executor, remote, remoteAuth(ctx.store.config, remote, ctx.engine.allowFileRemotes));
  } catch (e) {
    if (e instanceof RemoteGitError) throw remoteAppError(e);
    throw e;
  }
  const needle = q?.trim().toLowerCase();
  return listing.refs.filter((r) => (!kind || r.kind === kind) && (!needle || r.name.toLowerCase().includes(needle) || r.commit.startsWith(needle))).map(remoteRefDto);
}

export async function listRefs(ctx: AppContext, repoPath: string, kind: string | undefined, q: string | undefined): Promise<RefDto[]> {
  if (!existsSync(join(repoPath, '.git'))) return [];
  const refs: RefDto[] = [];
  const SEP = '\u001f';
  if (!kind || kind === 'branch' || kind === 'tag') {
    const patterns = !kind ? ['refs/heads', 'refs/tags'] : kind === 'branch' ? ['refs/heads'] : ['refs/tags'];
    const text = await gitText(ctx, repoPath, 'for-each-ref', ['--sort=-committerdate', `--format=%(refname)${SEP}%(objectname)${SEP}%(contents:subject)${SEP}%(authorname)${SEP}%(committerdate:iso-strict)`, '--count=200', ...patterns]);
    for (const line of (text ?? '').split('\n').filter(Boolean)) {
      const [ref, commit, subject, author, date] = line.split(SEP);
      const isTag = ref!.startsWith('refs/tags/');
      refs.push({ kind: isTag ? 'tag' : 'branch', name: ref!.replace(/^refs\/(heads|tags)\//, ''), commit: commit ?? '', subject: subject ?? '', author: author ?? '', date: date || null });
    }
  }
  if (!kind || kind === 'commit') {
    const text = await gitText(ctx, repoPath, 'log', ['-n', '50', `--format=%H${SEP}%s${SEP}%an${SEP}%cI`]);
    for (const line of (text ?? '').split('\n').filter(Boolean)) {
      const [commit, subject, author, date] = line.split(SEP);
      refs.push({ kind: 'commit', name: commit!.slice(0, 12), commit: commit!, subject: subject ?? '', author: author ?? '', date: date || null });
    }
  }
  const needle = q?.trim().toLowerCase();
  return needle ? refs.filter((r) => r.name.toLowerCase().includes(needle) || r.commit.startsWith(needle) || r.subject.toLowerCase().includes(needle)) : refs;
}

/** One entry of `POST /projects/{pid}/repos`: probe the source again, validate the ref, add. */
async function addFromSource(ctx: AppContext, projectId: string, r: { path?: string | undefined; git?: string | undefined; uploadId?: string | undefined; name?: string | undefined; ref?: string | undefined }) {
  const { store } = ctx;
  const given = [r.path, r.git, r.uploadId].filter((x) => x !== undefined).length;
  if (given !== 1) throw new AppError('COMMON_VALIDATION', 'give exactly one of path, git or uploadId');
  if (r.uploadId !== undefined) {
    if (r.ref) throw new AppError('COMMON_VALIDATION', 'an uploaded archive has no branches or commits');
    const up = ctx.uploads.get(r.uploadId);
    const row = await addArchiveRepository(store, ctx.engine.executor, projectId, { file: up.file, fileName: up.fileName, ...(r.name ? { name: r.name } : {}) });
    ctx.uploads.remove(r.uploadId);
    return row;
  }
  if (r.git !== undefined) {
    return addGitRepository(store, ctx.engine.executor, projectId, { url: r.git, allowFileRemotes: ctx.engine.allowFileRemotes, ...(r.ref ? { ref: r.ref } : {}), ...(r.name ? { name: r.name } : {}) });
  }
  const probe = await probeRepo(ctx, r.path!);
  return addRepository(store, projectId, {
    path: r.path!, ...(r.ref ? { ref: r.ref } : {}), name: r.name ?? probe.suggestedName, auditable: probe.auditable, languages: Object.keys(probe.languages).sort(),
  });
}

export function registerProjectRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get('/api/v1/projects', async () => listProjects(store).map((p) => projectDto(store, p)));
  app.post('/api/v1/projects', async (req, reply) => {
    const b = parseBody(B.PostProjectsBody, req.body);
    const p = createProject(store, b.name.trim());
    reply.code(201);
    return projectDto(store, p);
  });
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid', async (req) => projectDto(store, getProject(store, req.params.pid)));
  app.patch<{ Params: { pid: string } }>('/api/v1/projects/:pid', async (req) => {
    const b = parseBody(B.PatchProjectsPidBody, req.body);
    if (b.internalTrust !== undefined) setInternalTrust(store, req.params.pid, b.internalTrust);
    return projectDto(store, updateProject(store, req.params.pid, { ...(b.name ? { name: b.name } : {}), ...(b.status ? { status: b.status } : {}) }));
  });
  app.delete<{ Params: { pid: string }; Querystring: { confirmName?: string } }>('/api/v1/projects/:pid', async (req, reply) => {
    // Destructive: the caller must repeat the project name (ConfirmDialog).
    deleteProject(store, req.params.pid, req.query.confirmName);
    reply.code(204);
    return null;
  });

  // one system folder dialog at a time; the chosen path only fills the form.
  let picking = false;
  app.post('/api/v1/directory-picks', async (): Promise<DirectoryPickDto> => {
    if (picking) return { status: 'unavailable', path: null, reason: '已经打开了一个目录选择窗口，请先在那个窗口里选择或取消' };
    picking = true;
    try {
      const r = await pickFolder();
      return { status: r.status, path: r.status === 'picked' ? r.path : null, reason: r.status === 'unavailable' ? r.reason : null };
    } finally {
      picking = false;
    }
  });
  app.post('/api/v1/repo-probes', async (req) => {
    const b = parseBody(B.PostRepoProbesBody, req.body);
    return probeSource(ctx, b);
  });
  app.post<{ Querystring: { name: string } }>('/api/v1/uploads', async (req, reply) => {
    const up = await ctx.uploads.save(req.body as Readable, req.query.name);
    reply.code(201);
    return up;
  });
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/repos', async (req) => {
    const p = getProject(store, req.params.pid);
    return listRepositories(store, p.id).map((r) => repoDto(store, getLiveRepository<any>(store, r.id)));
  });
  app.post<{ Params: { pid: string } }>('/api/v1/projects/:pid/repos', async (req, reply) => {
    const b = parseBody(B.PostProjectsPidReposBody, req.body);
    const p = getProject(store, req.params.pid);
    const results = [];
    for (const r of b.repos) {
      try {
        const row = await addFromSource(ctx, p.id, r);
        results.push({ ok: true, repo: repoDto(store, getLiveRepository<any>(store, row.id)) });
      } catch (e) {
        if (!(e instanceof AppError)) throw e;
        results.push({ ok: false, path: r.path ?? r.git ?? r.uploadId ?? '', error: { code: e.code, hint: e.hint ?? null } });
      }
    }
    reply.code(results.some((r) => r.ok) ? 201 : 422);
    return { results };
  });
  // ---- project analysis: repository roles (manual only) ----
  app.post<{ Params: { pid: string } }>('/api/v1/projects/:pid/analyze', async (req, reply) => {
    const p = getProject(store, req.params.pid);
    if (listRepositories(store, p.id).length === 0) throw new AppError('REPOSITORY_NOT_FOUND', 'project has no repositories; add one first');
    const id = ctx.engine.jobs.startAnalysis(p.id);
    reply.code(202);
    return { analysisId: id };
  });
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/analysis', async (req) => {
    const p = getProject(store, req.params.pid);
    const a = Q.latestProjectAnalysis<any>(store, p.id);
    return { analysis: a ? analysisDto(store, a) : null };
  });
  // ---- topology (If-Match / revision like other edited resources) ----
  // a service's responsibility card (inbound exposure, guarantees recorded as facts, outbound calls).
  app.get<{ Params: { pid: string; repo: string } }>('/api/v1/projects/:pid/services/:repo/card', async (req) => ctx.engine.serviceCard(req.params.pid, req.params.repo));
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/topology', async (req, reply) => {
    const t = getTopology(store, getProject(store, req.params.pid).id);
    etag(reply, t.revision);
    return t;
  });
  app.patch<{ Params: { pid: string } }>('/api/v1/projects/:pid/topology', async (req, reply) => {
    const b = parseBody(B.PatchProjectsPidTopologyBody, req.body);
    const p = getProject(store, req.params.pid);
    const t = editTopology(store, p.id, expectedRevision(req, b), b);
    etag(reply, t.revision);
    return t;
  });
  app.get<{ Params: { rid: string } }>('/api/v1/repos/:rid', async (req) => {
    return repoDto(store, getLiveRepository<any>(store, req.params.rid));
  });
  app.patch<{ Params: { rid: string } }>('/api/v1/repos/:rid', async (req) => {
    const b = parseBody(B.PatchReposRidBody, req.body);
    updateRepository(store, req.params.rid, { ...(b.defaultRef !== undefined ? { defaultRef: b.defaultRef } : {}), ...(b.role ? { role: b.role } : {}), ...(b.auditable !== undefined ? { auditable: b.auditable } : {}) });
    return repoDto(store, getLiveRepository<any>(store, req.params.rid));
  });
  app.delete<{ Params: { rid: string } }>('/api/v1/repos/:rid', async (req, reply) => {
    // Soft remove: finished audits keep referring to it.
    removeRepository(store, req.params.rid);
    reply.code(204);
    return null;
  });
  app.get<{ Params: { rid: string }; Querystring: { kind?: string; q?: string } }>('/api/v1/repos/:rid/refs', async (req) => {
    const r = getLiveRepository<{ source_uri: string; source_kind: string }>(store, req.params.rid);
    if (req.query.kind && !['branch', 'tag', 'commit'].includes(req.query.kind)) throw new AppError('COMMON_VALIDATION', 'kind');
    if (r.source_kind === 'archive') return [];
    if (r.source_kind === 'git') return remoteRefs(ctx, r.source_uri, req.query.kind, req.query.q);
    return listRefs(ctx, r.source_uri, req.query.kind, req.query.q);
  });
}
