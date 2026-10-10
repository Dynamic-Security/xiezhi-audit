// CLI client mode: when a service runs on this data-dir, the CLI talks to its local API
// with the bearer token from `<data-dir>/run/api.json` instead of opening the store (single writer).
import { createReadStream, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import type {
  AnalysisDto, ApiErrorBody, AuditDetailDto, AuditSummaryDto, EventDto, ExportDto, GitCredentialDto, Page, PlanDto, ProjectDto, RepoDto, ServiceDiscovery, UploadDto, VulnSummaryDto,
} from '@xiezhi/contracts';
import { modeArgs } from './modes.js';
import { huntCommand } from './hunt.js';
import { CliExit, EXIT_ERROR, EXIT_INCOMPLETE, EXIT_OK, confirm, print, printJson, readSecret } from './io.js';
import { readSse, type SseMessage } from './sse.js';

export class RemoteError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

export interface Remote {
  base: string;
  get<T>(path: string): Promise<T>;
  post<T>(path: string, body?: unknown, headers?: Record<string, string>): Promise<T>;
  send<T>(method: 'PUT' | 'PATCH' | 'DELETE', path: string, body?: unknown): Promise<T>;
  /** Stream a local file to POST /uploads (application/octet-stream). */
  upload(file: string): Promise<UploadDto>;
  raw(path: string): Promise<Response>;
  /** Read an SSE stream until it closes or `onMessage` returns false. */
  stream(path: string, onMessage: (m: SseMessage) => boolean | void): Promise<void>;
}

/**
 * Read the discovery file (owner + 0600 enforced) and confirm the service answers.
 * Returns null when no service is running for this data-dir.
 */
export async function discover(dataDir: string): Promise<Remote | null> {
  const path = join(dataDir, 'run', 'api.json');
  let info: ServiceDiscovery;
  try {
    const st = statSync(path);
    if ((st.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && st.uid !== process.getuid())) {
      throw new CliExit(EXIT_ERROR, `${path} 权限或属主不安全，拒绝使用；请运行 xiezhi doctor`);
    }
    info = JSON.parse(readFileSync(path, 'utf8')) as ServiceDiscovery;
  } catch (e) {
    if (e instanceof CliExit) throw e;
    return null;
  }
  const base = `http://127.0.0.1:${info.port}`;
  const headers = { authorization: `Bearer ${info.token}`, accept: 'application/json' };
  try {
    const r = await fetch(`${base}/api/v1/health`, { signal: AbortSignal.timeout(3000) });
    if (!r.ok) return null;
  } catch {
    return null;
  }
  const call = async <T>(method: string, p: string, body?: unknown, extra: Record<string, string> = {}, raw?: { stream: NodeJS.ReadableStream }): Promise<T> => {
    const res = await fetch(`${base}/api/v1${p}`, {
      method, headers: { ...headers, ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...extra },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      ...(raw ? { body: raw.stream as unknown as ReadableStream, duplex: 'half' } : {}),
    } as RequestInit);
    if (!res.ok) {
      const b = (await res.json().catch(() => null)) as ApiErrorBody | null;
      throw new RemoteError(res.status, b?.error.code ?? 'INTERNAL', `${b?.error.message ?? `HTTP ${res.status}`}${b?.error.hint ? ` — ${b.error.hint}` : ''}${b?.error.requestId ? `（请求 ${b.error.requestId}）` : ''}`);
    }
    return (res.status === 204 ? undefined : await res.json()) as T;
  };
  return {
    base,
    get: (p) => call('GET', p),
    post: (p, body, h) => call('POST', p, body ?? {}, h),
    send: (m, p, body) => call(m, p, body),
    upload: (file) => call('POST', `/uploads?name=${encodeURIComponent(basename(file))}`, undefined, { 'content-type': 'application/octet-stream' }, { stream: createReadStream(file) }),
    raw: (p) => fetch(`${base}/api/v1${p}`, { headers }),
    stream: (p, onMessage) => readSse(`${base}/api/v1${p}`, { authorization: headers.authorization }, onMessage),
  };
}

const TERMINAL = ['completed', 'partial', 'failed', 'cancelled'];

export async function findProject(r: Remote, idOrName: string): Promise<ProjectDto> {
  const all = await r.get<ProjectDto[]>('/projects');
  const p = all.find((x) => x.id === idOrName || x.name === idOrName);
  if (!p) throw new CliExit(EXIT_ERROR, `项目不存在：${idOrName}`);
  return p;
}

function exitFor(a: { status: string; partialReasons: string[] }, id: string): number {
  print(`审计 ${id} 状态：${a.status}${a.partialReasons.length ? `（${a.partialReasons.join(' > ')}）` : ''}`);
  if (a.status === 'completed') return EXIT_OK;
  if (a.status === 'waiting_budget') print(`预算不足。追加后继续：xiezhi audit resume ${id} --add-tokens 100000`);
  if (a.status === 'interrupted' || a.status === 'paused') print(`可继续：xiezhi audit resume ${id}`);
  return a.status === 'failed' ? EXIT_ERROR : EXIT_INCOMPLETE;
}

function printEvent(e: EventDto): void {
  if (e.type === 'step.status_changed' && ['running', 'succeeded', 'failed'].includes(String(e.payload.to))) print(`  [${e.ts.slice(11, 19)}] ${String(e.payload.kind)} ${String(e.payload.to)}`);
  else if (e.type === 'vuln.created') print(`  发现漏洞 V-${String(e.payload.display_no)}（${String(e.payload.confirm_status)}）`);
  else if (e.type === 'question.asked') print(`  Agent 提问：${String(e.payload.text)}`);
}

export interface FollowTiming {
  /** Polling period once SSE is given up (5 s). */
  pollMs: number;
  /** How long to poll before trying SSE again (60 s). */
  sseRetryMs: number;
  /** Pause between SSE reconnects. */
  reconnectMs: number;
}
const TIMING: FollowTiming = { pollMs: 5000, sseRetryMs: 60_000, reconnectMs: 1000 };
const sleep = (ms: number) => new Promise((ok) => setTimeout(ok, ms));

/**
 * Follow an audit until `until(status)` holds: print its events from the start over
 * SSE, de-duplicated by seq and resumed with `after`; three failed connections within 30 s switch to
 * JSON polling, and SSE is retried every 60 s. Only status changes newer than the snapshot taken first
 * count, so a replayed old transition (e.g. an earlier pause) never ends the wait.
 */
/** `printedUpTo`: events up to this seq were already printed (e.g. by the planning follow) — not repeated. */
export async function follow(r: Remote, id: string, until: (s: string) => boolean, timing: FollowTiming = TIMING, printedUpTo = 0): Promise<AuditDetailDto> {
  const first = await r.get<AuditDetailDto>(`/audits/${id}`);
  if (until(first.status)) return first;
  const liveFrom = first.lastEventSeq;
  let status: string = first.status;
  let after = printedUpTo;
  let failures: number[] = [];
  const onEvent = (e: EventDto) => {
    if (e.seq <= after) return;
    after = e.seq;
    printEvent(e);
    if (e.type === 'audit.status_changed' && e.seq > liveFrom) status = String(e.payload.to);
  };
  const resync = async (lastSeq: number) => {
    after = lastSeq;
    status = (await r.get<AuditDetailDto>(`/audits/${id}`)).status;
  };
  for (;;) {
    let ended = false;
    let failed = false;
    let pending = null as Promise<void> | null;
    try {
      await r.stream(`/audits/${id}/events?after=${after}`, (m) => {
        if (m.event === 'end') { ended = true; return false; }
        if (m.event === 'resync') { pending = resync((JSON.parse(m.data) as { lastSeq: number }).lastSeq); return false; }
        try { onEvent(JSON.parse(m.data) as EventDto); } catch { /* ignore malformed frame */ }
        return !until(status);
      });
    } catch {
      failed = true;
    }
    if (pending) await pending;
    if (ended || until(status)) return r.get<AuditDetailDto>(`/audits/${id}`);
    if (!failed && pending) continue;
    const now = Date.now();
    failures = [...failures.filter((t) => now - t < 30_000), now];
    if (failures.length < 3) { await sleep(timing.reconnectMs); continue; }
    // Degrade to JSON polling for a while, then try SSE again with the same `after`.
    const deadline = Date.now() + timing.sseRetryMs;
    while (Date.now() < deadline) {
      const res = await r.get<{ resync: boolean; events: EventDto[]; lastSeq: number; status: string }>(`/audits/${id}/events?after=${after}`).catch(() => null);
      if (res) {
        if (res.resync) await resync(res.lastSeq);
        else res.events.forEach(onEvent);
        if (until(res.status)) return r.get<AuditDetailDto>(`/audits/${id}`);
      }
      await sleep(timing.pollMs);
    }
    failures = [];
  }
}

export async function remoteCommand(r: Remote, cmd: string, sub: string | undefined, args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args, allowPositionals: true, strict: false,
    options: {
      project: { type: 'string' }, repo: { type: 'string' }, ref: { type: 'string' }, strategy: { type: 'string' }, title: { type: 'string' },
      yes: { type: 'boolean' }, wait: { type: 'boolean' }, json: { type: 'boolean' }, 'add-tokens': { type: 'string' }, stage: { type: 'string' }, 'decline-budget': { type: 'boolean' }, 'no-stage-quotas': { type: 'boolean' }, 'restart-filtered': { type: 'boolean' },
      path: { type: 'string' }, git: { type: 'string' }, archive: { type: 'string' }, username: { type: 'string' }, 'from-env': { type: 'string' }, name: { type: 'string' }, format: { type: 'string' }, out: { type: 'string' }, 'no-snippets': { type: 'boolean' }, 'no-local-roots': { type: 'boolean' },
      follow: { type: 'boolean' }, scene: { type: 'string' }, base: { type: 'string' }, mode: { type: 'string' }, repos: { type: 'string' }, related: { type: 'string' },
      'threat-model': { type: 'string', multiple: true },
    },
  });
  const str = (k: string) => (typeof values[k] === 'string' ? (values[k] as string) : undefined);
  const need = (v: string | undefined, what: string) => { if (!v) throw new CliExit(EXIT_ERROR, `缺少参数：${what}`); return v; };

  if (cmd === 'project') {
    if (sub === 'list') { for (const p of await r.get<ProjectDto[]>('/projects')) print(`${p.id}  ${p.name}`); return EXIT_OK; }
    if (sub === 'create') { const p = await r.post<ProjectDto>('/projects', { name: need(positionals[0], 'name') }); print(`已创建项目 ${p.name} (${p.id})`); return EXIT_OK; }
    if (sub === 'show') {
      const p = await findProject(r, need(positionals[0], 'name'));
      print(`${p.name} (${p.id})`);
      for (const rp of await r.get<RepoDto[]>(`/projects/${p.id}/repos`)) print(`  仓库 ${rp.name}  ${rp.locator}${rp.defaultRef ? `@${rp.defaultRef}` : ''}  角色 ${rp.role}${rp.roleSource === 'user' ? '（人工）' : ''}`);
      for (const v of (await r.get<Page<VulnSummaryDto>>(`/projects/${p.id}/vulnerabilities?sort=displayNo&limit=200`)).items) print(`  V-${v.displayNo} [${v.severity}] ${v.title}（${v.confirmStatus}/${v.lifecycle}）`);
      return EXIT_OK;
    }
    if (sub === 'analyze') {
      const p = await findProject(r, need(positionals[0], 'project'));
      const { analysisId } = await r.post<{ analysisId: string }>(`/projects/${p.id}/analyze`);
      let a: AnalysisDto | null;
      for (;;) {
        a = (await r.get<{ analysis: AnalysisDto | null }>(`/projects/${p.id}/analysis`)).analysis;
        if (a && a.id === analysisId && a.status !== 'running') break;
        await sleep(1000);
      }
      print(`分析 ${a.id}：${a.status}${a.reason ? `（${a.reason}）` : ''}${a.model ? ` · 模型 ${a.model} · ${a.tokens.input + a.tokens.output} tokens` : ''}`);
      for (const x of a.repos) print(`  ${x.name}  ${x.status}  ${x.roles.map((ro) => `${ro.role} ${ro.confidence.toFixed(2)}`).join('、') || '—'}${x.error ? `  ${x.error}` : ''}`);
      return a.status === 'succeeded' ? EXIT_OK : a.status === 'partial' ? EXIT_INCOMPLETE : EXIT_ERROR;
    }
    if (sub === 'add-repo') {
      const p = await findProject(r, need(positionals[0], 'project'));
      if ([str('path'), str('git'), str('archive')].filter(Boolean).length !== 1) throw new CliExit(EXIT_ERROR, '需要且只能指定 --path、--git、--archive 之一');
      if (str('archive') && str('ref')) throw new CliExit(EXIT_ERROR, '压缩包没有分支或提交，不能指定 --ref');
      const source = str('git') ? { git: str('git') } : str('archive') ? { uploadId: (await r.upload(resolve(str('archive')!))).uploadId } : { path: resolve(str('path')!) };
      const res = await r.post<{ results: { ok: boolean; repo?: RepoDto; error?: { code: string; hint: string | null } }[] }>(`/projects/${p.id}/repos`, {
        repos: [{ ...source, ...(str('ref') ? { ref: str('ref') } : {}), ...(str('name') ? { name: str('name') } : {}) }],
      }).catch((e) => { if (e instanceof RemoteError && e.status === 422) return null; throw e; });
      const first = res?.results[0];
      if (!first?.ok) throw new CliExit(EXIT_ERROR, `添加失败：${first?.error?.hint ?? first?.error?.code ?? ''}`);
      print(`已添加仓库 ${first.repo!.name} → ${first.repo!.locator}${first.repo!.auditable ? '' : '（上下文仓库：未发现可完整审计的源码）'}`);
      return EXIT_OK;
    }
  }
  if (cmd === 'audit') {
    if (sub === 'list') {
      const p = str('project') ? await findProject(r, str('project')!) : null;
      for (const a of (await r.get<Page<AuditSummaryDto>>(`/audits?limit=200${p ? `&projectId=${p.id}` : ''}`)).items.reverse()) print(`${a.id}  ${a.status.padEnd(16)} ${a.createdAt.slice(0, 16)}  ${a.title}`);
      return EXIT_OK;
    }
    if (sub === 'status') {
      const id = need(positionals[0], 'auditId');
      let a = await r.get<AuditDetailDto>(`/audits/${id}`);
      if (values.follow && !TERMINAL.includes(a.status)) a = await follow(r, id, (s) => TERMINAL.includes(s) || ['waiting_budget', 'paused', 'interrupted', 'awaiting_confirm'].includes(s));
      if (values.json) { printJson(a); return EXIT_OK; }
      print(`${a.id}  ${a.title}`);
      print(`状态：${a.status}${a.partialReasons.length ? `（${a.partialReasons.join(' > ')}）` : ''} · 阶段 ${a.phase}`);
      print(`预算：${a.budget.consumed.tokens}/${a.budget.effective.tokens} tokens`);
      for (const st of a.steps) print(`  ${st.kind.padEnd(10)} ${st.status.padEnd(14)} attempt=${st.attempt} tokens=${st.tokensIn + st.tokensOut}${st.errorClass ? ` ${st.errorClass}` : ''}`);
      return EXIT_OK;
    }
    if (sub === 'cancel') { await r.post(`/audits/${need(positionals[0], 'auditId')}/cancel`); print('已取消'); return EXIT_OK; }
    if (sub === 'start') {
      const p = await findProject(r, need(str('project'), '--project'));
      const tms = (values['threat-model'] as string[] | undefined)?.filter((x) => typeof x === 'string');
      const base = str('strategy') ? JSON.parse(readFileSync(resolve(str('strategy')!), 'utf8')) as Record<string, unknown> : undefined;
      // --threat-model <id> (repeatable).
      const override = tms?.length ? { ...(base ?? {}), threatModels: [...new Set(tms)] } : base;
      const repos = await r.get<RepoDto[]>(`/projects/${p.id}/repos`);
      const multi = str('mode') === 'multi';
      const repo = str('repo') ? repos.find((x) => x.name === str('repo') || x.id === str('repo')) : repos.filter((x) => x.auditable).length === 1 ? repos.find((x) => x.auditable) : undefined;
      if (!repo && !multi) throw new CliExit(EXIT_ERROR, str('repo') ? `仓库不存在：${str('repo')}` : '项目有多个仓库，请用 --repo 指定目标仓库，或 --mode multi 做多仓库合并审计');
      const created = await r.post<{ auditId: string }>('/audit-plans', {
        projectId: p.id, ...(repo && !multi ? { repository: repo.id } : {}), ...modeArgs(str('mode'), str('repos'), str('related')), ...(str('ref') ? { ref: str('ref') } : {}), ...(str('title') ? { title: str('title') } : {}), ...(override ? { strategyOverride: override } : {}),
        ...(str('scene') ? { scene: str('scene') } : {}), ...(str('base') ? { baseRef: str('base') } : {}),
      });
      const id = created.auditId;
      print(`审计 ${id} 已创建（服务模式），正在生成计划…`);
      const a = await follow(r, id, (s) => s !== 'planning');
      if (a.status !== 'awaiting_confirm') return exitFor(a, id);
      const plan = await r.get<PlanDto>(`/audit-plans/${id}`);
      if (plan.plan) {
        print('— 审计计划 —');
        print(plan.plan.summary);
        const inc = plan.plan.incremental;
        if (inc) print(`增量：对比 ${inc.base.ref ?? (inc.base.commit ? inc.base.commit.slice(0, 12) : '上次审计的版本')}；变更文件 新增 ${inc.changedFiles.added} / 修改 ${inc.changedFiles.modified} / 删除 ${inc.changedFiles.deleted} / 移动 ${inc.changedFiles.renamed}；影响分析 ${inc.mode}`);
        for (const d of plan.plan.focusDirections) print(`  重点：${d.direction} — ${d.reason}`);
        print(`预估：${plan.plan.estimate.tokens.p50}–${plan.plan.estimate.tokens.p90} tokens`);
      }
      if (!values.yes) {
        if (!process.stdin.isTTY) throw new CliExit(EXIT_ERROR, `非交互环境需要 --yes 确认计划；也可以在界面中确认：${r.base}/audits/${id}`);
        if (!(await confirm('确认按此计划开始审计？'))) { await r.post(`/audits/${id}/cancel`); print('已取消'); return EXIT_INCOMPLETE; }
      }
      await r.post(`/audit-plans/${id}/confirm`, {}, { 'idempotency-key': `cli-confirm-${id}` });
      if (!values.wait) { print(`已开始。查看进度：xiezhi audit status ${id} --follow，或在界面打开 ${r.base}/audits/${id}`); return EXIT_OK; }
      return exitFor(await follow(r, id, (s) => TERMINAL.includes(s) || ['waiting_budget', 'paused', 'interrupted'].includes(s), undefined, a.lastEventSeq), id);
    }
    if (sub === 'resume') {
      const id = need(positionals[0], 'auditId');
      const a = await r.get<AuditDetailDto>(`/audits/${id}`);
      if (values['no-stage-quotas']) {
        await r.post(`/audits/${id}/budget-grants`, { ...(str('add-tokens') ? { tokens: Number(str('add-tokens')) } : {}), liftStageQuotas: true }, { 'idempotency-key': `cli-${id}-${a.budget.effective.tokens}-lift-${str('add-tokens') ?? ''}` });
        if (a.status === 'interrupted' || a.status === 'paused') await r.post(`/audits/${id}/resume`, values['restart-filtered'] ? { restartFiltered: true } : undefined);
      } else if (a.status === 'waiting_budget') {
        if (values['decline-budget']) await r.post(`/audits/${id}/budget-grants/decline`);
        else if (str('add-tokens')) await r.post(`/audits/${id}/budget-grants`, { tokens: Number(str('add-tokens')), ...(str('stage') ? { stage: str('stage') } : {}) }, { 'idempotency-key': `cli-${id}-${a.budget.effective.tokens}-${str('add-tokens')}-${str('stage') ?? ''}` });
        else throw new CliExit(EXIT_ERROR, '审计在等待预算：使用 --add-tokens N 追加、--no-stage-quotas 取消阶段额度，或 --decline-budget 用已有结果收尾');
      } else {
        if (str('add-tokens')) await r.post(`/audits/${id}/budget-grants`, { tokens: Number(str('add-tokens')) }, { 'idempotency-key': `cli-${id}-${a.budget.effective.tokens}-${str('add-tokens')}` });
        if (a.status === 'interrupted' || a.status === 'paused') await r.post(`/audits/${id}/resume`, values['restart-filtered'] ? { restartFiltered: true } : undefined);
      }
      print('已继续');
      if (!values.wait) return EXIT_OK;
      return exitFor(await follow(r, id, (s) => TERMINAL.includes(s) || ['waiting_budget', 'paused', 'interrupted'].includes(s)), id);
    }
  }
  if (cmd === 'config' && (sub === 'set-git-credential' || sub === 'remove-git-credential')) {
    const host = (positionals[0] ?? '').trim().toLowerCase();
    if (!/^[a-z0-9.-]+(:[0-9]{1,5})?$/.test(host)) throw new CliExit(EXIT_ERROR, 'host 应为域名（可带端口），例如 gitlab.example.com');
    if (sub === 'remove-git-credential') {
      await r.send('DELETE', `/settings/git-credentials/${encodeURIComponent(host)}`);
      print(`已删除 ${host} 的 Git 凭证`);
      return EXIT_OK;
    }
    const username = need(str('username'), '--username');
    const envVar = str('from-env');
    const token = envVar ? process.env[envVar] ?? '' : await readSecret(`输入 ${host} 的 token（不回显）：`);
    if (!token) throw new CliExit(EXIT_ERROR, 'token 为空');
    const saved = await r.send<GitCredentialDto>('PUT', `/settings/git-credentials/${encodeURIComponent(host)}`, { username, token });
    print(`已保存 ${host} 的 Git 凭证（${saved.token.hint ?? '已配置'}）`);
    return EXIT_OK;
  }
  if (cmd === 'hunt') {
    return huntCommand({
      createBasis: async (input) => (await r.post<{ basisId: string }>('/hunt-bases', input)).basisId,
      getBasis: (id) => r.get(`/hunt-bases/${id}`),
      createHunt: (basisId, scope) => r.post('/hunts', { basisId, ...('all' in scope ? { allProjects: true } : { projectIds: scope.projectIds }) }),
      confirm: async (id) => { await r.post(`/hunts/${id}/confirm`); },
      getHunt: (id) => r.get(`/hunts/${id}`),
      results: (id) => r.get(`/hunts/${id}/results`),
      promote: (hitId) => r.post(`/hunt-hits/${hitId}/promote`),
      export: async (id, format) => (await r.raw(`/hunts/${id}/export?format=${format}`)).text(),
      saveAsSkill: async (id, category, name) => r.post<{ name: string; draftId: string }>(`/hunt-bases/${id}/save-as-skill`, { category, ...(name ? { name } : {}) }),
    }, sub, args);
  }
  if (cmd === 'export') {
    const id = need(sub, 'auditId');
    const format = need(str('format'), '--format');
    if (!['md', 'html', 'json', 'sarif'].includes(format)) throw new CliExit(EXIT_ERROR, 'format 只能是 md、html、json、sarif');
    const job = await r.post<ExportDto>('/exports', { scope: 'audit', ids: [id], format, ...(values['no-snippets'] ? { snippets: false } : {}), ...(values['no-local-roots'] ? { localRoots: false } : {}) });
    if (job.status !== 'succeeded') throw new CliExit(EXIT_ERROR, '导出失败');
    const res = await r.raw(`/exports/${job.id}/download`);
    const out = resolve(need(str('out'), '--out'));
    writeFileSync(out, Buffer.from(await res.arrayBuffer()));
    print(`已导出 ${out}${job.warning ? `（注意：${job.warning}）` : ''}`);
    return EXIT_OK;
  }
  throw new CliExit(EXIT_ERROR, `服务运行中：${cmd} ${sub ?? ''} 需要在界面中操作，或先停止服务（服务持有数据目录的写锁）`);
}
