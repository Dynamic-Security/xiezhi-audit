#!/usr/bin/env node
// xiezhi CLI. Headless mode — the CLI holds the single-writer lock and runs the
// same engine in-process. Exit codes: 0 ok, 2 argument/system error, 3 audit not completed.
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { basename, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { AppError, appVersion, BUDGET_STAGES, CONFIG_MODEL_STAGES, NO_MODEL_STAGES, maskSecret, originOf, type AppConfig, type BudgetStage, type ModelApi, type SkillCategory } from '@xiezhi/contracts';
import { Store, resolveDataDir } from '@xiezhi/store';
import {
  Engine, renderThreatModelReport, approveKnowledgeDraft, findDraft, listAllDrafts, rejectKnowledgeDraft, addArchiveRepository, addGitRepository, addRepository, answerQuestion, createHunt, getBasis, getHunt, huntPlan, huntTargets, refreshHunt, createProject, getAudit, getProject, listProjects, listRepositories, runDoctor, type AuditPlan, type RunResult, queries as Q,
} from '@xiezhi/engine';
import { exportAudit, type ExportFormat } from '@xiezhi/report';
import { caseIndexBody, installBuiltinSkills, listKnowledge, readSkill, scanLayer } from '@xiezhi/knowledge';
import { Recorder, Replayer, listModels, piVersion, promptTemplateHash, withProbedLimits, type ModelMode } from '@xiezhi/agent';
import { collectSecrets, toolSchemaHash } from '@xiezhi/contracts';
import { startServer, DEFAULT_PORT, draftDto } from '@xiezhi/server';
import { knowledgeWriteCommand } from './knowledge.js';
import { errorText as evalErrorText, main as evalMain } from '@xiezhi/eval';
import { Executor, openBrowser } from '@xiezhi/context';
import { CliExit, EXIT_ERROR, EXIT_INCOMPLETE, EXIT_OK, confirm, errorLine, print, printJson, questionPrompter, readSecret, rejectSecretArgs } from './io.js';
import { RemoteError, discover, findProject, remoteCommand } from './remote.js';
import { modeArgs } from './modes.js';
import { huntCommand } from './hunt.js';


const HELP = `xiezhi — 代码安全审计

用法：xiezhi [--data-dir DIR] <命令> [参数]

  serve [--port N] [--open]                         启动本地服务与 Web 工作台（仅监听 127.0.0.1，默认 4820）；--open 自动打开浏览器
  open                                              服务运行中时，生成新的一次性浏览器登录链接
  doctor [--json]                                   环境诊断
  version                                           显示版本
  config list | get <key> | set <key> <value>       配置（defaultModel / fallbackModel 用 provider/model；
                                                    stageModels.<阶段> 用 provider/model、default 或 none）
  config add-provider <id> --api <api> --base-url <url> --models a,b [--context-window N] [--max-tokens N]
                                                    读取服务端模型列表中的上下文窗口 / 最大输出（若有）；
                                                    --context-window / --max-tokens 对所列模型统一设置（支持 200k 写法）
  config set-model-limits <providerId> <modelId> [--context-window N] [--max-tokens N]
                                                    设置单个模型的上下文窗口 / 最大输出；未设置时按 128k / 8192 处理
  config set-secret <providerId> [--from-env VAR]   设置模型服务密钥（TTY 隐藏输入或 stdin）
  config set-git-credential <host> --username <u> [--from-env VAR]
                                                    设置某域名的 Git HTTPS token（TTY 隐藏输入或 stdin）
  config remove-git-credential <host>               删除某域名的 Git 凭证
  project create <name> | list | show <name>
  project analyze <project>                         AI 识别仓库角色（手动触发；使用轻量模型，未设置时用默认模型）
  project add-repo <project> (--path <dir> | --git <url> | --archive <file>) [--ref <ref>] [--name <name>]
                                                    本地目录、Git 地址（https / ssh）或压缩包（zip / tar / tar.gz）
  audit start --project <p> [--scene full|incremental] [--base <ref>] [--repo <r>] [--ref <ref>] [--strategy <file.json>] [--title <t>] [--yes] [--wait]
             [--related <r1,r2>] | [--mode multi [--repos <r1,r2>]]
                                                    单仓库审计可加关联仓库（只作证据）；多仓库合并审计默认包含全部可审计仓库
                                                    增量审计默认对比上次审计的版本，--base 指定任意分支或提交
             [--threat-model <id> …]                关联需求威胁模型（可重复；全量或增量审计）
  audit status <auditId> [--json] [--follow]          --wait / --follow 只在客户端模式（服务运行时）有效
  audit list [--project <p>]
  audit resume <auditId> [--add-tokens N [--stage S]] [--no-stage-quotas] [--decline-budget] [--restart-filtered]
                                                    --restart-filtered：被内容过滤拦截的步骤从头开始（不加则原样重试）
  audit cancel <auditId>
  export <auditId> --format md|html|json|sarif --out <path> [--no-snippets] [--no-local-roots]
  knowledge list|show <name>|lint [--project <p>] [--json]    知识库（只读；编辑用界面或任意编辑器）
  knowledge import <文件|-> [--project <p>] [--case] [--no-organize]   导入为草稿（AI 整理、校验、查重）
  knowledge drafts [--project <p>] | approve <draftId> [--replace] [--delete-original] | reject <draftId>
  eval validate|run|score|report|experiment …          评测基准；基准目录用 --bench 或 XIEZHI_AUDIT_BENCH
  hunt basis (--prompt <文本|@文件> | --intel <文本|@文件> | --skill <name>)   AI 整理风险排查依据
  hunt start --basis <id> (--projects a,b | --all) [--yes] [--wait]         风险排查（每个项目一条排查审计）
  hunt show <huntId> | promote <hitId> | export <huntId> --format md|html|json --out <path>
  hunt save-skill <basisId> [--category vuln_case|audit_method] [--name n]
  threat-model list --project <p> [--json] | export <id> [--out <path>]   需求威胁模型（只读；新建与研判用界面）

服务运行时，project / audit / export 命令通过本地 API 提交（客户端模式）；audit start 默认确认后立即返回，
加 --wait 等待结束；audit status <id> --follow 跟随进度。

退出码：0 成功；2 参数或系统错误；3 审计未完成（partial / 已取消 / 已中断 / 等待预算）。
退出码不反映漏洞数量或严重度。`;

function openStore(dataDir: string | undefined, lock = true): Store {
  return Store.open({ dataDir: resolveDataDir(dataDir), role: 'cli', lock });
}

/**
 * Test hooks: XIEZHI_AUDIT_REPLAY=<fixture> serves recorded responses (mismatch fails, no
 * network); XIEZHI_AUDIT_RECORD=<fixture> records live responses (redacted) and appends on exit.
 */
const recorders: { recorder: Recorder; path: string; models: string[] }[] = [];

async function openEngine(store: Store): Promise<Engine> {
  let mode: ModelMode = { kind: 'live' };
  if (process.env.XIEZHI_AUDIT_REPLAY) mode = { kind: 'replay', replayer: Replayer.load(process.env.XIEZHI_AUDIT_REPLAY) };
  else if (process.env.XIEZHI_AUDIT_RECORD) {
    const recorder = new Recorder(collectSecrets(store.config));
    recorders.push({ recorder, path: process.env.XIEZHI_AUDIT_RECORD, models: store.config.modelProviders.flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`)) });
    mode = { kind: 'record', recorder };
  }
  return Engine.open({ store, mode });
}

function flushRecordings(): void {
  for (const r of recorders.splice(0)) r.recorder.save(r.path, { piVersion: piVersion(), models: r.models, recordedAt: new Date().toISOString(), promptHash: promptTemplateHash(), toolSchemaHash: toolSchemaHash() });
}

function need(v: string | undefined, what: string): string {
  if (!v) throw new CliExit(EXIT_ERROR, `缺少参数：${what}`);
  return v;
}

function printPlan(plan: AuditPlan): void {
  print('— 审计计划 —');
  print(plan.submitted.summary);
  print(`规模：文件 ${plan.scale.files}，入口 ${plan.scale.entrypoints}，危险点 ${plan.scale.sinks}，候选 ${plan.scale.candidates}`);
  if (plan.incremental) {
    const i = plan.incremental;
    print(`增量：对比 ${i.base.ref ?? (i.base.commit ? i.base.commit.slice(0, 12) : '上次审计的版本')}；变更文件 新增 ${i.changedFiles.added} / 修改 ${i.changedFiles.modified} / 删除 ${i.changedFiles.deleted} / 移动 ${i.changedFiles.renamed}；影响分析 ${i.mode}${i.fallbackReasons.length ? `（${i.fallbackReasons.join(', ')}）` : ''}`);
  }
  for (const d of plan.submitted.focusDirections) print(`  重点：${d.direction} — ${d.reason}`);
  if (plan.submitted.contextNeeded.length) print(`待补充上下文：${plan.submitted.contextNeeded.join('；')}`);
  const e = plan.estimate;
  print(`预估：${e.tokens.p50}–${e.tokens.p90} tokens，${Math.round(e.durationSec.p50 / 60)}–${Math.round(e.durationSec.p90 / 60)} 分钟${e.cost ? `，成本 ${e.cost.p50.toFixed(2)}–${e.cost.p90.toFixed(2)} ${e.cost.currency}` : '，成本未知'}`);
  for (const l of plan.limitations) print(`  限制：${l}`);
}

function resultExit(r: RunResult | { status: string; partialReasons: string[] }, auditId: string): number {
  const reasons = r.partialReasons.length ? `（${r.partialReasons.join(' > ')}）` : '';
  print(`审计 ${auditId} 结束状态：${r.status}${reasons}`);
  if (r.status === 'completed') return EXIT_OK;
  if (r.status === 'waiting_budget') {
    const s = (r as RunResult).suggestedTopUp;
    print(`预算不足。追加后继续：xiezhi audit resume ${auditId} --add-tokens ${s ?? 100000}`);
    print(`或放弃并用已有结果收尾：xiezhi audit resume ${auditId} --decline-budget`);
  }
  if (r.status === 'interrupted') print(`已中断，可继续：xiezhi audit resume ${auditId}`);
  if (r.status === 'paused') print(`已暂停，可继续：xiezhi audit resume ${auditId}（有步骤被内容过滤拦截时，加 --restart-filtered 让这些步骤从头开始）`);
  return r.status === 'failed' ? EXIT_ERROR : EXIT_INCOMPLETE;
}

async function runWithSignal<T>(fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const ac = new AbortController();
  const onSig = () => {
    if (!ac.signal.aborted) {
      process.stderr.write('\n收到中断信号，正在保存进度…\n');
      ac.abort();
    }
  };
  process.on('SIGINT', onSig);
  process.on('SIGTERM', onSig);
  try {
    return await fn(ac.signal);
  } finally {
    process.off('SIGINT', onSig);
    process.off('SIGTERM', onSig);
  }
}

function onEvents(store: Store): () => void {
  return store.onEvent((e) => {
    if (e.type === 'step.status_changed' && ['running', 'succeeded', 'failed'].includes(String(e.payload.to))) {
      print(`  [${new Date(e.ts).toISOString().slice(11, 19)}] ${e.payload.kind} ${e.payload.to}${e.payload.error_class ? ` (${e.payload.error_class})` : ''}`);
    } else if (e.type === 'vuln.created') {
      print(`  发现漏洞 V-${e.payload.display_no}（${e.payload.confirm_status}）`);
    } else if (e.type === 'question.asked') {
      print(`  Agent 提问${e.payload.blocking ? '（影响结论）' : ''}：${e.payload.text}`);
    }
  });
}

/** While the queue runs on a TTY, Agent questions are asked interactively. */
async function runQueueInteractive(store: Store, engine: Engine) {
  const prompter = questionPrompter(async (qid, text) => { await answerQuestion(engine, qid, text); });
  const off = store.onEvent((e) => { if (e.type === 'question.asked') prompter.ask(String(e.payload.question_id), String(e.payload.text)); });
  try {
    return await runWithSignal((signal) => engine.runQueue(signal));
  } finally {
    off();
    prompter.stop();
  }
}

/** `--add-tokens N [--stage S]`: the tokens go to the total, and to stage S's quota when given. */
function topUpDelta(values: { 'add-tokens'?: string; stage?: string }): { tokens: number; stage?: BudgetStage } {
  const stage = values.stage;
  if (stage !== undefined && !(BUDGET_STAGES as readonly string[]).includes(stage)) throw new CliExit(EXIT_ERROR, `--stage 只能是 ${BUDGET_STAGES.join(' / ')}`);
  return { tokens: Number(values['add-tokens']), ...(stage ? { stage: stage as BudgetStage } : {}) };
}

/** `--threat-model <id>` (repeatable): the requirement threat models the audit references. */
export function withThreatModelArgs(override: Record<string, unknown> | undefined, ids: string[] | undefined): Record<string, unknown> | undefined {
  if (!ids?.length) return override;
  return { ...(override ?? {}), threatModels: [...new Set(ids)] };
}

/** `threat-model list --project <p>` and `threat-model export <id> --out <path>` (read-only). */
async function cmdThreatModel(sub: string | undefined, args: string[], dataDir?: string): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { project: { type: 'string' }, out: { type: 'string' }, json: { type: 'boolean' } } });
  const store = openStore(dataDir, false);
  try {
    if (sub === 'list') {
      const project = getProject(store, need(values.project, '--project'));
      const rows = Q.listThreatModels(store, project.id);
      if (values.json) { printJson(rows); return EXIT_OK; }
      for (const t of rows) print(`${t.id}  ${t.status.padEnd(10)} 来源 ${t.sourceCount}  需规避 ${t.riskCounts.to_mitigate} 已规避 ${t.riskCounts.mitigated} 接受 ${t.riskCounts.accepted} 误报 ${t.riskCounts.false_positive} 待研判 ${t.riskCounts.pending}  ${t.title}`);
      return EXIT_OK;
    }
    if (sub === 'export') {
      const text = renderThreatModelReport(store, need(positionals[0], 'threatModelId'));
      if (values.out) { writeFileSync(resolve(values.out), text); print(`已导出到 ${resolve(values.out)}`); } else print(text);
      return EXIT_OK;
    }
    throw new CliExit(EXIT_ERROR, 'threat-model 子命令：list | export');
  } finally {
    store.close();
  }
}

async function cmdAudit(sub: string | undefined, args: string[], dataDir?: string): Promise<number> {
  const { values, positionals } = parseArgs({
    args, allowPositionals: true,
    options: {
      project: { type: 'string' }, repo: { type: 'string' }, ref: { type: 'string' }, strategy: { type: 'string' }, title: { type: 'string' },
      yes: { type: 'boolean' }, wait: { type: 'boolean' }, json: { type: 'boolean' }, 'add-tokens': { type: 'string' }, stage: { type: 'string' }, 'decline-budget': { type: 'boolean' }, 'no-stage-quotas': { type: 'boolean' }, 'restart-filtered': { type: 'boolean' },
      scene: { type: 'string' }, base: { type: 'string' }, mode: { type: 'string' }, repos: { type: 'string' }, related: { type: 'string' },
      'threat-model': { type: 'string', multiple: true },
    },
  });
  if (values.scene && !['full', 'incremental'].includes(values.scene)) throw new CliExit(EXIT_ERROR, 'scene 只能是 full 或 incremental');
  const store = openStore(dataDir);
  try {
    if (sub === 'list') {
      const rows = Q.auditList(store, values.project);
      for (const r of rows) print(`${r.id}  ${r.status.padEnd(16)} ${new Date(r.created_at).toISOString().slice(0, 16)}  ${r.title}`);
      return EXIT_OK;
    }
    if (sub === 'status') {
      const id = need(positionals[0], 'auditId');
      const engine = await openEngine(store);
      const s = engine.status(id);
      if (values.json) { printJson({ ...s, audit: { ...s.audit } }); return EXIT_OK; }
      const consumed = JSON.parse(s.audit.budget_consumed) as { tokens: number };
      const eff = JSON.parse(s.audit.budget_effective) as { tokens: number };
      print(`${s.audit.id}  ${s.audit.title}`);
      print(`状态：${s.audit.status}${JSON.parse(s.audit.partial_reasons).length ? `（${JSON.parse(s.audit.partial_reasons).join(' > ')}）` : ''}`);
      print(`预算：${consumed.tokens}/${eff.tokens} tokens`);
      for (const st of s.steps) print(`  ${st.kind.padEnd(10)} ${st.status.padEnd(14)} attempt=${st.attempt} tokens=${st.tokens}${st.error ? ` ${st.error}` : ''}`);
      return EXIT_OK;
    }
    if (sub === 'cancel') {
      const engine = await openEngine(store);
      engine.cancel(need(positionals[0], 'auditId'));
      print('已取消');
      return EXIT_OK;
    }
    if (sub === 'start') {
      const engine = await openEngine(store);
      const project = getProject(store, need(values.project, '--project'));
      const override = withThreatModelArgs(values.strategy ? JSON.parse(readFileSync(resolve(values.strategy), 'utf8')) as Record<string, unknown> : undefined, values['threat-model']);
      const id = engine.createAudit({
        projectId: project.id, origin: 'cli', ...(values.repo ? { repository: values.repo } : {}), ...(values.ref ? { ref: values.ref } : {}),
        ...(values.scene ? { scene: values.scene as 'full' | 'incremental' } : {}), ...(values.base ? { baseRef: values.base } : {}),
        ...(values.title ? { title: values.title } : {}), ...(override ? { strategyOverride: override } : {}),
        ...modeArgs(values.mode, values.repos, values.related),
      });
      print(`审计 ${id} 已创建，正在生成计划…`);
      const off = onEvents(store);
      try {
        const plan = await runWithSignal((signal) => engine.plan(id, signal));
        if (!plan) return resultExit({ status: getAudit(store, id).status, partialReasons: [] }, id);
        printPlan(plan);
        if (!values.yes) {
          if (!process.stdin.isTTY) throw new CliExit(EXIT_ERROR, '非交互环境需要 --yes 确认计划');
          if (!(await confirm('确认按此计划开始审计？'))) {
            engine.cancel(id);
            print('已取消');
            return EXIT_INCOMPLETE;
          }
        }
        engine.confirm(id);
        const results = await runQueueInteractive(store, engine);
        // A run that requeues itself leaves several results for one audit; the last one is final.
        const mine = results.findLast((r) => r.auditId === id);
        return resultExit(mine?.result ?? { status: getAudit(store, id).status, partialReasons: [] }, id);
      } finally {
        off();
      }
    }
    if (sub === 'resume') {
      const id = need(positionals[0], 'auditId');
      const engine = await openEngine(store);
      const a = getAudit(store, id);
      const off = onEvents(store);
      try {
        // --no-stage-quotas drops the audit's stage quotas (with --add-tokens, in the same grant).
        if (values['no-stage-quotas']) engine.topUp(id, { ...(values['add-tokens'] ? { tokens: Number(values['add-tokens']) } : {}), liftStageQuotas: true }, `cli-${id}-${a.budget_effective}-lift-${values['add-tokens'] ?? ''}`);
        else if (a.status === 'waiting_budget') {
          if (values['decline-budget']) engine.declineBudget(id);
          else if (values['add-tokens']) engine.topUp(id, topUpDelta(values), `cli-${id}-${a.budget_effective}-${values['add-tokens']}-${values.stage ?? ''}`);
          else throw new CliExit(EXIT_ERROR, '审计在等待预算：使用 --add-tokens N 追加、--no-stage-quotas 取消阶段额度，或 --decline-budget 用已有结果收尾');
        } else if (values['add-tokens']) {
          engine.topUp(id, topUpDelta(values), `cli-${id}-${a.budget_effective}-${values['add-tokens']}-${values.stage ?? ''}`);
        }
        const now = getAudit(store, id);
        if (now.status === 'interrupted' || now.status === 'paused') engine.resume(id, values['restart-filtered'] ? { restartFiltered: true } : {});
        if (getAudit(store, id).status === 'planning') {
          const plan = await runWithSignal((signal) => engine.plan(id, signal));
          if (!plan) return resultExit({ status: getAudit(store, id).status, partialReasons: [] }, id);
          printPlan(plan);
          if (!values.yes && !(await confirm('确认按此计划开始审计？'))) return EXIT_INCOMPLETE;
          engine.confirm(id);
        }
        const results = await runQueueInteractive(store, engine);
        // A run that requeues itself leaves several results for one audit; the last one is final.
        const mine = results.findLast((r) => r.auditId === id);
        return resultExit(mine?.result ?? { status: getAudit(store, id).status, partialReasons: JSON.parse(getAudit(store, id).partial_reasons) }, id);
      } finally {
        off();
      }
    }
    throw new CliExit(EXIT_ERROR, `未知子命令 audit ${sub ?? ''}`);
  } finally {
    store.close();
  }
}

async function cmdProject(sub: string | undefined, args: string[], dataDir?: string): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { path: { type: 'string' }, git: { type: 'string' }, archive: { type: 'string' }, ref: { type: 'string' }, name: { type: 'string' } } });
  const store = openStore(dataDir);
  try {
    if (sub === 'create') { const p = createProject(store, need(positionals[0], 'name')); print(`已创建项目 ${p.name} (${p.id})`); return EXIT_OK; }
    if (sub === 'list') { for (const p of listProjects(store)) print(`${p.id}  ${p.name}`); return EXIT_OK; }
    if (sub === 'show') {
      const p = getProject(store, need(positionals[0], 'name'));
      print(`${p.name} (${p.id})`);
      for (const r of listRepositories(store, p.id)) print(`  仓库 ${r.name}  ${r.source_uri}${r.default_ref ? `@${r.default_ref}` : ''}  角色 ${r.role}${r.role_source === 'user' ? '（人工）' : ''}`);
      const vulns = Q.projectVulnList(store, p.id);
      for (const v of vulns) print(`  V-${v.display_no} [${v.severity}] ${v.title}（${v.confirm_status}/${v.lifecycle}）`);
      return EXIT_OK;
    }
    if (sub === 'analyze') {
      const p = getProject(store, need(positionals[0], 'project'));
      const engine = await openEngine(store);
      const id = engine.jobs.startAnalysis(p.id);
      await engine.jobs.analysisDone(id);
      printAnalysis(store, id);
      const st = Q.projectAnalysis(store, id)!.status;
      return st === 'succeeded' ? EXIT_OK : st === 'partial' ? EXIT_INCOMPLETE : EXIT_ERROR;
    }
    if (sub === 'add-repo') {
      const p = getProject(store, need(positionals[0], 'project'));
      if ([values.path, values.git, values.archive].filter(Boolean).length !== 1) throw new CliExit(EXIT_ERROR, '需要且只能指定 --path、--git、--archive 之一');
      const name = values.name ? { name: values.name } : {};
      const ref = values.ref ? { ref: values.ref } : {};
      let r;
      if (values.git) r = await addGitRepository(store, cliExecutor(store), p.id, { url: values.git, ...ref, ...name });
      else if (values.archive) {
        if (values.ref) throw new CliExit(EXIT_ERROR, '压缩包没有分支或提交，不能指定 --ref');
        r = await addArchiveRepository(store, cliExecutor(store), p.id, { file: resolve(values.archive), fileName: basename(values.archive), ...name });
      } else r = addRepository(store, p.id, { path: values.path!, ...ref, ...name });
      print(`已添加仓库 ${r.name} → ${r.source_uri}${r.is_auditable ? '' : '（上下文仓库：未发现可完整审计的源码）'}`);
      return EXIT_OK;
    }
    throw new CliExit(EXIT_ERROR, `未知子命令 project ${sub ?? ''}`);
  } finally {
    store.close();
  }
}

function printAnalysis(store: Store, id: string): void {
  const a = Q.projectAnalysis(store, id)!;
  print(`分析 ${id}：${a.status}${a.reason ? `（${a.reason}）` : ''}${a.model ? ` · 模型 ${a.model} · ${a.tokens_in + a.tokens_out} tokens` : ''}`);
  for (const r of Q.analysisRoleRows(store, id)) {
    print(`  ${r.name}  ${r.status}  角色 ${r.role}${r.role_source === 'user' ? '（人工修正，未覆盖）' : ''}${r.error ? `  ${r.error}` : ''}`);
  }
}

/** Same executor settings as the engine, for repository probes in headless mode. */
function cliExecutor(store: Store): Executor {
  const t = store.config.tools;
  return new Executor({ scratchDir: join(store.paths.tmp, 'exec'), paths: { ...(t.rgPath ? { rg: t.rgPath } : {}), ...(t.gitPath ? { git: t.gitPath } : {}) } });
}

function maskedConfig(cfg: AppConfig): unknown {
  return {
    ...cfg, modelProviders: cfg.modelProviders.map((p) => ({ ...p, apiKey: maskSecret(p.apiKey) })),
    ...(cfg.gitCredentials ? { gitCredentials: cfg.gitCredentials.map((c) => ({ ...c, token: maskSecret(c.token) })) } : {}),
  };
}

export function gitHostArg(raw: string | undefined): string {
  const host = (raw ?? '').trim().toLowerCase();
  if (!/^[a-z0-9.-]+(:[0-9]{1,5})?$/.test(host)) throw new CliExit(EXIT_ERROR, 'host 应为域名（可带端口），例如 gitlab.example.com');
  return host;
}

const SETTABLE: Record<string, (cfg: AppConfig, v: string) => AppConfig> = {
  defaultModel: (c, v) => ({ ...c, defaultModel: modelRef(v) }),
  fallbackModel: (c, v) => ({ ...c, fallbackModel: modelRef(v) }),
  // per-stage models — provider/model, `none` (triage / merge only) or `default` (follow the default model).
  ...Object.fromEntries(CONFIG_MODEL_STAGES.map((k) => [`stageModels.${k}`, (c: AppConfig, v: string): AppConfig => {
    const sm: Record<string, unknown> = { ...(c.stageModels ?? {}) };
    if (v === 'default') delete sm[k];
    else if (v === 'none') {
      if (!(NO_MODEL_STAGES as readonly string[]).includes(k)) throw new CliExit(EXIT_ERROR, `${k} 阶段不能不用模型；用 default 跟随默认模型`);
      sm[k] = null;
    } else sm[k] = modelRef(v);
    return { ...c, stageModels: sm as AppConfig['stageModels'] };
  }])),
  'concurrency.modelRequests': (c, v) => ({ ...c, concurrency: { ...c.concurrency, modelRequests: Number(v) } }),
  'engine.budgetTolerance': (c, v) => ({ ...c, engine: { ...c.engine, budgetTolerance: Number(v) } }),
  'export.snippets': (c, v) => ({ ...c, export: { ...c.export, snippets: v === 'true' } }),
  'export.localRoots': (c, v) => ({ ...c, export: { ...c.export, localRoots: v === 'true' } }),
  'tools.rgPath': (c, v) => ({ ...c, tools: { ...c.tools, rgPath: v } }),
  'tools.gitPath': (c, v) => ({ ...c, tools: { ...c.tools, gitPath: v } }),
};

function modelRef(v: string) {
  const [provider, ...rest] = v.split('/');
  if (!provider || rest.length === 0) throw new CliExit(EXIT_ERROR, '模型格式为 provider/model');
  return { provider, model: rest.join('/') };
}

/** A token count from the command line: digits, optionally with k / m (`200k`). */
function tokenArg(v: string | undefined, flag: string, min: number): number | undefined {
  if (v === undefined) return undefined;
  const m = /^\s*(\d+(?:\.\d+)?)\s*([km]?)\s*$/i.exec(v);
  const n = m ? Math.round(Number(m[1]) * (m[2]!.toLowerCase() === 'k' ? 1000 : m[2]!.toLowerCase() === 'm' ? 1_000_000 : 1)) : NaN;
  if (!Number.isInteger(n) || n < min) throw new CliExit(EXIT_ERROR, `${flag} 须为不小于 ${min} 的整数（可写作 200k）`);
  return n;
}

type ProviderCfg = AppConfig['modelProviders'][number];

/**
 * Fill the context window / output cap of a provider's models from its model listing where the configuration has none.
 * Best effort: a service that lists no limits (or cannot be reached yet, e.g. before its key is set) changes nothing.
 */
async function probeModelLimits(p: ProviderCfg): Promise<{ provider: ProviderCfg; note: string }> {
  const r = await listModels(p);
  if (!r.ok) return { provider: p, note: `未能读取模型上限（${r.detail}）${p.apiKey ? '' : '；设置密钥（config set-secret）后会再读取'}` };
  const { models, updated } = withProbedLimits(p.models, r.limits ?? {});
  if (!updated.length) return { provider: p, note: Object.keys(r.limits ?? {}).length ? '' : '服务端模型列表未提供上下文窗口 / 最大输出' };
  const shown = models.filter((m) => updated.includes(m.id)).map((m) => `${m.id}（上下文 ${m.contextWindow ?? '—'}，输出 ${m.maxTokens ?? '—'}）`);
  return { provider: { ...p, models }, note: `已读取模型上限：${shown.join('；')}` };
}

const UNSET_LIMITS_HINT = '未设置上限的模型按 128k 上下文、8192 输出处理；可用 config set-model-limits 设置';

async function cmdConfig(sub: string | undefined, args: string[], dataDir?: string): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { api: { type: 'string' }, 'base-url': { type: 'string' }, models: { type: 'string' }, 'from-env': { type: 'string' }, username: { type: 'string' }, 'context-window': { type: 'string' }, 'max-tokens': { type: 'string' } } });
  const store = openStore(dataDir);
  try {
    const cfg = store.config;
    if (sub === 'list') { printJson(maskedConfig(cfg)); return EXIT_OK; }
    if (sub === 'get') {
      const key = need(positionals[0], 'key');
      const v = key.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], maskedConfig(cfg));
      printJson(v ?? null);
      return EXIT_OK;
    }
    if (sub === 'set') {
      const key = need(positionals[0], 'key');
      const setter = SETTABLE[key];
      if (!setter) throw new CliExit(EXIT_ERROR, `不支持的配置项 ${key}；可设置：${Object.keys(SETTABLE).join(', ')}`);
      store.saveConfig(setter(cfg, need(positionals[1], 'value')));
      print('已保存');
      return EXIT_OK;
    }
    if (sub === 'add-provider') {
      const id = need(positionals[0], 'providerId');
      const api = need(values.api, '--api') as ModelApi;
      const baseUrl = need(values['base-url'], '--base-url');
      const u = new URL(baseUrl);
      if (u.username || u.password) throw new AppError('SECRET_ON_COMMAND_LINE', 'baseUrl must not contain credentials');
      const contextWindow = tokenArg(values['context-window'], '--context-window', 1024);
      const maxTokens = tokenArg(values['max-tokens'], '--max-tokens', 256);
      const existing = cfg.modelProviders.find((p) => p.id === id);
      // a model listed again keeps what is known about it (limits set earlier); flags given here win.
      const known = new Map((existing?.models ?? []).map((m) => [m.id, m]));
      const models = need(values.models, '--models').split(',').map((m) => m.trim()).filter(Boolean)
        .map((m) => ({ ...(known.get(m) ?? { id: m }), ...(contextWindow ? { contextWindow } : {}), ...(maxTokens ? { maxTokens } : {}) }));
      // Changing baseUrl starts a new credential binding: the old key is cleared.
      const keepKey = existing && existing.baseUrl === baseUrl ? { ...(existing.apiKey ? { apiKey: existing.apiKey, apiKeyOrigin: existing.apiKeyOrigin } : {}) } : {};
      const probed = await probeModelLimits({ id, api, baseUrl, models, ...keepKey } as ProviderCfg);
      store.saveConfig({ ...cfg, modelProviders: [...cfg.modelProviders.filter((p) => p.id !== id), probed.provider] });
      print(`已保存模型服务 ${id}${existing && !keepKey.apiKey && existing.apiKey ? '（baseUrl 已变更，原密钥已清除，请重新设置）' : ''}`);
      if (probed.note) print(probed.note);
      if (probed.provider.models.some((m) => !m.contextWindow)) print(UNSET_LIMITS_HINT);
      return EXIT_OK;
    }
    if (sub === 'set-model-limits') {
      const id = need(positionals[0], 'providerId');
      const modelId = need(positionals[1], 'modelId');
      const contextWindow = tokenArg(values['context-window'], '--context-window', 1024);
      const maxTokens = tokenArg(values['max-tokens'], '--max-tokens', 256);
      if (!contextWindow && !maxTokens) throw new CliExit(EXIT_ERROR, '缺少参数：--context-window 或 --max-tokens');
      const p = cfg.modelProviders.find((x) => x.id === id);
      if (!p) throw new CliExit(EXIT_ERROR, `模型服务 ${id} 不存在；先执行 config add-provider`);
      if (!p.models.some((m) => m.id === modelId)) throw new CliExit(EXIT_ERROR, `模型服务 ${id} 没有模型 ${modelId}`);
      const models = p.models.map((m) => (m.id === modelId ? { ...m, ...(contextWindow ? { contextWindow } : {}), ...(maxTokens ? { maxTokens } : {}) } : m));
      store.saveConfig({ ...cfg, modelProviders: cfg.modelProviders.map((x) => (x.id === id ? { ...x, models } : x)) });
      const m = models.find((x) => x.id === modelId)!;
      print(`已保存 ${id}/${modelId}：上下文 ${m.contextWindow ?? '未设置'}，最大输出 ${m.maxTokens ?? '未设置'}`);
      return EXIT_OK;
    }
    if (sub === 'set-secret') {
      const id = need(positionals[0], 'providerId');
      const p = cfg.modelProviders.find((x) => x.id === id);
      if (!p) throw new CliExit(EXIT_ERROR, `模型服务 ${id} 不存在；先执行 config add-provider`);
      const secret = values['from-env'] ? process.env[values['from-env']] ?? '' : await readSecret(`输入 ${id} 的密钥（不回显）：`);
      if (!secret) throw new CliExit(EXIT_ERROR, '密钥为空');
      // with the key in place the model listing can usually be read: fill the limits add-provider could not.
      const probed = await probeModelLimits({ ...p, apiKey: secret, apiKeyOrigin: originOf(p.baseUrl) });
      store.saveConfig({ ...cfg, modelProviders: cfg.modelProviders.map((x) => (x.id === id ? probed.provider : x)) });
      print(`已保存（${maskSecret(secret).hint ?? '已配置'}）`);
      if (probed.note) print(probed.note);
      return EXIT_OK;
    }
    if (sub === 'set-git-credential') {
      const host = gitHostArg(positionals[0]);
      const username = need(values.username, '--username');
      const token = values['from-env'] ? process.env[values['from-env']] ?? '' : await readSecret(`输入 ${host} 的 token（不回显）：`);
      if (!token) throw new CliExit(EXIT_ERROR, 'token 为空');
      const list = (cfg.gitCredentials ?? []).filter((c) => c.host !== host);
      store.saveConfig({ ...cfg, gitCredentials: [...list, { host, username, token }].sort((a, b) => a.host.localeCompare(b.host)) });
      print(`已保存 ${host} 的 Git 凭证（${maskSecret(token).hint ?? '已配置'}）`);
      return EXIT_OK;
    }
    if (sub === 'remove-git-credential') {
      const host = gitHostArg(positionals[0]);
      if (!(cfg.gitCredentials ?? []).some((c) => c.host === host)) throw new CliExit(EXIT_ERROR, `${host} 没有配置 Git 凭证`);
      store.saveConfig({ ...cfg, gitCredentials: (cfg.gitCredentials ?? []).filter((c) => c.host !== host) });
      print(`已删除 ${host} 的 Git 凭证`);
      return EXIT_OK;
    }
    throw new CliExit(EXIT_ERROR, `未知子命令 config ${sub ?? ''}`);
  } finally {
    store.close();
  }
}

async function cmdExport(args: string[], dataDir?: string): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { format: { type: 'string' }, out: { type: 'string' }, 'no-snippets': { type: 'boolean' }, 'no-local-roots': { type: 'boolean' } } });
  const id = need(positionals[0], 'auditId');
  const format = need(values.format, '--format') as ExportFormat;
  if (!['md', 'html', 'json', 'sarif'].includes(format)) throw new CliExit(EXIT_ERROR, 'format 只能是 md、html、json、sarif');
  const store = openStore(dataDir);
  try {
    getAudit(store, id);
    const text = exportAudit(store, id, format, { ...(values['no-snippets'] ? { snippets: false } : {}), ...(values['no-local-roots'] ? { localRoots: false } : {}) });
    const out = resolve(need(values.out, '--out'));
    writeFileSync(out, text);
    print(`已导出 ${out}${format === 'sarif' ? '（注意：SARIF 保留被审代码原文，可能包含代码中的明文密钥）' : ''}`);
    return EXIT_OK;
  } finally {
    store.close();
  }
}

/** Headless risk hunts: the engine runs in this process. */
async function cmdHunt(sub: string | undefined, args: string[], dataDir?: string): Promise<number> {
  const store = openStore(dataDir);
  try {
    const engine = await openEngine(store);
    const results = (id: string) => ({ hunt: huntDtoLocal(store, id), targets: huntTargets(store, id).map((t) => ({ ...t, evidence: [], pendingCondition: null })), hits: localHits(store, id) });
    return await huntCommand({
      createBasis: async (input) => engine.jobs.startBasis(input),
      getBasis: async (id) => { await engine.jobs.basisDone(id); const b = getBasis(store, id); return { id: b.id, kind: b.kind, title: b.title, status: b.status as 'ready', error: b.error, revision: b.revision, basis: b.basis_ref ? store.artifacts.getJson(b.basis_ref) : null, skillName: b.skill_name, model: b.model, createdAt: new Date(b.created_at).toISOString() }; },
      createHunt: async (basisId, scope) => { const id = createHunt(store, { basisId, scope }); engine.jobs.startPrecheck(id); await engine.jobs.precheckDone(id); const p = huntPlan(store, id); return { ...(huntDtoLocal(store, id) as object), plan: { projects: p.projects, estimate: p.estimate } } as never; },
      confirm: async (id) => {
        for (const aid of engine.confirmHunt(id, 'cli')) await engine.plan(aid, new AbortController().signal);
        await runQueueInteractive(store, engine);
      },
      getHunt: async (id) => huntDtoLocal(store, id),
      results: async (id) => results(id) as never,
      promote: (hitId) => engine.promoteHuntHit(hitId),
      export: async () => { throw new CliExit(EXIT_ERROR, '导出排查报告需要服务模式（xiezhi serve），或在界面中导出'); },
      saveAsSkill: async (id, category, name) => { const d = engine.jobs.saveBasisAsSkill(id, { category, ...(name ? { name } : {}) }); await engine.jobs.draftDone(d.id); return { name: d.name ?? '', draftId: d.id }; },
    }, sub, args);
  } finally {
    flushRecordings();
    store.close();
  }
}

function huntDtoLocal(store: Store, id: string) {
  refreshHunt(store, id);
  const h = getHunt(store, id);
  const plan = h.status === 'planned' ? huntPlan(store, id) : null;
  return { id: h.id, title: h.title, status: h.status, summary: JSON.parse(h.summary), plan: plan ? { projects: plan.projects, estimate: plan.estimate } : null } as never;
}

function localHits(store: Store, id: string) {
  return Q.huntLocalHits(store, id)
    .map((f) => ({ id: f.id, projectName: f.project_name, repoName: f.repo_name, title: f.title, severity: f.severity, location: JSON.parse(f.location), promotedDisplayNo: f.promoted }));
}

/**
 * knowledge list | show | lint: read-only over the knowledge directories, so it runs
 * locally even while the service owns the data-dir (no writer lock). Editing goes through the web
 * page or any editor; `import` arrives with drafts.
 */
async function cmdKnowledge(sub: string | undefined, args: string[], dataDir?: string): Promise<number> {
  if (sub && ['import', 'drafts', 'approve', 'reject'].includes(sub)) return cmdKnowledgeDrafts(sub, args, dataDir);
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { project: { type: 'string' }, json: { type: 'boolean' } } });
  const store = openStore(dataDir, false);
  try {
    // Built-ins are only copied when missing, so this is safe next to a running service.
    installBuiltinSkills(store.paths.knowledgeGlobal);
    const project = values.project ? getProject(store, values.project) : null;
    const projectDirs = new Map(listProjects(store).map((p) => [p.id, join(store.paths.projects, p.id, 'knowledge')]));
    const items = listKnowledge(store.paths.knowledgeGlobal, projectDirs, project ? { projectId: project.id } : {});
    if (sub === 'list') {
      if (values.json) { printJson(items); return EXIT_OK; }
      for (const i of items) {
        const flags = [
          i.layer === 'project' ? '项目' : '全局', i.overridesGlobal ? '覆盖全局' : '', i.overriddenBy.length && i.layer === 'global' ? '被项目覆盖' : '',
          i.disabled ? '已停用' : '', i.verified === false ? '未核实' : '', i.valid ? '' : '无效',
        ].filter(Boolean).join('·');
        print(`${i.name.padEnd(32)} ${(i.category ?? '-').padEnd(12)} ${(i.load ?? '-').padEnd(18)} ${flags}`);
      }
      return EXIT_OK;
    }
    if (sub === 'show') {
      const name = positionals[0];
      if (!name) throw new CliExit(EXIT_ERROR, '缺少参数：name');
      const d = (project ? readSkill(join(store.paths.projects, project.id, 'knowledge'), 'project', name) : null) ?? readSkill(store.paths.knowledgeGlobal, 'global', name);
      if (!d) throw new CliExit(EXIT_ERROR, `skill 不存在：${name}`);
      if (values.json) { printJson(d); return EXIT_OK; }
      print(`# ${d.layer === 'project' ? '项目' : '全局'} ${d.name}（${d.files.map((f) => f.path).join('、')}）${d.valid ? '' : `  无效：${d.errors.join('; ')}`}`);
      print(d.entryText);
      return EXIT_OK;
    }
    if (sub === 'lint') {
      let problems = 0;
      for (const i of items) {
        if (!i.valid) { problems++; print(`无效  ${i.layer}:${i.path} — ${i.errors.join('; ')}`); }
        for (const w of i.warnings) print(`警告  ${i.layer}:${i.path} — ${w}`);
      }
      const layers: ['global' | 'project', string][] = [['global', store.paths.knowledgeGlobal], ...(project ? [['project', join(store.paths.projects, project.id, 'knowledge')] as ['project', string]] : [])];
      for (const [layer, dir] of layers) {
        for (const s of scanLayer(dir, layer).skills) {
          if (s.category !== 'vuln_case' || !s.dir) continue;
          const idx = caseIndexBody(s.dir);
          for (const f of idx.invalid) { problems++; print(`无效  ${layer}:${s.name}/${f} — 案例文件头不完整或 vuln_class 不在词表中`); }
        }
      }
      print(problems ? `共 ${problems} 处问题` : '全部有效');
      return problems ? EXIT_ERROR : EXIT_OK;
    }
    throw new CliExit(EXIT_ERROR, '用法：knowledge list|show <name>|lint [--project <p>] [--json]');
  } finally {
    store.close();
  }
}

/** Drafts go through the service when it runs (it owns the writer lock), else through a local engine. */
async function cmdKnowledgeDrafts(sub: string, args: string[], dataDir?: string): Promise<number> {
  const remote = await discover(resolveDataDir(dataDir));
  if (remote) {
    try {
      return await knowledgeWriteCommand({
        projectId: async (p) => (await findProject(remote, p)).id,
        create: (body) => remote.post('/knowledge/drafts', body),
        get: (id) => remote.get(`/knowledge/drafts/${id}`),
        list: (pid) => remote.get(`/knowledge/drafts${pid ? `?projectId=${pid}` : ''}`),
        approve: (id, body) => remote.post(`/knowledge/drafts/${id}/approve`, body),
        reject: (id) => remote.post(`/knowledge/drafts/${id}/reject`),
      }, sub, args);
    } catch (e) {
      if (e instanceof RemoteError) throw new CliExit(EXIT_ERROR, `错误 [${e.code}]：${e.message}`);
      throw e;
    }
  }
  const store = openStore(dataDir);
  try {
    const engine = await openEngine(store);
    return await knowledgeWriteCommand({
      projectId: async (p) => getProject(store, p).id,
      create: async (body) => {
        const b = body as { layer: 'global' | 'project'; projectId?: string; kind: 'skill' | 'case'; text: string; organize: boolean; name?: string; category?: SkillCategory; source: { kind: 'manual' | 'upload'; label: string } };
        const d = engine.jobs.startDraft({ ...b, source: { ...b.source, ref: null } });
        await engine.jobs.draftDone(d.id);
        return draftDto(findDraft(store, d.id).draft);
      },
      get: async (id) => draftDto(findDraft(store, id).draft),
      list: async (pid) => listAllDrafts(store, pid ? { projectId: pid } : {}).map(draftDto),
      approve: async (id, body) => approveKnowledgeDraft(store, id, body as { replace?: boolean; afterMove?: 'delete' | 'keep' }),
      reject: async (id) => draftDto(rejectKnowledgeDraft(store, id)),
    }, sub, args);
  } finally {
    flushRecordings();
    store.close();
  }
}

async function cmdServe(args: string[], dataDir?: string): Promise<number> {
  const { values } = parseArgs({ args, options: { port: { type: 'string' }, open: { type: 'boolean' } } });
  const port = values.port ? Number(values.port) : Number(process.env.XIEZHI_AUDIT_PORT ?? DEFAULT_PORT);
  let mode: ModelMode | undefined;
  if (process.env.XIEZHI_AUDIT_REPLAY) mode = { kind: 'replay', replayer: Replayer.load(process.env.XIEZHI_AUDIT_REPLAY) };
  const server = await startServer({ ...(dataDir ? { dataDir } : {}), port, ...(mode ? { mode } : {}) });
  print(`獬豸审计已启动：${server.bootstrapUrl}`);
  print(`（引导码 5 分钟内有效，仅可使用一次；过期后运行 xiezhi open 获取新链接；data-dir：${server.dataDir}）`);
  print('按 Ctrl+C 停止服务。');
  if (values.open) {
    if (await openBrowser(server.bootstrapUrl)) print('已在浏览器中打开。');
    else print('无法自动打开浏览器，请手动打开上面的链接。');
  }
  await new Promise<void>((done) => {
    const stop = () => {
      process.off('SIGINT', stop);
      process.off('SIGTERM', stop);
      process.stderr.write('\n正在停止服务，进行中的审计将标记为已中断…\n');
      void server.close().then(done, done);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  });
  return EXIT_OK;
}

export async function main(argv: string[]): Promise<number> {
  rejectSecretArgs(argv);
  let dataDir: string | undefined;
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--data-dir') dataDir = argv[++i];
    else if (argv[i]!.startsWith('--data-dir=')) dataDir = argv[i]!.slice('--data-dir='.length);
    else rest.push(argv[i]!);
  }
  const [cmd, sub, ...args] = rest;
  if (cmd === 'serve') return cmdServe([...(sub ? [sub] : []), ...args], dataDir);
  if (cmd === 'open') {
    const remote = await discover(resolveDataDir(dataDir));
    if (!remote) throw new CliExit(EXIT_ERROR, '服务未运行；先执行 xiezhi serve');
    const r = await remote.post<{ url: string }>('/session/bootstrap-codes');
    print(`在浏览器中打开（5 分钟内有效，只能使用一次）：\n${r.url}`);
    return EXIT_OK;
  }
  // Client mode: a running service owns the data-dir; talk to its API.
  if (cmd && ['project', 'audit', 'export', 'config', 'hunt'].includes(cmd)) {
    const remote = await discover(resolveDataDir(dataDir));
    if (remote) {
      try {
        return await remoteCommand(remote, cmd, sub, args);
      } catch (e) {
        if (e instanceof RemoteError) throw new CliExit(EXIT_ERROR, `错误 [${e.code}]：${e.message}`);
        throw e;
      }
    }
  }
  switch (cmd) {
    case undefined: case 'help': case '--help': case '-h': print(HELP); return EXIT_OK;
    case 'version': case '--version': case '-V': print(appVersion()); return EXIT_OK;
    case 'doctor': {
      const checks = await runDoctor(dataDir);
      if (sub === '--json' || args.includes('--json')) printJson(checks);
      else for (const c of checks) print(`${c.level.toUpperCase().padEnd(5)} ${c.name.padEnd(12)} ${c.detail}${c.impact ? ` — 影响：${c.impact}` : ''}${c.fix ? ` — 修复：${c.fix}` : ''}`);
      return checks.some((c) => c.level === 'fatal') ? EXIT_ERROR : EXIT_OK;
    }
    case 'project': return cmdProject(sub, args, dataDir);
    case 'audit': return cmdAudit(sub, args, dataDir);
    case 'config': return cmdConfig(sub, args, dataDir);
    case 'export': return cmdExport([...(sub ? [sub] : []), ...args], dataDir);
    case 'knowledge': return cmdKnowledge(sub, args, dataDir);
    // 已定结论 1: the evaluation driver is a CLI subcommand reusing the engine.
    case 'eval': return evalMain([...(sub ? [sub] : []), ...args]).catch((e) => { throw new CliExit(EXIT_ERROR, evalErrorText(e)); });
    case 'hunt': return cmdHunt(sub, args, dataDir);
    case 'threat-model': return cmdThreatModel(sub, args, dataDir);
    default: throw new CliExit(EXIT_ERROR, `未知命令 ${cmd}；运行 xiezhi help 查看用法`);
  }
}

/** Runs the CLI and sets the exit code; the entry point of `node dist/main.js` and of the npm package's `bin/xiezhi.js`. */
export function runCli(argv: string[]): Promise<void> {
  return main(argv).then(
    (code) => { flushRecordings(); process.exitCode = code; },
    (e) => {
      flushRecordings();
      process.stderr.write(errorLine(e) + '\n');
      process.exitCode = e instanceof CliExit ? e.code : EXIT_ERROR;
    },
  );
}

const isEntry = !!process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (isEntry) void runCli(process.argv.slice(2));
