// Benchmark run driver: every sample × repeat runs in a fresh temporary data-dir
// with an explicit configuration file and an explicit knowledge set; nothing is read from the user's
// data-dir. Results are extracted into run records; the temporary data-dir is removed afterwards.
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AppConfig, AppError, BUDGET_STAGES, canonicalJson, check, configStageModel, normalizePending, originOf, sha256Hex, upgradeConfig, type AppConfig as AppConfigT, type ModelRef,
} from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { Executor, runGit } from '@xiezhi/context';
import { builtinSkillsDir, installBuiltinSkills } from '@xiezhi/knowledge';
import { piVersion, type ModelMode } from '@xiezhi/agent';
import { Engine, addRepository, budgetStage, budgetStoppedStages, createHunt, createProject, getBasis, huntTargets, queries as Q } from '@xiezhi/engine';
import { checkRootHashes, prepareTrees, sampleTrees, treeDir, type Bench } from './bench.js';
import { cacheKey, cacheStatus, readCached, writeCached, type CacheParts } from './cache.js';
import { holdoutFingerprints, knowledgeDirs, scanForLeaks, type LeakHit } from './leak.js';
import { META_FORMAT, RUN_FORMAT, type AttemptRec, type AuditRec, type FindingRec, type JudgementRec, type RiskTargetRec, type RunMeta, type RunRecord, type RunStatus, type SessionRec, type StepRec } from './record.js';
import type { Partition, Sample } from './schema.js';
import type { RemoteOptions } from './trees.js';
import { byString, EvalError, priced, removeTree, walkFiles, writeJson } from './util.js';

export type SampleFilter = Record<string, string[]>;

export interface RunOptions {
  bench: Bench;
  configPath: string;
  out: string;
  partition: Partition;
  filter?: SampleFilter;
  repeats?: number;
  /** Explicit knowledge set copied into the global layer next to the built-in skills. */
  knowledgeDir?: string;
  /** Holdout runs are release-only and must be asked for explicitly. */
  allowHoldout?: boolean;
  strategyOverride?: Record<string, unknown>;
  /** Tests / replay only; default live. */
  mode?: ModelMode;
  /** Skip the provider reachability check (replay mode never needs it). */
  skipPreflight?: boolean;
  keepData?: boolean;
  maxParallel?: number;
  /** Stop scheduling once the known USD cost reaches this. */
  maxCostUsd?: number;
  name?: string;
  runner?: { retryBackoffMs?: number; rateLimitBackoffMs?: number };
  log?: (line: string) => void;
  /** Shared across the runs of one experiment (limits.max_cost_usd is per experiment). */
  costTracker?: { usd: number };
  /** Result cache directory; runs whose inputs are unchanged are reused instead of re-run. */
  cacheDir?: string;
  /** Where and how remote sample trees are fetched. */
  trees?: RemoteOptions;
  /** Tests only: identity of the product code under test when the working tree is not a clean commit. */
  codeId?: string;
}

const FILTER_KEYS = ['sample', 'project', 'kind', 'language', 'scene', 'tag', 'dataset', 'tier'] as const;

/** Tier membership: smoke ⊂ core ⊂ full; a sample without a tier is only in full. */
export function inTier(s: Sample, tier: string): boolean {
  if (tier === 'full') return true;
  if (tier === 'core') return s.tier === 'smoke' || s.tier === 'core';
  if (tier === 'smoke') return s.tier === 'smoke';
  throw new EvalError('USAGE', `tier 只能是 smoke / core / full：${tier}`);
}

export function parseFilter(items: string[]): SampleFilter {
  const out: SampleFilter = {};
  for (const item of items) {
    const eq = item.indexOf('=');
    const key = eq > 0 ? item.slice(0, eq) : '';
    if (!(FILTER_KEYS as readonly string[]).includes(key)) throw new EvalError('USAGE', `--filter 只支持 ${FILTER_KEYS.join('/')}=值[,值]：${item}`);
    out[key] = [...(out[key] ?? []), ...item.slice(eq + 1).split(',').map((v) => v.trim()).filter(Boolean)];
  }
  return out;
}

export function selectSamples(bench: Bench, partition: Partition, filter: SampleFilter = {}): Sample[] {
  const pick = (key: string, value: string | string[]) => {
    const want = filter[key];
    if (!want?.length) return true;
    const vals = Array.isArray(value) ? value : [value];
    return want.some((w) => vals.includes(w));
  };
  const tiers = filter.tier ?? [];
  return bench.samples.filter((s) => s.partition === partition && pick('sample', s.sample_id) && pick('project', s.project) && pick('kind', s.kind)
    && pick('language', s.language) && pick('scene', s.scene) && pick('tag', s.tags) && pick('dataset', s.source.dataset)
    && (!tiers.length || tiers.some((t) => inTier(s, t))));
}

/** Read the explicit configuration file (never the user's data-dir). */
export function loadEvalConfig(path: string): AppConfigT {
  const abs = resolve(path);
  const userDir = resolve(homedir(), '.xiezhi-code-audit');
  if (abs === userDir || abs.startsWith(userDir + sep)) throw new EvalError('CONFIG_INVALID', `评测不读取用户数据目录中的配置（${userDir}）；请把模型服务配置复制到单独的文件并用 --config 指定`);
  if (!existsSync(abs)) throw new EvalError('CONFIG_INVALID', `配置文件不存在：${abs}`);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(abs, 'utf8'));
  } catch (e) {
    throw new EvalError('CONFIG_INVALID', `配置文件不是合法 JSON：${(e as Error).message}`);
  }
  // Configs with the light / chat model keys keep working (they become stage models).
  const r = check(AppConfig, raw && typeof raw === 'object' ? upgradeConfig(raw as Record<string, unknown>) : raw);
  if (!r.ok) throw new EvalError('CONFIG_INVALID', '配置文件不符合 config.json schema', r.issues.slice(0, 10).map((i) => `${i.path} ${i.message}`));
  if (!r.value.defaultModel) throw new EvalError('CONFIG_INVALID', '配置文件缺少 defaultModel');
  return r.value;
}

function modelsIn(value: unknown, out: Map<string, Set<string>>): void {
  if (!value || typeof value !== 'object') return;
  const o = value as Record<string, unknown>;
  if (typeof o.provider === 'string' && typeof o.model === 'string') out.set(o.provider, new Set([...(out.get(o.provider) ?? []), o.model]));
  for (const v of Object.values(o)) modelsIn(v, out);
}

/**
 * Provider preflight (no model call): the configured base URL must answer HTTP, and when the provider
 * publishes an OpenAI-style `/models` listing, every model the run uses must be in it. An unreachable
 * gateway or an unknown model fails the whole run up front with a clear message.
 */
export async function preflightProviders(cfg: AppConfigT, override: Record<string, unknown> = {}, timeoutMs = 5000): Promise<void> {
  const used = new Map<string, Set<string>>();
  modelsIn({ d: cfg.defaultModel, s: cfg.stageModels, o: override }, used);
  const unreachable: string[] = [];
  const unknown: string[] = [];
  for (const id of [...used.keys()].sort(byString)) {
    const p = cfg.modelProviders.find((x) => x.id === id);
    if (!p) { unreachable.push(`${id}：配置中没有这个模型服务`); continue; }
    try {
      const res = await fetch(p.baseUrl, { method: 'GET', signal: AbortSignal.timeout(timeoutMs), redirect: 'manual' });
      await res.body?.cancel();
    } catch (e) {
      const c = (e as { cause?: { code?: string; message?: string; errors?: { code?: string }[] } }).cause;
      const cause = c?.code ?? c?.errors?.[0]?.code ?? c?.message ?? (e as Error).message;
      unreachable.push(`${id}（${originOf(p.baseUrl)}）：${cause}`);
      continue;
    }
    if (p.api === 'anthropic-messages') continue;
    try {
      const res = await fetch(`${p.baseUrl.replace(/\/+$/, '')}/models`, {
        method: 'GET', signal: AbortSignal.timeout(timeoutMs), redirect: 'manual',
        headers: { ...(p.headers ?? {}), ...(p.apiKey ? { authorization: `Bearer ${p.apiKey}` } : {}) },
      });
      if (!res.ok) { await res.body?.cancel(); continue; }
      const listed = new Set(((await res.json()) as { data?: { id?: string }[] }).data?.map((m) => m.id).filter((x): x is string => !!x) ?? []);
      if (!listed.size) continue;
      for (const m of [...used.get(id)!].sort(byString)) if (!listed.has(m)) unknown.push(`${id}/${m}：模型服务的 /models 中没有这个模型`);
    } catch {
      // No usable listing: reachability is all we can check without calling a model.
    }
  }
  if (unreachable.length) throw new EvalError('PROVIDER_UNREACHABLE', '模型服务不可达，未运行任何样本。请启动模型网关或在 --config 中改用可用的服务。', unreachable);
  if (unknown.length) throw new EvalError('PROVIDER_UNREACHABLE', '配置的模型在模型服务中不存在，未运行任何样本。请在 --config 中改用服务列出的模型。', unknown);
}

async function codeRevision(dir: string): Promise<{ revision: string | null; dirty: boolean | null }> {
  const scratch = mkdtempSync(join(tmpdir(), 'ca-eval-git-'));
  try {
    const ex = new Executor({ scratchDir: scratch });
    const head = await runGit(ex, dir, 'rev-parse', ['--verify', 'HEAD'], { collectStdout: true });
    if (head.status !== 'ok') return { revision: null, dirty: null };
    const st = await runGit(ex, dir, 'status', ['--porcelain', '--untracked-files=normal'], { collectStdout: true });
    return { revision: head.stdoutData!.toString('utf8').trim(), dirty: st.status === 'ok' ? st.stdoutData!.toString('utf8').trim().length > 0 : null };
  } catch {
    return { revision: null, dirty: null };
  } finally {
    removeTree(scratch);
  }
}

/** Behaviour-relevant configuration without secrets (and, for the result cache, without prices). */
export function configIdentity(cfg: AppConfigT, withPricing = true): Record<string, unknown> {
  const noSecrets: Record<string, unknown> = { ...cfg, modelProviders: cfg.modelProviders.map(({ apiKey: _k, apiKeyOrigin: _o, ...rest }) => rest), gitCredentials: undefined };
  if (!withPricing) delete noSecrets.pricing;
  return noSecrets;
}

function maskedConfig(cfg: AppConfigT): RunMeta['config'] {
  const ref = (m: ModelRef | undefined) => (m ? `${m.provider}/${m.model}` : null);
  const safe = {
    providers: cfg.modelProviders.map((p) => ({ id: p.id, api: p.api, origin: originOf(p.baseUrl), models: p.models.map((m) => m.id) })),
    // `cheap_model` (kept for older reports) is the triage stage model.
    default_model: ref(cfg.defaultModel), cheap_model: ref(configStageModel(cfg, 'triage') ?? undefined), priced_models: Object.keys(cfg.pricing).sort(byString),
  };
  // Hash of everything that affects behaviour, secrets excluded.
  return { sha256: sha256Hex(canonicalJson(configIdentity(cfg))), ...safe };
}

function skillList(dir: string): { name: string; sha256: string }[] {
  // A skill is a single `<name>.md` file or a directory with SKILL.md; other files are sub-files.
  return walkFiles(dir).filter((f) => f.endsWith('SKILL.md') || (!f.includes('/') && f.endsWith('.md')))
    .map((f) => ({ name: f.endsWith('SKILL.md') ? dirname(f) : f.slice(0, -3), sha256: sha256Hex(readFileSync(join(dir, f))) }));
}

// ---------------------------------------------------------------------------------------------

interface Ctx {
  opts: RunOptions;
  cfg: AppConfigT;
  leak: ReturnType<typeof holdoutFingerprints> | null;
  mode: ModelMode;
}

export function copyTreeForRun(from: string, to: string): void {
  removeTree(to);
  mkdirSync(to, { recursive: true });
  // The source cache may hold the tree behind a symlink (a shared or merged cache): copy the real directory,
  // not the link, which would collide with the directory just created.
  cpSync(realpathSync(from), to, { recursive: true });
}


function collectFindings(store: Store, auditId: string): FindingRec[] {
  const rows = Q.evalFindings(store, auditId);
  return rows.map((r) => {
    const loc = JSON.parse(r.location) as { path?: string; startLine?: number; endLine?: number };
    const status: FindingRec['status'] = r.confirm_status === 'false_positive' ? 'dismissed'
      : r.confirm_status === 'pending' || (!r.confirm_status && r.confirmation === 'pending') ? 'pending' : 'confirmed';
    const pc = normalizePending(r.missing_context ? JSON.parse(r.missing_context) : null);
    return {
      id: r.id, display_no: r.display_no, title: r.title, category: r.category, cwe: r.cwe, severity: r.severity, confidence: r.confidence_score,
      repo: r.repo, path: loc.path ?? '', start_line: loc.startLine ?? 0, end_line: loc.endLine ?? loc.startLine ?? 0,
      entries: JSON.parse(r.entry_keys) as string[], status, vulnerability_id: r.vulnerability_id, match_level: r.match_level,
      pending: pc ? { missing: pc.missing.map((m) => `${m.kind}:${m.ref}`), holds_if: pc.holdsIf.map((c) => c.statement), refuted_if: pc.refutedIf.map((c) => c.statement) } : null,
      trace: traceOf(store, auditId, r.id, r.vulnerability_id),
    };
  });
}

/** Hypotheses of the audit (see AuditRec.hypotheses); nothing when there are none. */
function hypothesesOf(store: Store, auditId: string): Pick<AuditRec, 'hypotheses'> {
  const rows = Q.evalHypotheses(store, auditId);
  if (!rows.length) return {};
  return {
    hypotheses: rows.map((h) => {
      // Threat-model hypotheses have no location until verified.
      const loc = (h.location ? JSON.parse(h.location) : {}) as { path?: string; startLine?: number; endLine?: number };
      return { category: h.category, repo: h.repo, path: loc.path ?? '', start_line: loc.startLine ?? 0, end_line: loc.endLine ?? loc.startLine ?? 0, status: h.status, origin: h.origin };
    }),
  };
}

/** Coverage (see AuditRec.coverage); nothing when the audit had no coverage items. */
function coverageOf(store: Store, auditId: string): Pick<AuditRec, 'coverage'> {
  const items = Q.evalCoverageItems(store, auditId);
  if (!items.length) return {};
  const count = (k: string) => ({ total: items.filter((i) => i.kind === k && i.status !== 'excluded').length, reviewed: items.filter((i) => i.kind === k && i.status === 'concluded').length });
  const concluded = items.filter((i) => i.status === 'concluded');
  const ranges = new Map(Q.readCoverage(store, auditId)
    .map((r) => [`${r.repository_id}\u0000${r.path}`, JSON.parse(r.ranges) as [number, number][]]));
  const read = concluded.filter((i) => (ranges.get(`${i.repository_id}\u0000${i.path}`) ?? []).some(([a, b]) => a <= i.end_line && b >= i.start_line)).length;
  return {
    coverage: {
      entry: count('entry'), sink: count('sink'),
      sinks: items.filter((i) => i.kind === 'sink').slice(0, 2000).map((i) => ({ repo: i.repo, path: i.path, line: i.start_line })),
      concluded: concluded.length, concluded_read: read,
    },
  };
}

/** G3: evidence verified, submission traceable in the trajectory, decision source recorded. */
function traceOf(store: Store, auditId: string, findingId: string, vulnId: string | null): NonNullable<FindingRec['trace']> {
  const ev = Q.findingEvidenceFlags(store, findingId);
  const code = ev.filter((e) => e.kind === 'code_range' || e.kind === 'call_chain_segment');
  const evidence = code.some((e) => e.ord === 0 && e.verified === 1) && code.every((e) => e.verified === 1);
  const trajectory = store.listEvents(auditId, 0, ['finding.submitted']).some((e) => e.payload.finding_id === findingId);
  const findingSource = Q.findingSource(store, findingId);
  const vulnSources = vulnId ? Q.vulnSources(store, vulnId) : [];
  const source = !!findingSource && (!vulnId || vulnSources.length > 0);
  return { evidence, trajectory, source };
}

/** A step's identity for the stage telemetry (domain and round of an expert, tier of a review). */
export function stepRec(s: Q.EvalStepRow): StepRec {
  const input = (() => { try { return JSON.parse(s.input) as Record<string, unknown>; } catch { return {}; } })();
  const domain = (input.domain as { name?: unknown } | undefined)?.name;
  const tier = s.kind === 'challenge' ? (input.light ? 'light' : input.vote ? 'vote' : 'full') : undefined;
  return {
    seq: s.seq, kind: s.kind, status: s.status, attempts: s.attempt, error_class: s.error_class,
    lineage: s.lineage_id, stage: budgetStage(s.kind, s.lineage_id), model: s.model, started_at: s.started_at, ended_at: s.ended_at, findings: s.findings,
    ...(typeof domain === 'string' ? { domain } : {}), ...(typeof input.round === 'number' ? { round: input.round } : {}), ...(tier ? { tier } : {}),
  };
}

const scalar = (v: unknown): v is string | number | boolean | null => v === null || ['string', 'number', 'boolean'].includes(typeof v);

/** Sessions (from `session.ended`) and judgements of an audit, keyed to step sequence numbers. */
export function telemetryOf(store: Store, auditId: string, steps: Q.EvalStepRow[]): Pick<AuditRec, 'sessions' | 'judgements'> {
  const seqOf = new Map(steps.map((s) => [s.id, s.seq]));
  const sessions: SessionRec[] = [];
  const judgements: JudgementRec[] = [];
  for (const e of Q.evalEvents(store, auditId, ['session.ended', 'judgement.made'])) {
    const seq = e.step_id ? seqOf.get(e.step_id) ?? null : null;
    if (e.type === 'judgement.made') {
      judgements.push({ step_seq: seq, kind: String(e.payload.kind ?? ''), fields: Object.fromEntries(Object.entries(e.payload).filter(([k, v]) => k !== 'kind' && k !== 'session' && scalar(v))) as JudgementRec['fields'] });
      continue;
    }
    const t = e.payload.telemetry as { prompt?: SessionRec['prompt']; peak_context?: number; compactions?: number; pushed?: SessionRec['pushed'] } | undefined;
    const role = (e.payload.session as { role?: string } | undefined)?.role === 'task' ? 'task' : 'main';
    sessions.push({
      step_seq: seq, role, status: String(e.payload.status ?? ''), turns: Number(e.payload.turns ?? 0),
      ...(t?.prompt ? { prompt: t.prompt } : {}), peak_context: t?.peak_context ?? 0, compactions: t?.compactions ?? 0, pushed: t?.pushed ?? [],
    });
  }
  return { ...(sessions.length ? { sessions } : {}), ...(judgements.length ? { judgements } : {}) };
}

function collectAudit(store: Store, cfg: AppConfigT, auditId: string, role: AuditRec['role'], version: string, declined: string[] | undefined, wallMs: number): AuditRec {
  const a = Q.evalAuditHead(store, auditId);
  const steps = Q.evalSteps(store, auditId);
  const attempts = Q.evalAttempts(store, auditId);
  const att: AttemptRec[] = attempts.map((x) => {
    const p = priced(cfg, x.provider, x.model, { in: x.tokens_in, out: x.tokens_out, cached: x.tokens_cached });
    return {
      step: x.kind, seq: x.seq, provider: x.provider, model: x.model, attempt: x.attempt, outcome: x.outcome, error_class: x.error_class,
      tokens_in: x.tokens_in, tokens_out: x.tokens_out, tokens_cached: x.tokens_cached, cost_micros: p.cost, currency: p.currency,
      duration_ms: x.ended_at ? Math.max(0, x.ended_at - x.started_at) : 0,
    };
  });
  const snaps = Q.snapshotHashes(store, auditId);
  const reverify = Q.reverifyVerdicts(store, auditId);
  return {
    audit_id: auditId, role, version, scene: a.scene, status: a.status, partial_reasons: JSON.parse(a.partial_reasons) as string[], error_class: a.error_class,
    budget_declined: !!declined, ...(declined?.length ? { budget_stopped_stages: declined } : {}), wall_ms: wallMs, model_ms: att.filter((x) => x.model).reduce((n, x) => n + x.duration_ms, 0),
    steps: steps.map(stepRec),
    attempts: att, findings: collectFindings(store, auditId), ...coverageOf(store, auditId), ...hypothesesOf(store, auditId),
    snapshot_hashes: Object.fromEntries(snaps.map((s) => [s.name, s.root_hash])),
    prompts: Q.evalPromptsHash(store, auditId),
    reverify: reverify.map((r) => ({ vulnerability_id: r.vulnerability_id, verdict: r.reverify_verdict, lifecycle_after: r.lifecycle_after })),
    ...telemetryOf(store, auditId, steps),
  };
}

/**
 * Run queued audits to an end; a budget wait is declined so the audit finishes with what it has. The result maps each
 * declined audit to the stages whose quota stopped it (empty: the total) so a record says why.
 */
async function drain(engine: Engine, store: Store, ids: string[]): Promise<Map<string, string[]>> {
  const declined = new Map<string, string[]>();
  const signal = new AbortController().signal;
  await engine.runQueue(signal);
  for (const id of ids) {
    if (engine.status(id).audit.status === 'waiting_budget') {
      declined.set(id, budgetStoppedStages(store, id));
      engine.declineBudget(id);
    }
  }
  if (declined.size) await engine.runQueue(signal);
  return declined;
}

/**
 * Eval measures quality under the total budget: a stage quota pauses an interactive audit for a
 * top-up, which the runner would decline, ending the run early with most of the total unused. So stage quotas are
 * off (every share 100%) unless the experiment sets `budget.stages` itself.
 */
export function evalStrategyOverride(o: Record<string, unknown> | undefined): Record<string, unknown> {
  const budget = (o?.budget ?? {}) as Record<string, unknown>;
  if (budget.stages !== undefined) return o ?? {};
  return { ...(o ?? {}), budget: { ...budget, stages: Object.fromEntries(BUDGET_STAGES.map((k) => [k, 1])) } };
}

async function auditOnce(engine: Engine, store: Store, cfg: AppConfigT, start: () => string, role: AuditRec['role'], version: string): Promise<AuditRec> {
  const t0 = Date.now();
  const id = start();
  const plan = await engine.plan(id, new AbortController().signal);
  const status = engine.status(id).audit.status;
  if (plan && status === 'awaiting_confirm') engine.confirm(id);
  const declined = plan ? await drain(engine, store, [id]) : new Map<string, string[]>();
  return collectAudit(store, cfg, id, role, version, declined.get(id), Date.now() - t0);
}

function overallStatus(audits: AuditRec[]): RunStatus {
  if (!audits.length) return 'error';
  if (audits.every((a) => a.status === 'completed')) return 'completed';
  if (audits.some((a) => a.status === 'failed')) return 'failed';
  if (audits.some((a) => a.status === 'cancelled')) return 'cancelled';
  return 'partial';
}

function assertNoLeak(hits: LeakHit[]): void {
  if (hits.length) {
    throw new EvalError('HOLDOUT_LEAK', '知识库中出现留出集答案的指纹，拒绝运行留出集',
      hits.slice(0, 20).map((h) => `${h.kind}: ${h.value} ← ${h.file}`));
  }
}

async function runSample(ctx: Ctx, s: Sample, repeat: number): Promise<RunRecord> {
  const { opts, cfg } = ctx;
  const tmp = mkdtempSync(join(tmpdir(), 'ca-eval-run-'));
  const dataDir = join(tmp, 'data');
  const work = join(tmp, 'work');
  const t0 = Date.now();
  const rec: RunRecord = {
    format: RUN_FORMAT, sample_id: s.sample_id, project: s.project, kind: s.kind, language: s.language, partition: s.partition, scene: s.scene,
    dataset: s.source.dataset, repeat, status: 'error', error: null, wall_ms: 0, audits: [], risk: null, integrity: [],
  };
  let store: Store | null = null;
  try {
    const trees = sampleTrees(s);
    const place = (version: string) => {
      for (const [name, ref] of trees.get(version)!) {
        const dir = treeDir(opts.bench, ref);
        if (!dir) throw new EvalError('BENCH_INVALID', `远程仓库 ${name} 尚未拉取`);
        copyTreeForRun(dir, join(work, name));
      }
    };
    place('base');
    store = Store.open({ dataDir, role: 'eval' });
    store.saveConfig(cfg);
    if (opts.knowledgeDir) cpSync(resolve(opts.knowledgeDir), store.paths.knowledgeGlobal, { recursive: true });
    const engine = await Engine.open({ store, mode: ctx.mode, runner: opts.runner ?? {} });
    if (ctx.leak) assertNoLeak(scanForLeaks(knowledgeDirs(dataDir), ctx.leak));
    const project = createProject(store, s.project);
    for (const r of s.repos) addRepository(store, project.id, { path: join(work, r.name), name: r.name });
    const auditable = s.repos.filter((r) => r.role === 'auditable').map((r) => r.name);
    const context = s.repos.filter((r) => r.role === 'context').map((r) => r.name);
    const mode = s.scene_input?.mode ?? (auditable.length > 1 ? 'multi' : 'single');
    const override = { strategyOverride: evalStrategyOverride(opts.strategyOverride) };
    const full = () => engine.createAudit({
      projectId: project.id, origin: 'cli', scene: 'full', title: `eval ${s.sample_id} r${repeat}`, ...override,
      ...(mode === 'multi' ? { mode: 'multi' as const, repositories: auditable } : { mode: 'single' as const, repository: auditable[0]!, related: context }),
    });

    if (s.scene === 'risk_hunt') {
      const text = readFileSync(join(opts.bench.root, s.scene_input!.basis_ref!), 'utf8');
      const bid = engine.jobs.startBasis({ kind: (s.scene_input!.basis_kind ?? 'prompt') as 'prompt' | 'intel', text });
      await engine.jobs.basisDone(bid);
      const b = getBasis(store, bid);
      const bu = b.usage ? JSON.parse(b.usage) as { input: number; output: number; cacheRead: number } : null;
      const bp = bu && b.model ? priced(cfg, null, b.model, { in: bu.input, out: bu.output, cached: bu.cacheRead }) : { cost: null, currency: null };
      rec.risk = { basis_status: b.status, basis_model: b.model, basis_tokens: b.tokens, basis_cost_micros: bp.cost, basis_currency: bp.currency, targets: [] };
      if (b.status === 'ready') {
        const t1 = Date.now();
        const hid = createHunt(store, { basisId: bid, scope: { projectIds: [project.id] } });
        const ids = engine.confirmHunt(hid, 'cli');
        for (const id of ids) await engine.plan(id, new AbortController().signal);
        const declined = await drain(engine, store, ids);
        for (const id of ids) rec.audits.push(collectAudit(store, cfg, id, 'hunt', 'base', declined.get(id), Date.now() - t1));
        rec.risk.targets = huntTargets(store, hid).map((t): RiskTargetRec => ({
          repo: t.repoName, verdict: t.verdict, reason: t.reason, verdict_source: t.verdictSource,
          evidence: Q.huntTargetEvidence(store!, t.id)
            .map((e) => ({ path: e.path, start_line: e.start_line, end_line: e.end_line, verified: e.verified === 1 })),
        }));
      } else {
        rec.error = { code: 'BASIS_FAILED', message: (b.error ?? 'basis drafting failed').slice(0, 500) };
      }
    } else {
      rec.audits.push(await auditOnce(engine, store, cfg, full, 'base', 'base'));
      for (const v of s.scene_input?.versions ?? []) {
        place(v.name);
        if (s.scene === 'incremental') {
          // G5: the same repository, incrementally against the full audit just finished (engine default baseline).
          const incremental = () => engine.createAudit({
            projectId: project.id, origin: 'cli', scene: 'incremental', title: `eval ${s.sample_id} r${repeat} incremental`, ...override,
            mode: 'single', repository: auditable[0]!, related: context,
          });
          rec.audits.push(await auditOnce(engine, store, cfg, incremental, 'incremental', v.name));
        } else if (s.scene === 'reverify') {
          // Every vulnerability of the project is reverified; the scorer picks the labelled one.
          const vulnIds = Q.activeVulnIds(store, project.id);
          if (!vulnIds.length) break;
          rec.audits.push(await auditOnce(engine, store, cfg, () => engine.createReverify({ vulnIds, origin: 'cli', ...override }), 'reverify', v.name));
        } else {
          rec.audits.push(await auditOnce(engine, store, cfg, full, 'version', v.name));
        }
      }
    }
    rec.status = rec.error ? 'error' : overallStatus(rec.audits);
    // The product must have seen exactly the manifest's trees.
    for (const a of rec.audits) {
      const expected = new Map<string, string>([...s.repos.map((r) => [r.name, r.root_hash] as const), ...(s.scene_input?.versions ?? []).filter((v) => v.name === a.version).flatMap((v) => v.repos.map((r) => [r.name, r.root_hash] as const))]);
      for (const [repo, actual] of Object.entries(a.snapshot_hashes)) {
        const want = expected.get(repo);
        if (want && actual && want !== actual) rec.integrity.push({ version: a.version, repo, expected: want, actual });
      }
    }
    if (rec.integrity.length) rec.status = 'invalid';
  } catch (e) {
    if (e instanceof EvalError && e.code === 'HOLDOUT_LEAK') throw e;
    rec.status = 'error';
    rec.error = { code: e instanceof AppError ? e.code : e instanceof EvalError ? e.code : 'INTERNAL', message: (e as Error).message.slice(0, 1000) };
  } finally {
    store?.close();
    rec.wall_ms = Date.now() - t0;
    if (!opts.keepData) removeTree(tmp);
    else opts.log?.(`  保留数据目录：${tmp}`);
  }
  return rec;
}

function knownUsd(rec: RunRecord): number {
  let micros = 0;
  for (const a of rec.audits) for (const x of a.attempts) if (x.currency === 'USD' && x.cost_micros) micros += x.cost_micros;
  return micros / 1e6;
}

export async function runBench(opts: RunOptions): Promise<RunMeta> {
  const { bench } = opts;
  const log = opts.log ?? (() => {});
  const repeats = opts.repeats ?? 1;
  if (!Number.isInteger(repeats) || repeats < 1) throw new EvalError('USAGE', '--repeats 至少为 1');
  if (opts.partition === 'holdout' && !opts.allowHoldout) {
    throw new EvalError('HOLDOUT_REFUSED', '留出集只在发布评测时运行；确需运行时加 --allow-holdout');
  }
  const cfg = loadEvalConfig(opts.configPath);
  const mode = opts.mode ?? { kind: 'live' };
  const samples = selectSamples(bench, opts.partition, opts.filter);
  if (!samples.length) throw new EvalError('USAGE', '没有符合分区与过滤条件的样本');

  // Holdout answers never reach the knowledge the product can see.
  let leak: Ctx['leak'] = null;
  const probe = mkdtempSync(join(tmpdir(), 'ca-eval-probe-'));
  let skills: RunMeta['knowledge']['skills'];
  try {
    const globalDir = join(probe, 'knowledge', 'global');
    mkdirSync(globalDir, { recursive: true });
    installBuiltinSkills(globalDir, builtinSkillsDir());
    if (opts.knowledgeDir) cpSync(resolve(opts.knowledgeDir), globalDir, { recursive: true });
    skills = skillList(globalDir);
    if (opts.partition === 'holdout') {
      leak = holdoutFingerprints(bench);
      assertNoLeak(scanForLeaks([globalDir], leak));
    }
  } finally {
    removeTree(probe);
  }

  if (!opts.skipPreflight && mode.kind === 'live') await preflightProviders(cfg, opts.strategyOverride);

  const unfetched = await prepareTrees(bench, samples, { ...opts.trees, log: opts.trees?.log ?? log });
  const invalid = await checkRootHashes(bench, samples.filter((s) => !unfetched.has(s.sample_id)));
  for (const [id, why] of unfetched) invalid.set(id, why);
  const runnable = samples.filter((s) => !invalid.has(s.sample_id));
  const out = resolve(opts.out);
  mkdirSync(out, { recursive: true });
  const cacheInfo: NonNullable<RunMeta['cache']> = { dir: opts.cacheDir ? resolve(opts.cacheDir) : null, enabled: false, reason: null, hits: 0, stored: 0 };
  if (existsSync(join(out, 'samples'))) rmSync(join(out, 'samples'), { recursive: true, force: true });
  const meta: RunMeta = {
    format: META_FORMAT, name: opts.name ?? null,
    bench: { root: bench.root, version: bench.manifest.bench_version, manifest_hash: bench.manifestHash, labels_hash: bench.labelsHash, commit: await codeRevision(bench.root) },
    partition: opts.partition, filter: opts.filter ?? {}, repeats, selected: samples.map((s) => s.sample_id),
    invalid: Object.fromEntries([...invalid.entries()].sort((a, b) => byString(a[0], b[0]))), skipped: [], stopped_reason: null, results: {},
    config: maskedConfig(cfg), strategy_override: evalStrategyOverride(opts.strategyOverride),
    knowledge: { dir: opts.knowledgeDir ? resolve(opts.knowledgeDir) : null, skills },
    // The product code under test is the repository this evaluator runs from (apps/eval/dist → repo root);
    // the benchmark lives in its own repository, recorded separately.
    code: await codeRevision(resolve(dirname(fileURLToPath(import.meta.url)), '../../..')), pi_version: piVersion(), node: process.versions.node, platform: `${process.platform}-${process.arch}`,
    model_mode: mode.kind, started_at: new Date().toISOString(), ended_at: null,
    cache: cacheInfo,
  };
  const cacheState = cacheStatus({ dir: opts.cacheDir, mode: mode.kind, code: meta.code, ...(opts.codeId ? { codeId: opts.codeId } : {}) });
  cacheInfo.enabled = cacheState.enabled;
  cacheInfo.reason = cacheState.reason;
  if (opts.cacheDir && !cacheState.enabled) log(`结果缓存未启用：${cacheState.reason}`);
  const cacheBase: Omit<CacheParts, 'sample' | 'repeat'> | null = cacheState.enabled ? {
    code: cacheState.codeId!, pi: meta.pi_version, config: configIdentity(cfg, false), strategy: evalStrategyOverride(opts.strategyOverride), knowledge: skills,
  } : null;
  writeJson(join(out, 'run.json'), meta);
  for (const [id, why] of invalid) log(`样本作废 ${id}：${why.join('；')}`);

  const ctx: Ctx = { opts, cfg, leak, mode };
  const jobs = runnable.flatMap((s) => Array.from({ length: repeats }, (_, i) => ({ s, repeat: i + 1 })));
  const tracker = opts.costTracker ?? { usd: 0 };
  let next = 0;
  const worker = async () => {
    while (next < jobs.length) {
      const job = jobs[next++]!;
      if (opts.maxCostUsd !== undefined && tracker.usd >= opts.maxCostUsd) {
        meta.skipped.push(`${job.s.sample_id}#${job.repeat}`);
        meta.stopped_reason = `已知费用达到上限 ${opts.maxCostUsd} USD`;
        continue;
      }
      const key = cacheBase ? cacheKey({ ...cacheBase, sample: job.s, repeat: job.repeat }) : null;
      const cached = key ? readCached(opts.cacheDir!, key, cfg) : null;
      let rec: RunRecord;
      if (cached) {
        rec = cached;
        cacheInfo.hits++;
        log(`复用缓存 ${job.s.sample_id} 第 ${job.repeat}/${repeats} 次（${key!.slice(0, 12)}）`);
      } else {
        log(`运行 ${job.s.sample_id} 第 ${job.repeat}/${repeats} 次…`);
        rec = await runSample(ctx, job.s, job.repeat);
        tracker.usd += knownUsd(rec);
        if (key && writeCached(opts.cacheDir!, key, rec)) cacheInfo.stored++;
      }
      meta.results[rec.status] = (meta.results[rec.status] ?? 0) + 1;
      writeJson(join(out, 'samples', job.s.sample_id, `r${job.repeat}.json`), rec);
      log(`  ${rec.status}${rec.error ? `（${rec.error.code}：${rec.error.message.slice(0, 120)}）` : ''}，${rec.audits.reduce((n, a) => n + a.findings.length, 0)} 条发现，${Math.round(rec.wall_ms / 1000)} 秒`);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(opts.maxParallel ?? 1, 8)) }, worker));
  meta.skipped.sort(byString);
  meta.ended_at = new Date().toISOString();
  writeJson(join(out, 'run.json'), meta);
  return meta;
}
