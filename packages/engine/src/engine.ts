// Job engine: planning → confirm/freeze → FIFO queue → pipeline run (`pipeline/`) with checkpoints at
// step boundaries, budget waits, interruption/resume and restart recovery. Budget accounting is in budget.ts, background
// jobs outside the pipeline in jobs.ts.
import { join } from 'node:path';
import {
  AppError, canonicalJson, TERMINAL_AUDIT_STATUSES, newId, sha256Hex, strategyHash, upgradeStrategy, type BudgetStage, type ModelRef, type Scene, type SnapshotManifest, type StructIndex, stageModel } from '@xiezhi/contracts';
import { buildIndex, Executor, loadRules, runCommand, runScript, SnapshotView, spawnService, type RuleSet } from '@xiezhi/context';
import { ConnectorPool } from '@xiezhi/connectors';
import { DEFAULT_PROMPTS_HASH, PromptSet, effectiveSkills, freezeSkills, installBuiltinSkills, resolvePromptOverrides, scanLayer, withPrompts } from '@xiezhi/knowledge';
import { ModelHub, modelGate, pingModel, type ModelMode } from '@xiezhi/agent';
import type { Store } from '@xiezhi/store';
import { budgetStoppedStages, checkpointDuration } from './budget.js';
import { ensureCoverageItems, incrementalCoverageTargets } from './coverage.js';
import { AuditRuntime, type PauseCause, type RepoInfo } from './runtime.js';
import { SERVICE_PAUSE_REASON, ServiceProbes, type ServicePing } from './service-probe.js';
import { confirmHunt } from './hunt.js';
import { BackgroundJobs, settleInterruptedJobs } from './jobs.js';
import { settleRevisionCards, matchVulnerabilities, planMatches, type CanonicalFinding } from './vulns.js';
import { freezeTopology } from './topology.js';
import { rerunAudit } from './rerun.js';
import { createAudit, createBackfillAudit, createReverifyAudit, type CreateAuditInput, type CreateBackfillInput, type CreateReverifyInput } from './services.js';
import { DURATION_CHECKPOINT_MS, getAudit, listSteps, transitionAudit, transitionStep, type AuditRow } from './state.js';
import { ensureStep, runStep, type RunnerOptions, type StepOutcome } from './step-runner.js';
import { type GateResult } from './steps/finalize.js';
import { planStep, reverifyPlan, riskHuntPlan, type AuditPlan } from './steps/plan.js';
import { planContextQuestions } from './facts.js';
import { responsibilityCard, type ResponsibilityCard } from './boundary.js';
import { clearSessions } from './resume.js';
import { ConversationService } from './conversation/service.js';
import { LspPool } from './lsp.js';
import { reverifyTargets } from './steps/verify-fix.js';
import { indexStep, snapshotStep } from './steps/prepare.js';
import { huntBasis } from './steps/risk.js';
import { scopeIdentity, scopeStep } from './steps/scope.js';
import { backfillPlan, backfillScope } from './steps/coverage-gap.js';
import { effectiveIndex } from './business.js';
import { approvedRuleSpecs, withProjectRules } from './project-rules.js';
import { supplementScope } from './threat.js';
import { createSupplementAudit, supplementCoverageTargets, supplementPlan, type CreateSupplementInput } from './supplement.js';
import { FLAG_BUDGET_DECLINED, type RunResult } from './pipeline/context.js';
import { runPipeline } from './pipeline/run.js';
import { updatePlanDraft, type DraftAuditRow } from './plan-edit.js';
import { withThreatModels } from './threat-model-audit.js';
import { filteredModels } from './queries/filtered.js';

export type { RunResult } from './pipeline/context.js';
export interface EngineOptions {
  store: Store;
  mode?: ModelMode;
  rulesDir?: string;
  runner?: Partial<RunnerOptions>;
  /** Test-only: accept file:// remote Git sources (fixtures). Never set from configuration or the API. */
  testAllowFileRemotes?: boolean;
  /**
   * Test-only: full and incremental audits hunt with the generalist batches instead of the lead, so the batch
   * machinery that gap fill, risk hunts and backfills still use is tested end to end. Never set from configuration, the
   * API or the strategy.
   */
  testGeneralistHunt?: boolean;
  /** The model service probe after an outage; default: one minimal request to the model (`pingModel`). */
  servicePing?: ServicePing;
  /** Probe intervals (default 1, 2, 4, 8, then 10 minutes). */
  probeDelaysMs?: number[];
}



/** Reason of the awaiting_confirm transition of audits that confirm themselves (reverify, backfill, risk hunt). */
export const AUTO_CONFIRM_REASON = 'plan ready; confirmed automatically';

/** Why an in-process run was stopped (AbortSignal.reason). */
export type StopReason = 'pause' | 'cancel' | 'shutdown';

export class Engine {
  /** In-process controllers for planning/running audits (pause/cancel of a live run). */
  private readonly active = new Map<string, AbortController>();
  private readonly steerSets = new Map<string, Set<(text: string) => Promise<void>>>();
  /** Runtimes of audits running in this process, for changes that apply live (concurrency). */
  private readonly running = new Map<string, AuditRuntime>();
  private readonly pauseRequested = new Set<string>();
  private readonly pauseTimers = new Map<string, NodeJS.Timeout>();
  /** Why the engine paused a run; absent when the user paused it. */
  private readonly pauseCauses = new Map<string, { reason: string; cause: PauseCause }>();
  /** Audits the service breaker paused, probed until the model service answers. */
  probes!: ServiceProbes;
  /** One minimal model request: the probe after an outage, and the check before a step fails on one. */
  servicePing!: ServicePing;
  private readonly autoResumed = new Set<(auditId: string) => void>();
  /** See EngineOptions.testAllowFileRemotes. */
  allowFileRemotes = false;
  /** See EngineOptions.testGeneralistHunt. */
  testGeneralistHunt = false;

  /** Live MCP sessions, breakers and tool caches of all connectors. */
  readonly connectors: ConnectorPool;
  /** AI conversations: replies run in-process and stream to subscribers. */
  readonly conversations: ConversationService;
  /** Language servers shared by audits, one per snapshot root and language. */
  readonly lsp: LspPool;
  /** Background jobs outside the pipeline: analyses, drafts, hunt bases and prechecks, imports, AI reports. */
  readonly jobs: BackgroundJobs;

  private constructor(
    readonly store: Store, readonly executor: Executor, public hub: ModelHub, readonly rules: RuleSet, private readonly runner: RunnerOptions, private readonly mode: ModelMode,
  ) {
    this.connectors = new ConnectorPool({
      launcher: (spec) => spawnService(executor, spec),
      connectorsDir: join(store.paths.tmp, 'connectors'),
      secrets: (id) => store.config.connectorSecrets?.[id] ?? {},
      confirmedCommand: (id) => store.get<{ h: string | null }>('SELECT confirmed_command_hash AS h FROM connector WHERE id = ?', id)?.h ?? null,
      runScript: (spec) => runScript(executor, spec),
      runCommand: (spec) => runCommand(executor, spec),
    });
    this.conversations = new ConversationService({ store, executor, rules, hub: () => this.hub, pool: () => this.connectors });
    this.lsp = new LspPool({ executor, config: () => store.config, indexesDir: store.paths.indexes, tmpDir: store.paths.tmp });
    this.jobs = new BackgroundJobs({ store, executor, rules, hub: () => this.hub, allowFileRemotes: () => this.allowFileRemotes, pool: () => this.connectors });
  }

  static async open(opts: EngineOptions): Promise<Engine> {
    const store = opts.store;
    const executor = new Executor({ scratchDir: join(store.paths.tmp, 'exec'), paths: { ...(store.config.tools.rgPath ? { rg: store.config.tools.rgPath } : {}), ...(store.config.tools.gitPath ? { git: store.config.tools.gitPath } : {}) } });
    const hub = await ModelHub.create(store.config, store.paths.agent, opts.mode ?? { kind: 'live' });
    // one limit for every model request of the process, read from the live config.
    modelGate.setCapacity(() => store.config.concurrency.modelRequests);
    installBuiltinSkills(store.paths.knowledgeGlobal);
    const engine = new Engine(store, executor, hub, loadRules(opts.rulesDir), {
      retryBackoffMs: opts.runner?.retryBackoffMs ?? 2_000, rateLimitBackoffMs: opts.runner?.rateLimitBackoffMs ?? 60_000,
    }, opts.mode ?? { kind: 'live' });
    engine.allowFileRemotes = !!opts.testAllowFileRemotes;
    engine.testGeneralistHunt = !!opts.testGeneralistHunt;
    engine.servicePing = opts.servicePing ?? (async (m) => {
      const p = store.config.modelProviders.find((x) => x.id === m.provider);
      return p ? pingModel(p, m.model) : { ok: false, detail: `provider ${m.provider} is not configured` };
    });
    engine.probes = new ServiceProbes({
      store, ...(opts.probeDelaysMs ? { delays: opts.probeDelaysMs } : {}),
      ping: engine.servicePing,
      resumed: (id) => { for (const l of engine.autoResumed) l(id); },
    });

    engine.recover();
    engine.watchServicePauses();
    engine.conversations.recover();
    // revision cards whose vulnerability was reviewed elsewhere before cards were settled on review.
    store.tx(() => settleRevisionCards(store));
    // Background jobs of the previous process (analyses, AI reports, drafts, imports, prechecks) cannot resume.
    settleInterruptedJobs(store);
    return engine;
  }

  /**
   * Rebuild the model hub after model settings changed. Runs already in progress keep the hub they
   * started with (their strategy is frozen anyway); new plans and runs use the new one.
   */
  async reloadModels(): Promise<void> {
    this.hub = await ModelHub.create(this.store.config, this.store.paths.agent, this.mode);
  }

  /** Called when the service probe queues an audit again: the service scheduler starts it. */
  onAutoResume(listener: (auditId: string) => void): () => void {
    this.autoResumed.add(listener);
    return () => this.autoResumed.delete(listener);
  }

  /** After a restart, audits the service breaker paused are probed again (the timers did not survive). */
  private watchServicePauses(): void {
    for (const a of this.store.all<{ id: string }>(`SELECT id FROM audit WHERE status = 'paused'`)) {
      const last = this.store.get<{ payload: string }>(
        `SELECT payload FROM event WHERE audit_id = ? AND type = 'audit.status_changed' ORDER BY seq DESC LIMIT 1`, a.id);
      if ((last ? JSON.parse(last.payload) as { reason?: string } : {}).reason !== SERVICE_PAUSE_REASON) continue;
      const trip = this.store.get<{ payload: string }>(
        `SELECT payload FROM event WHERE audit_id = ? AND type = 'judgement.made' AND json_extract(payload, '$.kind') = 'service_breaker' ORDER BY seq DESC LIMIT 1`, a.id);
      const model = trip ? (JSON.parse(trip.payload) as { model?: ModelRef | null }).model : null;
      if (model) this.probes.watch(a.id, model);
    }
  }

  /** Stop background jobs, conversations, language servers and connectors (service shutdown); analyses end as `interrupted`. */
  async stopAnalyses(): Promise<void> {
    this.probes.stopAll();
    await this.jobs.stop();
    await this.conversations.stopAll();
    await this.lsp.close();
    await this.connectors.closeAll();
  }

  /** Confirm a hunt: one risk_hunt audit per project (planned and confirmed without a model, then queued). */
  confirmHunt(huntId: string, origin: 'cli' | 'ui' | 'conversation' = 'ui'): string[] {
    return confirmHunt(this.store, this.hub.knownModels(), huntId, origin);
  }

  /**
   * Promote a canonical hit to a vulnerability of its project, deduplicated by the same-vulnerability
   * rules (fingerprint, rename following; no model call).
   */
  async promoteHuntHit(findingId: string): Promise<{ vulnId: string; displayNo: number; created: boolean }> {
    const f = this.store.get<CanonicalFinding & { audit_id: string; state: string; step_id: string; promoted_vulnerability_id: string | null }>('SELECT * FROM finding WHERE id = ?', findingId);
    if (!f) throw new AppError('COMMON_NOT_FOUND', findingId);
    const scene = getAudit(this.store, f.audit_id).scene;
    if (scene !== 'risk_hunt') throw new AppError('COMMON_VALIDATION', 'only risk hunt hits can be promoted');
    if (f.state !== 'canonical') throw new AppError('COMMON_VALIDATION', `hit is ${f.state}, not canonical`);
    const existing = f.promoted_vulnerability_id ? this.store.get<{ id: string; display_no: number }>('SELECT id, display_no FROM vulnerability WHERE id = ?', f.promoted_vulnerability_id) : undefined;
    if (existing) return { vulnId: existing.id, displayNo: existing.display_no, created: false };
    const rt = this.runtime(f.audit_id);
    const plans = await planMatches(rt, [f], { attempt: 1, signal: new AbortController().signal, stepId: f.step_id }, false);
    const before = this.store.get<{ n: number }>('SELECT COUNT(*) AS n FROM vulnerability WHERE project_id = ?', rt.audit.project_id)!.n;
    this.store.tx(() => matchVulnerabilities(rt, [f], f.step_id, plans));
    const occ = this.store.get<{ vulnerability_id: string }>('SELECT vulnerability_id FROM vuln_occurrence WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1', findingId);
    if (!occ) throw new AppError('INTERNAL', 'promotion did not link a vulnerability');
    this.store.update('finding', { id: findingId }, { promoted_vulnerability_id: occ.vulnerability_id });
    const v = this.store.get<{ display_no: number }>('SELECT display_no FROM vulnerability WHERE id = ?', occ.vulnerability_id)!;
    const created = this.store.get<{ n: number }>('SELECT COUNT(*) AS n FROM vulnerability WHERE project_id = ?', rt.audit.project_id)!.n > before;
    return { vulnId: occ.vulnerability_id, displayNo: v.display_no, created };
  }

  /** Restart recovery: never auto-continue; the user resumes explicitly. */
  recover(): string[] {
    const recovered: string[] = [];
    for (const a of this.store.all<{ id: string; status: string }>(`SELECT id, status FROM audit WHERE status IN ('planning','running','cancelling')`)) {
      // Only running steps were cut off; ready/retry_wait simply continue on resume.
      for (const s of this.store.all<{ id: string }>(`SELECT id FROM step WHERE audit_id = ? AND status = 'running'`, a.id)) {
        transitionStep(this.store, s.id, 'interrupted', {}, 'service restart');
      }
      // the time since the last checkpoint is not charged — it may include the downtime.
      this.store.update('audit', { id: a.id }, { running_since: null });
      transitionAudit(this.store, a.id, a.status === 'cancelling' ? 'cancelled' : 'interrupted', { reason: 'service restart' });
      recovered.push(a.id);
    }
    return recovered;
  }

  /** Rerun with the source audit's configuration. */
  rerun(sourceId: string, origin: 'cli' | 'ui' | 'conversation' = 'ui'): string {
    return rerunAudit(this.store, this.hub.knownModels(), sourceId, origin);
  }

  /** Backfill ("一键补审") audit for uncovered targets of a finished audit; plan it and it runs. */
  createBackfill(input: CreateBackfillInput): string {
    return createBackfillAudit(this.store, this.hub.knownModels(), input);
  }

  /** Supplement (追加执行) of a finished audit: logic review or risk hypotheses; plan it and it runs. */
  createSupplement(input: CreateSupplementInput): string {
    return createSupplementAudit(this.store, this.hub.knownModels(), input);
  }

  /** Reverification audit for tracked vulnerabilities; plan it and it runs without a confirmation. */
  createReverify(input: CreateReverifyInput): string {
    return createReverifyAudit(this.store, this.hub.knownModels(), input);
  }

  createAudit(input: Omit<CreateAuditInput, 'scene'> & { scene?: Scene }): string {
    return createAudit(this.store, this.hub.knownModels(), { scene: 'full', ...input });
  }

  private runtime(auditId: string): AuditRuntime {
    const rt = new AuditRuntime(this.store, auditId, this.executor, this.hub);
    rt.connectorPool = this.connectors;
    rt.lspPool = this.lsp;
    rt.rules = this.rules;
    rt.allowFileRemotes = this.allowFileRemotes;
    rt.testGeneralistHunt = this.testGeneralistHunt;
    rt.servicePing = this.servicePing;
    let steers = this.steerSets.get(auditId);
    if (!steers) this.steerSets.set(auditId, (steers = new Set()));
    rt.steers = steers;
    rt.load();
    return rt;
  }

  /** Link an external signal to an engine-owned controller so pause/cancel can stop this run. */
  private attach(auditId: string, external: AbortSignal): AbortController {
    const ac = new AbortController();
    if (external.aborted) ac.abort(external.reason);
    else external.addEventListener('abort', () => ac.abort(external.reason ?? 'shutdown'), { once: true });
    this.active.set(auditId, ac);
    return ac;
  }

  private detach(auditId: string, ac: AbortController): void {
    if (this.active.get(auditId) === ac) this.active.delete(auditId);
    this.pauseRequested.delete(auditId);
    this.pauseCauses.delete(auditId);
    const t = this.pauseTimers.get(auditId);
    if (t) clearTimeout(t);
    this.pauseTimers.delete(auditId);
  }

  isActive(auditId: string): boolean {
    return this.active.has(auditId);
  }

  /** Send a steer message to every running session of the audit; returns how many received it. */
  async steer(auditId: string, text: string): Promise<number> {
    const set = this.steerSets.get(auditId);
    if (!set || set.size === 0) return 0;
    await Promise.all([...set].map((s) => s(text).catch(() => undefined)));
    return set.size;
  }

  private async loadIndexes(rt: AuditRuntime): Promise<void> {
    // A target of a multi-repository incremental audit without a baseline is audited in full, so it has the
    // structure index (its candidates and coverage) even with AST off.
    const full = (r: RepoInfo) => rt.strategy.tools.ast || (rt.audit.scene === 'incremental' && r.role === 'target' && !rt.baseRepo(r.id));
    for (const repo of rt.repos.filter((r) => !full(r))) {
      // Identity only: cached by rootHash; failure just leaves findings without fingerprints.
      if (rt.identityIndexes.has(repo.name)) continue;
      try {
        rt.identityIndexes.set(repo.name, (await buildIndex(rt.views.get(repo.name)!, this.rules, { indexesDir: this.store.paths.indexes, ...rt.indexLanguages(repo.name) })).index);
      } catch { /* no fingerprints: matching falls back to suspected matching */ }
    }
    for (const repo of rt.repos.filter(full)) {
      if (rt.indexes.has(repo.name)) continue;
      const r = await buildIndex(rt.views.get(repo.name)!, this.rules, { indexesDir: this.store.paths.indexes, ...rt.indexLanguages(repo.name) });
      let index = effectiveIndex(r.index, rt.strategy);
      // the frozen project rules run as extra sinks (not cached with the index: the rules are per project).
      if (rt.knowledge.projectRules?.length) {
        const pr = await withProjectRules(rt.views.get(repo.name)!, index, rt.knowledge.projectRules);
        index = pr.index;
        if (pr.added || pr.skipped.length) rt.event('judgement.made', { kind: 'project_rules', repo: repo.name, added: pr.added, skipped: pr.skipped });
      }
      rt.indexes.set(repo.name, index);
    }
  }

  /** a service's responsibility card from the latest snapshot of its repository (index cached on disk). */
  async serviceCard(projectId: string, repoName: string): Promise<ResponsibilityCard> {
    const repo = this.store.get<{ id: string; name: string }>('SELECT id, name FROM repository WHERE project_id = ? AND name = ? AND removed_at IS NULL', projectId, repoName);
    if (!repo) throw new AppError('COMMON_NOT_FOUND', `repository ${repoName}`);
    const snap = this.store.get<{ root_hash: string; manifest_ref: string }>('SELECT root_hash, manifest_ref FROM snapshot WHERE repository_id = ? ORDER BY created_at DESC LIMIT 1', repo.id);
    let index: StructIndex | undefined;
    if (snap) {
      try {
        const view = new SnapshotView(repo.name, join(this.store.paths.snapshots, snap.root_hash), this.store.artifacts.getJson<SnapshotManifest>(snap.manifest_ref));
        index = (await buildIndex(view, this.rules, { indexesDir: this.store.paths.indexes })).index;
      } catch { /* the card without inbound entries */ }
    }
    return responsibilityCard(this.store, projectId, repo.name, index);
  }

  private freezeKnowledge(auditId: string): void {
    const a = getAudit(this.store, auditId);
    if (a.knowledge_ref) return;
    const global = scanLayer(this.store.paths.knowledgeGlobal, 'global');
    const project = scanLayer(join(this.store.paths.projects, a.project_id, 'knowledge'), 'project');
    // the requirement threat models the audit references are frozen with its knowledge.
    // the prompt overrides in effect now are the audit's for its whole life; the requirement threat
    // model summary frozen with the knowledge is rendered with them.
    const prompts = resolvePromptOverrides(this.store.paths.knowledgeGlobal, join(this.store.paths.projects, a.project_id, 'knowledge'));
    const frozen = withPrompts(new PromptSet(prompts), () => withThreatModels(this.store, freezeSkills(effectiveSkills(global, project), this.store.artifacts), upgradeStrategy(JSON.parse(a.strategy_draft)).threatModels));
    if (prompts.hash !== DEFAULT_PROMPTS_HASH) frozen.prompts = prompts;
    // the approved project rules now are the audit's.
    const projectRules = approvedRuleSpecs(this.store, a.project_id);
    if (projectRules.length) frozen.projectRules = projectRules;
    this.store.update('audit', { id: auditId }, { knowledge_ref: this.store.artifacts.putJson(frozen) });
  }

  // ---- planning ---------------------------------------------------------------

  async plan(auditId: string, external: AbortSignal): Promise<AuditPlan | null> {
    const ac = this.attach(auditId, external);
    try {
      return await this.planInner(auditId, ac.signal);
    } finally {
      this.detach(auditId, ac);
    }
  }

  private async planInner(auditId: string, signal: AbortSignal): Promise<AuditPlan | null> {
    let a = getAudit(this.store, auditId);
    if (a.status === 'interrupted') {
      // Interrupted during planning: resume planning directly (plan steps are idempotent).
      this.store.update('audit', { id: auditId }, { status: 'planning' });
      a = getAudit(this.store, auditId);
    }
    if (a.status !== 'planning') throw new AppError('INVALID_TRANSITION', `audit is ${a.status}, expected planning`);
    this.freezeKnowledge(auditId);
    let rt = this.runtime(auditId);
    const repos = this.store.all<{ repository_id: string; name: string }>(
      'SELECT ar.repository_id, r.name FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id WHERE ar.audit_id = ? ORDER BY r.name', auditId);
    for (const r of repos) {
      // Backfill audits reuse the source audit's snapshot (attached at creation).
      if (this.store.get('SELECT 1 FROM audit_repository WHERE audit_id = ? AND repository_id = ? AND snapshot_id IS NOT NULL', auditId, r.repository_id)) continue;
      const step = ensureStep(this.store, auditId, { kind: 'snapshot', identity: { repo: r.repository_id }, input: { repo: r.name }, required: true, maxAttempts: 1 });
      const out = await runStep(rt, step, signal, this.runner, (ctx) => snapshotStep(rt, r.repository_id, ctx));
      if (out !== 'succeeded') return this.planningStopped(auditId, out, 'snapshot failed', signal);
    }
    rt = this.runtime(auditId);
    const incremental = a.scene === 'incremental';
    if (incremental) {
      // Baseline given as a ref: snapshot it like the head; each target has its own.
      const byRef = new Set(this.store.all<{ repository_id: string }>(
        `SELECT repository_id FROM audit_repository WHERE audit_id = ? AND role_in_audit = 'target' AND base_requested_ref IS NOT NULL`, auditId).map((r) => r.repository_id));
      for (const target of rt.targets.filter((t) => byRef.has(t.id) && !rt.baseRepo(t.id))) {
        const step = ensureStep(this.store, auditId, { kind: 'snapshot', identity: { repo: target.id, base: true }, input: { repo: target.name, base: true }, required: true, maxAttempts: 1 });
        const out = await runStep(rt, step, signal, this.runner, (ctx) => snapshotStep(rt, target.id, ctx, { base: true }));
        if (out !== 'succeeded') return this.planningStopped(auditId, out, 'baseline snapshot failed', signal);
      }
      rt = this.runtime(auditId);
    }
    if (rt.strategy.tools.ast) {
      // Related and context repositories are evidence only: no structure index, no candidates.
      for (const r of rt.targets) {
        const step = ensureStep(this.store, auditId, { kind: 'index', identity: { repo: r.id, root: r.rootHash, rules: this.rules.version }, input: { repo: r.name }, maxAttempts: 1 });
        const out = await runStep(rt, step, signal, this.runner, (ctx) => indexStep(rt, this.rules, r.name, ctx));
        if (out === 'interrupted') return this.planningStopped(auditId, out, 'interrupted', signal);
      }
    }
    await this.loadIndexes(rt);
    if (incremental) {
      for (const target of rt.targets) {
        const scopeRow = ensureStep(this.store, auditId, { kind: 'scope', identity: scopeIdentity(rt, this.rules, target), input: { repo: target.name }, required: true, maxAttempts: 1 });
        const out = await runStep(rt, scopeRow, signal, this.runner, (ctx) => scopeStep(rt, this.rules, ctx, target));
        if (out !== 'succeeded') return this.planningStopped(auditId, out, 'impact analysis failed', signal);
      }
    }
    const backfill = backfillScope(rt);
    const supplement = supplementScope(rt);
    if (backfill || supplement) {
      // deterministic plan, confirmed at once ("一键补审" / 追加执行 are actions).
      const row = ensureStep(this.store, auditId, { kind: 'plan', identity: { audit: auditId }, required: true, maxAttempts: 1 });
      const out = await runStep(rt, row, signal, this.runner, async () => (backfill ? backfillPlan(rt, backfill) : supplementPlan(rt, supplement!)));
      if (out !== 'succeeded') return this.planningStopped(auditId, out, 'plan failed', signal);
      a = getAudit(this.store, auditId);
      transitionAudit(this.store, auditId, 'awaiting_confirm', { reason: AUTO_CONFIRM_REASON });
      this.store.appendEvent(auditId, 'plan.generated', { plan_ref: a.plan_ref });
      this.confirm(auditId);
      return this.store.artifacts.getJson<AuditPlan>(a.plan_ref!);
    }
    if (a.scene === 'risk_hunt') {
      // deterministic plan, confirmed at once (the hunt was confirmed as a whole).
      const row = ensureStep(this.store, auditId, { kind: 'plan', identity: { audit: auditId }, required: true, maxAttempts: 1 });
      const out = await runStep(rt, row, signal, this.runner, async () => riskHuntPlan(rt, huntBasis(rt)));
      if (out !== 'succeeded') return this.planningStopped(auditId, out, 'plan failed', signal);
      a = getAudit(this.store, auditId);
      transitionAudit(this.store, auditId, 'awaiting_confirm', { reason: AUTO_CONFIRM_REASON });
      this.store.appendEvent(auditId, 'plan.generated', { plan_ref: a.plan_ref });
      this.confirm(auditId);
      return this.store.artifacts.getJson<AuditPlan>(a.plan_ref!);
    }
    if (a.scene === 'reverify') {
      // deterministic plan, confirmed at once (reverification is an action on vulnerabilities).
      const row = ensureStep(this.store, auditId, { kind: 'plan', identity: { audit: auditId }, required: true, maxAttempts: 1 });
      const out = await runStep(rt, row, signal, this.runner, async () => reverifyPlan(rt, reverifyTargets(rt)));
      if (out !== 'succeeded') return this.planningStopped(auditId, out, 'plan failed', signal);
      a = getAudit(this.store, auditId);
      transitionAudit(this.store, auditId, 'awaiting_confirm', { reason: AUTO_CONFIRM_REASON });
      this.store.appendEvent(auditId, 'plan.generated', { plan_ref: a.plan_ref });
      this.confirm(auditId);
      return this.store.artifacts.getJson<AuditPlan>(a.plan_ref!);
    }
    const planStepRow = ensureStep(this.store, auditId, { kind: 'plan', identity: { audit: auditId }, required: true, maxAttempts: 2, model: stageModel(rt.strategy, 'profile')! });
    let out = await runStep(rt, planStepRow, signal, this.runner, (ctx) => planStep(rt, ctx));
    // A failed plan model does not fail the audit — an engine-written plan supersedes it.
    if (out === 'failed') {
      const fb = ensureStep(this.store, auditId, { kind: 'plan', identity: { audit: auditId, fallback: true }, input: { supersedes: planStepRow.id }, required: true, maxAttempts: 1, model: null });
      this.store.appendEvent(auditId, 'judgement.made', { kind: 'plan_fallback', reason: 'plan model failed; engine-written plan used' }, planStepRow.id);
      out = await runStep(rt, fb, signal, this.runner, (ctx) => planStep(rt, ctx, { deterministic: true }));
    }
    if (out !== 'succeeded') return this.planningStopped(auditId, out, 'plan failed', signal);
    a = getAudit(this.store, auditId);
    // the context the plan asks for becomes questions; the answers become enterprise facts.
    planContextQuestions(this.store, auditId, planStepRow.id, this.store.artifacts.getJson<AuditPlan>(a.plan_ref!).submitted?.contextNeeded ?? []);
    transitionAudit(this.store, auditId, 'awaiting_confirm', { reason: a.auto_start ? AUTO_CONFIRM_REASON : 'plan ready' });
    this.store.appendEvent(auditId, 'plan.generated', { plan_ref: a.plan_ref });
    // form audits start at once by default; conversation audits were confirmed on their card.
    if (a.auto_start) this.confirm(auditId);
    return this.store.artifacts.getJson<AuditPlan>(a.plan_ref!);
  }

  private planningStopped(auditId: string, out: StepOutcome, reason: string, signal: AbortSignal): null {
    if (out === 'interrupted' && signal.reason === 'cancel') {
      this.cancelSteps(auditId);
      transitionAudit(this.store, auditId, 'cancelled', { reason: 'cancelled by user' });
    } else if (out === 'interrupted') transitionAudit(this.store, auditId, 'interrupted', { reason });
    else {
      const failed = listSteps(this.store, auditId).find((s) => s.status === 'failed');
      transitionAudit(this.store, auditId, 'failed', { reason, errorClass: failed?.error_class ?? 'INTERNAL' });
    }
    return null;
  }

  /** Freeze strategy + confirm. CLI `--yes` calls this right after plan(). */
  confirm(auditId: string): void {
    const a = getAudit(this.store, auditId);
    if (a.status !== 'awaiting_confirm') throw new AppError('INVALID_TRANSITION', `audit is ${a.status}`);
    const strategy = upgradeStrategy(JSON.parse(a.strategy_draft));
    const hash = strategyHash(strategy);
    this.store.tx(() => {
      // The topology is frozen with the strategy: later edits do not change this audit.
      this.store.update('audit', { id: auditId }, { strategy_frozen: strategy, strategy_hash: hash, topology_ref: freezeTopology(this.store, a.project_id) });
      this.store.appendEvent(auditId, 'plan.confirmed', { strategy_hash: hash });
      transitionAudit(this.store, auditId, 'queued', { reason: 'plan confirmed' });
    });
  }

  /** Edit the plan of an audit not yet confirmed: merge the override into the draft, check it, recompute the budget. */
  updatePlan(auditId: string, expectedRevision: number | undefined, patch: { strategyOverride: Record<string, unknown>; title?: string }): DraftAuditRow {
    return updatePlanDraft(this.store, this.hub.knownModels(), auditId, expectedRevision, patch);
  }

  // ---- controls -----------------------------------------------------------------

  /**
   * Continue an interrupted or paused audit. `restartFiltered`: steps a content filter refused start afresh —
   * their saved conversation is dropped — instead of retrying the conversation as it is.
   */
  resume(auditId: string, opts: { restartFiltered?: boolean; switchModel?: ModelRef; switchScope?: 'filtered' | 'later' } = {}): void {
    const a = getAudit(this.store, auditId);
    this.probes.cancel(auditId);
    if ((opts.restartFiltered || opts.switchModel) && ['interrupted', 'paused'].includes(a.status)) {
      const to = opts.switchModel;
      if (to && !this.store.config.modelProviders.some((p) => p.id === to.provider && p.models.some((m) => m.id === to.model))) {
        throw new AppError('COMMON_VALIDATION', `model ${to.provider}/${to.model} is not configured`);
      }
      if (to && opts.switchScope === 'later') {
        const switches = JSON.parse(a.model_switches || '{}') as Record<string, ModelRef>;
        const key = `${to.provider}/${to.model}`;
        const from = filteredModels(this.store, auditId).filter((m) => m !== key);
        for (const m of from) switches[m] = to;
        delete switches[key];
        this.store.update('audit', { id: auditId }, { model_switches: JSON.stringify(switches) });
        this.store.appendEvent(auditId, 'intervention.applied', { kind: 'switch_model_later', from, to });
      }
      for (const s of listSteps(this.store, auditId).filter((x) => x.status === 'interrupted' && x.error_class === 'CONTENT_FILTERED')) {
        if (opts.restartFiltered) {
          clearSessions(this.store, auditId, s.id);
          this.store.appendEvent(auditId, 'intervention.applied', { kind: 'restart_filtered', text: 'step restarts afresh after a content filter refusal' }, s.id);
        }
        // “切换模型重试” — the user picks the model; recorded like an automatic fallback (`model.fallback`), so
        // the resumed run (AuditRuntime.load → modelFor) uses it and the trajectory shows the switch.
        if (to) {
          const from = s.provider && s.model ? `${s.provider}/${s.model}` : null;
          this.store.update('step', { id: s.id }, { model: to.model, provider: to.provider, max_attempts: s.max_attempts + 1 });
          this.store.appendEvent(auditId, 'model.fallback', { from, to, reason: 'CONTENT_FILTERED', manual: true }, s.id);
        }
      }
    }
    if (!['interrupted', 'paused'].includes(a.status)) throw new AppError('AUDIT_NOT_RESUMABLE', a.status);
    if (a.status === 'interrupted' && !a.strategy_frozen) {
      this.store.update('audit', { id: auditId }, { status: 'planning' });
      return;
    }
    transitionAudit(this.store, auditId, 'queued', { reason: 'resumed by user' });
  }

  /**
   * Cancel. A run in this process is aborted and settles into `cancelled` when its
   * attempts have landed; otherwise the audit is cancelled directly. Committed results are kept.
   */
  cancel(auditId: string): void {
    const a = getAudit(this.store, auditId);
    if (TERMINAL_AUDIT_STATUSES.includes(a.status)) throw new AppError('AUDIT_TERMINAL', a.status);
    this.probes.cancel(auditId);
    const ac = this.active.get(auditId);
    if (ac) {
      if (a.status === 'running') transitionAudit(this.store, auditId, 'cancelling', { reason: 'cancel requested' });
      ac.abort('cancel');
      return;
    }
    if (a.status === 'running' || a.status === 'cancelling') {
      throw new AppError('INVALID_TRANSITION', 'audit is running in another process; stop that process first');
    }
    this.store.tx(() => {
      this.cancelSteps(auditId);
      transitionAudit(this.store, auditId, 'cancelled', { reason: 'cancelled by user' });
    });
    clearSessions(this.store, auditId);
  }

  private cancelSteps(auditId: string): void {
    this.store.tx(() => {
      for (const s of listSteps(this.store, auditId)) {
        if (['pending', 'ready', 'blocked_budget', 'retry_wait', 'interrupted', 'running'].includes(s.status)) transitionStep(this.store, s.id, 'cancelled', {}, 'audit cancelled');
      }
    });
  }

  /**
   * Pause a run in this process: no new steps are dispatched; every running session
   * stops before its next model request, its transcript saved, so `resume` — in this process or after a restart —
   * continues it where it stopped. Sessions still busy after pauseGraceSec (a long reply, a sub-agent) are aborted;
   * their transcripts keep everything up to the last complete entry. The audit ends in `paused`.
   */
  async pause(auditId: string): Promise<void> {
    const a = getAudit(this.store, auditId);
    if (a.status === 'queued') {
      // Not started yet: paused directly is not a legal transition; cancel-free alternative is to keep queued.
      throw new AppError('AUDIT_INVALID_TRANSITION', 'audit is queued; cancel it or wait until it starts');
    }
    if (a.status !== 'running' || !this.active.has(auditId)) throw new AppError('AUDIT_INVALID_TRANSITION', `audit is ${a.status}`);
    if (this.pauseRequested.has(auditId)) return;
    this.pauseRequested.add(auditId);
    this.store.appendEvent(auditId, 'intervention.received', { kind: 'pause', text: 'pause requested' });
    const rt = this.running.get(auditId);
    if (rt) rt.pausing = true;
    const grace = this.store.config.engine.pauseGraceSec * 1000;
    const t = setTimeout(() => this.active.get(auditId)?.abort('pause'), grace);
    t.unref?.();
    this.pauseTimers.set(auditId, t);
  }

  /**
   * Top up budget (idempotent per key). waiting_budget → queued. With `stage` the
   * tokens go to that stage quota and to the total alike, so the stage can use them without hitting the total.
   */
  topUp(auditId: string, delta: { tokens?: number; durationSec?: number; stage?: BudgetStage; liftStageQuotas?: boolean }, idempotencyKey: string, actor: 'user' | 'cli' = 'cli'): void {
    this.store.tx(() => {
      if (this.store.get('SELECT 1 FROM budget_adjustment WHERE audit_id = ? AND idempotency_key = ?', auditId, idempotencyKey)) return;
      const a = getAudit(this.store, auditId);
      if (TERMINAL_AUDIT_STATUSES.includes(a.status)) throw new AppError('AUDIT_TERMINAL', a.status);
      const eff = JSON.parse(a.budget_effective) as { tokens: number; durationMs: number; costMicros: number | null; stages?: Partial<Record<BudgetStage, number>> };
      if (delta.liftStageQuotas) return this.liftStageQuotas(a, eff, delta, idempotencyKey, actor);
      if (delta.stage && eff.stages?.[delta.stage] === undefined) throw new AppError('COMMON_VALIDATION', `audit has no quota for stage ${delta.stage}`);
      // Without a stage, the stages of the steps waiting for budget get the tokens too, so a
      // total-only top-up (CLI, older clients) cannot leave the audit waiting on a stage quota.
      const targets = (delta.stage ? [delta.stage] : budgetStoppedStages(this.store, auditId)).filter((k) => eff.stages?.[k] !== undefined);
      const next = {
        ...eff, tokens: eff.tokens + (delta.tokens ?? 0), durationMs: eff.durationMs + (delta.durationSec ?? 0) * 1000,
        ...(targets.length ? { stages: { ...eff.stages, ...Object.fromEntries(targets.map((k) => [k, eff.stages![k]! + (delta.tokens ?? 0)])) } } : {}),
      };
      this.store.insert('budget_adjustment', { id: newId('budgetAdjustment'), audit_id: auditId, idempotency_key: idempotencyKey, delta, actor, reason: 'top-up' });
      this.store.update('audit', { id: auditId }, { budget_effective: next });
      this.store.appendEvent(auditId, 'budget.topped_up', { delta, effective: next });
      if (a.status === 'waiting_budget') transitionAudit(this.store, auditId, 'queued', { reason: 'budget topped up' });
    });
  }

  /**
   * Drop the stage quotas of a confirmed audit — from then on only the total limits it
   * (plus any tokens / time of the same grant). Steps check the budget record each time, so a running audit follows at
   * once; one waiting for a stage quota continues, one also past its total keeps waiting for a total top-up.
   */
  private liftStageQuotas(a: AuditRow, eff: { tokens: number; durationMs: number; costMicros: number | null; stages?: Partial<Record<BudgetStage, number>> },
    delta: { tokens?: number; durationSec?: number; liftStageQuotas?: boolean }, idempotencyKey: string, actor: 'user' | 'cli'): void {
    if (a.status === 'planning' || a.status === 'awaiting_confirm') throw new AppError('INVALID_TRANSITION', `${a.status}: switch the stage quotas off when adjusting the plan`);
    const { stages: _lifted, ...rest } = eff;
    const next = { ...rest, tokens: eff.tokens + (delta.tokens ?? 0), durationMs: eff.durationMs + (delta.durationSec ?? 0) * 1000 };
    this.store.insert('budget_adjustment', { id: newId('budgetAdjustment'), audit_id: a.id, idempotency_key: idempotencyKey, delta, actor, reason: 'lift-stage-quotas' });
    this.store.update('audit', { id: a.id }, { budget_effective: next });
    this.store.appendEvent(a.id, 'budget.topped_up', { delta, effective: next });
    const used = (JSON.parse(a.budget_consumed) as { tokens: number }).tokens;
    if (a.status === 'waiting_budget' && used < next.tokens) transitionAudit(this.store, a.id, 'queued', { reason: 'stage quotas lifted' });
  }

  /** Decline a top-up: finish with the results so far (partial, BUDGET_EXHAUSTED). */
  declineBudget(auditId: string): void {
    const a = getAudit(this.store, auditId);
    if (a.status !== 'waiting_budget') throw new AppError('INVALID_TRANSITION', a.status);
    this.store.tx(() => {
      this.store.update('audit', { id: auditId }, { phase: FLAG_BUDGET_DECLINED });
      transitionAudit(this.store, auditId, 'queued', { reason: 'budget declined; finalizing' });
    });
  }

  // ---- execution ------------------------------------------------------------------

  /** Run queued audits in FIFO order (concurrency.audits = 1). */
  async runQueue(signal: AbortSignal): Promise<{ auditId: string; result: RunResult }[]> {
    const done: { auditId: string; result: RunResult }[] = [];
    while (!signal.aborted) {
      const next = this.store.get<{ id: string }>(`SELECT id FROM audit WHERE status = 'queued' ORDER BY queued_at, id LIMIT 1`);
      if (!next) break;
      done.push({ auditId: next.id, result: await this.run(next.id, signal) });
    }
    return done;
  }

  async run(auditId: string, external: AbortSignal): Promise<RunResult> {
    const ac = this.attach(auditId, external);
    try {
      const r = await this.runInner(auditId, ac.signal);
      // paused by the service breaker → probe the model service, continue when it answers.
      const c = this.pauseCauses.get(auditId)?.cause;
      if (r.status === 'paused' && c?.kind === 'service' && c.model) this.probes.watch(auditId, c.model);
      return r;
    } finally {
      this.detach(auditId, ac);
    }
  }

  private async runInner(auditId: string, signal: AbortSignal): Promise<RunResult> {
    transitionAudit(this.store, auditId, 'running', { reason: 'dequeued' });
    // Building the runtime reads the frozen strategy and snapshot manifests. If that throws,
    // the audit must end as failed here; otherwise it stays `running` with no runner and only a restart frees it.
    let rt: AuditRuntime;
    try {
      rt = this.runtime(auditId);
    } catch (e) {
      this.store.appendEvent(auditId, 'error', { error_class: 'INTERNAL', summary: `audit could not be loaded: ${String((e as Error).message)}`.slice(0, 500) });
      transitionAudit(this.store, auditId, 'failed', { reason: 'audit could not be loaded', errorClass: 'INTERNAL' });
      clearSessions(this.store, auditId);
      return { status: 'failed', partialReasons: [] };
    }
    this.running.set(auditId, rt);
    // a step the content filter refused, with no fallback model, pauses the audit for a person.
    rt.requestPause = (reason, cause) => {
      if (this.pauseRequested.has(auditId)) return;
      this.pauseRequested.add(auditId);
      this.pauseCauses.set(auditId, { reason, cause });
      rt.pausing = true;
      this.store.appendEvent(auditId, 'intervention.received', { kind: 'pause', text: reason, by: 'engine', cause: cause.kind });
      // A session waiting on a service that does not answer would hold its slot until the request times out.
      if (cause.kind === 'service') {
        const t = setTimeout(() => this.active.get(auditId)?.abort('pause'), this.store.config.engine.pauseGraceSec * 1000);
        t.unref?.();
        this.pauseTimers.set(auditId, t);
      }
    };
    // settle the running time every half minute, so a crash loses at most that much and a restart
    // does not count the time the service was down.
    const beat = setInterval(() => { try { checkpointDuration(this.store, auditId); } catch { /* the next beat retries */ } }, DURATION_CHECKPOINT_MS);
    beat.unref?.();
    try {
      await this.loadIndexes(rt);
      // Incremental: only the impact set is in scope for coverage; outside it everything
      // is not_covered. A full-scan fallback covers everything like a full audit.
      const backfill = backfillScope(rt);
      const supplement = supplementScope(rt);
      ensureCoverageItems(rt, backfill ? new Set(backfill.targets) : supplement ? supplementCoverageTargets(rt, supplement)
        : rt.audit.scene === 'incremental' ? incrementalCoverageTargets(rt) : undefined);
      return await this.pipeline(rt, signal);
    } catch (e) {
      if (signal.aborted || this.pauseRequested.has(auditId)) return this.halt(auditId, signal);
      this.store.appendEvent(auditId, 'error', { error_class: 'INTERNAL', summary: String((e as Error).message).slice(0, 500) });
      transitionAudit(this.store, auditId, 'failed', { reason: 'engine error', errorClass: 'INTERNAL' });
      return { status: 'failed', partialReasons: [] };
    } finally {
      clearInterval(beat);
      if (this.running.get(auditId) === rt) this.running.delete(auditId);
      // saved transcripts only matter while the audit may still continue.
      if (TERMINAL_AUDIT_STATUSES.includes(getAudit(this.store, auditId).status)) clearSessions(this.store, auditId);
    }
  }

  /**
   * Apply a new session limit to a running audit: sessions not yet started use it at once; running ones
   * are not interrupted. Returns whether the audit was running here.
   */
  applyConcurrency(auditId: string, sessions: number): boolean {
    const rt = this.running.get(auditId);
    if (!rt) return false;
    rt.strategy = { ...rt.strategy, concurrency: { ...rt.strategy.concurrency, sessions } };
    rt.slots.setCapacity(() => rt.strategy.concurrency.sessions);
    return true;
  }

  private interruptRunning(auditId: string): void {
    for (const s of listSteps(this.store, auditId)) if (s.status === 'running') transitionStep(this.store, s.id, 'interrupted', {}, 'interrupted');
    if (getAudit(this.store, auditId).status === 'running') transitionAudit(this.store, auditId, 'interrupted', { reason: 'process interrupted' });
  }

  /** Settle a stopped run according to why it stopped (pause / cancel / shutdown). */
  private halt(auditId: string, signal: AbortSignal): RunResult {
    const reason: StopReason = signal.reason === 'cancel' ? 'cancel' : this.pauseRequested.has(auditId) || signal.reason === 'pause' ? 'pause' : 'shutdown';
    if (reason === 'cancel') {
      this.store.tx(() => {
        this.cancelSteps(auditId);
        const st = getAudit(this.store, auditId).status;
        if (st === 'running') transitionAudit(this.store, auditId, 'cancelling', { reason: 'cancel requested' });
        transitionAudit(this.store, auditId, 'cancelled', { reason: 'cancelled by user' });
      });
      return { status: 'cancelled', partialReasons: [] };
    }
    if (reason === 'pause') {
      this.store.tx(() => {
        for (const s of listSteps(this.store, auditId)) if (s.status === 'running') transitionStep(this.store, s.id, 'interrupted', {}, 'paused');
        if (getAudit(this.store, auditId).status === 'running') transitionAudit(this.store, auditId, 'paused', { reason: this.pauseCauses.get(auditId)?.reason ?? 'paused by user' });
      });
      return { status: 'paused', partialReasons: [] };
    }
    this.interruptRunning(auditId);
    return { status: 'interrupted', partialReasons: [] };
  }

  /** The audit pipeline, in `pipeline/` one function per stage. */
  private pipeline(rt: AuditRuntime, signal: AbortSignal): Promise<RunResult> {
    return runPipeline({
      store: this.store, runner: this.runner,
      halt: (auditId, sig) => this.halt(auditId, sig),
      pauseRequested: (auditId) => this.pauseRequested.has(auditId),
      closeLsp: (roots) => this.lsp.close(roots),
    }, rt, signal);
  }

  status(auditId: string) {
    const a = getAudit(this.store, auditId);
    const steps = listSteps(this.store, auditId);
    return {
      audit: a,
      // tokens as the budget counts them (cached input included): the steps add up to `budget.consumed.tokens`.
      steps: steps.map((s) => ({ kind: s.kind, status: s.status, attempt: s.attempt, tokens: s.tokens_in + s.tokens_out + s.tokens_cached, error: s.error_class })),
      plan: a.plan_ref ? this.store.artifacts.getJson<AuditPlan>(a.plan_ref) : null,
      gate: a.gate_ref ? this.store.artifacts.getJson<GateResult>(a.gate_ref) : null,
    };
  }
}

export function idempotencyKey(parts: unknown): string {
  return sha256Hex(canonicalJson(parts)).slice(0, 32);
}
