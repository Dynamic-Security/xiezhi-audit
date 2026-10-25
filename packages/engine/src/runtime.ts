// Per-audit runtime: loaded snapshots/indexes, frozen strategy/knowledge, budget account, trajectory
// wiring for agent sessions, and read-coverage flushing.
import { AsyncLocalStorage } from 'node:async_hooks';
import { existsSync, rmdirSync, rmSync } from 'node:fs';
import { dirname } from 'node:path';
import {
  answerOptions, crossModels, isAuditLanguage, newId, stageFallback, stageModel, upgradeStrategy, type AuditLanguage, type BudgetStage, type Connection, type AuditStrategy, type EventType, type ImpactSet, type ModelRef, type SnapshotManifest, type StepKind, type StructIndex,
} from '@xiezhi/contracts';
import {
  computeRepoSignals, CONNECT_VERSION, extractConnections, type ConnectLimit, gitLog, parseGitUrl, remoteCacheDir, toolSymbolLookup, matchConnections, mergeRanges, SnapshotView, type CrossRepoData, type Executor, type IndexMap, type Range, type RuleSet,
  type ToolContext,
} from '@xiezhi/context';
import { P, PromptSet, sessionKnowledge, type FrozenKnowledge, type KnowledgeNeed, type Phase, type TaskFacts } from '@xiezhi/knowledge';
import {
  buildAuditTools, DEFAULT_CONTEXT_WINDOW, systemPromptSections, detectInjection, findTranscript, modelCallContext, newNonce, PriorityGate, readTranscriptMeta, startSession, unverifiedKnowledgeNote, withEgressScope, wrapUntrusted, type AuditTool, type EgressScope, type InjectionSignal, type BudgetVerdict, type ConnectorAccess, type ModelHub, type SessionEvent,
  type SessionOutcome, type UsageDelta,
} from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import { activeFacts } from './facts.js';
import { confidentialAllowed, egressSink, filesOfIds } from './egress.js';
import { cardText, effectiveTrust, responsibilityCard } from './boundary.js';
import { projectGateways } from './gateway.js';

/** sessions that judge findings get the service card (hunts, experts, gap fills, explore, reviews). */
const SERVICE_CARD_KINDS: ReadonlySet<string> = new Set(['hunt', 'coverage-gap', 'challenge', 'review', 'verify-fix']);
import { Type } from 'typebox';
import type { ConnectorPool } from '@xiezhi/connectors';
import { indexLanguagesFor } from './auditable.js';
import { languageOf, type LspPool } from './lsp.js';
import { buildConnectorAccess, connectorPrompt, type ConnectorRef } from './connector-access.js';
import { costMicros } from './estimates.js';
import { getAudit, isCrossLane, sessionLimit, type AuditRow, type StepRow } from './state.js';
import { budgetStage, stepStage } from './stages.js';
import { resumableTranscript, transcriptDir, TRANSIENT_SESSION_ERRORS } from './resume.js';
import { isSystemModel, renderSystemModel, renderThreatModel, type ProfileOutput, type SystemModelOutput } from './steps/profile.js';
import { serviceMappings, type Topology } from './topology.js';
import type { ServicePing } from './service-probe.js';


/** Why the engine paused an audit: `service` is continued by the service probe, the others by a person. */
export interface PauseCause { kind: 'content_filter' | 'quota' | 'service'; model?: ModelRef | null }
export interface RepoInfo { id: string; name: string; snapshotId: string; rootHash: string; role: string }

/** `stages`: per-stage quota (effective) or usage (consumed) in tokens. */
export interface Budget { tokens: number; durationMs: number; costMicros?: number | null; stages?: Partial<Record<BudgetStage, number>> }

export interface SessionArgs {
  stepId: string; attempt: number; kind: StepKind; phase: Phase; model: ModelRef; prompt: string; submitTools: AuditTool[];
  requiredSubmits: string[]; maxTurns: number; signal: AbortSignal; sceneDetail?: string; cognitiveSlice?: string;
  knowledgeNeeds?: KnowledgeNeed[]; extraTools?: AuditTool[]; withIndex?: boolean; askUser?: boolean;
  /** Pure-judgement sessions (e.g. semantic merge) get only their submit tools: no code exploration. */
  submitOnly?: boolean;
  onSteerHandle?: (steer: (text: string) => Promise<void>) => void;
  /** A `task` sub-agent: waits at most `waitMs` for a session slot. */
  task?: { goal: string; files?: string[]; waitMs: number };
  /**
   * Once the step (sub-agents included) has used this many tokens, the session is told to wrap up and
   * submit. A soft limit: the budget and stage quotas still apply as before.
   */
  tokenCap?: number;
  /** see SessionSpec.completionCheck — what the session still owes once its required results are in. */
  completionCheck?: () => string | null;
  /** Audited content placed after the prompt, scanned and wrapped in the session's data boundary. */
  untrustedPrompt?: { source: string; text: string }[];
  /**
   * items pushed into the prompt, by kind (e.g. `lead`, `candidate`, `hypothesis`); the session's telemetry
   * records how many of each the model referenced in a tool call. Skill bodies and connector operations are added here.
   */
  pushed?: { kind: string; ids: string[] }[];
  /** false = no threat-model summary in the system prompt (the session reads it on demand). */
  threatModel?: boolean;
  /** the vulnerability classes the session works on — the knowledge prefilter matches skills against these. */
  vulnClasses?: string[];
  /**
   * A coordinating session that does not read code itself — `read` and `grep` are left out
   * of its tools; its `task` sub-agents read (their reads count for the step).
   */
  noCodeRead?: boolean;
  /**
   * When one model request's context (input + cache tokens) reaches this, the session is
   * told to wrap up with `wrapUpMessage` — a coordinator then hands over to a fresh session instead of being compacted.
   */
  contextCap?: number;
  wrapUpMessage?: string;
  /**
   * the session takes no session slot — the lead mostly waits for the subtasks it dispatched, which need the
   * slots (with `concurrency.sessions` = 1 it would otherwise hold the only one and wait forever). Its model requests
   * still pass the global gate.
   */
  noSlot?: boolean;
  /**
   * The repository the session works on: tools default to it and the session runs in its directory.
   * Without it, the audit's first target repository.
   */
  repo?: string;
  /**
   * The session reads only `repo` — no other repository's code, no cross_repo_trace; peers through their
   * responsibility cards. A per-repository understanding session of a multi-repository audit (its sub-agents inherit it).
   */
  ownRepoOnly?: boolean;
  /**
   * The prompt sends the model to service_card (the cross-repository system session): the tool is there even
   * when the project counts as a monolith (no gateway). Own-repository sessions get it the same way.
   */
  serviceCards?: boolean;
}

interface SessionScope { id: string; role: 'main' | 'task'; parent?: string }
/** The agent session the current code runs in: events raised inside it carry its identity. */
const sessionScope = new AsyncLocalStorage<SessionScope>();

export class AuditRuntime {
  readonly views = new Map<string, SnapshotView>();
  /** Incremental audits: baseline snapshots by repository name. */
  readonly baseViews = new Map<string, SnapshotView>();
  private readonly baseRepos: RepoInfo[] = [];
  readonly indexes = new Map<string, StructIndex>();
  /**
   * Indexes built only for vulnerability identity when `tools.ast` is off: fingerprints need
   * the sink's function, which only the parser knows. Never shown to the agent, never used for
   * candidates or coverage.
   */
  readonly identityIndexes = new Map<string, StructIndex>();
  /** Index rules (set by the engine); needed to index other snapshots, e.g. for rename following. */
  rules?: RuleSet;
  /** Test-only file:// remote sources (EngineOptions.testAllowFileRemotes). */
  allowFileRemotes = false;
  /** Test-only: see EngineOptions.testGeneralistHunt. */
  testGeneralistHunt = false;
  readonly repos: RepoInfo[] = [];
  readonly auditArtifacts = new Set<string>();
  knowledge: FrozenKnowledge = { skills: [] };
  /** the audit's frozen prompt set (defaults without overrides). */
  get prompts(): PromptSet { return this.knowledge.prompts ? (this.promptSet ??= new PromptSet(this.knowledge.prompts)) : PromptSet.DEFAULT; }
  private promptSet?: PromptSet;
  /** Steps whose sessions read suspected injected instructions in the audited code. */
  readonly codeInjectionSteps = new Set<string>();
  /** Set by the engine: the connector pool used for `connector_query`. */
  connectorPool: ConnectorPool | null = null;
  /** Set by the engine: language servers for `definition` / `references` (`tools.lsp`). */
  lspPool: LspPool | null = null;
  /** Skills (and `name/file`) each step's sessions actually read or had injected: `knowledgeRefs` must be among them. */
  readonly knowledgeRead = new Map<string, Set<string>>();
  /** fact ids facts_query returned per step (the ones a finding may cite). */
  readonly factsSeen = new Map<string, Set<string>>();
  strategy!: AuditStrategy;
  private pendingReads = new Map<string, Range[]>();
  private reservedTokens = 0;
  private readonly reservedByStage = new Map<BudgetStage, number>();
  private readonly stageOfStep = new Map<string, BudgetStage | null>();
  /** Set by the engine when the user pauses: sessions stop at their next model request. */
  pausing = false;
  /**
   * Set by the engine: pause the audit (a content filter refused a step and no fallback exists; the
   * model service is down, or its balance / quota is used up). `cause` says who continues: a person, or the probe.
   */
  requestPause: ((reason: string, cause: PauseCause) => void) | null = null;
  /** Consecutive service failures across steps since the last model reply. Any model reply resets it. */
  serviceFailures = 0;
  /** The service breaker tripped: further service errors interrupt their step instead of failing it. */
  serviceDown = false;
  /** Set by the engine: checks the model service before a step fails on service errors. */
  servicePing: ServicePing | null = null;
  /** A service check in flight: steps failing at the same time wait for the same answer. */
  serviceChecking: Promise<boolean> | null = null;
  /** Main sessions started per step attempt (`stepId:attempt` → count): the transcript of the n-th is `a<attempt>-s<n>`. */
  private readonly sessionSeq = new Map<string, number>();
  /** Step → the attempt whose transcript its current session continues (for the `session.resumed` event). */
  private readonly resumedFrom = new Map<string, number>();
  /**
   * Session slots of this audit: every agent session holds one, `task` sub-agents included;
   * sub-agents go first when a slot frees up. Capacity follows the strategy (adjustable while running).
   */
  readonly slots = new PriorityGate(() => this.strategy?.concurrency.sessions ?? 1);
  /**
   * Steps running on their fallback model: step id → the model that replaces the stage's for every
   * session of the step (sub-agents included). Restored from `model.fallback` events when a run resumes.
   */
  readonly fallbacks = new Map<string, ModelRef>();
  /**
   * “切换模型重试 · 之后所有步骤”: a model a content filter refused (`provider/model`) → the model the user chose
   * for every later step that would run on it. Kept on the audit row (`model_switches`).
   */
  readonly modelSwitches = new Map<string, ModelRef>();
  /**
   * Cross lanes a content filter refused while another lane of the task goes on: they wait for a person for
   * the rest of this run and are skipped when it finishes. Not restored: a resumed run tries them again.
   */
  readonly filteredLanes = new Set<string>();
  /** Steer handles of sessions currently running for this audit (answers, interventions, pause). */
  steers: Set<(text: string) => Promise<void>> = new Set();

  constructor(readonly store: Store, readonly auditId: string, readonly executor: Executor, readonly hub: ModelHub) {}

  get audit(): AuditRow {
    return getAudit(this.store, this.auditId);
  }

  /** Load snapshots (and cached indexes) referenced by audit_repository. */
  load(): void {
    const a = this.audit;
    const strategy = upgradeStrategy(JSON.parse(a.strategy_frozen ?? a.strategy_draft));
    // The switched model is read from the step row, which the switch updated: the event is redacted, and a provider id
    // equal to a configured secret came back as `[REDACTED]` and failed the step as “not configured”.
    this.fallbacks.clear();
    const stepRows = new Map(this.store.all<{ id: string; provider: string | null; model: string | null }>('SELECT id, provider, model FROM step WHERE audit_id = ?', this.auditId).map((r) => [r.id, r]));
    for (const e of this.store.listEvents(this.auditId, 0, ['model.fallback'])) {
      const row = e.stepId ? stepRows.get(e.stepId) : undefined;
      if (!row?.provider || !row.model || e.payload.degraded || !e.payload.to) continue;
      const thinking = (e.payload.to as ModelRef).thinking;
      this.fallbacks.set(row.id, { provider: row.provider, model: row.model, ...(thinking ? { thinking } : {}) });
    }
    this.modelSwitches.clear();
    for (const [from, to] of Object.entries(JSON.parse(a.model_switches || '{}') as Record<string, ModelRef>)) this.modelSwitches.set(from, to);
    // A limit changed while the audit ran is kept in the trajectory; a resumed run picks it up again.
    this.strategy = { ...strategy, concurrency: { ...strategy.concurrency, sessions: sessionLimit(this.store, this.auditId, strategy.concurrency.sessions) } };
    if (a.knowledge_ref) this.knowledge = this.store.artifacts.getJson<FrozenKnowledge>(a.knowledge_ref);
    const rows = this.store.all<{ repository_id: string; name: string; snapshot_id: string | null; role_in_audit: string; root_hash: string | null; manifest_ref: string | null; base_snapshot_id: string | null; base_root: string | null; base_manifest: string | null }>(
      `SELECT ar.repository_id, r.name, ar.snapshot_id, ar.role_in_audit, s.root_hash, s.manifest_ref, ar.base_snapshot_id, b.root_hash AS base_root, b.manifest_ref AS base_manifest
       FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id LEFT JOIN snapshot s ON s.id = ar.snapshot_id
       LEFT JOIN snapshot b ON b.id = ar.base_snapshot_id WHERE ar.audit_id = ? ORDER BY r.name`, this.auditId);
    this.repos.length = 0;
    this.baseRepos.length = 0;
    for (const r of rows) {
      if (r.base_snapshot_id && r.base_root && r.base_manifest) {
        this.baseRepos.push({ id: r.repository_id, name: r.name, snapshotId: r.base_snapshot_id, rootHash: r.base_root, role: r.role_in_audit });
        if (!this.baseViews.has(r.name)) {
          this.baseViews.set(r.name, new SnapshotView(r.name, `${this.store.paths.snapshots}/${r.base_root}`, this.store.artifacts.getJson<SnapshotManifest>(r.base_manifest)));
        }
      }
      if (!r.snapshot_id || !r.manifest_ref || !r.root_hash) continue;
      this.repos.push({ id: r.repository_id, name: r.name, snapshotId: r.snapshot_id, rootHash: r.root_hash, role: r.role_in_audit });
      if (!this.views.has(r.name)) {
        const manifest = this.store.artifacts.getJson<SnapshotManifest>(r.manifest_ref);
        this.views.set(r.name, new SnapshotView(r.name, `${this.store.paths.snapshots}/${r.root_hash}`, manifest));
      }
    }
  }

  /** Repositories findings may land in (single: the target; multi: every auditable repository). */
  get targets(): RepoInfo[] {
    const t = this.repos.filter((r) => r.role === 'target');
    return t.length ? t : this.repos.slice(0, 1);
  }

  get targetRepo(): RepoInfo {
    const t = this.repos.find((r) => r.role === 'target') ?? this.repos[0];
    if (!t) throw new Error('audit has no snapshot');
    return t;
  }

  /** Index for identity (fingerprints, rename following): the audit's index, or the identity-only one. */
  identityIndex(repoName: string): StructIndex | undefined {
    return this.indexes.get(repoName) ?? this.identityIndexes.get(repoName);
  }

  /** Baseline snapshot of a target repository (incremental audits; default the first target). */
  baseRepo(repoId = this.targetRepo.id): RepoInfo | undefined {
    return this.baseRepos.find((r) => r.id === repoId);
  }

  /**
   * Impact sets computed by this audit's scope steps (incremental audits), by target repository name: one per target.
   * A scope step without `input.repo` (older audits) is the first target's.
   */
  impacts(): Map<string, ImpactSet> {
    const out = new Map<string, ImpactSet>();
    for (const row of this.store.all<{ output_ref: string; input: string }>(`SELECT output_ref, input FROM step WHERE audit_id = ? AND kind = 'scope' AND status = 'succeeded' ORDER BY seq`, this.auditId)) {
      out.set(fromJson<{ repo?: string }>(row.input, {}).repo ?? this.targetRepo.name, this.store.artifacts.getJson<ImpactSet>(row.output_ref));
    }
    return out;
  }

  /** Impact set of one target repository (default the first target), or null. */
  impact(repoName = this.targetRepo.name): ImpactSet | null {
    return this.impacts().get(repoName) ?? null;
  }

  repoByName(name: string | undefined): RepoInfo | undefined {
    return name ? this.repos.find((r) => r.name === name) : this.targetRepo;
  }

  toolContext(signal?: AbortSignal, stepId?: string, scope?: { repo?: string; only?: boolean }): ToolContext {
    const repo = scope?.repo && this.views.has(scope.repo) ? scope.repo : this.targetRepo.name;
    return {
      views: scope?.only ? new Map([[repo, this.views.get(repo)!]]) : this.views, defaultRepo: repo, executor: this.executor, artifacts: this.store.artifacts,
      auditArtifacts: this.auditArtifacts, ...(signal ? { signal } : {}),
      onRead: (e) => {
        const key = `${e.repo}\u0000${e.path}`;
        (this.pendingReads.get(key) ?? this.pendingReads.set(key, []).get(key)!).push([e.startLine, e.endLine]);
        this.event('file.read', { repo: e.repo, path: e.path, startLine: e.startLine, endLine: e.endLine }, stepId ?? null);
      },
    };
  }

  /** Read ranges (merged) for a repo/path including those not yet flushed. */
  readRanges(repo: string, path: string): Range[] {
    const repoId = this.repos.find((r) => r.name === repo)?.id;
    const row = repoId ? this.store.get<{ ranges: string }>('SELECT ranges FROM read_coverage WHERE audit_id = ? AND repository_id = ? AND path = ?', this.auditId, repoId, path) : undefined;
    return mergeRanges([...fromJson<Range[]>(row?.ranges, []), ...(this.pendingReads.get(`${repo}\u0000${path}`) ?? [])]);
  }

  /** Flush read ranges into read_coverage (reads count even for failed attempts — they happened). */
  flushReads(stepId: string | null): void {
    if (this.pendingReads.size === 0) return;
    const pending = this.pendingReads;
    this.pendingReads = new Map();
    this.store.tx(() => {
      for (const [key, ranges] of pending) {
        const [repoName, path] = key.split('\u0000') as [string, string];
        const repo = this.repos.find((r) => r.name === repoName);
        if (!repo) continue;
        const existing = this.store.get<{ ranges: string }>('SELECT ranges FROM read_coverage WHERE audit_id = ? AND repository_id = ? AND path = ?', this.auditId, repo.id, path);
        const merged = mergeRanges([...fromJson<Range[]>(existing?.ranges, []), ...ranges]);
        const linesRead = merged.reduce((n, [a, b]) => n + b - a + 1, 0);
        const fileLines = this.views.get(repoName)?.file(path)?.lines ?? 0;
        this.store.db.run(
          `INSERT INTO read_coverage(audit_id, repository_id, path, ranges, lines_read, file_lines, last_step_id) VALUES (?,?,?,?,?,?,?)
           ON CONFLICT(audit_id, repository_id, path) DO UPDATE SET ranges = excluded.ranges, lines_read = excluded.lines_read, last_step_id = excluded.last_step_id`,
          this.auditId, repo.id, path, JSON.stringify(merged), linesRead, fileLines, stepId,
        );
      }
    });
  }

  /** The model a session of this step uses: the step's fallback once it switched, else the requested one. */
  modelFor(stepId: string, requested: ModelRef): ModelRef {
    return this.fallbacks.get(stepId) ?? requested;
  }

  /**
   * The fallback for a step that failed on its model: the stage's fallback, else the global one.
   * In cross review a fallback that is one of the other cross models would make two “independent” opinions the same
   * model: the step is reported as degraded instead.
   */
  /** The model a step runs on: the one recorded on the step, else its stage's model (null for steps without a model). */
  stepModel(step: Pick<StepRow, 'kind' | 'lineage_id' | 'model' | 'provider'>): ModelRef | null {
    if (step.model && step.provider) return { provider: step.provider, model: step.model };
    const stage = stepStage(step.kind, step.lineage_id);
    return stage ? stageModel(this.strategy, stage) : null;
  }

  fallbackFor(step: Pick<StepRow, 'kind' | 'lineage_id' | 'model' | 'provider' | 'input'>): { to: ModelRef; degraded: boolean } | null {
    const stage = stepStage(step.kind, step.lineage_id);
    if (!stage) return null;
    const current = this.stepModel(step);
    if (!current) return null;
    const to = stageFallback(this.strategy, stage, this.store.config.fallbackModel, current);
    if (!to) return null;
    // A cross lane whose fallback is itself one of the cross models is degraded rather than replaced. Other
    // steps of a crossed stage (lead, gap, recheck) give a single opinion and switch.
    return { to, degraded: this.duplicatesCrossModel(step, to) };
  }

  /**
   * The model a step switches to before it starts because the user chose “之后所有步骤” for the model it would run on;
   * null when there is no switch, or when the step is a cross lane and the chosen model is another cross model.
   */
  laterSwitch(step: Pick<StepRow, 'kind' | 'lineage_id' | 'model' | 'provider' | 'input'>): { from: string; to: ModelRef } | null {
    const current = this.stepModel(step);
    if (!current) return null;
    const from = `${current.provider}/${current.model}`;
    let to = this.modelSwitches.get(from);
    // A switch whose target was itself switched later follows the chain (bounded: each model is a key once).
    for (let i = 0; to && i < this.modelSwitches.size; i++) to = this.modelSwitches.get(`${to.provider}/${to.model}`) ?? to;
    if (!to || (to.provider === current.provider && to.model === current.model)) return null;
    return this.duplicatesCrossModel(step, to) ? null : { from, to };
  }

  /** A cross lane of a crossed stage that would run on one of the other cross models. */
  private duplicatesCrossModel(step: Pick<StepRow, 'kind' | 'lineage_id' | 'input'>, to: ModelRef): boolean {
    const stage = stepStage(step.kind, step.lineage_id);
    if (!stage || !isCrossLane(step)) return false;
    const crossed = stage === 'hunt' ? crossModels(this.strategy, 'hunt')
      : stage === 'logic' ? crossModels(this.strategy, 'threat') ?? crossModels(this.strategy, 'verify')
        : stage === 'challenge' ? crossModels(this.strategy, 'review') : null;
    return !!crossed && crossed.some((m) => m.provider === to.provider && m.model === to.model);
  }

  /** Events raised inside an agent session carry its identity, so sub-agents can be told apart from their parent. */
  event(type: EventType, payload: Record<string, unknown>, stepId: string | null = null): void {
    const s = sessionScope.getStore();
    this.store.appendEvent(this.auditId, type, s && payload.session === undefined ? { ...payload, session: { id: s.id, role: s.role, ...(s.parent ? { parent: s.parent } : {}) } } : payload, stepId);
  }

  // ---- budget ---------------------------------------------------

  budget(): { effective: Budget; consumed: Budget } {
    const a = this.audit;
    return { effective: JSON.parse(a.budget_effective) as Budget, consumed: JSON.parse(a.budget_consumed) as Budget };
  }

  remainingTokens(): number {
    const { effective, consumed } = this.budget();
    return effective.tokens - consumed.tokens - this.reservedTokens;
  }

  /** The budget stage a step charges; null for steps outside every stage. */
  stageOf(stepId: string): BudgetStage | null {
    if (!this.stageOfStep.has(stepId)) {
      const row = this.store.get<{ kind: string; lineage_id: string | null }>('SELECT kind, lineage_id FROM step WHERE id = ?', stepId);
      this.stageOfStep.set(stepId, row ? budgetStage(row.kind, row.lineage_id) : null);
    }
    return this.stageOfStep.get(stepId)!;
  }

  /** What is left of a stage quota after usage and reservations; Infinity when the audit has no quota for it. */
  stageRemaining(stage: BudgetStage | null): number {
    if (!stage) return Infinity;
    const { effective, consumed } = this.budget();
    const limit = effective.stages?.[stage];
    if (limit === undefined) return Infinity;
    return limit - (consumed.stages?.[stage] ?? 0) - (this.reservedByStage.get(stage) ?? 0);
  }

  /** Whether a stage has used or reserved anything yet: its first step may start on any quota. */
  stageStarted(stage: BudgetStage | null): boolean {
    if (!stage) return false;
    return (this.budget().consumed.stages?.[stage] ?? 0) > 0 || (this.reservedByStage.get(stage) ?? 0) > 0;
  }

  reserve(stepId: string, tokens: number): void {
    this.reservedTokens += tokens;
    const stage = this.stageOf(stepId);
    if (stage) this.reservedByStage.set(stage, (this.reservedByStage.get(stage) ?? 0) + tokens);
    this.event('budget.reserved', { tokens, remaining: this.remainingTokens(), ...(stage ? { stage, stage_remaining: this.stageRemaining(stage) } : {}) }, stepId);
  }

  release(tokens: number, stepId?: string): void {
    this.reservedTokens = Math.max(0, this.reservedTokens - tokens);
    const stage = stepId ? this.stageOf(stepId) : null;
    if (stage) this.reservedByStage.set(stage, Math.max(0, (this.reservedByStage.get(stage) ?? 0) - tokens));
  }

  /** Charge actual usage (failed attempts included) and decide continue / wrap-up / abort. */
  charge(stepId: string, attempt: number, model: ModelRef, u: UsageDelta): BudgetVerdict {
    if (u.total > 0) this.serviceFailures = 0;
    const tolerance = this.store.config.engine.budgetTolerance;
    const pricing = this.store.config.pricing[`${model.provider}/${model.model}`];
    const cost = costMicros(pricing, u);
    let verdict: BudgetVerdict = 'continue';
    this.store.tx(() => {
      const { effective, consumed } = this.budget();
      // Once any usage has an unknown price the total cost is "unknown" (null) for good.
      const priorUnknown = consumed.costMicros === null && consumed.tokens > 0;
      const stage = this.stageOf(stepId);
      const next: Budget = {
        tokens: consumed.tokens + u.total,
        durationMs: consumed.durationMs ?? 0,
        costMicros: cost === null || priorUnknown ? null : (consumed.costMicros ?? 0) + cost,
        // usage per stage, kept for every stage so a later top-up or report can show it.
        ...(stage || consumed.stages ? { stages: { ...consumed.stages, ...(stage ? { [stage]: (consumed.stages?.[stage] ?? 0) + u.total } : {}) } } : {}),
      };
      this.store.update('audit', { id: this.auditId }, { budget_consumed: next });
      this.store.db.run(
        'UPDATE step SET tokens_in = tokens_in + ?, tokens_out = tokens_out + ?, tokens_cached = tokens_cached + ?, cost_micros = CASE WHEN ? IS NULL THEN cost_micros ELSE COALESCE(cost_micros, 0) + ? END WHERE id = ?',
        u.input, u.output, u.cacheRead, cost, cost ?? 0, stepId,
      );
      this.store.db.run(
        'UPDATE step_attempt SET tokens_in = tokens_in + ?, tokens_out = tokens_out + ?, tokens_cached = tokens_cached + ? WHERE step_id = ? AND attempt = ?',
        u.input, u.output, u.cacheRead, stepId, attempt,
      );
      this.event('budget.charged', { tokens: u.total, cost_micros: cost, consumed: next.tokens, effective: effective.tokens }, stepId);
      if (next.tokens > effective.tokens * (1 + tolerance)) verdict = 'abort';
      else if (next.tokens > effective.tokens) verdict = 'wrap_up';
      // a used-up stage quota neither wraps up nor aborts mid-turn — the session stops before its
      // next model request (`beforeRequest`) and a later attempt continues its transcript. The total still wraps up /
      // aborts. There is no cost cap any more; cost is only recorded.
    });
    return verdict;
  }

  /** Whether a stage has used its whole quota; a stage without a quota never is. */
  stageExhausted(stage: BudgetStage | null): boolean {
    if (!stage) return false;
    const { effective, consumed } = this.budget();
    const limit = effective.stages?.[stage];
    return limit !== undefined && (consumed.stages?.[stage] ?? 0) >= limit;
  }

  /**
   * Before every model request of a step's session: a pause, or a stage quota used up, stops
   * the session here — between turns, with its transcript complete on disk — so a later attempt continues it.
   */
  beforeRequest(stepId: string): 'continue' | 'pause' | 'budget' {
    if (this.pausing) {
      this.event('session.paused', { reason: 'pause' }, stepId);
      return 'pause';
    }
    const stage = this.stageOf(stepId);
    if (!this.stageExhausted(stage)) return 'continue';
    const { effective, consumed } = this.budget();
    this.event('session.paused', { reason: 'budget', stage, consumed: consumed.stages?.[stage!] ?? 0, limit: effective.stages?.[stage!] }, stepId);
    return 'budget';
  }

  // ---- knowledge & sessions ----------------------------------------------------

  /** Index options for a repository of this audit: a user-set “auditable” repository indexes all its audit languages. */
  indexLanguages(repoName: string, view: SnapshotView | undefined = this.views.get(repoName)): { languages?: AuditLanguage[] } {
    const id = this.repos.find((r) => r.name === repoName)?.id ?? this.baseRepos.find((r) => r.name === repoName)?.id;
    const languages = view ? indexLanguagesFor(this.store, id, view) : undefined;
    return languages ? { languages } : {};
  }

  taskFacts(phase: Phase): TaskFacts {
    const target = this.targetRepo;
    const stats = this.views.get(target.name)?.manifest.stats.byLang ?? {};
    const idx = this.indexes.get(target.name);
    const frameworks = [...new Set(idx?.entrypoints.map((e) => e.framework) ?? [])];
    const vulnClasses = [...new Set([...(idx?.sinks.map((s) => s.category) ?? []), ...this.strategy.focus.categories, 'authz_object', 'authz_function'])];
    return {
      scene: this.audit.scene as TaskFacts['scene'], phase,
      languages: Object.keys(stats).filter(isAuditLanguage), frameworks, vulnClasses, repoRoles: [],
      include: this.strategy.knowledge.include, exclude: this.strategy.knowledge.exclude,
    };
  }

  /**
   * Run one agent session for a step attempt with trajectory, knowledge usage, budget charging and
   * injection reporting wired in.
   */
  /**
   * Run an agent session in one of this audit's session slots. A `task` sub-agent waits at most
   * `task.waitMs` for a slot and otherwise fails as a tool error, so a parent holding a slot never deadlocks on it.
   * Model requests of the session then pass the global gate; waits for either are recorded.
   */
  async session(args: SessionArgs): Promise<SessionOutcome> {
    args = { ...args, model: this.modelFor(args.stepId, args.model) };
    const parent = sessionScope.getStore();
    const scope: SessionScope = args.task
      ? { id: newId('session'), role: 'task', ...(parent ? { parent: parent.id } : {}) }
      : { id: newId('session'), role: 'main' };
    return sessionScope.run(scope, async () => {
      const t0 = Date.now();
      const waitSignal = args.task ? AbortSignal.any([args.signal, AbortSignal.timeout(args.task.waitMs)]) : args.signal;
      let slot: { release: () => void; waited: boolean };
      // A sub-agent that gives up waiting never emits task.started; its goal rides on the wait events.
      const goal = args.task ? { goal: args.task.goal.slice(0, 500) } : {};
      try {
        slot = args.noSlot ? { release: () => {}, waited: false } : await this.slots.acquire({ high: !!args.task, signal: waitSignal, onQueued: () => this.event('session.queued', { wait: 'slot', ...goal }, args.stepId) });
      } catch (e) {
        if (args.signal.aborted || !args.task) throw e;
        this.event('session.dequeued', { wait: 'slot', ms: Date.now() - t0, gaveUp: true, ...goal }, args.stepId);
        throw new Error(P('feedback.task.no_slot', { seconds: Math.round(args.task.waitMs / 1000), sessions: this.strategy.concurrency.sessions }), { cause: e });
      }
      if (slot.waited) this.event('session.dequeued', { wait: 'slot', ms: Date.now() - t0 }, args.stepId);
      if (args.task) this.event('task.started', { goal: args.task.goal.slice(0, 500), ...(args.task.files?.length ? { files: args.task.files.slice(0, 10) } : {}) }, args.stepId);
      try {
        const outcome = await modelCallContext.run({
          priority: 'background',
          onQueued: () => this.event('session.queued', { wait: 'model' }, args.stepId),
          onDequeued: (ms) => this.event('session.dequeued', { wait: 'model', ms }, args.stepId),
        }, () => this.runSession(args));
        if (args.task) this.event('task.finished', { status: outcome.status, turns: outcome.turns, input: outcome.usage.input, output: outcome.usage.output, ms: Date.now() - t0 }, args.stepId);
        return outcome;
      } catch (e) {
        if (args.task) this.event('task.finished', { status: 'failed', error: (e as Error).message.slice(0, 300), ms: Date.now() - t0 }, args.stepId);
        throw e;
      } finally {
        slot.release();
      }
    });
  }

  private async runSession(args: SessionArgs): Promise<SessionOutcome> {
    // main sessions are saved to a transcript; one the previous attempt left between turns (pause,
    // stage quota) or cut off (shutdown, crash) continues with its own data-boundary nonce.
    const main = sessionScope.getStore()?.role !== 'task';
    const seqKey = `${args.stepId}:${args.attempt}`;
    const seq = main ? (this.sessionSeq.get(seqKey) ?? 0) : 0;
    if (main) this.sessionSeq.set(seqKey, seq + 1);
    const dir = main ? transcriptDir(this.store, this.auditId, args.stepId, args.attempt, seq) : null;
    const resumeFrom = main ? resumableTranscript(this.store, this.auditId, args.stepId, args.attempt - 1, seq) : null;
    const nonce = (resumeFrom ? readTranscriptMeta(resumeFrom)?.nonce : undefined) ?? newNonce();
    if (resumeFrom) this.restoreStepMemory(args.stepId);
    const facts = this.taskFacts(args.phase);
    const sk = sessionKnowledge(this.knowledge, args.vulnClasses?.length ? { ...facts, vulnClasses: args.vulnClasses } : facts, this.store.artifacts, args.knowledgeNeeds ?? []);
    const reads = this.knowledgeRead.get(args.stepId) ?? new Set<string>();
    this.knowledgeRead.set(args.stepId, reads);
    for (const b of sk.bodies) reads.add(b.name);
    this.store.tx(() => {
      for (const u of sk.usage) this.recordSkill(args.stepId, u.name, u.layer, u.sha256, u.level, u.trigger, u.reason, u.tokens);
      this.event('knowledge.loaded', { level: 'index', items: sk.readable.size, bodies: sk.bodies.map((b) => b.name) }, args.stepId);
    });
    const onInjection = (src: { repo: string; path: string }, signals: InjectionSignal[]) => {
      // Instructions found in the audited code hold this session's connector calls for approval.
      if (!src.repo.startsWith('connector:')) this.codeInjectionSteps.add(args.stepId);
      for (const s of signals) this.event('injection_suspected', { repo: src.repo, path: src.path, line: s.line, signal: s.signal, excerpt: s.excerpt }, args.stepId);
    };
    // Tools returning audited content (`untrusted`) are scanned and wrapped like read output.
    const guarded = (t: AuditTool): AuditTool => (t.untrusted ? {
      ...t,
      run: async (a, signal) => {
        const r = await t.run(a, signal);
        const signals = detectInjection(r.text);
        if (signals.length) onInjection({ repo: this.targetRepo.name, path: `${t.untrusted}${typeof a?.path === 'string' ? `:${a.path}` : ''}` }, signals);
        return { ...r, text: wrapUntrusted(nonce, 'tool_output', t.untrusted!, r.text) };
      },
    } : t);
    // The prompt's audited content (e.g. diffs of an incremental batch) goes after it, inside the boundary.
    const untrustedText = (args.untrustedPrompt ?? []).map((u) => {
      const signals = detectInjection(u.text);
      if (signals.length) onInjection({ repo: this.targetRepo.name, path: u.source }, signals);
      return wrapUntrusted(nonce, 'tool_output', u.source, u.text);
    });
    const prompt = untrustedText.length ? `${args.prompt}\n\n${untrustedText.join('\n')}` : args.prompt;
    const access = args.submitOnly ? null : this.connectorAccess(args.stepId);
    const factAccess = args.submitOnly ? null : this.factsAccess(args.stepId, nonce, args.model);
    const repo = args.repo && this.views.has(args.repo) ? args.repo : this.targetRepo.name;
    const only = !!args.ownRepoOnly && this.repos.length > 1;
    // An own-repository session gets the peers' responsibility cards instead of their code.
    const cards = only || (!!args.serviceCards && this.repos.length > 1);
    const serviceAccess = args.submitOnly || (!SERVICE_CARD_KINDS.has(args.kind) && !cards) ? null : this.serviceAccess(args.stepId, nonce, args.model, repo, cards);
    const otherRepo = (r: string | undefined) => {
      if (only && r && r !== repo) throw new Error(P('feedback.own_repo_only', { repo }));
    };
    const indexes = only ? new Map([...this.indexes].filter(([k]) => k === repo)) : this.indexes;
    // In a multi-repository audit a code reference without a repository is in the session's
    // repository when the file is there, else in the one repository that has that path — not the audit's first target
    // (findings of php-invoice sessions were refused as missing from cs-depot).
    const sessionRepo = args.repo && this.views.has(args.repo) ? args.repo : undefined;
    const has = (r: string, path: string) => { try { this.views.get(r)!.guard(path); return true; } catch { return false; } };
    const refRepo = (path: string) => {
      if (sessionRepo && has(sessionRepo, path)) return sessionRepo;
      const hits = this.repos.filter((r) => this.views.has(r.name) && has(r.name, path));
      return hits.length === 1 ? hits[0]!.name : sessionRepo;
    };
    // A cited range running a little past the end of the file (`config/app.php:1-10` for 6 lines) ends at its last line.
    const lastLine = (repoName: string | undefined, path: string) => {
      const view = this.views.get(repoName ?? this.targetRepo.name);
      try { return view?.file(view.guard(path))?.lines; } catch { return undefined; }
    };
    const submitTools = args.submitTools.map((t) => ({
      ...t,
      normalize: (a: unknown) => {
        const own = t.normalize ? t.normalize(a) : a;
        return clampRefEnds(this.repos.length > 1 ? withRefRepo(own, refRepo) : own, lastLine);
      },
    }));
    const tools = args.submitOnly ? [...submitTools] : [
      ...buildAuditTools({
        ctx: this.toolContext(args.signal, args.stepId, { repo, only }), nonce,
        ...(args.withIndex !== false && this.strategy.tools.ast ? { indexes: indexes as IndexMap } : {}),
        // knowledge read per session ≤ 25% of the model's context window.
        knowledge: { frozen: this.knowledge, readable: sk.readable, artifacts: this.store.artifacts, tokenCap: this.knowledgeCap(args.model) },
        askUser: args.askUser ?? false,
        ...(this.repos.length > 1 && !only ? { crossRepo: () => this.crossRepoData() } : {}),
        ...(access ? { connectors: access } : {}),
        ...(this.strategy.tools.lsp ? { lsp: {
          definition: (r, p, l, sym, sig) => { otherRepo(r); return this.lspQuery('definition', r ?? repo, p, l, sym, sig ?? args.signal, args.stepId); },
          references: (r, p, l, sym, sig) => { otherRepo(r); return this.lspQuery('references', r ?? repo, p, l, sym, sig ?? args.signal, args.stepId); },
        } } : {}),
        ...(this.strategy.tools.gitHistory ? { gitLog: (r: string | undefined, a: { path?: string; n?: number; grep?: string }, signal?: AbortSignal) => { otherRepo(r); return this.gitLog(r ?? repo, a, signal); } } : {}),
        hooks: {
          onCrossRepo: (r) => this.event('cross_repo.traced', { repo: r.repo, peers: r.peers, unresolved: r.unresolved, missing: r.missing.slice(0, 10) }, args.stepId),
          onInjection,
          onSkillRead: (r) => {
            reads.add(r.name);
            reads.add(`${r.name}/${r.file}`);
            this.recordSkill(args.stepId, r.name, r.layer, r.sha256, r.file.endsWith('SKILL.md') || r.file === `${r.name}.md` ? 'body' : 'file', 'on_demand', `model_request: ${r.reason}`, r.tokens);
            this.event('knowledge.loaded', { skill: r.name, layer: r.layer, file: r.file, reason: r.reason, tokens: r.tokens }, args.stepId);
          },
          onQuestion: (q) => {
            const id = newId('question');
            this.store.tx(() => {
              this.store.insert('question', { id, audit_id: this.auditId, step_id: args.stepId, text: q.question, blocking: q.blocking ? 1 : 0, status: 'open', options: answerOptions(q.options) });
              this.event('question.asked', { question_id: id, text: q.question.slice(0, 500), blocking: q.blocking }, args.stepId);
            });
            return id;
          },
        },
      }),
      ...(args.extraTools ?? []).map(guarded),
      ...(factAccess ? [factAccess.tool] : []),
      ...(serviceAccess?.tool ? [serviceAccess.tool] : []),
      ...submitTools,
    ].filter((t) => !args.noCodeRead || !CODE_READ_TOOLS.has(t.name));
    const threatModel = args.threatModel !== false && THREAT_MODEL_KINDS.has(args.kind) ? this.threatModel() : null;
    const sceneDetail = [args.sceneDetail, this.repoRoster(only ? repo : undefined)].filter(Boolean).join('\n');
    const sections = systemPromptSections({
      step: args.kind, scene: this.audit.scene as TaskFacts['scene'], nonce, ...(sceneDetail ? { sceneDetail } : {}),
      mandatoryKnowledge: sk.bodies.map((b) => {
        const unverified = this.knowledge.skills.find((f) => f.name === b.name)?.verified === false;
        return { name: b.name, text: unverified ? `${unverifiedKnowledgeNote()}\n${wrapUntrusted(nonce, 'knowledge', `skill:${b.name}`, b.text.replace(/^---[\s\S]*?---\n/, ''))}` : b.text };
      }),
      ...(threatModel ? { threatModel } : {}),
      ...(args.cognitiveSlice ? { cognitiveSlice: args.cognitiveSlice } : {}),
      // a submit-only session has no load_skill tool, so it gets no index telling it to use one.
      ...(args.submitOnly ? {} : { skillIndex: sk.indexText }),
      ...(access || factAccess || serviceAccess ? { extra: [serviceAccess?.note, factAccess?.note, access ? connectorPrompt(access.operations, nonce) : null].filter(Boolean).join('\n\n') } : {}),
    });
    const systemPrompt = sections.map((x) => x.text).join('\n\n');
    // what was pushed into this session, for the stage telemetry recorded with `session.ended`.
    const pushed = [
      ...(args.pushed ?? []),
      ...(sk.bodies.length ? [{ kind: 'skill_body', ids: sk.bodies.map((b) => b.name) }] : []),
      ...(access?.operations.length ? [{ kind: 'connector_op', ids: [...new Set(access.operations.map((o) => o.tool))] }] : []),
    ].filter((x) => x.ids.length);
    const promptInfo = {
      system: Object.fromEntries(sections.map((x) => [x.name, x.text.length])),
      task: args.prompt.length,
      ...(untrustedText.length ? { untrusted: untrustedText.reduce((n, t) => n + t.length, 0) } : {}),
      tools: tools.length,
      tool_schema: tools.reduce((n, t) => n + t.description.length + JSON.stringify(t.parameters).length, 0),
    };
    // the outbound record of this session (files the prompt and the tools carried, facts, tokens).
    const egressScopeArgs: EgressScope = {
      kind: 'audit', auditId: this.auditId, stepId: args.stepId, projectId: this.audit.project_id,
      promptFiles: filesOfIds((args.pushed ?? []).flatMap((x) => x.ids)), sink: egressSink(this.store, () => ({ withheldFacts: factAccess?.withheld ?? 0 })),
    };
    const handle = withEgressScope(egressScopeArgs, () => startSession({
      hub: this.hub, model: args.model, cwd: this.views.get(repo)!.root, agentDir: this.store.paths.agent,
      systemPrompt, prompt, tools, requiredSubmits: args.requiredSubmits, maxTurns: args.maxTurns, signal: args.signal,
      onEvent: (e) => this.sessionEvent(args.stepId, e, e.type === 'session.ended' ? { kind: args.kind, prompt: promptInfo, pushed } : undefined),
      ...(pushed.length ? { trackIds: pushed.flatMap((x) => x.ids) } : {}),
      ...(args.wrapUpMessage ? { wrapUpMessage: args.wrapUpMessage } : {}),
      onUsage: (u) => {
        const verdict = this.charge(args.stepId, args.attempt, args.model, u);
        if (verdict === 'continue' && args.contextCap !== undefined && u.input + u.cacheRead + u.cacheWrite >= args.contextCap) return 'wrap_up';
        if (verdict !== 'continue' || args.tokenCap === undefined) return verdict;
        const used = this.store.get<{ n: number }>('SELECT tokens_in + tokens_out + tokens_cached AS n FROM step WHERE id = ?', args.stepId)?.n ?? 0;
        return used >= args.tokenCap ? 'wrap_up' : verdict;
      },
      beforeRequest: async () => this.beforeRequest(args.stepId),
      ...(args.completionCheck ? { completionCheck: args.completionCheck } : {}),
      ...(dir ? { transcript: { dir, ...(resumeFrom ? { resumeFrom } : {}), meta: { nonce } } } : {}),
    }));
    if (resumeFrom) this.resumedFrom.set(args.stepId, Number(/[/\\]a(\d+)-s\d+[/\\][^/\\]+$/.exec(resumeFrom)?.[1] ?? args.attempt - 1));
    const steer = (t: string) => handle.steer(t);
    args.onSteerHandle?.(steer);
    this.steers.add(steer);
    let keep = false;
    try {
      const outcome = await handle.outcome;
      // A session stopped between turns, cut off, or hit by a transient provider error can continue; anything
      // else starts afresh next time.
      keep = outcome.status === 'aborted' || outcome.status === 'budget_stopped'
        || (outcome.status === 'error' && TRANSIENT_SESSION_ERRORS.includes(outcome.errorClass ?? ''));
      return outcome;
    } catch (e) {
      keep = true; // the session could not even run (signal, setup): what it had stays continuable
      throw e;
    } finally {
      this.steers.delete(steer);
      this.flushReads(args.stepId);
      // The earlier transcript was copied into this one. Remove it once this session kept its own copy, finished, or
      // failed in a way that starts afresh — not when this attempt failed before writing anything.
      if (resumeFrom && ((keep && dir && findTranscript(dir)) || !keep)) rmSync(dirname(resumeFrom), { recursive: true, force: true });
      if (dir && !keep) {
        rmSync(dir, { recursive: true, force: true });
        try { rmdirSync(dirname(dir)); } catch { /* other sessions of the step are still there */ }
      }
    }
  }

  /**
   * What the engine kept in memory for a step's sessions, rebuilt from the store when a session continues after a
   * restart: the skills it read (for `knowledgeRefs`) and whether it read suspected injected instructions.
   */
  private restoreStepMemory(stepId: string): void {
    const reads = this.knowledgeRead.get(stepId) ?? new Set<string>();
    this.knowledgeRead.set(stepId, reads);
    for (const r of this.store.all<{ skill_name: string }>('SELECT DISTINCT skill_name FROM skill_usage WHERE step_id = ?', stepId)) reads.add(r.skill_name);
    const injected = this.store.all<{ payload: string }>(`SELECT payload FROM event WHERE audit_id = ? AND step_id = ? AND type = 'injection_suspected'`, this.auditId, stepId);
    if (injected.some((e) => !String((JSON.parse(e.payload) as { repo?: string }).repo ?? '').startsWith('connector:'))) this.codeInjectionSteps.add(stepId);
  }

  /** Multi-repository audits: which repositories exist and what findings may target. */
  repoRoster(ownRepo?: string): string | null {
    if (this.repos.length < 2) return null;
    const ROLE = { target: '审计目标', related: P('runtime.repo_roster.related'), context: P('runtime.repo_roster.context') } as Record<string, string>;
    return [
      P('runtime.repo_roster.intro', { n: this.repos.length }),
      ...this.repos.map((r) => `- ${r.name}：${ROLE[r.role] ?? r.role}`),
      // An own-repository session does not trace across repositories (the system session does).
      ownRepo ? P('runtime.repo_roster.own_repo', { repo: ownRepo }) : P('runtime.repo_roster.rule'),
    ].join('\n');
  }

  private crossRepoCache: Promise<CrossRepoData> | null = null;

  /** Connection points and matches of this audit's snapshots, for cross_repo_trace (cached per runtime). */
  crossRepoData(): Promise<CrossRepoData> {
    this.crossRepoCache ??= (async () => {
      const connections: Connection[] = [];
      const limits: NonNullable<CrossRepoData['limits']> = [];
      const names: { repo: string; appNames: string[] }[] = [];
      for (const r of this.repos) {
        const view = this.views.get(r.name);
        if (!view) continue;
        const idx = this.indexes.get(r.name) ?? this.identityIndexes.get(r.name) ?? null;
        const signals = computeRepoSignals(view, idx, idx ? 'complete' : 'skipped');
        names.push({ repo: r.name, appNames: signals.appNames });
        const cached = this.store.get<{ connections_ref: string }>(
          'SELECT connections_ref FROM repo_analysis WHERE repository_id = ? AND root_hash = ? AND connections_ref IS NOT NULL ORDER BY created_at DESC LIMIT 1', r.id, r.rootHash);
        const hit = cached ? this.store.artifacts.getJson<{ v: number; connections: Connection[]; limit?: ConnectLimit }>(cached.connections_ref) : null;
        if (hit && hit.v === CONNECT_VERSION) {
          connections.push(...hit.connections);
          if (hit.limit) limits.push({ repo: r.name, ...hit.limit });
        } else {
          connections.push(...await extractConnections(view, idx, signals, { onLimit: (l) => limits.push({ repo: r.name, ...l }) }));
        }
      }
      const { matches } = matchConnections(connections, names, serviceMappings(this.store, this.audit.project_id));
      const a = this.audit;
      const topo = a.topology_ref ? this.store.artifacts.getJson<Topology>(a.topology_ref) : null;
      const nodeName = new Map((topo?.nodes ?? []).map((n) => [n.id, n.name]));
      const userEdges = (topo?.edges ?? []).filter((e) => e.origin === 'user').map((e) => ({ from: nodeName.get(e.from) ?? '?', to: nodeName.get(e.to) ?? '?', kind: e.kind, protocol: e.protocol }));
      return { connections, matches, indexes: this.indexes, userEdges, ...(limits.length ? { limits } : {}) };
    })();
    return this.crossRepoCache;
  }

  private threatModelCache: { ref: string; text: string } | null = null;

  /** This audit's profile (own or reused), rendered for the system prompt; null before/without one. */
  threatModel(): string | null {
    // One profile per target repository (multi-repository audits have several).
    const rows = this.store.all<{ output_ref: string }>(
      `SELECT output_ref FROM step WHERE audit_id = ? AND kind = 'profile' AND status IN ('succeeded','skipped') AND output_ref IS NOT NULL ORDER BY seq`, this.auditId);
    if (!rows.length) return null;
    const key = rows.map((r) => r.output_ref).join(',');
    if (this.threatModelCache?.ref !== key) {
      const all = rows.map((r) => this.store.artifacts.getJson<ProfileOutput | SystemModelOutput>(r.output_ref));
      const outs = all.filter((o): o is ProfileOutput => !isSystemModel(o));
      // The cross-repository system model, once, after the repositories' own profiles.
      const system = all.find(isSystemModel);
      const repoText = outs.length === 1
        ? renderThreatModel(outs[0]!.profile)
        : outs.map((o) => `### 仓库 ${this.repos.find((r) => r.id === o.repositoryId)?.name ?? o.repositoryId}\n${renderThreatModel(o.profile, Math.floor(6000 / outs.length))}`).join('\n\n');
      const text = system ? `${repoText}\n\n### 系统（跨仓库）\n${renderSystemModel(system.model)}` : repoText;
      this.threatModelCache = { ref: key, text };
    }
    return this.threatModelCache.text;
  }

  /**
   * Read-only connector operations authorized for this task: the strategy's connectors that
   * are enabled and tested with the current configuration, and the tools left on (read and write). Unavailable connectors are simply absent.
   */
  private connectorAccess(stepId: string): ConnectorAccess | null {
    if (!this.connectorPool || !this.strategy.connectors?.length) return null;
    return buildConnectorAccess({
      store: this.store, pool: this.connectorPool, refs: this.strategy.connectors, auditId: this.auditId, stepId, artifacts: this.auditArtifacts,
      onQueried: (payload) => this.event('connector.queried', payload, stepId),
      onWriteRequested: (payload) => this.event('connector.write_requested', payload, stepId),
      codeInjectionSeen: () => this.codeInjectionSteps.has(stepId),
    });
  }

  /**
   * definition / references through the language server of the snapshot; on any failure the tree-sitter index
   * answers instead (`source: ts`) and the fallback is recorded (the gate reports INDEX_DEGRADED).
   */
  private async lspQuery(kind: 'definition' | 'references', repoName: string | undefined, path: string, line: number, symbol: string | undefined, signal: AbortSignal | undefined, stepId: string) {
    const repo = repoName ? this.repoByName(repoName) : this.targetRepo;
    if (!repo) throw new Error(`unknown repository ${repoName}`);
    const view = this.views.get(repo.name)!;
    const rel = view.guard(path);
    const language = languageOf(rel);
    let reason: string;
    if (this.lspPool && language) {
      try {
        const s = await this.lspPool.session(view, language, signal);
        const locations = kind === 'definition' ? await s.definition(rel, line, symbol) : await s.references(rel, line, symbol);
        return { source: 'lsp' as const, locations };
      } catch (e) {
        reason = (e as Error).message.slice(0, 300);
      }
    } else {
      reason = language ? 'language servers are not available in this process' : 'no language server for this file type';
    }
    this.event('judgement.made', { kind: 'lsp_fallback', query: kind, repo: repo.name, path: rel, reason }, stepId);
    const idx = this.indexes.get(repo.name) ?? this.identityIndexes.get(repo.name);
    if (!idx || !symbol) return { source: 'ts' as const, locations: [], note: P('feedback.lsp.no_symbol', { reason }) };
    const defs = toolSymbolLookup(new Map([[repo.name, idx]]) as IndexMap, { repo: repo.name, name: symbol }).symbols;
    if (kind === 'definition') return { source: 'ts' as const, note: `language server unavailable: ${reason}`, locations: defs.map((d) => ({ path: d.path, startLine: d.range.startLine, endLine: d.range.endLine })) };
    const refs = defs.flatMap((d) => idx.callEdges.filter((e) => e.to === d.symbolId).map((e) => ({ path: e.site.path, startLine: e.site.line, endLine: e.site.line })));
    return { source: 'ts' as const, note: `language server unavailable: ${reason}`, locations: refs };
  }

  /**
   * `git_log` for a repository of this audit: the local repository or the remote source's bare
   * cache, at the commit the snapshot resolved. Archives and work-tree-only folders have no history.
   */
  private async gitLog(repoName: string | undefined, a: { path?: string; n?: number; grep?: string }, signal?: AbortSignal) {
    const repo = repoName ? this.repoByName(repoName) : this.targetRepo;
    if (!repo) throw new Error(`unknown repository ${repoName}`);
    const row = this.store.get<{ source_kind: string; source_uri: string; commit: string | null }>(
      'SELECT r.source_kind, r.source_uri, s.resolved_commit AS "commit" FROM repository r JOIN snapshot s ON s.id = ? WHERE r.id = ?', repo.snapshotId, repo.id);
    if (!row?.commit) throw new Error(`${repo.name}: the audited version has no resolved commit (not a git source)`);
    let dir: string;
    if (row.source_kind === 'local') dir = row.source_uri;
    else if (row.source_kind === 'git') dir = remoteCacheDir(this.store.paths.gitCache, parseGitUrl(row.source_uri, { allowFile: true }));
    else throw new Error(`${repo.name}: archive sources carry no git history`);
    if (!existsSync(dir)) throw new Error(`${repo.name}: git data is not available locally`);
    return gitLog(this.executor, dir, row.commit, { ...a, ...(signal ? { signal } : {}) });
  }

  private knowledgeCap(model: ModelRef): number {
    return Math.floor(this.contextWindow(model)) >> 2;
  }

  /** The context window `model` is registered with (the default for one the configuration does not know). */
  contextWindow(model: ModelRef): number {
    try {
      return (this.hub.resolve(model) as { contextWindow?: number }).contextWindow || DEFAULT_CONTEXT_WINDOW;
    } catch {
      return DEFAULT_CONTEXT_WINDOW;
    }
  }

  /**
   * Keep only knowledge references that this step actually read; the rest are dropped with a
   * contract warning. Returns the kept refs with their layer and whether the skill is verified.
   */
  knowledgeRefs(stepId: string, refs: string[] | undefined): { name: string; file: string | null; layer: string; verified: boolean }[] {
    if (!refs?.length) return [];
    const read = this.knowledgeRead.get(stepId) ?? new Set<string>();
    const kept: { name: string; file: string | null; layer: string; verified: boolean }[] = [];
    const dropped: string[] = [];
    for (const ref of [...new Set(refs)]) {
      const [name, ...rest] = ref.split('/');
      const skill = this.knowledge.skills.find((f) => f.name === name);
      if (!skill || !read.has(ref)) { dropped.push(ref); continue; }
      kept.push({ name: name!, file: rest.length ? rest.join('/') : null, layer: skill.layer, verified: skill.verified !== false });
    }
    if (dropped.length) this.event('contract.violation', { tool: 'knowledge_refs', attempt: 0, issues: dropped.map((d) => `knowledge ref "${d}" was not read in this step; dropped`) }, stepId);
    return kept;
  }

  /** keep only fact ids facts_query returned in this step; the rest are dropped with a contract warning. */
  factRefs(stepId: string, refs: string[] | undefined): string[] {
    if (!refs?.length) return [];
    const seen = this.factsSeen.get(stepId) ?? new Set<string>();
    const kept = [...new Set(refs)].filter((r) => seen.has(r));
    const dropped = [...new Set(refs)].filter((r) => !seen.has(r));
    if (dropped.length) this.event('contract.violation', { tool: 'fact_refs', attempt: 0, issues: dropped.map((d) => `fact ref "${d}" was not returned by facts_query in this step; dropped`) }, stepId);
    return kept;
  }

  /** The target service's responsibility card in the prompt and service_card for peers, when the project has service boundaries. */
  private serviceAccess(stepId: string, nonce: string, model: ModelRef, repo = this.targetRepo.name, always = false): { tool: AuditTool | null; note: string } | null {
    const gateways = projectGateways(this.store, this.audit.project_id, this.views);
    const trust = effectiveTrust(this.store, this.audit.project_id, gateways);
    if (trust.value === 'monolith' && !always) return null;
    const confidential = confidentialAllowed(this.store, model);
    const card = responsibilityCard(this.store, this.audit.project_id, repo, this.indexes.get(repo), gateways, { confidential });
    const peers = this.store.all<{ name: string }>('SELECT name FROM repository WHERE project_id = ? AND removed_at IS NULL AND name != ? ORDER BY name', this.audit.project_id, repo).map((r) => r.name);
    const tool: AuditTool | null = peers.length ? {
      name: 'service_card', kind: 'read', description: P('tool.service_card'),
      parameters: Type.Object({ service: Type.String({ maxLength: 200, description: `One of: ${peers.slice(0, 30).join(', ')}` }) }, { additionalProperties: false }),
      run: (a: { service: string }) => {
        // The session's own service is answered too — gpt-6-luna asked for it in 5 of 19 calls.
        const name = [repo, ...peers].find((p) => p.toLowerCase() === a.service.toLowerCase());
        if (!name) throw new Error(`unknown service ${a.service}; use one of: ${peers.slice(0, 30).join(', ')}`);
        this.event('tool.called', { tool: 'service_card', service: name }, stepId);
        return { text: wrapUntrusted(nonce, 'knowledge', `card:${name}`, cardText(responsibilityCard(this.store, this.audit.project_id, name, this.indexes.get(name), gateways, { confidential }))) };
      },
    } : null;
    return { tool, note: P('section.service_card', { card: cardText(card) }) };
  }

  /** the facts_query tool and the prompt note, when the project has facts in force. */
  private factsAccess(stepId: string, nonce: string, model: ModelRef): { tool: AuditTool; note: string; withheld: number } | null {
    // confidential facts only for the models allowed to receive them.
    const allowed = confidentialAllowed(this.store, model);
    const visible = (f: { sensitivity: string }) => allowed || f.sensitivity !== 'confidential';
    const all = activeFacts(this.store, this.audit.project_id);
    const facts = all.filter(visible);
    const withheld = all.length - facts.length;
    if (withheld) this.event('judgement.made', { kind: 'facts_withheld', model: `${model.provider}/${model.model}`, withheld }, stepId);
    if (!facts.length) return null;
    const TRUST: Record<string, string> = { authoritative: '权威', verified: '已核实', unverified: '未核实' };
    const tool: AuditTool = {
      name: 'facts_query', kind: 'read', description: P('tool.facts_query'),
      parameters: Type.Object({
        topic: Type.Optional(Type.String({ maxLength: 40 })), keyword: Type.Optional(Type.String({ maxLength: 200 })),
        scope: Type.Optional(Type.String({ maxLength: 200, description: 'A repository or service name; facts without a scope always match.' })),
      }, { additionalProperties: false }),
      run: (a: { topic?: string; keyword?: string; scope?: string }) => {
        const k = a.keyword?.toLowerCase();
        const hit = activeFacts(this.store, this.audit.project_id).filter(visible).filter((f) => {
          if (a.topic && f.topic !== a.topic) return false;
          if (k && !f.statement.toLowerCase().includes(k) && !f.fact_key.toLowerCase().includes(k)) return false;
          if (a.scope) {
            const sc = fromJson<{ repos?: string[]; services?: string[] }>(f.scope, {});
            const names = [...(sc.repos ?? []), ...(sc.services ?? [])];
            if (names.length && !names.some((n) => n.toLowerCase() === a.scope!.toLowerCase())) return false;
          }
          return true;
        }).slice(0, 30);
        const seen = this.factsSeen.get(stepId) ?? new Set<string>();
        for (const f of hit) seen.add(f.id);
        this.factsSeen.set(stepId, seen);
        this.event('tool.called', { tool: 'facts_query', facts: hit.map((f) => f.id) }, stepId);
        const lines = hit.map((f) => {
          const sc = fromJson<{ repos?: string[]; services?: string[]; paths?: string[] }>(f.scope, {});
          const scope = [...(sc.repos ?? []), ...(sc.services ?? []), ...(sc.paths ?? [])].join('、');
          return `- id=${f.id} [${TRUST[f.trust] ?? f.trust} · ${f.topic}${scope ? ` · 范围：${scope}` : ''} · v${f.version}] ${f.statement}`;
        });
        return { text: `${P('data.facts_result')}\n${wrapUntrusted(nonce, 'knowledge', 'facts', lines.join('\n') || '（没有匹配的事实）')}` };
      },
    };
    const topics = [...new Set(facts.map((f) => f.topic))].join('、');
    return { tool, note: P('section.facts', { count: facts.length, topics }), withheld };
  }

  /**
   * Keep only connector calls made in this step; each kept ref says whether that call counted as
   * authoritative and where its response is stored. The rest are dropped with a contract warning.
   */
  connectorRefs(stepId: string, refs: string[] | undefined): ConnectorRef[] {
    if (!refs?.length) return [];
    const kept: ConnectorRef[] = [];
    const dropped: string[] = [];
    for (const id of [...new Set(refs)]) {
      const c = this.store.get<{ id: string; name: string; operation: string; authoritative: number; response_ref: string | null; response_hash: string | null; created_at: number }>(
        `SELECT cc.id, c.name, cc.operation, cc.authoritative, cc.response_ref, cc.response_hash, cc.created_at FROM connector_call cc JOIN connector c ON c.id = cc.connector_id
         WHERE cc.id = ? AND cc.audit_id = ? AND cc.step_id = ? AND cc.status = 'ok'`, id, this.auditId, stepId);
      if (!c) { dropped.push(id); continue; }
      kept.push({ callId: c.id, connector: c.name, operation: c.operation, authoritative: !!c.authoritative, responseRef: c.response_ref, responseHash: c.response_hash, at: c.created_at });
    }
    if (dropped.length) this.event('contract.violation', { tool: 'connector_refs', attempt: 0, issues: dropped.map((d) => `connector ref "${d}" is not a successful query of this step; dropped`) }, stepId);
    return kept;
  }

  private recordSkill(stepId: string, name: string, layer: string, sha: string, level: string, trigger: string, reason: string, tokens: number): void {
    this.store.insert('skill_usage', {
      id: newId('skillUsage'), audit_id: this.auditId, step_id: stepId, skill_name: name, layer, skill_hash: sha, level,
      trigger: ['on_demand', 'always', 'phase', 'user_pinned', 'knowledge_need'].includes(trigger) ? trigger : 'on_demand', reason, tokens,
    });
  }

  private sessionEvent(stepId: string, e: SessionEvent, ended?: { kind: StepKind; prompt: Record<string, unknown>; pushed: { kind: string; ids: string[] }[] }): void {
    switch (e.type) {
      case 'session.started': this.event('session.started', { model: e.model }, stepId); break;
      case 'session.resumed': this.event('session.resumed', { fromAttempt: this.resumedFrom.get(stepId) ?? null, messages: e.messages, repaired: e.repaired }, stepId); break;
      case 'session.turn': {
        this.event('session.turn', { turn: e.turn, ...e.usage }, stepId);
        // what the Agent said this turn, for the narrative trajectory; model output shown as data.
        const text = (e.text ?? '').trim();
        this.event('agent.note', {
          turn: e.turn, text: text.slice(0, 2000), ...(text.length > 2000 ? { truncated: true } : {}),
          input: e.usage.input, output: e.usage.output, cache_read: e.usage.cacheRead,
        }, stepId);
        break;
      }
      case 'session.ended': {
        // Prompt section sizes (characters), peak context, compactions and push usage.
        const ref = new Set(e.telemetry.referenced);
        const pushed = (ended?.pushed ?? []).map((x) => ({ kind: x.kind, n: x.ids.length, referenced: x.ids.filter((id) => ref.has(id)).length }));
        this.event('session.ended', {
          status: e.status, turns: e.turns,
          telemetry: { ...(ended ? { kind: ended.kind, prompt: ended.prompt } : {}), peak_context: e.telemetry.peakContext, compactions: e.telemetry.compactions, pushed },
        }, stepId);
        break;
      }
      case 'session.compacted': this.event('session.compacted', { reason: e.reason }, stepId); break;
      case 'tool.called': this.event('tool.called', { tool: e.tool, call_id: e.callId, args: summarizeArgs(e.args) }, stepId); break;
      case 'tool.result': this.event('tool.result', { tool: e.tool, call_id: e.callId, ok: e.ok, preview: e.preview.slice(0, 1000), duration_ms: e.durationMs, ...(e.summary ? { summary: e.summary } : {}) }, stepId); break;
      case 'contract.violation': this.event('contract.violation', { tool: e.tool, attempt: e.attempt, issues: e.issues.slice(0, 10) }, stepId); break;
      case 'security.blocked': this.event('security.blocked', { tool: e.tool, reason: e.reason }, stepId); break;
    }
  }
}

/** tools a coordinating session (`noCodeRead`) does not get. */
const CODE_READ_TOOLS: ReadonlySet<string> = new Set(['read', 'grep']);

/** Steps whose sessions get the threat-model section. */
const THREAT_MODEL_KINDS: ReadonlySet<StepKind> = new Set(['hunt', 'challenge', 'review', 'verify-fix', 'coverage-gap', 'decide']);

function summarizeArgs(args: unknown): unknown {
  const s = JSON.stringify(args ?? {});
  return s.length <= 2000 ? args : { truncated: true, preview: s.slice(0, 2000) };
}

/** How far past the last line a cited end may be and still be read as “to the end of the file”. */
export const REF_END_SLACK = 20;

/**
 * A copy of `v` where every code reference whose end lies a little past its file's last line (start inside the file,
 * at most REF_END_SLACK lines over) ends there; a range far beyond the file stays as it is and is refused.
 */
export function clampRefEnds(v: unknown, lastLine: (repo: string | undefined, path: string) => number | undefined): unknown {
  if (Array.isArray(v)) return v.map((x) => clampRefEnds(x, lastLine));
  if (!v || typeof v !== 'object') return v;
  const o = Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, clampRefEnds(x, lastLine)]));
  if (typeof o.path !== 'string' || typeof o.startLine !== 'number' || typeof o.endLine !== 'number') return o;
  const last = lastLine(typeof o.repo === 'string' && o.repo ? o.repo : undefined, o.path);
  return last !== undefined && o.startLine >= 1 && o.startLine <= last && o.endLine > last && o.endLine - last <= REF_END_SLACK ? { ...o, endLine: last } : o;
}

/**
 * A copy of `v` where every code reference (`{ path, startLine }`) without a repository names one: `repo`, or what it
 * returns for the reference's path (left without one when it returns nothing).
 */
export function withRefRepo(v: unknown, repo: string | ((path: string) => string | undefined)): unknown {
  if (Array.isArray(v)) return v.map((x) => withRefRepo(x, repo));
  if (!v || typeof v !== 'object') return v;
  const o = Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, withRefRepo(x, repo)]));
  if (typeof o.path !== 'string' || typeof o.startLine !== 'number' || (o.repo !== undefined && o.repo !== '')) return o;
  const r = typeof repo === 'string' ? repo : repo(o.path);
  return r ? { ...o, repo: r } : o;
}
