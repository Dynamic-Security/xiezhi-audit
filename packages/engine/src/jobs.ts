// Background jobs outside the audit pipeline: project analyses, hunt bases and
// prechecks, knowledge and pack drafts, architecture imports and AI reports. Each runs in-process; `xDone(id)` resolves
// when it has ended (at once when it is not running here). Moved out of the Engine class.
import { type Executor, type RuleSet } from '@xiezhi/context';
import { join } from 'node:path';
import { failInterruptedDrafts, type Draft } from '@xiezhi/knowledge';
import type { ModelHub } from '@xiezhi/agent';
import type { ConnectorPool } from '@xiezhi/connectors';
import type { Store } from '@xiezhi/store';
import { createAiReportJob, runAiReport, type AiReportRequest } from './ai-report.js';
import { createAnalysis, runAnalysis } from './analyze.js';
import { createArchitectureImport, runArchitectureImport } from './architecture.js';
import { basisSkillText, createBasis, draftBasis, precheckHunt, type BasisInput } from './hunt.js';
import { createDraft, processDraft, type CreateDraftInput } from './knowledge.js';
import { createRuleDraft, processRuleDraft, type ProjectRuleRow } from './project-rules.js';
import { createCaseDraft, processCaseDraft, type VerificationCaseRow } from './verification.js';
import { createFixDraft, processFixDraft, type FixSuggestionRow } from './fixes.js';
import { createPackDraft, listPackDrafts, processPackDraft, savePackDraft, type PackDraftRow } from './packs.js';
import { getProject, listProjects } from './services.js';
import { beginGeneration, runThreatModelGeneration, type GenerateOptions } from './threat-model-gen.js';

/** Jobs of one kind running in this process, by id. */
class JobSet {
  private readonly jobs = new Map<string, { ac: AbortController; done: Promise<void> }>();

  start(id: string, run: (signal: AbortSignal) => Promise<void>): void {
    const ac = new AbortController();
    const done = run(ac.signal).finally(() => this.jobs.delete(id));
    this.jobs.set(id, { ac, done });
  }

  has(id: string): boolean {
    return this.jobs.has(id);
  }

  done(id: string): Promise<void> {
    return this.jobs.get(id)?.done ?? Promise.resolve();
  }

  /** Abort every job and wait until all have ended. */
  async stop(): Promise<void> {
    const all = [...this.jobs.values()];
    for (const j of all) j.ac.abort();
    await Promise.allSettled(all.map((j) => j.done));
  }
}

export interface JobDeps {
  store: Store;
  executor: Executor;
  rules: RuleSet;
  /** Read at each start: the hub is rebuilt when model settings change. */
  hub: () => ModelHub;
  allowFileRemotes: () => boolean;
  /** Connectors for online threat-model sources; absent in tools that run without the pool. */
  pool?: () => ConnectorPool | null;
}

export class BackgroundJobs {
  private readonly analyses = new JobSet();
  private readonly reports = new JobSet();
  private readonly prechecks = new JobSet();
  private readonly drafts = new JobSet();
  private readonly ruleDrafts = new JobSet();
  private readonly caseDrafts = new JobSet();
  private readonly fixDrafts = new JobSet();
  private readonly bases = new JobSet();
  private readonly packDrafts = new JobSet();
  private readonly imports = new JobSet();
  private readonly threatModels = new JobSet();

  constructor(private readonly d: JobDeps) {}

  /** Generate an AI report in the background; the export row shows its phase. */
  startAiReport(req: AiReportRequest, options: Record<string, unknown>): string {
    const id = createAiReportJob(this.d.store, req, options);
    this.reports.start(id, (signal) => runAiReport({ store: this.d.store, hub: this.d.hub() }, id, req, signal));
    return id;
  }

  aiReportDone(id: string): Promise<void> {
    return this.reports.done(id);
  }

  /** Start a project analysis in the background (only on user request). */
  startAnalysis(projectId: string): string {
    getProject(this.d.store, projectId);
    const id = createAnalysis(this.d.store, projectId);
    this.analyses.start(id, (signal) => runAnalysis({ store: this.d.store, executor: this.d.executor, hub: this.d.hub(), rules: this.d.rules, allowFileRemotes: this.d.allowFileRemotes() }, projectId, id, signal));
    return id;
  }

  analysisDone(id: string): Promise<void> {
    return this.analyses.done(id);
  }

  // ---- risk hunts ----

  /** Create a basis draft and organize it in the background with the audit model. */
  startBasis(input: BasisInput): string {
    const id = createBasis(this.d.store, input);
    this.bases.start(id, (signal) => draftBasis({ store: this.d.store, hub: this.d.hub() }, id, signal));
    return id;
  }

  basisDone(id: string): Promise<void> {
    return this.bases.done(id);
  }

  /** Run the deterministic precheck of a planned hunt in the background. */
  startPrecheck(huntId: string): void {
    if (this.prechecks.has(huntId)) return;
    this.prechecks.start(huntId, (signal) => precheckHunt({ store: this.d.store, executor: this.d.executor, allowFileRemotes: this.d.allowFileRemotes() }, huntId, signal));
  }

  precheckDone(huntId: string): Promise<void> {
    return this.prechecks.done(huntId);
  }

  /** Risk hunt basis → global skill draft. */
  saveBasisAsSkill(basisId: string, opts: { name?: string; category: 'vuln_case' | 'audit_method' }): Draft {
    const { name, text, title } = basisSkillText(this.d.store, basisId, opts);
    return this.startDraft({ layer: 'global', kind: 'skill', text, organize: false, name, source: { kind: 'hunt_basis', ref: basisId, label: `风险排查依据「${title}」` } });
  }

  // ---- knowledge drafts ----

  /** Create a knowledge draft and process it in the background (organize, checks, contradictions). */
  startDraft(input: CreateDraftInput): Draft {
    const draft = createDraft(this.d.store, input);
    this.drafts.start(draft.id, (signal) => processDraft({ store: this.d.store, hub: this.d.hub() }, draft.id, signal));
    return draft;
  }

  draftDone(id: string): Promise<void> {
    return this.drafts.done(id);
  }

  // ---- project rules ----

  /** Draft a project rule for a vulnerability with the chat model in the background. */
  startRuleDraft(vulnId: string): ProjectRuleRow {
    const row = createRuleDraft(this.d.store, vulnId);
    this.ruleDrafts.start(row.id, (signal) => processRuleDraft({ store: this.d.store, hub: this.d.hub() }, row.id, signal));
    return row;
  }

  ruleDraftDone(id: string): Promise<void> {
    return this.ruleDrafts.done(id);
  }

  // ---- verification cases and fix suggestions ----

  startCaseDraft(vulnId: string): VerificationCaseRow {
    const row = createCaseDraft(this.d.store, vulnId);
    this.caseDrafts.start(row.id, (signal) => processCaseDraft({ store: this.d.store, hub: this.d.hub() }, row.id, signal));
    return row;
  }

  caseDraftDone(id: string): Promise<void> {
    return this.caseDrafts.done(id);
  }

  startFixDraft(vulnId: string): FixSuggestionRow {
    const row = createFixDraft(this.d.store, vulnId);
    this.fixDrafts.start(row.id, (signal) => processFixDraft({ store: this.d.store, hub: this.d.hub() }, row.id, signal));
    return row;
  }

  fixDraftDone(id: string): Promise<void> {
    return this.fixDrafts.done(id);
  }

  // ---- connector pack drafts ----

  startPackDraft(input: { openapi: string; name?: string; focus?: string }): PackDraftRow {
    const draft = createPackDraft(this.d.store, input);
    this.packDrafts.start(draft.id, (signal) => processPackDraft({ store: this.d.store, hub: this.d.hub() }, draft.id, signal));
    return draft;
  }

  packDraftDone(id: string): Promise<void> {
    return this.packDrafts.done(id);
  }

  // ---- architecture imports ----

  /** Import architecture material: topology proposals now, a project architecture draft for review. */
  startArchitectureImport(projectId: string, input: { text: string; label: string }): string {
    const id = createArchitectureImport(this.d.store, projectId, input);
    this.imports.start(id, (signal) => runArchitectureImport({ store: this.d.store, hub: this.d.hub(), startDraft: (x) => this.startDraft(x) }, id, signal));
    return id;
  }

  architectureImportDone(id: string): Promise<void> {
    return this.imports.done(id);
  }

  // ---- requirement threat models ----

  /** Generate (or regenerate) a threat model in the background; refused while one runs. */
  startThreatModel(id: string, opts: GenerateOptions = {}): void {
    const run = beginGeneration(this.d.store, id, opts);
    this.threatModels.start(id, (signal) => runThreatModelGeneration({ store: this.d.store, hub: this.d.hub(), pool: this.d.pool?.() ?? null }, id, run, signal));
  }

  threatModelDone(id: string): Promise<void> {
    return this.threatModels.done(id);
  }

  /**
   * Stop every background job (service shutdown). Basis drafts, pack drafts and architecture
   * imports are stopped too: each settles as `failed`, so none is left “in progress” with nothing running it.
   */
  async stop(): Promise<void> {
    await Promise.all([this.analyses, this.prechecks, this.drafts, this.reports, this.bases, this.packDrafts, this.imports, this.threatModels, this.ruleDrafts, this.caseDrafts, this.fixDrafts].map((j) => j.stop()));
  }
}

const RESTARTED = '服务重启，处理被中断，请重新发起';

/**
 * After a restart no job of the previous process runs any more: whatever it left “in progress” is
 * settled — analyses as interrupted, the others as failed with a note — instead of showing as running for ever.
 */
export function settleInterruptedJobs(store: Store): void {
  const now = Date.now();
  store.tx(() => {
    store.db.run(`UPDATE project_analysis SET status = 'interrupted', reason = 'service restart', ended_at = ? WHERE status = 'running'`, now);
    store.db.run(`UPDATE export_job SET status = 'failed', progress = NULL, error = '服务重启，生成被中断', updated_at = ? WHERE status = 'running'`, now);
    store.db.run(`UPDATE hunt_basis SET status = 'failed', error = ?, updated_at = ? WHERE status = 'drafting'`, RESTARTED, now);
    store.db.run(`UPDATE architecture_import SET status = 'failed', error = ?, updated_at = ? WHERE status = 'running'`, RESTARTED, now);
    store.db.run(`UPDATE threat_model SET status = 'failed', error = ?, updated_at = ? WHERE status = 'generating'`, RESTARTED, now);
    store.db.run(`UPDATE project_rule SET status = 'failed', error = ?, updated_at = ? WHERE status = 'drafting'`, RESTARTED, now);
    store.db.run(`UPDATE verification_case SET status = 'failed', error = ?, updated_at = ? WHERE status = 'drafting'`, RESTARTED, now);
    store.db.run(`UPDATE fix_suggestion SET status = 'failed', error = ?, updated_at = ? WHERE status = 'drafting'`, RESTARTED, now);
    store.db.run(`UPDATE risk_hunt SET precheck = json_set(precheck, '$.status', 'failed', '$.error', ?), updated_at = ? WHERE json_extract(precheck, '$.status') = 'running'`, RESTARTED, now);
  });
  // Knowledge drafts: the knowledge package's own rule (it existed, but nothing called it).
  for (const dir of [store.paths.knowledgeGlobal, ...listProjects(store).map((p) => join(store.paths.projects, p.id, 'knowledge'))]) failInterruptedDrafts(dir);
  for (const d of listPackDrafts(store).filter((x) => x.status === 'organizing')) savePackDraft(store, { ...d, status: 'failed', error: RESTARTED });
}
