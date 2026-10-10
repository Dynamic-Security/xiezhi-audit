// 追加执行: run risk-hypothesis-first afterwards on a finished full / incremental audit — a
// new threat model and its verification, or verifying the still `proposed` hypotheses the audit left.
// The per-entry logic review is part of it; the old `logic_review` kind runs the merged analysis. Like a
// backfill it is a separate audit on the same snapshots with `base_audit_id` = the source; it never
// changes the source's artifacts except for the verdicts of the source's own hypotheses. Its hypotheses are listed
// with the source audit (`hypothesisAuditIds`).
import { calibrated } from './calibration.js';
import { AppError, auditBudget, checkStrategy, newId, stageModel, upgradeStrategy } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { estimateStep } from './estimates.js';
import type { AuditRuntime } from './runtime.js';
import type { StepResult } from './step-runner.js';
import { engineLimitations, type AuditPlan } from './steps/plan.js';
import { buildCandidates, rankCandidates, type TriageOutput } from './steps/triage.js';
import { hypothesisAuditIds, type SupplementKind, type SupplementScope } from './threat.js';
import { DOMAIN_EXPERT_TOKENS } from './estimates.js';
import { pendingLateDomains } from './domain-plan.js';

export interface CreateSupplementInput {
  auditId: string;
  kind: SupplementKind;
  /** threat_hypotheses: verify these `proposed` hypotheses instead of building a new threat model. */
  hypothesisIds?: string[];
  /** domains: the late domains to run; default all of them not run yet. */
  domainIds?: string[];
  origin: 'cli' | 'ui' | 'conversation';
}

const TITLE: Record<SupplementKind, string> = { logic_review: '追加：按入口的逻辑审查', threat_hypotheses: '追加：风险假设先行', domains: '追加：新增的风险领域' };

export function createSupplementAudit(store: Store, knownModels: Set<string>, raw: CreateSupplementInput): string {
  // the logic review is part of risk-hypothesis-first; the old kind runs the merged analysis.
  const input: CreateSupplementInput = raw.kind === 'logic_review' ? { ...raw, kind: 'threat_hypotheses' } : raw;
  const src = store.get<{ id: string; project_id: string; title: string; status: string; scene: string; strategy_frozen: string | null; strategy_sources: string; mode: string; scope: string }>(
    'SELECT id, project_id, title, status, scene, strategy_frozen, strategy_sources, mode, scope FROM audit WHERE id = ?', input.auditId);
  if (!src) throw new AppError('AUDIT_NOT_FOUND', input.auditId);
  if (!['completed', 'partial'].includes(src.status) || !src.strategy_frozen) throw new AppError('AUDIT_INVALID_TRANSITION', 'only finished audits can be supplemented');
  if (!['full', 'incremental'].includes(src.scene)) throw new AppError('CONFIG_INVALID', 'supplements apply to full and incremental audits');
  const srcScope = fromJson<{ backfill?: unknown; supplement?: unknown }>(src.scope, {});
  if (srcScope.backfill || srcScope.supplement) throw new AppError('CONFIG_INVALID', 'start the supplement from the original audit, not from a backfill or supplement');
  const ids = input.kind === 'threat_hypotheses' ? [...new Set(input.hypothesisIds ?? [])] : [];
  if (input.kind !== 'threat_hypotheses' && input.hypothesisIds?.length) throw new AppError('COMMON_VALIDATION', 'hypothesisIds only apply to threat_hypotheses');
  if (input.kind !== 'domains' && input.domainIds?.length) throw new AppError('COMMON_VALIDATION', 'domainIds only apply to domains');
  // domains a person added after the expert phase, not run by a supplement yet.
  let domainIds: string[] = [];
  if (input.kind === 'domains') {
    const late = pendingLateDomains(store, src.id).map((d) => d.id);
    domainIds = input.domainIds?.length ? [...new Set(input.domainIds)] : late;
    if (!domainIds.length || domainIds.some((d) => !late.includes(d))) throw new AppError('COMMON_VALIDATION', 'no domains added after the expert phase are waiting for a supplement');
  }
  if (ids.length) {
    const audits = hypothesisAuditIds(store, src.id);
    const proposed = new Set(store.all<{ id: string }>(
      `SELECT id FROM hypothesis WHERE origin = 'threat_model' AND status = 'proposed' AND audit_id IN (${audits.map(() => '?').join(',')})`, ...audits).map((h) => h.id));
    if (ids.some((id) => !proposed.has(id))) throw new AppError('COMMON_VALIDATION', 'some hypotheses are not unverified threat-model hypotheses of this audit');
  }
  const base = upgradeStrategy(JSON.parse(src.strategy_frozen));
  // A supplement runs one analysis, so its budget has no stage quotas.
  const { stages: _stages, ...baseBudget } = base.budget;
  const strategy = {
    ...base,
    // The index gives the entry list of the threat model (and its logic-review entries); it is cached by rootHash.
    tools: { ...base.tools, ast: true, coverageCompare: false },
    multiModel: { enabled: false, models: [] },
    stages: input.kind === 'domains' ? { ...base.stages, deepExplore: false, threatHypotheses: false } : { ...base.stages, deepExplore: false, threatHypotheses: true },
    budget: ids.length ? { ...baseBudget, tokens: Math.max(60_000, 25_000 * ids.length), durationSec: 600 + 120 * ids.length } : baseBudget,
    coverageTarget: { ...base.coverageTarget, entry: 0, sink: 0, onShortfall: 'declare' as const },
  };
  const issues = checkStrategy(strategy, 'full', knownModels);
  if (issues.length) throw new AppError('STRATEGY_INVALID', issues.map((i) => `${i.path}: ${i.message}`).join('; '));
  const id = newId('audit');
  const budget = auditBudget(strategy);
  const repos = store.all<{ repository_id: string; snapshot_id: string | null; requested_ref: string | null; role_in_audit: string }>(
    'SELECT repository_id, snapshot_id, requested_ref, role_in_audit FROM audit_repository WHERE audit_id = ?', src.id);
  const supplement: SupplementScope = { auditId: src.id, kind: input.kind, ...(ids.length ? { hypothesisIds: ids } : {}), ...(domainIds.length ? { domainIds } : {}) };
  const title = ids.length ? `追加：验证风险假设（${ids.length} 条）` : domainIds.length ? `追加：新增的风险领域（${domainIds.length} 个）` : TITLE[input.kind];
  store.tx(() => {
    store.insert('audit', {
      id, project_id: src.project_id, scene: 'full', mode: src.mode, title: `${title} · ${src.title}`, status: 'planning', strategy_draft: strategy,
      strategy_sources: fromJson(src.strategy_sources, {}), base_audit_id: src.id,
      scope: { include: strategy.scope.include, exclude: strategy.scope.exclude, focus: strategy.focus, supplement },
      budget_initial: budget, budget_effective: budget, budget_consumed: { tokens: 0, durationMs: 0, costMicros: 0 }, origin: input.origin, conversation_id: null,
    });
    // Same snapshots as the source audit: planning does not re-snapshot pre-attached repositories.
    for (const r of repos) store.insert('audit_repository', { audit_id: id, repository_id: r.repository_id, snapshot_id: r.snapshot_id, requested_ref: r.requested_ref, role_in_audit: r.role_in_audit });
    store.appendEvent(id, 'audit.status_changed', { from: null, to: 'planning', reason: `${input.kind} supplement of ${src.id}` });
  });
  return id;
}

/** The candidate selection of a supplement in the triage shape: no regular hunt batches (only verification). */
export function supplementSelection(rt: AuditRuntime, _sup: SupplementScope): TriageOutput {
  return { candidates: rankCandidates(buildCandidates(rt)), selected: [], overflow: [], batches: [] };
}

/** Coverage items of a supplement: none (its coverage is the hypothesis table, listed with the source audit). */
export function supplementCoverageTargets(_rt: AuditRuntime, _sup: SupplementScope): Set<string> {
  return new Set();
}

/** Deterministic plan (like a backfill): the work is known from the source audit; it starts at once. */
export function supplementPlan(rt: AuditRuntime, sup: SupplementScope): StepResult {
  const store = rt.store;
  const source = store.get<{ title: string }>('SELECT title FROM audit WHERE id = ?', sup.auditId);
  const s = rt.strategy;
  const v = rt.views.get(rt.targetRepo.name)!;
  const verify = sup.hypothesisIds?.length ?? 0;
  const domains = sup.domainIds?.length ?? 0;
  const byStep: Record<string, number> = {};
  // Calibrated from this data directory's history.
  const logic = stageModel(s, 'logic');
  if (domains) byStep.hunt = DOMAIN_EXPERT_TOKENS * domains;
  else if (verify) byStep.hunt = calibrated(store, estimateStep('hunt', verify), 'hunt', logic);
  else {
    byStep['threat-model'] = calibrated(store, estimateStep('threat-model') * rt.targets.length, 'threat-model', logic);
    byStep.hunt = calibrated(store, estimateStep('hunt', Math.min(s.limits.maxCandidates, 40)), 'hunt', logic);
  }
  const tokens = Object.values(byStep).reduce((a, b) => a + b, 0);
  const pricing = store.config.pricing[`${s.models.audit.provider}/${s.models.audit.model}`];
  const cost = (t: number) => (pricing ? (t * 0.8 * pricing.input + t * 0.2 * pricing.output) / 1e6 : 0);
  const what = domains ? `为审计中途新增的 ${domains} 个风险领域各运行一位领域专家` : verify ? `逐条验证 ${verify} 条尚未验证的风险假设` : '结合项目画像与威胁模型列出风险假设清单，再逐条用代码验证';
  const plan: AuditPlan = {
    submitted: {
      summary: `追加执行「${source?.title ?? sup.auditId}」：${what}；使用同一代码快照，结论并回原审计的覆盖对照。`,
      focusDirections: [{ direction: domains ? '新增的风险领域' : '风险假设先行', reason: '用户在审计结束后选择追加执行' }],
      plannedKnowledge: [], contextNeeded: [], limitations: [],
    },
    scale: { files: v.manifest.stats.fileCount, byLang: v.manifest.stats.byLang, entrypoints: 0, sinks: 0, candidates: verify, sinksByCategory: {} },
    estimate: {
      tokens: { p50: Math.ceil(tokens * 0.7), p90: Math.ceil(tokens * 1.3) }, durationSec: { p50: 300 + 60 * (verify || 20), p90: 600 + 180 * (verify || 20) },
      cost: pricing ? { p50: cost(tokens * 0.7), p90: cost(tokens * 1.3), currency: pricing.currency } : null, byStep,
    },
    strategySources: JSON.parse(rt.audit.strategy_sources) as Record<string, string>,
    limitations: [...engineLimitations(rt), '追加执行只做所选的分析；覆盖不等于检出率。'],
    knowledge: rt.knowledge.skills.map((k) => k.name),
  };
  const ref = store.artifacts.putJson(plan);
  return { outputRef: ref, apply: () => store.update('audit', { id: rt.auditId }, { plan_ref: ref }) };
}

