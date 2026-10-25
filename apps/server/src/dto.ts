// Projections from store rows to API DTOs. Each function lists the exposed fields
// explicitly, acting as the response whitelist: internal columns, refs and secrets never leave.
import { BUDGET_STAGES, SEVERITIES, contextItem, derivePhase, normalizePending, stageMeta, type BudgetStage, upgradeStrategy, type AuditDetailDto, type AuditSummaryDto, type ModelRef, type CodeLocDto, type ReverifyItemDto, type SuspectedMatchDto, type EventDto, type FindingDto, type GateDto, type PlanDto, type ProjectDto, type QuestionDto, type RepoDto, type RevisionDto, type SeverityCounts, type AnalysisDto, type RepoAnalysisDto, type RepoSignals, type StepDto, type VulnDetailDto, type VulnSummaryDto, type AuditEvent } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { budgetSuggestion, listSteps, queries as Q, runningDelta, type AuditPlan, type AuditRow, type GateResult, type RepoRoleOutput, type StepRow } from '@xiezhi/engine';
import type { FindingDetail } from '@xiezhi/report';
import { effectiveTrust } from '@xiezhi/engine';

export const iso = (ms: number | null | undefined): string | null => (ms ? new Date(ms).toISOString() : null);
const isoReq = (ms: number): string => new Date(ms).toISOString();

function emptyCounts(): SeverityCounts {
  return Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
}

export function projectDto(store: Store, p: { id: string; name: string; status: string; created_at: number }): ProjectDto {
  const repoCount = Q.repoCount(store, p.id);
  const openVulns = emptyCounts();
  for (const r of Q.openVulnCounts(store, p.id)) openVulns[r.severity] = r.n;
  const last = Q.lastAudit(store, p.id);
  return {
    id: p.id, name: p.name, status: p.status as ProjectDto['status'], createdAt: isoReq(p.created_at), repoCount, openVulns,
    lastAudit: last ? { id: last.id, status: last.status, endedAt: iso(last.ended_at) } : null,
    coverage: projectCoverage(store, p.id),
    internalTrust: (() => {
      const t = effectiveTrust(store, p.id);
      return { setting: t.source === 'user' ? (t.value as 'zero_trust' | 'gateway_boundary' | 'trusted_network') : null, effective: t.value, reason: t.reason };
    })(),
  };
}

/** Coverage of the latest finished audit that compared coverage (覆盖是否完整). */
function projectCoverage(store: Store, projectId: string): ProjectDto['coverage'] {
  const a = Q.latestCoverageAudit(store, projectId);
  if (!a) return null;
  const s = fromJson<{ coverageTarget?: { entry: number; sink: number } }>(a.strategy_frozen, {});
  const count = (kind: string, status?: string) => Q.coverageCount(store, a.id, kind, status);
  const entry = { total: count('entry'), reviewed: count('entry', 'concluded') };
  const sink = { total: count('sink'), reviewed: count('sink', 'concluded') };
  const ratio = (x: { total: number; reviewed: number }) => (x.total ? x.reviewed / x.total : 1);
  return { auditId: a.id, entry, sink, complete: ratio(entry) >= (s.coverageTarget?.entry ?? 1) && ratio(sink) >= (s.coverageTarget?.sink ?? 1) };
}

export function repoDto(store: Store, r: { id: string; project_id: string; name: string; source_kind: string; source_uri: string; default_ref: string | null; languages: string; role: string; role_source: string; is_auditable: number; auditable_source?: string; auditable_auto?: number | null; auditable_reason?: string | null; created_at: number; source_meta: string }): RepoDto {
  const latest = Q.latestRoleResult(store, r.id);
  const meta = fromJson<{ fileName?: string; rootHash?: string; headCommit?: string; defaultBranch?: string }>(r.source_meta, {});
  const snap = Q.lastRepoSnapshot(store, r.id);
  return {
    id: r.id, projectId: r.project_id, name: r.name, sourceKind: r.source_kind as RepoDto['sourceKind'], locator: r.source_uri,
    defaultRef: r.default_ref, languages: fromJson<string[]>(r.languages, []), role: r.role, auditable: !!r.is_auditable, createdAt: isoReq(r.created_at),
    lastSnapshot: snap ? { commit: snap.resolved_commit, ref: snap.requested_ref, worktree: !!snap.is_worktree, auditId: snap.audit_id } : null,
    sourceDetail: { fileName: meta.fileName ?? null, rootHash: meta.rootHash ?? null, headCommit: meta.headCommit ?? null, defaultBranch: meta.defaultBranch ?? null },
    roleSource: r.role_source === 'user' ? 'user' : 'ai',
    auditableSource: r.auditable_source === 'user' ? 'user' : 'auto',
    auditableAuto: r.auditable_auto === null || r.auditable_auto === undefined ? !!r.is_auditable : !!r.auditable_auto,
    auditableReason: r.auditable_reason ?? null,
    aiRoles: latest ? [...latest.judgement.roles].sort((a, b) => b.confidence - a.confidence).map((x) => ({ role: x.role, confidence: x.confidence })) : [],
  };
}

export function analysisDto(store: Store, a: { id: string; status: string; reason: string | null; model: string | null; started_at: number; ended_at: number | null; tokens_in: number; tokens_out: number; cost_micros: number | null }): AnalysisDto {
  const rows = Q.analysisRepos(store, a.id);
  return {
    id: a.id, status: a.status as AnalysisDto['status'], reason: a.reason, model: a.model, startedAt: isoReq(a.started_at), endedAt: a.ended_at ? isoReq(a.ended_at) : null,
    tokens: { input: a.tokens_in, output: a.tokens_out }, costMicros: a.cost_micros,
    repos: rows.map((x) => {
      const out = x.result_ref ? store.artifacts.getJson<RepoRoleOutput>(x.result_ref) : null;
      return {
        repositoryId: x.repository_id, name: x.name, status: x.status as RepoAnalysisDto['status'], rootHash: x.root_hash, error: x.error,
        roles: out ? [...out.judgement.roles].sort((p, q) => q.confidence - p.confidence) : [], rationale: out?.judgement.rationale ?? null,
        signals: x.signals_ref ? store.artifacts.getJson<RepoSignals>(x.signals_ref) : null,
      };
    }),
  };
}

export function auditSummary(store: Store, a: AuditRow, steps?: StepRow[]): AuditSummaryDto {
  const st = steps ?? listSteps(store, a.id);
  const projectName = Q.projectName(store, a.project_id);
  const eff = fromJson<{ tokens: number; durationMs: number; costMicros: number | null; stages?: Partial<Record<BudgetStage, number>> }>(a.budget_effective, { tokens: 0, durationMs: 0, costMicros: null });
  const con = fromJson<{ tokens: number; durationMs?: number; costMicros?: number | null; stages?: Partial<Record<BudgetStage, number>> }>(a.budget_consumed, { tokens: 0 });
  // while waiting, what the total and each stopped stage need (with the 1.2 margin); the same
  // numbers as the engine's `budget.exhausted` event.
  const sug = a.status === 'waiting_budget' ? budgetSuggestion(store, a.id) : null;
  const stageSug = new Map((sug?.stages ?? []).map((x) => [x.stage, x.tokens]));
  const stages = eff.stages ? BUDGET_STAGES.filter((k) => eff.stages![k] !== undefined).map((stage) => ({
    stage, limit: eff.stages![stage]!, consumed: con.stages?.[stage] ?? 0, stopped: stageSug.has(stage),
    ...(stageSug.has(stage) ? { suggestedTopUp: stageSug.get(stage)! } : {}),
  })) : undefined;
  const suggestedTopUp = sug?.tokens;
  // the live part is capped like a settlement, so a page open across a sleep does not jump.
  const liveMs = a.status === 'running' && a.running_since ? runningDelta(Date.now(), a.running_since) : 0;
  return {
    id: a.id, projectId: a.project_id, projectName: projectName ?? '', title: a.title, scene: a.scene as AuditSummaryDto['scene'],
    mode: a.mode as AuditSummaryDto['mode'], status: a.status, phase: derivePhase(a.status, st),
    partialReasons: fromJson(a.partial_reasons, []), errorClass: a.error_class, origin: a.origin,
    createdAt: isoReq(a.created_at), startedAt: iso(a.started_at), endedAt: iso(a.ended_at),
    budget: {
      effective: { tokens: eff.tokens, durationMs: eff.durationMs, costMicros: eff.costMicros ?? null },
      consumed: { tokens: con.tokens ?? 0, durationMs: (con.durationMs ?? 0) + liveMs, costMicros: con.costMicros === undefined ? 0 : con.costMicros },
      ...(stages ? { stages } : {}), ...(suggestedTopUp !== undefined ? { suggestedTopUp } : {}),
    },
    repos: Q.auditRepos(store, a.id).map((r) => ({ id: r.id, name: r.name, ref: r.requested_ref, commit: r.resolved_commit, worktree: !!r.is_worktree, roleInAudit: r.role_in_audit })),
    findingCount: Q.canonicalFindingCount(store, a.id),
    openQuestions: Q.openQuestionCount(store, a.id),
    conversationId: a.conversation_id && Q.conversationExists(store, a.conversation_id) ? a.conversation_id : null,
  };
}

export function stepDto(s: StepRow): StepDto {
  return {
    id: s.id, seq: s.seq, kind: s.kind, lineage: s.lineage_id, status: s.status, attempt: s.attempt, maxAttempts: s.max_attempts,
    model: s.model ? `${s.provider ?? ''}/${s.model}` : null, tokensIn: s.tokens_in, tokensOut: s.tokens_out, costMicros: s.cost_micros,
    errorClass: s.error_class, errorSummary: s.error_summary ? s.error_summary.slice(0, 300) : null, startedAt: iso(s.started_at), endedAt: iso(s.ended_at),
  };
}

export function gateDto(g: GateResult | null): GateDto | null {
  if (!g) return null;
  return { status: g.status, partialReasons: g.partialReasons, checks: g.checks, coverage: g.coverage, ...(g.notices?.length ? { notices: g.notices } : {}) };
}

export function auditDetail(store: Store, a: AuditRow): AuditDetailDto {
  const steps = listSteps(store, a.id);
  const refs = fromJson<Record<string, string>>(a.report_refs, {});
  return {
    ...auditSummary(store, a, steps),
    strategyHash: a.strategy_hash, steps: steps.map(stepDto),
    gate: gateDto(a.gate_ref ? store.artifacts.getJson<GateResult>(a.gate_ref) : null),
    lastEventSeq: Q.lastEventSeq(store, a.id),
    exports: { md: !!refs.md, json: !!refs.json, sarif: !!refs.sarif },
    reverify: a.scene === 'reverify' ? reverifyItems(store, a) : null,
    filteredModels: Q.filteredModels(store, a.id),
    modelSwitches: Object.entries(fromJson<Record<string, ModelRef>>(a.model_switches, {})).map(([from, to]) => ({ from, to })),
  };
}

/** Targets of a reverification audit with their verdicts (null until decided). */
function reverifyItems(store: Store, a: AuditRow): ReverifyItemDto[] {
  const ids = fromJson<{ reverify?: string[] }>(a.scope, {}).reverify ?? [];
  return ids.map((id) => {
    const v = Q.vulnHeader(store, id);
    const o = Q.reverifyOccurrence(store, a.id, id);
    const step = o ? fromJson<{ step?: string }>(o.match_basis, {}).step : undefined;
    const out = step ? Q.stepOutputRef(store, step) : null;
    const reasoning = out ? store.artifacts.getJson<{ reasoning?: string }>(out).reasoning ?? null : null;
    return {
      vulnId: id, displayNo: v?.display_no ?? 0, title: v?.title ?? '', severity: (v?.severity ?? 'info') as ReverifyItemDto['severity'], category: v?.category ?? '',
      verdict: (o?.reverify_verdict ?? null) as ReverifyItemDto['verdict'], lifecycleBefore: (o?.lifecycle_before ?? null) as ReverifyItemDto['lifecycleBefore'],
      lifecycleAfter: (o?.lifecycle_after ?? null) as ReverifyItemDto['lifecycleAfter'], reasoning,
    };
  });
}

export function planDto(store: Store, a: AuditRow & { draft_rev?: number }): PlanDto {
  const plan = a.plan_ref ? store.artifacts.getJson<AuditPlan>(a.plan_ref) : null;
  return {
    auditId: a.id, status: a.status, revision: a.draft_rev ?? 1, scene: a.scene as PlanDto['scene'],
    plan: plan ? {
      summary: plan.submitted.summary, focusDirections: plan.submitted.focusDirections, plannedKnowledge: plan.submitted.plannedKnowledge ?? [],
      contextNeeded: plan.submitted.contextNeeded.map((c) => contextItem(c).question), limitations: plan.limitations, scale: plan.scale,
      estimate: {
        tokens: plan.estimate.tokens, durationSec: plan.estimate.durationSec, cost: plan.estimate.cost ?? null,
        ...(plan.estimate.byStage ? { stages: plan.estimate.byStage.map((x) => ({ stage: x.stage, label: stageMeta(x.stage).label, tokens: x.tokens, switch: stageMeta(x.stage).switch ?? null })) } : {}),
      },
      knowledge: plan.knowledge,
      incremental: plan.incremental ?? null,
    } : null,
    strategy: upgradeStrategy(JSON.parse(a.strategy_frozen ?? a.strategy_draft)), strategySources: fromJson(a.strategy_sources, {}),
    mode: a.mode as PlanDto['mode'],
    repos: Q.auditRepos(store, a.id).map((r) => {
      const dirty = Q.snapshotDirty(store, r);
      return { id: r.id, name: r.name, ref: r.requested_ref, commit: r.resolved_commit, worktree: !!r.is_worktree, rootHash: r.root_hash, roleInAudit: r.role_in_audit, ...(dirty !== undefined ? { dirty } : {}) };
    }),
  };
}

export function questionDto(q: { id: string; audit_id: string; text: string; blocking: number; status: string; answer: string | null; save_as_skill?: string; as_fact?: number; options?: string | null; created_at: number; answered_at: number | null }): QuestionDto {
  return {
    id: q.id, auditId: q.audit_id, text: q.text, blocking: !!q.blocking, status: q.status as QuestionDto['status'], answer: q.answer,
    saveAsSkill: (q.save_as_skill ?? 'none') as QuestionDto['saveAsSkill'],
    asFact: !!q.as_fact,
    options: fromJson<string[]>(q.options ?? null, []),
    createdAt: isoReq(q.created_at), answeredAt: iso(q.answered_at),
  };
}

export function eventDto(e: AuditEvent): EventDto {
  return { seq: e.seq, type: e.type, stepId: e.stepId, ts: isoReq(e.ts), payload: e.payload };
}

export function findingDto(store: Store, f: Record<string, any>): FindingDto {
  const vulnId = Q.findingVulnId(store, f.audit_id, f.id);
  const v = vulnId ? Q.vulnHeader(store, vulnId) : undefined;
  const repo = Q.repositoryName(store, f.repository_id) ?? '';
  const loc = fromJson<CodeLocDto>(f.location, { repo, path: '', startLine: 1, endLine: 1 });
  return {
    id: f.id, displayNo: f.display_no, auditId: f.audit_id, title: f.title, category: f.category, cwe: f.cwe, severity: f.severity,
    confidence: f.confidence, state: f.state, repo, location: { ...loc, repo }, vulnId: vulnId ?? null,
    vulnDisplayNo: v?.display_no ?? null, confirmStatus: (v?.confirm_status ?? null) as FindingDto['confirmStatus'],
    lifecycle: (v?.lifecycle ?? null) as FindingDto['lifecycle'], stepId: f.step_id,
  };
}

export function vulnSummary(store: Store, v: Record<string, any>): VulnSummaryDto {
  const repo = Q.repositoryName(store, v.repository_id) ?? '';
  const entryCount = Q.activeEntryCount(store, v.id);
  return {
    id: v.id, projectId: v.project_id, displayNo: v.display_no, title: v.title, category: v.category, cwe: v.cwe, severity: v.severity,
    severityOriginal: v.severity_original, confidence: v.confidence, confirmStatus: v.confirm_status, handlingStatus: v.handling_status,
    lifecycle: v.lifecycle, pendingKind: v.pending_kind, sources: fromJson<string[]>(v.sources, []), repo, module: v.module, boundary: v.boundary ?? null,
    evidenceComplete: !!v.evidence_complete, confirmOverride: !!v.confirm_override, entryCount, firstSeenAuditId: v.first_seen_audit_id, lastSeenAuditId: v.last_seen_audit_id,
    updatedAt: isoReq(v.updated_at), revision: v.rev, suspectedLink: !!v.suspected_link,
    // covered, not found, but nothing verified the fix → suggest reverification.
    reverifySuggested: v.lifecycle !== 'fixed_verified' && Q.latestPresence(store, v.id) === 'not_found_unverified',
    status: v.status, mergedIntoId: v.merged_into_id ?? null,
    mergedIntoNo: v.merged_into_id ? Q.vulnDisplayNo(store, v.merged_into_id) ?? null : null,
    threatRisk: v.threat_risk ? fromJson<VulnSummaryDto['threatRisk']>(v.threat_risk, null) : null,
  };
}

/** Pending "suspected same" links of a vulnerability, with the linked finding and the model's reason. */
export function suspectedMatches(store: Store, vulnId: string): SuspectedMatchDto[] {
  return Q.suspectedMatchRows(store, vulnId).map((r) => ({
    occurrenceId: r.occurrence_id, auditId: r.audit_id, auditTitle: r.audit_title, findingId: r.finding_id, findingNo: r.display_no, findingTitle: r.title,
    location: fromJson<CodeLocDto>(r.location, { repo: '', path: '', startLine: 1, endLine: 1 }), sinkSymbol: r.sink_symbol, sinkApi: r.sink_api,
    entries: fromJson<string[]>(r.entry_keys, []), rootCause: r.root_cause, reason: String(fromJson<{ reason?: string }>(r.match_basis, {}).reason ?? ''),
    createdAt: isoReq(r.created_at),
  }));
}

export function vulnDetail(store: Store, v: Record<string, any>): VulnDetailDto {
  const detail = store.artifacts.getJson<FindingDetail>(v.detail_ref);
  const finding = Q.firstFinding(store, v.id);
  const challenge = finding?.challenge_ref ? store.artifacts.getJson<FindingDetail['challenge']>(finding.challenge_ref) : null;
  const evidence = Q.vulnEvidence(store, v.id);
  const repoOfSnap = (sid: string | null) => (sid ? Q.snapshotRepoName(store, sid) ?? null : null);
  const auditOfSnap = (sid: string | null) => (sid ? Q.snapshotAudit(store, sid) ?? null : null);
  return {
    ...vulnSummary(store, v),
    sinkSymbol: v.sink_symbol, sinkApi: v.sink_api, rootCause: v.root_cause, handlingReason: v.handling_reason,
    pendingCondition: normalizePending(fromJson(v.missing_context, null)),
    entries: Q.vulnEntries(store, v.id).map((e) => ({ key: e.entry_key, state: e.state })),
    suspectedMatches: suspectedMatches(store, v.id),
    fingerprints: Q.vulnFingerprints(store, v.id)
      .map((f) => ({ fp: f.fp, kind: f.kind, active: !!f.active })),
    mergedFrom: Q.mergedFrom(store, v.id)
      .map((m) => ({ id: m.id, displayNo: m.display_no, title: m.title })),
    proposals: Q.proposals(store, v.id)
      .map((r) => ({ revisionId: r.id, dimension: r.dimension, to: r.to_value === null ? null : JSON.parse(r.to_value), reason: r.reason, auditId: r.audit_id, createdAt: isoReq(r.created_at) })),
    layers: {
      evidence: evidence.map((e) => ({
        kind: e.kind, repo: repoOfSnap(e.snapshot_id), path: e.path, startLine: e.start_line, endLine: e.end_line, verified: !!e.verified,
        note: e.note, snapshotId: e.snapshot_id, auditId: auditOfSnap(e.snapshot_id) ?? finding?.audit_id ?? null,
      })),
      reasoning: {
        chain: detail.chain ?? [], reasoning: detail.reasoning ?? '', counterCheck: detail.counterCheck ?? '',
        challenge: challenge ? { verdict: challenge.confirmation, reason: challenge.reason, confidenceDelta: challenge.confidenceDelta, against: [challenge.codeDefense, challenge.threatModel].filter(Boolean).join('\n') || null, affirm: challenge.affirm ?? null } : null,
        consensus: latestConsensus(store, v.id, detail),
      },
      exploit: detail.exploitConditions ?? [],
      attack: detail.attackPath ? { path: detail.attackPath, impact: detail.impact ?? '' } : null,
      fix: detail.remediation ?? { approach: '' },
    },
  };
}

/**
 * The latest cross review of the vulnerability: a later audit that matched it keeps its own finding detail (the
 * vulnerability keeps the first one), so read the newest occurrence that was cross reviewed.
 */
function latestConsensus(store: Store, vid: string, detail: object): VulnDetailDto['layers']['reasoning']['consensus'] {
  for (const ref of Q.recentDetailRefs(store, vid)) {
    const c = consensusOf(store.artifacts.getJson<object>(ref));
    if (c) return c;
  }
  return consensusOf(detail);
}

/** The cross-review record the reconcile step put on the finding detail (engine steps/consensus.ts). */
function consensusOf(detail: object): VulnDetailDto['layers']['reasoning']['consensus'] {
  const c = (detail as { consensus?: { models?: string[]; support?: string[]; conflicts?: { model: string; verdict: string; reason: string }[]; unavailable?: string[] } }).consensus;
  if (!c?.models?.length && !c?.unavailable?.length) return null;
  return {
    models: c.models ?? [], support: c.support ?? [], conflicts: (c.conflicts ?? []).map((x) => ({ model: x.model, verdict: x.verdict, reason: x.reason })), unavailable: c.unavailable ?? [],
  };
}

export function revisionDto(store: Store, r: {
  id: string; seq: number; dimension: string; source: string; actor: string; from_value: string | null; to_value: string | null; reason: string | null; state: string;
  audit_id: string | null; created_at: number; review_ms?: number | null; review_batch?: number | null;
}): RevisionDto {
  return {
    id: r.id, seq: r.seq, dimension: r.dimension, source: r.source, actor: r.actor, from: fromJson(r.from_value, null), to: fromJson(r.to_value, null),
    reason: r.reason, state: r.state, auditId: r.audit_id, createdAt: isoReq(r.created_at), undoable: identityUndoable(store, r),
    reviewMs: r.review_ms ?? null, reviewBatch: r.review_batch ?? null,
  };
}

/** Mirror of the engine rule: a merge/split is undoable while it is the latest identity change of all involved. */
function identityUndoable(store: Store, r: { dimension: string; to_value: string | null }): boolean {
  if (r.dimension !== 'identity' || !r.to_value) return false;
  const op = fromJson<{ op?: string; source?: string; target?: string; created?: string } | null>(r.to_value, null);
  if (!op || (op.op !== 'merge' && op.op !== 'split')) return false;
  const involved = op.op === 'merge' ? [op.source, op.target] : [op.source, op.created];
  return involved.every((vid) => Q.latestIdentityChange(store, vid ?? '') === r.to_value);
}
