// Run-time interaction and human review: question answers, user
// interventions and vulnerability review. User text is data, never a control instruction (P8):
// it reaches models only as clearly-labelled context via steer or the cognitive-state slice.
import {
  AppError, isDeferAnswer, upgradeStrategy, CONFIRM_STATUSES, HANDLING_STATUSES, SEVERITIES, type ConfirmStatus, type HandlingStatus, type InterventionKind, type Severity,
} from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { loadState, saveState, type CognitiveState } from './cognitive.js';
import type { Engine } from './engine.js';
import { getAudit, listSteps, sessionLimit, transitionStep, USER_SKIPPED_MARK } from './state.js';
import { addRevision, settleRevisionCards } from './vulns.js';
import { P } from '@xiezhi/knowledge';
import { factFromAnswer } from './facts.js';

const TERMINAL = ['completed', 'partial', 'failed', 'cancelled'];

/** Wrap user-provided text so the model treats it as data. */
export function userDataBlock(label: string, text: string): string {
  const clean = text.replace(/<\/?user_data[^>]*>/gi, '');
  return `${P('data.user_data', { label })}\n<user_data>\n${clean}\n</user_data>`;
}

function appendUserItem(store: Store, auditId: string, field: keyof CognitiveState, text: string, ref: string): void {
  store.tx(() => {
    const { version, state } = loadState(store, auditId);
    state[field].push({ id: `USER-${ref}`, text, source: 'user', stepId: ref });
    saveState(store, auditId, version + 1, ref, state);
  });
}

export async function answerQuestion(engine: Engine, questionId: string, answer: string): Promise<{ routed: 'steer' | 'state' | 'closed_audit'; factId?: string }> {
  const store = engine.store;
  const text = answer.trim();
  if (!text) throw new AppError('COMMON_VALIDATION', 'answer is empty');
  if (text.length > 8000) throw new AppError('COMMON_VALIDATION', 'answer too long (max 8000 chars)');
  const q = store.get<{ id: string; audit_id: string; text: string; status: string }>('SELECT id, audit_id, text, status FROM question WHERE id = ?', questionId);
  if (!q) throw new AppError('QUESTION_NOT_FOUND', questionId);
  if (q.status !== 'open') throw new AppError('QUESTION_CLOSED', q.status);
  const audit = getAudit(store, q.audit_id);
  let routed: 'steer' | 'state' | 'closed_audit' = 'closed_audit';
  // “让 Agent 自行查询”: steer the agent, but it is not something the user stated (no confirmed fact, no project fact).
  const deferred = isDeferAnswer(text);
  store.tx(() => {
    store.update('question', { id: q.id }, { status: 'answered', answer: text, answered_at: Date.now(), save_as_skill: 'offered' });
    if (!TERMINAL.includes(audit.status) && !deferred) {
      appendUserItem(store, q.audit_id, 'confirmedFacts', `用户回答（未经代码核实）：问「${q.text.slice(0, 300)}」答「${text.slice(0, 1500)}」`, q.id);
      routed = 'state';
    }
  });
  if (!TERMINAL.includes(audit.status)) {
    const n = await engine.steer(q.audit_id, userDataBlock(`用户对提问「${q.text.slice(0, 300)}」的回答`, text));
    if (n > 0) routed = 'steer';
  }
  // an answered plan-context question becomes an enterprise fact of the project.
  const fact = factFromAnswer(store, q.id, 'user');
  store.appendEvent(q.audit_id, 'question.answered', { question_id: q.id, text: text.slice(0, 500), routed, ...(fact ? { fact_id: fact.id } : {}) });
  return { routed, ...(fact ? { factId: fact.id } : {}) };
}

export function dismissQuestion(store: Store, questionId: string): void {
  const q = store.get<{ id: string; audit_id: string; status: string }>('SELECT id, audit_id, status FROM question WHERE id = ?', questionId);
  if (!q) throw new AppError('QUESTION_NOT_FOUND', questionId);
  if (q.status !== 'open') throw new AppError('QUESTION_CLOSED', q.status);
  store.tx(() => {
    store.update('question', { id: q.id }, { status: 'dismissed', answered_at: Date.now() });
    store.appendEvent(q.audit_id, 'question.answered', { question_id: q.id, dismissed: true, routed: 'none' });
  });
}

export interface InterventionInput { kind: InterventionKind; text: string; target?: string }

/**
 * Interventions. Never modify the frozen strategy: supplement / refocus / deep_dive
 * are steered into running sessions and recorded in the cognitive state for later steps; skip with
 * a pending step id as target marks that step skipped (USER_SKIPPED in the gate).
 */
export async function intervene(engine: Engine, auditId: string, input: InterventionInput): Promise<{ applied: string[] }> {
  const store = engine.store;
  const a = getAudit(store, auditId);
  if (TERMINAL.includes(a.status)) throw new AppError('AUDIT_INVALID_TRANSITION', `audit is ${a.status}`);
  const text = input.text.trim();
  if (!text && input.kind !== 'skip') throw new AppError('COMMON_VALIDATION', 'text is required');
  if (text.length > 8000) throw new AppError('COMMON_VALIDATION', 'text too long (max 8000 chars)');
  const ev = store.appendEvent(auditId, 'intervention.received', { kind: input.kind, text: text.slice(0, 1000), ...(input.target ? { target: input.target } : {}) });
  const ref = `I${ev.seq}`;
  const applied: string[] = [];
  if (input.kind === 'skip' && input.target) {
    const step = listSteps(store, auditId).find((s) => s.id === input.target);
    if (!step) throw new AppError('COMMON_NOT_FOUND', `step ${input.target}`);
    if (!['pending', 'interrupted', 'retry_wait', 'blocked_budget', 'ready'].includes(step.status) || step.required) {
      throw new AppError('AUDIT_INVALID_TRANSITION', `step ${step.kind} is ${step.status}${step.required ? ' (required)' : ''}`);
    }
    transitionStep(store, step.id, 'skipped', { error_summary: USER_SKIPPED_MARK }, 'skipped by user');
    applied.push('step_skipped');
  } else {
    const label = { supplement: '用户补充的信息', refocus: '用户调整的审计重点', skip: '用户要求跳过的范围', deep_dive: '用户要求深入分析的疑点' }[input.kind];
    const field: keyof CognitiveState = input.kind === 'supplement' ? 'confirmedFacts' : input.kind === 'skip' ? 'ruledOutDirections' : 'activeHypotheses';
    appendUserItem(store, auditId, field, `${label}（未经代码核实）：${text.slice(0, 1500)}`, ref);
    applied.push('state');
    const n = await engine.steer(auditId, userDataBlock(label, text));
    if (n > 0) applied.push('steer');
  }
  store.appendEvent(auditId, 'intervention.applied', { kind: input.kind, ref, applied });
  return { applied };
}

/**
 * Change how many agent sessions an audit runs at once: 1 to the global model-request limit.
 * Recorded in the trajectory as an intervention (a resumed run re-applies it; the frozen strategy stays immutable)
 * and applied at once to a run in this process.
 */
export function setAuditConcurrency(engine: Engine, auditId: string, sessions: number): { from: number; to: number; live: boolean } {
  const store = engine.store;
  const a = getAudit(store, auditId);
  if (TERMINAL.includes(a.status)) throw new AppError('AUDIT_INVALID_TRANSITION', `audit is ${a.status}`);
  const max = Math.min(16, store.config.concurrency.modelRequests);
  if (!Number.isInteger(sessions) || sessions < 1 || sessions > max) throw new AppError('COMMON_VALIDATION', `sessions must be 1–${max} (the global model-request limit)`);
  const strategy = upgradeStrategy(JSON.parse(a.strategy_frozen ?? a.strategy_draft));
  const from = sessionLimit(store, auditId, strategy.concurrency.sessions);
  // The frozen strategy is immutable: the new limit is recorded as an intervention and re-applied from it on resume.
  const ev = store.appendEvent(auditId, 'intervention.received', { kind: 'concurrency', text: `并发会话数 ${from} → ${sessions}`, from, to: sessions });
  const live = engine.applyConcurrency(auditId, sessions);
  store.appendEvent(auditId, 'intervention.applied', { kind: 'concurrency', ref: `I${ev.seq}`, applied: live ? ['recorded', 'live'] : ['recorded'] });
  return { from, to: sessions, live };
}

export interface VulnReview {
  confirmStatus?: ConfirmStatus; handlingStatus?: HandlingStatus; severity?: Severity; reason?: string;
  /** G1: ms the person spent on this decision, measured by the client; stored on the first revision written. */
  reviewMs?: number;
  /** Size of the batch this decision belongs to (batch actions); absent for a single-item decision. */
  reviewBatch?: number;
}

/** Upper bound of a recorded review duration (24 h); longer values are clamped (a panel left open overnight). */
export const MAX_REVIEW_MS = 86_400_000;

/** Marks the revision of a confirmation made without complete evidence. */
export const CONFIRM_OVERRIDE_NOTE = '证据不完整，人工确认';

/**
 * Human review with optimistic concurrency. Every changed dimension is a
 * revision with source=human. `confirmed` needs complete evidence, or a reason when the person confirms
 * without it (`confirm_override`; batch review keeps the strict rule, `strictEvidence`); false
 * positive and accepted risk need a reason; a severity change keeps the original value.
 */
export function reviewVulnerability(store: Store, vulnId: string, patch: VulnReview, expectedRev: number, actor = 'user', opts: { strictEvidence?: boolean } = {}): { rev: number; revisionIds: string[] } {
  return store.tx(() => {
    const v = store.get<{
      id: string; rev: number; confirm_status: ConfirmStatus; handling_status: HandlingStatus; severity: Severity; severity_original: Severity | null;
      evidence_complete: number; status: string;
    }>('SELECT id, rev, confirm_status, handling_status, severity, severity_original, evidence_complete, status FROM vulnerability WHERE id = ?', vulnId);
    if (!v) throw new AppError('VULN_NOT_FOUND', vulnId);
    if (v.rev !== expectedRev) throw new AppError('COMMON_REVISION_CONFLICT', `current revision ${v.rev}`, { revision: v.rev });
    const reason = patch.reason?.trim() ?? '';
    const changes: Record<string, unknown> = {};
    const revisionIds: string[] = [];
    if (patch.confirmStatus !== undefined && patch.confirmStatus !== v.confirm_status) {
      if (!CONFIRM_STATUSES.includes(patch.confirmStatus)) throw new AppError('COMMON_VALIDATION', 'confirmStatus');
      const override = patch.confirmStatus === 'confirmed' && !v.evidence_complete;
      if (override && (opts.strictEvidence || !reason)) throw new AppError('VULN_EVIDENCE_INCOMPLETE', opts.strictEvidence ? 'batch confirm needs complete evidence' : 'confirming without complete evidence needs a reason');
      if (patch.confirmStatus === 'false_positive' && !reason) throw new AppError('VULN_REASON_REQUIRED', 'false positive needs a reason');
      changes.confirm_status = patch.confirmStatus;
      changes.confirm_override = override ? 1 : 0;
      changes.pending_kind = patch.confirmStatus === 'pending' ? 'insufficient_evidence' : null;
      revisionIds.push(addRevision(store, vulnId, { dimension: 'confirm', source: 'human', actor, from: v.confirm_status, to: patch.confirmStatus, reason: override ? `${CONFIRM_OVERRIDE_NOTE}：${reason}` : reason || 'human review' }));
      store.db.run(`UPDATE revision SET state = CASE WHEN to_value = ? THEN 'applied' ELSE 'rejected' END WHERE vulnerability_id = ? AND dimension = 'confirm' AND state = 'proposed'`,
        JSON.stringify(patch.confirmStatus), vulnId);
    }
    if (patch.handlingStatus !== undefined && patch.handlingStatus !== v.handling_status) {
      if (!HANDLING_STATUSES.includes(patch.handlingStatus)) throw new AppError('COMMON_VALIDATION', 'handlingStatus');
      if (patch.handlingStatus === 'risk_accepted' && !reason) throw new AppError('VULN_REASON_REQUIRED', 'accepting risk needs a reason');
      changes.handling_status = patch.handlingStatus;
      changes.handling_reason = reason || null;
      revisionIds.push(addRevision(store, vulnId, { dimension: 'handling', source: 'human', actor, from: v.handling_status, to: patch.handlingStatus, reason: reason || 'human review' }));
      // A human handling decision settles open proposals: the matching one is applied,
      // the others are rejected.
      store.db.run(`UPDATE revision SET state = CASE WHEN to_value = ? THEN 'applied' ELSE 'rejected' END WHERE vulnerability_id = ? AND dimension = 'handling' AND state = 'proposed'`,
        JSON.stringify(patch.handlingStatus), vulnId);
    }
    if (patch.severity !== undefined && patch.severity !== v.severity) {
      if (!SEVERITIES.includes(patch.severity)) throw new AppError('COMMON_VALIDATION', 'severity');
      changes.severity = patch.severity;
      if (!v.severity_original) changes.severity_original = v.severity;
      revisionIds.push(addRevision(store, vulnId, { dimension: 'severity', source: 'human', actor, from: v.severity, to: patch.severity, reason: reason || 'human review' }));
      store.db.run(`UPDATE revision SET state = CASE WHEN to_value = ? THEN 'applied' ELSE 'rejected' END WHERE vulnerability_id = ? AND dimension = 'severity' AND state = 'proposed'`,
        JSON.stringify(patch.severity), vulnId);
    }
    if (Object.keys(changes).length === 0) return { rev: v.rev, revisionIds };
    store.update('vulnerability', { id: vulnId }, changes);
    // All dimensions written: settle the conversation cards this review completed.
    settleRevisionCards(store, vulnId);
    // G1: one duration per decision, on its first revision, so a decision that changes two dimensions counts once.
    if (patch.reviewMs !== undefined && Number.isFinite(patch.reviewMs) && patch.reviewMs >= 0) {
      store.db.run('UPDATE revision SET review_ms = ?, review_batch = ? WHERE id = ?',
        Math.min(Math.round(patch.reviewMs), MAX_REVIEW_MS), patch.reviewBatch ?? null, revisionIds[0]!);
    }
    return { rev: store.get<{ rev: number }>('SELECT rev FROM vulnerability WHERE id = ?', vulnId)!.rev, revisionIds };
  });
}

type ReviewedValues = { confirmStatus?: ConfirmStatus; handlingStatus?: HandlingStatus; severity?: Severity };

/**
 * Apply an AI revision suggestion (conversation card) as the person's review.
 * The suggestion is stale only when a dimension it changes no longer has the value it was made against; other
 * changes since then (a later audit moving the lifecycle, a severity edit when the card only confirms) leave it
 * valid, so the whole-vulnerability revision is not compared.
 */
export function applyRevisionSuggestion(store: Store, input: { vulnId: string; from: ReviewedValues; to: ReviewedValues; reason: string; actor?: string }): { rev: number; revisionIds: string[] } {
  return store.tx(() => {
    const v = store.get<{ rev: number; confirm_status: ConfirmStatus; handling_status: HandlingStatus; severity: Severity }>(
      'SELECT rev, confirm_status, handling_status, severity FROM vulnerability WHERE id = ?', input.vulnId);
    if (!v) throw new AppError('VULN_NOT_FOUND', input.vulnId);
    const now: ReviewedValues = { confirmStatus: v.confirm_status, handlingStatus: v.handling_status, severity: v.severity };
    const keys = (Object.keys(input.to) as (keyof ReviewedValues)[]).filter((k) => input.to[k] !== undefined);
    // a dimension already at the proposed value (set elsewhere) is done, not a conflict; only a third value
    // is, and only the dimensions still open are written.
    const changed = keys.filter((k) => now[k] !== input.from[k] && now[k] !== input.to[k]);
    if (changed.length) throw new AppError('COMMON_REVISION_CONFLICT', `changed since the suggestion: ${changed.join(', ')}`, { revision: v.rev, changed });
    const open = Object.fromEntries(keys.filter((k) => now[k] !== input.to[k]).map((k) => [k, input.to[k]])) as ReviewedValues;
    return reviewVulnerability(store, input.vulnId, { ...open, reason: input.reason }, v.rev, input.actor ?? 'user');
  });
}

export interface BatchReviewInput {
  items: { id: string; revision: number }[];
  confirmStatus?: ConfirmStatus; handlingStatus?: HandlingStatus; reason?: string;
  /** Elapsed ms of the whole batch (selection → apply); split evenly over the items it changed. */
  reviewMs?: number;
}
export interface BatchReviewResult { id: string; ok: boolean; revision?: number; code?: string; unchanged?: boolean }

/**
 * Batch review: the single-item rules apply to each item on its own —
 * confirming needs complete evidence, a false positive or accepted risk needs a reason (one shared
 * reason for the batch), each item needs its current revision. Ineligible items are reported with
 * their error code and left unchanged; every changed item gets its own revisions.
 */
export function batchReviewVulnerabilities(store: Store, input: BatchReviewInput, actor = 'user'): BatchReviewResult[] {
  if (input.confirmStatus === undefined && input.handlingStatus === undefined) throw new AppError('COMMON_VALIDATION', 'confirmStatus or handlingStatus is required');
  if (new Set(input.items.map((i) => i.id)).size !== input.items.length) throw new AppError('COMMON_VALIDATION', 'duplicate vulnerability ids');
  const patch: VulnReview = {
    ...(input.confirmStatus !== undefined ? { confirmStatus: input.confirmStatus } : {}),
    ...(input.handlingStatus !== undefined ? { handlingStatus: input.handlingStatus } : {}),
    ...(input.reason ? { reason: input.reason } : {}),
  };
  const firstRevision = new Map<string, string>();
  const results = input.items.map((it): BatchReviewResult => {
    try {
      const r = reviewVulnerability(store, it.id, patch, it.revision, actor, { strictEvidence: true });
      if (!r.revisionIds.length) return { id: it.id, ok: true, revision: r.rev, unchanged: true };
      firstRevision.set(it.id, r.revisionIds[0]!);
      return { id: it.id, ok: true, revision: r.rev };
    } catch (e) {
      if (!(e instanceof AppError)) throw e;
      return { id: it.id, ok: false, code: e.code };
    }
  });
  if (input.reviewMs !== undefined && Number.isFinite(input.reviewMs) && input.reviewMs >= 0 && firstRevision.size) {
    const per = Math.round(Math.min(input.reviewMs, MAX_REVIEW_MS * firstRevision.size) / firstRevision.size);
    store.tx(() => {
      for (const id of firstRevision.values()) store.db.run('UPDATE revision SET review_ms = ?, review_batch = ? WHERE id = ?', Math.min(per, MAX_REVIEW_MS), firstRevision.size, id);
    });
  }
  return results;
}

export interface ReviewTimingStats { count: number; medianMs: number | null; meanMs: number | null }
export interface ReviewStats {
  /** Decisions made one at a time from the detail panel. */
  single: ReviewTimingStats;
  /** Items decided in batch actions (per-item share of the batch time) and how many batches. */
  batch: ReviewTimingStats & { batches: number };
  /** Human confirm / false-positive decisions, timed or not (G1 online: share marked false positive). */
  decisions: { confirmed: number; falsePositive: number };
}

function timing(ms: number[]): ReviewTimingStats {
  if (!ms.length) return { count: 0, medianMs: null, meanMs: null };
  const s = [...ms].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return { count: s.length, medianMs: s.length % 2 ? s[mid]! : Math.round((s[mid - 1]! + s[mid]!) / 2), meanMs: Math.round(s.reduce((a, b) => a + b, 0) / s.length) };
}

/**
 * G1 online metric: human review time per decision of a project's vulnerabilities
 * (active or merged since), from the revisions that carry a client-measured duration.
 */
export function reviewStats(store: Store, projectId: string): ReviewStats {
  const rows = store.all<{ review_ms: number; review_batch: number | null }>(
    `SELECT r.review_ms, r.review_batch FROM revision r JOIN vulnerability v ON v.id = r.vulnerability_id
     WHERE v.project_id = ? AND r.source = 'human' AND r.review_ms IS NOT NULL`, projectId);
  const single = rows.filter((r) => r.review_batch === null).map((r) => r.review_ms);
  const batch = rows.filter((r) => r.review_batch !== null);
  const decided = store.all<{ to_value: string; n: number }>(
    `SELECT r.to_value, COUNT(*) AS n FROM revision r JOIN vulnerability v ON v.id = r.vulnerability_id
     WHERE v.project_id = ? AND r.source = 'human' AND r.dimension = 'confirm' AND r.state = 'applied' GROUP BY r.to_value`, projectId);
  const n = (to: string) => decided.find((d) => d.to_value === JSON.stringify(to))?.n ?? 0;
  return {
    single: timing(single),
    // Each item of a batch carries the batch's changed-item count, so the sum of 1/size is the number of batches.
    batch: { ...timing(batch.map((r) => r.review_ms)), batches: Math.round(batch.reduce((a, r) => a + 1 / r.review_batch!, 0)) },
    decisions: { confirmed: n('confirmed'), falsePositive: n('false_positive') },
  };
}
