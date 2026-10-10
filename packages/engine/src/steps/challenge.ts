// Adversarial review (was challenge + independent review): after reconcile, one fresh
// session per canonical finding argues against it. It sees the claim and where the evidence is, not the hunt's
// reasoning (the evidence lines as code snippets and the pending condition; the finder's reasoning only
// through a query tool, read when the reviewer wants it), plus the counter-evidence of the audit: other members of its cluster, other models' or the other
// line's ruled-out places, refuted hypotheses nearby, cross-review conflicts. Verdict maintain / pending / refuted;
// it can never delete a finding — refuted makes it “待确认” with lower confidence and both sides kept.
import { Type } from 'typebox';
import { placeholderPendingIssues, SubmitChallenge, type CodeRef, type PendingCondition, type SubmitChallenge as Verdict } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import { fromJson } from '@xiezhi/store';
import { confidenceTier } from '../identity.js';
import { pendingOf } from '../vulns.js';
import { insertConnectorEvidence } from '../connector-access.js';
import type { AuditRuntime } from '../runtime.js';
import { sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { pendingClueIssues, validateCodeRef } from './hunt.js';
import type { EdgeLink, EvidenceCheck } from '../evidence.js';
import { P } from '@xiezhi/knowledge';

const EDGE_TEXT: Record<EdgeLink, string> = {
  same_function: '同一函数内', resolved: '索引中有确定的调用边', heuristic: '索引中只有启发式调用边（按名称匹配）',
  not_in_index: '索引中没有调用边', unknown: '无法定位到函数，未核对',
};

/** Confidence a refuted finding loses at least (it stays at or above minConfidence: a person decides). */
export const REFUTED_DELTA = -0.3;
const NEAR = 20;

/** Counter-evidence and the other members of the finding's cluster, for the review prompt. */
function counterEvidence(rt: AuditRuntime, findingId: string, loc: CodeRef & { repo: string }, detail: Record<string, unknown>): string[] {
  const store = rt.store;
  const out: string[] = [];
  const members = store.all<{ lineage_id: string; title: string; model: string | null; location: string }>(
    `SELECT f.lineage_id, f.title, f.model, f.location FROM finding_merge m JOIN finding f ON f.id = m.source_finding_id WHERE m.target_finding_id = ? ORDER BY f.lineage_id`, findingId);
  if (members.length) {
    out.push('', P('challenge.cluster_heading', { n: members.length }));
    for (const m of members.slice(0, 10)) {
      const l = fromJson<CodeRef>(m.location, { path: '', startLine: 0, endLine: 0 });
      out.push(`- ${m.lineage_id}${m.model ? `（${m.model}）` : ''}：${m.title} @ ${l.path}:${l.startLine}`);
    }
  }
  const against: string[] = [];
  const consensus = detail.consensus as { conflicts?: { model: string; verdict: string; reason: string }[] } | undefined;
  for (const c of consensus?.conflicts ?? []) against.push(`- 模型 ${c.model} 在同一危险点的结论为 ${c.verdict}：${c.reason.slice(0, 300)}`);
  const near = (id: string) => {
    const m = /^([^:]+):(.+?)#L(\d+)/.exec(id);
    return !!m && m[2] === loc.path && Math.abs(Number(m[3]) - loc.startLine) <= NEAR;
  };
  const outputs = store.all<{ output_ref: string; lineage_id: string | null }>(
    `SELECT output_ref, lineage_id FROM step WHERE audit_id = ? AND kind IN ('hunt','coverage-gap') AND status = 'succeeded' AND output_ref IS NOT NULL AND (lineage_id IS NULL OR lineage_id NOT LIKE 'LEAD-%') ORDER BY seq`, rt.auditId);
  for (const o of outputs) {
    const h = store.artifacts.getJson<{ model?: string; ruledOut?: { targetId: string; reason: string }[] }>(o.output_ref);
    for (const r of h.ruledOut ?? []) if (near(r.targetId) && against.length < 15) against.push(`- ${o.lineage_id ?? '追查'}${h.model ? `（${h.model}）` : ''}排除了附近的 ${r.targetId}：${r.reason.slice(0, 300)}`);
  }
  const hyps = store.all<{ statement: string; attempts: string; location: string | null }>(
    `SELECT statement, attempts, location FROM hypothesis WHERE audit_id = ? AND status = 'refuted' AND location IS NOT NULL`, rt.auditId);
  for (const h of hyps) {
    const l = fromJson<CodeRef>(h.location, { path: '', startLine: 0, endLine: 0 });
    if (l.path === loc.path && Math.abs(l.startLine - loc.startLine) <= NEAR && against.length < 20) against.push(`- 被反驳的风险假设“${h.statement.slice(0, 150)}”：${h.attempts.slice(0, 300)}`);
  }
  if (against.length) out.push('', P('challenge.counter_heading'), ...against);
  return out;
}

interface FindingRow { id: string; title: string; category: string; severity: string; confidence_score: number; location: string; entry_keys: string; root_cause: string; detail_ref: string; repository_id: string }

/** Turns of a light review; a full review has up to 40. */
export const LIGHT_REVIEW_TURNS = 12;

/**
 * The review tier of a finding: full for critical / high findings that are not pending, light for
 * the others; every finding is full with `stages.tieredReview: false`.
 */
/**
 * The review tier by dispute (replaces the earlier "pending findings get the light review"): every
 * critical / high finding and every finding the hunt models disagreed on (cross-check conflicts) gets the full review;
 * the rest the light one.
 */
export function reviewTier(s: { stages: { tieredReview?: boolean } }, f: { severity: string; conflicted?: boolean }): 'full' | 'light' {
  if (s.stages.tieredReview === false) return 'full';
  return f.severity === 'critical' || f.severity === 'high' || f.conflicted ? 'full' : 'light';
}

/** Lines per evidence snippet and in all. */
export const SNIPPET_LINES = 15;
export const SNIPPET_TOTAL_LINES = 120;

/** The cited lines (location first, then evidence and chain), numbered; audited code, so it goes in the data boundary. */
export function evidenceSnippets(rt: AuditRuntime, refs: (CodeRef & { repo?: string })[]): string {
  const seen = new Set<string>();
  const out: string[] = [];
  let total = 0;
  for (const r of refs) {
    const repo = rt.repoByName(r.repo ?? '') ?? rt.targetRepo;
    const view = rt.views.get(repo.name);
    if (!view) continue;
    let rel: string;
    try { rel = view.guard(r.path); } catch { continue; }
    const start = Math.max(1, r.startLine);
    const end = Math.min(r.endLine, start + SNIPPET_LINES - 1);
    const key = `${repo.name}:${rel}:${start}`;
    if (seen.has(key) || !view.validRange(rel, start, end)) continue;
    seen.add(key);
    if (total + (end - start + 1) > SNIPPET_TOTAL_LINES) break;
    total += end - start + 1;
    out.push(`### ${repo.name}:${rel}:${start}-${end}`, ...view.lines(rel).slice(start - 1, end).map((l, i) => `${String(start + i).padStart(5)}  ${l}`), '');
  }
  return out.join('\n');
}

/** The pending condition of the claim, for the reviewer to settle. */
export function pendingLines(pc: PendingCondition | undefined): string[] {
  if (!pc) return [];
  const cond = (c: unknown) => (typeof c === 'string' ? c : (c as { statement?: string; condition?: string }).statement ?? (c as { condition?: string }).condition ?? JSON.stringify(c));
  return [
    '', P('challenge.pending_heading'),
    ...pc.missing.map((m) => `- 缺少（${m.kind}）：${m.ref}${m.hint ? `：${m.hint}` : ''}`),
    `- 成立条件：${pc.holdsIf.map(cond).join('；')}`,
    `- 不成立条件：${pc.refutedIf.map(cond).join('；')}`,
    `- 成立时严重度：${pc.severityIfHolds}`,
  ];
}

/** The finder's reasoning on demand: not in the prompt, so the reviewer starts from the code. */
function reasoningTool(detail: Record<string, unknown>): AuditTool {
  return {
    name: 'finding_reasoning', kind: 'read',
    description: P('tool.finding_reasoning'),
    parameters: Type.Object({}, { additionalProperties: false }),
    run: () => ({ text: [`推理：${String(detail.reasoning ?? '（未提供）')}`, `发现者的反向检查：${String(detail.counterCheck ?? '（未提供）')}`].join('\n').slice(0, 6000) }),
  };
}

export async function challengeStep(rt: AuditRuntime, findingId: string, ctx: AttemptContext, opts: { model?: import('@xiezhi/contracts').ModelRef; vote?: boolean; light?: boolean } = {}): Promise<StepResult> {
  const f = rt.store.get<FindingRow>('SELECT * FROM finding WHERE id = ?', findingId);
  if (!f) throw new Error(`finding ${findingId} not found`);
  const detail = rt.store.artifacts.getJson<Record<string, unknown>>(f.detail_ref);
  const submit: AuditTool = {
    name: 'submit_challenge', kind: 'submit', parameters: SubmitChallenge,
    description: P('tool.submit_challenge'),
    validate: (a: Verdict) => [
      ...(a.confirmation === 'refuted' && !(a.evidence ?? []).length ? [P('feedback.challenge.refuted_evidence')] : []),
      ...(a.evidence ?? []).flatMap((e, i) => validateCodeRef(rt, e, `evidence[${i}]`, true)),
      ...(a.confirmation === 'pending' ? placeholderPendingIssues(a.pendingCondition, 'submit_challenge') : []),
      ...(a.confirmation === 'pending' ? pendingClueIssues(rt, a.pendingCondition, 'submit_challenge') : []),
      ...(a.confirmation === 'pending' && !a.pendingCondition ? [P('feedback.challenge.pending_condition')] : []),
    ],
    run: () => ({ text: 'accepted' }),
  };
  const model = opts.model ?? rt.strategy.models.challenge ?? rt.strategy.models.audit;
  const loc = fromJson<{ repo: string; path: string; startLine: number; endLine: number }>(f.location, { repo: '', path: '', startLine: 1, endLine: 1 });
  const claim = detail as {
    attackPath?: string; impact?: string; exploitConditions?: { condition: string; status: string }[]; evidence?: CodeRef[]; chain?: CodeRef[];
    missingCheck?: { location: CodeRef; expected: string }; evidenceCheck?: EvidenceCheck; pendingCondition?: PendingCondition;
  };
  // the engine's check of the claim, refuted item by item.
  const ec = claim.evidenceCheck;
  const checklist = ec ? [
    '', P('challenge.evidence_check_heading'),
    ...ec.edges.map((e) => `- 调用 ${e.from} → ${e.to}：${EDGE_TEXT[e.link]}`),
    ...(claim.missingCheck ? [`- 应有的检查：${claim.missingCheck.location.path}:${claim.missingCheck.location.startLine}-${claim.missingCheck.location.endLine}，应校验：${claim.missingCheck.expected}`] : []),
    ...(ec.gaps.length ? ['缺口：', ...ec.gaps.map((g) => `- ${g}`), P('challenge.gap_rule')] : []),
  ] : [];
  const where = [...(claim.evidence ?? []), ...(claim.chain ?? [])].slice(0, 20).map((e) => `- ${e.repo ?? loc.repo}:${e.path}:${e.startLine}-${e.endLine}${e.note ? `（${e.note.slice(0, 100)}）` : ''}`);
  const prompt = [
    P('challenge.intro'),
    ...(opts.light ? [P('challenge.light', { turns: LIGHT_REVIEW_TURNS })] : []),
    P('challenge.rules'),
    '',
    `发现：${f.title}（${f.category}，严重度 ${f.severity}，置信度 ${f.confidence_score}）`,
    `危险点：${loc.repo}:${loc.path}:${loc.startLine}-${loc.endLine}`,
    `入口：${fromJson<string[]>(f.entry_keys, []).join('、') || '（未给出）'}`,
    `根因：${f.root_cause}`,
    ...(claim.attackPath ? [`攻击路径：${claim.attackPath}`] : []),
    ...(claim.impact ? [`影响：${claim.impact}`] : []),
    ...(claim.exploitConditions?.length ? [`前置条件：${claim.exploitConditions.map((c) => `${c.condition}（${c.status}）`).join('；')}`] : []),
    ...(where.length ? ['证据位置：', ...where] : []),
    ...checklist,
    ...pendingLines(claim.pendingCondition),
    ...counterEvidence(rt, findingId, loc, detail),
  ].join('\n');
  const snippets = evidenceSnippets(rt, [loc, ...(claim.evidence ?? []), ...(claim.chain ?? []), ...(claim.missingCheck ? [claim.missingCheck.location] : [])]);
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'challenge', phase: 'challenge', model, signal: ctx.signal, prompt,
    submitTools: [submit], requiredSubmits: ['submit_challenge'], maxTurns: Math.min(opts.light ? LIGHT_REVIEW_TURNS : 40, rt.strategy.limits.maxTurnsPerStep),
    extraTools: [reasoningTool(detail)],
    // the evidence lines are audited code — scanned and wrapped in the data boundary after the prompt.
    ...(snippets ? { untrustedPrompt: [{ source: 'evidence', text: snippets }] } : {}),
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const submitted = (outcome.submissions.submit_challenge as Verdict[]).at(-1)!;
  const knowledge = rt.knowledgeRefs(ctx.stepId, submitted.knowledgeRefs);
  const connectors = rt.connectorRefs(ctx.stepId, submitted.connectorRefs);
  const verdict: ReviewVerdict = { ...submitted, knowledge, connectors, model: `${model.provider}/${model.model}` };
  const outputRef = rt.store.artifacts.putJson(verdict);
  // Cross-checked review: each model's verdict is a vote; combineReviews applies them together.
  if (opts.vote) return { outputRef };
  return { outputRef, apply: () => applyReview(rt, findingId, verdict, outputRef, ctx.stepId) };
}

type KnowledgeRef = ReturnType<AuditRuntime['knowledgeRefs']>[number];
type ConnectorRef = ReturnType<AuditRuntime['connectorRefs']>[number];
export type ReviewVerdict = Verdict & { knowledge: KnowledgeRef[]; connectors: ConnectorRef[]; model: string; votes?: Omit<ReviewVerdict, 'votes'>[] };

/**
 * Several models reviewed the same finding: votes never decide by themselves — any refuted vote
 * makes it refuted (pending, both sides kept for a person), any pending vote makes it pending, otherwise it is
 * maintained; the confidence moves by the mean adjustment. Deterministic; runs once per finding.
 */
export function combineReviews(rt: AuditRuntime, findingId: string, ctx: AttemptContext): StepResult {
  const outs = rt.store.all<{ output_ref: string; input: string }>(
    `SELECT output_ref, input FROM step WHERE audit_id = ? AND kind = 'challenge' AND status = 'succeeded' AND output_ref IS NOT NULL ORDER BY seq`, rt.auditId)
    .filter((x) => { const i = fromJson<{ findingId?: string; vote?: boolean }>(x.input, {}); return i.findingId === findingId && i.vote === true; })
    .map((x) => rt.store.artifacts.getJson<ReviewVerdict>(x.output_ref));
  if (!outs.length) return { outputRef: rt.store.artifacts.putJson({ votes: [] }) };
  const pick = (c: string) => outs.filter((v) => v.confirmation === c);
  const confirmation = pick('refuted').length ? 'refuted' : pick('pending').length ? 'pending' : 'maintain';
  const lead = pick(confirmation)[0]!;
  const combined: ReviewVerdict = {
    ...lead, confirmation,
    confidenceDelta: outs.reduce((n, v) => n + v.confidenceDelta, 0) / outs.length,
    codeDefense: outs.map((v) => `【${v.model}】${v.codeDefense}`).join('\n').slice(0, 4000),
    threatModel: outs.map((v) => `【${v.model}】${v.threatModel}`).join('\n').slice(0, 4000),
    affirm: outs.map((v) => `【${v.model}】${v.affirm}`).join('\n').slice(0, 4000),
    reason: `${outs.length} 个模型：${outs.map((v) => `${v.model} ${v.confirmation}`).join('，')}。${lead.reason}`.slice(0, 2000),
    evidence: outs.flatMap((v) => v.evidence ?? []).slice(0, 10),
    knowledge: outs.flatMap((v) => v.knowledge), connectors: outs.flatMap((v) => v.connectors),
    model: outs.map((v) => v.model).join(' + '), votes: outs,
  };
  const outputRef = rt.store.artifacts.putJson(combined);
  return { outputRef, apply: () => applyReview(rt, findingId, combined, outputRef, ctx.stepId) };
}

/** Apply a review verdict to the finding (single review, or the combination of the cross-checked votes). */
function applyReview(rt: AuditRuntime, findingId: string, verdict: ReviewVerdict, outputRef: string, stepId: string): void {
  const f = rt.store.get<FindingRow>('SELECT * FROM finding WHERE id = ?', findingId)!;
  const detail = rt.store.artifacts.getJson<Record<string, unknown>>(f.detail_ref);
  const { knowledge, connectors } = verdict;
  let score = Math.min(1, Math.max(0, f.confidence_score + verdict.confidenceDelta));
  // Refuted: lower by at least REFUTED_DELTA but keep it at the reporting threshold — a person decides.
  if (verdict.confirmation === 'refuted') score = Math.max(Math.min(score, f.confidence_score + REFUTED_DELTA), Math.min(f.confidence_score, rt.strategy.minConfidence));
  const patch: Record<string, unknown> = {};
  let pending = verdict.pendingCondition ?? null;
  // Unverified knowledge or non-authoritative connector data alone cannot rule a finding out:
  // a lowering that would drop it below the reporting threshold keeps it as pending instead.
  const basis = [...knowledge.map((k) => ({ verified: k.verified, name: `${k.name}${k.file ? `/${k.file}` : ''}`, kind: 'knowledge' as const })),
    ...connectors.map((c) => ({ verified: c.authoritative, name: `连接器 ${c.connector}/${c.operation}`, kind: 'connector' as const }))];
  const unverifiedBasis = basis.length > 0 && basis.every((b) => !b.verified) && verdict.confidenceDelta < 0 && score < rt.strategy.minConfidence;
  if (unverifiedBasis) {
    score = rt.strategy.minConfidence;
    patch.confirmation = 'pending';
    const names = basis.map((b) => b.name).join('、');
    pending = pending ?? {
      missing: basis.map((b) => ({ kind: 'business_rule' as const, ref: b.name, hint: b.kind === 'knowledge' ? `核实知识「${b.name}」的内容` : `核实${b.name}返回的内容` })),
      holdsIf: [{ statement: `未核实知识 ${names} 所述的防护实际不存在或不覆盖该入口` }], refutedIf: [{ statement: `${names} 所述经核实成立：${verdict.reason.slice(0, 300)}` }],
      severityIfHolds: (['critical', 'high', 'medium', 'low'].includes(f.severity) ? f.severity : 'low') as 'high', suggestedActions: ['add_knowledge', 'ask_user'],
    };
  }
  Object.assign(patch, { confidence_score: score, confidence: confidenceTier(score), challenge_ref: outputRef });
  if (verdict.confirmation === 'pending' || verdict.confirmation === 'refuted') patch.confirmation = 'pending';
  const reviewed = {
    verdict: verdict.confirmation, against: `${verdict.codeDefense}\n${verdict.threatModel}`.slice(0, 4000), affirm: verdict.affirm, reason: verdict.reason, evidence: verdict.evidence ?? [], model: verdict.model,
    ...(verdict.votes ? { votes: verdict.votes.map((v) => ({ model: v.model, verdict: v.confirmation, confidenceDelta: v.confidenceDelta, reason: v.reason })) } : {}),
  };
  // A condition counts only when the finding ends up pending: a “maintain” verdict with a pendingCondition
  // attached anyway made every challenged finding pending in a calibration run.
  patch.detail_ref = rt.store.artifacts.putJson({ ...detail, adversarialReview: reviewed, ...(patch.confirmation === 'pending' && pending && !pendingOf(detail) ? { pendingCondition: pending } : {}) });
  rt.store.update('finding', { id: findingId }, patch);
  if (connectors.length) {
    const next = rt.store.get<{ n: number }>(`SELECT COALESCE(MAX(ord), -1) + 1 AS n FROM evidence WHERE owner_kind = 'finding' AND owner_id = ?`, findingId)!.n;
    insertConnectorEvidence(rt.store, 'finding', findingId, connectors, stepId, next);
  }
  rt.event('finding.challenged', { finding_id: findingId, confirmation: patch.confirmation === 'pending' && verdict.confirmation === 'refuted' ? 'refuted' : patch.confirmation ?? verdict.confirmation, confidence_delta: verdict.confidenceDelta, confidence: score, ...(verdict.votes ? { votes: verdict.votes.length } : {}), ...(unverifiedBasis ? { unverified_knowledge_basis: knowledge.map((k) => k.name), ...(connectors.length ? { unverified_connector_basis: connectors.map((c) => c.callId) } : {}) } : {}) }, stepId);
}
