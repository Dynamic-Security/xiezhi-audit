// Verification cases: for a confirmed or pending vulnerability, a model writes the steps a user runs
// in their own test environment — preconditions, ordered steps (HTTP requests, a test snippet or manual actions) and the
// expected results when vulnerable and when fixed. The engine never executes them. The user records the
// result: reproduced confirms the vulnerability (a person's verification), not reproduced proposes a false positive for
// review, inconclusive is kept as a note.
import { Type } from 'typebox';
import { AppError, newId, type ModelRef } from '@xiezhi/contracts';
import { boundaryDeclaration, newNonce, startSession, type AuditTool, type ModelHub } from '@xiezhi/agent';
import { P } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';
import { reviewVulnerability } from './interact.js';
import { withLivePrompts } from './prompts.js';
import { chatModelOf } from './services.js';
import { addRevision } from './vulns.js';
import { readSnapshotTool, vulnBrief, vulnContext } from './vuln-context.js';

export const VERIFICATION_OUTCOMES = ['reproduced', 'not_reproduced', 'inconclusive'] as const;
export type VerificationOutcome = (typeof VERIFICATION_OUTCOMES)[number];
export const STEP_KINDS = ['http', 'test', 'manual'] as const;

export interface VerificationStep { kind: (typeof STEP_KINDS)[number]; title: string; content: string; lang?: string }
export interface VerificationCaseRow {
  id: string; project_id: string; vulnerability_id: string; status: 'drafting' | 'ready' | 'failed'; source: 'ai' | 'user';
  preconditions: string | null; steps: string | null; expected: string | null; notes: string | null; model: string | null; tokens: number; error: string | null;
  outcome: VerificationOutcome | null; outcome_note: string | null; outcome_by: string | null; outcome_at: number | null; created_at: number; updated_at: number;
}

export function getVerificationCase(store: Store, id: string): VerificationCaseRow {
  const r = store.get<VerificationCaseRow>('SELECT * FROM verification_case WHERE id = ?', id);
  if (!r) throw new AppError('COMMON_NOT_FOUND', `verification case ${id}`);
  return r;
}

/** Start an AI case for a vulnerability (confirmed or pending; not a false positive). */
export function createCaseDraft(store: Store, vulnId: string): VerificationCaseRow {
  const c = vulnContext(store, vulnId);
  if (c.vuln.confirm_status === 'false_positive') throw new AppError('COMMON_VALIDATION', 'the vulnerability is a false positive');
  if (store.get(`SELECT 1 FROM verification_case WHERE vulnerability_id = ? AND status = 'drafting'`, vulnId)) throw new AppError('INVALID_TRANSITION', 'a verification case is already being written for this vulnerability');
  const id = newId('verificationCase');
  store.insert('verification_case', { id, project_id: c.vuln.project_id, vulnerability_id: vulnId, status: 'drafting', source: 'ai' });
  return getVerificationCase(store, id);
}

const SubmitCase = Type.Object({
  preconditions: Type.Array(Type.String({ minLength: 2, maxLength: 500 }), { maxItems: 12 }),
  steps: Type.Array(Type.Object({
    kind: Type.Union(STEP_KINDS.map((k) => Type.Literal(k))), title: Type.String({ minLength: 2, maxLength: 200 }),
    content: Type.String({ minLength: 2, maxLength: 6000 }), lang: Type.Optional(Type.String({ maxLength: 40 })),
  }, { additionalProperties: false }), { minItems: 1, maxItems: 12 }),
  expected: Type.Object({ vulnerable: Type.String({ minLength: 4, maxLength: 1500 }), fixed: Type.String({ minLength: 4, maxLength: 1500 }) }, { additionalProperties: false }),
  notes: Type.Optional(Type.String({ maxLength: 1500 })),
}, { additionalProperties: false });
type SubmitCase = { preconditions: string[]; steps: VerificationStep[]; expected: { vulnerable: string; fixed: string }; notes?: string };

async function processCaseDraftInner(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const row = getVerificationCase(store, id);
  const usage = { total: 0 };
  let model: ModelRef | null = null;
  try {
    try { model = chatModelOf(store.config); } catch { throw new AppError('MODEL_NOT_CONFIGURED', 'verification cases need a chat or default model'); }
    const c = vulnContext(store, row.vulnerability_id);
    const nonce = newNonce();
    const submit: AuditTool = { name: 'submit_verification_case', kind: 'submit', parameters: SubmitCase, description: P('tool.submit_verification_case'), run: () => ({ text: 'recorded' }) };
    const outcome = await startSession({
      hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
      systemPrompt: [P('role.verification_author'), boundaryDeclaration(nonce)].join('\n\n'),
      prompt: [P('verification.guide'), '', vulnBrief(c, nonce)].join('\n'),
      tools: [readSnapshotTool(c.view, nonce), submit], requiredSubmits: ['submit_verification_case'], maxTurns: 10, signal,
      onUsage: (u) => { usage.total += u.total; return 'continue'; },
    }).outcome;
    const sub = (outcome.submissions.submit_verification_case as SubmitCase[] | undefined)?.at(-1);
    if (!sub) throw new Error(`the model did not submit (${outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
    store.update('verification_case', { id }, {
      status: 'ready', preconditions: sub.preconditions, steps: sub.steps, expected: sub.expected, notes: sub.notes ?? null, model: `${model.provider}/${model.model}`, tokens: usage.total,
    });
  } catch (e) {
    store.update('verification_case', { id }, { status: 'failed', error: (e as Error).message.slice(0, 500), tokens: usage.total, ...(model ? { model: `${model.provider}/${model.model}` } : {}) });
  }
}

export async function processCaseDraft(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const row = getVerificationCase(deps.store, id);
  return withLivePrompts(deps.store, row.project_id, () => processCaseDraftInner(deps, id, signal), 'verification_case', id);
}

/**
 * The user's result of running the case. Reproduced: the vulnerability is confirmed by a person's verification (also
 * without complete evidence — the reason names the case). Not reproduced: a proposed false positive for review (an
 * environment can differ). Inconclusive: only kept. A later result replaces the earlier one.
 */
export function recordCaseResult(store: Store, id: string, input: { outcome: VerificationOutcome; note?: string }, actor: string): VerificationCaseRow {
  const r = getVerificationCase(store, id);
  if (r.status !== 'ready') throw new AppError('INVALID_TRANSITION', `verification case is ${r.status}`);
  if (!VERIFICATION_OUTCOMES.includes(input.outcome)) throw new AppError('COMMON_VALIDATION', 'outcome');
  const note = input.note?.trim() ?? '';
  if (input.outcome !== 'reproduced' && !note) throw new AppError('VULN_REASON_REQUIRED', 'describe what you observed');
  return store.tx(() => {
    store.update('verification_case', { id }, { outcome: input.outcome, outcome_note: note || null, outcome_by: actor, outcome_at: Date.now() });
    const v = store.get<{ rev: number; confirm_status: string }>('SELECT rev, confirm_status FROM vulnerability WHERE id = ?', r.vulnerability_id)!;
    const reason = `用户验证（验证用例 ${id}）：${input.outcome === 'reproduced' ? '复现' : input.outcome === 'not_reproduced' ? '未复现' : '无法判断'}${note ? `；${note}` : ''}`;
    if (input.outcome === 'reproduced' && v.confirm_status !== 'confirmed') {
      reviewVulnerability(store, r.vulnerability_id, { confirmStatus: 'confirmed', reason }, v.rev, actor);
    } else if (input.outcome === 'not_reproduced' && v.confirm_status !== 'false_positive') {
      addRevision(store, r.vulnerability_id, { dimension: 'confirm', source: 'human', actor: 'verification', from: v.confirm_status, to: 'false_positive', reason, state: 'proposed' });
    }
    return getVerificationCase(store, id);
  });
}

export interface CaseView {
  preconditions: string[]; steps: VerificationStep[]; expected: { vulnerable: string; fixed: string } | null; notes: string | null;
}
export function caseView(r: VerificationCaseRow): CaseView {
  return { preconditions: fromJson<string[]>(r.preconditions, []), steps: fromJson<VerificationStep[]>(r.steps, []), expected: fromJson<CaseView['expected']>(r.expected, null), notes: r.notes };
}
