// The lead: one coordinating session per hunt model replaces the fixed rounds of the domain
// experts. It does not read code (no read / grep); it looks at the plan and the obligation ledger and dispatches
// subtasks — a domain view with a concrete goal and starting files — each of which is an expert round (a step, a
// checkpoint) that reads code and submits its conclusions straight to the engine. The lead only gets a few lines back
// per subtask. When its context reaches the cap it writes a handoff and a fresh lead session continues (no compaction).
import { Type } from 'typebox';
import type { AuditTool } from '@xiezhi/agent';
import type { ModelRef } from '@xiezhi/contracts';
import type { AuditRuntime } from './runtime.js';
import { sessionError, type AttemptContext, type StepResult } from './step-runner.js';
import { profileTool, type PlannedDomain } from './domains.js';
import { auditSystemModel } from './steps/profile.js';
import { stateQueryTool } from './steps/hunt.js';
import { P } from '@xiezhi/knowledge';

/** A lead session's context cap before it hands over (tokens of one request). */
export const LEAD_CONTEXT_CAP = 40_000;
/** Lead sessions per hunt model at most (the first and its successors). */
export const MAX_LEAD_SESSIONS = 5;
/** Subtasks one dispatch call may start. */
export const MAX_DISPATCH = 6;

export interface LeadTask { domainId: string; goal: string; files?: string[] }
/** Stored as the lead step's output; readers of hunt outputs skip `LEAD-*` steps (consensus, challenge, prior conclusions). */
export interface LeadOutput { done: boolean; summary: string; handoff: string | null; dispatched: number }

export interface LeadDeps {
  /** The plan and the ledger as the lead sees them (domains, subtasks so far, must-answers, gaps, budget). */
  ledger(): string;
  /** Run the subtasks (side by side across domains) and return one receipt line each. */
  dispatch(tasks: LeadTask[], signal: AbortSignal | undefined): Promise<string[]>;
}

/** The cross-service risk leads of the system model, for the lead to assign to domains (unverified). */
function systemRisks(rt: AuditRuntime): string[] {
  const m = auditSystemModel(rt);
  if (!m?.risks?.length) return [];
  return ['', P('lead.system_risks_heading'), ...m.risks.map((r) => `- ${r.title}（${r.repos.join('、')}）：${r.statement}`)];
}

export function leadPrompt(rt: AuditRuntime, domains: PlannedDomain[], session: number, handoff: string | null, ledger: string): string {
  const incremental = rt.audit.scene === 'incremental';
  return [
    P('lead.intro', { session }),
    incremental ? P('lead.incremental') : '',
    '',
    P('lead.plan_heading'),
    ...domains.map((d) => `- ${d.id}「${d.name}」：${d.focus}（类别：${d.categories.join('、')}${d.mechanisms.length ? `；需整体检查的机制：${d.mechanisms.map((m) => m.name).join('、')}` : ''}）`),
    ...systemRisks(rt),
    '',
    P('lead.how'),
    ...(handoff ? ['', P('lead.handoff_heading'), handoff] : []),
    '',
    P('lead.ledger_heading'),
    ledger,
  ].join('\n');
}

export async function leadStep(rt: AuditRuntime, ctx: AttemptContext, input: { model: ModelRef; domains: PlannedDomain[]; session: number; handoff: string | null; statePrefix?: string }, deps: LeadDeps): Promise<StepResult> {
  let dispatched = 0;
  const domainIds = new Set(input.domains.map((d) => d.id));
  const ledger: AuditTool = {
    name: 'ledger', kind: 'read',
    description: P('tool.ledger'),
    parameters: Type.Object({}, { additionalProperties: false }),
    run: () => ({ text: deps.ledger() }),
  };
  const dispatch: AuditTool = {
    name: 'dispatch', kind: 'read',
    description: P('tool.dispatch', { max: MAX_DISPATCH }),
    parameters: Type.Object({
      tasks: Type.Array(Type.Object({
        domainId: Type.String({ maxLength: 20 }),
        goal: Type.String({ minLength: 10, maxLength: 1500 }),
        files: Type.Optional(Type.Array(Type.String({ maxLength: 500 }), { maxItems: 10 })),
      }, { additionalProperties: false }), { minItems: 1, maxItems: MAX_DISPATCH }),
    }, { additionalProperties: false }),
    async run(a: { tasks: LeadTask[] }, signal) {
      const unknown = a.tasks.filter((t) => !domainIds.has(t.domainId)).map((t) => t.domainId);
      if (unknown.length) throw new Error(P('feedback.lead.unknown_domain', { ids: unknown.join(', ') }));
      const receipts = await deps.dispatch(a.tasks, signal);
      dispatched += a.tasks.length;
      return { text: receipts.join('\n') };
    },
  };
  const done: AuditTool = {
    name: 'submit_lead_done', kind: 'submit',
    description: P('tool.submit_lead_done'),
    parameters: Type.Object({
      done: Type.Boolean(),
      summary: Type.String({ minLength: 1, maxLength: 3000 }),
      handoff: Type.Optional(Type.String({ maxLength: 4000 })),
    }, { additionalProperties: false }),
    run: () => ({ text: 'recorded' }),
  };
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'hunt', phase: 'hunt', model: input.model, signal: ctx.signal,
    prompt: leadPrompt(rt, input.domains, input.session, input.handoff, deps.ledger()),
    submitTools: [done], requiredSubmits: ['submit_lead_done'], maxTurns: rt.strategy.limits.maxTurnsPerStep,
    extraTools: [ledger, dispatch, stateQueryTool(rt, input.statePrefix), profileTool(rt)],
    noCodeRead: true, noSlot: true, threatModel: false, contextCap: LEAD_CONTEXT_CAP,
    wrapUpMessage: P('nudge.lead.wrap_up'),
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const sub = (outcome.submissions.submit_lead_done as { done: boolean; summary: string; handoff?: string }[]).at(-1)!;
  const out: LeadOutput = { done: sub.done, summary: sub.summary, handoff: sub.handoff ?? null, dispatched };
  rt.event('judgement.made', { kind: 'lead_session', session: input.session, done: sub.done, dispatched }, ctx.stepId);
  return { outputRef: rt.store.artifacts.putJson(out) };
}
