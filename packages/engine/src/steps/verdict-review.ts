// Second-opinion review of a favourable verdict: reverify “已修复” (guard against a fix judged
// too early) and risk hunt “受影响” (only affected verdicts are reviewed). Enabled by `stages.adversarialReview`.
// The reviewer can keep the verdict or doubt it; a doubt never flips it to the opposite conclusion, it turns
// it into “待确认” with the reviewer's condition, and a person decides (same rule as the finding challenge).
import { Type } from 'typebox';
import { SubmitVerdictReview, type SubmitVerdictReview as Review } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import type { AuditRuntime } from '../runtime.js';
import { sessionError, type AttemptContext } from '../step-runner.js';
import { validateCodeRef } from './hunt.js';
import { P } from '@xiezhi/knowledge';

/**
 * `reasoning`: the reasoning behind the verdict under review is not in the prompt — the reviewer
 * starts from the code and reads it through `verdict_reasoning` when it wants to.
 */
export async function reviewVerdict(rt: AuditRuntime, ctx: AttemptContext, subject: 'fixed' | 'affected', context: string[], reasoning?: string): Promise<Review> {
  const submit: AuditTool = {
    name: 'submit_verdict_review', kind: 'submit', parameters: SubmitVerdictReview,
    description: P('tool.submit_verdict_review'),
    validate: (a: Review) => {
      const issues: string[] = [];
      a.evidence.forEach((e, i) => issues.push(...validateCodeRef(rt, e, `evidence[${i}]`, true)));
      if (a.decision === 'doubt' && !a.pendingCondition) issues.push(P('feedback.verdict_review.doubt_condition'));
      if (a.decision === 'doubt' && a.evidence.length === 0) issues.push(P('feedback.verdict_review.doubt_evidence'));
      return issues;
    },
    run: (a: Review) => ({ text: `recorded: ${a.decision}` }),
  };
  const what = subject === 'fixed'
    ? P('verdict_review.fixed')
    : P('verdict_review.affected');
  const prompt = [
    what,
    P('verdict_review.rules'),
    ...(reasoning ? [P('verdict_review.reasoning_note')] : []),
    '', ...context,
  ].join('\n');
  const reasoningTool: AuditTool[] = reasoning ? [{
    name: 'verdict_reasoning', kind: 'read', parameters: Type.Object({}, { additionalProperties: false }),
    description: P('tool.verdict_reasoning'),
    run: () => ({ text: reasoning.slice(0, 6000) }),
  }] : [];
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'challenge', phase: 'challenge', model: rt.strategy.models.challenge ?? rt.strategy.models.audit, signal: ctx.signal,
    prompt, submitTools: [submit], requiredSubmits: ['submit_verdict_review'], maxTurns: Math.min(40, rt.strategy.limits.maxTurnsPerStep), extraTools: reasoningTool,
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const r = (outcome.submissions.submit_verdict_review as Review[]).at(-1)!;
  rt.event('judgement.made', { kind: subject === 'fixed' ? 'fix_review' : 'affected_review', decision: r.decision, reason: r.reason.slice(0, 500) }, ctx.stepId);
  return r;
}
