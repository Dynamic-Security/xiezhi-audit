// Verification cases over the API: generate one for a vulnerability with the chat model (the engine
// never executes it), list them, and record the result the user observed in their own environment.
import type { FastifyInstance } from 'fastify';
import { PostCaseResultBody, type VerificationCaseDto } from '@xiezhi/contracts';
import { caseView, getVerificationCase, queries as Q, recordCaseResult, type VerificationCaseRow, type VerificationOutcome } from '@xiezhi/engine';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';

const iso = (n: number) => new Date(n).toISOString();

export function caseDto(r: VerificationCaseRow): VerificationCaseDto {
  const v = caseView(r);
  return {
    id: r.id, projectId: r.project_id, vulnerabilityId: r.vulnerability_id, status: r.status, source: r.source,
    preconditions: v.preconditions, steps: v.steps.map((s) => ({ kind: s.kind, title: s.title, content: s.content, lang: s.lang ?? null })), expected: v.expected, notes: v.notes,
    model: r.model, tokens: r.tokens, error: r.error, outcome: r.outcome, outcomeNote: r.outcome_note, outcomeAt: r.outcome_at ? iso(r.outcome_at) : null,
    createdAt: iso(r.created_at), updatedAt: iso(r.updated_at),
  };
}

export function registerVerificationRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/verification-cases', async (req) => Q.listVerificationCases(store, req.params.vid).map(caseDto));
  app.post<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/verification-cases', async (req, reply) => {
    reply.code(202);
    return caseDto(ctx.engine.jobs.startCaseDraft(req.params.vid));
  });
  app.get<{ Params: { id: string } }>('/api/v1/verification-cases/:id', async (req) => caseDto(getVerificationCase(store, req.params.id)));
  app.post<{ Params: { id: string } }>('/api/v1/verification-cases/:id/result', async (req) => {
    const b = parseBody(PostCaseResultBody, req.body);
    return caseDto(recordCaseResult(store, req.params.id, { outcome: b.outcome as VerificationOutcome, ...(b.note ? { note: b.note } : {}) }, 'user'));
  });
}
