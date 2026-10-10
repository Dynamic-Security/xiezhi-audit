// Fix suggestions over the API: generate a patch suggestion for a confirmed vulnerability (checked against the
// snapshot, never written to the repository), list them, and start a reverification linked to a suggestion.
import type { FastifyInstance } from 'fastify';
import { AppError, type FixSuggestionDto } from '@xiezhi/contracts';
import { fixPatchesOf, fixReverifyState, getFixSuggestion, linkFixReverify, queries as Q, type FixSuggestionRow } from '@xiezhi/engine';
import type { AppContext } from '../context.js';

const iso = (n: number) => new Date(n).toISOString();

export function fixDto(store: AppContext['store'], r: FixSuggestionRow): FixSuggestionDto {
  return {
    id: r.id, projectId: r.project_id, vulnerabilityId: r.vulnerability_id, status: r.status, summary: r.summary, patches: fixPatchesOf(r), verify: r.verify, notes: r.notes,
    model: r.model, tokens: r.tokens, error: r.error, reverify: fixReverifyState(store, r), createdAt: iso(r.created_at), updatedAt: iso(r.updated_at),
  };
}

export function registerFixRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/fix-suggestions', async (req) => Q.listFixSuggestions(store, req.params.vid).map((r) => fixDto(store, r)));
  app.post<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/fix-suggestions', async (req, reply) => {
    reply.code(202);
    return fixDto(store, ctx.engine.jobs.startFixDraft(req.params.vid));
  });
  app.get<{ Params: { id: string } }>('/api/v1/fix-suggestions/:id', async (req) => fixDto(store, getFixSuggestion(store, req.params.id)));
  /** Reverify the vulnerability after applying the patch: a reverify audit (planned at once), linked to the suggestion. */
  app.post<{ Params: { id: string } }>('/api/v1/fix-suggestions/:id/reverify', async (req, reply) => {
    const r = getFixSuggestion(store, req.params.id);
    if (r.status !== 'ready') throw new AppError('INVALID_TRANSITION', `fix suggestion is ${r.status}`);
    const auditId = ctx.engine.createReverify({ vulnIds: [r.vulnerability_id], origin: 'ui', note: `修复建议 ${r.id} 应用后复验` });
    ctx.scheduler.plan(auditId);
    reply.code(202);
    return fixDto(store, linkFixReverify(store, r.id, auditId));
  });
}
