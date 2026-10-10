// 领域规划: the risk domains of a domain-hunt audit, visible while it runs and adjustable without
// blocking it. Reads and edits go through the engine (no SQL here).
import type { FastifyInstance } from 'fastify';
import { AppError } from '@xiezhi/contracts';
import { DomainPlanError, domainPlanView, editDomainPlan } from '@xiezhi/engine';
import * as B from '../bodies.js';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';

function mapError(e: unknown): never {
  if (e instanceof DomainPlanError) throw new AppError(e.code === 'NOT_FOUND' ? 'COMMON_NOT_FOUND' : 'COMMON_VALIDATION', e.message);
  throw e;
}

export function registerDomainPlanRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get<{ Params: { aid: string } }>('/api/v1/audits/:aid/domain-plan', async (req) => {
    try { return domainPlanView(store, req.params.aid); } catch (e) { return mapError(e); }
  });
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/domain-plan/edits', async (req) => {
    const b = parseBody(B.PostAuditsAidDomainPlanEditsBody, req.body);
    try { return editDomainPlan(store, req.params.aid, b, 'user'); } catch (e) { return mapError(e); }
  });
}
