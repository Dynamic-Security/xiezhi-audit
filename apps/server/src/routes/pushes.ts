// Pushing vulnerabilities to external systems by push guide: started by the user,
// executed at once unless the guide asks for confirmation or the payload looks injected.
import type { FastifyInstance } from 'fastify';
import type { PushDto, PushGuideDto } from '@xiezhi/contracts';
import { cancelPush, confirmPush, getProject, linkExternalRecord, pushGuideList, startPush, syncRecords, type PushPlan } from '@xiezhi/engine';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';
import { PostProjectsPidPushesBody, PostPushesIdConfirmBody, PutVulnerabilitiesVidSyncBody } from '../bodies.js';

const dto = (p: PushPlan): PushDto => ({
  id: p.id, projectId: p.projectId, skill: p.skill, connectorId: p.connectorId, connectorName: p.connectorName, status: p.status,
  confirmRequired: p.confirmRequired, confirmReasons: p.confirmReasons, payloadHash: p.payloadHash, token: p.token,
  expiresAt: new Date(p.expiresAt).toISOString(), tokens: p.tokens,
  items: p.items.map((i) => ({
    vulnId: i.vulnId, displayNo: i.displayNo, title: i.title, action: i.action, operation: i.operation, args: i.args, skipReason: i.skipReason,
    reasons: i.reasons, existing: i.existing, result: i.result ?? null, steps: i.steps,
  })),
});

export function registerPushRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  // The model hub is rebuilt when model settings change: read it per request.
  const deps = () => ({ store, hub: ctx.engine.hub, pool: ctx.engine.connectors });
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/push-guides', async (req): Promise<PushGuideDto[]> => pushGuideList(store, req.params.pid));
  app.post<{ Params: { pid: string } }>('/api/v1/projects/:pid/pushes', async (req) => {
    getProject(store, req.params.pid);
    const b = parseBody(PostProjectsPidPushesBody, req.body);
    return dto(await startPush(deps(), { projectId: req.params.pid, skill: b.skill, vulnIds: b.vulnIds, ...(b.preview ? { preview: true } : {}) }));
  });
  app.post<{ Params: { id: string } }>('/api/v1/pushes/:id/confirm', async (req) => {
    const b = parseBody(PostPushesIdConfirmBody, req.body);
    return dto(await confirmPush(deps(), req.params.id, b.token, b.payloadHash));
  });
  app.delete<{ Params: { id: string } }>('/api/v1/pushes/:id', async (_req, reply) => {
    cancelPush(_req.params.id);
    return reply.code(204).send();
  });
  app.get<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/sync', async (req) =>
    syncRecords(store, req.params.vid).map((r) => ({ ...r, updatedAt: new Date(r.updatedAt).toISOString() })));
  // link an existing external record (made by hand, or by a push whose result had no recognizable ID).
  app.put<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/sync', async (req) => {
    const b = parseBody(PutVulnerabilitiesVidSyncBody, req.body);
    linkExternalRecord(store, req.params.vid, { connectorId: b.connectorId, externalId: b.externalId, ...(b.externalUrl !== undefined ? { externalUrl: b.externalUrl } : {}) });
    return syncRecords(store, req.params.vid).map((r) => ({ ...r, updatedAt: new Date(r.updatedAt).toISOString() }));
  });
}
