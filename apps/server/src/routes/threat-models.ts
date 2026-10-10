// Requirement threat models: sources of any number and kind, background generation,
// risk triage and Markdown export. Reads come from engine queries, changes from engine functions.
import type { FastifyInstance } from 'fastify';
import { AppError, redact } from '@xiezhi/contracts';
import {
  acknowledgeSourceInjection, addThreatSource, cancelThreatModelSync, confirmThreatModelSync, createThreatModel, planThreatModelSync, pushGuideList, type ThreatSyncPlan, deleteThreatModel, deleteThreatSource, getProject, queries as Q,
  renderThreatModelReport, reorderThreatSources, setThreatRiskStatus, setThreatRiskStatuses, updateThreatModel, updateThreatSource,
} from '@xiezhi/engine';
import * as B from '../bodies.js';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';

const USER = 'user';

function syncDto(p: ThreatSyncPlan) {
  return {
    id: p.id, threatModelId: p.threatModelId, skill: p.skill, connectorId: p.connectorId, connectorName: p.connectorName, status: p.status, action: p.action,
    skipReason: p.skipReason, reasons: p.reasons, existing: p.existing, steps: p.steps, payloadHash: p.payloadHash, token: p.token,
    expiresAt: new Date(p.expiresAt).toISOString(), tokens: p.tokens, result: p.result,
  };
}

export function registerThreatModelRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  const detail = (id: string) => {
    const d = Q.threatModelDetail(store, id);
    if (!d) throw new AppError('THREAT_MODEL_NOT_FOUND', id);
    return d;
  };

  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/threat-models', async (req) => {
    const p = getProject(store, req.params.pid);
    return { items: Q.listThreatModels(store, p.id) };
  });
  app.post<{ Params: { pid: string } }>('/api/v1/projects/:pid/threat-models', async (req, reply) => {
    const b = parseBody(B.PostThreatModelBody, req.body);
    const tm = createThreatModel(store, req.params.pid, b);
    reply.code(201);
    return detail(tm.id);
  });
  app.get<{ Params: { tid: string } }>('/api/v1/threat-models/:tid', async (req) => detail(req.params.tid));
  app.patch<{ Params: { tid: string } }>('/api/v1/threat-models/:tid', async (req) => {
    const b = parseBody(B.PatchThreatModelBody, req.body);
    updateThreatModel(store, req.params.tid, b);
    return detail(req.params.tid);
  });
  app.delete<{ Params: { tid: string } }>('/api/v1/threat-models/:tid', async (req, reply) => {
    deleteThreatModel(store, req.params.tid);
    reply.code(204);
    return null;
  });

  app.post<{ Params: { tid: string } }>('/api/v1/threat-models/:tid/sources', async (req, reply) => {
    const b = parseBody(B.PostThreatSourceBody, req.body);
    const s = addThreatSource(store, req.params.tid, b);
    reply.code(201);
    return Q.threatSourceDto(s);
  });
  app.patch<{ Params: { sid: string } }>('/api/v1/threat-model-sources/:sid', async (req) => {
    const { injectionAck, ...b } = parseBody(B.PatchThreatSourceBody, req.body);
    let s = updateThreatSource(store, req.params.sid, b);
    if (injectionAck) s = acknowledgeSourceInjection(store, s.id);
    return Q.threatSourceDto(s);
  });
  app.delete<{ Params: { sid: string } }>('/api/v1/threat-model-sources/:sid', async (req, reply) => {
    deleteThreatSource(store, req.params.sid);
    reply.code(204);
    return null;
  });
  app.get<{ Params: { sid: string } }>('/api/v1/threat-model-sources/:sid/content', async (req) => {
    const text = Q.threatSourceText(store, req.params.sid);
    if (text === null) throw new AppError('THREAT_SOURCE_NOT_FOUND', `${req.params.sid} has no content`);
    return { text: redact(text, store.redactOptions()) };
  });
  app.put<{ Params: { tid: string } }>('/api/v1/threat-models/:tid/source-order', async (req) => {
    const b = parseBody(B.PutThreatSourceOrderBody, req.body);
    return { items: reorderThreatSources(store, req.params.tid, b.ids).map(Q.threatSourceDto) };
  });

  app.post<{ Params: { tid: string } }>('/api/v1/threat-models/:tid/generate', async (req, reply) => {
    const b = parseBody(B.PostThreatGenerateBody, req.body ?? {});
    ctx.engine.jobs.startThreatModel(req.params.tid, b);
    reply.code(202);
    return detail(req.params.tid);
  });

  app.patch<{ Params: { rid: string } }>('/api/v1/threat-risks/:rid', async (req) => {
    const b = parseBody(B.PatchThreatRiskBody, req.body);
    return Q.threatRiskDto(setThreatRiskStatus(store, req.params.rid, { status: b.status, reason: b.reason ?? null, actor: USER }), store);
  });
  app.patch<{ Params: { tid: string } }>('/api/v1/threat-models/:tid/risks', async (req) => {
    const b = parseBody(B.PatchThreatRisksBody, req.body);
    const results = setThreatRiskStatuses(store, req.params.tid, b.ids, { status: b.status, reason: b.reason ?? null, actor: USER });
    return { results, threatModel: detail(req.params.tid) };
  });

  app.get<{ Params: { tid: string } }>('/api/v1/threat-models/:tid/export', async (req, reply) => {
    const text = redact(renderThreatModelReport(store, req.params.tid), store.redactOptions());
    reply.header('Content-Type', 'text/markdown; charset=utf-8').header('Content-Disposition', `attachment; filename="threat-model-${req.params.tid}.md"`);
    return text;
  });

  // sync to an online document — guides with push.target threat_model; always previewed, then confirmed.
  const deps = () => ({ store, hub: ctx.engine.hub, pool: ctx.engine.connectors });
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/threat-sync-guides', async (req) => pushGuideList(store, req.params.pid, 'threat_model'));
  app.post<{ Params: { tid: string } }>('/api/v1/threat-models/:tid/sync', async (req) => {
    const b = parseBody(B.PostThreatSyncBody, req.body ?? {});
    const report = redact(renderThreatModelReport(store, req.params.tid), store.redactOptions());
    return syncDto(await planThreatModelSync(deps(), { threatModelId: req.params.tid, report, ...(b.skill ? { skill: b.skill } : {}), ...(b.document ? { document: b.document } : {}) }));
  });
  app.post<{ Params: { id: string } }>('/api/v1/threat-syncs/:id/confirm', async (req) => {
    const b = parseBody(B.PostThreatSyncConfirmBody, req.body);
    return syncDto(await confirmThreatModelSync(deps(), req.params.id, b.token, b.payloadHash));
  });
  app.delete<{ Params: { id: string } }>('/api/v1/threat-syncs/:id', async (req, reply) => {
    cancelThreatModelSync(req.params.id);
    reply.code(204);
    return null;
  });
}
