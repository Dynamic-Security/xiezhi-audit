// Connector packs: list, built-in examples, files (content-hash edits), AI drafts from OpenAPI.
import type { FastifyInstance } from 'fastify';
import type { ConnectorPackDraftDto } from '@xiezhi/contracts';
import {
  approvePackDraft, deletePack, getPackDraft, installExamplePack, listExamplePacks, listPackDrafts, listPacks, packDir, readPackDraftFiles,
  readPackFiles, rejectPackDraft, summarizePack, writePackFile, type PackDraftRow,
} from '@xiezhi/engine';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';
import { PostConnectorPackDraftsBody, PutConnectorPackFileBody } from '../bodies.js';

const draftDto = (d: PackDraftRow): ConnectorPackDraftDto => ({ ...d, createdAt: new Date(d.createdAt).toISOString() });

export function registerPackRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get('/api/v1/connector-packs', async () => listPacks(store));
  app.get('/api/v1/connector-packs/examples', async () => listExamplePacks());
  app.post<{ Params: { name: string } }>('/api/v1/connector-packs/examples/:name/install', async (req, reply) => {
    reply.code(201);
    return installExamplePack(store, req.params.name);
  });
  app.get<{ Params: { name: string } }>('/api/v1/connector-packs/:name', async (req) => ({ ...summarizePack(packDir(store, req.params.name), req.params.name), files: readPackFiles(store, req.params.name) }));
  app.put<{ Params: { name: string; '*': string } }>('/api/v1/connector-packs/:name/files/*', async (req) => {
    const b = parseBody(PutConnectorPackFileBody, req.body);
    return writePackFile(store, req.params.name, req.params['*'], b.text, b.baseSha256);
  });
  app.delete<{ Params: { name: string } }>('/api/v1/connector-packs/:name', async (req, reply) => {
    deletePack(store, req.params.name);
    return reply.code(204).send();
  });
  // AI drafts from an OpenAPI document: declarative operations only, reviewed before they become a pack.
  app.get('/api/v1/connector-pack-drafts', async () => listPackDrafts(store).map(draftDto));
  app.post('/api/v1/connector-pack-drafts', async (req, reply) => {
    const b = parseBody(PostConnectorPackDraftsBody, req.body);
    const d = ctx.engine.jobs.startPackDraft({ openapi: b.openapi, ...(b.name ? { name: b.name } : {}), ...(b.focus ? { focus: b.focus } : {}) });
    reply.code(202);
    return draftDto(d);
  });
  app.get<{ Params: { id: string } }>('/api/v1/connector-pack-drafts/:id', async (req) => ({ ...draftDto(getPackDraft(store, req.params.id)), files: readPackDraftFiles(store, req.params.id) }));
  app.post<{ Params: { id: string } }>('/api/v1/connector-pack-drafts/:id/approve', async (req) => approvePackDraft(store, req.params.id));
  app.post<{ Params: { id: string } }>('/api/v1/connector-pack-drafts/:id/reject', async (req, reply) => {
    rejectPackDraft(store, req.params.id);
    return reply.code(204).send();
  });
}
