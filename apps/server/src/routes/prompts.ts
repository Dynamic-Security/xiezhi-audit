// Pipeline prompts in the knowledge base: list every catalog entry with its default and the
// overrides of the global layer and, with `projectId`, the project layer; override one entry of a layer (checked for
// variables and locked tokens), restore one entry or a whole layer to the defaults. Audits already started keep the
// prompts they froze.
import type { FastifyInstance } from 'fastify';
import { AppError, PutPromptBody, type PromptDto, type PromptListDto } from '@xiezhi/contracts';
import { deleteAllPromptOverrides, deletePromptOverride, listPrompts, promptDef, savePromptOverride, type PromptView } from '@xiezhi/knowledge';
import { getProject } from '@xiezhi/engine';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';
import { knowledgeDirs, translate } from './knowledge.js';

export function promptDto(v: PromptView): PromptDto {
  return {
    id: v.def.id, group: v.def.group, title: v.def.title, description: v.def.description, editable: v.editable, readonlyReason: v.editable ? null : v.def.readonly ?? '工具说明只读展示',
    variables: v.variables, locked: v.locked, defaultText: v.def.text, global: v.global, project: v.project, effectiveLayer: v.effectiveLayer, effectiveText: v.effectiveText,
  };
}

export function registerPromptRoutes(app: FastifyInstance, ctx: AppContext): void {
  const dirs = knowledgeDirs(ctx);
  const layerDir = (projectId: string | undefined) => {
    if (!projectId) return { dir: dirs.global, projectDir: null };
    getProject(ctx.store, projectId);
    return { dir: dirs.project(projectId), projectDir: dirs.project(projectId) };
  };
  const list = (projectId: string | undefined): PromptListDto => {
    const { projectDir } = layerDir(projectId);
    const r = listPrompts(dirs.global, projectDir);
    return { items: r.items.map(promptDto), hash: r.hash, overrides: r.overrides, invalid: r.invalid };
  };
  const one = (id: string, projectId: string | undefined): PromptDto => {
    const v = list(projectId).items.find((i) => i.id === id);
    if (!v) throw new AppError('COMMON_NOT_FOUND', `prompt ${id}`);
    return v;
  };

  app.get<{ Querystring: { projectId?: string } }>('/api/v1/knowledge/prompts', async (req) => list(req.query.projectId));
  app.put<{ Params: { id: string } }>('/api/v1/knowledge/prompts/:id', async (req) => {
    const body = parseBody(PutPromptBody, req.body);
    if (!promptDef(req.params.id)) throw new AppError('COMMON_NOT_FOUND', `prompt ${req.params.id}`);
    const { dir } = layerDir(body.projectId);
    translate(() => savePromptOverride(dir, req.params.id, body.text));
    return one(req.params.id, body.projectId);
  });
  app.delete<{ Params: { id: string }; Querystring: { projectId?: string } }>('/api/v1/knowledge/prompts/:id', async (req) => {
    const { dir } = layerDir(req.query.projectId);
    deletePromptOverride(dir, req.params.id);
    return one(req.params.id, req.query.projectId);
  });
  app.delete<{ Querystring: { projectId?: string } }>('/api/v1/knowledge/prompts', async (req) => {
    const { dir } = layerDir(req.query.projectId);
    return { restored: deleteAllPromptOverrides(dir) };
  });
}
