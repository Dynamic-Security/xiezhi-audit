// Architecture material imports: AI proposes services and connections from pasted or
// uploaded material; they enter the topology as imported / inferred; the material becomes a project
// architecture knowledge draft for review.
import type { FastifyInstance } from 'fastify';
import { AppError, type ArchitectureImportDto } from '@xiezhi/contracts';
import { getArchitectureImport, getProject, type ArchitectureImportResult, type ArchitectureImportRow, queries as Q } from '@xiezhi/engine';
import { fromJson } from '@xiezhi/store';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';
import { PostProjectsPidArchitectureImportsBody } from '../bodies.js';

export function importDto(r: ArchitectureImportRow): ArchitectureImportDto {
  return {
    id: r.id, projectId: r.project_id, label: r.label, status: r.status, result: fromJson<ArchitectureImportResult | null>(r.result, null), draftId: r.draft_id,
    error: r.error, model: r.model, tokens: r.tokens, createdAt: new Date(r.created_at).toISOString(), updatedAt: new Date(r.updated_at).toISOString(),
  };
}

export function registerArchitectureRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.post<{ Params: { pid: string } }>('/api/v1/projects/:pid/architecture-imports', async (req, reply) => {
    const b = parseBody(PostProjectsPidArchitectureImportsBody, req.body);
    const id = ctx.engine.jobs.startArchitectureImport(req.params.pid, { text: b.text, label: b.label?.trim() || '架构资料' });
    reply.code(202);
    return importDto(getArchitectureImport(store, id));
  });
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/architecture-imports', async (req) => {
    getProject(store, req.params.pid);
    return Q.architectureImports<ArchitectureImportRow>(store, req.params.pid).map(importDto);
  });
  app.get<{ Params: { pid: string; iid: string } }>('/api/v1/projects/:pid/architecture-imports/:iid', async (req) => {
    const r = getArchitectureImport(store, req.params.iid);
    if (r.project_id !== req.params.pid) throw new AppError('COMMON_NOT_FOUND', 'architecture import');
    return importDto(r);
  });
}
