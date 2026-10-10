// Knowledge management routes: list with annotations, read / edit /
// delete skills and sub-files of either layer with content-hash concurrency, project and global
// overrides, and `knowledge.changed` notifications from the directory watcher.
import { join } from 'node:path';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import {
  AppError, SKILL_CATEGORIES, type KnowledgeChangedDto, type KnowledgeDraftDto, type SkillBodyDto, type SkillCategory, type SkillDto,
} from '@xiezhi/contracts';
import {
  approveKnowledgeDraft, findDraft, getProject, listAllDrafts, listProjects, moveToGlobalPreview, questionDraftInput, rejectKnowledgeDraft, updateDraft,
  vulnerabilityCaseInput, type CreateDraftInput,
} from '@xiezhi/engine';
import {
  KnowledgeError, deleteSkill, deleteSkillFile, failInterruptedDrafts, listKnowledge, readSettings, readSkill, readSkillFile, regenerateCaseIndexes, setOverride,
  sweepDrafts, watchKnowledge, writeSkillEntry, writeSkillFile, type Draft, type KnowledgeWatcher, type Layer, type SkillDetail,
} from '@xiezhi/knowledge';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';
import {
  PostDistillCaseBody, PostKnowledgeDraftApproveBody, PostKnowledgeDraftsBody, PostMoveToGlobalBody, PutKnowledgeDraftBody, PutKnowledgeOverrideBody, PutSkillBody,
  PutSkillFileBody,
} from '../bodies.js';

type Params = { pid?: string; name: string; '*'?: string };

export function translate<T>(fn: () => T): T {
  try {
    return fn();
  } catch (e) {
    if (!(e instanceof KnowledgeError)) throw e;
    switch (e.kind) {
      case 'not_found': throw new AppError('COMMON_NOT_FOUND', e.message);
      case 'exists': throw new AppError('KNOWLEDGE_EXISTS', e.message);
      case 'bad_path': throw new AppError('KNOWLEDGE_PATH_INVALID', e.message);
      case 'invalid': throw new AppError('KNOWLEDGE_INVALID', (e.detail.errors ?? []).join('; ').slice(0, 400), { errors: e.detail.errors ?? [] });
      case 'conflict': throw new AppError('COMMON_REVISION_CONFLICT', 'the file changed on disk', { current: e.detail.current });
    }
  }
}

/** Content hash from `If-Match: "<sha256>"` or the body / query field. */
function baseHash(req: FastifyRequest, fromBody: string | null | undefined, required: boolean): string | null {
  const h = req.headers['if-match'];
  if (typeof h === 'string') {
    const m = /^(?:W\/)?"([0-9a-f]{64})"$/.exec(h.trim());
    if (!m) throw new AppError('COMMON_VALIDATION', 'bad If-Match');
    return m[1]!;
  }
  if (fromBody !== undefined) return fromBody;
  if (required) throw new AppError('COMMON_PRECONDITION_REQUIRED');
  return null;
}

export function skillDto(d: SkillDetail): SkillBodyDto {
  return {
    name: d.name, layer: d.layer, form: d.form, valid: d.valid, errors: d.errors, warnings: d.warnings, category: d.category, description: d.description,
    load: d.load, verified: d.verified, source: d.source, sha256: d.sha256, entryFile: d.entryFile, body: d.entryText, entrySha256: d.entrySha256,
    files: d.files, updatedAt: new Date(d.updatedAt).toISOString(),
  };
}

const iso = (ms: number | null) => (ms ? new Date(ms).toISOString() : null);

export function draftDto(d: Draft): KnowledgeDraftDto {
  return {
    id: d.id, layer: d.layer, projectId: d.projectId, status: d.status, revision: d.revision, kind: d.kind, name: d.name, library: d.library, text: d.text,
    inputPreview: d.input.slice(0, 4000), source: d.source, checks: d.checks, model: d.model, tokens: d.tokens, error: d.error, moveFrom: d.moveFrom,
    createdAt: iso(d.createdAt)!, updatedAt: iso(d.updatedAt)!, decidedAt: iso(d.decidedAt),
  };
}

export function knowledgeDirs(ctx: AppContext): { global: string; project: (pid: string) => string; all: () => Map<string, string> } {
  const { store } = ctx;
  return {
    global: store.paths.knowledgeGlobal,
    project: (pid) => join(store.paths.projects, pid, 'knowledge'),
    all: () => new Map(listProjects(store).map((p) => [p.id, join(store.paths.projects, p.id, 'knowledge')])),
  };
}

/** Rebuild generated case indexes of a layer and tell open pages (watcher and API writes both call it). */
function layerChanged(ctx: AppContext, layer: Layer, projectId: string | null): void {
  const dirs = knowledgeDirs(ctx);
  try {
    for (const r of regenerateCaseIndexes(layer === 'global' ? dirs.global : dirs.project(projectId!), layer)) {
      if (r.warning) ctx.log('warn', 'case index', { skill: r.skill, warning: r.warning });
    }
  } catch (e) {
    ctx.log('warn', 'case index regeneration failed', { error: (e as Error).message });
  }
  ctx.notify('knowledge.changed', { layer, projectId } satisfies KnowledgeChangedDto);
}

/** Drafts interrupted by a restart fail; decided drafts older than 30 days are removed. */
function sweepAllDrafts(ctx: AppContext, startup: boolean): void {
  const dirs = knowledgeDirs(ctx);
  for (const dir of [dirs.global, ...dirs.all().values()]) {
    try {
      if (startup) failInterruptedDrafts(dir);
      sweepDrafts(dir);
    } catch (e) {
      ctx.log('warn', 'draft sweep failed', { error: (e as Error).message });
    }
  }
}

export function startKnowledgeWatch(ctx: AppContext): KnowledgeWatcher {
  const dirs = knowledgeDirs(ctx);
  sweepAllDrafts(ctx, true);
  const sweep = setInterval(() => sweepAllDrafts(ctx, false), 3600_000);
  sweep.unref();
  const w = watchKnowledge(dirs.global, ctx.store.paths.projects, (changes) => {
    for (const c of changes) layerChanged(ctx, c.layer, c.projectId);
  });
  if (!w.active) ctx.log('warn', 'knowledge directory watching is unavailable; changes made outside the app appear after a refresh');
  // Startup reconciliation: regenerate indexes changed while the service was stopped.
  layerChanged(ctx, 'global', null);
  for (const pid of dirs.all().keys()) layerChanged(ctx, 'project', pid);
  return { get active() { return w.active; }, close() { clearInterval(sweep); w.close(); } };
}

export function registerKnowledgeRoutes(app: FastifyInstance, ctx: AppContext): void {
  const dirs = knowledgeDirs(ctx);
  const layerOf = (p: Params): { layer: Layer; dir: string; pid: string | null } => {
    if (!p.pid) return { layer: 'global', dir: dirs.global, pid: null };
    getProject(ctx.store, p.pid);
    return { layer: 'project', dir: dirs.project(p.pid), pid: p.pid };
  };

  app.get<{ Querystring: { projectId?: string } }>('/api/v1/knowledge', async (req) => {
    if (req.query.projectId) getProject(ctx.store, req.query.projectId);
    return listKnowledge(dirs.global, dirs.all(), { ...(req.query.projectId ? { projectId: req.query.projectId } : {}) }).map((i): SkillDto => ({
      name: i.name, layer: i.layer, valid: i.valid, errors: i.errors, warnings: i.warnings, category: i.category, description: i.description, load: i.load,
      verified: i.verified, path: i.path, updatedAt: i.updatedAt ? new Date(i.updatedAt).toISOString() : null,
      disabled: i.disabled, disabledBy: i.disabledBy, overridesGlobal: i.overridesGlobal, overriddenBy: i.overriddenBy,
    }));
  });

  for (const prefix of ['/api/v1/knowledge/global', '/api/v1/projects/:pid/knowledge']) {
    app.get<{ Params: Params }>(`${prefix}/:name`, async (req) => {
      const { layer, dir } = layerOf(req.params);
      const d = translate(() => readSkill(dir, layer, req.params.name));
      if (!d) throw new AppError('COMMON_NOT_FOUND', 'skill');
      return skillDto(d);
    });
    app.put<{ Params: Params }>(`${prefix}/:name`, async (req) => {
      const { layer, dir, pid } = layerOf(req.params);
      const body = parseBody(PutSkillBody, req.body);
      const d = translate(() => writeSkillEntry(dir, layer, req.params.name, body.text, baseHash(req, body.baseSha256, false), body.form ? { form: body.form } : {}));
      layerChanged(ctx, layer, pid);
      return skillDto(d);
    });
    app.delete<{ Params: Params; Querystring: { baseSha256?: string } }>(`${prefix}/:name`, async (req, reply) => {
      const { layer, dir, pid } = layerOf(req.params);
      translate(() => deleteSkill(dir, req.params.name, baseHash(req, req.query.baseSha256, true)!));
      layerChanged(ctx, layer, pid);
      return reply.code(204).send();
    });
    app.get<{ Params: Params }>(`${prefix}/:name/files/*`, async (req) => {
      const { dir } = layerOf(req.params);
      const path = req.params['*'] ?? '';
      const f = translate(() => readSkillFile(dir, req.params.name, path));
      return { path, text: f.text, sha256: f.sha256 };
    });
    app.put<{ Params: Params }>(`${prefix}/:name/files/*`, async (req) => {
      const { layer, dir, pid } = layerOf(req.params);
      const body = parseBody(PutSkillFileBody, req.body);
      const d = translate(() => writeSkillFile(dir, layer, req.params.name, req.params['*'] ?? '', body.text, baseHash(req, body.baseSha256, false)));
      layerChanged(ctx, layer, pid);
      return skillDto(d);
    });
    app.delete<{ Params: Params; Querystring: { baseSha256?: string } }>(`${prefix}/:name/files/*`, async (req) => {
      const { layer, dir, pid } = layerOf(req.params);
      const d = translate(() => deleteSkillFile(dir, layer, req.params.name, req.params['*'] ?? '', baseHash(req, req.query.baseSha256, true)!));
      layerChanged(ctx, layer, pid);
      return skillDto(d);
    });
  }

  // Overrides: the project hides a skill by name or a whole category; the global layer
  // takes a skill offline for every project.
  const overrideDto = (dir: string) => {
    const s = readSettings(dir);
    return { disabled: s.disabled, disabledCategories: s.disabled_categories };
  };
  app.put<{ Params: { pid: string; name: string } }>('/api/v1/projects/:pid/knowledge-overrides/:name', async (req) => {
    getProject(ctx.store, req.params.pid);
    const { disabled } = parseBody(PutKnowledgeOverrideBody, req.body);
    const dir = dirs.project(req.params.pid);
    setOverride(dir, { name: req.params.name }, disabled);
    layerChanged(ctx, 'project', req.params.pid);
    return overrideDto(dir);
  });
  app.put<{ Params: { pid: string; category: string } }>('/api/v1/projects/:pid/knowledge-category-overrides/:category', async (req) => {
    getProject(ctx.store, req.params.pid);
    if (!(SKILL_CATEGORIES as readonly string[]).includes(req.params.category)) throw new AppError('COMMON_VALIDATION', 'unknown category');
    const { disabled } = parseBody(PutKnowledgeOverrideBody, req.body);
    const dir = dirs.project(req.params.pid);
    setOverride(dir, { category: req.params.category as SkillCategory }, disabled);
    layerChanged(ctx, 'project', req.params.pid);
    return overrideDto(dir);
  });
  app.put<{ Params: { name: string } }>('/api/v1/knowledge/global-overrides/:name', async (req) => {
    const { disabled } = parseBody(PutKnowledgeOverrideBody, req.body);
    setOverride(dirs.global, { name: req.params.name }, disabled);
    layerChanged(ctx, 'global', null);
    return overrideDto(dirs.global);
  });

  // ---- drafts ----
  app.get<{ Querystring: { projectId?: string; all?: string } }>('/api/v1/knowledge/drafts', async (req) =>
    listAllDrafts(ctx.store, { ...(req.query.projectId ? { projectId: req.query.projectId } : {}), includeDecided: req.query.all === '1' }).map(draftDto));
  app.post('/api/v1/knowledge/drafts', async (req, reply) => {
    const b = parseBody(PostKnowledgeDraftsBody, req.body);
    let input: CreateDraftInput;
    if (b.questionId) {
      const q = questionDraftInput(ctx.store, b.questionId);
      input = {
        layer: 'project' as const, projectId: q.projectId, kind: 'skill' as const, text: q.text, organize: true,
        category: (b.category ?? 'business') as SkillCategory, source: { kind: 'question' as const, ref: b.questionId, label: q.label },
      };
    } else {
      if (!b.text) throw new AppError('COMMON_VALIDATION', 'text or questionId is required');
      if (b.layer === 'project') getProject(ctx.store, b.projectId ?? '');
      const organize = b.organize ?? true;
      const kind = b.kind ?? 'skill';
      input = {
        layer: b.layer, projectId: b.layer === 'project' ? b.projectId! : null, kind, text: b.text, organize,
        ...(b.name ? { name: b.name } : {}), ...(b.category ? { category: b.category as SkillCategory } : {}),
        source: { kind: b.source?.kind ?? (organize ? 'text' : 'manual'), ref: b.source?.kind === 'connector' || b.source?.kind === 'conversation' ? b.source.ref ?? null : null, label: b.source?.label ?? (organize ? '粘贴的文本' : '手写') },
      };
    }
    const d = ctx.engine.jobs.startDraft(input);
    reply.code(202);
    return draftDto(d);
  });
  app.get<{ Params: { did: string } }>('/api/v1/knowledge/drafts/:did', async (req) => draftDto(findDraft(ctx.store, req.params.did).draft));
  app.put<{ Params: { did: string } }>('/api/v1/knowledge/drafts/:did', async (req) => {
    const b = parseBody(PutKnowledgeDraftBody, req.body);
    return draftDto(updateDraft(ctx.store, req.params.did, b.revision, { text: b.text, ...(b.name ? { name: b.name } : {}) }));
  });
  app.post<{ Params: { did: string } }>('/api/v1/knowledge/drafts/:did/approve', async (req) => {
    const b = parseBody(PostKnowledgeDraftApproveBody, req.body);
    const r = approveKnowledgeDraft(ctx.store, req.params.did, b);
    layerChanged(ctx, r.draft.layer, r.draft.projectId);
    if (r.draft.moveFrom && b.afterMove === 'delete') layerChanged(ctx, 'project', r.draft.moveFrom.projectId);
    return { draft: draftDto(r.draft), name: r.name, file: r.file };
  });
  app.post<{ Params: { did: string } }>('/api/v1/knowledge/drafts/:did/reject', async (req) => draftDto(rejectKnowledgeDraft(ctx.store, req.params.did)));

  // Case distillation from a vulnerability.
  app.post<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/distill-case', async (req, reply) => {
    const b = parseBody(PostDistillCaseBody, req.body);
    const v = vulnerabilityCaseInput(ctx.store, req.params.vid);
    const d = ctx.engine.jobs.startDraft({
      layer: b.layer, projectId: b.layer === 'project' ? v.projectId : null, kind: 'case', text: v.text, organize: true,
      source: { kind: 'vulnerability', ref: req.params.vid, label: v.label },
    });
    reply.code(202);
    return draftDto(d);
  });

  // Move a project skill to global: preview with private-information hints, then a global draft.
  app.post<{ Params: { pid: string; name: string } }>('/api/v1/projects/:pid/knowledge/:name/move-to-global', async (req, reply) => {
    const b = parseBody(PostMoveToGlobalBody, req.body);
    const preview = moveToGlobalPreview(ctx.store, req.params.pid, req.params.name);
    if (!b.confirm) return preview;
    const d = ctx.engine.jobs.startDraft({
      layer: 'global', kind: 'skill', text: b.text ?? preview.text, organize: false, name: req.params.name,
      source: { kind: 'move_to_global', ref: `${req.params.pid}:${req.params.name}`, label: `项目 skill ${req.params.name}` },
      moveFrom: { projectId: req.params.pid, name: req.params.name },
    });
    reply.code(202);
    return draftDto(d);
  });
}
