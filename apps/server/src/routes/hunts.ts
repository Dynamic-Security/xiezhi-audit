// Risk hunts: bases, hunts over projects, results, promote, rerun /
// compare, verdict override and export.
import type { FastifyInstance } from 'fastify';
import { AppError, normalizePending, redact, type HuntBasis, type HuntBasisDto, type HuntDto, type HuntHitDto, type HuntResultsDto } from '@xiezhi/contracts';
import {
  compareHunts, createHunt, getBasis, getHunt, huntPlan, huntTargets, overrideHuntTarget, refreshHunt, rerunHunt, renameHunt, deleteHunt, updateBasis,
  type BasisRow, type HuntRow, type HuntScopeSpec, queries as Q,
} from '@xiezhi/engine';
import { renderHuntReport, type HuntReportModel } from '@xiezhi/report';
import { fromJson, type Store } from '@xiezhi/store';
import * as B from '../bodies.js';
import type { AppContext } from '../context.js';
import { expectedRevision, parseBody } from '../http.js';

const iso = (ms: number | null) => (ms ? new Date(ms).toISOString() : null);

export function basisDto(store: Store, b: BasisRow): HuntBasisDto {
  return {
    id: b.id, kind: b.kind, title: b.title, status: b.status as HuntBasisDto['status'], error: b.error, revision: b.revision,
    basis: b.basis_ref ? store.artifacts.getJson<HuntBasis>(b.basis_ref) : null, skillName: b.skill_name, model: b.model, createdAt: new Date(b.created_at).toISOString(),
  };
}

export function huntDto(store: Store, h: HuntRow, withPlan: boolean): HuntDto {
  const scope = fromJson<HuntScopeSpec>(h.scope, {});
  const summary = fromJson<Partial<HuntDto['summary']>>(h.summary, {});
  const plan = withPlan ? huntPlan(store, h.id) : null;
  return {
    id: h.id, title: h.title, status: h.status as HuntDto['status'], basisId: h.basis_id, basisKind: h.basis_kind, skillName: h.skill_name,
    scope: { all: !!scope.all, projectIds: scope.projectIds ?? [] }, rerunOfId: h.rerun_of_id,
    summary: { projects: 0, repositories: 0, affected: 0, notAffected: 0, pending: 0, unfinished: 0, hits: 0, projectVerdicts: {}, ...summary },
    createdAt: new Date(h.created_at).toISOString(), startedAt: iso(h.started_at), endedAt: iso(h.ended_at), basis: store.artifacts.getJson<HuntBasis>(h.basis_ref),
    plan: plan ? { projects: plan.projects, estimate: plan.estimate } : null,
    auditIds: Q.huntAuditIds(store, h.id),
  };
}

function evidenceOf(store: Store, ownerKind: string, ownerId: string) {
  return Q.evidenceWithRepo(store, ownerKind, ownerId)
    .map((e) => ({ kind: e.kind, repo: e.repo, path: e.path, startLine: e.start_line, endLine: e.end_line, note: e.note, verified: !!e.verified }));
}

export function huntResults(store: Store, id: string, projectId?: string): HuntResultsDto {
  refreshHunt(store, id);
  const h = getHunt(store, id);
  const targets = huntTargets(store, id).filter((t) => !projectId || t.projectId === projectId).map((t) => {
    const pc = Q.huntTargetPendingCondition(store, t.id);
    return { ...t, evidence: evidenceOf(store, 'risk_hunt_target', t.id), pendingCondition: normalizePending(pc ? JSON.parse(pc) : null) };
  });
  const auditIds = [...new Set(targets.map((t) => t.auditId).filter((x): x is string => !!x))];
  const hits: HuntHitDto[] = auditIds.flatMap((aid) => Q.huntHitRows(store, aid).map((f) => {
    const loc = JSON.parse(f.location) as { path: string; startLine: number; endLine: number };
    const d = store.artifacts.getJson<{ reasoning?: string; exploitConditions?: { condition: string; status: string; source: string }[] }>(f.detail_ref);
    const promotedNo = f.promoted_vulnerability_id ? Q.vulnDisplayNo(store, f.promoted_vulnerability_id) : undefined;
    return {
      id: f.id, projectId: f.project_id, projectName: f.project_name, repoName: f.repo_name, auditId: aid, title: f.title, severity: f.severity, category: f.category, confidence: f.confidence,
      location: { path: loc.path, startLine: loc.startLine, endLine: loc.endLine }, reasoning: d.reasoning ?? '', exploitConditions: d.exploitConditions ?? [],
      evidence: evidenceOf(store, 'finding', f.id), promotedVulnId: f.promoted_vulnerability_id, promotedDisplayNo: promotedNo ?? null,
    };
  }));
  return { hunt: huntDto(store, h, false), targets, hits };
}

export function registerHuntRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.post('/api/v1/hunt-bases', async (req, reply) => {
    const b = parseBody(B.PostHuntBasesBody, req.body);
    const input = b.kind === 'skill' ? { kind: 'skill' as const, skill: b.skill ?? '' } : { kind: b.kind, text: b.text ?? '' };
    if (input.kind === 'skill' && !input.skill) throw new AppError('COMMON_VALIDATION', 'skill is required');
    const id = ctx.engine.jobs.startBasis(input);
    reply.code(202);
    return { basisId: id };
  });
  app.get<{ Params: { bid: string } }>('/api/v1/hunt-bases/:bid', async (req) => basisDto(store, getBasis(store, req.params.bid)));
  app.patch<{ Params: { bid: string } }>('/api/v1/hunt-bases/:bid', async (req) => {
    const b = parseBody(B.PatchHuntBasesBidBody, req.body);
    return basisDto(store, updateBasis(store, req.params.bid, expectedRevision(req, b), b.basis));
  });
  app.post<{ Params: { bid: string } }>('/api/v1/hunt-bases/:bid/save-as-skill', async (req) => {
    const b = parseBody(B.PostHuntBasesBidSaveAsSkillBody, req.body);
    const d = ctx.engine.jobs.saveBasisAsSkill(req.params.bid, { category: b.category, ...(b.name ? { name: b.name } : {}) });
    return { name: d.name ?? '', draftId: d.id };
  });

  app.get('/api/v1/hunts', async () => Q.listHuntRows<HuntRow>(store).map((h) => {
    if (h.status === 'running') refreshHunt(store, h.id);
    return huntDto(store, getHunt(store, h.id), false);
  }));
  app.post('/api/v1/hunts', async (req, reply) => {
    const b = parseBody(B.PostHuntsBody, req.body);
    const id = createHunt(store, { basisId: b.basisId, scope: b.allProjects ? { all: true } : { projectIds: b.projectIds ?? [] }, ...(b.title ? { title: b.title } : {}) });
    ctx.engine.jobs.startPrecheck(id);
    reply.code(201);
    return huntDto(store, getHunt(store, id), true);
  });
  app.get<{ Params: { hid: string } }>('/api/v1/hunts/:hid', async (req) => {
    refreshHunt(store, req.params.hid);
    return huntDto(store, getHunt(store, req.params.hid), true);
  });
  app.patch<{ Params: { hid: string } }>('/api/v1/hunts/:hid', async (req) => {
    const b = parseBody(B.PatchHuntsHidBody, req.body);
    return huntDto(store, renameHunt(store, req.params.hid, b.title), false);
  });
  app.delete<{ Params: { hid: string } }>('/api/v1/hunts/:hid', async (req, reply) => {
    deleteHunt(store, req.params.hid);
    return reply.code(204).send();
  });
  app.post<{ Params: { hid: string } }>('/api/v1/hunts/:hid/confirm', async (req) => {
    const ids = ctx.engine.confirmHunt(req.params.hid, 'ui');
    for (const id of ids) if (Q.auditStatus(store, id) === 'planning') ctx.scheduler.plan(id);
    return huntDto(store, getHunt(store, req.params.hid), false);
  });
  app.get<{ Params: { hid: string }; Querystring: { projectId?: string } }>('/api/v1/hunts/:hid/results', async (req) => huntResults(store, req.params.hid, req.query.projectId));
  app.post<{ Params: { hid: string } }>('/api/v1/hunts/:hid/rerun', async (req, reply) => {
    const id = rerunHunt(store, req.params.hid);
    reply.code(201);
    return huntDto(store, getHunt(store, id), true);
  });
  app.get<{ Params: { hid: string }; Querystring: { with: string } }>('/api/v1/hunts/:hid/compare', async (req) => ({ items: compareHunts(store, req.params.hid, req.query.with) }));
  app.get<{ Params: { hid: string }; Querystring: { format?: string } }>('/api/v1/hunts/:hid/export', async (req, reply) => {
    const format = (req.query.format ?? 'md') as 'md' | 'html' | 'json';
    if (!['md', 'html', 'json'].includes(format)) throw new AppError('EXPORT_FORMAT_UNSUPPORTED', format);
    const r = huntResults(store, req.params.hid);
    const model: HuntReportModel = {
      title: r.hunt.title, status: r.hunt.status, basis: r.hunt.basis, summary: r.hunt.summary, startedAt: r.hunt.startedAt, endedAt: r.hunt.endedAt,
      targets: r.targets.map((t) => ({ projectName: t.projectName, repoName: t.repoName, verdict: t.verdict, reason: t.reason, verdictSource: t.verdictSource, delta: t.delta, evidence: t.evidence.map((e) => ({ path: e.path, startLine: e.startLine, note: e.note })) })),
      hits: r.hits.map((h) => ({ projectName: h.projectName, repoName: h.repoName, title: h.title, severity: h.severity, location: h.location, reasoning: h.reasoning, promotedDisplayNo: h.promotedDisplayNo })),
    };
    const text = redact(renderHuntReport(model, format), store.redactOptions());
    const type = format === 'json' ? 'application/json' : format === 'html' ? 'text/html' : 'text/markdown';
    reply.header('Content-Type', `${type}; charset=utf-8`).header('Content-Disposition', `attachment; filename="hunt-${r.hunt.id}.${format}"`);
    return text;
  });
  app.post<{ Params: { hitId: string } }>('/api/v1/hunt-hits/:hitId/promote', async (req) => ctx.engine.promoteHuntHit(req.params.hitId));
  app.patch<{ Params: { tid: string } }>('/api/v1/hunt-targets/:tid', async (req) => {
    const b = parseBody(B.PatchHuntTargetsTidBody, req.body);
    overrideHuntTarget(store, req.params.tid, b.verdict, b.reason);
    return { ok: true };
  });
}
