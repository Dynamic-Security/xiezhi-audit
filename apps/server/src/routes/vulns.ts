// Project vulnerabilities, review and identity decisions.
import type { FastifyInstance } from 'fastify';
import { AppError, CONFIRM_STATUSES, HANDLING_STATUSES, LIFECYCLES, SEVERITIES } from '@xiezhi/contracts';
import {
  batchReviewVulnerabilities, decideSuspectedMatch, getProject, mergeVulnerabilities, reviewStats, reviewVulnerability, splitVulnerability, undoIdentityOp, queries as Q,
} from '@xiezhi/engine';
import { exportProject } from '@xiezhi/report';
import * as B from '../bodies.js';
import type { AppContext } from '../context.js';
import { revisionDto, vulnDetail, vulnSummary } from '../dto.js';
import { etag, expectedRevision, idempotent, multi, paginate, parseBody } from '../http.js';

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const CONF_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };
const SORTABLE = new Set(['severity', 'confidence', 'displayNo', 'updatedAt', 'category']);
const RANKED: Record<string, Record<string, number>> = { severity: SEV_RANK, confidence: CONF_RANK };
const EXPORT_MIME: Record<string, string> = { md: 'text/markdown; charset=utf-8', html: 'text/html; charset=utf-8', json: 'application/json; charset=utf-8', sarif: 'application/sarif+json' };

export function registerVulnRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  const row = (id: string) => {
    const v = Q.getVulnerability<any>(store, id);
    if (!v) throw new AppError('VULN_NOT_FOUND', id);
    return v;
  };

  app.get<{ Params: { pid: string }; Querystring: Record<string, string | string[] | undefined> }>('/api/v1/projects/:pid/vulnerabilities', async (req) => {
    const p = getProject(store, req.params.pid);
    const q = req.query;
    const f = {
      severity: multi(q.severity), confirmation: multi(q.confirmation), handling: multi(q.handling), lifecycle: multi(q.lifecycle),
      category: multi(q.category), repo: multi(q.repo), source: multi(q.source),
    };
    for (const s of f.severity) if (!SEVERITIES.includes(s as never)) throw new AppError('COMMON_VALIDATION', 'severity');
    for (const s of f.confirmation) if (!CONFIRM_STATUSES.includes(s as never)) throw new AppError('COMMON_VALIDATION', 'confirmation');
    for (const s of f.handling) if (!HANDLING_STATUSES.includes(s as never)) throw new AppError('COMMON_VALIDATION', 'handling');
    for (const s of f.lifecycle) if (!LIFECYCLES.includes(s as never)) throw new AppError('COMMON_VALIDATION', 'lifecycle');
    const text = typeof q.q === 'string' ? q.q.toLowerCase() : '';
    let items = Q.activeVulnerabilities<any>(store, p.id).map((v) => vulnSummary(store, v))
      .filter((v) => (!f.severity.length || f.severity.includes(v.severity)) && (!f.confirmation.length || f.confirmation.includes(v.confirmStatus))
        && (!f.handling.length || f.handling.includes(v.handlingStatus)) && (!f.lifecycle.length || f.lifecycle.includes(v.lifecycle))
        && (!f.category.length || f.category.includes(v.category)) && (!f.repo.length || f.repo.includes(v.repo))
        && (!f.source.length || v.sources.some((s) => f.source.includes(s)))
        && (!text || `V-${v.displayNo} ${v.title} ${v.category}`.toLowerCase().includes(text)));
    const sort = typeof q.sort === 'string' ? q.sort : '-severity,displayNo';
    const keys = sort.split(',').map((k) => ({ desc: k.startsWith('-'), key: k.replace(/^-/, '') }));
    for (const k of keys) if (!SORTABLE.has(k.key)) throw new AppError('COMMON_VALIDATION', `sort ${k.key}`);
    items = items.sort((a, b) => {
      for (const k of keys) {
        const rank = RANKED[k.key];
        const av = rank ? rank[(a as any)[k.key]] ?? 0 : (a as any)[k.key];
        const bv = rank ? rank[(b as any)[k.key]] ?? 0 : (b as any)[k.key];
        const c = av < bv ? -1 : av > bv ? 1 : 0;
        if (c) return k.desc ? -c : c;
      }
      return 0;
    });
    return paginate(items, { ...(typeof q.limit === 'string' ? { limit: q.limit } : {}), ...(typeof q.cursor === 'string' ? { cursor: q.cursor } : {}) });
  });

  app.get<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid', async (req, reply) => {
    const v = row(req.params.vid);
    etag(reply, v.rev);
    return vulnDetail(store, v);
  });

  app.patch<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid', async (req, reply) => {
    const b = parseBody(B.PatchVulnerabilitiesVidBody, req.body);
    const expected = expectedRevision(req, b);
    const { rev } = reviewVulnerability(store, req.params.vid, b, expected, 'user');
    etag(reply, rev);
    return vulnDetail(store, row(req.params.vid));
  });

  // "Suspected same" decision: confirm the link or separate the finding.
  app.post<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/match-decision', async (req, reply) => {
    const b = parseBody(B.PostVulnerabilitiesVidMatchDecisionBody, req.body);
    const expected = expectedRevision(req, b);
    const v = row(req.params.vid);
    if (v.rev !== expected) throw new AppError('COMMON_REVISION_CONFLICT', `current revision ${v.rev}`, { revision: v.rev });
    const r = decideSuspectedMatch(store, v.id, b.occurrenceId, b.decision, { actor: 'user', ...(b.reason ? { reason: b.reason } : {}) });
    const after = row(v.id);
    etag(reply, after.rev);
    return { vulnerability: vulnDetail(store, after), created: r.created };
  });

  // Reverification: single and batch share one entry; creates a reverify audit
  // that plans deterministically and starts without a confirmation step.
  app.post('/api/v1/reverifications', async (req, reply) => idempotent(store, req, reply, 'POST /reverifications', async () => {
    const b = parseBody(B.PostReverificationsBody, req.body);
    const id = ctx.engine.createReverify({ vulnIds: b.vulnIds, origin: 'ui', ...(b.refs ? { refs: b.refs } : {}), ...(b.note ? { note: b.note } : {}) });
    ctx.scheduler.plan(id);
    return { status: 202, body: { auditId: id, planId: id, status: 'planning' as const } };
  }));

  // Manual identity corrections. Optimistic concurrency on the vulnerability acted on.
  app.post('/api/v1/vulnerabilities/merge', async (req) => {
    const b = parseBody(B.PostVulnerabilitiesMergeBody, req.body);
    const target = row(b.targetId);
    const expected = expectedRevision(req, b);
    mergeVulnerabilities(store, { sourceIds: b.sourceIds, targetId: target.id, reason: b.reason, actor: 'user', targetRevision: expected });
    return vulnDetail(store, row(target.id));
  });
  app.post<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/split', async (req) => {
    const b = parseBody(B.PostVulnerabilitiesVidSplitBody, req.body);
    const expected = expectedRevision(req, b);
    const created = splitVulnerability(store, { vulnId: row(req.params.vid).id, entryKeys: b.entryKeys ?? [], fingerprints: b.fingerprints ?? [], reason: b.reason, actor: 'user', revision: expected });
    return { vulnerability: vulnDetail(store, row(req.params.vid)), created };
  });
  app.post<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/identity-undo', async (req) => {
    const b = parseBody(B.PostVulnerabilitiesVidIdentityUndoBody, req.body);
    const expected = expectedRevision(req, b);
    undoIdentityOp(store, { vulnId: row(req.params.vid).id, revisionId: b.revisionId, actor: 'user', revision: expected, ...(b.reason ? { reason: b.reason } : {}) });
    return vulnDetail(store, row(req.params.vid));
  });

  // Batch review: handling status, confirm or false positive with one shared
  // reason; the single-item rules apply per item and skipped items come back with their error code.
  app.post('/api/v1/vulnerabilities/batch-updates', async (req) => {
    const b = parseBody(B.PostVulnerabilitiesBatchUpdatesBody, req.body);
    return {
      results: batchReviewVulnerabilities(store, {
        items: b.items, ...(b.confirmStatus ? { confirmStatus: b.confirmStatus } : {}), ...(b.handlingStatus ? { handlingStatus: b.handlingStatus } : {}),
        ...(b.reason ? { reason: b.reason } : {}), ...(b.reviewMs !== undefined ? { reviewMs: b.reviewMs } : {}),
      }, 'user'),
    };
  });

  // G1 online metric: human review time per decision, from the revisions.
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/review-stats', async (req) => reviewStats(store, getProject(store, req.params.pid).id));

  // Project-level export: every active vulnerability across audits, rendered by packages/report.
  app.get<{ Params: { pid: string }; Querystring: Record<string, string | string[] | undefined> }>('/api/v1/projects/:pid/export', async (req, reply) => {
    const p = getProject(store, req.params.pid);
    const q = req.query;
    const format = (typeof q.format === 'string' ? q.format : 'md') as 'md' | 'html' | 'json' | 'sarif';
    const vulnIds = multi(q.vulnIds);
    const text = exportProject(store, p.id, format, {
      ...(q.snippets === '0' || q.snippets === '1' ? { snippets: q.snippets === '1' } : {}),
      ...(q.localRoots === '0' || q.localRoots === '1' ? { localRoots: q.localRoots === '1' } : {}),
      filter: { ...(vulnIds.length ? { vulnIds } : {}), ...(q.includePending === '0' ? { includePending: false } : {}) },
    });
    reply.header('Content-Type', EXPORT_MIME[format]!);
    reply.header('Content-Disposition', `attachment; filename="project-${p.id}.${format}"`);
    reply.header('Content-Security-Policy', "sandbox; default-src 'none'; style-src 'unsafe-inline'");
    return reply.send(text);
  });

  app.get<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/revisions', async (req) => {
    row(req.params.vid);
    return Q.vulnRevisions<any>(store, req.params.vid).map((r) => revisionDto(store, r));
  });

  /** Trajectory fragments that produced the vulnerability (bidirectional trace). */
  app.get<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/trajectory-links', async (req) => {
    row(req.params.vid);
    // Merged vulnerabilities are read through their target.
    return Q.trajectoryLinks(store, req.params.vid)
      .map((r) => ({ auditId: r.audit_id, auditTitle: r.title, findingId: r.finding_id, findingNo: r.display_no, stepId: r.step_id, presence: r.presence }));
  });
}
