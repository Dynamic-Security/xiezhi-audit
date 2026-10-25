// Audits: plans, controls, questions, interventions, trajectory, usage, findings, coverage, snapshot
// source, exports.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { effectiveSkills, scanLayer, splitFrontmatter } from '@xiezhi/knowledge';
import { AppError, AUDIT_STATUSES, normalizePending, TRAJECTORY_GROUPS, TRAJECTORY_NOISE, newId, type TrajectoryGroup, type AuditStatus, type CoverageDto, type CoverageItemDto, type EventType, type ExportDto, type SnapshotManifest, type SourceDto, type TreeEntryDto, type UsageRow } from '@xiezhi/contracts';
import { fromJson } from '@xiezhi/store';
import { SnapshotView } from '@xiezhi/context';
import { aiReportFallback, aiReportModel, answerQuestion, importSarif, coverageItemDetail, getExportJob, listExportJobs, queries as Q, renderExport, type ExportRow, listWriteRequests, auditCoverage, estimateAiReport, compareAudits, dismissQuestion, executionOverview, getAudit, intervene, listSteps, setAuditConcurrency, type AuditRow } from '@xiezhi/engine';
import { knowledgeUsage } from '@xiezhi/report';
import * as B from '../bodies.js';
import type { AppContext } from '../context.js';
import { connectorWriteDto } from './connectors.js';
import { auditDetail, auditSummary, eventDto, findingDto, planDto, projectDto, questionDto, stepDto } from '../dto.js';
import { etag, expectedRevision, idempotent, multi, paginate, parseBody } from '../http.js';

const TERMINAL: AuditStatus[] = ['completed', 'partial', 'failed', 'cancelled'];
const MIME: Record<string, string> = { md: 'text/markdown; charset=utf-8', html: 'text/html; charset=utf-8', json: 'application/json; charset=utf-8', sarif: 'application/sarif+json' };
const EXT: Record<string, string> = { md: 'md', html: 'html', json: 'json', sarif: 'sarif' };

function repoView(ctx: AppContext, auditId: string, repoId: string): SnapshotView {
  const row = Q.auditRepoSnapshot(ctx.store, auditId, repoId);
  if (!row) throw new AppError('SOURCE_NOT_IN_MANIFEST', 'repository has no snapshot in this audit');
  const manifest = ctx.store.artifacts.getJson<SnapshotManifest>(row.manifest_ref);
  return new SnapshotView(row.name, `${ctx.store.paths.snapshots}/${row.root_hash}`, manifest);
}

function exportDto(r: ExportRow): ExportDto {
  const opts = fromJson<{ reportSkill?: string }>(r.options, {});
  return {
    id: r.id, auditId: r.audit_id, format: r.format as ExportDto['format'], status: r.status as ExportDto['status'], bytes: r.bytes,
    createdAt: new Date(r.created_at).toISOString(), fileName: `audit-${r.audit_id}${r.mode === 'ai' ? '-ai' : ''}.${EXT[r.format]}`,
    warning: r.format === 'sarif' ? 'SARIF 保留被审代码原文，文件可能包含代码中的明文密钥' : null,
    mode: r.mode as ExportDto['mode'], model: r.model, tokens: r.tokens, progress: r.progress as ExportDto['progress'], reportSkill: opts.reportSkill ?? null,
    error: r.status === 'failed' ? r.error : null, verification: fromJson<ExportDto['verification']>(r.verification, null),
  };
}

/** A coverage item with what it is (the interface of an entry, the risky call of a sink). */
function coverageItemDto(indexesDir: string, c: ReturnType<typeof Q.coverageItems>[number]): CoverageItemDto {
  return {
    id: c.id, kind: c.kind as CoverageItemDto['kind'], repo: c.repo, targetId: c.target_id, category: c.category, path: c.path, startLine: c.start_line, endLine: c.end_line,
    status: c.status, verdict: c.verdict, detail: coverageItemDetail(indexesDir, c), findingId: c.finding_id,
  };
}

export function registerAuditRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store, engine, scheduler } = ctx;
  const audit = (id: string): AuditRow & { draft_rev: number } => getAudit(store, id) as AuditRow & { draft_rev: number };

  // ---- plans ----
  // external scanner results (SARIF 2.1.0) for an audit that has not finished.
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/external-results', { bodyLimit: 32 * 1024 * 1024 }, async (req) => {
    const b = parseBody(B.PostExternalResultsBody, req.body);
    return importSarif(ctx.store, req.params.aid, b.sarif);
  });
  app.post('/api/v1/audit-plans', async (req, reply) => idempotent(store, req, reply, 'POST /audit-plans', async () => {
    const b = parseBody(B.PostAuditPlansBody, req.body);
    const id = engine.createAudit({
      projectId: b.projectId, origin: 'ui', ...(b.repository ? { repository: b.repository } : {}), ...(b.ref ? { ref: b.ref } : {}),
      ...(b.mode ? { mode: b.mode } : {}), ...(b.related ? { related: b.related } : {}), ...(b.repositories ? { repositories: b.repositories } : {}), ...(b.refs ? { refs: b.refs } : {}),
      ...(b.scene ? { scene: b.scene } : {}), ...(b.baseRef ? { baseRef: b.baseRef } : {}), ...(b.baseRefs ? { baseRefs: b.baseRefs } : {}), ...(b.baseAuditId ? { baseAuditId: b.baseAuditId } : {}),
      ...(b.title ? { title: b.title } : {}), ...(b.strategyOverride ? { strategyOverride: b.strategyOverride } : {}), ...(b.autoStart ? { autoStart: true } : {}),
    });
    scheduler.plan(id);
    return { status: 202, body: { auditId: id, planId: id, status: 'planning' } };
  }));
  app.get<{ Params: { id: string } }>('/api/v1/audit-plans/:id', async (req, reply) => {
    const a = audit(req.params.id);
    etag(reply, a.draft_rev);
    return planDto(store, a);
  });
  app.patch<{ Params: { id: string } }>('/api/v1/audit-plans/:id', async (req, reply) => {
    const b = parseBody(B.PatchAuditPlansIdBody, req.body);
    const expected = expectedRevision(req, b);
    const updated = engine.updatePlan(req.params.id, expected, { strategyOverride: b.strategyOverride, ...(b.title ? { title: b.title } : {}) });
    etag(reply, updated.draft_rev);
    return planDto(store, updated);
  });
  app.post<{ Params: { id: string } }>('/api/v1/audit-plans/:id/confirm', async (req, reply) => idempotent(store, req, reply, `POST /audit-plans/${req.params.id}/confirm`, async () => {
    const a = audit(req.params.id);
    if (a.status !== 'awaiting_confirm') throw new AppError(a.status === 'planning' ? 'AUDIT_PLAN_NOT_READY' : 'AUDIT_INVALID_TRANSITION', `audit is ${a.status}`);
    engine.confirm(a.id);
    scheduler.kick();
    return { status: 200, body: auditDetail(store, audit(a.id)) };
  }));

  // ---- audits ----
  app.get<{ Querystring: { projectId?: string; status?: string | string[]; scene?: string; limit?: string; cursor?: string } }>('/api/v1/audits', async (req) => {
    const statuses = multi(req.query.status);
    for (const s of statuses) if (!AUDIT_STATUSES.includes(s as AuditStatus)) throw new AppError('COMMON_VALIDATION', 'status');
    const rows = Q.listAudits(store, { ...(req.query.projectId ? { projectId: req.query.projectId } : {}), ...(req.query.scene ? { scene: req.query.scene } : {}), statuses });
    const page = paginate(rows, req.query);
    return { ...page, items: page.items.map((a) => auditSummary(store, a)) };
  });
  app.get<{ Params: { aid: string } }>('/api/v1/audits/:aid', async (req) => auditDetail(store, audit(req.params.aid)));

  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/cancel', async (req) => {
    engine.cancel(req.params.aid);
    return auditDetail(store, audit(req.params.aid));
  });
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/pause', async (req) => {
    await engine.pause(req.params.aid);
    return auditDetail(store, audit(req.params.aid));
  });
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/resume', async (req) => {
    const a = audit(req.params.aid);
    if (a.status === 'waiting_budget') throw new AppError('AUDIT_INVALID_TRANSITION', 'waiting for budget: add budget or decline');
    const b = req.body ? parseBody(B.PostAuditsAidResumeBody, req.body) : {};
    engine.resume(a.id, { ...(b.restartFiltered ? { restartFiltered: true } : {}), ...(b.switchModel ? { switchModel: b.switchModel, ...(b.switchScope ? { switchScope: b.switchScope } : {}) } : {}) });
    scheduler.afterResume(a.id);
    return auditDetail(store, audit(a.id));
  });
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/budget-grants', async (req, reply) => idempotent(store, req, reply, `POST /audits/${req.params.aid}/budget-grants`, async () => {
    const b = parseBody(B.PostAuditsAidBudgetGrantsBody, req.body);
    if (!b.tokens && !b.durationSec && !b.liftStageQuotas) throw new AppError('COMMON_VALIDATION', 'tokens, durationSec or liftStageQuotas required');
    if (b.liftStageQuotas && b.stage) throw new AppError('COMMON_VALIDATION', 'stage and liftStageQuotas exclude each other');
    const key = (req.headers['idempotency-key'] as string | undefined) ?? newId('budgetAdjustment');
    engine.topUp(req.params.aid, b, key, 'user');
    scheduler.kick();
    return { status: 200, body: auditDetail(store, audit(req.params.aid)) };
  }));
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/budget-grants/decline', async (req) => {
    engine.declineBudget(req.params.aid);
    scheduler.kick();
    return auditDetail(store, audit(req.params.aid));
  });
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/rerun', async (req, reply) => idempotent(store, req, reply, `POST /audits/${req.params.aid}/rerun`, async () => {
    const id = engine.rerun(audit(req.params.aid).id, 'ui');
    scheduler.plan(id);
    return { status: 202, body: { auditId: id, planId: id, status: 'planning' as const } };
  }));
  app.get<{ Params: { aid: string }; Querystring: { with: string } }>('/api/v1/audits/:aid/compare', async (req) => {
    const c = compareAudits(store, audit(req.params.aid).id, req.query.with);
    return { ...c, base: { ...c.base, createdAt: new Date(c.base.createdAt).toISOString() }, target: { ...c.target, createdAt: new Date(c.target.createdAt).toISOString() } };
  });

  // ---- questions & interventions ----
  app.get<{ Params: { aid: string } }>('/api/v1/audits/:aid/questions', async (req) => {
    audit(req.params.aid);
    return Q.auditQuestions<any>(store, req.params.aid).map(questionDto);
  });
  app.post<{ Params: { qid: string } }>('/api/v1/questions/:qid/answer', async (req) => {
    const b = parseBody(B.PostQuestionsQidAnswerBody, req.body);
    const r = await answerQuestion(engine, req.params.qid, b.answer);
    return { ...r, question: questionDto(Q.getQuestion<any>(store, req.params.qid)) };
  });
  app.post<{ Params: { qid: string } }>('/api/v1/questions/:qid/dismiss', async (req) => {
    dismissQuestion(store, req.params.qid);
    return questionDto(Q.getQuestion<any>(store, req.params.qid));
  });
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/interventions', async (req) => {
    const b = parseBody(B.PostAuditsAidInterventionsBody, req.body);
    return intervene(engine, req.params.aid, { kind: b.kind, text: b.text, ...(b.target ? { target: b.target } : {}) });
  });

  // ---- steps, trajectory, usage ----
  // Execution overview: phases, candidates with progress, agent sessions and live concurrency.
  app.get<{ Params: { aid: string } }>('/api/v1/audits/:aid/execution', async (req) => { audit(req.params.aid); return executionOverview(store, req.params.aid); });
  // Adjust the audit's parallel sessions while it runs.
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/concurrency', async (req) => {
    const b = parseBody(B.PostAuditConcurrencyBody, req.body);
    return setAuditConcurrency(engine, req.params.aid, b.sessions);
  });
  app.get<{ Params: { aid: string; sid: string } }>('/api/v1/audits/:aid/steps/:sid/filtered', async (req) => { audit(req.params.aid); return Q.filteredStepDetail(store, req.params.aid, req.params.sid); });
  app.get<{ Params: { aid: string } }>('/api/v1/audits/:aid/steps', async (req) => {
    audit(req.params.aid);
    return listSteps(store, req.params.aid).map(stepDto);
  });
  app.get<{ Params: { aid: string }; Querystring: { after?: string; type?: string | string[]; step?: string; q?: string; limit?: string; all?: string } }>('/api/v1/audits/:aid/trajectory', async (req) => {
    audit(req.params.aid);
    const after = Number(req.query.after ?? 0) || 0;
    const groups = multi(req.query.type);
    for (const g of groups) if (!(g in TRAJECTORY_GROUPS)) throw new AppError('COMMON_VALIDATION', `type ${g}`);
    const types = groups.length ? groups.flatMap((g): readonly EventType[] => TRAJECTORY_GROUPS[g as TrajectoryGroup]) : undefined;
    const limit = Math.min(Number(req.query.limit ?? 500) || 500, 2000);
    const q = req.query.q?.toLowerCase();
    let events = store.listEvents(req.params.aid, after, types);
    if (!types && req.query.all !== '1') events = events.filter((e) => !(TRAJECTORY_NOISE as readonly EventType[]).includes(e.type));
    if (req.query.step) events = events.filter((e) => e.stepId === req.query.step);
    if (q) events = events.filter((e) => JSON.stringify(e.payload).toLowerCase().includes(q));
    const items = events.slice(0, limit).map(eventDto);
    return { items, nextAfter: items.length ? items[items.length - 1]!.seq : after, hasMore: events.length > limit };
  });
  app.get<{ Params: { aid: string }; Querystring: { groupBy?: string } }>('/api/v1/audits/:aid/usage', async (req) => {
    audit(req.params.aid);
    const by = req.query.groupBy ?? 'step';
    if (!['step', 'model', 'stage'].includes(by)) throw new AppError('COMMON_VALIDATION', 'groupBy');
    const rows = new Map<string, UsageRow>();
    for (const s of listSteps(store, req.params.aid)) {
      if (s.tokens_in + s.tokens_out + s.tokens_cached === 0 && s.cost_micros === null) continue;
      const key = by === 'model' ? (s.model ? `${s.provider}/${s.model}` : '（确定性处理）') : s.kind;
      const r = rows.get(key) ?? { key, tokensIn: 0, tokensOut: 0, tokensCached: 0, costMicros: 0, unknownCostCalls: 0, calls: 0 };
      r.tokensIn += s.tokens_in;
      r.tokensOut += s.tokens_out;
      r.tokensCached += s.tokens_cached;
      r.calls += 1;
      if (s.cost_micros === null) r.unknownCostCalls += 1; else r.costMicros = (r.costMicros ?? 0) + s.cost_micros;
      rows.set(key, r);
    }
    return [...rows.values()];
  });

  // ---- findings ----
  app.get<{ Params: { aid: string }; Querystring: { severity?: string | string[]; state?: string | string[] } }>('/api/v1/audits/:aid/findings', async (req) => {
    audit(req.params.aid);
    const sev = multi(req.query.severity);
    const states = multi(req.query.state);
    const rows = Q.auditFindings<any>(store, req.params.aid)
      .filter((f) => (states.length ? states.includes(f.state) : ['canonical', 'insufficient'].includes(f.state)) && (!sev.length || sev.includes(f.severity)));
    return rows.map((f) => findingDto(store, f));
  });

  // ---- knowledge used (G9) ----
  app.get<{ Params: { aid: string } }>('/api/v1/audits/:aid/knowledge-usage', async (req) => {
    const a = audit(req.params.aid);
    const u = knowledgeUsage(store, a.id);
    return { ...u, totalTokens: fromJson<{ tokens?: number }>(a.budget_consumed, {}).tokens ?? 0 };
  });

  // ---- coverage ----
  app.get<{ Params: { aid: string } }>('/api/v1/audits/:aid/coverage', async (req) => {
    const a = audit(req.params.aid);
    const strategy = JSON.parse(a.strategy_frozen ?? a.strategy_draft) as { tools: { coverageCompare: boolean } };
    const children = Q.childAudits(store, a.id);
    const backfills = children
      .map((x) => ({ x, targets: fromJson<{ backfill?: { targets: string[] } }>(x.scope, {}).backfill?.targets }))
      .filter((y) => !!y.targets)
      .map(({ x, targets }) => ({
        auditId: x.id, title: x.title, status: x.status as CoverageDto['backfills'][number]['status'], targets: targets!.length,
        concluded: Q.concludedCoverageCount(store, x.id),
      }));
    const st = strategy as { stages?: { logicReview?: boolean; threatHypotheses?: boolean } };
    // 追加执行: supplements started from this audit; their hypotheses count in its coverage.
    const supplements = children
      .map((x) => ({ x, sup: fromJson<{ supplement?: { auditId: string; kind: 'logic_review' | 'threat_hypotheses' } }>(x.scope, {}).supplement }))
      .filter((y) => y.sup?.auditId === a.id)
      .map(({ x, sup }) => ({
        auditId: x.id, title: x.title, status: x.status as CoverageDto['supplements'][number]['status'], kind: sup!.kind,
        hypotheses: Q.threatHypothesisCount(store, x.id),
      }));
    const out: CoverageDto = {
      enabled: strategy.tools.coverageCompare, repos: auditCoverage(store, a.id), backfills,
      // the logic review is part of risk-hypothesis-first (old strategies with logicReview count as on).
      analyses: { logicReview: st.stages?.logicReview === true, threatHypotheses: st.stages?.threatHypotheses === true || st.stages?.logicReview === true }, supplements,
      supplementable: ['completed', 'partial'].includes(a.status) && ['full', 'incremental'].includes(a.scene)
        && !(['backfill', 'supplement'] as const).some((k) => fromJson<Record<string, unknown>>(a.scope, {})[k]),
    };
    return out;
  });
  app.get<{ Params: { aid: string }; Querystring: { kind?: string; repo?: string; status?: string | string[] } }>('/api/v1/audits/:aid/coverage/items', async (req) => {
    audit(req.params.aid);
    const statuses = multi(req.query.status);
    return Q.coverageItems(store, req.params.aid)
      .filter((c) => (!req.query.kind || c.kind === req.query.kind) && (!req.query.repo || c.repo === req.query.repo || c.repository_id === req.query.repo) && (!statuses.length || statuses.includes(c.status)))
      .map((c) => coverageItemDto(store.paths.indexes, c));
  });

  app.get<{ Params: { aid: string }; Querystring: { kind?: string; repo?: string } }>('/api/v1/audits/:aid/coverage/uncovered', async (req) => {
    audit(req.params.aid);
    return Q.coverageItems(store, req.params.aid, true)
      .filter((c) => (!req.query.kind || c.kind === req.query.kind) && (!req.query.repo || c.repo === req.query.repo || c.repository_id === req.query.repo))
      .map((c) => coverageItemDto(store.paths.indexes, c));
  });
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/coverage/backfills', async (req, reply) => idempotent(store, req, reply, `POST /audits/${req.params.aid}/coverage/backfills`, async () => {
    const b = parseBody(B.PostAuditsAidCoverageBackfillsBody, req.body);
    if (!b.all && !b.itemIds?.length) throw new AppError('COMMON_VALIDATION', 'itemIds or all:true');
    const id = engine.createBackfill({ auditId: audit(req.params.aid).id, origin: 'ui', ...(b.all ? { all: true } : { itemIds: b.itemIds! }) });
    scheduler.plan(id);
    return { status: 202, body: { auditId: id, planId: id, status: 'planning' as const } };
  }));

  // 追加执行: an optional analysis on a finished full / incremental audit, same snapshots, starts at once.
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/supplements', async (req, reply) => idempotent(store, req, reply, `POST /audits/${req.params.aid}/supplements`, async () => {
    const b = parseBody(B.PostAuditsAidSupplementsBody, req.body);
    const id = engine.createSupplement({ auditId: audit(req.params.aid).id, kind: b.kind, ...(b.hypothesisIds ? { hypothesisIds: b.hypothesisIds } : {}), ...(b.domainIds ? { domainIds: b.domainIds } : {}), origin: 'ui' });
    scheduler.plan(id);
    return { status: 202, body: { auditId: id, planId: id, status: 'planning' as const } };
  }));

  // ---- snapshot source (manifest-only, never the live working tree) ----
  app.get<{ Params: { aid: string; rid: string }; Querystring: { path?: string } }>('/api/v1/audits/:aid/repos/:rid/tree', async (req) => {
    audit(req.params.aid);
    const view = repoView(ctx, req.params.aid, req.params.rid);
    const prefix = (req.query.path ?? '').replace(/^\/+|\/+$/g, '');
    const seen = new Map<string, TreeEntryDto>();
    for (const f of view.listFiles()) {
      if (prefix && !f.path.startsWith(`${prefix}/`)) continue;
      const rest = prefix ? f.path.slice(prefix.length + 1) : f.path;
      const [head, ...tail] = rest.split('/');
      const path = prefix ? `${prefix}/${head}` : head!;
      if (tail.length) { if (!seen.has(path)) seen.set(path, { name: head!, path, kind: 'dir' }); } else seen.set(path, { name: head!, path, kind: 'file', lines: f.lines, lang: f.lang ?? null });
    }
    return [...seen.values()].sort((a, b) => (a.kind === b.kind ? a.name.localeCompare(b.name) : a.kind === 'dir' ? -1 : 1));
  });
  app.get<{ Params: { aid: string; rid: string }; Querystring: { path?: string; from?: string; to?: string } }>('/api/v1/audits/:aid/repos/:rid/source', async (req) => {
    audit(req.params.aid);
    const view = repoView(ctx, req.params.aid, req.params.rid);
    let rel: string;
    try {
      rel = view.guard(req.query.path ?? '');
    } catch {
      throw new AppError('SOURCE_NOT_IN_MANIFEST');
    }
    const lines = view.lines(rel);
    const from = Math.max(1, Number(req.query.from ?? 1) || 1);
    const to = Math.min(lines.length, Math.max(from, Number(req.query.to ?? from + 400) || from + 400), from + 2000);
    return { repo: view.repo, path: rel, from, to, totalLines: lines.length, lines: lines.slice(from - 1, to), rootHash: view.rootHash } satisfies SourceDto;
  });

  /**
   * The chosen report skill (category `report`, project layer first) and its optional `template.md`
   * Without a template the default layout is kept.
   */
  const reportTemplate = (projectId: string, name: string): string | null => {
    const eff = effectiveSkills(scanLayer(store.paths.knowledgeGlobal, 'global'), scanLayer(join(store.paths.projects, projectId, 'knowledge'), 'project'));
    const s = eff.find((x) => x.name === name);
    if (!s || s.category !== 'report') throw new AppError('COMMON_VALIDATION', `report skill ${name} is not available for this project`);
    const file = s.dir ? join(s.dir, 'template.md') : null;
    return file && existsSync(file) ? readFileSync(file, 'utf8') : null;
  };
  /** The report skill as instructions for the AI report: its body, then its template if any. */
  const reportInstructions = (projectId: string, name: string): string => {
    const eff = effectiveSkills(scanLayer(store.paths.knowledgeGlobal, 'global'), scanLayer(join(store.paths.projects, projectId, 'knowledge'), 'project'));
    const s = eff.find((x) => x.name === name);
    if (!s || s.category !== 'report') throw new AppError('COMMON_VALIDATION', `report skill ${name} is not available for this project`);
    const body = splitFrontmatter(readFileSync(s.entry, 'utf8')).body.trim();
    const tpl = reportTemplate(projectId, name);
    return tpl ? `${body}\n\n模板（按这个结构组织章节；{{…}} 为原确定性报告的章节位置，可忽略占位符本身）：\n${tpl}` : body;
  };
  const exportFilter = (b: { vulnIds?: string[]; includePending?: boolean; trajectory?: boolean }) =>
    ({ ...(b.vulnIds ? { vulnIds: b.vulnIds } : {}), ...(b.includePending === false ? { includePending: false } : {}), ...(b.trajectory ? { trajectory: true } : {}) });

  app.get<{ Params: { aid: string }; Querystring: { includePending?: string; snippets?: string } }>('/api/v1/audits/:aid/ai-report', async (req) => {
    const a = audit(req.params.aid);
    const d = aiReportModel(store, a.id);
    const snippets = req.query.snippets !== undefined ? req.query.snippets === '1' : store.config.export.snippets;
    return { ...d, estimate: estimateAiReport(store, a.id, exportFilter({ includePending: req.query.includePending !== '0' }), snippets) };
  });
  app.get<{ Params: { eid: string } }>('/api/v1/exports/:eid/preview', async (req) => {
    const r = getExportJob(store, req.params.eid);
    if (!r || r.status !== 'succeeded' || !r.markdown_ref) throw new AppError('EXPORT_NOT_FOUND');
    return { markdown: store.artifacts.getText(r.markdown_ref) };
  });

  // ---- exports ----
  app.post('/api/v1/exports', async (req, reply) => idempotent(store, req, reply, 'POST /exports', async () => {
    const b = parseBody(B.PostExportsBody, req.body);
    const a = audit(b.ids[0]!);
    if (!TERMINAL.includes(a.status) && a.status !== 'waiting_budget' && a.status !== 'paused' && a.status !== 'interrupted') {
      throw new AppError('AUDIT_INVALID_TRANSITION', 'export is available once the audit has stopped');
    }
    const reportSkill = b.reportSkill ?? store.config.export.reportSkill ?? null;
    if (b.mode === 'ai') {
      // the report model writes md / html in the background; the client polls the export.
      if (b.format !== 'md' && b.format !== 'html') throw new AppError('COMMON_VALIDATION', 'AI reports are Markdown or HTML');
      const d = aiReportModel(store, a.id);
      const model = b.model ?? d.model;
      if (!store.config.modelProviders.some((p) => p.id === model.provider && p.models.some((m) => m.id === model.model))) {
        throw new AppError('CONFIG_INVALID', `model ${model.provider}/${model.model} is not configured`);
      }
      const fb = aiReportFallback(store, a.id, model);
      const snippets = b.snippets ?? store.config.export.snippets;
      const opts = { snippets, ...(reportSkill ? { reportSkill } : {}), ...exportFilter(b) };
      const eid = ctx.engine.jobs.startAiReport({
        auditId: a.id, format: b.format, model, fallback: fb, instructions: reportSkill ? reportInstructions(a.project_id, reportSkill) : null,
        filter: exportFilter(b), snippets,
      }, opts);
      return { status: 202, body: exportDto(getExportJob(store, eid)!) };
    }
    const template = reportSkill ? reportTemplate(a.project_id, reportSkill) : null;
    const opts = {
      ...(b.snippets !== undefined ? { snippets: b.snippets } : {}), ...(b.localRoots !== undefined ? { localRoots: b.localRoots } : {}),
      ...(reportSkill ? { reportSkill } : {}),
      ...(b.vulnIds ? { vulnIds: b.vulnIds } : {}), ...(b.includePending === false ? { includePending: false } : {}), ...(b.trajectory ? { trajectory: true } : {}),
    };
    const filter = { ...(b.vulnIds ? { vulnIds: b.vulnIds } : {}), ...(b.includePending === false ? { includePending: false } : {}), ...(b.trajectory ? { trajectory: true } : {}) };
    const job = renderExport(store, a.id, b.format, opts, { ...opts, template, filter }, (e) => ctx.log('error', 'export failed', { auditId: a.id, error: String(e.message) }));
    return { status: 202, body: exportDto(job) };
  }));
  app.get<{ Params: { eid: string } }>('/api/v1/exports/:eid', async (req) => {
    const r = getExportJob(store, req.params.eid);
    if (!r) throw new AppError('EXPORT_NOT_FOUND');
    return exportDto(r);
  });
  app.get<{ Params: { eid: string } }>('/api/v1/exports/:eid/download', async (req, reply) => {
    const r = getExportJob(store, req.params.eid);
    if (!r || r.status !== 'succeeded' || !r.artifact_ref) throw new AppError('EXPORT_NOT_FOUND');
    const dto = exportDto(r);
    reply.header('Content-Type', MIME[r.format]);
    reply.header('Content-Disposition', `attachment; filename="${dto.fileName}"`);
    reply.header('Content-Security-Policy', "sandbox; default-src 'none'; style-src 'unsafe-inline'");
    return reply.send(store.artifacts.get(r.artifact_ref));
  });
  app.get<{ Params: { aid: string } }>('/api/v1/audits/:aid/exports', async (req) =>
    listExportJobs(store, req.params.aid).map(exportDto));

  // ---- home ----
  app.get('/api/v1/inbox', async () => inbox(ctx));
  app.get('/api/v1/dashboard', async () => {
    const running = Q.activeAudits(store).map((a) => auditSummary(store, a));
    return { inbox: inbox(ctx), running, projects: Q.activeProjects<any>(store).map((p) => projectDto(store, p)) };
  });
}

function inbox(ctx: AppContext) {
  const { store } = ctx;
  const q = Q.openQuestions<any>(store);
  const by = (s: AuditStatus) => Q.recentAuditsIn(store, s).map((a) => auditSummary(store, a));
  return {
    questions: q.map((x) => ({ ...questionDto(x), auditTitle: x.audit_title, projectName: x.project_name })),
    waitingBudget: by('waiting_budget'), interrupted: [...by('interrupted'), ...by('paused')], awaitingConfirm: by('awaiting_confirm'),
    pendingVulns: Q.pendingVulnsByProject(store)
      .map((r) => {
        const missing = new Set<string>();
        for (const mc of Q.pendingMissingContexts(store, r.project_id)) {
          for (const m of normalizePending(JSON.parse(mc))?.missing ?? []) missing.add(m.ref);
        }
        return { projectId: r.project_id, projectName: r.name, count: r.n, missing: [...missing].slice(0, 5) };
      }),
    proposals: Q.proposedRevisions(store)
      .map((r) => ({ vulnId: r.vid, displayNo: r.display_no, projectId: r.project_id, projectName: r.project_name, title: r.title, dimension: r.dimension, to: r.to_value === null ? null : JSON.parse(r.to_value), reason: r.reason, conversationId: r.conversation_id })),
    connectorWrites: listWriteRequests(store, 'pending').map((w) => connectorWriteDto(store, w)),
  };
}
