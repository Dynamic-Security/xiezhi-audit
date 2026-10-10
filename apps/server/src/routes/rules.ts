// Project rules over the API: draft one for a vulnerability with the chat model or write one, try a
// pattern on the vulnerability's snapshot, approve / reject / retire. Approved rules apply from the next audit.
import type { FastifyInstance } from 'fastify';
import { AppError, PostProjectRuleBody, ProjectRuleDecisionBody, TestProjectRuleBody, type ProjectRuleDto } from '@xiezhi/contracts';
import { addProjectRule, decideProjectRule, getProject, getProjectRule, queries as Q, ruleOriginOf, ruleValidationOf, testRule, vulnContext, type ProjectRuleRow, type RuleMatcher } from '@xiezhi/engine';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';

const iso = (n: number) => new Date(n).toISOString();

export function ruleDto(store: AppContext['store'], r: ProjectRuleRow): ProjectRuleDto {
  return {
    id: r.id, projectId: r.project_id, vulnerabilityId: r.vulnerability_id, vulnDisplayNo: r.vulnerability_id ? Q.vulnDisplayNo(store, r.vulnerability_id) ?? null : null,
    lang: r.lang, matcher: r.matcher, pattern: r.pattern, category: r.category, cwe: r.cwe, title: r.title, rationale: r.rationale, status: r.status, source: r.source,
    origin: ruleOriginOf(r), validation: ruleValidationOf(r), model: r.model, tokens: r.tokens, error: r.error,
    decidedAt: r.decided_at ? iso(r.decided_at) : null, createdAt: iso(r.created_at), updatedAt: iso(r.updated_at),
  };
}

export function registerRuleRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get<{ Params: { pid: string }; Querystring: { vulnId?: string } }>('/api/v1/projects/:pid/rules', async (req) => {
    getProject(store, req.params.pid);
    return Q.listProjectRules(store, req.params.pid, req.query.vulnId).map((r) => ruleDto(store, r));
  });
  app.post<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/rules', async (req, reply) => {
    const b = parseBody(PostProjectRuleBody, req.body);
    if (b.mode === 'ai') {
      reply.code(202);
      return ruleDto(store, ctx.engine.jobs.startRuleDraft(req.params.vid));
    }
    if (!b.matcher || !b.pattern) throw new AppError('COMMON_VALIDATION', 'matcher and pattern are required (or mode: ai)');
    return ruleDto(store, await addProjectRule(store, req.params.vid, { matcher: b.matcher as RuleMatcher, pattern: b.pattern, ...(b.title ? { title: b.title } : {}), ...(b.rationale ? { rationale: b.rationale } : {}) }, 'user'));
  });
  app.post<{ Params: { vid: string } }>('/api/v1/vulnerabilities/:vid/rules/test', async (req) => {
    const b = parseBody(TestProjectRuleBody, req.body);
    const c = vulnContext(store, req.params.vid);
    if (!c.lang) throw new AppError('COMMON_VALIDATION', `the language of ${c.origin.path} is not supported by rules`);
    return testRule(c.view, c.origin, { lang: c.lang, matcher: b.matcher as RuleMatcher, pattern: b.pattern });
  });
  app.get<{ Params: { rid: string } }>('/api/v1/rules/:rid', async (req) => ruleDto(store, getProjectRule(store, req.params.rid)));
  app.post<{ Params: { rid: string } }>('/api/v1/rules/:rid/decision', async (req) => {
    const b = parseBody(ProjectRuleDecisionBody, req.body);
    return ruleDto(store, await decideProjectRule(store, req.params.rid, b.decision as 'approve' | 'reject' | 'retire', 'user'));
  });
}
