// "未排除的假设": hypotheses a hunt could neither prove nor refute are listed
// per audit next to the results; a reviewer converts one to a (pending) vulnerability or dismisses it.
// The threat model's risk hypotheses with their verification (also from supplements).
import type { FastifyInstance } from 'fastify';
import { AppError, HYPOTHESIS_STATUSES, type HypothesisDto } from '@xiezhi/contracts';
import { addHypothesis, decideHypothesis, hypothesisAuditIds, HypothesisEditError, HypothesisError, listHypotheses, relatedOf, type HypothesisRow, queries as Q } from '@xiezhi/engine';
import { fromJson, type Store } from '@xiezhi/store';
import * as B from '../bodies.js';
import type { AppContext } from '../context.js';
import { multi, parseBody } from '../http.js';

const STATUSES = HYPOTHESIS_STATUSES;

/** The finding that proves a confirmed hypothesis, followed through a merge, and its vulnerability. */
function proving(store: Store, findingId: string | null): { state: string | null; vulnerabilityId: string | null } {
  if (!findingId) return { state: null, vulnerabilityId: null };
  return Q.provingFinding(store, findingId);
}

function dto(store: Store, h: HypothesisRow): HypothesisDto {
  const repo = Q.repositoryName(store, h.repository_id) ?? '';
  const p = proving(store, h.finding_id);
  return {
    id: h.id, auditId: h.audit_id, repo, category: h.category, statement: h.statement, attempts: h.attempts, entry: h.entry_key,
    location: h.location ? fromJson(h.location, { repo, path: '', startLine: 1, endLine: 1 }) : null, status: h.status, vulnerabilityId: h.vulnerability_id ?? p.vulnerabilityId,
    decidedReason: h.decided_reason, createdAt: new Date(h.created_at).toISOString(),
    origin: h.origin, priority: h.priority, basis: h.basis, relatedEntries: relatedOf(h).entries, relatedFiles: relatedOf(h).files,
    findingId: h.finding_id, verifiedAt: h.verified_at ? new Date(h.verified_at).toISOString() : null, findingState: p.state,
    threatRiskId: (h as HypothesisRow & { threat_risk_id?: string | null }).threat_risk_id ?? null,
  };
}

export function registerHypothesisRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get<{ Params: { aid: string }; Querystring: Record<string, string | string[] | undefined> }>('/api/v1/audits/:aid/hypotheses', async (req) => {
    if (!Q.auditExists(store, req.params.aid)) throw new AppError('COMMON_NOT_FOUND', req.params.aid);
    const want = multi(req.query.status);
    for (const s of want) if (!(STATUSES as readonly string[]).includes(s)) throw new AppError('COMMON_VALIDATION', 'status');
    const origin = typeof req.query.origin === 'string' ? req.query.origin : undefined;
    if (origin && origin !== 'hunt' && origin !== 'threat_model') throw new AppError('COMMON_VALIDATION', 'origin');
    // The audit's own hypotheses and those of its supplements (追加执行).
    const all = listHypotheses(store, hypothesisAuditIds(store, req.params.aid)).filter((h) => !origin || h.origin === origin);
    const counts = { proposed: 0, confirmed: 0, open: 0, refuted: 0, converted: 0, dismissed: 0 };
    for (const h of all) counts[h.status]++;
    return { items: all.filter((h) => !want.length || want.includes(h.status)).map((h) => dto(store, h)), counts };
  });

  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/hypotheses', async (req, reply) => {
    const b = parseBody(B.PostAuditsAidHypothesesBody, req.body);
    try {
      const h = addHypothesis(store, req.params.aid, { ...b, actor: 'user' });
      reply.code(201);
      return dto(store, h);
    } catch (e) {
      if (e instanceof HypothesisEditError) throw new AppError(e.code === 'NOT_FOUND' ? 'COMMON_NOT_FOUND' : 'COMMON_VALIDATION', e.message);
      throw e;
    }
  });

  app.post<{ Params: { hid: string } }>('/api/v1/hypotheses/:hid/decision', async (req) => {
    const b = parseBody(B.PostHypothesesHidDecisionBody, req.body);
    try {
      const r = decideHypothesis(store, req.params.hid, b.action, { reason: b.reason, actor: 'user', ...(b.severity ? { severity: b.severity } : {}) });
      const h = Q.getHypothesis<HypothesisRow>(store, req.params.hid)!;
      return { hypothesis: dto(store, h), vulnerability: r.vulnerabilityId ? { id: r.vulnerabilityId, displayNo: r.displayNo! } : null };
    } catch (e) {
      if (e instanceof HypothesisError) throw new AppError(e.code === 'NOT_FOUND' ? 'HYPOTHESIS_NOT_FOUND' : 'HYPOTHESIS_DECIDED', e.message);
      throw e;
    }
  });
}
