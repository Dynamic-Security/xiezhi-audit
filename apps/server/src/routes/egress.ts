// Outbound records over the API: per audit or per project, as JSON or CSV (for compliance review).
import type { FastifyInstance, FastifyReply } from 'fastify';
import type { EgressDto } from '@xiezhi/contracts';
import { getAudit, getProject, queries as Q } from '@xiezhi/engine';
import { fromJson } from '@xiezhi/store';
import type { AppContext } from '../context.js';

const iso = (n: number) => new Date(n).toISOString();
export function egressDto(r: Q.EgressRow): EgressDto {
  return {
    id: r.id, kind: r.kind, auditId: r.audit_id, step: r.lineage_id ?? r.step_id, conversationId: r.conversation_id, ref: r.ref, provider: r.provider, model: r.model,
    endpoint: r.endpoint, status: r.status, turns: r.turns, tokens: { input: r.tokens_in, output: r.tokens_out, cached: r.tokens_cached },
    files: fromJson<{ repo?: string; path: string }[]>(r.files, []), facts: fromJson<string[]>(r.facts, []), withheldFacts: r.withheld_facts,
    tools: fromJson<Record<string, number>>(r.tools, {}), startedAt: iso(r.started_at), endedAt: iso(r.ended_at),
  };
}

const CSV_HEAD = ['started_at', 'kind', 'audit', 'step', 'provider', 'model', 'endpoint', 'status', 'tokens_in', 'tokens_out', 'files', 'facts', 'withheld_facts'];
const cell = (v: unknown) => { const t = String(v ?? ''); return /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
function csv(reply: FastifyReply, name: string, rows: EgressDto[]): string {
  reply.header('content-type', 'text/csv; charset=utf-8').header('content-disposition', `attachment; filename="${name}"`);
  return ['\ufeff' + CSV_HEAD.join(','), ...rows.map((r) => [r.startedAt, r.kind, r.auditId, r.step, r.provider, r.model, r.endpoint, r.status, r.tokens.input, r.tokens.output,
    r.files.map((f) => `${f.repo ? `${f.repo}:` : ''}${f.path}`).join(' '), r.facts.join(' '), r.withheldFacts].map(cell).join(','))].join('\n');
}

export function registerEgressRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get<{ Params: { aid: string }; Querystring: { format?: string } }>('/api/v1/audits/:aid/egress', async (req, reply) => {
    getAudit(store, req.params.aid);
    const rows = Q.egressOfAudit(store, req.params.aid).map(egressDto);
    return req.query.format === 'csv' ? csv(reply, `egress-${req.params.aid}.csv`, rows) : rows;
  });
  app.get<{ Params: { pid: string }; Querystring: { format?: string } }>('/api/v1/projects/:pid/egress', async (req, reply) => {
    getProject(store, req.params.pid);
    const rows = Q.egressOfProject(store, req.params.pid).map(egressDto);
    return req.query.format === 'csv' ? csv(reply, `egress-${req.params.pid}.csv`, rows) : rows;
  });
}
