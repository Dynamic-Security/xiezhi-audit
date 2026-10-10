// Enterprise facts over the API: list a project's facts, add one (by a person, or from a review
// ruling), change it (a new version), retract it, import what the project already knows, and see one key's versions
// with the vulnerabilities that rely on it. Reads come from engine queries, writes go through engine functions.
import type { FastifyInstance } from 'fastify';
import { type GatewayExposureDto, PostFactBody, PutFactBody, RetractFactBody, type FactDetailDto, type FactDto, type FactSensitivity, type FactSource, type FactTopic, type FactTrust } from '@xiezhi/contracts';
import { addFact, getFact, getProject, importFacts, projectGateways, queries as Q, retractFact, reviseFact, type FactRow, type FactScope } from '@xiezhi/engine';
import { fromJson } from '@xiezhi/store';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';

const iso = (n: number) => new Date(n).toISOString();

export function factDto(store: AppContext['store'], f: FactRow): FactDto {
  const impact = Q.factImpact(store, f.project_id, f.fact_key);
  return {
    id: f.id, projectId: f.project_id, key: f.fact_key, version: f.version, topic: f.topic, statement: f.statement, scope: fromJson<FactScope>(f.scope, {}),
    sourceKind: f.source_kind, sourceRef: f.source_ref, trust: f.trust, sensitivity: f.sensitivity, status: f.status, createdBy: f.created_by, reason: f.reason,
    createdAt: iso(f.created_at), updatedAt: iso(f.updated_at),
    affected: { vulns: new Set(impact.map((i) => i.vulnerability_id)).size, stale: new Set(impact.filter((i) => i.stale).map((i) => i.vulnerability_id)).size },
  };
}

export function registerFactRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  app.get<{ Params: { pid: string }; Querystring: { status?: string; topic?: string; q?: string } }>('/api/v1/projects/:pid/facts', async (req) => {
    getProject(store, req.params.pid);
    return Q.listFacts(store, req.params.pid, req.query).map((f) => factDto(store, f));
  });
  app.post<{ Params: { pid: string } }>('/api/v1/projects/:pid/facts', async (req) => {
    const b = parseBody(PostFactBody, req.body);
    const sourceKind = (b.sourceKind ?? 'user') as FactSource;
    const f = addFact(store, req.params.pid, {
      topic: b.topic as FactTopic, statement: b.statement, ...(b.scope ? { scope: b.scope } : {}), sourceKind, sourceRef: b.sourceRef ?? null,
      trust: (b.trust ?? 'verified') as FactTrust, ...(b.sensitivity ? { sensitivity: b.sensitivity as FactSensitivity } : {}), reason: b.reason ?? null,
      // A review ruling is kept per vulnerability: saving it again writes its next version.
      ...(sourceKind === 'review' && b.sourceRef ? { key: `review:${b.sourceRef}` } : {}),
    }, 'user');
    return factDto(store, f);
  });
  app.post<{ Params: { pid: string } }>('/api/v1/projects/:pid/facts/import', async (req) => importFacts(store, req.params.pid));
  // the entry-exposure map — every gateway route, what it forwards to and whether it authenticates first.
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/gateway-exposure', async (req): Promise<GatewayExposureDto> => {
    getProject(store, req.params.pid);
    const auth = (a: { kind: string; mechanism: string; site: { path: string; line: number } } | null) => (a ? { kind: a.kind, mechanism: a.mechanism, path: a.site.path, line: a.site.line } : null);
    return {
      gateways: projectGateways(store, req.params.pid).map((g) => ({
        gateway: g.gateway, global: g.report.global.map((a) => auth(a)!),
        routes: g.report.routes.map((r) => ({
          pathTemplate: r.pathTemplate, upstream: r.upstream, stripPrefix: r.stripPrefix, auth: auth(r.auth),
          effectiveAuth: r.auth?.kind === 'off' ? null : auth(r.auth ?? g.report.global[0] ?? null), setHeaders: r.setHeaders, removeHeaders: r.removeHeaders, path: r.site.path, line: r.site.line,
        })),
      })),
    };
  });
  app.get<{ Params: { fid: string } }>('/api/v1/facts/:fid', async (req): Promise<FactDetailDto> => {
    const f = getFact(store, req.params.fid);
    return {
      fact: factDto(store, f), versions: Q.factVersions(store, f.project_id, f.fact_key).map((v) => factDto(store, v)),
      impact: Q.factImpact(store, f.project_id, f.fact_key).map((i) => ({ vulnerabilityId: i.vulnerability_id, displayNo: i.display_no, title: i.title, auditId: i.audit_id, version: i.version, stale: !!i.stale })),
    };
  });
  app.put<{ Params: { fid: string } }>('/api/v1/facts/:fid', async (req) => {
    const b = parseBody(PutFactBody, req.body);
    return factDto(store, reviseFact(store, req.params.fid, {
      ...(b.topic ? { topic: b.topic as FactTopic } : {}), ...(b.statement ? { statement: b.statement } : {}), ...(b.scope ? { scope: b.scope } : {}),
      ...(b.trust ? { trust: b.trust as FactTrust } : {}), ...(b.sensitivity ? { sensitivity: b.sensitivity as FactSensitivity } : {}), ...(b.reason ? { reason: b.reason } : {}),
    }, 'user'));
  });
  app.post<{ Params: { fid: string } }>('/api/v1/facts/:fid/retract', async (req) => {
    const b = parseBody(RetractFactBody, req.body);
    return factDto(store, retractFact(store, req.params.fid, b.reason, 'user'));
  });
}
