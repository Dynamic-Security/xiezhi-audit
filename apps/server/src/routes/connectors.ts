// Connectors: CRUD without credential values, write-only secrets,
// stdio command confirmation, connectivity test, tool exposure, recent call log.
import type { FastifyInstance } from 'fastify';
import { AppError, maskSecret, type ConnectorCallDto, type ConnectorDto, type ConnectorWriteDto, type ProjectConnectorDto } from '@xiezhi/contracts';
import { detectInjection } from '@xiezhi/agent';
import {
  commandLine, confirmConnectorCommand, confirmationHash, connectorSecretNames, connectorStatus, createConnector, deleteConnector, getConnector, setConnectorSecrets, setToolExposure, decideWriteRequest, listWriteRequests, type WriteRequestRow,
  testConnector, updateConnector, getProject, projectConnectors, setProjectConnectors, userConnectorQuery,
  type ConnectorConfig, type ConnectorRow, type ConnectorTest, type ConnectorTool, queries as Q,
  discoverMcpConfigs, importMcpConfig,
} from '@xiezhi/engine';
import { fromJson, type Store } from '@xiezhi/store';
import type { AppContext } from '../context.js';
import { parseBody } from '../http.js';
import { PatchConnectorsIdBody, PostConnectorImportsBody, PostConnectorsBody, PostConnectorsIdConfirmCommandBody, PostConnectorsIdQueryBody, PostConnectorWritesIdDecisionBody, PutProjectsPidConnectorsBody } from '../bodies.js';

/** A write request as the API shows it: connector and tool names, what started it, decision and result. */
export function connectorWriteDto(store: Store, w: WriteRequestRow): ConnectorWriteDto {
  const c = Q.findConnector<ConnectorRow>(store, w.connector_id);
  const tool = c ? fromJson<ConnectorTool[]>(c.tools, []).find((t) => t.name === w.tool) : undefined;
  const iso = (ms: number | null) => (ms ? new Date(ms).toISOString() : null);
  return {
    id: w.id, connectorId: w.connector_id, connector: c?.name ?? w.connector_id, tool: w.tool, toolDescription: tool?.description ?? null, args: fromJson(w.args, {}), reason: w.reason,
    source: w.source, auditId: w.audit_id, auditTitle: w.audit_id ? Q.auditTitle(store, w.audit_id) ?? null : null,
    conversationId: w.conversation_id, conversationTitle: w.conversation_id ? Q.conversationTitle(store, w.conversation_id) ?? null : null,
    status: w.status, signals: fromJson<string[]>(w.signals, []), result: w.result, error: w.error, decisionNote: w.decision_note, decidedAt: iso(w.decided_at), createdAt: iso(w.created_at)!,
  };
}

export function registerConnectorRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  const pool = ctx.engine.connectors;
  const dto = (r: ConnectorRow): ConnectorDto => {
    const packs = store.paths.connectorPacks;
    const secrets = store.config.connectorSecrets?.[r.id] ?? {};
    const t = fromJson<ConnectorTest | null>(r.last_test, null);
    const b = pool.breaker(r.id);
    return {
      id: r.id, name: r.name, protocol: r.protocol, authoritative: !!r.authoritative, enabled: !!r.enabled, status: connectorStatus(r, packs),
      config: fromJson<ConnectorConfig>(r.config, {}), commandLine: commandLine(r, packs), commandHash: confirmationHash(r, packs),
      secrets: connectorSecretNames(r, packs).map((name) => ({ name, ...maskSecret(secrets[name]) })),
      tools: fromJson<ConnectorTool[]>(r.tools, []).map((x) => ({
        name: x.name, ...(x.title ? { title: x.title } : {}), ...(x.description ? { description: x.description } : {}),
        readOnlyHint: x.readOnlyHint, destructiveHint: x.destructiveHint, exposed: x.exposed,
      })),
      lastTest: t ? { ok: t.ok, at: new Date(t.at).toISOString(), server: t.server, error: t.error, toolCount: t.toolCount } : null,
      breaker: { state: b.state, failures: b.failures }, createdAt: new Date(r.created_at).toISOString(), updatedAt: new Date(r.updated_at).toISOString(),
    };
  };

  // ---- write requests ----
  app.get<{ Querystring: { status?: string } }>('/api/v1/connector-writes', async (req) => {
    const st = req.query.status;
    if (st && !['pending', 'executed', 'failed', 'rejected'].includes(st)) throw new AppError('COMMON_VALIDATION', 'unknown status');
    return listWriteRequests(store, st as WriteRequestRow['status'] | undefined).map((w) => connectorWriteDto(store, w));
  });
  for (const decision of ['approve', 'reject'] as const) {
    app.post<{ Params: { id: string } }>(`/api/v1/connector-writes/:id/${decision}`, async (req) => {
      const b = parseBody(PostConnectorWritesIdDecisionBody, req.body ?? {});
      return connectorWriteDto(store, await decideWriteRequest(store, pool, req.params.id, decision, b.note));
    });
  }

  app.get('/api/v1/connectors', async () => Q.listConnectorRows<ConnectorRow>(store).map(dto));
  app.post('/api/v1/connectors', async (req, reply) => {
    const b = parseBody(PostConnectorsBody, req.body);
    reply.code(201);
    return dto(createConnector(store, { name: b.name, protocol: b.protocol, config: b.config as ConnectorConfig, ...(b.authoritative !== undefined ? { authoritative: b.authoritative } : {}) }));
  });
  // MCP servers configured in other tools (Cursor, Claude Code …), credentials masked; import one as a connector.
  app.get('/api/v1/connector-imports', async () => discoverMcpConfigs());
  app.post('/api/v1/connector-imports', async (req, reply) => {
    const b = parseBody(PostConnectorImportsBody, req.body);
    const row = await importMcpConfig(store, pool, {
      candidate: b.candidate, ...(b.name ? { name: b.name } : {}),
      ...(b.secrets ? { secrets: b.secrets } : {}), ...(b.extraArgs ? { extraArgs: b.extraArgs } : {}),
    });
    reply.code(201);
    return dto(getConnector(store, row.id));
  });
  app.get<{ Params: { id: string } }>('/api/v1/connectors/:id', async (req) => dto(getConnector(store, req.params.id)));
  app.patch<{ Params: { id: string } }>('/api/v1/connectors/:id', async (req) => {
    const b = parseBody(PatchConnectorsIdBody, req.body);
    const id = req.params.id;
    await updateConnector(store, pool, id, {
      ...(b.name ? { name: b.name } : {}), ...(b.config ? { config: b.config as ConnectorConfig } : {}),
      ...(b.authoritative !== undefined ? { authoritative: b.authoritative } : {}), ...(b.enabled !== undefined ? { enabled: b.enabled } : {}),
    });
    if (b.secrets) await setConnectorSecrets(store, pool, id, b.secrets);
    if (b.tools) setToolExposure(store, id, b.tools);
    return dto(getConnector(store, id));
  });
  app.delete<{ Params: { id: string } }>('/api/v1/connectors/:id', async (req, reply) => {
    await deleteConnector(store, pool, req.params.id);
    return reply.code(204).send();
  });
  app.post<{ Params: { id: string } }>('/api/v1/connectors/:id/confirm-command', async (req) => {
    const b = parseBody(PostConnectorsIdConfirmCommandBody, req.body);
    return dto(confirmConnectorCommand(store, req.params.id, b.commandHash));
  });
  app.post<{ Params: { id: string } }>('/api/v1/connectors/:id/test', async (req) => dto(await testConnector(store, pool, req.params.id)));
  app.get<{ Params: { id: string } }>('/api/v1/connectors/:id/calls', async (req) => {
    getConnector(store, req.params.id);
    return Q.connectorCalls(store, req.params.id)
      .map((c): ConnectorCallDto => ({ id: c.id, operation: c.operation, kind: c.kind, status: c.status, durationMs: c.duration_ms, responseBytes: c.response_bytes, error: c.error, auditId: c.audit_id, createdAt: new Date(c.created_at).toISOString() }));
  });

  // A read-only query started by the user: the result is unverified external data.
  app.post<{ Params: { id: string } }>('/api/v1/connectors/:id/query', async (req) => {
    const b = parseBody(PostConnectorsIdQueryBody, req.body);
    const r = await userConnectorQuery(store, pool, req.params.id, b.tool, b.args);
    return { ...r, injection: detectInjection(r.text).slice(0, 10) };
  });

  // Project bindings: the context connectors a project's audits may query by default.
  const bindings = (pid: string): ProjectConnectorDto[] => projectConnectors(store, pid).map((b) => {
    const r = getConnector(store, b.connectorId);
    return { connectorId: r.id, name: r.name, scope: b.scope, status: connectorStatus(r, store.paths.connectorPacks), enabled: !!r.enabled };
  });
  app.get<{ Params: { pid: string } }>('/api/v1/projects/:pid/connectors', async (req) => {
    getProject(store, req.params.pid);
    return bindings(req.params.pid);
  });
  app.put<{ Params: { pid: string } }>('/api/v1/projects/:pid/connectors', async (req) => {
    getProject(store, req.params.pid);
    const b = parseBody(PutProjectsPidConnectorsBody, req.body);
    setProjectConnectors(store, req.params.pid, b.connectorIds);
    return bindings(req.params.pid);
  });
}
