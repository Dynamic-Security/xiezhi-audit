// over the API: create MCP connectors, write-only secrets kept in config.json, stdio
// command confirmation, connectivity test, read-only tool exposure, status transitions, call log.
import { createServer as createHttp, type Server } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig, type ConnectorDto } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { startServer, type RunningServer } from '@xiezhi/server';
// @ts-expect-error plain ESM fixture without types
import { handle } from '../../../packages/connectors/test/fake-mcp.mjs';

const FAKE = resolve(__dirname, '../../../packages/connectors/test/fake-mcp.mjs');

async function freePort(): Promise<number> {
  return new Promise((ok) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as { port: number }).port;
      s.close(() => ok(p));
    });
  });
}

let srv: RunningServer;
let mcp: Server;
let mcpUrl: string;
let base: string;
let token: string;
let dataDir: string;

async function api(method: string, path: string, body?: unknown) {
  if (method === 'POST' && body === undefined) body = {};
  const res = await fetch(`${base}${path}`, {
    method, headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, json: text && res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : null };
}

beforeAll(async () => {
  mcp = createHttp((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (req.headers.authorization !== 'Bearer tk-abc-123') { res.writeHead(401); res.end('unauthorized'); return; }
      const r = handle(JSON.parse(body));
      if (!r) { res.writeHead(202); res.end(); return; }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(r));
    });
  });
  await new Promise<void>((ok) => mcp.listen(0, '127.0.0.1', () => ok()));
  mcpUrl = `http://127.0.0.1:${(mcp.address() as { port: number }).port}/mcp`;
  dataDir = join(mkdtempSync(join(tmpdir(), 'ca-conn-api-')), 'data');
  const pre = Store.open({ dataDir, role: 'setup' });
  pre.saveConfig(defaultAppConfig());
  pre.close();
  srv = await startServer({ dataDir, port: await freePort(), webRoot: null, heartbeatMs: 200 });
  base = srv.url.replace(/\/$/, '');
  token = JSON.parse(readFileSync(join(dataDir, 'run', 'api.json'), 'utf8')).token;
});

afterAll(async () => {
  await srv?.close();
  await new Promise<void>((ok) => mcp.close(() => ok()));
});

describe('connectors API', () => {
  it('manages an HTTP MCP connector with write-only secrets, a connectivity test and all tools offered', async () => {
    // Credentials must be secret references, never literal values.
    const literal = await api('POST', '/api/v1/connectors', { name: 'tickets', protocol: 'mcp_http', purpose: 'context', config: { url: mcpUrl, headers: { Authorization: 'Bearer tk-abc-123' } } });
    expect(literal.status).toBe(400);
    const created = await api('POST', '/api/v1/connectors', { name: 'tickets', protocol: 'mcp_http', purpose: 'context', config: { url: mcpUrl, headers: { Authorization: 'Bearer ${secret:token}' } } });
    expect(created.status).toBe(201);
    let c = created.json as ConnectorDto;
    expect(c).toMatchObject({ status: 'untested', authoritative: false, secrets: [{ name: 'token', configured: false }] });
    // The authoritative mark is a context-connector setting.
    expect((await api('PATCH', `/api/v1/connectors/${c.id}`, { authoritative: true })).json.authoritative).toBe(true);
    expect((await api('PATCH', `/api/v1/connectors/${c.id}`, { authoritative: false })).json.authoritative).toBe(false);
    // The deprecated purpose is ignored; any connector can be authoritative and the DTO has no purpose / allowWrite.
    const legacy = await api('POST', '/api/v1/connectors', { name: 'sync-x', protocol: 'mcp_http', purpose: 'sync', allowWrite: true, authoritative: true, config: { url: mcpUrl } });
    expect(legacy.status).toBe(201);
    expect(legacy.json.authoritative).toBe(true);
    expect('purpose' in legacy.json || 'allowWrite' in legacy.json).toBe(false);
    await api('DELETE', `/api/v1/connectors/${legacy.json.id}`);

    c = (await api('POST', `/api/v1/connectors/${c.id}/test`)).json;
    expect(c.status).toBe('failed');
    expect(c.lastTest!.error).toMatch(/secret token is not configured/);

    c = (await api('PATCH', `/api/v1/connectors/${c.id}`, { secrets: { token: 'tk-abc-123' } })).json;
    expect(c.secrets).toEqual([{ name: 'token', configured: true }]);
    expect(JSON.stringify(c)).not.toContain('tk-abc-123');
    expect((await api('PATCH', `/api/v1/connectors/${c.id}`, { secrets: { other: 'x' } })).status).toBe(400);
    // The value lives in config.json only.
    expect(JSON.parse(readFileSync(join(dataDir, 'config.json'), 'utf8')).connectorSecrets[c.id]).toEqual({ token: 'tk-abc-123' });
    const db = new DatabaseSync(join(dataDir, 'db.sqlite'), { readOnly: true });
    expect(JSON.stringify(db.prepare('SELECT * FROM connector').all())).not.toContain('tk-abc-123');
    db.close();

    c = (await api('POST', `/api/v1/connectors/${c.id}/test`)).json;
    expect(c).toMatchObject({ status: 'ready', lastTest: { ok: true, server: { name: 'fake-mcp', protocolVersion: '2025-06-18' }, toolCount: 6 } });
    // Every tool starts offered to the Agent, read or write; the user may turn one off.
    expect(c.tools.map((t) => [t.name, t.readOnlyHint, t.exposed])).toEqual([['search', true, true], ['create_issue', false, true], ['fail', true, true], ['slow', true, true], ['env', true, true], ['get_ticket', null, true]]);
    expect((await api('PATCH', `/api/v1/connectors/${c.id}`, { tools: [{ name: 'create_issue', exposed: false }] })).json.tools.find((t: { name: string }) => t.name === 'create_issue').exposed).toBe(false);
    expect((await api('PATCH', `/api/v1/connectors/${c.id}`, { tools: [{ name: 'nope', exposed: false }] })).status).toBe(400);
    // Calls held for approval (instructions from the audited code): listing and deciding.
    expect((await api('GET', '/api/v1/connector-writes?status=pending')).json).toEqual([]);
    expect((await api('GET', '/api/v1/connector-writes?status=nope')).status).toBe(400);
    expect((await api('POST', '/api/v1/connector-writes/cwr_missing/approve', {})).status).toBe(404);
    expect((await api('GET', '/api/v1/inbox')).json.connectorWrites).toEqual([]);

    // Any configuration change sends it back to “untested”; after a re-test each tool keeps its choice.
    c = (await api('PATCH', `/api/v1/connectors/${c.id}`, { config: { url: mcpUrl, headers: { Authorization: 'Bearer ${secret:token}', 'X-Team': 'sec' } } })).json;
    expect(c.status).toBe('untested');
    c = (await api('POST', `/api/v1/connectors/${c.id}/test`)).json;
    expect(c.status).toBe('ready');
    expect(c.tools.find((t) => t.name === 'search')!.exposed).toBe(true);
    expect(c.tools.find((t) => t.name === 'create_issue')!.exposed).toBe(false);
    const calls = (await api('GET', `/api/v1/connectors/${c.id}/calls`)).json as { kind: string; status: string }[];
    expect(calls.map((x) => `${x.kind}:${x.status}`)).toEqual(['test:ok', 'test:ok', 'test:error']);
    expect((await api('DELETE', `/api/v1/connectors/${c.id}`)).status).toBe(204);
    expect(JSON.parse(readFileSync(join(dataDir, 'config.json'), 'utf8')).connectorSecrets?.[c.id]).toBeUndefined();
  });

  it('requires confirming the exact stdio command line before it runs', async () => {
    const created = await api('POST', '/api/v1/connectors', { name: 'local-mcp', protocol: 'mcp_stdio', purpose: 'context', config: { command: { path: process.execPath, args: [FAKE, '--stdio'], env: { API_TOKEN: '${secret:api}' } } } });
    let c = created.json as ConnectorDto;
    expect(c.status).toBe('needs_confirmation');
    expect(c.commandLine).toBe(`API_TOKEN='\${secret:api}' ${process.execPath} ${FAKE} --stdio`);
    c = (await api('POST', `/api/v1/connectors/${c.id}/test`)).json;
    expect(c.lastTest).toMatchObject({ ok: false, error: expect.stringMatching(/confirm/) });
    expect((await api('POST', `/api/v1/connectors/${c.id}/confirm-command`, { commandHash: '0'.repeat(64) })).status).toBe(412);
    c = (await api('POST', `/api/v1/connectors/${c.id}/confirm-command`, { commandHash: c.commandHash })).json;
    await api('PATCH', `/api/v1/connectors/${c.id}`, { secrets: { api: 'sec-1' } });
    c = (await api('POST', `/api/v1/connectors/${c.id}/test`)).json;
    expect(c).toMatchObject({ status: 'ready', lastTest: { ok: true, toolCount: 6 } });
    // Editing the command invalidates the confirmation.
    c = (await api('PATCH', `/api/v1/connectors/${c.id}`, { config: { command: { path: process.execPath, args: [FAKE, '--stdio', '-v'], env: { API_TOKEN: '${secret:api}' } } } })).json;
    expect(c.status).toBe('needs_confirmation');
  });

  it('binds context connectors to a project and runs user queries (any MCP tool)', async () => {
    const project = (await api('POST', '/api/v1/projects', { name: 'bind-demo' })).json as { id: string };
    let c = (await api('POST', '/api/v1/connectors', { name: 'docs', protocol: 'mcp_http', purpose: 'context', config: { url: mcpUrl, headers: { Authorization: 'Bearer ${secret:token}' } } })).json as ConnectorDto;
    await api('PATCH', `/api/v1/connectors/${c.id}`, { secrets: { token: 'tk-abc-123' } });
    c = (await api('POST', `/api/v1/connectors/${c.id}/test`)).json;
    expect(c.status).toBe('ready');
    const bound = await api('PUT', `/api/v1/projects/${project.id}/connectors`, { connectorIds: [c.id] });
    expect(bound.json).toEqual([{ connectorId: c.id, name: 'docs', scope: 'project', status: 'ready', enabled: true }]);
    const q = await api('POST', `/api/v1/connectors/${c.id}/query`, { tool: 'search', args: { q: 'gateway' } });
    expect(q.json).toEqual({ text: 'results for gateway\n[image omitted]', isError: false, bytes: expect.any(Number), authoritative: false, injection: [] });
    // The user can call any tool of an MCP connector; tools not declared read-only are logged as writes.
    expect((await api('POST', `/api/v1/connectors/${c.id}/query`, { tool: 'get_ticket', args: { id: '1' } })).status).toBe(200);
    const d = await api('POST', '/api/v1/knowledge/drafts', { layer: 'project', projectId: project.id, text: `外部系统返回：${q.json.text}`, organize: false, name: 'gw-facts', source: { kind: 'connector', ref: `${c.id}:search`, label: '连接器 docs · search' } });
    expect(d.json.source).toEqual({ kind: 'connector', ref: `${c.id}:search`, label: '连接器 docs · search' });
    const calls = (await api('GET', `/api/v1/connectors/${c.id}/calls`)).json as { kind: string; status: string; operation: string }[];
    expect(calls.map((x) => `${x.kind}:${x.operation}:${x.status}`).slice(0, 2)).toEqual(['write:get_ticket:ok', 'read:search:ok']);
  });
});

