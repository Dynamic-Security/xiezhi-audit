// over the API: install the Jira example pack, connect it (http connector, script confirmation,
// secrets), test and query through a fake Jira, and draft a pack from OpenAPI with the (fake) model.
import { createServer as createHttp, type Server } from 'node:http';
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig, type ConnectorDto } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { startServer, type RunningServer } from '@xiezhi/server';
import { startFakeOpenAI, type FakeServer } from '../../../packages/agent/test/fake-openai.js';
import { fakeAgent } from '../../../packages/engine/test/fake-agent.js';
// @ts-expect-error plain ESM fixture without types
import { createFakeJira } from '../../../packages/connectors/test/fake-jira.mjs';

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
let model: FakeServer;
let jiraSrv: Server;
let jiraUrl: string;
let base: string;
let token: string;
const jira = createFakeJira();

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
  jiraSrv = createHttp(jira.handler);
  await new Promise<void>((ok) => jiraSrv.listen(0, '127.0.0.1', () => ok()));
  jiraUrl = `http://127.0.0.1:${(jiraSrv.address() as { port: number }).port}`;
  model = await startFakeOpenAI((b) => fakeAgent()(b));
  const dataDir = join(mkdtempSync(join(tmpdir(), 'ca-packs-api-')), 'data');
  const pre = Store.open({ dataDir, role: 'setup' });
  pre.saveConfig({ ...defaultAppConfig(), modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl: model.url, apiKey: 'sk-packs-test-0123456789', models: [{ id: 'm1' }] }], defaultModel: { provider: 'gw', model: 'm1' } });
  pre.close();
  srv = await startServer({ dataDir, port: await freePort(), webRoot: null, heartbeatMs: 200 });
  base = srv.url.replace(/\/$/, '');
  token = JSON.parse(readFileSync(join(dataDir, 'run', 'api.json'), 'utf8')).token;
});

afterAll(async () => {
  await srv?.close();
  await model?.close();
  await new Promise<void>((ok) => jiraSrv.close(() => ok()));
});

describe('connector packs API', () => {
  it('installs the Jira example and runs it as an http connector after confirming its script', async () => {
    expect((await api('GET', '/api/v1/connector-packs/examples')).json.map((p: { name: string }) => p.name)).toContain('jira-cloud');
    const installed = await api('POST', '/api/v1/connector-packs/examples/jira-cloud/install');
    expect(installed.json).toMatchObject({ name: 'jira-cloud', valid: true, scripts: ['scripts/basic-auth.mjs'], secrets: ['email', 'api_token'] });
    expect((await api('POST', '/api/v1/connector-packs/examples/jira-cloud/install')).status).toBe(400);
    const detail = (await api('GET', '/api/v1/connector-packs/jira-cloud')).json;
    expect(detail.files.map((f: { path: string }) => f.path)).toEqual(['CONNECTOR.md', 'operations.yaml', 'scripts/basic-auth.mjs']);

    let c = (await api('POST', '/api/v1/connectors', { name: 'jira', protocol: 'http', purpose: 'context', config: { pack: 'jira-cloud', base_url: jiraUrl } })).json as ConnectorDto;
    expect(c).toMatchObject({ status: 'needs_confirmation', secrets: [{ name: 'api_token', configured: false }, { name: 'email', configured: false }] });
    expect(c.commandLine).toContain('scripts/basic-auth.mjs');
    c = (await api('POST', `/api/v1/connectors/${c.id}/confirm-command`, { commandHash: c.commandHash })).json;
    await api('PATCH', `/api/v1/connectors/${c.id}`, { secrets: { email: 'alice@example.com', api_token: 'jira-token-1' } });
    c = (await api('POST', `/api/v1/connectors/${c.id}/test`)).json;
    expect(c).toMatchObject({ status: 'ready', lastTest: { ok: true, server: { name: 'jira-cloud', protocolVersion: 'connector-pack/1' }, toolCount: 6 } });
    // Pack operations, read or write, start offered to the Agent.
    expect(c.tools.map((t) => [t.name, t.exposed])).toEqual([['search_issues', true], ['get_issue', true], ['get_transitions', true], ['create_issue', true], ['add_comment', true], ['transition_issue', true]]);
    const q = await api('POST', `/api/v1/connectors/${c.id}/query`, { tool: 'get_issue', args: { issue: 'SEC-1' } });
    expect(JSON.parse(q.json.text)).toMatchObject({ key: 'SEC-1', 'fields.summary': 'Order IDOR' });
    expect((await api('POST', `/api/v1/connectors/${c.id}/query`, { tool: 'create_issue', args: {} })).status).toBe(400);

    // Editing the script requires a new confirmation; the pack is used, so it cannot be deleted.
    const script = detail.files.find((f: { path: string }) => f.path === 'scripts/basic-auth.mjs');
    await api('PUT', '/api/v1/connector-packs/jira-cloud/files/scripts/basic-auth.mjs', { text: `${script.text}\n// changed\n`, baseSha256: script.sha256 });
    expect((await api('GET', `/api/v1/connectors/${c.id}`)).json.status).toBe('needs_confirmation');
    expect((await api('DELETE', '/api/v1/connector-packs/jira-cloud')).status).toBe(400);
  });

  it('drafts a declarative pack from an OpenAPI document and turns it into a pack after review', async () => {
    const d = await api('POST', '/api/v1/connector-pack-drafts', { openapi: JSON.stringify({ openapi: '3.0.0', info: { title: 'Tickets' }, paths: { '/api/tickets': { get: {}, post: {} } } }), name: 'tickets-api' });
    expect(d.status).toBe(202);
    let draft = d.json;
    for (let i = 0; draft.status === 'organizing' && i < 100; i++) {
      await new Promise((r) => setTimeout(r, 100));
      draft = (await api('GET', `/api/v1/connector-pack-drafts/${draft.id}`)).json;
    }
    expect(draft).toMatchObject({ status: 'ready', name: 'tickets-api', errors: [] });
    expect(draft.files.map((f: { path: string }) => f.path)).toEqual(['CONNECTOR.md', 'operations.yaml']);
    expect(draft.files[1].text).toContain('list_tickets');
    const approved = await api('POST', `/api/v1/connector-pack-drafts/${draft.id}/approve`);
    expect(approved.json).toMatchObject({ name: 'tickets-api', valid: true, scripts: [], operations: [{ name: 'list_tickets', kind: 'read' }, { name: 'create_ticket', kind: 'write' }] });
    expect((await api('GET', '/api/v1/connector-packs')).json.map((p: { name: string }) => p.name)).toEqual(['jira-cloud', 'tickets-api']);
  });
});
