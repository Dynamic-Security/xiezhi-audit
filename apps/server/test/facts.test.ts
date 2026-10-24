// over the API: enterprise facts — add, change (a new version), retract, import, detail.
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig, type FactDetailDto, type FactDto } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { startServer, type RunningServer } from '@xiezhi/server';
import { startFakeOpenAI, type FakeServer } from '../../../packages/agent/test/fake-openai.js';
import { fakeAgent } from '../../../packages/engine/test/fake-agent.js';

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
let base: string;
let token: string;
let dataDir: string;

async function api(method: string, path: string, body?: unknown, headers: Record<string, string> = {}) {
  const res = await fetch(`${base}${path}`, {
    method, headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, json: text && res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : null };
}

beforeAll(async () => {
  dataDir = join(mkdtempSync(join(tmpdir(), 'ca-facts-')), 'data');
  model = await startFakeOpenAI((b) => fakeAgent()(b));
  const pre = Store.open({ dataDir, role: 'setup' });
  pre.saveConfig({ ...defaultAppConfig(), modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl: model.url, apiKey: 'sk-know-test-0123456789', models: [{ id: 'm1' }] }], defaultModel: { provider: 'gw', model: 'm1' } });
  pre.close();
  srv = await startServer({ dataDir, port: await freePort(), webRoot: null, heartbeatMs: 200 });
  base = srv.url.replace(/\/$/, '');
  token = JSON.parse(readFileSync(join(dataDir, 'run', 'api.json'), 'utf8')).token;
});

afterAll(async () => {
  await srv?.close();
  await model?.close();
});

describe('enterprise facts API', () => {
  it('adds, changes, retracts, imports and lists facts with their versions', async () => {
    const project = (await api('POST', '/api/v1/projects', { name: 'mesh' })).json as { id: string };
    const base = `/api/v1/projects/${project.id}/facts`;
    expect((await api('GET', base)).json).toEqual([]);
    expect((await api('POST', base, { topic: 'nope', statement: 'x' })).status).toBe(400);
    const a = (await api('POST', base, { topic: 'gateway', statement: '网关校验 JWT', scope: { services: ['order-service'] }, sensitivity: 'confidential' })).json as FactDto;
    expect(a).toMatchObject({ version: 1, trust: 'verified', sensitivity: 'confidential', sourceKind: 'user', status: 'active', scope: { services: ['order-service'] }, affected: { vulns: 0, stale: 0 } });
    const b = (await api('PUT', `/api/v1/facts/${a.id}`, { statement: '网关校验 JWT 并写入 X-User-Id', reason: '与运维确认' })).json as FactDto;
    expect(b).toMatchObject({ key: a.key, version: 2, reason: '与运维确认' });
    expect((await api('PUT', `/api/v1/facts/${a.id}`, { statement: 'x' })).status).toBe(400);
    const d = (await api('GET', `/api/v1/facts/${b.id}`)).json as FactDetailDto;
    expect(d.versions.map((v) => [v.version, v.status])).toEqual([[2, 'active'], [1, 'superseded']]);
    // A review ruling is kept per vulnerability.
    const r1 = (await api('POST', base, { topic: 'auth', statement: '订单接口由网关做归属校验', sourceKind: 'review', sourceRef: 'vul_X' })).json as FactDto;
    const r2 = (await api('POST', base, { topic: 'auth', statement: '订单接口由网关做归属校验（v2）', sourceKind: 'review', sourceRef: 'vul_X' })).json as FactDto;
    expect([r1.key, r2.key, r2.version]).toEqual(['review:vul_X', 'review:vul_X', 2]);
    expect((await api('POST', `/api/v1/facts/${b.id}/retract`, { reason: '' })).status).toBe(400);
    expect(((await api('POST', `/api/v1/facts/${b.id}/retract`, { reason: '网关迁移' })).json as FactDto).status).toBe('retracted');
    expect(((await api('GET', base)).json as FactDto[]).map((f) => f.key)).toEqual(['review:vul_X']);
    expect(((await api('GET', `${base}?status=all`)).json as FactDto[]).length).toBe(4);
    const imp = await api('POST', `${base}/import`, {});
    expect(imp.json).toMatchObject({ added: expect.any(Number), updated: 0 });
  });
});
