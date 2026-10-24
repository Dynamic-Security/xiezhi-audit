// over the API: outbound records (JSON and CSV) and the models allowed to receive confidential facts.
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig, newId, type EgressDto } from '@xiezhi/contracts';
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
  return { status: res.status, type: res.headers.get('content-type') ?? '', text, json: text && res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : null };
}

beforeAll(async () => {
  dataDir = join(mkdtempSync(join(tmpdir(), 'ca-egress-')), 'data');
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

describe('outbound records API', () => {
  it('lists a project\'s records as JSON and CSV; unknown audits are 404', async () => {
    const project = (await api('POST', '/api/v1/projects', { name: 'egress' })).json as { id: string };
    const st = Store.open({ dataDir, role: 'test' });
    st.insert('egress_record', {
      id: newId('egress'), kind: 'conversation', audit_id: null, step_id: null, conversation_id: 'cnv_x', project_id: project.id, ref: 'cnv_x', provider: 'gw', model: 'm1',
      endpoint: '127.0.0.1:1', status: 'ok', turns: 2, tokens_in: 1200, tokens_out: 300, tokens_cached: 0, files: [{ repo: 'shop', path: 'a/B.java' }], facts: ['fct_1'], withheld_facts: 1,
      tools: { read_file: 2 }, started_at: 1_700_000_000_000, ended_at: 1_700_000_001_000,
    });
    st.close();
    const rows = (await api('GET', `/api/v1/projects/${project.id}/egress`)).json as EgressDto[];
    expect(rows).toEqual([expect.objectContaining({ kind: 'conversation', conversationId: 'cnv_x', provider: 'gw', model: 'm1', withheldFacts: 1, files: [{ repo: 'shop', path: 'a/B.java' }], facts: ['fct_1'], tokens: { input: 1200, output: 300, cached: 0 }, tools: { read_file: 2 } })]);
    const csv = await api('GET', `/api/v1/projects/${project.id}/egress?format=csv`);
    expect(csv.type).toContain('text/csv');
    expect(csv.text.split('\n')).toEqual([expect.stringContaining('started_at,kind,audit,step,provider'), expect.stringContaining(',conversation,,,gw,m1,127.0.0.1:1,ok,1200,300,shop:a/B.java,fct_1,1')]);
    expect((await api('GET', '/api/v1/audits/aud_nope/egress')).status).toBe(404);
  });

  it('saves the models allowed to receive confidential facts (configured models only)', async () => {
    let ms = (await api('GET', '/api/v1/settings/models')).json;
    expect(ms.confidentialModels).toEqual([]);
    const put = (confidentialModels: string[]) => api('PUT', '/api/v1/settings/models', { defaultModel: ms.defaultModel, stageModels: ms.stageModels, fallbackModel: ms.fallbackModel, confidentialModels, revision: ms.revision });
    expect((await put(['gw/nope'])).status).toBe(422);
    expect((await put(['gw/m1'])).status).toBe(200);
    ms = (await api('GET', '/api/v1/settings/models')).json;
    expect(ms.confidentialModels).toEqual(['gw/m1']);
    expect((await put([])).status).toBe(200);
    expect((await api('GET', '/api/v1/settings/models')).json.confidentialModels).toEqual([]);
  });
});
