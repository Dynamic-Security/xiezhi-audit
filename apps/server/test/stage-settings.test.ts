// Model settings: the default model, the
// per-stage table and one fallback in settings → 模型; the scene defaults keep only cross review.
import { createServer } from 'node:net';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { startServer, type RunningServer } from '@xiezhi/server';

const M1 = { provider: 'gw', model: 'm1' };
const M2 = { provider: 'gw', model: 'm2' };
let srv: RunningServer;
let base: string;
let token: string;

async function freePort(): Promise<number> {
  return new Promise((ok) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => { const p = (s.address() as { port: number }).port; s.close(() => ok(p)); });
  });
}
async function api(method: string, path: string, body?: unknown) {
  const res = await fetch(`${base}${path}`, {
    method, headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

beforeAll(async () => {
  const dataDir = join(mkdtempSync(join(tmpdir(), 'ca-stage-set-')), 'data');
  const pre = Store.open({ dataDir, role: 'setup' });
  pre.saveConfig({ ...defaultAppConfig(), modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl: 'http://127.0.0.1:1/v1', apiKey: 'sk-stage-settings-000000', models: [{ id: 'm1' }, { id: 'm2' }] }], defaultModel: M1 });
  pre.close();
  srv = await startServer({ dataDir, port: await freePort(), webRoot: null });
  base = srv.url.replace(/\/$/, '');
  token = JSON.parse(readFileSync(join(dataDir, 'run', 'api.json'), 'utf8')).token;
});
afterAll(async () => { await srv?.close(); });

describe('model settings', () => {
  it('saves the default model, per-stage models (null = no model, triage / merge only) and the fallback; scene defaults follow them', async () => {
    let ms = (await api('GET', '/api/v1/settings/models')).json;
    expect(ms).toMatchObject({ defaultModel: M1, stageModels: {}, fallbackModel: null });
    const stageModels = { hunt: { ...M2, thinking: 'high' }, triage: null, chat: M2 };
    expect((await api('PUT', '/api/v1/settings/models', { defaultModel: M1, stageModels, fallbackModel: M2, revision: ms.revision })).status).toBe(200);
    ms = (await api('GET', '/api/v1/settings/models')).json;
    expect(ms).toMatchObject({ defaultModel: M1, stageModels, fallbackModel: M2 });
    const eff = (await api('GET', '/api/v1/settings/scene-defaults/full')).json.effective;
    expect(eff.models).toMatchObject({ audit: { ...M2, thinking: 'high' }, triage: null, merge: M1, report: M1, challenge: M1 });
    // Only triage and merge can run without a model; unknown models and stale revisions are refused.
    expect((await api('PUT', '/api/v1/settings/models', { defaultModel: M1, stageModels: { explore: null }, fallbackModel: null, revision: ms.revision })).status).toBeGreaterThanOrEqual(400);
    expect((await api('PUT', '/api/v1/settings/models', { defaultModel: M1, stageModels: { report: { provider: 'gw', model: 'ghost' } }, fallbackModel: null, revision: ms.revision })).status).toBeGreaterThanOrEqual(400);
    expect((await api('PUT', '/api/v1/settings/models', { defaultModel: M1, cheapModel: M2, stageModels: {}, fallbackModel: null, revision: ms.revision })).status).toBeGreaterThanOrEqual(400);
    // The old roles are gone from the body (additionalProperties: false) — and null clears the fallback.
    expect((await api('PUT', '/api/v1/settings/models', { defaultModel: M1, stageModels: {}, fallbackModel: null, revision: ms.revision })).status).toBe(200);
    expect((await api('GET', '/api/v1/settings/models')).json).toMatchObject({ stageModels: {}, fallbackModel: null });
  });

  it('scene defaults keep cross review but no stage models or per-stage fallbacks', async () => {
    const sd = (await api('GET', '/api/v1/settings/scene-defaults/full')).json;
    const override = { ...sd.override, models: { logic: { ...M2, thinking: 'high' } }, modelFallbacks: { hunt: M2 }, multiModel: { enabled: true, models: [M1, { ...M2, thinking: 'low' }] } };
    const put = await api('PUT', '/api/v1/settings/scene-defaults/full', { override, revision: sd.revision });
    expect(put.status).toBe(200);
    expect(put.json.override.models).toBeUndefined();
    expect(put.json.override.modelFallbacks).toBeUndefined();
    const eff = (await api('GET', '/api/v1/settings/scene-defaults/full')).json.effective;
    expect(eff.models.logic).toEqual(M1); // from settings → 模型 (the default model), not the scene layer
    expect(eff.modelFallbacks).toBeUndefined();
    expect(eff.multiModel.models[1]).toEqual({ ...M2, thinking: 'low' });
  });
});

describe('external tool paths in general settings', () => {
  it('sets a language server path, clears it with null, rejects a relative path', async () => {
    let g = (await api('GET', '/api/v1/settings/general')).json;
    expect(g.tools).toEqual({});
    const ts = '/opt/lsp/bin/typescript-language-server';
    expect((await api('PATCH', '/api/v1/settings/general', { revision: g.revision, tools: { tsLspPath: ts, nodePath: '/opt/node/bin/node' } })).status).toBe(200);
    g = (await api('GET', '/api/v1/settings/general')).json;
    expect(g.tools).toEqual({ tsLspPath: ts, nodePath: '/opt/node/bin/node' });
    expect((await api('PATCH', '/api/v1/settings/general', { revision: g.revision, tools: { tsLspPath: 'bin/tls' } })).status).toBe(400);
    expect((await api('PATCH', '/api/v1/settings/general', { revision: g.revision, tools: { tsLspPath: null } })).status).toBe(200);
    expect((await api('GET', '/api/v1/settings/general')).json.tools).toEqual({ nodePath: '/opt/node/bin/node' });
  });
});
