// Model provider forms: probe the models of an unsaved form, check it with one minimal request per
// selected model, reuse a saved key only for the origin it is bound to, never follow redirects, never echo keys.
import { createServer as createHttpServer, type Server } from 'node:http';
import { createServer } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { startServer, type RunningServer } from '@xiezhi/server';
import { startFakeOpenAI, type FakeServer } from '../../../packages/agent/test/fake-openai.js';

const KEY = 'sk-providers-test-secret-0123456789';

async function freePort(): Promise<number> {
  return new Promise((ok) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => { const p = (s.address() as { port: number }).port; s.close(() => ok(p)); });
  });
}

let model: FakeServer;
let redirector: Server;
let redirectUrl: string;
let srv: RunningServer;
let base: string;
let token: string;
const bodies: string[] = [];

async function api(method: string, path: string, body?: unknown) {
  const res = await fetch(`${base}${path}`, {
    method, headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  bodies.push(text);
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

beforeAll(async () => {
  model = await startFakeOpenAI(() => ({ text: 'p' }), { models: ['m1', 'm2', 'm3'] });
  redirector = createHttpServer((_req, res) => { res.writeHead(302, { location: 'http://example.invalid/' }); res.end(); });
  await new Promise<void>((ok) => redirector.listen(0, '127.0.0.1', () => ok()));
  redirectUrl = `http://127.0.0.1:${(redirector.address() as { port: number }).port}/v1`;
  const dataDir = join(mkdtempSync(join(tmpdir(), 'ca-prov-')), 'data');
  const pre = Store.open({ dataDir, role: 'setup' });
  pre.saveConfig({ ...defaultAppConfig(), modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl: model.url, apiKey: KEY, apiKeyOrigin: new URL(model.url).origin, models: [{ id: 'm1' }] }], defaultModel: { provider: 'gw', model: 'm1' } });
  pre.close();
  srv = await startServer({ dataDir, port: await freePort(), webRoot: null });
  base = srv.url.replace(/\/$/, '');
  token = JSON.parse((await import('node:fs')).readFileSync(join(dataDir, 'run', 'api.json'), 'utf8')).token;
});
afterAll(async () => {
  await srv?.close();
  await model?.close();
  await new Promise((ok) => redirector?.close(ok));
});

describe('provider form probe and check', () => {
  it('probes the models of an unsaved form with the key it carries', async () => {
    model.reset();
    const r = await api('POST', '/api/v1/settings/model-providers/probe', { api: 'openai-completions', baseUrl: model.url, apiKey: 'sk-form-key-0000000000' });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ ok: true, models: ['m1', 'm2', 'm3'] });
  });

  it('reuses a saved key only for the origin it is bound to', async () => {
    model.reset();
    const same = await api('POST', '/api/v1/settings/model-providers/check', { id: 'gw', api: 'openai-completions', baseUrl: model.url, models: ['m2'] });
    expect(same.json.models[0]).toMatchObject({ id: 'm2', ok: true });
    expect(model.requests.at(-1)!.headers.authorization).toBe(`Bearer ${KEY}`);
    // Same provider id, another origin: tried without the saved key.
    const other = model.url.replace('127.0.0.1', 'localhost');
    model.reset();
    await api('POST', '/api/v1/settings/model-providers/check', { id: 'gw', api: 'openai-completions', baseUrl: other, models: ['m2'] });
    expect(model.requests.at(-1)!.headers.authorization).toBeUndefined();
  });

  it('checks each selected model with one minimal request and tells a missing model apart', async () => {
    model.reset();
    const r = await api('POST', '/api/v1/settings/model-providers/check', { id: 'gw', api: 'openai-completions', baseUrl: model.url, models: ['m1', 'nope', 'm3'] });
    expect(r.json).toMatchObject({ ok: false, list: { ok: true, count: 3 }, truncated: false });
    const byId = Object.fromEntries((r.json.models as { id: string; ok: boolean; detail: string }[]).map((m) => [m.id, m]));
    expect(byId.m1!.ok && byId.m3!.ok).toBe(true);
    expect(byId.nope).toMatchObject({ ok: false, detail: expect.stringContaining('404') });
    expect(r.json.detail).toBe('2/3 个模型可用');
    const sent = model.requests.map((q) => q.body as { model: string; max_tokens?: number });
    expect(sent.map((b) => b.model).sort()).toEqual(['m1', 'm3', 'nope']);
    expect(sent.every((b) => b.max_tokens === 1)).toBe(true);
  });

  it('checks at most 10 models per request', async () => {
    const ids = Array.from({ length: 12 }, (_, i) => `x${i}`);
    const r = await api('POST', '/api/v1/settings/model-providers/check', { id: 'gw', api: 'openai-completions', baseUrl: model.url, models: ids });
    expect(r.json.models).toHaveLength(10);
    expect(r.json.truncated).toBe(true);
  });

  it('does not follow redirects and rejects a bad address', async () => {
    const r = await api('POST', '/api/v1/settings/model-providers/probe', { api: 'openai-completions', baseUrl: redirectUrl, apiKey: 'sk-form-key-0000000000' });
    expect(r.json).toMatchObject({ ok: false, detail: expect.stringContaining('重定向') });
    const c = await api('POST', '/api/v1/settings/model-providers/check', { api: 'openai-completions', baseUrl: redirectUrl, models: ['m1'] });
    expect(c.json.models[0]).toMatchObject({ ok: false, detail: expect.stringContaining('重定向') });
    expect((await api('POST', '/api/v1/settings/model-providers/probe', { api: 'openai-completions', baseUrl: 'ftp://x' })).status).toBe(400);
  });

  it('never returns a key', () => {
    expect(bodies.some((b) => b.includes(KEY) || b.includes('sk-form-key-0000000000'))).toBe(false);
  });
});

describe('deleting a provider still named by model settings', () => {
  const add = (id: string) => api('POST', '/api/v1/settings/model-providers', { id, api: 'openai-completions', baseUrl: model.url, models: [{ id: 'm1' }, { id: 'm2' }] });
  const settings = async () => (await api('GET', '/api/v1/settings/models')).json;
  const putModels = async (patch: Record<string, unknown>) => {
    const cur = await settings();
    const r = await api('PUT', '/api/v1/settings/models', { defaultModel: cur.defaultModel, stageModels: cur.stageModels, fallbackModel: cur.fallbackModel, confidentialModels: cur.confidentialModels, ...patch, revision: cur.revision });
    expect(r.status).toBe(200);
  };

  it('deletes an unreferenced provider', async () => {
    expect((await add('spare')).status).toBe(201);
    const list = (await api('GET', '/api/v1/settings/model-providers')).json;
    expect(list.find((p: { id: string }) => p.id === 'spare').references).toEqual([]);
    const r = await api('DELETE', '/api/v1/settings/model-providers/spare');
    expect(r).toMatchObject({ status: 200, json: { cleared: [] } });
    expect((await api('GET', '/api/v1/settings/model-providers')).json.map((p: { id: string }) => p.id)).toEqual(['gw']);
  });

  it('refuses a provider used only as the fallback model, naming it, and clears it when asked', async () => {
    await add('fb');
    await putModels({ fallbackModel: { provider: 'fb', model: 'm2' } });
    const list = (await api('GET', '/api/v1/settings/model-providers')).json;
    expect(list.find((p: { id: string }) => p.id === 'fb').references).toEqual([{ setting: 'fallbackModel', label: '备用模型', model: 'fb/m2' }]);
    const r = await api('DELETE', '/api/v1/settings/model-providers/fb');
    expect(r.status).toBe(409);
    expect(r.json.error).toMatchObject({ code: 'PROVIDER_IN_USE', hint: expect.stringContaining('备用模型'), details: { references: [{ setting: 'fallbackModel', model: 'fb/m2' }] } });
    expect((await settings()).fallbackModel).toMatchObject({ provider: 'fb' });
    const ok = await api('DELETE', '/api/v1/settings/model-providers/fb?clearReferences=1');
    expect(ok).toMatchObject({ status: 200, json: { cleared: [{ setting: 'fallbackModel', label: '备用模型', model: 'fb/m2' }] } });
    const s = await settings();
    expect(s.fallbackModel).toBeNull();
    expect(s.defaultModel).toMatchObject({ provider: 'gw', model: 'm1' });
  });

  it('clears per-stage, confidential and cross-check references, keeping the others', async () => {
    await add('st');
    await putModels({ stageModels: { hunt: { provider: 'st', model: 'm1' }, chat: { provider: 'gw', model: 'm1' }, triage: null }, confidentialModels: ['st/m1', 'gw/m1'] });
    const sd = (await api('GET', '/api/v1/settings/scene-defaults/full')).json;
    const group = { enabled: true, models: [{ provider: 'gw', model: 'm1' }, { provider: 'st', model: 'm2' }], stages: { hunt: true } };
    expect((await api('PUT', '/api/v1/settings/scene-defaults/full', { override: { ...sd.override, multiModel: group }, revision: sd.revision })).status).toBe(200);

    const r = await api('DELETE', '/api/v1/settings/model-providers/st');
    expect(r.status).toBe(409);
    expect(r.json.error.details.references.map((x: { setting: string }) => x.setting)).toEqual(['stageModels.hunt', 'confidentialModels', 'sceneDefaults.full.multiModel']);
    expect(r.json.error.hint).toContain('各阶段模型 · 领域审计');

    expect((await api('DELETE', '/api/v1/settings/model-providers/st?clearReferences=1')).status).toBe(200);
    const s = await settings();
    expect(s.stageModels).toEqual({ chat: { provider: 'gw', model: 'm1' }, triage: null });
    expect(s.confidentialModels).toEqual(['gw/m1']);
    const full = (await api('GET', '/api/v1/settings/scene-defaults/full')).json;
    expect(full.override.multiModel).toMatchObject({ enabled: false, models: [{ provider: 'gw', model: 'm1' }] });
    expect(JSON.stringify([s, full.override])).not.toContain('"st"');
  });

  it('refuses the provider of the default model until cleared, then leaves no default', async () => {
    await putModels({ stageModels: {}, confidentialModels: [] });
    const refs = (await api('DELETE', '/api/v1/settings/model-providers/gw')).json.error.details.references;
    expect(refs).toEqual([{ setting: 'defaultModel', label: '默认模型', model: 'gw/m1' }, { setting: 'sceneDefaults.full.multiModel', label: '任务创建默认值 · 全量审计 · 多模型交叉', model: 'gw/m1' }]);
    expect((await api('DELETE', '/api/v1/settings/model-providers/gw?clearReferences=1')).status).toBe(200);
    expect((await settings()).defaultModel).toBeNull();
    expect((await api('GET', '/api/v1/settings/scene-defaults/full')).json.override.multiModel.models).toEqual([]);
    expect((await api('DELETE', '/api/v1/settings/model-providers/gw')).status).toBe(404);
  });
});
