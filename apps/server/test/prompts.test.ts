// over the API: the pipeline prompts with their defaults and layer overrides; saving checks variables
// and locked tokens; one entry or a whole layer goes back to the defaults.
import { mkdtempSync, readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig, type PromptDto, type PromptListDto } from '@xiezhi/contracts';
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
  dataDir = join(mkdtempSync(join(tmpdir(), 'ca-prompts-')), 'data');
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

describe('pipeline prompts API', () => {
  it('lists every group, saves a checked override per layer, restores one or all', async () => {
    const list = (await api('GET', '/api/v1/knowledge/prompts')).json as PromptListDto;
    expect(list.hash).toBe('default');
    expect(new Set(list.items.map((p) => p.group))).toEqual(new Set(['role_rules', 'step_task', 'standalone', 'conversation', 'nudge', 'data_note', 'tool']));
    expect(list.items.filter((p) => p.group === 'tool').every((p) => !p.editable && p.readonlyReason)).toBe(true);
    expect(list.items.some((p) => p.id.startsWith('field.submitfindings.'))).toBe(true);
    const intro = list.items.find((p) => p.id === 'challenge.intro')!;
    expect(intro).toMatchObject({ editable: true, effectiveLayer: 'default', global: null, project: null });
    expect(intro.locked).toContain('submit_challenge');

    const bad = await api('PUT', '/api/v1/knowledge/prompts/challenge.intro', { text: '随便复核一下' });
    expect(bad.status).toBe(422);
    expect((bad.json.error.details.errors as string[]).join()).toMatch(/锁定词.*submit_challenge/);
    expect((await api('PUT', '/api/v1/knowledge/prompts/boundary.declaration', { text: 'x' })).status).toBe(422);
    expect((await api('PUT', '/api/v1/knowledge/prompts/nope.entry', { text: 'x' })).status).toBe(404);

    const g = await api('PUT', '/api/v1/knowledge/prompts/challenge.intro', { text: `【全局】${intro.defaultText}` });
    expect(g.status).toBe(200);
    expect(g.json as PromptDto).toMatchObject({ effectiveLayer: 'global', global: { valid: true, defaultChanged: false } });
    const project = (await api('POST', '/api/v1/projects', { name: 'shop' })).json as { id: string };
    const p = await api('PUT', '/api/v1/knowledge/prompts/challenge.intro', { text: `【项目】${intro.defaultText}`, projectId: project.id });
    expect((p.json as PromptDto).effectiveLayer).toBe('project');
    const inProject = (await api('GET', `/api/v1/knowledge/prompts?projectId=${project.id}`)).json as PromptListDto;
    expect(inProject.overrides).toBe(1);
    expect(inProject.items.find((x) => x.id === 'challenge.intro')!.effectiveText.startsWith('【项目】')).toBe(true);
    // Restoring the project entry falls back to the global override; restoring the global layer to the default.
    const one = await api('DELETE', `/api/v1/knowledge/prompts/challenge.intro?projectId=${project.id}`);
    expect((one.json as PromptDto).effectiveLayer).toBe('global');
    const all = await api('DELETE', '/api/v1/knowledge/prompts');
    expect(all.json.restored).toEqual(['challenge.intro']);
    expect(((await api('GET', '/api/v1/knowledge/prompts')).json as PromptListDto).hash).toBe('default');
  });
});
