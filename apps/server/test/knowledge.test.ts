// over the API: list with annotations, edit with content hashes, sub-files,
// overrides, generated case index, and `knowledge.changed` on the global stream for edits made on disk.
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig, sha256Hex, type KnowledgeDraftDto, type SkillBodyDto, type SkillDto } from '@xiezhi/contracts';
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

const skill = (name: string, body = '正文', extra = '') => `---\nname: ${name}\ndescription: 订单接口越权判断方法，审计按 ID 读写订单的接口时读取\ncategory: audit_method\n${extra}---\n${body}\n`;

beforeAll(async () => {
  dataDir = join(mkdtempSync(join(tmpdir(), 'ca-know-')), 'data');
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

describe('knowledge management API', () => {
  it('edits global and project skills with content hashes and lists them with annotations', async () => {
    const project = (await api('POST', '/api/v1/projects', { name: 'shop' })).json as { id: string };
    const created = await api('PUT', '/api/v1/knowledge/global/order-idor-method', { text: skill('order-idor-method'), baseSha256: null });
    expect(created.status).toBe(200);
    const g = created.json as SkillBodyDto;
    expect(g).toMatchObject({ layer: 'global', form: 'file', valid: true, category: 'audit_method' });
    expect((await api('PUT', '/api/v1/knowledge/global/order-idor-method', { text: skill('order-idor-method'), baseSha256: null })).status).toBe(409);

    // Stale hash → 412 with the disk version; invalid text → 422 with the errors.
    const stale = await api('PUT', '/api/v1/knowledge/global/order-idor-method', { text: skill('order-idor-method', 'mine'), baseSha256: sha256Hex('x') });
    expect(stale.status).toBe(412);
    expect(stale.json.error.details.current.sha256).toBe(g.entrySha256);
    const invalid = await api('PUT', '/api/v1/knowledge/global/order-idor-method', { text: '---\nname: order-idor-method\n---\n', baseSha256: g.entrySha256 });
    expect(invalid.status).toBe(422);
    expect(invalid.json.error.details.errors.join()).toMatch(/description/);
    const edited = await api('PUT', '/api/v1/knowledge/global/order-idor-method', { text: skill('order-idor-method', '新正文') }, { 'if-match': `"${g.entrySha256}"` });
    expect(edited.status).toBe(200);

    // Project copy overrides the global one; a sub-file turns it into a directory skill.
    const p = await api('PUT', `/api/v1/projects/${project.id}/knowledge/order-idor-method`, { text: skill('order-idor-method', '项目版本'), baseSha256: null });
    expect(p.status).toBe(200);
    const sub = await api('PUT', `/api/v1/projects/${project.id}/knowledge/order-idor-method/files/examples/Bad.java`, { text: 'class Bad {}', baseSha256: null });
    expect((sub.json as SkillBodyDto).files.map((f) => f.path)).toEqual(['SKILL.md', 'examples/Bad.java']);
    const file = await api('GET', `/api/v1/projects/${project.id}/knowledge/order-idor-method/files/examples/Bad.java`);
    expect(file.json).toEqual({ path: 'examples/Bad.java', text: 'class Bad {}', sha256: sha256Hex('class Bad {}') });
    expect((await api('GET', `/api/v1/projects/${project.id}/knowledge/order-idor-method/files/../x.md`)).status).toBe(404);
    expect((await api('PUT', `/api/v1/projects/${project.id}/knowledge/order-idor-method/files/a.exe`, { text: 'x', baseSha256: null })).status).toBe(400);

    expect((await api('PUT', `/api/v1/projects/${project.id}/knowledge-overrides/ssrf-method`, { disabled: true })).json).toEqual({ disabled: ['ssrf-method'], disabledCategories: [] });
    await api('PUT', '/api/v1/knowledge/global-overrides/report-default-template', { disabled: true });
    const view = (await api('GET', `/api/v1/knowledge?projectId=${project.id}`)).json as SkillDto[];
    const row = (layer: string, name: string) => view.find((s) => s.layer === layer && s.name === name)!;
    expect(row('project', 'order-idor-method')).toMatchObject({ overridesGlobal: true, disabled: false, path: 'order-idor-method/SKILL.md' });
    expect(row('global', 'order-idor-method').overriddenBy).toEqual([project.id]);
    expect(row('global', 'ssrf-method')).toMatchObject({ disabled: true, disabledBy: ['project_name'] });
    expect(row('global', 'report-default-template')).toMatchObject({ disabled: true, disabledBy: ['global'] });
    const globalView = (await api('GET', '/api/v1/knowledge')).json as SkillDto[];
    expect(globalView.every((s) => s.layer === 'global')).toBe(true);
    expect(globalView.find((s) => s.name === 'order-idor-method')!.overriddenBy).toEqual([project.id]);

    // Delete needs the hash the user saw.
    expect((await api('DELETE', '/api/v1/knowledge/global/order-idor-method')).status).toBe(428);
    const cur = (await api('GET', '/api/v1/knowledge/global/order-idor-method')).json as SkillBodyDto;
    expect((await api('DELETE', `/api/v1/knowledge/global/order-idor-method?baseSha256=${cur.entrySha256}`)).status).toBe(204);
    expect((await api('GET', '/api/v1/knowledge/global/order-idor-method')).status).toBe(404);
  });

  it('regenerates the case index on writes and pushes knowledge.changed for edits made on disk', async () => {
    const res = await api('PUT', '/api/v1/knowledge/global/vuln-cases/files/ssrf-webhook.md', {
      text: '---\nname: ssrf-webhook\ndescription: Webhook 回调地址未限制内网\nvuln_class: ssrf\n---\n## 漏洞模式\n', baseSha256: null,
    });
    expect(res.status).toBe(200);
    const lib = (await api('GET', '/api/v1/knowledge/global/vuln-cases')).json as SkillBodyDto;
    expect(lib.body).toContain('- `ssrf-webhook.md` — Webhook 回调地址未限制内网');

    const ac = new AbortController();
    const stream = await fetch(`${base}/api/v1/events`, { headers: { authorization: `Bearer ${token}` }, signal: ac.signal });
    const reader = stream.body!.getReader();
    const got = (async () => {
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return buf;
        buf += new TextDecoder().decode(value);
        if (buf.includes('event: knowledge.changed')) return buf;
      }
    })();
    await new Promise((r) => setTimeout(r, 400));
    writeFileSync(join(dataDir, 'knowledge', 'global', 'handmade-method.md'), skill('handmade-method'));
    const text = await Promise.race([got, new Promise<string>((r) => setTimeout(() => r('timeout'), 5000))]);
    ac.abort();
    expect(text).toMatch(/event: knowledge\.changed\ndata: \{"type":"knowledge\.changed","auditId":null,"payload":\{"layer":"global","projectId":null\}\}/);
  });

  it('imports text as a draft, shows the checks, approves it; moves a project skill to global', async () => {
    const created = await api('POST', '/api/v1/knowledge/drafts', { layer: 'global', text: '订单接口：按 id 查询时应比较当前用户。', source: { kind: 'text' } });
    expect(created.status).toBe(202);
    let d = created.json as KnowledgeDraftDto;
    for (let i = 0; d.status === 'organizing' && i < 100; i++) {
      await new Promise((r) => setTimeout(r, 100));
      d = (await api('GET', `/api/v1/knowledge/drafts/${d.id}`)).json as KnowledgeDraftDto;
    }
    expect(d).toMatchObject({ status: 'ready', name: 'order-owner-method', layer: 'global', checks: { errors: [] } });
    expect(((await api('GET', '/api/v1/knowledge/drafts')).json as KnowledgeDraftDto[]).map((x) => x.id)).toContain(d.id);
    expect((await api('PUT', `/api/v1/knowledge/drafts/${d.id}`, { text: d.text.replace('# 订单归属校验', '# 订单归属校验（修订）'), revision: 1 })).json.revision).toBe(2);
    const ok = await api('POST', `/api/v1/knowledge/drafts/${d.id}/approve`, {});
    expect(ok.json).toMatchObject({ name: 'order-owner-method', file: null, draft: { status: 'approved' } });
    expect(((await api('GET', '/api/v1/knowledge/global/order-owner-method')).json as SkillBodyDto).body).toContain('（修订）');

    const project = (await api('POST', '/api/v1/projects', { name: 'shop-move' })).json as { id: string };
    await api('PUT', `/api/v1/projects/${project.id}/knowledge/shop-rules`, { text: skill('shop-rules', '内网 10.1.2.3 的网关负责鉴权'), baseSha256: null });
    const preview = await api('POST', `/api/v1/projects/${project.id}/knowledge/shop-rules/move-to-global`, {});
    expect(preview.json.hints).toEqual([expect.objectContaining({ kind: 'ip', text: '10.1.2.3' })]);
    const moved = await api('POST', `/api/v1/projects/${project.id}/knowledge/shop-rules/move-to-global`, { confirm: true, text: preview.json.text.replace('内网 10.1.2.3 的', '') });
    expect(moved.status).toBe(202);
    let md = moved.json as KnowledgeDraftDto;
    for (let i = 0; md.status === 'organizing' && i < 100; i++) {
      await new Promise((r) => setTimeout(r, 100));
      md = (await api('GET', `/api/v1/knowledge/drafts/${md.id}`)).json as KnowledgeDraftDto;
    }
    expect(md.moveFrom).toEqual({ projectId: project.id, name: 'shop-rules' });
    await api('POST', `/api/v1/knowledge/drafts/${md.id}/approve`, { afterMove: 'delete' });
    expect((await api('GET', `/api/v1/projects/${project.id}/knowledge/shop-rules`)).status).toBe(404);
    expect(((await api('GET', '/api/v1/knowledge/global/shop-rules')).json as SkillBodyDto).body).not.toContain('10.1.2.3');
  });
});
