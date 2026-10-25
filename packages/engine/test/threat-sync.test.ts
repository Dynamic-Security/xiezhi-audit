// Syncing a threat model to an online document through a `target: threat_model` push guide —
// always previewed, single-use confirmation, the document ID kept in sync_record, unchanged report skipped, the same
// document updated later; vulnerability pushes never list these guides.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { defaultAppConfig } from '@xiezhi/contracts';
import { commandHash } from '@xiezhi/connectors';
import { Store } from '@xiezhi/store';
import {
  Engine, addThreatSource, confirmConnectorCommand, confirmThreatModelSync, createConnector, createProject, createThreatModel, planThreatModelSync,
  documentRef, fixedKey, pushGuideList, queries as Q, withFixed, renderThreatModelReport, setConnectorSecrets, setThreatRiskStatus, testConnector,
} from '@xiezhi/engine';
import { startFakeOpenAI, type FakeServer } from '../../agent/test/fake-openai.js';

const FAKE_MCP = resolve(__dirname, '../../connectors/test/fake-mcp.mjs');
let model: FakeServer;
beforeAll(async () => { model = await startFakeOpenAI(() => ({ text: 'unused' })); });
afterAll(async () => { await model.close(); });

const GUIDE = `---
name: tm-doc-sync
description: 测试用：把威胁建模报告同步为外部记录，再次同步时更新同一条记录
category: push_guide
push:
  target: threat_model
  connector: tickets
  operation: create_issue
  external_id: $..key
  update_operations: [create_issue]
  update_key: key
---
# 同步指引（测试）
`;

describe('threat-model sync', () => {
  it('previews, confirms once, records the document, skips an unchanged report and updates the same document', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'xz-m15s-'));
    const store = Store.open({ dataDir: join(dir, 'data'), role: 'test' });
    store.saveConfig({
      ...defaultAppConfig(),
      modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl: model.url, apiKey: 'test-key-123456', models: [{ id: 'm1', contextWindow: 64_000, maxTokens: 4096 }] }],
      defaultModel: { provider: 'gw', model: 'm1' },
    });
    const engine = await Engine.open({ store });
    const deps = { store, hub: engine.hub, pool: engine.connectors };
    const p = createProject(store, 'shop');
    const g = join(store.paths.projects, p.id, 'knowledge', 'tm-doc-sync');
    mkdirSync(g, { recursive: true });
    writeFileSync(join(g, 'SKILL.md'), GUIDE);
    writeFileSync(join(g, 'template.yaml'), 'title: "{{document_title}}"\nbody: "{{report}}"\n');
    writeFileSync(join(g, 'template-update.yaml'), 'body: "{{report}}"\n');

    const tm = createThreatModel(store, p.id, { title: '订单退款' });
    addThreatSource(store, tm.id, { kind: 'text', text: '买家可以申请退款。' });
    store.update('threat_model', { id: tm.id }, { status: 'ready', generated_at: Date.now(), clarification_ref: store.artifacts.put('## 功能\n- 申请退款（S1）') });
    store.insert('threat_risk', { id: 'thr_1', threat_model_id: tm.id, no: 1, category: 'abuse', level: 'low', statement: '反复申请退款。', sources: [1] });
    const report = () => renderThreatModelReport(store, tm.id);

    // Listed for threat models only; the connector is not there yet.
    expect(pushGuideList(store, p.id, 'threat_model').map((x) => x.name).sort()).toEqual(['feishu-doc-threat-model-sync', 'tm-doc-sync']);
    expect(pushGuideList(store, p.id).map((x) => x.name)).not.toContain('tm-doc-sync');
    await expect(planThreatModelSync(deps, { threatModelId: tm.id, report: report() })).rejects.toThrow(/choose a sync guide/);
    await expect(planThreatModelSync(deps, { threatModelId: tm.id, skill: 'tm-doc-sync', report: report() })).rejects.toThrow(/does not exist/);

    const command = { path: process.execPath, args: [FAKE_MCP, '--stdio'], env: { API_TOKEN: '${secret:api}' } };
    const c = createConnector(store, { name: 'tickets', protocol: 'mcp_stdio', purpose: 'context', config: { command } });
    confirmConnectorCommand(store, c.id, commandHash(command));
    await setConnectorSecrets(store, engine.connectors, c.id, { api: 'sec-1' });
    await testConnector(store, engine.connectors, c.id);

    const plan = await planThreatModelSync(deps, { threatModelId: tm.id, skill: 'tm-doc-sync', report: report() });
    expect(plan).toMatchObject({ status: 'awaiting_confirm', action: 'create', existing: null, reasons: ['同步会写入外部文档，需要先确认'] });
    expect(plan.steps).toEqual([{ operation: 'create_issue', args: { title: 'shop 威胁建模 · 订单退款', body: expect.stringContaining('| R1 | 低 | 滥用 | 反复申请退款。') }, ok: null, error: null }]);
    await expect(confirmThreatModelSync(deps, plan.id, 'wrong', plan.payloadHash)).rejects.toThrow(/does not match/);
    const done = await confirmThreatModelSync(deps, plan.id, plan.token!, plan.payloadHash);
    expect(done.result).toEqual({ ok: true, externalId: 'T-1', externalUrl: null, error: null });
    await expect(confirmThreatModelSync(deps, plan.id, plan.token!, plan.payloadHash)).rejects.toThrow(/not found or expired/);
    expect(Q.threatModelDetail(store, tm.id)!.syncs).toEqual([expect.objectContaining({ connectorName: 'tickets', externalId: 'T-1' })]);

    expect(await planThreatModelSync(deps, { threatModelId: tm.id, skill: 'tm-doc-sync', report: report() })).toMatchObject({ action: 'skip', skipReason: '报告与上次同步时相同', token: null });

    // A triage changes the report: the same document is updated with its key from sync_record.
    setThreatRiskStatus(store, 'thr_1', { status: 'accepted', reason: '影响有限', actor: 'user' });
    const upd = await planThreatModelSync(deps, { threatModelId: tm.id, skill: 'tm-doc-sync', report: report() });
    expect(upd).toMatchObject({ action: 'update', existing: { externalId: 'T-1' } });
    expect(upd.steps[0]!.args).toEqual({ body: expect.stringContaining('接受风险'), key: 'T-1' });
    expect((await confirmThreatModelSync(deps, upd.id, upd.token!, upd.payloadHash)).result?.ok).toBe(true);
    expect(store.all("SELECT local_kind, external_id FROM sync_record WHERE local_id = ?", tm.id)).toEqual([{ local_kind: 'threat_model', external_id: 'T-1' }]);
    expect(store.all("SELECT kind, confirmed_by FROM connector_call WHERE connector_id = ? AND operation = 'create_issue'", c.id)).toEqual([
      { kind: 'write', confirmed_by: 'user' }, { kind: 'write', confirmed_by: 'user' },
    ]);
    await engine.stopAnalyses();
  }, 60_000);

  it('nested update keys and syncing into an existing document', () => {
    expect(fixedKey('path.document_id', 'D1')).toEqual({ path: { document_id: 'D1' } });
    expect(fixedKey('key', 'T-1')).toEqual({ key: 'T-1' });
    expect(fixedKey(undefined, 'x')).toEqual({});
    expect(withFixed({ path: { block_id: 'B', document_id: 'wrong' }, data: { a: 1 } }, fixedKey('path.document_id', 'D1')))
      .toEqual({ path: { block_id: 'B', document_id: 'D1' }, data: { a: 1 } });
    expect(documentRef('https://acme.feishu.cn/docx/AbC123xyz?from=home')).toEqual({ externalId: 'AbC123xyz', externalUrl: 'https://acme.feishu.cn/docx/AbC123xyz' });
    expect(documentRef('AbC123xyz')).toEqual({ externalId: 'AbC123xyz', externalUrl: null });
    expect(() => documentRef('https://acme.feishu.cn/wiki/Node1')).toThrow(/wiki page/);
    expect(() => documentRef('bad id!')).toThrow(/invalid document ID/);
  });
});

describe('threat-model sync into an existing document', () => {
  it('plans an update with the nested document key from the given link, then records it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'xz-m15s8-'));
    const store = Store.open({ dataDir: join(dir, 'data'), role: 'test' });
    store.saveConfig({ ...defaultAppConfig(), modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl: model.url, apiKey: 'test-key-123456', models: [{ id: 'm1' }] }], defaultModel: { provider: 'gw', model: 'm1' } });
    const engine = await Engine.open({ store });
    const deps = { store, hub: engine.hub, pool: engine.connectors };
    const p = createProject(store, 'shop');
    const g = join(store.paths.projects, p.id, 'knowledge', 'doc-sync');
    mkdirSync(g, { recursive: true });
    writeFileSync(join(g, 'SKILL.md'), GUIDE.replace('name: tm-doc-sync', 'name: doc-sync').replace('update_key: key', 'update_key: path.document_id'));
    writeFileSync(join(g, 'template.yaml'), 'title: "{{document_title}}"\n');
    writeFileSync(join(g, 'template-update.yaml'), 'data:\n  body: "{{report}}"\npath:\n  block_id: root\n');
    const command = { path: process.execPath, args: [FAKE_MCP, '--stdio'], env: { API_TOKEN: '${secret:api}' } };
    const c = createConnector(store, { name: 'tickets', protocol: 'mcp_stdio', purpose: 'context', config: { command } });
    confirmConnectorCommand(store, c.id, commandHash(command));
    await setConnectorSecrets(store, engine.connectors, c.id, { api: 'sec-1' });
    await testConnector(store, engine.connectors, c.id);
    const tm = createThreatModel(store, p.id, { title: '退款' });
    addThreatSource(store, tm.id, { kind: 'text', text: 'x' });
    store.update('threat_model', { id: tm.id }, { status: 'ready', generated_at: Date.now(), clarification_ref: store.artifacts.put('## 功能\n- x（S1）') });
    const report = renderThreatModelReport(store, tm.id);

    const plan = await planThreatModelSync(deps, { threatModelId: tm.id, skill: 'doc-sync', report, document: 'https://acme.feishu.cn/docx/Doc42abc' });
    expect(plan).toMatchObject({ action: 'update', existing: { externalId: 'Doc42abc', externalUrl: 'https://acme.feishu.cn/docx/Doc42abc' } });
    expect(plan.steps[0]!.args).toEqual({ data: { body: expect.stringContaining('# 退款') }, path: { block_id: 'root', document_id: 'Doc42abc' } });
    const done = await confirmThreatModelSync(deps, plan.id, plan.token!, plan.payloadHash);
    expect(done.result).toMatchObject({ ok: true, externalId: 'Doc42abc', externalUrl: 'https://acme.feishu.cn/docx/Doc42abc' });
    expect(Q.threatModelDetail(store, tm.id)!.syncs).toEqual([expect.objectContaining({ externalId: 'Doc42abc' })]);
    // Next time without a link: the recorded document, unchanged report → skipped.
    expect((await planThreatModelSync(deps, { threatModelId: tm.id, skill: 'doc-sync', report })).action).toBe('skip');
    await engine.stopAnalyses();
  }, 60_000);
});
