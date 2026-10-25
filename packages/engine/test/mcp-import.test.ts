// Importing MCP servers configured in other tools — credentials masked on discovery,
// copied / left blank / dropped on import, commands resolved to absolute paths, unsupported transports reported.
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Store } from '@xiezhi/store';
import { Engine, discoverMcpConfigs, getConnector, importMcpConfig } from '@xiezhi/engine';

const SECRET = 'app-secret-value-123456';
const UAT = 'u-user-token-abcdef';
let home: string;
let bin: string;

beforeAll(() => {
  home = mkdtempSync(join(tmpdir(), 'xz-home-'));
  bin = join(home, 'bin');
  mkdirSync(bin);
  writeFileSync(join(bin, 'npx'), '#!/bin/sh\n');
  chmodSync(join(bin, 'npx'), 0o755);
  mkdirSync(join(home, '.cursor'));
  writeFileSync(join(home, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: {
    'feishu-mcp': { command: 'npx', args: ['-y', '@larksuiteoapi/lark-mcp', 'mcp', '-a', 'cli_123', '-s', SECRET, '-l', 'zh', '-u', UAT] },
    tickets: { command: 'nosuchcmd-xyz', args: [], env: { API_TOKEN: 'tok-999999', REGION: 'cn' } },
  } }));
  writeFileSync(join(home, '.claude.json'), JSON.stringify({ mcpServers: {
    docs: { type: 'http', url: 'https://mcp.example.com/mcp', headers: { Authorization: 'Bearer hdr-secret-777', 'X-Team': 'sec' } },
    legacy: { type: 'sse', url: 'https://old.example.com/sse' },
    flow: { url: 'https://mcp.example.cn/message?token=qry-secret-555&lang=zh' },
  }, projects: {} }));
});

let dir: string;
let store: Store;
let engine: Engine;
beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'xz-imp-'));
  store = Store.open({ dataDir: join(dir, 'data'), role: 'test' });
  engine = await Engine.open({ store });
});
afterAll(async () => { await engine.stopAnalyses(); store.close(); });

describe('importing MCP configurations', () => {
  it('discovers servers of several tools without exposing credentials', () => {
    const all = discoverMcpConfigs({ home, pathDirs: [bin] });
    expect(all.map((c) => c.id).sort()).toEqual(['claude_code:docs', 'claude_code:flow', 'claude_code:legacy', 'cursor:feishu-mcp', 'cursor:tickets']);
    expect(JSON.stringify(all)).not.toMatch(new RegExp(`${SECRET}|${UAT}|tok-999999|hdr-secret-777|qry-secret-555`));
    const lark = all.find((c) => c.id === 'cursor:feishu-mcp')!;
    expect(lark).toMatchObject({ protocol: 'mcp_stdio', resolvedPath: join(bin, 'npx'), args: ['-y', '@larksuiteoapi/lark-mcp', 'mcp', '-a', 'cli_123', '-s', '<密钥>', '-l', 'zh', '-u', '<密钥>'] });
    expect(lark.secrets.map((s) => [s.name, s.where, s.key])).toEqual([['s', 'arg', '-s'], ['u', 'arg', '-u']]);
    expect(all.find((c) => c.id === 'cursor:tickets')!.issues[0]).toMatch(/找不到命令/);
    expect(all.find((c) => c.id === 'claude_code:docs')!.secrets).toEqual([expect.objectContaining({ name: 'authorization', where: 'header' })]);
    expect(all.find((c) => c.id === 'claude_code:flow')).toMatchObject({ url: 'https://mcp.example.cn/message?token=<密钥>&lang=zh', secrets: [expect.objectContaining({ name: 'token', where: 'query' })] });
    expect(all.find((c) => c.id === 'claude_code:legacy')!.issues).toContain('SSE 传输不受支持（只支持 stdio 与 streamable HTTP）');
  });

  it('imports with credentials copied, left blank or dropped, and extra arguments', async () => {
    const row = await importMcpConfig(store, engine.connectors, {
      candidate: 'cursor:feishu-mcp', name: 'Feishu', purpose: 'context', allowWrite: true, secrets: { s: 'import', u: 'drop' }, extraArgs: ['-t', 'docx.v1.document.rawContent'], home, pathDirs: [bin],
    });
    const c = getConnector(store, row.id);
    expect(JSON.parse(c.config).command).toEqual({ path: join(bin, 'npx'), args: ['-y', '@larksuiteoapi/lark-mcp', 'mcp', '-a', 'cli_123', '-s', '${secret:s}', '-l', 'zh', '-t', 'docx.v1.document.rawContent'], env: { npm_config_cache: join(home, '.npm') } });
    expect(store.config.connectorSecrets?.[row.id]).toEqual({ s: SECRET });
    expect(c.confirmed_command_hash).toBeNull();

    const http = await importMcpConfig(store, engine.connectors, { candidate: 'claude_code:docs', purpose: 'context', secrets: { authorization: 'import' }, home, pathDirs: [bin] });
    expect(JSON.parse(getConnector(store, http.id).config)).toEqual({ url: 'https://mcp.example.com/mcp', headers: { Authorization: 'Bearer ${secret:authorization}', 'X-Team': 'sec' } });
    expect(store.config.connectorSecrets?.[http.id]).toEqual({ authorization: 'hdr-secret-777' });

    const flow = await importMcpConfig(store, engine.connectors, { candidate: 'claude_code:flow', purpose: 'context', secrets: { token: 'import' }, home, pathDirs: [bin] });
    expect(JSON.parse(getConnector(store, flow.id).config).url).toBe('https://mcp.example.cn/message?token=${secret:token}&lang=zh');
    expect(store.config.connectorSecrets?.[flow.id]).toEqual({ token: 'qry-secret-555' });
    await expect(importMcpConfig(store, engine.connectors, { candidate: 'cursor:tickets', purpose: 'context', home, pathDirs: [bin] })).rejects.toThrow(/not found/);
    await expect(importMcpConfig(store, engine.connectors, { candidate: 'claude_code:legacy', purpose: 'context', home })).rejects.toThrow(/SSE/);
    await expect(importMcpConfig(store, engine.connectors, { candidate: 'cursor:nope', purpose: 'context', home })).rejects.toThrow(/not found/);
    await expect(importMcpConfig(store, engine.connectors, { candidate: 'cursor:feishu-mcp', name: 'Feishu', purpose: 'context', home, pathDirs: [bin] })).rejects.toThrow(/already exists/);
  });
});
