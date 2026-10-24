// Connector packs that run a CLI (lark-cli) — command templates without a shell, stdin for
// long content, optional flags dropped, the user's HOME for `home: user`, confirmation of program + commands.
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Store } from '@xiezhi/store';
import {
  Engine, commandLine, confirmConnectorCommand, confirmationHash, connectorSpec, connectorStatus, createConnector, getConnector, installExamplePack, testConnector, userConnectorQuery,
} from '@xiezhi/engine';

let dir: string;
let store: Store;
let engine: Engine;
let fake: string;
let log: string;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'xz-cli-'));
  log = join(dir, 'calls.log');
  fake = join(dir, 'lark-cli');
  // A stand-in for lark-cli: records args, HOME, the notifier variables and stdin, prints lark-cli-like JSON.
  writeFileSync(fake, `#!/bin/sh
IN=$(cat)
printf '%s|HOME=%s|N=%s|STDIN=%s\\n' "$*" "$HOME" "$LARKSUITE_CLI_NO_UPDATE_NOTIFIER" "$IN" >> ${JSON.stringify(log)}
case "$2" in
  +fetch) echo '{"ok":true,"data":{"document":{"document_id":"D1","content":"# PRD\\\\n买家可以退款"}}}' ;;
  +create) echo '{"ok":true,"data":{"document":{"document_id":"NewDoc9","url":"https://acme.feishu.cn/docx/NewDoc9"}}}' ;;
  +update) echo '{"ok":true,"data":{"revision_id":7}}' ;;
  *) echo "unknown" >&2; exit 2 ;;
esac
`);
  chmodSync(fake, 0o755);
  store = Store.open({ dataDir: join(dir, 'data'), role: 'test' });
  engine = await Engine.open({ store });
});
afterAll(async () => { await engine.stopAnalyses(); store.close(); });

describe('CLI connector packs', () => {
  it('needs the program and commands confirmed, then reads and writes through the CLI', async () => {
    installExamplePack(store, 'lark-cli');
    const c = createConnector(store, { name: 'Feishu', protocol: 'http', purpose: 'context', allowWrite: true, config: { pack: 'lark-cli', program_path: fake } });
    expect(connectorStatus(c, store.paths.connectorPacks)).toBe('needs_confirmation');
    const shown = commandLine(c, store.paths.connectorPacks)!;
    expect(shown).toContain('使用你的 HOME');
    expect(shown).toContain(`[read] fetch_doc: ${fake} docs +fetch --doc {doc} --doc-format markdown --as {as}`);
    expect(shown).toContain('[write] overwrite_doc:');
    confirmConnectorCommand(store, c.id, confirmationHash(c, store.paths.connectorPacks)!);
    const tested = await testConnector(store, engine.connectors, c.id);
    expect(connectorStatus(tested, store.paths.connectorPacks)).toBe('ready');
    expect(JSON.parse(getConnector(store, c.id).tools).map((t: { name: string; readOnlyHint: boolean }) => [t.name, t.readOnlyHint])).toEqual([['fetch_doc', true], ['create_doc', false], ['overwrite_doc', false]]);

    const read = await userConnectorQuery(store, engine.connectors, c.id, 'fetch_doc', { doc: 'https://acme.feishu.cn/wiki/Node1' });
    expect(read).toMatchObject({ isError: false });
    expect(read.text).toContain('买家可以退款');
    // Writes go through the pool as a push / sync does (userConnectorQuery only runs read operations of packs).
    const created = await engine.connectors.call(connectorSpec(getConnector(store, c.id), store.paths.connectorPacks), 'create_doc', { title: '订单 威胁建模', content: '# 报告\n- R1 越权' });
    expect(JSON.parse(created.text)).toEqual({ document_id: 'NewDoc9', url: 'https://acme.feishu.cn/docx/NewDoc9' });

    const calls = readFileSync(log, 'utf8').trim().split('\n');
    expect(calls[0]).toBe(`docs +fetch --doc https://acme.feishu.cn/wiki/Node1 --doc-format markdown --as user|HOME=${homedir()}|N=1|STDIN=`);
    // The optional --parent-token is left out; the body goes through stdin, not the command line.
    expect(calls[1]!.startsWith(`docs +create --doc-format markdown --title 订单 威胁建模 --content - --as user|HOME=${homedir()}|N=1|STDIN=# 报告`)).toBe(true);
  });

  it('a changed program path needs a new confirmation; a missing program is reported', async () => {
    const c = getConnector(store, store.get<{ id: string }>("SELECT id FROM connector WHERE name = 'Feishu'")!.id);
    const before = confirmationHash(c, store.paths.connectorPacks);
    const other = createConnector(store, { name: 'Feishu2', protocol: 'http', purpose: 'context', config: { pack: 'lark-cli', program_path: '/usr/bin/true' } });
    expect(confirmationHash(other, store.paths.connectorPacks)).not.toBe(before);
    const missing = createConnector(store, { name: 'Feishu3', protocol: 'http', purpose: 'context', config: { pack: 'lark-cli', program_path: join(dir, 'nope') } });
    confirmConnectorCommand(store, missing.id, confirmationHash(missing, store.paths.connectorPacks)!);
    const t = await testConnector(store, engine.connectors, missing.id);
    expect(connectorStatus(t, store.paths.connectorPacks)).toBe('ready');
    await expect(userConnectorQuery(store, engine.connectors, missing.id, 'fetch_doc', { doc: 'x' })).rejects.toThrow(/not an executable file/);
  });
});
