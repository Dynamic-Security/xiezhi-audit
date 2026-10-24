// connector packs: validation, templates (typed JSON fill, safe path params, query),
// extraction, the Jira example against a fake Jira with script authentication through the executor, and
// script confirmation by hash.
import { cpSync, mkdtempSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Executor, runScript } from '@xiezhi/context';
import { ConnectorPool, checkArgs, extract, fillBody, fillPath, loadPack, packScriptsHash, PackError, type ConnectorSpec } from '@xiezhi/connectors';
// @ts-expect-error plain ESM fixture without types
import { createFakeJira } from './fake-jira.mjs';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-pack-'));
const JIRA = resolve(__dirname, '../../../connector-packs/jira-cloud');

let server: Server;
let base: string;
const jira = createFakeJira();
beforeAll(async () => {
  server = createServer(jira.handler);
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', () => ok()));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(() => new Promise<void>((ok) => server.close(() => ok())));

describe('pack format', () => {
  it('validates the Jira example and reports every problem of a broken pack', () => {
    const p = loadPack(JIRA, 'jira-cloud');
    expect(p.operations.map((o) => `${o.name}:${o.kind}`)).toEqual(['search_issues:read', 'get_issue:read', 'get_transitions:read', 'create_issue:write', 'add_comment:write', 'transition_issue:write']);
    expect(p.scripts).toEqual(['scripts/basic-auth.mjs']);
    const dir = tmp();
    writeFileSync(join(dir, 'CONNECTOR.md'), '---\nname: Bad_Name\ndescription: short\nauth: { type: header, name: Authorization, value: "Bearer literal" }\n---\n');
    writeFileSync(join(dir, 'operations.yaml'), 'operations:\n  - name: delete_all\n    kind: write\n    method: GET\n    path: /x/{id}\n    description: d\n');
    const err = (() => { try { loadPack(dir); } catch (e) { return e as PackError; } throw new Error('expected'); })();
    expect(err.errors.join('\n')).toMatch(/name must match[\s\S]*description[\s\S]*auth.value must reference a secret[\s\S]*GET operations must be read[\s\S]*unknown parameter \{id\}/);
  });

  it('fills templates safely and extracts results', () => {
    const op = loadPack(JIRA, 'jira-cloud').operations.find((o) => o.name === 'create_issue')!;
    const args = checkArgs(op, { project: 'SEC', summary: 'x', description: 'd' });
    expect(args).toEqual({ project: 'SEC', summary: 'x', description: 'd', issue_type: 'Bug' });
    expect(() => checkArgs(op, { project: 'sec', summary: 'x', description: 'd' })).toThrow(/does not match/);
    expect(() => checkArgs(op, { summary: 'x' })).toThrow(/project is required/);
    expect(() => checkArgs(op, { project: 'SEC', summary: 'x', description: 'd', evil: 1 })).toThrow(/unknown parameter evil/);
    const body = fillBody(op.body, { ...args, labels: ['a', 'b'] }) as { fields: Record<string, unknown> };
    expect(body.fields.labels).toEqual(['a', 'b']);
    expect((fillBody(op.body, args) as { fields: Record<string, unknown> }).fields.labels).toBeUndefined();
    expect(fillPath('/issue/{issue}', { issue: 'SEC 1' })).toBe('/issue/SEC%201');
    expect(() => fillPath('/issue/{issue}', { issue: '../admin' })).toThrow(/without/);
    expect(extract({ issues: [{ key: 'A', fields: { summary: 's', x: 1 } }] }, '$.issues[*].{key,fields.summary}')).toEqual([{ key: 'A', 'fields.summary': 's' }]);
    expect(extract({ id: '1', key: 'K', self: 'u', other: 2 }, '$.{id,key}')).toEqual({ id: '1', key: 'K' });
  });
});

describe('Jira example pack through the pool', () => {
  it('authenticates with its script (after confirmation) and calls read and write operations', async () => {
    const dir = tmp();
    cpSync(JIRA, join(dir, 'jira-cloud'), { recursive: true });
    const p = loadPack(join(dir, 'jira-cloud'), 'jira-cloud');
    const hash = packScriptsHash(p, process.execPath);
    const executor = new Executor({ scratchDir: tmp() });
    const spec: ConnectorSpec = { id: 'con_jira', name: 'jira', protocol: 'http', pack: { dir: join(dir, 'jira-cloud'), name: 'jira-cloud', hash: p.hash, baseUrl: base, variables: {}, interpreterPath: process.execPath } };
    const deps = (confirmed: string | null) => ({
      launcher: () => { throw new Error('no stdio'); }, connectorsDir: tmp(), confirmedCommand: () => confirmed,
      secrets: () => ({ email: 'alice@example.com', api_token: 'jira-token-1' }), runScript: (s: Parameters<typeof runScript>[1]) => runScript(executor, s),
    });
    await expect(new ConnectorPool(deps(null)).test(spec)).rejects.toMatchObject({ code: 'not_confirmed' });
    const pool = new ConnectorPool(deps(hash));
    const t = await pool.test(spec);
    expect(t.tools.filter((x) => x.annotations?.readOnlyHint).map((x) => x.name)).toEqual(['search_issues', 'get_issue', 'get_transitions']);
    const found = await pool.call(spec, 'search_issues', { jql: 'project = SEC AND text ~ "order"' });
    expect(JSON.parse(found.text)).toEqual([{ key: 'SEC-1', 'fields.summary': 'Order IDOR', 'fields.status.name': 'To Do', 'fields.assignee.displayName': 'Bob', 'fields.labels': ['audit'] }]);
    expect(jira.requests.at(-1)).toMatchObject({ method: 'GET', path: '/rest/api/3/search/jql', query: { jql: 'project = SEC AND text ~ "order"', maxResults: '10', fields: 'summary,status,assignee,labels' } });
    const created = await pool.call(spec, 'create_issue', { project: 'SEC', summary: 'SQL injection in search', description: 'line 1\nline 2', labels: ['xiezhi-audit'] });
    expect(JSON.parse(created.text)).toMatchObject({ key: 'SEC-2' });
    expect(jira.requests.at(-1)!.body.fields.description.content[0].content[0].text).toBe('line 1\nline 2');
    expect((await pool.call(spec, 'get_issue', { issue: 'NOPE-1' })).isError).toBe(true);
    // A changed script invalidates the confirmation.
    writeFileSync(join(dir, 'jira-cloud', 'scripts', 'basic-auth.mjs'), 'process.stdout.write("{}")');
    const changed = loadPack(join(dir, 'jira-cloud'), 'jira-cloud');
    await expect(new ConnectorPool(deps(hash)).test({ ...spec, pack: { ...spec.pack!, hash: changed.hash } })).rejects.toMatchObject({ code: 'not_confirmed' });
    await pool.closeAll();
  });
});
