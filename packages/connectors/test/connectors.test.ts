// connector core: outbound address checks, MCP over streamable HTTP and stdio (through
// the executor), secrets at the edge, command confirmation, tools cache, circuit breaker.
import { createServer, type Server } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Executor, spawnService } from '@xiezhi/context';
import {
  ConnectorPool, OutboundError, classifyAddress, commandHash, outbound, resolveChecked, secretRefs, TOOL_DESCRIPTION_MAX, type ConnectorSpec,
} from '@xiezhi/connectors';
// @ts-expect-error plain ESM fixture without types
import { handle } from './fake-mcp.mjs';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-conn-'));
const FAKE = resolve(__dirname, 'fake-mcp.mjs');

let http: Server;
let base: string;
const seen: { session?: string; version?: string }[] = [];
beforeAll(async () => {
  http = createServer((req, res) => {
    if (req.url === '/redirect') { res.writeHead(302, { location: 'http://169.254.169.254/' }); res.end(); return; }
    if (req.method === 'DELETE') { res.writeHead(200); res.end(); return; }
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const msg = JSON.parse(body);
      seen.push({ session: req.headers['mcp-session-id'] as string | undefined, version: req.headers['mcp-protocol-version'] as string | undefined });
      const r = handle(msg, { API_TOKEN: req.headers.authorization });
      if (!r) { res.writeHead(202); res.end(); return; }
      if (r === 'never') return;
      if (msg.method === 'tools/call') {
        // Streamable HTTP may answer with an event stream.
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.end(`event: message\ndata: ${JSON.stringify(r)}\n\n`);
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json', ...(msg.method === 'initialize' ? { 'mcp-session-id': 'sess-1' } : {}) });
      res.end(JSON.stringify(r));
    });
  });
  await new Promise<void>((ok) => http.listen(0, '127.0.0.1', () => ok()));
  base = `http://127.0.0.1:${(http.address() as { port: number }).port}`;
});
afterAll(() => new Promise<void>((ok) => http.close(() => ok())));

describe('outbound address control', () => {
  it('classifies addresses including IPv4-mapped IPv6', () => {
    expect(['8.8.8.8', '127.0.0.1', '10.1.2.3', '172.20.0.1', '192.168.1.1', '100.64.0.1', '169.254.169.254', '0.0.0.0', '224.0.0.1', '::1', 'fe80::1', 'fd00::1', '::ffff:169.254.169.254', '2001:db8::1'].map(classifyAddress))
      .toEqual(['public', 'loopback', 'private', 'private', 'private', 'private', 'link_local', 'unspecified', 'multicast', 'loopback', 'link_local', 'private', 'link_local', 'public']);
  });

  it('allows loopback / private only for the configured host and never link-local', async () => {
    await expect(resolveChecked('127.0.0.1', { configuredHosts: [] })).rejects.toThrow(/loopback/);
    await expect(resolveChecked('127.0.0.1', { configuredHosts: ['127.0.0.1'] })).resolves.toMatchObject({ address: '127.0.0.1', internal: true });
    await expect(resolveChecked('169.254.169.254', { configuredHosts: ['169.254.169.254'] })).rejects.toThrow(/link-local/);
    await expect(resolveChecked('::ffff:127.0.0.1', { configuredHosts: [] })).rejects.toThrow(/loopback/);
  });

  it('refuses http to public hosts, userinfo, and redirects', async () => {
    await expect(outbound({ url: 'http://93.184.216.34/', method: 'GET', policy: { configuredHosts: [] } })).rejects.toThrow(/only allowed for hosts on a private network/);
    await expect(outbound({ url: 'https://user:pw@127.0.0.1/', method: 'GET', policy: { configuredHosts: ['127.0.0.1'] } })).rejects.toThrow(/credentials in URLs/);
    const err = await outbound({ url: `${base}/redirect`, method: 'GET', policy: { configuredHosts: ['127.0.0.1'] } }).catch((e) => e);
    expect(err).toBeInstanceOf(OutboundError);
    expect((err as OutboundError).code).toBe('redirect');
  });
});

describe('MCP connectors', () => {
  const deps = (confirmed: string | null, secrets: Record<string, string> = {}) => ({
    launcher: (spec: Parameters<typeof spawnService>[1]) => spawnService(new Executor({ scratchDir: tmp() }), spec),
    connectorsDir: tmp(), secrets: () => secrets, confirmedCommand: () => confirmed,
  });

  it('talks streamable HTTP: session id, negotiated version, paginated tools, SSE results, secrets in headers', async () => {
    const spec: ConnectorSpec = { id: 'con_http', name: 'tickets', protocol: 'mcp_http', url: `${base}/mcp`, headers: { authorization: 'Bearer ${secret:token}' } };
    expect(secretRefs(spec)).toEqual(['token']);
    const pool = new ConnectorPool(deps(null, { token: 'tk-123' }));
    const t = await pool.test(spec);
    expect(t.server).toMatchObject({ serverName: 'fake-mcp', protocolVersion: '2025-06-18', hasTools: true });
    expect(t.tools.map((x) => x.name)).toEqual(['search', 'create_issue', 'fail', 'slow', 'env', 'get_ticket']);
    expect(t.tools[0]!.description!.length).toBe(TOOL_DESCRIPTION_MAX);
    const r = await pool.call(spec, 'search', { q: 'SHOP-1' });
    expect(r).toEqual({ text: 'results for SHOP-1\n[image omitted]', isError: false, structured: null });
    expect((await pool.call(spec, 'env', {})).text).toContain('Bearer tk-123');
    expect(seen.at(-1)).toEqual({ session: 'sess-1', version: '2025-06-18' });
    expect(await pool.call(spec, 'fail', {})).toMatchObject({ isError: true, text: 'backend down' });
    await pool.closeAll();
  });

  it('runs stdio servers only with a confirmed command, a minimal environment and a private cwd', async () => {
    process.env.SHOULD_NOT_LEAK = 'leaked';
    const spec: ConnectorSpec = { id: 'con_stdio', name: 'local', protocol: 'mcp_stdio', command: { path: process.execPath, args: [FAKE, '--stdio'], env: { API_TOKEN: '${secret:api}' } } };
    await expect(new ConnectorPool(deps(null)).test(spec)).rejects.toMatchObject({ code: 'not_confirmed' });
    await expect(new ConnectorPool(deps('0'.repeat(64))).test(spec)).rejects.toMatchObject({ code: 'not_confirmed' });
    const d = deps(commandHash(spec.command!), { api: 'sec-456' });
    const pool = new ConnectorPool(d);
    const t = await pool.test(spec);
    expect(t.tools).toHaveLength(6);
    const env = JSON.parse((await pool.call(spec, 'env', {})).text) as { token: string; home: string; inherited: string | null; cwd: string };
    expect(env.token).toBe('sec-456');
    expect(env.inherited).toBeNull();
    expect(env.cwd.endsWith('con_stdio')).toBe(true);
    expect(env.home).not.toBe(process.env.HOME);
    // Changing the command line invalidates the confirmation.
    await expect(pool.test({ ...spec, command: { ...spec.command!, args: [FAKE, '--stdio', '--extra'] } })).rejects.toMatchObject({ code: 'not_confirmed' });
    await pool.closeAll();
    delete process.env.SHOULD_NOT_LEAK;
  });

  it('opens the circuit after 3 failures and probes once after the cooldown', async () => {
    let now = 1_000_000;
    const spec: ConnectorSpec = { id: 'con_slow', name: 'slow', protocol: 'mcp_http', url: `${base}/mcp`, timeouts: { callMs: 300 } };
    const pool = new ConnectorPool({ ...deps(null), now: () => now });
    for (let i = 0; i < 3; i++) await expect(pool.call(spec, 'slow', {})).rejects.toMatchObject({ code: 'timeout' });
    expect(pool.breaker('con_slow')).toMatchObject({ state: 'open', failures: 3 });
    await expect(pool.call(spec, 'search', { q: 'x' })).rejects.toMatchObject({ code: 'unavailable' });
    now += 61_000;
    expect((await pool.call(spec, 'search', { q: 'x' })).text).toContain('results for x');
    expect(pool.breaker('con_slow')).toMatchObject({ state: 'closed', failures: 0 });
    await pool.closeAll();
  });
});
