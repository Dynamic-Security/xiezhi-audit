// OpenAPI contract: every API route carries contract schemas, responses are serialized
// through them (field whitelist), and the generated document matches the committed snapshot.
// Regenerate after an intended API change: UPDATE_OPENAPI=1 pnpm vitest run apps/server/test/openapi.test.ts
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import { canonicalJson } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { Engine } from '@xiezhi/engine';
import { buildApp, ROUTE_DOCS } from '@xiezhi/server';
import { compactOpenApi, routeSchema } from '../src/spec.js';

const SNAPSHOT = resolve(__dirname, '../../../docs/api/openapi.json');
let store: Store;
let built: Awaited<ReturnType<typeof buildApp>>;

beforeAll(async () => {
  store = Store.open({ dataDir: join(mkdtempSync(join(tmpdir(), 'ca-oa-')), 'data'), role: 'test' });
  const engine = await Engine.open({ store });
  built = await buildApp({ store, engine, port: 4820, webRoot: null });
  await built.app.ready();
});
afterAll(async () => {
  await built.app.close();
  store.close();
});

describe('openapi', () => {
  it('every /api route is documented and every documented route exists', () => {
    const api = built.routes.filter((r) => r.split(' ')[1]!.startsWith('/api/'));
    const undocumented = api.filter((r) => !ROUTE_DOCS[r]);
    expect(undocumented).toEqual([]);
    const missing = Object.keys(ROUTE_DOCS).filter((k) => !api.includes(k));
    expect(missing).toEqual([]);
  });

  it('matches the committed snapshot', () => {
    const doc = compactOpenApi(built.app.swagger() as unknown as Record<string, unknown>) as { openapi: string; paths: Record<string, Record<string, unknown>>; components: { schemas: Record<string, unknown> } };
    expect(doc.openapi).toBe('3.1.0');
    expect(Object.keys(doc.components.schemas)).toContain('AuditDetailDto');
    expect(JSON.stringify(doc.paths)).toContain('#/components/schemas/VulnDetailDto');
    expect(Object.keys(doc.paths).length).toBeGreaterThan(50);
    const refs = [...JSON.stringify(doc).matchAll(/"\$ref":"#\/components\/schemas\/(\w+)"/g)].map((m) => m[1]!);
    expect(refs.length).toBeGreaterThan(100);
    for (const r of new Set(refs)) expect(doc.components.schemas[r], r).toBeTruthy();
    const text = JSON.stringify(JSON.parse(canonicalJson(doc)), null, 2) + '\n';
    if (process.env.UPDATE_OPENAPI === '1' || !existsSync(SNAPSHOT)) writeFileSync(SNAPSHOT, text);
    expect(text).toBe(readFileSync(SNAPSHOT, 'utf8'));
  });

  it('is served at /api/v1/openapi.json (authenticated) and contains no static-file routes', async () => {
    const token = built.ctx.auth.cliToken;
    const r = await built.app.inject({ method: 'GET', url: '/api/v1/openapi.json', headers: { host: '127.0.0.1:4820', authorization: `Bearer ${token}` } });
    expect(r.statusCode).toBe(200);
    const doc = r.json() as { paths: Record<string, unknown> };
    expect(Object.keys(doc.paths).every((p) => p.startsWith('/api/'))).toBe(true);
    const anon = await built.app.inject({ method: 'GET', url: '/api/v1/openapi.json', headers: { host: '127.0.0.1:4820' } });
    expect(anon.statusCode).toBe(401);
  });

  it('response schemas act as a field whitelist (strip at object level, fail closed inside nullable unions)', async () => {
    const f = Fastify();
    f.get('/top', { schema: routeSchema(ROUTE_DOCS['GET /api/v1/health']!) }, async () => ({
      status: 'ok', version: '1', dataDirWritable: true, lockHolder: null, piVersion: 'x', apiKey: 'sk-leak-top',
    }));
    f.get('/nested', { schema: routeSchema(ROUTE_DOCS['GET /api/v1/health']!) }, async () => ({
      status: 'ok', version: '1', dataDirWritable: true, lockHolder: { pid: 1, role: 'serve', token: 'sk-leak-nested' }, piVersion: 'x',
    }));
    const top = await f.inject({ method: 'GET', url: '/top' });
    expect(top.statusCode).toBe(200);
    expect(top.body).not.toContain('leak');
    expect(JSON.parse(top.body)).toEqual({ status: 'ok', version: '1', dataDirWritable: true, lockHolder: null, piVersion: 'x' });
    const nested = await f.inject({ method: 'GET', url: '/nested' });
    expect(nested.statusCode).toBe(500);
    expect(nested.body).not.toContain('leak');
    await f.close();
  });

  it('request bodies are validated without coercion or silent stripping', async () => {
    const token = built.ctx.auth.cliToken;
    const h = { host: '127.0.0.1:4820', authorization: `Bearer ${token}`, 'content-type': 'application/json' };
    const extra = await built.app.inject({ method: 'POST', url: '/api/v1/projects', headers: h, payload: { name: 'a', admin: true } });
    expect(extra.statusCode).toBe(400);
    expect(extra.json().error.code).toBe('COMMON_VALIDATION');
    const typed = await built.app.inject({ method: 'POST', url: '/api/v1/projects', headers: h, payload: { name: 123 } });
    expect(typed.statusCode).toBe(400);
    // Schema errors say which field is wrong (paths and rules only, no values).
    const missing = await built.app.inject({ method: 'POST', url: '/api/v1/connectors', headers: h, payload: { name: 'x', protocol: 'mcp_stdio', purpose: 'context', config: { command: { path: '/bin/x', args: [] } } } });
    expect(missing.statusCode).toBe(400);
    expect(missing.json().error.hint).toMatch(/env/);
    const ok = await built.app.inject({ method: 'POST', url: '/api/v1/projects', headers: h, payload: { name: 'ok-project' } });
    expect(ok.statusCode).toBe(201);
  });

  it('query parameters are documented and validated (repeatable, closed sets, no undeclared keys)', async () => {
    const doc = compactOpenApi(built.app.swagger() as unknown as Record<string, unknown>) as { paths: Record<string, Record<string, { parameters?: { in: string; name: string; required: boolean }[] }>> };
    const q = (path: string, method = 'get') => (doc.paths[path]![method]!.parameters ?? []).filter((p) => p.in === 'query').map((p) => p.name).sort();
    expect(q('/api/v1/audits')).toEqual(['cursor', 'limit', 'projectId', 'scene', 'status']);
    expect(q('/api/v1/audits/{aid}/trajectory')).toEqual(['after', 'all', 'limit', 'q', 'step', 'type']);
    expect(q('/api/v1/projects/{pid}/vulnerabilities')).toEqual(['category', 'confirmation', 'cursor', 'handling', 'lifecycle', 'limit', 'q', 'repo', 'severity', 'sort', 'source']);
    expect(doc.paths['/api/v1/projects/{pid}']!.delete!.parameters!.find((p) => p.name === 'confirmName')!.required).toBe(true);

    const h = { host: '127.0.0.1:4820', authorization: `Bearer ${built.ctx.auth.cliToken}` };
    const get = (url: string) => built.app.inject({ method: 'GET', url, headers: h });
    expect((await get('/api/v1/audits?status=running&status=completed&limit=5')).statusCode).toBe(200);
    for (const bad of ['/api/v1/audits?status=bogus', '/api/v1/audits?limit=abc', '/api/v1/audits?unknown=1', '/api/v1/audits?scene=x']) {
      const r = await get(bad);
      expect(r.statusCode, bad).toBe(400);
      expect(r.json().error.code, bad).toBe('COMMON_VALIDATION');
    }
    const p = (await built.app.inject({ method: 'POST', url: '/api/v1/projects', headers: { ...h, 'content-type': 'application/json' }, payload: { name: 'q-project' } })).json() as { id: string };
    expect((await get(`/api/v1/projects/${p.id}/vulnerabilities?severity=high&severity=critical&sort=-severity,displayNo`)).statusCode).toBe(200);
    expect((await get(`/api/v1/projects/${p.id}/vulnerabilities?sort=title`)).statusCode).toBe(400);
    expect((await built.app.inject({ method: 'DELETE', url: `/api/v1/projects/${p.id}`, headers: h })).statusCode).toBe(400);
  });
});
