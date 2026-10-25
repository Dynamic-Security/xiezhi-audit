// JavaScript / TypeScript server-side index: Express / Koa / Fastify / NestJS entries, sinks with taint hints,
// auth signals, call edges and imports, on small inline sources (never executed).
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { Executor, SnapshotView, buildIndex, createSnapshot, loadRules } from '@xiezhi/context';

const PKG = (deps: Record<string, string>) => JSON.stringify({ name: 't', dependencies: deps });

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m11js-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const v = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(v, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key)!;
const sinksOf = (idx: StructIndex, category: string) => idx.sinks.filter((s) => s.category === category);

describe('Express', () => {
  it('routes with router prefixes mounted in the same file, route chains and middleware chains', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4' }),
      'src/app.js': `const express = require('express');
const passport = require('passport');
const app = express();
const api = express.Router();
app.use(express.json());
app.use('/api', passport.authenticate('jwt', { session: false }), api);
api.get('/users/:id', requireRole('admin'), getUser);
api.route('/items').get(listItems).post(createItem);
app.get('/health', (req, res) => res.send('ok'));
function getUser(req, res) { res.json({}); }
function listItems(req, res) {}
function createItem(req, res) {}
function requireRole(r) { return (req, res, next) => next(); }
const cache = new Map();
cache.get('/users/:id', getUser);
module.exports = app;
`,
    });
    expect(keys(idx)).toEqual(['GET /api/items', 'GET /api/users/{}', 'GET /health', 'POST /api/items']);
    const u = entry(idx, 'GET /api/users/{}');
    expect(u.framework).toBe('express');
    expect(u.handler).toBe('repo:src/app.js#src/app.getUser(2)');
    expect(u.middlewares).toEqual(['express.json()', "passport.authenticate('jwt', { session: false })", "requireRole('admin')"]);
    expect(u.authSignals).toEqual(u.middlewares.slice(1));
    // inline handlers get a synthetic symbol
    expect(entry(idx, 'GET /health').handler).toMatch(/#src\/app\.<anonymous GET \/health>\(2\)$/);
    expect(idx.symbols.some((s) => s.name === '<anonymous GET /health>')).toBe(true);
  });

  it('routers mounted from another file get the mount prefix and the mounting middlewares; handlers resolve across files', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4' }),
      'src/server.ts': `import express from 'express';
import ticketRoutes from './routes/tickets';
import { requireAuth } from './middleware/auth';
const app = express();
app.use(requireAuth);
app.use('/api/v1/tickets', ticketRoutes);
export default app;
`,
      'src/routes/tickets.ts': `import { Router } from 'express';
import * as ctrl from '../controllers/ticket.controller';
const router = Router();
router.get('/:id', ctrl.getTicket);
router.post('/', ctrl.createTicket);
export default router;
`,
      'src/controllers/ticket.controller.ts': `import { Request, Response } from 'express';
export async function getTicket(req: Request, res: Response) { res.json(await load(req.params.id)); }
export const createTicket = async (req: Request, res: Response) => { res.status(201).end(); };
function load(id: string) { return { id }; }
`,
      'src/middleware/auth.ts': `export function requireAuth(req: any, res: any, next: any) { next(); }
`,
    });
    expect(keys(idx)).toEqual(['GET /api/v1/tickets/{}', 'POST /api/v1/tickets']);
    const g = entry(idx, 'GET /api/v1/tickets/{}');
    expect(g.handler).toBe('repo:src/controllers/ticket.controller.ts#src/controllers/ticket.controller.getTicket(2)');
    expect(g.middlewares).toEqual(['requireAuth']);
    expect(g.authSignals).toEqual(['requireAuth']);
    expect(entry(idx, 'POST /api/v1/tickets').handler).toBe('repo:src/controllers/ticket.controller.ts#src/controllers/ticket.controller.createTicket(2)');
    // same-module bare call → resolved
    const edge = idx.callEdges.find((e) => e.calleeText === 'load');
    expect(edge).toMatchObject({ from: g.handler, to: 'repo:src/controllers/ticket.controller.ts#src/controllers/ticket.controller.load(1)', confidence: 'resolved' });
  });

  it('controller instances from another module resolve to that class even when method names collide; awaited generic calls are sinks', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4', axios: '1' }),
      'src/routes.ts': `import { Router } from 'express';
import { OrderController } from './order.controller';
const orders = new OrderController();
const router = Router();
router.post('/orders', wrap(orders.create.bind(orders)));
export default router;
`,
      'src/order.controller.ts': `import axios from 'axios';
export class OrderController {
  async create(req: any, res: any) { const r = await axios.get<string>(req.body.callback); res.json(r.data); }
}
`,
      'src/order.repository.ts': `export class OrderRepository { async create(row: any, tx: any) { return row; } }
`,
    });
    expect(entry(idx, 'POST /orders').handler).toBe('repo:src/order.controller.ts#src/order.controller.OrderController.create(2)');
    expect(sinksOf(idx, 'ssrf').map((s) => s.symbolId)).toEqual(['repo:src/order.controller.ts#src/order.controller.OrderController.create(2)']);
  });

  it('non-route calls with verb names are not entries', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4', axios: '1' }),
      'src/client.js': `const axios = require('axios');
const express = require('express');
async function sync(cache, map, req, res) {
  await axios.get('/api/users', { params: { a: 1 } });
  cache.get('key');
  map.delete('/x', 1);
  res.get('Content-Type');
  req.get('host');
}
module.exports = { sync };
`,
    });
    expect(idx.entrypoints).toEqual([]);
  });
});

describe('Koa and Fastify', () => {
  it('koa-router prefix / use, fastify shorthand + route() + register prefix + hooks', async () => {
    const idx = await indexOf({
      'package.json': PKG({ koa: '2', '@koa/router': '12', fastify: '4' }),
      'src/koa.js': `const Koa = require('koa');
const Router = require('@koa/router');
const app = new Koa();
const router = new Router({ prefix: '/api' });
router.use(jwt({ secret: 's' }));
router.get('/orders/:id', async (ctx) => { ctx.body = {}; });
router.del('user-del', '/users/:id', removeUser);
app.use(router.routes());
async function removeUser(ctx) {}
`,
      'src/fast.ts': `import Fastify from 'fastify';
const app = Fastify();
async function userRoutes(fastify: any) {
  fastify.addHook('onRequest', fastify.authenticate);
  fastify.get('/users/:id', { preHandler: [checkOwner] }, getUser);
  fastify.route({ method: ['PUT', 'PATCH'], url: '/users/:id', handler: updateUser });
}
app.register(userRoutes, { prefix: '/v2' });
app.post('/login', async (req: any, reply: any) => reply.send({}));
async function getUser(req: any, reply: any) {}
async function updateUser(req: any, reply: any) {}
function checkOwner(req: any, reply: any, done: any) { done(); }
`,
    });
    expect(keys(idx)).toEqual(['DELETE /api/users/{}', 'GET /api/orders/{}', 'GET /v2/users/{}', 'PATCH /v2/users/{}', 'POST /login', 'PUT /v2/users/{}']);
    expect(entry(idx, 'GET /api/orders/{}').framework).toBe('koa');
    expect(entry(idx, 'GET /api/orders/{}').authSignals).toEqual(["jwt({ secret: 's' })"]);
    expect(entry(idx, 'DELETE /api/users/{}').handler).toBe('repo:src/koa.js#src/koa.removeUser(1)');
    const fu = entry(idx, 'GET /v2/users/{}');
    expect(fu.framework).toBe('fastify');
    expect(fu.middlewares).toEqual(['fastify.authenticate', 'checkOwner']);
    expect(fu.authSignals).toEqual(['fastify.authenticate']);
    expect(entry(idx, 'PUT /v2/users/{}').handler).toBe('repo:src/fast.ts#src/fast.updateUser(2)');
  });
});

describe('NestJS', () => {
  it('controllers, method decorators, guards on class / method, typed constructor injection → resolved edges', async () => {
    const idx = await indexOf({
      'package.json': PKG({ '@nestjs/core': '10', '@nestjs/common': '10' }),
      'src/tickets/tickets.controller.ts': `import { Controller, Get, Post, Param, Body, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { TicketsService } from './tickets.service';
import { Roles } from '../auth/roles.decorator';

@Controller('tickets')
@UseGuards(AuthGuard('jwt'))
export class TicketsController {
  constructor(private readonly tickets: TicketsService) {}

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.tickets.findOne(id);
  }

  @Post()
  @Roles('admin')
  create(@Body() dto: any) {
    return this.tickets.create(dto);
  }

  helper() { return 1; }
}
`,
      'src/tickets/tickets.service.ts': `import { Injectable } from '@nestjs/common';
@Injectable()
export class TicketsService {
  findOne(id: string) { return this.load(id); }
  create(dto: any) { return dto; }
  private load(id: string) { return { id }; }
}
`,
      'src/main.ts': `import { NestFactory } from '@nestjs/core';
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalGuards(new JwtAuthGuard());
  await app.listen(3000);
}
bootstrap();
`,
    });
    expect(keys(idx)).toEqual(['GET /tickets/{}', 'POST /tickets']);
    const g = entry(idx, 'GET /tickets/{}');
    expect(g.framework).toBe('nestjs');
    expect(g.handler).toBe('repo:src/tickets/tickets.controller.ts#src/tickets/tickets.controller.TicketsController.findOne(1)');
    expect(g.authSignals).toEqual(["@UseGuards(AuthGuard('jwt'))"]);
    expect(entry(idx, 'POST /tickets').authSignals).toEqual(["@UseGuards(AuthGuard('jwt'))", "@Roles('admin')"]);
    const kinds = idx.authSignals.map((s) => `${s.kind}:${s.detail}`);
    expect(kinds).toEqual(expect.arrayContaining(["annotation:@UseGuards(AuthGuard('jwt'))", "annotation:@Roles('admin')", 'security_config:app.useGlobalGuards(new JwtAuthGuard())']));
    // typed receiver (constructor parameter property) → resolved; this-call → resolved
    expect(idx.callEdges.find((e) => e.from === g.handler && e.calleeText === 'this.tickets.findOne')).toMatchObject({
      to: 'repo:src/tickets/tickets.service.ts#src/tickets/tickets.service.TicketsService.findOne(1)', confidence: 'resolved',
    });
    expect(idx.callEdges.find((e) => e.calleeText === 'this.load')).toMatchObject({ to: 'repo:src/tickets/tickets.service.ts#src/tickets/tickets.service.TicketsService.load(1)', confidence: 'resolved' });
    const cls = idx.symbols.find((s) => s.name === 'TicketsController')!;
    expect(cls.kind).toBe('class');
    expect(idx.symbols.find((s) => s.name === 'helper')?.kind).toBe('method');
  });
});

describe('sinks', () => {
  it('SQL: template literals and concatenation are string_concat, literals constant, tagged templates ignored', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4', pg: '8', '@prisma/client': '5' }),
      'src/repo.ts': `import { Pool } from 'pg';
const pool = new Pool();
export async function byStatus(status: string) {
  return pool.query(\`SELECT * FROM tickets WHERE status = '\${status}'\`);
}
export async function byOwner(owner: string) {
  const sql = 'SELECT * FROM tickets WHERE owner = ' + owner;
  return pool.query(sql);
}
export async function byId(id: string) {
  return pool.query('SELECT * FROM tickets WHERE id = $1', [id]);
}
export async function viaPrisma(prisma: any, name: string) {
  await prisma.$queryRaw\`SELECT * FROM t WHERE name = \${name}\`;
  return prisma.$queryRawUnsafe('SELECT * FROM t WHERE name = ' + name);
}
`,
    });
    const s = sinksOf(idx, 'sqli').map((x) => `${x.range.startLine}:${x.taintHint ?? '-'}`);
    expect(s).toEqual(['11:constant', '15:string_concat', '4:string_concat', '8:string_concat']);
    expect(sinksOf(idx, 'sqli')[0]!.symbolId).toBe('repo:src/repo.ts#src/repo.byId(1)');
  });

  it('cmdi / code injection / ssrf / path traversal / redirect / deserialization / xxe / nosqli', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4', axios: '1', 'node-serialize': '0.0.4', libxmljs: '1', mongoose: '7' }),
      'src/misc.js': `const { exec, execFile } = require('child_process');
const cp = require('node:child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const serialize = require('node-serialize');
const libxml = require('libxmljs');
const vm = require('vm');
function run(req, res) {
  exec('convert ' + req.query.file);
  execFile('convert', ['-resize', '10x10', 'a.png']);
  cp.spawn(req.body.cmd, { shell: true });
  eval(req.body.expr);
  setTimeout('tick()', 10);
  setTimeout(() => {}, 10);
  vm.runInNewContext(req.body.code);
  axios.get(req.query.url);
  axios.get('https://example.com/status');
  fetch(\`http://\${req.query.host}/x\`);
  fs.readFile(path.join('/data', req.params.name), () => {});
  res.sendFile(req.query.p);
  res.redirect(req.query.next);
  res.redirect('/login');
  serialize.unserialize(req.cookies.profile);
  libxml.parseXml(req.body, { noent: true });
  libxml.parseXml(req.body);
  User.find({ $where: 'this.name == "' + req.query.n + '"' });
  User.find(req.body);
  res.send('<h1>' + req.query.q + '</h1>');
}
module.exports = { run };
`,
    });
    const cats = idx.sinks.map((s) => `${s.range.startLine}:${s.category}:${s.taintHint ?? '-'}`).sort((a, b) => parseInt(a) - parseInt(b));
    expect(cats).toEqual([
      '10:cmdi:string_concat', '11:cmdi:constant', '12:cmdi:-', '13:code_injection:-', '14:code_injection:constant', '16:code_injection:-',
      '17:ssrf:-', '19:ssrf:string_concat', '20:path_traversal:string_concat', '21:path_traversal:-', '22:open_redirect:-',
      '24:deserialization:-', '25:xxe:-', '27:nosqli:string_concat', '28:nosqli:-', '29:xss:string_concat',
    ]);
    expect(idx.sinks.every((s) => s.symbolId === 'repo:src/misc.js#src/misc.run(2)')).toBe(true);
  });

  it('business-sensitive sinks: by-id lookups and state writes', async () => {
    const idx = await indexOf({
      'package.json': PKG({ '@nestjs/core': '10', typeorm: '0.3' }),
      'src/orders.service.ts': `export class OrdersService {
  constructor(private readonly repo: any, private readonly prisma: any) {}
  async get(id: string) { return this.repo.findOne({ where: { id } }); }
  async list(user: string) { return this.repo.findOne({ where: { user } }); }
  async pay(orderId: number) {
    const o = await this.prisma.order.findUnique({ where: { id: orderId } });
    o.status = 'PAID';
    await this.repo.save(o);
    await this.repo.update(orderId, { amount: 0 });
    await this.repo.update(orderId, { note: 'x' });
  }
}
`,
    });
    expect(sinksOf(idx, 'authz_object').map((s) => s.range.startLine)).toEqual([3, 6]);
    expect(sinksOf(idx, 'business_logic').map((s) => s.range.startLine).sort()).toEqual([8, 9]);
  });

  it('JS and TS/TSX grammars compile every rule (no rule_error gaps)', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4' }),
      'a.js': 'const x = 1;\n', 'b.ts': 'export const y: number = 1;\n', 'c.tsx': 'export const C = () => <div/>;\n', 'd.mjs': 'export default 1;\n',
    });
    expect(idx.gaps.filter((g) => g.reason === 'rule_error')).toEqual([]);
  });
});

describe('calls and imports', () => {
  it('CommonJS / ES imports resolve to module functions; packages are external; class instances resolve by type', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4', lodash: '4' }),
      'lib/util/index.js': `exports.slug = function (s) { return s; };
module.exports.trim = (s) => s;
`,
      'lib/svc.js': `const util = require('./util');
const { trim } = require('./util');
const _ = require('lodash');
const Repo = require('./repo');
class Svc {
  constructor() { this.repo = new Repo(); }
  run(x) { util.slug(x); trim(x); _.merge({}, x); this.repo.load(x); return helper(x); }
}
function helper(x) { return x; }
module.exports = Svc;
`,
      'lib/repo.js': `class Repo { load(id) { return id; } }
module.exports = Repo;
`,
    });
    const from = 'repo:lib/svc.js#lib/svc.Svc.run(1)';
    const out = idx.callEdges.filter((e) => e.from === from).map((e) => `${e.calleeText}→${e.to}:${e.confidence}`).sort();
    expect(out).toEqual([
      'helper→repo:lib/svc.js#lib/svc.helper(1):resolved',
      'this.repo.load→repo:lib/repo.js#lib/repo.Repo.load(1):resolved',
      'trim→repo:lib/util/index.js#lib/util.trim(1):resolved',
      'util.slug→repo:lib/util/index.js#lib/util.slug(1):resolved',
    ]);
  });
});

describe('handler factories (juice-shop style)', () => {
  it('a handler written as a factory call resolves to the factory, through wrappers', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4' }),
      'routes/search.ts': `export function searchProducts () {
  return (req: any, res: any) => { res.json([]) }
}
`,
      'routes/address.ts': `module.exports.delAddressById = function delAddressById () {
  return async (req: any, res: any) => { res.json({}) }
}
`,
      'server.ts': `import express from 'express'
import { searchProducts } from './routes/search'
import * as address from './routes/address'
const app = express()
const utils = { asyncHandler: (f: any) => f }
app.get('/rest/products/search', utils.asyncHandler(searchProducts()))
app.delete('/api/Addresss/:id', address.delAddressById())
`,
    });
    expect(idx.entrypoints.find((e) => e.entryKey.endsWith('GET /rest/products/search'))!.handler).toMatch(/searchProducts\(0\)$/);
    const del = idx.entrypoints.find((e) => e.entryKey.endsWith('DELETE /api/Addresss/{}'))!;
    expect(del.handler).not.toContain('<unresolved');
  });
});
