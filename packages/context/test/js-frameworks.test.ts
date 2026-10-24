// JS / TS framework coverage — hapi, Restify, Egg, Midway, Next.js (API routes, route handlers,
// Server Actions, middleware), Nuxt / Nitro server routes; the Next.js / Nuxt backend rule; framework sinks.
// Small inline sources, never executed.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { auditLanguagesOfView, Executor, SnapshotView, buildIndex, createSnapshot, loadRules } from '@xiezhi/context';

const PKG = (deps: Record<string, string>) => JSON.stringify({ name: 't', dependencies: deps });

async function viewOf(files: Record<string, string>): Promise<{ view: SnapshotView; root: string }> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1120-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return { view: new SnapshotView('repo', s.root, s.manifest), root };
}

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const { view, root } = await viewOf(files);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key)!;
const sinksOf = (idx: StructIndex, category: string) => idx.sinks.filter((s) => s.category === category);

describe('hapi', () => {
  it('route objects in server.route and in route modules; auth false, explicit and default strategies; pre handlers', async () => {
    const idx = await indexOf({
      'package.json': PKG({ '@hapi/hapi': '21', '@hapi/inert': '7' }),
      'lib/server.js': `const Hapi = require('@hapi/hapi');
const routes = require('./routes');
const init = async () => {
  const server = Hapi.server({ port: 3000 });
  server.auth.strategy('jwt', 'jwt', {});
  server.auth.default('jwt');
  server.route(routes);
  server.route({ method: 'GET', path: '/health', options: { auth: false }, handler: () => 'ok' });
  await server.start();
};
init();
`,
      'lib/routes.js': `const users = require('./users');
module.exports = [
  { method: 'GET', path: '/users/{id}', handler: users.get },
  { method: ['PUT', 'PATCH'], path: '/users/{id}', options: { auth: { strategy: 'admin' }, pre: [{ method: loadUser }], handler: users.update } },
  { method: '*', path: '/files/{p*}', handler: (request, h) => h.file(request.params.p) },
];
function loadUser(request) { return {}; }
`,
      'lib/users.js': `exports.get = async (request, h) => h.redirect(request.query.next);
exports.update = async (request, h) => ({});
`,
    });
    expect(keys(idx)).toEqual(['ANY /files/{}', 'GET /health', 'GET /users/{}', 'PATCH /users/{}', 'PUT /users/{}']);
    const health = entry(idx, 'GET /health');
    expect(health.framework).toBe('hapi');
    expect(health.middlewares).toEqual(['auth: false']);
    expect(health.authSignals).toEqual([]);
    expect(entry(idx, 'GET /users/{}').authSignals).toEqual(["server.auth.default('jwt')"]);
    expect(entry(idx, 'GET /users/{}').handler).toBe('repo:lib/users.js#lib/users.get(2)');
    const put = entry(idx, 'PUT /users/{}');
    expect(put.authSignals).toEqual(["auth: { strategy: 'admin' }"]);
    expect(put.middlewares).toContain('{ method: loadUser }');
    expect(sinksOf(idx, 'path_traversal').map((s) => s.api)).toEqual(['h.file']);
    expect(sinksOf(idx, 'open_redirect').map((s) => s.api)).toEqual(['h.redirect']);
  });

  it('a repository without hapi does not read `{ method, path, handler }` objects as routes', async () => {
    const idx = await indexOf({
      'package.json': PKG({ express: '4' }),
      'src/app.js': `const express = require('express');
const app = express();
const table = [{ method: 'GET', path: '/x', handler: () => 1 }];
module.exports = { app, table };
`,
    });
    expect(keys(idx)).toEqual([]);
  });
});

describe('Restify', () => {
  it('server routes, `del`, path objects and handler chains', async () => {
    const idx = await indexOf({
      'package.json': PKG({ restify: '11' }),
      'server.js': `const restify = require('restify');
const server = restify.createServer();
server.use(restify.plugins.bodyParser());
server.get('/pets/:id', getPet);
server.del({ path: '/pets/:id', version: '1.0.0' }, requireAuth, deletePet);
function getPet(req, res, next) { res.send({}); next(); }
function deletePet(req, res, next) { next(); }
function requireAuth(req, res, next) { next(); }
server.listen(8080);
`,
    });
    expect(keys(idx)).toEqual(['DELETE /pets/{}', 'GET /pets/{}']);
    const del = entry(idx, 'DELETE /pets/{}');
    expect(del.framework).toBe('restify');
    expect(del.handler).toBe('repo:server.js#server.deletePet(3)');
    expect(del.authSignals).toEqual(['requireAuth']);
  });
});

describe('Egg', () => {
  it('router file routes resolve to controller files; resources, namespaces, string handlers, global and route middleware', async () => {
    const idx = await indexOf({
      'package.json': PKG({ egg: '3' }),
      'config/config.default.js': `module.exports = appInfo => {
  const config = {};
  config.middleware = [ 'gzip', 'authCheck' ];
  return config;
};
`,
      'app/router.js': `module.exports = app => {
  const { router, controller, middleware } = app;
  const admin = router.namespace('/admin', middleware.adminOnly());
  router.get('/', controller.home.index);
  router.get('user', '/user/:id', controller.user.show);
  router.post('/topic/create', middleware.auth(), 'topic.create');
  router.resources('posts', '/api/posts', controller.posts);
  admin.get('/users', controller.admin.userInfo.list);
  const { userInfo } = controller.admin;
  admin.post('/users', userInfo.list);
};
`,
      'app/controller/home.js': `const { Controller } = require('egg');
class HomeController extends Controller {
  async index() { this.ctx.body = 'hi'; }
}
module.exports = HomeController;
`,
      'app/controller/user.js': `const { Controller } = require('egg');
class UserController extends Controller {
  async show() {
    const { ctx } = this;
    const res = await ctx.curl(ctx.query.url);
    ctx.unsafeRedirect(ctx.query.next);
    this.ctx.redirect('/user/' + ctx.params.id);
    this.ctx.redirect(\`https://www.example.com/search?q=\${ctx.query.q}\`);
    ctx.body = res.data;
  }
}
module.exports = UserController;
`,
      'app/controller/topic.js': `const Controller = require('egg').Controller;
class TopicController extends Controller { async create() {} }
module.exports = TopicController;
`,
      'app/controller/posts.js': `const { Controller } = require('egg');
class PostsController extends Controller {
  async index() {} async new() {} async show() {} async edit() {} async create() {} async update() {} async destroy() {}
}
module.exports = PostsController;
`,
      'app/controller/admin/user_info.js': `const { Controller } = require('egg');
class UserInfoController extends Controller { async list() {} }
module.exports = UserInfoController;
`,
    });
    expect(keys(idx)).toEqual([
      'DELETE /api/posts/{}', 'GET /', 'GET /admin/users', 'GET /api/posts', 'GET /api/posts/new', 'GET /api/posts/{}', 'GET /api/posts/{}/edit',
      'GET /user/{}', 'POST /admin/users', 'POST /api/posts', 'POST /topic/create', 'PUT /api/posts/{}',
    ]);
    expect(idx.entrypoints.every((e) => e.framework === 'egg')).toBe(true);
    expect(entry(idx, 'GET /user/{}').handler).toBe('repo:app/controller/user.js#app/controller/user.UserController.show(0)');
    expect(entry(idx, 'POST /topic/create').handler).toBe('repo:app/controller/topic.js#app/controller/topic.TopicController.create(0)');
    expect(entry(idx, 'GET /api/posts/{}/edit').handler).toBe('repo:app/controller/posts.js#app/controller/posts.PostsController.edit(0)');
    expect(entry(idx, 'GET /admin/users').handler).toBe('repo:app/controller/admin/user_info.js#app/controller/admin/user_info.UserInfoController.list(0)');
    expect(entry(idx, 'GET /').middlewares).toEqual(['config.middleware: gzip', 'config.middleware: authCheck']);
    expect(entry(idx, 'GET /').authSignals).toEqual(['config.middleware: authCheck']);
    expect(entry(idx, 'POST /topic/create').authSignals).toEqual(['config.middleware: authCheck', 'middleware.auth()']);
    expect(entry(idx, 'GET /admin/users').middlewares).toContain('middleware.adminOnly()');
    expect(entry(idx, 'POST /admin/users').handler).toBe(entry(idx, 'GET /admin/users').handler);
    expect(sinksOf(idx, 'ssrf').map((s) => s.api)).toEqual(['ctx.curl']);
    expect(sinksOf(idx, 'open_redirect').map((s) => s.api)).toEqual(['ctx.unsafeRedirect']);
  });
});

describe('Midway', () => {
  it('@Controller prefixes, @Del, decorator middleware options and guards', async () => {
    const idx = await indexOf({
      'package.json': PKG({ '@midwayjs/core': '3', '@midwayjs/koa': '3' }),
      'src/controller/user.controller.ts': `import { Controller, Get, Del, Post, Inject, UseGuard } from '@midwayjs/core';
import { AuthMiddleware } from '../middleware/auth.middleware';
import { AdminGuard } from '../guard/admin.guard';
@Controller('/api/user', { middleware: [AuthMiddleware] })
export class UserController {
  @Inject() ctx: any;
  @Get('/:id')
  async getUser() { return {}; }
  @Del('/:id', { middleware: [AuditMiddleware] })
  @UseGuard(AdminGuard)
  async remove() { return {}; }
  @Post()
  async create() { return {}; }
}
`,
    });
    expect(keys(idx)).toEqual(['DELETE /api/user/{}', 'GET /api/user/{}', 'POST /api/user']);
    const del = entry(idx, 'DELETE /api/user/{}');
    expect(del.framework).toBe('midway');
    expect(del.middlewares).toEqual(['AuthMiddleware', '@UseGuard(AdminGuard)', 'AuditMiddleware']);
    expect(del.authSignals).toEqual(['AuthMiddleware', '@UseGuard(AdminGuard)']);
    expect(del.handler).toBe('repo:src/controller/user.controller.ts#src/controller/user.controller.UserController.remove(0)');
  });
});

describe('Next.js', () => {
  const NEXT_APP = {
    'package.json': PKG({ next: '15', react: '19' }),
    'src/middleware.ts': `import { NextResponse } from 'next/server';
import { getToken } from 'next-auth/jwt';
export async function middleware(req) {
  const token = await getToken({ req });
  if (!token) return NextResponse.redirect(new URL('/login', req.url));
  return NextResponse.next();
}
export const config = { matcher: ['/api/admin/:path*', '/dashboard/:path*'] };
`,
    'src/pages/api/users/[id].ts': `import type { NextApiRequest, NextApiResponse } from 'next';
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'GET') return res.json({});
  if (req.method === 'DELETE') return res.status(204).end();
}
`,
    'src/pages/api/index.ts': `export default (req, res) => res.json({ ok: true });
`,
    'src/app/api/admin/posts/route.ts': `import { auth } from '@/auth';
export async function GET() { return Response.json([]); }
export async function POST(req: Request) {
  const session = await auth();
  return Response.json({});
}
`,
    'src/app/(marketing)/api/hooks/[...slug]/route.ts': `const handler = async (req: Request) => new Response('ok');
export { handler as GET, handler as POST };
`,
    'src/app/_lib/route.ts': `export async function GET() { return new Response('x'); }
`,
    'src/app/actions.ts': `'use server';
import { redirect } from 'next/navigation';
import { db } from '@/db';
export async function createPost(formData: FormData) {
  await db.post.create({ data: { title: formData.get('title') } });
  redirect(formData.get('next') as string);
}
export async function deletePost(id: string) {
  const user = await currentUser();
  await db.post.delete({ where: { id } });
}
`,
    'src/app/dashboard/page.tsx': `export default function Page() {
  async function rename(formData: FormData) {
    'use server';
    await save(formData);
  }
  return <form action={rename}><button /></form>;
}
`,
  };

  it('API routes, route handlers (groups, catch-all, private folders), middleware matchers, Server Actions and redirects', async () => {
    const idx = await indexOf(NEXT_APP);
    expect(keys(idx)).toEqual([
      'ANY /api', 'DELETE /api/users/{}', 'GET /api/admin/posts', 'GET /api/hooks/{}', 'GET /api/users/{}', 'POST /api/admin/posts', 'POST /api/hooks/{}',
      'rpc:next-action:src/app/actions#createPost', 'rpc:next-action:src/app/actions#deletePost', 'rpc:next-action:src/app/dashboard/page#rename',
    ]);
    const post = entry(idx, 'POST /api/admin/posts');
    expect(post.framework).toBe('nextjs');
    expect(post.authSignals).toEqual(['next middleware (auth): src/middleware.ts', 'auth call: auth()']);
    expect(entry(idx, 'GET /api/admin/posts').authSignals).toEqual(['next middleware (auth): src/middleware.ts']);
    expect(entry(idx, 'GET /api/users/{}').authSignals).toEqual([]);
    expect(entry(idx, 'GET /api/hooks/{}').handler).toBe('repo:src/app/(marketing)/api/hooks/[...slug]/route.ts#src/app/(marketing)/api/hooks/[...slug]/route.handler(1)');
    const create = entry(idx, 'rpc:next-action:src/app/actions#createPost');
    expect(create.kind).toBe('rpc');
    expect(create.protocol).toBe('next-action');
    expect(create.authSignals).toEqual([]);
    expect(entry(idx, 'rpc:next-action:src/app/actions#deletePost').authSignals).toEqual(['auth call: currentUser()']);
    expect(sinksOf(idx, 'open_redirect').map((s) => `${s.api}@${s.path}`)).toEqual(['redirect@src/app/actions.ts']);
  });

  it('a Next.js app is a backend only with server code', async () => {
    const pagesOnly = await viewOf({
      'package.json': PKG({ next: '15', react: '19' }),
      'app/page.tsx': 'export default function Page() { return <main />; }\n',
      'components/nav.tsx': 'export function Nav() { return <nav />; }\n',
    });
    expect(auditLanguagesOfView(pagesOnly.view)).toEqual([]);
    const withActions = await viewOf({
      'package.json': PKG({ next: '15', react: '19' }),
      'app/page.tsx': 'export default function Page() { return <main />; }\n',
      'lib/actions.ts': "'use server';\nexport async function save() {}\n",
    });
    expect(auditLanguagesOfView(withActions.view)).toEqual(['typescript']);
    const withApi = await viewOf({
      'package.json': PKG({ next: '15', react: '19' }),
      'app/api/ping/route.ts': "export function GET() { return new Response('pong'); }\n",
    });
    expect(auditLanguagesOfView(withApi.view)).toEqual(['typescript']);
  });
});

describe('Nuxt', () => {
  it('server/api and server/routes files, method suffixes, server middleware, inline auth and server sinks', async () => {
    const idx = await indexOf({
      'package.json': PKG({ nuxt: '3' }),
      'server/middleware/auth.ts': `export default defineEventHandler(async (event) => { await requireUserSession(event); });
`,
      'server/api/todos/index.get.ts': `export default defineEventHandler(async (event) => {
  return useDB().select().from(tables.todos);
});
`,
      'server/api/todos/[id].delete.ts': `export default eventHandler(async (event) => {
  const { user } = await requireUserSession(event);
  const { id } = getRouterParams(event);
  return {};
});
`,
      'server/routes/go.ts': `export default defineEventHandler(async (event) => {
  const q = getQuery(event);
  const data = await $fetch(q.url as string);
  return sendRedirect(event, q.to as string);
});
`,
      'pages/index.vue': '<template><div /></template>\n',
      'composables/api.ts': "export const load = (id: string) => $fetch(`/api/todos/${id}`);\n",
    });
    expect(keys(idx)).toEqual(['ANY /go', 'DELETE /api/todos/{}', 'GET /api/todos']);
    const del = entry(idx, 'DELETE /api/todos/{}');
    expect(del.framework).toBe('nuxt');
    expect(del.authSignals).toEqual(['server middleware (auth): server/middleware/auth.ts', 'auth call: requireUserSession()']);
    expect(sinksOf(idx, 'ssrf').map((s) => `${s.api}@${s.path}`)).toEqual(['$fetch@server/routes/go.ts']);
    expect(sinksOf(idx, 'open_redirect').map((s) => `${s.api}@${s.path}`)).toEqual(['sendRedirect@server/routes/go.ts']);
  });
});
