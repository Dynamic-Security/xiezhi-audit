// HTTP service: 127.0.0.1 only, Host/Origin/CSRF/bearer checks, unified error
// mapping, JSON logs without secrets, the React app as static files with SPA fallback.
import { appendFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import fastifySwagger from '@fastify/swagger';
import { AppError, newId, redactDeep, resourcePath } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import type { Engine } from '@xiezhi/engine';
import { SERVER_VERSION, type AppContext } from './context.js';
import { ROUTE_DOCS, compactOpenApi, routeSchema } from './spec.js';
import { ErrorRing, toApiError } from './errors.js';
import { Scheduler } from './scheduler.js';
import { AuthState, SECURITY_HEADERS, isApiPath, isNonCanonicalTarget, parseCookies, safeEqual, sessionCookieName } from './security.js';
import { Uploads } from './uploads.js';
import { registerCoreRoutes } from './routes/core.js';
import { registerKnowledgeRoutes, startKnowledgeWatch } from './routes/knowledge.js';
import { registerPromptRoutes } from './routes/prompts.js';
import { registerFactRoutes } from './routes/facts.js';
import { registerEgressRoutes } from './routes/egress.js';
import { registerRuleRoutes } from './routes/rules.js';
import { registerVerificationRoutes } from './routes/verification.js';
import { registerFixRoutes } from './routes/fixes.js';
import { registerConnectorRoutes } from './routes/connectors.js';
import { registerArchitectureRoutes } from './routes/architecture.js';
import { registerPackRoutes } from './routes/packs.js';
import { registerConversationRoutes } from './routes/conversations.js';
import { registerPushRoutes } from './routes/pushes.js';
import { registerProjectRoutes } from './routes/projects.js';
import { registerAuditRoutes } from './routes/audits.js';
import { registerVulnRoutes } from './routes/vulns.js';
import { registerHypothesisRoutes } from './routes/hypotheses.js';
import { registerDomainPlanRoutes } from './routes/domain-plan.js';
import { registerThreatModelRoutes } from './routes/threat-models.js';
import { registerEventRoutes } from './routes/events.js';
import { registerHuntRoutes } from './routes/hunts.js';


/** Write endpoints that can change a vulnerability or the conversation cards about it. */
const VULN_WRITES = /^\/api\/v1\/(vulnerabilities(\/|$)|cards\/[^/]+\/(apply|dismiss)$|verification-cases\/[^/]+\/result$)/;
export interface BuildOptions {
  store: Store;
  engine: Engine;
  port: number;
  /** Directory with the built web app (index.html). Omit to serve the API only. */
  webRoot?: string | null;
  heartbeatMs?: number;
  /** Watch the knowledge directories (default true); tests that do not need it turn it off. */
  watchKnowledge?: boolean;
}

const PUBLIC_API = new Set(['GET /api/v1/health', 'POST /api/session/bootstrap', 'GET /api/session']);
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function defaultWebRoot(): string | null {
  // `web/` of an installed package; `apps/web/dist` of a source checkout.
  for (const c of [resourcePath('web'), resourcePath('apps', 'web', 'dist')]) if (existsSync(join(c, 'index.html'))) return c;
  return null;
}

type AuthedRequest = FastifyRequest & { session?: { id: string; csrf: string }; bearer?: boolean };

/**
 * API requests are decided by the matched route pattern, never the raw URL: the router percent-decodes
 * the path, so `/%61pi/v1/projects` runs the /api/v1/projects handler. A request that matched no route
 * is an API request when its path decodes to /api.
 */
function isApiRequest(req: FastifyRequest): boolean {
  const pattern = req.routeOptions.url;
  return pattern === undefined ? isApiPath(rawPath(req)) : pattern.startsWith('/api/');
}

function rawPath(req: FastifyRequest): string {
  return req.url.split('?')[0]!;
}

export async function buildApp(opts: BuildOptions): Promise<{ app: FastifyInstance; ctx: AppContext; routes: string[] }> {
  const { store, engine } = opts;
  const logFile = join(store.paths.logs, 'server.log');
  const log: AppContext['log'] = (level, msg, extra) => {
    const levels = ['debug', 'info', 'warn', 'error'];
    if (levels.indexOf(level) < levels.indexOf(store.config.log.level)) return;
    const line = JSON.stringify(redactDeep({ ts: new Date().toISOString(), level, component: 'server', msg, ...extra }, store.redactOptions()));
    try { appendFileSync(logFile, line + '\n', { mode: 0o600 }); } catch { /* logging must never break requests */ }
  };
  const ctx: AppContext = {
    store, engine, scheduler: new Scheduler(engine, (m, e) => log('error', m, e)), auth: new AuthState(opts.port), errors: new ErrorRing(),
    startedAt: Date.now(), log, doctorCache: null, providerTests: new Map(), stream: { heartbeatMs: opts.heartbeatMs ?? 15_000, replayLimit: 5000 }, openStreams: new Set(),
    uploads: new Uploads(join(store.paths.tmp, 'uploads')),
    notices: new Set(),
    notify: (type, payload) => { for (const fn of ctx.notices) fn(type, payload); },
  };
  // Upload TTL: at startup and hourly.
  ctx.uploads.sweep();
  const sweepTimer = setInterval(() => { try { ctx.uploads.sweep(); } catch { /* retried next hour */ } }, 3600_000);
  sweepTimer.unref();

  const registeredRoutes: string[] = [];
  const app = Fastify({
    logger: false, forceCloseConnections: true,
    // Validation must never silently rewrite input: reject unknown fields, no type coercion.
    ajv: { customOptions: { removeAdditional: false, coerceTypes: false, useDefaults: false, allErrors: false } }, genReqId: () => newId('request'), bodyLimit: 2 * 1024 * 1024, trustProxy: false, routerOptions: { ignoreTrailingSlash: true } });

  app.addHook('onRequest', async (req: AuthedRequest, reply) => {
    // Host (anti DNS-rebinding)
    if (!ctx.auth.allowedHosts.includes(String(req.headers.host ?? ''))) throw new AppError('AUTH_HOST_REJECTED');
    if (req.method === 'OPTIONS') throw new AppError('AUTH_ORIGIN_REJECTED', 'preflight is not supported');
    if (req.headers['sec-fetch-site'] === 'cross-site') throw new AppError('AUTH_ORIGIN_REJECTED');
    const origin = req.headers.origin;
    if (origin !== undefined && !ctx.auth.allowedOrigins.includes(origin)) throw new AppError('AUTH_ORIGIN_REJECTED');
    if (!isApiRequest(req)) return;
    reply.header('Cache-Control', 'no-store');
    const bearer = ctx.auth.checkBearer(req.headers.authorization);
    const session = ctx.auth.session(parseCookies(req.headers.cookie)[sessionCookieName(ctx.auth.port)]);
    if (bearer) req.bearer = true;
    if (session) req.session = session;
    // The registered pattern, so PUBLIC_API and the checks below see the same string the router matched.
    const route = req.routeOptions.url === undefined ? '' : `${req.method} ${req.routeOptions.url}`;
    if (!PUBLIC_API.has(route) && !bearer && !session) throw new AppError('AUTH_SESSION_REQUIRED');
    // Checked after authentication, so callers without credentials only ever see 401.
    if (isNonCanonicalTarget(rawPath(req))) throw new AppError('COMMON_VALIDATION', 'API requests must use a plain /api/... path');
    if (WRITE_METHODS.has(req.method)) {
      if (!bearer) {
        // Browser writes must carry our Origin and the session CSRF token.
        if (!origin) throw new AppError('AUTH_ORIGIN_REJECTED', 'writes without Origin require the CLI token');
        if (route !== 'POST /api/session/bootstrap') {
          const csrf = req.headers['x-csrf-token'];
          if (typeof csrf !== 'string' || !session || !safeEqual(csrf, session.csrf)) throw new AppError('AUTH_CSRF_INVALID');
        }
      }
      const contentType = String(req.headers['content-type'] ?? '');
      if (route === 'POST /api/v1/uploads') {
        if (!contentType.startsWith('application/octet-stream')) throw new AppError('COMMON_VALIDATION', 'Content-Type must be application/octet-stream');
      } else if (req.method !== 'DELETE' && !contentType.startsWith('application/json')) {
        throw new AppError('COMMON_VALIDATION', 'Content-Type must be application/json');
      }
    }
  });

  app.addHook('onSend', async (req, reply, payload) => {
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) if (!reply.getHeader(k)) reply.header(k, v);
    return payload;
  });

  app.addHook('onResponse', async (req, reply) => {
    if (isApiRequest(req)) {
      log(reply.statusCode >= 500 ? 'error' : 'info', 'request', {
        requestId: req.id, method: req.method, path: rawPath(req), status: reply.statusCode, ms: Math.round(reply.elapsedTime),
      });
      // a change to a vulnerability made in one place (detail panel, list batch, conversation card,
      // verification result, merge / split) refreshes every open page — the cards about it, badges, lists.
      if (req.method !== 'GET' && reply.statusCode < 400 && VULN_WRITES.test(rawPath(req))) {
        const vid = (req.params as { vid?: string } | undefined)?.vid ?? null;
        ctx.notify('vuln.changed', { vulnId: vid });
      }
    }
  });

  app.setErrorHandler((err, req, reply) => {
    const mapped = toApiError(err, req.id, store.redactOptions());
    if (mapped.status >= 500) {
      ctx.errors.push({ ts: new Date().toISOString(), requestId: req.id, code: mapped.body.error.code, message: mapped.logMessage.split('\n')[0]!.slice(0, 300) });
      log('error', 'request failed', { requestId: req.id, error: mapped.logMessage });
    }
    reply.code(mapped.status).header('Content-Type', 'application/json; charset=utf-8').send(mapped.body);
  });

  // Attach contract schemas to every documented API route; undocumented /api routes are a test failure.
  app.addHook('onRoute', (route) => {
    const methods = Array.isArray(route.method) ? route.method : [route.method];
    for (const m of methods) if (m !== 'HEAD') registeredRoutes.push(`${m} ${route.url}`);
    for (const m of methods) {
      const doc = ROUTE_DOCS[`${m} ${route.url}`];
      if (doc) {
        route.schema = { ...(route.schema ?? {}), ...routeSchema(doc) };
        return;
      }
    }
    if (!route.url.startsWith('/api/') && route.schema === undefined) route.schema = { hide: true };
  });
  await app.register(fastifySwagger, {
    openapi: {
      openapi: '3.1.0',
      info: { title: 'xiezhi-audit local API', version: SERVER_VERSION, description: '仅监听 127.0.0.1。浏览器使用会话 cookie + X-CSRF-Token；CLI 使用 <data-dir>/run/api.json 中的 Bearer token。' },
      servers: [{ url: 'http://127.0.0.1:4820' }],
      components: {
        securitySchemes: {
          session: { type: 'apiKey', in: 'cookie', name: 'ca_session' },
          cliToken: { type: 'http', scheme: 'bearer' },
        },
      },
      security: [{ session: [] }, { cliToken: [] }],
    },
    hideUntagged: true,
  });

  const knowledgeWatch = opts.watchKnowledge === false ? null : startKnowledgeWatch(ctx);
  app.addHook('onClose', async () => {
    knowledgeWatch?.close();
    clearInterval(sweepTimer);
    for (const close of [...ctx.openStreams]) close();
  });
  // Raw bytes for POST /uploads only (the onRequest hook rejects octet-stream elsewhere); the upload
  // handler streams to disk and enforces its own size cap instead of bodyLimit.
  app.addContentTypeParser('application/octet-stream', (_req, payload, done) => done(null, payload));

  registerCoreRoutes(app, ctx);
  registerProjectRoutes(app, ctx);
  registerAuditRoutes(app, ctx);
  registerVulnRoutes(app, ctx);
  registerHypothesisRoutes(app, ctx);
  registerDomainPlanRoutes(app, ctx);
  registerThreatModelRoutes(app, ctx);
  registerEventRoutes(app, ctx);
  registerHuntRoutes(app, ctx);
  registerKnowledgeRoutes(app, ctx);
  registerPromptRoutes(app, ctx);
  registerFactRoutes(app, ctx);
  registerEgressRoutes(app, ctx);
  registerRuleRoutes(app, ctx);
  registerVerificationRoutes(app, ctx);
  registerFixRoutes(app, ctx);
  registerConnectorRoutes(app, ctx);
  registerArchitectureRoutes(app, ctx);
  registerPackRoutes(app, ctx);
  registerPushRoutes(app, ctx);
  registerConversationRoutes(app, ctx);
  ctx.engine.conversations.onNotice(ctx.notify);

  app.get('/api/v1/openapi.json', async () => compactOpenApi(app.swagger() as unknown as Record<string, unknown>));

  const webRoot = opts.webRoot === undefined ? defaultWebRoot() : opts.webRoot;
  if (webRoot) {
    await app.register(fastifyStatic, { root: webRoot, prefix: '/', index: false, wildcard: false, serveDotFiles: false });
    const indexHtml = readFileSync(join(webRoot, 'index.html'));
    const spa = async (_req: FastifyRequest, reply: import('fastify').FastifyReply) => reply.header('Content-Type', 'text/html; charset=utf-8').header('Cache-Control', 'no-cache').send(indexHtml);
    app.get('/', spa);
    app.setNotFoundHandler(async (req, reply) => {
      const path = rawPath(req);
      if (req.method === 'GET' && !isApiPath(path) && !/\.[a-z0-9]{1,8}$/i.test(path)) return spa(req, reply);
      throw new AppError('COMMON_NOT_FOUND');
    });
  } else {
    app.setNotFoundHandler(async () => { throw new AppError('COMMON_NOT_FOUND'); });
  }
  return { app, ctx, routes: registeredRoutes };
}
