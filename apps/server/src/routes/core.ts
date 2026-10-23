// Session, health, settings and diagnostics routes.
import { readdirSync, statSync, lstatSync } from 'node:fs';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import {
  AppError, AuditStrategy, SCENES, canonicalJson, check, checkStrategy, maskSecret, mergeStrategy, originOf,
  redact, sceneDefaults, sha256Hex, NO_MODEL_STAGES, type AppConfig, type DiagnosticsDto, type GeneralSettingsDto, type ModelSettingsDto, type ProviderDto,
  type GitCredentialDto, type Scene, type SessionInfo,
} from '@xiezhi/contracts';
import { readLock } from '@xiezhi/store';
import { modelDefaults, runDoctor, queries as Q } from '@xiezhi/engine';
import { listModels, pingModel, piVersion } from '@xiezhi/agent';
import * as B from '../bodies.js';
import { SERVER_VERSION, type AppContext } from '../context.js';
import { parseBody } from '../http.js';
import { sessionCookie } from '../security.js';

const cfgRev = (v: unknown) => sha256Hex(canonicalJson(v ?? null)).slice(0, 16);

function providerDto(ctx: AppContext, p: AppConfig['modelProviders'][number]): ProviderDto {
  return {
    id: p.id, api: p.api, baseUrl: p.baseUrl, apiKey: maskSecret(p.apiKey),
    models: p.models.map((m) => ({ id: m.id, ...(m.name ? { name: m.name } : {}), ...(m.contextWindow ? { contextWindow: m.contextWindow } : {}), ...(m.maxTokens ? { maxTokens: m.maxTokens } : {}), ...(m.reasoning !== undefined ? { reasoning: m.reasoning } : {}) })),
    lastTest: ctx.providerTests.get(p.id) ?? null,
  };
}

function validBaseUrl(u: string): string {
  let url: URL;
  try { url = new URL(u); } catch { throw new AppError('COMMON_VALIDATION', 'baseUrl is not a URL'); }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new AppError('COMMON_VALIDATION', 'baseUrl must be http(s)');
  if (url.username || url.password) throw new AppError('COMMON_VALIDATION', 'baseUrl must not contain credentials');
  if (url.search) throw new AppError('COMMON_VALIDATION', 'baseUrl must not contain a query string');
  return u.replace(/\/+$/, '');
}

/** Checked per request at most: the rest of the selection is left for another check. */
const CHECK_MAX_MODELS = 10;

function dirSize(root: string, cap = 200_000): number {
  let total = 0;
  let n = 0;
  const walk = (d: string) => {
    let entries: string[];
    try { entries = readdirSync(d); } catch { return; }
    for (const name of entries) {
      if (++n > cap) return;
      const p = join(d, name);
      try {
        const st = lstatSync(p);
        if (st.isDirectory()) walk(p); else total += st.size;
      } catch { /* vanished */ }
    }
  };
  walk(root);
  return total;
}

let storageCache: { at: number; value: Record<string, number> } | null = null;

export function registerCoreRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store, auth } = ctx;

  // ---- session ----
  app.post('/api/session/bootstrap', async (req, reply) => {
    const body = parseBody(B.PostSessionBootstrapBody, req.body);
    const s = auth.redeem(body.code);
    reply.header('Set-Cookie', sessionCookie(s.id, auth.port));
    return { authenticated: true, csrfToken: s.csrf, version: SERVER_VERSION, dataDir: '<data-dir>' } satisfies SessionInfo;
  });
  // the CSRF token is handed out only at bootstrap; a cookie that reached another local port cannot
  // be turned into write access here (the web app keeps the token in origin-scoped storage).
  app.get('/api/session', async (req) => {
    const s = (req as unknown as { session?: { csrf: string } }).session;
    return { authenticated: !!s, csrfToken: null, version: SERVER_VERSION, dataDir: '<data-dir>' } satisfies SessionInfo;
  });
  /** CLI (bearer only): issue a fresh bootstrap URL for `xiezhi open`. */
  app.post('/api/v1/session/bootstrap-codes', async (req) => {
    if (!(req as unknown as { bearer?: boolean }).bearer) throw new AppError('AUTH_SESSION_REQUIRED');
    return { url: auth.bootstrapUrl(auth.issueBootstrap()), expiresInSec: 300 };
  });

  app.get('/api/v1/health', async () => {
    const lock = readLock(store.paths.lock);
    let writable = true;
    try { statSync(store.paths.root); } catch { writable = false; }
    return { status: 'ok', version: SERVER_VERSION, dataDirWritable: writable, lockHolder: lock ? { pid: lock.pid, role: lock.role } : null, piVersion: piVersion() };
  });

  // ---- model providers ----
  app.get('/api/v1/settings/model-providers', async () => store.config.modelProviders.map((p) => providerDto(ctx, p)));
  app.post('/api/v1/settings/model-providers', async (req, reply) => {
    const b = parseBody(B.ProviderCreate, req.body);
    const cfg = store.config;
    if (cfg.modelProviders.some((p) => p.id === b.id)) throw new AppError('CONFIG_INVALID', `provider ${b.id} exists`);
    const baseUrl = validBaseUrl(b.baseUrl);
    const next = { id: b.id, api: b.api, baseUrl, models: b.models, ...(b.apiKey ? { apiKey: b.apiKey, apiKeyOrigin: originOf(baseUrl) } : {}) };
    store.saveConfig({ ...cfg, modelProviders: [...cfg.modelProviders, next] });
    await ctx.engine.reloadModels();
    reply.code(201);
    return providerDto(ctx, next);
  });
  app.patch<{ Params: { id: string } }>('/api/v1/settings/model-providers/:id', async (req) => {
    const b = parseBody(B.ProviderPatch, req.body);
    const cfg = store.config;
    const cur = cfg.modelProviders.find((p) => p.id === req.params.id);
    if (!cur) throw new AppError('PROVIDER_NOT_FOUND', req.params.id);
    const baseUrl = b.baseUrl ? validBaseUrl(b.baseUrl) : cur.baseUrl;
    const originChanged = originOf(baseUrl) !== originOf(cur.baseUrl);
    // Empty / omitted key keeps the old one — unless the origin changed: that is a new binding.
    const key = b.apiKey ? b.apiKey : originChanged ? undefined : cur.apiKey;
    const { apiKey: _k, apiKeyOrigin: _o, ...rest } = cur;
    const next = { ...rest, api: b.api ?? cur.api, baseUrl, models: b.models ?? cur.models, ...(key ? { apiKey: key, apiKeyOrigin: originOf(baseUrl) } : {}) };
    store.saveConfig({ ...cfg, modelProviders: cfg.modelProviders.map((p) => (p.id === cur.id ? next : p)) });
    ctx.providerTests.delete(cur.id);
    await ctx.engine.reloadModels();
    return { ...providerDto(ctx, next), keyCleared: originChanged && !b.apiKey && !!cur.apiKey };
  });
  app.delete<{ Params: { id: string } }>('/api/v1/settings/model-providers/:id', async (req, reply) => {
    const cfg = store.config;
    if (!cfg.modelProviders.some((p) => p.id === req.params.id)) throw new AppError('PROVIDER_NOT_FOUND', req.params.id);
    const refs = [cfg.defaultModel, cfg.fallbackModel, ...Object.values(cfg.stageModels ?? {})].filter((m) => m?.provider === req.params.id);
    if (refs.length) throw new AppError('CONFIG_INVALID', 'provider is referenced by model settings; change them first');
    store.saveConfig({ ...cfg, modelProviders: cfg.modelProviders.filter((p) => p.id !== req.params.id) });
    await ctx.engine.reloadModels();
    reply.code(204);
    return null;
  });
  /**
   * An unsaved provider form. With `id` and no key in the form, the saved key is reused — but only for the
   * origin it is bound to: a form pointing elsewhere is tried without a key.
   */
  const formProvider = (b: { id?: string | undefined; api: AppConfig['modelProviders'][number]['api']; baseUrl: string; apiKey?: string | undefined }): AppConfig['modelProviders'][number] => {
    const baseUrl = validBaseUrl(b.baseUrl);
    const saved = b.id ? store.config.modelProviders.find((p) => p.id === b.id) : undefined;
    const reuse = !b.apiKey && saved?.apiKey && (saved.apiKeyOrigin ?? originOf(saved.baseUrl)) === originOf(baseUrl) ? saved.apiKey : undefined;
    const key = b.apiKey || reuse;
    return { id: b.id ?? 'form', api: b.api, baseUrl, models: [], ...(saved?.headers ? { headers: saved.headers } : {}), ...(key ? { apiKey: key } : {}) };
  };
  const clean = (s: string) => redact(s, store.redactOptions());
  app.post('/api/v1/settings/model-providers/probe', async (req) => {
    const p = formProvider(parseBody(B.ProviderProbeBody, req.body));
    const r = await listModels(p);
    return { ok: r.ok, detail: clean(r.detail), models: r.models ?? [], limits: r.limits ?? {} };
  });
  app.post('/api/v1/settings/model-providers/check', async (req) => {
    const b = parseBody(B.ProviderCheckBody, req.body);
    const p = formProvider(b);
    const list = await listModels(p);
    const ids = [...new Set(b.models.map((m) => m.trim()).filter(Boolean))];
    const tried = ids.slice(0, CHECK_MAX_MODELS);
    const results: { id: string; ok: boolean; ms: number; detail: string }[] = new Array(tried.length);
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(3, tried.length) }, async () => {
      while (next < tried.length) {
        const i = next++;
        const r = await pingModel(p, tried[i]!);
        results[i] = { id: tried[i]!, ok: r.ok, ms: r.ms, detail: clean(r.detail) };
      }
    }));
    const okModels = results.filter((r) => r.ok).length;
    const ok = (list.ok || okModels > 0) && (!tried.length || okModels === tried.length);
    const detail = !tried.length
      ? (list.ok ? `地址与密钥可用：${clean(list.detail)}` : clean(list.detail))
      : `${okModels}/${tried.length} 个模型可用${list.ok ? '' : `；模型列表：${clean(list.detail)}`}`;
    return { ok, detail, list: { ok: list.ok, detail: clean(list.detail), count: list.models?.length ?? 0 }, models: results, truncated: ids.length > tried.length };
  });
  app.post<{ Params: { id: string } }>('/api/v1/settings/model-providers/:id/test', async (req) => {
    const p = store.config.modelProviders.find((x) => x.id === req.params.id);
    if (!p) throw new AppError('PROVIDER_NOT_FOUND', req.params.id);
    if (p.apiKey && p.apiKeyOrigin && p.apiKeyOrigin !== originOf(p.baseUrl)) throw new AppError('CREDENTIAL_BINDING_MISMATCH');
    const r = await listModels(p);
    const detail = redact(r.detail, store.redactOptions());
    const rec = { ok: r.ok, at: new Date().toISOString(), detail };
    ctx.providerTests.set(p.id, rec);
    return { ...rec, models: r.models ?? [] };
  });

  // ---- Git HTTPS credentials: token write-only, shown masked ----
  const gitCredDto = (c: { host: string; username: string; token?: string | undefined }): GitCredentialDto => ({ host: c.host, username: c.username, token: maskSecret(c.token) });
  const gitHost = (raw: string) => {
    const host = raw.trim().toLowerCase();
    if (!/^[a-z0-9.-]+(:[0-9]{1,5})?$/.test(host) || host.length > 255) throw new AppError('COMMON_VALIDATION', 'host must be a domain name with an optional port, e.g. gitlab.example.com');
    return host;
  };
  app.get('/api/v1/settings/git-credentials', async () => (store.config.gitCredentials ?? []).map(gitCredDto));
  app.put<{ Params: { host: string } }>('/api/v1/settings/git-credentials/:host', async (req) => {
    const b = parseBody(B.PutSettingsGitCredentialsHostBody, req.body);
    const host = gitHost(req.params.host);
    const cfg = store.config;
    const list = cfg.gitCredentials ?? [];
    const cur = list.find((c) => c.host === host);
    const token = b.token ? b.token : cur?.token;
    const next = { host, username: b.username.trim(), ...(token ? { token } : {}) };
    store.saveConfig({ ...cfg, gitCredentials: [...list.filter((c) => c.host !== host), next].sort((a, x) => a.host.localeCompare(x.host)) });
    return gitCredDto(next);
  });
  app.delete<{ Params: { host: string } }>('/api/v1/settings/git-credentials/:host', async (req, reply) => {
    const host = gitHost(req.params.host);
    const cfg = store.config;
    if (!(cfg.gitCredentials ?? []).some((c) => c.host === host)) throw new AppError('COMMON_NOT_FOUND', host);
    store.saveConfig({ ...cfg, gitCredentials: (cfg.gitCredentials ?? []).filter((c) => c.host !== host) });
    reply.code(204);
    return null;
  });

  /** a scene layer has no stage models or per-stage fallbacks (settings → 模型 owns them). */
  const sceneLayer = (layer: Record<string, unknown>): Record<string, unknown> => {
    const { models: _m, modelFallbacks: _f, ...rest } = layer;
    return rest;
  };

  // ---- model settings ----
  // default model + per-stage models + one fallback.
  const modelSettings = (): ModelSettingsDto => {
    const c = store.config;
    const stageModels = c.stageModels ?? {};
    const confidentialModels = c.confidentialModels ?? [];
    return { defaultModel: c.defaultModel ?? null, stageModels, fallbackModel: c.fallbackModel ?? null, confidentialModels, revision: cfgRev([c.defaultModel, stageModels, c.fallbackModel, confidentialModels]) };
  };
  app.get('/api/v1/settings/models', async () => modelSettings());
  app.put('/api/v1/settings/models', async (req) => {
    const b = parseBody(B.PutSettingsModelsBody, req.body);
    if (b.revision !== modelSettings().revision) throw new AppError('COMMON_REVISION_CONFLICT');
    const known = new Set(store.config.modelProviders.flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`)));
    for (const m of [b.defaultModel, b.fallbackModel, ...Object.values(b.stageModels)]) if (m && !known.has(`${m.provider}/${m.model}`)) throw new AppError('CONFIG_INVALID', `model ${m.provider}/${m.model} is not configured`);
    for (const [k, m] of Object.entries(b.stageModels)) {
      if (m === null && !(NO_MODEL_STAGES as readonly string[]).includes(k)) throw new AppError('CONFIG_INVALID', `stage ${k} cannot run without a model; omit it to follow the default model`);
    }
    for (const k of b.confidentialModels ?? []) if (!known.has(k)) throw new AppError('CONFIG_INVALID', `model ${k} is not configured`);
    const { defaultModel: _d, stageModels: _s, fallbackModel: _f, confidentialModels: _c, ...rest } = store.config;
    const confidential = b.confidentialModels ?? store.config.confidentialModels ?? [];
    store.saveConfig({ ...rest, ...(b.defaultModel ? { defaultModel: b.defaultModel } : {}), stageModels: b.stageModels, ...(b.fallbackModel ? { fallbackModel: b.fallbackModel } : {}), ...(confidential.length ? { confidentialModels: [...new Set(confidential)] } : {}) });
    return modelSettings();
  });

  // ---- scene defaults ----
  app.get<{ Params: { scene: string } }>('/api/v1/settings/scene-defaults/:scene', async (req) => {
    const scene = req.params.scene as Scene;
    if (!SCENES.includes(scene)) throw new AppError('COMMON_NOT_FOUND', 'scene');
    const layer = sceneLayer((store.config.sceneDefaults as Record<string, Record<string, unknown> | undefined>)[scene] ?? {});
    let effective: unknown = null;
    try {
      effective = mergeStrategy(sceneDefaults(scene, modelDefaults(store.config)), layer, undefined).strategy;
    } catch { /* no model configured yet */ }
    return { scene, override: layer, effective, revision: cfgRev(layer), runnable: scene === 'full' };
  });
  app.put<{ Params: { scene: string } }>('/api/v1/settings/scene-defaults/:scene', async (req) => {
    const scene = req.params.scene as Scene;
    if (!SCENES.includes(scene)) throw new AppError('COMMON_NOT_FOUND', 'scene');
    const b = parseBody(B.PutSettingsSceneDefaultsSceneBody, req.body);
    const cur = sceneLayer((store.config.sceneDefaults as Record<string, Record<string, unknown> | undefined>)[scene] ?? {});
    if (b.revision !== cfgRev(cur)) throw new AppError('COMMON_REVISION_CONFLICT');
    const override = sceneLayer(b.override);
    const merged = mergeStrategy(sceneDefaults(scene, modelDefaults(store.config)), override, undefined).strategy;
    const r = check(AuditStrategy, merged);
    if (!r.ok) throw new AppError('STRATEGY_INVALID', r.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; '));
    const known = new Set(store.config.modelProviders.flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`)));
    const issues = checkStrategy(merged, scene, known).filter((i) => i.path !== 'scene');
    if (issues.length) throw new AppError('STRATEGY_INVALID', issues.map((i) => `${i.path}: ${i.message}`).join('; '));
    store.saveConfig({ ...store.config, sceneDefaults: { ...store.config.sceneDefaults, [scene]: override } });
    return { scene, override, effective: merged, revision: cfgRev(override), runnable: scene === 'full' };
  });

  // ---- general ----
  const general = (): GeneralSettingsDto => {
    const c = store.config;
    const body = { concurrency: { audits: c.concurrency.audits, modelRequests: c.concurrency.modelRequests }, engine: c.engine, export: c.export, log: c.log, pricing: c.pricing };
    return { ...body, revision: cfgRev(body) };
  };
  app.get('/api/v1/settings/general', async () => general());
  app.patch('/api/v1/settings/general', async (req) => {
    const b = parseBody(B.PatchSettingsGeneralBody, req.body);
    if (b.revision !== general().revision) throw new AppError('COMMON_REVISION_CONFLICT');
    const c = store.config;
    // `reportSkill: null` clears the default report skill.
    const { reportSkill, ...exp } = { ...c.export, ...b.export };
    store.saveConfig({
      ...c, concurrency: { ...c.concurrency, ...b.concurrency }, engine: { ...c.engine, ...b.engine }, export: { ...exp, ...(reportSkill ? { reportSkill } : {}) },
      log: { ...c.log, ...b.log }, pricing: b.pricing ?? c.pricing,
    });
    ctx.scheduler.kick();
    return general();
  });

  // ---- diagnostics ----
  const diagnostics = async (force: boolean): Promise<DiagnosticsDto> => {
    if (force || !ctx.doctorCache || Date.now() - ctx.doctorCache.at > 10 * 60_000) {
      ctx.doctorCache = { at: Date.now(), checks: await runDoctor(store.paths.root) };
    }
    if (!storageCache || Date.now() - storageCache.at > 10 * 60_000 || force) {
      const p = store.paths;
      storageCache = { at: Date.now(), value: Object.fromEntries(['snapshots', 'indexes', 'artifacts', 'logs', 'tmp'].map((k) => [k, dirSize(p[k as 'tmp'])])) };
      storageCache.value.db = (() => { try { return statSync(p.db).size; } catch { return 0; } })();
    }
    const q = (s: 'queued' | 'running') => Q.countAuditsIn(store, s);
    return {
      checks: ctx.doctorCache.checks.map((c) => ({ ...c, detail: redact(c.detail, store.redactOptions()), ...(c.fix ? { fix: redact(c.fix, store.redactOptions()) } : {}) })),
      checkedAt: new Date(ctx.doctorCache.at).toISOString(), storage: storageCache.value,
      runtime: { version: SERVER_VERSION, piVersion: piVersion(), pid: process.pid, uptimeSec: Math.round((Date.now() - ctx.startedAt) / 1000), queued: q('queued'), running: q('running') },
      recentErrors: ctx.errors.list(),
    };
  };
  app.get('/api/v1/diagnostics', async () => diagnostics(false));
  app.post('/api/v1/diagnostics/run', async () => diagnostics(true));
}
