// Per-snapshot facts for the JS / TS frameworks whose routes are not visible from one file —
// Next.js / Nuxt file routing (the project root, middleware), Egg (controller files by property path, global
// middleware from config), hapi (the default auth strategy), and which of these frameworks the nearest package.json
// declares (route files of hapi / Egg / Next.js usually import nothing from the framework). Text scans only (no
// parsing); plain data, so it crosses worker threads in `ExtractInput.langContext`.
import type { SnapshotView } from '../snapshot/view.js';
import { AUTH_NAME_RE } from './common.js';

/** `ExtractInput.langContext` of a JS / TS file; set only for files under a package that declares one of the frameworks. */
export interface JsFrameworkContext {
  /** Framework markers declared by the nearest package.json (and the repository root's). */
  deps: string[];
  /** Directory of that package.json ('' = repository root): Next.js / Nuxt routes and Egg `app/` are relative to it. */
  appRoot: string;
  /** Egg router files: controller property path (`admin.userInfo`) → module path of the controller file. */
  eggControllers?: Record<string, string>;
  /** Egg: `config.middleware` names (global middleware applied to every route). */
  eggMiddleware?: string[];
  /** Next.js route files: `middleware.ts` matchers (null = every path) and whether it looks like authentication. */
  nextMiddleware?: { file: string; matchers: string[] | null; auth: boolean };
  /** Nuxt / Nitro server routes: `server/middleware/*` files (run on every request) and whether each looks like authentication. */
  nuxtMiddleware?: { file: string; auth: boolean }[];
  /** hapi: `server.auth.default(…)` text (applies to every route without `auth: false`). */
  hapiDefaultAuth?: string;
}

/** Dependencies that select the context above; other repositories get no `langContext` (index unchanged). */
const MARKERS = ['@hapi/hapi', 'hapi', 'egg', 'next', 'nuxt', 'nitropack', 'h3'] as const;
const MAX_BYTES = 512 * 1024;

const dirOf = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
const under = (root: string, p: string) => root === '' || p.startsWith(root + '/');
const rel = (root: string, p: string) => (root === '' ? p : p.slice(root.length + 1));
const camel = (s: string) => s.replace(/[_-]+([a-z0-9])/gi, (_m, c: string) => c.toUpperCase());

/** Module key of a JS / TS file (same as `jsModulePath`; repeated here to keep this module free of the extractor). */
const moduleOf = (path: string) => {
  const p = path.replace(/\.(d\.)?[cm]?[jt]sx?$/, '');
  return p === 'index' ? '.' : p.endsWith('/index') ? p.slice(0, -'/index'.length) : p;
};

function quotedStrings(text: string): string[] {
  return [...text.matchAll(/(['"`])((?:\\.|(?!\1)[^\\\n])*)\1/g)].map((m) => m[2]!);
}

/** Per-file framework context for one snapshot (cached per view). */
const cache = new WeakMap<SnapshotView, Map<string, JsFrameworkContext>>();

export function jsFrameworkContexts(view: SnapshotView): Map<string, JsFrameworkContext> {
  const hit = cache.get(view);
  if (hit) return hit;
  const out = new Map<string, JsFrameworkContext>();
  cache.set(view, out);
  const files = view.listFiles().filter((f) => !f.path.includes('node_modules/'));
  const read = (path: string): string | null => {
    const f = files.find((x) => x.path === path);
    if (!f || f.size > MAX_BYTES) return null;
    try { return view.text(path); } catch { return null; }
  };
  // Packages declaring a marker, deepest first (a file belongs to its nearest package.json).
  const pkgs: { dir: string; deps: string[] }[] = [];
  for (const f of files) {
    if (!(f.path === 'package.json' || f.path.endsWith('/package.json'))) continue;
    const text = read(f.path);
    if (!text) continue;
    try {
      const j = JSON.parse(text) as Record<string, Record<string, unknown> | undefined>;
      const deps = [...Object.keys(j.dependencies ?? {}), ...Object.keys(j.devDependencies ?? {}), ...Object.keys(j.peerDependencies ?? {})];
      pkgs.push({ dir: dirOf(f.path), deps: deps.filter((d) => (MARKERS as readonly string[]).includes(d)) });
    } catch { /* not JSON */ }
  }
  if (!pkgs.some((p) => p.deps.length)) return out;
  pkgs.sort((a, b) => b.dir.length - a.dir.length);
  const rootDeps = pkgs.find((p) => p.dir === '')?.deps ?? [];
  const jsFiles = files.filter((f) => f.lang === 'javascript' || f.lang === 'typescript');

  const perRoot = new Map<string, Omit<JsFrameworkContext, 'deps' | 'appRoot'>>();
  const factsOf = (root: string, deps: string[]) => {
    const cached = perRoot.get(root);
    if (cached) return cached;
    const facts: Omit<JsFrameworkContext, 'deps' | 'appRoot'> = {};
    const inRoot = jsFiles.filter((f) => under(root, f.path));
    if (deps.includes('egg')) {
      const controllers: Record<string, string> = {};
      for (const f of inRoot) {
        const m = /^app\/controller\/(.+)\.[cm]?[jt]s$/.exec(rel(root, f.path));
        if (m && !m[1]!.endsWith('.d')) controllers[m[1]!.split('/').map(camel).join('.')] = moduleOf(f.path);
      }
      facts.eggControllers = controllers;
      const mws: string[] = [];
      for (const name of ['config.default', 'config.prod', 'config.local']) {
        for (const ext of ['js', 'ts']) {
          const text = read(`${root ? root + '/' : ''}config/${name}.${ext}`);
          const list = text && /\bmiddleware\s*[:=]\s*\[([^\]]*)\]/.exec(text);
          if (list) for (const s of quotedStrings(list[1]!)) if (!mws.includes(s)) mws.push(s);
        }
      }
      if (mws.length) facts.eggMiddleware = mws;
    }
    if (deps.includes('next')) {
      for (const cand of ['middleware.ts', 'middleware.js', 'src/middleware.ts', 'src/middleware.js']) {
        const file = `${root ? root + '/' : ''}${cand}`;
        const text = read(file);
        if (text === null) continue;
        const mm = /\bmatcher\s*:\s*(\[[^\]]*\]|(['"`])[^'"`]*\2)/.exec(text);
        facts.nextMiddleware = { file, matchers: mm ? quotedStrings(mm[1]!) : null, auth: AUTH_NAME_RE.test(text) };
        break;
      }
    }
    if (deps.includes('nuxt') || deps.includes('nitropack')) {
      const mws = inRoot.filter((f) => /^server\/middleware\/[^/]+\.[cm]?[jt]s$/.test(rel(root, f.path)));
      if (mws.length) facts.nuxtMiddleware = mws.map((f) => ({ file: f.path, auth: AUTH_NAME_RE.test(read(f.path) ?? '') }));
    }
    if (deps.includes('@hapi/hapi') || deps.includes('hapi')) {
      for (const f of inRoot) {
        const text = read(f.path);
        const m = text && /\.auth\.default\s*\(([^)]*)\)/.exec(text);
        if (m) { facts.hapiDefaultAuth = `server.auth.default(${m[1]!.replace(/\s+/g, ' ').trim()})`.slice(0, 120); break; }
      }
    }
    perRoot.set(root, facts);
    return facts;
  };

  for (const f of jsFiles) {
    const pkg = pkgs.find((p) => under(p.dir, f.path));
    const deps = [...new Set([...(pkg?.deps ?? []), ...rootDeps])].sort();
    if (!deps.length) continue;
    const appRoot = pkg?.dir ?? '';
    const facts = factsOf(appRoot, deps);
    const r = rel(appRoot, f.path);
    const ctx: JsFrameworkContext = { deps, appRoot };
    if (facts.eggControllers && /^app\/router(\.[cm]?[jt]s$|\/)/.test(r)) {
      ctx.eggControllers = facts.eggControllers;
      if (facts.eggMiddleware) ctx.eggMiddleware = facts.eggMiddleware;
    }
    if (facts.nextMiddleware && /^(src\/)?(pages\/api|app)\//.test(r)) ctx.nextMiddleware = facts.nextMiddleware;
    if (facts.nuxtMiddleware && /^server\/(api|routes)\//.test(r)) ctx.nuxtMiddleware = facts.nuxtMiddleware;
    if (facts.hapiDefaultAuth) ctx.hapiDefaultAuth = facts.hapiDefaultAuth;
    out.set(f.path, ctx);
  }
  return out;
}

// ---- file routing ------------------------------------------------------------------------------------------------------

/** `[id]` → `:id`, `[...slug]` / `[[...slug]]` → `:slug*`; null for segments that are not part of the URL. */
function routeSegment(seg: string): string | null {
  if (/^\(.*\)$/.test(seg) || seg.startsWith('@')) return null; // route groups, parallel-route slots
  const catchAll = /^\[\[?\.\.\.([^\]]+)\]?\]$/.exec(seg);
  if (catchAll) return `:${catchAll[1]}*`;
  const dyn = /^\[([^\]]+)\]$/.exec(seg);
  return dyn ? `:${dyn[1]}` : seg;
}

const routeOf = (segs: string[]) => '/' + segs.map(routeSegment).filter((s): s is string => s !== null).join('/');

/** Next.js route of a file relative to its app root: Pages Router API routes and App Router route handlers. */
export function nextRouteOf(relPath: string): { kind: 'pages' | 'app'; route: string } | null {
  const p = relPath.replace(/^src\//, '');
  const pages = /^pages\/(api(?:\/.*)?)\.[cm]?[jt]sx?$/.exec(p);
  if (pages) {
    const segs = pages[1]!.split('/');
    if (segs[segs.length - 1] === 'index') segs.pop();
    return { kind: 'pages', route: routeOf(segs) };
  }
  const app = /^app\/(?:(.*)\/)?route\.[cm]?[jt]s$/.exec(p);
  if (app) {
    const segs = app[1] ? app[1].split('/') : [];
    if (segs.some((s) => s.startsWith('_'))) return null; // private folders are not routable
    return { kind: 'app', route: routeOf(segs) };
  }
  return null;
}

/** Nuxt / Nitro server route: `server/api/…` → `/api/…`, `server/routes/…` → `/…`; `name.get.ts` sets the method. */
export function nuxtRouteOf(relPath: string): { route: string; method: string } | null {
  const m = /^server\/(api|routes)\/(.+)\.[cm]?[jt]s$/.exec(relPath);
  if (!m) return null;
  const segs = m[2]!.split('/');
  let last = segs.pop()!;
  let method = 'ANY';
  const verb = /^(.*)\.(get|post|put|patch|delete|head|options)$/i.exec(last);
  if (verb) { last = verb[1]!; method = verb[2]!.toUpperCase(); }
  if (last !== 'index') segs.push(last);
  return { route: routeOf([...(m[1] === 'api' ? ['api'] : []), ...segs]), method };
}

/** Whether a Next.js middleware matcher (path-to-regexp style, or a regex group) covers `route`. */
export function nextMatcherCovers(matchers: string[] | null, route: string): boolean {
  if (!matchers) return true;
  return matchers.some((m) => {
    const src = m
      .replace(/\/:(\w+)\*/g, '(?:/.*)?')
      .replace(/\/:(\w+)\+/g, '/.+')
      .replace(/:(\w+)/g, '[^/]+');
    try { return new RegExp(`^${src}$`).test(route); } catch { return false; }
  });
}
