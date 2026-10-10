// Deterministic repository signal summary for role recognition. Output holds only paths,
// counts, dependency coordinates and rule hits — never comments or documents of the audited repository,
// so the summary cannot carry instructions from the repository into the model (P8).
import { parse as parseYaml } from 'yaml';
import type { GATEWAY_KINDS, RepoSignals, StructIndex } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';

const MAX_TEXT_BYTES = 512 * 1024;
const MAX_LIST = 200;
const MAX_SCANNED = 5000;

const SECURITY_DEPS = [
  /spring-boot-starter-security/, /spring-security/, /oauth2/i, /jjwt/, /java-jwt/, /nimbus-jose-jwt/, /shiro/, /sa-token/, /keycloak/,
  /golang-jwt\/jwt/, /dgrijalva\/jwt-go/, /casbin/, /ory\//, /^passport/, /next-auth/, /jsonwebtoken/,
  // Python, PHP, .NET, Kotlin / Ktor, NestJS.
  /^flask-(login|jwt|jwt-extended|security|principal)$/i, /^pyjwt$/i, /simplejwt/i, /^authlib$/i, /^python-jose$/i, /^django-allauth$/i, /^fastapi-users$/i,
  /^laravel\/(sanctum|passport|fortify)$/, /^tymon\/jwt-auth$/, /^firebase\/php-jwt$/, /^symfony\/security/, /^lcobucci\/jwt$/,
  /^Microsoft\.AspNetCore\.Authentication/, /^Microsoft\.AspNetCore\.Identity/, /^Microsoft\.Identity\./, /IdentityServer/, /^System\.IdentityModel\.Tokens\.Jwt$/,
  /ktor-server-auth/, /^@nestjs\/(passport|jwt)$/,
];
const FRONTEND_DEPS: Record<string, string> = { react: 'react', vue: 'vue', '@angular/core': 'angular', svelte: 'svelte', next: 'next', nuxt: 'nuxt' };
const AUTH_ROUTE = /\/(oauth2?|login|logout|token|auth|sso|signin|signup|register|session)(\/|$|\{)/i;
const JS_EXT = /\.(js|jsx|ts|tsx|vue|mjs|cjs)$/;

type GatewayKind = (typeof GATEWAY_KINDS)[number];

function tag(xml: string, name: string): string | undefined {
  return new RegExp(`<${name}>\\s*([^<\\s]+)\\s*</${name}>`).exec(xml)?.[1];
}

/** Maven: own coordinate (parent groupId as fallback), declared dependencies and sub-modules. */
function parsePom(xml: string): { provides: string | null; deps: string[]; modules: string[] } {
  const noComments = xml.replace(/<!--[\s\S]*?-->/g, '');
  const withoutBlocks = noComments.replace(/<(parent|dependencies|dependencyManagement|build|profiles|plugins)>[\s\S]*?<\/\1>/g, '');
  const parent = /<parent>([\s\S]*?)<\/parent>/.exec(noComments)?.[1] ?? '';
  const group = tag(withoutBlocks, 'groupId') ?? tag(parent, 'groupId');
  const artifact = tag(withoutBlocks, 'artifactId');
  const deps = [...noComments.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)]
    .map((m) => [tag(m[1]!, 'groupId'), tag(m[1]!, 'artifactId')])
    .filter(([g, a]) => g && a).map(([g, a]) => `${g}:${a}`);
  const modules = [...noComments.matchAll(/<module>\s*([^<\s]+)\s*<\/module>/g)].map((m) => m[1]!);
  return { provides: group && artifact ? `${group}:${artifact}` : null, deps, modules };
}

function parseGradle(text: string): string[] {
  return [...text.matchAll(/\b(?:implementation|api|compile|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['"]([^:'"\s]+):([^:'"\s]+)/g)].map((m) => `${m[1]}:${m[2]}`);
}

function parseGoMod(text: string): { provides: string | null; deps: string[] } {
  const provides = /^module\s+(\S+)/m.exec(text)?.[1] ?? null;
  const deps: string[] = [];
  const block = /^require\s*\(([\s\S]*?)^\)/m.exec(text)?.[1] ?? '';
  for (const line of [...block.split('\n'), ...[...text.matchAll(/^require\s+(\S+\s+\S+)/gm)].map((m) => m[1]!)]) {
    const mod = line.trim().split(/\s+/)[0];
    if (mod && !mod.startsWith('//')) deps.push(mod);
  }
  return { provides, deps };
}

function parsePackageJson(text: string): { provides: string | null; deps: string[] } {
  try {
    const j = JSON.parse(text) as { name?: unknown; dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown>; peerDependencies?: Record<string, unknown> };
    const deps = [...Object.keys(j.dependencies ?? {}), ...Object.keys(j.peerDependencies ?? {}), ...Object.keys(j.devDependencies ?? {})];
    return { provides: typeof j.name === 'string' && j.name ? j.name : null, deps };
  } catch {
    return { provides: null, deps: [] };
  }
}

/** PEP 508 requirement → distribution name (`Django>=4; python_version>"3"` → `Django`). */
function reqName(line: string): string | null {
  const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line.replace(/#.*/, ''));
  return m && !line.trim().startsWith('-') ? m[1]! : null;
}

function parseRequirements(text: string): string[] {
  return text.split('\n').map(reqName).filter((x): x is string => !!x);
}

/** pyproject.toml: [project] name / dependencies and [tool.poetry] name / dependencies (no TOML evaluation needed). */
function parsePyproject(text: string): { provides: string | null; deps: string[] } {
  const section = (name: string) => new RegExp(`^\\[${name.replace(/\./g, '\\.')}\\]\\s*$([\\s\\S]*?)(?=^\\[|(?![\\s\\S]))`, 'm').exec(text)?.[1] ?? '';
  const project = section('project');
  const poetry = section('tool.poetry');
  const provides = /^name\s*=\s*["']([^"']+)["']/m.exec(project)?.[1] ?? /^name\s*=\s*["']([^"']+)["']/m.exec(poetry)?.[1] ?? null;
  const list = /^dependencies\s*=\s*\[([\s\S]*?)\]/m.exec(project)?.[1] ?? '';
  const deps = [...list.matchAll(/["']([^"']+)["']/g)].map((m) => reqName(m[1]!)).filter((x): x is string => !!x);
  for (const m of section('tool.poetry.dependencies').matchAll(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/gm)) if (m[1]!.toLowerCase() !== 'python') deps.push(m[1]!);
  return { provides, deps };
}

function parseComposer(text: string): { provides: string | null; deps: string[] } {
  try {
    const j = JSON.parse(text) as { name?: unknown; require?: Record<string, unknown>; 'require-dev'?: Record<string, unknown> };
    const deps = [...Object.keys(j.require ?? {}), ...Object.keys(j['require-dev'] ?? {})].filter((d) => d.includes('/'));
    return { provides: typeof j.name === 'string' && j.name ? j.name : null, deps };
  } catch {
    return { provides: null, deps: [] };
  }
}

/** MSBuild project: PackageReference ids and the assembly name (file name when not set). */
function parseCsproj(path: string, text: string): { provides: string | null; deps: string[] } {
  const noComments = text.replace(/<!--[\s\S]*?-->/g, '');
  const deps = [...noComments.matchAll(/<PackageReference\b[^>]*\bInclude\s*=\s*"([^"]+)"/g)].map((m) => m[1]!);
  const assembly = /<AssemblyName>\s*([^<\s]+)\s*<\/AssemblyName>/.exec(noComments)?.[1] ?? path.split('/').pop()!.replace(/\.csproj$/, '');
  return { provides: assembly, deps };
}

function yamlDoc(text: string): unknown {
  try { return parseYaml(text, { maxAliasCount: 50, logLevel: 'silent' }); } catch { return null; }
}

function get(o: unknown, path: string[]): unknown {
  let cur = o;
  for (const k of path) {
    if (!cur || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

/** Route counts of recognized gateway configuration files (Spring Cloud Gateway, Zuul, Nginx, Kong, APISIX). */
function gatewayConfig(path: string, text: string): { kind: GatewayKind; routes: number } | null {
  const base = path.split('/').pop()!.toLowerCase();
  if (/\.(ya?ml)$/.test(base)) {
    const doc = yamlDoc(text);
    const scg = get(doc, ['spring', 'cloud', 'gateway', 'routes']);
    if (Array.isArray(scg)) return { kind: 'spring_cloud_gateway', routes: scg.length };
    const zuul = get(doc, ['zuul', 'routes']);
    if (zuul && typeof zuul === 'object') return { kind: 'zuul', routes: Object.keys(zuul).length };
    if (doc && typeof doc === 'object' && '_format_version' in (doc as object)) {
      const services = (get(doc, ['services']) as { routes?: unknown[] }[] | undefined) ?? [];
      const nested = Array.isArray(services) ? services.reduce((n, s) => n + (Array.isArray(s?.routes) ? s.routes.length : 0), 0) : 0;
      const top = get(doc, ['routes']);
      return { kind: 'kong', routes: nested + (Array.isArray(top) ? top.length : 0) };
    }
    const routes = get(doc, ['routes']);
    if (Array.isArray(routes) && (base.includes('apisix') || routes.some((r) => r && typeof r === 'object' && ('upstream' in r || 'upstream_id' in r) && 'uri' in r))) {
      return { kind: 'apisix', routes: routes.length };
    }
    return null;
  }
  if (base.endsWith('.properties')) {
    const scg = new Set([...text.matchAll(/^spring\.cloud\.gateway\.routes\[(\d+)\]/gm)].map((m) => m[1]));
    if (scg.size) return { kind: 'spring_cloud_gateway', routes: scg.size };
    const zuul = new Set([...text.matchAll(/^zuul\.routes\.([^.\s=]+)\./gm)].map((m) => m[1]));
    if (zuul.size) return { kind: 'zuul', routes: zuul.size };
    return null;
  }
  if (base === 'nginx.conf' || base.endsWith('.conf')) {
    const noComments = text.replace(/#[^\n]*/g, '');
    if (!/\bproxy_pass\b/.test(noComments)) return null;
    const locations = [...noComments.matchAll(/\blocation\b[^{]*\{([^{}]*)\}/g)].filter((m) => /\bproxy_pass\b/.test(m[1]!)).length;
    return { kind: 'nginx', routes: locations };
  }
  return null;
}

function isOpenApi(path: string, head: string): boolean {
  const base = path.split('/').pop()!.toLowerCase();
  if (!/\.(ya?ml|json)$/.test(base)) return false;
  if (/^(openapi|swagger)/.test(base)) return true;
  return /^\s*(openapi|swagger)\s*:/m.test(head) || /^\s*\{\s*"(openapi|swagger)"\s*:/.test(head);
}

const uniq = (xs: Iterable<string>) => [...new Set(xs)].sort();
const cap = (xs: string[]) => xs.slice(0, MAX_LIST);

export function computeRepoSignals(view: SnapshotView, index: StructIndex | null, indexStatus: RepoSignals['indexStatus']): RepoSignals {
  const files = view.listFiles();
  const languages: Record<string, number> = {};
  for (const f of files) if (f.lang) languages[f.lang] = (languages[f.lang] ?? 0) + 1;
  const read = (path: string): string | null => {
    const f = view.file(path);
    if (!f || f.size > MAX_TEXT_BYTES) return null;
    try { return view.text(path); } catch { return null; }
  };
  const dir = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');

  const modules: RepoSignals['modules'] = [];
  const appNames: string[] = [];
  const provides: string[] = [];
  const deps: string[] = [];
  const gatewayConfigs: RepoSignals['gatewayConfigs'] = [];
  const persistence = { mapperFiles: 0, daoOrRepositoryFiles: 0, sqlFiles: 0 };
  const contracts = { proto: 0, openapi: 0 };
  const clientCalls = { fetch: 0, axios: 0 };
  let scanned = 0;
  for (const f of files) {
    const p = f.path;
    const base = p.split('/').pop()!;
    if (base === 'pom.xml') {
      const t = read(p);
      if (t) { const pom = parsePom(t); if (pom.provides) provides.push(pom.provides); deps.push(...pom.deps); }
      modules.push({ path: dir(p), lang: 'java', buildFile: base });
    } else if (base === 'build.gradle' || base === 'build.gradle.kts') {
      const t = read(p);
      if (t) deps.push(...parseGradle(t));
      modules.push({ path: dir(p), lang: base.endsWith('.kts') ? 'kotlin' : 'java', buildFile: base });
    } else if (base === 'go.mod') {
      const t = read(p);
      if (t) { const g = parseGoMod(t); if (g.provides) provides.push(g.provides); deps.push(...g.deps); }
      modules.push({ path: dir(p), lang: 'go', buildFile: base });
    } else if (/^requirements[\w.-]*\.txt$/.test(base) || base === 'pyproject.toml') {
      const t = read(p);
      if (t) {
        if (base === 'pyproject.toml') { const py = parsePyproject(t); if (py.provides) provides.push(py.provides); deps.push(...py.deps); }
        else deps.push(...parseRequirements(t));
      }
      if (!modules.some((m) => m.path === dir(p) && m.lang === 'python')) modules.push({ path: dir(p), lang: 'python', buildFile: base });
    } else if (base === 'composer.json' && !p.includes('vendor/')) {
      const t = read(p);
      if (t) { const c = parseComposer(t); if (c.provides) provides.push(c.provides); deps.push(...c.deps); }
      modules.push({ path: dir(p), lang: 'php', buildFile: base });
    } else if (base.endsWith('.csproj')) {
      const t = read(p);
      if (t) { const c = parseCsproj(p, t); if (c.provides) provides.push(c.provides); deps.push(...c.deps); }
      modules.push({ path: dir(p), lang: 'csharp', buildFile: base });
    } else if (base === 'package.json' && !p.includes('node_modules/')) {
      const t = read(p);
      if (t) { const pj = parsePackageJson(t); if (pj.provides) provides.push(pj.provides); deps.push(...pj.deps); }
      modules.push({ path: dir(p), lang: 'javascript', buildFile: base });
    }
    if (/Mapper\.xml$/.test(base) || /\/mappers?\//.test(`/${p}`) && base.endsWith('.xml')) persistence.mapperFiles++;
    if (/(Dao|Repository|Mapper)\.(java|kt|go|cs|php|ts|js)$/.test(base) || /_(dao|repo|repository)\.(go|py)$/.test(base) || /^(repositor(y|ies)|dao|models)\.py$/.test(base)) persistence.daoOrRepositoryFiles++;
    if (base.endsWith('.sql')) persistence.sqlFiles++;
    if (base.endsWith('.proto')) contracts.proto++;
    const configLike = /\.(ya?ml|properties|conf|json)$/.test(base.toLowerCase());
    if (configLike && scanned < MAX_SCANNED) {
      scanned++;
      const t = read(p);
      if (t) {
        if (/^(application|bootstrap)[\w-]*\.(ya?ml|properties)$/.test(base)) {
          if (base.endsWith('.properties')) {
            for (const m of t.matchAll(/^(?:spring|dubbo)\.application\.name\s*[=:]\s*([\w.-]+)\s*$/gm)) appNames.push(m[1]!);
          } else {
            const d = yamlDoc(t);
            for (const v of [get(d, ['spring', 'application', 'name']), get(d, ['dubbo', 'application', 'name'])]) if (typeof v === 'string' && /^[\w.-]{1,100}$/.test(v)) appNames.push(v);
          }
        }
        const g = gatewayConfig(p, t);
        if (g) gatewayConfigs.push({ path: p, ...g });
        if (isOpenApi(p, t.slice(0, 400))) contracts.openapi++;
      }
    } else if (JS_EXT.test(base) && scanned < MAX_SCANNED && !p.includes('node_modules/')) {
      scanned++;
      const t = read(p);
      if (t) {
        clientCalls.fetch += (t.match(/\bfetch\s*\(/g) ?? []).length;
        clientCalls.axios += (t.match(/\baxios\s*(\.\s*(get|post|put|patch|delete|request|create)\s*)?\(/g) ?? []).length;
      }
    }
  }
  const depList = uniq(deps);
  const frontendFrameworks = uniq(depList.filter((d) => d in FRONTEND_DEPS).map((d) => FRONTEND_DEPS[d]!));
  const securityDependencies = depList.filter((d) => SECURITY_DEPS.some((re) => re.test(d)));
  const sinks: Record<string, number> = {};
  const authSignals: Record<string, number> = {};
  const entrypoints = { http: 0, rpc: 0, authRoutes: 0, authRouteSamples: [] as string[] };
  if (index) {
    for (const s of index.sinks) sinks[s.category] = (sinks[s.category] ?? 0) + 1;
    for (const a of index.authSignals) authSignals[a.kind] = (authSignals[a.kind] ?? 0) + 1;
    for (const e of index.entrypoints) {
      if (e.kind === 'http') entrypoints.http++;
      else if (e.kind === 'rpc') entrypoints.rpc++;
      if (e.pathTemplate && AUTH_ROUTE.test(e.pathTemplate)) {
        entrypoints.authRoutes++;
        if (entrypoints.authRouteSamples.length < 8) entrypoints.authRouteSamples.push(e.entryKey);
      }
    }
  }
  for (const c of provides) {
    const last = c.split(/[:/]/).pop();
    if (last && /^[\w.-]{1,100}$/.test(last)) appNames.push(last);
  }
  return {
    fileCount: files.length, appNames: uniq(appNames), languages, modules: modules.slice(0, 100), provides: uniq(provides), dependencies: cap(depList),
    securityDependencies, frontendFrameworks, entrypoints, sinks, authSignals, persistence, gatewayConfigs: gatewayConfigs.slice(0, 50),
    contracts, clientCalls, referencedBy: [], indexStatus,
  };
}

/**
 * Fill `referencedBy`: a repository is referenced by every other repository that declares a dependency
 * on one of its published coordinates (shared_lib signal).
 */
export function linkReferences(repos: { name: string; signals: RepoSignals }[]): void {
  for (const r of repos) {
    const mine = new Set(r.signals.provides);
    r.signals.referencedBy = repos
      .filter((o) => o !== r && o.signals.dependencies.some((d) => mine.has(d) || [...mine].some((m) => d.startsWith(`${m}/`))))
      .map((o) => o.name).sort();
  }
}
