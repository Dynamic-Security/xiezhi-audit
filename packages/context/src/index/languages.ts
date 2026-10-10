// Language plugins of the structure index: one entry per full-audit language — which grammar
// parses a file, which rules apply, the per-file extractor, and how calls resolve across files. Everything
// language-specific in the index goes through this table; `assemble` and `build` stay language-neutral.
//
// Conventions every extractor follows (so identities and call resolution work the same way):
// - symbolId `<repo>:<path>#<container>.<name>(<arity>)`; `container` is `<module or package>.<Class>` for
//   methods and the module / package for top-level functions (`kind: 'func'`). Arity counts declared
//   parameters without the implicit receiver (`self`, `cls`, `this`).
// - `FileExtract.pkg` is the module key top-level functions are grouped by (Go import path, Java package,
//   Python dotted module, PHP / C# namespace, JS module path without extension, Kotlin package).
// - `RawCall.receiverText` is null for bare calls; `receiverImport` names the module an imported name /
//   alias refers to (resolved against `pkg`); `receiverType` is a statically known class name.
import type { Tree } from 'web-tree-sitter';
import { AUDIT_LANGUAGES, auditLanguagesOf, cargoDependencyNames, FULLSTACK_DEPENDENCIES, isRustBackend, isFullstackServerPath, isJsBackend, USE_SERVER_DIRECTIVE_RE, type AuditLanguage, type IndexSymbol } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';
import type { CompiledRule } from './common.js';
import { extractCsharp } from './extract-csharp.js';
import { csharpInputContext } from './extract-csharp-context.js';
import { extractGo } from './extract-go.js';
import { extractJava } from './extract-java.js';
import { javaWebContexts } from './extract-java-web.js';
import { extractJs, jsInputContext, jsResolve } from './extract-js.js';
import { extractKotlin } from './extract-kotlin.js';
import { extractPhp } from './extract-php.js';
import { phpFrameworkContexts } from './extract-php-frameworks.js';
import { extractPython, pythonInputContext } from './extract-python.js';
import { extractRuby } from './extract-ruby.js';
import { rubyInputContext } from './extract-ruby-context.js';
import { extractRust } from './extract-rust.js';
import { rustInputContext } from './extract-rust-context.js';
import type { GrammarLang } from './grammar.js';
import type { ExtractInput, FileExtract, RawCall } from './types.js';

/** Lookup tables built once per index by `assemble`. */
export interface ResolveTables {
  byId: Map<string, IndexSymbol>;
  /** `<name>/<arity>` → callables. */
  byNameArity: Map<string, IndexSymbol[]>;
  /** `<Class>.<name>/<arity>` → methods (class = last segment of the container). */
  byClassNameArity: Map<string, IndexSymbol[]>;
  /** `<pkg>|<name>` → top-level functions (`kind: 'func'`). */
  pkgFuncs: Map<string, IndexSymbol[]>;
}

/** Candidates with whether the match is exact; `external` = a call outside the repository graph (no edge). */
export type CallResolution = { candidates: IndexSymbol[]; exact: boolean } | 'external' | null;

export interface LanguagePlugin {
  id: AuditLanguage;
  /** `rules/<ruleLang>/…` rules apply (TS shares the JavaScript rules). */
  ruleLang: string;
  grammar(path: string): GrammarLang;
  extract(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract;
  /** Language-specific resolution; null falls back to name + arity. */
  resolveCall(call: RawCall, file: FileExtract, t: ResolveTables): CallResolution;
  /** Whether the name + arity fallback may land on top-level functions (not only methods). */
  fallbackToFuncs: boolean;
  /** Extra per-file inputs computed once per snapshot (e.g. the Go module of each file). */
  inputContext?(view: SnapshotView): (path: string) => Partial<ExtractInput>;
}

const classOf = (container: string | undefined) => container?.split('.').pop();
const SELF_RECEIVERS = new Set(['this', 'self', 'super', '$this', 'static', 'parent', 'cls']);

function javaResolve(c: RawCall, f: FileExtract, t: ResolveTables): CallResolution {
  const from = t.byId.get(c.from);
  if (!c.receiverText || c.receiverText === 'this' || c.receiverText === 'super') {
    return { candidates: (t.byClassNameArity.get(`${classOf(from?.container)}.${c.method}/${c.arity}`) ?? []).filter((s) => s.path === f.path), exact: true };
  }
  if (c.receiverType) return { candidates: t.byClassNameArity.get(`${c.receiverType}.${c.method}/${c.arity}`) ?? [], exact: true };
  return null;
}

function goResolve(c: RawCall, f: FileExtract, t: ResolveTables): CallResolution {
  if (!c.receiverText) return { candidates: t.pkgFuncs.get(`${f.pkg}|${c.method}`) ?? [], exact: true };
  if (c.receiverImport) {
    const candidates = t.pkgFuncs.get(`${c.receiverImport}|${c.method}`) ?? [];
    return candidates.length ? { candidates, exact: true } : 'external';
  }
  return null;
}

/**
 * Resolution for the languages beyond Java / Go: bare calls → same-module functions, then methods of the enclosing class
 * (Kotlin / C# / PHP implicit `this`), or the module an imported name refers to; self receivers → the
 * enclosing class; import-alias receivers → that module's functions (none → external); typed receivers →
 * that class's methods.
 */
export function genericResolve(c: RawCall, f: FileExtract, t: ResolveTables): CallResolution {
  const from = t.byId.get(c.from);
  const sameClass = () => (t.byClassNameArity.get(`${classOf(from?.container)}.${c.method}/${c.arity}`) ?? []).filter((s) => s.path === f.path);
  if (!c.receiverText) {
    if (c.receiverImport) {
      const imported = t.pkgFuncs.get(`${c.receiverImport}|${c.method}`) ?? [];
      return imported.length ? { candidates: imported, exact: true } : 'external';
    }
    const local = t.pkgFuncs.get(`${f.pkg}|${c.method}`) ?? [];
    if (local.length) return { candidates: local, exact: true };
    if (from?.kind === 'method') {
      const own = sameClass();
      if (own.length) return { candidates: own, exact: true };
    }
    return null;
  }
  if (SELF_RECEIVERS.has(c.receiverText)) return { candidates: sameClass(), exact: true };
  if (c.receiverImport) {
    const candidates = t.pkgFuncs.get(`${c.receiverImport}|${c.method}`) ?? [];
    if (candidates.length) return { candidates, exact: true };
    const typed = t.byClassNameArity.get(`${c.receiverImport.split(/[./\\]/).pop()}.${c.method}/${c.arity}`) ?? [];
    return typed.length ? { candidates: typed, exact: true } : 'external';
  }
  if (c.receiverType) return { candidates: t.byClassNameArity.get(`${c.receiverType}.${c.method}/${c.arity}`) ?? [], exact: true };
  return null;
}

function goModules(view: SnapshotView): { dir: string; module: string }[] {
  const mods: { dir: string; module: string }[] = [];
  for (const f of view.listFiles()) {
    if (f.path === 'go.mod' || f.path.endsWith('/go.mod')) {
      const m = /^module\s+(\S+)/m.exec(view.text(f.path));
      if (m) mods.push({ dir: f.path === 'go.mod' ? '' : f.path.slice(0, -'/go.mod'.length), module: m[1]! });
    }
  }
  return mods.sort((a, b) => b.dir.length - a.dir.length);
}

/**
 * Go gRPC service implementations per package directory: struct types embedding `UnimplementedXxxServer`
 * and types registered with `RegisterXxxServer(s, &T{})`. Methods often live in other files of the package, so the
 * extractor gets the package's map. Text scan (comments stripped).
 */
function goGrpcTypes(view: SnapshotView): { types: Map<string, Map<string, string>>; interceptors: Map<string, string[]> } {
  const out = new Map<string, Map<string, string>>();
  /** `<package dir>|<Type>` or `svc:<Service>` → interceptors of the server(s) the implementation is registered on. */
  const interceptors = new Map<string, string[]>();
  for (const f of view.listFiles()) {
    if (f.lang !== 'go' || f.size > 2 * 1024 * 1024) continue;
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    if (!/Unimplemented\w+Server|Register\w+Server\s*\(|Interceptor\s*\(/.test(text)) continue;
    const clean = text.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '');
    const dir = f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : '';
    const add = (type: string, svc: string) => { const m = out.get(dir) ?? new Map<string, string>(); m.set(type, svc); out.set(dir, m); };
    for (const s of clean.matchAll(/\btype\s+(\w+)\s+struct\s*\{([^{}]*)\}/g)) {
      const emb = /^\s*\*?(?:\w+\.)?Unimplemented(\w+)Server\s*$/m.exec(s[2]!);
      if (emb) add(s[1]!, emb[1]!);
    }
    for (const r of clean.matchAll(/\bRegister(\w+)Server\s*\(\s*[\w.()]+\s*,\s*&?(\w+)\s*\{/g)) add(r[2]!, r[1]!);
    // Server interceptors (grpc.UnaryInterceptor(x), grpc.ChainUnaryInterceptor(a, b), stream variants) apply to the
    // implementations registered in the same file: `&T{}` → that type in this package, otherwise by service name.
    const local: string[] = [];
    for (const i of clean.matchAll(/\bgrpc\.(?:Chain)?(?:Unary|Stream)Interceptor\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)/g)) {
      const t = `${i[0].split('(')[0]}(${i[1]!.replace(/\s+/g, ' ').trim()})`.slice(0, 160);
      if (!local.includes(t)) local.push(t);
    }
    if (!local.length) continue;
    for (const r of clean.matchAll(/\bRegister(\w+)Server\s*\(\s*[\w.()]+\s*,\s*(&?)([\w.]+)\s*(\{|\()/g)) {
      const literal = r[4] === '{' && !r[3]!.includes('.');
      const key = literal ? `${dir}|${r[3]}` : `svc:${r[1]}`;
      interceptors.set(key, [...new Set([...(interceptors.get(key) ?? []), ...local])]);
    }
  }
  return { types: out, interceptors };
}

/**
 * beego controllers, for router files that register them by type (`beego.Router("/u", &UserController{})`):
 * per type, the exported methods without parameters and the `// @router /p [get,post]` annotations above methods.
 * Only repositories that import beego are scanned; only files mentioning beego get the facts.
 */
interface BeegoFacts { methods: Record<string, string[]>; annotations: Record<string, { method: string; path: string; verbs: string[] }[]> }
function goBeego(view: SnapshotView): BeegoFacts | null {
  const files = view.listFiles().filter((f) => f.lang === 'go' && f.size <= 2 * 1024 * 1024);
  const texts = new Map<string, string>();
  let uses = false;
  for (const f of files) {
    let t: string;
    try { t = view.text(f.path); } catch { continue; }
    if (/"github\.com\/(beego\/beego|astaxie\/beego)/.test(t)) uses = true;
    if (/func\s*\(\s*\w+\s+\*?\w+\s*\)/.test(t)) texts.set(f.path, t);
  }
  if (!uses) return null;
  const facts: BeegoFacts = { methods: {}, annotations: {} };
  for (const t of texts.values()) {
    const lines = t.split('\n');
    let pending: { path: string; verbs: string[] }[] = [];
    for (const line of lines) {
      const ann = /^\s*\/\/\s*@router\s+(\S+)\s*(?:\[([^\]]*)\])?/.exec(line);
      if (ann) { pending.push({ path: ann[1]!, verbs: (ann[2] ?? 'get').split(',').map((v) => v.trim().toUpperCase()).filter(Boolean) }); continue; }
      const fn = /^func\s*\(\s*\w+\s+\*?(\w+)\s*\)\s*([A-Z]\w*)\s*\(\s*\)/.exec(line);
      if (fn) {
        (facts.methods[fn[1]!] ??= []).push(fn[2]!);
        for (const p of pending) (facts.annotations[fn[1]!] ??= []).push({ method: fn[2]!, ...p });
      }
      if (!/^\s*\/\//.test(line) && line.trim()) pending = [];
    }
  }
  return facts;
}

const jsGrammar = (path: string): GrammarLang => (/\.tsx$/.test(path) ? 'tsx' : /\.(ts|mts|cts)$/.test(path) ? 'typescript' : 'javascript');

export const LANGUAGE_PLUGINS: Record<AuditLanguage, LanguagePlugin> = {
  java: {
    id: 'java', ruleLang: 'java', grammar: () => 'java', extract: extractJava, resolveCall: javaResolve, fallbackToFuncs: true,
    // web.xml / struts.xml / @WebFilter facts for servlet and Struts 2 classes.
    inputContext(view) {
      const web = javaWebContexts(view);
      return (path) => { const ctx = web(path); return ctx ? { langContext: ctx as unknown as Record<string, unknown> } : {}; };
    },
  },
  go: {
    id: 'go', ruleLang: 'go', grammar: () => 'go', extract: extractGo, resolveCall: goResolve, fallbackToFuncs: false,
    inputContext(view) {
      const mods = goModules(view);
      const { types: grpc, interceptors } = goGrpcTypes(view);
      const beego = goBeego(view);
      return (path) => {
        const mod = mods.find((m) => m.dir === '' || path.startsWith(m.dir + '/'));
        const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
        const types = grpc.get(dir);
        let beegoCtx: BeegoFacts | null = null;
        if (beego) { try { if (/beego/.test(view.text(path))) beegoCtx = beego; } catch { /* unreadable */ } }
        if (!types) return { ...(mod ? { goModule: mod.module, goModuleDir: mod.dir } : {}), ...(beegoCtx ? { langContext: { beego: beegoCtx } } : {}) };
        // Interceptors of the servers this package's implementations are registered on (by type, else by service).
        const scoped: Record<string, string[]> = {};
        for (const [type, svc] of types) {
          const list = interceptors.get(`${dir}|${type}`) ?? interceptors.get(`svc:${svc}`);
          if (list?.length) scoped[type] = list;
        }
        return { ...(mod ? { goModule: mod.module, goModuleDir: mod.dir } : {}), langContext: { grpcTypes: Object.fromEntries(types), grpcInterceptors: scoped, ...(beegoCtx ? { beego: beegoCtx } : {}) } };
      };
    },
  },
  python: { id: 'python', ruleLang: 'python', grammar: () => 'python', extract: extractPython, resolveCall: genericResolve, fallbackToFuncs: true, inputContext: pythonInputContext },
  javascript: { id: 'javascript', ruleLang: 'javascript', grammar: jsGrammar, extract: extractJs, resolveCall: (c, f, t) => jsResolve(c, f, t, genericResolve), fallbackToFuncs: true, inputContext: jsInputContext },
  typescript: { id: 'typescript', ruleLang: 'javascript', grammar: jsGrammar, extract: extractJs, resolveCall: (c, f, t) => jsResolve(c, f, t, genericResolve), fallbackToFuncs: true, inputContext: jsInputContext },
  php: {
    id: 'php', ruleLang: 'php', grammar: () => 'php', extract: extractPhp, resolveCall: genericResolve, fallbackToFuncs: true,
    // Composer dependencies selecting Slim / CodeIgniter 4 / Yii 2 rules.
    inputContext(view) {
      const fw = phpFrameworkContexts(view);
      return (path) => { const ctx = fw.get(path); return ctx ? { langContext: ctx as unknown as Record<string, unknown> } : {}; };
    },
  },
  kotlin: { id: 'kotlin', ruleLang: 'kotlin', grammar: () => 'kotlin', extract: extractKotlin, resolveCall: genericResolve, fallbackToFuncs: true },
  csharp: { id: 'csharp', ruleLang: 'csharp', grammar: () => 'csharp', extract: extractCsharp, resolveCall: genericResolve, fallbackToFuncs: false, inputContext: csharpInputContext },
  // Ruby (bare calls resolve to methods of the enclosing class) and Rust (module functions, impl methods).
  // controllers, callbacks and mount prefixes across files (extract-ruby-context.ts).
  ruby: { id: 'ruby', ruleLang: 'ruby', grammar: () => 'ruby', extract: extractRuby, resolveCall: genericResolve, fallbackToFuncs: true, inputContext: rubyInputContext },
  // router composition across files (extract-rust-context.ts).
  rust: { id: 'rust', ruleLang: 'rust', grammar: () => 'rust', extract: extractRust, resolveCall: genericResolve, fallbackToFuncs: true, inputContext: rustInputContext },
};

export function pluginFor(lang: string): LanguagePlugin | null {
  return (AUDIT_LANGUAGES as readonly string[]).includes(lang) ? LANGUAGE_PLUGINS[lang as AuditLanguage] : null;
}

const MAX_MANIFEST_BYTES = 512 * 1024;

/** npm dependency names declared by the repository's package.json files (outside node_modules). */
function npmDependencies(view: SnapshotView): string[] {
  const out: string[] = [];
  for (const f of view.listFiles()) {
    if (!(f.path === 'package.json' || f.path.endsWith('/package.json')) || f.path.includes('node_modules/') || f.size > MAX_MANIFEST_BYTES) continue;
    try {
      const j = JSON.parse(view.text(f.path)) as Record<string, Record<string, unknown> | undefined>;
      out.push(...Object.keys(j.dependencies ?? {}), ...Object.keys(j.devDependencies ?? {}), ...Object.keys(j.peerDependencies ?? {}));
    } catch { /* not JSON */ }
  }
  return out;
}

/**
 * Audit languages of a snapshot (drives `is_auditable` and which files the index parses). JS / TS count
 * only for a declared server-side framework, so frontends stay context repositories.
 */
export function auditLanguagesOfView(view: SnapshotView): AuditLanguage[] {
  const byLang = view.manifest.stats.byLang;
  const hasJs = (byLang.javascript ?? 0) + (byLang.typescript ?? 0) > 0;
  // Rust counts only when a Cargo.toml declares a server framework.
  const rustBackend = (byLang.rust ?? 0) > 0 && isRustBackend(cargoDependencies(view));
  if (!hasJs) return auditLanguagesOf(byLang, false, rustBackend);
  const deps = npmDependencies(view);
  return auditLanguagesOf(byLang, isJsBackend(deps) || (deps.some((d) => (FULLSTACK_DEPENDENCIES as readonly string[]).includes(d)) && hasFullstackServerCode(view)), rustBackend);
}

/** Dependency names declared by the repository's Cargo.toml files (outside target/). */
function cargoDependencies(view: SnapshotView): string[] {
  const out: string[] = [];
  for (const f of view.listFiles()) {
    if (!(f.path === 'Cargo.toml' || f.path.endsWith('/Cargo.toml')) || f.size > MAX_MANIFEST_BYTES) continue;
    try { out.push(...cargoDependencyNames(view.text(f.path))); } catch { /* unreadable */ }
  }
  return out;
}

/**
 * a Next.js / Nuxt app is a backend only with server code — API routes, route handlers, Nitro
 * server routes, or a `'use server'` module (Server Actions); a page-only app stays a frontend context repository.
 */
function hasFullstackServerCode(view: SnapshotView): boolean {
  const files = view.listFiles().filter((f) => (f.lang === 'javascript' || f.lang === 'typescript') && !f.path.includes('node_modules/'));
  if (files.some((f) => isFullstackServerPath(f.path))) return true;
  for (const f of files) {
    if (f.size > MAX_MANIFEST_BYTES) continue;
    try { if (USE_SERVER_DIRECTIVE_RE.test(view.text(f.path).slice(0, 2048))) return true; } catch { /* unreadable */ }
  }
  return false;
}

