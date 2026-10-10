// Python extraction: symbols, calls with receiver facts, Flask / FastAPI / Django (+ DRF)
// entries, sinks, auth signals.
//
// Two passes:
// 1. `pythonInputContext` (once per snapshot, text only): a light line scanner over every Python file records
//    module names (package roots from `__init__.py`), classes / methods / functions with arity and decorators,
//    module-level instances, routers (Blueprint / APIRouter / DRF routers) and where they are mounted
//    (`register_blueprint`, `include_router`, Django `include()`), so each file receives the route prefixes and
//    the facts of the modules it imports (cross-file class-based views, decorators of imported view functions).
// 2. `extractPython` (per file, tree-sitter): everything else. Without a context (single-file use) the file's
//    own scan is used, so same-file prefixes still resolve.
import type { Node, Tree } from 'web-tree-sitter';
import type { AuthSignal } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';
import { AUTH_NAME_RE, captureMap, fillApi, makeSink, rangeOf, ruleMatches, type CompiledRule } from './common.js';
import { rpcOf } from './proto.js';
import { emptyExtract, joinRoute, type ExtractInput, type FileExtract, type HandlerRef, type RawEntry } from './types.js';

// ---- per-snapshot facts (text scan) -------------------------------------------------------------------------

export interface PyFunc { arity: number; min: number; varargs: boolean; decorators: string[] }
export interface PyClass { bases: string[]; methods: Record<string, PyFunc>; decorators: string[]; attrs: Record<string, string> }
export interface PyModuleFacts { path: string; classes: Record<string, PyClass>; funcs: Record<string, PyFunc>; instances: Record<string, string> }
export interface PyRouter { framework: 'flask' | 'fastapi' | 'drf'; prefixes: string[]; middlewares: string[] }

/** Per-file context handed to the extractor through `ExtractInput.langContext`. */
export interface PythonContext {
  module: string;
  isInit: boolean;
  /** Facts of this module and of the repository modules it imports. */
  modules: Record<string, PyModuleFacts>;
  /** `from x import y` names that are repository modules (`x.y`). */
  submodules: string[];
  /** Local names (defined or imported) that are routers, with their resolved prefixes and middlewares. */
  routers: Record<string, PyRouter>;
  /** Django: prefixes under which this module's `urlpatterns` are included. */
  modulePrefixes: string[];
  /** Channels consumer classes routed anywhere in the snapshot (`websocket_urlpatterns`, `URLRouter`). */
  wsRouted?: string[];
}

interface RawImport { from: string | null; names: { name: string; alias: string }[] }
interface RawRouter { varName: string; ctor: string; prefix: string; deps: string[] }
/** kind `mount`: `parent.register_blueprint / include_router(target, prefix)`; `include`: Django include / router urls. */
interface RawMount { kind: 'mount' | 'include'; parent: string; target: string; prefix: string | null; deps: string[] }
interface FileScan { facts: PyModuleFacts; imports: RawImport[]; routers: RawRouter[]; mounts: RawMount[]; hooks: { varName: string; fn: string }[]; wsRouted: string[] }

interface LLine { indent: number; text: string }
const MAX_LOGICAL_LINE = 20_000;

/** Logical lines: comments dropped, bracketed / backslash continuations joined, triple-quoted strings emptied. */
function logicalLines(src: string): LLine[] {
  const out: LLine[] = [];
  let buf = '';
  let depth = 0;
  let indent = 0;
  let triple: string | null = null;
  for (const raw of src.split('\n')) {
    const l = raw.replace(/\r$/, '');
    if (!buf && !triple) {
      if (/^\s*(#|$)/.test(l)) continue;
      indent = l.length - l.trimStart().length;
    }
    let s = '';
    let j = 0;
    while (j < l.length) {
      if (triple) {
        const k = l.indexOf(triple, j);
        if (k < 0) break;
        j = k + 3;
        triple = null;
        s += '""';
        continue;
      }
      const ch = l[j]!;
      if (ch === '#') break;
      if (l.startsWith('"""', j) || l.startsWith("'''", j)) { triple = l.slice(j, j + 3); j += 3; continue; }
      if (ch === '"' || ch === "'") {
        let k = j + 1;
        while (k < l.length && l[k] !== ch) k += l[k] === '\\' ? 2 : 1;
        s += l.slice(j, k + 1);
        j = k + 1;
        continue;
      }
      if (ch === '(' || ch === '[' || ch === '{') depth++;
      else if (ch === ')' || ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
      s += ch;
      j++;
    }
    const cont = /\\\s*$/.test(s);
    buf += (buf ? ' ' : '') + s.replace(/\\\s*$/, '').trim();
    // An unbalanced bracket must not turn the rest of a large file into one line (quadratic scans).
    if ((triple || depth > 0 || cont) && buf.length < MAX_LOGICAL_LINE) continue;
    depth = 0;
    triple = null;
    if (buf.trim()) out.push({ indent, text: buf.trim() });
    buf = '';
  }
  if (buf.trim()) out.push({ indent, text: buf.trim() });
  return out;
}

/** Split at top-level commas (outside brackets and strings). */
function splitTop(s: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = '';
  let q: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]!;
    if (q) {
      cur += ch;
      if (ch === '\\') { cur += s[++i] ?? ''; continue; }
      if (ch === q) q = null;
      continue;
    }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    if (ch === ',' && depth === 0) { if (cur.trim()) out.push(cur.trim()); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

/** Text inside the brackets opening at `open`. */
function balanced(s: string, open: number): string | null {
  let depth = 0;
  let q: string | null = null;
  for (let i = open; i < s.length; i++) {
    const ch = s[i]!;
    if (q) { if (ch === '\\') i++; else if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") q = ch;
    else if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') { depth--; if (depth === 0) return s.slice(open + 1, i); }
  }
  return null;
}

function splitArgs(argText: string): { pos: string[]; kw: Map<string, string> } {
  const pos: string[] = [];
  const kw = new Map<string, string>();
  for (const p of splitTop(argText)) {
    const m = /^(\w+)\s*=(?!=)\s*([\s\S]*)$/.exec(p);
    if (m) kw.set(m[1]!, m[2]!.trim());
    else if (!p.startsWith('*')) pos.push(p);
  }
  return { pos, kw };
}

/** A plain string literal (no f-string); adjacent literals are joined. */
function strLit(expr: string | undefined): string | null {
  if (expr === undefined) return null;
  let rest = expr.trim();
  let out = '';
  let any = false;
  while (rest) {
    const m = /^([rRbBuU]{0,2})(['"])((?:\\.|(?!\2).)*)\2\s*/.exec(rest);
    if (!m) return null;
    out += m[3];
    any = true;
    rest = rest.slice(m[0].length);
  }
  return any ? out : null;
}

const depsOf = (text: string | undefined): string[] => [...(text ?? '').matchAll(/\b(Depends|Security)\(\s*([\w.]*)/g)].map((m) => `${m[1]}(${m[2]})`);

function funcFacts(params: string, dropFirst: boolean, decorators: string[]): PyFunc {
  let arity = 0;
  let min = 0;
  let varargs = false;
  let kwOnly = false;
  splitTop(params).forEach((p, i) => {
    const name = p.split(/[:=]/)[0]!.trim();
    if (i === 0 && dropFirst && (name === 'self' || name === 'cls')) return;
    if (name === '/') return;
    if (name === '*') { kwOnly = true; return; }
    if (name.startsWith('**')) { varargs = true; return; }
    if (name.startsWith('*')) { varargs = true; kwOnly = true; return; }
    arity++;
    if (!p.includes('=') && !kwOnly) min++;
  });
  return { arity, min, varargs, decorators };
}

const ROUTER_CTORS: Record<string, PyRouter['framework']> = {
  // Sanic apps / blueprints share Flask's prefix handling (`url_prefix`); entries are reported as `sanic`.
  Sanic: 'flask',
  Blueprint: 'flask', Flask: 'flask', Api: 'flask', APIRouter: 'fastapi', FastAPI: 'fastapi', DefaultRouter: 'drf', SimpleRouter: 'drf',
};

/** Line-based scan of one Python file (no tree): structure, imports, routers and mounts. */
export function scanPython(src: string): FileScan {
  const facts: PyModuleFacts = { path: '', classes: {}, funcs: {}, instances: {} };
  const scan: FileScan = { facts, imports: [], routers: [], mounts: [], hooks: [], wsRouted: [] };
  const stack: { indent: number; kind: 'class' | 'def'; name: string }[] = [];
  let decorators: string[] = [];
  for (const ll of logicalLines(src)) {
    while (stack.length && stack[stack.length - 1]!.indent >= ll.indent) stack.pop();
    const t = ll.text;
    const top = stack[stack.length - 1];
    if (t.startsWith('@')) { decorators.push(t.slice(1).trim().slice(0, 200)); continue; }
    let m = /^(?:async\s+)?def\s+(\w+)\s*\(/.exec(t);
    if (m) {
      const params = balanced(t, m[0].length - 1) ?? '';
      const inClass = top?.kind === 'class' && stack.length === 1;
      const f = funcFacts(params, inClass && !decorators.some((d) => /^staticmethod\b/.test(d)), decorators);
      if (!top) facts.funcs[m[1]!] ??= f;
      else if (inClass) facts.classes[top.name]!.methods[m[1]!] ??= f;
      for (const d of decorators) {
        const hm = /^(\w+)\.(before_request|before_app_request)$/.exec(d);
        if (hm) scan.hooks.push({ varName: hm[1]!, fn: m[1]! });
      }
      stack.push({ indent: ll.indent, kind: 'def', name: m[1]! });
      decorators = [];
      continue;
    }
    m = /^class\s+(\w+)\s*([(:])/.exec(t);
    if (m) {
      const bases = m[2] === '(' ? splitTop(balanced(t, t.indexOf('(')) ?? '').filter((b) => !/^\w+\s*=/.test(b)) : [];
      if (!top) facts.classes[m[1]!] ??= { bases, methods: {}, decorators, attrs: {} };
      stack.push({ indent: ll.indent, kind: 'class', name: m[1]! });
      decorators = [];
      continue;
    }
    decorators = [];
    if (top?.kind === 'class' && stack.length === 1) {
      const am = /^(\w+)\s*(?::[^=]*)?=(?!=)\s*(.+)$/.exec(t);
      if (am) facts.classes[top.name]!.attrs[am[1]!] = am[2]!.slice(0, 300);
    }
    if (!stack.some((s) => s.kind === 'class')) {
      const im = /^(\w+)\s*(?::\s*[\w.[\], ]+)?=\s*(?:\w+\.)*([A-Z]\w*)\s*\(/.exec(t);
      if (im && !top) facts.instances[im[1]!] = im[2]!;
      const rm = /^(\w+)\s*(?::[^=]+)?=\s*(?:\w+\.)*(Blueprint|APIRouter|FastAPI|Flask|Api|DefaultRouter|SimpleRouter)\s*\(/.exec(t);
      if (rm) {
        const { pos, kw } = splitArgs(balanced(t, rm[0].length - 1) ?? '');
        const prefix = rm[2] === 'Blueprint' ? strLit(kw.get('url_prefix')) : rm[2] === 'APIRouter' || rm[2] === 'Api' ? strLit(kw.get('prefix')) : null;
        void pos;
        scan.routers.push({ varName: rm[1]!, ctor: rm[2]!, prefix: prefix ?? '', deps: depsOf(kw.get('dependencies')) });
      }
    }
    if ((m = /^import\s+(.+)$/.exec(t))) {
      for (const part of splitTop(m[1]!)) {
        const am = /^([\w.]+)(?:\s+as\s+(\w+))?$/.exec(part);
        if (am) scan.imports.push({ from: null, names: [{ name: am[1]!, alias: am[2] ?? am[1]!.split('.')[0]! }] });
      }
    } else if ((m = /^from\s+(\S+)\s+import\s+(.+)$/.exec(t))) {
      const names = splitTop(m[2]!.replace(/^\(|\)$/g, '')).map((p) => /^(\w+)(?:\s+as\s+(\w+))?$/.exec(p)).filter((x): x is RegExpExecArray => !!x)
        .map((x) => ({ name: x[1]!, alias: x[2] ?? x[1]! }));
      scan.imports.push({ from: m[1]!, names });
    }
    for (const mm of t.matchAll(/([\w.]+)\.(register_blueprint|include_router)\s*\(/g)) {
      const { pos, kw } = splitArgs(balanced(t, mm.index! + mm[0].length - 1) ?? '');
      if (!pos[0]) continue;
      const pk = mm[2] === 'register_blueprint' ? 'url_prefix' : 'prefix';
      scan.mounts.push({ kind: 'mount', parent: mm[1]!, target: pos[0], prefix: kw.has(pk) ? strLit(kw.get(pk)) ?? '{?}' : null, deps: depsOf(kw.get('dependencies')) });
    }
    for (const mm of t.matchAll(/\b(path|re_path|url)\s*\(/g)) {
      const inner = balanced(t, mm.index! + mm[0].length - 1);
      if (!inner) continue;
      const { pos } = splitArgs(inner);
      const view = pos[1] ?? '';
      const inc = /^include\s*\(/.exec(view);
      if (!inc) continue;
      const route = strLit(pos[0]);
      if (route === null) continue;
      const incArgs = splitTop(balanced(view, view.indexOf('(')) ?? '');
      let target = incArgs[0] ?? '';
      if (target.startsWith('(')) target = splitTop(target.slice(1, -1))[0] ?? '';
      scan.mounts.push({ kind: 'include', parent: '', target, prefix: mm[1] === 'path' ? route : regexRoute(route), deps: [] });
    }
    if (/^urlpatterns\b/.test(t)) {
      for (const mm of t.matchAll(/(\w+)\.urls\b/g)) {
        if (/include\s*\(\s*\(?\s*$/.test(t.slice(0, mm.index))) continue;
        scan.mounts.push({ kind: 'include', parent: '', target: `${mm[1]}.urls`, prefix: '', deps: [] });
      }
    }
    const hc = /^(\w+)\.(before_request|before_app_request)\s*\(\s*(\w+)\s*\)$/.exec(t);
    if (hc) scan.hooks.push({ varName: hc[1]!, fn: hc[3]! });
    // Channels consumers named in WebSocket routing (`X.as_asgi()`, Channels 2 `path("ws/", XConsumer)`).
    if (/^websocket_urlpatterns\b/.test(t) || /\bURLRouter\s*\(/.test(t)) {
      for (const mm of t.matchAll(/\b(\w+)\s*\.\s*as_asgi\b/g)) scan.wsRouted.push(mm[1]!);
      for (const mm of t.matchAll(/\b(?:re_)?path\s*\(\s*[rRuU]?(['"])[^'"]*\1\s*,\s*(?:\w+\.)*(\w*Consumer)\s*[,)]/g)) scan.wsRouted.push(mm[2]!);
    }
  }
  return scan;
}

/** Django `re_path` / `url` regex → route template (`(?P<pk>\d+)` → `{pk}`). */
export function regexRoute(re: string): string {
  let s = re.replace(/^\^/, '').replace(/\$$/, '');
  s = s.replace(/\(\?P<(\w+)>(?:[^()]|\([^()]*\))*\)/g, '{$1}').replace(/\((?:[^()]|\([^()]*\))*\)/g, '{}');
  return s.replace(/\\(.)/g, '$1').replace(/[?*+]$/, '');
}

/** Dotted module of a file: package chain from `__init__.py` directories, else the path (leading `src/` stripped). */
export function pythonModuleOf(path: string, initDirs?: ReadonlySet<string>): string {
  const parts = path.replace(/\.pyi?$/, '').split('/');
  const last = parts.length - 1;
  let root = last;
  if (initDirs) while (root > 0 && initDirs.has(parts.slice(0, root).join('/'))) root--;
  let mod = root < last ? parts.slice(root) : (parts[0] === 'src' && parts.length > 1 ? parts.slice(1) : parts);
  if (mod[mod.length - 1] === '__init__' && mod.length > 1) mod = mod.slice(0, -1);
  return mod.join('.');
}

function resolveRelative(from: string, module: string, isInit: boolean): string {
  const m = /^(\.*)(.*)$/.exec(from)!;
  const level = m[1]!.length;
  if (level === 0) return from;
  let pkg = module.split('.');
  if (!isInit) pkg = pkg.slice(0, -1);
  pkg = pkg.slice(0, Math.max(0, pkg.length - (level - 1)));
  return [...pkg, ...(m[2] ? m[2].split('.') : [])].join('.');
}

interface Alias { module: string; name: string | null }

function aliasesOf(imports: RawImport[], module: string, isInit: boolean, isModule: (m: string) => boolean): Map<string, Alias> {
  const out = new Map<string, Alias>();
  for (const imp of imports) {
    if (imp.from === null) {
      for (const n of imp.names) out.set(n.alias, { module: n.alias === n.name.split('.')[0] ? n.alias : n.name, name: null });
    } else {
      const mod = resolveRelative(imp.from, module, isInit);
      for (const n of imp.names) out.set(n.alias, isModule(`${mod}.${n.name}`) ? { module: `${mod}.${n.name}`, name: null } : { module: mod, name: n.name });
    }
  }
  return out;
}

const MAX_PREFIXES = 8;

/** Snapshot-wide scan → per-file contexts (module names, imported facts, router prefixes, Django includes). */
export function pythonInputContext(view: SnapshotView): (path: string) => Partial<ExtractInput> {
  const files = view.listFiles().filter((f) => f.lang === 'python' && f.path.endsWith('.py') && f.size <= 2 * 1024 * 1024);
  const initDirs = new Set(files.filter((f) => f.path === '__init__.py' || f.path.endsWith('/__init__.py')).map((f) => f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : ''));
  const byModule = new Map<string, { path: string; isInit: boolean; scan: FileScan }>();
  const moduleOfPath = new Map<string, string>();
  for (const f of files) {
    const module = pythonModuleOf(f.path, initDirs);
    moduleOfPath.set(f.path, module);
    if (byModule.has(module)) continue;
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    let scan: FileScan;
    try { scan = scanPython(text); } catch { continue; }
    scan.facts.path = f.path;
    byModule.set(module, { path: f.path, isInit: /(^|\/)__init__\.py$/.test(f.path), scan });
  }
  const isModule = (m: string) => byModule.has(m);
  const wsRouted = [...new Set([...byModule.values()].flatMap((e) => e.scan.wsRouted))];
  const findModule = (m: string): string | null => {
    if (byModule.has(m)) return m;
    const hits = [...byModule.keys()].filter((k) => k.endsWith(`.${m}`));
    return hits.length === 1 ? hits[0]! : null;
  };
  const aliasCache = new Map<string, Map<string, Alias>>();
  const aliases = (module: string) => {
    let a = aliasCache.get(module);
    if (!a) {
      const e = byModule.get(module);
      a = e ? aliasesOf(e.scan.imports, module, e.isInit, isModule) : new Map();
      aliasCache.set(module, a);
    }
    return a;
  };
  /** Router key `<module>:<var>` of an expression in `module` (`bp`, `views.bp`, `router.urls` → router). */
  const keyOf = (module: string, expr: string): string | null => {
    const parts = expr.trim().replace(/\.urls$/, '').split('.');
    if (!parts.every((p) => /^\w+$/.test(p))) return null;
    const a = aliases(module).get(parts[0]!);
    if (parts.length === 1) return a ? (a.name ? `${a.module}:${a.name}` : null) : `${module}:${parts[0]}`;
    if (!a) return null;
    const mod = [a.name ? `${a.module}.${a.name}` : a.module, ...parts.slice(1, -1)].join('.');
    return `${mod}:${parts[parts.length - 1]}`;
  };
  const routers = new Map<string, { framework: PyRouter['framework']; own: string; deps: string[] }>();
  const mountsInto = new Map<string, { from: string; prefix: string | null; deps: string[] }[]>();
  for (const [module, e] of byModule) {
    for (const r of e.scan.routers) routers.set(`${module}:${r.varName}`, { framework: ROUTER_CTORS[r.ctor]!, own: r.prefix, deps: [...r.deps] });
  }
  for (const [module, e] of byModule) {
    for (const h of e.scan.hooks) {
      const k = keyOf(module, h.varName);
      const r = k ? routers.get(k) : undefined;
      if (r) r.deps.push(`before_request:${h.fn}`);
    }
    for (const m of e.scan.mounts) {
      let target: string | null;
      let from: string | null;
      if (m.kind === 'include') {
        const lit = strLit(m.target);
        const mod = lit !== null ? findModule(lit) : null;
        target = lit !== null ? (mod ? `${mod}:` : null) : keyOf(module, m.target);
        from = `${module}:`;
      } else {
        target = keyOf(module, m.target);
        from = keyOf(module, m.parent);
      }
      if (!target || !from || target === from) continue;
      const list = mountsInto.get(target) ?? [];
      list.push({ from, prefix: m.prefix, deps: m.deps });
      mountsInto.set(target, list);
    }
  }
  const memo = new Map<string, { prefix: string; mw: string[] }[]>();
  const full = (key: string, seen: Set<string>): { prefix: string; mw: string[] }[] => {
    const cached = memo.get(key);
    if (cached) return cached;
    const info = routers.get(key);
    const own = info?.own ?? '';
    const mounts = seen.has(key) ? [] : mountsInto.get(key) ?? [];
    let out: { prefix: string; mw: string[] }[];
    if (!mounts.length) out = [{ prefix: own, mw: info?.deps ?? [] }];
    else {
      out = [];
      const next = new Set(seen).add(key);
      for (const m of mounts) {
        for (const p of full(m.from, next)) {
          const local = info?.framework === 'flask' ? (m.prefix ?? own) : info?.framework === 'fastapi' ? joinRoute(m.prefix ?? '', own) : (m.prefix ?? '');
          out.push({ prefix: joinRoute(p.prefix, local), mw: [...p.mw, ...m.deps, ...(info?.deps ?? [])] });
          if (out.length >= MAX_PREFIXES) break;
        }
        if (out.length >= MAX_PREFIXES) break;
      }
    }
    memo.set(key, out);
    return out;
  };
  return (path) => {
    const module = moduleOfPath.get(path) ?? pythonModuleOf(path, initDirs);
    const e = byModule.get(module);
    if (!e || e.path !== path) return { langContext: contextFromScan(scanFromSelf(path), module, /(^|\/)__init__\.py$/.test(path)) as unknown as Record<string, unknown> };
    const a = aliases(module);
    const modules: Record<string, PyModuleFacts> = { [module]: e.scan.facts };
    const submodules: string[] = [];
    for (const al of a.values()) {
      const m = byModule.get(al.module);
      if (m) modules[al.module] = m.scan.facts;
      if (!al.name && al.module.includes('.')) submodules.push(al.module);
    }
    const ctxRouters: Record<string, PyRouter> = {};
    const names = new Set([...e.scan.routers.map((r) => r.varName), ...a.keys()]);
    for (const n of names) {
      const k = keyOf(module, n);
      const info = k ? routers.get(k) : undefined;
      if (!k || !info) continue;
      const f = full(k, new Set());
      ctxRouters[n] = { framework: info.framework, prefixes: [...new Set(f.map((x) => x.prefix))], middlewares: [...new Set(f.flatMap((x) => x.mw))] };
    }
    const mp = mountsInto.has(`${module}:`) ? [...new Set(full(`${module}:`, new Set()).map((x) => x.prefix))] : [''];
    const ctx: PythonContext = { module, isInit: e.isInit, modules, submodules, routers: ctxRouters, modulePrefixes: mp, wsRouted };
    return { langContext: ctx as unknown as Record<string, unknown> };
  };
  function scanFromSelf(path: string): FileScan {
    try { return scanPython(view.text(path)); } catch { return scanPython(''); }
  }
}

/** Context of a file on its own (no snapshot scan): same-file routers and prefixes only. */
function contextFromScan(scan: FileScan, module: string, isInit: boolean): PythonContext {
  const routers: Record<string, PyRouter> = {};
  for (const r of scan.routers) routers[r.varName] = { framework: ROUTER_CTORS[r.ctor]!, prefixes: [r.prefix], middlewares: [...r.deps] };
  for (const h of scan.hooks) routers[h.varName]?.middlewares.push(`before_request:${h.fn}`);
  for (const m of scan.mounts) {
    if (m.kind !== 'mount') continue;
    const r = routers[m.target];
    const parent = routers[m.parent];
    if (!r || !parent || m.target === m.parent) continue;
    const local = r.framework === 'flask' ? (m.prefix ?? r.prefixes[0]!) : joinRoute(m.prefix ?? '', r.prefixes[0]!);
    r.prefixes = parent.prefixes.map((p) => joinRoute(p, local));
    r.middlewares = [...parent.middlewares, ...m.deps, ...r.middlewares];
  }
  for (const m of scan.mounts) {
    if (m.kind !== 'include' || !/^\w+\.urls$/.test(m.target)) continue;
    const r = routers[m.target.slice(0, -'.urls'.length)];
    if (r) r.prefixes = r.prefixes.map((p) => joinRoute(m.prefix ?? '', p));
  }
  scan.facts.path ||= '';
  return { module, isInit, modules: { [module]: scan.facts }, submodules: [], routers, modulePrefixes: [''], wsRouted: scan.wsRouted };
}

// ---- tree helpers ---------------------------------------------------------------------------------------------

const named = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c && c.type !== 'comment');

/** Literal value of a plain string node (no interpolation); null otherwise. */
function stringValue(n: Node | null | undefined, consts?: Map<string, string>): string | null {
  if (!n) return null;
  if (n.type === 'string') {
    if (n.namedChildren.some((c) => c?.type === 'interpolation')) return null;
    return n.namedChildren.filter((c) => c?.type === 'string_content' || c?.type === 'escape_sequence').map((c) => c!.text).join('');
  }
  if (n.type === 'concatenated_string') {
    const parts = named(n).map((c) => stringValue(c, consts));
    return parts.every((p) => p !== null) ? parts.join('') : null;
  }
  if (n.type === 'binary_operator' && n.childForFieldName('operator')?.text === '+') {
    const l = stringValue(n.childForFieldName('left'), consts);
    const r = stringValue(n.childForFieldName('right'), consts);
    return l !== null && r !== null ? l + r : null;
  }
  if (n.type === 'parenthesized_expression') return stringValue(named(n)[0], consts);
  if (n.type === 'identifier' && consts?.has(n.text)) return consts.get(n.text)!;
  return null;
}

function stringList(n: Node | null | undefined): string[] | null {
  if (!n) return null;
  if (n.type === 'list' || n.type === 'tuple' || n.type === 'set') {
    const vals = named(n).map((c) => stringValue(c));
    return vals.every((v) => v !== null) ? (vals as string[]) : null;
  }
  const s = stringValue(n);
  return s === null ? null : [s];
}

interface CallArgs { pos: Node[]; kw: Map<string, Node>; splat: boolean }
function callArgs(args: Node | null | undefined): CallArgs {
  const out: CallArgs = { pos: [], kw: new Map(), splat: false };
  for (const a of named(args)) {
    if (a.type === 'keyword_argument') {
      const k = a.childForFieldName('name')?.text;
      const v = a.childForFieldName('value');
      if (k && v) out.kw.set(k, v);
    } else if (a.type === 'list_splat' || a.type === 'dictionary_splat') out.splat = true;
    else out.pos.push(a);
  }
  return out;
}

const firstLineOf = (node: Node): string => {
  const body = node.childForFieldName('body');
  const text = body ? node.text.slice(0, body.startIndex - node.startIndex) : node.text;
  const s = text.replace(/\s+/g, ' ').trim().replace(/:$/, '');
  return s.length > 300 ? `${s.slice(0, 300)}…` : s;
};

const clip = (s: string, n = 200) => { const t = s.replace(/\s+/g, ' ').trim(); return t.length > n ? `${t.slice(0, n)}…` : t; };

function decoratorTexts(def: Node): string[] {
  const p = def.parent;
  if (p?.type !== 'decorated_definition') return [];
  return named(p).filter((c) => c.type === 'decorator').map((d) => clip(d.text.replace(/^@\s*/, ''), 160));
}

/** Declared arity of a `parameters` node (without self / cls, splats and separators). */
function paramArity(params: Node | null, dropFirst: boolean): { arity: number; min: number; varargs: boolean } {
  let arity = 0;
  let min = 0;
  let varargs = false;
  let kwOnly = false;
  named(params).forEach((p, i) => {
    const t = p.type;
    const inner = t === 'typed_parameter' ? named(p)[0] : null;
    if (t === 'list_splat_pattern' || inner?.type === 'list_splat_pattern') { varargs = true; kwOnly = true; return; }
    if (t === 'dictionary_splat_pattern' || inner?.type === 'dictionary_splat_pattern') { varargs = true; return; }
    if (t === 'keyword_separator') { kwOnly = true; return; }
    if (t === 'positional_separator') return;
    const name = t === 'identifier' ? p.text : (p.childForFieldName('name')?.text ?? named(p)[0]?.text ?? '');
    if (i === 0 && dropFirst && (name === 'self' || name === 'cls')) return;
    arity++;
    if ((t === 'identifier' || t === 'typed_parameter') && !kwOnly) min++;
  });
  return { arity, min, varargs };
}

/** Class name of a type annotation (`Optional[X]`, `"X"`, `Annotated[X, …]`, `pkg.X`). */
function typeName(n: Node | null | undefined): string | null {
  if (!n) return null;
  let t = n.text.replace(/^['"]|['"]$/g, '').trim();
  for (;;) {
    const m = /^(?:typing\.)?(Optional|Annotated|Type)\[(.*)\]$/.exec(t);
    if (!m) break;
    t = splitTop(m[2]!)[0] ?? '';
  }
  t = t.split('|')[0]!.trim();
  const last = t.split('.').pop() ?? '';
  return /^[A-Z]\w*$/.test(last) ? last : null;
}

const PY_BUILTINS = new Set(('abs all any ascii bin bool breakpoint bytearray bytes callable chr classmethod compile complex delattr dict dir divmod '
  + 'enumerate eval exec filter float format frozenset getattr globals hasattr hash help hex id input int isinstance issubclass iter len list '
  + 'locals map max memoryview min next object oct open ord pow print property range repr reversed round set setattr slice sorted '
  + 'staticmethod str sum super tuple type vars zip __import__').split(' '));

const HTTP_METHOD_NAMES = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];
const ROUTE_DECORATOR_RE = /^[\w.]+\.(route|get|post|put|delete|patch|head|options|api_route|websocket)\s*\(|^(api_view|action|swagger_auto_schema|extend_schema)\b/;
const PY_AUTH_EXTRA = /_required\b|current_user|current_active|require_(?!http|GET|POST|safe)|requires_|oauth|api_?key|principal|IsAuthenticated|IsAdmin|permission|staff|superuser|LoginRequired|user_passes_test/i;
export const isPyAuth = (s: string): boolean => !/\bAllowAny\b|csrf_exempt/.test(s) && (AUTH_NAME_RE.test(s) || PY_AUTH_EXTRA.test(s));

/** Django / DRF generic views: HTTP methods served by a base class without explicit handlers. */
const BASE_METHODS: [RegExp, string[]][] = [
  [/(^|\.)(ListCreateAPIView)$/, ['GET', 'POST']],
  [/(^|\.)(RetrieveUpdateDestroyAPIView)$/, ['GET', 'PUT', 'PATCH', 'DELETE']],
  [/(^|\.)(RetrieveUpdateAPIView)$/, ['GET', 'PUT', 'PATCH']],
  [/(^|\.)(RetrieveDestroyAPIView)$/, ['GET', 'DELETE']],
  [/(^|\.)(ListAPIView|RetrieveAPIView|ListView|DetailView|TemplateView|RedirectView|ArchiveIndexView|YearArchiveView|MonthArchiveView)$/, ['GET']],
  [/(^|\.)(CreateAPIView)$/, ['POST']],
  [/(^|\.)(UpdateAPIView)$/, ['PUT', 'PATCH']],
  [/(^|\.)(DestroyAPIView)$/, ['DELETE']],
  [/(^|\.)(CreateView|UpdateView|FormView|DeleteView|LoginView|PasswordChangeView)$/, ['GET', 'POST']],
];
const VIEWSET_ACTIONS: Record<string, { method: string; detail: boolean }> = {
  list: { method: 'GET', detail: false }, create: { method: 'POST', detail: false }, retrieve: { method: 'GET', detail: true },
  update: { method: 'PUT', detail: true }, partial_update: { method: 'PATCH', detail: true }, destroy: { method: 'DELETE', detail: true },
};
function inheritedActions(bases: string[]): string[] {
  const b = bases.map((x) => x.split('.').pop() ?? x);
  if (b.includes('ModelViewSet')) return Object.keys(VIEWSET_ACTIONS);
  const out: string[] = [];
  if (b.includes('ReadOnlyModelViewSet')) out.push('list', 'retrieve');
  if (b.includes('ListModelMixin')) out.push('list');
  if (b.includes('CreateModelMixin')) out.push('create');
  if (b.includes('RetrieveModelMixin')) out.push('retrieve');
  if (b.includes('UpdateModelMixin')) out.push('update', 'partial_update');
  if (b.includes('DestroyModelMixin')) out.push('destroy');
  return out;
}

/** Methods named by Django view decorators (`require_POST`, `require_http_methods([...])`, `api_view([...])`). */
function methodsFromDecorators(decorators: string[]): string[] | null {
  for (const d of decorators) {
    if (/^require_GET\b|^require_safe\b/.test(d)) return ['GET'];
    if (/^require_POST\b/.test(d)) return ['POST'];
    const m = /^(?:require_http_methods|api_view)\s*\(\s*\[([^\]]*)\]/.exec(d);
    if (m) return [...m[1]!.matchAll(/['"](\w+)['"]/g)].map((x) => x[1]!.toUpperCase());
    if (/^api_view\s*\(\s*\)|^api_view$/.test(d)) return ['GET'];
  }
  return null;
}

type Taint = 'string_concat' | 'constant' | undefined;

// ---- extractor ------------------------------------------------------------------------------------------------

export function extractPython(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const isInitFile = /(^|\/)__init__\.pyi?$/.test(input.path);
  const ctx = (input.langContext as PythonContext | undefined) ?? contextFromScan(scanPython(input.text), pythonModuleOf(input.path), isInitFile);
  const pkg = ctx.module;
  fx.pkg = pkg;
  const root = tree.rootNode;
  const repo = input.repo;
  const ownFacts = ctx.modules[pkg];

  // ---- imports ----
  const aliases = new Map<string, Alias>();
  const imports = new Set<string>();
  const addImport = (m: string) => { const parts = m.split('.'); for (let i = 1; i <= parts.length; i++) imports.add(parts.slice(0, i).join('.')); };
  const submodules = new Set(ctx.submodules);
  const isRepoModule = (m: string) => submodules.has(m) || !!ctx.modules[m];
  for (const n of root.descendantsOfType(['import_statement', 'import_from_statement'])) {
    if (!n) continue;
    if (n.type === 'import_statement') {
      for (const c of named(n)) {
        if (c.type === 'dotted_name') { const head = c.text.split('.')[0]!; aliases.set(head, { module: head, name: null }); addImport(c.text); }
        else if (c.type === 'aliased_import') {
          const name = c.childForFieldName('name')?.text;
          const alias = c.childForFieldName('alias')?.text;
          if (name && alias) { aliases.set(alias, { module: name, name: null }); addImport(name); }
        }
      }
    } else {
      const modNode = n.childForFieldName('module_name');
      if (!modNode) continue;
      const mod = resolveRelative(modNode.text.replace(/\s+/g, ''), pkg, isInitFile);
      if (mod) addImport(mod);
      for (const c of named(n)) {
        if (c.id === modNode.id) continue;
        let name: string | undefined;
        let alias: string | undefined;
        if (c.type === 'dotted_name') { name = c.text; alias = c.text; }
        else if (c.type === 'aliased_import') { name = c.childForFieldName('name')?.text; alias = c.childForFieldName('alias')?.text; }
        if (!name || !alias) continue;
        const full = mod ? `${mod}.${name}` : name;
        addImport(full);
        aliases.set(alias, isRepoModule(full) ? { module: full, name: null } : { module: mod, name });
      }
    }
  }

  // ---- symbols ----
  interface ClassInfo { dotted: string; symbolId: string; node: Node; bases: string[]; methods: Map<string, { id: string; node: Node; arity: number; min: number; varargs: boolean }>; fields: Map<string, string> }
  const classes = new Map<number, ClassInfo>();
  const classByName = new Map<string, ClassInfo>();
  const funcIds = new Map<number, string>();
  const moduleFuncs = new Map<string, { id: string; node: Node; arity: number; min: number; varargs: boolean }>();
  const seenIds = new Set<string>();
  const pushSymbol = (s: FileExtract['symbols'][number]) => { if (!seenIds.has(s.symbolId)) { seenIds.add(s.symbolId); fx.symbols.push(s); } };
  // Iterative walk: error-heavy parses can nest thousands of levels deep.
  const work: [Node, ClassInfo | null, boolean][] = [[root, null, false]];
  const pushChildren = (nodes: Node[], cls: ClassInfo | null, inFunc: boolean) => { for (let i = nodes.length - 1; i >= 0; i--) work.push([nodes[i]!, cls, inFunc]); };
  while (work.length) {
    const [node, cls, inFunc] = work.pop()!;
    if (node.type === 'class_definition' && !inFunc) {
      const name = node.childForFieldName('name')?.text ?? '?';
      const dotted = cls ? `${cls.dotted}.${name}` : name;
      const symbolId = `${repo}:${input.path}#${pkg}.${dotted}`;
      const bases = named(node.childForFieldName('superclasses')).filter((b) => b.type !== 'keyword_argument').map((b) => b.text);
      const info: ClassInfo = { dotted, symbolId, node, bases, methods: new Map(), fields: new Map() };
      classes.set(node.id, info);
      if (!cls) classByName.set(name, info);
      pushSymbol({
        symbolId, repo, kind: bases.some((b) => /(^|\.)Protocol$/.test(b)) ? 'interface' : 'class', name, container: cls ? `${pkg}.${cls.dotted}` : pkg,
        path: input.path, range: rangeOf(node.parent?.type === 'decorated_definition' ? node.parent : node), signature: firstLineOf(node), qualifiedName: `${pkg}.${dotted}`,
      });
      pushChildren(named(node.childForFieldName('body')), info, false);
      continue;
    }
    if (node.type === 'function_definition') {
      if (!inFunc) {
        const name = node.childForFieldName('name')?.text ?? '?';
        const isStatic = decoratorTexts(node).some((d) => /^staticmethod\b/.test(d));
        const a = paramArity(node.childForFieldName('parameters'), !!cls && !isStatic);
        const container = cls ? `${pkg}.${cls.dotted}` : pkg;
        const symbolId = `${repo}:${input.path}#${container}.${name}(${a.arity})`;
        funcIds.set(node.id, symbolId);
        const rec = { id: symbolId, node, ...a };
        if (cls) { if (!cls.methods.has(name)) cls.methods.set(name, rec); } else if (!moduleFuncs.has(name)) moduleFuncs.set(name, rec);
        pushSymbol({
          symbolId, repo, kind: cls ? 'method' : 'func', name, container, path: input.path,
          range: rangeOf(node.parent?.type === 'decorated_definition' ? node.parent : node), signature: firstLineOf(node),
          qualifiedName: `${container}.${name}`,
        });
      }
      pushChildren(named(node.childForFieldName('body')), null, true);
      continue;
    }
    pushChildren(named(node), cls, inFunc);
  }

  /** Enclosing function / class / symbol of a node; memoized along the parent chain (linear on deep trees). */
  interface Scope { def: Node | null; cls: ClassInfo | null; symbol: string | null }
  const TOP: Scope = { def: null, cls: null, symbol: null };
  const scopeCache = new Map<number, Scope>();
  const scopeOf = (node: Node): Scope => {
    const path: Node[] = [];
    let base = TOP;
    for (let cur = node.parent; cur; cur = cur.parent) {
      const c = scopeCache.get(cur.id);
      if (c) { base = c; break; }
      path.push(cur);
    }
    for (let i = path.length - 1; i >= 0; i--) {
      const p = path[i]!;
      if (p.type === 'decorator') base = { ...base, symbol: null };
      else if (p.type === 'function_definition' && funcIds.has(p.id)) base = { def: p, cls: base.cls, symbol: funcIds.get(p.id)! };
      else if (p.type === 'class_definition' && classes.has(p.id)) base = { def: base.def, cls: classes.get(p.id)!, symbol: classes.get(p.id)!.symbolId };
      scopeCache.set(p.id, base);
    }
    return base;
  };
  const enclosingDef = (node: Node): Node | null => scopeOf(node).def;
  const enclosingClass = (node: Node): ClassInfo | null => scopeOf(node).cls;
  const enclosingSymbol = (node: Node): string | null => scopeOf(node).symbol;

  // ---- module constants, assignments and types ----
  const consts = new Map<string, string>();
  const moduleTypes = new Map<string, string>();
  const ctorType = (v: Node | null | undefined): string | null => {
    if (v?.type === 'boolean_operator') return ctorType(v.childForFieldName('right')) ?? ctorType(v.childForFieldName('left'));
    if (v?.type === 'conditional_expression') return named(v).map(ctorType).find((t) => !!t) ?? null;
    if (v?.type !== 'call') return null;
    const f = v.childForFieldName('function');
    const last = f?.type === 'identifier' ? f.text : f?.type === 'attribute' ? f.childForFieldName('attribute')?.text : null;
    return last && /^[A-Z]\w*$/.test(last) ? last : null;
  };
  for (const st of named(root)) {
    const a = st.type === 'expression_statement' ? named(st)[0] : null;
    if (a?.type !== 'assignment') continue;
    const left = a.childForFieldName('left');
    if (left?.type !== 'identifier') continue;
    const right = a.childForFieldName('right');
    const s = stringValue(right);
    if (s !== null) consts.set(left.text, s);
    const t = ctorType(right) ?? typeName(a.childForFieldName('type'));
    if (t) moduleTypes.set(left.text, t);
  }
  // Class field types: `self.x = Cls(...)`, `self.x: Cls`, `self.x = param` (annotated), class-level `x = Cls()`.
  for (const info of classes.values()) {
    for (const st of named(info.node.childForFieldName('body'))) {
      const a = st.type === 'expression_statement' ? named(st)[0] : null;
      if (a?.type === 'assignment' && a.childForFieldName('left')?.type === 'identifier') {
        const t = ctorType(a.childForFieldName('right')) ?? typeName(a.childForFieldName('type'));
        if (t) info.fields.set(a.childForFieldName('left')!.text, t);
      }
    }
    for (const m of info.methods.values()) {
      const params = new Map<string, string>();
      for (const p of named(m.node.childForFieldName('parameters'))) {
        const pn = p.childForFieldName('name')?.text ?? named(p)[0]?.text;
        const t = typeName(p.childForFieldName('type'));
        if (pn && t) params.set(pn, t);
      }
      for (const a of m.node.descendantsOfType('assignment')) {
        const left = a?.childForFieldName('left');
        if (left?.type !== 'attribute' || left.childForFieldName('object')?.text !== 'self') continue;
        const right = a!.childForFieldName('right');
        const t = ctorType(right) ?? typeName(a!.childForFieldName('type')) ?? (right?.type === 'identifier' ? params.get(right.text) ?? null : null);
        const field = left.childForFieldName('attribute')?.text;
        if (field && t && !info.fields.has(field)) info.fields.set(field, t);
      }
    }
  }
  const localTypeCache = new Map<number, Map<string, string>>();
  const localTypes = (def: Node): Map<string, string> => {
    let m = localTypeCache.get(def.id);
    if (m) return m;
    m = new Map();
    for (const p of named(def.childForFieldName('parameters'))) {
      const pn = p.childForFieldName('name')?.text ?? named(p)[0]?.text;
      const t = typeName(p.childForFieldName('type'));
      if (pn && t) m.set(pn, t);
    }
    for (const a of def.descendantsOfType('assignment')) {
      const left = a?.childForFieldName('left');
      if (left?.type !== 'identifier') continue;
      const t = ctorType(a!.childForFieldName('right')) ?? typeName(a!.childForFieldName('type'));
      if (t) m.set(left.text, t);
    }
    localTypeCache.set(def.id, m);
    return m;
  };
  // Assignments per scope for taint (`sql = f"…"; cursor.execute(sql)`).
  const assignCache = new Map<number, Map<string, { rhs: Node; aug: boolean; pos: number }[]>>();
  const assignmentsIn = (scope: Node): Map<string, { rhs: Node; aug: boolean; pos: number }[]> => {
    let m = assignCache.get(scope.id);
    if (m) return m;
    m = new Map();
    const nodes = scope.type === 'module' ? named(scope).flatMap((s) => (s.type === 'expression_statement' ? named(s) : [])) : scope.descendantsOfType(['assignment', 'augmented_assignment']).filter((x): x is Node => !!x);
    for (const a of nodes) {
      if (a.type !== 'assignment' && a.type !== 'augmented_assignment') continue;
      const left = a.childForFieldName('left');
      const rhs = a.childForFieldName('right');
      if (left?.type !== 'identifier' || !rhs) continue;
      const list = m.get(left.text) ?? [];
      list.push({ rhs, aug: a.type === 'augmented_assignment', pos: a.startIndex });
      m.set(left.text, list);
    }
    assignCache.set(scope.id, m);
    return m;
  };

  const isStringy = (n: Node | null | undefined): boolean => !!n && (n.type === 'string' || n.type === 'concatenated_string'
    || (n.type === 'binary_operator' && (isStringy(n.childForFieldName('left')) || isStringy(n.childForFieldName('right')))));
  const exprTaint = (n: Node | null | undefined, depth = 0): Taint => {
    if (!n || depth > 4) return undefined;
    switch (n.type) {
      case 'string': return n.namedChildren.some((c) => c?.type === 'interpolation') ? 'string_concat' : 'constant';
      case 'concatenated_string': return named(n).some((c) => exprTaint(c, depth + 1) === 'string_concat') ? 'string_concat' : 'constant';
      case 'integer': case 'float': case 'true': case 'false': case 'none': return 'constant';
      case 'parenthesized_expression': case 'keyword_argument': return exprTaint(n.type === 'keyword_argument' ? n.childForFieldName('value') : named(n)[0], depth + 1);
      case 'binary_operator': {
        const op = n.childForFieldName('operator')?.text;
        const l = n.childForFieldName('left');
        const r = n.childForFieldName('right');
        const lt = exprTaint(l, depth + 1);
        const rt = exprTaint(r, depth + 1);
        if (lt === 'constant' && rt === 'constant') return 'constant';
        if (lt === 'string_concat' || rt === 'string_concat') return 'string_concat';
        if ((op === '+' || op === '%') && (isStringy(l) || isStringy(r))) return 'string_concat';
        return undefined;
      }
      case 'call': {
        const f = n.childForFieldName('function');
        if (f?.type === 'attribute') {
          const attr = f.childForFieldName('attribute')?.text ?? '';
          const obj = f.childForFieldName('object');
          if ((attr === 'format' || attr === 'format_map' || attr === 'join') && (isStringy(obj) || exprTaint(obj, depth + 1) === 'constant')) {
            return attr === 'join' || named(n.childForFieldName('arguments')).length > 0 ? 'string_concat' : 'constant';
          }
        }
        if (f && /^(text|(?:sa|sqlalchemy)\.text|SQL|sql\.SQL)$/.test(f.text)) return exprTaint(named(n.childForFieldName('arguments'))[0], depth + 1);
        return undefined;
      }
      case 'list': case 'tuple': {
        const ts = named(n).map((c) => exprTaint(c, depth + 1));
        if (ts.includes('string_concat')) return 'string_concat';
        return ts.length && ts.every((t) => t === 'constant') ? 'constant' : undefined;
      }
      case 'identifier': {
        const def = enclosingDef(n);
        const found = [...(def ? assignmentsIn(def).get(n.text) ?? [] : []), ...(assignmentsIn(root).get(n.text) ?? [])].filter((a) => a.pos < n.startIndex);
        if (!found.length) return undefined;
        const ts = found.map((a) => { const t = exprTaint(a.rhs, depth + 1); return a.aug && t === undefined ? 'string_concat' : t; });
        if (ts.includes('string_concat')) return 'string_concat';
        return ts.every((t) => t === 'constant') ? 'constant' : undefined;
      }
      default: return undefined;
    }
  };
  const argsTaint = (args: Node | undefined, firstOnly: boolean): Taint => {
    if (!args) return undefined;
    if (args.type !== 'argument_list') return exprTaint(args);
    const a = callArgs(args);
    const items = firstOnly ? [a.pos[0] ?? a.kw.get('sql') ?? a.kw.get('query') ?? a.kw.get('url') ?? a.kw.get('statement')].filter((x): x is Node => !!x) : [...a.pos, ...a.kw.values()];
    if (!items.length) return undefined;
    const ts = items.map((x) => exprTaint(x));
    if (ts.includes('string_concat')) return 'string_concat';
    return !a.splat && ts.every((t) => t === 'constant') ? 'constant' : undefined;
  };

  // ---- receiver facts ----
  const factsClass = (name: string): { module: string; cls: PyClass } | null => {
    for (const [module, f] of Object.entries(ctx.modules)) {
      if (module === pkg) continue;
      const c = f.classes[name];
      if (c) return { module, cls: c };
    }
    return null;
  };
  const moduleOfExpr = (n: Node): string | null => {
    const parts = n.text.split('.');
    if (!parts.every((p) => /^\w+$/.test(p))) return null;
    const a = aliases.get(parts[0]!);
    if (!a) return null;
    if (a.name) {
      // `from lxml import etree`: an external lowercase name used as a receiver is taken as a submodule.
      if (/^[A-Z]/.test(a.name) || ctx.modules[a.module]) return null;
      return [`${a.module}.${a.name}`, ...parts.slice(1)].join('.');
    }
    return [a.module, ...parts.slice(1)].join('.');
  };
  const receiverTypeOf = (n: Node, at: Node): string | null => {
    if (n.type === 'call') {
      if (n.childForFieldName('function')?.text === 'super') return enclosingClass(at)?.bases[0]?.split('.').pop() ?? null;
      return ctorType(n);
    }
    if (n.type === 'attribute' && n.childForFieldName('object')?.text === 'self') {
      const field = n.childForFieldName('attribute')?.text ?? '';
      return enclosingClass(at)?.fields.get(field) ?? null;
    }
    if (n.type !== 'identifier') return null;
    const def = enclosingDef(at);
    const local = def ? localTypes(def).get(n.text) : undefined;
    if (local) return local;
    const cls = enclosingClass(at);
    if (n.text === 'cls' && cls) return null;
    const mt = moduleTypes.get(n.text);
    if (mt) return mt;
    if (classByName.has(n.text)) return n.text;
    const a = aliases.get(n.text);
    if (a?.name) {
      if (/^[A-Z]/.test(a.name)) return a.name;
      const inst = ctx.modules[a.module]?.instances[a.name];
      if (inst) return inst;
    }
    return null;
  };
  const builtinOrImport = (name: string): string | null => {
    const a = aliases.get(name);
    if (a) return a.name ? a.module : a.module;
    if (moduleFuncs.has(name) || classByName.has(name) || consts.has(name) || moduleTypes.has(name)) return null;
    return PY_BUILTINS.has(name) ? 'builtins' : null;
  };
  const methodFacts = (className: string, method: string): { arity: number; min: number; varargs: boolean } | null => {
    const local = classByName.get(className)?.methods.get(method);
    if (local) return local;
    return factsClass(className)?.cls.methods[method] ?? null;
  };
  const fitArity = (argc: number, splat: boolean, f: { arity: number; min: number; varargs: boolean } | null | undefined): number =>
    (f && (splat || (argc >= f.min && (argc <= f.arity || f.varargs))) ? f.arity : argc);

  // ---- calls ----
  for (const call of root.descendantsOfType('call')) {
    if (!call) continue;
    const from = enclosingSymbol(call);
    if (!from) continue;
    const fn = call.childForFieldName('function');
    const argsNode = call.childForFieldName('arguments');
    const a = argsNode?.type === 'argument_list' ? callArgs(argsNode) : { pos: argsNode ? [argsNode] : [], kw: new Map(), splat: false };
    const argc = a.pos.length + a.kw.size;
    const line = call.startPosition.row + 1;
    if (fn?.type === 'identifier') {
      const name = fn.text;
      if (/^[A-Z]/.test(name) && (classByName.has(name) || aliases.get(name)?.name)) {
        const init = methodFacts(name, '__init__');
        if (init) fx.calls.push({ from, method: '__init__', receiverText: name, receiverType: name, receiverImport: null, arity: fitArity(argc, a.splat, init), line, calleeText: name });
        continue;
      }
      const imp = builtinOrImport(name);
      const local = moduleFuncs.get(name);
      const importedFacts = aliases.get(name)?.name ? ctx.modules[aliases.get(name)!.module]?.funcs[aliases.get(name)!.name!] : undefined;
      fx.calls.push({ from, method: name, receiverText: null, receiverType: null, receiverImport: imp, arity: fitArity(argc, a.splat, local ?? importedFacts), line, calleeText: name });
    } else if (fn?.type === 'attribute') {
      const method = fn.childForFieldName('attribute')?.text;
      const obj = fn.childForFieldName('object');
      if (!method || !obj) continue;
      const receiverText = clip(obj.type === 'call' && obj.childForFieldName('function')?.text === 'super' ? 'super()' : obj.text);
      const receiverImport = obj.type === 'identifier' || obj.type === 'attribute' ? moduleOfExpr(obj) : null;
      const receiverType = receiverImport ? null : receiverTypeOf(obj, call);
      let arity = argc;
      if (receiverText === 'self' || receiverText === 'cls') {
        const cls = enclosingClass(call);
        arity = fitArity(argc, a.splat, cls?.methods.get(method));
      } else if (receiverImport) {
        arity = fitArity(argc, a.splat, ctx.modules[receiverImport]?.funcs[method]);
      } else if (receiverType) {
        arity = fitArity(argc, a.splat, methodFacts(receiverType, method));
      }
      fx.calls.push({ from, method, receiverText, receiverType, receiverImport, arity, line, calleeText: clip(fn.text) });
    }
  }

  // ---- handlers, decorators and auth ----
  const handlerOfNode = (def: Node): { ref: HandlerRef; decorators: string[]; deps: string[] } => {
    const id = funcIds.get(def.id);
    const deps: string[] = [];
    for (const p of named(def.childForFieldName('parameters'))) {
      const v = p.childForFieldName('value');
      const t = p.childForFieldName('type');
      for (const n of [v, t]) {
        if (!n) continue;
        for (const m of n.text.matchAll(/\b(Depends|Security)\(\s*([\w.]*)/g)) deps.push(`${m[1]}(${m[2]})`);
      }
    }
    return { ref: { ...(id ? { symbolId: id } : {}), range: rangeOf(def) }, decorators: decoratorTexts(def), deps };
  };
  const classAuth = (c: { bases: string[]; decorators: string[]; attrs: Record<string, string> }): string[] => {
    const out: string[] = [];
    for (const d of c.decorators) if (!ROUTE_DECORATOR_RE.test(d)) out.push(`@${d}`);
    for (const b of c.bases) if (/(LoginRequired|PermissionRequired|UserPassesTest|Staff|Superuser)\w*Mixin/.test(b)) out.push(b);
    for (const k of ['permission_classes', 'authentication_classes', 'decorators', 'method_decorators']) if (c.attrs[k]) out.push(`${k} = ${clip(c.attrs[k]!, 120)}`);
    return out;
  };
  const localClassFacts = (info: ClassInfo): { bases: string[]; decorators: string[]; attrs: Record<string, string> } => {
    const f = ownFacts?.classes[info.dotted];
    const attrs: Record<string, string> = { ...(f?.attrs ?? {}) };
    for (const st of named(info.node.childForFieldName('body'))) {
      const a = st.type === 'expression_statement' ? named(st)[0] : null;
      const left = a?.type === 'assignment' ? a.childForFieldName('left') : null;
      if (left?.type === 'identifier' && a!.childForFieldName('right')) attrs[left.text] = clip(a!.childForFieldName('right')!.text, 300);
    }
    return { bases: info.bases, decorators: decoratorTexts(info.node), attrs };
  };

  /** A view reference: local / imported function, `module.func`, or a wrapper call around one. */
  interface ViewRef { kind: 'func' | 'class'; name: string; module: string | null; local: boolean; wrappers: string[]; text: string }
  const viewRef = (n: Node, wrappers: string[] = []): ViewRef | null => {
    if (n.type === 'call') {
      const f = n.childForFieldName('function');
      const args = callArgs(n.childForFieldName('arguments'));
      if (f?.type === 'attribute' && f.childForFieldName('attribute')?.text === 'as_view') {
        const inner = viewRef(f.childForFieldName('object')!, wrappers);
        return inner ? { ...inner, kind: 'class' } : null;
      }
      if (f && args.pos.length >= 1 && /^(\w+\.)*\w+$/.test(f.text)) return viewRef(args.pos[args.pos.length - 1]!, [...wrappers, clip(f.text, 80)]);
      if (f?.type === 'call' && args.pos.length === 1) return viewRef(args.pos[0]!, [...wrappers, clip(f.text, 80)]);
      return null;
    }
    if (n.type === 'identifier') {
      const a = aliases.get(n.text);
      if (a?.name) return { kind: /^[A-Z]/.test(a.name) ? 'class' : 'func', name: a.name, module: a.module, local: false, wrappers, text: n.text };
      return { kind: classByName.has(n.text) ? 'class' : 'func', name: n.text, module: pkg, local: true, wrappers, text: n.text };
    }
    if (n.type === 'attribute') {
      const obj = n.childForFieldName('object');
      const name = n.childForFieldName('attribute')?.text ?? '';
      const mod = obj ? moduleOfExpr(obj) : null;
      if (mod) return { kind: /^[A-Z]/.test(name) ? 'class' : 'func', name, module: mod, local: false, wrappers, text: n.text };
      return { kind: 'func', name, module: null, local: false, wrappers, text: n.text };
    }
    return null;
  };

  interface Resolved { method: string; ref: HandlerRef; middlewares: string[]; suffix?: string }
  const funcHandler = (v: ViewRef): { ref: HandlerRef; decorators: string[] } => {
    if (v.local) {
      const f = moduleFuncs.get(v.name);
      if (f) return { ref: handlerOfNode(f.node).ref, decorators: decoratorTexts(f.node) };
      return { ref: { text: v.text }, decorators: [] };
    }
    const facts = v.module ? ctx.modules[v.module]?.funcs[v.name] : undefined;
    return { ref: { text: v.text.includes('.') ? v.text : v.name, ...(v.module ? { importPath: v.module } : {}) }, decorators: facts?.decorators ?? [] };
  };
  /** HTTP methods of a class-based view with their handler references and class / method level decorators. */
  const classHandlers = (v: ViewRef, mode: 'view' | 'viewset' | 'falcon', suffix?: string): Resolved[] | null => {
    const local = v.local ? classByName.get(v.name) : undefined;
    const remote = !local && v.module ? ctx.modules[v.module]?.classes[v.name] : undefined;
    if (!local && !remote) return null;
    const cf = local ? localClassFacts(local) : { bases: remote!.bases, decorators: remote!.decorators, attrs: remote!.attrs };
    const classMw = classAuth(cf);
    const methodNames = local ? [...local.methods.keys()] : Object.keys(remote!.methods);
    const methodDecorators = (m: string): string[] => (local ? decoratorTexts(local.methods.get(m)!.node) : remote!.methods[m]!.decorators);
    const classRef = (): HandlerRef => (local
      ? { symbolId: local.symbolId, range: rangeOf(local.node) }
      : { symbolId: `${repo}:${ctx.modules[v.module!]!.path}#${v.module}.${v.name}` });
    const methodRef = (m: string): HandlerRef => (local
      ? { symbolId: local.methods.get(m)!.id, range: rangeOf(local.methods.get(m)!.node) }
      : { text: `${v.name}.${m}`, importPath: v.module! });
    const out: Resolved[] = [];
    const mw = (m: string | null) => [...v.wrappers, ...classMw, ...(m ? methodDecorators(m).filter((d) => !ROUTE_DECORATOR_RE.test(d)).map((d) => `@${d}`) : [])];
    if (mode === 'falcon') {
      // falcon responders `on_get` / `on_post` (… `on_get_<suffix>` with `add_route(…, suffix=…)`).
      for (const hm of HTTP_METHOD_NAMES) {
        const name = suffix ? `on_${hm}_${suffix}` : `on_${hm}`;
        if (methodNames.includes(name)) out.push({ method: hm.toUpperCase(), ref: methodRef(name), middlewares: mw(name) });
      }
      return out;
    }
    if (mode === 'view') {
      const defined = HTTP_METHOD_NAMES.filter((m) => methodNames.includes(m));
      for (const m of defined) out.push({ method: m.toUpperCase(), ref: methodRef(m), middlewares: mw(m) });
      if (!defined.length) {
        const inherited = BASE_METHODS.find(([re]) => cf.bases.some((b) => re.test(b)))?.[1];
        for (const m of inherited ?? ['ANY']) out.push({ method: m, ref: classRef(), middlewares: mw(null) });
      }
      return out;
    }
    const actions = new Set([...Object.keys(VIEWSET_ACTIONS).filter((a) => methodNames.includes(a)), ...inheritedActions(cf.bases)]);
    for (const act of Object.keys(VIEWSET_ACTIONS)) {
      if (!actions.has(act)) continue;
      const spec = VIEWSET_ACTIONS[act]!;
      const defined = methodNames.includes(act);
      out.push({ method: spec.method, ref: defined ? methodRef(act) : classRef(), middlewares: mw(defined ? act : null), suffix: spec.detail ? '{pk}' : '' });
    }
    for (const m of methodNames) {
      const act = methodDecorators(m).find((d) => /^action\b/.test(d));
      if (!act) continue;
      const argText = /^action\s*\(([\s\S]*)\)$/.exec(act)?.[1] ?? '';
      const { kw } = splitArgs(argText);
      const detail = /True/.test(kw.get('detail') ?? '');
      const urlPath = strLit(kw.get('url_path')) ?? m;
      const methods = [...(kw.get('methods') ?? "['get']").matchAll(/['"](\w+)['"]/g)].map((x) => x[1]!.toUpperCase());
      for (const hm of methods.length ? methods : ['GET']) out.push({ method: hm, ref: methodRef(m), middlewares: mw(m), suffix: detail ? `{pk}/${urlPath}` : urlPath });
    }
    return out;
  };

  const pushEntry = (ruleId: string, framework: string, method: string, path: string, ref: HandlerRef, at: Node, middlewares: string[]) => {
    const mws = [...new Set(middlewares)];
    const e: RawEntry = {
      ruleId, framework, httpMethod: method, pathTemplate: path, handler: ref, path: input.path, range: rangeOf(at),
      // sanic-jwt / sanic-ext decorators (`@protected()`, `@scoped(…)`) do not match the generic auth names.
      middlewares: mws, authSignals: mws.filter((m) => isPyAuth(m) || (framework === 'sanic' && /^@(protected|scoped|authorized)\b/.test(m))),
    };
    fx.entries.push(e);
  };

  const routerOf = (n: Node | undefined): { name: string; framework: PyRouter['framework'] | null; prefixes: string[]; middlewares: string[] } | null => {
    if (!n) return null;
    const r = ctx.routers[n.text];
    if (r) return { name: n.text, ...r };
    if (n.type !== 'identifier' && n.type !== 'attribute') return null;
    const fw = imports.has('fastapi') ? 'fastapi' : imports.has('flask') ? 'flask' : null;
    return { name: n.text, framework: fw, prefixes: [''], middlewares: [] };
  };

  const addAuth = (sig: AuthSignal) => {
    if (!fx.authSignals.some((s) => s.target === sig.target && s.detail === sig.detail)) fx.authSignals.push(sig);
  };
  const defTarget = (def: Node): string | null => (def.type === 'function_definition' ? funcIds.get(def.id) ?? null : def.type === 'class_definition' ? classes.get(def.id)?.symbolId ?? null : null);

  // ---- rules ----
  const seenSinks = new Set<string>();
  for (const { rule, query, error } of rules) {
    if (error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${error}` }); continue; }
    if (!query) continue;
    if (rule.match?.requiresImportAny && !rule.match.requiresImportAny.some((i) => imports.has(i))) continue;
    if (rule.match?.notImportAny?.some((i) => imports.has(i))) continue;
    try {
      for (const match of query.matches(root)) {
        const cap = captureMap(match.captures, rule.captures);
        if (rule.kind === 'sink') {
          const node = cap.get('call');
          if (!node) continue;
          const receiver = cap.get('receiver') ?? null;
          const methodNode = cap.get('method') ?? cap.get('field') ?? null;
          const argsNode = cap.get('args') ?? cap.get('value');
          const method = methodNode?.text ?? '';
          let receiverImport: string | null;
          let receiverType: string | null = null;
          if (receiver) {
            receiverImport = receiver.type === 'identifier' || receiver.type === 'attribute' ? moduleOfExpr(receiver) : null;
            if (!receiverImport) receiverType = receiverTypeOf(receiver, node);
          } else receiverImport = builtinOrImport(method);
          const a = argsNode?.type === 'argument_list' ? callArgs(argsNode) : { pos: argsNode ? [argsNode] : [], kw: new Map<string, Node>(), splat: false };
          if (!ruleMatches(rule.match, { receiverText: receiver?.text ?? null, receiverType, receiverImport, imports, argCount: a.pos.length + a.kw.size })) continue;
          let api = fillApi(rule.api ?? '', { method, receiver: receiver ? clip(receiver.text, 80) : '', module: receiverImport ?? (receiver ? clip(receiver.text, 80) : ''), type: receiverType ?? '' });
          let taint = argsTaint(argsNode, rule.category !== 'business_logic' && rule.category !== 'authz_object');
          if (!sinkPost(rule.post, { method, receiver, a, node, text: input.text })) continue;
          if (rule.post === 'python_subprocess') {
            const shell = a.kw.get('shell');
            if (shell && shell.text !== 'False') api += ' shell=True';
          }
          if (rule.category === 'authz_object' || rule.category === 'business_logic') taint = undefined;
          const sink = makeSink(repo, input.path, rule, node, enclosingSymbol(node), clip(api, 200), taint);
          if (!seenSinks.has(sink.sinkId)) { seenSinks.add(sink.sinkId); fx.sinks.push(sink); }
        } else if (rule.kind === 'entrypoint') {
          handleEntry(rule.id, rule.post, rule.framework, cap);
        } else if (rule.kind === 'auth_signal') {
          handleAuth(rule.id, rule.post, cap);
        }
      }
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${(e as Error).message}` });
    }
  }
  try { channelEntries(); } catch (e) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `python.channels: ${(e as Error).message}` }); }
  grpcServicers();
  return fx;

  function handleEntry(ruleId: string, post: string | undefined, framework: string, cap: Map<string, Node>): void {
    const call = cap.get('call');
    if (!call) return;
    const args = callArgs(cap.get('args'));
    if (post === 'python_flask_route' || post === 'python_fastapi_route' || post === 'python_sanic_route') {
      const verb = cap.get('verb')?.text ?? '';
      const r = routerOf(cap.get('router'));
      const def = cap.get('handler');
      if (!r || !def || def.type !== 'function_definition') return;
      const sanic = imports.has('sanic');
      // in a Sanic file the Flask-shaped router (Sanic / Blueprint) is reported by the Sanic rule.
      if (post === 'python_flask_route' && sanic) return;
      const fw = post === 'python_sanic_route' ? (sanic && r.framework !== 'fastapi' ? 'sanic' : null) : r.framework ?? (verb === 'route' ? 'flask' : null);
      if (!fw) return;
      if (post === 'python_flask_route' ? fw !== 'flask' : post === 'python_fastapi_route' ? fw !== 'fastapi' : false) return;
      if (verb === 'websocket') return; // WebSocket routes are channel entries (channelEntries)
      const path = stringValue(args.pos[0] ?? args.kw.get('path') ?? args.kw.get('rule'), consts);
      if (path === null) return;
      if ((fw === 'flask' || fw === 'sanic') && !path.startsWith('/') && path !== '') return;
      const listed = stringList(args.kw.get('methods'));
      const methods = verb === 'route' || verb === 'api_route' ? (listed?.map((m) => m.toUpperCase()) ?? [verb === 'route' ? 'GET' : 'ANY']) : [verb.toUpperCase()];
      const h = handlerOfNode(def);
      const decoratorMw = h.decorators.filter((d) => !ROUTE_DECORATOR_RE.test(d)).map((d) => `@${d}`);
      const routeDeps = depsOf(args.kw.get('dependencies')?.text);
      for (const prefix of r.prefixes) {
        for (const m of methods) pushEntry(ruleId, fw, m, joinRoute(prefix, path), h.ref, def, [...r.middlewares, ...routeDeps, ...decoratorMw, ...h.deps]);
      }
      return;
    }
    if (post === 'python_tornado_app' || post === 'python_aiohttp_route' || post === 'python_falcon_route') {
      frameworkRoute(ruleId, post, call, args);
      return;
    }
    if (post === 'python_aiohttp_decorator') {
      aiohttpDecorated(ruleId, cap);
      return;
    }
    if (post === 'python_flask_add_url_rule') {
      const verb = cap.get('verb')?.text ?? '';
      const r = routerOf(cap.get('router'));
      if (!r || (r.framework && r.framework !== 'flask') || (!r.framework && !imports.has('flask'))) return;
      if (verb === 'add_resource') {
        const v = args.pos[0] ? viewRef(args.pos[0]) : null;
        const hs = v ? classHandlers(v, 'view') : null;
        if (!hs) return;
        for (const urlNode of args.pos.slice(1)) {
          const url = stringValue(urlNode, consts);
          if (url === null) continue;
          for (const prefix of r.prefixes) for (const h of hs) pushEntry(ruleId, 'flask', h.method, joinRoute(prefix, url), h.ref, call, [...r.middlewares, ...h.middlewares]);
        }
        return;
      }
      const url = stringValue(args.pos[0] ?? args.kw.get('rule'), consts);
      const viewNode = args.pos[2] ?? args.kw.get('view_func');
      if (url === null || !viewNode) return;
      const v = viewRef(viewNode);
      if (!v) return;
      const listed = stringList(args.kw.get('methods'))?.map((m) => m.toUpperCase());
      const hs: Resolved[] = v.kind === 'class'
        ? classHandlers(v, 'view') ?? [{ method: 'ANY', ref: { text: v.text }, middlewares: v.wrappers }]
        : (() => { const f = funcHandler(v); return (listed ?? ['GET']).map((m) => ({ method: m, ref: f.ref, middlewares: [...v.wrappers, ...f.decorators.map((d) => `@${d}`)] })); })();
      for (const prefix of r.prefixes) for (const h of hs) pushEntry(ruleId, 'flask', h.method, joinRoute(prefix, url), h.ref, call, [...r.middlewares, ...h.middlewares]);
      return;
    }
    if (post === 'python_django_path') {
      const fnName = cap.get('fn')?.text ?? '';
      const al = aliases.get(fnName);
      if (!al?.name || !/^django\b/.test(al.module)) return;
      const route = stringValue(args.pos[0] ?? args.kw.get('route'), consts);
      const viewNode = args.pos[1] ?? args.kw.get('view');
      if (route === null || !viewNode) return;
      if (viewNode.type === 'call' && /^include$/.test(viewNode.childForFieldName('function')?.text ?? '')) return;
      if (viewNode.type === 'attribute' && viewNode.childForFieldName('attribute')?.text === 'urls') return;
      const path = al.name === 'path' ? route : regexRoute(route);
      const v = viewRef(viewNode);
      if (!v) return;
      let hs: Resolved[];
      if (v.kind === 'class') hs = classHandlers(v, 'view') ?? [{ method: 'ANY', ref: { text: v.text, ...(v.module ? { importPath: v.module } : {}) }, middlewares: v.wrappers }];
      else {
        const f = funcHandler(v);
        const decos = f.decorators;
        hs = (methodsFromDecorators(decos) ?? ['ANY']).map((m) => ({ method: m, ref: f.ref, middlewares: [...v.wrappers, ...decos.filter((d) => !ROUTE_DECORATOR_RE.test(d)).map((d) => `@${d}`)] }));
      }
      for (const prefix of ctx.modulePrefixes) for (const h of hs) pushEntry(ruleId, 'django', h.method, joinRoute(prefix, path), h.ref, call, h.middlewares);
      return;
    }
    if (post === 'python_drf_router') {
      const routerNode = cap.get('router');
      const r = routerNode ? ctx.routers[routerNode.text] : undefined;
      if (!r || r.framework !== 'drf') return;
      const prefix = stringValue(args.pos[0] ?? args.kw.get('prefix'), consts);
      const viewNode = args.pos[1] ?? args.kw.get('viewset');
      if (prefix === null || !viewNode) return;
      const v = viewRef(viewNode);
      const hs = v ? classHandlers({ ...v, kind: 'class' }, 'viewset') : null;
      if (!hs) return;
      for (const p of r.prefixes) for (const h of hs) pushEntry(ruleId, 'django', h.method, joinRoute(joinRoute(p, prefix), h.suffix ?? ''), h.ref, call, [...r.middlewares, ...h.middlewares]);
      void framework;
    }
  }


  /**
   * gRPC servicers — classes deriving from a generated `XxxServicer` (`helloworld_pb2_grpc.GreeterServicer`,
   * sync or `grpc.aio`); each public method is an rpc entry (proto names when the snapshot has the .proto; without it,
   * methods taking `(request, context)`). Method decorators are middlewares.
   */
  function grpcServicers(): void {
    /** The generated servicer a class derives from, directly or through classes of this file (`EmailService(BaseEmailService)`). */
    const servicerOf = (bases: string[], depth = 0): string | undefined => {
      for (const b of bases) {
        const direct = /(?:^|\.)(\w+)Servicer$/.exec(b)?.[1];
        if (direct) return direct;
        const local = depth < 3 ? classByName.get(b) : undefined;
        const viaLocal = local ? servicerOf(local.bases, depth + 1) : undefined;
        if (viaLocal) return viaLocal;
      }
      return undefined;
    };
    for (const info of classes.values()) {
      const service = servicerOf(info.bases);
      if (!service) continue;
      const hasProto = !!input.grpcServices?.some((s) => s.name === service);
      for (const [name, m] of info.methods) {
        if (name.startsWith('_')) continue;
        if (!hasProto && m.arity < 2) continue;
        const rpc = rpcOf(input.grpcServices, service, name);
        if (!rpc) continue;
        const mws = decoratorTexts(m.node).map((d) => `@${d}`);
        fx.entries.push({ rpc, ruleId: 'python.grpc.servicer', framework: 'grpc', httpMethod: 'RPC', pathTemplate: '', handler: { symbolId: m.id }, path: input.path, range: rangeOf(m.node), middlewares: mws, authSignals: mws.filter(isPyAuth) });
      }
    }
  }
  /** app-wide middlewares declared in this file (`web.Application(middlewares=[…])`, `falcon.App(middleware=[…])`). */
  function appMiddlewares(kw: 'middlewares' | 'middleware', ctor: RegExp): string[] {
    const out: string[] = [];
    for (const c of root.descendantsOfType('call')) {
      const f = c?.childForFieldName('function')?.text ?? '';
      if (!c || !ctor.test(f)) continue;
      const list = callArgs(c.childForFieldName('arguments')).kw.get(kw);
      if (list?.type === 'list') for (const x of named(list)) out.push(clip(x.text, 80));
    }
    return out;
  }
  /** A handler class given as an instance (`ThingsResource(db)`), a class name or an attribute. */
  function classView(n: Node): ViewRef | null {
    if (n.type === 'call') {
      const f = n.childForFieldName('function');
      return f && /^[A-Z]/.test(f.text.split('.').pop() ?? '') ? viewRef(f) : null;
    }
    return viewRef(n);
  }
  /**
   * tornado `Application([(pattern, Handler), url(pattern, Handler)])` / `add_handlers(host, […])` (a list
   * variable of this file too); aiohttp `router.add_get|…|add_route|add_view(…)` and `web.get|…|route|view(…)`;
   * falcon `app.add_route(path, Resource(), suffix=…)`.
   */
  function frameworkRoute(ruleId: string, post: string, call: Node, args: CallArgs): void {
    const fnText = call.childForFieldName('function')?.text ?? '';
    if (post === 'python_tornado_app') {
      if (![...imports].some((m) => m === 'tornado' || m.startsWith('tornado.'))) return;
      let list = /add_handlers$/.test(fnText) ? args.pos[1] : args.pos[0] ?? args.kw.get('handlers');
      if (list?.type === 'identifier') {
        const name = list.text;
        list = undefined;
        for (const a of root.descendantsOfType('assignment')) if (a?.childForFieldName('left')?.text === name && a.childForFieldName('right')?.type === 'list') list = a.childForFieldName('right')!;
      }
      if (list?.type !== 'list') return;
      for (const item of named(list)) {
        const parts = item.type === 'tuple' ? named(item) : item.type === 'call' && /(^|\.)(url|URLSpec)$/.test(item.childForFieldName('function')?.text ?? '') ? callArgs(item.childForFieldName('arguments')).pos : [];
        const pattern = stringValue(parts[0], consts);
        if (pattern === null || !parts[1]) continue;
        const v = classView(parts[1]);
        const hs = v ? classHandlers({ ...v, kind: 'class' }, 'view') : null;
        for (const h of hs ?? []) pushEntry(ruleId, 'tornado', h.method, regexRoute(pattern), h.ref, item, h.middlewares);
      }
      return;
    }
    const verb = /[\w]+$/.exec(fnText)?.[0] ?? '';
    if (post === 'python_aiohttp_route') {
      if (![...imports].some((m) => m === 'aiohttp' || m.startsWith('aiohttp.'))) return;
      const routerCall = /^add_/.test(verb);
      if (!routerCall && !/^(web\.)?(get|post|put|patch|delete|head|route|view)$/.test(fnText)) return;
      const v = verb.replace(/^add_/, '');
      const isRoute = v === 'route';
      const method = isRoute ? (stringValue(args.pos[0], consts) ?? '*').toUpperCase() : v.toUpperCase();
      const rest = isRoute ? args.pos.slice(1) : args.pos;
      const path = stringValue(rest[0] ?? args.kw.get('path'), consts);
      const hn = rest[1] ?? args.kw.get('handler');
      if (path === null || !hn || !path.startsWith('/')) return;
      const mws = appMiddlewares('middlewares', /(^|\.)Application$/);
      if (v === 'view') {
        const cv = classView(hn);
        for (const h of (cv ? classHandlers({ ...cv, kind: 'class' }, 'view') : null) ?? []) pushEntry(ruleId, 'aiohttp', h.method, path, h.ref, call, [...mws, ...h.middlewares]);
        return;
      }
      const fv = viewRef(hn);
      if (!fv) return;
      const f = funcHandler(fv);
      pushEntry(ruleId, 'aiohttp', method === '*' ? 'ANY' : method, path, f.ref, call, [...mws, ...fv.wrappers, ...f.decorators.filter((d) => !ROUTE_DECORATOR_RE.test(d)).map((d) => `@${d}`)]);
      return;
    }
    if (post === 'python_falcon_route' && verb === 'add_route' && imports.has('falcon')) {
      const path = stringValue(args.pos[0] ?? args.kw.get('uri_template'), consts);
      const res = args.pos[1] ?? args.kw.get('resource');
      if (path === null || !res) return;
      const v = classView(res);
      const suffix = stringValue(args.kw.get('suffix'), consts) ?? undefined;
      const mws = appMiddlewares('middleware', /(^|\.)(App|API)$/);
      for (const h of (v ? classHandlers({ ...v, kind: 'class' }, 'falcon', suffix) : null) ?? []) pushEntry(ruleId, 'falcon', h.method, path, h.ref, call, [...mws, ...h.middlewares]);
    }
  }
  /** aiohttp `routes = web.RouteTableDef()` with `@routes.get('/p')` functions and `@routes.view('/p')` classes. */
  function aiohttpDecorated(ruleId: string, cap: Map<string, Node>): void {
    if (![...imports].some((m) => m === 'aiohttp' || m.startsWith('aiohttp.'))) return;
    const router = cap.get('router');
    const def = cap.get('handler');
    const verb = cap.get('verb')?.text ?? '';
    if (!router || !def) return;
    const tableCtor = root.descendantsOfType('assignment').some((a) => a?.childForFieldName('left')?.text === router.text && /RouteTableDef\s*\(/.test(a.childForFieldName('right')?.text ?? ''));
    if (!tableCtor) return;
    const args = callArgs(cap.get('args'));
    const path = stringValue(args.pos[0] ?? args.kw.get('path'), consts);
    if (path === null) return;
    const mws = appMiddlewares('middlewares', /(^|\.)Application$/);
    if (def.type === 'class_definition') {
      const name = def.childForFieldName('name')?.text ?? '';
      for (const h of classHandlers({ kind: 'class', name, module: pkg, local: true, wrappers: [], text: name }, 'view') ?? []) pushEntry(ruleId, 'aiohttp', h.method, path, h.ref, def, [...mws, ...h.middlewares]);
      return;
    }
    const isRoute = verb === 'route';
    const method = isRoute ? (stringValue(args.pos[0], consts) ?? '*').toUpperCase() : verb.toUpperCase();
    const p = isRoute ? stringValue(args.pos[1], consts) : path;
    if (p === null) return;
    const h = handlerOfNode(def);
    pushEntry(ruleId, 'aiohttp', method === '*' ? 'ANY' : method, p, h.ref, def, [...mws, ...h.decorators.filter((d) => !ROUTE_DECORATOR_RE.test(d)).map((d) => `@${d}`)]);
  }
  /**
   * entries that are not HTTP routes — WebSocket routes and consumers, Socket.IO events, queue consumers
   * (Celery, Dramatiq, Kafka, RabbitMQ), timed jobs (Celery beat, APScheduler, `schedule`), commands (click, typer,
   * Django management) and Thrift handlers. Text-level facts only; nothing runs.
   */
  function channelEntries(): void {
    type Channel = NonNullable<RawEntry['channel']>;
    const pushChannel = (channel: Channel, ruleId: string, framework: string, ref: HandlerRef, at: Node, middlewares: string[]) => {
      const mws = [...new Set(middlewares)];
      fx.entries.push({
        channel, ruleId, framework, httpMethod: '', pathTemplate: '', handler: ref, path: input.path, range: rangeOf(at),
        middlewares: mws, authSignals: mws.filter(isPyAuth),
      });
    };
    const has = (...mods: string[]) => mods.some((m) => imports.has(m));
    const defMw = (def: Node) => decoratorTexts(def).filter((d) => !ROUTE_DECORATOR_RE.test(d) && !CHANNEL_DECORATOR_RE.test(d)).map((d) => `@${d}`);
    const typeOf = (n: Node | null | undefined, at: Node): string | null => (n ? receiverTypeOf(n, at) : null);
    const lit = (n: Node | null | undefined): string | null => stringValue(n, consts);
    const textOrLit = (n: Node): string => lit(n) ?? `{${clip(n.text, 60)}}`;
    /** Handler of a callable reference: local / imported function, `self.m`, `fn.s(...)`, or a `"pkg.mod:func"` string. */
    const fnRef = (n: Node | null | undefined, at: Node): { ref: HandlerRef; name: string; mw: string[] } | null => {
      if (!n) return null;
      const s = lit(n);
      if (s !== null) {
        const m = /^([\w.]+?)(?:[:.](\w+))?$/.exec(s);
        if (!m) return null;
        const [mod, name] = m[2] ? [m[1]!, m[2]] : [null, m[1]!];
        const local = !mod || mod === pkg ? moduleFuncs.get(name) : undefined;
        return { ref: local ? handlerOfNode(local.node).ref : { text: name, ...(mod ? { importPath: mod } : {}) }, name: s, mw: [] };
      }
      if (n.type === 'call') {
        const f = n.childForFieldName('function');
        if (f?.type === 'attribute' && /^(s|si|signature|delay|apply_async)$/.test(f.childForFieldName('attribute')?.text ?? '')) return fnRef(f.childForFieldName('object'), at);
        return null;
      }
      if (n.type === 'attribute' && n.childForFieldName('object')?.text === 'self') {
        const name = n.childForFieldName('attribute')?.text ?? '';
        const m = enclosingClass(at)?.methods.get(name);
        return { ref: m ? { symbolId: m.id, range: rangeOf(m.node) } : { text: n.text }, name, mw: m ? defMw(m.node) : [] };
      }
      if (n.type !== 'identifier' && n.type !== 'attribute') return null;
      const v = viewRef(n);
      if (!v || v.kind !== 'func') return null;
      const f = funcHandler(v);
      return { ref: f.ref, name: v.name, mw: f.decorators.filter((d) => !CHANNEL_DECORATOR_RE.test(d)).map((d) => `@${d}`) };
    };

    // ---- decorated functions ----
    for (const dd of root.descendantsOfType('decorated_definition')) {
      const def = dd?.childForFieldName('definition');
      if (!dd || def?.type !== 'function_definition') continue;
      const fnName = def.childForFieldName('name')?.text ?? '?';
      for (const deco of named(dd).filter((c) => c.type === 'decorator')) {
        const e = named(deco)[0];
        if (!e) continue;
        const isCall = e.type === 'call';
        const fnNode = isCall ? e.childForFieldName('function') : e;
        if (!fnNode) continue;
        const args = isCall ? callArgs(e.childForFieldName('arguments')) : { pos: [] as Node[], kw: new Map<string, Node>(), splat: false };
        const obj = fnNode.type === 'attribute' ? fnNode.childForFieldName('object') : null;
        const attr = fnNode.type === 'attribute' ? fnNode.childForFieldName('attribute')?.text ?? '' : fnNode.text;
        const objType = typeOf(obj, deco);
        const h = () => handlerOfNode(def);
        // FastAPI / Starlette / Quart `@app.websocket("/ws")`.
        if (obj && (attr === 'websocket' || attr === 'websocket_route') && isCall) {
          const r = routerOf(obj);
          const fw = r?.framework === 'fastapi' ? 'fastapi' : has('starlette') ? 'starlette' : has('quart') ? 'quart' : null;
          const path = lit(args.pos[0] ?? args.kw.get('path'));
          if (!r || !fw || path === null) continue;
          const hh = h();
          const mw = [...r.middlewares, ...depsOf(args.kw.get('dependencies')?.text), ...defMw(def), ...hh.deps];
          for (const prefix of fw === 'fastapi' ? r.prefixes : ['']) {
            const p = joinRoute(prefix, path);
            pushChannel({ kind: 'socket', protocol: 'websocket', key: `ws:${p}`, route: p }, 'python.fastapi.websocket', fw, hh.ref, def, mw);
          }
          continue;
        }
        // Socket.IO `@sio.on("event", namespace="/x")`, `@sio.event`.
        if (obj && (attr === 'on' || attr === 'event') && (objType ? /^(SocketIO|Server|AsyncServer)$/.test(objType) : has('socketio', 'flask_socketio') && /sio|socket/i.test(obj.text))) {
          const event = attr === 'event' ? fnName : lit(args.pos[0]);
          if (event === null) continue;
          const ns = lit(args.kw.get('namespace') ?? (attr === 'on' ? args.pos[1] : undefined));
          const route = ns && ns !== '/' ? `${ns}#${event}` : event;
          pushChannel({ kind: 'socket', protocol: 'socketio', key: `socketio:${route}`, route }, 'python.socketio.event', 'socketio', h().ref, def, defMw(def));
          continue;
        }
        // Celery `@app.task`, `@shared_task(name=…)`.
        const aliasOf = (n: Node) => aliases.get(n.text.split('.')[0]!);
        const celeryShared = attr === 'shared_task' && (obj ? /celery/.test(obj.text) : aliases.get('shared_task')?.module.startsWith('celery') ?? false);
        if (celeryShared || (obj && attr === 'task' && (objType === 'Celery' || (has('celery') && !objType)))) {
          const name = lit(args.kw.get('name')) ?? fnName;
          pushChannel({ kind: 'message', protocol: 'celery', key: `mq:celery:${name}`, route: name }, 'python.celery.task', 'celery', h().ref, def, defMw(def));
          continue;
        }
        // Dramatiq `@dramatiq.actor(queue_name=…)`.
        if (attr === 'actor' && (obj ? obj.text === 'dramatiq' || aliasOf(obj)?.module === 'dramatiq' : aliases.get('actor')?.module.startsWith('dramatiq') ?? false)) {
          const name = lit(args.kw.get('actor_name')) ?? fnName;
          pushChannel({ kind: 'message', protocol: 'dramatiq', key: `mq:dramatiq:${name}`, route: lit(args.kw.get('queue_name')) ?? name }, 'python.dramatiq.actor', 'dramatiq', h().ref, def, defMw(def));
          continue;
        }
        // APScheduler `@scheduler.scheduled_job("interval", minutes=3)`.
        if (obj && attr === 'scheduled_job' && isCall) {
          const trigger = lit(args.pos[0] ?? args.kw.get('trigger')) ?? '';
          pushChannel({ kind: 'schedule', protocol: 'cron', key: `cron:${fnName}`, route: scheduleText(trigger, args.kw) }, 'python.apscheduler', 'apscheduler', h().ref, def, defMw(def));
          continue;
        }
        // click `@click.command()` / `@cli.command("name")`, typer `@app.command()`.
        if (attr === 'command' && obj) {
          const fw = objType === 'Typer' ? 'typer' : obj.text === 'click' || clickGroup(obj) ? 'click' : has('click') ? 'click' : has('typer') ? 'typer' : null;
          if (!fw) continue;
          const name = lit(args.pos[0] ?? args.kw.get('name')) ?? fnName.replace(/_/g, '-');
          pushChannel({ kind: 'cli', protocol: 'cli', key: `cli:${name}`, route: name }, 'python.click.command', fw, h().ref, def, defMw(def));
          continue;
        }
      }
    }

    // ---- calls ----
    const kafkaFw = has('confluent_kafka') ? 'confluent-kafka' : has('aiokafka') ? 'aiokafka' : 'kafka-python';
    const enclosingRef = (call: Node): HandlerRef => {
      const def = enclosingDef(call);
      const id = enclosingSymbol(call);
      return { ...(id ? { symbolId: id } : {}), range: rangeOf(def ?? call) };
    };
    for (const call of root.descendantsOfType('call')) {
      if (!call) continue;
      const fn = call.childForFieldName('function');
      if (!fn) continue;
      const a = callArgs(call.childForFieldName('arguments'));
      const attr = fn.type === 'attribute' ? fn.childForFieldName('attribute')?.text ?? '' : fn.text.split('.').pop() ?? '';
      const obj = fn.type === 'attribute' ? fn.childForFieldName('object') : null;
      // Kafka: `KafkaConsumer("orders", …)`, `consumer.subscribe(["orders"])`.
      let topics: string[] | null = null;
      if (/^(KafkaConsumer|AIOKafkaConsumer)$/.test(attr) && has('kafka', 'aiokafka')) topics = a.pos.map(textOrLit);
      else if (attr === 'subscribe' && obj) {
        const t = typeOf(obj, call);
        const arg = a.kw.get('topics') ?? a.pos[0];
        const kafkaRecv = t ? /^(KafkaConsumer|AIOKafkaConsumer|Consumer|DeserializingConsumer)$/.test(t) : has('kafka', 'confluent_kafka', 'aiokafka') && (arg?.type === 'list' || arg?.type === 'tuple' || a.kw.has('topics'));
        if (kafkaRecv && arg) topics = stringList(arg) ?? (arg.type === 'list' || arg.type === 'tuple' ? named(arg).map(textOrLit) : [textOrLit(arg)]);
      }
      if (topics) {
        for (const topic of topics) pushChannel({ kind: 'message', protocol: 'kafka', key: `mq:kafka:${topic}`, route: topic }, 'python.kafka.consumer', kafkaFw, enclosingRef(call), call, []);
        continue;
      }
      // RabbitMQ (pika 1.x / 0.x, amqp): `channel.basic_consume(queue="q", on_message_callback=fn)`.
      if (attr === 'basic_consume' && obj) {
        let queue = a.kw.get('queue');
        let cb = a.kw.get('on_message_callback') ?? a.kw.get('consumer_callback') ?? a.kw.get('callback');
        if (!queue && !cb) {
          if (lit(a.pos[0]) === null && lit(a.pos[1]) !== null) { cb = a.pos[0]; queue = a.pos[1]; } else { queue = a.pos[0]; cb = a.pos[1]; }
        } else if (!queue) queue = a.pos[0];
        else cb ??= a.pos[0];
        if (!queue) continue;
        const q = textOrLit(queue);
        const f = fnRef(cb, call);
        pushChannel({ kind: 'message', protocol: 'rabbitmq', key: `mq:rabbitmq:${q}`, route: q }, 'python.pika.consume', has('pika') ? 'pika' : 'amqp', f?.ref ?? enclosingRef(call), call, f?.mw ?? []);
        continue;
      }
      // APScheduler `scheduler.add_job(fn, "cron", hour=1)`.
      if (attr === 'add_job' && obj) {
        const t = typeOf(obj, call);
        if (!(t ? /Scheduler$/.test(t) : has('apscheduler', 'flask_apscheduler') || /sched/i.test(obj.text))) continue;
        const f = fnRef(a.pos[0] ?? a.kw.get('func'), call);
        if (!f) continue;
        const trigger = lit(a.pos[1] ?? a.kw.get('trigger')) ?? '';
        pushChannel({ kind: 'schedule', protocol: 'cron', key: `cron:${f.name}`, route: scheduleText(trigger, a.kw) }, 'python.apscheduler', 'apscheduler', f.ref, call, f.mw);
        continue;
      }
      // Celery `sender.add_periodic_task(10.0, task.s(…))`.
      if (attr === 'add_periodic_task' && obj && a.pos[0]) {
        const f = fnRef(a.pos[1] ?? a.kw.get('sig'), call);
        if (!f) continue;
        pushChannel({ kind: 'schedule', protocol: 'cron', key: `cron:${f.name}`, route: clip(a.pos[0].text, 120) }, 'python.celery.beat', 'celery', f.ref, call, f.mw);
        continue;
      }
      // `schedule.every(10).minutes.do(job)`.
      if (attr === 'do' && obj && has('schedule') && /^(?:schedule\.)?every\s*\(/.test(obj.text)) {
        const f = fnRef(a.pos[0], call);
        if (!f) continue;
        pushChannel({ kind: 'schedule', protocol: 'cron', key: `cron:${f.name}`, route: clip(obj.text.replace(/^schedule\./, ''), 120) }, 'python.schedule', 'schedule', f.ref, call, f.mw);
        continue;
      }
      // Starlette `WebSocketRoute("/ws", endpoint)`, FastAPI `app.add_api_websocket_route("/ws", fn)`.
      if ((attr === 'WebSocketRoute' && has('starlette', 'fastapi')) || ((attr === 'add_api_websocket_route' || attr === 'add_websocket_route') && obj)) {
        const path = lit(a.pos[0] ?? a.kw.get('path'));
        const f = fnRef(a.pos[1] ?? a.kw.get('endpoint'), call);
        if (path === null) continue;
        const r = attr === 'WebSocketRoute' ? null : routerOf(obj ?? undefined);
        const fw = r?.framework === 'fastapi' ? 'fastapi' : 'starlette';
        for (const prefix of r?.framework === 'fastapi' ? r.prefixes : ['']) {
          const p = joinRoute(prefix, path);
          pushChannel({ kind: 'socket', protocol: 'websocket', key: `ws:${p}`, route: p }, 'python.fastapi.websocket', fw, f?.ref ?? enclosingRef(call), call, [...(r?.middlewares ?? []), ...(f?.mw ?? [])]);
        }
        continue;
      }
    }

    // ---- Celery beat schedules (`app.conf.beat_schedule = {...}`, `CELERY_BEAT_SCHEDULE`, `conf.update(beat_schedule=…)`) ----
    const beatDicts: Node[] = [];
    for (const asg of root.descendantsOfType('assignment')) {
      const left = asg?.childForFieldName('left');
      const right = asg?.childForFieldName('right');
      if (left && right?.type === 'dictionary' && /(^|\.)(beat_schedule|CELERY_BEAT_SCHEDULE|CELERYBEAT_SCHEDULE)$/.test(left.text)) beatDicts.push(right);
    }
    for (const kw of root.descendantsOfType('keyword_argument')) {
      const v = kw?.childForFieldName('value');
      if (kw?.childForFieldName('name')?.text === 'beat_schedule' && v?.type === 'dictionary') beatDicts.push(v);
    }
    for (const d of beatDicts) {
      for (const pair of named(d).filter((c) => c.type === 'pair')) {
        const v = pair.childForFieldName('value');
        const fields = new Map<string, Node>();
        if (v?.type === 'dictionary') {
          for (const p of named(v).filter((c) => c.type === 'pair')) { const k = lit(p.childForFieldName('key')); const val = p.childForFieldName('value'); if (k && val) fields.set(k, val); }
        } else if (v?.type === 'call' && v.childForFieldName('function')?.text === 'dict') {
          for (const [k, val] of callArgs(v.childForFieldName('arguments')).kw) fields.set(k, val);
        }
        const task = lit(fields.get('task'));
        if (!task) continue;
        const f = fnRef(fields.get('task'), pair);
        const sched = fields.get('schedule');
        pushChannel({ kind: 'schedule', protocol: 'cron', key: `cron:${task}`, route: sched ? clip(sched.text, 120) : '' }, 'python.celery.beat', 'celery', f?.ref ?? { text: task }, pair, []);
      }
    }

    // ---- classes: Channels consumers, Socket.IO namespaces, Django commands, Thrift handlers ----
    const wsRouted = new Set(ctx.wsRouted ?? []);
    const nsOf = new Map<string, string>();
    for (const call of root.descendantsOfType('call')) {
      const f = call?.childForFieldName('function');
      if (!call || !f || !/(^|\.)(register_namespace|on_namespace)$/.test(f.text)) continue;
      const inst = callArgs(call.childForFieldName('arguments')).pos[0];
      const ctor = inst?.type === 'call' ? inst.childForFieldName('function')?.text.split('.').pop() : undefined;
      const ns = inst?.type === 'call' ? lit(callArgs(inst.childForFieldName('arguments')).pos[0]) : null;
      if (ctor && ns) nsOf.set(ctor, ns);
    }
    const cmdFile = /(^|\/)management\/commands\/(\w+)\.py$/.exec(input.path);
    for (const info of classes.values()) {
      if (info.dotted.includes('.')) continue;
      const bases = info.bases.map((b) => b.split('.').pop() ?? b);
      const mw = () => classAuth(localClassFacts(info));
      const methodRef = (names: string[]): HandlerRef => {
        const m = names.map((n) => info.methods.get(n)).find((x) => !!x);
        return m ? { symbolId: m.id, range: rangeOf(m.node) } : { symbolId: info.symbolId, range: rangeOf(info.node) };
      };
      if (bases.some((b) => CONSUMER_BASES.test(b)) && !wsRouted.has(info.dotted)) {
        const key = `ws:${info.dotted}`;
        pushChannel({ kind: 'socket', protocol: 'websocket', key, route: info.dotted }, 'python.channels.consumer', 'channels', methodRef(CONSUMER_METHODS), info.node, mw());
      }
      if (bases.some((b) => /^(Async)?Namespace$/.test(b)) && has('socketio', 'flask_socketio')) {
        const ns = nsOf.get(info.dotted);
        for (const [name, m] of info.methods) {
          const ev = /^on_(\w+)$/.exec(name)?.[1];
          if (!ev) continue;
          const route = ns && ns !== '/' ? `${ns}#${ev}` : ev;
          pushChannel({ kind: 'socket', protocol: 'socketio', key: `socketio:${route}`, route }, 'python.socketio.event', 'socketio', { symbolId: m.id, range: rangeOf(m.node) }, m.node, [...mw(), ...defMw(m.node)]);
        }
      }
      if (cmdFile && info.dotted === 'Command' && bases.some((b) => /^(Base|Label|App)Command$/.test(b))) {
        const name = cmdFile[2]!;
        pushChannel({ kind: 'cli', protocol: 'cli', key: `cli:${name}`, route: name }, 'python.django.command', 'django', methodRef(['handle', 'handle_label', 'handle_app_config']), info.node, mw());
      }
      const iface = info.bases.find((b) => /(^|\.)Iface$/.test(b));
      if (iface) {
        const parts = iface.split('.');
        const service = parts.length > 1 ? parts[parts.length - 2]! : aliases.get('Iface')?.module.split('.').pop();
        if (!service) continue;
        for (const [name, m] of info.methods) {
          if (name.startsWith('_')) continue;
          const route = `${service}/${name}`;
          pushChannel({ kind: 'rpc', protocol: 'thrift', key: `rpc:thrift:${route}`, route }, 'python.thrift.iface', 'thrift', { symbolId: m.id, range: rangeOf(m.node) }, m.node, [...mw(), ...defMw(m.node)]);
        }
      }
    }

    // ---- Channels routing: `websocket_urlpatterns = [path("ws/chat/<room>/", ChatConsumer.as_asgi())]` ----
    const lists: Node[] = [];
    for (const asg of root.descendantsOfType('assignment')) {
      const right = asg?.childForFieldName('right');
      if (asg?.childForFieldName('left')?.text === 'websocket_urlpatterns' && right) lists.push(right);
    }
    for (const call of root.descendantsOfType('call')) {
      if (call?.childForFieldName('function')?.text.split('.').pop() !== 'URLRouter') continue;
      const arg = callArgs(call.childForFieldName('arguments')).pos[0];
      if (arg && !lists.some((l) => l.startIndex <= arg.startIndex && arg.endIndex <= l.endIndex)) lists.push(arg);
    }
    const seen = new Set<number>();
    for (const l of lists) {
      for (const call of l.descendantsOfType('call')) {
        if (!call || seen.has(call.id)) continue;
        const fname = call.childForFieldName('function')?.text.split('.').pop() ?? '';
        if (!/^(path|re_path|url)$/.test(fname)) continue;
        seen.add(call.id);
        const a = callArgs(call.childForFieldName('arguments'));
        const route = lit(a.pos[0] ?? a.kw.get('route'));
        let view = a.pos[1] ?? a.kw.get('view');
        if (route === null || !view) continue;
        if (view.type === 'call' && view.childForFieldName('function')?.childForFieldName('attribute')?.text === 'as_asgi') view = view.childForFieldName('function')!.childForFieldName('object')!;
        const v = viewRef(view);
        if (!v || v.kind !== 'class') continue;
        const local = v.local ? classByName.get(v.name) : undefined;
        const remote = !local && v.module ? ctx.modules[v.module]?.classes[v.name] : undefined;
        let ref: HandlerRef = { text: v.text, ...(v.module && !v.local ? { importPath: v.module } : {}) };
        let mw: string[] = [];
        const pick = CONSUMER_METHODS.find((m) => (local ? local.methods.has(m) : !!remote?.methods[m]));
        if (local) {
          const m = pick ? local.methods.get(pick) : undefined;
          ref = m ? { symbolId: m.id, range: rangeOf(m.node) } : { symbolId: local.symbolId, range: rangeOf(local.node) };
          mw = classAuth(localClassFacts(local));
        } else if (remote) {
          ref = pick ? { text: `${v.name}.${pick}`, importPath: v.module! } : { symbolId: `${repo}:${ctx.modules[v.module!]!.path}#${v.module}.${v.name}` };
          mw = classAuth(remote);
        }
        for (let p = call.parent; p; p = p.parent) {
          if (p.type !== 'call') continue;
          const ft = p.childForFieldName('function')?.text ?? '';
          if (/Middleware|Auth|OriginValidator/.test(ft)) mw.unshift(clip(ft, 80));
        }
        const p = joinRoute('', fname === 'path' ? route : regexRoute(route));
        pushChannel({ kind: 'socket', protocol: 'websocket', key: `ws:${p}`, route: p }, 'python.channels.consumer', 'channels', ref, call, mw);
      }
    }

    function clickGroup(obj: Node): boolean {
      if (obj.type !== 'identifier') return false;
      const local = moduleFuncs.get(obj.text);
      if (local) return decoratorTexts(local.node).some((d) => /(^|\.)group\b/.test(d));
      const al = aliases.get(obj.text);
      return !!al?.name && (ctx.modules[al.module]?.funcs[al.name]?.decorators ?? []).some((d) => /(^|\.)group\b/.test(d));
    }
  }

  function handleAuth(ruleId: string, post: string | undefined, cap: Map<string, Node>): void {
    if (post === 'python_decorator_auth') {
      const deco = cap.get('decorator');
      const def = cap.get('def');
      if (!deco || !def) return;
      const text = clip(deco.text.replace(/^@\s*/, ''), 160);
      if (ROUTE_DECORATOR_RE.test(text) || !isPyAuth(text)) return;
      const target = defTarget(def);
      if (target) addAuth({ target, kind: 'annotation', detail: `@${text}`, ruleId });
    } else if (post === 'python_class_auth') {
      const cls = cap.get('class');
      const name = cap.get('name')?.text;
      const value = cap.get('value');
      const info = cls ? classes.get(cls.id) : undefined;
      if (!info || !name || !value) return;
      if (/^\[\s*\]$|^\(\s*\)$/.test(value.text) || !isPyAuth(value.text)) return;
      addAuth({ target: info.symbolId, kind: 'annotation', detail: `${name} = ${clip(value.text, 160)}`, ruleId });
    } else if (post === 'python_class_mixin_auth') {
      const cls = cap.get('class');
      const info = cls ? classes.get(cls.id) : undefined;
      if (!info) return;
      for (const b of info.bases) if (/(LoginRequired|PermissionRequired|UserPassesTest|Staff|Superuser)\w*Mixin/.test(b)) addAuth({ target: info.symbolId, kind: 'annotation', detail: b, ruleId });
    } else if (post === 'python_fastapi_depends') {
      const call = cap.get('call');
      const fnName = cap.get('fn')?.text ?? '';
      const arg = named(cap.get('args'))[0];
      if (!call || !arg || !(fnName === 'Security' || isPyAuth(arg.text))) return;
      // Handler parameter defaults (`user = Depends(get_current_user)`) belong to the function; router / app
      // dependencies (`APIRouter(dependencies=[…])`) to the file.
      let def: Node | null = null;
      for (let p = call.parent; p; p = p.parent) {
        if (p.type === 'parameters') { def = p.parent; break; }
        if (p.type === 'block' || p.type === 'module') break;
      }
      const target = (def && funcIds.get(def.id)) ?? `${repo}:${input.path}`;
      addAuth({ target, kind: def ? 'annotation' : 'middleware', detail: `${fnName}(${clip(arg.text, 120)})`, ruleId });
    } else if (post === 'python_before_request') {
      const def = cap.get('def');
      const hook = cap.get('hook')?.text ?? '';
      const routerName = cap.get('router')?.text ?? '';
      const fnName = def?.childForFieldName('name')?.text;
      if (!fnName) return;
      addAuth({ target: `${repo}:${input.path}`, kind: 'middleware', detail: `${routerName}.${hook}: ${fnName}`, ruleId });
    } else if (post === 'python_django_settings') {
      const name = cap.get('name')?.text ?? '';
      const value = cap.get('value');
      if (!value) return;
      const items = name === 'REST_FRAMEWORK'
        ? [...value.text.matchAll(/['"](DEFAULT_(?:PERMISSION|AUTHENTICATION)_CLASSES)['"]\s*:\s*([[(][^\])]*[\])])/g)].map((m) => `${m[1]}: ${clip(m[2]!, 160)}`)
        : named(value).map((c) => stringValue(c)).filter((s): s is string => !!s && /auth|login|token|jwt|perm|oauth|sso|otp|csrf/i.test(s));
      for (const it of items) addAuth({ target: `${repo}:${input.path}`, kind: 'security_config', detail: `${name}: ${it}`, ruleId });
    }
  }

  function sinkPost(post: string | undefined, s: { method: string; receiver: Node | null; a: CallArgs; node: Node; text: string }): boolean {
    const first = s.a.pos[0];
    switch (post) {
      case 'python_yaml_load': {
        if (/^safe_/.test(s.method)) return false;
        const loader = s.a.kw.get('Loader') ?? s.a.pos[1];
        return !loader || !/Safe|Base/.test(loader.text);
      }
      case 'python_nonconst':
        return !!first && exprTaint(first) !== 'constant';
      case 'python_redirect':
        if (!first || exprTaint(first) === 'constant') return false;
        return !(first.type === 'call' && /(^|\.)(url_for|reverse|reverse_lazy|resolve_url)$/.test(first.childForFieldName('function')?.text ?? ''));
      case 'python_lxml':
        return !/resolve_entities\s*=\s*False/.test(s.text);
      case 'python_by_id': {
        const idKw = [...s.a.kw.entries()].some(([k, v]) => /^(id|pk|uuid|\w+_id|\w+_pk|\w+__id|\w+__pk|\w+_uuid)$/.test(k) && exprTaint(v) !== 'constant');
        if (!s.receiver) return idKw; // get_object_or_404(Model, pk=…)
        const rt = s.receiver.text;
        const classLike = /(^|\.)[A-Z](?=\w*[a-z])\w*$/.test(rt);
        const managerLike = classLike || /(^|\.)objects$|\.objects\.|_set$|(^|\.)query$|session$|repo|dao|store|manager/i.test(rt);
        if (!managerLike || /^(request|self\.request|kwargs|data|params|headers|os\.environ|environ|cache|settings)(\.|$)/.test(rt) || /\.(GET|POST|args|form|json|headers|cookies|query_params|data|META|session)$/.test(rt)) return false;
        if (idKw) return true;
        const positional = s.a.pos.filter((p) => exprTaint(p) !== 'constant');
        return /^(get|get_or_404|get_or_none)$/.test(s.method) && positional.length >= 1 && (classLike || /(^|\.)query$|session$|repo|dao|store/i.test(rt));
      }
      case 'python_state_write': {
        if (s.node.type === 'call') return [...s.a.kw.keys()].some((k) => STATE_FIELD_RE.test(k));
        return true;
      }
      default:
        return true;
    }
  }
}

// decorators that declare a non-HTTP entry (not middlewares of it).
const CHANNEL_DECORATOR_RE = /^[\w.]+\.(websocket|websocket_route|on|event|task|shared_task|actor|scheduled_job|command|group)\b|^(shared_task|actor)\b|^(click|typer)\./;
const CONSUMER_BASES = /^(Async)?(Json)?WebsocketConsumer$/;
const CONSUMER_METHODS = ['receive_json', 'receive', 'websocket_receive', 'connect', 'websocket_connect'];

/** APScheduler trigger and its timing keywords (`cron hour=1 minute=0`). */
function scheduleText(trigger: string, kw: Map<string, Node>): string {
  const parts = [...kw].filter(([k]) => !/^(id|name|func|args|kwargs|trigger|replace_existing|misfire_grace_time|coalesce|max_instances|jobstore|executor)$/.test(k)).map(([k, v]) => `${k}=${v.text}`);
  return clip([trigger, ...parts].filter(Boolean).join(' '), 120);
}

const STATE_FIELD_RE = /^(status|state|role|roles|is_admin|is_staff|is_superuser|is_active|balance|amount|price|total|paid|paid_at|credit|credits|quantity|discount|approved|verified|owner|owner_id|user_id)$/;
