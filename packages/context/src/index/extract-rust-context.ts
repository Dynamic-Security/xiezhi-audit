// Rust snapshot-level facts: routers are composed across files — axum `nest("/api", api::routes())`
// / `merge(users::router())`, actix-web `web::scope("/api").configure(users::config).service(get_user)`, Rocket
// `mount("/api", routes![a, b])` — so one text pass over every `.rs` file (comments and string contents masked, values
// read from the original) records, per function, the prefixes it is mounted under and the auth middleware applied
// there (axum layers added after the `nest`, actix `wrap` on the scope). Each file receives its functions' bases, the
// web frameworks its crate depends on (nearest Cargo.toml) and nothing else.
import { cargoDependencyNames } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';
import type { ExtractInput } from './types.js';

/** Crate directory and crate-relative module path of a file (`src/` layout; other files keep their path). */
export function rustModuleOf(path: string): { crate: string; module: string } {
  const m = /^(?:(.*)\/)?src\/(.+)\.rs$/.exec(path);
  if (!m) return { crate: '', module: path.replace(/\.rs$/, '').split('/').join('::') };
  const segs = m[2]!.split('/');
  const last = segs[segs.length - 1]!;
  if (last === 'mod' || ((last === 'lib' || last === 'main') && segs.length === 1)) segs.pop();
  return { crate: m[1] ?? '', module: segs.join('::') };
}

/** Module key (`FileExtract.pkg`) of a crate-relative module path. */
export const pkgKey = (crate: string, module: string) => (crate ? (module ? `${crate}/${module}` : crate) : module);

export interface RsBase { prefix: string; auth: string[] }
export interface RustContext {
  /** Web frameworks the file's crate depends on (`axum`, `actix-web`, `rocket`, `poem`, `warp`, `tonic`…). */
  frameworks: string[];
  /** Function name (declared in this file) → prefixes and inherited auth middleware; absent = mounted at the root. */
  fnBases: Record<string, RsBase[]>;
  /** Workspace crates by the name code uses (`lemmy_api` → `crates/api/api`), for paths into sibling crates. */
  crates: Record<string, string>;
  /**
   * Whether the file's crate is a web / RPC server crate or one it depends on (workspace path dependencies,
   * transitively). Sinks are recorded only there: CLI, desktop and tooling crates of the same workspace are context.
   */
  serverReachable: boolean;
  /**
   * Extractor / request-guard types declared in the snapshot whose `FromRequest` / `FromRequestParts` impl rejects
   * unauthenticated requests or reads credentials (`Headers`, `AdminHeaders`, `LocalUserView`, `UserAuth`).
   */
  guardTypes: string[];
  /** tonic service (trait) name → interceptors / auth layers of the servers it is added to. */
  grpcAuth: Record<string, string[]>;
}

const MAX_BYTES = 1024 * 1024;
const WEB_CRATES = ['axum', 'actix-web', 'rocket', 'poem', 'warp', 'salvo', 'tide', 'ntex', 'tonic', 'loco-rs', 'gotham'];

/** Auth-ish middleware / layer / guard text (infrastructure layers such as sessions, CORS and tracing excluded). */
export const RS_AUTH_RE = /auth|jwt|token|bearer|login|guard|permission|acl|rbac|admin|require_user|current_user|identity|api_?key|signature|oauth|basic|verify|claims|access/i;
const RS_NOT_AUTH_RE = /^(?:\w+::)*(?:Cors|Trace|Compression|Timeout|Catch|Propagate|SetRequestId|RequestId|NormalizePath|DefaultHeaders|Logger|SessionManager|Session|CookieManager|IdentityMiddleware|SessionMiddleware|Cache|Limit|RequestBodyLimit|HandleError|Extension)\w*\b/;
/** A request-guard impl body that authenticates: rejects with 401 / 403, or reads tokens / sessions / credentials. */
const GUARD_BODY_RE = /Unauthorized|UNAUTHORIZED|Forbidden|FORBIDDEN|\b40[13]\b|jwt|Jwt|JWT|bearer|Bearer|token|Token|session|Session|auth|Auth|login|Login|claims|Claims|password|api_key|ApiKey/;
export const isRustAuth = (text: string) => RS_AUTH_RE.test(text) && !RS_NOT_AUTH_RE.test(text.trim());

/** Same-length copy of Rust source with comments and string / char contents blanked (quotes kept). */
export function maskRust(text: string): string {
  const out = text.split('');
  let i = 0;
  const blank = (a: number, b: number) => { for (let k = a; k < b; k++) if (out[k] !== '\n') out[k] = ' '; };
  while (i < text.length) {
    const c = text[i]!;
    const n = text[i + 1];
    if (c === '/' && n === '/') { const e = text.indexOf('\n', i); const end = e < 0 ? text.length : e; blank(i, end); i = end; continue; }
    if (c === '/' && n === '*') {
      let depth = 1; let k = i + 2;
      while (k < text.length && depth > 0) { if (text[k] === '/' && text[k + 1] === '*') { depth++; k += 2; } else if (text[k] === '*' && text[k + 1] === '/') { depth--; k += 2; } else k++; }
      blank(i, k); i = k; continue;
    }
    const raw = /^(b?r)(#*)"/.exec(text.slice(i, i + 12));
    if (raw && (i === 0 || !/\w/.test(text[i - 1]!))) {
      const close = '"' + raw[2];
      const start = i + raw[0].length;
      const e = text.indexOf(close, start);
      const end = e < 0 ? text.length : e;
      blank(start, end); i = end + close.length; continue;
    }
    if (c === '"') {
      let k = i + 1;
      while (k < text.length && text[k] !== '"') k += text[k] === '\\' ? 2 : 1;
      blank(i + 1, k); i = k + 1; continue;
    }
    if (c === "'") {
      const ch = /^'(\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'\n])'/.exec(text.slice(i, i + 14));
      if (ch) { blank(i + 1, i + ch[0].length - 1); i += ch[0].length; continue; }
    }
    i++;
  }
  return out.join('');
}

/** Index of the bracket closing the one at `open` (masked text). */
function closeOf(m: string, open: number): number {
  const pairs: Record<string, string> = { '(': ')', '[': ']', '{': '}' };
  const stack: string[] = [];
  for (let k = open; k < m.length; k++) {
    const ch = m[k]!;
    if (pairs[ch]) stack.push(pairs[ch]!);
    else if (ch === ')' || ch === ']' || ch === '}') { if (stack.pop() !== ch) return -1; if (!stack.length) return k; }
  }
  return -1;
}
/** Split the argument text between `open` and its closing paren at top-level commas: [start, end) ranges. */
function argRanges(m: string, open: number): [number, number][] {
  const close = closeOf(m, open);
  if (close < 0) return [];
  const out: [number, number][] = [];
  let depth = 0; let start = open + 1;
  for (let k = open + 1; k < close; k++) {
    const ch = m[k]!;
    if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') depth--;
    else if (ch === ',' && depth === 0) { out.push([start, k]); start = k + 1; }
  }
  if (m.slice(start, close).trim()) out.push([start, close]);
  return out;
}
interface Seg { name: string; open: number; close: number }
/** Method-call segments following position `at` (`.layer(x).nest("/a", y)?.await`). */
function chainAfter(m: string, at: number): Seg[] {
  const segs: Seg[] = [];
  let k = at;
  for (;;) {
    const r = /^\s*(?:\?\s*)?\.\s*(\w+)\s*(?:::\s*<[^>]*>\s*)?(\()?/.exec(m.slice(k, k + 200));
    if (!r) break;
    if (!r[2]) { if (r[1] === 'await') { k += r[0].length; continue; } break; }
    const open = k + r[0].length - 1;
    const close = closeOf(m, open);
    if (close < 0) break;
    segs.push({ name: r[1]!, open, close });
    k = close + 1;
  }
  return segs;
}

/** `use` aliases of a file: local name → full path (`crate::api::users`, `super::x`). */
export function useAliases(masked: string, raw: string): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (tree: string, prefix: string) => {
    let depth = 0; let start = 0;
    const parts: string[] = [];
    for (let k = 0; k < tree.length; k++) {
      const ch = tree[k];
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      else if (ch === ',' && depth === 0) { parts.push(tree.slice(start, k)); start = k + 1; }
    }
    parts.push(tree.slice(start));
    for (const p0 of parts) {
      const p = p0.trim();
      if (!p) continue;
      const brace = p.indexOf('{');
      if (brace >= 0) { walk(p.slice(brace + 1, p.lastIndexOf('}')), joinRs(prefix, p.slice(0, brace).replace(/::\s*$/, '').trim())); continue; }
      const as = /^(.*?)\s+as\s+(\w+)$/.exec(p);
      const path = joinRs(prefix, (as ? as[1]! : p).trim());
      if (path.endsWith('::*')) continue;
      const segs = path.split('::');
      const local = as ? as[2]! : segs[segs.length - 1] === 'self' ? segs[segs.length - 2]! : segs[segs.length - 1]!;
      out.set(local, segs[segs.length - 1] === 'self' ? segs.slice(0, -1).join('::') : path);
    }
  };
  for (const u of masked.matchAll(/\buse\s+([^;]+);/g)) walk(raw.slice(u.index! + u[0].indexOf(u[1]!), u.index! + u[0].indexOf(u[1]!) + u[1]!.length).replace(/\s+/g, ' '), '');
  return out;
}
const joinRs = (a: string, b: string) => (a ? (b ? `${a}::${b}` : a) : b);

interface RsFn { key: string; name: string; pkg: string; start: number; end: number; path: string }
interface Edge { parent: string | null; ref: string; file: FileScan; prefix: string; auth: string[] }
interface FileScan { path: string; crate: string; module: string[]; aliases: Map<string, string>; fns: RsFn[] }

/**
 * Module key (`pkg`) a path written in a file refers to: `use` aliases first, `crate::` / `self::` / `super::`
 * relative to the crate / module, other paths as child modules of the current module.
 */
function resolveModule(segs: string[], f: FileScan, crates: Record<string, string> = {}): string {
  if (!segs.length) return pkgKey(f.crate, f.module.join('::'));
  const head = segs[0]!;
  if (crates[head] !== undefined && !f.aliases.has(head)) return pkgKey(crates[head]!, segs.slice(1).join('::'));
  const alias = f.aliases.get(head);
  let abs: string[];
  if (head === 'crate') abs = segs.slice(1);
  else if (head === 'self') abs = [...f.module, ...segs.slice(1)];
  else if (head === 'super') { abs = [...f.module]; let k = 0; while (segs[k] === 'super') { abs.pop(); k++; } abs.push(...segs.slice(k)); }
  else if (alias) return resolveModule([...alias.split('::'), ...segs.slice(1)], f, crates);
  else abs = [...f.module, ...segs];
  return pkgKey(f.crate, abs.join('::'));
}

export function rustInputContext(view: SnapshotView): (path: string) => Partial<ExtractInput> {
  // Crates: directory → web frameworks, all dependency names, package / lib names (nearest Cargo.toml decides a file's crate).
  const crateDeps = new Map<string, string[]>();
  const crateAllDeps = new Map<string, string[]>();
  const crates: Record<string, string> = {};
  for (const f of view.listFiles()) {
    if (!(f.path === 'Cargo.toml' || f.path.endsWith('/Cargo.toml')) || f.size > MAX_BYTES) continue;
    try {
      const text = view.text(f.path);
      const dir = f.path === 'Cargo.toml' ? '' : f.path.slice(0, -'/Cargo.toml'.length);
      const deps = cargoDependencyNames(text);
      // Optional, feature-gated integrations (`axum = { …, optional = true }`) do not make a library a server crate.
      const optional = new Set([...text.matchAll(/^\s*([\w-]+)\s*=\s*\{[^}\n]*\boptional\s*=\s*true/gm)].map((x) => x[1]!));
      crateDeps.set(dir, deps.filter((d) => WEB_CRATES.includes(d) && !optional.has(d)));
      crateAllDeps.set(dir, deps);
      for (const sec of ['package', 'lib']) {
        const body = new RegExp(`^\\[${sec}\\]\\s*$([\\s\\S]*?)(?=^\\[|(?![\\s\\S]))`, 'm').exec(text)?.[1] ?? '';
        const name = /^\s*name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
        if (name) crates[name.replace(/-/g, '_')] = dir;
      }
    } catch { /* unreadable */ }
  }
  const crateDirOf = (path: string): string | null => {
    let dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
    for (;;) {
      if (crateDeps.has(dir)) return dir;
      if (!dir) return null;
      dir = dir.includes('/') ? dir.slice(0, dir.lastIndexOf('/')) : '';
    }
  };
  const frameworksOf = (path: string): string[] => {
    const dir = crateDirOf(path);
    return dir !== null ? crateDeps.get(dir)! : [...new Set([...crateDeps.values()].flat())];
  };
  // Server-reachable crates: web / RPC crates and the workspace crates they depend on (transitively).
  const reachable = new Set<string>();
  const visit = (dir: string) => {
    if (reachable.has(dir)) return;
    reachable.add(dir);
    for (const d of crateAllDeps.get(dir) ?? []) { const sub = crates[d.replace(/-/g, '_')]; if (sub !== undefined) visit(sub); }
  };
  for (const [dir, fw] of crateDeps) if (fw.length) visit(dir);

  const files: FileScan[] = [];
  const guardTypes = new Set<string>();
  const grpcAuth = new Map<string, Set<string>>();
  /** Request-guard impls: type → impl body (raw). */
  const guardImpls = new Map<string, string>();
  const edges: Edge[] = [];
  const fnsByKey = new Map<string, RsFn[]>();
  const fnsByName = new Map<string, RsFn[]>();
  for (const f of view.listFiles()) {
    if (f.lang !== 'rust' || f.size > MAX_BYTES || f.path.includes('/target/')) continue;
    let raw: string;
    try { raw = view.text(f.path); } catch { continue; }
    if (/FromRequest/.test(raw)) {
      const mg = maskRust(raw);
      for (const g of mg.matchAll(/\bimpl\s*(?:<[^{]*?>)?\s*(?:[\w:]+::)?(?:Optional)?FromRequest(?:Parts)?\s*(?:<[^{]*?>)?\s+for\s+(\w+)/g)) {
        const open = mg.indexOf('{', g.index! + g[0].length);
        const close = open < 0 ? -1 : closeOf(mg, open);
        if (close > 0 && !/^(Maybe|Optional)/.test(g[1]!)) guardImpls.set(g[1]!, raw.slice(open, close));
      }
    }
    if (/add_service|with_interceptor/.test(raw)) {
      // tonic: `Server::builder().layer(auth).add_service(GreeterServer::with_interceptor(svc, check_auth))`
      const mt = maskRust(raw);
      for (const b of mt.matchAll(/\bServer::builder\s*\(\s*\)/g)) {
        const segs = chainAfter(mt, b.index! + b[0].length);
        const layers = segs.filter((x) => x.name === 'layer').map((x) => oneLine(`.layer(${raw.slice(x.open + 1, x.close)})`)).filter((t) => isRustAuth(t.slice(7)));
        for (const x of segs.filter((y) => y.name === 'add_service' || y.name === 'add_optional_service')) {
          const arg = raw.slice(x.open + 1, x.close);
          const svc = /(\w+)Server::(?:new|with_interceptor|from_arc)/.exec(arg)?.[1];
          if (!svc) continue;
          const set = grpcAuth.get(svc) ?? new Set<string>();
          for (const l of layers) set.add(l);
          const ic = /with_interceptor\s*\([^,]+,\s*([^)]+)\)/.exec(arg)?.[1];
          if (ic) set.add(oneLine(`with_interceptor(${ic.trim()})`));
          grpcAuth.set(svc, set);
        }
      }
      for (const w of mt.matchAll(/(\w+)Server::with_interceptor\s*\(/g)) {
        const a = argRanges(mt, w.index! + w[0].length - 1);
        if (a[1]) { const set = grpcAuth.get(w[1]!) ?? new Set<string>(); set.add(oneLine(`with_interceptor(${raw.slice(...a[1]).trim()})`)); grpcAuth.set(w[1]!, set); }
      }
    }
    if (!/\b(nest|merge|scope|service|configure|mount|route)\s*\(|\broutes!|\.\s*(append|extend)\s*\(/.test(raw)) { collectFns(raw, f.path); continue; }
    const m = maskRust(raw);
    const fs = collectFns(raw, f.path, m);
    const enclosing = (at: number) => { let best: RsFn | null = null; for (const fn of fs.fns) if (fn.start <= at && at <= fn.end && (!best || fn.start > best.start)) best = fn; return best?.key ?? null; };
    const str = (a: number, b: number): string | null => { const t = raw.slice(a, b).trim(); const s = /^"((?:[^"\\]|\\.)*)"$/.exec(t); return s ? s[1]! : null; };
    const refOf = (a: number, b: number, at: number): string | null => {
      const t = m.slice(a, b).trim();
      const call = /^((?:\w+::)*\w+)\s*(?:::\s*<[^>]*>\s*)?\(/.exec(t);
      if (call) return call[1]!;
      const id = /^((?:\w+::)*\w+)$/.exec(t);
      if (!id) return null;
      // `let api = api::router();` earlier in the same function
      const fnKey = enclosing(at);
      const fn = fs.fns.find((x) => x.key === fnKey);
      if (fn && !id[1]!.includes('::')) {
        const lets = [...m.slice(fn.start, at).matchAll(new RegExp(`\\blet\\s+(?:mut\\s+)?${id[1]}\\s*(?::[^=;]+)?=\\s*((?:\\w+::)*\\w+)\\s*(?:::\\s*<[^>]*>\\s*)?\\(`, 'g'))];
        if (lets.length) return lets[lets.length - 1]![1]!;
      }
      return id[1]!;
    };
    const authOf = (segs: Seg[], names: string[]) => segs.filter((s) => names.includes(s.name)).map((s) => oneLine(`.${s.name}(${raw.slice(s.open + 1, s.close)})`)).filter((t) => isRustAuth(t.replace(/^\.\w+\(/, '')));
    // axum: `.nest("/p", x::router())` / `.merge(x::router())`, with the auth layers added after it in the chain.
    for (const n of m.matchAll(/\.\s*(nest|merge)\s*\(/g)) {
      const open = n.index! + n[0].length - 1;
      const args = argRanges(m, open);
      const prefix = n[1] === 'nest' ? str(...args[0]!) : '';
      const target = n[1] === 'nest' ? args[1] : args[0];
      if (prefix === null || !target) continue;
      const ref = refOf(target[0], target[1], n.index!);
      if (!ref || /^Router$|::new$/.test(ref)) continue;
      const after = chainAfter(m, closeOf(m, open) + 1);
      edges.push({ parent: enclosing(n.index!), ref, file: fs, prefix, auth: authOf(after, ['layer', 'route_layer']) });
    }
    // actix-web: scope / App chains with `.service(handler)`, `.configure(fn)`, `.wrap(mw)`.
    const consumed = new Set<number>();
    const walkChain = (rootEnd: number, prefix: string, inherited: string[], at: number) => {
      const segs = chainAfter(m, rootEnd);
      const auth = [...inherited, ...authOf(segs, ['wrap', 'wrap_fn'])];
      for (const s of segs) {
        if (s.name !== 'service' && s.name !== 'configure') continue;
        const inner = m.slice(s.open + 1, s.close).trim();
        const sc = /^(?:web::)?scope\s*\(/.exec(inner);
        if (sc && s.name === 'service') {
          const so = s.open + 1 + m.slice(s.open + 1).search(/\S/) + sc[0].length - 1;
          consumed.add(so);
          const a = argRanges(m, so);
          const p = a[0] ? str(...a[0]) : null;
          if (p !== null) walkChain(closeOf(m, so) + 1, joinPath(prefix, p), auth, at);
          continue;
        }
        const ref = refOf(s.open + 1, s.close, s.open);
        if (ref && !/^(web::)?(resource|route|scope)$|::new$|^Files$/.test(ref)) edges.push({ parent: enclosing(at), ref, file: fs, prefix, auth });
        consumed.add(s.open);
      }
    };
    for (const app of m.matchAll(/\bApp::new\s*\(\s*\)/g)) walkChain(app.index! + app[0].length, '', [], app.index!);
    for (const sc of m.matchAll(/(?<![\w.])(?:web::)?scope\s*\(/g)) {
      const open = sc.index! + sc[0].length - 1;
      if (consumed.has(open)) continue;
      const a = argRanges(m, open);
      const p = a[0] ? str(...a[0]) : null;
      if (p === null) continue;
      walkChain(closeOf(m, open) + 1, joinPath('', p), [], sc.index!);
    }
    // `cfg.service(h)` / `cfg.configure(f)` in configuration functions: registered at the function's own base.
    for (const s of m.matchAll(/\.\s*(service|configure)\s*\(/g)) {
      const open = s.index! + s[0].length - 1;
      if (consumed.has(open)) continue;
      const ref = refOf(open + 1, closeOf(m, open), s.index!);
      if (ref && !/^(web::)?(resource|route|scope)$|::new$|^Files$/.test(ref)) edges.push({ parent: enclosing(s.index!), ref, file: fs, prefix: '', auth: [] });
    }
    // Rocket: `.mount("/p", routes![a, m::b])`, `.mount([base, "/api"].concat(), api::core_routes())`; route-list functions
    // (`fn routes() -> Vec<Route> { routes![a, b] }`, `routes.append(&mut x::routes())`) pass their prefix on.
    const routeList = (a0: number, a1: number, at: number, prefix: string) => {
      const text = m.slice(a0, a1);
      const list = /routes!\s*[[(]([^\])]*)[\])]/.exec(text);
      if (list) { for (const r of list[1]!.split(',').map((x) => x.trim()).filter(Boolean)) edges.push({ parent: enclosing(at), ref: r, file: fs, prefix, auth: [] }); return; }
      const ref = refOf(a0, a1, at);
      if (ref && !/^(vec|Vec::new)$/.test(ref)) edges.push({ parent: enclosing(at), ref, file: fs, prefix, auth: [] });
    };
    for (const mt of m.matchAll(/\.\s*mount\s*\(/g)) {
      const open = mt.index! + mt[0].length - 1;
      const a = argRanges(m, open);
      if (!a[0] || !a[1]) continue;
      // A computed base (`[base_path, "/api"].concat()`, `format!("{}/api", base)`) contributes its literal parts.
      const p = str(...a[0]) ?? ([...raw.slice(...a[0]).matchAll(/"([^"]*)"/g)].map((x) => x[1]!.replace(/\{[^}]*\}/g, '')).join('') || null);
      if (p === null) continue;
      routeList(a[1][0], a[1][1], mt.index!, p);
    }
    if (/routes!/.test(raw)) {
      for (const r of m.matchAll(/(?<![.\w])routes!\s*\[/g)) {
        // `routes![…]` not directly inside a mount call: the enclosing function's route list.
        const before = m.slice(Math.max(0, r.index! - 200), r.index!);
        if (/\.\s*mount\s*\([^()]*,\s*$/.test(before)) continue;
        routeList(r.index!, closeOf(m, r.index! + r[0].length - 1) + 1, r.index!, '');
      }
    }
    {
      for (const ap of m.matchAll(/\.\s*(append|extend)\s*\(\s*(?:&mut\s+)?((?:\w+::)*\w+)\s*\(\s*\)/g)) {
        if (/routes?$/i.test(ap[2]!)) edges.push({ parent: enclosing(ap.index!), ref: ap[2]!, file: fs, prefix: '', auth: [] });
      }
    }
  }

  function collectFns(raw: string, path: string, masked?: string): FileScan {
    const m = masked ?? maskRust(raw);
    const { crate, module } = rustModuleOf(path);
    const pkg = pkgKey(crate, module);
    const fs: FileScan = { path, crate, module: module ? module.split('::') : [], aliases: /\buse\b/.test(raw) ? useAliases(m, raw) : new Map(), fns: [] };
    for (const fn of m.matchAll(/\bfn\s+(\w+)\s*(?:<[^>{]*>)?\s*\(/g)) {
      const open = fn.index! + fn[0].length - 1;
      const close = closeOf(m, open);
      if (close < 0) continue;
      const brace = m.slice(close).search(/[{;]/);
      if (brace < 0 || m[close + brace] !== '{') continue;
      const start = close + brace;
      const end = closeOf(m, start);
      const rec: RsFn = { key: `${pkg}#${fn[1]}`, name: fn[1]!, pkg, start, end: end < 0 ? m.length : end, path };
      fs.fns.push(rec);
      push(fnsByKey, rec.key, rec);
      push(fnsByName, rec.name, rec);
    }
    files.push(fs);
    return fs;
  }

  // Resolve edge targets to declared functions: exact module path, else a unique function of that name in a module ending with the written path.
  const filesByPkg = new Map<string, FileScan>();
  for (const f of files) filesByPkg.set(pkgKey(f.crate, f.module.join('::')), f);
  const resolveFn = (ref: string, file: FileScan, depth = 0): string | null => {
    const segs = ref.split('::');
    const name = segs.pop()!;
    const alias = segs.length ? undefined : file.aliases.get(name);
    const mod = resolveModule(segs.length ? segs : alias ? alias.split('::').slice(0, -1) : [], file, crates);
    const real = alias ? alias.split('::').pop()! : name;
    const exact = `${mod}#${real}`;
    if (fnsByKey.has(exact)) return exact;
    // Re-exports (`pub use core::routes as core_routes;` in the target module).
    const target = filesByPkg.get(mod);
    const re = target?.aliases.get(real);
    if (re && depth < 3 && target) return resolveFn(re, target, depth + 1);
    return null;
  };
  const targetOf = (e: Edge): string | null => {
    const segs = e.ref.split('::');
    const name = segs.pop()!;
    const exact = resolveFn(e.ref, e.file);
    if (exact) return exact;
    const tail = segs.filter((s) => s !== 'crate' && s !== 'self' && s !== 'super').join('::');
    const cands = (fnsByName.get(name) ?? []).filter((f) => !tail || f.pkg === tail || f.pkg.endsWith(`::${tail}`) || f.pkg.endsWith(`/${tail}`));
    return cands.length === 1 ? cands[0]!.key : null;
  };
  // Auth guards: impls that authenticate themselves, then (to a fixpoint) impls that delegate to one (`OrgHeaders::from_request`).
  for (const [t, body] of guardImpls) if (GUARD_BODY_RE.test(body)) guardTypes.add(t);
  for (let changed = true; changed;) {
    changed = false;
    for (const [t, body] of guardImpls) {
      if (guardTypes.has(t)) continue;
      if ([...body.matchAll(/\b(\w+)::from_request(?:_parts)?\b|<(\w+)\s+as\s+FromRequest/g)].some((m) => guardTypes.has(m[1] ?? m[2]!))) { guardTypes.add(t); changed = true; }
    }
  }
  const incoming = new Map<string, Edge[]>();
  for (const e of edges) { const t = targetOf(e); if (t) push(incoming, t, e); }
  const memo = new Map<string, RsBase[]>();
  const basesOf = (key: string, seen: Set<string>): RsBase[] => {
    const hit = memo.get(key);
    if (hit) return hit;
    const ins = incoming.get(key);
    if (!ins?.length || seen.has(key) || seen.size > 12) return [{ prefix: '', auth: [] }];
    const out = new Map<string, RsBase>();
    for (const e of ins) {
      const parents = e.parent ? basesOf(e.parent, new Set([...seen, key])) : [{ prefix: '', auth: [] }];
      for (const p of parents) {
        const b = { prefix: joinPath(p.prefix, e.prefix), auth: [...new Set([...e.auth, ...p.auth])] };
        out.set(`${b.prefix}|${b.auth.join('|')}`, b);
      }
    }
    const res = [...out.values()].sort((a, b) => a.prefix.localeCompare(b.prefix));
    memo.set(key, res);
    return res;
  };
  const byPath = new Map<string, FileScan>();
  for (const f of files) byPath.set(f.path, f);
  return (path) => {
    const fs = byPath.get(path);
    const fnBases: Record<string, RsBase[]> = {};
    for (const fn of fs?.fns ?? []) {
      if (!incoming.has(fn.key)) continue;
      const b = basesOf(fn.key, new Set());
      if (b.length !== 1 || b[0]!.prefix || b[0]!.auth.length) fnBases[fn.name] = b;
    }
    const dir = crateDirOf(path);
    const ctx: RustContext = { frameworks: frameworksOf(path), fnBases, crates, serverReachable: dir === null || reachable.has(dir) || !reachable.size, guardTypes: [...guardTypes].sort(), grpcAuth: Object.fromEntries([...grpcAuth].map(([k, v]) => [k, [...v]])) };
    return { langContext: ctx as unknown as Record<string, unknown> };
  };
}

export function joinPath(a: string, b: string): string {
  const j = `/${a}/${b}`.replace(/\/{2,}/g, '/');
  return j.length > 1 ? j.replace(/\/+$/, '') : '';
}
const oneLine = (s: string) => { const t = s.replace(/\s+/g, ' ').trim(); return t.length > 160 ? t.slice(0, 160) + '…' : t; };
function push<K, V>(m: Map<K, V[]>, k: K, v: V): void { const a = m.get(k); if (a) a.push(v); else m.set(k, [v]); }
