// Rust extraction (80–83): symbols (free functions, `impl` / trait-impl methods, structs,
// enums, traits, inline `mod` blocks), calls with receiver facts and `use` aliases; entries of axum (router chains with
// `nest` / `merge` / `layer`), actix-web (route macros, `App` / `scope` / `resource` builders, `wrap`) and Rocket (route
// macros, `mount` prefixes) with auth signals from layers, middleware and extractor / request-guard types; sinks from
// `rules/rust/**`.
//
// Identities follow the registry conventions (languages.ts): the module key `FileExtract.pkg` is the crate-relative
// module path joined with `::` (`src/lib.rs` / `src/main.rs` → '', `src/api/users.rs` → `api::users`,
// `src/api/mod.rs` → `api`), prefixed by the crate directory when the crate is not at the repository root
// (`server/src/db.rs` → `server/db`). Free functions have that container; methods of `impl T` have `<module>.T`;
// arity excludes `self`.
import type { Node, Tree } from 'web-tree-sitter';
import { fillApi, makeSink, rangeOf, ruleMatches, type CompiledRule } from './common.js';
import { isRustAuth, joinPath, pkgKey, rustModuleOf, type RsBase, type RustContext } from './extract-rust-context.js';
import { rpcOf } from './proto.js';
import { emptyExtract, type ExtractInput, type FileExtract, type HandlerRef, type RawEntry } from './types.js';

export { rustModuleOf };

const named = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c);
const oneLine = (s: string, n = 200) => { const t = s.replace(/\s+/g, ' ').trim(); return t.length > n ? t.slice(0, n) + '…' : t; };

/** Type name of an `impl` target / type node (`Arc<UserRepo>` → `Arc`, `crate::db::Repo` → `Repo`, `&Self` → `Self`). */
export function rustTypeName(t: Node | null | undefined): string | null {
  if (!t) return null;
  const s = t.text.replace(/^&\s*(mut\s+)?/, '').replace(/<.*$/s, '').split('::').pop()?.trim() ?? '';
  return /^[A-Za-z_]\w*$/.test(s) ? s : null;
}

export function extractRust(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const root = tree.rootNode;
  const repo = input.repo;
  const { crate, module: fileModule } = rustModuleOf(input.path);
  fx.pkg = pkgKey(crate, fileModule);
  const fnIds = new Map<number, string>();
  const implTypes = new Map<number, string>(); // impl node → type name
  const ctx = input.langContext as RustContext | undefined;
  const crates = ctx?.crates ?? {};

  // ---- `use` aliases: local name → module path (crate-relative for `crate::` / `self::` / `super::`) ----
  const aliases = new Map<string, string>();
  const absolute = (path: string, moduleSegs: string[]): string => {
    const parts = path.split('::').filter(Boolean);
    let base: string[];
    if (parts[0] === 'crate') { parts.shift(); base = []; }
    else if (parts[0] === 'self') { parts.shift(); base = [...moduleSegs]; }
    else if (parts[0] === 'super') { base = [...moduleSegs]; while (parts[0] === 'super') { parts.shift(); base.pop(); } }
    else if (crates[parts[0]!] !== undefined) return pkgKey(crates[parts.shift()!]!, parts.join('::')); // sibling workspace crate
    else return path; // external crate path
    return pkgKey(crate, [...base, ...parts].join('::'));
  };
  const fileSegs = fileModule ? fileModule.split('::') : [];
  for (const u of root.descendantsOfType('use_declaration')) {
    const arg = u?.childForFieldName('argument');
    if (!arg) continue;
    const add = (path: string, alias?: string) => {
      const segs = path.split('::');
      const local = alias ?? segs[segs.length - 1]!;
      if (local === 'self') { aliases.set(segs[segs.length - 2] ?? local, absolute(segs.slice(0, -1).join('::'), fileSegs)); return; }
      aliases.set(local, absolute(path, fileSegs));
    };
    const walk = (n: Node, prefix: string) => {
      if (n.type === 'scoped_identifier' || n.type === 'identifier' || n.type === 'crate' || n.type === 'self' || n.type === 'super') add(prefix ? `${prefix}::${n.text}` : n.text);
      else if (n.type === 'use_as_clause') add(prefix ? `${prefix}::${n.childForFieldName('path')?.text}` : n.childForFieldName('path')?.text ?? '', n.childForFieldName('alias')?.text);
      else if (n.type === 'scoped_use_list') { const p = n.childForFieldName('path')?.text ?? ''; const list = n.childForFieldName('list'); for (const c of named(list)) walk(c, prefix ? `${prefix}::${p}` : p); }
      else if (n.type === 'use_list') for (const c of named(n)) walk(c, prefix);
    };
    walk(arg, '');
  }

  // ---- symbols ----
  const signature = (n: Node) => {
    const body = n.childForFieldName('body');
    return oneLine(body ? n.text.slice(0, body.startIndex - n.startIndex) : n.text, 300);
  };
  const arityOf = (fn: Node) => named(fn.childForFieldName('parameters')).filter((p) => p.type === 'parameter').length;
  const visit = (node: Node, modSegs: string[], implType: string | null) => {
    const container = pkgKey(crate, modSegs.join('::'));
    if (node.type === 'mod_item' && node.childForFieldName('body')) {
      const name = node.childForFieldName('name')?.text ?? '?';
      for (const c of named(node.childForFieldName('body'))) visit(c, [...modSegs, name], null);
      return;
    }
    if (node.type === 'impl_item') {
      const t = rustTypeName(node.childForFieldName('type'));
      if (t) implTypes.set(node.id, t);
      for (const c of named(node.childForFieldName('body'))) visit(c, modSegs, t);
      return;
    }
    if (node.type === 'struct_item' || node.type === 'enum_item' || node.type === 'trait_item') {
      const name = node.childForFieldName('name')?.text ?? '?';
      fx.symbols.push({
        symbolId: `${repo}:${input.path}#${container}.${name}`, repo, kind: node.type === 'trait_item' ? 'interface' : 'class', name, container,
        path: input.path, range: rangeOf(node), signature: signature(node), qualifiedName: `${container ? `${container}::` : ''}${name}`,
      });
      if (node.type === 'trait_item') for (const c of named(node.childForFieldName('body'))) visit(c, modSegs, name);
      return;
    }
    if (node.type === 'function_item') {
      const name = node.childForFieldName('name')?.text ?? '?';
      const arity = arityOf(node);
      const owner = implType ? `${container}.${implType}` : container;
      const symbolId = `${repo}:${input.path}#${owner}.${name}(${arity})`;
      fnIds.set(node.id, symbolId);
      fx.symbols.push({
        symbolId, repo, kind: implType ? 'method' : 'func', name, container: owner, path: input.path, range: rangeOf(node),
        signature: signature(node), qualifiedName: `${container ? `${container}::` : ''}${implType ? `${implType}::` : ''}${name}`,
      });
      for (const c of named(node.childForFieldName('body'))) visit(c, modSegs, null);
      return;
    }
    for (const c of named(node)) visit(c, modSegs, implType);
  };
  visit(root, fileSegs, null);

  const enclosingFn = (n: Node): Node | null => {
    for (let p = n.parent; p; p = p.parent) if (fnIds.has(p.id)) return p;
    return null;
  };
  const enclosingImpl = (n: Node): string | null => {
    for (let p = n.parent; p; p = p.parent) { const t = implTypes.get(p.id); if (t) return t; }
    return null;
  };

  // ======================= entries, auth signals, sinks =======================
  const rawAliases = aliases;
  const frameworks = new Set(ctx?.frameworks ?? []);
  const fnBases = (n: Node): RsBase[] => {
    const fn = enclosingFn(n);
    const name = fn?.childForFieldName('name')?.text;
    return (name && ctx?.fnBases[name]) || [{ prefix: '', auth: [] }];
  };
  const str = (n: Node | null | undefined): string | null => {
    if (!n) return null;
    if (n.type === 'string_literal' || n.type === 'raw_string_literal') return named(n).filter((c) => c.type === 'string_content').map((c) => c.text).join('');
    return null;
  };
  const argsOf = (call: Node): Node[] => named(call.childForFieldName('arguments'));
  /** Method-call view of a call: `recv.name(args)` → { name, recv }; `path::name(args)` / `name(args)` → { name, path }. */
  const callInfo = (call: Node): { name: string; recv: Node | null; path: string | null; fn: Node } | null => {
    let f = call.childForFieldName('function');
    if (!f) return null;
    if (f.type === 'generic_function') f = f.childForFieldName('function') ?? f;
    if (f.type === 'field_expression') return { name: f.childForFieldName('field')?.text ?? '', recv: f.childForFieldName('value'), path: null, fn: f };
    if (f.type === 'scoped_identifier') return { name: f.childForFieldName('name')?.text ?? '', recv: null, path: f.childForFieldName('path')?.text ?? '', fn: f };
    if (f.type === 'identifier') return { name: f.text, recv: null, path: null, fn: f };
    return null;
  };
  /** Next call up a method chain: `x.a()` → the call `x.a().b(…)` whose receiver is `x.a()`. */
  const chainParent = (n: Node): Node | null => {
    const p = n.parent;
    if (p?.type === 'field_expression' && p.childForFieldName('value')?.id === n.id && p.parent?.type === 'call_expression') return p.parent;
    if ((p?.type === 'await_expression' || p?.type === 'try_expression') && p.parent) return chainParent(p);
    return null;
  };
  const chainTop = (n: Node): Node => { let cur = n; for (let up = chainParent(cur); up; up = chainParent(cur)) cur = up; return cur; };
  /** Root call of a chain (`web::scope("/api")` in `web::scope("/api").wrap(a).service(b)`). */
  const chainRoot = (n: Node): Node => {
    let cur = n;
    for (;;) {
      const f = cur.type === 'call_expression' ? cur.childForFieldName('function') : null;
      const v = f?.type === 'field_expression' ? f.childForFieldName('value') : null;
      if (v?.type === 'call_expression') cur = v; else return cur;
    }
  };
  const chainCalls = (top: Node): Node[] => {
    const out: Node[] = [];
    for (let cur: Node | null = top; cur?.type === 'call_expression';) {
      out.unshift(cur);
      const f: Node | null = cur.childForFieldName('function');
      const v: Node | null = f?.type === 'field_expression' ? f.childForFieldName('value') : null;
      cur = v?.type === 'call_expression' ? v : null;
    }
    return out;
  };

  /** Handler reference of an expression: function path, closure (synthetic symbol), or `Type::method`. */
  const syntheticIds = new Set<string>();
  const handlerRef = (h: Node | undefined, label: string): HandlerRef => {
    if (!h) return { text: 'anonymous' };
    if (h.type === 'closure_expression' || h.type === 'async_block') {
      const container = fx.pkg;
      let name = `<${label}>`;
      let symbolId = `${repo}:${input.path}#${container}.${name}(0)`;
      for (let i = 2; syntheticIds.has(symbolId); i++) { name = `<${label} #${i}>`; symbolId = `${repo}:${input.path}#${container}.${name}(0)`; }
      syntheticIds.add(symbolId);
      const arity = named(h.childForFieldName('parameters')).length;
      symbolId = symbolId.replace(/\(0\)$/, `(${arity})`);
      fnIds.set(h.id, symbolId);
      fx.symbols.push({ symbolId, repo, kind: 'func', name, container, path: input.path, range: rangeOf(h), signature: oneLine(h.text.split('\n')[0]!, 300), qualifiedName: `${container ? `${container}::` : ''}${name}` });
      return { symbolId, range: rangeOf(h) };
    }
    const text = h.text.replace(/::<[^>]*>/g, '').replace(/\s+/g, '');
    if (!/^[\w:]+$/.test(text)) return { text: oneLine(text, 80) };
    const segs = text.split('::');
    const name = segs.pop()!;
    if (segs.length && /^[A-Z]/.test(segs[segs.length - 1]!)) return { text: name, className: segs[segs.length - 1]! }; // `UserHandler::create`
    if (!segs.length) {
      const imp = aliases.get(name);
      if (imp && imp.includes('::')) return { text: name, importPath: imp.slice(0, imp.lastIndexOf('::')) };
      return { text: name, importPath: fx.pkg };
    }
    const head = segs[0]!;
    const mod = aliases.has(head) ? [aliases.get(head)!, ...segs.slice(1)].join('::') : head === 'crate' || head === 'self' || head === 'super' || crates[head] !== undefined ? absolute(segs.join('::'), fileSegs) : pkgKey(crate, [...fileSegs, ...segs].join('::'));
    return { text: name, importPath: mod };
  };
  /** Auth signals from a handler's extractor / request-guard parameter types (`claims: Claims`, `Extension<CurrentUser>`, `user: AuthUser`). */
  const fnByName = new Map<string, Node>();
  const fnNodeById = new Map<number, Node>();
  const guardTypes = new Set(ctx?.guardTypes ?? []);
  for (const fnNode of root.descendantsOfType('function_item')) if (fnNode) { fnNodeById.set(fnNode.id, fnNode); const n = fnNode.childForFieldName('name')?.text; if (n && !fnByName.has(n)) fnByName.set(n, fnNode); }
  const guardSignals = (fn: Node | undefined): string[] => {
    if (!fn) return [];
    const out: string[] = [];
    for (const p of named(fn.childForFieldName('parameters'))) {
      if (p.type !== 'parameter') continue;
      const t = p.childForFieldName('type');
      if (t && isGuardType(t.text, guardTypes)) out.push(`extractor: ${oneLine(t.text, 80)}`);
    }
    return out;
  };
  // Every function's guard parameters are auth signals on its symbol; entries in router files pick them up (`targetSignals`).
  for (const [id, symbolId] of fnIds) {
    const fn = fnNodeById.get(id);
    if (!fn) continue;
    for (const g of guardSignals(fn)) if (!fx.authSignals.some((x) => x.target === symbolId && x.detail === g)) fx.authSignals.push({ target: symbolId, kind: 'annotation', detail: g, ruleId: 'rust.web.route-macros' });
  }
  const sameFileHandler = (ref: HandlerRef): Node | undefined => (ref.importPath === fx.pkg && ref.text ? fnByName.get(ref.text) : undefined);
  const pushEntry = (ruleId: string, framework: string, method: string, path: string, ref: HandlerRef, at: Node, middlewares: string[], auth: string[]) => {
    fx.entries.push({ ruleId, framework, httpMethod: method, pathTemplate: path || '/', handler: { ...ref, targetSignals: true }, path: input.path, range: rangeOf(at), middlewares: [...new Set(middlewares)], authSignals: [...new Set(auth)] });
  };

  // ---- axum ----
  const AXUM_VERBS: Record<string, string> = { get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH', delete: 'DELETE', head: 'HEAD', options: 'OPTIONS', trace: 'TRACE', any: 'ANY' };
  /** `get(a).post(b).layer(x)` → verbs with handlers and method-level layers. */
  const methodRouter = (n: Node | undefined): { verbs: { verb: string; h: Node | undefined }[]; layers: string[] } => {
    const verbs: { verb: string; h: Node | undefined }[] = [];
    const layers: string[] = [];
    let cur: Node | null = n ?? null;
    while (cur?.type === 'call_expression') {
      const ci = callInfo(cur);
      if (!ci) break;
      const a = argsOf(cur);
      if (AXUM_VERBS[ci.name]) verbs.unshift({ verb: AXUM_VERBS[ci.name]!, h: a[0] });
      else if (ci.name === 'on' || ci.name === 'on_service') { const vs = [...(a[0]?.text ?? '').matchAll(/MethodFilter::(\w+)/g)].map((m) => m[1]!); for (const v of vs.length ? vs : ['ANY']) verbs.unshift({ verb: v, h: a[1] }); }
      else if (ci.name === 'layer' || ci.name === 'route_layer') { const t = oneLine(a[0]?.text ?? '', 160); if (isRustAuth(t)) layers.push(`.${ci.name}(${t})`); }
      else if (/_service$/.test(ci.name)) return { verbs: [], layers: [] };
      cur = ci.recv && ci.recv.type === 'call_expression' ? ci.recv : null;
    }
    return { verbs, layers };
  };
  /**
   * Prefixes and auth layers of a router chain position, climbing: later `.layer` / `.route_layer` segments of the
   * same chain, `.nest("/p", <chain>)` / `.merge(<chain>)` of an enclosing chain, `let x = <chain>` and its later use,
   * and finally the function's own bases from the snapshot (`fnBases`).
   */
  const climbAxum = (n: Node, depth = 0): RsBase[] => {
    if (depth > 8) return [{ prefix: '', auth: [] }];
    const auth: string[] = [];
    let cur = n;
    for (let up = chainParent(cur); up; up = chainParent(cur)) {
      const ci = callInfo(up);
      if (ci && (ci.name === 'layer' || ci.name === 'route_layer')) { const t = oneLine(argsOf(up)[0]?.text ?? '', 160); if (isRustAuth(t)) auth.push(`.${ci.name}(${t})`); }
      cur = up;
    }
    const withAuth = (bs: RsBase[], prefix: string) => bs.map((b) => ({ prefix: joinPath(b.prefix, prefix), auth: [...new Set([...auth, ...b.auth])] }));
    const p = cur.parent;
    if (p?.type === 'arguments' && p.parent?.type === 'call_expression') {
      const outer = p.parent;
      const ci = callInfo(outer);
      if (ci?.name === 'nest' || ci?.name === 'merge') return withAuth(climbAxum(outer, depth + 1), ci.name === 'nest' ? str(argsOf(outer)[0]) ?? '' : '');
    }
    const binding = p?.type === 'let_declaration' ? p.childForFieldName('pattern') : p?.type === 'assignment_expression' && p.childForFieldName('right')?.id === cur.id ? p.childForFieldName('left') : null;
    if (binding?.type === 'identifier') {
      const fn = enclosingFn(cur);
      const uses = (fn ?? root).descendantsOfType('identifier').filter((i): i is Node => !!i && i.text === binding.text && i.startIndex > cur.endIndex);
      for (const u of uses) {
        const up = u.parent;
        if (up?.type === 'arguments' && up.parent?.type === 'call_expression') {
          const ci = callInfo(up.parent);
          if (ci?.name === 'nest' || ci?.name === 'merge') return withAuth(climbAxum(up.parent, depth + 1), ci.name === 'nest' ? str(argsOf(up.parent)[0]) ?? '' : '');
          continue;
        }
        if (up?.type === 'field_expression' && up.childForFieldName('value')?.id === u.id) return withAuth(climbAxum(u, depth + 1), '');
      }
    }
    return withAuth(fnBases(cur), '');
  };

  // ---- actix-web builder ----
  const ACTIX_VERBS: Record<string, string> = { get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH', delete: 'DELETE', head: 'HEAD', trace: 'TRACE' };
  /** `web::get().to(h)`, `web::route().guard(guard::Post()).to(h)`, `web::method(Method::GET).to(h)` → verbs + handler. */
  const actixRoute = (n: Node | undefined): { verbs: string[]; h: Node | undefined } | null => {
    if (n?.type !== 'call_expression') return null;
    const ci = callInfo(n);
    if (ci?.name !== 'to' || !ci.recv) return null;
    const t = ci.recv.text;
    const m = /(?:^|::)(get|post|put|patch|delete|head|trace)\s*\(\s*\)/.exec(t);
    const g = [...t.matchAll(/guard::(Get|Post|Put|Patch|Delete|Head|Trace)\b/g)].map((x) => x[1]!.toUpperCase());
    const mm = [...t.matchAll(/Method::([A-Z]+)/g)].map((x) => x[1]!);
    const verbs = m ? [ACTIX_VERBS[m[1]!]!] : g.length ? g : mm.length ? mm : ['ANY'];
    return { verbs, h: argsOf(n)[0] };
  };
  /** Scope prefixes and `wrap` middleware around an actix chain position, then the function's bases. */
  const climbActix = (n: Node, depth = 0): RsBase[] => {
    if (depth > 8) return [{ prefix: '', auth: [] }];
    const top = chainTop(n);
    const calls = chainCalls(top);
    const rootCall = chainRoot(top);
    const rci = callInfo(rootCall);
    const prefix = rci?.name === 'scope' ? str(argsOf(rootCall)[0]) ?? '' : '';
    const auth = calls.map((c) => ({ c, ci: callInfo(c) })).filter(({ ci }) => ci?.name === 'wrap' || ci?.name === 'wrap_fn').map(({ c, ci }) => `.${ci!.name}(${oneLine(argsOf(c)[0]?.text ?? '', 160)})`).filter((t) => isRustAuth(t.replace(/^\.\w+\(/, '')));
    const withAuth = (bs: RsBase[]) => bs.map((b) => ({ prefix: joinPath(b.prefix, prefix), auth: [...new Set([...auth, ...b.auth])] }));
    const p = top.parent;
    if (p?.type === 'arguments' && p.parent?.type === 'call_expression' && callInfo(p.parent)?.name === 'service') return withAuth(climbActix(p.parent, depth + 1));
    return withAuth(fnBases(top));
  };

  // ---- macro routes: actix-web `#[get("/p")]`, Rocket `#[get("/p/<id>")]` ----
  const rocket = frameworks.has('rocket');
  const actix = frameworks.has('actix-web') || frameworks.has('ntex');
  const MACRO_VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace', 'connect', 'route']);
  const macroRoutes = (ruleId: string) => {
    for (const fn of root.descendantsOfType('function_item')) {
      if (!fn) continue;
      const attrs: Node[] = [];
      for (let s = fn.previousNamedSibling; s && (s.type === 'attribute_item' || s.type === 'line_comment' || s.type === 'block_comment'); s = s.previousNamedSibling) if (s.type === 'attribute_item') attrs.push(s);
      const name = fn.childForFieldName('name')?.text ?? '';
      const symbolId = fnIds.get(fn.id);
      if (!symbolId) continue;
      for (const a of attrs) {
        const attr = named(a)[0];
        const pathNode = attr ? named(attr)[0] : undefined;
        const macro = pathNode?.text.split('::').pop() ?? '';
        if (!MACRO_VERBS.has(macro)) continue;
        const crateHint = pathNode?.text.includes('::') ? pathNode.text.split('::')[0] : null;
        const tt = attr?.childForFieldName('arguments');
        if (!tt) continue;
        const strings = named(tt).filter((c) => c.type === 'string_literal');
        const ttText = tt.text;
        const uri0 = /\buri\s*=\s*"([^"]*)"/.exec(ttText)?.[1] ?? str(strings[0]) ?? null;
        if (uri0 === null) continue;
        // Rocket query segments (`/go?<to>&<page>`) are not part of the path.
        const uri = uri0.replace(/\?.*$/, '');
        const isRocket = crateHint === 'rocket' || (crateHint !== 'actix_web' && crateHint !== 'ntex' && (rocket && !actix ? true : !rocket && actix ? false : /<[^>]+>/.test(uri)));
        let verbs: string[];
        if (macro === 'route') {
          const vs = [...ttText.matchAll(/method\s*=\s*"?(\w+)"?/g)].map((m) => m[1]!.toUpperCase());
          const bare = [...ttText.matchAll(/^\s*\(?\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g)].map((m) => m[1]!);
          verbs = vs.length ? vs : bare.length ? bare : ['ANY'];
        } else verbs = [macro.toUpperCase()];
        const wrap = [...ttText.matchAll(/wrap\s*=\s*"([^"]*)"/g)].map((m) => `wrap = "${m[1]}"`).filter(isRustAuth);
        const guards = guardSignals(fn);
        const bases = ctx?.fnBases[name] ?? [{ prefix: '', auth: [] }];
        for (const b of bases) for (const v of verbs) {
          pushEntry(ruleId, isRocket ? 'rocket' : 'actix-web', v, joinPath(b.prefix, uri), { symbolId, range: rangeOf(fn) }, fn, [...b.auth, ...wrap], [...b.auth, ...wrap, ...guards]);
        }
      }
    }
  };

  const builderRoutes = (ruleId: string) => {
    for (const call of root.descendantsOfType('call_expression')) {
      if (!call) continue;
      const ci = callInfo(call);
      if (!ci) continue;
      const a = argsOf(call);
      if (ci.name === 'route' && ci.recv && a.length === 2 && str(a[0]) !== null) {
        const path = str(a[0])!;
        const ar = actixRoute(a[1]);
        if (ar) {
          // actix `.route("/p", web::get().to(h))` on App / Scope / ServiceConfig
          const ref = handlerRef(ar.h, `${ar.verbs.join(',')} ${path}`);
          for (const b of climbActix(call)) for (const v of ar.verbs) pushEntry(ruleId, 'actix-web', v, joinPath(b.prefix, path), ref, call, b.auth, [...b.auth, ...guardSignals(sameFileHandler(ref))]);
          continue;
        }
        if (!frameworks.has('axum') && frameworks.size) continue;
        const mr = methodRouter(a[1]);
        if (!mr.verbs.length) continue;
        const bases = climbAxum(call);
        for (const { verb, h } of mr.verbs) {
          const ref = handlerRef(h, `${verb} ${path}`);
          const guards = guardSignals(h?.type === 'closure_expression' ? h : sameFileHandler(ref));
          for (const b of bases) pushEntry(ruleId, 'axum', verb, joinPath(b.prefix, path), ref, call, [...b.auth, ...mr.layers], [...b.auth, ...mr.layers, ...guards]);
        }
        continue;
      }
      // actix `web::resource("/p").route(web::post().to(h))` / `.to(h)` / `.get(h)`
      if ((ci.name === 'route' && a.length === 1) || (ci.name === 'to' && ci.recv?.type === 'call_expression' && callInfo(ci.recv)?.name !== 'get') || (ACTIX_VERBS[ci.name] && a.length === 1 && ci.recv)) {
        const rootCall = chainRoot(call);
        const rci = callInfo(rootCall);
        if (rci?.name !== 'resource' || rootCall.id === call.id) continue;
        const path = str(argsOf(rootCall)[0]);
        if (path === null) continue;
        const spec = ci.name === 'route' ? actixRoute(a[0]) : ci.name === 'to' ? { verbs: ['ANY'], h: a[0] } : { verbs: [ACTIX_VERBS[ci.name]!], h: a[0] };
        if (!spec) continue;
        const ref = handlerRef(spec.h, `${spec.verbs.join(',')} ${path}`);
        for (const b of climbActix(call)) for (const v of spec.verbs) pushEntry(ruleId, 'actix-web', v, joinPath(b.prefix, path), ref, call, b.auth, [...b.auth, ...guardSignals(sameFileHandler(ref))]);
      }
    }
  };

  /** Inside `#[cfg(test)] mod …` or a `#[test]` / `#[tokio::test]` function. */
  const testMemo = new Map<number, boolean>();
  const isTestItem = (n: Node): boolean => {
    for (let s = n.previousNamedSibling; s && (s.type === 'attribute_item' || s.type === 'line_comment' || s.type === 'block_comment'); s = s.previousNamedSibling) {
      if (s.type === 'attribute_item' && /^#\[\s*(cfg\s*\(\s*test\s*\)|(\w+::)*test\b|rstest\b|test_case\b)/.test(s.text)) return true;
    }
    return false;
  };
  const inTestCode = (n: Node): boolean => {
    for (let p = n.parent; p; p = p.parent) {
      if (p.type !== 'mod_item' && p.type !== 'function_item') continue;
      let hit = testMemo.get(p.id);
      if (hit === undefined) { hit = isTestItem(p); testMemo.set(p.id, hit); }
      if (hit) return true;
    }
    return false;
  };


  // ---- non-HTTP entries: tonic services, MQ consumers, cron jobs, clap subcommands ----
  const camelRpc = (name: string) => name.split('_').map((w) => (w ? w[0]!.toUpperCase() + w.slice(1) : w)).join('');
  const pushChannel = (ruleId: string, framework: string, channel: NonNullable<RawEntry['channel']>, ref: HandlerRef, at: Node, auth: string[] = []) => {
    fx.entries.push({ channel, ruleId, framework, httpMethod: '', pathTemplate: '', handler: ref, path: input.path, range: rangeOf(at), middlewares: auth, authSignals: auth });
  };
  const enclosingRef = (n: Node): HandlerRef => { const fn = enclosingFn(n); return fn ? { symbolId: fnIds.get(fn.id)!, range: rangeOf(fn) } : { text: 'anonymous', range: rangeOf(n) }; };
  const channelEntries = (ruleId: string) => {
    // tonic: `#[tonic::async_trait] impl Greeter for MyGreeter { async fn say_hello(&self, req: Request<…>) … }`
    for (const impl of root.descendantsOfType('impl_item')) {
      if (!impl) continue;
      const trait = impl.childForFieldName('trait')?.text.replace(/<.*$/, '').split('::').pop();
      if (!trait) continue;
      let asyncTrait = false;
      for (let sib = impl.previousNamedSibling; sib?.type === 'attribute_item'; sib = sib.previousNamedSibling) if (/async_trait/.test(sib.text)) asyncTrait = true;
      const proto = input.grpcServices?.some((g) => g.name === trait) ?? false;
      if (!proto && !(asyncTrait && /Request</.test(impl.text) && /tonic/.test(input.text))) continue;
      const auth = ctx?.grpcAuth?.[trait] ?? [];
      for (const fnNode of named(impl.childForFieldName('body'))) {
        if (fnNode.type !== 'function_item') continue;
        const id = fnIds.get(fnNode.id);
        const name = fnNode.childForFieldName('name')?.text ?? '';
        const rpc = rpcOf(input.grpcServices, trait, camelRpc(name));
        if (!id || !rpc) continue;
        fx.entries.push({ rpc, ruleId, framework: 'tonic', httpMethod: 'RPC', pathTemplate: '', handler: { symbolId: id, targetSignals: true }, path: input.path, range: rangeOf(fnNode), middlewares: auth, authSignals: auth });
      }
    }
    for (const call of root.descendantsOfType('call_expression')) {
      if (!call) continue;
      const ci = callInfo(call);
      if (!ci) continue;
      const a = argsOf(call);
      // lapin: `channel.basic_consume("queue", "tag", opts, args)`
      if (ci.name === 'basic_consume' && ci.recv) { const q = str(a[0]); if (q) pushChannel(ruleId, 'lapin', { kind: 'message', protocol: 'rabbitmq', key: `mq:rabbitmq:${q}`, route: q }, enclosingRef(call), call); continue; }
      // rdkafka / rskafka: `consumer.subscribe(&["orders", "payments"])`
      if (ci.name === 'subscribe' && ci.recv && /consumer|kafka/i.test(ci.recv.text)) {
        for (const t of [...(a[0]?.text ?? '').matchAll(/"([^"]+)"/g)].map((m) => m[1]!)) pushChannel(ruleId, 'rdkafka', { kind: 'message', protocol: 'kafka', key: `mq:kafka:${t}`, route: t }, enclosingRef(call), call);
        continue;
      }
      // tokio-cron-scheduler: `Job::new_async("0 0 * * * *", |id, sched| Box::pin(async move { … }))`
      if (ci.path && /(^|::)Job$/.test(ci.path) && /^new(_async|_cron_job|_cron_job_async|_repeated|_repeated_async|_one_shot|_one_shot_async)?$/.test(ci.name) && a.length >= 2) {
        const when = str(a[0]) ?? oneLine(a[0]!.text, 60);
        const ref = handlerRef(a[a.length - 1], `cron ${when}`);
        pushChannel(ruleId, 'tokio-cron-scheduler', { kind: 'schedule', protocol: 'cron', key: `cron:${when}:${input.path}:${call.startPosition.row + 1}`, route: when }, ref, call);
      }
    }
    // clap: `#[derive(Subcommand)] enum Commands { Import { … }, Serve }` → one command per variant (server-reachable crates only:
    // a workspace's client CLI is context).
    if (ctx?.serverReachable === false) return;
    for (const en of root.descendantsOfType('enum_item')) {
      if (!en) continue;
      let sub = false;
      for (let sib = en.previousNamedSibling; sib?.type === 'attribute_item'; sib = sib.previousNamedSibling) if (/derive\s*\([^)]*\bSubcommand\b/.test(sib.text)) sub = true;
      if (!sub) continue;
      const enumName = en.childForFieldName('name')?.text ?? '';
      const container = fx.pkg;
      const enumId = `${repo}:${input.path}#${container}.${enumName}`;
      for (const v of named(en.childForFieldName('body'))) {
        if (v.type !== 'enum_variant') continue;
        const vn = v.childForFieldName('name')?.text ?? '';
        const cmd = vn.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
        pushChannel(ruleId, 'clap', { kind: 'cli', protocol: 'cli', key: `cli:${cmd}`, route: cmd }, { symbolId: enumId, range: rangeOf(v) }, v);
      }
    }
  };

  // ---- rules ----
  const seenSinks = new Set<string>();
  const ordered = [...rules].sort((x, y) => (x.rule.kind === 'entrypoint' ? 0 : 1) - (y.rule.kind === 'entrypoint' ? 0 : 1));
  const ran = new Set<string>();
  for (const { rule, query, error } of ordered) {
    if (error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${error}` }); continue; }
    if (!query) continue;
    try {
      if (rule.post === 'rust_router_routes' || rule.post === 'rust_macro_routes' || rule.post === 'rust_channels') {
        if (ran.has(rule.post)) continue;
        ran.add(rule.post);
        if (rule.post === 'rust_router_routes') builderRoutes(rule.id); else if (rule.post === 'rust_macro_routes') macroRoutes(rule.id); else channelEntries(rule.id);
        continue;
      }
      if (rule.kind !== 'sink' || ctx?.serverReachable === false) continue;
      for (const match of query.matches(root)) {
        const cap = new Map<string, Node>();
        for (const c of match.captures) if (!cap.has(c.name)) cap.set(c.name, c.node);
        const node = cap.get('call');
        if (!node || inTestCode(node)) continue;
        const method = cap.get('method')?.text ?? '';
        const recvNode = cap.get('receiver') ?? null;
        // Receiver text with `use` aliases expanded (`fs::read` → `std::fs`); bare imported calls use their module.
        let receiverText: string | null = recvNode ? recvNode.text.replace(/\s+/g, '') : null;
        if (receiverText && recvNode?.type !== 'call_expression' && /^[\w:]+$/.test(receiverText)) { const segs = receiverText.split('::'); const al = rawAliases.get(segs[0]!); if (al) receiverText = [al, ...segs.slice(1)].join('::'); }
        if (!recvNode && method) { const al = rawAliases.get(method); if (al && al.includes('::')) receiverText = al.slice(0, al.lastIndexOf('::')); }
        const a = node.type === 'call_expression' ? argsOf(node) : [];
        if (!ruleMatches(rule.match, { receiverText, receiverType: null, receiverImport: null, imports: new Set(), argCount: a.length })) continue;
        const verdict = rustSinkPost(rule.post, { node, method, a, receiverText, taint: (x) => rustTaint(x, enclosingFn(node)) });
        if (!verdict) continue;
        const api = fillApi(rule.api ?? '', { method, receiver: receiverText ? oneLine(receiverText, 80) : '', module: receiverText ? oneLine(receiverText, 80) : '' });
        const fnNode = enclosingFn(node);
        const taint = rule.category === 'other' || rule.category === 'authz_object' ? undefined : verdict === true ? rustTaint(a[0], fnNode) : verdict;
        const sink = makeSink(repo, input.path, rule, node, fnNode ? fnIds.get(fnNode.id) ?? null : null, oneLine(api, 200), taint);
        const mNode = cap.get('method');
        if (recvNode && mNode) sink.sinkId = `${repo}:${input.path}#L${mNode.startPosition.row + 1}:${mNode.startPosition.column + 1}:${sink.category}`;
        if (!seenSinks.has(sink.sinkId)) { seenSinks.add(sink.sinkId); fx.sinks.push(sink); }
      }
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${(e as Error).message}` });
    }
  }

  // ---- calls ----
  for (const call of root.descendantsOfType('call_expression')) {
    if (!call) continue;
    const fnNode = enclosingFn(call);
    const from = fnNode ? fnIds.get(fnNode.id) : undefined;
    const f = call.childForFieldName('function');
    if (!from || !f) continue;
    const arity = named(call.childForFieldName('arguments')).length;
    const line = call.startPosition.row + 1;
    if (f.type === 'identifier') {
      // `helper(x)`: same module, or an imported function (`use crate::db::helper`).
      const imp = aliases.get(f.text);
      const modPath = imp && imp.includes('::') ? imp.slice(0, imp.lastIndexOf('::')) : imp && imp.includes('/') ? imp : null;
      fx.calls.push({ from, method: f.text, receiverText: null, receiverType: null, receiverImport: modPath, arity, line, calleeText: f.text });
    } else if (f.type === 'scoped_identifier') {
      // `Type::new(…)`, `module::f(…)`, `crate::a::f(…)`, `Self::helper(…)`.
      const name = f.childForFieldName('name')?.text ?? '';
      const path = f.childForFieldName('path')?.text ?? '';
      const head = path.split('::')[0]!;
      const last = path.split('::').pop()!;
      const typeLike = /^[A-Z]/.test(last);
      const type = last === 'Self' ? enclosingImpl(call) : typeLike ? last : null;
      const mod = typeLike ? null : aliases.has(head) ? [aliases.get(head)!, ...path.split('::').slice(1)].join('::') : absolute(path, fileSegs);
      fx.calls.push({ from, method: name, receiverText: last === 'Self' ? 'self' : path, receiverType: type, receiverImport: mod, arity, line, calleeText: oneLine(f.text) });
    } else if (f.type === 'field_expression') {
      // Method call `recv.m(…)`; `self.m(…)` resolves within the impl.
      const name = f.childForFieldName('field')?.text ?? '';
      const recv = f.childForFieldName('value');
      fx.calls.push({ from, method: name, receiverText: recv?.type === 'self' ? 'self' : oneLine(recv?.text ?? '', 200), receiverType: null, receiverImport: null, arity, line, calleeText: oneLine(f.text) });
    }
  }
  return fx;
}

/** Extractor / request-guard parameter types that authenticate (`Claims`, `AuthUser`, `Extension<CurrentUser>`, `ReqData<Claims>`, `BearerAuth`). */
const GUARD_TYPE_RE = /^(?:Auth\w*|\w*Auth|\w*Claims|Current\w*|\w*Session|\w*Token|Bearer\w*|Jwt\w*|\w*Jwt|\w*Identity|\w*Principal|Admin\w*|\w*Admin|\w*Guard|Authenticated\w*|Logged\w*|Require\w*|\w*User|\w*ApiKey|ApiKey\w*|Authorization)$/;
const INPUT_WRAPPERS = /^(?:\w+::)*(Json|Form|Query|Path|State|Data|Multipart|Bytes|String|Payload|HttpRequest|Request|Body|Value|Valid\w*|Garde|Option<Json|Option<Query)\b/;
export function isGuardType(text: string, declared: ReadonlySet<string> = new Set()): boolean {
  const t = text.replace(/\s+/g, '').replace(/^&(?:mut)?/, '');
  // Optional guards (`Option<AuthUser>`, `MaybeAuthUser`) admit anonymous requests: not enforcement.
  if (INPUT_WRAPPERS.test(t) || /^(?:\w+::)*Option</.test(t)) return false;
  const inner = /^(?:\w+::)*(?:Extension|ReqData|TypedHeader|Result|Auth|web::ReqData)<(.+)>$/.exec(t);
  const core = (inner ? inner[1]! : t).replace(/<.*$/, '').split('::').pop()!;
  if (/^(Maybe|Optional)/.test(core)) return false;
  if (declared.has(core)) return true;
  if (/^Authorization$/.test(core) && /Bearer|Basic/.test(t)) return true;
  return GUARD_TYPE_RE.test(core) && !/^(Create|Update|New|Delete|Register|Login|Signup|SignUp)\w*$/.test(core);
}

type Taint = 'string_concat' | 'constant' | undefined;
/** String taint of a Rust expression: literals, `format!`, `+` concatenation, and `let` bindings in the same function. */
function rustTaint(n: Node | null | undefined, fn: Node | null, depth = 0): Taint {
  if (!n || depth > 5) return undefined;
  switch (n.type) {
    case 'string_literal': case 'raw_string_literal': case 'integer_literal': case 'boolean_literal': case 'char_literal': return 'constant';
    case 'reference_expression': case 'parenthesized_expression': case 'unary_expression': return rustTaint(named(n).pop(), fn, depth + 1);
    case 'macro_invocation': {
      const m = n.childForFieldName('macro')?.text ?? '';
      if (/^(concat|stringify|include_str|env)$/.test(m)) return 'constant';
      if (/^(format|format_args)$/.test(m)) {
        const tt = named(n).find((c) => c.type === 'token_tree');
        const parts = named(tt);
        const lit = parts[0]?.type === 'string_literal' ? parts[0].text : '';
        return parts.length > 1 || /\{[A-Za-z_]\w*[^}]*\}/.test(lit) ? 'string_concat' : 'constant';
      }
      return undefined;
    }
    case 'binary_expression': {
      if (n.childForFieldName('operator')?.text !== '+') return undefined;
      const l = rustTaint(n.childForFieldName('left'), fn, depth + 1);
      const r = rustTaint(n.childForFieldName('right'), fn, depth + 1);
      return l === 'constant' && r === 'constant' ? 'constant' : 'string_concat';
    }
    case 'call_expression': {
      const f = n.childForFieldName('function');
      const a = named(n.childForFieldName('arguments'));
      if (f?.type === 'field_expression') {
        const m = f.childForFieldName('field')?.text ?? '';
        if (/^(to_string|to_owned|as_str|as_ref|into|clone|trim|as_bytes|to_vec)$/.test(m)) return rustTaint(f.childForFieldName('value'), fn, depth + 1);
        if (m === 'join' || m === 'concat' || m === 'replace') return 'string_concat';
      }
      if (f?.type === 'scoped_identifier' && /^(String::from|String::new|str::to_string)$/.test(f.text)) return a.length ? rustTaint(a[0], fn, depth + 1) : 'constant';
      return undefined;
    }
    case 'identifier': {
      if (!fn) return undefined;
      let found: Node | null = null;
      for (const d of fn.descendantsOfType('let_declaration')) {
        if (!d || d.startIndex > n.startIndex) continue;
        if (d.childForFieldName('pattern')?.text.replace(/^mut\s+/, '') === n.text) found = d.childForFieldName('value');
      }
      // `let mut sql = String::from(…); sql.push_str(&x)` / `sql += &x` builders
      if (found && new RegExp(`\\b${n.text}\\s*(\\.push_str\\s*\\(|\\+=)`).test(fn.text)) return 'string_concat';
      return found ? rustTaint(found, fn, depth + 1) : undefined;
    }
    default: return undefined;
  }
}

/** Post filters of Rust sink rules; `true` keeps the sink with the first argument's taint, a Taint value overrides it. */
function rustSinkPost(post: string | undefined, s: { node: Node; method: string; a: Node[]; receiverText: string | null; taint: (n: Node | undefined) => Taint }): boolean | Taint {
  const first = s.a[0];
  const nonConst = (n: Node | undefined) => !!n && s.taint(n) !== 'constant';
  switch (post) {
    case undefined: return true;
    case 'rust_nonconst': return nonConst(first);
    case 'rust_sql': {
      // Only SQL text built at runtime: `format!`, `+`, push_str builders (prepared statements with binds are safe).
      const arg = s.method === 'from_string' || s.method === 'from_sql_and_values' ? s.a[1] : first;
      return s.taint(arg) === 'string_concat' ? 'string_concat' : false;
    }
    case 'rust_command': {
      if (nonConst(first)) return true;
      // `Command::new("sh").arg("-c").arg(x)`: a shell with a non-constant script.
      if (!/^"(sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)"$/.test(first?.text ?? '')) return false;
      let chain = s.node;
      for (let p = chain.parent; p && (p.type === 'field_expression' || p.type === 'call_expression'); p = p.parent) chain = p;
      const args = chain.descendantsOfType('call_expression').filter((c): c is Node => !!c && /\.(arg|args)$/.test(c.childForFieldName('function')?.text ?? ''));
      return /"(-c|\/C|-Command)"/.test(chain.text) && args.some((c) => named(c.childForFieldName('arguments')).some((x) => s.taint(x) !== 'constant' && !/^"/.test(x.text))) ? 'string_concat' : false;
    }
    case 'rust_concat': return s.taint(first) === 'string_concat' ? 'string_concat' : false;
    default: return true;
  }
}

