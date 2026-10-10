// JavaScript / TypeScript server-side extraction: symbols (classes, interfaces, methods, top-level and
// exported functions, synthetic symbols for inline route handlers), ES / CommonJS imports, calls with receiver facts,
// Express / Koa / Fastify routes (router prefixes, `app.use('/p', router)` mounts in the file and across files, middleware
// chains), NestJS controllers (decorators, guards), GraphQL resolvers (resolver maps, NestJS / TypeGraphQL decorators),
// non-HTTP entries (WebSocket / Socket.IO, NestJS gateways / microservices / schedules, Kafka / RabbitMQ / BullMQ /
// Redis consumers, cron jobs, commander / yargs commands), sinks (rules/javascript) and auth signals.
// `.js/.jsx/.mjs/.cjs` use the JavaScript grammar, `.ts/.mts/.cts` TypeScript and `.tsx` TSX; every query in
// rules/javascript compiles under all three, and grammar differences (decorator placement, field node names) are handled here.
import type { Node, Tree } from 'web-tree-sitter';
import { USE_SERVER_DIRECTIVE_RE } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';
import { AUTH_NAME_RE, captureMap, fillApi, makeSink, rangeOf, ruleMatches, unquote, type CompiledRule } from './common.js';
import type { CallResolution, ResolveTables } from './languages.js';
import { jsFrameworkContexts, nextMatcherCovers, nextRouteOf, nuxtRouteOf, type JsFrameworkContext } from './extract-js-frameworks.js';
import { graphqlEntryOf } from './graphql.js';
import { rpcOf } from './proto.js';
import { emptyExtract, joinRoute, type ExtractInput, type FileExtract, type HandlerRef, type RawCall, type RawEntry } from './types.js';

// ---- module paths --------------------------------------------------------------------------------------------------

const EXT_RE = /\.(d\.)?[cm]?[jt]sx?$/;

/** Module key of a file: path without extension; `index` files stand for their directory (root index → `.`). */
export function jsModulePath(path: string): string {
  const p = path.replace(EXT_RE, '');
  if (p === 'index') return '.';
  return p.endsWith('/index') ? p.slice(0, -'/index'.length) : p;
}

/** Relative specifiers resolve against the importing file's directory; package specifiers stay as written (`node:` dropped). */
export function resolveJsSpecifier(fromPath: string, spec: string): string {
  if (spec.startsWith('node:')) return spec.slice(5);
  if (!spec.startsWith('.')) return spec;
  const parts = fromPath.split('/');
  parts.pop();
  for (const seg of spec.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return jsModulePath(parts.join('/')) || '.';
}

const isRelativeSpec = (spec: string) => spec.startsWith('.');
const packageRoot = (spec: string) => (spec.startsWith('@') ? spec.split('/').slice(0, 2).join('/') : spec.split('/')[0]!);

// ---- call resolution -------------------------------------------------------------------------------------------------

const repoModulesCache = new WeakMap<ResolveTables, Set<string>>();

/**
 * JS / TS call resolution: the generic rules, except that an import of a module of this repository whose export is not a
 * plain function (a class instance, a re-export, `export default {…}` of imported functions) falls back to name + arity
 * (heuristic) instead of being treated as external. Package imports stay external.
 */
export function jsResolve(
  c: RawCall, f: FileExtract, t: ResolveTables,
  base: (c: RawCall, f: FileExtract, t: ResolveTables) => CallResolution,
): CallResolution {
  const r = base(c, f, t);
  if (r !== 'external' || !c.receiverImport) return r;
  let mods = repoModulesCache.get(t);
  if (!mods) {
    mods = new Set<string>();
    for (const s of t.byId.values()) if (/\.[cm]?[jt]sx?$/.test(s.path)) mods.add(jsModulePath(s.path));
    repoModulesCache.set(t, mods);
  }
  return mods.has(c.receiverImport) ? null : r;
}

// ---- cross-file router mounts (input context) ------------------------------------------------------------------------

export interface JsMount { prefix: string; middlewares: string[] }

const MIDDLEWARE_NAME_RE = /auth|jwt|guard|limit|cors|helmet|logger|log$|parser|middleware|session|static|error|csrf|compress|passport|validat/i;
const MAX_SCAN_BYTES = 512 * 1024;

/** Top-level comma-separated arguments of the call whose `(` is at `open` (strings / brackets balanced). */
function scanArgs(text: string, open: number): string[] | null {
  let depth = 0;
  let quote: string | null = null;
  let start = open + 1;
  const parts: string[] = [];
  const end = Math.min(text.length, open + 4000);
  for (let i = open; i < end; i++) {
    const ch = text[i]!;
    if (quote) {
      if (ch === '\\') i++;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') quote = ch;
    else if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      depth--;
      if (depth === 0) {
        parts.push(text.slice(start, i));
        return parts.map((p) => p.trim()).filter((p) => p.length > 0);
      }
    } else if (ch === ',' && depth === 1) {
      parts.push(text.slice(start, i));
      start = i + 1;
    }
  }
  return null;
}

const literalOf = (t: string): string | null => {
  const m = /^(['"`])([^'"`]*)\1$/.exec(t.trim());
  return m && !m[2]!.includes('${') ? m[2]! : null;
};

interface FileMount { from: string; recvIsApp: boolean; prefix: string; middlewares: string[]; target: string }

/** Mounts declared in one file: `x.use('/p', …mw, importedRouter)`, `x.use(r.routes())`, `x.register(plugin, { prefix })`. */
function fileMounts(path: string, text: string): FileMount[] {
  const from = jsModulePath(path);
  const bindings = new Map<string, string>();
  const bind = (names: string, spec: string) => {
    if (!isRelativeSpec(spec)) return;
    const mod = resolveJsSpecifier(path, spec);
    for (const n of names.split(',')) {
      const local = n.trim().split(/\s+as\s+|\s*:\s*/).pop()?.trim();
      if (local && /^[\w$]+$/.test(local)) bindings.set(local, mod);
    }
  };
  for (const m of text.matchAll(/import\s+([\w$]+)\s*(?:,\s*\{([^}]*)\})?\s*from\s*['"]([^'"]+)['"]/g)) { bind(m[1]!, m[3]!); if (m[2]) bind(m[2], m[3]!); }
  for (const m of text.matchAll(/import\s+\*\s+as\s+([\w$]+)\s+from\s*['"]([^'"]+)['"]/g)) bind(m[1]!, m[2]!);
  for (const m of text.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"]([^'"]+)['"]/g)) bind(m[1]!, m[2]!);
  for (const m of text.matchAll(/(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g)) bind(m[1]!, m[2]!);
  for (const m of text.matchAll(/(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)/g)) bind(m[1]!, m[2]!);
  const apps = new Set<string>();
  for (const m of text.matchAll(/(?:const|let|var)\s+([\w$]+)\s*(?::\s*[\w.<>]+\s*)?=\s*(?:await\s+)?(?:express|fastify|Fastify|new\s+Koa|NestFactory\.create)\s*[(<]/g)) apps.add(m[1]!);

  const refOf = (raw: string): { module?: string; local?: string } => {
    const t = raw.trim();
    const req = /^(?:require|(?:await\s+)?import)\(\s*['"](\.[^'"]+)['"]\s*\)(?:\.default)?$/.exec(t);
    if (req) return { module: resolveJsSpecifier(path, req[1]!) };
    const id = /^([\w$]+)(\.routes\(\s*\)|\.default|\.router)?$/.exec(t);
    if (!id) return {};
    const name = id[1]!;
    if (!id[2] && MIDDLEWARE_NAME_RE.test(name)) return {};
    return bindings.has(name) ? { module: bindings.get(name)! } : { local: name };
  };

  const pathless = new Map<string, { pos: number; mws: string[] }[]>();
  const localParent = new Map<string, { parent: string; prefix: string }>();
  const raw: { recv: string; pos: number; prefix: string; mws: string[]; target: string }[] = [];
  for (const m of text.matchAll(/([\w$]+)\s*\.\s*(use|register)\s*\(/g)) {
    const recv = m[1]!;
    const args = scanArgs(text, m.index! + m[0].length - 1);
    if (!args?.length) continue;
    if (m[2] === 'register') {
      const ref = refOf(args[0]!);
      const prefix = /prefix\s*:\s*(['"`])([^'"`$]*)\1/.exec(args[1] ?? '')?.[2] ?? '';
      if (ref.module) raw.push({ recv, pos: m.index!, prefix, mws: [], target: ref.module });
      else if (ref.local) localParent.set(ref.local, { parent: recv, prefix });
      continue;
    }
    const path0 = literalOf(args[0]!);
    const rest = path0 !== null ? args.slice(1) : args;
    const refs = rest.map(refOf);
    const routerIdx = refs.findIndex((r, i) => r.module && (i === rest.length - 1 || /\.routes\(/.test(rest[i]!)));
    const before = (pathless.get(recv) ?? []).filter((u) => u.pos < m.index!).flatMap((u) => u.mws);
    if (routerIdx >= 0) {
      raw.push({ recv, pos: m.index!, prefix: path0 ?? '', mws: [...before, ...rest.slice(0, routerIdx).map(short)], target: refs[routerIdx]!.module! });
    } else if (path0 !== null && refs[rest.length - 1]?.local) {
      localParent.set(refs[rest.length - 1]!.local!, { parent: recv, prefix: path0 });
    } else if (path0 === null) {
      const list = pathless.get(recv) ?? [];
      list.push({ pos: m.index!, mws: rest.map(short) });
      pathless.set(recv, list);
    }
  }
  return raw.map((r) => {
    let recv = r.recv;
    let prefix = r.prefix;
    for (let i = 0; i < 5 && localParent.has(recv); i++) {
      const p = localParent.get(recv)!;
      prefix = joinRoute(p.prefix, prefix);
      recv = p.parent;
    }
    return { from, recvIsApp: apps.has(recv), prefix, middlewares: r.mws, target: r.target };
  });
}

const contextCache = new WeakMap<SnapshotView, Map<string, JsMount[]>>();

/** Mount prefixes of every JS / TS module mounted by another file (composed along mount chains, at most 4 per module). */
export function jsMountsOf(view: SnapshotView): Map<string, JsMount[]> {
  const cached = contextCache.get(view);
  if (cached) return cached;
  const byTarget = new Map<string, FileMount[]>();
  const files: string[] = [];
  for (const f of view.listFiles()) {
    if ((f.lang !== 'javascript' && f.lang !== 'typescript') || f.path.includes('node_modules/') || f.size > MAX_SCAN_BYTES) continue;
    files.push(f.path);
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    if (!/\.\s*(use|register)\s*\(/.test(text)) continue;
    for (const m of fileMounts(f.path, text)) {
      const list = byTarget.get(m.target) ?? [];
      list.push(m);
      byTarget.set(m.target, list);
    }
  }
  const memo = new Map<string, JsMount[] | null>();
  const prefixesOf = (mod: string, depth: number, seen: Set<string>): JsMount[] | null => {
    if (memo.has(mod)) return memo.get(mod)!;
    const ms = byTarget.get(mod);
    if (!ms || depth > 6 || seen.has(mod)) return null;
    seen.add(mod);
    const out: JsMount[] = [];
    for (const m of ms) {
      const parents = m.recvIsApp ? null : prefixesOf(m.from, depth + 1, seen);
      for (const p of parents ?? [{ prefix: '', middlewares: [] }]) {
        const prefix = joinRoute(p.prefix, m.prefix);
        if (!out.some((o) => o.prefix === prefix)) out.push({ prefix, middlewares: [...p.middlewares, ...m.middlewares] });
      }
    }
    seen.delete(mod);
    const res = out.slice(0, 4);
    memo.set(mod, res);
    return res;
  };
  const result = new Map<string, JsMount[]>();
  for (const p of files) {
    const mod = jsModulePath(p);
    const mounts = prefixesOf(mod, 0, new Set());
    if (mounts?.length) result.set(p, mounts);
  }
  contextCache.set(view, result);
  return result;
}

export function jsInputContext(view: SnapshotView): (path: string) => Partial<ExtractInput> {
  const mounts = jsMountsOf(view);
  const frameworks = jsFrameworkContexts(view);
  return (path) => {
    const m = mounts.get(path);
    const fw = frameworks.get(path);
    return { ...(m ? { jsMounts: m } : {}), ...(fw ? { langContext: fw as unknown as Record<string, unknown> } : {}) };
  };
}

// ---- per-file extraction ---------------------------------------------------------------------------------------------

interface Binding { module: string; kind: 'default' | 'namespace' | 'named'; name: string; relative: boolean }
interface ClassInfo { name: string; symbolId: string; node: Node; fields: Map<string, string>; methods: Map<string, { id: string; arity: number }> }
interface Base { prefix: string; middlewares: string[] }

const FUNCTION_TYPES = new Set(['function_declaration', 'generator_function_declaration', 'function_expression', 'function', 'generator_function', 'arrow_function', 'method_definition']);
const FUNCTION_VALUES = new Set(['function_expression', 'function', 'generator_function', 'arrow_function']);
const CLASS_TYPES = new Set(['class_declaration', 'abstract_class_declaration', 'class']);
const PRIMITIVES = new Set(['string', 'number', 'boolean', 'any', 'unknown', 'object', 'void', 'never', 'Promise', 'Array', 'Record', 'Partial', 'Readonly', 'Map', 'Set', 'Date', 'Function']);
const HTTP_VERBS: Record<string, string> = { get: 'GET', post: 'POST', put: 'PUT', delete: 'DELETE', del: 'DELETE', patch: 'PATCH', options: 'OPTIONS', head: 'HEAD', all: 'ANY' };
const NEST_VERBS: Record<string, string> = { Get: 'GET', Post: 'POST', Put: 'PUT', Delete: 'DELETE', Patch: 'PATCH', Options: 'OPTIONS', Head: 'HEAD', All: 'ANY', Search: 'SEARCH' };
/** Midway: Nest-style decorators, `@Del` for DELETE. */
const MIDWAY_VERBS: Record<string, string> = { ...NEST_VERBS, Del: 'DELETE' };
/** Authentication calls inside a Next.js / Nuxt handler body (no middleware chain there). */
const INLINE_AUTH_RE = /\b(auth|getServerSession|getSession|currentUser|getUser|requireUser|requireAuth|verifySession|getToken|getAuth|checkAuth|requireUserSession|getUserSession|validateRequest|getServerAuthSession)\s*\(/;
const NEXT_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
const NEST_AUTH_DECORATORS = /^(UseGuards|Roles|Public|SkipAuth|AllowAnonymous|Permissions|RequirePermissions|RequireRoles|Auth|Authorized|Authenticated|SetMetadata|ApiBearerAuth|Scopes)$/;
const ROUTER_NAME_RE = /(^|\.)(app|api|server|routes?|\w*[Rr]outer|fastify|instance|v\d+)$/;
const NOT_ROUTER_RE = /^(req|res|request|response|reply|ctx|axios|http|https|client|cache|map|store|session|config|headers|params|query|this)$/;
const FASTIFY_HOOKS = /^(preHandler|onRequest|preValidation|preParsing|beforeHandler)$/;
const STATE_FIELDS = 'status|state|amount|balance|price|role|roles|quantity|qty|credit|credits|points|total|paid|isPaid|approved|verified|isAdmin|stock|discount|refund\\w*';
const STATE_FIELD_RE = new RegExp(`\\b(${STATE_FIELDS})\\b`, 'i');
const ID_ARG_RE = /(^|[^\w$])(_id|id|\w+Id|\w+_id)\b/;
const REQUEST_DATA_RE = /\b(req|request)\.(body|query|params|headers|cookies)\b|\bctx\.(request\.body|query|params)\b|\brequest\.(payload|body)\b/;

const short = (t: string) => t.replace(/\s+/g, ' ').trim().slice(0, 120);
const named = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c && c.type !== 'comment');

/** Type name from a `type_annotation` / type node text: `: Repository<User>` → `Repository`, `a.B` → `B`. */
function typeNameOf(text: string | undefined): string | null {
  if (!text) return null;
  const m = /^[:\s]*(?:readonly\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)/.exec(text);
  if (!m) return null;
  const name = m[1]!.split('.').pop()!;
  return PRIMITIVES.has(name) ? null : name;
}

export function extractJs(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const root = tree.rootNode;
  const pkg = jsModulePath(input.path);
  fx.pkg = pkg;

  // ---- imports ----
  const bindings = new Map<string, Binding>();
  const imports = new Set<string>();
  const addImport = (spec: string) => {
    const mod = resolveJsSpecifier(input.path, spec);
    imports.add(mod);
    if (!isRelativeSpec(spec)) imports.add(packageRoot(mod));
    return mod;
  };
  const bindLocal = (local: string, spec: string, kind: Binding['kind'], name: string) => {
    bindings.set(local, { module: resolveJsSpecifier(input.path, spec), kind, name, relative: isRelativeSpec(spec) });
  };
  const requireSpec = (n: Node | null | undefined): string | null => {
    if (n?.type !== 'call_expression' || n.childForFieldName('function')?.text !== 'require') return null;
    const a = named(n.childForFieldName('arguments'))[0];
    return a?.type === 'string' ? unquote(a.text) : null;
  };
  for (const stmt of named(root)) {
    if (stmt.type !== 'import_statement') continue;
    const src = stmt.childForFieldName('source');
    if (!src) continue;
    const spec = unquote(src.text);
    addImport(spec);
    const clause = named(stmt).find((c) => c.type === 'import_clause');
    for (const c of named(clause)) {
      if (c.type === 'identifier') bindLocal(c.text, spec, 'default', 'default');
      else if (c.type === 'namespace_import') { const id = named(c).find((x) => x.type === 'identifier'); if (id) bindLocal(id.text, spec, 'namespace', '*'); }
      else if (c.type === 'named_imports') {
        for (const s of named(c)) {
          if (s.type !== 'import_specifier') continue;
          const nm = s.childForFieldName('name')?.text;
          const alias = s.childForFieldName('alias')?.text ?? nm;
          if (nm && alias) bindLocal(alias, spec, nm === 'default' ? 'default' : 'named', nm);
        }
      }
    }
    // TS `import x = require('y')`
    const req = named(stmt).find((c) => c.type === 'import_require_clause');
    const reqId = named(req).find((c) => c.type === 'identifier');
    if (reqId) bindLocal(reqId.text, spec, 'namespace', '*');
  }
  for (const d of root.descendantsOfType('variable_declarator')) {
    if (!d) continue;
    const value = d.childForFieldName('value');
    const nameNode = d.childForFieldName('name');
    let spec = requireSpec(value);
    let member: string | null = null;
    if (!spec && value?.type === 'member_expression') {
      spec = requireSpec(value.childForFieldName('object'));
      member = value.childForFieldName('property')?.text ?? null;
    }
    if (!spec || !nameNode) continue;
    if (nameNode.type === 'identifier') bindLocal(nameNode.text, spec, member && member !== 'default' ? 'named' : member === 'default' ? 'default' : 'namespace', member ?? '*');
    else if (nameNode.type === 'object_pattern') {
      for (const p of named(nameNode)) {
        if (p.type === 'shorthand_property_identifier_pattern') bindLocal(p.text, spec, 'named', p.text);
        else if (p.type === 'pair_pattern') {
          const key = p.childForFieldName('key')?.text;
          const val = p.childForFieldName('value');
          if (key && val?.type === 'identifier') bindLocal(val.text, spec, 'named', key);
        }
      }
    }
  }
  for (const c of root.descendantsOfType('call_expression')) {
    const spec = requireSpec(c);
    if (spec) addImport(spec);
  }

  // ---- symbols ----
  const fnIds = new Map<number, string>(); // function-like node id → symbolId
  const localFuncs = new Map<string, string>(); // top-level function name → symbolId
  const classes = new Map<number, ClassInfo>(); // class node id → info
  const classByName = new Map<string, ClassInfo>();
  const ids = new Set<string>();
  const arityOf = (fn: Node): number => {
    const single = fn.childForFieldName('parameter');
    if (single) return 1;
    return named(fn.childForFieldName('parameters')).filter((p) => {
      const pat = p.childForFieldName('pattern');
      return !(pat?.type === 'this' || p.type === 'this');
    }).length;
  };
  const signatureOf = (decl: Node, fn: Node) => {
    const body = fn.childForFieldName('body');
    const end = body && body.startIndex > decl.startIndex ? body.startIndex - decl.startIndex : decl.text.length;
    return decl.text.slice(0, end).replace(/\s+/g, ' ').replace(/\s*=>\s*$/, ' =>').trim().slice(0, 300);
  };
  const addFunc = (name: string, fn: Node, decl: Node): string => {
    const symbolId = `${input.repo}:${input.path}#${pkg}.${name}(${arityOf(fn)})`;
    fnIds.set(fn.id, symbolId);
    if (ids.has(symbolId)) return symbolId;
    ids.add(symbolId);
    if (!localFuncs.has(name)) localFuncs.set(name, symbolId);
    fx.symbols.push({
      symbolId, repo: input.repo, kind: 'func', name, container: pkg, path: input.path, range: rangeOf(decl),
      signature: signatureOf(decl, fn), qualifiedName: `${pkg}#${name}`,
    });
    return symbolId;
  };
  /** Function node of a value (`() => {}`, `function () {}`, `wrap(async () => {})`). */
  const functionOfValue = (v: Node | null | undefined): Node | null => {
    if (!v) return null;
    if (FUNCTION_VALUES.has(v.type)) return v;
    if (v.type === 'parenthesized_expression') return functionOfValue(named(v)[0]);
    if (v.type === 'call_expression') {
      const args = named(v.childForFieldName('arguments'));
      const last = args[args.length - 1];
      return last && FUNCTION_VALUES.has(last.type) ? last : null;
    }
    return null;
  };
  const addClass = (cls: Node, fallbackName: string) => {
    const name = cls.childForFieldName('name')?.text ?? fallbackName;
    const container = `${pkg}.${name}`;
    const symbolId = `${input.repo}:${input.path}#${container}`;
    const body = cls.childForFieldName('body');
    const info: ClassInfo = { name, symbolId, node: cls, fields: new Map(), methods: new Map() };
    classes.set(cls.id, info);
    if (!classByName.has(name)) classByName.set(name, info);
    if (!ids.has(symbolId)) {
      ids.add(symbolId);
      fx.symbols.push({
        symbolId, repo: input.repo, kind: cls.type === 'interface_declaration' ? 'interface' : 'class', name, container: pkg,
        path: input.path, range: rangeOf(cls), signature: signatureOf(cls, cls), qualifiedName: `${pkg}#${name}`,
      });
    }
    if (cls.type === 'interface_declaration') return;
    for (const m of named(body)) {
      let fn: Node | null = null;
      let mname: string | undefined;
      if (m.type === 'method_definition') { fn = m; mname = m.childForFieldName('name')?.text; }
      else if (m.type === 'public_field_definition' || m.type === 'field_definition') {
        const key = m.childForFieldName('name') ?? m.childForFieldName('property');
        mname = key?.text;
        const value = m.childForFieldName('value');
        fn = functionOfValue(value);
        const t = typeNameOf(m.childForFieldName('type')?.text)
          ?? (value?.type === 'new_expression' ? typeNameOf(value.childForFieldName('constructor')?.text) : null);
        if (mname && t) info.fields.set(mname, t);
      }
      if (!fn || !mname) continue;
      const arity = arityOf(fn);
      const mid = `${input.repo}:${input.path}#${container}.${mname}(${arity})`;
      fnIds.set(fn.id, mid);
      info.methods.set(mname, { id: mid, arity });
      if (ids.has(mid)) continue;
      ids.add(mid);
      fx.symbols.push({
        symbolId: mid, repo: input.repo, kind: 'method', name: mname, container, path: input.path, range: rangeOf(m),
        signature: signatureOf(m, fn), qualifiedName: `${pkg}#${name}.${mname}`,
      });
      if (mname === 'constructor') {
        // TS parameter properties: `constructor(private readonly svc: UsersService)`
        for (const p of named(fn.childForFieldName('parameters'))) {
          if (!p.children.some((c) => c?.type === 'accessibility_modifier' || c?.type === 'readonly')) continue;
          const pn = p.childForFieldName('pattern')?.text;
          const t = typeNameOf(p.childForFieldName('type')?.text);
          if (pn && t) info.fields.set(pn, t);
        }
      }
    }
    // `this.x = new X()` anywhere in the class
    for (const a of cls.descendantsOfType('assignment_expression')) {
      const left = a?.childForFieldName('left');
      const right = a?.childForFieldName('right');
      if (left?.type === 'member_expression' && left.childForFieldName('object')?.type === 'this' && right?.type === 'new_expression') {
        const t = typeNameOf(right.childForFieldName('constructor')?.text);
        const f = left.childForFieldName('property')?.text;
        if (f && t && !info.fields.has(f)) info.fields.set(f, t);
      }
    }
  };
  const addObjectFuncs = (obj: Node) => {
    for (const p of named(obj)) {
      if (p.type === 'method_definition') {
        const n = p.childForFieldName('name')?.text;
        if (n) addFunc(n, p, p);
      } else if (p.type === 'pair') {
        const n = p.childForFieldName('key')?.text;
        const fn = functionOfValue(p.childForFieldName('value'));
        if (n && fn) addFunc(unquote(n), fn, p);
      }
    }
  };
  const visitDeclaration = (d: Node, stmt: Node, isDefault: boolean) => {
    if (d.type === 'function_declaration' || d.type === 'generator_function_declaration') addFunc(d.childForFieldName('name')?.text ?? 'default', d, stmt);
    else if (CLASS_TYPES.has(d.type) || d.type === 'interface_declaration') addClass(d, isDefault ? 'default' : 'anonymous');
    else if (d.type === 'lexical_declaration' || d.type === 'variable_declaration') {
      for (const v of named(d)) {
        if (v.type !== 'variable_declarator') continue;
        const n = v.childForFieldName('name');
        const value = v.childForFieldName('value');
        if (n?.type !== 'identifier' || !value) continue;
        const fn = functionOfValue(value);
        if (fn) addFunc(n.text, fn, d);
        else if (CLASS_TYPES.has(value.type)) addClass(value, n.text);
        else if (value.type === 'object') addObjectFuncs(value);
      }
    } else if (isDefault) {
      const fn = functionOfValue(d);
      if (fn) addFunc(fn.childForFieldName('name')?.text ?? 'default', fn, stmt);
      else if (d.type === 'object') addObjectFuncs(d);
    }
  };
  for (const stmt of named(root)) {
    if (stmt.type === 'export_statement') {
      const decl = stmt.childForFieldName('declaration');
      const value = stmt.childForFieldName('value');
      const isDefault = stmt.children.some((c) => c?.type === 'default');
      if (decl) visitDeclaration(decl, stmt, isDefault);
      else if (value) visitDeclaration(value, stmt, true);
      else {
        const inner = named(stmt).find((c) => FUNCTION_VALUES.has(c.type) || CLASS_TYPES.has(c.type) || c.type === 'object');
        if (inner) visitDeclaration(inner, stmt, true);
      }
    } else if (stmt.type === 'expression_statement') {
      const a = named(stmt)[0];
      if (a?.type !== 'assignment_expression') continue;
      const left = a.childForFieldName('left')?.text ?? '';
      const right = a.childForFieldName('right');
      if (!right) continue;
      const exp = /^(?:module\.)?exports(?:\.([\w$]+))?$/.exec(left);
      if (!exp) continue;
      const fn = functionOfValue(right);
      if (exp[1]) { if (fn) addFunc(exp[1], fn, stmt); else if (CLASS_TYPES.has(right.type)) addClass(right, exp[1]); }
      else if (left === 'module.exports') {
        if (fn) addFunc(fn.childForFieldName('name')?.text ?? 'default', fn, stmt);
        else if (right.type === 'object') addObjectFuncs(right);
        else if (CLASS_TYPES.has(right.type)) addClass(right, 'default');
      }
    } else visitDeclaration(stmt, stmt, false);
  }

  /** Function node of a symbol id declared in this file. */
  const fnIdNode = (id: string): Node | null => {
    for (const [nid, sid] of fnIds) if (sid === id) return root.descendantsOfType([...FUNCTION_TYPES]).find((n) => n?.id === nid) ?? null;
    return null;
  };
  /** Symbol of a local function referenced by name (`sayHello` in `{ sayHello }`). */
  const fnIdOf = (n: Node): HandlerRef | null => {
    const name = n.type === 'shorthand_property_identifier' || n.type === 'identifier' ? n.text : null;
    const id = name ? localFuncs.get(name) : undefined;
    return id ? { symbolId: id } : null;
  };
  const enclosingFnNode = (node: Node): Node | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (fnIds.has(p.id)) return p;
    return null;
  };
  const enclosingSymbol = (node: Node): string | null => {
    const f = enclosingFnNode(node);
    return f ? fnIds.get(f.id) ?? null : null;
  };
  const enclosingClass = (node: Node): ClassInfo | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) { const c = classes.get(p.id); if (c) return c; }
    return null;
  };

  // ---- local types (per function) ----
  const localTypeCache = new Map<number, Map<string, string>>();
  const localTypes = (fn: Node | null): Map<string, string> => {
    if (!fn) return new Map();
    const hit = localTypeCache.get(fn.id);
    if (hit) return hit;
    const m = new Map<string, string>();
    for (const p of named(fn.childForFieldName('parameters'))) {
      const pn = p.childForFieldName('pattern');
      const t = typeNameOf(p.childForFieldName('type')?.text);
      if (pn?.type === 'identifier' && t) m.set(pn.text, t);
    }
    for (const d of fn.descendantsOfType('variable_declarator')) {
      const n = d?.childForFieldName('name');
      if (n?.type !== 'identifier') continue;
      const value = d!.childForFieldName('value');
      const t = typeNameOf(d!.childForFieldName('type')?.text) ?? (value?.type === 'new_expression' ? typeNameOf(value.childForFieldName('constructor')?.text) : null);
      if (t) m.set(n.text, t);
    }
    localTypeCache.set(fn.id, m);
    return m;
  };
  const fileTypes = new Map<string, string>();
  for (const stmt of named(root)) {
    const decl = stmt.type === 'export_statement' ? stmt.childForFieldName('declaration') : stmt;
    if (decl?.type !== 'lexical_declaration' && decl?.type !== 'variable_declaration') continue;
    for (const v of named(decl)) {
      const n = v.childForFieldName('name');
      const value = v.childForFieldName('value');
      if (n?.type === 'identifier' && value?.type === 'new_expression') {
        const t = typeNameOf(value.childForFieldName('constructor')?.text);
        if (t) fileTypes.set(n.text, t);
      }
    }
  }
  /** Receiver facts shared by calls and sink rules. */
  const receiverFacts = (obj: Node | null | undefined, at: Node): { receiverText: string | null; receiverType: string | null; receiverImport: string | null } => {
    if (!obj) return { receiverText: null, receiverType: null, receiverImport: null };
    const receiverText = obj.type === 'this' ? 'this' : obj.text.slice(0, 200);
    let receiverType: string | null = null;
    let receiverImport: string | null = null;
    if (obj.type === 'identifier') {
      const b = bindings.get(obj.text);
      if (b) {
        if (b.kind === 'named' && b.relative && /^[A-Z]/.test(b.name)) receiverType = b.name;
        else receiverImport = b.module;
      } else {
        receiverType = localTypes(enclosingFnNode(at)).get(obj.text) ?? fileTypes.get(obj.text) ?? (classByName.has(obj.text) ? obj.text : null);
      }
    } else if (obj.type === 'member_expression') {
      const o = obj.childForFieldName('object');
      const prop = obj.childForFieldName('property')?.text;
      if (o?.type === 'this' && prop) receiverType = enclosingClass(at)?.fields.get(prop) ?? null;
      else {
        let leftmost: Node | null = obj;
        while (leftmost?.type === 'member_expression') leftmost = leftmost.childForFieldName('object');
        const b = leftmost?.type === 'identifier' ? bindings.get(leftmost.text) : undefined;
        if (b && !b.relative) receiverImport = b.module;
        const spec = requireSpec(leftmost);
        if (spec) receiverImport = resolveJsSpecifier(input.path, spec);
      }
    } else {
      const spec = requireSpec(obj);
      if (spec) receiverImport = resolveJsSpecifier(input.path, spec);
    }
    return { receiverText, receiverType, receiverImport };
  };

  // ---- constants and string folding ----
  // File-level `const X = '…'` strings (route paths, SQL fragments).
  const consts = new Map<string, string>();
  const topDeclarators = named(root).flatMap((st) => {
    const decl = st.type === 'export_statement' ? st.childForFieldName('declaration') : st;
    return decl?.type === 'lexical_declaration' || decl?.type === 'variable_declaration' ? named(decl) : [];
  });
  for (const d of topDeclarators) {
    const n = d.childForFieldName('name');
    const v = d.childForFieldName('value');
    if (n?.type === 'identifier' && v && (v.type === 'string' || (v.type === 'template_string' && !named(v).some((c) => c.type === 'template_substitution')))) {
      if (!consts.has(n.text)) consts.set(n.text, unquote(v.text));
    }
  }
  const stringOf = (n: Node | null | undefined): string | null => {
    if (!n) return null;
    if (n.type === 'string') return unquote(n.text);
    if (n.type === 'template_string') {
      let out = '';
      for (const c of n.children) {
        if (!c || c.type === '`') continue;
        if (c.type === 'template_substitution') {
          const inner = named(c)[0];
          out += inner?.type === 'identifier' && consts.has(inner.text) ? consts.get(inner.text)! : '{?}';
        } else out += c.text;
      }
      return out;
    }
    if (n.type === 'identifier') return consts.get(n.text) ?? null;
    if (n.type === 'binary_expression') {
      const l = stringOf(n.childForFieldName('left'));
      const r = stringOf(n.childForFieldName('right'));
      return l !== null && r !== null ? l + r : null;
    }
    return null;
  };

  // ---- routers, mounts, middleware registrations ----
  interface RouterDecl { kind: 'app' | 'router'; prefix: string }
  interface Mount { parent: string; prefix: string; middlewares: string[]; pos: number; node: Node }
  const routerDecls = new Map<string, RouterDecl>();
  const localMounts = new Map<string, Mount[]>();
  const uses = new Map<string, { pos: number; path: string; middlewares: string[] }[]>();
  const push = <V>(m: Map<string, V[]>, k: string, v: V) => { const a = m.get(k); if (a) a.push(v); else m.set(k, [v]); };
  const objectProp = (obj: Node | undefined, key: string): Node | null => {
    for (const p of named(obj)) if (p.type === 'pair' && unquote(p.childForFieldName('key')?.text ?? '') === key) return p.childForFieldName('value');
    return null;
  };
  const isFrameworkFactory = (text: string) => {
    const head = text.split('.')[0]!;
    const b = bindings.get(head);
    return b && !b.relative && /^(express|fastify|koa|@koa\/router|koa-router|@nestjs\/core|restify)$/.test(packageRoot(b.module));
  };
  for (const d of root.descendantsOfType('variable_declarator')) {
    const n = d?.childForFieldName('name');
    let v = d?.childForFieldName('value');
    if (n?.type !== 'identifier' || !v) continue;
    if (v.type === 'await_expression') v = named(v)[0] ?? null;
    if (!v) continue;
    if (v.type === 'call_expression') {
      const fn = v.childForFieldName('function')?.text ?? '';
      const args = named(v.childForFieldName('arguments'));
      if (/^(express\.)?Router$/.test(fn) || /^(express\.Router|Router)$/.test(fn)) routerDecls.set(n.text, { kind: 'router', prefix: stringOf(objectProp(args[0], 'prefix')) ?? '' });
      else if ((fn === 'express' || fn === 'fastify' || fn === 'Fastify' || fn === 'NestFactory.create') || (isFrameworkFactory(fn) && !/Router/.test(fn))) routerDecls.set(n.text, { kind: 'app', prefix: '' });
    } else if (v.type === 'new_expression') {
      const ctor = v.childForFieldName('constructor')?.text ?? '';
      const args = named(v.childForFieldName('arguments'));
      if (/^(Koa|Hono)$/.test(ctor)) routerDecls.set(n.text, { kind: 'app', prefix: '' });
      else if (/Router$/.test(ctor)) routerDecls.set(n.text, { kind: 'router', prefix: stringOf(objectProp(args[0], 'prefix')) ?? '' });
    }
  }
  const allCalls = root.descendantsOfType('call_expression').filter((c): c is Node => !!c);
  const routerRefName = (n: Node): string | null => {
    // `r`, `r.routes()`, `r.middleware()`
    if (n.type === 'identifier') return n.text;
    if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function');
      if (fn?.type === 'member_expression' && /^(routes|middleware)$/.test(fn.childForFieldName('property')?.text ?? '')) {
        const o = fn.childForFieldName('object');
        return o?.type === 'identifier' ? o.text : null;
      }
    }
    return null;
  };
  const isLocalRouterName = (name: string) => routerDecls.has(name) || localFuncs.has(name);
  const middlewareTexts = (nodes: Node[]): string[] => nodes.flatMap((n) => (n.type === 'array' ? named(n).map((x) => short(x.text)) : [short(n.text)]));
  for (const call of allCalls) {
    const fn = call.childForFieldName('function');
    if (fn?.type !== 'member_expression') continue;
    const recv = fn.childForFieldName('object');
    const prop = fn.childForFieldName('property')?.text;
    if (recv?.type !== 'identifier' || !prop) continue;
    const args = named(call.childForFieldName('arguments'));
    if (prop === 'use') {
      const path0 = args[0] && (args[0].type === 'string' || args[0].type === 'template_string') ? stringOf(args[0]) : null;
      const rest = path0 !== null ? args.slice(1) : args;
      let mounted = false;
      rest.forEach((a, i) => {
        const rn = routerRefName(a);
        if (rn && (routerDecls.has(rn) || a.type === 'call_expression') && rn !== recv.text) {
          push(localMounts, rn, { parent: recv.text, prefix: path0 ?? '', middlewares: middlewareTexts(rest.slice(0, i)), pos: call.startIndex, node: call });
          mounted = true;
        }
      });
      if (!mounted) push(uses, recv.text, { pos: call.startIndex, path: path0 ?? '', middlewares: middlewareTexts(rest) });
    } else if (prop === 'register' && args[0]) {
      const rn = args[0].type === 'identifier' ? args[0].text : null;
      if (rn && isLocalRouterName(rn)) push(localMounts, rn, { parent: recv.text, prefix: stringOf(objectProp(args[1], 'prefix')) ?? '', middlewares: [], pos: call.startIndex, node: call });
    } else if (prop === 'addHook' && args.length >= 2 && FASTIFY_HOOKS.test(stringOf(args[0]) ?? '')) {
      push(uses, recv.text, { pos: call.startIndex, path: '', middlewares: middlewareTexts(args.slice(1)) });
    } else if (prop === 'prefix' && args[0] && routerDecls.has(recv.text)) {
      routerDecls.get(recv.text)!.prefix = stringOf(args[0]) ?? '';
    }
  }
  /** Name of the function (declaration, `const f = …`, `export default`) whose parameter `name` is, for `register(f, { prefix })`. */
  const paramOwnerName = (at: Node, name: string): string | null => {
    for (let p: Node | null = at.parent; p; p = p.parent) {
      if (!FUNCTION_TYPES.has(p.type)) continue;
      const params = p.childForFieldName('parameter') ? [p.childForFieldName('parameter')!] : named(p.childForFieldName('parameters'));
      const has = params.some((x) => (x.type === 'identifier' ? x.text : x.childForFieldName('pattern')?.text) === name);
      if (!has) continue;
      const own = p.childForFieldName('name')?.text;
      if (own) return own;
      const parent = p.parent;
      if (parent?.type === 'variable_declarator') return parent.childForFieldName('name')?.text ?? null;
      if (parent?.type === 'arguments' && parent.parent?.parent?.type === 'variable_declarator') return parent.parent.parent.childForFieldName('name')?.text ?? null;
      return null;
    }
    return null;
  };
  const underPath = (rel: string, usePath: string) => usePath === '' || usePath === '/' || rel === usePath || rel.startsWith(usePath.replace(/\/+$/, '') + '/');
  const resolveName = (name: string, at: Node, pos: number, rel: string, depth: number): Base[] => {
    if (depth > 6) return [{ prefix: '', middlewares: [] }];
    const decl = routerDecls.get(name);
    const own = decl?.prefix ?? '';
    const relHere = joinRoute(own, rel);
    const localUses = (uses.get(name) ?? []).filter((u) => u.pos < pos && underPath(relHere, u.path)).flatMap((u) => u.middlewares);
    let mounts = localMounts.get(name) ?? [];
    if (!mounts.length && !decl) {
      const owner = paramOwnerName(at, name);
      if (owner) mounts = localMounts.get(owner) ?? [];
    }
    let parents: Base[];
    if (mounts.length) {
      parents = mounts.slice(0, 4).flatMap((m) => resolveName(m.parent, m.node, m.pos, joinRoute(m.prefix, relHere), depth + 1)
        .map((p) => ({ prefix: joinRoute(p.prefix, m.prefix), middlewares: [...p.middlewares, ...m.middlewares] })));
    } else if (decl?.kind === 'app') parents = [{ prefix: '', middlewares: [] }];
    else parents = input.jsMounts?.length ? input.jsMounts : [{ prefix: '', middlewares: [] }];
    return parents.map((p) => ({ prefix: joinRoute(p.prefix, own), middlewares: [...p.middlewares, ...localUses] }));
  };
  /** Route receiver → bases: identifiers, `r.route('/p')` chains (`r.route('/p').get(a).post(b)`), `this.router`. */
  const resolveRouter = (recv: Node, pos: number, rel: string, depth = 0): Base[] | null => {
    if (depth > 8) return null;
    if (recv.type === 'identifier') return resolveName(recv.text, recv, pos, rel, 0);
    if (recv.type === 'call_expression') {
      const fn = recv.childForFieldName('function');
      if (fn?.type !== 'member_expression') return null;
      const prop = fn.childForFieldName('property')?.text ?? '';
      const obj = fn.childForFieldName('object')!;
      if (prop === 'route') {
        const p = stringOf(named(recv.childForFieldName('arguments'))[0]);
        if (p === null) return null;
        return resolveRouter(obj, pos, joinRoute(p, rel), depth + 1)?.map((b) => ({ prefix: joinRoute(b.prefix, p), middlewares: b.middlewares })) ?? null;
      }
      if (HTTP_VERBS[prop] && obj.type === 'call_expression') return resolveRouter(obj, pos, rel, depth + 1);
      return null;
    }
    if (recv.type === 'member_expression') return input.jsMounts?.length ? input.jsMounts : [{ prefix: '', middlewares: [] }];
    return null;
  };

  // ---- handlers ----
  const syntheticIds = new Map<number, string>();
  const syntheticFor = (fn: Node, label: string): string => {
    const hit = syntheticIds.get(fn.id) ?? fnIds.get(fn.id);
    if (hit) return hit;
    let name = `<anonymous ${label}>`;
    let symbolId = `${input.repo}:${input.path}#${pkg}.${name}(${arityOf(fn)})`;
    for (let i = 2; ids.has(symbolId); i++) {
      name = `<anonymous ${label} #${i}>`;
      symbolId = `${input.repo}:${input.path}#${pkg}.${name}(${arityOf(fn)})`;
    }
    ids.add(symbolId);
    syntheticIds.set(fn.id, symbolId);
    fnIds.set(fn.id, symbolId);
    fx.symbols.push({
      symbolId, repo: input.repo, kind: 'func', name, container: pkg, path: input.path, range: rangeOf(fn),
      signature: signatureOf(fn, fn), qualifiedName: `${pkg}#${name}`,
    });
    return symbolId;
  };
  const handlerRef = (n: Node, label: string, depth = 0): { ref: HandlerRef; wrappers: string[] } => {
    if (depth > 4) return { ref: { text: short(n.text) }, wrappers: [] };
    if (FUNCTION_VALUES.has(n.type)) return { ref: { symbolId: syntheticFor(n, label), range: rangeOf(n) }, wrappers: [] };
    if (n.type === 'identifier') {
      const local = localFuncs.get(n.text);
      if (local) return { ref: { symbolId: local }, wrappers: [] };
      const b = bindings.get(n.text);
      if (b?.relative) return { ref: { text: b.kind === 'named' ? b.name : 'default', importPath: b.module }, wrappers: [] };
      return { ref: { text: n.text }, wrappers: [] };
    }
    if (n.type === 'member_expression') {
      const obj = n.childForFieldName('object');
      const prop = n.childForFieldName('property')?.text ?? '';
      if (obj?.type === 'this') {
        const m = enclosingClass(n)?.methods.get(prop);
        return { ref: m ? { symbolId: m.id } : { text: n.text }, wrappers: [] };
      }
      if (obj?.type === 'identifier') {
        const b = bindings.get(obj.text);
        if (b?.relative && b.kind !== 'named') return { ref: { text: `${obj.text}.${prop}`, importPath: b.module }, wrappers: [] };
        const t = localTypes(enclosingFnNode(n)).get(obj.text) ?? fileTypes.get(obj.text) ?? (b?.kind === 'named' ? b.name : obj.text);
        const m = classByName.get(t)?.methods.get(prop);
        if (m) return { ref: { symbolId: m.id }, wrappers: [] };
        // Instance of a class from another module: `Class.method` lets assembly pick that class's method.
        if (t !== obj.text || /^[A-Z]/.test(t)) return { ref: { text: `${t}.${prop}` }, wrappers: [] };
      }
      return { ref: { text: n.text }, wrappers: [] };
    }
    if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function');
      const args = named(n.childForFieldName('arguments'));
      if (fn?.type === 'member_expression' && fn.childForFieldName('property')?.text === 'bind') return handlerRef(fn.childForFieldName('object')!, label, depth + 1);
      const last = args[args.length - 1];
      if (last) {
        const inner = handlerRef(last, label, depth + 1);
        const w = short(fn?.text ?? '');
        return { ref: inner.ref, wrappers: AUTH_NAME_RE.test(w) ? [w, ...inner.wrappers] : inner.wrappers };
      }
      // Handler factory `searchProducts()` / `address.delAddressById()` (juice-shop style): the factory
      // body holds the returned handler, so the entry points at the factory.
      if (fn && (fn.type === 'identifier' || fn.type === 'member_expression')) return handlerRef(fn, label, depth + 1);
    }
    return { ref: { text: short(n.text) }, wrappers: [] };
  };
  const pushEntry = (ruleId: string, framework: string, method: string, fullPath: string, handler: Node, call: Node, middlewares: string[]) => {
    const h = handlerRef(handler, `${method} ${fullPath}`);
    const mws = [...middlewares, ...h.wrappers];
    const entry: RawEntry = {
      ruleId, framework, httpMethod: method, pathTemplate: fullPath, handler: h.ref, path: input.path, range: rangeOf(call),
      middlewares: mws, authSignals: mws.filter((m) => AUTH_NAME_RE.test(m)),
    };
    fx.entries.push(entry);
  };

  const routeReceiverOk = (recv: Node, rule: CompiledRule['rule']): boolean => {
    if (recv.type === 'identifier') {
      if (NOT_ROUTER_RE.test(recv.text)) return false;
      const b = bindings.get(recv.text);
      if (b && !b.relative && !/^(express|fastify|koa|@koa\/router|koa-router|restify)$/.test(packageRoot(b.module))) return false;
      if (routerDecls.has(recv.text) || localMounts.has(recv.text)) return true;
      return ruleMatches(rule.match, { receiverText: recv.text, receiverType: null, receiverImport: null, imports, argCount: 2 });
    }
    if (recv.type === 'member_expression') return ROUTER_NAME_RE.test(recv.text) && !/^(this\.)?(http|client|axios|cache)\b/.test(recv.text);
    if (recv.type === 'call_expression') return /\.route\(/.test(recv.text);
    return false;
  };

  const routeCall = (rule: CompiledRule['rule'], call: Node, recv: Node, verb: string, args: Node[]) => {
    const framework = rule.framework;
    if (verb === 'route') {
      // Fastify `fastify.route({ method, url, handler, preHandler })` (Express `r.route('/p')` is a chain receiver).
      const opts = args[0];
      if (opts?.type !== 'object') return;
      const url = stringOf(objectProp(opts, 'url') ?? objectProp(opts, 'path'));
      const handler = objectProp(opts, 'handler');
      const methodNode = objectProp(opts, 'method');
      if (url === null || !handler || !methodNode) return;
      const methods = methodNode.type === 'array' ? named(methodNode).map((m) => stringOf(m)) : [stringOf(methodNode)];
      const hooks = named(opts).filter((p) => p.type === 'pair' && FASTIFY_HOOKS.test(unquote(p.childForFieldName('key')?.text ?? ''))).flatMap((p) => middlewareTexts([p.childForFieldName('value')!]));
      const bases = resolveRouter(recv, call.startIndex, url) ?? [{ prefix: '', middlewares: [] }];
      for (const b of bases) for (const m of methods) if (m) pushEntry(rule.id, framework, m.toUpperCase(), joinRoute(b.prefix, url), handler, call, [...b.middlewares, ...hooks]);
      return;
    }
    const method = HTTP_VERBS[verb];
    if (!method) return;
    let rest = args;
    let path: string | null;
    if (recv.type === 'call_expression' && /\.route\(/.test(recv.text)) path = '';
    else {
      // Koa named routes: router.get('name', '/path', …)
      if (framework === 'koa' && args.length >= 3 && args[0]?.type === 'string' && args[1]?.type === 'string') rest = args.slice(1);
      // Restify `server.get({ path: '/p', version }, …)`.
      path = framework === 'restify' && rest[0]?.type === 'object' ? stringOf(objectProp(rest[0], 'path')) : stringOf(rest[0]);
      if (path === null) return;
      rest = rest.slice(1);
    }
    if (rest.length < 1) return;
    const handlerNode = rest[rest.length - 1]!;
    if (!(FUNCTION_VALUES.has(handlerNode.type) || /^(identifier|member_expression|call_expression)$/.test(handlerNode.type))) {
      // Fastify `fastify.get('/p', { preHandler, handler })`
      if (handlerNode.type !== 'object' || !objectProp(handlerNode, 'handler')) return;
    }
    if (!rule.match?.requiresImportAny && !path.startsWith('/') && path !== '') return;
    const mids: string[] = [];
    let handler = handlerNode;
    for (const m of rest.slice(0, -1)) {
      if (m.type === 'object') mids.push(...named(m).filter((p) => p.type === 'pair' && FASTIFY_HOOKS.test(unquote(p.childForFieldName('key')?.text ?? ''))).flatMap((p) => middlewareTexts([p.childForFieldName('value')!])));
      else mids.push(...middlewareTexts([m]));
    }
    if (handlerNode.type === 'object') {
      handler = objectProp(handlerNode, 'handler')!;
      mids.push(...named(handlerNode).filter((p) => p.type === 'pair' && FASTIFY_HOOKS.test(unquote(p.childForFieldName('key')?.text ?? ''))).flatMap((p) => middlewareTexts([p.childForFieldName('value')!])));
    }
    const bases = resolveRouter(recv, call.startIndex, path);
    if (!bases) return;
    for (const b of bases) pushEntry(rule.id, framework, method, joinRoute(b.prefix, path), handler, call, [...b.middlewares, ...mids]);
  };

  // ---- decorators (NestJS) ----
  const decoratorsOf = (node: Node): Node[] => {
    const out = named(node).filter((c) => c.type === 'decorator');
    if (node.parent?.type === 'export_statement') out.unshift(...named(node.parent).filter((c) => c.type === 'decorator'));
    // TS: method decorators are siblings preceding the member in the class body.
    const before: Node[] = [];
    if (node.parent?.type === 'class_body') for (let s = node.previousNamedSibling; s && s.type === 'decorator'; s = s.previousNamedSibling) before.unshift(s);
    return [...before, ...out];
  };
  const decoratorName = (d: Node): string => {
    const e = named(d)[0];
    const callee = e?.type === 'call_expression' ? e.childForFieldName('function') : e;
    return (callee?.text ?? '').split('.').pop() ?? '';
  };
  const decoratorArgs = (d: Node): Node[] => {
    const e = named(d)[0];
    return e?.type === 'call_expression' ? named(e.childForFieldName('arguments')) : [];
  };
  const pathsOfArg = (a: Node | undefined): string[] => {
    if (!a) return [''];
    if (a.type === 'array') return named(a).map((x) => stringOf(x) ?? '{?}');
    if (a.type === 'object') { const p = objectProp(a, 'path'); return p ? pathsOfArg(p) : ['']; }
    return [stringOf(a) ?? '{?}'];
  };
  const nestMiddleware = (ds: Node[]) => ds.filter((d) => /^Use\w+$/.test(decoratorName(d)) || NEST_AUTH_DECORATORS.test(decoratorName(d))).map((d) => short(d.text));
  /** Midway `{ middleware: [AuthMiddleware] }` decorator options. */
  const optionMiddleware = (d: Node): string[] => {
    const opts = decoratorArgs(d).find((a) => a.type === 'object');
    const list = opts ? objectProp(opts, 'middleware') : null;
    return list ? middlewareTexts([list]) : [];
  };
  const nestController = (rule: CompiledRule['rule'], dec: Node, midway = false) => {
    let cls: Node | null = dec.parent;
    if (cls?.type === 'export_statement') cls = cls.childForFieldName('declaration');
    if (!cls || !CLASS_TYPES.has(cls.type)) return;
    const info = classes.get(cls.id);
    const verbs = midway ? MIDWAY_VERBS : NEST_VERBS;
    const firstArg = decoratorArgs(dec)[0];
    const prefixes = midway && firstArg?.type === 'object' ? [''] : pathsOfArg(firstArg);
    const classMw = [...nestMiddleware(decoratorsOf(cls)), ...(midway ? optionMiddleware(dec) : [])];
    for (const m of named(cls.childForFieldName('body'))) {
      if (m.type !== 'method_definition') continue;
      const ds = decoratorsOf(m);
      const verbDec = ds.find((d) => verbs[decoratorName(d)]);
      if (!verbDec) continue;
      const method = verbs[decoratorName(verbDec)]!;
      const mw = [...classMw, ...nestMiddleware(ds), ...(midway ? optionMiddleware(verbDec) : [])];
      const symbolId = fnIds.get(m.id);
      for (const prefix of prefixes) {
        for (const p of pathsOfArg(midway && decoratorArgs(verbDec)[0]?.type === 'object' ? undefined : decoratorArgs(verbDec)[0])) {
          fx.entries.push({
            ruleId: rule.id, framework: rule.framework, httpMethod: method, pathTemplate: joinRoute(prefix, p),
            handler: symbolId ? { symbolId } : { text: `${info?.name ?? '?'}.${m.childForFieldName('name')?.text ?? '?'}` },
            path: input.path, range: rangeOf(m), middlewares: mw, authSignals: mw.filter((x) => AUTH_NAME_RE.test(x) || NEST_AUTH_DECORATORS.test(x.slice(1).split('(')[0]!)),
          });
        }
      }
    }
  };

  // ---- rules: entrypoints and auth signals first (they create handler symbols), then calls, then sinks ----
  const fileTarget = `${input.repo}:${input.path}`;
  const addSignal = (target: string, kind: 'annotation' | 'middleware' | 'security_config', detail: string, ruleId: string) => {
    if (!fx.authSignals.some((s) => s.target === target && s.detail === detail)) fx.authSignals.push({ target, kind, detail: detail.slice(0, 300), ruleId });
  };
  const ruleApplies = (rule: CompiledRule['rule']) => !(rule.match?.requiresImportAny && !rule.match.requiresImportAny.some((i) => imports.has(i)))
    && !rule.match?.notImportAny?.some((i) => imports.has(i));
  const runRule = (cr: CompiledRule, fn: (cap: Map<string, Node>) => void) => {
    if (cr.error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${cr.rule.id}: ${cr.error}` }); return; }
    if (!cr.query || !ruleApplies(cr.rule)) return;
    try {
      for (const match of cr.query.matches(root)) fn(captureMap(match.captures, cr.rule.captures));
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${cr.rule.id}: ${(e as Error).message}` });
    }
  };
  const seenRoutes = new Set<number>();
  for (const cr of rules) {
    const { rule } = cr;
    if (rule.kind === 'entrypoint') {
      runRule(cr, (cap) => {
        const call = cap.get('call');
        if (!call) return;
        if (rule.post === 'js_router_route') {
          const recv = cap.get('router');
          const verb = cap.get('verb')?.text ?? '';
          if (!recv || seenRoutes.has(call.id) || !routeReceiverOk(recv, rule)) return;
          // Egg router files are read by `js.egg.router`, not as Express routes of a parameter router.
          if (rule.id === 'js.express.route-param' && (input.langContext as JsFrameworkContext | undefined)?.eggControllers) return;
          seenRoutes.add(call.id);
          routeCall(rule, call, recv, verb, named(cap.get('args')));
        } else if (rule.post === 'js_nestjs_controller') nestController(rule, call);
        else if (rule.post === 'js_midway_controller') nestController(rule, call, true);
      });
    } else if (rule.kind === 'auth_signal') {
      runRule(cr, (cap) => {
        const node = cap.get('call') ?? cap.get('decorator');
        if (!node) return;
        if (rule.post === 'js_decorator_auth') {
          if (node.parent?.type === 'required_parameter' || node.parent?.type === 'optional_parameter' || node.parent?.type === 'formal_parameters') return;
          let owner: Node | null = node.parent;
          if (owner?.type === 'class_body') { let s = node.nextNamedSibling; while (s?.type === 'decorator') s = s.nextNamedSibling; owner = s; }
          if (owner?.type === 'export_statement') owner = owner.childForFieldName('declaration');
          if (!owner) return;
          const target = owner.type === 'method_definition' ? fnIds.get(owner.id) : classes.get(owner.id)?.symbolId;
          if (target) addSignal(target, 'annotation', short(node.text), rule.id);
        } else if (rule.post === 'js_security_config') {
          let outer = node;
          while (outer.parent?.type === 'member_expression' && outer.parent.parent?.type === 'call_expression') outer = outer.parent.parent;
          if (/forRoutes|apply/.test(node.text) && !AUTH_NAME_RE.test(outer.text)) return;
          addSignal(enclosingSymbol(outer) ?? fileTarget, 'security_config', short(outer.parent?.type === 'object' ? outer.parent.text : outer.text), rule.id);
        } else if (rule.post === 'js_use_auth') {
          for (const a of named(cap.get('args'))) {
            if (a.type === 'string' || a.type === 'template_string') continue;
            if (AUTH_NAME_RE.test(a.text) && !FUNCTION_VALUES.has(a.type)) addSignal(enclosingSymbol(node) ?? fileTarget, 'middleware', short(a.text), rule.id);
          }
        }
      });
    }
  }
  // ---- GraphQL resolvers ----
  const gqlRoots = input.graphql?.roots ?? { query: 'Query', mutation: 'Mutation', subscription: 'Subscription' };
  const rootNames = new Set([gqlRoots.query, gqlRoots.mutation, gqlRoots.subscription]);
  const pushGraphql = (type: string, field: string, handler: HandlerRef | null, node: Node, mw: string[], ruleId: string, framework: string) => {
    const g = graphqlEntryOf(input.graphql, type, field);
    if (!g || !handler) return;
    const middlewares = [...mw, ...g.directives];
    fx.entries.push({
      rpc: g.rpc, ruleId: `${ruleId}.${g.root ? 'operation' : 'field'}`, framework, httpMethod: 'RPC', pathTemplate: g.pathTemplate, handler,
      path: input.path, range: rangeOf(node), middlewares, authSignals: middlewares.filter((x) => AUTH_NAME_RE.test(x) || NEST_AUTH_DECORATORS.test(x.slice(1).split('(')[0]!)),
    });
  };
  /** Members of a resolver-map type object (`Query: { user: (_, { id }) => …, async posts() {…}, list }`). */
  const resolverMap = (type: string, obj: Node) => {
    for (const m of named(obj)) {
      let field: string | undefined;
      let ref: HandlerRef | null = null;
      if (m.type === 'method_definition') {
        field = m.childForFieldName('name')?.text;
        ref = { symbolId: syntheticFor(m, `${type}.${field}`), range: rangeOf(m) };
      } else if (m.type === 'pair') {
        field = literalOf(m.childForFieldName('key')?.text ?? '') ?? m.childForFieldName('key')?.text;
        const v = m.childForFieldName('value');
        const fn = functionOfValue(v);
        // `{ subscribe: …, resolve: … }` (subscriptions, field configs): the object as a whole.
        if (fn) ref = { symbolId: syntheticFor(fn, `${type}.${field}`), range: rangeOf(fn) };
        else if (v?.type === 'identifier' || v?.type === 'member_expression') ref = handlerRef(v, `${type}.${field}`).ref;
        else if (v?.type === 'object') { const inner = named(v).find((x) => x.type === 'method_definition' || x.type === 'pair'); if (inner) ref = { symbolId: syntheticFor(inner.type === 'pair' ? functionOfValue(inner.childForFieldName('value')) ?? inner : inner, `${type}.${field}`), range: rangeOf(v) }; }
      } else if (m.type === 'shorthand_property_identifier') {
        field = m.text;
        ref = handlerRef(m, `${type}.${field}`).ref;
      }
      if (field && ref) pushGraphql(type, field, ref, m, [], 'js.graphql.resolver-map', 'graphql');
    }
  };
  const keyText = (n: Node | null | undefined) => (n ? literalOf(n.text) ?? n.text : '');
  for (const obj of root.descendantsOfType('object')) {
    if (!obj) continue;
    const pairs = named(obj).filter((p) => p.type === 'pair' && p.childForFieldName('value')?.type === 'object');
    if (!pairs.some((p) => rootNames.has(keyText(p.childForFieldName('key'))))) continue;
    for (const p of pairs) {
      const type = keyText(p.childForFieldName('key'));
      if (rootNames.has(type) || input.graphql?.types[type]) resolverMap(type, p.childForFieldName('value')!);
    }
  }
  // `export const Query = { … }` / `const Mutation: Resolvers['Mutation'] = { … }`.
  for (const d of root.descendantsOfType('variable_declarator')) {
    const name = d?.childForFieldName('name')?.text ?? '';
    const v = d?.childForFieldName('value');
    if (rootNames.has(name) && v?.type === 'object' && d?.parent?.parent?.type !== 'statement_block') resolverMap(name, v);
  }
  // NestJS (`@nestjs/graphql`) / TypeGraphQL: `@Query()`, `@Mutation()`, `@Subscription()`, `@ResolveField()` / `@FieldResolver()`.
  const GQL_DECORATORS: Record<string, string | null> = { Query: gqlRoots.query, Mutation: gqlRoots.mutation, Subscription: gqlRoots.subscription, ResolveField: null, FieldResolver: null };
  for (const info of classes.values()) {
    const cls = info.node;
    const resolverDec = decoratorsOf(cls).find((d) => decoratorName(d) === 'Resolver');
    const members = named(cls.childForFieldName('body')).filter((m) => m.type === 'method_definition');
    // Without `@Resolver`, only when the file imports a GraphQL decorator package (NestJS REST has a `@Query()` parameter decorator).
    if (!resolverDec && ![...imports].some((i) => /^(@nestjs\/graphql|type-graphql)$/.test(i))) continue;
    // `@Resolver(() => Album)`, `@Resolver(of => Album)`, `@Resolver('Album')`.
    const ra = resolverDec ? decoratorArgs(resolverDec)[0] : undefined;
    const parentType = ra ? (stringOf(ra) ?? /=>\s*\[?\s*(\w+)/.exec(ra.text)?.[1] ?? null) : null;
    const classMw = nestMiddleware(decoratorsOf(cls));
    for (const m of members) {
      const ds = decoratorsOf(m);
      for (const d of ds) {
        const kind = decoratorName(d);
        if (!(kind in GQL_DECORATORS)) continue;
        const type = GQL_DECORATORS[kind] ?? parentType;
        if (!type) continue;
        const args = decoratorArgs(d);
        const field = args.map((a) => stringOf(a)).find((x) => !!x) ?? (args.find((a) => a.type === 'object') ? stringOf(objectProp(args.find((a) => a.type === 'object'), 'name')) : null) ?? m.childForFieldName('name')?.text ?? '';
        const symbolId = fnIds.get(m.id);
        pushGraphql(type, field, symbolId ? { symbolId } : null, m, [...classMw, ...nestMiddleware(ds)], 'js.graphql.decorator', 'graphql');
      }
    }
  }

  // ---- channel entries: sockets, queue consumers, timed jobs, commands; gated on the file's imports ----
  type Channel = NonNullable<RawEntry['channel']>;
  const imported = (...pkgs: string[]) => pkgs.some((p) => imports.has(p));
  const seenChannels = new Set<string>();
  const pushChannel = (ruleId: string, framework: string, ch: Channel, handler: Node | HandlerRef | null | undefined, node: Node, middlewares: string[] = [], nest = false) => {
    const dedupe = `${ch.key}@${node.id}`;
    if (seenChannels.has(dedupe)) return;
    seenChannels.add(dedupe);
    const label = `${ch.protocol} ${ch.route}`;
    const h = !handler ? { ref: {}, wrappers: [] as string[] }
      : !('type' in handler) ? { ref: handler, wrappers: [] as string[] }
      : handler.type === 'method_definition' ? { ref: { symbolId: fnIds.get(handler.id) ?? syntheticFor(handler, label), range: rangeOf(handler) }, wrappers: [] as string[] }
      : handlerRef(handler, label);
    const mws = [...middlewares, ...h.wrappers];
    fx.entries.push({
      channel: ch, ruleId, framework, httpMethod: '', pathTemplate: '', handler: h.ref, path: input.path, range: rangeOf(node),
      middlewares: mws, authSignals: mws.filter((x) => AUTH_NAME_RE.test(x) || (nest && NEST_AUTH_DECORATORS.test(x.slice(1).split('(')[0]!))),
    });
  };
  const callParts = (c: Node) => {
    const fn = c.childForFieldName('function');
    const member = fn?.type === 'member_expression';
    return { fn, recv: member ? fn.childForFieldName('object') : null, prop: member ? fn.childForFieldName('property')?.text ?? '' : '', args: named(c.childForFieldName('arguments')) };
  };
  /** Value of the first `const name = …` anywhere in the file, `await` unwrapped. */
  const declOf = (name: string): Node | null => {
    for (const d of root.descendantsOfType('variable_declarator')) {
      if (d?.childForFieldName('name')?.text !== name) continue;
      const v = d.childForFieldName('value');
      return v?.type === 'await_expression' ? named(v)[0] ?? null : v;
    }
    return null;
  };
  /** Display name of a queue / topic / channel argument: string, file constant, local string variable, regex or text. */
  const nameOf = (n: Node | null | undefined): string => {
    if (!n) return '?';
    const s = stringOf(n) ?? (n.type === 'identifier' ? stringOf(declOf(n.text)) : null);
    return s ?? short(n.text);
  };
  /** `key: value` or `key(…) {…}` member of an object literal. */
  const memberOf = (obj: Node | null | undefined, key: string): Node | null =>
    objectProp(obj ?? undefined, key) ?? named(obj).find((m) => m.type === 'method_definition' && m.childForFieldName('name')?.text === key) ?? null;
  const localFnNode = (name: string): Node | null => {
    for (const d of root.descendantsOfType('function_declaration')) if (d?.childForFieldName('name')?.text === name) return d;
    return functionOfValue(declOf(name));
  };
  const fnOf = (n: Node | undefined): Node | null => (!n ? null : FUNCTION_VALUES.has(n.type) ? n : n.type === 'identifier' ? localFnNode(n.text) : null);
  const paramName = (fn: Node, i: number): string | null => {
    const single = fn.childForFieldName('parameter');
    const p = single ? (i === 0 ? single : undefined) : named(fn.childForFieldName('parameters'))[i];
    const id = p?.type === 'identifier' ? p : p?.childForFieldName('pattern');
    return id?.type === 'identifier' ? id.text : null;
  };
  /** The leftmost identifier of `a.B` (or `require('pkg')`) binds a package whose root matches `re`. */
  const isFromPkg = (n: Node | null | undefined, re: RegExp): boolean => {
    let left = n;
    while (left?.type === 'member_expression') left = left.childForFieldName('object');
    if (!left) return false;
    const spec = requireSpec(left);
    if (spec) return re.test(packageRoot(spec));
    const b = left.type === 'identifier' ? bindings.get(left.text) : undefined;
    return !!b && !b.relative && re.test(packageRoot(b.module));
  };
  const fnLike = (n: Node | undefined) => !!n && (FUNCTION_VALUES.has(n.type) || n.type === 'identifier' || n.type === 'member_expression');
  const nsPrefix = (ns: string) => (ns && ns !== '/' ? (ns.startsWith('/') ? ns : `/${ns}`) : '');
  const uniqueTopicNames = (xs: string[]) => [...new Set(xs)];

  // ws: `new WebSocketServer({ path })` / `new WebSocket.Server(…)`; the entry is its `connection` handler.
  const wsServers = new Map<string, Node>();
  if (imported('ws')) {
    for (const d of root.descendantsOfType('variable_declarator')) {
      const n = d?.childForFieldName('name');
      const v = d?.childForFieldName('value');
      if (n?.type !== 'identifier' || v?.type !== 'new_expression') continue;
      const ctor = v.childForFieldName('constructor');
      if (/(^|\.)(WebSocketServer|Server)$/.test(ctor?.text ?? '') && isFromPkg(ctor, /^ws$/)) wsServers.set(n.text, v);
    }
    for (const [name, v] of wsServers) {
      const route = stringOf(objectProp(named(v.childForFieldName('arguments'))[0], 'path')) ?? name;
      const conn = allCalls.find((c) => { const p = callParts(c); return p.recv?.text === name && p.prop === 'on' && stringOf(p.args[0]) === 'connection'; });
      pushChannel('js.ws.server', 'ws', { kind: 'socket', protocol: 'websocket', key: `ws:${route}`, route }, conn ? callParts(conn).args[1] : null, conn ?? v);
    }
  }
  // Socket.IO: `socket.on('event', fn)` inside `io.on('connection', socket => …)` (namespaces `io.of('/ns')`, handlers
  // registered by a local function the socket is passed to); `io.use(mw)` / `.use(mw)` chains are middlewares.
  if (imported('socket.io')) {
    const SKIP_EVENTS = /^(disconnect|disconnecting|error|connect_error|newListener|removeListener)$/;
    const serverOf = (recv: Node | null, depth = 0): { ns: string; mws: string[] } => {
      if (!recv || depth > 5) return { ns: '', mws: [] };
      if (recv.type === 'identifier') {
        const own = (uses.get(recv.text) ?? []).filter((u) => u.path === '').flatMap((u) => u.middlewares);
        const v = declOf(recv.text);
        const inner = v?.type === 'call_expression' ? serverOf(v, depth + 1) : { ns: '', mws: [] };
        return inner.ns ? { ns: inner.ns, mws: [...inner.mws, ...own] } : { ns: '', mws: own };
      }
      if (recv.type === 'call_expression') {
        const p = callParts(recv);
        if (p.prop === 'of') return { ns: nsPrefix(nameOf(p.args[0])), mws: [] };
        if (p.prop === 'use') { const o = serverOf(p.recv, depth + 1); return { ns: o.ns, mws: [...o.mws, ...middlewareTexts(p.args)] }; }
      }
      return { ns: '', mws: [] };
    };
    const scanSocket = (fn: Node, idx: number, ns: string, mws: string[], depth: number) => {
      const sock = paramName(fn, idx);
      const body = fn.childForFieldName('body');
      if (!sock || !body) return;
      for (const c of body.descendantsOfType('call_expression')) {
        if (!c) continue;
        const { fn: f, recv, prop, args } = callParts(c);
        if (recv?.type === 'identifier' && recv.text === sock && /^(on|once|onAny)$/.test(prop)) {
          const event = prop === 'onAny' ? '*' : stringOf(args[0]);
          if (event === null || SKIP_EVENTS.test(event) || (prop !== 'onAny' && args.length < 2)) continue;
          const route = ns ? `${ns}#${event}` : event;
          pushChannel('js.socketio.event', 'socket.io', { kind: 'socket', protocol: 'socketio', key: `socketio:${route}`, route }, args[args.length - 1], c, mws);
        } else if (depth < 2 && f?.type === 'identifier') {
          const i = args.findIndex((a) => a.type === 'identifier' && a.text === sock);
          const target = i >= 0 ? localFnNode(f.text) : null;
          if (target && target.id !== fn.id) scanSocket(target, i, ns, mws, depth + 1);
        }
      }
    };
    for (const call of allCalls) {
      const { recv, prop, args } = callParts(call);
      if (prop !== 'on' || !recv || !/^(connection|connect)$/.test(stringOf(args[0]) ?? '')) continue;
      if (recv.type === 'identifier' && wsServers.has(recv.text)) continue;
      const cb = fnOf(args[1]);
      if (!cb) continue;
      const { ns, mws } = serverOf(recv);
      scanSocket(cb, 0, ns, mws, 0);
    }
  }
  // uWebSockets.js `app.ws('/p', { message })`, express-ws `app.ws('/p', …mw, handler)`, @fastify/websocket
  // `fastify.get('/p', { websocket: true }, handler)` / `fastify.route({ websocket: true, … })` (its HTTP entry stays).
  const uws = imported('uWebSockets.js');
  const expressWs = imported('express-ws');
  const fastifyWs = imported('@fastify/websocket', 'fastify-websocket');
  if (uws || expressWs || fastifyWs) {
    const wsRoutes = (recv: Node, call: Node, p: string, ruleId: string, framework: string, handler: Node | null, mws: string[]) => {
      for (const b of resolveRouter(recv, call.startIndex, p) ?? [{ prefix: '', middlewares: [] }]) {
        const route = joinRoute(b.prefix, p);
        pushChannel(ruleId, framework, { kind: 'socket', protocol: 'websocket', key: `ws:${route}`, route }, handler, call, [...b.middlewares, ...mws]);
      }
    };
    for (const call of allCalls) {
      const { recv, prop, args } = callParts(call);
      if (!recv) continue;
      if (prop === 'ws' && args.length >= 2) {
        const p = stringOf(args[0]);
        const last = args[args.length - 1]!;
        if (p === null) continue;
        if (uws && last.type === 'object') {
          const route = p;
          pushChannel('js.uws.ws', 'uWebSockets.js', { kind: 'socket', protocol: 'websocket', key: `ws:${route}`, route }, memberOf(last, 'message') ?? memberOf(last, 'open'), call);
        } else if (expressWs && last.type !== 'object') wsRoutes(recv, call, p, 'js.express-ws.route', 'express-ws', last, middlewareTexts(args.slice(1, -1)));
      } else if (fastifyWs && (prop === 'get' || prop === 'route')) {
        const opts = prop === 'route' ? args[0] : args[1];
        if (opts?.type !== 'object' || objectProp(opts, 'websocket')?.text !== 'true') continue;
        const p = prop === 'route' ? stringOf(objectProp(opts, 'url') ?? objectProp(opts, 'path')) : stringOf(args[0]);
        const h = memberOf(opts, 'wsHandler') ?? (prop === 'get' ? args[2] : undefined) ?? memberOf(opts, 'handler');
        if (p !== null && h) wsRoutes(recv, call, p, 'js.fastify.websocket', 'fastify-websocket', h, []);
      }
    }
  }
  // NestJS: gateways (`@SubscribeMessage`), microservices (`@MessagePattern` / `@EventPattern`), `@Cron` / `@Interval`,
  // `@nestjs/bull(mq)` processors (`@Processor('q')` + `@Process()` / `process()`); guards as for controllers.
  const nestWs = imported('@nestjs/websockets');
  const nestMs = imported('@nestjs/microservices');
  const nestSched = imported('@nestjs/schedule');
  const nestBull = imported('@nestjs/bull', '@nestjs/bullmq');
  if (nestWs || nestMs || nestSched || nestBull) {
    const TRANSPORTS: Record<string, string> = { KAFKA: 'kafka', RMQ: 'rabbitmq', REDIS: 'redis', NATS: 'nats', MQTT: 'mqtt', TCP: 'tcp', GRPC: 'grpc' };
    const CONTEXTS: Record<string, string> = { Kafka: 'kafka', Rmq: 'rabbitmq', Redis: 'redis', Nats: 'nats', Mqtt: 'mqtt', Tcp: 'tcp' };
    const patternText = (a: Node | undefined): string | null => {
      if (!a) return null;
      if (a.type === 'object') return named(a).filter((p) => p.type === 'pair').map((p) => `${keyText(p.childForFieldName('key'))}:${nameOf(p.childForFieldName('value'))}`).join(',') || null;
      return nameOf(a);
    };
    const wsProto = /\bWsAdapter\b/.test(input.text) || imported('@nestjs/platform-ws') ? 'websocket' : 'socketio';
    for (const info of classes.values()) {
      const cls = info.node;
      const cds = decoratorsOf(cls);
      const classMw = nestMiddleware(cds);
      const gw = cds.find((d) => decoratorName(d) === 'WebSocketGateway');
      const ns = nsPrefix(stringOf(objectProp(gw ? decoratorArgs(gw).find((a) => a.type === 'object') : undefined, wsProto === 'websocket' ? 'path' : 'namespace')) ?? '');
      const proc = cds.find((d) => decoratorName(d) === 'Processor');
      const procArg = proc ? decoratorArgs(proc)[0] : undefined;
      const queue = procArg ? stringOf(procArg) ?? stringOf(objectProp(procArg, 'name')) : null;
      const methods = named(cls.childForFieldName('body')).filter((m) => m.type === 'method_definition');
      const hasProcess = methods.some((m) => decoratorsOf(m).some((d) => decoratorName(d) === 'Process'));
      for (const m of methods) {
        const ds = decoratorsOf(m);
        const mname = m.childForFieldName('name')?.text ?? '?';
        const symbolId = fnIds.get(m.id);
        const ref: HandlerRef = symbolId ? { symbolId } : { text: `${info.name}.${mname}` };
        const mw = [...classMw, ...nestMiddleware(ds)];
        const queueEntry = (job: string | null) => {
          const route = job ? `${queue}/${job}` : queue!;
          pushChannel('js.bullmq.worker', 'nestjs', { kind: 'message', protocol: 'bullmq', key: `mq:bullmq:${route}`, route }, ref, m, mw, true);
        };
        if (nestBull && queue && !hasProcess && mname === 'process') queueEntry(null);
        for (const d of ds) {
          const dn = decoratorName(d);
          const a = decoratorArgs(d);
          if (dn === 'SubscribeMessage' && nestWs) {
            const event = stringOf(a[0]) ?? mname;
            const route = ns ? `${ns}#${event}` : event;
            pushChannel('js.nest.gateway', 'nestjs', { kind: 'socket', protocol: wsProto, key: `${wsProto === 'websocket' ? 'ws' : 'socketio'}:${route}`, route }, ref, m, mw, true);
          } else if ((dn === 'MessagePattern' || dn === 'EventPattern') && nestMs) {
            const pattern = patternText(a[0]) ?? mname;
            const t = /\bTransport\.(\w+)/.exec(a.slice(1).map((x) => x.text).join(' '))?.[1];
            const c = /\b(Kafka|Rmq|Redis|Nats|Mqtt|Tcp)Context\b/.exec(m.childForFieldName('parameters')?.text ?? '')?.[1];
            const protocol = t ? TRANSPORTS[t] ?? t.toLowerCase() : c ? CONTEXTS[c]! : 'nest-microservice';
            pushChannel('js.nest.microservice', 'nestjs', { kind: 'message', protocol, key: `mq:${protocol}:${pattern}`, route: pattern }, ref, m, mw, true);
          } else if ((dn === 'Cron' || dn === 'Interval') && nestSched) {
            const ms = a.find((x) => x.type !== 'string' && x.type !== 'object');
            const route = dn === 'Cron' ? (a[0] ? stringOf(a[0]) ?? short(a[0].text) : '?') : `${ms ? short(ms.text) : '?'}ms`;
            pushChannel('js.nest.schedule', 'nestjs', { kind: 'schedule', protocol: dn === 'Cron' ? 'cron' : 'interval', key: `cron:${info.name}.${mname}`, route }, ref, m, mw, true);
          } else if (dn === 'Process' && nestBull && queue) queueEntry(stringOf(a[0]) ?? stringOf(objectProp(a[0], 'name')));
        }
      }
    }
  }
  // kafkajs: `consumer.run({ eachMessage | eachBatch })`, topics from `consumer.subscribe({ topic | topics })` on the same receiver.
  if (imported('kafkajs')) {
    for (const call of allCalls) {
      const { recv, prop, args } = callParts(call);
      if (prop !== 'run' || !recv || args[0]?.type !== 'object') continue;
      const h = memberOf(args[0], 'eachMessage') ?? memberOf(args[0], 'eachBatch');
      if (!h) continue;
      const topics: string[] = [];
      for (const c of allCalls) {
        const p = callParts(c);
        if (p.prop !== 'subscribe' || p.recv?.text !== recv.text || p.args[0]?.type !== 'object') continue;
        const one = objectProp(p.args[0], 'topic');
        const many = objectProp(p.args[0], 'topics');
        if (one) topics.push(nameOf(one));
        if (many) topics.push(...(many.type === 'array' ? named(many).map(nameOf) : [nameOf(many)]));
      }
      for (const topic of topics.length ? uniqueTopicNames(topics) : ['?']) {
        pushChannel('js.kafkajs.consumer', 'kafkajs', { kind: 'message', protocol: 'kafka', key: `mq:kafka:${topic}`, route: topic }, h, call);
      }
    }
  }
  // amqplib: `channel.consume('queue', fn)`.
  if (imported('amqplib', 'amqp-connection-manager')) {
    for (const call of allCalls) {
      const { recv, prop, args } = callParts(call);
      if (prop !== 'consume' || !recv || args.length < 2 || !fnLike(args[1])) continue;
      const queue = nameOf(args[0]);
      pushChannel('js.amqp.consume', 'amqplib', { kind: 'message', protocol: 'rabbitmq', key: `mq:rabbitmq:${queue}`, route: queue }, args[1], call);
    }
  }
  // bullmq `new Worker('queue', fn)`; bull / bullmq `queue.process([name,] [concurrency,] fn)` on a `new Queue('q')` / `Bull('q')`.
  const bullPkg = imported('bullmq') ? 'bullmq' : imported('bull') ? 'bull' : null;
  if (bullPkg) {
    const queues = new Map<string, string>();
    for (const d of root.descendantsOfType('variable_declarator')) {
      const n = d?.childForFieldName('name');
      const v0 = d?.childForFieldName('value');
      const v = v0?.type === 'await_expression' ? named(v0)[0] : v0;
      const callee = v?.type === 'new_expression' ? v.childForFieldName('constructor') : v?.type === 'call_expression' ? v.childForFieldName('function') : null;
      if (n?.type === 'identifier' && callee && /(^|\.)(Queue|Bull)$/.test(callee.text) && isFromPkg(callee, /^bull(mq)?$/)) {
        queues.set(n.text, nameOf(named(v!.childForFieldName('arguments'))[0]));
      }
    }
    for (const ne of root.descendantsOfType('new_expression')) {
      const ctor = ne?.childForFieldName('constructor');
      if (!ne || !ctor || !/(^|\.)Worker$/.test(ctor.text) || !isFromPkg(ctor, /^bullmq$/)) continue;
      const args = named(ne.childForFieldName('arguments'));
      const queue = nameOf(args[0]);
      pushChannel('js.bullmq.worker', 'bullmq', { kind: 'message', protocol: 'bullmq', key: `mq:bullmq:${queue}`, route: queue }, fnLike(args[1]) ? args[1] : null, ne);
    }
    for (const call of allCalls) {
      const { recv, prop, args } = callParts(call);
      if (prop !== 'process' || recv?.type !== 'identifier' || !queues.has(recv.text) || !fnLike(args[args.length - 1])) continue;
      const job = args.length >= 2 && args[0]!.type === 'string' ? stringOf(args[0]) : null;
      const route = job ? `${queues.get(recv.text)}/${job}` : queues.get(recv.text)!;
      pushChannel('js.bull.process', bullPkg, { kind: 'message', protocol: 'bullmq', key: `mq:bullmq:${route}`, route }, args[args.length - 1], call);
    }
  }
  // redis / ioredis: `sub.subscribe('ch', listener)` (node-redis v4) or `sub.subscribe('ch'); sub.on('message', fn)` (ioredis).
  const redisPkg = imported('ioredis') ? 'ioredis' : imported('redis') ? 'redis' : null;
  if (redisPkg) {
    for (const call of allCalls) {
      const { recv, prop, args } = callParts(call);
      if (!recv || !/^(subscribe|pSubscribe|psubscribe|sSubscribe|ssubscribe)$/.test(prop)) continue;
      const chans = args.flatMap((a) => (a.type === 'array' ? named(a) : [a])).map((a) => stringOf(a)).filter((s): s is string => s !== null);
      if (!chans.length) continue;
      const on = allCalls.find((c) => { const p = callParts(c); return p.recv?.text === recv.text && p.prop === 'on' && /^p?message(Buffer)?$/.test(stringOf(p.args[0]) ?? ''); });
      const last = args[args.length - 1];
      const h = on ? callParts(on).args[1] : args.length > 1 && fnLike(last) && stringOf(last) === null ? last : null;
      for (const ch of uniqueTopicNames(chans)) pushChannel('js.redis.subscribe', redisPkg, { kind: 'message', protocol: 'redis', key: `mq:redis:${ch}`, route: ch }, h, call);
    }
  }
  // node-cron `cron.schedule(spec, fn)`, cron `new CronJob(spec, fn)` / `CronJob.from({ cronTime, onTick })`,
  // node-schedule `scheduleJob([name,] spec, fn)`; key by handler name, else by spec.
  if (imported('node-cron', 'cron', 'node-schedule')) {
    const cronEntry = (framework: string, spec: Node | null | undefined, h: Node | null | undefined, node: Node) => {
      if (!h || !fnLike(h)) return;
      const route = spec ? stringOf(spec) ?? short(spec.text) : '?';
      const name = h.type === 'identifier' || h.type === 'member_expression' ? h.text : route;
      pushChannel('js.cron', framework, { kind: 'schedule', protocol: 'cron', key: `cron:${name}`, route }, h, node);
    };
    for (const call of allCalls) {
      const { fn, recv, prop, args } = callParts(call);
      const callee = recv ? prop : fn?.type === 'identifier' ? bindings.get(fn.text)?.name ?? fn.text : '';
      const from = recv ?? fn;
      if (callee === 'schedule' && isFromPkg(from, /^node-cron$/)) cronEntry('node-cron', args[0], args[1], call);
      else if (callee === 'scheduleJob' && isFromPkg(from, /^node-schedule$/)) cronEntry('node-schedule', args.length >= 3 ? args[1] : args[0], args[args.length - 1], call);
      else if (callee === 'from' && recv && /(^|\.)CronJob$/.test(recv.text) && isFromPkg(recv, /^cron$/)) cronEntry('cron', objectProp(args[0], 'cronTime'), objectProp(args[0], 'onTick'), call);
    }
    for (const ne of root.descendantsOfType('new_expression')) {
      const ctor = ne?.childForFieldName('constructor');
      if (!ne || !ctor || !/(^|\.)CronJob$/.test(ctor.text) || !isFromPkg(ctor, /^cron$/)) continue;
      const args = named(ne.childForFieldName('arguments'));
      if (args[0]?.type === 'object') cronEntry('cron', objectProp(args[0], 'cronTime'), objectProp(args[0], 'onTick'), ne);
      else cronEntry('cron', args[0], args[1], ne);
    }
  }
  // commander `program.command('name <arg>')…action(fn)` / `new Command('name').action(fn)`; yargs
  // `.command('name', desc, builder, handler)` / `.command({ command, handler })`. The key is the command's first word.
  const cliName = (spec: string | null | undefined) => spec?.trim().split(/\s+/)[0] || null;
  if (imported('commander')) {
    const commandOf = (n: Node | null | undefined, depth = 0): string | null => {
      if (!n || depth > 12) return null;
      if (n.type === 'call_expression') {
        const { fn, recv, prop, args } = callParts(n);
        if (!recv) return fn?.text === 'createCommand' ? stringOf(args[0]) : null;
        return prop === 'command' || prop === 'createCommand' ? stringOf(args[0]) : commandOf(recv, depth + 1);
      }
      if (n.type === 'new_expression') return /(^|\.)Command$/.test(n.childForFieldName('constructor')?.text ?? '') ? stringOf(named(n.childForFieldName('arguments'))[0]) : null;
      if (n.type === 'identifier') { const v = declOf(n.text); return v ? commandOf(v, depth + 1) : null; }
      return null;
    };
    for (const call of allCalls) {
      const { recv, prop, args } = callParts(call);
      if (prop !== 'action' || !recv || !fnLike(args[0])) continue;
      const name = cliName(commandOf(recv));
      if (name) pushChannel('js.commander.command', 'commander', { kind: 'cli', protocol: 'cli', key: `cli:${name}`, route: name }, args[0], call);
    }
  }
  if (imported('yargs')) {
    const specOf = (n: Node | null | undefined) => (n?.type === 'array' ? stringOf(named(n)[0]) : stringOf(n));
    for (const call of allCalls) {
      const { recv, prop, args } = callParts(call);
      if (prop !== 'command' || !recv || !args[0]) continue;
      const obj = args[0].type === 'object' ? args[0] : args[2]?.type === 'object' && memberOf(args[2], 'handler') ? args[2] : null;
      const spec = args[0].type === 'object' ? specOf(objectProp(args[0], 'command')) : specOf(args[0]);
      const h = args.length >= 4 ? args[3] : obj ? memberOf(obj, 'handler') : null;
      const name = cliName(spec);
      if (name && h) pushChannel('js.yargs.command', 'yargs', { kind: 'cli', protocol: 'cli', key: `cli:${name}`, route: name }, h, call);
    }
  }

  // ---- frameworks: hapi route objects, Egg router files, Next.js / Nuxt file routes, Server Actions ----
  const fw = input.langContext as JsFrameworkContext | undefined;
  const declares = (...pkgs: string[]) => pkgs.some((p) => imports.has(p) || !!fw?.deps.includes(p));
  const relPath = fw?.appRoot ? input.path.slice(fw.appRoot.length + 1) : input.path;
  /** Handler of a node: a function declared in this file keeps its symbol; otherwise `handlerRef`. */
  const refOf = (n: Node, label: string): { ref: HandlerRef; wrappers: string[] } => {
    const id = fnIds.get(n.id);
    return id ? { ref: { symbolId: id }, wrappers: [] } : handlerRef(n, label);
  };
  /** Function node behind a handler expression in this file (for inline-auth scans). */
  const bodyOf = (n: Node | null | undefined): Node | null => {
    if (!n) return null;
    if (FUNCTION_TYPES.has(n.type) || fnIds.has(n.id)) return n;
    if (n.type === 'identifier') return localFnNode(n.text);
    if (n.type === 'call_expression') { const a = named(n.childForFieldName('arguments')); return bodyOf(a[a.length - 1]); }
    return null;
  };
  const inlineAuth = (fn: Node | null): string[] => {
    const m = fn ? INLINE_AUTH_RE.exec(fn.text) : null;
    return m ? [`auth call: ${m[1]}()`] : [];
  };
  const pushHttp = (ruleId: string, framework: string, method: string, route: string, ref: { ref: HandlerRef; wrappers: string[] }, node: Node, mws: string[], notAuth: string[] = []) => {
    const all = [...mws, ...ref.wrappers];
    fx.entries.push({
      ruleId, framework, httpMethod: method, pathTemplate: route, handler: ref.ref, path: input.path, range: rangeOf(node),
      middlewares: all, authSignals: all.filter((x) => !notAuth.includes(x) && AUTH_NAME_RE.test(x)),
    });
  };
  /** Default export of the file (function, `wrap(handler)`, identifier). */
  const defaultExport = (): Node | null => {
    for (const st of named(root)) {
      if (st.type !== 'export_statement' || !st.children.some((c) => c?.type === 'default')) continue;
      return st.childForFieldName('declaration') ?? st.childForFieldName('value') ?? named(st).find((c) => c.type !== 'comment' && c.type !== 'decorator') ?? null;
    }
    return null;
  };
  /** Exported functions by exported name: declarations, `export const X = …`, `export { a as X }`, `export const { X } = obj`. */
  const namedExports = (): Map<string, Node> => {
    const out = new Map<string, Node>();
    for (const st of named(root)) {
      if (st.type !== 'export_statement' || st.children.some((c) => c?.type === 'default')) continue;
      const decl = st.childForFieldName('declaration');
      if (decl?.type === 'function_declaration' || decl?.type === 'generator_function_declaration') {
        const n = decl.childForFieldName('name')?.text;
        if (n) out.set(n, decl);
      } else if (decl?.type === 'lexical_declaration' || decl?.type === 'variable_declaration') {
        for (const v of named(decl)) {
          const n = v.childForFieldName('name');
          const value = v.childForFieldName('value');
          if (n?.type === 'identifier' && value) out.set(n.text, value);
          else if (n?.type === 'object_pattern' && value) {
            for (const p of named(n)) if (p.type === 'shorthand_property_identifier_pattern') out.set(p.text, value);
          }
        }
      } else {
        const clause = named(st).find((c) => c.type === 'export_clause');
        for (const sp of named(clause)) {
          const local = sp.childForFieldName('name');
          const exported = sp.childForFieldName('alias')?.text ?? local?.text;
          if (local && exported) out.set(exported, local);
        }
      }
    }
    return out;
  };
  const frameworkRules = rules.filter((cr) => cr.rule.kind === 'entrypoint' && /^js_(hapi_route|egg_route|next_route|nuxt_route|next_server_action)$/.test(cr.rule.post ?? ''));
  for (const cr of frameworkRules) {
    const { rule } = cr;
    if (rule.post === 'js_hapi_route') {
      if (!declares('@hapi/hapi', 'hapi')) continue;
      runRule(cr, (cap) => {
        const obj = cap.get('call');
        if (obj?.type !== 'object') return;
        const route = stringOf(objectProp(obj, 'path'));
        const methodNode = objectProp(obj, 'method');
        if (route === null || !route.startsWith('/') || !methodNode) return;
        const optsNode = objectProp(obj, 'options') ?? objectProp(obj, 'config');
        const opts = optsNode?.type === 'object' ? optsNode : undefined;
        const handler = objectProp(obj, 'handler') ?? (opts ? objectProp(opts, 'handler') : null);
        if (!handler) return;
        const mws: string[] = [];
        const notAuth: string[] = [];
        const auth = opts ? objectProp(opts, 'auth') : null;
        if (auth?.text === 'false') { mws.push('auth: false'); notAuth.push('auth: false'); }
        else if (auth) mws.push(short(`auth: ${auth.text}`));
        else if (fw?.hapiDefaultAuth) mws.push(fw.hapiDefaultAuth);
        const pre = opts ? objectProp(opts, 'pre') : null;
        if (pre) mws.push(...middlewareTexts([pre]));
        const methods = methodNode.type === 'array' ? named(methodNode).map((m) => stringOf(m)) : [stringOf(methodNode)];
        const ref = refOf(handler, `${methods.join(',')} ${route}`);
        for (const m of methods) if (m) pushHttp(rule.id, rule.framework, m === '*' ? 'ANY' : m.toUpperCase(), route, ref, obj, mws, notAuth);
      });
    } else if (rule.post === 'js_egg_route') {
      // Egg router files (`app/router.js`, `app/router/**`): `router.verb([name,] path, ...mw, controller.a.b)`,
      // `router.resources([name,] prefix, ...mw, controller.a)`, `router.namespace(prefix, ...mw)` sub-routers.
      const controllers = fw?.eggControllers;
      if (!controllers || !declares('egg')) continue;
      const global = (fw?.eggMiddleware ?? []).map((m) => `config.middleware: ${m}`);
      // `const { user, topic } = controller.api` / `const { site } = app.controller`: local name → controller path.
      const aliases = new Map<string, string>();
      for (const d of root.descendantsOfType('variable_declarator')) {
        const pat = d?.childForFieldName('name');
        const from = /^(?:this\.)?(?:app\.)?controller((?:\.\w+)*)$/.exec(d?.childForFieldName('value')?.text ?? '');
        if (pat?.type !== 'object_pattern' || !from) continue;
        for (const p of named(pat)) {
          const key = p.type === 'shorthand_property_identifier_pattern' ? p.text : p.type === 'pair_pattern' ? p.childForFieldName('key')?.text : undefined;
          const local = p.type === 'pair_pattern' ? p.childForFieldName('value')?.text : key;
          if (key && local) aliases.set(local, `controller${from[1]}.${key}`);
        }
      }
      const controllerText = (n: Node): string => {
        if (n.type === 'string') return `controller.${stringOf(n) ?? ''}`;
        const t = n.text.replace(/^this\./, '').replace(/^app\./, '');
        const head = t.split('.')[0]!;
        return aliases.has(head) ? aliases.get(head)! + t.slice(head.length) : t;
      };
      const eggRef = (n: Node, label: string): { ref: HandlerRef; wrappers: string[] } => {
        const text = controllerText(n);
        const m = /^controller\.([\w.]+)$/.exec(text);
        if (!m) return refOf(n, label);
        const segs = m[1]!.split('.');
        const method = segs.pop()!;
        const mod = controllers[segs.join('.')];
        return mod ? { ref: { text: method, importPath: mod, moduleMember: true }, wrappers: [] } : { ref: { text: m[1]! }, wrappers: [] };
      };
      const base = (recv: Node): { prefix: string; mws: string[] } | null => {
        if (/^(this\.)?(app\.)?router$/.test(recv.text)) return { prefix: '', mws: [] };
        const v = recv.type === 'identifier' ? declOf(recv.text) : recv.type === 'call_expression' ? recv : null;
        if (v?.type !== 'call_expression') return null;
        const p = callParts(v);
        if (p.prop !== 'namespace' || !p.recv || !/^(this\.)?(app\.)?router$/.test(p.recv.text)) return null;
        const prefix = stringOf(p.args[0]);
        return prefix === null ? null : { prefix, mws: middlewareTexts(p.args.slice(1)) };
      };
      const RESOURCES: [string, string, string][] = [['GET', '', 'index'], ['GET', '/new', 'new'], ['GET', '/:id', 'show'], ['GET', '/:id/edit', 'edit'], ['POST', '', 'create'], ['PUT', '/:id', 'update'], ['DELETE', '/:id', 'destroy']];
      runRule(cr, (cap) => {
        const call = cap.get('call');
        const recv = cap.get('router');
        const verb = cap.get('verb')?.text ?? '';
        if (!call || !recv) return;
        const b = base(recv);
        if (!b) return;
        let args = named(cap.get('args'));
        if (args.length >= 3 && stringOf(args[0]) !== null && stringOf(args[1]) !== null && args[1]!.type !== 'identifier') args = args.slice(1);
        const route = stringOf(args[0]);
        if (route === null || args.length < 2) return;
        const handler = args[args.length - 1]!;
        const mws = [...global, ...b.mws, ...middlewareTexts(args.slice(1, -1))];
        const full = joinRoute(b.prefix, route);
        if (verb === 'resources') {
          const key = /^controller\.([\w.]+)$/.exec(controllerText(handler))?.[1];
          const mod = key ? controllers[key] : undefined;
          for (const [method, suffix, action] of RESOURCES) {
            const ref: HandlerRef = mod ? { text: action, importPath: mod, moduleMember: true } : { text: `${key ?? short(handler.text)}.${action}` };
            pushHttp(rule.id, rule.framework, method, joinRoute(full, suffix), { ref, wrappers: [] }, call, mws);
          }
          return;
        }
        const method = HTTP_VERBS[verb];
        if (method) pushHttp(rule.id, rule.framework, method, full, eggRef(handler, `${method} ${full}`), call, mws);
      });
    } else if (rule.post === 'js_next_route') {
      if (!declares('next')) continue;
      const r = nextRouteOf(relPath);
      if (!r) continue;
      const nm = fw?.nextMiddleware;
      const mw = nm && nextMatcherCovers(nm.matchers, r.route) ? [`next middleware${nm.auth ? ' (auth)' : ''}: ${nm.file}`] : [];
      if (r.kind === 'pages') {
        const h = defaultExport();
        if (!h) continue;
        // Methods the handler branches on (`req.method === 'POST'`, `case 'DELETE':`); none → any method.
        const fn = bodyOf(h);
        const methods = [...new Set([...(fn?.text ?? input.text).matchAll(/\.method\s*[!=]==?\s*['"](\w+)['"]|case\s+['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]/g)].map((m) => (m[1] ?? m[2])!.toUpperCase()))].filter((m) => NEXT_METHODS.includes(m));
        const ref = refOf(h, `${r.route}`);
        for (const m of methods.length ? methods : ['ANY']) pushHttp(rule.id, rule.framework, m, r.route, ref, h, [...mw, ...inlineAuth(fn)]);
      } else {
        for (const [name, node] of namedExports()) {
          if (!NEXT_METHODS.includes(name)) continue;
          const fn = bodyOf(node);
          pushHttp(rule.id, rule.framework, name, r.route, refOf(fn ?? node, `${name} ${r.route}`), node, [...mw, ...inlineAuth(fn)]);
        }
      }
    } else if (rule.post === 'js_nuxt_route') {
      if (!declares('nuxt', 'nitropack')) continue;
      const r = nuxtRouteOf(relPath);
      const h = r ? defaultExport() : null;
      if (!r || !h) continue;
      const fn = bodyOf(h);
      const mw = (fw?.nuxtMiddleware ?? []).map((m) => `server middleware${m.auth ? ' (auth)' : ''}: ${m.file}`);
      pushHttp(rule.id, rule.framework, r.method, r.route, refOf(h, `${r.method} ${r.route}`), h, [...mw, ...inlineAuth(fn)]);
    } else if (rule.post === 'js_next_server_action') {
      // Server Actions: every export of a `'use server'` module, and functions whose body starts with `'use server'`.
      // Any client can POST to them, so they are entries; key `rpc:next-action:<module>#<function>`.
      if (!declares('next')) continue;
      const action = (name: string, fn: Node, node: Node) => {
        const route = `${pkg}#${name}`;
        const key = `rpc:next-action:${route}`;
        if (fx.entries.some((e) => e.channel?.key === key)) return;
        const ref = refOf(fn, `action ${name}`);
        const mws = [...ref.wrappers, ...inlineAuth(bodyOf(fn))];
        fx.entries.push({
          channel: { kind: 'rpc', protocol: 'next-action', key, route }, ruleId: rule.id, framework: rule.framework, httpMethod: '', pathTemplate: '',
          handler: ref.ref, path: input.path, range: rangeOf(node), middlewares: mws, authSignals: mws.filter((x) => AUTH_NAME_RE.test(x)),
        });
      };
      if (USE_SERVER_DIRECTIVE_RE.test(input.text.slice(0, 2048))) {
        for (const [name, node] of namedExports()) { const fn = bodyOf(node); if (fn) action(name, fn, node); }
        const d = defaultExport();
        const dfn = bodyOf(d);
        if (d && dfn) action('default', dfn, d);
      }
      for (const fn of root.descendantsOfType([...FUNCTION_TYPES])) {
        if (!fn) continue;
        const first = named(fn.childForFieldName('body'))[0];
        if (first?.type !== 'expression_statement' || !/^(['"])use server\1;?$/.test(first.text)) continue;
        const name = fn.childForFieldName('name')?.text ?? (fn.parent?.type === 'variable_declarator' ? fn.parent.childForFieldName('name')?.text : undefined) ?? `<inline L${fn.startPosition.row + 1}>`;
        action(name, fn, fn);
      }
    }
  }

  // ---- gRPC servers: @grpc/grpc-js `server.addService(svc, impl)`, NestJS `@GrpcMethod` / `@GrpcStreamMethod` ----
  const grpcRpc = (service: string, method: string) => {
    // Generated stubs name the service `GreeterService` for proto `Greeter`.
    const svc = input.grpcServices?.some((x) => x.name === service) ? service : service.replace(/Service$/, '') || service;
    return rpcOf(input.grpcServices, svc, method);
  };
  if (imported('@grpc/grpc-js', 'grpc')) {
    for (const call of allCalls) {
      const { prop, args } = callParts(call);
      if (prop !== 'addService' || args.length < 2) continue;
      const svcText = args[0]!.text;
      const service = /(?:^|\.)(\w+)\.service$/.exec(svcText)?.[1] ?? /^(\w+)$/.exec(svcText)?.[1];
      if (!service) continue;
      let impl: Node | null = args[1]!;
      if (impl.type === 'identifier') impl = declOf(impl.text);
      const methods: { name: string; node: Node }[] = [];
      if (impl?.type === 'object') {
        for (const m of named(impl)) {
          if (m.type === 'pair') { const v = m.childForFieldName('value'); const k = keyText(m.childForFieldName('key')); if (v && k) methods.push({ name: k, node: v }); }
          else if (m.type === 'shorthand_property_identifier') methods.push({ name: m.text, node: m });
          else if (m.type === 'method_definition') methods.push({ name: m.childForFieldName('name')?.text ?? '', node: m });
        }
      } else if (impl?.type === 'new_expression') {
        const cls = classByName.get(impl.childForFieldName('constructor')?.text ?? '');
        for (const [name, m] of cls?.methods ?? []) if (name !== 'constructor') methods.push({ name, node: fnIdNode(m.id) ?? call });
      }
      for (const m of methods) {
        const rpc = grpcRpc(service, m.name);
        if (!rpc) continue;
        const ref: HandlerRef = m.node.type === 'method_definition' && fnIds.get(m.node.id) ? { symbolId: fnIds.get(m.node.id)! } : fnIdOf(m.node) ?? handlerRef(m.node, `rpc ${service}.${m.name}`).ref;
        fx.entries.push({ rpc, ruleId: 'js.grpc.add-service', framework: 'grpc', httpMethod: 'RPC', pathTemplate: '', handler: ref, path: input.path, range: rangeOf(m.node), middlewares: [], authSignals: [] });
      }
    }
  }
  if (imported('@nestjs/microservices')) {
    for (const info of classes.values()) {
      const classMw = nestMiddleware(decoratorsOf(info.node));
      for (const m of named(info.node.childForFieldName('body')).filter((x) => x.type === 'method_definition')) {
        const ds = decoratorsOf(m);
        const g = ds.find((d) => /^Grpc(Stream)?Method$/.test(decoratorName(d)));
        if (!g) continue;
        const a = decoratorArgs(g);
        const mname = m.childForFieldName('name')?.text ?? '';
        const service = stringOf(a[0]) ?? info.name;
        const method = stringOf(a[1]) ?? mname.charAt(0).toUpperCase() + mname.slice(1);
        const rpc = grpcRpc(service, method);
        const id = fnIds.get(m.id);
        if (!rpc || !id) continue;
        const mw = [...classMw, ...nestMiddleware(ds)];
        fx.entries.push({ rpc, ruleId: 'js.nest.grpc-method', framework: 'nestjs', httpMethod: 'RPC', pathTemplate: '', handler: { symbolId: id }, path: input.path, range: rangeOf(m), middlewares: mw, authSignals: mw.filter((x) => AUTH_NAME_RE.test(x) || NEST_AUTH_DECORATORS.test(x.slice(1).split('(')[0]!)) });
      }
    }
  }

  for (const e of fx.entries) {
    if (e.framework === 'nestjs') continue; // decorators are reported by the auth-signal rule
    for (const mw of e.authSignals) if (!fx.authSignals.some((s) => s.detail === mw)) addSignal(fileTarget, 'middleware', mw, e.ruleId);
  }

  // ---- calls ----
  for (const call of allCalls) {
    const from = enclosingSymbol(call);
    if (!from) continue;
    let fn = call.childForFieldName('function');
    if (fn?.type === 'await_expression') fn = named(fn)[0] ?? null; // TS: `await x.m<T>(…)`
    const argsNode = call.childForFieldName('arguments');
    const arity = argsNode?.type === 'template_string' ? 1 : named(argsNode).length;
    let method: string | null = null;
    let facts = { receiverText: null as string | null, receiverType: null as string | null, receiverImport: null as string | null };
    if (fn?.type === 'identifier') {
      if (fn.text === 'require') continue;
      method = fn.text;
      const b = bindings.get(fn.text);
      if (b) {
        if (b.kind === 'named') method = b.name;
        facts.receiverImport = b.module;
      }
    } else if (fn?.type === 'member_expression') {
      method = fn.childForFieldName('property')?.text ?? null;
      facts = receiverFacts(fn.childForFieldName('object'), call);
    }
    if (!method) continue;
    let callArity = arity;
    // JS arguments may be omitted: calls to a method of a class in this file use its declared arity.
    const cls = facts.receiverText === 'this' ? enclosingClass(call) : facts.receiverType ? classByName.get(facts.receiverType) : null;
    const declared = cls?.methods.get(method);
    if (declared && arity <= declared.arity) callArity = declared.arity;
    fx.calls.push({
      from, method, receiverText: facts.receiverText, receiverType: facts.receiverType, receiverImport: facts.receiverImport,
      arity: callArity, line: call.startPosition.row + 1, calleeText: (fn?.text ?? method).slice(0, 200),
    });
  }

  // ---- sinks ----
  const declValue = (id: Node): Node | null => {
    // The last `const x = …` / `x = …` before the use, in the enclosing function (or the file).
    const scope = enclosingFnNode(id) ?? root;
    let best: Node | null = null;
    for (const d of scope.descendantsOfType('variable_declarator')) {
      if (!d || d.startIndex > id.startIndex) continue;
      if (d.childForFieldName('name')?.text === id.text) best = d.childForFieldName('value');
    }
    for (const a of scope.descendantsOfType('assignment_expression')) {
      if (!a || a.startIndex > id.startIndex || (best && a.startIndex < best.startIndex)) continue;
      if (a.childForFieldName('left')?.text === id.text) best = a.childForFieldName('right');
    }
    for (const a of scope.descendantsOfType('augmented_assignment_expression')) {
      if (a && a.startIndex < id.startIndex && a.childForFieldName('left')?.text === id.text) return a;
    }
    return best;
  };
  /** 'lit' (literal), 'concat' (built by concatenation / interpolation / format / path.join), or 'var'. */
  const shape = (n: Node | null | undefined, depth = 0): 'lit' | 'concat' | 'var' => {
    if (!n || depth > 3) return 'var';
    switch (n.type) {
      case 'string': case 'number': case 'true': case 'false': case 'null': case 'undefined': case 'regex': return 'lit';
      case 'template_string': {
        // Substitutions of file-level string constants (`SELECT ${COLUMNS} …`) keep the template constant.
        const subs = named(n).filter((c) => c.type === 'template_substitution');
        return subs.every((c) => { const e = named(c)[0]; return e?.type === 'identifier' && consts.has(e.text); }) ? 'lit' : 'concat';
      }
      case 'parenthesized_expression': case 'as_expression': case 'non_null_expression': case 'satisfies_expression': return shape(named(n)[0], depth + 1);
      case 'augmented_assignment_expression': return 'concat';
      case 'binary_expression': {
        const l = shape(n.childForFieldName('left'), depth + 1);
        const r = shape(n.childForFieldName('right'), depth + 1);
        if (l === 'lit' && r === 'lit') return 'lit';
        return n.childForFieldName('operator')?.text === '+' || n.children.some((c) => c?.type === '+') ? 'concat' : 'var';
      }
      case 'array': return named(n).every((c) => shape(c, depth + 1) === 'lit') ? 'lit' : 'var';
      case 'object': {
        const vals = named(n).map((p) => (p.type === 'pair' ? shape(p.childForFieldName('value'), depth + 1) : 'var'));
        return vals.includes('concat') ? 'concat' : vals.every((v) => v === 'lit') ? 'lit' : 'var';
      }
      case 'identifier': {
        if (consts.has(n.text)) return 'lit';
        const v = declValue(n);
        return v ? shape(v, depth + 1) : 'var';
      }
      case 'call_expression': {
        const f = n.childForFieldName('function')?.text ?? '';
        const args = named(n.childForFieldName('arguments'));
        if (/(^|\.)(concat|format|join|resolve|replace|sprintf)$/.test(f) || /^(util\.format|path\.(join|resolve))$/.test(f)) {
          return args.every((a) => shape(a, depth + 1) === 'lit') && !/\.(concat|join)$/.test(f) ? 'lit' : 'concat';
        }
        return 'var';
      }
      default: return 'var';
    }
  };
  /** Literal text a string expression starts with (`'/a/' + x` → `/a/`, `` `/b/${x}` `` → `/b/`). */
  const leadingLiteral = (n: Node | null | undefined, depth = 0): string => {
    if (!n || depth > 4) return '';
    if (n.type === 'string') return unquote(n.text);
    if (n.type === 'template_string') { let out = ''; for (const c of n.children) { if (!c || c.type === '`') continue; if (c.type === 'template_substitution') break; out += c.text; } return out; }
    if (n.type === 'binary_expression') return leadingLiteral(n.childForFieldName('left'), depth + 1);
    if (n.type === 'parenthesized_expression' || n.type === 'as_expression') return leadingLiteral(named(n)[0], depth + 1);
    if (n.type === 'identifier') return consts.get(n.text) ?? '';
    return '';
  };
  const taintOf = (category: string, args: Node[]): string | undefined => {
    const first = shape(args[0]);
    if (first === 'concat') return 'string_concat';
    if (category === 'sqli' || category === 'nosqli' || category === 'ssrf' || category === 'open_redirect' || category === 'path_traversal') return first === 'lit' ? 'constant' : undefined;
    const all = args.map((a) => shape(a));
    if (all.some((s) => s === 'concat')) return 'string_concat';
    return all.length > 0 && all.every((s) => s === 'lit') ? 'constant' : undefined;
  };
  const sinkAllowed = (post: string | undefined, args: Node[], receiver: Node | null, call: Node, method: string, taint: string | undefined): boolean => {
    switch (post) {
      case undefined: return true;
      case 'js_sink_string_code': {
        const a = args[0];
        if (!a) return false;
        return /^(string|template_string|binary_expression)$/.test(a.type) || (a.type === 'identifier' && !localFuncs.has(a.text) && shape(a) !== 'var');
      }
      case 'js_sink_non_literal': return args.length > 0 && taint !== 'constant' && !args.every((a) => shape(a) === 'lit');
      case 'js_sink_concat_only': return taint === 'string_concat';
      case 'js_sink_html_concat': return taint === 'string_concat' && /<[a-zA-Z/!]/.test(args[0]?.text ?? '');
      case 'js_sink_xml_noent': return args.some((a) => /noent\s*:\s*true/.test(a.text));
      case 'js_sink_request_arg': return args.some((a) => REQUEST_DATA_RE.test(a.text));
      case 'js_sink_nosql_filter': {
        const a = args[0];
        if (!a) return false;
        if (a.type === 'object') return /(^|[{,\s'"])\$where\b/.test(a.text) || named(a).some((p) => p.type === 'pair' && REQUEST_DATA_RE.test(p.childForFieldName('value')?.text ?? '') && /^(req|request|ctx)\./.test(p.childForFieldName('value')?.text ?? '') && !/\.(id|_id)$/.test(p.childForFieldName('value')?.text ?? ''));
        return REQUEST_DATA_RE.test(a.text) && /^(req|request|ctx)\.[\w.]+$/.test(a.text);
      }
      // open-redirect targets — `new URL('/login', req.url)` checks the URL's first argument; a target whose
      // literal prefix fixes the origin (`'/topic/' + id`, `` `https://host/?q=${q}` ``) cannot leave the site.
      case 'js_sink_redirect_target': {
        const a = args[0];
        if (!a) return false;
        const target = a.type === 'new_expression' && /(^|\.)URL$/.test(a.childForFieldName('constructor')?.text ?? '') ? named(a.childForFieldName('arguments'))[0] : a;
        if (!target || shape(target) === 'lit') return false;
        return !/^(\/(?!\/)|https?:\/\/[^/?#\s]+[/?#])/.test(leadingLiteral(target));
      }
      // Nuxt / Nitro server code (auto-imported h3 utilities): `sendRedirect(event, url)`, `$fetch(url)`.
      case 'js_sink_nuxt_server': {
        if (!/^server\//.test(relPath) || !declares('nuxt', 'nitropack', 'h3')) return false;
        const a = method === 'sendRedirect' ? args[1] : args[0];
        if (!a || shape(a) === 'lit') return false;
        return method !== 'sendRedirect' || !/^(\/(?!\/)|https?:\/\/[^/?#\s]+[/?#])/.test(leadingLiteral(a));
      }
      case 'js_sink_by_id': return /ById|ByPk|ByID/.test(method) || args.some((a) => ID_ARG_RE.test(a.text));
      case 'js_sink_state_write': {
        if (method === 'save' || method === 'persist' || method === 'flush') {
          // `entity.status = …; repo.save(entity)` / `entity.save()`: the saved object had a state field assigned.
          const body = enclosingFnNode(call)?.text ?? '';
          const names = [receiver?.text, args[0]?.type === 'identifier' ? args[0].text : undefined].filter((t): t is string => !!t && /^[\w$.]+$/.test(t));
          return names.some((t) => new RegExp(`(^|[^\\w$.])${t.replace(/[.$]/g, (c) => `\\${c}`)}\\.(${STATE_FIELDS})\\s*[-+*]?=[^=]`, 'i').test(body))
            || STATE_FIELD_RE.test(args.map((a) => a.text).join(' '));
        }
        return STATE_FIELD_RE.test(args.map((a) => a.text).join(' '));
      }
      default: return true;
    }
  };
  const seenSinks = new Set<string>();
  for (const cr of rules) {
    if (cr.rule.kind !== 'sink') continue;
    const { rule } = cr;
    runRule(cr, (cap) => {
      const call = cap.get('call');
      if (!call) return;
      const args = named(cap.get('args'));
      const receiver = cap.get('receiver') ?? null;
      const methodNode = cap.get('method');
      const method = methodNode?.text ?? '';
      let facts: { receiverText: string | null; receiverType: string | null; receiverImport: string | null };
      if (receiver) facts = receiverFacts(receiver, call);
      else {
        const b = methodNode?.type === 'identifier' ? bindings.get(method) : undefined;
        facts = { receiverText: null, receiverType: null, receiverImport: b?.module ?? null };
      }
      if (!ruleMatches(rule.match, { ...facts, imports, argCount: args.length })) return;
      const category = rule.category ?? 'other';
      const taint = taintOf(category, args);
      if (!sinkAllowed(rule.post, args, receiver, call, method, taint)) return;
      const api = fillApi(rule.api ?? '', { method, receiver: facts.receiverText, importPath: facts.receiverImport ?? facts.receiverText });
      const sink = makeSink(input.repo, input.path, rule, call, enclosingSymbol(call), api, taint);
      if (!seenSinks.has(sink.sinkId)) { seenSinks.add(sink.sinkId); fx.sinks.push(sink); }
    });
  }
  return fx;
}
