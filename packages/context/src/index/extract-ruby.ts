// Ruby extraction (76–79): symbols (modules, classes, instance and singleton methods,
// top-level methods), calls with receiver facts; entries of Rails (config/routes.rb DSL resolved to controller
// actions, callbacks along the inheritance chain), Sinatra (classic and modular, namespaces, mount prefixes) and
// Grape (prefix / version / namespace / route_param, mounts); auth signals; sinks from `rules/ruby/**`.
//
// Identities follow the registry conventions (languages.ts): a class / module `A::B` declared in a file has container
// `<namespace>.<Name>` where the namespace is the enclosing constant path (or the file path at top level); methods are
// `<class container>.<name>(<arity>)` with the arity counting declared parameters except blocks; `self.x` methods use
// the same container. `FileExtract.pkg` is the file path (Ruby has no file-level module). Sinatra and Grape route
// blocks get synthetic symbols `<container>.<VERB /path>(<block params>)` so calls inside them have a caller.
import type { Node, Tree } from 'web-tree-sitter';
import type { AuthSignal } from '@xiezhi/contracts';
import { fillApi, makeSink, rangeOf, ruleMatches, type CompiledRule } from './common.js';
import { rpcOf } from './proto.js';
import { effectiveFilters, joinPath, RB_ROUTES_RE, type RbClassFacts, type RubyContext } from './extract-ruby-context.js';
import { emptyExtract, type ExtractInput, type FileExtract, type HandlerRef, type RawEntry } from './types.js';

const named = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c);
const oneLine = (s: string, n = 200) => { const t = s.replace(/\s+/g, ' ').trim(); return t.length > n ? t.slice(0, n) + '…' : t; };
const PARAM_TYPES = new Set(['identifier', 'optional_parameter', 'keyword_parameter', 'splat_parameter', 'hash_splat_parameter', 'destructured_parameter', 'forward_parameter']);
const VERBS: Record<string, string> = { get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH', delete: 'DELETE', head: 'HEAD', options: 'OPTIONS', link: 'LINK', unlink: 'UNLINK' };
/** Statement containers whose calls the DSL walkers look through (conditionals, `begin`, parentheses). */
const PASS_THROUGH = new Set(['body_statement', 'block_body', 'then', 'else', 'elsif', 'if', 'unless', 'begin', 'parenthesized_statements', 'case', 'when', 'ensure', 'rescue']);

/** Callback / filter names and auth macros that guard a request (CSRF token checks and locale filters excluded). */
export const RB_AUTH_RE = /auth|login|logged_in|signed_in|sign_in|session|permi|rbac|acl|guard|admin|role|access|require_(?:user|account|member|owner|staff|api|token|login|valid)|current_user|jwt|token|verify_(?:user|token|api|jwt|access|signature|admin|authorized|policy)|policy|pundit|cancan|http_basic|http_digest|warden|signature|protected!|ensure_\w*(?:user|owner|admin|member)/i;
const NOT_AUTH_RE = /authenticity_token|forgery|csrf|set_locale|session_store/i;
export const isRbAuth = (s: string) => RB_AUTH_RE.test(s) && !NOT_AUTH_RE.test(s);
/** Bookkeeping callbacks that mention sessions / tokens / sign-ins without enforcing anything (`update_user_sign_in`, `set_session_activity`). */
const BOOKKEEPING_RE = /^(update|set|track|store|log|record|touch|clear|reset|save|refresh)_/;
/**
 * Whether a callback guards access: its name when it has one (bookkeeping names excluded), otherwise (a lambda / block
 * callback, an auth macro) the declaration text.
 */
export const isRbAuthCallback = (name: string, detail: string) => (name.startsWith('<') ? isRbAuth(detail) : !BOOKKEEPING_RE.test(name) && isRbAuth(name));
/** Calls inside a route block / endpoint that enforce authentication or authorization. */
const BLOCK_AUTH_RE = /\b(authenticate\w*!|authorize!?|authorized\?|protected!|require_(?:login|user|admin|auth\w*|signed_in\w*)!?|login_required!?|warden\.authenticate!?|policy_scope|halt\s*\(?\s*40[13]\b|error!\s*\([^)]*\b40[13]\b|current_user!|check_auth\w*!?|ensure_\w*(?:auth|login|user|admin)\w*!?)/;

export interface RubyClass { name: string; path: string; container: string; symbolId: string; node: Node; superclass: string | null; methods: Map<string, string> }

/** Constant path of a `constant` / `scope_resolution` node (`Admin::UsersController`); leading `::` dropped. */
export function constantPath(n: Node | null | undefined): string {
  return (n?.text ?? '').replace(/^::/, '').replace(/\s+/g, '');
}

/** Literal text of a string (without interpolation), symbol or bare identifier; null otherwise. */
function literal(n: Node | null | undefined): string | null {
  if (!n) return null;
  if (n.type === 'string') return named(n).every((c) => c.type === 'string_content' || c.type === 'escape_sequence') ? named(n).map((c) => c.text).join('') : null;
  if (n.type === 'simple_symbol') return n.text.replace(/^:/, '');
  if (n.type === 'hash_key_symbol' || n.type === 'identifier' || n.type === 'constant') return n.text;
  if (n.type === 'delimited_symbol') return n.text.replace(/^:["']|["']$/g, '');
  return null;
}
/** Names of an array / symbol array / single value (`[:a, :b]`, `%i[a b]`, `:a`). */
function namesOf(n: Node | null | undefined): string[] {
  if (!n) return [];
  if (n.type === 'array' || n.type === 'symbol_array' || n.type === 'string_array') return named(n).map((c) => literal(c) ?? c.text).filter(Boolean);
  const l = literal(n);
  return l ? [l] : [];
}

interface Args { pos: Node[]; kw: Map<string, Node>; block: Node | null }
function argsOf(call: Node): Args {
  const pos: Node[] = [];
  const kw = new Map<string, Node>();
  for (const a of named(call.childForFieldName('arguments'))) {
    if (a.type === 'pair') {
      const k = a.childForFieldName('key');
      const v = a.childForFieldName('value');
      const key = k ? literal(k) : null;
      if (key !== null && v && (k!.type === 'hash_key_symbol' || k!.type === 'simple_symbol')) kw.set(key, v);
      else pos.push(a); // `'path' => 'c#a'`
    } else if (a.type === 'hash') {
      for (const p of named(a)) { const k = p.childForFieldName('key'); const v = p.childForFieldName('value'); const key = k ? literal(k) : null; if (key !== null && v) kw.set(key, v); }
    } else if (a.type !== 'block_argument') pos.push(a);
  }
  return { pos, kw, block: call.childForFieldName('block') };
}
const blockBody = (block: Node | null | undefined): Node | null => block?.childForFieldName('body') ?? null;

type Taint = 'string_concat' | 'constant' | undefined;
/**
 * Interpolations that do not carry outside data: constants, table / column names, quoting and sanitizing helpers
 * (`"#{Message.table_name}.id < ?"`, `"#{connection.quote(x)}"`).
 */
const SAFE_INTERP_RE = /^(?:[A-Z][\w:]*|self\.class|self)(?:\.(?:table_name|quoted_table_name|primary_key|quoted_primary_key|name|model_name\.\w+))?$|(?:^|\.)(?:table_name|quoted_table_name|quote|quote_column_name|quote_table_name|quote_string|sanitize_sql\w*|sanitize_sql_like|sanitize|connection\.quote\w*)\b(?:\([^()]*\))?$|\.(?:to_i|to_f|size|count|length|id)$/;
const safeInterpolation = (i: Node) => { const inner = named(i); return inner.length === 1 && SAFE_INTERP_RE.test(inner[0]!.text.replace(/\s+/g, '')); };
/** Heredoc bodies of the file being extracted, in document order (a `heredoc_beginning` pairs with the next body). */
let heredocBodies: Node[] = [];
const heredocBody = (start: Node) => heredocBodies.find((b) => b.startIndex >= start.endIndex) ?? null;
function taintOf(n: Node | null | undefined, depth = 0): Taint {
  if (!n || depth > 6) return undefined;
  switch (n.type) {
    case 'string': case 'subshell': case 'regex': case 'heredoc_body': return named(n).some((c) => c.type === 'interpolation' && !safeInterpolation(c)) ? 'string_concat' : 'constant';
    case 'heredoc_beginning': return taintOf(heredocBody(n), depth + 1);
    case 'simple_symbol': case 'delimited_symbol': case 'integer': case 'float': case 'nil': case 'true': case 'false': case 'hash_key_symbol': case 'constant': case 'scope_resolution': return n.type === 'delimited_symbol' && named(n).some((c) => c.type === 'interpolation') ? 'string_concat' : 'constant';
    case 'array': case 'symbol_array': case 'string_array': case 'hash': case 'pair': case 'argument_list': {
      const ts = named(n).map((c) => taintOf(c, depth + 1));
      if (ts.includes('string_concat')) return 'string_concat';
      return ts.every((t) => t === 'constant') ? 'constant' : undefined;
    }
    case 'binary': {
      const op = n.childForFieldName('operator')?.text;
      const l = taintOf(n.childForFieldName('left'), depth + 1);
      const r = taintOf(n.childForFieldName('right'), depth + 1);
      if (l === 'constant' && r === 'constant') return 'constant';
      if ((op === '+' || op === '<<' || op === '%') && (n.childForFieldName('left')?.type === 'string' || n.childForFieldName('right')?.type === 'string' || l === 'string_concat' || r === 'string_concat')) return 'string_concat';
      return undefined;
    }
    case 'parenthesized_statements': return taintOf(named(n)[0], depth + 1);
    case 'call': {
      const m = n.childForFieldName('method')?.text ?? '';
      if (/^(join|format|sprintf|gsub|sub|concat)$/.test(m)) return 'string_concat';
      // String-preserving calls on a literal / heredoc (`<<~SQL.squish`, `"…".freeze`).
      if (/^(squish|strip|freeze|chomp|dup|to_s|lstrip|rstrip|downcase|upcase|html_safe)$/.test(m)) return taintOf(n.childForFieldName('receiver'), depth + 1);
      return undefined;
    }
    default: return undefined;
  }
}
const PARAMS_RE = /\b(params|request\.(?:params|query_parameters|request_parameters|body|raw_post|headers|referr?er|url|path|query_string|env)|cookies|declared\(params\)|env\[["']QUERY_STRING)\b/;

export function extractRuby(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const root = tree.rootNode;
  const repo = input.repo;
  fx.pkg = input.path;
  const ctx = input.langContext as RubyContext | undefined;
  heredocBodies = root.descendantsOfType('heredoc_body').filter((b): b is Node => !!b);
  const classes = new Map<number, RubyClass>();
  const classByQualified = new Map<string, RubyClass>();
  const methodIds = new Map<number, string>();
  const ids = new Set<string>();

  // ---- symbols ----
  const signature = (n: Node) => {
    const body = n.childForFieldName('body');
    return oneLine(body ? n.text.slice(0, body.startIndex - n.startIndex) : n.text.split('\n')[0]!, 300);
  };
  const arityOf = (method: Node): number => named(method.childForFieldName('parameters')).filter((p) => PARAM_TYPES.has(p.type)).length;
  const visit = (node: Node, ns: string[], cls: RubyClass | null) => {
    if (node.type === 'class' || node.type === 'module') {
      const path = constantPath(node.childForFieldName('name'));
      const parts = path.split('::');
      const name = parts.pop()!;
      const full = [...ns, ...parts];
      const namespace = full.length ? full.join('::') : input.path;
      const container = `${namespace}.${name}`;
      const symbolId = `${repo}:${input.path}#${container}`;
      const info: RubyClass = {
        name, path: [...full, name].join('::'), container, symbolId, node,
        superclass: node.type === 'class' ? constantPath(named(node.childForFieldName('superclass'))[0]) || null : null, methods: new Map(),
      };
      classes.set(node.id, info);
      if (!classByQualified.has(info.path)) classByQualified.set(info.path, info);
      ids.add(symbolId);
      fx.symbols.push({
        symbolId, repo, kind: node.type === 'module' ? 'interface' : 'class', name, container: namespace, path: input.path, range: rangeOf(node),
        signature: signature(node), qualifiedName: info.path,
      });
      for (const c of named(node)) visit(c, [...full, name], info);
      return;
    }
    if (node.type === 'method' || node.type === 'singleton_method') {
      const name = node.childForFieldName('name')?.text ?? '?';
      const arity = arityOf(node);
      const container = cls ? cls.container : input.path;
      const symbolId = `${repo}:${input.path}#${container}.${name}(${arity})`;
      methodIds.set(node.id, symbolId);
      ids.add(symbolId);
      if (cls && !cls.methods.has(name)) cls.methods.set(name, symbolId);
      fx.symbols.push({
        symbolId, repo, kind: cls ? 'method' : 'func', name, container, path: input.path, range: rangeOf(node),
        signature: signature(node), qualifiedName: cls ? `${cls.path}${node.type === 'singleton_method' ? '.' : '#'}${name}` : `${input.path}#${name}`,
      });
      for (const c of named(node)) visit(c, ns, cls);
      return;
    }
    for (const c of named(node)) visit(c, ns, cls);
  };
  visit(root, [], null);

  const enclosingMethod = (n: Node): Node | null => {
    for (let p = n.parent; p; p = p.parent) if (methodIds.has(p.id)) return p;
    return null;
  };
  const enclosingClass = (n: Node): RubyClass | null => {
    for (let p = n.parent; p; p = p.parent) { const c = classes.get(p.id); if (c) return c; }
    return null;
  };
  /** Calling symbol: the method or route block, else the class body (DSL calls such as `before_action`), else none (top-level script). */
  const enclosingSymbol = (n: Node): string | null => {
    const m = enclosingMethod(n);
    if (m) return methodIds.get(m.id) ?? null;
    return enclosingClass(n)?.symbolId ?? null;
  };

  // `require 'x'` names plus Gemfile gems: rule `requiresImportAny` and framework detection.
  const imports = new Set<string>(ctx?.gems ?? []);
  for (const call of root.descendantsOfType('call')) {
    const m = call?.childForFieldName('method')?.text;
    if (call && !call.childForFieldName('receiver') && (m === 'require' || m === 'require_relative')) {
      const v = literal(named(call.childForFieldName('arguments'))[0]);
      if (v) imports.add(v.split('/')[0]!);
    }
  }
  const chainOf = (q: string): string[] => {
    const out: string[] = [];
    const seen = new Set<string>();
    for (let cur: string | null = q; cur && !seen.has(cur) && out.length < 12;) {
      seen.add(cur);
      out.push(cur);
      cur = ctx?.classes[cur]?.superclass ?? (cur === q ? classByQualified.get(q)?.superclass ?? null : null);
    }
    return out;
  };

  const addAuth = (sig: AuthSignal) => { if (!fx.authSignals.some((s) => s.target === sig.target && s.detail === sig.detail)) fx.authSignals.push(sig); };
  /** Synthetic symbol for a route block (Sinatra, Grape) so calls inside have a caller. */
  const blockSymbol = (block: Node | null, label: string, cls: RubyClass | null, at: Node): string | null => {
    if (!block) return null;
    const hit = methodIds.get(block.id);
    if (hit) return hit;
    const container = cls ? cls.container : input.path;
    const arity = named(block.childForFieldName('parameters')).length;
    let name = `<${label}>`;
    let symbolId = `${repo}:${input.path}#${container}.${name}(${arity})`;
    for (let i = 2; ids.has(symbolId); i++) { name = `<${label} #${i}>`; symbolId = `${repo}:${input.path}#${container}.${name}(${arity})`; }
    ids.add(symbolId);
    methodIds.set(block.id, symbolId);
    fx.symbols.push({ symbolId, repo, kind: cls ? 'method' : 'func', name, container, path: input.path, range: rangeOf(at), signature: oneLine(at.text.split('\n')[0]!, 300), qualifiedName: cls ? `${cls.path}#${name}` : `${input.path}#${name}` });
    return symbolId;
  };
  const pushEntry = (ruleId: string, framework: string, method: string, path: string, handler: HandlerRef, at: Node, middlewares: string[], authSignals: string[]) => {
    const e: RawEntry = { ruleId, framework, httpMethod: method, pathTemplate: path || '/', handler, path: input.path, range: rangeOf(at), middlewares: [...new Set(middlewares)], authSignals: [...new Set(authSignals)] };
    fx.entries.push(e);
  };
  const blockAuth = (block: Node | null): string[] => {
    if (!block) return [];
    const out: string[] = [];
    for (const m of block.text.matchAll(new RegExp(BLOCK_AUTH_RE.source, 'g'))) { const t = oneLine(m[1]!, 80); if (!out.includes(t) && out.length < 3) out.push(t); }
    return out;
  };

  // ======================= Rails routes (config/routes.rb, config/routes/*.rb) =======================
  function railsRoutes(ruleId: string): void {
    if (!RB_ROUTES_RE.test(input.path)) return;
    const classesCtx = ctx?.classes ?? {};
    interface Res { controller: string; collection: string; member: string; nested: string; param: string; singular: boolean }
    interface Scope { path: string; shallowPath: string; module: string[]; controller?: string; auth: string[]; res?: Res; on?: 'member' | 'collection' | 'new'; shallow: boolean }
    const concerns = new Map<string, Node>();
    const camel = (s: string) => s.split('_').map((w) => (w ? w[0]!.toUpperCase() + w.slice(1) : w)).join('');
    const controllerQ = (ctrl: string, mod: string[]): string => {
      const segs = ctrl.startsWith('/') ? ctrl.slice(1).split('/') : [...mod, ...ctrl.split('/')];
      const q = segs.map(camel).join('::') + 'Controller';
      return classesCtx[q] ? q : byLower.get(q.toLowerCase()) ?? q;
    };
    const cleanPath = (p: string) => p.replace(/\([^()]*\)/g, '').replace(/\([^()]*\)/g, '');
    const emit = (verbs: string[], path: string, ctrl: string, action: string, at: Node, scope: Scope) => {
      const q = controllerQ(ctrl, ctrl.startsWith('/') ? [] : scope.module);
      // Handler: the action on the controller or an ancestor; the controller class when the action is implicit (template only).
      const qualified: string[] = [];
      for (const anc of chainOfCtx(q)) qualified.push(`${anc}#${action}`);
      qualified.push(q);
      const filters = effectiveFilters(q, action, classesCtx);
      const definer = chainOfCtx(q).map((c) => classesCtx[c]).find((c) => c?.actions.includes(action));
      const auth = [...scope.auth, ...filters.filter((f) => isRbAuthCallback(f.name, f.detail)).map((f) => f.detail), ...(definer?.methodAuth[action] ?? []).map((a) => `${a} (in action)`)];
      for (const v of verbs) pushEntry(ruleId, 'rails', v, cleanPath(path) || '/', { qualified, text: `${q}#${action}`, range: rangeOf(at) }, at, filters.map((f) => f.name), auth);
    };
    const chainOfCtx = (q: string): string[] => {
      const out: string[] = [];
      const seen = new Set<string>();
      for (let cur: string | undefined = q; cur && !seen.has(cur) && out.length < 12; cur = classesCtx[cur]?.superclass ?? undefined) { seen.add(cur); out.push(cur); }
      return out;
    };
    const target = (v: Node | undefined): { ctrl?: string; action?: string } | null => {
      const t = literal(v);
      if (t === null) return null;
      const [c, a] = t.split('#');
      return a !== undefined ? { ctrl: c!, action: a } : { action: c! };
    };
    const verbsOf = (via: Node | undefined, method: string): string[] => {
      if (method !== 'match') return [VERBS[method]!];
      const vs = namesOf(via).map((x) => x.toUpperCase());
      return !vs.length || vs.includes('ALL') ? ['ANY'] : vs;
    };
    // Common English inflections (ActiveSupport defaults); irregular words fall back to the plain rules.
    const singular = (s: string) => (/ies$/.test(s) ? s.slice(0, -3) + 'y' : /(ss|us|is)$/.test(s) ? s : /(x|ch|sh|ss|us)es$/.test(s) ? s.slice(0, -2) : /s$/.test(s) ? s.slice(0, -1) : s);
    const plural = (s: string) => (/(ss|us|x|ch|sh)$/.test(s) ? s + 'es' : /s$/.test(s) ? s : /[^aeiou]y$/.test(s) ? s.slice(0, -1) + 'ies' : s + 's');
    // Acronym inflections (`ActivityPub`, `OAuth`, `API`) differ from plain camel case: match declared controllers ignoring case.
    const byLower = new Map(Object.keys(classesCtx).map((q) => [q.toLowerCase(), q]));

    const route = (call: Node, method: string, a: Args, scope: Scope) => {
      const first = a.pos[0];
      let path: string | null = null;
      let tgt: { ctrl?: string; action?: string } | null = null;
      if (first?.type === 'pair') { path = literal(first.childForFieldName('key')); tgt = target(first.childForFieldName('value') ?? undefined); if (!tgt) return; }
      else if (first) { path = literal(first); if (path === null) return; }
      else if (method !== 'root') return;
      const to = a.kw.get('to');
      if (to) { tgt = target(to); if (!tgt) return; } // `to: redirect(…)` / a Rack app: not a controller action
      const on = (literal(a.kw.get('on')) as Scope['on'] | null) ?? scope.on;
      const isSym = first?.type === 'simple_symbol';
      let ctrl = tgt?.ctrl ?? literal(a.kw.get('controller')) ?? scope.controller ?? scope.res?.controller;
      let action = tgt?.action ?? literal(a.kw.get('action')) ?? null;
      let full: string;
      if (scope.res && (isSym || (!tgt?.ctrl && path !== null && !path.includes('/')))) {
        // `post :publish` inside resources / member / collection
        action ??= path ?? '';
        const base = on === 'member' ? scope.res.member : on === 'collection' ? scope.res.collection : on === 'new' ? joinPath(scope.res.collection, 'new') : scope.res.nested;
        full = joinPath(base, path ?? '');
        ctrl ??= scope.res.controller;
      } else {
        full = method === 'root' ? (scope.path || '/') : joinPath(scope.path, path ?? '');
        if (!action && !ctrl && path && /^\/?[\w-]+\/[\w-]+$/.test(path)) { const [c, x] = path.replace(/^\//, '').split('/'); ctrl = c!; action = x!; }
        if (!action && path && ctrl) action = path.split('/').pop()!.replace(/^:/, '');
      }
      if (method === 'root' && !tgt) { const t = target(a.pos[0]); if (t?.ctrl) { ctrl = t.ctrl; action = t.action ?? null; } }
      if (!ctrl || !action) return;
      emit(method === 'root' ? ['GET'] : verbsOf(a.kw.get('via'), method), full, ctrl, action, call, scope);
    };

    const resources = (call: Node, singularRes: boolean, a: Args, scope: Scope) => {
      const names = a.pos.map((n) => literal(n)).filter((n): n is string => !!n);
      const only = a.kw.has('only') ? namesOf(a.kw.get('only')) : null;
      const except = namesOf(a.kw.get('except'));
      const shallow = scope.shallow || a.kw.get('shallow')?.type === 'true';
      for (const name of names) {
        const seg = literal(a.kw.get('path')) ?? name;
        const ctrlName = literal(a.kw.get('controller')) ?? (singularRes ? plural(name) : name);
        const mod = literal(a.kw.get('module'));
        const resScope: Scope = { ...scope, module: mod ? [...scope.module, ...mod.split('/')] : scope.module };
        const param = literal(a.kw.get('param')) ?? 'id';
        const collection = joinPath(scope.path, seg);
        const member = singularRes ? collection : joinPath(shallow ? joinPath(scope.shallowPath, seg) : collection, `:${param}`);
        const nested = singularRes ? collection : joinPath(collection, `:${singular(name)}_${param}`);
        const actions: [string, string[], string][] = singularRes
          ? [['show', ['GET'], member], ['new', ['GET'], joinPath(collection, 'new')], ['create', ['POST'], collection], ['edit', ['GET'], joinPath(member, 'edit')], ['update', ['PATCH', 'PUT'], member], ['destroy', ['DELETE'], member]]
          : [['index', ['GET'], collection], ['new', ['GET'], joinPath(collection, 'new')], ['create', ['POST'], collection], ['show', ['GET'], member], ['edit', ['GET'], joinPath(member, 'edit')], ['update', ['PATCH', 'PUT'], member], ['destroy', ['DELETE'], member]];
        for (const [act, verbs, p] of actions) {
          if (only && !only.includes(act)) continue;
          if (except.includes(act)) continue;
          emit(verbs, p, ctrlName, act, call, resScope);
        }
        const inner: Scope = { ...resScope, path: nested, shallowPath: shallow ? scope.shallowPath : nested, shallow, res: { controller: ctrlName, collection, member, nested, param, singular: singularRes } };
        delete inner.on;
        for (const c of namesOf(a.kw.get('concerns'))) { const body = concerns.get(c); if (body) walk(body, inner); }
        if (a.block) walk(blockBody(a.block), inner);
      }
    };

    const walk = (body: Node | null, scope: Scope): void => {
      if (!body) return;
      for (const n of named(body)) {
        if (n.type !== 'call') { if (PASS_THROUGH.has(n.type)) walk(n, scope); continue; }
        if (n.childForFieldName('receiver')) {
          // `Rails.application.routes.draw do … end` (and engine routes)
          if (n.childForFieldName('method')?.text === 'draw' && n.childForFieldName('block')) walk(blockBody(n.childForFieldName('block')), scope);
          continue;
        }
        const m = n.childForFieldName('method')?.text ?? '';
        const a = argsOf(n);
        switch (m) {
          case 'get': case 'post': case 'put': case 'patch': case 'delete': case 'options': case 'head': case 'match': case 'root':
            route(n, m, a, scope);
            break;
          case 'resources': case 'resource':
            resources(n, m === 'resource', a, scope);
            break;
          case 'namespace': {
            const name = literal(a.pos[0]);
            if (!name) break;
            const p = literal(a.kw.get('path')) ?? name;
            const modKw = a.kw.get('module');
            const mod = modKw ? (modKw.type === 'nil' || modKw.type === 'false' ? null : literal(modKw)) : name;
            walk(blockBody(a.block), { ...scope, path: joinPath(scope.path, p), shallowPath: joinPath(scope.shallowPath, p), module: mod ? [...scope.module, ...mod.split('/')] : scope.module });
            break;
          }
          case 'scope': {
            const p = literal(a.pos[0]) ?? literal(a.kw.get('path')) ?? '';
            const mod = literal(a.kw.get('module'));
            const ctrl = literal(a.kw.get('controller'));
            walk(blockBody(a.block), { ...scope, path: joinPath(scope.path, p), shallowPath: joinPath(scope.shallowPath, p), module: mod ? [...scope.module, ...mod.split('/')] : scope.module, ...(ctrl ? { controller: ctrl } : {}) });
            break;
          }
          case 'controller': {
            const ctrl = literal(a.pos[0]);
            if (ctrl) walk(blockBody(a.block), { ...scope, controller: ctrl });
            break;
          }
          case 'member': case 'collection': case 'new':
            if (scope.res) walk(blockBody(a.block), { ...scope, on: m });
            break;
          case 'concern': {
            const name = literal(a.pos[0]);
            const body = blockBody(a.block);
            if (name && body) concerns.set(name, body);
            break;
          }
          case 'concerns':
            for (const c of a.pos.flatMap((x) => namesOf(x))) { const body = concerns.get(c); if (body) walk(body, scope); }
            break;
          case 'authenticate': case 'authenticated': case 'authenticate_user': {
            const what = oneLine(`${m} ${a.pos.map((x) => x.text).join(', ')}`, 120);
            walk(blockBody(a.block), { ...scope, auth: [...scope.auth, `routes: ${what}`] });
            break;
          }
          case 'constraints': {
            const text = oneLine(a.pos.map((x) => x.text).join(', '), 120);
            walk(blockBody(a.block), { ...scope, auth: isRbAuth(text) ? [...scope.auth, `routes: constraints ${text}`] : scope.auth });
            break;
          }
          case 'draw': case 'mount': case 'devise_for': case 'direct': case 'resolve': case 'use_doorkeeper':
            break;
          default:
            // `defaults … do`, `with_options … do`, `devise_scope :user do`, `scope` helpers of gems: same scope.
            if (a.block) walk(blockBody(a.block), scope);
        }
      }
    };
    walk(root, { path: '', shallowPath: '', module: [], auth: [], shallow: false });
  }

  // ======================= Sinatra =======================
  const SINATRA_BASE_RE = /^(Sinatra::(Base|Application)|Padrino::Application)$/;
  function sinatraRoutes(ruleId: string): void {
    const scopes: { body: Node; cls: RubyClass | null }[] = [];
    // Classic style: `require 'sinatra'` and routes at the top level.
    if (/require\s*\(?\s*['"]sinatra['"]/.test(input.text)) scopes.push({ body: root, cls: null });
    for (const c of classes.values()) {
      if (c.node.type === 'class' && chainOf(c.path).some((n) => SINATRA_BASE_RE.test(n))) {
        const body = c.node.childForFieldName('body');
        if (body) scopes.push({ body, cls: c });
      }
    }
    for (const { body, cls } of scopes) {
      const bases = (cls && ctx?.mountBases[cls.path]) || [''];
      // Class-wide auth: `use Rack::Auth::Basic`, `use Warden::Manager`, `register Sinatra::Auth…`, `before do authenticate! end`.
      const classAuth: string[] = [];
      const filters: { pattern: RegExp | null; auth: string[] }[] = [];
      const collect = (n: Node | null, prefix: string) => {
        for (const s of named(n)) {
          if (s.type !== 'call' || s.childForFieldName('receiver')) { if (PASS_THROUGH.has(s.type)) collect(s, prefix); continue; }
          const m = s.childForFieldName('method')?.text ?? '';
          const a = argsOf(s);
          if ((m === 'use' || m === 'register') && isRbAuth(a.pos.map((x) => x.text).join(' '))) classAuth.push(oneLine(s.text, 120));
          else if (m === 'before') {
            const auth = blockAuth(a.block);
            const pat = literal(a.pos[0]);
            if (auth.length) filters.push({ pattern: pat ? new RegExp('^' + joinPath(prefix, pat).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$') : null, auth: auth.map((x) => `before${pat ? ` '${pat}'` : ''}: ${x}`) });
          } else if (m === 'namespace' && a.block) collect(blockBody(a.block), joinPath(prefix, literal(a.pos[0]) ?? ''));
        }
      };
      collect(body, '');
      const walk = (n: Node | null, prefix: string) => {
        for (const s of named(n)) {
          if (s.type !== 'call' || s.childForFieldName('receiver')) { if (PASS_THROUGH.has(s.type)) walk(s, prefix); continue; }
          const m = s.childForFieldName('method')?.text ?? '';
          const a = argsOf(s);
          if (m === 'namespace' && a.block) { walk(blockBody(a.block), joinPath(prefix, literal(a.pos[0]) ?? '')); continue; }
          const verb = VERBS[m];
          if (!verb || !a.block || !a.pos[0]) continue;
          const p0 = a.pos[0];
          // Regexp routes keep their pattern (`%r{/files/(\w+)}` → `/files/(\w+)`).
          const rel = p0.type === 'regex' ? named(p0).map((c) => c.text).join('') : literal(p0);
          if (rel === null) continue;
          const local = joinPath(prefix, rel);
          const conds = [...a.kw.entries()].filter(([k, v]) => isRbAuth(k) || isRbAuth(v.text)).map(([k, v]) => `${k}: ${oneLine(v.text, 60)}`);
          const fromFilters = filters.filter((f) => !f.pattern || f.pattern.test(local)).flatMap((f) => f.auth);
          const sym = blockSymbol(a.block, `${verb} ${local || '/'}`, cls, s);
          for (const b of bases) {
            pushEntry(ruleId, 'sinatra', verb, joinPath(b, local), { ...(sym ? { symbolId: sym } : {}), range: rangeOf(s) }, s, [...classAuth], [...classAuth, ...fromFilters, ...conds, ...blockAuth(a.block)]);
          }
        }
      };
      walk(body, '');
    }
  }

  // ======================= Grape =======================
  function grapeApis(ruleId: string): void {
    for (const c of classes.values()) {
      if (c.node.type !== 'class') continue;
      if (!chainOf(c.path).some((n) => /^Grape::API(::Instance)?$/.test(n))) continue;
      const body = c.node.childForFieldName('body');
      if (!body) continue;
      let prefix = '';
      let version = '';
      for (const s of named(body)) {
        if (s.type !== 'call' || s.childForFieldName('receiver')) continue;
        const m = s.childForFieldName('method')?.text;
        const a = argsOf(s);
        if (m === 'prefix') prefix = literal(a.pos[0]) ?? prefix;
        if (m === 'version') { const using = literal(a.kw.get('using')); if (!using || using === 'path') version = literal(a.pos[0]) ?? (a.pos[0]?.type === 'array' ? namesOf(a.pos[0])[0] ?? '' : ''); }
      }
      const bases = (ctx?.mountBases[c.path] ?? ['']).map((b) => joinPath(joinPath(b, prefix), version));
      const walk = (n: Node | null, path: string, auth: string[]) => {
        // Callbacks / auth helpers of this scope apply to its endpoints and nested namespaces.
        const scopeAuth = [...auth];
        for (const s of named(n)) {
          if (s.type !== 'call' || s.childForFieldName('receiver')) continue;
          const m = s.childForFieldName('method')?.text ?? '';
          const a = argsOf(s);
          if (m === 'before' || m === 'before_validation') for (const x of blockAuth(a.block)) scopeAuth.push(`${m}: ${x}`);
          if (m === 'http_basic' || m === 'http_digest' || m === 'auth') scopeAuth.push(oneLine(`${m} ${a.pos.map((x) => x.text).join(', ')}`, 120));
          if (m === 'use' && isRbAuth(a.pos.map((x) => x.text).join(' '))) scopeAuth.push(oneLine(s.text, 120));
        }
        for (const s of named(n)) {
          if (s.type !== 'call' || s.childForFieldName('receiver')) { if (PASS_THROUGH.has(s.type)) walk(s, path, scopeAuth); continue; }
          const m = s.childForFieldName('method')?.text ?? '';
          const a = argsOf(s);
          if (/^(namespace|resource|resources|group|segment)$/.test(m) && a.block) { walk(blockBody(a.block), joinPath(path, literal(a.pos[0]) ?? ''), scopeAuth); continue; }
          if (m === 'route_param' && a.block) { const p = literal(a.pos[0]); walk(blockBody(a.block), p ? joinPath(path, `:${p}`) : path, scopeAuth); continue; }
          let verbs: string[] = [];
          let rel: string | null = null;
          if (VERBS[m] && a.block) { verbs = [VERBS[m]!]; rel = a.pos[0] ? literal(a.pos[0]) : ''; }
          else if (m === 'route' && a.block) {
            const v = a.pos[0];
            verbs = v?.type === 'simple_symbol' && v.text === ':any' ? ['ANY'] : namesOf(v).map((x) => x.toUpperCase());
            rel = a.pos[1] ? literal(a.pos[1]) : '';
          }
          if (!verbs.length || rel === null) continue;
          const local = joinPath(path, rel);
          const sym = blockSymbol(a.block, `${verbs.join(',')} ${local || '/'}`, c, s);
          for (const b of bases) for (const v of verbs) pushEntry(ruleId, 'grape', v, joinPath(b, local), { ...(sym ? { symbolId: sym } : {}), range: rangeOf(s) }, s, [], [...scopeAuth, ...blockAuth(a.block)]);
        }
      };
      walk(body, '', []);
    }
  }


  // ======================= non-HTTP entries =======================
  const camelRpc = (name: string) => name.split('_').map((w) => (w ? w[0]!.toUpperCase() + w.slice(1) : w)).join('');
  const pushChannel = (ruleId: string, framework: string, channel: NonNullable<RawEntry['channel']>, ref: HandlerRef, at: Node, auth: string[] = []) => {
    fx.entries.push({ channel, ruleId, framework, httpMethod: '', pathTemplate: '', handler: ref, path: input.path, range: rangeOf(at), middlewares: [], authSignals: auth });
  };
  const includesOf = (q: string): string[] => chainOf(q).flatMap((x) => ctx?.classes[x]?.includes ?? []);
  function channelEntries(ruleId: string): void {
    for (const c of classes.values()) {
      if (c.node.type !== 'class') continue;
      const body = c.node.childForFieldName('body');
      const bodyText = body?.text ?? '';
      const chain = chainOf(c.path);
      // gRPC services: `class GreeterServer < Helloworld::Greeter::Service` (grpc gem), methods `say_hello(req, call)`.
      const g = /^(?:::)?(?:\w+::)*(\w+)::Service$/.exec(c.superclass ?? '');
      if (g) {
        const hasProto = !!input.grpcServices?.some((x) => x.name === g[1]);
        for (const [name, id] of c.methods) {
          if (name === 'initialize' || name.startsWith('_')) continue;
          const rpc = rpcOf(input.grpcServices, g[1]!, camelRpc(name));
          if (!rpc || (!hasProto && !/\(\d+\)$/.test(id))) continue;
          fx.entries.push({ rpc, ruleId, framework: 'grpc', httpMethod: 'RPC', pathTemplate: '', handler: { symbolId: id }, path: input.path, range: rangeOf(c.node), middlewares: [], authSignals: [] });
        }
      }
      // Background jobs: Sidekiq (`include Sidekiq::Job` / `Sidekiq::Worker`), ActiveJob (`< ApplicationJob`), Resque (`@queue`).
      const perform = c.methods.get('perform');
      if (!perform) continue;
      const incs = [...includesOf(c.path), ...[...bodyText.matchAll(/^\s*include\s+([\w:]+)/gm)].map((m) => m[1]!)];
      const protocol = incs.some((i) => /(^|::)Sidekiq::(Job|Worker)$/.test(i)) ? 'sidekiq'
        : chain.some((x) => /^(ActiveJob::Base|ApplicationJob)$/.test(x)) ? 'activejob'
          : /^\s*@queue\s*=/m.test(bodyText) ? 'resque'
            : incs.some((i) => /(^|::)Shoryuken::Worker$/.test(i)) ? 'shoryuken' : incs.some((i) => /(^|::)Sneakers::Worker$/.test(i)) ? 'sneakers' : null;
      if (!protocol) continue;
      const queue = /(?:sidekiq_options\b[^\n]*\bqueue:|queue_as\s*\(?|@queue\s*=|shoryuken_options\b[^\n]*\bqueue:|from_queue\s*\(?)\s*[:'"]?([\w.-]+)/.exec(bodyText)?.[1] ?? 'default';
      pushChannel(ruleId, protocol, { kind: 'message', protocol, key: `mq:${protocol}:${c.path}`, route: queue }, { symbolId: perform }, c.node);
      for (const cron of ctx?.schedules?.[c.path] ?? []) pushChannel(ruleId, protocol, { kind: 'schedule', protocol: 'cron', key: `cron:${c.path}`, route: cron }, { symbolId: perform }, c.node);
    }
    // whenever (config/schedule.rb): `every 1.day, at: '4:30 am' do runner "Report.generate"; rake "db:clean"; command "…" end`
    if (/(^|\/)config\/schedule\.rb$/.test(input.path)) {
      for (const call of root.descendantsOfType('call')) {
        if (!call || call.childForFieldName('method')?.text !== 'every' || call.childForFieldName('receiver')) continue;
        const a = argsOf(call);
        const when = oneLine(call.childForFieldName('arguments')?.text ?? '', 80);
        for (const s2 of named(blockBody(a.block))) {
          if (s2.type !== 'call' || s2.childForFieldName('receiver')) continue;
          const kind = s2.childForFieldName('method')?.text ?? '';
          const what = literal(named(s2.childForFieldName('arguments'))[0]);
          if (!what || !/^(runner|rake|command|script)$/.test(kind)) continue;
          const m = /^([A-Z][\w:]*)\.(\w+[!?]?)/.exec(what);
          const ref: HandlerRef = kind === 'runner' && m ? { text: m[2]!, className: m[1]!.split('::').pop()! } : { text: `${kind} ${what}` };
          pushChannel(ruleId, 'whenever', { kind: 'schedule', protocol: 'cron', key: `cron:${kind === 'runner' ? what : `${kind} ${what}`}`, route: when }, ref, s2);
        }
      }
    }
    // Rake tasks (`.rake`, Rakefile): `namespace :db do task seed: :environment do … end end` → command-line entries.
    if (/(\.rake|(^|\/)Rakefile)$/.test(input.path)) {
      const walk = (n: Node | null, ns: string[]) => {
        for (const s2 of named(n)) {
          if (s2.type !== 'call' || s2.childForFieldName('receiver')) { if (PASS_THROUGH.has(s2.type)) walk(s2, ns); continue; }
          const m = s2.childForFieldName('method')?.text;
          const a = argsOf(s2);
          if (m === 'namespace') { const name = literal(a.pos[0]); if (name) walk(blockBody(a.block), [...ns, name]); continue; }
          if (m !== 'task' || !a.block) continue;
          const first = a.pos[0];
          const name = first?.type === 'pair' ? literal(first.childForFieldName('key')) : literal(first) ?? (a.kw.size ? [...a.kw.keys()][0]! : null);
          if (!name) continue;
          const full = [...ns, name].join(':');
          const sym = blockSymbol(a.block, `rake ${full}`, null, s2);
          pushChannel(ruleId, 'rake', { kind: 'cli', protocol: 'cli', key: `cli:rake ${full}`, route: `rake ${full}` }, { ...(sym ? { symbolId: sym } : {}), range: rangeOf(s2) }, s2);
        }
      };
      walk(root, []);
    }
  }

  // ======================= Rails controllers: callbacks and authorization calls =======================
  function controllerSignals(ruleId: string): void {
    for (const c of classes.values()) {
      const facts: RbClassFacts | undefined = ctx?.classes[c.path];
      if (!facts) continue;
      const isController = /Controller$/.test(c.path) || chainOf(c.path).some((q) => /Controller(::Base|::API)?$/.test(q) || /Controller(::Base|::API)?$/.test(ctx?.classes[q]?.superclass ?? ''));
      if (!isController) continue;
      for (const f of facts.filters) if (f.kind === 'before' && f.names.some((n) => isRbAuthCallback(n, f.text))) addAuth({ target: c.symbolId, kind: 'filter', detail: f.text, ruleId });
      for (const [name, id] of c.methods) {
        const eff = effectiveFilters(c.path, name, ctx?.classes ?? {});
        for (const f of eff) if (isRbAuthCallback(f.name, f.detail)) addAuth({ target: id, kind: 'filter', detail: f.detail, ruleId });
      }
    }
  }

  // ---- rules: entries first (route blocks become symbols), then auth signals and sinks ----
  const seenSinks = new Set<string>();
  const ran = new Set<string>();
  const ordered = [...rules].sort((x, y) => (x.rule.kind === 'entrypoint' ? 0 : 1) - (y.rule.kind === 'entrypoint' ? 0 : 1));
  for (const { rule, query, error } of ordered) {
    if (error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${error}` }); continue; }
    if (!query) continue;
    if (rule.match?.requiresImportAny && !rule.match.requiresImportAny.some((i) => imports.has(i))) continue;
    try {
      if (rule.post === 'ruby_rails_routes' || rule.post === 'ruby_sinatra_routes' || rule.post === 'ruby_grape_api' || rule.post === 'ruby_rails_filters' || rule.post === 'ruby_channels') {
        if (ran.has(rule.post)) continue;
        ran.add(rule.post);
        if (!query.matches(root).length) continue;
        if (rule.post === 'ruby_rails_routes') railsRoutes(rule.id);
        else if (rule.post === 'ruby_sinatra_routes') sinatraRoutes(rule.id);
        else if (rule.post === 'ruby_grape_api') grapeApis(rule.id);
        else if (rule.post === 'ruby_channels') channelEntries(rule.id);
        else controllerSignals(rule.id);
        continue;
      }
      for (const match of query.matches(root)) {
        const cap = new Map<string, Node>();
        for (const c of match.captures) if (!cap.has(c.name)) cap.set(c.name, c.node);
        const node = cap.get('call');
        if (!node) continue;
        if (rule.kind === 'auth_signal') {
          const target = enclosingSymbol(node);
          if (target) addAuth({ target, kind: 'security_config', detail: oneLine(node.text, 160), ruleId: rule.id });
          continue;
        }
        if (rule.kind !== 'sink') continue;
        const receiver = cap.get('receiver') ?? null;
        const method = cap.get('method')?.text ?? '';
        const a = node.type === 'call' ? argsOf(node) : { pos: [], kw: new Map<string, Node>(), block: null };
        const receiverType = receiver && (receiver.type === 'constant' || receiver.type === 'scope_resolution') ? constantPath(receiver).split('::').pop()! : null;
        if (!ruleMatches(rule.match, { receiverText: receiver?.text ?? null, receiverType, receiverImport: null, imports, argCount: a.pos.length + a.kw.size })) continue;
        const verdict = sinkPost(rule.post, { method, receiver, a, node });
        if (!verdict) continue;
        const api = fillApi(rule.api ?? '', { method, receiver: receiver ? oneLine(receiver.text, 80) : '', module: receiver ? oneLine(receiver.text, 80) : '', type: receiverType ?? '' });
        const taint = rule.category === 'authz_object' || rule.category === 'business_logic' || rule.category === 'csrf' ? undefined : node.type === 'subshell' ? taintOf(node) : verdict === true ? taintOf(a.pos[0] ?? [...a.kw.values()][0] ?? receiver) : verdict;
        const sink = makeSink(repo, input.path, rule, node, enclosingSymbol(node), oneLine(api, 200), taint);
        // Chained calls (`Post.where(…).order(params[:s])`) start where the chain starts: identify them by the method name.
        const mNode = cap.get('method');
        if (receiver && mNode) sink.sinkId = `${repo}:${input.path}#L${mNode.startPosition.row + 1}:${mNode.startPosition.column + 1}:${sink.category}`;
        if (!seenSinks.has(sink.sinkId)) { seenSinks.add(sink.sinkId); fx.sinks.push(sink); }
      }
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${(e as Error).message}` });
    }
  }

  // ---- calls ----
  // `Foo.bar` → receiver type Foo (class method); `Foo.new.bar` → Foo; `self.x` / bare `x(…)` → the enclosing class.
  const typeOf = (recv: Node | null): string | null => {
    if (!recv) return null;
    if (recv.type === 'constant' || recv.type === 'scope_resolution') return constantPath(recv).split('::').pop() ?? null;
    if (recv.type === 'call' && recv.childForFieldName('method')?.text === 'new') return typeOf(recv.childForFieldName('receiver'));
    return null;
  };
  for (const call of root.descendantsOfType('call')) {
    if (!call) continue;
    const from = enclosingSymbol(call);
    const method = call.childForFieldName('method')?.text;
    if (!from || !method) continue;
    const recv = call.childForFieldName('receiver');
    const args = call.childForFieldName('arguments');
    const arity = named(args).filter((a) => a.type !== 'block_argument').length;
    fx.calls.push({
      from, method, receiverText: recv ? (recv.type === 'self' ? 'self' : oneLine(recv.text, 200)) : null,
      receiverType: recv?.type === 'self' ? null : typeOf(recv), receiverImport: null, arity, line: call.startPosition.row + 1,
      calleeText: oneLine(recv ? `${recv.text}.${method}` : method, 200),
    });
  }
  // Bare identifiers used as statements (`load_post` in an action) are calls of methods without arguments,
  // unless the method assigns a local of that name.
  const localsOf = new Map<number, Set<string>>();
  for (const id of root.descendantsOfType('identifier')) {
    if (!id || !id.parent || !(id.parent.type === 'body_statement' || id.parent.type === 'block_body' || id.parent.type === 'then' || id.parent.type === 'else')) continue;
    const m = enclosingMethod(id);
    if (!m) continue;
    const from = methodIds.get(m.id)!;
    let locals = localsOf.get(m.id);
    if (!locals) {
      locals = new Set<string>();
      for (const asg of m.descendantsOfType(['assignment', 'operator_assignment'])) { const l = asg?.childForFieldName('left'); if (l?.type === 'identifier') locals.add(l.text); }
      for (const ps of [m.childForFieldName('parameters'), ...m.descendantsOfType(['block_parameters', 'method_parameters', 'lambda_parameters'])]) {
        for (const p of named(ps)) locals.add((p.childForFieldName('name') ?? p).text);
      }
      localsOf.set(m.id, locals);
    }
    if (locals.has(id.text)) continue;
    fx.calls.push({ from, method: id.text, receiverText: null, receiverType: null, receiverImport: null, arity: 0, line: id.startPosition.row + 1, calleeText: id.text });
  }
  return fx;
}

/** Post filters of Ruby sink rules; `true` keeps the sink with the first argument's taint, a Taint value overrides it. */
function sinkPost(post: string | undefined, s: { method: string; receiver: Node | null; a: Args; node: Node }): boolean | Taint {
  const first = s.a.pos[0];
  const nonConst = (n: Node | null | undefined) => !!n && taintOf(n) !== 'constant';
  const fromRequest = (n: Node | null | undefined) => !!n && PARAMS_RE.test(n.text);
  switch (post) {
    case undefined: return true;
    case 'ruby_nonconst': return nonConst(first);
    case 'ruby_subshell': return named(s.node).some((c) => c.type === 'interpolation');
    case 'ruby_sql': {
      // ActiveRecord string conditions: interpolated / concatenated strings, request values, SQL-named variables.
      if (!first) return false;
      if (first.type === 'hash' || first.type === 'pair' || first.type === 'simple_symbol' || first.type === 'symbol_array') return false;
      if (first.type === 'array') { const f0 = named(first)[0]; return !!f0 && taintOf(f0) === 'string_concat' ? 'string_concat' : false; }
      const t = taintOf(first);
      if (t === 'string_concat') return 'string_concat';
      if (t === 'constant') return false;
      if (/^(order|reorder|group|pluck|select|from|joins|having|lock|calculate|pick|distinct_on|in_order_of)$/.test(s.method)) return fromRequest(first) || ((first.type === 'identifier' || first.type === 'instance_variable') && /(sort|order|direction)/i.test(first.text));
      return fromRequest(first) || /^(sql|query|conditions?|clause|where_clause|filter)\b|_sql$|_(conditions?|clause)$/i.test(first.text);
    }
    case 'ruby_raw_sql': {
      if (!nonConst(first)) return false;
      return !(first!.type === 'call' && /^(sanitize_sql\w*|quote\w*)$/.test(first!.childForFieldName('method')?.text ?? ''));
    }
    case 'ruby_redirect': {
      if (!first || first.type === 'simple_symbol') return false;
      if (first.type === 'call' && /_(path|url)$/.test(first.childForFieldName('method')?.text ?? '')) return false;
      if (first.type === 'identifier' && /_(path|url)$/.test(first.text)) return false;
      return fromRequest(first) || (first.type === 'string' && taintOf(first) === 'string_concat' && fromRequest(first));
    }
    case 'ruby_render_inline': { const v = s.a.kw.get('inline'); return !!v && nonConst(v) ? (taintOf(v) ?? true) : false; }
    case 'ruby_render_file': {
      const v = s.a.kw.get('file') ?? s.a.kw.get('template');
      if (v) return nonConst(v) && (fromRequest(v) || taintOf(v) === 'string_concat') ? (taintOf(v) ?? true) : false;
      return !!first && first.type !== 'hash' && nonConst(first) && fromRequest(first);
    }
    case 'ruby_send': return !!first && first.type !== 'simple_symbol' && (fromRequest(first) || (taintOf(first) === 'string_concat' && fromRequest(first)));
    case 'ruby_request_name': return !!first && fromRequest(first);
    case 'ruby_constantize': return !!s.receiver && nonConst(s.receiver) && (fromRequest(s.receiver) || s.receiver.type === 'interpolation' || taintOf(s.receiver) === 'string_concat' || /\b(type|klass|class_name|model|kind|name)\b/.test(s.receiver.text));
    case 'ruby_yaml_load': return nonConst(first) && !s.a.kw.has('permitted_classes');
    case 'ruby_oj_load': { const mode = s.a.kw.get('mode')?.text ?? ''; return nonConst(first) && !/^:(strict|compat|json|null|rails|wab|custom)$/.test(mode); }
    case 'ruby_json_create': return s.method === 'load' ? nonConst(first) : s.a.kw.get('create_additions')?.type === 'true';
    case 'ruby_http': { const u = first ?? s.a.kw.get('url') ?? s.a.kw.get('base_url') ?? s.a.kw.get('uri'); return nonConst(u) && u!.type !== 'hash'; }
    case 'ruby_xxe': return /NOENT|DTDLOAD|\.noent|\.dtdload|huge/.test(s.node.text);
    case 'ruby_by_id': {
      const recv = s.receiver;
      if (!recv || !(recv.type === 'constant' || recv.type === 'scope_resolution')) return false;
      if (s.method === 'find') return !!first && fromRequest(first);
      return [...s.a.kw.entries()].some(([k, v]) => /^(id|uuid|slug|\w+_id)$/.test(k) && fromRequest(v)) || (/^find_by_(id|uuid|slug)!?$/.test(s.method) && fromRequest(first));
    }
    case 'ruby_html_safe': {
      // Request data, or strings interpolating unescaped values (`"<b>#{name}</b>".html_safe`); a helper's own output is not flagged.
      const v = s.method === 'html_safe' ? s.receiver : first;
      if (!v) return false;
      if (fromRequest(v)) return true;
      const interps = v.type === 'string' || v.type === 'heredoc_beginning' ? named(v.type === 'string' ? v : heredocBody(v)).filter((c) => c.type === 'interpolation') : [];
      return interps.some((i) => !safeInterpolation(i) && !/^\s*(h|html_escape|escape_\w+|ERB::Util\.\w+|CGI\.escape\w*|sanitize|strip_tags|j|escape_javascript|t|l|link_to|content_tag|tag\.\w+|image_tag|\w+_(path|url))\b/.test(named(i)[0]?.text ?? ''));
    }
    case 'ruby_permit': return s.method === 'permit!' || /:(role|roles|admin|is_admin|superuser|owner_id|user_id|account_id|balance|price|verified|approved|confirmed_at|permissions?)\b/.test(s.a.pos.map((x) => x.text).join(' '));
    case 'ruby_csrf': {
      if (s.method === 'skip_forgery_protection') return true;
      if (s.method === 'protect_from_forgery') return s.a.kw.has('except') || s.a.kw.has('only') || s.a.kw.get('if') !== undefined || s.a.kw.get('unless') !== undefined;
      return s.a.pos.some((p) => literal(p) === 'verify_authenticity_token');
    }
    default: return true;
  }
}
