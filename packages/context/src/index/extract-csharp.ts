// C# extraction: symbols, calls (with receiver types from fields, properties, constructor /
// primary-constructor parameters and locals), ASP.NET Core entries (attribute-routed controllers and minimal
// APIs with MapGroup prefixes and endpoint conventions), sinks (post functions `csharp_*`) and auth signals.
//
// Identity conventions (languages.ts):
// - `pkg` = namespace (block or file-scoped). Method containers are `<namespace>.<Class>` (nested: `Outer.Inner`).
// - Constructors are named after their class (`OrdersController.OrdersController`, as the eval locator does);
//   extension methods do not count their `this` parameter.
// - Top-level statements become the synthesized method `Program.Main(0)` (what the compiler generates); top-level
//   local functions are methods of `Program`.
// - `[controller]` / `[action]` route tokens are replaced by the lower-cased class name without `Controller` /
//   the action name without `Async` (ASP.NET Core routing is case-insensitive; lower case matches what clients
//   call). Route constraints `{id:int}` / `{id?}` / `{*path}` are reduced to the parameter name.
import type { Node, Tree } from 'web-tree-sitter';
import type { AuthSignal } from '@xiezhi/contracts';
import { AUTH_NAME_RE, captureMap, fillApi, makeSink, rangeOf, ruleMatches, unquote, type CompiledRule } from './common.js';
import { rpcOf } from './proto.js';
import { emptyExtract, joinRoute, type ExtractInput, type FileExtract, type HandlerRef, type RawEntry } from './types.js';
import { razorPageOf, type CsAttr, type CsClassFacts, type CsConventionalRoute, type CsharpContext, type CsRazorPage } from './extract-csharp-context.js';

const TYPE_DECLS = new Set(['class_declaration', 'interface_declaration', 'struct_declaration', 'record_declaration', 'record_struct_declaration', 'enum_declaration']);
const METHOD_DECLS = new Set(['method_declaration', 'constructor_declaration']);
const HTTP_ATTR: Record<string, string> = {
  HttpGet: 'GET', HttpPost: 'POST', HttpPut: 'PUT', HttpDelete: 'DELETE', HttpPatch: 'PATCH', HttpHead: 'HEAD', HttpOptions: 'OPTIONS',
};
const MAP_VERB: Record<string, string> = { MapGet: 'GET', MapPost: 'POST', MapPut: 'PUT', MapDelete: 'DELETE', MapPatch: 'PATCH' };
/** Endpoint conventions that change who may call an endpoint (kept as middlewares; auth ones also as signals). */
const CONVENTION_RE = /^(RequireAuthorization|AllowAnonymous|AddEndpointFilter|AddEndpointFilterFactory|RequireCors|RequireHost|RequireRateLimiting|DisableAntiforgery|WithMetadata)$/;
const PIPELINE_CONFIG_RE = /^(AddAuthentication|AddAuthorization|AddAuthorizationBuilder|AddJwtBearer|AddCookie|AddIdentity|AddDefaultIdentity)$/;

/** Whether `inner` is a receiver link of the fluent chain ending at `outer` (`inner.X(…).Y(…)`). */
function isChainOf(outer: Node, inner: Node): boolean {
  for (let cur: Node | null = outer; cur && cur.type === 'invocation_expression';) {
    if (cur.id === inner.id) return true;
    const fn = cur.childForFieldName('function');
    cur = fn?.type === 'member_access_expression' ? fn.childForFieldName('expression') : null;
  }
  return false;
}

/** Pipeline middlewares that matter for access control (other `Use*` calls such as UseStaticFiles are left out). */
const PIPELINE_RE = /^Use(Authentication|Authorization|Middleware|Cors|Antiforgery|RateLimiter|Session)$/;
const CONTROLLER_BASE_RE = /^(ControllerBase|Controller|ApiController|ODataController|AbpController|AbpControllerBase)$/;
/** Same names as rules/csharp/aspnetcore/auth-attribute.scm: attributes that count as auth signals when inherited. */
const AUTH_ATTR_RE = /^(Authorize|AllowAnonymous|TypeFilter|ServiceFilter|ValidateAntiForgeryToken|AutoValidateAntiforgeryToken|IgnoreAntiforgeryToken|RequireHttps|[A-Za-z]*(Auth|Permission|Role|Jwt|ApiKey|Guard|Acl|Rbac|Secur|Login|Claim)[A-Za-z]*)$/;
/** synthetic rule id of entries from conventional routes (no tree-sitter query: they come from Program.cs). */
export const CONVENTIONAL_RULE_ID = 'csharp.aspnetcore.conventional-route';
/** synthetic rule id of Razor Pages handler entries (the route comes from the `.cshtml` file). */
export const RAZOR_PAGE_RULE_ID = 'csharp.aspnetcore.razor-page';
const PAGE_HANDLER_RE = /^On(Get|Post|Put|Delete|Patch|Head|Options)(\w*?)(Async)?$/;
/** `{controller:slugify=Home}` parameter transformer: `ChangePassword` → `change-password`. */
const slugify = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
const attrText = (a: CsAttr) => {
  const parts = [...a.args.map((x) => (/^[\w.]+$/.test(x) ? x : `"${x}"`)), ...Object.entries(a.named).map(([k, v]) => `${k} = "${v}"`)];
  return `[${a.name}${parts.length ? `(${parts.join(', ')})` : ''}]`;
};
const STRING_BUILDERS = /^(Format|Concat|Join|Combine|Append|AppendLine|AppendFormat|Insert|Replace|ToString|Add)$/;
const LITERALS = new Set(['string_literal', 'verbatim_string_literal', 'raw_string_literal', 'integer_literal', 'real_literal', 'boolean_literal', 'null_literal', 'character_literal']);
const WRAPPERS = new Set(['parenthesized_expression', 'cast_expression', 'await_expression', 'checked_expression', 'postfix_unary_expression']);

interface TypeInfo { name: string; container: string; symbolId: string; node: Node; members: Map<string, string>; bases: string[] }

/** `global::System.Collections.Generic.List<Foo>?` → `List`. */
export function csType(t: string): string {
  let depth = 0;
  let out = '';
  for (const ch of t) {
    if (ch === '<') depth++;
    else if (ch === '>') depth--;
    else if (depth === 0) out += ch;
  }
  const s = out.replace(/^global::/, '').replace(/\[[,\s]*\]/g, '').replace(/[?\s]/g, '');
  return s.split('.').pop() ?? s;
}

const named = (n: Node | null | undefined): Node[] => (n ? n.namedChildren.filter((c): c is Node => !!c) : []);
const truncate = (s: string, n: number) => (s.length > n ? s.slice(0, n) + '…' : s);
const oneLine = (s: string) => s.replace(/\s+/g, ' ').trim();

/** Expression of an `argument` node (skips `name:` and `ref` / `out` modifiers). */
function argExpr(arg: Node): Node | null {
  const kids = named(arg);
  return kids.length ? kids[kids.length - 1]! : null;
}
function argsOf(list: Node | null | undefined): Node[] {
  if (!list) return [];
  if (list.type !== 'argument_list') return [list];
  return named(list).filter((a) => a.type === 'argument').map(argExpr).filter((x): x is Node => !!x);
}

function unwrap(n: Node): Node {
  let cur = n;
  for (let i = 0; i < 8 && WRAPPERS.has(cur.type); i++) {
    const kids = named(cur);
    const inner = kids[kids.length - 1];
    if (!inner) break;
    cur = inner;
  }
  return cur;
}

/** Name node of an invocation's function (bare `F`, `x.F`, `x?.F`, generic `F<T>`). */
function invocationParts(call: Node): { method: string; receiver: Node | null } | null {
  const fn = call.childForFieldName('function');
  if (!fn) return null;
  const nameOf = (n: Node | null) => (n?.type === 'generic_name' ? n.namedChildren[0]?.text ?? null : n?.text ?? null);
  if (fn.type === 'identifier' || fn.type === 'generic_name') {
    const m = nameOf(fn);
    return m ? { method: m, receiver: null } : null;
  }
  if (fn.type === 'member_access_expression') {
    const m = nameOf(fn.childForFieldName('name'));
    return m ? { method: m, receiver: fn.childForFieldName('expression') } : null;
  }
  if (fn.type === 'conditional_access_expression') {
    const binding = named(fn).find((c) => c.type === 'member_binding_expression');
    const m = nameOf(binding?.childForFieldName('name') ?? null);
    return m ? { method: m, receiver: fn.childForFieldName('condition') } : null;
  }
  return null;
}

function assignOp(a: Node): string {
  for (const c of a.children) if (c && !c.isNamed && /=$/.test(c.text)) return c.text;
  return '=';
}

/** Value expression of a `variable_declarator` (the node after the name). */
function declaratorValue(d: Node): Node | null {
  const name = d.childForFieldName('name');
  const kids = named(d).filter((c) => c.id !== name?.id && c.type !== 'bracketed_argument_list');
  return kids.length ? kids[kids.length - 1]! : null;
}

interface AttrInfo { name: string; node: Node; positional: string[]; namedArgs: Map<string, string> }

function attributesOf(decl: Node): AttrInfo[] {
  const out: AttrInfo[] = [];
  for (const list of named(decl)) {
    if (list.type !== 'attribute_list') continue;
    for (const attr of named(list)) {
      if (attr.type !== 'attribute') continue;
      const name = (attr.childForFieldName('name')?.text ?? '').split('.').pop()!.replace(/Attribute$/, '');
      const positional: string[] = [];
      const namedArgs = new Map<string, string>();
      const argList = named(attr).find((c) => c.type === 'attribute_argument_list');
      for (const a of named(argList)) {
        if (a.type !== 'attribute_argument') continue;
        const key = a.childForFieldName('name')?.text;
        const kids = named(a);
        const val = kids[kids.length - 1];
        const text = val ? (/string_literal/.test(val.type) ? literalText(val) : val.text) : '';
        if (key && val && val.id !== a.childForFieldName('name')?.id) namedArgs.set(key, text);
        else positional.push(text);
      }
      out.push({ name, node: attr, positional, namedArgs });
    }
  }
  return out;
}

function literalText(n: Node): string {
  if (n.type === 'verbatim_string_literal') return n.text.slice(2, -1).replace(/""/g, '"');
  if (n.type === 'raw_string_literal') return n.text.replace(/^"{3,}/, '').replace(/"{3,}$/, '');
  return unquote(n.text);
}

/** `{id:int}` → `{id}`, `{id?}` → `{id}`, `{*path}` → `{path}` (the key normalizes any `{…}` to `{}`). */
export function stripRouteConstraints(p: string): string {
  return p.replace(/\{\*{0,2}([A-Za-z_]\w*)[^}]*\}/g, '{$1}');
}

export function extractCsharp(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const root = tree.rootNode;
  const fileNs = named(root).find((n) => n.type === 'file_scoped_namespace_declaration')?.childForFieldName('name')?.text ?? '';
  const nsOf = (node: Node): string => {
    const parts: string[] = [];
    for (let p: Node | null = node.parent; p; p = p.parent) if (p.type === 'namespace_declaration') parts.unshift(p.childForFieldName('name')?.text ?? '');
    return [fileNs, ...parts].filter(Boolean).join('.');
  };
  const firstNs = fileNs || (root.descendantsOfType('namespace_declaration')[0]?.childForFieldName('name')?.text ?? '');
  fx.pkg = firstNs;

  // ---- usings ----
  const imports = new Set<string>();
  const aliases = new Map<string, string>();
  for (const u of root.descendantsOfType('using_directive')) {
    if (!u) continue;
    const alias = u.childForFieldName('name')?.text;
    const target = named(u).filter((c) => c.id !== u.childForFieldName('name')?.id).pop()?.text;
    if (!target) continue;
    if (alias) aliases.set(alias, target);
    else imports.add(target);
  }

  // ---- symbols ----
  const csCtx = input.langContext as CsharpContext | undefined;
  const types = new Map<number, TypeInfo>();
  const fnIds = new Map<number, string>();
  const scopeTypes = new Map<number, Map<string, string>>();
  const signature = (node: Node): string => {
    const first = node.children.find((c) => !!c && c.type !== 'attribute_list') ?? node;
    const body = node.childForFieldName('body') ?? named(node).find((c) => c.type === 'arrow_expression_clause' || c.type === 'declaration_list') ?? null;
    const end = body ? body.startIndex : node.endIndex;
    return truncate(oneLine(input.text.slice(first.startIndex, Math.max(first.startIndex, end))), 300);
  };
  const localTypes = (scope: Node, into: Map<string, string>) => {
    for (const p of scope.descendantsOfType('parameter')) {
      const t = p?.childForFieldName('type');
      const n = p?.childForFieldName('name')?.text;
      if (t && n && !into.has(n)) into.set(n, csType(t.text));
    }
    for (const decl of scope.descendantsOfType('variable_declaration')) {
      if (!decl) continue;
      const t = decl.childForFieldName('type');
      for (const d of named(decl)) {
        if (d.type !== 'variable_declarator') continue;
        const vn = d.childForFieldName('name')?.text;
        let tn: string | null = t && t.type !== 'implicit_type' ? csType(t.text) : null;
        if (!tn) {
          const v = declaratorValue(d);
          const inner = v ? unwrap(v) : null;
          if (inner?.type === 'object_creation_expression') tn = csType(inner.childForFieldName('type')?.text ?? '');
        }
        if (vn && tn && !into.has(vn)) into.set(vn, tn);
      }
    }
  };
  const paramInfo = (params: Node | null): { arity: number; types: string[] } => {
    const ps = named(params).filter((p) => p.type === 'parameter');
    const isExt = ps[0] ? named(ps[0]).some((c) => c.type === 'modifier' && c.text === 'this') : false;
    const kept = isExt ? ps.slice(1) : ps;
    return { arity: kept.length, types: kept.map((p) => csType(p.childForFieldName('type')?.text ?? '?')) };
  };
  const addMethod = (node: Node, container: string, name: string) => {
    const { arity, types: ptypes } = paramInfo(node.childForFieldName('parameters'));
    const symbolId = `${input.repo}:${input.path}#${container}.${name}(${arity})`;
    fnIds.set(node.id, symbolId);
    const locals = new Map<string, string>();
    localTypes(node, locals);
    scopeTypes.set(node.id, locals);
    fx.symbols.push({
      symbolId, repo: input.repo, kind: 'method', name, container, path: input.path, range: rangeOf(node),
      signature: signature(node), qualifiedName: `${container}.${name}(${ptypes.join(',')})`,
    });
  };

  const visit = (node: Node, outer: TypeInfo | null) => {
    let current = outer;
    if (TYPE_DECLS.has(node.type)) {
      const name = node.childForFieldName('name')?.text ?? '?';
      const ns = nsOf(node);
      const container = outer ? `${outer.container}.${name}` : ns ? `${ns}.${name}` : name;
      const symbolId = `${input.repo}:${input.path}#${container}`;
      const members = new Map<string, string>();
      const body = node.childForFieldName('body');
      for (const m of named(body)) {
        if (m.type === 'field_declaration' || m.type === 'event_field_declaration') {
          const decl = named(m).find((c) => c.type === 'variable_declaration');
          const t = decl?.childForFieldName('type');
          for (const d of named(decl)) if (d.type === 'variable_declarator' && t) members.set(d.childForFieldName('name')?.text ?? '', csType(t.text));
        } else if (m.type === 'property_declaration') {
          const t = m.childForFieldName('type');
          const n = m.childForFieldName('name')?.text;
          if (t && n) members.set(n, csType(t.text));
        }
      }
      // Primary constructor / positional record parameters are members too.
      for (const p of named(named(node).find((c) => c.type === 'parameter_list'))) {
        const t = p.childForFieldName('type');
        const n = p.childForFieldName('name')?.text;
        if (t && n && !members.has(n)) members.set(n, csType(t.text));
      }
      const bases = named(named(node).find((c) => c.type === 'base_list')).map((b) => csType(b.text));
      const info: TypeInfo = { name, container, symbolId, node, members, bases };
      types.set(node.id, info);
      fx.symbols.push({
        symbolId, repo: input.repo, kind: node.type === 'interface_declaration' ? 'interface' : 'class', name,
        container: outer ? outer.container : ns, path: input.path, range: rangeOf(node), signature: signature(node), qualifiedName: container,
      });
      current = info;
    } else if (METHOD_DECLS.has(node.type) && outer) {
      addMethod(node, outer.container, node.type === 'constructor_declaration' ? outer.name : (node.childForFieldName('name')?.text ?? '?'));
    }
    for (const c of named(node)) visit(c, current);
  };
  visit(root, null);

  // Top-level statements → `Program.Main(0)`; top-level local functions → `Program.<name>`.
  const globals = named(root).filter((n) => n.type === 'global_statement');
  let mainId: string | null = null;
  const mainLocals = new Map<string, string>();
  if (globals.length) {
    mainId = `${input.repo}:${input.path}#Program.Main(0)`;
    for (const g of globals) localTypes(g, mainLocals);
    fx.symbols.push({
      symbolId: mainId, repo: input.repo, kind: 'method', name: 'Main', container: 'Program', path: input.path,
      range: { startLine: rangeOf(globals[0]!).startLine, endLine: rangeOf(globals[globals.length - 1]!).endLine },
      signature: 'top-level statements', qualifiedName: 'Program.Main()',
    });
    for (const g of globals) {
      const fn = named(g).find((c) => c.type === 'local_function_statement');
      if (fn) addMethod(fn, 'Program', fn.childForFieldName('name')?.text ?? '?');
    }
  }

  const enclosingFn = (node: Node): Node | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) {
      if (fnIds.has(p.id)) return p;
      if (TYPE_DECLS.has(p.type) || p.type === 'global_statement') return null;
    }
    return null;
  };
  const enclosingType = (node: Node): TypeInfo | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (TYPE_DECLS.has(p.type)) return types.get(p.id) ?? null;
    return null;
  };
  const inGlobal = (node: Node): boolean => {
    for (let p: Node | null = node.parent; p; p = p.parent) {
      if (p.type === 'global_statement') return true;
      if (TYPE_DECLS.has(p.type)) return false;
    }
    return false;
  };
  const enclosingSymbol = (node: Node): string | null => {
    const fn = enclosingFn(node);
    if (fn) return fnIds.get(fn.id) ?? null;
    if (mainId && inGlobal(node)) return mainId;
    return enclosingType(node)?.symbolId ?? null;
  };
  /** The scope node whose locals / assignments are visible at `node` (method, local function, or the root for top-level code). */
  const scopeOf = (node: Node): Node => enclosingFn(node) ?? (inGlobal(node) ? root : enclosingType(node)?.node ?? root);
  const memberType = (name: string, at: Node): string | undefined => {
    for (let p: Node | null = at.parent; p; p = p.parent) {
      if (TYPE_DECLS.has(p.type)) {
        const t = types.get(p.id)?.members.get(name);
        if (t) return t;
      }
    }
    return undefined;
  };
  const localType = (name: string, at: Node): string | undefined => {
    const fn = enclosingFn(at);
    if (fn) return scopeTypes.get(fn.id)?.get(name);
    return inGlobal(at) ? mainLocals.get(name) : undefined;
  };

  interface Receiver { text: string | null; type: string | null; imp: string | null }
  const receiverFacts = (recv: Node | null, at: Node): Receiver => {
    if (!recv) return { text: null, type: null, imp: null };
    const r = unwrap(recv);
    if (r.type === 'this') return { text: 'this', type: null, imp: null };
    if (r.type === 'base') {
      const bases = enclosingType(at)?.bases ?? [];
      return { text: 'base', type: bases.find((b) => !/^I[A-Z]/.test(b)) ?? null, imp: null };
    }
    if (r.type === 'object_creation_expression') return { text: recv.text, type: csType(r.childForFieldName('type')?.text ?? ''), imp: null };
    let name: string | null = null;
    if (r.type === 'identifier') name = r.text;
    else if (r.type === 'member_access_expression' && r.childForFieldName('expression')?.type === 'this') name = r.childForFieldName('name')?.text ?? null;
    if (name) {
      const t = localType(name, at) ?? memberType(name, at);
      if (t) return { text: recv.text, type: t, imp: null };
      if (r.type === 'identifier' && /^[A-Z]/.test(name)) {
        // A static class (or an alias of one): `File.ReadAllText`, `Json.DeserializeObject` with `using Json = …`.
        const target = aliases.get(name) ?? name;
        return { text: recv.text, type: csType(target), imp: target };
      }
      return { text: recv.text, type: null, imp: null };
    }
    // Fully qualified static calls: `System.IO.File.ReadAllText`.
    if (r.type === 'member_access_expression' && /^[A-Z][\w]*(\.[A-Z]\w*)+$/.test(r.text) && /^(System|Microsoft|Newtonsoft)\./.test(r.text)) {
      return { text: recv.text, type: csType(r.text), imp: r.text };
    }
    return { text: recv.text, type: null, imp: null };
  };

  // ---- calls ----
  for (const call of root.descendantsOfType('invocation_expression')) {
    if (!call) continue;
    const parts = invocationParts(call);
    if (!parts || parts.method === 'nameof') continue;
    const from = enclosingSymbol(call);
    if (!from) continue;
    const r = receiverFacts(parts.receiver, call);
    fx.calls.push({
      from, method: parts.method, receiverText: r.text, receiverType: r.text === 'this' ? null : r.type, receiverImport: r.imp,
      arity: argsOf(call.childForFieldName('arguments')).length, line: call.startPosition.row + 1,
      calleeText: truncate(oneLine(call.childForFieldName('function')?.text ?? parts.method), 200),
    });
  }

  // ---- string taint (language-local; the shared taintHintOf is Java / Go oriented) ----
  const valueCache = new Map<number, Map<string, { values: Node[]; appended: boolean }>>();
  const valuesIn = (scope: Node) => {
    let m = valueCache.get(scope.id);
    if (m) return m;
    m = new Map();
    const add = (name: string, v: Node | null, appended = false) => {
      const e = m!.get(name) ?? { values: [], appended: false };
      if (v) e.values.push(v);
      e.appended ||= appended;
      m!.set(name, e);
    };
    for (const d of scope.descendantsOfType('variable_declarator')) {
      const n = d?.childForFieldName('name')?.text;
      if (d && n) add(n, declaratorValue(d));
    }
    for (const a of scope.descendantsOfType('assignment_expression')) {
      const left = a?.childForFieldName('left');
      if (!a || left?.type !== 'identifier') continue;
      const op = assignOp(a);
      add(left.text, a.childForFieldName('right'), op === '+=');
    }
    valueCache.set(scope.id, m);
    return m;
  };
  const constFields = new Map<string, Node>();
  for (const f of root.descendantsOfType('field_declaration')) {
    if (!f || !named(f).some((c) => c.type === 'modifier' && (c.text === 'const' || c.text === 'readonly'))) continue;
    for (const d of f.descendantsOfType('variable_declarator')) {
      const n = d?.childForFieldName('name')?.text;
      const v = d ? declaratorValue(d) : null;
      if (n && v) constFields.set(n, v);
    }
  }
  const resolved = (id: Node): { values: Node[]; appended: boolean } => {
    const own = valuesIn(scopeOf(id)).get(id.text);
    if (own && own.values.length) return own;
    const field = constFields.get(id.text);
    return field ? { values: [field], appended: false } : { values: [], appended: false };
  };
  const isConst = (e: Node, depth = 0): boolean => {
    const n = unwrap(e);
    if (LITERALS.has(n.type) || n.type === 'typeof_expression') return true;
    if (n.type === 'interpolated_string_expression') return !named(n).some((c) => c.type === 'interpolation');
    if (n.type === 'binary_expression') {
      const l = n.childForFieldName('left');
      const r = n.childForFieldName('right');
      return !!l && !!r && isConst(l, depth) && isConst(r, depth);
    }
    if (n.type === 'invocation_expression' && n.childForFieldName('function')?.text === 'nameof') return true;
    if (n.type === 'identifier' && depth < 3) {
      const v = resolved(n);
      return v.values.length > 0 && !v.appended && v.values.every((x) => isConst(x, depth + 1));
    }
    return false;
  };
  const isDynamic = (e: Node, depth = 0): boolean => {
    const n = unwrap(e);
    if (n.type === 'interpolated_string_expression') return named(n).some((c) => c.type === 'interpolation');
    if (n.type === 'binary_expression') {
      const l = n.childForFieldName('left');
      const r = n.childForFieldName('right');
      const op = n.childForFieldName('operator')?.text ?? n.children.find((c) => !!c && !c.isNamed)?.text;
      if (op !== '+') return false;
      return !(l && r && isConst(l, depth) && isConst(r, depth));
    }
    if (n.type === 'conditional_expression') {
      return [n.childForFieldName('consequence'), n.childForFieldName('alternative')].some((x) => !!x && isDynamic(x, depth));
    }
    if (n.type === 'invocation_expression') {
      const parts = invocationParts(n);
      if (!parts || !STRING_BUILDERS.test(parts.method)) return false;
      if (parts.method === 'ToString' || parts.method === 'Add') {
        // `sb.ToString()` of a StringBuilder built in this scope.
        const recv = parts.receiver ? unwrap(parts.receiver) : null;
        if (parts.method === 'Add' || recv?.type !== 'identifier') return false;
        return (localType(recv.text, n) ?? memberType(recv.text, n)) === 'StringBuilder';
      }
      const args = argsOf(n.childForFieldName('arguments'));
      return args.some((a) => !isConst(a, depth));
    }
    if (n.type === 'identifier' && depth < 3) {
      const v = resolved(n);
      return v.appended || v.values.some((x) => isDynamic(x, depth + 1));
    }
    return false;
  };
  const taintOf = (exprs: Node[]): string | undefined => {
    if (!exprs.length) return undefined;
    if (exprs.some((e) => isDynamic(e))) return 'string_concat';
    if (exprs.every((e) => isConst(e))) return 'constant';
    return undefined;
  };

  // ---- rules ----
  const seenSinks = new Set<string>();
  const pushSink = (s: ReturnType<typeof makeSink>) => { if (!seenSinks.has(s.sinkId)) { seenSinks.add(s.sinkId); fx.sinks.push(s); } };
  const scopeText = (n: Node) => { const fn = enclosingFn(n); return fn ? fn.text : n.text; };
  const methodEntries = new Set<number>();
  const stmtCache = new Map<number, { router: string; pos: number; text: string }[]>();
  const attrEntries = new Set<RawEntry>();

  for (const { rule, query, error } of rules) {
    if (error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${error}` }); continue; }
    if (!query) continue;
    if (rule.match?.requiresImportAny && !rule.match.requiresImportAny.some((i) => imports.has(i))) continue;
    try {
      for (const match of query.matches(root)) {
        const cap = captureMap(match.captures, rule.captures);
        if (rule.kind === 'sink') {
          const node = cap.get('call');
          if (!node) continue;
          const argsNode = cap.get('args');
          const args = argsOf(argsNode);
          const recvNode = cap.get('receiver') ?? null;
          const r = receiverFacts(recvNode, node);
          if (!ruleMatches(rule.match, { receiverText: r.text, receiverType: r.type, receiverImport: r.imp, imports, argCount: args.length })) continue;
          // Data arguments: the command line for cmdi (all arguments + initializer), otherwise the first argument
          // (SQL text, URL, path, payload).
          const initializer = node.type === 'object_creation_expression' ? node.childForFieldName('initializer') : null;
          const initValues = named(initializer).filter((a) => a.type === 'assignment_expression').map((a) => a.childForFieldName('right')).filter((x): x is Node => !!x);
          let data = rule.category === 'cmdi' ? [...args, ...initValues] : args.slice(0, 1);
          if (!data.length && initValues.length) data = initValues;
          if (!postSinkOk(rule.post, node, args, r)) continue;
          const api = fillApi(rule.api ?? '', {
            method: cap.get('method')?.text, type: cap.get('type')?.text, receiver: r.text, receiverType: r.type ?? r.text,
          });
          const noTaint = rule.framework === 'business';
          pushSink(makeSink(input.repo, input.path, rule, node, enclosingSymbol(node), api, noTaint ? undefined : taintOf(data)));
        } else if (rule.kind === 'entrypoint' && rule.post === 'csharp_aspnet_action') {
          const method = cap.get('handler');
          if (!method || methodEntries.has(method.id)) continue;
          methodEntries.add(method.id);
          for (const e of actionEntries(rule.id, method)) { fx.entries.push(e); attrEntries.add(e); }
        } else if (rule.kind === 'entrypoint' && rule.post === 'csharp_minimal_api') {
          const e = minimalEntries(rule.id, cap);
          for (const x of e.entries) { fx.entries.push(x); if (e.methodGroup) attrEntries.add(x); }
        } else if (rule.kind === 'auth_signal') {
          const sig = authSignal(rule.id, rule.post, cap);
          if (sig && !fx.authSignals.some((s) => s.target === sig.target && s.detail === sig.detail)) fx.authSignals.push(sig);
        }
      }
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${(e as Error).message}` });
    }
  }

  for (const e of conventionalEntries()) { fx.entries.push(e); attrEntries.add(e); }
  for (const e of razorPageEntries()) { fx.entries.push(e); attrEntries.add(e); }
  for (const e of grpcEntries()) { fx.entries.push(e); attrEntries.add(e); }
  for (const e of hubEntries()) { fx.entries.push(e); attrEntries.add(e); }
  for (const e of channelEntries()) { fx.entries.push(e); attrEntries.add(e); }

  // Attribute signals ([Authorize], [AllowAnonymous], filters) on the action or its controller (and outer classes).
  for (const entry of attrEntries) {
    const handler = entry.handler.symbolId ?? '';
    const owners = new Set([handler]);
    for (let cls = handler.replace(/\.[^.#]+\(\d+\)$/, ''); cls.includes('#'); cls = cls.replace(/\.[^.#]+$/, '')) {
      owners.add(cls);
      if (!/\.[^.#]+$/.test(cls)) break;
    }
    const attrs = fx.authSignals.filter((s) => s.kind === 'annotation' && owners.has(s.target)).map((s) => s.detail);
    entry.authSignals = [...new Set([...entry.authSignals, ...attrs])];
  }
  for (const e of fx.entries) {
    for (const mw of e.middlewares) {
      if (!e.authSignals.includes(mw)) continue;
      if (!fx.authSignals.some((s) => s.detail === mw)) fx.authSignals.push({ target: `${input.repo}:${input.path}`, kind: 'middleware', detail: mw, ruleId: e.ruleId });
    }
  }
  return fx;

  // ---- post functions -----------------------------------------------------------------------------------

  function postSinkOk(post: string | undefined, node: Node, args: Node[], r: Receiver): boolean {
    switch (post) {
      case undefined: return true;
      case 'csharp_formattable_sql': {
        // EF `FromSql` / `ExecuteSqlCommand` with an interpolated string bind a FormattableString (parameters).
        const a0 = args[0] ? unwrap(args[0]) : null;
        return !!a0 && a0.type !== 'interpolated_string_expression';
      }
      case 'csharp_command_execute': {
        // Only when the command text is not visible in this method (built elsewhere); otherwise the
        // `new SqlCommand(…)` / `CommandText =` sink already covers it.
        if (!r.text || !/^\w+$/.test(r.text)) return true;
        const text = scopeText(node);
        const esc = r.text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return !new RegExp(`\\b${esc}\\s*=\\s*new\\s+\\w*Command\\b|\\b${esc}\\.CommandText\\s*=`).test(text);
      }
      case 'csharp_json_typename':
        return /TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)/.test(input.text);
      case 'csharp_dynamic_type': {
        const a0 = args[0] ? unwrap(args[0]) : null;
        return !!a0 && a0.type !== 'typeof_expression';
      }
      case 'csharp_redirect':
        return !/\bIsLocalUrl\s*\(/.test(scopeText(node));
      case 'csharp_by_id': {
        const parts = node.type === 'invocation_expression' ? invocationParts(node) : null;
        const m = parts?.method ?? '';
        const lambda = args.find((a) => unwrap(a).type === 'lambda_expression');
        const idCompare = (n: Node) => /(\.|\b)(Id|ID)\s*==|==\s*[\w.]*\.(Id|ID)\b|\b\w*(Id|ID)\s*==/.test(n.text);
        if (/^(Find|FindAsync)$/.test(m)) return lambda ? idCompare(lambda) : args.length > 0;
        if (/^(First|FirstOrDefault|Single|SingleOrDefault|Where|Any|FirstAsync|FirstOrDefaultAsync|SingleAsync|SingleOrDefaultAsync|AnyAsync)$/.test(m)) return !!lambda && idCompare(lambda);
        return true;
      }
      case 'csharp_state_write': {
        const text = scopeText(node);
        return /\b(SaveChanges|SaveChangesAsync|Update|UpdateAsync|UpdateRange|Commit|CommitAsync)\s*\(/.test(text);
      }
      default: return true;
    }
  }

  function actionEntries(ruleId: string, method: Node): RawEntry[] {
    const cls = enclosingType(method);
    const symbolId = fnIds.get(method.id);
    if (!cls || !symbolId || cls.node.type === 'interface_declaration') return [];
    const clsAttrs = attributesOf(cls.node);
    const inherited = inheritedOf(cls);
    const isController = clsAttrs.some((a) => a.name === 'ApiController' || a.name === 'Controller' || a.name === 'Route')
      || cls.bases.some((b) => CONTROLLER_BASE_RE.test(b)) || /Controller$/.test(cls.name)
      || inherited.some((x) => x.bases.some((b) => CONTROLLER_BASE_RE.test(b)) || x.attrs.some((a) => a.name === 'ApiController' || a.name === 'Route'));
    if (!isController || clsAttrs.some((a) => a.name === 'NonController')) return [];
    const attrs = attributesOf(method);
    if (attrs.some((a) => a.name === 'NonAction')) return [];
    const controllerToken = cls.name.replace(/Controller$/, '').toLowerCase();
    const methodName = method.childForFieldName('name')?.text ?? '';
    const actionToken = (attrs.find((a) => a.name === 'ActionName')?.positional[0] ?? methodName.replace(/Async$/, '')).toLowerCase();
    const area = clsAttrs.find((a) => a.name === 'Area')?.positional[0] ?? inherited.flatMap((x) => x.attrs).find((a) => a.name === 'Area')?.args[0];
    const templateOf = (a: AttrInfo): string | null => a.namedArgs.get('Template') ?? (a.positional[0] !== undefined && a.positional[0] !== '' ? a.positional[0] : a.positional.length ? '' : null);
    const routes: { method: string; tmpl: string }[] = [];
    const bareVerbs: string[] = [];
    for (const a of attrs) {
      const verb = HTTP_ATTR[a.name];
      if (verb) {
        const t = templateOf(a);
        if (t === null) bareVerbs.push(verb);
        else routes.push({ method: verb, tmpl: t });
      } else if (a.name === 'AcceptVerbs') {
        bareVerbs.push(...a.positional.map((v) => v.toUpperCase()).filter((v) => /^[A-Z]+$/.test(v)));
      }
    }
    const routeTemplates = attrs.filter((a) => a.name === 'Route').map((a) => templateOf(a) ?? '');
    const accept = attrs.find((a) => a.name === 'AcceptVerbs')?.namedArgs.get('Route');
    if (accept !== undefined) routeTemplates.push(accept);
    for (const t of routeTemplates) for (const m of bareVerbs.length ? bareVerbs : ['ANY']) routes.push({ method: m, tmpl: t });
    if (!routeTemplates.length) for (const m of bareVerbs) routes.push({ method: m, tmpl: '' });
    // Class [Route] prefixes; when the class has none, the nearest ancestor's (attribute is inherited).
    let prefixes = clsAttrs.filter((a) => a.name === 'Route').map((a) => templateOf(a) ?? '');
    if (!prefixes.length) prefixes = inherited.find((x) => x.attrs.some((a) => a.name === 'Route'))?.attrs.filter((a) => a.name === 'Route').map((a) => a.named.Template ?? a.args[0] ?? '') ?? [];
    // A bare [HttpPost] with no route template anywhere is a verb constraint on a conventionally routed action:
    // its path comes from MapControllerRoute (conventionalEntries), not from the attribute.
    if (!prefixes.length && !routeTemplates.length && !routes.some((r) => r.tmpl !== '')) return [];
    const inheritedAuth = inheritedAuthOf(cls);
    const out: RawEntry[] = [];
    const seen = new Set<string>();
    const tokens = (p: string) => stripRouteConstraints(p.replace(/\[controller\]/gi, controllerToken).replace(/\[action\]/gi, actionToken).replace(/\[area\]/gi, (area ?? 'area').toLowerCase()));
    for (const r of routes) {
      for (const prefix of prefixes.length ? prefixes : ['']) {
        const absolute = /^~?\//.test(r.tmpl);
        const path = tokens(absolute ? r.tmpl.replace(/^~/, '') : joinRoute(prefix, r.tmpl));
        const full = path.startsWith('/') ? path : `/${path}`;
        const k = `${r.method} ${full}`;
        if (seen.has(k)) continue;
        seen.add(k);
        out.push({ ruleId, framework: 'aspnetcore', httpMethod: r.method, pathTemplate: full, handler: { symbolId }, path: input.path, range: rangeOf(method), middlewares: [], authSignals: [...inheritedAuth] });
        if (absolute) break;
      }
    }
    return out;
  }

  // ---- ancestors in other files and conventional routes ------------------------------

  function inheritedOf(cls: TypeInfo): CsClassFacts[] {
    return csCtx?.ancestors[cls.name] ?? [];
  }

  /** Auth attributes declared on ancestor classes (ASP.NET attributes are inherited), as entry signals. */
  function inheritedAuthOf(cls: TypeInfo): string[] {
    const out: string[] = [];
    for (const anc of inheritedOf(cls)) for (const a of anc.attrs) if (AUTH_ATTR_RE.test(a.name)) out.push(truncate(`${attrText(a)}（继承自 ${anc.name}）`, 200));
    return out;
  }

  /** Path of a conventional route for (controller, action), or null when the route cannot reach this action. */
  function expandRoute(route: CsConventionalRoute, controller: string, action: string, area: string | undefined): string | null {
    const pattern = route.pattern;
    const has = (n: string) => new RegExp(`\\{\\*{0,2}${n}\\b`, 'i').test(pattern);
    if (!has('controller') && route.defaults.controller?.toLowerCase() !== controller.toLowerCase()) return null;
    if (!has('action') && route.defaults.action?.toLowerCase() !== action.toLowerCase()) return null;
    const routeArea = route.area ?? (has('area') ? undefined : null);
    if (area && routeArea === null) return null; // area controllers are reached only through area routes
    if (!area && (route.area || has('area'))) return null;
    if (route.area && area && route.area.toLowerCase() !== area.toLowerCase()) return null;
    const path = pattern.replace(/\{\*{0,2}([A-Za-z_]\w*)((?::[^=?}]+)*)(=[^?}]*)?\??\}/g, (_m, name: string, constraints: string) => {
      const transform = (v: string) => (/:slugify\b/i.test(constraints ?? '') ? slugify(v) : v.toLowerCase());
      const n = name.toLowerCase();
      if (n === 'controller') return transform(controller);
      if (n === 'action') return transform(action);
      if (n === 'area') return (area ?? '').toLowerCase();
      return `{${name}}`;
    });
    const full = `/${path}`.replace(/\/{2,}/g, '/');
    return full.length > 1 ? full.replace(/\/+$/, '') : full;
  }

  /**
   * Conventionally routed MVC actions: public instance methods without route attributes on controllers that have
   * no [Route] / [ApiController] (own or inherited); one entry per registered route that can reach them.
   */
  function conventionalEntries(): RawEntry[] {
    const routes = csCtx?.routes ?? [];
    if (!routes.length) return [];
    const out: RawEntry[] = [];
    for (const cls of types.values()) {
      if (cls.node.type !== 'class_declaration') continue;
      const mods = named(cls.node).filter((c) => c.type === 'modifier').map((c) => c.text);
      if (mods.includes('abstract') || mods.includes('static')) continue;
      const clsAttrs = attributesOf(cls.node);
      const inherited = inheritedOf(cls);
      const allAttrs = [...clsAttrs.map((a) => a.name), ...inherited.flatMap((x) => x.attrs.map((a) => a.name))];
      if (allAttrs.includes('ApiController') || allAttrs.includes('Route') || allAttrs.includes('NonController')) continue;
      const isController = cls.bases.some((b) => CONTROLLER_BASE_RE.test(b)) || /Controller$/.test(cls.name) || allAttrs.includes('Controller')
        || inherited.some((x) => x.bases.some((b) => CONTROLLER_BASE_RE.test(b)));
      if (!isController) continue;
      const controller = cls.name.replace(/Controller$/, '');
      const area = clsAttrs.find((a) => a.name === 'Area')?.positional[0] ?? inherited.flatMap((x) => x.attrs).find((a) => a.name === 'Area')?.args[0];
      const inheritedAuth = inheritedAuthOf(cls);
      for (const m of named(cls.node.childForFieldName('body'))) {
        if (m.type !== 'method_declaration') continue;
        const mm = named(m).filter((c) => c.type === 'modifier').map((c) => c.text);
        if (!mm.includes('public') || mm.includes('static') || mm.includes('abstract')) continue;
        const name = m.childForFieldName('name')?.text ?? '';
        if (name === 'Dispose') continue;
        const attrs = attributesOf(m);
        if (attrs.some((a) => a.name === 'NonAction' || a.name === 'Route')) continue;
        if (attrs.some((a) => HTTP_ATTR[a.name] && (a.namedArgs.get('Template') ?? a.positional[0] ?? '') !== '')) continue;
        const symbolId = fnIds.get(m.id);
        if (!symbolId) continue;
        const verbs = attrs.flatMap((a) => (HTTP_ATTR[a.name] ? [HTTP_ATTR[a.name]!] : a.name === 'AcceptVerbs' ? a.positional.map((v) => v.toUpperCase()) : []));
        const action = (attrs.find((a) => a.name === 'ActionName')?.positional[0] ?? name).replace(/Async$/, '');
        const seen = new Set<string>();
        for (const r of routes) {
          const path = expandRoute(r, controller, action, area);
          if (path === null) continue;
          for (const verb of verbs.length ? verbs : ['ANY']) {
            const k = `${verb} ${path}`;
            if (seen.has(k)) continue;
            seen.add(k);
            const mws = r.conventions;
            out.push({
              ruleId: CONVENTIONAL_RULE_ID, framework: 'aspnetcore', httpMethod: verb, pathTemplate: path, handler: { symbolId }, path: input.path,
              range: rangeOf(m), middlewares: [...mws], authSignals: [...inheritedAuth, ...mws.filter((c) => /^(RequireAuthorization|AllowAnonymous)\(/.test(c))],
            });
          }
        }
      }
    }
    return out;
  }

  // ---- Razor Pages ----------------------------------------------------------------------------

  /** The page a PageModel class serves: its code-behind page, else the page whose `@model` names it. */
  function pageOf(cls: TypeInfo): CsRazorPage | null {
    const own = csCtx?.pagesByCodeBehind[input.path];
    if (own && (!own.model || own.model === cls.name)) return own;
    const byModel = csCtx?.pagesByModel[cls.name] ?? [];
    const dir = input.path.includes('/') ? input.path.slice(0, input.path.lastIndexOf('/')) : '';
    const near = byModel.filter((p) => (p.file.includes('/') ? p.file.slice(0, p.file.lastIndexOf('/')) : '') === dir);
    if (near.length === 1 || byModel.length === 1) return (near[0] ?? byModel[0])!;
    // No .cshtml seen (not in the snapshot or no context): fall back to the code-behind path itself.
    if (!csCtx && /\.cshtml\.cs$/.test(input.path)) return razorPageOf(input.path.slice(0, -3), '@page');
    return null;
  }

  /** Route of a page handler: `/area/folder/page` (trailing Index dropped) + `@page` template; named handlers go into a
   *  `{handler}` route parameter when the template has one, else into `?handler=name`. */
  function pageRoute(page: CsRazorPage, handler: string): string {
    const base = `${page.area ? `/${page.area}` : ''}${page.pagePath.replace(/\/Index$/i, '') || ''}`.toLowerCase();
    let tmpl = page.template.trim();
    const absolute = /^~?\//.test(tmpl);
    const hasHandlerParam = /\{handler\b[^}]*\}/i.test(tmpl);
    tmpl = tmpl.replace(/\{handler\b[^}]*\}/i, handler.toLowerCase());
    let path = absolute ? tmpl.replace(/^~/, '') : joinRoute(base || '/', tmpl);
    path = stripRouteConstraints(path).replace(/\/{2,}/g, '/');
    if (path.length > 1) path = path.replace(/\/+$/, '');
    if (!path.startsWith('/')) path = `/${path}`;
    return handler && !hasHandlerParam ? `${path}?handler=${handler.toLowerCase()}` : path;
  }

  /** Signals from Razor Pages conventions (AuthorizePage / AuthorizeFolder / AllowAnonymousTo…, MapRazorPages().RequireAuthorization()). */
  function pageConventionSignals(page: CsRazorPage): string[] {
    const out: string[] = [];
    const pagePath = page.pagePath.toLowerCase();
    for (const c of csCtx?.pageConventions ?? []) {
      if ((c.area ?? '').toLowerCase() !== (page.area ?? '').toLowerCase()) continue;
      const p = c.path.toLowerCase().replace(/\/+$/, '');
      const hit = c.scope === 'page' ? pagePath === p : p === '' || pagePath === p || pagePath.startsWith(`${p}/`);
      if (hit) out.push(c.text);
    }
    return out;
  }

  function razorPageEntries(): RawEntry[] {
    const out: RawEntry[] = [];
    for (const cls of types.values()) {
      if (cls.node.type !== 'class_declaration') continue;
      const mods = named(cls.node).filter((c) => c.type === 'modifier').map((c) => c.text);
      if (mods.includes('abstract') || mods.includes('static')) continue;
      const isPageModel = cls.bases.includes('PageModel') || inheritedOf(cls).some((x) => x.bases.includes('PageModel'));
      if (!isPageModel) continue;
      const page = pageOf(cls);
      if (!page) continue;
      const signals = [...inheritedAuthOf(cls), ...pageConventionSignals(page), ...(csCtx?.razorConventions ?? []).filter((c) => /^(RequireAuthorization|AllowAnonymous)\(/.test(c))];
      for (const m of named(cls.node.childForFieldName('body'))) {
        if (m.type !== 'method_declaration') continue;
        const mm = named(m).filter((c) => c.type === 'modifier').map((c) => c.text);
        if (!mm.includes('public') || mm.includes('static')) continue;
        const hm = PAGE_HANDLER_RE.exec(m.childForFieldName('name')?.text ?? '');
        if (!hm || attributesOf(m).some((a) => a.name === 'NonHandler')) continue;
        const symbolId = fnIds.get(m.id);
        if (!symbolId) continue;
        out.push({
          ruleId: RAZOR_PAGE_RULE_ID, framework: 'aspnetcore', httpMethod: hm[1]!.toUpperCase(), pathTemplate: pageRoute(page, hm[2] ?? ''),
          handler: { symbolId }, path: input.path, range: rangeOf(m), middlewares: [...(csCtx?.razorConventions ?? [])], authSignals: [...new Set(signals)],
        });
      }
    }
    return out;
  }

  // ---- gRPC services -----------------------------------------------------------------------------

  /**
   * `class GreeterService : Greeter.GreeterBase` with `public override` rpc methods. `XxxBase` counts as a gRPC base
   * only when the .proto declares service Xxx or the class is registered with `MapGrpcService<T>()`.
   */
  function grpcEntries(): RawEntry[] {
    const out: RawEntry[] = [];
    for (const cls of types.values()) {
      if (cls.node.type !== 'class_declaration') continue;
      const registered = csCtx?.grpcServices[cls.name];
      const service = [...cls.bases, ...inheritedOf(cls).flatMap((x) => x.bases)].map((b) => /^(\w+)Base$/.exec(b)?.[1]).find((s) => !!s && (input.grpcServices?.some((g) => g.name === s) || registered !== undefined));
      if (!service) continue;
      const conventions = registered ?? [];
      const interceptors = csCtx?.grpcInterceptors ?? [];
      const signals = [...inheritedAuthOf(cls), ...conventions.filter((c) => /^(RequireAuthorization|AllowAnonymous)\(/.test(c)), ...interceptors.filter((i) => AUTH_NAME_RE.test(i))];
      for (const m of named(cls.node.childForFieldName('body'))) {
        if (m.type !== 'method_declaration') continue;
        const mm = named(m).filter((c) => c.type === 'modifier').map((c) => c.text);
        if (!mm.includes('public') || !mm.includes('override')) continue;
        const rpc = rpcOf(input.grpcServices, service, m.childForFieldName('name')?.text ?? '');
        const symbolId = fnIds.get(m.id);
        if (!rpc || !symbolId) continue;
        out.push({
          rpc, ruleId: 'csharp.grpc.service', framework: 'grpc', httpMethod: 'RPC', pathTemplate: '', handler: { symbolId }, path: input.path,
          range: rangeOf(m), middlewares: [...conventions, ...interceptors], authSignals: [...new Set(signals)],
        });
      }
    }
    return out;
  }

  // ---- SignalR hubs -----------------------------------------------------------------------------

  /**
   * Hub methods clients can invoke: public instance methods of non-abstract `Hub` / `Hub<T>` subclasses (lifecycle
   * overrides excluded). Entry kind `rpc`, key `rpc:signalr:<hub path>/<method>` (the hub path from `MapHub<T>("/x")`,
   * else the class name) — not a gRPC service, so it never becomes a gRPC connection.
   */
  function hubEntries(): RawEntry[] {
    const out: RawEntry[] = [];
    for (const cls of types.values()) {
      if (cls.node.type !== 'class_declaration') continue;
      const mods = named(cls.node).filter((c) => c.type === 'modifier').map((c) => c.text);
      if (mods.includes('abstract') || mods.includes('static')) continue;
      if (![...cls.bases, ...inheritedOf(cls).flatMap((x) => x.bases)].includes('Hub')) continue;
      const registrations = csCtx?.hubs[cls.name] ?? [{ path: cls.name, conventions: [] }];
      const filters = csCtx?.hubFilters ?? [];
      for (const m of named(cls.node.childForFieldName('body'))) {
        if (m.type !== 'method_declaration') continue;
        const mm = named(m).filter((c) => c.type === 'modifier').map((c) => c.text);
        const name = m.childForFieldName('name')?.text ?? '';
        if (!mm.includes('public') || mm.includes('static') || /^(OnConnectedAsync|OnDisconnectedAsync|Dispose)$/.test(name)) continue;
        const attrs = attributesOf(m);
        const method = attrs.find((a) => a.name === 'HubMethodName')?.positional[0] ?? name;
        const symbolId = fnIds.get(m.id);
        if (!symbolId) continue;
        for (const r of registrations) {
          const signals = [...inheritedAuthOf(cls), ...r.conventions.filter((c) => /^(RequireAuthorization|AllowAnonymous)\(/.test(c)), ...filters.filter((f) => AUTH_NAME_RE.test(f))];
          out.push({
            rpc: { service: `signalr:${r.path}`, method }, ruleId: 'csharp.signalr.hub', framework: 'signalr', httpMethod: 'RPC', pathTemplate: '',
            handler: { symbolId }, path: input.path, range: rangeOf(m), middlewares: [...r.conventions, ...filters], authSignals: [...new Set(signals)],
          });
        }
      }
    }
    return out;
  }

  // ---- socket / message / schedule / cli entries -----------------------------------------------

  /**
   * Non-HTTP entry points (kind from `channel`): raw WebSockets (`AcceptWebSocketAsync` in a mapped lambda, a
   * middleware or an action), message consumers (MassTransit, NServiceBus, Confluent Kafka, Azure Service Bus,
   * Azure Functions triggers), schedules (Hangfire, Quartz, BackgroundService, TimerTrigger) and CLI commands
   * (System.CommandLine, CommandLineParser, Spectre.Console). Azure Functions `[HttpTrigger]` become http entries.
   */
  function channelEntries(): RawEntry[] {
    const out: RawEntry[] = [];
    const push = (
      kind: 'socket' | 'message' | 'schedule' | 'cli', protocol: string, key: string, route: string, ruleId: string, framework: string,
      handler: HandlerRef, at: Node, extra: { middlewares?: string[]; authSignals?: string[] } = {},
    ) => out.push({
      channel: { kind, protocol, key, route }, ruleId, framework, httpMethod: '', pathTemplate: '', handler, path: input.path, range: rangeOf(at),
      middlewares: extra.middlewares ?? [], authSignals: [...new Set(extra.authSignals ?? [])],
    });
    const mods = (n: Node) => named(n).filter((c) => c.type === 'modifier').map((c) => c.text);
    const bodyOf = (cls: TypeInfo) => named(cls.node.childForFieldName('body'));
    const methodsOf = (cls: TypeInfo, re: RegExp) => bodyOf(cls)
      .filter((m) => m.type === 'method_declaration' && re.test(m.childForFieldName('name')?.text ?? '') && !mods(m).includes('static') && fnIds.has(m.id));
    const rawBases = (cls: TypeInfo) => named(named(cls.node).find((c) => c.type === 'base_list')).map((b) => oneLine(b.text));
    const allBases = (cls: TypeInfo) => [...cls.bases, ...inheritedOf(cls).flatMap((x) => x.bases)];
    const concrete = (cls: TypeInfo) => cls.node.type === 'class_declaration' && !mods(cls.node).some((m) => m === 'abstract' || m === 'static');
    const short = (sym: string) => sym.replace(/^[^#]*#/, '').replace(/\(\d+\)$/, '').split('.').slice(-2).join('.');
    const methodSym = (typeName: string | null, name: string): string | undefined =>
      fx.symbols.find((s) => s.kind === 'method' && s.name === name && (typeName === null || s.container.split('.').pop() === typeName))?.symbolId;
    const fnDecls = root.descendantsOfType(['method_declaration', 'constructor_declaration', 'local_function_statement']).filter((n): n is Node => !!n);
    const fnNode = (sym: string | undefined): Node | undefined => (sym ? fnDecls.find((n) => fnIds.get(n.id) === sym) : undefined);
    const pathIn = (text: string) => /\bPath\s*==\s*"(\/[^"]*)"|\bStartsWithSegments\s*\(\s*"(\/[^"]*)"|"(\/[^"]*)"\s*==\s*[\w.]*\bPath\b/.exec(text)?.slice(1).find((x) => x !== undefined);
    const typeArg = (call: Node): string | null => {
      const fn = call.childForFieldName('function');
      const nm = fn?.type === 'member_access_expression' ? fn.childForFieldName('name') : fn;
      const ta = nm?.type === 'generic_name' ? named(nm).find((c) => c.type === 'type_argument_list') : undefined;
      return ta ? csType(named(ta)[0]?.text ?? '') || null : null;
    };
    const lambdaOf = (n: Node | undefined) => (n && ['lambda_expression', 'anonymous_method_expression'].includes(unwrap(n).type) ? unwrap(n) : null);
    const ACCEPT_RE = /\bAcceptWebSocketAsync\s*\(/;

    // Raw WebSockets: the outermost mapped / pipeline delegate that accepts the socket, then methods that do.
    const covered: Node[] = [];
    const inside = (n: Node) => covered.some((c) => n.startIndex >= c.startIndex && n.endIndex <= c.endIndex);
    for (const call of root.descendantsOfType('invocation_expression')) {
      if (!call || inside(call)) continue;
      const parts = invocationParts(call);
      if (!parts?.receiver || !/^(Map|MapGet|MapPost|MapWhen|Use|UseWhen|Run)$/.test(parts.method)) continue;
      const args = argsOf(call.childForFieldName('arguments'));
      const fn = args.map((a) => lambdaOf(a)).find((l) => !!l && ACCEPT_RE.test(l.text)) ?? null;
      const mapped = /^Map(Get|Post)?$/.test(parts.method);
      const group = !fn && mapped && args[1] && !lambdaOf(args[1]) ? handlerRef(args[1]) : null;
      const groupNode = fnNode(group?.ref.symbolId);
      if (!fn && !(groupNode && ACCEPT_RE.test(groupNode.text))) continue;
      covered.push(call);
      if (groupNode) covered.push(groupNode);
      const literal = mapped ? stringOf(args[0]) : null;
      const path = literal !== null ? stripRouteConstraints(joinRoute(resolveRouter(parts.receiver, call.startIndex).prefix, literal)) : pathIn((fn ?? groupNode)!.text);
      const ref = fn ? handlerRef(fn).ref : group!.ref;
      const name = path ?? (ref.symbolId ? short(ref.symbolId) : 'anonymous');
      push('socket', 'websocket', `ws:${name}`, name, 'csharp.websocket', 'aspnetcore', ref, call);
    }
    for (const cls of types.values()) {
      for (const m of bodyOf(cls)) {
        const symbolId = fnIds.get(m.id);
        if (!symbolId || inside(m)) continue;
        const accepts = m.descendantsOfType('invocation_expression').some((c) => !!c && invocationParts(c)?.method === 'AcceptWebSocketAsync' && !inside(c));
        if (!accepts) continue;
        // Path: compared in the method, else the action's route, else `app.Map("/ws", Class.Method)` / `b => b.UseMiddleware<T>()`.
        const action = fx.entries.find((e) => !e.channel && !e.rpc && e.handler.symbolId === symbolId);
        const own = pathIn(m.text);
        const mname = `${cls.name}.${m.childForFieldName('name')?.text ?? '?'}`;
        const paths = own ? [own] : action ? [action.pathTemplate] : csCtx?.wsMiddlewares?.[mname] ?? csCtx?.wsMiddlewares?.[cls.name] ?? [mname];
        for (const p of paths) {
          push('socket', 'websocket', `ws:${p}`, p, 'csharp.websocket', 'aspnetcore', { symbolId }, m,
            { middlewares: action?.middlewares ?? [], authSignals: [...inheritedAuthOf(cls), ...(action?.authSignals ?? [])] });
        }
      }
    }

    // Message handlers, schedules and commands declared by class shape.
    for (const cls of types.values()) {
      if (!concrete(cls)) continue;
      const inherited = inheritedAuthOf(cls);
      for (const b of rawBases(cls)) {
        const g = /^(?:[\w.]+\.)?(IConsumer|IHandleMessages|IAmStartedByMessages)\s*<(.+)>$/.exec(b);
        if (!g) continue;
        const msg = csType(g[2]!);
        const mt = g[1] === 'IConsumer'
          ? { protocol: 'masstransit', ruleId: 'csharp.masstransit.consumer', method: /^Consume$/ }
          : { protocol: 'nservicebus', ruleId: 'csharp.nservicebus.handler', method: /^Handle$/ };
        const ms = methodsOf(cls, mt.method);
        // Several IConsumer<A>, IConsumer<B>: the overload whose parameter carries the message type.
        const typed = ms.find((x) => named(x.childForFieldName('parameters')).some((p) => {
          const t = p.childForFieldName('type')?.text ?? '';
          return csType(t) === msg || new RegExp(`<\\s*(?:[\\w.]+\\.)?${msg}\\s*>`).test(t);
        }));
        const m = typed ?? ms[0];
        if (!m) continue;
        push('message', mt.protocol, `mq:${mt.protocol}:${msg}`, msg, mt.ruleId, mt.protocol, { symbolId: fnIds.get(m.id)! }, m, { authSignals: inherited });
      }
      const bases = allBases(cls);
      if (bases.includes('IJob') && (imports.has('Quartz') || bodyOf(cls).some((m) => /\bIJobExecutionContext\b/.test(m.childForFieldName('parameters')?.text ?? '')))) {
        for (const m of methodsOf(cls, /^Execute$/)) {
          for (const cron of csCtx?.quartzCrons?.[cls.name] ?? ['']) {
            push('schedule', 'cron', `cron:${cls.name}.Execute`, cron, 'csharp.quartz.job', 'quartz', { symbolId: fnIds.get(m.id)! }, m, { authSignals: inherited });
          }
        }
      }
      if (bases.includes('BackgroundService')) {
        for (const m of methodsOf(cls, /^ExecuteAsync$/)) {
          push('schedule', 'hosted-service', `cron:${cls.name}.ExecuteAsync`, '', 'csharp.hosted.service', 'dotnet-hosting', { symbolId: fnIds.get(m.id)! }, m, { authSignals: inherited });
        }
      }
      if (bases.some((b) => /^(Command|AsyncCommand)$/.test(b))) {
        // Spectre.Console.Cli: `class AddCommand : Command<AddSettings>` / `AsyncCommand<T>` with Execute(CommandContext …);
        // the name from `config.AddCommand<AddCommand>("add")`, else the class name.
        const exec = methodsOf(cls, /^(Execute|ExecuteAsync)$/).find((m) => /\bCommandContext\b/.test(m.childForFieldName('parameters')?.text ?? ''));
        if (exec) {
          for (const n of csCtx?.cliCommands?.[cls.name] ?? [slugify(cls.name.replace(/Command$/, '') || cls.name)]) {
            push('cli', 'cli', `cli:${n}`, n, 'csharp.cli.command', 'spectre-console', { symbolId: fnIds.get(exec.id)! }, exec, { authSignals: inherited });
          }
        } else {
          // System.CommandLine subclass: `public AddCommand() : base("add", "…") { this.SetHandler(…); }`.
          for (const ctor of bodyOf(cls).filter((c) => c.type === 'constructor_declaration' && fnIds.has(c.id))) {
            const init = named(ctor).find((c) => c.type === 'constructor_initializer');
            const name = init && /^:\s*base\b/.test(init.text) ? stringOf(argsOf(named(init).find((c) => c.type === 'argument_list'))[0]) : null;
            if (!name) continue;
            const set = ctor.descendantsOfType('invocation_expression').find((c) => !!c && /^(SetHandler|SetAction)$/.test(invocationParts(c)?.method ?? ''));
            const h = set ? argsOf(set.childForFieldName('arguments'))[0] : undefined;
            push('cli', 'cli', `cli:${name}`, name, 'csharp.cli.command', 'system-commandline', h ? handlerRef(h).ref : { symbolId: fnIds.get(ctor.id)! }, ctor, { authSignals: inherited });
          }
        }
      }
      // CommandLineParser: `[Verb("add")] class AddOptions`; the handler is `WithParsed<AddOptions>(RunAdd)` when in this file.
      const verb = attributesOf(cls.node).find((a) => a.name === 'Verb');
      const verbName = verb?.namedArgs.get('name') ?? verb?.positional[0];
      if (verbName) {
        const parsed = root.descendantsOfType('invocation_expression').find((c) => !!c && invocationParts(c)?.method === 'WithParsed' && typeArg(c) === cls.name);
        const h = parsed ? argsOf(parsed.childForFieldName('arguments'))[0] : undefined;
        push('cli', 'cli', `cli:${verbName}`, verbName, 'csharp.cli.command', 'commandlineparser', h ? handlerRef(h).ref : { symbolId: cls.symbolId }, cls.node);
      }
    }

    // Azure Functions: trigger attributes on a function's parameters.
    for (const cls of types.values()) {
      for (const m of bodyOf(cls)) {
        const symbolId = fnIds.get(m.id);
        if (m.type !== 'method_declaration' || !symbolId) continue;
        const methodName = m.childForFieldName('name')?.text ?? '?';
        const ref: HandlerRef = { symbolId };
        for (const p of named(m.childForFieldName('parameters'))) {
          if (p.type !== 'parameter') continue;
          for (const a of attributesOf(p)) {
            const pos = a.positional;
            const arg = (k: string) => a.namedArgs.get(k);
            if (a.name === 'TimerTrigger') {
              push('schedule', 'cron', `cron:${cls.name}.${methodName}`, arg('Schedule') ?? pos[0] ?? '', 'csharp.azure.function', 'azure-functions', ref, m);
            } else if (a.name === 'HttpTrigger') {
              // http entry: `/api/<Route or function name>` (the default host prefix); function keys count as an auth signal.
              const fname = attributesOf(m).find((x) => x.name === 'Function' || x.name === 'FunctionName')?.positional[0] ?? methodName;
              const level = pos.find((x) => /AuthorizationLevel\./.test(x));
              const verbs = pos.filter((x) => /^[a-zA-Z]+$/.test(x) && x !== 'null').map((x) => x.toUpperCase());
              const route = stripRouteConstraints(joinRoute('/api', arg('Route') ?? fname));
              for (const v of verbs.length ? verbs : ['ANY']) {
                out.push({
                  ruleId: 'csharp.azure.function', framework: 'azure-functions', httpMethod: v, pathTemplate: route, handler: ref, path: input.path, range: rangeOf(m),
                  middlewares: [], authSignals: level && !/Anonymous$/.test(level) ? [`[HttpTrigger(${level})]`] : [],
                });
              }
            } else {
              const sb = arg('QueueName') ?? (arg('TopicName') ? `${arg('TopicName')}/${arg('SubscriptionName') ?? ''}` : pos.length >= 2 ? `${pos[0]}/${pos[1]}` : pos[0]);
              const trig: Record<string, [string, string | undefined]> = {
                ServiceBusTrigger: ['azure-servicebus', sb],
                QueueTrigger: ['azure-storage-queue', arg('QueueName') ?? pos[0]],
                KafkaTrigger: ['kafka', arg('Topic') ?? pos[1]],
                EventHubTrigger: ['azure-eventhubs', arg('EventHubName') ?? arg('eventHubName') ?? pos[0]],
                RabbitMQTrigger: ['rabbitmq', arg('QueueName') ?? pos[0]],
              };
              const t = trig[a.name];
              if (!t) continue;
              const name = t[1] ?? '{?}';
              push('message', t[0], `mq:${t[0]}:${name}`, name, 'csharp.azure.function', 'azure-functions', ref, m);
            }
          }
        }
      }
    }

    // Calls: System.CommandLine `new Command("x")`, Confluent Kafka `Subscribe`, Azure Service Bus processors, Hangfire recurring jobs.
    for (const call of root.descendantsOfType(['invocation_expression', 'object_creation_expression'])) {
      if (!call) continue;
      if (call.type === 'object_creation_expression') {
        if (csType(call.childForFieldName('type')?.text ?? '') !== 'Command') continue;
        const name = stringOf(argsOf(call.childForFieldName('arguments'))[0]);
        if (!name) continue;
        // `var add = new Command("add")` + `add.SetHandler(h)` / `add.SetAction(h)` / `add.Handler = CommandHandler.Create(h)`, or `{ Handler = … }`.
        const decl = call.parent?.type === 'equals_value_clause' ? call.parent.parent : call.parent;
        const v = decl?.type === 'variable_declarator' ? decl.childForFieldName('name')?.text : decl?.type === 'assignment_expression' ? decl.childForFieldName('left')?.text : undefined;
        let h: Node | null = null;
        for (const c of (enclosingFn(call) ?? root).descendantsOfType(['invocation_expression', 'assignment_expression'])) {
          if (!c) continue;
          if (c.type === 'invocation_expression') {
            const parts = invocationParts(c);
            if (v && parts?.receiver?.text === v && /^(SetHandler|SetAction)$/.test(parts.method)) { h = argsOf(c.childForFieldName('arguments'))[0] ?? null; break; }
            continue;
          }
          const left = c.childForFieldName('left')?.text ?? '';
          if (!(v && left === `${v}.Handler`) && !(left === 'Handler' && c.parent?.type === 'initializer_expression' && c.parent.parent?.id === call.id)) continue;
          const r = c.childForFieldName('right');
          h = r && unwrap(r).type === 'invocation_expression' ? argsOf(unwrap(r).childForFieldName('arguments'))[0] ?? null : r;
          break;
        }
        if (h) push('cli', 'cli', `cli:${name}`, name, 'csharp.cli.command', 'system-commandline', handlerRef(h).ref, call);
        continue;
      }
      const parts = invocationParts(call);
      if (!parts?.receiver) continue;
      const args = argsOf(call.childForFieldName('arguments'));
      const sym = enclosingSymbol(call);
      const here: HandlerRef = sym ? { symbolId: sym } : { range: rangeOf(call) };
      if (parts.method === 'Subscribe' && args.length) {
        // Confluent.Kafka: consumer.Subscribe("orders") / Subscribe(new[] { "a", "b" }); Rx `Subscribe(x => …)` is not one.
        const r = receiverFacts(parts.receiver, call);
        if (!imports.has('Confluent.Kafka') && !/^I?Consumer$/.test(r.type ?? '')) continue;
        const a0 = unwrap(args[0]!);
        if (lambdaOf(a0)) continue;
        const one = stringOf(a0);
        const topics = one !== null ? [one] : a0.descendantsOfType(['string_literal', 'verbatim_string_literal']).filter((x): x is Node => !!x).map(literalText);
        for (const t of topics.length ? topics : ['{?}']) push('message', 'kafka', `mq:kafka:${t}`, t, 'csharp.kafka.consumer', 'confluent-kafka', here, call);
      } else if (/^(CreateProcessor|CreateSessionProcessor)$/.test(parts.method) && args.length) {
        // Azure.Messaging.ServiceBus: client.CreateProcessor("queue") / ("topic", "subscription"); handler from `ProcessMessageAsync += H`.
        const r = receiverFacts(parts.receiver, call);
        if (!imports.has('Azure.Messaging.ServiceBus') && r.type !== 'ServiceBusClient') continue;
        const q = stringOf(args[0]);
        const sub = args[1] ? stringOf(args[1]) : null;
        const name = q === null ? '{?}' : sub ? `${q}/${sub}` : q;
        const assign = (enclosingType(call)?.node ?? root).descendantsOfType('assignment_expression')
          .find((x) => !!x && /(^|\.)ProcessMessageAsync$/.test(x.childForFieldName('left')?.text ?? '') && assignOp(x) === '+=');
        const right = assign?.childForFieldName('right');
        push('message', 'azure-servicebus', `mq:azure-servicebus:${name}`, name, 'csharp.azure.servicebus.processor', 'azure-servicebus', right ? handlerRef(right).ref : here, call);
      } else if (parts.method === 'AddOrUpdate') {
        // Hangfire: RecurringJob.AddOrUpdate("id", () => x.Run(), Cron.Daily) / AddOrUpdate<T>("id", t => t.Run(), "0 * * * *").
        const r = receiverFacts(parts.receiver, call);
        if (!/(^|\.)RecurringJob$/.test(parts.receiver.text) && !/^I?RecurringJobManager(V2)?$/.test(r.type ?? '')) continue;
        const li = args.findIndex((a) => !!lambdaOf(a));
        if (li < 0) continue;
        const body = lambdaOf(args[li])!.childForFieldName('body');
        const inv = body ? (unwrap(body).type === 'invocation_expression' ? unwrap(body) : body.descendantsOfType('invocation_expression')[0] ?? null) : null;
        const ip = inv ? invocationParts(inv) : null;
        if (!inv || !ip) continue;
        const owner = typeArg(call)
          ?? (ip.receiver ? receiverFacts(ip.receiver, inv).type ?? (/^[A-Z]\w*$/.test(ip.receiver.text) ? ip.receiver.text : null) : enclosingType(call)?.name ?? null);
        const target = owner ? `${owner}.${ip.method}` : ip.method;
        const id = li > 0 ? stringOf(args[0]) : null;
        const cronArg = args[li + 1];
        const cron = cronArg ? stringOf(cronArg) ?? oneLine(cronArg.text) : '';
        const s = methodSym(owner, ip.method);
        push('schedule', 'cron', `cron:${id ?? target}`, cron, 'csharp.hangfire.recurring', 'hangfire', s ? { symbolId: s } : { text: target, ...(owner ? { className: owner } : {}) }, call);
      }
    }
    return out;
  }

  function stringOf(n: Node | null | undefined): string | null {
    if (!n) return null;
    const x = unwrap(n);
    if (/string_literal$/.test(x.type)) return literalText(x);
    if (x.type === 'interpolated_string_expression') {
      return named(x).map((c) => (c.type === 'interpolation' ? '{?}' : c.type === 'string_content' ? c.text : '')).join('');
    }
    if (x.type === 'binary_expression') {
      const l = stringOf(x.childForFieldName('left'));
      const r = stringOf(x.childForFieldName('right'));
      return l !== null && r !== null ? l + r : null;
    }
    if (x.type === 'identifier') {
      const v = resolved(x).values;
      return v.length === 1 && v[0]!.id !== x.id ? stringOf(v[0]) : null;
    }
    if (x.type === 'member_access_expression') {
      const f = constFields.get(x.childForFieldName('name')?.text ?? '');
      return f ? stringOf(f) : null;
    }
    return null;
  }

  function conventionText(call: Node, name: string): string {
    const args = call.childForFieldName('arguments')?.text ?? '()';
    const fn = call.childForFieldName('function');
    const nameNode = fn?.type === 'member_access_expression' ? fn.childForFieldName('name') : null;
    return truncate(oneLine(`${nameNode?.text ?? name}${args}`), 160);
  }

  /** Router expression → (prefix, conventions) following MapGroup and endpoint-convention chains. */
  function resolveRouter(node: Node, pos: number, depth = 0): { prefix: string; conventions: string[] } {
    if (depth > 8) return { prefix: '', conventions: [] };
    const n = unwrap(node);
    if (n.type === 'invocation_expression') {
      const parts = invocationParts(n);
      if (!parts?.receiver) return { prefix: '', conventions: [] };
      const parent = resolveRouter(parts.receiver, pos, depth + 1);
      if (parts.method === 'MapGroup') {
        const p = stringOf(argsOf(n.childForFieldName('arguments'))[0]) ?? '{?}';
        return { prefix: joinRoute(parent.prefix, p), conventions: parent.conventions };
      }
      if (CONVENTION_RE.test(parts.method)) return { prefix: parent.prefix, conventions: [...parent.conventions, conventionText(n, parts.method)] };
      return parent;
    }
    if (n.type === 'identifier') {
      const scope = scopeOf(n);
      let base: { prefix: string; conventions: string[] } = { prefix: '', conventions: [] };
      const decl = [...valuesIn(scope).get(n.text)?.values ?? []].filter((v) => v.startIndex < pos).pop();
      if (decl) base = resolveRouter(decl, decl.startIndex, depth + 1);
      // Statement-level conventions / middlewares on this router before the route (`g.RequireAuthorization();`, `app.UseMiddleware<X>();`).
      const later = statementConventions(scope).filter((s) => s.router === n.text && s.pos < pos).map((s) => s.text);
      return { prefix: base.prefix, conventions: [...base.conventions, ...later] };
    }
    return { prefix: '', conventions: [] };
  }

  function statementConventions(scope: Node): { router: string; pos: number; text: string }[] {
    let list = stmtCache.get(scope.id);
    if (list) return list;
    list = [];
    for (const stmt of scope.descendantsOfType('invocation_expression')) {
      if (!stmt || stmt.parent?.type !== 'expression_statement') continue;
      const parts = invocationParts(stmt);
      const recv = parts?.receiver ? unwrap(parts.receiver) : null;
      if (!parts || recv?.type !== 'identifier') continue;
      if (CONVENTION_RE.test(parts.method) || PIPELINE_RE.test(parts.method) || (/^Use[A-Z]\w*$/.test(parts.method) && AUTH_NAME_RE.test(parts.method))) {
        list.push({ router: recv.text, pos: stmt.startIndex, text: conventionText(stmt, parts.method) });
      }
    }
    stmtCache.set(scope.id, list);
    return list;
  }

  function minimalEntries(ruleId: string, cap: Map<string, Node>): { entries: RawEntry[]; methodGroup: boolean } {
    const call = cap.get('call');
    const router = cap.get('router');
    const verb = cap.get('verb')?.text ?? '';
    if (!call || !router) return { entries: [], methodGroup: false };
    const args = argsOf(cap.get('args'));
    const path = stringOf(args[0]);
    if (path === null) return { entries: [], methodGroup: false };
    let methods: string[];
    let handler: Node | undefined;
    if (verb === 'MapMethods') {
      methods = (args[1] ? args[1].descendantsOfType(['string_literal', 'verbatim_string_literal']).filter((x): x is Node => !!x).map((x) => literalText(x).toUpperCase()) : []);
      if (!methods.length) methods = ['ANY'];
      handler = args[2];
    } else {
      methods = [MAP_VERB[verb] ?? 'ANY'];
      handler = args[1];
    }
    if (!handler) return { entries: [], methodGroup: false };
    const r = resolveRouter(router, call.startIndex);
    // Conventions chained on the endpoint itself: `app.MapGet(…).RequireAuthorization()`.
    const own: string[] = [];
    let cur: Node = call;
    while (cur.parent?.type === 'member_access_expression' && cur.parent.childForFieldName('expression')?.id === cur.id && cur.parent.parent?.type === 'invocation_expression') {
      const inv = cur.parent.parent;
      const name = cur.parent.childForFieldName('name')?.text ?? '';
      if (CONVENTION_RE.test(name)) own.push(conventionText(inv, name));
      cur = inv;
    }
    const middlewares = [...r.conventions, ...own];
    const authSignals = middlewares.filter((m) => /^(RequireAuthorization|AllowAnonymous)\b/.test(m) || (AUTH_NAME_RE.test(m) && !/^Use(Authentication|Authorization)\(/.test(m)));
    const h = handlerRef(handler);
    const fullPath = stripRouteConstraints(joinRoute(r.prefix, path));
    return {
      entries: methods.map((m) => ({ ruleId, framework: 'aspnetcore', httpMethod: m, pathTemplate: fullPath, handler: h.ref, path: input.path, range: rangeOf(call), middlewares, authSignals })),
      methodGroup: !h.lambda,
    };
  }

  function handlerRef(n: Node): { ref: HandlerRef; lambda: boolean } {
    const x = unwrap(n);
    if (x.type === 'lambda_expression' || x.type === 'anonymous_method_expression') {
      const sym = enclosingSymbol(x);
      return { ref: { ...(sym ? { symbolId: sym } : {}), range: rangeOf(x) }, lambda: true };
    }
    const byName = (typeName: string | null, name: string): string | undefined => {
      for (const s of fx.symbols) {
        if (s.kind !== 'method' || s.name !== name) continue;
        if (typeName === null || s.container.split('.').pop() === typeName) return s.symbolId;
      }
      return undefined;
    };
    if (x.type === 'identifier') {
      const own = enclosingType(x)?.name ?? (inGlobal(x) ? 'Program' : null);
      const id = byName(own, x.text);
      return { ref: id ? { symbolId: id } : { text: x.text }, lambda: false };
    }
    if (x.type === 'member_access_expression') {
      const typeName = x.childForFieldName('expression')?.text.split('.').pop() ?? null;
      const id = byName(typeName, x.childForFieldName('name')?.text ?? '');
      return { ref: id ? { symbolId: id } : { text: x.text }, lambda: false };
    }
    return { ref: { text: truncate(x.text, 120) }, lambda: false };
  }

  function authSignal(ruleId: string, post: string | undefined, cap: Map<string, Node>): AuthSignal | null {
    if (post === 'csharp_auth_attribute') {
      const attr = cap.get('attribute');
      if (!attr) return null;
      const owner = attr.parent?.parent; // attribute_list → declaration
      if (!owner) return null;
      const target = METHOD_DECLS.has(owner.type) ? fnIds.get(owner.id) : TYPE_DECLS.has(owner.type) ? types.get(owner.id)?.symbolId : undefined;
      if (!target) return null;
      return { target, kind: 'annotation', detail: truncate(`[${oneLine(attr.text)}]`, 200), ruleId };
    }
    if (post === 'csharp_pipeline_auth') {
      const call = cap.get('call');
      const name = cap.get('method')?.text ?? '';
      if (!call) return null;
      if (name === 'RequireAuthorization' && !/Map(Controllers|DefaultControllerRoute|ControllerRoute|RazorPages|Hub|Blazor)/.test(call.text)) return null;
      // Nested configuration (`AddAuthorization(o => o.AddPolicy(…))`) is reported with the enclosing call.
      for (let p: Node | null = call.parent; p; p = p.parent) {
        if (p.type === 'invocation_expression' && PIPELINE_CONFIG_RE.test(invocationParts(p)?.method ?? '') && !isChainOf(p, call)) return null;
      }
      // Report the outermost call of a fluent chain once.
      let outer: Node = call;
      while (outer.parent?.type === 'member_access_expression' && outer.parent.parent?.type === 'invocation_expression' && outer.parent.childForFieldName('expression')?.id === outer.id) outer = outer.parent.parent;
      const target = enclosingSymbol(outer) ?? `${input.repo}:${input.path}`;
      const kind: AuthSignal['kind'] = /^Use/.test(name) ? 'middleware' : 'security_config';
      return { target, kind, detail: truncate(oneLine(outer.text), 300), ruleId };
    }
    if (post === 'csharp_filter_class') {
      const cls = cap.get('class');
      if (!cls) return null;
      const info = types.get(cls.id);
      if (!info) return null;
      const sup = cap.get('super')?.text ?? '';
      if (!sup && !named(info.node.childForFieldName('body')).some((m) => m.type === 'method_declaration' && /^(Invoke|InvokeAsync)$/.test(m.childForFieldName('name')?.text ?? ''))) return null;
      const kind: AuthSignal['kind'] = /Middleware$/.test(sup || info.name) ? 'middleware' : 'filter';
      return { target: info.symbolId, kind, detail: sup ? `${info.name} : ${csType(sup)}` : `${info.name} (middleware)`, ruleId };
    }
    return null;
  }
}
