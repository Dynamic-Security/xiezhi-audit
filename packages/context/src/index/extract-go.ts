// Go extraction: symbols, imports, calls, sinks, gin/echo/net/http routes (group prefixes and
// middleware chains in registration order), gRPC services and gqlgen GraphQL resolvers.
import type { Node, Tree } from 'web-tree-sitter';
import {
  AUTH_NAME_RE, captureMap, fillApi, makeSink, rangeOf, ruleMatches, taintHintOf, unquote, type CompiledRule,
} from './common.js';
import { graphqlEntryOf } from './graphql.js';
import { rpcOf } from './proto.js';
import { emptyExtract, joinRoute, type ExtractInput, type FileExtract, type HandlerRef, type RawEntry } from './types.js';

const FUNC_TYPES = new Set(['function_declaration', 'method_declaration']);
/** Request string sources (gorilla/mux, gin, echo, chi, net/http, fiber, iris). */
const REQUEST_STRING_RE = /mux\.Vars\(|\.(Param|Params|Query|DefaultQuery|QueryParam|FormValue|PostFormValue|PostForm|GetString|PathValue|URLParam)\(|URL\.Query\(\)|chi\.URLParam\(|\.Header\.Get\(/;
const NUMERIC_RE = /strconv\.|\.Parse(Int|Uint|Float)|cast\.To(Int|Uint)|\.(GetInt|GetUint|ParamsInt|QueryInt)\(/;
const CONCAT_ARG_RE = /\+|Sprint/;

export function defaultAlias(importPath: string): string {
  const parts = importPath.split('/');
  let last = parts[parts.length - 1] ?? importPath;
  if (/^v\d+$/.test(last) && parts.length > 1) last = parts[parts.length - 2]!;
  last = last.replace(/\.v\d+$/, '').replace(/^go-/, '').replace(/-go$/, '');
  return last.replace(/[^A-Za-z0-9_]/g, '');
}

function receiverTypeName(method: Node): string {
  const recv = method.childForFieldName('receiver');
  const t = recv?.descendantsOfType('type_identifier')[0];
  return t?.text ?? '?';
}

export function extractGo(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const root = tree.rootNode;
  const pkgName = root.namedChildren.find((n) => n?.type === 'package_clause')?.namedChildren[0]?.text ?? 'main';
  const relDir = input.path.includes('/') ? input.path.slice(0, input.path.lastIndexOf('/')) : '';
  const modDir = input.goModuleDir ?? '';
  const sub = modDir && relDir.startsWith(modDir) ? relDir.slice(modDir.length).replace(/^\//, '') : relDir;
  const importPath = input.goModule ? (sub ? `${input.goModule}/${sub}` : input.goModule) : (relDir || pkgName);
  fx.pkg = importPath;
  fx.pkgName = pkgName;

  // ---- imports ----
  const aliases = new Map<string, string>();
  const imports = new Set<string>();
  for (const spec of root.descendantsOfType('import_spec')) {
    if (!spec) continue;
    const p = unquote(spec.childForFieldName('path')?.text ?? '');
    if (!p) continue;
    imports.add(p);
    const name = spec.childForFieldName('name')?.text;
    if (name === '_' || name === '.') continue;
    aliases.set(name ?? defaultAlias(p), p);
  }

  // ---- symbols ----
  const funcIds = new Map<number, string>();
  for (const fn of root.namedChildren) {
    if (!fn || !FUNC_TYPES.has(fn.type)) continue;
    const name = fn.childForFieldName('name')?.text ?? '?';
    const params = fn.childForFieldName('parameters');
    let arity = 0;
    for (const p of params?.namedChildren ?? []) {
      if (!p) continue;
      const names = p.namedChildren.filter((c) => c?.type === 'identifier').length;
      arity += Math.max(1, names);
    }
    const isMethod = fn.type === 'method_declaration';
    const recv = isMethod ? receiverTypeName(fn) : '';
    const container = isMethod ? `${pkgName}.${recv}` : pkgName;
    const symbolId = `${input.repo}:${input.path}#${container}.${name}(${arity})`;
    funcIds.set(fn.id, symbolId);
    const sigEnd = fn.text.indexOf('{');
    fx.symbols.push({
      symbolId, repo: input.repo, kind: isMethod ? 'method' : 'func', name, container, path: input.path, range: rangeOf(fn),
      signature: (sigEnd > 0 ? fn.text.slice(0, sigEnd) : fn.text).replace(/\s+/g, ' ').trim().slice(0, 300),
      qualifiedName: isMethod ? `${importPath}.(${recv}).${name}` : `${importPath}.${name}`,
    });
  }
  const enclosingFunc = (node: Node): Node | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (FUNC_TYPES.has(p.type)) return p;
    return null;
  };
  const enclosingSymbol = (node: Node): string | null => {
    const f = enclosingFunc(node);
    return f ? funcIds.get(f.id) ?? null : null;
  };

  // ---- calls ----
  for (const call of root.descendantsOfType('call_expression')) {
    if (!call) continue;
    const from = enclosingSymbol(call);
    if (!from) continue;
    const fn = call.childForFieldName('function');
    const args = call.childForFieldName('arguments');
    let method: string | null = null;
    let receiverText: string | null = null;
    let receiverImport: string | null = null;
    if (fn?.type === 'identifier') method = fn.text;
    else if (fn?.type === 'selector_expression') {
      method = fn.childForFieldName('field')?.text ?? null;
      const operand = fn.childForFieldName('operand');
      receiverText = operand?.text ?? null;
      if (operand?.type === 'identifier') receiverImport = aliases.get(operand.text) ?? null;
    }
    if (!method) continue;
    fx.calls.push({
      from, method, receiverText, receiverType: null, receiverImport, arity: args?.namedChildren.length ?? 0,
      line: call.startPosition.row + 1, calleeText: (fn?.text ?? method).slice(0, 200),
    });
  }

  // ---- helpers for routes ----
  const consts = new Map<string, string>();
  for (const spec of root.descendantsOfType('const_spec')) {
    const name = spec?.childForFieldName('name')?.text;
    const value = spec?.childForFieldName('value')?.namedChildren[0];
    if (name && value && /string_literal/.test(value.type)) consts.set(name, unquote(value.text));
  }
  const stringOf = (n: Node | null | undefined): string | null => {
    if (!n) return null;
    if (/string_literal/.test(n.type)) return unquote(n.text);
    if (n.type === 'identifier' && consts.has(n.text)) return consts.get(n.text)!;
    if (n.type === 'binary_expression') {
      const l = stringOf(n.childForFieldName('left'));
      const r = stringOf(n.childForFieldName('right'));
      return l !== null && r !== null ? l + r : null;
    }
    return null;
  };
  const assignments: { name: string; value: Node; pos: number }[] = [];
  for (const a of [...root.descendantsOfType('short_var_declaration'), ...root.descendantsOfType('assignment_statement')]) {
    if (!a) continue;
    const left = a.childForFieldName('left')?.namedChildren ?? [];
    const right = a.childForFieldName('right')?.namedChildren ?? [];
    left.forEach((l, i) => { if (l?.type === 'identifier' && right[i]) assignments.push({ name: l.text, value: right[i]!, pos: a.startIndex }); });
  }
  const useCalls: { router: string; args: Node[]; pos: number }[] = [];
  for (const call of root.descendantsOfType('call_expression')) {
    const fn = call?.childForFieldName('function');
    if (fn?.type === 'selector_expression' && fn.childForFieldName('field')?.text === 'Use') {
      useCalls.push({ router: fn.childForFieldName('operand')?.text ?? '', args: (call!.childForFieldName('arguments')?.namedChildren ?? []).filter((x): x is Node => !!x), pos: call!.startIndex });
    }
  }
  const handlerName = (n: Node): string => n.text.replace(/\s+/g, ' ').slice(0, 120);
  /**
   * whether a GORM inline condition is a request string — the expression itself or the last assignment to
   * the identifier before the call (in the same function) reads a path / query / form value without a numeric
   * conversion.
   */
  const requestString = (cond: Node | undefined, call: Node): boolean => {
    if (!cond) return false;
    const fromRequest = (t: string) => REQUEST_STRING_RE.test(t) && !NUMERIC_RE.test(t);
    if (cond.type !== 'identifier') return fromRequest(cond.text);
    const fn = enclosingFunc(call);
    const a = assignments.filter((x) => x.name === cond.text && x.pos < call.startIndex && (!fn || (x.pos >= fn.startIndex && x.pos < fn.endIndex))).pop();
    return !!a && fromRequest(a.value.text);
  };

  /** Resolve a router expression to (prefix, middlewares) following Group() and Use() chains. */
  const resolveRouter = (node: Node, pos: number, depth = 0): { prefix: string; middlewares: string[] } => {
    if (depth > 8) return { prefix: '', middlewares: [] };
    if (node.type === 'call_expression') {
      const fn = node.childForFieldName('function');
      if (fn?.type === 'selector_expression' && fn.childForFieldName('field')?.text === 'Group') {
        const parent = resolveRouter(fn.childForFieldName('operand')!, pos, depth + 1);
        const args = (node.childForFieldName('arguments')?.namedChildren ?? []).filter((x): x is Node => !!x);
        return { prefix: joinRoute(parent.prefix, stringOf(args[0]) ?? '{?}'), middlewares: [...parent.middlewares, ...args.slice(1).map(handlerName)] };
      }
      return { prefix: '', middlewares: [] };
    }
    if (node.type === 'identifier') {
      const name = node.text;
      const assign = assignments.filter((a) => a.name === name && a.pos < pos).pop();
      const base = assign ? resolveRouter(assign.value, assign.pos, depth + 1) : { prefix: '', middlewares: [] };
      const uses = useCalls.filter((u) => u.router === name && u.pos < pos).flatMap((u) => u.args.map(handlerName));
      return { prefix: base.prefix, middlewares: [...base.middlewares, ...uses] };
    }
    return { prefix: '', middlewares: [] };
  };

  // ---- receiver types of handler references (`h.GetUser`) ----
  const goTypeName = (t: string | null | undefined): string | null => {
    if (!t) return null;
    const s = t.replace(/^[\s*&]+/, '').replace(/\[.*$/s, '').split('.').pop()?.trim() ?? '';
    return /^[A-Za-z_]\w*$/.test(s) ? s : null;
  };
  /** Struct field name → type over the file's structs (a name declared with different types is ambiguous: null). */
  const fieldTypes = new Map<string, string | null>();
  for (const fd of root.descendantsOfType('field_declaration')) {
    const t = goTypeName(fd?.childForFieldName('type')?.text);
    for (const id of fd?.namedChildren ?? []) {
      if (id?.type !== 'field_identifier') continue;
      fieldTypes.set(id.text, fieldTypes.has(id.text) && fieldTypes.get(id.text) !== t ? null : t);
    }
  }
  const varSpecs = new Map<string, { type: string | null; value: Node | null }>();
  for (const spec of root.descendantsOfType('var_spec')) {
    const name = spec?.childForFieldName('name')?.text;
    if (name) varSpecs.set(name, { type: goTypeName(spec!.childForFieldName('type')?.text), value: spec!.childForFieldName('value')?.namedChildren[0] ?? null });
  }
  /** Type of a value expression: `&T{}`, `T{}`, `pkg.T{}`, `NewT(...)` / `pkg.NewT(...)`, or an identifier assigned one. */
  const typeOfExpr = (v: Node | null | undefined, at: Node, depth = 0): string | null => {
    if (!v || depth > 4) return null;
    if (v.type === 'unary_expression' && v.text.startsWith('&')) return typeOfExpr(v.childForFieldName('operand'), at, depth + 1);
    if (v.type === 'parenthesized_expression') return typeOfExpr(v.namedChildren[0], at, depth + 1);
    if (v.type === 'composite_literal') return goTypeName(v.childForFieldName('type')?.text);
    if (v.type === 'call_expression') {
      const f = v.childForFieldName('function');
      const name = f?.type === 'selector_expression' ? f.childForFieldName('field')?.text : f?.type === 'identifier' ? f.text : undefined;
      return /^New([A-Z]\w*)$/.exec(name ?? '')?.[1] ?? null;
    }
    if (v.type === 'identifier') return identType(v.text, at, depth + 1);
    return null;
  };
  const identType = (name: string, at: Node, depth = 0): string | null => {
    const fn = enclosingFunc(at);
    if (fn) {
      const recv = fn.type === 'method_declaration' ? fn.childForFieldName('receiver') : null;
      for (const list of [recv, fn.childForFieldName('parameters')]) {
        for (const p of list?.namedChildren ?? []) {
          if (p?.type === 'parameter_declaration' && p.namedChildren.some((c) => c?.type === 'identifier' && c.text === name)) return goTypeName(p.childForFieldName('type')?.text);
        }
      }
      const a = assignments.filter((x) => x.name === name && x.pos < at.startIndex && x.pos >= fn.startIndex && x.pos < fn.endIndex).pop();
      if (a) return typeOfExpr(a.value, at, depth + 1);
    }
    const v = varSpecs.get(name);
    return v ? v.type ?? typeOfExpr(v.value, at, depth + 1) : null;
  };
  /** Receiver type of `x.M` / `s.users.M` handler references, when this file shows it. */
  const receiverTypeOf = (operand: Node, at: Node): string | null => {
    if (operand.type === 'identifier') return identType(operand.text, at);
    if (operand.type === 'selector_expression') return fieldTypes.get(operand.childForFieldName('field')?.text ?? '') ?? null;
    return null;
  };

  /** Unwrap `mw(h)` / `http.HandlerFunc(h)` style wrappers into (handler ref, wrapper names). */
  const handlerRef = (n: Node): { ref: HandlerRef; wrappers: string[] } => {
    if (n.type === 'func_literal') {
      const sym = enclosingSymbol(n);
      return { ref: { ...(sym ? { symbolId: sym } : {}), range: rangeOf(n) }, wrappers: [] };
    }
    if (n.type === 'call_expression') {
      const args = (n.childForFieldName('arguments')?.namedChildren ?? []).filter((x): x is Node => !!x);
      const fnText = n.childForFieldName('function')?.text ?? '';
      if (args.length > 0) {
        const inner = handlerRef(args[args.length - 1]!);
        const wrapper = /^http\.(HandlerFunc|StripPrefix)$/.test(fnText) ? [] : [fnText];
        return { ref: inner.ref, wrappers: [...wrapper, ...inner.wrappers] };
      }
    }
    if (n.type === 'selector_expression') {
      const operand = n.childForFieldName('operand');
      const imp = operand?.type === 'identifier' ? aliases.get(operand.text) : undefined;
      // `h.GetUser` — the receiver's type when this file shows it, so assemble picks UserHandler.GetUser.
      const typeHint = !imp && operand ? receiverTypeOf(operand, n) : null;
      return { ref: { text: n.text, ...(imp ? { importPath: imp } : {}), ...(typeHint ? { typeHint } : {}) }, wrappers: [] };
    }
    return { ref: { text: n.text }, wrappers: [] };
  };

  /** the handler expression of each HTTP route, to find the routes that upgrade to a WebSocket. */
  const routeHandlers = new Map<RawEntry, Node>();
  const makeEntry = (ruleId: string, framework: string, method: string, path: string, handler: Node, callNode: Node, middlewares: string[]): RawEntry => {
    const h = handlerRef(handler);
    const mws = [...middlewares, ...h.wrappers];
    const entry: RawEntry = {
      ruleId, framework, httpMethod: method, pathTemplate: path, handler: h.ref, path: input.path, range: rangeOf(callNode),
      middlewares: mws, authSignals: mws.filter((m) => AUTH_NAME_RE.test(m)),
    };
    routeHandlers.set(entry, handler);
    return entry;
  };


  // ---- beego and go-zero routes ----
  const beegoFacts = (input.langContext as { beego?: { methods: Record<string, string[]>; annotations: Record<string, { method: string; path: string; verbs: string[] }[]> } } | undefined)?.beego;
  const BEEGO_VERBS: Record<string, string> = { Get: 'GET', Post: 'POST', Put: 'PUT', Delete: 'DELETE', Patch: 'PATCH', Head: 'HEAD', Options: 'OPTIONS', Any: 'ANY' };
  /** Directory of the package a controller type comes from (`controllers.UserController` → its import's directory). */
  const typeDir = (n: Node | undefined): string | undefined => {
    const t = n?.type === 'unary_expression' ? n.childForFieldName('operand') : n;
    const typeText = t?.type === 'composite_literal' ? t.childForFieldName('type')?.text ?? '' : '';
    const alias = /^(\w+)\./.exec(typeText)?.[1];
    const imp = alias ? aliases.get(alias) : undefined;
    if (!alias) return input.path.includes('/') ? input.path.slice(0, input.path.lastIndexOf('/')) : '';
    if (!imp) return undefined;
    // Without go.mod (GOPATH layout): the import path's last two segments, matched as a directory suffix.
    if (!input.goModule) return imp.split('/').slice(-2).join('/');
    if (!(imp === input.goModule || imp.startsWith(input.goModule + '/'))) return undefined;
    const rel = imp.slice(input.goModule.length).replace(/^\//, '');
    return [input.goModuleDir, rel].filter(Boolean).join('/');
  };
  /** Type name of a controller argument: `&controllers.UserController{}`, `new(UserController)`. */
  const controllerType = (n: Node | undefined): string | null => {
    if (!n) return null;
    if (n.type === 'unary_expression') return controllerType(n.childForFieldName('operand') ?? undefined);
    if (n.type === 'composite_literal') return goTypeName(n.childForFieldName('type')?.text);
    if (n.type === 'call_expression' && n.childForFieldName('function')?.text === 'new') return goTypeName(n.childForFieldName('arguments')?.namedChildren[0]?.text);
    return null;
  };
  /** Prefixes of the enclosing `NSNamespace("/p", …)` / `NewNamespace("/p", …)` calls, outermost first. */
  const beegoPrefix = (call: Node): string => {
    const parts: string[] = [];
    for (let p: Node | null = call.parent; p; p = p.parent) {
      if (p.type !== 'call_expression') continue;
      const f = p.childForFieldName('function');
      const name = f?.type === 'selector_expression' ? f.childForFieldName('field')?.text : f?.text;
      if (name === 'NSNamespace' || name === 'NewNamespace') parts.unshift(stringOf(p.childForFieldName('arguments')?.namedChildren[0]) ?? '');
    }
    return parts.reduce((a, b) => joinRoute(a, b), '');
  };
  /** `InsertFilter(pattern, pos, filter)` calls of this file: middlewares for routes under the pattern. */
  const beegoFilters = (): { pattern: string; text: string }[] => {
    const out: { pattern: string; text: string }[] = [];
    for (const c of root.descendantsOfType('call_expression')) {
      const f = c?.childForFieldName('function');
      if (f?.type !== 'selector_expression' || f.childForFieldName('field')?.text !== 'InsertFilter') continue;
      const a = (c!.childForFieldName('arguments')?.namedChildren ?? []).filter((x): x is Node => !!x);
      const pattern = stringOf(a[0]);
      if (pattern !== null && a[2]) out.push({ pattern, text: handlerName(a[2]) });
    }
    return out;
  };
  const filtersFor = (route: string) => beegoFilters().filter((f) => f.pattern === '*' || f.pattern === '/*' || route === f.pattern || (f.pattern.endsWith('*') && route.startsWith(f.pattern.slice(0, -1).replace(/\/$/, '')))).map((f) => `InsertFilter(${f.pattern}): ${f.text}`);
  /** A controller method declared in this file (`func (c *T) M()`), preferred over the repository-wide name match. */
  const localMethod = (type: string, name: string): string | undefined => {
    for (const fn of root.namedChildren) {
      if (fn?.type === 'method_declaration' && receiverTypeName(fn) === type && fn.childForFieldName('name')?.text === name) return funcIds.get(fn.id);
    }
    return undefined;
  };
  const beegoEntry = (ruleId: string, method: string, route: string, ref0: HandlerRef, call: Node) => {
    const local = ref0.typeHint && ref0.text ? localMethod(ref0.typeHint, ref0.text.split('.').pop()!) : undefined;
    const ref = local ? { symbolId: local } : ref0;
    const mws = filtersFor(route);
    fx.entries.push({ ruleId, framework: 'beego', httpMethod: method, pathTemplate: route, handler: ref, path: input.path, range: rangeOf(call), middlewares: mws, authSignals: mws.filter((m) => AUTH_NAME_RE.test(m)) });
  };
  /**
   * beego (v1 `github.com/astaxie/beego`, v2 `…/server/web`): `Router(path, &C{}, "get,post:Save;*:Any")` (no mapping →
   * the controller's Get / Post / … methods), `Include(&C{})` (`// @router` annotations), `AutoRouter(&C{})`, function
   * routes `Get|Post|…|Any(path, fn)`, their `NS*` forms inside `NSNamespace`, and `InsertFilter` middlewares.
   */
  const beegoRoute = (ruleId: string, call: Node, verb: string, args: Node[]) => {
    if (![...imports].some((i) => /^github\.com\/(beego\/beego|astaxie\/beego)/.test(i))) return;
    const v = verb.replace(/^NS/, '');
    const prefix = beegoPrefix(call);
    if (v === 'Router') {
      const path = stringOf(args[0]);
      const t = controllerType(args[1]);
      if (path === null || !t) return;
      const route = joinRoute(prefix, path);
      const mapping = stringOf(args[2]);
      const dir = typeDir(args[1]);
      const ref = (m: string): HandlerRef => ({ text: `${t}.${m}`, typeHint: t, ...(dir !== undefined ? { dirHint: dir } : {}) });
      if (mapping) {
        for (const part of mapping.split(';')) {
          const [verbs, fn] = part.split(':');
          if (!verbs || !fn) continue;
          for (const vb of verbs.split(',')) beegoEntry(ruleId, vb.trim() === '*' ? 'ANY' : vb.trim().toUpperCase(), route, ref(fn.trim()), call);
        }
        return;
      }
      const defined = (beegoFacts?.methods[t] ?? []).filter((m) => BEEGO_VERBS[m]);
      for (const m of defined.length ? defined : ['Get']) beegoEntry(ruleId, BEEGO_VERBS[m] ?? 'GET', route, ref(m), call);
      return;
    }
    if (v === 'Include') {
      for (const a of args) {
        const t = controllerType(a);
        for (const ann of (t ? beegoFacts?.annotations[t] : undefined) ?? []) {
          const dir = typeDir(a);
          for (const vb of ann.verbs) beegoEntry(ruleId, vb === '*' ? 'ANY' : vb, joinRoute(prefix, ann.path), { text: `${t}.${ann.method}`, typeHint: t!, ...(dir !== undefined ? { dirHint: dir } : {}) }, call);
        }
      }
      return;
    }
    if (v === 'AutoRouter') {
      const t = controllerType(args[0]);
      if (!t) return;
      const ctrl = t.replace(/Controller$/, '').toLowerCase();
      for (const m of beegoFacts?.methods[t] ?? []) beegoEntry(ruleId, 'ANY', joinRoute(prefix, `/${ctrl}/${m.toLowerCase()}`), { text: `${t}.${m}`, typeHint: t }, call);
      return;
    }
    if (BEEGO_VERBS[v]) {
      const path = stringOf(args[0]);
      if (path === null || !args[1]) return;
      const h = handlerRef(args[1]);
      beegoEntry(ruleId, BEEGO_VERBS[v]!, joinRoute(prefix, path), h.ref, call);
    }
  };
  /**
   * go-zero generated routes (`internal/handler/routes.go`): `server.AddRoutes([]rest.Route{{Method, Path, Handler}}, opts…)`
   * and `AddRoute(rest.Route{…})`; `rest.WithPrefix` prefixes, `rest.WithJwt` / `rest.WithMiddlewares` / `WithSignature`
   * are middlewares; the handler is the `XxxHandler(svcCtx)` factory.
   */
  const gozeroRoutes = (ruleId: string, call: Node, args: Node[]) => {
    if (!imports.has('github.com/zeromicro/go-zero/rest')) return;
    const mws: string[] = [];
    let prefix = '';
    const routes: Node[] = [];
    const collect = (n: Node | undefined) => {
      if (!n) return;
      if (n.type === 'composite_literal') {
        const t = n.childForFieldName('type')?.text ?? '';
        const body = n.childForFieldName('body');
        if (/^\[\]\s*rest\.Route$/.test(t)) for (const el of body?.namedChildren ?? []) { const lit = el?.type === 'literal_element' ? el.namedChildren[0] : el; if (lit) routes.push(lit); }
        else if (/^rest\.Route$/.test(t)) routes.push(n);
        return;
      }
      if (n.type === 'call_expression') {
        const f = n.childForFieldName('function')?.text ?? '';
        const a = (n.childForFieldName('arguments')?.namedChildren ?? []).filter((x): x is Node => !!x);
        if (/\.WithMiddlewares$/.test(f)) { for (const x of a[0]?.childForFieldName('body')?.namedChildren ?? []) if (x) mws.push(handlerName(x)); for (const x of a.slice(1)) collect(x); }
        else if (/\.WithPrefix$/.test(f)) prefix = stringOf(a[0]) ?? prefix;
        else if (/\.(WithJwt|WithJwtTransition|WithSignature|WithMiddleware)$/.test(f)) mws.push(handlerName(n));
        return;
      }
      if (n.type === 'variadic_argument') collect(n.namedChildren[0] ?? undefined);
    };
    for (const a of args) collect(a);
    for (const r of routes) {
      const fields = new Map<string, Node>();
      for (const kv of (r.type === 'literal_value' ? r : r.childForFieldName('body'))?.namedChildren ?? []) {
        if (kv?.type !== 'keyed_element') continue;
        const [k, val] = kv.namedChildren.filter((x): x is Node => !!x);
        if (k && val) fields.set(k.text, val.type === 'literal_element' ? val.namedChildren[0] ?? val : val);
      }
      const mNode = fields.get('Method');
      const method = mNode ? stringOf(mNode)?.toUpperCase() ?? /Method(\w+)$/.exec(mNode.text)?.[1]?.toUpperCase() ?? 'ANY' : 'ANY';
      const path = stringOf(fields.get('Path'));
      const hn = fields.get('Handler');
      if (path === null || !hn) continue;
      const fn = hn.type === 'call_expression' ? hn.childForFieldName('function') ?? hn : hn;
      fx.entries.push(makeEntry(ruleId, 'go-zero', method, joinRoute(prefix, path), fn, r, mws));
    }
  };

  // ---- rules ----
  const seen = new Set<string>();
  for (const { rule, query, error } of rules) {
    if (error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${error}` }); continue; }
    if (!query) continue;
    if (rule.match?.requiresImportAny && !rule.match.requiresImportAny.some((i) => imports.has(i))) continue;
    if (rule.match?.notImportAny?.some((i) => imports.has(i))) continue;
    try {
      for (const match of query.matches(root)) {
        const cap = captureMap(match.captures, rule.captures);
        const call = cap.get('call');
        if (!call) continue;
        const args = (cap.get('args')?.namedChildren ?? []).filter((x): x is Node => !!x);
        if (rule.kind === 'sink') {
          const receiver = cap.get('receiver') ?? null;
          const receiverImport = receiver?.type === 'identifier' ? aliases.get(receiver.text) ?? null : null;
          if (!ruleMatches(rule.match, { receiverText: receiver?.text ?? null, receiverType: null, receiverImport, imports, argCount: args.length })) continue;
          const api = fillApi(rule.api ?? '', { method: cap.get('method')?.text, receiver: receiver?.text, importPath: receiverImport ?? receiver?.text });
          let taint = taintHintOf(cap.get('args'));
          if (rule.post === 'go_gorm_request_condition') {
            if (!requestString(cap.get('cond'), call)) continue;
            taint = 'request_string';
          } else if (rule.post === 'go_gorm_raw_clause') {
            const cond = cap.get('cond');
            if (!cond || !(cond.type === 'binary_expression' || /^fmt\.Sprint/.test(cond.text)) || !CONCAT_ARG_RE.test(cond.text)) continue;
            taint = 'string_concat';
          }
          const sink = makeSink(input.repo, input.path, rule, call, enclosingSymbol(call), api, taint);
          if (!seen.has(sink.sinkId)) { seen.add(sink.sinkId); fx.sinks.push(sink); }
        } else if (rule.kind === 'entrypoint' && rule.post === 'go_router_route') {
          const verb = cap.get('verb')?.text ?? '';
          const router = cap.get('router');
          if (!router) continue;
          // Skip receivers that are import aliases (e.g. `http.Get` is a client call, not a route).
          if (router.type === 'identifier' && aliases.has(router.text)) continue;
          // gin / echo use GET…; flamego / macaron / chi use Get….
          let method = verb === 'Any' || verb === 'All' ? 'ANY' : verb.toUpperCase();
          let rest = args;
          if (verb === 'Handle') { method = (stringOf(args[0]) ?? 'ANY').toUpperCase(); rest = args.slice(1); }
          if (verb === 'Match') continue;
          const path = stringOf(rest[0]);
          if (path === null || rest.length < 2) continue;
          // Title-case verbs are common method names (cache.Get("k", &v)): only literal route paths count.
          if (['flamego', 'chi', 'fiber', 'hertz'].includes(rule.framework) && !path.startsWith('/')) continue;
          const r = resolveRouter(router, call.startIndex);
          const fullPath = joinRoute(r.prefix, path);
          const isEcho = rule.framework === 'echo';
          const handler = isEcho ? rest[1]! : rest[rest.length - 1]!;
          const routeMw = (isEcho ? rest.slice(2) : rest.slice(1, -1)).map(handlerName);
          fx.entries.push(makeEntry(rule.id, rule.framework, method, fullPath, handler, call, [...r.middlewares, ...routeMw]));
        } else if (rule.kind === 'entrypoint' && rule.post === 'go_beego_route') {
          beegoRoute(rule.id, call, cap.get('verb')?.text ?? '', args);
        } else if (rule.kind === 'entrypoint' && rule.post === 'go_gozero_routes') {
          gozeroRoutes(rule.id, call, args);
        } else if (rule.kind === 'entrypoint' && rule.post === 'go_nethttp_route') {
          const pattern = stringOf(args[0]);
          if (pattern === null || args.length < 2) continue;
          const m = /^([A-Z]+)\s+(\S+)$/.exec(pattern);
          const method = m ? m[1]! : 'ANY';
          const rawPath = m ? m[2]! : pattern;
          const hostless = rawPath.startsWith('/') ? rawPath : rawPath.slice(Math.max(0, rawPath.indexOf('/')));
          fx.entries.push(makeEntry(rule.id, 'nethttp', method, hostless, args[1]!, call, []));
        }
      }
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${(e as Error).message}` });
    }
  }
  // ---- gRPC service implementations: methods of types the package scan identified ----
  const grpcCtx = input.langContext as { grpcTypes?: Record<string, string>; grpcInterceptors?: Record<string, string[]> } | undefined;
  const grpcTypes = grpcCtx?.grpcTypes;
  if (grpcTypes) {
    const hasProto = (svc: string) => !!input.grpcServices?.some((s) => s.name === svc);
    for (const fn of root.namedChildren) {
      if (fn?.type !== 'method_declaration') continue;
      const recvType = receiverTypeName(fn);
      const svc = grpcTypes[recvType];
      const interceptors = grpcCtx?.grpcInterceptors?.[recvType] ?? [];
      const name = fn.childForFieldName('name')?.text ?? '';
      if (!svc || !/^[A-Z]/.test(name) || /^mustEmbed/.test(name)) continue;
      // Without the .proto, only methods shaped like handlers (a context or a stream parameter) count.
      if (!hasProto(svc) && !/context\.Context|_\w+Server\b|\w+Server\b/.test(fn.childForFieldName('parameters')?.text ?? '')) continue;
      const rpc = rpcOf(input.grpcServices, svc, name);
      const symbolId = funcIds.get(fn.id);
      if (!rpc || !symbolId) continue;
      fx.entries.push({
        rpc, ruleId: 'go.grpc.service', framework: 'grpc', httpMethod: 'RPC', pathTemplate: '', handler: { symbolId },
        path: input.path, range: rangeOf(fn), middlewares: [...interceptors], authSignals: interceptors.filter((x) => AUTH_NAME_RE.test(x)),
      });
      // HTTP transcoding of the same rpc (`option (google.api.http)`; grpc-gateway / kratos) — another entry,
      // same handler. gRPC interceptors do not run on the HTTP transport, so no middlewares are carried over.
      const svcFacts = input.grpcServices?.find((x) => x.name === svc);
      for (const b of svcFacts?.http?.[rpc.method] ?? []) {
        fx.entries.push({
          ruleId: 'go.grpc.http-binding', framework: [...imports].some((i) => i.startsWith('github.com/go-kratos/kratos')) || /\bkratos\b/.test(input.text) ? 'kratos' : 'grpc-gateway',
          httpMethod: b.method, pathTemplate: b.path, handler: { symbolId }, path: input.path, range: rangeOf(fn), middlewares: [], authSignals: [],
        });
      }
    }
  }
  // ---- GraphQL resolvers: gqlgen methods on `<type>Resolver` for the schema's types ----
  if (input.graphql) {
    const typeByPrefix = new Map(Object.keys(input.graphql.types).map((t) => [t.toLowerCase(), t]));
    for (const fn of root.namedChildren) {
      if (fn?.type !== 'method_declaration') continue;
      const prefix = /^([a-z]\w*)Resolver$/.exec(receiverTypeName(fn))?.[1];
      const type = prefix ? typeByPrefix.get(prefix.toLowerCase()) : undefined;
      const name = fn.childForFieldName('name')?.text ?? '';
      const symbolId = funcIds.get(fn.id);
      if (!type || !symbolId || !/^[A-Z]/.test(name)) continue;
      const g = graphqlEntryOf(input.graphql, type, name);
      if (!g) continue;
      fx.entries.push({
        rpc: g.rpc, ruleId: g.root ? 'go.gqlgen.operation' : 'go.gqlgen.field', framework: 'gqlgen', httpMethod: 'RPC', pathTemplate: g.pathTemplate,
        handler: { symbolId }, path: input.path, range: rangeOf(fn), middlewares: g.directives, authSignals: g.directives.filter((d) => AUTH_NAME_RE.test(d)),
      });
    }
  }
  extractGoChannels();
  for (const e of fx.entries) {
    for (const mw of e.authSignals) {
      if (!fx.authSignals.some((s) => s.detail === mw)) fx.authSignals.push({ target: `${input.repo}:${input.path}`, kind: 'middleware', detail: mw, ruleId: e.ruleId });
    }
  }
  return fx;

  /**
   * entries that are not HTTP routes — WebSocket upgrades (a socket entry beside the HTTP route, keyed by the
   * route; `ws:<func>` when no route in this file registers the handler), queue consumers (sarama, kafka-go, amqp, NATS,
   * go-redis, NSQ), robfig/cron jobs, cobra / urfave-cli commands and Thrift processors. Per file: a sarama handler or
   * Thrift handler type declared in another file than its registration is matched by name in `assemble`, or not at all.
   */
  function extractGoChannels(): void {
    const calls = root.descendantsOfType('call_expression').filter((c): c is Node => !!c);
    const argsOf = (call: Node): Node[] => (call.childForFieldName('arguments')?.namedChildren ?? []).filter((x): x is Node => !!x);
    const fieldOf = (call: Node): string | null => {
      const f = call.childForFieldName('function');
      return f?.type === 'selector_expression' ? f.childForFieldName('field')?.text ?? null : f?.type === 'identifier' ? f.text : null;
    };
    const operandOf = (call: Node): Node | null => {
      const f = call.childForFieldName('function');
      return f?.type === 'selector_expression' ? f.childForFieldName('operand') : null;
    };
    const importsAny = (re: RegExp) => [...imports].some((p) => re.test(p));
    const aliasesOf = (re: RegExp) => new Set([...aliases].filter(([, p]) => re.test(p)).map(([a]) => a));
    const textOf = (n: Node) => stringOf(n) ?? n.text.replace(/\s+/g, ' ').slice(0, 120);
    const funcLabel = (fn: Node) => {
      const name = fn.childForFieldName('name')?.text ?? '?';
      return fn.type === 'method_declaration' ? `${receiverTypeName(fn)}.${name}` : name;
    };
    const enclosingRef = (n: Node): HandlerRef => {
      const s = enclosingSymbol(n);
      return s ? { symbolId: s } : { range: rangeOf(n) };
    };
    const unwrap = (n: Node | null | undefined): Node | null => {
      let x = n ?? null;
      while (x && (x.type === 'literal_element' || x.type === 'parenthesized_expression')) x = x.namedChildren[0] ?? null;
      if (x?.type === 'unary_expression' && x.text.startsWith('&')) return unwrap(x.childForFieldName('operand'));
      return x;
    };
    const fieldsOf = (lit: Node): Map<string, Node> => {
      const out = new Map<string, Node>();
      for (const kv of lit.childForFieldName('body')?.namedChildren ?? []) {
        if (kv?.type !== 'keyed_element') continue;
        const k = unwrap(kv.childForFieldName('key') ?? kv.namedChildren[0]);
        const v = unwrap(kv.childForFieldName('value') ?? kv.namedChildren[1]);
        if (k && v) out.set(k.text, v);
      }
      return out;
    };
    const varValues = new Map<string, Node>();
    for (const spec of root.descendantsOfType('var_spec')) {
      const name = spec?.childForFieldName('name')?.text;
      const value = spec?.childForFieldName('value')?.namedChildren[0];
      if (name && value) varValues.set(name, value);
    }
    /** The value last assigned to `name` before `pos` (or its package-level `var`). */
    const valueOf = (n: Node, pos: number, depth = 0): Node => {
      const x = unwrap(n) ?? n;
      if (x.type !== 'identifier' || depth > 4) return x;
      const a = assignments.filter((v) => v.name === x.text && v.pos < pos).pop();
      const v = a?.value ?? varValues.get(x.text);
      return v ? valueOf(v, a?.pos ?? pos, depth + 1) : x;
    };
    /** Type name of a handler value: `&T{}`, `T{}`, `NewT(...)`, through local assignments. */
    const typeOfValue = (n: Node, pos: number): string | null => {
      const v = valueOf(n, pos);
      if (v.type === 'composite_literal') return v.childForFieldName('type')?.text.split('.').pop()?.replace(/\[.*$/, '') ?? null;
      if (v.type === 'call_expression') return /^New(\w+)$/.exec(fieldOf(v) ?? '')?.[1] ?? null;
      return null;
    };
    const listOf = (n: Node, pos: number): string[] => {
      const v = valueOf(n, pos);
      if (v.type === 'composite_literal' && /^\[\]/.test(v.childForFieldName('type')?.text ?? '')) {
        return (v.childForFieldName('body')?.namedChildren ?? []).map((e) => unwrap(e)).filter((e): e is Node => !!e).map(textOf);
      }
      return [stringOf(v) ?? textOf(n)];
    };
    /** Go's own name for a closure: `<func>.func<n>` in source order within the declaring function. */
    const closureName = (lit: Node): string => {
      const fn = enclosingFunc(lit);
      if (!fn) return `func@L${lit.startPosition.row + 1}`;
      const i = fn.descendantsOfType('func_literal').findIndex((x) => x?.id === lit.id);
      return `${funcLabel(fn)}.func${i + 1}`;
    };
    /** Handler of a job / command / subscription callback and the name it is known by. */
    const callback = (n: Node): { ref: HandlerRef; name: string } => {
      const x = unwrap(n) ?? n;
      if (x.type === 'func_literal') return { ref: handlerRef(x).ref, name: closureName(x) };
      if (x.type === 'call_expression' && argsOf(x).length) return callback(argsOf(x).pop()!);
      return { ref: handlerRef(x).ref, name: x.text.replace(/\s+/g, ' ').slice(0, 120) };
    };
    const push = (kind: NonNullable<RawEntry['channel']>['kind'], protocol: string, key: string, route: string, ruleId: string, framework: string,
      handler: HandlerRef, range: RawEntry['range'], middlewares: string[] = []): void => {
      fx.entries.push({
        channel: { kind, protocol, key, route }, ruleId, framework, httpMethod: '', pathTemplate: '', handler, path: input.path, range,
        middlewares: [...middlewares], authSignals: middlewares.filter((m) => AUTH_NAME_RE.test(m)),
      });
    };
    const funcsByName = new Map<string, Node[]>();
    for (const fn of root.namedChildren) {
      if (!fn || !FUNC_TYPES.has(fn.type)) continue;
      const name = fn.childForFieldName('name')?.text ?? '';
      funcsByName.set(name, [...(funcsByName.get(name) ?? []), fn]);
    }

    // ---- WebSocket: gorilla `upgrader.Upgrade(w, r, h)`, nhooyr / coder `websocket.Accept(w, r, opts)`, fiber `websocket.New(h)` ----
    const gorilla = importsAny(/^github\.com\/gorilla\/websocket$/);
    const nhooyr = aliasesOf(/^(nhooyr\.io\/websocket|github\.com\/coder\/websocket)$/);
    const fiberWs = aliasesOf(/^github\.com\/gofiber\/(websocket|contrib\/websocket)/);
    const upgrades = new Map<Node, string>();
    for (const call of calls) {
      const f = fieldOf(call);
      const op = operandOf(call);
      if (!op || (aliases.has(op.text) && !nhooyr.has(op.text))) continue;
      if (f === 'Upgrade' && argsOf(call).length === 3 && (gorilla || /upgrader/i.test(op.text))) upgrades.set(call, 'gorilla-websocket');
      else if (f === 'Accept' && nhooyr.has(op.text) && argsOf(call).length >= 2) upgrades.set(call, 'nhooyr-websocket');
    }
    const upgradesIn = (n: Node) => [...upgrades.keys()].filter((u) => u.startIndex >= n.startIndex && u.endIndex <= n.endIndex);
    const covered = new Set<Node>();
    /** Same-file function named like the handler that upgrades; `methods` when the reference is `x.Name`. */
    const upgradingFunc = (name: string, methods: boolean, except?: Node | null): Node | null =>
      (funcsByName.get(name) ?? []).find((fn) => (methods || fn.type === 'function_declaration') && fn.id !== except?.id && upgradesIn(fn).length > 0) ?? null;
    const socketOf = (h: Node): { handler: HandlerRef; framework: string } | null => {
      if (h.type === 'call_expression') {
        const op = operandOf(h);
        if (fieldOf(h) === 'New' && op && fiberWs.has(op.text)) return { handler: callback(h).ref, framework: 'fiber-websocket' };
        const a = argsOf(h);
        if (a.length) return socketOf(a[a.length - 1]!);
        const fn = upgradingFunc(fieldOf(h) ?? '', !!op); // handler factory `wsHandler()`
        if (!fn) return null;
        upgradesIn(fn).forEach((u) => covered.add(u));
        return { handler: { symbolId: funcIds.get(fn.id)! }, framework: upgrades.get(upgradesIn(fn)[0]!)! };
      }
      if (h.type === 'func_literal') {
        const inside = upgradesIn(h);
        if (inside.length) {
          inside.forEach((u) => covered.add(u));
          return { handler: handlerRef(h).ref, framework: upgrades.get(inside[0]!)! };
        }
        // `func(w, r) { serveWs(hub, w, r) }`
        for (const c of h.descendantsOfType('call_expression')) {
          const fn = c ? upgradingFunc(fieldOf(c) ?? '', !!operandOf(c), enclosingFunc(h)) : null;
          if (!fn) continue;
          upgradesIn(fn).forEach((u) => covered.add(u));
          return { handler: { symbolId: funcIds.get(fn.id)! }, framework: upgrades.get(upgradesIn(fn)[0]!)! };
        }
        return null;
      }
      if (h.type === 'identifier' || h.type === 'selector_expression') {
        const fn = upgradingFunc(h.text.split('.').pop()!, h.type === 'selector_expression');
        if (!fn) return null;
        upgradesIn(fn).forEach((u) => covered.add(u));
        return { handler: { symbolId: funcIds.get(fn.id)! }, framework: upgrades.get(upgradesIn(fn)[0]!)! };
      }
      return null;
    };
    if (upgrades.size || fiberWs.size) {
      for (const [entry, h] of routeHandlers) {
        const s = socketOf(h);
        if (s) push('socket', 'websocket', `ws:${entry.pathTemplate}`, entry.pathTemplate, 'go.websocket.upgrade', s.framework, s.handler, entry.range, entry.middlewares);
      }
      const unrouted = new Map<number, { fn: Node; framework: string }>();
      for (const [u, framework] of upgrades) {
        const fn = covered.has(u) ? null : enclosingFunc(u);
        if (fn && !unrouted.has(fn.id)) unrouted.set(fn.id, { fn, framework });
      }
      for (const { fn, framework } of unrouted.values()) {
        const name = funcLabel(fn);
        push('socket', 'websocket', `ws:${name}`, name, 'go.websocket.upgrade', framework, { symbolId: funcIds.get(fn.id)! }, rangeOf(fn));
      }
    }

    // ---- Kafka: sarama consumer groups / partition consumers, segmentio kafka-go readers ----
    if (importsAny(/^github\.com\/(IBM|Shopify)\/sarama$/)) {
      let groupConsume = false;
      for (const call of calls) {
        const a = argsOf(call);
        if (fieldOf(call) === 'Consume' && a.length === 3 && operandOf(call)) {
          groupConsume = true;
          const type = typeOfValue(a[2]!, call.startIndex);
          const handler: HandlerRef = { text: `${type ?? a[2]!.text}.ConsumeClaim` };
          for (const t of listOf(a[1]!, call.startIndex)) push('message', 'kafka', `mq:kafka:${t}`, t, 'go.kafka.consumer', 'sarama', handler, rangeOf(call));
        } else if (fieldOf(call) === 'ConsumePartition' && a.length === 3) {
          const t = textOf(a[0]!);
          push('message', 'kafka', `mq:kafka:${t}`, t, 'go.kafka.consumer', 'sarama', enclosingRef(call), rangeOf(call));
        }
      }
      // A ConsumerGroupHandler whose `Consume(ctx, topics, h)` is not in this file: keyed by the handler type.
      if (!groupConsume) {
        for (const fn of root.namedChildren) {
          if (fn?.type !== 'method_declaration' || fn.childForFieldName('name')?.text !== 'ConsumeClaim') continue;
          if (!/ConsumerGroupClaim/.test(fn.childForFieldName('parameters')?.text ?? '')) continue;
          const t = receiverTypeName(fn);
          push('message', 'kafka', `mq:kafka:${t}`, t, 'go.kafka.consumer', 'sarama', { symbolId: funcIds.get(fn.id)! }, rangeOf(fn));
        }
      }
    }
    const kafkaGo = aliasesOf(/^github\.com\/segmentio\/kafka-go$/);
    for (const call of calls) {
      const op = operandOf(call);
      if (!op || !kafkaGo.has(op.text) || fieldOf(call) !== 'NewReader' || !argsOf(call)[0]) continue;
      const cfg = valueOf(argsOf(call)[0]!, call.startIndex);
      const fields = cfg.type === 'composite_literal' ? fieldsOf(cfg) : new Map<string, Node>();
      const topics = fields.get('Topic') ? [textOf(fields.get('Topic')!)] : fields.get('GroupTopics') ? listOf(fields.get('GroupTopics')!, call.startIndex) : [cfg.text.slice(0, 120)];
      for (const t of topics) push('message', 'kafka', `mq:kafka:${t}`, t, 'go.kafka.consumer', 'kafka-go', enclosingRef(call), rangeOf(call));
    }

    // ---- RabbitMQ: `ch.Consume(queue, consumer, autoAck, exclusive, noLocal, noWait, args)` ----
    if (importsAny(/^github\.com\/(streadway\/amqp|rabbitmq\/amqp091-go)$/)) {
      for (const call of calls) {
        const a = argsOf(call);
        const f = fieldOf(call);
        const q = f === 'Consume' && a.length === 7 ? a[0] : f === 'ConsumeWithContext' && a.length === 8 ? a[1] : undefined;
        if (!q || !operandOf(call)) continue;
        // `q.Name` of `q, _ := ch.QueueDeclare("tasks", ...)`
        let queue = textOf(q);
        const decl = q.type === 'selector_expression' && q.childForFieldName('field')?.text === 'Name' ? valueOf(q.childForFieldName('operand')!, call.startIndex) : null;
        if (decl?.type === 'call_expression' && fieldOf(decl) === 'QueueDeclare' && stringOf(argsOf(decl)[0])) queue = stringOf(argsOf(decl)[0])!;
        push('message', 'rabbitmq', `mq:rabbitmq:${queue}`, queue, 'go.amqp.consumer', 'amqp', enclosingRef(call), rangeOf(call));
      }
    }

    // ---- NATS: `nc.Subscribe(subj, h)`, `QueueSubscribe(subj, queue, h)`, sync / channel / pull variants ----
    if (importsAny(/^github\.com\/nats-io\/nats\.go/)) {
      for (const call of calls) {
        const f = fieldOf(call) ?? '';
        const a = argsOf(call);
        if (!operandOf(call) || !/^(Queue)?Subscribe(Sync)?$|^Chan(Queue)?Subscribe$|^PullSubscribe$/.test(f) || !a[0] || (stringOf(a[0]) === null && /ctx|context/i.test(a[0].text))) continue;
        const subject = textOf(a[0]);
        const h = f === 'Subscribe' ? a[1] : f === 'QueueSubscribe' ? a[2] : undefined;
        push('message', 'nats', `mq:nats:${subject}`, subject, 'go.nats.subscribe', 'nats', h ? callback(h).ref : enclosingRef(call), rangeOf(call));
      }
    }

    // ---- Redis pub/sub: `rdb.Subscribe(ctx, "ch1", "ch2")` (go-redis) ----
    if (importsAny(/^github\.com\/(redis\/go-redis|go-redis\/redis)/)) {
      for (const call of calls) {
        const a = argsOf(call);
        if (!operandOf(call) || !/^[PS]?Subscribe$/.test(fieldOf(call) ?? '') || a.length < 2 || stringOf(a[0]) !== null) continue;
        for (const ch of a.slice(1)) {
          const c = textOf(ch);
          push('message', 'redis', `mq:redis:${c}`, c, 'go.redis.subscribe', 'go-redis', enclosingRef(call), rangeOf(call));
        }
      }
    }

    // ---- NSQ: `nsq.NewConsumer(topic, channel, cfg)` with `c.AddHandler(h)` in the same function ----
    const nsq = aliasesOf(/^github\.com\/nsqio\/go-nsq$/);
    for (const call of calls) {
      const op = operandOf(call);
      if (!op || !nsq.has(op.text) || fieldOf(call) !== 'NewConsumer' || !argsOf(call)[0]) continue;
      const topic = textOf(argsOf(call)[0]!);
      const fn = enclosingFunc(call);
      const add = fn?.descendantsOfType('call_expression').find((c) => !!c && /^Add(Concurrent)?Handlers?$/.test(fieldOf(c) ?? '') && argsOf(c).length > 0);
      let handler = enclosingRef(call);
      if (add) {
        const h = argsOf(add)[0]!;
        const type = typeOfValue(h, add.startIndex);
        handler = type ? { text: `${type}.HandleMessage` } : callback(h).ref;
      }
      push('message', 'nsq', `mq:nsq:${topic}`, topic, 'go.nsq.consumer', 'nsq', handler, rangeOf(call));
    }

    // ---- robfig/cron: `c.AddFunc(spec, fn)`, `c.AddJob(spec, job)` ----
    if (importsAny(/^github\.com\/robfig\/cron/)) {
      for (const call of calls) {
        const f = fieldOf(call);
        const a = argsOf(call);
        if (!operandOf(call) || (f !== 'AddFunc' && f !== 'AddJob') || a.length !== 2) continue;
        const spec = textOf(a[0]!);
        let cb: { ref: HandlerRef; name: string };
        if (f === 'AddJob') {
          const type = typeOfValue(a[1]!, call.startIndex);
          const name = `${type ?? a[1]!.text}.Run`;
          cb = { ref: { text: name }, name };
        } else cb = callback(a[1]!);
        push('schedule', 'cron', `cron:${cb.name}`, spec, 'go.cron', 'robfig-cron', cb.ref, rangeOf(call));
      }
    }

    // ---- asynq: `mux.HandleFunc("email:deliver", fn)` / `mux.Handle(type, h)` (task type → handler) ----
    if (importsAny(/^github\.com\/hibiken\/asynq$/)) {
      for (const call of calls) {
        const f = fieldOf(call);
        const a = argsOf(call);
        if ((f !== 'HandleFunc' && f !== 'Handle') || a.length !== 2 || !operandOf(call)) continue;
        const type = textOf(a[0]!);
        let cb: { ref: HandlerRef; name: string };
        if (f === 'Handle') {
          const t = typeOfValue(a[1]!, call.startIndex);
          const name = `${t ?? a[1]!.text}.ProcessTask`;
          cb = { ref: t ? { text: name, typeHint: t } : { text: name }, name };
        } else cb = callback(a[1]!);
        push('message', 'asynq', `mq:asynq:${type}`, type, 'go.asynq.handler', 'asynq', cb.ref, rangeOf(call));
      }
    }

    // ---- Commands: cobra `&cobra.Command{Use, Run/RunE}`, urfave/cli `&cli.Command{Name, Action}` / `cli.App` ----
    const cobra = aliasesOf(/^github\.com\/spf13\/cobra$/);
    const urfave = aliasesOf(/^github\.com\/urfave\/cli(\/v\d+)?$/);
    if (cobra.size || urfave.size) {
      for (const lit of root.descendantsOfType('composite_literal')) {
        const type = lit?.childForFieldName('type')?.text ?? '';
        const [pkg, name] = type.split('.');
        if (!lit || !pkg || !name) continue;
        const fields = fieldsOf(lit);
        let cmd: string | null = null;
        let run: Node | undefined;
        let framework = '';
        if (cobra.has(pkg) && name === 'Command') {
          cmd = fields.get('Use') ? textOf(fields.get('Use')!).split(/\s+/)[0] ?? null : null;
          run = fields.get('RunE') ?? fields.get('Run');
          framework = 'cobra';
        } else if (urfave.has(pkg) && (name === 'Command' || name === 'App')) {
          cmd = fields.get('Name') ? textOf(fields.get('Name')!) : null;
          run = fields.get('Action');
          framework = 'urfave-cli';
        }
        if (!cmd || !run) continue;
        push('cli', 'cli', `cli:${cmd}`, cmd, framework === 'cobra' ? 'go.cobra.command' : 'go.urfave.command', framework, callback(run).ref, rangeOf(lit));
      }
    }

    // ---- Thrift: `NewXxxServiceProcessor(handler)` — the handler type's exported methods declared in this file ----
    if (importsAny(/^github\.com\/apache\/thrift\/lib\/go\/thrift$/)) {
      for (const call of calls) {
        const svc = /^New(\w+)Processor$/.exec(fieldOf(call) ?? '')?.[1];
        if (!svc || /^T[A-Z]/.test(svc) || argsOf(call).length !== 1) continue;
        const type = typeOfValue(argsOf(call)[0]!, call.startIndex);
        for (const fn of root.namedChildren) {
          if (fn?.type !== 'method_declaration' || !type || receiverTypeName(fn) !== type) continue;
          const m = fn.childForFieldName('name')?.text ?? '';
          if (!/^[A-Z]/.test(m)) continue;
          push('rpc', 'thrift', `rpc:thrift:${svc}/${m}`, `${svc}/${m}`, 'go.thrift.processor', 'thrift', { symbolId: funcIds.get(fn.id)! }, rangeOf(fn));
        }
      }
    }
  }
}
