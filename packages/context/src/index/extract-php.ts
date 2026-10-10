// PHP extraction: symbols (namespaces, classes / interfaces / traits / enums, methods, functions and a
// file-level `<main>` for top-level code), calls with receiver facts (`use` imports, typed properties, constructor
// promotion, parameter types, `new`), entries (Laravel / ThinkPHP route files with group prefixes and middleware,
// resource routes, Symfony `#[Route]` attributes, native scripts that read request superglobals), sinks and
// auth signals. The grammar is tree-sitter-php's `php` variant (HTML text nodes included).
import type { Node, Tree } from 'web-tree-sitter';
import type { AuthSignal, IndexSymbol } from '@xiezhi/contracts';
import {
  AUTH_NAME_RE, captureMap, fillApi, makeSink, rangeOf, ruleMatches, type CompiledRule,
} from './common.js';
import type { PhpFrameworkContext } from './extract-php-frameworks.js';
import { emptyExtract, joinRoute, type ExtractInput, type FileExtract, type HandlerRef, type RawEntry } from './types.js';

const CLASS_TYPES = new Set(['class_declaration', 'interface_declaration', 'trait_declaration', 'enum_declaration']);
const FUNC_TYPES = new Set(['method_declaration', 'function_definition']);
const CLOSURE_TYPES = new Set(['anonymous_function', 'arrow_function', 'anonymous_function_creation_expression']);
const CALL_TYPES = ['function_call_expression', 'member_call_expression', 'nullsafe_member_call_expression', 'scoped_call_expression', 'object_creation_expression'];
/** Top-level statements that declare rather than execute (a file with only these has no `<main>`). */
const DECLARATION_TYPES = new Set([
  'php_tag', 'php_end_tag', 'text', 'text_interpolation', 'comment', 'namespace_definition', 'namespace_use_declaration',
  'function_definition', 'const_declaration', 'declare_statement', 'empty_statement', ...CLASS_TYPES,
]);
const SELF_SCOPES = new Set(['self', 'static', 'parent']);
const PRIMITIVE_TYPES = /^(int|float|string|bool|array|mixed|void|null|callable|iterable|object|never|false|true|self|static)$/i;
/** Built-in functions never defined in a repository (no call record: they only produce unresolved edges). */
const BUILTIN_RE = /^(array_\w+|str_\w+|mb_\w+|preg_\w+|json_\w+|is_\w+|in_array|count|sizeof|strlen|strpos|stripos|strrpos|substr|substr_count|sprintf|vsprintf|printf|implode|explode|join|trim|ltrim|rtrim|strtolower|strtoupper|ucfirst|lcfirst|ucwords|intval|floatval|boolval|strval|isset|empty|unset|compact|extract|list|range|min|max|abs|round|floor|ceil|time|date|strtotime|microtime|mktime|number_format|htmlspecialchars|htmlentities|strip_tags|addslashes|stripslashes|nl2br|urlencode|urldecode|rawurlencode|base64_encode|base64_decode|md5|sha1|hash|hash_hmac|crc32|random_int|rand|mt_rand|uniqid|var_dump|print_r|var_export|sort|usort|uasort|uksort|ksort|krsort|asort|arsort|rsort|define|defined|constant|function_exists|method_exists|property_exists|class_exists|get_class|gettype|settype|func_get_args|dirname|basename|pathinfo|realpath|file_exists|sleep|usleep|serialize|header|headers_sent|http_build_query|parse_url|filter_var|session_start|session_destroy|session_regenerate_id|ob_start|ob_get_clean|error_log|trigger_error|sprintf|config|env|now|collect|app|view|response|request|route|url|asset|trans|__|abort|abort_if|abort_unless|dd|dump|logger|auth|session|old|csrf_token|bcrypt|data_get|value|tap|optional|throw_if|throw_unless)$/i;
const SUPERGLOBAL_RE = /\$_(GET|POST|REQUEST|COOKIE|FILES)\b|php:\/\/input/;
const PHP_AUTH_RE = /^(can|ability|abilities|role|permission|scope|scopes):|verified|password\.confirm/i;
const ROUTE_VERBS: Record<string, string> = { get: 'GET', post: 'POST', put: 'PUT', patch: 'PATCH', delete: 'DELETE', options: 'OPTIONS', any: 'ANY' };
const RESOURCE_ACTIONS: [action: string, method: string, suffix: string][] = [
  ['index', 'GET', ''], ['create', 'GET', '/create'], ['store', 'POST', ''], ['show', 'GET', '/{id}'], ['edit', 'GET', '/{id}/edit'],
  ['update', 'PUT', '/{id}'], ['update', 'PATCH', '/{id}'], ['destroy', 'DELETE', '/{id}'],
];
const THINK_RESOURCE_ACTIONS: [action: string, method: string, suffix: string][] = [
  ['index', 'GET', ''], ['create', 'GET', '/create'], ['save', 'POST', ''], ['read', 'GET', '/:id'], ['edit', 'GET', '/:id/edit'],
  ['update', 'PUT', '/:id'], ['delete', 'DELETE', '/:id'],
];
/** Web document roots stripped from a native script's URL. */
const DOCROOT_RE = /^(public|public_html|htdocs|www|web|html)\//;

interface ClassInfo { name: string; fqn: string; container: string; symbolId: string; node: Node; fields: Map<string, string>; methods: Map<string, string> }
interface RouteCtx { prefix: string[]; middlewares: string[]; controller: string | null; namespace: string | null }

const named = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c);
const lastSeg = (name: string) => name.replace(/^\\/, '').split('\\').pop() ?? name;
const truncate = (s: string, n: number) => (s.length > n ? s.slice(0, n) + '…' : s);
const oneLine = (s: string, n = 200) => truncate(s.replace(/\s+/g, ' ').trim(), n);

/** Value of a string literal without interpolation (single / double quoted, nowdoc), `X::class` → `X`; else null. */
export function phpString(n: Node | null | undefined): string | null {
  if (!n) return null;
  if (n.type === 'string' || n.type === 'encapsed_string' || n.type === 'nowdoc') {
    if (named(n).some((c) => c.type !== 'string_content' && c.type !== 'escape_sequence' && c.type !== 'string_value' && c.type !== 'nowdoc_body' && c.type !== 'heredoc_start' && c.type !== 'heredoc_end')) return null;
    if (n.type === 'nowdoc') return named(n).filter((c) => c.type === 'nowdoc_body').map((c) => c.text).join('');
    const t = n.text;
    return t.length >= 2 ? t.slice(1, -1).replace(/\\(['"\\])/g, '$1') : '';
  }
  if (n.type === 'class_constant_access_expression') {
    const parts = named(n);
    if (parts.length === 2 && parts[1]!.text === 'class') return parts[0]!.text;
    return null;
  }
  if (n.type === 'binary_expression' && n.childForFieldName('operator')?.text === '.') {
    const l = phpString(n.childForFieldName('left'));
    const r = phpString(n.childForFieldName('right'));
    return l !== null && r !== null ? l + r : null;
  }
  if (n.type === 'parenthesized_expression') return phpString(named(n)[0]);
  return null;
}

/** Arguments of an `arguments` node: `{ name, value }` (named arguments keep their name). */
export function phpArgs(args: Node | null | undefined): { name: string | null; value: Node }[] {
  const out: { name: string | null; value: Node }[] = [];
  for (const a of named(args)) {
    if (a.type !== 'argument') { out.push({ name: null, value: a }); continue; }
    const nameNode = a.childForFieldName('name');
    const parts = named(a).filter((c) => c.id !== nameNode?.id);
    const value = parts[parts.length - 1];
    if (value) out.push({ name: nameNode?.text ?? null, value });
  }
  return out;
}

/** `[k => v, v2]` → entries (key null for list elements). */
function arrayEntries(n: Node | null | undefined): { key: string | null; value: Node }[] {
  if (!n || n.type !== 'array_creation_expression') return [];
  const out: { key: string | null; value: Node }[] = [];
  for (const el of named(n)) {
    if (el.type !== 'array_element_initializer') continue;
    const parts = named(el);
    if (parts.length >= 2) out.push({ key: phpString(parts[0]), value: parts[parts.length - 1]! });
    else if (parts[0]) out.push({ key: null, value: parts[0] });
  }
  return out;
}

/** Strings of a string / array-of-strings / `X::class` argument (middleware lists, HTTP methods). */
function stringsOf(n: Node | null | undefined): string[] {
  if (!n) return [];
  if (n.type === 'array_creation_expression') return arrayEntries(n).flatMap((e) => stringsOf(e.value));
  const s = phpString(n);
  if (s !== null) return [n.type === 'class_constant_access_expression' ? lastSeg(s) : s];
  return [oneLine(n.text, 120)];
}

const LITERAL_TYPES = new Set(['string', 'nowdoc', 'integer', 'float', 'boolean', 'null', 'name', 'class_constant_access_expression']);
const HANDLE_ARG_RE = /^\$(conn|con|link|db|dbh|mysqli|pdo|ch|curl|handle|mysql|connection|stmt)\w*$/i;

function isBuilt(n: Node): boolean {
  if (n.type === 'binary_expression' && n.childForFieldName('operator')?.text === '.') return true;
  if ((n.type === 'encapsed_string' || n.type === 'heredoc' || n.type === 'shell_command_expression') && phpString(n) === null) {
    return n.type === 'shell_command_expression' ? named(n).some((c) => c.type !== 'string_content' && c.type !== 'escape_sequence') : true;
  }
  if (n.type === 'function_call_expression' && /^\\?(sprintf|vsprintf|implode|join|str_replace|strtr|str_repeat)$/i.test(n.childForFieldName('function')?.text ?? '')) return true;
  if (n.type === 'augmented_assignment_expression' && /\.=/.test(n.text)) return true;
  return false;
}

function isLiteral(n: Node): boolean {
  if (n.type === 'encapsed_string') return phpString(n) !== null;
  if (n.type === 'array_creation_expression') return arrayEntries(n).every((e) => isLiteral(e.value));
  if (n.type === 'unary_op_expression') return named(n).every(isLiteral);
  if (n.type === 'binary_expression') return named(n).every(isLiteral);
  return LITERAL_TYPES.has(n.type);
}

/**
 * PHP taint hint (the shared `taintHintOf` is Java / Go oriented): `string_concat` when an argument is built with
 * `.`, interpolation (double quotes, heredoc, backticks) or sprintf-like formatting; `constant` when every argument is a
 * literal (a leading connection handle such as `$conn` / `$ch` is ignored).
 */
export function phpTaintHint(node: Node | undefined): string | undefined {
  if (!node) return undefined;
  const values = node.type === 'arguments' ? phpArgs(node).map((a) => a.value) : [node];
  let built = false;
  const walk = (n: Node, depth: number): void => {
    if (built || depth > 12) return;
    if (isBuilt(n)) { built = true; return; }
    // Closures and nested calls are opaque: only the argument expression itself counts.
    if (CLOSURE_TYPES.has(n.type)) return;
    for (const c of named(n)) walk(c, depth + 1);
  };
  for (const v of values) walk(v, 0);
  if (node.type !== 'arguments') {
    // Statement-like sinks (include, backticks, echo): the expression under the keyword.
    for (const c of named(node)) walk(c, 0);
  }
  if (built) return 'string_concat';
  const rest = values.length >= 2 && values[0]!.type === 'variable_name' && HANDLE_ARG_RE.test(values[0]!.text) ? values.slice(1) : values;
  if (node.type === 'arguments' && rest.length > 0 && rest.every(isLiteral)) return 'constant';
  return undefined;
}

export function extractPhp(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const root = tree.rootNode;
  const repo = input.repo;

  // ---- namespace and use imports ----
  const nsOf = new Map<number, string>(); // top-level statement id → namespace
  const uses = new Map<string, string>(); // alias → FQN (classes)
  const funcUses = new Map<string, string>(); // function alias → namespace of the function
  const imports = new Set<string>();
  let firstNs: string | null = null;
  const readUse = (decl: Node) => {
    const isFunc = /^use\s+function\b/i.test(decl.text);
    if (/^use\s+const\b/i.test(decl.text)) return;
    const prefixNode = named(decl).find((c) => c.type === 'namespace_name');
    const prefix = prefixNode ? prefixNode.text.replace(/^\\/, '') : '';
    for (const clause of decl.descendantsOfType('namespace_use_clause')) {
      if (!clause) continue;
      const target = named(clause).find((c) => c.type === 'qualified_name' || c.type === 'name');
      if (!target) continue;
      const fqn = (prefix ? `${prefix}\\` : '') + target.text.replace(/^\\/, '');
      const alias = clause.childForFieldName('alias')?.text ?? lastSeg(fqn);
      imports.add(fqn);
      if (isFunc) funcUses.set(alias.toLowerCase(), fqn.includes('\\') ? fqn.slice(0, fqn.lastIndexOf('\\')) : '');
      else uses.set(alias.toLowerCase(), fqn);
    }
  };
  const topLevel: { node: Node; ns: string }[] = [];
  {
    let ns = '';
    const visitTop = (nodes: Node[]) => {
      for (const n of nodes) {
        if (n.type === 'namespace_definition') {
          const name = n.childForFieldName('name')?.text.replace(/^\\/, '') ?? '';
          firstNs ??= name;
          const body = n.childForFieldName('body');
          if (body) { const saved = ns; ns = name; visitTop(named(body)); ns = saved; } else ns = name;
          continue;
        }
        if (n.type === 'namespace_use_declaration') readUse(n);
        nsOf.set(n.id, ns);
        topLevel.push({ node: n, ns });
      }
    };
    visitTop(named(root));
  }
  const pkg = firstNs ?? input.path;
  fx.pkg = pkg;
  const nsAt = (node: Node): string => {
    let top: Node = node;
    for (let p = node.parent; p && p.type !== 'program'; p = p.parent) {
      if (nsOf.has(p.id)) return nsOf.get(p.id)!;
      top = p;
    }
    return nsOf.get(top.id) ?? firstNs ?? '';
  };
  /** Fully qualified class name as PHP resolves it (use imports, then the current namespace). */
  const resolveClass = (name: string, at: Node): string => {
    if (name.startsWith('\\')) return name.slice(1);
    const [head, ...rest] = name.split('\\');
    const imported = uses.get(head!.toLowerCase());
    if (imported) return [imported, ...rest].join('\\');
    const ns = nsAt(at);
    return ns ? `${ns}\\${name}` : name;
  };
  const containerOf = (ns: string) => ns || input.path;

  // ---- symbols ----
  const classes = new Map<number, ClassInfo>();
  const funcIds = new Map<number, string>();
  const localTypes = new Map<number, Map<string, string>>();
  const paramTypesOf = (fn: Node, locals: Map<string, string>): number => {
    let arity = 0;
    for (const p of named(fn.childForFieldName('parameters'))) {
      if (!/parameter/.test(p.type)) continue;
      arity++;
      const t = p.childForFieldName('type');
      const vn = p.childForFieldName('name')?.text.replace(/^\$/, '');
      const tn = t ? simpleType(t) : null;
      if (vn && tn) locals.set(vn, tn);
    }
    return arity;
  };
  const visit = (node: Node, cls: ClassInfo | null) => {
    if (CLASS_TYPES.has(node.type)) {
      const name = node.childForFieldName('name')?.text ?? '?';
      const ns = nsAt(node);
      const container = containerOf(ns);
      const symbolId = `${repo}:${input.path}#${container}.${name}`;
      const info: ClassInfo = { name, fqn: ns ? `${ns}\\${name}` : name, container: `${container}.${name}`, symbolId, node, fields: new Map(), methods: new Map() };
      for (const member of named(node.childForFieldName('body'))) {
        if (member.type !== 'property_declaration') continue;
        const t = member.childForFieldName('type');
        const tn = t ? simpleType(t) : null;
        if (!tn) continue;
        for (const el of member.descendantsOfType('property_element')) {
          const vn = el?.childForFieldName('name')?.text.replace(/^\$/, '') ?? named(el).find((c) => c.type === 'variable_name')?.text.replace(/^\$/, '');
          if (vn) info.fields.set(vn, tn);
        }
      }
      classes.set(node.id, info);
      fx.symbols.push({
        symbolId, repo, kind: node.type === 'interface_declaration' ? 'interface' : 'class', name, container, path: input.path,
        range: rangeOf(node), signature: signatureOf(node), qualifiedName: ns ? `${ns}\\${name}` : name,
      });
      for (const c of named(node)) visit(c, info);
      return;
    }
    if (FUNC_TYPES.has(node.type)) {
      const name = node.childForFieldName('name')?.text ?? '?';
      const locals = new Map<string, string>();
      const arity = paramTypesOf(node, locals);
      const isMethod = node.type === 'method_declaration' && !!cls;
      const ns = nsAt(node);
      const container = isMethod ? cls!.container : containerOf(ns);
      const symbolId = `${repo}:${input.path}#${container}.${name}(${arity})`;
      funcIds.set(node.id, symbolId);
      localTypes.set(node.id, locals);
      if (isMethod) {
        cls!.methods.set(name.toLowerCase(), symbolId);
        // Constructor promotion (`private OrderRepo $repo`) and `$this->repo = $repo` from typed parameters.
        if (name.toLowerCase() === '__construct') {
          for (const p of named(node.childForFieldName('parameters'))) {
            if (p.type !== 'property_promotion_parameter') continue;
            const t = p.childForFieldName('type');
            const vn = p.childForFieldName('name')?.text.replace(/^\$/, '');
            const tn = t ? simpleType(t) : null;
            if (vn && tn) cls!.fields.set(vn, tn);
          }
          for (const a of node.descendantsOfType('assignment_expression')) {
            const left = a?.childForFieldName('left');
            const right = a?.childForFieldName('right');
            if (left?.type === 'member_access_expression' && left.childForFieldName('object')?.text === '$this' && right?.type === 'variable_name') {
              const tn = locals.get(right.text.replace(/^\$/, ''));
              const field = left.childForFieldName('name')?.text;
              if (tn && field && !cls!.fields.has(field)) cls!.fields.set(field, tn);
            }
          }
        }
      }
      fx.symbols.push({
        symbolId, repo, kind: isMethod ? 'method' : 'func', name, container, path: input.path, range: rangeOf(node),
        signature: signatureOf(node),
        qualifiedName: isMethod ? `${cls!.fqn}::${name}` : ns ? `${ns}\\${name}` : name,
      });
      // Local variables assigned with `new Foo(...)`.
      const body = node.childForFieldName('body');
      for (const a of body?.descendantsOfType('assignment_expression') ?? []) {
        const left = a?.childForFieldName('left');
        const right = a?.childForFieldName('right');
        if (left?.type === 'variable_name' && right?.type === 'object_creation_expression') {
          const cn = named(right).find((c) => c.type === 'name' || c.type === 'qualified_name');
          if (cn) locals.set(left.text.replace(/^\$/, ''), lastSeg(cn.text));
        }
      }
      for (const c of named(node)) visit(c, cls);
      return;
    }
    for (const c of named(node)) visit(c, cls);
  };
  visit(root, null);

  // File-level `<main>`: top-level executable code (route files, native scripts, templates).
  const hasMain = topLevel.some(({ node }) => !DECLARATION_TYPES.has(node.type));
  const lastLine = root.endPosition.row + 1;
  const mainId = hasMain ? `${repo}:${input.path}#<main>(0)` : null;
  if (mainId) {
    fx.symbols.push({
      symbolId: mainId, repo, kind: 'func', name: '<main>', container: pkg, path: input.path,
      range: { startLine: 1, endLine: Math.max(1, lastLine) }, signature: `<main> ${input.path}`, qualifiedName: `${input.path}#<main>`,
    });
  }

  const enclosingFunc = (node: Node): Node | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (FUNC_TYPES.has(p.type)) return p;
    return null;
  };
  const enclosingClass = (node: Node): ClassInfo | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (CLASS_TYPES.has(p.type)) return classes.get(p.id) ?? null;
    return null;
  };
  const enclosingSymbol = (node: Node): string | null => {
    const f = enclosingFunc(node);
    if (f) return funcIds.get(f.id) ?? null;
    return enclosingClass(node)?.symbolId ?? mainId;
  };
  /** Statically known class of a receiver expression: `$this->repo` (typed property), `$var` (parameter / `new`). */
  const typeOf = (receiver: Node | null, at: Node): string | null => {
    if (!receiver) return null;
    if (receiver.type === 'member_access_expression' || receiver.type === 'nullsafe_member_access_expression') {
      if (receiver.childForFieldName('object')?.text !== '$this') return null;
      const field = receiver.childForFieldName('name')?.text;
      return field ? enclosingClass(at)?.fields.get(field) ?? null : null;
    }
    if (receiver.type === 'variable_name') {
      if (receiver.text === '$this') return null;
      const f = enclosingFunc(at);
      return f ? localTypes.get(f.id)?.get(receiver.text.replace(/^\$/, '')) ?? null : null;
    }
    if (receiver.type === 'object_creation_expression') {
      const cn = named(receiver).find((c) => c.type === 'name' || c.type === 'qualified_name');
      return cn ? lastSeg(cn.text) : null;
    }
    if (receiver.type === 'parenthesized_expression') return typeOf(named(receiver)[0] ?? null, at);
    return null;
  };

  // ---- calls ----
  for (const type of CALL_TYPES) {
    for (const call of root.descendantsOfType(type)) {
      if (!call) continue;
      const from = enclosingSymbol(call);
      if (!from) continue;
      const args = call.childForFieldName('arguments') ?? named(call).find((c) => c.type === 'arguments') ?? null;
      const arity = named(args).length;
      const line = call.startPosition.row + 1;
      if (type === 'function_call_expression') {
        const fn = call.childForFieldName('function');
        if (!fn || (fn.type !== 'name' && fn.type !== 'qualified_name')) continue;
        const name = lastSeg(fn.text);
        if (fn.type === 'name' && BUILTIN_RE.test(name)) continue;
        const qualified = fn.type === 'qualified_name' && fn.text.replace(/^\\/, '').includes('\\');
        const imported = funcUses.get(name.toLowerCase());
        const receiverImport = qualified ? (() => { const q = resolveClass(fn.text, call); return q.slice(0, q.lastIndexOf('\\')); })() : imported ?? null;
        fx.calls.push({ from, method: name, receiverText: null, receiverType: null, receiverImport, arity, line, calleeText: truncate(fn.text, 200) });
      } else if (type === 'member_call_expression' || type === 'nullsafe_member_call_expression') {
        const nameNode = call.childForFieldName('name');
        if (nameNode?.type !== 'name') continue;
        const obj = call.childForFieldName('object');
        fx.calls.push({
          from, method: nameNode.text, receiverText: obj?.text ?? null, receiverType: obj?.text === '$this' ? null : typeOf(obj, call), receiverImport: null,
          arity, line, calleeText: truncate(`${oneLine(obj?.text ?? '', 150)}->${nameNode.text}`, 200),
        });
      } else if (type === 'scoped_call_expression') {
        const nameNode = call.childForFieldName('name');
        const scope = call.childForFieldName('scope');
        if (nameNode?.type !== 'name' || !scope) continue;
        const scopeText = scope.text;
        if (SELF_SCOPES.has(scopeText.toLowerCase()) || scope.type === 'relative_scope') {
          fx.calls.push({ from, method: nameNode.text, receiverText: scopeText.toLowerCase(), receiverType: null, receiverImport: null, arity, line, calleeText: `${scopeText}::${nameNode.text}` });
        } else if (scope.type === 'name' || scope.type === 'qualified_name') {
          const fqn = resolveClass(scopeText, call);
          fx.calls.push({ from, method: nameNode.text, receiverText: scopeText, receiverType: lastSeg(fqn), receiverImport: fqn, arity, line, calleeText: `${scopeText}::${nameNode.text}` });
        } else {
          fx.calls.push({ from, method: nameNode.text, receiverText: scopeText, receiverType: typeOf(scope, call), receiverImport: null, arity, line, calleeText: truncate(`${scopeText}::${nameNode.text}`, 200) });
        }
      } else {
        const cn = named(call).find((c) => c.type === 'name' || c.type === 'qualified_name');
        if (!cn) continue;
        const fqn = resolveClass(cn.text, call);
        fx.calls.push({ from, method: '__construct', receiverText: cn.text, receiverType: lastSeg(fqn), receiverImport: fqn, arity, line, calleeText: `new ${cn.text}` });
      }
    }
  }

  // ---- routes (Laravel / ThinkPHP): chains, groups, handlers ----
  const routeFacade = (scope: Node | null): boolean => {
    if (!scope || (scope.type !== 'name' && scope.type !== 'qualified_name')) return false;
    return lastSeg(scope.text) === 'Route';
  };
  interface ChainLink { name: string; args: Node | null; node: Node }
  /** Calls below `call` in a fluent chain, root first; null when the chain does not start at `Route::`. */
  const chainBelow = (call: Node): ChainLink[] | null => {
    const links: ChainLink[] = [];
    let cur: Node | null = call.type === 'member_call_expression' ? call.childForFieldName('object') : null;
    if (call.type === 'scoped_call_expression') return routeFacade(call.childForFieldName('scope')) ? [] : null;
    while (cur) {
      if (cur.type === 'member_call_expression') {
        links.push({ name: cur.childForFieldName('name')?.text ?? '', args: cur.childForFieldName('arguments'), node: cur });
        cur = cur.childForFieldName('object');
      } else if (cur.type === 'scoped_call_expression') {
        if (!routeFacade(cur.childForFieldName('scope'))) return null;
        links.push({ name: cur.childForFieldName('name')?.text ?? '', args: cur.childForFieldName('arguments'), node: cur });
        return links.reverse();
      } else return null;
    }
    return null;
  };
  /** Calls chained after `call` (`->middleware(...)->name(...)`). */
  const chainAbove = (call: Node): ChainLink[] => {
    const links: ChainLink[] = [];
    let cur: Node = call;
    while (cur.parent?.type === 'member_call_expression' && cur.parent.childForFieldName('object')?.id === cur.id) {
      cur = cur.parent;
      links.push({ name: cur.childForFieldName('name')?.text ?? '', args: cur.childForFieldName('arguments'), node: cur });
    }
    return links;
  };
  const applyLinks = (ctx: RouteCtx, links: ChainLink[]) => {
    for (const l of links) {
      const a = phpArgs(l.args);
      if (l.name === 'prefix') ctx.prefix.push(phpString(a[0]?.value) ?? '{?}');
      else if (l.name === 'middleware') ctx.middlewares.push(...a.flatMap((x) => stringsOf(x.value)));
      else if (l.name === 'controller') ctx.controller = lastSeg(phpString(a[0]?.value) ?? '') || ctx.controller;
      else if (l.name === 'namespace') ctx.namespace = phpString(a[0]?.value) ?? ctx.namespace;
    }
  };
  /** Group closures around a route call, outermost first (Laravel / ThinkPHP `group`). */
  const groupCtx = (call: Node, think: boolean): RouteCtx => {
    const groups: Node[] = [];
    for (let p: Node | null = call.parent; p; p = p.parent) {
      if (!CLOSURE_TYPES.has(p.type)) continue;
      const g = p.parent?.type === 'argument' ? p.parent.parent?.parent : null;
      if (g && (g.type === 'member_call_expression' || g.type === 'scoped_call_expression') && g.childForFieldName('name')?.text === 'group') groups.push(g);
    }
    const ctx: RouteCtx = { prefix: [], middlewares: [], controller: null, namespace: null };
    if (!think && /(^|\/)routes\/api\.php$/.test(input.path)) ctx.prefix.push('api');
    for (const g of groups.reverse()) {
      const below = chainBelow(g);
      if (below === null) continue;
      applyLinks(ctx, below);
      const a = phpArgs(g.childForFieldName('arguments'));
      const first = a[0]?.value;
      if (first && !CLOSURE_TYPES.has(first.type)) {
        if (first.type === 'array_creation_expression') {
          for (const e of arrayEntries(first)) {
            if (e.key === 'prefix') ctx.prefix.push(phpString(e.value) ?? '{?}');
            else if (e.key === 'middleware') ctx.middlewares.push(...stringsOf(e.value));
            else if (e.key === 'namespace') ctx.namespace = phpString(e.value);
            else if (e.key === 'controller') ctx.controller = lastSeg(phpString(e.value) ?? '') || null;
          }
        } else ctx.prefix.push(phpString(first) ?? '{?}');
      }
      applyLinks(ctx, chainAbove(g));
    }
    return ctx;
  };
  /** `Class.method` handler: resolved here when the class is in this file, otherwise by `assemble` (class + method). */
  const classRef = (cls: string, method: string): HandlerRef => {
    const c = lastSeg(cls);
    const local = [...classes.values()].find((x) => x.name === c)?.methods.get(method.toLowerCase());
    return local ? { symbolId: local } : { text: `${c}.${method}`, className: c };
  };
  const routeHandler = (n: Node | undefined, ctx: RouteCtx, think: boolean): HandlerRef | null => {
    if (!n) return null;
    if (CLOSURE_TYPES.has(n.type)) {
      const sym = enclosingSymbol(n);
      return { ...(sym ? { symbolId: sym } : {}), range: rangeOf(n) };
    }
    const ref = classRef;
    if (n.type === 'array_creation_expression') {
      const [c, m] = arrayEntries(n).map((e) => phpString(e.value));
      return c && m ? ref(c, m) : null;
    }
    if (n.type === 'class_constant_access_expression') {
      const c = phpString(n);
      return c ? ref(c, '__invoke') : null;
    }
    const s = phpString(n);
    if (s === null) return { text: oneLine(n.text, 120) };
    const at = /^(.+?)(?:@|::)(\w+)$/.exec(s);
    if (at) return ref(at[1]!, at[2]!);
    if (think && s.includes('/')) {
      const parts = s.replace(/^\//, '').split('/');
      const action = parts.pop()!;
      const c = parts.pop() ?? '';
      return ref(c.charAt(0).toUpperCase() + c.slice(1).replace(/[._](\w)/g, (_m, x: string) => x.toUpperCase()), action);
    }
    if (ctx.controller && /^\w+$/.test(s)) return ref(ctx.controller, s);
    return null;
  };
  const authOf = (mws: string[]) => mws.filter((m) => AUTH_NAME_RE.test(m) || PHP_AUTH_RE.test(m));
  const pushEntry = (ruleId: string, framework: string, method: string, path: string, handler: HandlerRef, node: Node, mws: string[]) => {
    const entry: RawEntry = {
      ruleId, framework, httpMethod: method, pathTemplate: path, handler, path: input.path, range: rangeOf(node),
      middlewares: [...new Set(mws)], authSignals: [...new Set(authOf(mws))],
    };
    fx.entries.push(entry);
  };
  const routeEntries = (ruleId: string, framework: string, call: Node, verb: string, think: boolean) => {
    const below = chainBelow(call);
    if (below === null) return;
    const ctx = groupCtx(call, think);
    applyLinks(ctx, below);
    const above = chainAbove(call);
    applyLinks(ctx, above);
    const args = phpArgs(call.childForFieldName('arguments'));
    const v = verb.toLowerCase();
    const full = (p: string) => {
      const path = think ? p.replace(/\[:(\w+)\]/g, ':$1').replace(/<(\w+)\??>/g, ':$1') : p;
      return joinRoute(ctx.prefix.reduce((acc, x) => joinRoute(acc, x), ''), path);
    };
    if (v === 'resource' || v === 'apiresource' || v === 'resources' || v === 'apiresources') {
      if (v === 'resources' || v === 'apiresources') return; // array form: not expanded
      const name = phpString(args[0]?.value);
      const ctrl = phpString(args[1]?.value);
      if (name === null || !ctrl) return;
      const only = above.find((l) => l.name === 'only');
      const except = above.find((l) => l.name === 'except');
      const onlySet = only ? new Set(phpArgs(only.args).flatMap((a) => stringsOf(a.value))) : null;
      const exceptSet = new Set(except ? phpArgs(except.args).flatMap((a) => stringsOf(a.value)) : []);
      const actions = think ? THINK_RESOURCE_ACTIONS : RESOURCE_ACTIONS.filter(([a]) => v !== 'apiresource' || (a !== 'create' && a !== 'edit'));
      // `photos.comments` nests: /photos/{photo}/comments.
      const base = name.split('.').map((seg, i, all) => (i < all.length - 1 ? `${seg}/{${seg}}` : seg)).join('/');
      for (const [action, method, suffix] of actions) {
        if ((onlySet && !onlySet.has(action)) || exceptSet.has(action)) continue;
        const target = classRef(lastSeg(ctrl.replace(/(@|::)\w+$/, '')), action);
        pushEntry(ruleId, framework, method, full(base + suffix), target, call, ctx.middlewares);
      }
      return;
    }
    let methods: string[];
    let pathArg: Node | undefined;
    let handlerArg: Node | undefined;
    if (v === 'match') {
      methods = stringsOf(args[0]?.value).map((m) => m.toUpperCase());
      pathArg = args[1]?.value;
      handlerArg = args[2]?.value;
    } else if (v === 'rule') {
      pathArg = args[0]?.value;
      handlerArg = args[1]?.value;
      const m = phpString(args[2]?.value);
      methods = m && m !== '*' ? m.split('|').map((x) => x.trim().toUpperCase()).filter(Boolean) : ['ANY'];
    } else {
      methods = [ROUTE_VERBS[v] ?? 'ANY'];
      pathArg = args[0]?.value;
      handlerArg = args[args.length - 1]?.value;
      if (args.length < 2) return;
    }
    const p = phpString(pathArg);
    if (p === null) return;
    const h = routeHandler(handlerArg, ctx, think) ?? { text: oneLine(handlerArg?.text ?? 'anonymous', 120) };
    for (const m of methods.length ? methods : ['ANY']) pushEntry(ruleId, framework, m, full(p), h, call, ctx.middlewares);
  };

  // ---- Symfony: #[Route] attributes / @Route docblocks, #[IsGranted] ----
  const attributesOf = (decl: Node): Node[] => {
    const list = decl.childForFieldName('attributes') ?? named(decl).find((c) => c.type === 'attribute_list');
    return list ? list.descendantsOfType('attribute').filter((a): a is Node => !!a) : [];
  };
  const attrName = (a: Node) => lastSeg(named(a).find((c) => c.type === 'name' || c.type === 'qualified_name')?.text ?? '');
  const docOf = (decl: Node): string => {
    let prev = decl.previousNamedSibling;
    while (prev && prev.type === 'attribute_list') prev = prev.previousNamedSibling;
    return prev?.type === 'comment' && prev.text.startsWith('/**') ? prev.text : '';
  };
  const routeAttr = (decl: Node): { paths: string[]; methods: string[] }[] => {
    const out: { paths: string[]; methods: string[] }[] = [];
    for (const a of attributesOf(decl)) {
      if (!/^(Route|Get|Post|Put|Patch|Delete)$/.test(attrName(a))) continue;
      const args = phpArgs(a.childForFieldName('parameters') ?? named(a).find((c) => c.type === 'arguments'));
      const pathArg = args.find((x) => x.name === 'path' || x.name === 'value') ?? args.find((x) => x.name === null);
      const methodsArg = args.find((x) => x.name === 'methods');
      const verb = attrName(a) === 'Route' ? null : attrName(a).toUpperCase();
      out.push({ paths: [phpString(pathArg?.value) ?? ''], methods: verb ? [verb] : methodsArg ? stringsOf(methodsArg.value).map((m) => m.toUpperCase()) : [] });
    }
    for (const m of docOf(decl).matchAll(/@Route\(\s*"([^"]*)"([^)]*)\)/g)) {
      const methods = /methods\s*=\s*\{([^}]*)\}/.exec(m[2]!)?.[1]?.match(/"(\w+)"/g)?.map((x) => x.replace(/"/g, '').toUpperCase()) ?? [];
      out.push({ paths: [m[1]!], methods });
    }
    return out;
  };
  const symfonyEntries = (ruleId: string, method: Node) => {
    const routes = routeAttr(method);
    if (!routes.length) return;
    const cls = enclosingClass(method);
    const symbolId = funcIds.get(method.id);
    if (!cls || !symbolId || cls.node.type !== 'class_declaration') return;
    const prefixes = routeAttr(cls.node).flatMap((r) => r.paths);
    for (const r of routes) {
      for (const prefix of prefixes.length ? prefixes : ['']) for (const p of r.paths) for (const hm of r.methods.length ? r.methods : ['ANY']) {
        fx.entries.push({ ruleId, framework: 'symfony', httpMethod: hm, pathTemplate: joinRoute(prefix, p), handler: { symbolId }, path: input.path, range: rangeOf(method), middlewares: [], authSignals: [] });
      }
    }
  };
  const addSignal = (sig: AuthSignal) => {
    if (!fx.authSignals.some((s) => s.target === sig.target && s.detail === sig.detail)) fx.authSignals.push(sig);
  };

  // ---- native scripts: top-level code reading request superglobals ----
  const nativeEntry = (ruleId: string) => {
    if (!mainId || !/\.php$/i.test(input.path)) return;
    const stmts = topLevel.map((t) => t.node).filter((n) => !DECLARATION_TYPES.has(n.type) || n.type === 'text_interpolation');
    const readsInput = (n: Node): boolean => SUPERGLOBAL_RE.test(n.text) && (n.descendantsOfType('variable_name').some((v) => !!v && /^\$_(GET|POST|REQUEST|COOKIE|FILES)$/.test(v.text) && !insideDecl(v)) || /php:\/\/input/.test(n.text));
    const firstRead = stmts.findIndex(readsInput);
    if (firstRead < 0) return;
    const mws: string[] = [];
    stmts.forEach((s, i) => {
      if (s.type === 'if_statement' && /\$_SESSION\b/.test(s.childForFieldName('condition')?.text ?? '') && /\b(exit|die|header|return|redirect|throw)\b/i.test(s.childForFieldName('body')?.text ?? s.text)) {
        mws.push(oneLine(`if ${s.childForFieldName('condition')?.text ?? ''}`, 200));
      } else if (i < firstRead && (s.type === 'expression_statement') && AUTH_NAME_RE.test(s.text.replace(/\bsession_(start|name|set_cookie_params|regenerate_id)\b/g, '')) && /(include|require|\w+\s*\()/.test(s.text) && !SUPERGLOBAL_RE.test(s.text)) {
        mws.push(oneLine(s.text.replace(/;$/, ''), 200));
      }
    });
    const url = '/' + input.path.replace(DOCROOT_RE, '');
    fx.entries.push({ ruleId, framework: 'php', httpMethod: 'ANY', pathTemplate: url, handler: { symbolId: mainId }, path: input.path, range: rangeOf(stmts[firstRead]!), middlewares: mws, authSignals: [...mws] });
    for (const d of mws) addSignal({ target: mainId, kind: 'middleware', detail: d, ruleId });
  };
  const insideDecl = (n: Node): boolean => {
    for (let p = n.parent; p; p = p.parent) if (FUNC_TYPES.has(p.type) || CLASS_TYPES.has(p.type)) return true;
    return false;
  };

  // ---- sockets, queue consumers, schedules and commands (found in code; never HTTP entries) ----
  type Channel = NonNullable<RawEntry['channel']>;
  const pushChannel = (ruleId: string, framework: string, channel: Channel, handler: HandlerRef, node: Node) => {
    fx.entries.push({ ruleId, framework, httpMethod: '', pathTemplate: '', handler, path: input.path, range: rangeOf(node), middlewares: [], authSignals: [], channel });
  };
  const closureRef = (n: Node): HandlerRef => {
    const sym = enclosingSymbol(n);
    return { ...(sym ? { symbolId: sym } : {}), range: rangeOf(n) };
  };
  /** Where a callback argument points: closure, `[$this, 'm']` / `[X::class, 'm']`, `X::class`, `new X`, `'X@m'`, `$var = fn`. */
  const callbackRef = (n: Node | undefined, at: Node, method = '__invoke'): HandlerRef | null => {
    if (!n) return null;
    if (CLOSURE_TYPES.has(n.type)) return closureRef(n);
    if (n.type === 'array_creation_expression') {
      const [o, m] = arrayEntries(n).map((e) => e.value);
      const mn = phpString(m);
      const cn = o?.text === '$this' ? enclosingClass(at)?.name ?? null : phpString(o);
      return cn && mn ? classRef(cn, mn) : null;
    }
    if (n.type === 'object_creation_expression') {
      const cn = named(n).find((c) => c.type === 'name' || c.type === 'qualified_name');
      return cn ? classRef(cn.text, method) : null;
    }
    if (n.type === 'variable_name') {
      const scope = enclosingFunc(at) ?? root;
      for (const a of scope.descendantsOfType('assignment_expression')) {
        const right = a?.childForFieldName('right');
        if (a?.childForFieldName('left')?.text === n.text && right && a.startIndex < at.startIndex) return callbackRef(right, at, method);
      }
      return null;
    }
    const s = phpString(n);
    if (s === null) return null;
    if (n.type === 'class_constant_access_expression') return classRef(s, method);
    const cm = /^(.+?)(?:@|::)(\w+)$/.exec(s);
    return cm ? classRef(cm[1]!, cm[2]!) : { text: s };
  };
  const methodRef = (cls: ClassInfo, ...names: string[]): HandlerRef | null => {
    for (const n of names) { const id = cls.methods.get(n.toLowerCase()); if (id) return { symbolId: id }; }
    return null;
  };
  const clauseNames = (cls: ClassInfo, type: string) => named(cls.node).filter((c) => c.type === type).flatMap((c) => named(c).map((x) => lastSeg(x.text)));
  const propString = (cls: ClassInfo, prop: string): string | null => {
    for (const member of named(cls.node.childForFieldName('body'))) {
      if (member.type !== 'property_declaration') continue;
      for (const el of member.descendantsOfType('property_element')) {
        if (el?.childForFieldName('name')?.text === `$${prop}`) return phpString(el.childForFieldName('default_value'));
      }
    }
    return null;
  };
  const attrArgs = (a: Node) => phpArgs(a.childForFieldName('parameters') ?? named(a).find((c) => c.type === 'arguments'));
  const attrArg = (a: Node, name: string, pos: number): Node | undefined => {
    const args = attrArgs(a);
    return args.find((x) => x.name === name)?.value ?? args.filter((x) => x.name === null)[pos]?.value;
  };
  const firstWord = (s: string) => s.trim().split(/[\s{]/)[0] ?? '';
  const firstParamType = (method: Node): string | null => {
    const p = named(method.childForFieldName('parameters')).find((c) => /parameter/.test(c.type));
    const t = p?.childForFieldName('type');
    return t ? simpleType(t) : null;
  };
  const FREQ_RE = /^(cron|every\w+|hourly\w*|daily\w*|weekly\w*|monthly\w*|quarterly\w*|yearly\w*|twice\w+|lastDayOfMonth|weekdays|weekends|mondays|tuesdays|wednesdays|thursdays|fridays|saturdays|sundays|days|at|between|unlessBetween|timezone)$/;
  const frequencyOf = (call: Node): string => {
    const parts = chainAbove(call).filter((l) => FREQ_RE.test(l.name)).map((l) => {
      if (l.name === 'cron') return phpString(phpArgs(l.args)[0]?.value) ?? oneLine(l.args?.text ?? '', 80);
      return `${l.name}${oneLine(l.args?.text ?? '()', 80)}`;
    });
    return parts.length ? parts.join('->') : '* * * * *';
  };
  const channelEntries = () => {
    // Classes: Ratchet components, queued jobs / listeners, Messenger handlers, cron tasks, console commands.
    for (const cls of classes.values()) {
      if (cls.node.type !== 'class_declaration') continue;
      const ifaces = new Set(clauseNames(cls, 'class_interface_clause'));
      const bases = new Set(clauseNames(cls, 'base_clause'));
      const attrs = attributesOf(cls.node);
      if (ifaces.has('MessageComponentInterface')) {
        const h = methodRef(cls, 'onMessage');
        if (h) pushChannel('php.ratchet.component', 'ratchet', { kind: 'socket', protocol: 'websocket', key: `ws:${cls.name}`, route: cls.name }, h, cls.node);
      }
      if (ifaces.has('ShouldQueue')) {
        const h = methodRef(cls, 'handle', '__invoke');
        if (h) pushChannel('php.laravel.job', 'laravel', { kind: 'message', protocol: 'laravel-queue', key: `mq:laravel-queue:${cls.name}`, route: cls.name }, h, cls.node);
      }
      const messenger = (method: Node | null, handles: Node | undefined) => {
        const symbolId = method ? funcIds.get(method.id) : undefined;
        const msg = (handles ? lastSeg(phpString(handles) ?? '') : '') || (method ? firstParamType(method) : null) || cls.name;
        pushChannel('php.symfony.messenger', 'symfony', { kind: 'message', protocol: 'symfony-messenger', key: `mq:symfony-messenger:${msg}`, route: msg }, symbolId ? { symbolId } : { text: `${cls.name}.__invoke`, className: cls.name }, method ?? cls.node);
      };
      const methodNode = (name: string) => named(cls.node.childForFieldName('body')).find((m) => m.type === 'method_declaration' && m.childForFieldName('name')?.text.toLowerCase() === name.toLowerCase()) ?? null;
      const classHandler = attrs.find((a) => attrName(a) === 'AsMessageHandler');
      if (classHandler) messenger(methodNode(phpString(attrArg(classHandler, 'method', 99)) ?? '__invoke'), attrArg(classHandler, 'handles', 99));
      else if (ifaces.has('MessageHandlerInterface')) messenger(methodNode('__invoke'), undefined);
      for (const m of named(cls.node.childForFieldName('body')).filter((x) => x.type === 'method_declaration')) {
        const a = attributesOf(m).find((x) => attrName(x) === 'AsMessageHandler');
        if (a) messenger(m, attrArg(a, 'handles', 99));
      }
      // Symfony Scheduler: #[AsCronTask('0 * * * *')] / #[AsPeriodicTask(frequency: '1 hour')] on the class or a method.
      const cronDecls = [cls.node, ...named(cls.node.childForFieldName('body')).filter((x) => x.type === 'method_declaration')];
      for (const decl of cronDecls) {
        for (const a of attributesOf(decl)) {
          const an = attrName(a);
          if (an !== 'AsCronTask' && an !== 'AsPeriodicTask') continue;
          const when = attrArg(a, an === 'AsCronTask' ? 'expression' : 'frequency', 0);
          const route = phpString(when) ?? oneLine(when?.text ?? '', 80);
          const mName = decl === cls.node ? phpString(attrArg(a, 'method', 99)) ?? '__invoke' : decl.childForFieldName('name')?.text ?? '__invoke';
          const h = methodRef(cls, mName) ?? { text: `${cls.name}.${mName}`, className: cls.name };
          const key = mName === '__invoke' ? cls.name : `${cls.name}.${mName}`;
          pushChannel('php.symfony.cron', 'symfony', { kind: 'schedule', protocol: 'cron', key: `cron:${key}`, route }, h, decl);
        }
      }
      // Console commands: Symfony (#[AsCommand], $defaultName, ->setName in configure) before Laravel ($signature / $name).
      const asCommand = attrs.find((a) => attrName(a) === 'AsCommand');
      const setName = methodNode('configure')?.descendantsOfType('member_call_expression').find((c) => c?.childForFieldName('name')?.text === 'setName');
      const symfonyName = (asCommand ? phpString(attrArg(asCommand, 'name', 0)) : null)
        ?? (bases.has('Command') ? propString(cls, 'defaultName') ?? (setName ? phpString(phpArgs(setName.childForFieldName('arguments'))[0]?.value) : null) : null);
      if (symfonyName) {
        const name = symfonyName.split('|').filter(Boolean)[0] ?? symfonyName;
        const h = methodRef(cls, 'execute', '__invoke') ?? { text: `${cls.name}.execute`, className: cls.name };
        pushChannel('php.symfony.command', 'symfony', { kind: 'cli', protocol: 'cli', key: `cli:${name}`, route: name }, h, cls.node);
      } else if (bases.has('Command')) {
        const sig = propString(cls, 'signature') ?? propString(cls, 'name');
        const name = sig ? firstWord(sig) : '';
        const h = methodRef(cls, 'handle', '__invoke');
        if (name && h) pushChannel('php.laravel.command', 'laravel', { kind: 'cli', protocol: 'cli', key: `cli:${name}`, route: name }, h, cls.node);
      }
    }

    // Calls: Swoole `->on('message')`, Workerman `websocket://` workers, Broadcast::channel, basic_consume, schedules, Artisan::command.
    const wsServer = root.descendantsOfType('object_creation_expression').find((n) => {
      const cn = n ? named(n).find((c) => c.type === 'name' || c.type === 'qualified_name')?.text ?? '' : '';
      return !!n && /^((Open)?Swoole\\WebSocket\\Server|swoole_websocket_server)$/i.test(resolveClass(cn, n).replace(/^.*\\(?=swoole_websocket_server$)/i, ''));
    });
    for (const call of root.descendantsOfType('member_call_expression')) {
      if (!call) continue;
      const name = call.childForFieldName('name')?.text ?? '';
      const args = phpArgs(call.childForFieldName('arguments'));
      if (name.toLowerCase() === 'on' && wsServer && phpString(args[0]?.value)?.toLowerCase() === 'message') {
        const wa = phpArgs(named(wsServer).find((c) => c.type === 'arguments'));
        const host = phpString(wa[0]?.value) ?? '*';
        const port = wa[1]?.value.text ?? '';
        const route = port ? `${host}:${port}` : host;
        const h = callbackRef(args[1]?.value, call) ?? closureRef(call);
        pushChannel('php.swoole.websocket', 'swoole', { kind: 'socket', protocol: 'websocket', key: `ws:${route}`, route }, h, call);
      } else if (name === 'basic_consume') {
        const qv = args.find((a) => a.name === 'queue')?.value ?? args.filter((a) => a.name === null)[0]?.value;
        const queue = phpString(qv) ?? oneLine(qv?.text ?? '?', 80);
        const cb = args.find((a) => a.name === 'callback')?.value ?? args.filter((a) => a.name === null)[6]?.value;
        const h = callbackRef(cb, call) ?? closureRef(call);
        pushChannel('php.amqp.consume', 'php-amqplib', { kind: 'message', protocol: 'rabbitmq', key: `mq:rabbitmq:${queue}`, route: queue }, h, call);
      } else if (/^(command|job|call|exec)$/.test(name) && /^\$schedule$/i.test(call.childForFieldName('object')?.text ?? '')) {
        scheduleEntry(call, name, args);
      }
    }
    for (const call of root.descendantsOfType('scoped_call_expression')) {
      if (!call) continue;
      const scope = lastSeg(call.childForFieldName('scope')?.text ?? '');
      const name = call.childForFieldName('name')?.text ?? '';
      const args = phpArgs(call.childForFieldName('arguments'));
      if (scope === 'Broadcast' && name === 'channel') {
        const ch = phpString(args[0]?.value);
        if (ch === null) continue;
        const h = callbackRef(args[1]?.value, call, 'join') ?? closureRef(call);
        pushChannel('php.laravel.broadcast', 'laravel', { kind: 'socket', protocol: 'broadcast', key: `ws:${ch}`, route: ch }, h, call);
      } else if (scope === 'Schedule' && /^(command|job|call|exec)$/.test(name)) {
        scheduleEntry(call, name, args);
      } else if (scope === 'Artisan' && name === 'command') {
        const cmd = firstWord(phpString(args[0]?.value) ?? '');
        if (!cmd) continue;
        const h = callbackRef(args[1]?.value, call) ?? closureRef(call);
        pushChannel('php.laravel.command', 'laravel', { kind: 'cli', protocol: 'cli', key: `cli:${cmd}`, route: cmd }, h, call);
      }
    }
    // Workerman: `$w = new Worker('websocket://host:port')` with `$w->onMessage = ...`.
    for (const n of root.descendantsOfType('object_creation_expression')) {
      if (!n || lastSeg(named(n).find((c) => c.type === 'name' || c.type === 'qualified_name')?.text ?? '') !== 'Worker') continue;
      const addr = phpString(phpArgs(named(n).find((c) => c.type === 'arguments'))[0]?.value);
      if (!addr || !/^websocket:\/\//i.test(addr)) continue;
      const route = addr.replace(/^websocket:\/\//i, '');
      const holder = n.parent?.type === 'assignment_expression' ? n.parent.childForFieldName('left')?.text : null;
      const assign = holder ? root.descendantsOfType('assignment_expression').find((a) => {
        const left = a?.childForFieldName('left');
        return left?.type === 'member_access_expression' && left.childForFieldName('name')?.text === 'onMessage' && left.childForFieldName('object')?.text === holder;
      }) : undefined;
      const h = (assign ? callbackRef(assign.childForFieldName('right') ?? undefined, assign) : null) ?? closureRef(n);
      pushChannel('php.workerman.websocket', 'workerman', { kind: 'socket', protocol: 'websocket', key: `ws:${route}`, route }, h, assign ?? n);
    }
  };
  /** Laravel scheduler: `$schedule->command('x')->daily()`, `->job(new X)`, `->call(fn)`, `->exec('cmd')`, `Schedule::...`. */
  const scheduleEntry = (call: Node, kind: string, args: { name: string | null; value: Node }[]) => {
    const v = args[0]?.value;
    let key: string | null;
    let h: HandlerRef;
    if (kind === 'command') {
      const s = phpString(v);
      if (s === null) return;
      key = v!.type === 'class_constant_access_expression' ? lastSeg(s) : firstWord(s);
      h = v!.type === 'class_constant_access_expression' ? classRef(s, 'handle') : closureRef(call);
    } else if (kind === 'job') {
      const cn = v?.type === 'object_creation_expression' ? named(v).find((c) => c.type === 'name' || c.type === 'qualified_name')?.text ?? null : phpString(v);
      if (!cn) return;
      key = lastSeg(cn);
      h = classRef(cn, 'handle');
    } else if (kind === 'exec') {
      key = phpString(v);
      if (key === null) return;
      h = closureRef(call);
    } else {
      h = callbackRef(v, call, '__invoke') ?? closureRef(call);
      const label = chainAbove(call).find((l) => l.name === 'name' || l.name === 'description');
      const cls = v?.type === 'object_creation_expression' ? named(v).find((c) => c.type === 'name' || c.type === 'qualified_name')?.text ?? null
        : v?.type === 'class_constant_access_expression' ? phpString(v)
        : v?.type === 'array_creation_expression' ? arrayEntries(v).map((e) => phpString(e.value)).filter(Boolean).join('.') || null : null;
      key = (label ? phpString(phpArgs(label.args)[0]?.value) : null) ?? (cls ? lastSeg(cls) : `${input.path}:${call.startPosition.row + 1}`);
    }
    pushChannel('php.laravel.schedule', 'laravel', { kind: 'schedule', protocol: 'cron', key: `cron:${key}`, route: frequencyOf(call) }, h, call);
  };


  // ---- WordPress hooks / REST routes / admin pages, Yii 2, CodeIgniter 3 / 4, Slim ----
  const fw = input.langContext as PhpFrameworkContext | undefined;
  const declares = (...deps: string[]) => deps.some((d) => !!fw?.deps.includes(d));
  const nodeOfSymbol = (id: string | undefined): Node | null => {
    if (!id) return null;
    for (const [nid, sid] of funcIds) if (sid === id) return root.descendantsOfType([...FUNC_TYPES]).find((n) => n?.id === nid) ?? null;
    return null;
  };
  const localFunc = (name: string): string | undefined => fx.symbols.find((x) => x.kind === 'func' && x.name.toLowerCase() === name.toLowerCase() && x.name !== '<main>')?.symbolId;
  /** Callback of a hook: closures, `[$this|__CLASS__|X::class, 'm']`, `'Class::m'`, a global function name (any file). */
  const hookCallback = (n: Node | undefined, at: Node): { ref: HandlerRef; body: Node | null } | null => {
    if (!n) return null;
    if (CLOSURE_TYPES.has(n.type)) return { ref: closureRef(n), body: n };
    if (n.type === 'array_creation_expression') {
      const [o, m] = arrayEntries(n).map((e) => e.value);
      const mn = phpString(m);
      if (o && mn && /^(__CLASS__|self::class|static::class)$/.test(o.text)) {
        const cls = enclosingClass(at);
        const ref = cls ? classRef(cls.name, mn) : { text: mn };
        return { ref, body: nodeOfSymbol(ref.symbolId) };
      }
    }
    if (n.type === 'string' || n.type === 'encapsed_string') {
      const s = phpString(n);
      if (s && /^\w+$/.test(s)) {
        const local = localFunc(s);
        return local ? { ref: { symbolId: local }, body: nodeOfSymbol(local) } : { ref: { text: s, anyFunction: true }, body: null };
      }
    }
    const ref = callbackRef(n, at);
    return ref ? { ref, body: nodeOfSymbol(ref.symbolId) } : null;
  };
  /** Capability / login checks (auth) and nonce checks (not auth) inside a callback body. */
  const wpChecks = (body: Node | null): { auth: string[]; other: string[] } => {
    const t = body?.text ?? '';
    const auth = [...t.matchAll(/\bcurrent_user_can\s*\(([^)]*)\)/g)].slice(0, 2).map((m) => `auth call: current_user_can(${oneLine(m[1]!, 60)})`);
    if (/\bis_user_logged_in\s*\(/.test(t)) auth.push('auth call: is_user_logged_in()');
    const other = [...t.matchAll(/\b(check_ajax_referer|wp_verify_nonce|check_admin_referer)\s*\(/g)].slice(0, 1).map((m) => `nonce: ${m[1]}()`);
    if (/\bis_admin\s*\(/.test(t)) other.push('is_admin() (not a capability check)');
    return { auth, other };
  };
  const pushWp = (ruleId: string, method: string, path: string, cb: { ref: HandlerRef; body: Node | null }, node: Node, mws: string[], auth: string[]) => {
    const checks = wpChecks(cb.body);
    fx.entries.push({
      ruleId, framework: 'wordpress', httpMethod: method, pathTemplate: path, handler: cb.ref, path: input.path, range: rangeOf(node),
      middlewares: [...new Set([...mws, ...checks.auth, ...checks.other])], authSignals: [...new Set([...auth, ...checks.auth])],
    });
  };
  const REQUEST_HOOKS = /^(init|admin_init|wp_loaded|template_redirect|parse_request|wp|plugins_loaded)$/;
  const REST_METHODS: Record<string, string[]> = { READABLE: ['GET'], CREATABLE: ['POST'], EDITABLE: ['POST', 'PUT', 'PATCH'], DELETABLE: ['DELETE'], ALLMETHODS: ['ANY'] };
  const ADMIN_PAGES: Record<string, [cap: number, slug: number, cb: number]> = {
    add_menu_page: [2, 3, 4], add_submenu_page: [3, 4, 5], add_options_page: [2, 3, 4], add_management_page: [2, 3, 4], add_users_page: [2, 3, 4],
    add_theme_page: [2, 3, 4], add_plugins_page: [2, 3, 4], add_dashboard_page: [2, 3, 4], add_posts_page: [2, 3, 4], add_pages_page: [2, 3, 4],
    add_media_page: [2, 3, 4], add_comments_page: [2, 3, 4], add_links_page: [2, 3, 4],
  };
  const wordpressEntries = (ruleId: string, call: Node) => {
    const fname = lastSeg(call.childForFieldName('function')?.text ?? '').toLowerCase();
    const args = phpArgs(call.childForFieldName('arguments'));
    const pos = (i: number) => args.filter((a) => a.name === null)[i]?.value;
    if (fname === 'add_action') {
      const hook = phpString(pos(0));
      const cb = hookCallback(pos(1), call);
      if (!hook || !cb) return;
      const ajax = /^wp_ajax_(nopriv_)?(.+)$/.exec(hook);
      const post = /^admin_post_(nopriv_)?(.+)$/.exec(hook);
      if (ajax || post) {
        const m = (ajax ?? post)!;
        const file = ajax ? 'admin-ajax.php' : 'admin-post.php';
        const gate = m[1] ? `${ajax ? 'wp_ajax' : 'admin_post'}_nopriv: no login required` : `${ajax ? 'wp_ajax' : 'admin_post'}: requires login`;
        pushWp(ruleId, 'ANY', `/wp-admin/${file}?action=${m[2]}`, cb, call, [gate], m[1] ? [] : [gate]);
      } else if (REQUEST_HOOKS.test(hook) && cb.body && SUPERGLOBAL_RE.test(cb.body.text)) {
        const mws = hook === 'admin_init' ? ['admin_init: also runs for unauthenticated admin-ajax.php / admin-post.php requests'] : [];
        pushWp(ruleId, 'ANY', `/*?wp_hook=${hook}`, cb, call, mws, []);
      }
    } else if (fname === 'register_rest_route') {
      const ns = phpString(pos(0));
      const route = phpString(pos(1));
      const opts = pos(2);
      if (ns === null || route === null || opts?.type !== 'array_creation_expression') return;
      const path = joinRoute(`/wp-json/${ns}`, route.replace(/\(\?P<(\w+)>[^()]*(?:\([^()]*\)[^()]*)*\)/g, '{$1}'));
      const entries = arrayEntries(opts);
      const endpoints = entries.some((e) => e.key === 'callback' || e.key === 'methods') ? [opts] : entries.filter((e) => e.key === null && e.value.type === 'array_creation_expression').map((e) => e.value);
      for (const ep of endpoints) {
        const kv = new Map(arrayEntries(ep).filter((e) => e.key).map((e) => [e.key!, e.value]));
        const cb = hookCallback(kv.get('callback'), call);
        if (!cb) continue;
        const mv = kv.get('methods');
        const methods = !mv ? ['GET'] : mv.type === 'class_constant_access_expression' ? REST_METHODS[named(mv)[1]?.text ?? ''] ?? ['ANY']
          : stringsOf(mv).flatMap((x) => x.split(',')).map((x) => x.trim().toUpperCase()).filter(Boolean);
        const pc = kv.get('permission_callback');
        const pcText = pc ? oneLine(pc.text, 80) : '';
        const open = !pc || /^['"]__return_true['"]$/.test(pcText);
        const gate = !pc ? 'permission_callback: missing (public)' : open ? 'permission_callback: __return_true (public)' : `permission_callback: ${pcText}`;
        const pcBody = pc ? hookCallback(pc, call)?.body ?? null : null;
        const pcChecks = wpChecks(pcBody).auth;
        for (const m of methods.length ? methods : ['GET']) pushWp(ruleId, m, path, cb, call, [gate, ...pcChecks], open ? pcChecks : [gate, ...pcChecks]);
      }
    } else if (ADMIN_PAGES[fname]) {
      const [ci, si, bi] = ADMIN_PAGES[fname]!;
      const cap = phpString(pos(ci)) ?? oneLine(pos(ci)?.text ?? '?', 60);
      const slug = phpString(pos(si));
      const cb = hookCallback(pos(bi), call);
      if (!slug || !cb) return;
      const gate = `capability: ${cap}`;
      pushWp(ruleId, 'ANY', `/wp-admin/admin.php?page=${slug}`, cb, call, [gate], [gate]);
    }
  };

  /** Yii: `FooBar` → `foo-bar`. */
  const kebab = (x: string) => x.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();
  const methodNodes = (cls: ClassInfo) => named(cls.node.childForFieldName('body')).filter((m) => m.type === 'method_declaration');
  const isPublic = (m: Node) => !/\b(private|protected|static)\b/.test(named(m).filter((c) => /modifier/.test(c.type)).map((c) => c.text).join(' '));
  /**
   * Yii 2 controllers (`yii\…\Controller` subclasses): `actionFooBar()` → `/<module>/<controller-id>/foo-bar`; VerbFilter
   * methods from `behaviors()`; AccessControl rules with roles other than `?` are auth signals on their actions (or the class).
   */
  const yiiEntries = (ruleId: string, cls: ClassInfo) => {
    if (![...imports].some((i) => i.startsWith('yii\\')) && !declares('yiisoft/yii2')) return;
    if (!clauseNames(cls, 'base_clause').some((b) => /Controller$/.test(b)) || !/Controller$/.test(cls.name)) return;
    const module = /\\modules\\(\w+)\\controllers\b/.exec(cls.fqn)?.[1];
    const sub = /\\controllers\\(.+)\\[^\\]+$/.exec(cls.fqn)?.[1]?.split('\\').map(kebab).join('/');
    const base = joinRoute(joinRoute(module ? kebab(module) : '', sub ?? ''), kebab(cls.name.replace(/Controller$/, '')));
    const behaviors = methodNodes(cls).find((m) => m.childForFieldName('name')?.text === 'behaviors')?.text ?? '';
    const verbs = new Map<string, string[]>();
    const vf = behaviors.indexOf('VerbFilter');
    if (vf >= 0) {
      for (const m of behaviors.slice(vf).matchAll(/['"]([\w-]+)['"]\s*=>\s*\[((?:\s*['"]\w+['"]\s*,?)+)\s*\]/g)) {
        const list = [...m[2]!.matchAll(/['"](\w+)['"]/g)].map((x) => x[1]!.toUpperCase()).filter((x) => /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(x));
        if (list.length && !verbs.has(m[1]!)) verbs.set(m[1]!, list);
      }
    }
    const access = new Map<string, string[]>();
    const classAuth: string[] = [];
    const ac = behaviors.indexOf('AccessControl');
    if (ac >= 0) {
      for (const r of behaviors.slice(ac).matchAll(/\[((?:[^[\]]|\[[^[\]]*\])*?'roles'\s*=>\s*\[[^\]]*\](?:[^[\]]|\[[^[\]]*\])*?)\]/g)) {
        if (/'allow'\s*=>\s*false/.test(r[1]!)) continue;
        const roles = [...(/'roles'\s*=>\s*\[([^\]]*)\]/.exec(r[1]!)?.[1] ?? '').matchAll(/['"]([^'"]+)['"]/g)].map((x) => x[1]!);
        if (!roles.length || roles.every((x) => x === '?')) continue;
        const sig = `AccessControl roles(${roles.join(', ')})`;
        const acts = /'actions'\s*=>\s*\[([^\]]*)\]/.exec(r[1]!)?.[1];
        if (acts) for (const a of acts.matchAll(/['"]([\w-]+)['"]/g)) access.set(a[1]!, [...(access.get(a[1]!) ?? []), sig]);
        else classAuth.push(sig);
      }
    }
    for (const m of methodNodes(cls)) {
      const name = m.childForFieldName('name')?.text ?? '';
      const am = /^action([A-Z]\w*)$/.exec(name);
      if (!am || name === 'actions' || !isPublic(m)) continue;
      const id = kebab(am[1]!);
      const symbolId = funcIds.get(m.id);
      if (!symbolId) continue;
      const auth = [...classAuth, ...(access.get(id) ?? [])];
      for (const hm of verbs.get(id) ?? ['ANY']) {
        fx.entries.push({ ruleId, framework: 'yii', httpMethod: hm, pathTemplate: joinRoute(base, id), handler: { symbolId }, path: input.path, range: rangeOf(m), middlewares: auth, authSignals: auth });
      }
      for (const a of auth) addSignal({ target: symbolId, kind: 'middleware', detail: a, ruleId });
    }
  };

  /** CodeIgniter 3: `class Blog extends CI_Controller` under `controllers/` → `/blog/<method>` for public methods not starting with `_`. */
  const ci3Entries = (ruleId: string, cls: ClassInfo) => {
    const bases = clauseNames(cls, 'base_clause');
    const dir = /(?:^|\/)controllers\/(?:(.*)\/)?[^/]+\.php$/i.exec(input.path);
    if (!dir || !bases.some((b) => /^(CI_Controller|MY_Controller|\w+_Controller)$/.test(b))) return;
    const base = joinRoute(dir[1] ?? '', cls.name.toLowerCase());
    const ctor = methodNodes(cls).find((m) => m.childForFieldName('name')?.text.toLowerCase() === '__construct');
    const mws = [
      ...bases.filter((b) => b !== 'CI_Controller').map((b) => `extends ${b}`),
      ...(ctor && /\b(session|logged_in|is_login|auth|login|permission)\b/i.test(ctor.text) && /\b(redirect|show_error|exit|die)\b/.test(ctor.text) ? ['auth check in __construct'] : []),
    ];
    for (const m of methodNodes(cls)) {
      const name = m.childForFieldName('name')?.text ?? '';
      const symbolId = funcIds.get(m.id);
      if (!symbolId || name.startsWith('_') || !isPublic(m)) continue;
      fx.entries.push({ ruleId, framework: 'codeigniter', httpMethod: 'ANY', pathTemplate: joinRoute(base, name.toLowerCase()), handler: { symbolId }, path: input.path, range: rangeOf(m), middlewares: mws, authSignals: authOf(mws) });
    }
  };
  const ciPath = (p: string) => p.replace(/\(:(\w+)\)/g, '{$1}');
  /** CodeIgniter 3 `config/routes.php`: `$route['products/(:num)'] = 'catalog/lookup/$1'`, `$route['x']['post'] = …`. */
  const ci3RouteEntry = (ruleId: string, assign: Node) => {
    if (!/(^|\/)config\/routes\.php$/.test(input.path)) return;
    const left = assign.childForFieldName('left');
    const keys: string[] = [];
    let cur: Node | null | undefined = left;
    while (cur?.type === 'subscript_expression') { const k = phpString(named(cur)[1]); if (k === null) return; keys.unshift(k); cur = named(cur)[0]; }
    if (cur?.text !== '$route' || !keys.length || /^(default_controller|404_override|translate_uri_dashes)$/.test(keys[0]!)) return;
    const target = phpString(assign.childForFieldName('right'));
    if (target === null) return;
    const parts = target.split('/').filter((x) => x && !x.startsWith('$'));
    if (!parts.length) return;
    const method = parts.length >= 2 ? parts.pop()! : 'index';
    const ctrl = parts.pop()!;
    pushEntry(ruleId, 'codeigniter', (keys[1] ?? 'ANY').toUpperCase(), ciPath(`/${keys[0]}`), classRef(ctrl.charAt(0).toUpperCase() + ctrl.slice(1), method), assign, []);
  };
  /** Group closures around a route call: `$routes->group('admin', ['filter' => 'auth'], fn)` / Slim `->group('/p', fn)->add(mw)`. */
  const groupsOf = (call: Node): Node[] => {
    const out: Node[] = [];
    for (let p: Node | null = call.parent; p; p = p.parent) {
      if (!CLOSURE_TYPES.has(p.type)) continue;
      const g = p.parent?.type === 'argument' ? p.parent.parent?.parent : null;
      if (g?.type === 'member_call_expression' && g.childForFieldName('name')?.text === 'group') out.unshift(g);
    }
    return out;
  };
  const optFilters = (n: Node | undefined): string[] => arrayEntries(n).filter((e) => e.key === 'filter').flatMap((e) => stringsOf(e.value)).map((f) => `filter: ${f}`);
  const CI4_RESOURCE: [method: string, suffix: string, action: string][] = [['GET', '', 'index'], ['GET', '/new', 'new'], ['POST', '', 'create'], ['GET', '/{id}', 'show'], ['GET', '/{id}/edit', 'edit'], ['PUT', '/{id}', 'update'], ['PATCH', '/{id}', 'update'], ['DELETE', '/{id}', 'delete']];
  /** CodeIgniter 4 `$routes->get|post|…|match|add|resource(…)`, with groups and `filter` options. */
  const ci4Route = (ruleId: string, call: Node, verb: string) => {
    if (!declares('codeigniter4/framework', 'codeigniter4/codeigniter4') && !/(^|\/)Config\/Routes\.php$/.test(input.path) && ![...imports].some((i) => i.startsWith('CodeIgniter\\'))) return;
    if (!/^\$routes$/.test(call.childForFieldName('object')?.text ?? '')) return;
    let prefix = '';
    const mws: string[] = [];
    for (const g of groupsOf(call)) {
      const ga = phpArgs(g.childForFieldName('arguments'));
      prefix = joinRoute(prefix, phpString(ga[0]?.value) ?? '');
      mws.push(...optFilters(ga[1]?.value));
    }
    const args = phpArgs(call.childForFieldName('arguments')).filter((a) => a.name === null);
    const handlerOf = (n: Node | undefined): HandlerRef | null => {
      if (!n) return null;
      if (CLOSURE_TYPES.has(n.type)) return closureRef(n);
      const s = phpString(n);
      if (n.type === 'array_creation_expression' || s === null) return routeHandler(n, { prefix: [], middlewares: [], controller: null, namespace: null }, false);
      const m = /^(.+?)::(\w+)/.exec(s.replace(/^\\/, ''));
      return m ? classRef(lastSeg(m[1]!), m[2]!) : null;
    };
    if (verb === 'resource') {
      const name = phpString(args[0]?.value);
      if (!name) return;
      const opts = args[1]?.value;
      const ctrl = phpString(arrayEntries(opts).find((e) => e.key === 'controller')?.value) ?? name.charAt(0).toUpperCase() + name.slice(1);
      for (const [m, suffix, action] of CI4_RESOURCE) pushEntry(ruleId, 'codeigniter', m, joinRoute(prefix, ciPath(name + suffix)), classRef(lastSeg(ctrl), action), call, [...mws, ...optFilters(opts)]);
      return;
    }
    const isMatch = verb === 'match';
    const methods = isMatch ? stringsOf(args[0]?.value).map((m) => m.toUpperCase()) : [ROUTE_VERBS[verb] ?? (verb === 'head' ? 'HEAD' : 'ANY')];
    const rest = isMatch ? args.slice(1) : args;
    const p = phpString(rest[0]?.value);
    const h = handlerOf(rest[1]?.value);
    if (p === null || !h) return;
    for (const m of methods) pushEntry(ruleId, 'codeigniter', m, joinRoute(prefix, ciPath(p)), h, call, [...mws, ...optFilters(rest[2]?.value)]);
  };
  /** Slim `$app|$group->get|post|…|any|map(…)` with `->group('/p', fn)` prefixes and `->add(mw)` middleware (route, group, same-file app). */
  const slimRoute = (ruleId: string, call: Node, verb: string) => {
    if (!declares('slim/slim') && ![...imports].some((i) => i.startsWith('Slim\\'))) return;
    const args = phpArgs(call.childForFieldName('arguments')).filter((a) => a.name === null);
    const isMap = verb === 'map';
    const methods = isMap ? stringsOf(args[0]?.value).map((m) => m.toUpperCase()) : [ROUTE_VERBS[verb] ?? 'ANY'];
    const rest = isMap ? args.slice(1) : args;
    const p = phpString(rest[0]?.value);
    const hn = rest[1]?.value;
    if (p === null || !hn || rest.length < 2) return;
    const addsOf = (n: Node) => chainAbove(n).filter((l) => l.name === 'add' || l.name === 'addMiddleware').flatMap((l) => phpArgs(l.args).flatMap((a) => stringsOf(a.value)));
    let prefix = '';
    const mws: string[] = [];
    const groups = groupsOf(call);
    let rootRecv = call.childForFieldName('object')?.text ?? '';
    for (const g of groups) {
      prefix = joinRoute(prefix, phpString(phpArgs(g.childForFieldName('arguments'))[0]?.value) ?? '');
      mws.push(...addsOf(g));
      rootRecv = groups[0]!.childForFieldName('object')?.text ?? rootRecv;
    }
    // App-wide middleware registered in this file (`$app->add(…)`); Slim applies it to every route.
    for (const c of root.descendantsOfType('member_call_expression')) {
      if (c?.childForFieldName('name')?.text === 'add' && c.childForFieldName('object')?.text === rootRecv && rootRecv === '$app') mws.unshift(...phpArgs(c.childForFieldName('arguments')).flatMap((a) => stringsOf(a.value)));
    }
    mws.push(...addsOf(call));
    let h: HandlerRef | null;
    const s = phpString(hn);
    if (s !== null && hn.type !== 'class_constant_access_expression' && /^[\w\\]+:\w+$/.test(s)) { const [c, m] = s.split(':'); h = classRef(lastSeg(c!), m!); }
    else h = CLOSURE_TYPES.has(hn.type) ? closureRef(hn) : callbackRef(hn, call);
    // Actions whose `__invoke` / CRUD method lives in an abstract base class: fall back to the action class; the
    // namespace from `use` imports picks among same-named classes (`Admin\DeleteAction`, `Stations\DeleteAction`).
    if (h?.className) {
      const clsNode = hn.type === 'class_constant_access_expression' ? named(hn)[0] : hn.type === 'array_creation_expression' ? named(arrayEntries(hn)[0]?.value)[0] : undefined;
      const fqn = clsNode && (clsNode.type === 'name' || clsNode.type === 'qualified_name') ? resolveClass(clsNode.text, clsNode) : undefined;
      h = { ...h, classFallback: true, ...(fqn ? { classFqn: fqn } : {}) };
    }
    for (const m of methods) pushEntry(ruleId, 'slim', m, joinRoute(prefix, p), h ?? { text: oneLine(hn.text, 120) }, call, mws);
  };

  // ---- rules ----
  const seen = new Set<string>();
  const funcBodyText = (n: Node) => (enclosingFunc(n) ?? root).text;
  for (const { rule, query, error } of rules) {
    if (error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${error}` }); continue; }
    if (!query) continue;
    if (rule.match?.requiresImportAny && !rule.match.requiresImportAny.some((i) => imports.has(i))) continue;
    if (rule.match?.notImportAny?.some((i) => imports.has(i))) continue;
    try {
      for (const match of query.matches(root)) {
        const cap = captureMap(match.captures, rule.captures);
        if (rule.kind === 'sink') {
          const call = cap.get('call');
          if (!call) continue;
          const receiver = cap.get('receiver') ?? null;
          const argsNode = cap.get('args');
          const argCount = argsNode?.type === 'arguments' ? named(argsNode).length : argsNode ? 1 : 0;
          const isClassRef = receiver && (receiver.type === 'name' || receiver.type === 'qualified_name');
          const receiverImport = isClassRef ? resolveClass(receiver.text, receiver) : null;
          const receiverType = isClassRef ? lastSeg(receiverImport!) : typeOf(receiver, call);
          if (!ruleMatches(rule.match, { receiverText: receiver?.text ?? null, receiverType, receiverImport: null, imports, argCount })) continue;
          const taint = phpTaintHint(argsNode ?? call);
          // php_dynamic_arg: only a SQL string built in the first argument counts (`where('name', 'like', '%' . $k)` binds).
          if (rule.post === 'php_dynamic_arg' && (argsNode?.type !== 'arguments' || phpTaintHint(phpArgs(argsNode)[0]?.value) !== 'string_concat')) continue;
          // WordPress: writes only when an argument reads the request; `maybe_unserialize(get_option(…))` is WordPress
          // storage; `$wpdb` SQL whose only interpolation is the table prefix / a table-name variable is not built from input.
          if (rule.post === 'php_request_arg' && !SUPERGLOBAL_RE.test(argsNode?.text ?? '')) continue;
          if (rule.post === 'php_not_wp_storage' && /^\\?(get_option|get_site_option|get_user_meta|get_post_meta|get_term_meta|get_comment_meta|get_transient|get_site_transient|get_metadata)\s*\(/.test(phpArgs(argsNode)[0]?.value.text ?? '')) continue;
          if (rule.post === 'php_wpdb_sql') {
            const first = phpArgs(argsNode)[0]?.value;
            // `$wpdb->get_row($wpdb->prepare("… {$table} …", $id))`: the statement is prepared.
            if (!first || /->\s*prepare\s*\(/.test(first.type === 'member_call_expression' ? `${first.childForFieldName('object')?.text ?? ''}->${first.childForFieldName('name')?.text ?? ''}(` : '')) continue;
            if (phpTaintHint(first) !== 'string_concat') continue;
            const rest = first.text.replace(/\{?\$wpdb->\w+\}?/g, '').replace(/\{?\$(table|tbl|prefix)\w*(->\w+)?\}?/gi, '');
            if (!/\$\w/.test(rest)) continue;
          }
          if (rule.post === 'php_state_save' && !/->\s*(status|state|amount|balance|price|total|role|credit|points|quantity|paid|is_admin|approved|level)\s*=[^=]/i.test(funcBodyText(call))) continue;
          const api = fillApi(rule.api ?? '', {
            method: cap.get('method')?.text.replace(/^\\/, ''), receiver: receiver ? oneLine(receiver.text, 80) : null,
            type: receiverType ?? (receiver ? oneLine(receiver.text, 80) : null),
          });
          const sink = makeSink(repo, input.path, rule, call, enclosingSymbol(call), api, taint);
          if (!seen.has(sink.sinkId)) { seen.add(sink.sinkId); fx.sinks.push(sink); }
        } else if (rule.kind === 'entrypoint') {
          if (rule.post === 'php_laravel_route' || rule.post === 'php_thinkphp_route') {
            const call = cap.get('call');
            const verb = cap.get('verb')?.text;
            if (call && verb) routeEntries(rule.id, rule.framework, call, verb, rule.post === 'php_thinkphp_route');
          } else if (rule.post === 'php_symfony_route') {
            const method = cap.get('handler');
            if (method) symfonyEntries(rule.id, method);
          } else if (rule.post === 'php_native_script') {
            nativeEntry(rule.id);
          } else if (rule.post === 'php_wordpress') {
            const call = cap.get('call');
            if (call) wordpressEntries(rule.id, call);
          } else if (rule.post === 'php_yii_controller' || rule.post === 'php_ci3_controller') {
            const cls = cap.get('class');
            const info = cls ? classes.get(cls.id) : undefined;
            if (info) (rule.post === 'php_yii_controller' ? yiiEntries : ci3Entries)(rule.id, info);
          } else if (rule.post === 'php_ci3_route') {
            const assign = cap.get('call');
            if (assign) ci3RouteEntry(rule.id, assign);
          } else if (rule.post === 'php_ci4_route' || rule.post === 'php_slim_route') {
            const call = cap.get('call');
            const verb = cap.get('verb')?.text;
            if (call && verb) (rule.post === 'php_ci4_route' ? ci4Route : slimRoute)(rule.id, call, verb.toLowerCase());
          }
        } else if (rule.kind === 'auth_signal') {
          if (rule.post === 'php_laravel_controller_middleware') {
            const call = cap.get('call');
            const fn = call ? enclosingFunc(call) : null;
            const cls = call ? enclosingClass(call) : null;
            if (!call || !fn || !cls || fn.childForFieldName('name')?.text.toLowerCase() !== '__construct') continue;
            const mws = phpArgs(call.childForFieldName('arguments')).flatMap((a) => stringsOf(a.value)).filter((m) => AUTH_NAME_RE.test(m) || PHP_AUTH_RE.test(m));
            if (!mws.length) continue;
            const above = chainAbove(call);
            const only = above.find((l) => l.name === 'only');
            const except = above.find((l) => l.name === 'except');
            let targets = [cls.symbolId];
            if (only || except) {
              const names = new Set(phpArgs((only ?? except)!.args).flatMap((a) => stringsOf(a.value)).map((x) => x.toLowerCase()));
              targets = [...cls.methods.entries()].filter(([n]) => n !== '__construct' && (only ? names.has(n) : !names.has(n))).map(([, id]) => id);
            }
            for (const t of targets) for (const m of mws) addSignal({ target: t, kind: 'middleware', detail: m, ruleId: rule.id });
          } else if (rule.post === 'php_symfony_is_granted') {
            const ann = cap.get('annotation');
            const owner = ann?.parent?.parent?.parent; // attribute → attribute_group → attribute_list → declaration
            if (!ann || !owner) continue;
            const target = owner.type === 'method_declaration' ? funcIds.get(owner.id) : CLASS_TYPES.has(owner.type) ? classes.get(owner.id)?.symbolId : undefined;
            if (target) addSignal({ target, kind: 'annotation', detail: oneLine(ann.text, 200), ruleId: rule.id });
          } else if (rule.post === 'php_authorize_call') {
            const call = cap.get('call');
            const target = call ? enclosingSymbol(call) : null;
            if (call && target) addSignal({ target, kind: 'security_config', detail: oneLine(call.text, 200), ruleId: rule.id });
          }
        }
      }
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${(e as Error).message}` });
    }
  }

  channelEntries();

  // Docblock `@IsGranted` / `@Security` (annotations without PHP 8 attributes).
  for (const cls of classes.values()) {
    for (const decl of [cls.node, ...named(cls.node.childForFieldName('body')).filter((m) => m.type === 'method_declaration')]) {
      const target = decl === cls.node ? cls.symbolId : funcIds.get(decl.id);
      const m = /@(IsGranted|Security)\(([^)]*)\)/.exec(docOf(decl));
      if (target && m) addSignal({ target, kind: 'annotation', detail: oneLine(m[0], 200), ruleId: 'php.symfony.is-granted' });
    }
  }

  // Attach in-file signals to entries: route middleware (file-level, as Go) and handler / class annotations.
  for (const e of fx.entries) {
    for (const mw of e.authSignals) {
      if (e.framework === 'php') continue;
      addSignal({ target: `${repo}:${input.path}`, kind: 'middleware', detail: mw, ruleId: e.ruleId });
    }
    const handler = e.handler.symbolId;
    if (!handler || e.framework === 'php') continue;
    const classId = handler.replace(/\.[^.#]+\(\d+\)$/, '');
    for (const s of fx.authSignals) {
      if ((s.target === handler || s.target === classId) && !e.authSignals.includes(s.detail)) e.authSignals.push(s.detail);
    }
  }
  return fx;
}

/** Simple class name of a type hint (`?OrderRepo`, `\App\Repo`, `Repo|null`); null for primitives. */
function simpleType(t: Node): string | null {
  const text = t.text.replace(/^\?/, '');
  const parts = text.split(/[|&]/).map((p) => p.trim()).filter((p) => p && !PRIMITIVE_TYPES.test(p));
  if (parts.length !== 1) return null;
  return lastSeg(parts[0]!);
}

function signatureOf(node: Node): string {
  const body = node.childForFieldName('body');
  const text = body ? node.text.slice(0, body.startIndex - node.startIndex) : node.text;
  // Attributes precede the declaration keywords; keep them (routes are declared there) but on one line.
  return oneLine(text, 300);
}

export type { IndexSymbol };
