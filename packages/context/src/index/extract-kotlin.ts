// Kotlin extraction: symbols (classes / interfaces / objects, methods incl. companion members,
// top-level and extension functions), calls with receiver facts, Spring MVC and Ktor routing entries,
// sinks (rules/kotlin) and auth signals (method security annotations, filters / interceptors, SecurityFilterChain
// DSL and fluent config, Ktor `authenticate { }` / `install(Authentication)`).
//
// Grammar note (@tree-sitter-grammars/tree-sitter-kotlin 1.1.0): a declaration with two or more annotations, one
// of them with arguments (`@RestController @RequestMapping("/x") class C {…}`), followed by another top-level
// declaration is sometimes parsed as an `annotated_expression` (the class body becomes a lambda) or leaves an
// ERROR node. When the file shows either at the top level, each top-level declaration is re-parsed on its own
// (rows preserved by a newline prefix), which parses correctly; see `kotlinUnits`.
import { Parser, type Node, type Tree } from 'web-tree-sitter';
import type { AuthSignal } from '@xiezhi/contracts';
import { AUTH_NAME_RE, captureMap, fillApi, makeSink, rangeOf, ruleMatches, type CompiledRule } from './common.js';
import { channelEntries, type JvmClass, type JvmMethod, type WsRegistration } from './extract-java.js';
import { rpcOf } from './proto.js';
import { emptyExtract, joinRoute, type ExtractInput, type FileExtract, type InheritedMapping, type JvmTypeFacts, type RawEntry } from './types.js';

const CLASS_TYPES = new Set(['class_declaration', 'object_declaration']);
const MAPPING_METHOD: Record<string, string> = {
  GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT', DeleteMapping: 'DELETE', PatchMapping: 'PATCH',
};
const SECURITY_ANN_RE = /^(PreAuthorize|PostAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresRoles|SaCheckLogin|SaCheckPermission|SaCheckRole)$/;
const KTOR_VERBS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options']);
const AUTHORIZE_BLOCK_RE = /^(authorizeHttpRequests|authorizeRequests|authorizeExchange)$/;
const XML_SECURE_RE = /disallow-doctype-decl|external-general-entities|FEATURE_SECURE_PROCESSING|SUPPORT_DTD|isExpandEntityReferences\s*=\s*false|setExpandEntityReferences\(\s*false|ACCESS_EXTERNAL_DTD/;
const MAX_REPARSE_CHUNKS = 400;

interface ClassInfo { name: string; dotted: string; symbolId: string; node: Node; fields: Map<string, string> }

// ---- small tree helpers --------------------------------------------------------------------------------------

const named = (n: Node | null | undefined): Node[] => (n ? n.namedChildren.filter((c): c is Node => !!c) : []);
const childOfType = (n: Node | null | undefined, type: string): Node | null => named(n).find((c) => c.type === type) ?? null;

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/** Simple type name: strip generics, nullability, annotations and the package. */
function eraseKt(t: string): string {
  let depth = 0;
  let out = '';
  for (const ch of t.replace(/@\w+(\([^)]*\))?\s*/g, '')) {
    if (ch === '<') depth++;
    else if (ch === '>') depth--;
    else if (depth === 0) out += ch;
  }
  return (out.replace(/[\s?!]/g, '').split('.').pop() ?? out).trim();
}

/** Declaration header up to its body (`{` block or `= expr`). */
function signatureOf(node: Node): string {
  const body = named(node).find((c) => c.type === 'function_body' || c.type === 'class_body' || c.type === 'enum_class_body');
  let text = node.text;
  if (body) {
    const at = text.lastIndexOf(body.text);
    if (at > 0) text = text.slice(0, at);
  }
  return truncate(text.replace(/\s+/g, ' ').replace(/\s*=?\s*$/, '').trim(), 300);
}

function annotationName(ann: Node): string {
  const t = childOfType(ann, 'user_type') ?? childOfType(childOfType(ann, 'constructor_invocation'), 'user_type');
  return named(t).filter((c) => c.type === 'identifier').pop()?.text ?? '';
}

function annotationsOf(decl: Node): Node[] {
  return named(childOfType(decl, 'modifiers')).filter((c) => c.type === 'annotation');
}

/** Call parts: `f(a)`, `r.f(a)`, `f { }`, `r.f(a) { }` — the trailing-lambda wrapper is a `call_expression`
 * whose callee is the inner call; `calleeOf` returns null for the wrapper (the inner call is the call). */
interface CallParts { name: string; receiver: Node | null; args: Node | null; lambda: boolean; nav: boolean }
function callParts(call: Node): CallParts | null {
  const callee = call.namedChildren[0];
  if (!callee) return null;
  const args = childOfType(call, 'value_arguments');
  const wrapper = call.parent?.type === 'call_expression' && call.parent.namedChildren[0]?.id === call.id ? call.parent : null;
  const lambda = !!childOfType(call, 'annotated_lambda') || !!(wrapper && childOfType(wrapper, 'annotated_lambda'));
  if (callee.type === 'identifier') return { name: callee.text, receiver: null, args, lambda, nav: false };
  if (callee.type === 'navigation_expression') {
    const kids = named(callee);
    const last = kids[kids.length - 1];
    if (kids.length < 2 || last?.type !== 'identifier') return null;
    return { name: last.text, receiver: kids[0]!, args, lambda, nav: true };
  }
  return null;
}

/** The expressions passed as arguments (named arguments give their value). */
function argExprs(args: Node | null | undefined): Node[] {
  if (!args) return [];
  if (args.type === 'parenthesized_expression') return named(args);
  return named(args).filter((a) => a.type === 'value_argument').map((a) => {
    const kids = named(a);
    return kids[kids.length - 1]!;
  }).filter(Boolean);
}

function argName(arg: Node): string | null {
  return arg.children.some((c) => c?.type === '=') ? named(arg)[0]?.text ?? null : null;
}

const INTERP_RE = /(^|[^\\])\$(\{|[A-Za-z_])/;
const isStringLit = (n: Node) => n.type === 'string_literal' || n.type === 'multiline_string_literal';
const hasInterpolation = (n: Node) => isStringLit(n) && (n.descendantsOfType('interpolation').length > 0 || INTERP_RE.test(n.text));

function isPlusConcat(n: Node): boolean {
  return n.type === 'binary_expression' && n.children.some((c) => c?.type === '+');
}

/** `+` concatenation, string templates, `format` / `buildString` / `StringBuilder` / `joinToString`. */
function isBuilt(n: Node): boolean {
  // Error paths (`?: throw E("… $x")`) and lambdas do not build the value.
  if (n.type === 'throw_expression' || n.type === 'jump_expression' || n.type === 'lambda_literal' || n.type === 'annotated_lambda') return false;
  if (hasInterpolation(n) || isPlusConcat(n)) return true;
  if (n.type === 'call_expression') {
    const p = callParts(n);
    if (p && /^(format|buildString|StringBuilder|append|joinToString|plus)$/.test(p.name)) return true;
  }
  return named(n).some(isBuilt);
}

function isConstantExpr(n: Node): boolean {
  if (isStringLit(n)) return !hasInterpolation(n);
  if (/^(number_literal|boolean_literal|character_literal|null_literal)$/.test(n.type)) return true;
  if (n.type === 'collection_literal') return named(n).every(isConstantExpr);
  if (n.type === 'call_expression') {
    const p = callParts(n);
    return !!p && !p.nav && /^(arrayOf|listOf|mutableListOf|setOf)$/.test(p.name) && argExprs(p.args).every(isConstantExpr);
  }
  return false;
}

// ---- re-parse of mis-parsed top-level declarations -----------------------------------------------------------

let reparser: { parser: Parser; language: unknown } | null = null;
function parserFor(tree: Tree): Parser {
  if (!reparser || reparser.language !== tree.language) {
    reparser?.parser.delete();
    const parser = new Parser();
    parser.setLanguage(tree.language);
    reparser = { parser, language: tree.language };
  }
  return reparser.parser;
}

const DECL_START_RE = /^(@|(public|private|internal|protected|abstract|open|final|sealed|data|enum|inline|value|annotation|suspend|operator|infix|tailrec|external|const|lateinit|expect|actual)\s|(class|interface|object|fun|val|var|typealias)\b)/;

/** Only annotations (and comments) so far — the declaration they belong to is still to come. */
function onlyAnnotations(text: string): boolean {
  let s = text.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/\/\/[^\n]*/g, ' ').trim();
  if (!s) return false;
  while (s.startsWith('@')) {
    const m = /^@[\w.:]+/.exec(s);
    if (!m) return false;
    s = s.slice(m[0].length).trimStart();
    if (s.startsWith('(')) {
      let depth = 0;
      let i = 0;
      for (; i < s.length; i++) {
        if (s[i] === '(') depth++;
        else if (s[i] === ')' && --depth === 0) break;
      }
      if (depth !== 0) return true; // annotation arguments continue on the next line
      s = s.slice(i + 1).trimStart();
    }
  }
  return s.length === 0;
}

/** Top-level declaration chunks (row ranges) by a lexical scan: column-0 declaration starts at bracket depth 0. */
function chunkRows(lines: string[], fromRow: number): [number, number][] {
  const chunks: [number, number][] = [];
  let depth = 0;
  let inBlock = false;
  let inRaw = false;
  let start = -1;
  let pending = '';
  for (let r = fromRow; r < lines.length; r++) {
    const line = lines[r]!;
    if (depth === 0 && !inBlock && !inRaw && DECL_START_RE.test(line) && !(start >= 0 && onlyAnnotations(pending))) {
      if (start >= 0) chunks.push([start, r - 1]);
      start = r;
      pending = '';
    }
    if (start >= 0) pending += line + '\n';
    for (let i = 0; i < line.length; i++) {
      const ch = line[i]!;
      if (inBlock) { if (ch === '*' && line[i + 1] === '/') { inBlock = false; i++; } continue; }
      if (inRaw) { if (line.startsWith('"""', i)) { inRaw = false; i += 2; } continue; }
      if (ch === '/' && line[i + 1] === '/') break;
      if (ch === '/' && line[i + 1] === '*') { inBlock = true; i++; continue; }
      if (line.startsWith('"""', i)) { inRaw = true; i += 2; continue; }
      if (ch === '"' || ch === '\'') {
        for (i++; i < line.length && line[i] !== ch; i++) if (line[i] === '\\') i++;
        continue;
      }
      if (ch === '{' || ch === '(' || ch === '[') depth++;
      else if ((ch === '}' || ch === ')' || ch === ']') && depth > 0) depth--;
    }
  }
  if (start >= 0) chunks.push([start, lines.length - 1]);
  return chunks;
}

export interface KotlinUnits { units: Node[]; trees: Tree[] }

/**
 * The top-level nodes to extract from. Normally the root; when the grammar mis-parsed a top-level declaration
 * (see the file header), every declaration after the imports is re-parsed alone with its rows preserved.
 */
export function kotlinUnits(text: string, tree: Tree): KotlinUnits {
  const root = tree.rootNode;
  const top = named(root);
  if (!top.some((c) => c.type === 'annotated_expression' || c.type === 'ERROR')) return { units: [root], trees: [] };
  const header = top.filter((c) => c.type === 'package_header' || c.type === 'import' || c.type === 'file_annotation');
  const fromRow = header.length ? header[header.length - 1]!.endPosition.row + 1 : 0;
  const lines = text.split('\n');
  const chunks = chunkRows(lines, fromRow);
  if (chunks.length === 0 || chunks.length > MAX_REPARSE_CHUNKS) return { units: [root], trees: [] };
  const parser = parserFor(tree);
  const trees: Tree[] = [];
  const units: Node[] = [...header];
  for (const [a, b] of chunks) {
    const t = parser.parse('\n'.repeat(a) + lines.slice(a, b + 1).join('\n'));
    if (!t) continue;
    trees.push(t);
    units.push(...named(t.rootNode));
  }
  return { units, trees };
}

function* descendants(units: Node[]): Generator<Node> {
  const stack: Node[] = [...units].reverse();
  while (stack.length) {
    const cur = stack.pop()!;
    yield cur;
    for (let i = cur.namedChildCount - 1; i >= 0; i--) {
      const c = cur.namedChild(i);
      if (c) stack.push(c);
    }
  }
}

// ---- extractor ----------------------------------------------------------------------------------------------

export function extractKotlin(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const { units, trees } = kotlinUnits(input.text, tree);
  try {
    return extractUnits(input, units, rules);
  } finally {
    for (const t of trees) t.delete();
  }
}

function extractUnits(input: ExtractInput, units: Node[], rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const all = [...descendants(units)];
  const byType = (type: string) => all.filter((n) => n.type === type);

  const pkgNode = all.find((n) => n.type === 'package_header');
  const pkg = childOfType(pkgNode, 'qualified_identifier')?.text ?? childOfType(pkgNode, 'identifier')?.text ?? '';
  fx.pkg = pkg;

  // ---- imports: simple name / alias → fully qualified ----
  const imports = new Set<string>();
  const importAlias = new Map<string, string>();
  for (const imp of byType('import')) {
    const q = childOfType(imp, 'qualified_identifier')?.text ?? '';
    if (!q) continue;
    const wildcard = /\.\*\s*$/.test(imp.text);
    imports.add(wildcard ? `${q}.*` : q);
    if (wildcard) continue;
    const alias = named(imp).find((c) => c.type === 'identifier')?.text;
    importAlias.set(alias ?? q.split('.').pop()!, q);
  }

  // ---- string constants (const val / val X = "…") for routes ----
  const consts = new Map<string, string>();
  for (const p of byType('property_declaration')) {
    const name = childOfType(childOfType(p, 'variable_declaration'), 'identifier')?.text;
    const value = named(p).find(isStringLit);
    if (name && value && !hasInterpolation(value)) consts.set(name, stringContent(value));
  }

  // ---- symbols ----
  const classes = new Map<number, ClassInfo>();
  const funcIds = new Map<number, string>();
  const funcNames = new Map<number, string>();
  const localTypes = new Map<number, Map<string, string>>();
  const localValues = new Map<number, Map<string, Node>>();

  const collectLocals = (fn: Node) => {
    const types = new Map<string, string>();
    const values = new Map<string, Node>();
    for (const p of named(childOfType(fn, 'function_value_parameters'))) {
      if (p.type !== 'parameter') continue;
      const n = childOfType(p, 'identifier')?.text;
      const t = named(p).find((c) => c.type === 'user_type' || c.type === 'nullable_type');
      if (n && t) types.set(n, eraseKt(t.text));
    }
    const body = childOfType(fn, 'function_body');
    for (const d of body?.descendantsOfType('property_declaration') ?? []) {
      if (!d) continue;
      const v = childOfType(d, 'variable_declaration');
      const n = childOfType(v, 'identifier')?.text;
      if (!n) continue;
      const t = named(v).find((c) => c.type === 'user_type' || c.type === 'nullable_type');
      const init = named(d).find((c) => c.type !== 'modifiers' && c.type !== 'variable_declaration');
      if (init) values.set(n, init);
      if (t) types.set(n, eraseKt(t.text));
      else if (init) { const ct = constructedType(init); if (ct) types.set(n, ct); }
    }
    localTypes.set(fn.id, types);
    localValues.set(fn.id, values);
  };

  const visit = (node: Node, outer: string | null) => {
    let container = outer;
    if (CLASS_TYPES.has(node.type)) {
      const name = node.childForFieldName('name')?.text ?? childOfType(node, 'identifier')?.text ?? '?';
      const dotted = outer ? `${outer}.${name}` : name;
      const symbolId = `${input.repo}:${input.path}#${dotted}`;
      const fields = new Map<string, string>();
      for (const cp of named(childOfType(childOfType(node, 'primary_constructor'), 'class_parameters'))) {
        const n = childOfType(cp, 'identifier')?.text;
        const t = named(cp).find((c) => c.type === 'user_type' || c.type === 'nullable_type');
        if (n && t) fields.set(n, eraseKt(t.text));
      }
      const body = childOfType(node, 'class_body') ?? childOfType(node, 'enum_class_body');
      const members = [...named(body), ...named(childOfType(childOfType(body, 'companion_object'), 'class_body'))];
      for (const m of members) {
        if (m.type !== 'property_declaration') continue;
        const v = childOfType(m, 'variable_declaration');
        const n = childOfType(v, 'identifier')?.text;
        const t = named(v).find((c) => c.type === 'user_type' || c.type === 'nullable_type');
        const init = named(m).find((c) => c.type === 'call_expression');
        const type = t ? eraseKt(t.text) : init ? constructedType(init) : null;
        if (n && type) fields.set(n, type);
      }
      classes.set(node.id, { name, dotted, symbolId, node, fields });
      const isInterface = node.children.some((c) => c?.type === 'interface');
      fx.symbols.push({
        symbolId, repo: input.repo, kind: isInterface ? 'interface' : 'class', name, container: outer ?? pkg,
        path: input.path, range: rangeOf(node), signature: signatureOf(node), qualifiedName: pkg ? `${pkg}.${dotted}` : dotted,
      });
      container = dotted;
    } else if (node.type === 'function_declaration' || node.type === 'secondary_constructor') {
      const inClass = !!outer && (node.parent?.type === 'class_body' || node.parent?.type === 'enum_class_body');
      const topLevel = !outer && (node.parent?.type === 'source_file');
      if (inClass || topLevel) {
        const name = node.type === 'secondary_constructor' ? '<init>' : (node.childForFieldName('name')?.text ?? '?');
        const params = named(childOfType(node, 'function_value_parameters')).filter((p) => p.type === 'parameter');
        const types = params.map((p) => eraseKt(named(p).find((c) => c.type !== 'identifier')?.text ?? '?'));
        const c = inClass ? outer! : pkg;
        const symbolId = `${input.repo}:${input.path}#${c ? c + '.' : ''}${name}(${params.length})`;
        funcIds.set(node.id, symbolId);
        funcNames.set(node.id, name);
        collectLocals(node);
        fx.symbols.push({
          symbolId, repo: input.repo, kind: inClass ? 'method' : 'func', name, container: c, path: input.path, range: rangeOf(node),
          signature: signatureOf(node),
          qualifiedName: inClass ? `${pkg ? pkg + '.' : ''}${outer}#${name}(${types.join(',')})` : `${pkg ? pkg + '.' : ''}${name}`,
        });
      }
      return; // local functions / classes inside a function body are not symbols
    }
    for (const c of named(node)) visit(c, container);
  };
  for (const u of units) visit(u, null);

  const enclosingFunc = (node: Node): Node | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (funcIds.has(p.id)) return p;
    return null;
  };
  const enclosingClass = (node: Node): ClassInfo | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (classes.has(p.id)) return classes.get(p.id)!;
    return null;
  };
  const enclosingSymbol = (node: Node): string | null => {
    const f = enclosingFunc(node);
    if (f) return funcIds.get(f.id) ?? null;
    return enclosingClass(node)?.symbolId ?? null;
  };
  const fieldType = (name: string, at: Node): string | null => {
    for (let p: Node | null = at.parent; p; p = p.parent) {
      const f = classes.get(p.id)?.fields.get(name);
      if (f) return f;
    }
    return null;
  };
  const typeOf = (receiver: Node | null, at: Node): string | null => {
    if (!receiver) return null;
    const ct = constructedType(receiver);
    if (ct) return ct;
    if (receiver.type === 'call_expression') {
      const p = callParts(receiver);
      if (p?.nav && p.name === 'getRuntime' && p.receiver?.text === 'Runtime') return 'Runtime';
      return null;
    }
    let name: string | null = null;
    if (receiver.type === 'identifier') name = receiver.text;
    else if (receiver.type === 'navigation_expression' && receiver.namedChildren[0]?.type === 'this_expression') name = receiver.namedChildren[1]?.text ?? null;
    if (!name) return null;
    const fn = enclosingFunc(at);
    const local = fn ? localTypes.get(fn.id)?.get(name) : undefined;
    if (local) return local;
    const f = fieldType(name, at);
    if (f) return f;
    return /^[A-Z]/.test(name) && receiver.type === 'identifier' ? name : null;
  };
  const receiverImportOf = (receiver: Node | null): string | null => (receiver?.type === 'identifier' ? importAlias.get(receiver.text) ?? null : null);

  // ---- calls ----
  for (const call of all) {
    let parts: CallParts | null = null;
    if (call.type === 'call_expression') parts = callParts(call);
    else if (call.type === 'binary_expression') parts = genericCallParts(call);
    if (!parts) continue;
    const from = enclosingSymbol(call);
    if (!from) continue;
    const arity = argExprs(parts.args).length + (parts.lambda ? 1 : 0);
    let method = parts.name;
    let receiverText: string | null = null;
    let receiverType: string | null = null;
    let receiverImport: string | null = null;
    if (!parts.nav) {
      if (/^[A-Z]/.test(method)) continue; // constructor call
      const imported = importAlias.get(method);
      if (imported) {
        method = imported.split('.').pop()!;
        receiverImport = imported.split('.').slice(0, -1).join('.');
      }
    } else {
      const r = parts.receiver!;
      receiverText = r.type === 'this_expression' ? 'this' : r.type === 'super_expression' ? 'super' : r.text;
      if (r.type !== 'this_expression' && r.type !== 'super_expression') {
        receiverImport = receiverImportOf(r);
        receiverType = receiverImport ? null : typeOf(r, call);
      }
    }
    fx.calls.push({
      from, method, receiverText, receiverType, receiverImport, arity, line: call.startPosition.row + 1,
      calleeText: truncate((call.namedChildren[0]?.text ?? method).replace(/\s+/g, ' '), 200),
    });
  }

  // ---- taint hint (Kotlin): templates / `+` / format → string_concat; literal SQL text → constant ----
  const resolveLocal = (n: Node, at: Node): Node => {
    if (n.type !== 'identifier') return n;
    const fn = enclosingFunc(at);
    return (fn ? localValues.get(fn.id)?.get(n.text) : undefined) ?? n;
  };
  const taintOf = (args: Node | undefined, at: Node, category: string | undefined): string | undefined => {
    const exprs = argExprs(args).map((e) => resolveLocal(e, at));
    if (exprs.length === 0) return undefined;
    if (exprs.some((e) => e.type !== 'lambda_literal' && e.type !== 'annotated_lambda' && isBuilt(e))) return 'string_concat';
    if (exprs.every(isConstantExpr)) return 'constant';
    // Bind parameters after a literal SQL text keep the statement constant.
    if (category === 'sqli' && isConstantExpr(exprs[0]!)) return 'constant';
    return undefined;
  };

  // ---- rules ----
  const seenSinks = new Set<string>();
  const ktorImported = [...imports].some((i) => /^io\.ktor\.(server\.|routing|application)/.test(i));
  const pushSink = (sink: ReturnType<typeof makeSink>) => {
    if (!seenSinks.has(sink.sinkId)) { seenSinks.add(sink.sinkId); fx.sinks.push(sink); }
  };
  const pushSignal = (sig: AuthSignal | null) => {
    if (sig && !fx.authSignals.some((s) => s.target === sig.target && s.detail === sig.detail)) fx.authSignals.push(sig);
  };
  const ktorCalls: { call: Node; verb: string; args: Node | null; ruleId: string }[] = [];
  const inherited: InheritedMapping[] = [];

  for (const { rule, query, error } of rules) {
    if (error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${error}` }); continue; }
    if (!query) continue;
    try {
      for (const unit of units) {
        for (const match of query.matches(unit)) {
          const cap = captureMap(match.captures, rule.captures);
          if (rule.kind === 'sink') {
            const node = cap.get('call');
            if (!node) continue;
            const receiver = cap.get('receiver') ?? null;
            const args = cap.get('args');
            if (rule.post === 'kotlin_redirect_view') {
              // `"redirect:" + x` / `"redirect:$x"`: a view name built from input.
              const lit = cap.get('literal');
              const built = node.type === 'binary_expression' ? isPlusConcat(node) : !!lit && hasInterpolation(lit);
              if (!built || !lit || !/^"redirect:/.test(lit.text)) continue;
              pushSink(makeSink(input.repo, input.path, rule, node, enclosingSymbol(node), fillApi(rule.api ?? '', {}), 'string_concat'));
              continue;
            }
            if (rule.post === 'kotlin_xml_factory') {
              const fn = enclosingFunc(node);
              if (XML_SECURE_RE.test((fn ?? enclosingClass(node)?.node ?? node).text)) continue;
            }
            if (rule.post === 'kotlin_exposed_exec' && ![...imports].some((i) => i.startsWith('org.jetbrains.exposed'))) continue;
            if (rule.post === 'kotlin_field_write') {
              // `x.status = …` / `x.amount += …` / `x.copy(status = …)`: property writes of business fields.
              const field = cap.get('field');
              if (!field) continue;
              const api = fillApi(rule.api ?? '', { field: field.text, method: field.text });
              pushSink(makeSink(input.repo, input.path, rule, node, enclosingSymbol(node), api, undefined));
              continue;
            }
            const receiverImport = receiverImportOf(receiver);
            const receiverType = typeOf(receiver, node);
            const argCount = argExprs(args).length;
            if (!ruleMatches(rule.match, { receiverText: receiver?.text ?? null, receiverType, receiverImport, imports, argCount })) continue;
            const api = fillApi(rule.api ?? '', {
              method: cap.get('method')?.text, type: cap.get('type')?.text, receiver: receiver?.text, receiverType: receiverType ?? receiver?.text,
            });
            pushSink(makeSink(input.repo, input.path, rule, node, enclosingSymbol(node), api, taintOf(args, node, rule.category)));
          } else if (rule.kind === 'entrypoint' && rule.post === 'kotlin_spring_mapping') {
            fx.entries.push(...springEntries(input, rule.id, cap.get('handler'), cap.get('annotation'), funcIds, enclosingClass, consts, inherited));
          } else if (rule.kind === 'entrypoint' && rule.post === 'kotlin_ktor_route') {
            const call = cap.get('call');
            const verb = cap.get('verb')?.text ?? '';
            if (call && ktorImported && KTOR_VERBS.has(verb)) ktorCalls.push({ call, verb, args: cap.get('args') ?? null, ruleId: rule.id });
          } else if (rule.kind === 'auth_signal') {
            pushSignal(authSignal(rule.id, rule.post, cap, funcIds, classes, enclosingSymbol, ktorImported));
          }
        }
      }
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${(e as Error).message}` });
    }
  }

  // ---- Ktor routes: prefixes from enclosing `route("/p") { }`, wrappers (`authenticate("jwt") { }`) as middlewares ----
  if (ktorCalls.length) fx.entries.push(...ktorEntries(input, ktorCalls, all, consts, funcIds, funcNames, enclosingFunc));

  // ---- sockets, queue consumers, timed jobs, commands, Thrift / Dubbo (shared with Java) ----
  const ws: WsRegistration[] = [];
  for (const call of byType('call_expression')) {
    const p = callParts(call);
    if (!p?.nav || p.name !== 'addHandler') continue;
    const fn = enclosingFunc(call);
    const registry = typeOf(p.receiver, call) === 'WebSocketHandlerRegistry'
      || /\bWebSocketHandlerRegistry\b/.test(childOfType(fn, 'function_value_parameters')?.text ?? '');
    const args = argExprs(p.args);
    const paths = args.slice(1).map((a) => constString(a, consts)).filter((x): x is string => x !== null);
    if (!registry || args.length < 2 || !paths.length) continue;
    const h = args[0]!;
    let handlerType = constructedType(h);
    const hp = h.type === 'call_expression' ? callParts(h) : null;
    if (!handlerType && hp && !hp.nav) {
      // `chatHandler()` — a @Bean function of the same class: its declared return type.
      const decl = named(fn?.parent).find((m) => m.type === 'function_declaration' && funcNames.get(m.id) === hp.name);
      const rt = named(decl).find((c) => c.type === 'user_type' || c.type === 'nullable_type');
      handlerType = rt ? eraseKt(rt.text) : null;
    } else if (!handlerType) handlerType = typeOf(h, call);
    ws.push({ handlerType, paths, call, registrar: fn ? funcIds.get(fn.id) ?? null : enclosingSymbol(call) });
  }
  const jvm = jvmClasses(classes, funcIds, funcNames, consts);
  fx.entries.push(...channelEntries(input, 'kotlin', jvm, [...imports], ws));
  fx.entries.push(...kotlinGrpcEntries(input, jvm));

  // Attach annotation-level auth signals to Spring entries (method or class level); Ktor wrappers become middleware signals.
  for (const entry of fx.entries) {
    if (entry.framework === 'spring' || entry.channel) {
      const handler = entry.handler.symbolId ?? '';
      const classId = handler.replace(/\.[^.#]+\(\d+\)$/, '');
      entry.authSignals = fx.authSignals.filter((s) => s.kind === 'annotation' && (s.target === handler || s.target === classId)).map((s) => s.detail);
    } else {
      for (const mw of entry.authSignals) pushSignal({ target: `${input.repo}:${input.path}`, kind: 'middleware', detail: mw, ruleId: entry.ruleId });
    }
  }
  // Mappings on interfaces / unannotated base classes, resolved against implementing controllers in assemble.
  for (const m of inherited) {
    const classId = m.symbolId.replace(/\.[^.#]+\(\d+\)$/, '');
    m.authSignals = fx.authSignals.filter((s) => s.kind === 'annotation' && (s.target === m.symbolId || s.target === classId)).map((s) => s.detail);
  }
  if (inherited.length) fx.inheritedMappings = inherited;
  const types = kotlinTypeFacts(classes, funcIds, funcNames, fx.authSignals, new Set(inherited.map((m) => m.owner)), consts);
  if (types.length) fx.jvmTypes = types;
  return fx;
}

/** Kotlin classes / objects as the facts `channelEntries` reads (interfaces and companion members excluded). */
function jvmClasses(classes: Map<number, ClassInfo>, funcIds: Map<number, string>, funcNames: Map<number, string>, consts: Map<string, string>): JvmClass[] {
  const out: JvmClass[] = [];
  const annsOf = (decl: Node) => annotationsOf(decl).map((a) => ({ name: annotationName(a), args: kotlinAnnotationArgs(a, consts), text: a.text }));
  for (const cls of classes.values()) {
    if (cls.node.children.some((c) => c?.type === 'interface')) continue;
    const supers = named(childOfType(cls.node, 'delegation_specifiers')).map((d) => {
      const t = childOfType(d, 'user_type') ?? childOfType(childOfType(d, 'constructor_invocation'), 'user_type');
      return (t?.text ?? d.text).replace(/<[^>]*>/g, '').replace(/\s+/g, '');
    });
    const methods: JvmMethod[] = [];
    for (const m of named(childOfType(cls.node, 'class_body'))) {
      const symbolId = m.type === 'function_declaration' ? funcIds.get(m.id) : undefined;
      if (!symbolId) continue;
      const vis = childOfType(childOfType(m, 'modifiers'), 'visibility_modifier')?.text ?? 'public';
      methods.push({ node: m, name: funcNames.get(m.id) ?? '', symbolId, anns: annsOf(m), exposed: vis === 'public' });
    }
    out.push({ name: cls.name, dotted: cls.dotted, symbolId: cls.symbolId, node: cls.node, anns: annsOf(cls.node), supers, methods });
  }
  return out;
}

/** `Foo(...)` constructor call → `Foo`. */
function constructedType(n: Node): string | null {
  if (n.type !== 'call_expression') return null;
  const callee = n.namedChildren[0];
  if (callee?.type === 'identifier' && /^[A-Z]/.test(callee.text)) return callee.text;
  return null;
}

/** `r.f<T>(x)` is parsed as comparisons `(r.f < T) > (x)`: recover the call. */
function genericCallParts(n: Node): CallParts | null {
  const left = n.childForFieldName('left');
  const right = n.childForFieldName('right');
  if (left?.type !== 'binary_expression' || right?.type !== 'parenthesized_expression') return null;
  if (!n.children.some((c) => c?.type === '>') || !left.children.some((c) => c?.type === '<')) return null;
  const callee = left.childForFieldName('left');
  const typeArg = left.childForFieldName('right');
  if (!callee || !typeArg || !/^[A-Z][\w.]*$/.test(typeArg.text)) return null;
  if (callee.type === 'navigation_expression') {
    const kids = named(callee);
    const last = kids[kids.length - 1];
    if (kids.length < 2 || last?.type !== 'identifier') return null;
    return { name: last.text, receiver: kids[0]!, args: right, lambda: false, nav: true };
  }
  if (callee.type === 'identifier') return { name: callee.text, receiver: null, args: right, lambda: false, nav: false };
  return null;
}

function stringContent(lit: Node): string {
  const t = lit.text;
  const body = t.startsWith('"""') ? t.slice(3, -3) : t.slice(1, -1);
  return body.replace(/\\\$/g, '$').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

/** Constant string value of an annotation / route argument (literals, `+`, templates of constants, constants). */
function constString(n: Node | null | undefined, consts: Map<string, string>): string | null {
  if (!n) return null;
  if (isStringLit(n)) {
    if (!hasInterpolation(n)) return stringContent(n);
    const raw = n.text.startsWith('"""') ? n.text.slice(3, -3) : n.text.slice(1, -1);
    const v = raw.replace(/\$\{(\w+)\}|\$([A-Za-z_]\w*)/g, (_m, a: string | undefined, b: string | undefined) => {
      return consts.get((a ?? b)!) ?? '{?}';
    });
    return v;
  }
  if (isPlusConcat(n)) {
    const l = constString(n.childForFieldName('left'), consts);
    const r = constString(n.childForFieldName('right'), consts);
    return l !== null && r !== null ? l + r : null;
  }
  if (n.type === 'identifier') return consts.get(n.text) ?? null;
  if (n.type === 'navigation_expression') return consts.get(n.namedChildren[n.namedChildCount - 1]?.text ?? '') ?? null;
  if (n.type === 'parenthesized_expression') return constString(n.namedChildren[0], consts);
  return null;
}

/** Annotation arguments: attribute → values (arrays `[…]` / `arrayOf(…)` flattened; `RequestMethod.GET` → `GET`). */
export function kotlinAnnotationArgs(ann: Node, consts: Map<string, string> = new Map()): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const args = childOfType(childOfType(ann, 'constructor_invocation'), 'value_arguments');
  const values = (n: Node): string[] => {
    if (n.type === 'collection_literal') return named(n).flatMap(values);
    if (n.type === 'call_expression') {
      const p = callParts(n);
      if (p && !p.nav && /^(arrayOf|listOf)$/.test(p.name)) return argExprs(p.args).flatMap(values);
    }
    const s = constString(n, consts);
    if (s !== null) return [s];
    if (n.type === 'navigation_expression' || n.type === 'identifier') return [n.text.split('.').pop() ?? n.text];
    return [n.text];
  };
  for (const a of named(args)) {
    if (a.type !== 'value_argument') continue;
    const key = argName(a) ?? 'value';
    const kids = named(a);
    const v = kids[kids.length - 1];
    if (v) out.set(key, values(v));
  }
  return out;
}

const isKotlinInterface = (decl: Node) => decl.children.some((c) => c?.type === 'interface');

/** A class Spring serves as a controller: `@…Controller` or a class-level `@RequestMapping` (interfaces never). */
function isKotlinController(decl: Node): boolean {
  if (decl.type !== 'class_declaration' || isKotlinInterface(decl)) return false;
  return annotationsOf(decl).map(annotationName).some((n) => /Controller$/.test(n) || n === 'RequestMapping');
}

const MAPPING_ANN_RE = /^(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)$/;

/** Type facts of the file's classes / interfaces for inherited mappings (see jvm-inherit.ts). */
function kotlinTypeFacts(
  classes: Map<number, ClassInfo>, funcIds: Map<number, string>, funcNames: Map<number, string>, signals: AuthSignal[], owners: Set<string>, consts: Map<string, string>,
): JvmTypeFacts[] {
  const out: JvmTypeFacts[] = [];
  const authOf = (target: string) => signals.filter((s) => s.kind === 'annotation' && s.target === target).map((s) => s.detail);
  for (const cls of classes.values()) {
    if (cls.node.type !== 'class_declaration') continue;
    const supers = named(childOfType(cls.node, 'delegation_specifiers')).map((d) => {
      const t = childOfType(d, 'user_type') ?? childOfType(childOfType(d, 'constructor_invocation'), 'user_type');
      return eraseKt(t?.text ?? d.text);
    }).filter((s) => !!s);
    if (!supers.length && !owners.has(cls.name)) continue;
    const classMapping = annotationsOf(cls.node).find((a) => annotationName(a) === 'RequestMapping');
    const methods: JvmTypeFacts['methods'] = [];
    for (const m of named(childOfType(cls.node, 'class_body'))) {
      const symbolId = m.type === 'function_declaration' ? funcIds.get(m.id) : undefined;
      if (!symbolId) continue;
      methods.push({
        name: funcNames.get(m.id) ?? '?', arity: Number(/\((\d+)\)$/.exec(symbolId)?.[1] ?? 0), symbolId, range: rangeOf(m),
        mapped: annotationsOf(m).some((a) => MAPPING_ANN_RE.test(annotationName(a))), authSignals: authOf(symbolId),
      });
    }
    out.push({
      name: cls.name, kind: isKotlinInterface(cls.node) ? 'interface' : 'class', supers, controller: isKotlinController(cls.node),
      prefixes: classMapping ? pathsOf(kotlinAnnotationArgs(classMapping, consts)) : null, classAuth: authOf(cls.symbolId), methods,
    });
  }
  return out;
}

function pathsOf(args: Map<string, string[]>): string[] {
  const p = args.get('path') ?? args.get('value');
  return p && p.length ? p : [''];
}

function springEntries(
  input: ExtractInput, ruleId: string, fn: Node | undefined, ann: Node | undefined, funcIds: Map<number, string>,
  enclosingClass: (n: Node) => ClassInfo | null, consts: Map<string, string>, inherited: InheritedMapping[],
): RawEntry[] {
  if (!fn || !ann) return [];
  const cls = enclosingClass(fn);
  if (!cls || cls.node.type !== 'class_declaration') return [];
  const name = annotationName(ann);
  const args = kotlinAnnotationArgs(ann, consts);
  const methods = MAPPING_METHOD[name] ? [MAPPING_METHOD[name]!] : (args.get('method')?.map((m) => m.toUpperCase()) ?? ['ANY']);
  const symbolId = funcIds.get(fn.id);
  if (!symbolId) return [];
  if (!isKotlinController(cls.node)) {
    // Interface (OpenAPI generator, shared Feign API) or unannotated base class: entries only of the
    // controllers implementing / extending it (assemble). A Feign client nobody implements stays a client.
    const arity = Number(/\((\d+)\)$/.exec(symbolId)?.[1] ?? 0);
    const fname = fn.childForFieldName('name')?.text ?? '?';
    for (const p of pathsOf(args)) for (const hm of methods) {
      inherited.push({ owner: cls.name, ruleId, httpMethod: hm, path: p, method: fname, arity, symbolId, range: rangeOf(fn), authSignals: [] });
    }
    return [];
  }
  const classMapping = annotationsOf(cls.node).find((a) => annotationName(a) === 'RequestMapping');
  const prefixes = classMapping ? pathsOf(kotlinAnnotationArgs(classMapping, consts)) : [''];
  const out: RawEntry[] = [];
  for (const prefix of prefixes) for (const p of pathsOf(args)) for (const hm of methods) {
    out.push({
      ruleId, framework: 'spring', httpMethod: hm, pathTemplate: joinRoute(prefix, p),
      handler: { symbolId }, path: input.path, range: rangeOf(fn), middlewares: [], authSignals: [],
    });
  }
  return out;
}

interface RouteCtx { prefix: string; middlewares: string[]; routed: boolean }

/** Block calls enclosing `node` up to its function: `route("/p") { }` prefixes, other wrappers as middlewares. */
function routeContext(node: Node, consts: Map<string, string>): RouteCtx {
  const frames: { name: string; head: string; path: string | null }[] = [];
  for (let p: Node | null = node.parent; p && p.type !== 'function_declaration'; p = p.parent) {
    if (p.type !== 'annotated_lambda') continue;
    const block = p.parent;
    if (block?.type !== 'call_expression') continue;
    const inner = block.namedChildren[0]?.type === 'call_expression' ? block.namedChildren[0] : block;
    const parts = callParts(inner);
    if (!parts || parts.nav) continue;
    const first = argExprs(parts.args)[0];
    const head = parts.args ? `${parts.name}${parts.args.text.replace(/\s+/g, ' ')}` : parts.name;
    frames.unshift({ name: parts.name, head: truncate(head, 120), path: parts.name === 'route' ? constString(first, consts) ?? '{?}' : null });
  }
  const ctx: RouteCtx = { prefix: '', middlewares: [], routed: false };
  for (const f of frames) {
    if (f.name === 'routing' || f.name === 'route') ctx.routed = true;
    if (f.name === 'route') ctx.prefix = joinRoute(ctx.prefix, f.path ?? '');
    else if (f.name !== 'routing' && !KTOR_VERBS.has(f.name)) ctx.middlewares.push(f.head);
  }
  return ctx;
}

function ktorEntries(
  input: ExtractInput, calls: { call: Node; verb: string; args: Node | null; ruleId: string }[], all: Node[],
  consts: Map<string, string>, funcIds: Map<number, string>, funcNames: Map<number, string>, enclosingFunc: (n: Node) => Node | null,
): RawEntry[] {
  // Same-file route functions (`fun Route.orders()` called inside `route("/api") { orders() }`): inherit the call
  // site's context when every call site agrees.
  const sites = new Map<string, Node[]>();
  for (const n of all) {
    if (n.type !== 'call_expression') continue;
    const p = callParts(n);
    if (p && !p.nav && argExprs(p.args).length === 0 && !p.lambda) {
      const arr = sites.get(p.name);
      if (arr) arr.push(n); else sites.set(p.name, [n]);
    }
  }
  const fnCtx = (fn: Node | null, depth: number): RouteCtx | null => {
    if (!fn || depth > 5) return null;
    const name = funcNames.get(fn.id);
    const at = name ? sites.get(name) ?? [] : [];
    if (at.length === 0) return null;
    const ctxs = at.map((s) => combine(fnCtx(enclosingFunc(s), depth + 1), routeContext(s, consts)));
    const key = (c: RouteCtx) => `${c.prefix}|${c.middlewares.join(',')}`;
    return ctxs.every((c) => key(c) === key(ctxs[0]!)) ? ctxs[0]! : null;
  };
  const combine = (outer: RouteCtx | null, inner: RouteCtx): RouteCtx => (outer
    ? { prefix: joinRoute(outer.prefix, inner.prefix), middlewares: [...outer.middlewares, ...inner.middlewares], routed: outer.routed || inner.routed }
    : inner);
  const out: RawEntry[] = [];
  for (const { call, verb, args, ruleId } of calls) {
    const exprs = argExprs(args);
    const path = exprs.length ? constString(exprs[0], consts) : '';
    if (path === null) continue; // `client.get(url)`-like calls with a computed first argument are not routes
    const fn = enclosingFunc(call);
    const ctx = combine(fnCtx(fn, 0), routeContext(call, consts));
    const recv = fn ? childOfType(fn, 'user_type')?.text ?? '' : '';
    if (!ctx.routed && !/^(Route|Routing|Application)$/.test(recv)) continue;
    const lambda = childOfType(call, 'annotated_lambda') ?? call;
    const sym = fn ? funcIds.get(fn.id) : undefined;
    out.push({
      ruleId, framework: 'ktor', httpMethod: verb.toUpperCase(), pathTemplate: joinRoute(ctx.prefix, path),
      handler: { ...(sym ? { symbolId: sym } : {}), range: rangeOf(lambda) }, path: input.path, range: rangeOf(call),
      middlewares: ctx.middlewares, authSignals: ctx.middlewares.filter((m) => AUTH_NAME_RE.test(m)),
    });
  }
  return out;
}

function authSignal(
  ruleId: string, post: string | undefined, cap: Map<string, Node>, funcIds: Map<number, string>,
  classes: Map<number, ClassInfo>, enclosingSymbol: (n: Node) => string | null, ktorImported: boolean,
): AuthSignal | null {
  if (post === 'kotlin_annotation_auth') {
    const ann = cap.get('annotation');
    if (!ann || !SECURITY_ANN_RE.test(annotationName(ann))) return null;
    const owner = ann.parent?.type === 'modifiers' ? ann.parent.parent : null;
    if (!owner) return null;
    const target = funcIds.get(owner.id) ?? classes.get(owner.id)?.symbolId;
    if (!target) return null;
    return { target, kind: 'annotation', detail: truncate(ann.text.replace(/\s+/g, ' '), 200), ruleId };
  }
  if (post === 'kotlin_filter_class') {
    const cls = cap.get('class');
    const sup = cap.get('super')?.text ?? '';
    const info = cls ? classes.get(cls.id) : undefined;
    if (!info) return null;
    return { target: info.symbolId, kind: /Interceptor/.test(sup) ? 'interceptor' : 'filter', detail: `${info.name} : ${sup}`, ruleId };
  }
  if (post === 'kotlin_security_config') {
    const call = cap.get('call');
    if (!call) return null;
    let outer: Node = call;
    for (;;) {
      const p = outer.parent;
      if (p?.type === 'navigation_expression' && p.namedChildren[0]?.id === outer.id && p.parent?.type === 'call_expression' && p.parent.namedChildren[0]?.id === p.id) outer = p.parent;
      else if (p?.type === 'call_expression' && p.namedChildren[0]?.id === outer.id) outer = p;
      else break;
    }
    // Inside an `authorizeHttpRequests { }` block: that block is the signal.
    for (let p: Node | null = outer.parent; p; p = p.parent) {
      if (p.type === 'call_expression' && p.id !== outer.id) {
        const parts = callParts(p.namedChildren[0]?.type === 'call_expression' ? p.namedChildren[0] : p);
        if (parts && AUTHORIZE_BLOCK_RE.test(parts.name)) return null;
      }
      if (p.type === 'function_declaration') break;
    }
    const target = enclosingSymbol(outer);
    if (!target) return null;
    return { target, kind: 'security_config', detail: truncate(outer.text.replace(/\s+/g, ' '), 300), ruleId };
  }
  if (post === 'kotlin_ktor_install_auth') {
    const call = cap.get('call');
    if (!call || !ktorImported) return null;
    const target = enclosingSymbol(call);
    if (!target) return null;
    return { target, kind: 'security_config', detail: truncate(call.text.replace(/\s+/g, ' '), 300), ruleId };
  }
  return null;
}

/**
 * gRPC service implementations in Kotlin — grpc-kotlin `XxxGrpcKt.XxxCoroutineImplBase()` and grpc-java
 * `XxxGrpc.XxxImplBase()` subclasses; each `override` public method is an rpc entry (proto names when the snapshot has
 * the .proto). `@GrpcService(interceptors = [A::class])` interceptors are middlewares, as for Java.
 */
function kotlinGrpcEntries(input: ExtractInput, classes: JvmClass[]): RawEntry[] {
  const out: RawEntry[] = [];
  for (const cls of classes) {
    const service = cls.supers.map((s) => /(?:^|\.)(\w+)Grpc(?:Kt)?\.\1(?:Coroutine)?ImplBase$/.exec(s)?.[1] ?? /(\w+?)(?:Coroutine)?ImplBase$/.exec(s)?.[1]).find((x) => !!x);
    if (!service) continue;
    const svcAnn = cls.anns.find((a) => a.name === 'GrpcService');
    const interceptors = svcAnn ? [...svcAnn.text.matchAll(/(\w+)::class/g)].map((m) => m[1]!) : [];
    const hasProto = !!input.grpcServices?.some((s) => s.name === service);
    for (const m of cls.methods) {
      if (!m.exposed) continue;
      const isOverride = /^\s*(@[\w.]+(\([^)]*\))?\s*)*([\w\s]*\s)?override\b/.test(m.node.text.slice(0, 200));
      if (!hasProto && !isOverride) continue;
      const rpc = rpcOf(input.grpcServices, service, m.name);
      if (!rpc) continue;
      out.push({
        rpc, ruleId: 'kotlin.grpc.service', framework: 'grpc', httpMethod: 'RPC', pathTemplate: '', handler: { symbolId: m.symbolId },
        path: input.path, range: rangeOf(m.node), middlewares: interceptors, authSignals: interceptors.filter((x) => AUTH_NAME_RE.test(x)),
      });
    }
  }
  return out;
}
