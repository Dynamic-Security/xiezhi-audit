// Java extraction: symbols, calls (with receiver type hints), Spring entries, auth signals, sinks.
import type { Node, Tree } from 'web-tree-sitter';
import type { AuthSignal, IndexSymbol } from '@xiezhi/contracts';
import {
  AUTH_NAME_RE, captureMap, fillApi, makeSink, rangeOf, ruleMatches, taintHintOf, unquote, type CompiledRule,
} from './common.js';
import { urlPatternCovers, type JavaWebContext } from './extract-java-web.js';
import { graphqlEntryOf } from './graphql.js';
import { rpcOf } from './proto.js';
import { emptyExtract, eraseType, joinRoute, type ExtractInput, type FileExtract, type HandlerRef, type InheritedMapping, type JvmTypeFacts, type RawEntry } from './types.js';

const CLASS_TYPES = new Set(['class_declaration', 'interface_declaration', 'enum_declaration', 'record_declaration']);
const METHOD_TYPES = new Set(['method_declaration', 'constructor_declaration']);
const MAPPING_METHOD: Record<string, string> = {
  GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT', DeleteMapping: 'DELETE', PatchMapping: 'PATCH',
};
/** frameworks whose entries carry auth in their middlewares (filters, interceptors, handlers). */
const MIDDLEWARE_AUTH_FRAMEWORKS = new Set(['servlet', 'struts2', 'vertx', 'webflux']);
const SECURITY_ANN_RE = /^(PreAuthorize|PostAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresRoles|SaCheckLogin|SaCheckPermission|SaCheckRole)$/;

interface ClassInfo { name: string; dotted: string; symbolId: string; node: Node; fields: Map<string, string> }

function annotationsOf(modifiers: Node | null): Node[] {
  if (!modifiers) return [];
  return modifiers.namedChildren.filter((n): n is Node => !!n && (n.type === 'annotation' || n.type === 'marker_annotation'));
}

function annName(ann: Node): string {
  const n = ann.childForFieldName('name');
  return (n?.text ?? '').split('.').pop() ?? '';
}

function modifiersOf(decl: Node): Node | null {
  return decl.namedChildren.find((n): n is Node => !!n && n.type === 'modifiers') ?? null;
}

/** Parse annotation arguments into attribute → string values (value/path/method...). */
export function annotationArgs(ann: Node): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const args = ann.childForFieldName('arguments');
  if (!args) return out;
  const values = (node: Node): string[] => {
    if (node.type === 'string_literal') return [unquote(node.text)];
    if (node.type === 'element_value_array_initializer') return node.namedChildren.flatMap((c) => (c ? values(c) : []));
    if (node.type === 'field_access' || node.type === 'identifier' || node.type === 'scoped_identifier') return [node.text.split('.').pop() ?? node.text];
    if (node.type === 'binary_expression') return [node.text.split('+').map((s) => unquote(s.trim())).join('')];
    return [node.text];
  };
  for (const child of args.namedChildren) {
    if (!child) continue;
    if (child.type === 'element_value_pair') {
      const key = child.childForFieldName('key')?.text ?? 'value';
      const val = child.childForFieldName('value');
      if (val) out.set(key, values(val));
    } else {
      out.set('value', values(child));
    }
  }
  return out;
}

export function extractJava(input: ExtractInput, tree: Tree, rules: CompiledRule[]): FileExtract {
  const fx = emptyExtract(input);
  const root = tree.rootNode;
  const pkgNode = root.namedChildren.find((n) => n?.type === 'package_declaration');
  const pkg = pkgNode ? pkgNode.text.replace(/^package\s+/, '').replace(/;\s*$/, '').trim() : '';
  fx.pkg = pkg;
  const classes = new Map<number, ClassInfo>();
  const methodIds = new Map<number, string>();
  const localTypes = new Map<number, Map<string, string>>();

  // ---- symbols ----
  const visit = (node: Node, outer: string | null) => {
    let container = outer;
    if (CLASS_TYPES.has(node.type)) {
      const name = node.childForFieldName('name')?.text ?? '?';
      const dotted = outer ? `${outer}.${name}` : name;
      const symbolId = `${input.repo}:${input.path}#${dotted}`;
      const fields = new Map<string, string>();
      const body = node.childForFieldName('body');
      for (const member of body?.namedChildren ?? []) {
        if (member?.type !== 'field_declaration') continue;
        const t = member.childForFieldName('type');
        for (const d of member.namedChildren) {
          if (d?.type === 'variable_declarator') {
            const vn = d.childForFieldName('name')?.text;
            if (vn && t) fields.set(vn, eraseType(t.text));
          }
        }
      }
      classes.set(node.id, { name, dotted, symbolId, node, fields });
      fx.symbols.push({
        symbolId, repo: input.repo, kind: node.type === 'interface_declaration' ? 'interface' : 'class', name, container: outer ?? pkg,
        path: input.path, range: rangeOf(node), signature: firstLine(node.text), qualifiedName: pkg ? `${pkg}.${dotted}` : dotted,
      });
      container = dotted;
    } else if (METHOD_TYPES.has(node.type) && outer) {
      const name = node.type === 'constructor_declaration' ? '<init>' : (node.childForFieldName('name')?.text ?? '?');
      const params = node.childForFieldName('parameters');
      const types: string[] = [];
      const locals = new Map<string, string>();
      for (const p of params?.namedChildren ?? []) {
        if (!p || (p.type !== 'formal_parameter' && p.type !== 'spread_parameter')) continue;
        const tNode = p.childForFieldName('type') ?? p.namedChildren.find((c) => !!c && /type|identifier/.test(c.type) && c.type !== 'modifiers') ?? null;
        const t = eraseType((tNode?.text ?? '?') + (p.type === 'spread_parameter' ? '...' : ''));
        types.push(t);
        const pn = p.childForFieldName('name')?.text ?? p.namedChildren.filter((c) => c?.type === 'variable_declarator').map((c) => c!.childForFieldName('name')?.text)[0];
        if (pn) locals.set(pn, t.replace(/\[\]$/, ''));
      }
      for (const decl of node.descendantsOfType('local_variable_declaration')) {
        if (!decl) continue;
        const t = decl.childForFieldName('type');
        for (const d of decl.namedChildren) {
          if (d?.type === 'variable_declarator') {
            const vn = d.childForFieldName('name')?.text;
            let typeName = t ? eraseType(t.text) : null;
            if (typeName === 'var') {
              const value = d.childForFieldName('value');
              typeName = value?.type === 'object_creation_expression' ? eraseType(value.childForFieldName('type')?.text ?? '') : null;
            }
            if (vn && typeName) locals.set(vn, typeName);
          }
        }
      }
      const symbolId = `${input.repo}:${input.path}#${outer}.${name}(${types.length})`;
      methodIds.set(node.id, symbolId);
      localTypes.set(node.id, locals);
      fx.symbols.push({
        symbolId, repo: input.repo, kind: 'method', name, container: outer, path: input.path, range: rangeOf(node),
        signature: firstLine(node.text), qualifiedName: `${pkg ? pkg + '.' : ''}${outer}#${name}(${types.join(',')})`,
      });
    }
    for (const c of node.namedChildren) if (c) visit(c, container);
  };
  visit(root, null);

  const enclosingMethod = (node: Node): Node | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (METHOD_TYPES.has(p.type)) return p;
    return null;
  };
  const enclosingClass = (node: Node): ClassInfo | null => {
    for (let p: Node | null = node.parent; p; p = p.parent) if (CLASS_TYPES.has(p.type)) return classes.get(p.id) ?? null;
    return null;
  };
  const enclosingSymbol = (node: Node): string | null => {
    const m = enclosingMethod(node);
    if (m) return methodIds.get(m.id) ?? null;
    return enclosingClass(node)?.symbolId ?? null;
  };
  const typeOf = (receiver: Node | null, at: Node): string | null => {
    if (!receiver) return null;
    if (receiver.type === 'object_creation_expression') return eraseType(receiver.childForFieldName('type')?.text ?? '');
    let name: string | null = null;
    if (receiver.type === 'identifier') name = receiver.text;
    else if (receiver.type === 'field_access' && receiver.childForFieldName('object')?.type === 'this') name = receiver.childForFieldName('field')?.text ?? null;
    if (!name) return null;
    const m = enclosingMethod(at);
    const local = m ? localTypes.get(m.id)?.get(name) : undefined;
    if (local) return local;
    for (let p: Node | null = at.parent; p; p = p.parent) {
      if (CLASS_TYPES.has(p.type)) {
        const f = classes.get(p.id)?.fields.get(name);
        if (f) return f;
      }
    }
    return /^[A-Z]/.test(name) ? name : null;
  };

  // ---- calls ----
  for (const call of root.descendantsOfType('method_invocation')) {
    if (!call) continue;
    const from = enclosingSymbol(call);
    if (!from) continue;
    const receiver = call.childForFieldName('object');
    const method = call.childForFieldName('name')?.text ?? '';
    const args = call.childForFieldName('arguments');
    fx.calls.push({
      from, method, receiverText: receiver?.text ?? null,
      receiverType: receiver?.type === 'this' ? null : typeOf(receiver, call), receiverImport: null,
      arity: args?.namedChildren.length ?? 0, line: call.startPosition.row + 1, calleeText: truncate(call.text.split('(')[0] ?? '', 200),
    });
  }

  // ---- rules ----
  // import declarations, for rules that require one (`requiresImportAny`).
  const imports = new Set<string>(importsOf(root));
  const seenSinks = new Set<string>();
  const inherited: InheritedMapping[] = [];
  for (const { rule, query, error } of rules) {
    if (error) { fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${error}` }); continue; }
    if (!query) continue;
    try {
      for (const match of query.matches(root)) {
        const cap = captureMap(match.captures, rule.captures);
        if (rule.kind === 'sink') {
          const node = cap.get('call');
          if (!node) continue;
          if (rule.post === 'mybatis_annotation_dollar') {
            const argsNode = cap.get('args');
            if (!argsNode || !/\$\{/.test(argsNode.text)) continue;
            const method = node.parent?.parent;
            const handler = method && METHOD_TYPES.has(method.type) ? methodIds.get(method.id) ?? null : null;
            const sink = makeSink(input.repo, input.path, rule, node, handler, fillApi(rule.api ?? '', { handler: handler ?? '?' }), 'string_concat');
            if (!seenSinks.has(sink.sinkId)) { seenSinks.add(sink.sinkId); fx.sinks.push(sink); }
            continue;
          }
          const receiver = cap.get('receiver') ?? null;
          const args = cap.get('args');
          // `stack.findValue("user")` with a literal expression is not an injection point.
          if (rule.post === 'java_sink_non_literal' && args?.namedChildren[0]?.type === 'string_literal') continue;
          const receiverType = typeOf(receiver, node);
          if (!ruleMatches(rule.match, {
            receiverText: receiver?.text ?? null, receiverType, receiverImport: null, imports, argCount: args?.namedChildren.length ?? 0,
          })) continue;
          const api = fillApi(rule.api ?? '', {
            method: cap.get('method')?.text, type: cap.get('type')?.text, receiver: receiver?.text, receiverType: receiverType ?? receiver?.text,
          });
          const sink = makeSink(input.repo, input.path, rule, node, enclosingSymbol(node), api, taintHintOf(args));
          if (!seenSinks.has(sink.sinkId)) { seenSinks.add(sink.sinkId); fx.sinks.push(sink); }
        } else if (rule.kind === 'entrypoint' && rule.post === 'spring_request_mapping') {
          fx.entries.push(...springEntries(input, rule.id, cap.get('handler'), cap.get('annotation'), methodIds, enclosingClass, inherited));
        } else if (rule.kind === 'entrypoint' && rule.post === 'jaxrs_resource') {
          fx.entries.push(...jaxrsEntries(input, rule.id, cap.get('handler'), cap.get('annotation'), methodIds, enclosingClass));
        } else if (rule.kind === 'entrypoint' && rule.post === 'java_servlet') {
          const cls = cap.get('class');
          const info = cls ? classes.get(cls.id) : undefined;
          if (info) fx.entries.push(...servletEntries(input, rule.id, info, pkg, methodIds));
        } else if (rule.kind === 'entrypoint' && rule.post === 'java_struts_action') {
          const cls = cap.get('class');
          const info = cls ? classes.get(cls.id) : undefined;
          if (info) fx.entries.push(...strutsEntries(input, rule.id, info, pkg, methodIds, imports));
        } else if (rule.kind === 'entrypoint' && rule.post === 'java_webflux_route') {
          const call = cap.get('call');
          if (call && [...imports].some((i) => /\.web\.(reactive|servlet)\.function\b/.test(i))) {
            fx.entries.push(...webfluxEntries(input, rule.id, call, [...imports].some((i) => /\.web\.reactive\.function\b/.test(i)) ? 'webflux' : 'spring', enclosingSymbol, enclosingClass, typeOf, methodIds));
          }
        } else if (rule.kind === 'entrypoint' && rule.post === 'java_vertx_route') {
          const call = cap.get('call');
          if (call && [...imports].some((i) => /^io\.vertx\.ext\.web\b/.test(i))) {
            const e = vertxEntry(input, rule.id, call, root, enclosingSymbol, enclosingClass, typeOf, methodIds);
            if (e) fx.entries.push(e);
          }
        } else if (rule.kind === 'auth_signal') {
          const sig = authSignal(rule.id, rule.post, cap, methodIds, enclosingClass, enclosingSymbol);
          if (sig && !fx.authSignals.some((s) => s.target === sig.target && s.detail === sig.detail)) fx.authSignals.push(sig);
        }
      }
    } catch (e) {
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: `${rule.id}: ${(e as Error).message}` });
    }
  }

  fx.entries.push(...grpcEntries(input, classes, methodIds));
  fx.entries.push(...graphqlEntries(input, classes, methodIds));
  fx.entries.push(...channelEntries(input, 'java', jvmClasses(classes, methodIds), importsOf(root), wsRegistrations(root, methodIds, enclosingSymbol, enclosingMethod, typeOf)));

  // Attach annotation-level auth signals to entries (method or class level).
  for (const entry of fx.entries) {
    const handler = entry.handler.symbolId ?? '';
    const classId = handler.replace(/\.[^.#]+\(\d+\)$/, '');
    entry.authSignals = [
      ...fx.authSignals.filter((s) => s.kind === 'annotation' && (s.target === handler || s.target === classId)).map((s) => s.detail),
      // gRPC services: auth-like interceptors from @GrpcService; servlet filters / security constraints,
      // Struts interceptors, Vert.x auth handlers.
      ...(entry.rpc || MIDDLEWARE_AUTH_FRAMEWORKS.has(entry.framework) ? entry.middlewares.filter((m) => AUTH_NAME_RE.test(m)) : []),
    ];
  }
  // Inherited mappings carry the declaring method's / type's annotation signals.
  for (const m of inherited) {
    const classId = m.symbolId.replace(/\.[^.#]+\(\d+\)$/, '');
    m.authSignals = fx.authSignals.filter((s) => s.kind === 'annotation' && (s.target === m.symbolId || s.target === classId)).map((s) => s.detail);
  }
  if (inherited.length) fx.inheritedMappings = inherited;
  const types = jvmTypeFacts(classes, methodIds, fx.authSignals, new Set(inherited.map((m) => m.owner)));
  if (types.length) fx.jvmTypes = types;
  return fx;
}

/**
 * gRPC service implementations: `class X extends GreeterGrpc.GreeterImplBase` → one `rpc` entry per
 * implemented rpc (proto names when the snapshot has the .proto; otherwise public `@Override` methods).
 */
function grpcEntries(input: ExtractInput, classes: Map<number, ClassInfo>, methodIds: Map<number, string>): RawEntry[] {
  const out: RawEntry[] = [];
  for (const cls of classes.values()) {
    if (cls.node.type !== 'class_declaration') continue;
    const sup = cls.node.childForFieldName('superclass')?.text ?? '';
    const service = /(\w+)ImplBase\s*$/.exec(sup.replace(/<[^>]*>/g, ''))?.[1];
    if (!service) continue;
    // grpc-spring-boot-starter: @GrpcService(interceptors = { AuthInterceptor.class }) → per-service interceptors.
    const svcAnn = annotationsOf(modifiersOf(cls.node)).find((a) => annName(a) === 'GrpcService');
    const interceptors = svcAnn ? [...(svcAnn.text.match(/(\w+)\.class/g) ?? [])].map((x) => x.replace(/\.class$/, '')) : [];
    for (const m of cls.node.childForFieldName('body')?.namedChildren ?? []) {
      if (m?.type !== 'method_declaration') continue;
      const mods = modifiersOf(m);
      const modText = mods?.text ?? '';
      if (!/\bpublic\b/.test(modText) || /\bstatic\b/.test(modText)) continue;
      const name = m.childForFieldName('name')?.text ?? '';
      const hasOverride = annotationsOf(mods).some((a) => annName(a) === 'Override');
      if (!input.grpcServices?.some((s) => s.name === service) && !hasOverride) continue;
      const rpc = rpcOf(input.grpcServices, service, name);
      const symbolId = methodIds.get(m.id);
      if (!rpc || !symbolId) continue;
      out.push({
        rpc, ruleId: 'java.grpc.service', framework: 'grpc', httpMethod: 'RPC', pathTemplate: '', handler: { symbolId },
        path: input.path, range: rangeOf(m), middlewares: interceptors, authSignals: [],
      });
    }
  }
  return out;
}

const GQL_ROOT_ANN: Record<string, 'query' | 'mutation' | 'subscription'> = {
  QueryMapping: 'query', MutationMapping: 'mutation', SubscriptionMapping: 'subscription', DgsQuery: 'query', DgsMutation: 'mutation', DgsSubscription: 'subscription',
};
const KICKSTART_ROOT: Record<string, 'query' | 'mutation' | 'subscription'> = {
  GraphQLQueryResolver: 'query', GraphQLMutationResolver: 'mutation', GraphQLSubscriptionResolver: 'subscription',
};

/** Simple name of a parameter's type, the element type for `List<Book>` / `Collection<Book>`. */
function sourceType(method: Node): string | null {
  const p = method.childForFieldName('parameters')?.namedChildren.find((x) => x?.type === 'formal_parameter');
  const t = p?.childForFieldName('type')?.text ?? '';
  const inner = /<\s*([\w.]+)\s*>/.exec(t)?.[1];
  return eraseType(inner ?? t) || null;
}

/**
 * GraphQL resolvers: Spring for GraphQL `@QueryMapping` / `@MutationMapping` / `@SubscriptionMapping` /
 * `@SchemaMapping` / `@BatchMapping`, Netflix DGS `@DgsQuery` / `@DgsMutation` / `@DgsSubscription` / `@DgsData`, and
 * graphql-java-kickstart `GraphQLQueryResolver` / `GraphQLMutationResolver` / `GraphQLResolver<T>` classes. Field names
 * default to the method name; with a schema, undeclared fields are not resolvers.
 */
function graphqlEntries(input: ExtractInput, classes: Map<number, ClassInfo>, methodIds: Map<number, string>): RawEntry[] {
  const out: RawEntry[] = [];
  const roots = input.graphql?.roots ?? { query: 'Query', mutation: 'Mutation', subscription: 'Subscription' };
  for (const cls of classes.values()) {
    if (cls.node.type !== 'class_declaration') continue;
    const classAnns = annotationsOf(modifiersOf(cls.node));
    const classType = classAnns.filter((a) => annName(a) === 'SchemaMapping').map((a) => annotationArgs(a).get('typeName')?.[0]).find((x) => !!x);
    const ifaces = cls.node.childForFieldName('interfaces')?.text ?? '';
    const kickRoots = Object.entries(KICKSTART_ROOT).filter(([k]) => new RegExp(`\\b${k}\\b`).test(ifaces)).map(([, v]) => v);
    const kickType = /\bGraphQLResolver\s*<\s*([\w.]+)\s*>/.exec(ifaces)?.[1]?.split('.').pop();
    for (const m of cls.node.childForFieldName('body')?.namedChildren ?? []) {
      if (m?.type !== 'method_declaration') continue;
      const symbolId = methodIds.get(m.id);
      if (!symbolId) continue;
      const mods = modifiersOf(m);
      const name = m.childForFieldName('name')?.text ?? '';
      const targets: { type: string; field: string; rule: string }[] = [];
      for (const a of annotationsOf(mods)) {
        const n = annName(a);
        const args = annotationArgs(a);
        if (GQL_ROOT_ANN[n]) {
          targets.push({ type: roots[GQL_ROOT_ANN[n]], field: args.get('name')?.[0] ?? args.get('field')?.[0] ?? args.get('value')?.[0] ?? name, rule: n.startsWith('Dgs') ? 'java.dgs' : 'java.spring-graphql' });
        } else if (n === 'SchemaMapping' || n === 'BatchMapping') {
          const type = args.get('typeName')?.[0] ?? classType ?? sourceType(m);
          if (type) targets.push({ type, field: args.get('field')?.[0] ?? args.get('value')?.[0] ?? name, rule: 'java.spring-graphql' });
        } else if (n === 'DgsData') {
          // Generated constants: `parentType = DgsConstants.SHOW.TYPE_NAME, field = DgsConstants.SHOW.Reviews`.
          const constType = /parentType\s*=\s*[\w.]*?(\w+)\.TYPE_NAME\b/.exec(a.text)?.[1];
          const type = constType ?? args.get('parentType')?.[0];
          if (type) targets.push({ type, field: args.get('field')?.[0] ?? name, rule: 'java.dgs' });
        }
      }
      if (!targets.length && /\bpublic\b/.test(mods?.text ?? '') && !/\bstatic\b/.test(mods?.text ?? '')) {
        // kickstart: getters `getX` / `isX` also resolve field `x`.
        const field = /^(get|is)[A-Z]/.test(name) ? name.replace(/^(get|is)(\w)/, (_, _p, c: string) => c.toLowerCase()) : name;
        for (const r of kickRoots) targets.push({ type: roots[r], field: name, rule: 'java.graphql-kickstart' });
        if (kickType) targets.push({ type: kickType, field, rule: 'java.graphql-kickstart' });
      }
      for (const t of targets) {
        const g = graphqlEntryOf(input.graphql, t.type, t.field);
        // kickstart getters: try the getter name too.
        const gq = g ?? (t.rule === 'java.graphql-kickstart' ? graphqlEntryOf(input.graphql, t.type, name) : null);
        if (!gq) continue;
        out.push({
          rpc: gq.rpc, ruleId: `${t.rule}.${gq.root ? 'operation' : 'field'}`, framework: 'graphql', httpMethod: 'RPC', pathTemplate: gq.pathTemplate,
          handler: { symbolId }, path: input.path, range: rangeOf(m), middlewares: gq.directives, authSignals: [],
        });
      }
    }
  }
  return out;
}

// ---- entries that are not HTTP routes (shared with Kotlin through the Jvm* facts) ----

/** One annotation as plain facts: simple name, attribute → values, source text (nested annotations are only in the text). */
export interface JvmAnn { name: string; args: Map<string, string[]>; text: string }
/** A method declared directly in a class body; `exposed`: callable from outside (Java `public`, Kotlin not private / protected / internal), not static. */
export interface JvmMethod { node: Node; name: string; symbolId: string; anns: JvmAnn[]; exposed: boolean }
/** A class (or Kotlin `object`); `supers`: supertype texts without generics (`UserService.Iface`, `CommandLineRunner`). */
export interface JvmClass { name: string; dotted: string; symbolId: string; node: Node; anns: JvmAnn[]; supers: string[]; methods: JvmMethod[] }
/** Spring `registry.addHandler(handler, "/path", …)`: the handler's type when known and the method that registers it. */
export interface WsRegistration { handlerType: string | null; paths: string[]; call: Node; registrar: string | null }

type Channel = NonNullable<RawEntry['channel']>;

const MQ_LISTENER: Record<string, { protocol: string; framework: string; attrs: string[]; nested?: RegExp }> = {
  KafkaListener: { protocol: 'kafka', framework: 'spring-kafka', attrs: ['topics', 'topicPattern'], nested: /TopicPartition\s*\(\s*topic\s*=\s*"([^"]*)"/g },
  RabbitListener: { protocol: 'rabbitmq', framework: 'spring-amqp', attrs: ['queues'], nested: /Queue\s*\(\s*(?:(?:value|name)\s*=\s*)?"([^"]*)"/g },
  JmsListener: { protocol: 'jms', framework: 'spring-jms', attrs: ['destination'] },
  SqsListener: { protocol: 'sqs', framework: 'spring-cloud-aws', attrs: ['value', 'queueNames'] },
  RocketMQMessageListener: { protocol: 'rocketmq', framework: 'rocketmq-spring', attrs: ['topic'] },
};
/** Class-level listeners dispatch to these methods (RocketMQ: the `RocketMQListener.onMessage` implementation). */
const MQ_CLASS_HANDLER: Record<string, (m: JvmMethod) => boolean> = {
  KafkaListener: (m) => m.anns.some((a) => a.name === 'KafkaHandler'),
  RabbitListener: (m) => m.anns.some((a) => a.name === 'RabbitHandler'),
  RocketMQMessageListener: (m) => m.name === 'onMessage' && m.exposed,
};
const SCHEDULE_ATTRS = ['cron', 'fixedRate', 'fixedRateString', 'fixedDelay', 'fixedDelayString'];
const WS_HANDLER_METHODS = ['handleTextMessage', 'handleMessage', 'handleBinaryMessage', 'afterConnectionEstablished'];

const simpleType = (t: string) => t.replace(/::class(\.java)?$|\.class$/, '').split('.').pop() ?? t;
const kebab = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, '$1-$2').toLowerCase();

/** `@MessageMapping` prefix + destination: `/`-joined unless the prefix uses `.` separators (`chat` + `send` → `chat.send`). */
function joinDestination(prefix: string, dest: string): string {
  if (!prefix) return dest;
  if (!dest) return prefix;
  if (prefix.endsWith('/') || dest.startsWith('/')) return `${prefix}/${dest}`.replace(/\/{2,}/g, '/');
  return `${prefix}${prefix.includes('.') && !prefix.includes('/') ? '.' : '/'}${dest}`;
}

/**
 * socket endpoints (`@ServerEndpoint`, Spring `addHandler`, STOMP `@MessageMapping` / `@SubscribeMapping`),
 * queue consumers (`@KafkaListener` / `@RabbitListener` / `@JmsListener` / `@SqsListener` / `@RocketMQMessageListener`),
 * timed jobs (`@Scheduled`, `@XxlJob`), commands (picocli `@Command`, Spring Shell `@ShellMethod` / `@Command`,
 * `CommandLineRunner` / `ApplicationRunner`) and RPC services (Thrift `X.Iface` implementations, Dubbo `@DubboService`
 * / dubbo `@Service`). Java and Kotlin hand in the same facts; `lang` prefixes the rule ids.
 */
export function channelEntries(input: ExtractInput, lang: 'java' | 'kotlin', classes: JvmClass[], imports: string[], ws: WsRegistration[]): RawEntry[] {
  const out: RawEntry[] = [];
  const push = (ruleId: string, framework: string, channel: Channel, handler: HandlerRef, node: Node) => {
    out.push({
      channel, ruleId: `${lang}.${ruleId}`, framework, httpMethod: '', pathTemplate: '', handler,
      path: input.path, range: rangeOf(node), middlewares: [], authSignals: [],
    });
  };
  const imported = (re: RegExp) => imports.some((i) => re.test(i));
  const springShell = imported(/^org\.springframework\.shell\b/);
  const picocli = imported(/^picocli\b/);
  const dubboService = imported(/^(org\.apache|com\.alibaba)\.dubbo\.config\.annotation\.(Service|\*)$/);
  const ref = (m: JvmMethod): HandlerRef => ({ symbolId: m.symbolId });

  for (const cls of classes) {
    const classAnn = (name: string) => cls.anns.find((a) => a.name === name);

    // ---- sockets ----
    const endpoint = classAnn('ServerEndpoint');
    if (endpoint) {
      const path = endpoint.args.get('value')?.[0] ?? '';
      const onMessage = ['OnMessage', 'OnOpen'].map((n) => cls.methods.find((m) => m.anns.some((a) => a.name === n))).find((m) => !!m);
      push('websocket.endpoint', 'jakarta-websocket', { kind: 'socket', protocol: 'websocket', key: `ws:${path}`, route: path },
        onMessage ? ref(onMessage) : { symbolId: cls.symbolId }, onMessage?.node ?? cls.node);
    }
    const prefixes = classAnn('MessageMapping')?.args.get('value') ?? [''];
    for (const m of cls.methods) {
      for (const a of m.anns) {
        if (a.name !== 'MessageMapping' && a.name !== 'SubscribeMapping') continue;
        const dests = a.args.get('value') ?? [''];
        for (const p of prefixes) for (const d of dests) {
          const dest = joinDestination(p, d);
          if (!dest) continue;
          push(a.name === 'MessageMapping' ? 'stomp.message' : 'stomp.subscribe', 'spring-messaging',
            { kind: 'socket', protocol: 'stomp', key: `stomp:${dest}`, route: dest }, ref(m), m.node);
        }
      }
    }

    // ---- queue consumers: method-level listeners, class-level ones on their handler methods ----
    const topicsOf = (a: JvmAnn): string => {
      const spec = MQ_LISTENER[a.name]!;
      const vals = spec.attrs.flatMap((k) => a.args.get(k) ?? []);
      if (!vals.length && spec.nested) vals.push(...[...a.text.matchAll(spec.nested)].map((x) => x[1]!));
      return vals.length ? vals.join(',') : '{?}';
    };
    const pushListener = (a: JvmAnn, m: JvmMethod) => {
      const spec = MQ_LISTENER[a.name]!;
      const topic = topicsOf(a);
      push(`${spec.protocol}.listener`, spec.framework, { kind: 'message', protocol: spec.protocol, key: `mq:${spec.protocol}:${topic}`, route: topic }, ref(m), m.node);
    };
    for (const a of cls.anns) {
      const handles = MQ_CLASS_HANDLER[a.name];
      if (handles) for (const m of cls.methods) if (handles(m)) pushListener(a, m);
    }
    for (const m of cls.methods) for (const a of m.anns) if (MQ_LISTENER[a.name] && a.name !== 'RocketMQMessageListener') pushListener(a, m);

    // ---- timed jobs ----
    for (const m of cls.methods) {
      for (const a of m.anns) {
        let route: string | null = null;
        let rule = 'scheduled';
        let framework = 'spring';
        if (a.name === 'Scheduled') {
          const k = SCHEDULE_ATTRS.find((x) => a.args.get(x)?.length);
          route = k === 'cron' ? a.args.get(k)![0]! : k ? `${k}=${a.args.get(k)![0]}` : 'scheduled';
        } else if (a.name === 'XxlJob') {
          route = a.args.get('value')?.[0] ?? m.name;
          rule = 'xxljob';
          framework = 'xxl-job';
        }
        if (route !== null) push(rule, framework, { kind: 'schedule', protocol: 'cron', key: `cron:${cls.dotted}.${m.name}`, route }, ref(m), m.node);
      }
    }

    // ---- commands ----
    const clsCommand = classAnn('Command');
    const shellClass = !!clsCommand && (springShell || clsCommand.args.has('command')) && !picocli;
    const group = clsCommand ? (shellClass ? clsCommand.args.get('command')?.[0] : clsCommand.args.get('name')?.[0]) ?? '' : '';
    if (clsCommand && !shellClass) {
      const run = cls.methods.find((m) => (m.name === 'call' || m.name === 'run') && m.exposed);
      const name = group || cls.name;
      push('picocli.command', 'picocli', { kind: 'cli', protocol: 'cli', key: `cli:${name}`, route: name }, run ? ref(run) : { symbolId: cls.symbolId }, run?.node ?? cls.node);
    }
    for (const m of cls.methods) {
      for (const a of m.anns) {
        let name: string | null = null;
        let framework = 'spring-shell';
        if (a.name === 'ShellMethod') name = a.args.get('key')?.[0] ?? kebab(m.name);
        else if (a.name === 'Command' && (springShell || a.args.has('command')) && !picocli) name = a.args.get('command')?.[0] ?? kebab(m.name);
        else if (a.name === 'Command' && clsCommand && !shellClass) { name = a.args.get('name')?.[0] ?? m.name; framework = 'picocli'; }
        if (name === null) continue;
        const full = group ? `${group} ${name}` : name;
        push(`${framework === 'picocli' ? 'picocli' : 'shell'}.command`, framework, { kind: 'cli', protocol: 'cli', key: `cli:${full}`, route: full }, ref(m), m.node);
      }
    }
    if (cls.supers.some((s) => /^(CommandLineRunner|ApplicationRunner)$/.test(simpleType(s)))) {
      const run = cls.methods.find((m) => m.name === 'run');
      if (run) push('cli.runner', 'spring-boot', { kind: 'cli', protocol: 'cli', key: `cli:${cls.dotted}`, route: cls.dotted }, ref(run), run.node);
    }

    // ---- RPC services: Thrift `X.Iface` implementations, Dubbo services (one entry per exposed method) ----
    const thrift = cls.supers.map((s) => /(?:^|\.)(\w+)\.(?:Async)?Iface$/.exec(s)?.[1]).find((x) => !!x);
    const dubbo = classAnn('DubboService') ?? cls.anns.find((a) => a.name === 'Service' && (dubboService || /dubbo/.test(a.text)));
    const services: { protocol: string; framework: string; rule: string; service: string }[] = [];
    if (thrift) services.push({ protocol: 'thrift', framework: 'thrift', rule: 'thrift.iface', service: thrift });
    if (dubbo) {
      const declared = dubbo.args.get('interfaceClass')?.[0] ?? dubbo.args.get('interfaceName')?.[0];
      const iface = declared ? simpleType(declared) : cls.supers.map(simpleType).find((s) => /^[A-Z]/.test(s)) ?? cls.name;
      services.push({ protocol: 'dubbo', framework: 'dubbo', rule: 'dubbo.service', service: iface });
    }
    for (const s of services) {
      for (const m of cls.methods) {
        if (!m.exposed) continue;
        const route = `${s.service}/${m.name}`;
        push(s.rule, s.framework, { kind: 'rpc', protocol: s.protocol, key: `rpc:${s.protocol}:${route}`, route }, ref(m), m.node);
      }
    }
  }

  // ---- Spring WebSocketConfigurer: `registry.addHandler(handler, "/path")` → the handler's message method ----
  for (const r of ws) {
    const local = r.handlerType ? classes.find((c) => c.name === r.handlerType) : undefined;
    const method = local ? WS_HANDLER_METHODS.map((n) => local.methods.find((m) => m.name === n)).find((m) => !!m) : undefined;
    const handler: HandlerRef = method ? ref(method)
      : r.handlerType ? { text: `${r.handlerType}.handleTextMessage`, className: r.handlerType, range: rangeOf(r.call) }
      : { ...(r.registrar ? { symbolId: r.registrar } : {}), range: rangeOf(r.call) };
    for (const path of r.paths) {
      push('websocket.handler', 'spring-websocket', { kind: 'socket', protocol: 'websocket', key: `ws:${path}`, route: path }, handler, r.call);
    }
  }
  return out;
}

/** Java classes as the facts `channelEntries` reads. */
function jvmClasses(classes: Map<number, ClassInfo>, methodIds: Map<number, string>): JvmClass[] {
  const out: JvmClass[] = [];
  const annsOf = (decl: Node): JvmAnn[] => annotationsOf(modifiersOf(decl)).map((a) => ({ name: annName(a), args: annotationArgs(a), text: a.text }));
  for (const cls of classes.values()) {
    if (cls.node.type !== 'class_declaration') continue;
    const sup = cls.node.childForFieldName('superclass')?.namedChildren[0];
    const ifaces = cls.node.childForFieldName('interfaces')?.namedChildren.find((n) => n?.type === 'type_list')?.namedChildren ?? [];
    const supers = [sup, ...ifaces].filter((n): n is Node => !!n).map((n) => n.text.replace(/<[^>]*>/g, '').replace(/\s+/g, ''));
    const methods: JvmMethod[] = [];
    for (const m of cls.node.childForFieldName('body')?.namedChildren ?? []) {
      const symbolId = m?.type === 'method_declaration' ? methodIds.get(m.id) : undefined;
      if (!m || !symbolId) continue;
      const mods = modifiersOf(m)?.text ?? '';
      methods.push({ node: m, name: m.childForFieldName('name')?.text ?? '', symbolId, anns: annsOf(m), exposed: /\bpublic\b/.test(mods) && !/\bstatic\b/.test(mods) });
    }
    out.push({ name: cls.name, dotted: cls.dotted, symbolId: cls.symbolId, node: cls.node, anns: annsOf(cls.node), supers, methods });
  }
  return out;
}

function importsOf(root: Node): string[] {
  return root.namedChildren.filter((n): n is Node => n?.type === 'import_declaration')
    .map((n) => n.text.replace(/^import\s+(static\s+)?/, '').replace(/\s*;\s*$/, '').replace(/\s+/g, ''));
}

/** `registry.addHandler(handler, "/a", "/b")` inside a `WebSocketHandlerRegistry` method. */
function wsRegistrations(
  root: Node, methodIds: Map<number, string>, enclosingSymbol: (n: Node) => string | null,
  enclosingMethod: (n: Node) => Node | null, typeOf: (receiver: Node | null, at: Node) => string | null,
): WsRegistration[] {
  const out: WsRegistration[] = [];
  for (const call of root.descendantsOfType('method_invocation')) {
    if (!call || call.childForFieldName('name')?.text !== 'addHandler') continue;
    const args = call.childForFieldName('arguments')?.namedChildren.filter((n): n is Node => !!n) ?? [];
    const fn = enclosingMethod(call);
    const registry = typeOf(call.childForFieldName('object'), call) === 'WebSocketHandlerRegistry'
      || /\bWebSocketHandlerRegistry\b/.test(fn?.childForFieldName('parameters')?.text ?? '');
    const paths = args.slice(1).filter((a) => a.type === 'string_literal').map((a) => unquote(a.text));
    if (!registry || args.length < 2 || !paths.length) continue;
    const h = args[0]!;
    let handlerType: string | null;
    if (h.type === 'object_creation_expression') handlerType = eraseType(h.childForFieldName('type')?.text ?? '') || null;
    else if (h.type === 'method_invocation' && !h.childForFieldName('object')) {
      // `chatHandler()` — a @Bean method of the same class: its declared return type.
      const name = h.childForFieldName('name')?.text;
      const decl = fn?.parent?.namedChildren.find((m) => m?.type === 'method_declaration' && m.childForFieldName('name')?.text === name);
      handlerType = decl ? eraseType(decl.childForFieldName('type')?.text ?? '') || null : null;
    } else handlerType = typeOf(h, call);
    out.push({ handlerType, paths, call, registrar: fn ? methodIds.get(fn.id) ?? null : enclosingSymbol(call) });
  }
  return out;
}

/** JAX-RS: HTTP-method annotation + class / method @Path; abstract base resources contribute their own paths. */
function jaxrsEntries(
  input: ExtractInput, ruleId: string, method: Node | undefined, ann: Node | undefined,
  methodIds: Map<number, string>, enclosingClass: (n: Node) => ClassInfo | null,
): RawEntry[] {
  if (!method || !ann) return [];
  const cls = enclosingClass(method);
  if (!cls || cls.node.type !== 'class_declaration') return [];
  const classPath = annotationsOf(modifiersOf(cls.node)).find((a) => annName(a) === 'Path');
  const methodPath = annotationsOf(modifiersOf(method)).find((a) => annName(a) === 'Path');
  const prefixes = classPath ? pathsOf(annotationArgs(classPath)) : [''];
  const paths = methodPath ? pathsOf(annotationArgs(methodPath)) : [''];
  const symbolId = methodIds.get(method.id);
  if (!symbolId) return [];
  const out: RawEntry[] = [];
  for (const prefix of prefixes) for (const p of paths) {
    out.push({
      ruleId, framework: 'jaxrs', httpMethod: annName(ann), pathTemplate: joinRoute(prefix, p),
      handler: { symbolId }, path: input.path, range: rangeOf(method), middlewares: [], authSignals: [],
    });
  }
  return out;
}

function springEntries(
  input: ExtractInput, ruleId: string, method: Node | undefined, ann: Node | undefined,
  methodIds: Map<number, string>, enclosingClass: (n: Node) => ClassInfo | null, inherited: InheritedMapping[],
): RawEntry[] {
  if (!method || !ann) return [];
  const cls = enclosingClass(method);
  if (!cls || (cls.node.type !== 'class_declaration' && cls.node.type !== 'interface_declaration')) return [];
  const name = annName(ann);
  const args = annotationArgs(ann);
  const paths = pathsOf(args);
  const methods = MAPPING_METHOD[name] ? [MAPPING_METHOD[name]!] : (args.get('method')?.map((m) => m.toUpperCase()) ?? ['ANY']);
  const symbolId = methodIds.get(method.id);
  if (!symbolId) return [];
  if (!isSpringController(cls.node)) {
    // Interface (OpenAPI generator, shared Feign API) or unannotated base class: an entry only of the
    // controllers that implement / extend it (assemble). A Feign client nobody implements stays a client.
    const arity = Number(/\((\d+)\)$/.exec(symbolId)?.[1] ?? 0);
    const mname = method.childForFieldName('name')?.text ?? '?';
    for (const p of paths) for (const hm of methods) {
      inherited.push({ owner: cls.name, ruleId, httpMethod: hm, path: p, method: mname, arity, symbolId, range: rangeOf(method), authSignals: [] });
    }
    return [];
  }
  const classMapping = annotationsOf(modifiersOf(cls.node)).find((a) => annName(a) === 'RequestMapping');
  const prefixes = classMapping ? pathsOf(annotationArgs(classMapping)) : [''];
  const out: RawEntry[] = [];
  for (const prefix of prefixes) for (const p of paths) for (const hm of methods) {
    out.push({
      ruleId, framework: 'spring', httpMethod: hm, pathTemplate: joinRoute(prefix, p),
      handler: { symbolId }, path: input.path, range: rangeOf(method), middlewares: [], authSignals: [],
    });
  }
  return out;
}

/** A class Spring serves as a controller: `@…Controller` or a class-level `@RequestMapping` (interfaces never). */
function isSpringController(decl: Node): boolean {
  if (decl.type !== 'class_declaration') return false;
  return annotationsOf(modifiersOf(decl)).map(annName).some((n) => /Controller$/.test(n) || n === 'RequestMapping');
}

const MAPPING_ANN_RE = /^(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)$/;
const superName = (t: string) => t.replace(/<[^>]*>/g, '').replace(/\s+/g, '').split('.').pop() ?? t;

/** Type facts of the file's classes / interfaces for inherited mappings (see jvm-inherit.ts). */
function jvmTypeFacts(classes: Map<number, ClassInfo>, methodIds: Map<number, string>, signals: AuthSignal[], owners: Set<string>): JvmTypeFacts[] {
  const out: JvmTypeFacts[] = [];
  const authOf = (target: string) => signals.filter((s) => s.kind === 'annotation' && s.target === target).map((s) => s.detail);
  for (const cls of classes.values()) {
    const t = cls.node.type;
    if (t !== 'class_declaration' && t !== 'interface_declaration') continue;
    const superNodes = [
      cls.node.childForFieldName('superclass')?.namedChildren[0],
      ...(cls.node.childForFieldName('interfaces')?.namedChildren.find((n) => n?.type === 'type_list')?.namedChildren ?? []),
      ...(cls.node.namedChildren.find((n) => n?.type === 'extends_interfaces')?.namedChildren.find((n) => n?.type === 'type_list')?.namedChildren ?? []),
    ].filter((n): n is Node => !!n);
    const supers = superNodes.map((n) => superName(n.text));
    const controller = isSpringController(cls.node);
    if (!supers.length && !owners.has(cls.name)) continue;
    const classMapping = annotationsOf(modifiersOf(cls.node)).find((a) => annName(a) === 'RequestMapping');
    const methods: JvmTypeFacts['methods'] = [];
    for (const m of cls.node.childForFieldName('body')?.namedChildren ?? []) {
      const symbolId = m?.type === 'method_declaration' ? methodIds.get(m.id) : undefined;
      if (!m || !symbolId) continue;
      methods.push({
        name: m.childForFieldName('name')?.text ?? '?', arity: Number(/\((\d+)\)$/.exec(symbolId)?.[1] ?? 0), symbolId, range: rangeOf(m),
        mapped: annotationsOf(modifiersOf(m)).some((a) => MAPPING_ANN_RE.test(annName(a))), authSignals: authOf(symbolId),
      });
    }
    out.push({
      name: cls.name, kind: t === 'interface_declaration' ? 'interface' : 'class', supers, controller,
      prefixes: classMapping ? pathsOf(annotationArgs(classMapping)) : null, classAuth: authOf(cls.symbolId), methods,
    });
  }
  return out;
}

function pathsOf(args: Map<string, string[]>): string[] {
  const p = args.get('path') ?? args.get('value');
  return p && p.length ? p : [''];
}

function authSignal(
  ruleId: string, post: string | undefined, cap: Map<string, Node>, methodIds: Map<number, string>,
  enclosingClass: (n: Node) => ClassInfo | null, enclosingSymbol: (n: Node) => string | null,
): AuthSignal | null {
  if (post === 'java_annotation_auth') {
    const ann = cap.get('annotation');
    if (!ann || !SECURITY_ANN_RE.test(annName(ann))) return null;
    const owner = ann.parent?.parent; // modifiers → declaration
    if (!owner) return null;
    const target = METHOD_TYPES.has(owner.type) ? methodIds.get(owner.id) : CLASS_TYPES.has(owner.type) ? enclosingClassSelf(owner, enclosingClass) : undefined;
    if (!target) return null;
    return { target, kind: 'annotation', detail: truncate(ann.text, 200), ruleId };
  }
  if (post === 'java_filter_class') {
    const cls = cap.get('class');
    const sup = cap.get('super')?.text ?? '';
    if (!cls) return null;
    const info = enclosingClassSelf(cls, enclosingClass);
    if (!info) return null;
    return { target: info, kind: /Interceptor/.test(sup) ? 'interceptor' : 'filter', detail: `${cls.childForFieldName('name')?.text} : ${sup}`, ruleId };
  }
  if (post === 'java_security_config') {
    const call = cap.get('call');
    if (!call) return null;
    // Report the outermost call of the fluent chain once (the caller dedupes on target+detail).
    let outer: Node = call;
    while (outer.parent?.type === 'method_invocation' && outer.parent.childForFieldName('object')?.id === outer.id) outer = outer.parent;
    const target = enclosingSymbol(outer);
    if (!target) return null;
    return { target, kind: 'security_config', detail: truncate(outer.text.replace(/\s+/g, ' '), 300), ruleId };
  }
  return null;
}

function enclosingClassSelf(classNode: Node, enclosingClass: (n: Node) => ClassInfo | null): string | undefined {
  // enclosingClass() looks at parents; find the info for the node itself via a child.
  const child = classNode.childForFieldName('body') ?? classNode.namedChildren.find((c) => !!c) ?? null;
  return child ? enclosingClass(child)?.symbolId : undefined;
}

function firstLine(text: string): string {
  const upto = text.indexOf('{');
  return truncate((upto > 0 ? text.slice(0, upto) : text).replace(/\s+/g, ' ').trim(), 300);
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '…' : s;
}

export type { IndexSymbol };

// ---- servlets, Struts 2 actions, Spring functional routes, Vert.x Web ----

const SERVLET_METHODS: Record<string, string> = { doGet: 'GET', doPost: 'POST', doPut: 'PUT', doDelete: 'DELETE', doHead: 'HEAD', doOptions: 'OPTIONS', doPatch: 'PATCH', service: 'ANY' };

function webOf(input: ExtractInput): JavaWebContext | null {
  return (input.langContext as JavaWebContext | undefined) ?? null;
}

const fqcnOf = (pkg: string, info: ClassInfo) => (pkg ? `${pkg}.${info.dotted}` : info.dotted);

/** Filters (`web.xml`, `@WebFilter`) and `<security-constraint>`s covering a route, as middlewares. */
function webMiddlewares(web: JavaWebContext | null, route: string): string[] {
  const out: string[] = [];
  for (const f of web?.filters ?? []) if (f.patterns.some((p) => urlPatternCovers(p, route))) out.push(`filter: ${f.name}`);
  for (const c of web?.constraints ?? []) {
    if (c.patterns.some((p) => urlPatternCovers(p, route))) out.push(`security-constraint: ${c.roles.length ? `roles(${c.roles.join(', ')})` : 'authenticated'}`);
  }
  return [...new Set(out)];
}

/**
 * Servlets: classes with `@WebServlet(urlPatterns | value)` or a `web.xml` `<servlet-mapping>`; one entry per
 * `doGet` / `doPost` / … (`service` = ANY) and url pattern, or one ANY entry on the class when the dispatch methods are
 * inherited (a `BaseServlet` that routes by a request parameter).
 */
function servletEntries(input: ExtractInput, ruleId: string, info: ClassInfo, pkg: string, methodIds: Map<number, string>): RawEntry[] {
  if (info.node.type !== 'class_declaration') return [];
  const web = webOf(input);
  const ann = annotationsOf(modifiersOf(info.node)).find((a) => annName(a) === 'WebServlet');
  const args = ann ? annotationArgs(ann) : null;
  const patterns = [...new Set([
    ...(args?.get('urlPatterns') ?? args?.get('value') ?? []),
    ...(web?.servlets?.[fqcnOf(pkg, info)] ?? web?.servlets?.[info.name] ?? []),
  ])];
  if (!patterns.length) return [];
  const handlers: { method: string; symbolId: string; node: Node }[] = [];
  for (const m of info.node.childForFieldName('body')?.namedChildren ?? []) {
    const name = m?.type === 'method_declaration' ? m.childForFieldName('name')?.text ?? '' : '';
    const id = m ? methodIds.get(m.id) : undefined;
    if (m && id && SERVLET_METHODS[name]) handlers.push({ method: SERVLET_METHODS[name]!, symbolId: id, node: m });
  }
  const out: RawEntry[] = [];
  for (const p of patterns) {
    const route = p.startsWith('/') ? p : `/${p}`;
    const mws = webMiddlewares(web, route);
    for (const h of handlers.length ? handlers : [{ method: 'ANY', symbolId: info.symbolId, node: info.node }]) {
      out.push({ ruleId, framework: 'servlet', httpMethod: h.method, pathTemplate: route, handler: { symbolId: h.symbolId }, path: input.path, range: rangeOf(h.node), middlewares: mws, authSignals: [] });
    }
  }
  return out;
}

/** Public, non-static methods without parameters (Struts action methods). */
function actionMethods(info: ClassInfo, methodIds: Map<number, string>): { name: string; symbolId: string; node: Node; anns: Node[] }[] {
  const out: { name: string; symbolId: string; node: Node; anns: Node[] }[] = [];
  for (const m of info.node.childForFieldName('body')?.namedChildren ?? []) {
    if (m?.type !== 'method_declaration') continue;
    const mods = modifiersOf(m);
    const id = methodIds.get(m.id);
    if (!id || !/\bpublic\b/.test(mods?.text ?? '') || /\bstatic\b/.test(mods?.text ?? '')) continue;
    if (m.childForFieldName('parameters')?.namedChildren.some((p) => p?.type === 'formal_parameter' || p?.type === 'spread_parameter')) continue;
    out.push({ name: m.childForFieldName('name')?.text ?? '', symbolId: id, node: m, anns: annotationsOf(mods) });
  }
  return out;
}

const interceptorRefs = (text: string) => [...text.matchAll(/@InterceptorRef\s*\(\s*(?:value\s*=\s*)?"([^"]+)"/g)].map((m) => `interceptor-ref: ${m[1]}`);

/**
 * Struts 2 actions: `struts*.xml` `<action name class method>` (namespace prefix, wildcard `name="user_*" method="{1}"`
 * expanded over the class's public methods, interceptor refs or the package default) and Convention-plugin
 * `@Action` / `@Actions` methods under the class `@Namespace`. URLs carry the action extension (`.action` by default).
 */
function strutsEntries(input: ExtractInput, ruleId: string, info: ClassInfo, pkg: string, methodIds: Map<number, string>, imports: Set<string>): RawEntry[] {
  if (info.node.type !== 'class_declaration') return [];
  const web = webOf(input);
  const ext = web?.strutsExt ?? '.action';
  const methods = actionMethods(info, methodIds);
  const out: RawEntry[] = [];
  const push = (route: string, symbolId: string, node: Node, mws: string[]) => {
    out.push({ ruleId, framework: 'struts2', httpMethod: 'ANY', pathTemplate: `${route.startsWith('/') ? route : `/${route}`}${ext}`, handler: { symbolId }, path: input.path, range: rangeOf(node), middlewares: [...new Set([...mws, ...webMiddlewares(web, route)])], authSignals: [] });
  };
  for (const a of web?.struts?.[fqcnOf(pkg, info)] ?? web?.struts?.[info.name] ?? []) {
    const wildcard = a.method && /\{\d\}/.test(a.method) && a.route.includes('*');
    if (wildcard) {
      const re = new RegExp(`^${a.method!.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\\\{\d\\\}|\{\d\}/, '(\\w+)')}$`);
      for (const m of methods) {
        const cap = re.exec(m.name)?.[1];
        if (cap) push(a.route.replace('*', cap), m.symbolId, m.node, a.interceptors);
      }
      continue;
    }
    const name = a.method ?? 'execute';
    const m = methods.find((x) => x.name === name);
    push(a.route, m?.symbolId ?? info.symbolId, m?.node ?? info.node, a.interceptors);
  }
  if ([...imports].some((i) => i.startsWith('org.apache.struts2.convention.annotation'))) {
    const classAnns = annotationsOf(modifiersOf(info.node));
    const ns = classAnns.filter((x) => annName(x) === 'Namespace').map((x) => annotationArgs(x).get('value')?.[0] ?? '')[0] ?? '';
    const classRefs = classAnns.filter((x) => /^InterceptorRefs?$/.test(annName(x))).flatMap((x) => interceptorRefs(x.text));
    for (const m of methods) {
      for (const ann of m.anns.filter((x) => annName(x) === 'Action' || annName(x) === 'Actions')) {
        const refs = [...classRefs, ...interceptorRefs(ann.text)];
        const names = annName(ann) === 'Action' ? [annotationArgs(ann).get('value')?.[0] ?? ''] : [...ann.text.matchAll(/@Action\s*\(\s*(?:value\s*=\s*)?"([^"]*)"/g)].map((x) => x[1]!);
        for (const n of names) if (n) push(n.startsWith('/') ? n : joinRoute(ns, n), m.symbolId, m.node, refs);
      }
    }
  }
  return out;
}

/** Handler of a Spring functional / Vert.x route: `h::m` → that class's method, `this::m`, else the enclosing method. */
function routeHandler(
  n: Node | undefined, at: Node, enclosingSymbol: (n: Node) => string | null, enclosingClass: (n: Node) => ClassInfo | null,
  typeOf: (receiver: Node | null, at: Node) => string | null, methodIds: Map<number, string>,
): HandlerRef {
  if (n?.type === 'method_reference') {
    const parts = n.namedChildren.filter((c): c is Node => !!c);
    const obj = parts[0];
    const name = parts[parts.length - 1]?.text ?? '';
    if (obj?.type === 'this') {
      const cls = enclosingClass(at);
      const m = cls?.node.childForFieldName('body')?.namedChildren.find((x) => x?.type === 'method_declaration' && x.childForFieldName('name')?.text === name);
      const id = m ? methodIds.get(m.id) : undefined;
      if (id) return { symbolId: id };
      return { text: `${cls?.name ?? '?'}.${name}`, ...(cls ? { className: cls.name } : {}) };
    }
    const type = obj ? typeOf(obj, at) ?? (/^[A-Z]/.test(obj.text) ? obj.text.split('.').pop()! : null) : null;
    return type ? { text: `${type}.${name}`, className: type } : { text: n.text };
  }
  const own = enclosingSymbol(at);
  return own ? { symbolId: own, ...(n ? { range: rangeOf(n) } : {}) } : { text: n?.text.slice(0, 120) ?? '?' };
}

const FN_VERBS = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$/;

/**
 * Spring functional routes (WebFlux `RouterFunctions`, WebMvc.fn): builder `route().GET("/p", h::m)` and predicate
 * `route(GET("/p"), h::m)` / `.andRoute(…)`; prefixes from enclosing `nest(path("/a"), …)` and builder
 * `.path("/a", b -> …)` / `.nest(path("/a"), …)`. Router `filter(…)`s are not applied.
 */
function webfluxEntries(
  input: ExtractInput, ruleId: string, call: Node, framework: string, enclosingSymbol: (n: Node) => string | null,
  enclosingClass: (n: Node) => ClassInfo | null, typeOf: (receiver: Node | null, at: Node) => string | null, methodIds: Map<number, string>,
): RawEntry[] {
  const verb = call.childForFieldName('name')?.text ?? '';
  const args = call.childForFieldName('arguments')?.namedChildren.filter((c): c is Node => !!c) ?? [];
  if (!FN_VERBS.test(verb) || args[0]?.type !== 'string_literal') return [];
  const path = unquote(args[0].text);
  let handlerNode: Node | undefined;
  if (args.length >= 2) handlerNode = args[args.length - 1];
  else {
    // Predicate form: the GET(…) call sits in the first argument of route(…) / andRoute(…).
    for (let p: Node | null = call.parent; p; p = p.parent) {
      if (p.type === 'method_invocation' && /^(route|andRoute)$/.test(p.childForFieldName('name')?.text ?? '')) {
        const pa = p.childForFieldName('arguments')?.namedChildren.filter((c): c is Node => !!c) ?? [];
        if (pa[0] && pa[0].startIndex <= call.startIndex && call.endIndex <= pa[0].endIndex) handlerNode = pa[1];
        break;
      }
    }
    if (!handlerNode) return [];
  }
  const prefixes: string[] = [];
  for (let p: Node | null = call.parent; p; p = p.parent) {
    if (p.type !== 'method_invocation') continue;
    const name = p.childForFieldName('name')?.text ?? '';
    const pa = p.childForFieldName('arguments')?.namedChildren.filter((c): c is Node => !!c) ?? [];
    const inside = (n: Node | undefined) => !!n && n.startIndex <= call.startIndex && call.endIndex <= n.endIndex;
    if (name === 'nest' && pa.length >= 2 && !inside(pa[0])) {
      const m = /\bpath\s*\(\s*"([^"]*)"/.exec(pa[0]!.text);
      if (m) prefixes.unshift(m[1]!);
    } else if (name === 'path' && pa.length >= 2 && pa[0]!.type === 'string_literal' && !inside(pa[0])) prefixes.unshift(unquote(pa[0]!.text));
  }
  const route = [...prefixes, path].reduce((a, b) => joinRoute(a, b), '');
  return [{ ruleId, framework, httpMethod: verb, pathTemplate: route, handler: routeHandler(handlerNode, call, enclosingSymbol, enclosingClass, typeOf, methodIds), path: input.path, range: rangeOf(call), middlewares: [], authSignals: [] }];
}

const VERTX_VERBS: Record<string, string> = { get: 'GET', post: 'POST', put: 'PUT', delete: 'DELETE', patch: 'PATCH', head: 'HEAD', options: 'OPTIONS', trace: 'TRACE', connect: 'CONNECT', route: 'ANY', getWithRegex: 'GET', postWithRegex: 'POST', putWithRegex: 'PUT', deleteWithRegex: 'DELETE', routeWithRegex: 'ANY' };
const VERTX_CHAIN = /^(handler|blockingHandler|respond|failureHandler|consumes|produces|order|virtualHost|useNormalizedPath)$/;

interface VertxRoute { recv: string; verb: string; path: string | null; handlers: Node[]; base: Node }

/** Walk `router.get("/p").handler(a).handler(b)` down to the route call; null when the chain does not start at a router verb. */
function vertxRouteOf(call: Node): VertxRoute | null {
  const handlers: Node[] = [];
  let cur: Node | null = call;
  while (cur?.type === 'method_invocation') {
    const name = cur.childForFieldName('name')?.text ?? '';
    const args = cur.childForFieldName('arguments')?.namedChildren.filter((c): c is Node => !!c) ?? [];
    if (VERTX_VERBS[name] && cur !== call) {
      const recv = cur.childForFieldName('object');
      if (!recv) return null;
      const str = args.find((a) => a.type === 'string_literal');
      const method = name === 'route' && args[0] && args[0].type !== 'string_literal' ? /HttpMethod\.(\w+)/.exec(args[0].text)?.[1] : undefined;
      return { recv: recv.text, verb: method ?? VERTX_VERBS[name]!, path: str ? unquote(str.text) : null, handlers, base: cur };
    }
    if (!VERTX_CHAIN.test(name)) return null;
    if (/^(handler|blockingHandler|respond)$/.test(name) && args[0]) handlers.unshift(args[0]);
    cur = cur.childForFieldName('object');
  }
  return null;
}

/**
 * Vert.x Web: `router.get("/p").handler(BodyHandler.create()).handler(this::get)` — the last handler is the entry,
 * earlier ones middlewares; `router.route([“/a/*”]).handler(authHandler)` (no verb, no concrete path) is middleware for
 * the same router's later routes under that prefix; `router.route("/api/*").subRouter(sub)` / `mountSubRouter` prefixes
 * a sub-router declared in the same file.
 */
function vertxEntry(
  input: ExtractInput, ruleId: string, call: Node, root: Node, enclosingSymbol: (n: Node) => string | null,
  enclosingClass: (n: Node) => ClassInfo | null, typeOf: (receiver: Node | null, at: Node) => string | null, methodIds: Map<number, string>,
): RawEntry | null {
  // Only the outermost handler call of a chain.
  if (call.parent?.type === 'method_invocation' && call.parent.childForFieldName('object')?.id === call.id && VERTX_CHAIN.test(call.parent.childForFieldName('name')?.text ?? '')) return null;
  const r = vertxRouteOf(call);
  if (!r || !r.handlers.length) return null;
  const isUse = (x: VertxRoute) => x.verb === 'ANY' && (x.path === null || x.path.endsWith('*'));
  if (isUse(r)) return null;
  const prefix = (p: string | null) => (p ?? '').replace(/\/?\*$/, '');
  // Middlewares registered earlier on the same router (file order), and sub-router mounts in this file.
  const uses: string[] = [];
  let mount = '';
  for (const c of root.descendantsOfType('method_invocation')) {
    if (!c) continue;
    const name = c.childForFieldName('name')?.text ?? '';
    const args = c.childForFieldName('arguments')?.namedChildren.filter((x): x is Node => !!x) ?? [];
    if (name === 'mountSubRouter' && args[1]?.text === r.recv && args[0]?.type === 'string_literal') mount = prefix(unquote(args[0].text));
    else if (name === 'subRouter' && args[0]?.text === r.recv) {
      const s = c.childForFieldName('object')?.childForFieldName('arguments')?.namedChildren.find((x) => x?.type === 'string_literal');
      if (s) mount = prefix(unquote(s.text));
    } else if (/^(handler|blockingHandler)$/.test(name) && c.startIndex < r.base.startIndex) {
      if (c.parent?.type === 'method_invocation' && c.parent.childForFieldName('object')?.id === c.id) continue;
      const u = vertxRouteOf(c);
      if (u && u.recv === r.recv && isUse(u) && (r.path ?? '').startsWith(prefix(u.path))) uses.push(...u.handlers.map((h) => h.text.replace(/\s+/g, ' ').slice(0, 120)));
    }
  }
  const handler = r.handlers[r.handlers.length - 1]!;
  const mws = [...uses, ...r.handlers.slice(0, -1).map((h) => h.text.replace(/\s+/g, ' ').slice(0, 120))];
  return {
    ruleId, framework: 'vertx', httpMethod: r.verb, pathTemplate: joinRoute(mount, r.path ?? ''), handler: routeHandler(handler, call, enclosingSymbol, enclosingClass, typeOf, methodIds),
    path: input.path, range: rangeOf(r.base), middlewares: mws, authSignals: [],
  };
}
