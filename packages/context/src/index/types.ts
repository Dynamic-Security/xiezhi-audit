// Per-file extraction output, assembled into a StructIndex by assemble.ts.
import type { AuthSignal, IndexGap, IndexSymbol, LineRange, Sink } from '@xiezhi/contracts';
import type { GraphqlSchema } from './graphql.js';
import type { GrpcService } from './proto.js';

export interface RawCall {
  from: string;
  method: string;
  receiverText: string | null;
  /** Java: statically known receiver type (simple name) when determinable. */
  receiverType: string | null;
  /** Go: import path when the receiver is an import alias. */
  receiverImport: string | null;
  arity: number;
  line: number;
  calleeText: string;
}

export interface HandlerRef {
  /** Resolved within the file (Java method, Go func literal). */
  symbolId?: string;
  /** Go: textual reference to resolve across files (`h`, `pkg.H`, `ctrl.H`). */
  text?: string;
  /** Go: package import path for `pkg.H` references. */
  importPath?: string;
  /**
   * PHP: the handler's class when `text` is `Class.method` declared in another file (Laravel / ThinkPHP route
   * files); `assemble` resolves the method within that class and attaches the class's / method's auth signals.
   */
  className?: string;
  /**
   * Go: the receiver type the file shows for `x.Method` (`x := &UserHandler{}`, a parameter, the
   * method receiver, a struct field, `NewUserHandler()`); `assemble` prefers that type's method and otherwise falls
   * back to the name match.
   */
  typeHint?: string;
  /**
   * JS (Egg `controller.user.show`): `text` is a method of whichever class module `importPath` declares (the
   * class name is not visible at the route); `assemble` picks the single method of that name in that module.
   */
  moduleMember?: boolean;
  /**
   * PHP (WordPress hook callbacks `'my_plugin_save'`): `text` is a global function declared in any file
   * (PHP keys global functions by file); `assemble` picks the single function of that name.
   */
  anyFunction?: boolean;
  /** Slim actions: when `className` has no method `text` (inherited from a base class), the class itself. */
  classFallback?: boolean;
  /** PHP: the class's fully qualified name (`App\\Controller\\Admin\\DeleteAction`) when the route file knows it. */
  classFqn?: string;
  /**
   * Ruby, Rails routes: qualified names to try in order — the action on the controller and on its ancestors
   * (`Admin::UsersController#show`, `Admin::BaseController#show`), then the controller class itself (implicit action
   * rendering a template). `assemble` takes the first that names exactly one symbol.
   */
  qualified?: string[];
  /**
   * Rust: attach the auth signals the handler's own file recorded on the resolved handler symbol (extractor /
   * request-guard parameters such as `claims: Claims`, `headers: AdminHeaders`), since routers usually live elsewhere.
   */
  targetSignals?: boolean;
  /** Go beego: directory of the handler's package (from the import path and go.mod; without go.mod a directory suffix), to pick among same-named types. */
  dirHint?: string;
  range?: LineRange;
}

export interface RawEntry {
  /**
   * gRPC service implementation: entry kind `rpc`, key `rpc:<service>/<method>`; httpMethod unused, pathTemplate
   * empty. GraphQL resolvers use service `graphql:<Type>` and the field signature as pathTemplate.
   */
  rpc?: { service: string; method: string };
  /**
   * entries that are neither HTTP routes nor gRPC-style services — sockets, queue consumers, timed jobs,
   * commands, and RPC frameworks with their own naming (Thrift, Dubbo). `key` is the identity (`ws:/chat`,
   * `socketio:message`, `stomp:/app/chat`, `mq:kafka:orders`, `cron:ReportJob.run`, `cli:import-users`,
   * `rpc:thrift:UserService/get`); `route` is what the table shows (path, event, topic, schedule or command).
   */
  channel?: { kind: 'socket' | 'message' | 'schedule' | 'cli' | 'rpc'; protocol: string; key: string; route: string };
  ruleId: string;
  framework: string;
  httpMethod: string;
  pathTemplate: string;
  handler: HandlerRef;
  path: string;
  range: LineRange;
  middlewares: string[];
  authSignals: string[];
}

/**
 * A Spring mapping declared on an interface or on a class that is not itself a controller (OpenAPI
 * generator `interface PetApi { @GetMapping … }`, an unannotated base class). Not an entry by itself; `assemble`
 * turns it into entries of the controllers that implement / extend the owner (any file, Java or Kotlin).
 */
export interface InheritedMapping {
  /** Simple name of the declaring type. */
  owner: string;
  ruleId: string;
  httpMethod: string;
  /** Method-level path (class-level prefixes come from the controller or its ancestors). */
  path: string;
  method: string;
  arity: number;
  symbolId: string;
  range: LineRange;
  authSignals: string[];
}

/** Java / Kotlin type facts for resolving inherited mappings across files. */
export interface JvmTypeFacts {
  name: string;
  kind: 'class' | 'interface';
  /** Simple names of the direct supertypes. */
  supers: string[];
  /** Counts as a Spring controller (`@…Controller` or a class-level `@RequestMapping`, not an interface). */
  controller: boolean;
  /** Own class-level `@RequestMapping` paths; null without one. */
  prefixes: string[] | null;
  classAuth: string[];
  methods: { name: string; arity: number; symbolId: string; range: LineRange; mapped: boolean; authSignals: string[] }[];
}

export interface FileExtract {
  path: string;
  /** Java / Kotlin: mappings inherited by implementing controllers, and the type facts to find them. */
  inheritedMappings?: InheritedMapping[];
  jvmTypes?: JvmTypeFacts[];
  lang: string;
  symbols: IndexSymbol[];
  calls: RawCall[];
  entries: RawEntry[];
  sinks: Sink[];
  authSignals: AuthSignal[];
  gaps: IndexGap[];
  /** Go: package directory import path; Java: package name. */
  pkg: string;
  /** Go: package clause name. */
  pkgName?: string;
}

export interface ExtractInput {
  repo: string;
  path: string;
  lang: string;
  text: string;
  /** Go module path from go.mod (for import-path computation). */
  goModule?: string;
  /** Directory of go.mod relative to repo root ('' for root). */
  goModuleDir?: string;
  /** gRPC services of the snapshot's .proto files (only when there are any). */
  grpcServices?: GrpcService[];
  /** The snapshot's GraphQL schema (only when there is one). */
  graphql?: GraphqlSchema;
  /** Language-specific per-file facts from the plugin's `inputContext` (plain data; crosses worker threads). */
  langContext?: Record<string, unknown>;
  /** JS / TS: prefixes (and middlewares) under which other files mount this module's router. */
  jsMounts?: { prefix: string; middlewares: string[] }[];
}

export function emptyExtract(input: ExtractInput): FileExtract {
  return { path: input.path, lang: input.lang, symbols: [], calls: [], entries: [], sinks: [], authSignals: [], gaps: [], pkg: '' };
}

/**
 * Normalize an HTTP path template for identity: `{id}`, `:id`, `<id>`, `*x` → `{}`. A query part
 * (Razor Pages named handlers `?handler=name`) is kept verbatim after the normalized path.
 */
export function normalizeRoute(path: string): string {
  const q = path.indexOf('?');
  if (q > 0 && /^\?[\w-]+=[\w-]*$/.test(path.slice(q))) return normalizeRoute(path.slice(0, q)) + path.slice(q);
  let p = path.trim();
  if (!p.startsWith('/')) p = '/' + p;
  p = p.replace(/\/{2,}/g, '/');
  if (p.length > 1) p = p.replace(/\/+$/, '');
  return p
    .split('/')
    .map((seg) => (/^\{[^}]*\}$/.test(seg) || /^:.+/.test(seg) || /^<[^>]*>$/.test(seg) || /^\*.*/.test(seg) ? '{}' : seg))
    .join('/');
}

export function joinRoute(prefix: string, path: string): string {
  const joined = `/${prefix}/${path}`.replace(/\/{2,}/g, '/');
  return joined.length > 1 ? joined.replace(/\/+$/, '') : joined;
}

export function entryKey(method: string, pathTemplate: string): string {
  return `${method.toUpperCase()} ${normalizeRoute(pathTemplate)}`;
}

/** Strip generics/annotations/final and normalize varargs for erased parameter types. */
export function eraseType(t: string): string {
  let s = t.replace(/@\w+(\([^)]*\))?\s*/g, '').replace(/\bfinal\s+/g, '').trim();
  let depth = 0;
  let out = '';
  for (const ch of s) {
    if (ch === '<') depth++;
    else if (ch === '>') depth--;
    else if (depth === 0) out += ch;
  }
  s = out.replace(/\s+/g, '');
  if (s.endsWith('...')) s = s.slice(0, -3) + '[]';
  const simple = s.split('.').pop() ?? s;
  return simple;
}
