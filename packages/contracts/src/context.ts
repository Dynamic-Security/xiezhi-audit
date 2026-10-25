// Snapshot manifest, structural index and exec-result shapes.
import { Type, type Static } from 'typebox';
import { closedSet } from './enums.js';

const Sha = Type.String({ pattern: '^[0-9a-f]{64}$' });
const RelPath = Type.String({ minLength: 1 });
export const LineRange = Type.Object({
  startLine: Type.Integer({ minimum: 1 }),
  endLine: Type.Integer({ minimum: 1 }),
}, { additionalProperties: false });
export type LineRange = Static<typeof LineRange>;

export const EXCLUDE_REASONS = ['vcs', 'agent_control', 'sensitive', 'binary', 'oversize', 'symlink_escape', 'skipped_symlink', 'build_output', 'scope'] as const;
export type ExcludeReason = (typeof EXCLUDE_REASONS)[number];

export const SnapshotManifest = Type.Object({
  rootHash: Sha,
  source: Type.Object({
    kind: closedSet(['local', 'git', 'archive'] as const),
    locator: Type.String(),
    ref: Type.Optional(Type.String()),
    commit: Type.Optional(Type.String()),
    worktree: Type.Optional(Type.Boolean()),
    /** A working-tree snapshot of a git directory: whether it differed from HEAD (absent when unknown). */
    dirty: Type.Optional(Type.Boolean()),
  }, { additionalProperties: false }),
  files: Type.Array(Type.Object({
    path: RelPath, sha256: Sha, size: Type.Integer({ minimum: 0 }),
    lines: Type.Integer({ minimum: 0 }),
    lang: Type.Optional(Type.String()),
    indexable: Type.Boolean(),
  }, { additionalProperties: false })),
  excluded: Type.Array(Type.Object({ path: RelPath, reason: closedSet(EXCLUDE_REASONS) }, { additionalProperties: false })),
  missing: Type.Array(Type.Object({
    path: RelPath, kind: closedSet(['submodule', 'lfs'] as const),
    url: Type.Optional(Type.String()), commit: Type.Optional(Type.String()),
  }, { additionalProperties: false })),
  stats: Type.Object({
    fileCount: Type.Integer(), totalBytes: Type.Integer(),
    byLang: Type.Record(Type.String(), Type.Integer()),
  }, { additionalProperties: false }),
  createdAt: Type.Integer(),
}, { additionalProperties: false });
export type SnapshotManifest = Static<typeof SnapshotManifest>;
export type ManifestFile = SnapshotManifest['files'][number];

const Site = Type.Object({ path: RelPath, line: Type.Integer({ minimum: 1 }) }, { additionalProperties: false });

export const IndexSymbol = Type.Object({
  symbolId: Type.String(),
  repo: Type.String(),
  kind: closedSet(['class', 'method', 'func', 'field', 'interface'] as const),
  name: Type.String(),
  container: Type.String(),
  path: RelPath,
  range: LineRange,
  signature: Type.String(),
  /** Qualified name used for vulnerability fingerprints, e.g. `com.x.OrderRepo#findById(Long)`. */
  qualifiedName: Type.String(),
}, { additionalProperties: false });
export type IndexSymbol = Static<typeof IndexSymbol>;

export const CallEdge = Type.Object({
  from: Type.String(),
  to: Type.Union([Type.String(), Type.Null()]),
  calleeText: Type.String(),
  site: Site,
  confidence: closedSet(['resolved', 'heuristic', 'unresolved'] as const),
}, { additionalProperties: false });
export type CallEdge = Static<typeof CallEdge>;

export const AuthSignal = Type.Object({
  target: Type.String(),
  kind: closedSet(['annotation', 'filter', 'interceptor', 'middleware', 'security_config'] as const),
  detail: Type.String(),
  ruleId: Type.String(),
}, { additionalProperties: false });
export type AuthSignal = Static<typeof AuthSignal>;

export const ENTRY_KINDS = ['http', 'rpc', 'internal', 'socket', 'message', 'schedule', 'cli'] as const;
export type EntryKind = (typeof ENTRY_KINDS)[number];

export const EntryPoint = Type.Object({
  entryId: Type.String(),
  /** Normalized key used for identity: `METHOD /path/{}` or `rpc:pkg.Svc/Method`. */
  entryKey: Type.String(),
  /**
   * `socket` (WebSocket, Socket.IO, STOMP), `message` (queue / topic consumers), `schedule` (timed
   * jobs), `cli` (commands) join http / rpc. Not stored in a database CHECK: the index is a JSON artifact.
   */
  kind: closedSet(ENTRY_KINDS),
  /** Precise protocol: http, grpc, graphql, signalr, websocket, socketio, stomp, kafka, rabbitmq, jms, redis, celery, cron, cli, thrift, dubbo… */
  protocol: Type.Optional(Type.String()),
  framework: Type.String(),
  httpMethod: Type.Optional(Type.String()),
  pathTemplate: Type.Optional(Type.String()),
  handler: Type.String(),
  path: RelPath,
  range: LineRange,
  middlewares: Type.Array(Type.String()),
  authSignals: Type.Array(Type.String()),
  ruleId: Type.String(),
}, { additionalProperties: false });
export type EntryPoint = Static<typeof EntryPoint>;

export const Sink = Type.Object({
  sinkId: Type.String(),
  category: Type.String(),
  /** Enclosing function symbol id (may be null for top-level code). */
  symbolId: Type.Union([Type.String(), Type.Null()]),
  path: RelPath,
  range: LineRange,
  api: Type.String(),
  taintHint: Type.Optional(Type.String()),
  ruleId: Type.String(),
}, { additionalProperties: false });
export type Sink = Static<typeof Sink>;

export const IndexGap = Type.Object({
  path: Type.String(),
  reason: closedSet(['parse_error', 'unsupported_lang', 'timeout', 'rule_error', 'oversize'] as const),
  detail: Type.String(),
}, { additionalProperties: false });
export type IndexGap = Static<typeof IndexGap>;

export const StructIndex = Type.Object({
  repo: Type.String(),
  rootHash: Sha,
  rulesVersion: Type.String(),
  symbols: Type.Array(IndexSymbol),
  callEdges: Type.Array(CallEdge),
  entrypoints: Type.Array(EntryPoint),
  authSignals: Type.Array(AuthSignal),
  sinks: Type.Array(Sink),
  gaps: Type.Array(IndexGap),
}, { additionalProperties: false });
export type StructIndex = Static<typeof StructIndex>;

// Outcome of a sandboxed command run.
export const EXEC_STATUSES = ['ok', 'exit_nonzero', 'timeout', 'output_limit', 'cancelled', 'spawn_error', 'resource_limit'] as const;
export type ExecStatus = (typeof EXEC_STATUSES)[number];
export const EXEC_EXIT_CODES: Partial<Record<ExecStatus, number>> = {
  timeout: 124, output_limit: 125, spawn_error: 127, cancelled: 130, resource_limit: 137,
};
export interface ExecStream { bytes: number; sha256: string; inlinePreview: string; artifactRef?: string }
export interface ExecResult {
  status: ExecStatus;
  exitCode: number;
  signal?: string;
  stdout: ExecStream;
  stderr: ExecStream;
  durationMs: number;
}

// incremental impact analysis.
export const IMPACT_MODES = ['precise', 'heuristic', 'full_scan'] as const;
export type ImpactMode = (typeof IMPACT_MODES)[number];
/** `no_baseline`: a target of a multi-repository incremental audit without a baseline is audited in full. */
export const IMPACT_FALLBACK_REASONS = ['no_baseline_index', 'parse_gap_in_changed_files', 'too_many_changes', 'unresolved_edges_dominant', 'ast_disabled', 'no_baseline'] as const;
export type ImpactFallbackReason = (typeof IMPACT_FALLBACK_REASONS)[number];

export const ChangedFiles = Type.Object({
  added: Type.Array(RelPath),
  modified: Type.Array(RelPath),
  deleted: Type.Array(RelPath),
  /** Same content (sha256) under a new path. */
  renamed: Type.Array(Type.Object({ from: RelPath, to: RelPath }, { additionalProperties: false })),
}, { additionalProperties: false });
export type ChangedFiles = Static<typeof ChangedFiles>;

export const DiffHunk = Type.Object({
  path: RelPath,
  /** 1-based line range in the base version (count 0 = pure insertion after `baseStart - 1`). */
  baseStart: Type.Integer({ minimum: 0 }), baseCount: Type.Integer({ minimum: 0 }),
  headStart: Type.Integer({ minimum: 0 }), headCount: Type.Integer({ minimum: 0 }),
}, { additionalProperties: false });
export type DiffHunk = Static<typeof DiffHunk>;

export const SymbolChange = Type.Object({
  /** Head-side symbol (base-side for deletions). */
  symbolId: Type.String(),
  qualifiedName: Type.String(),
  change: closedSet(['added', 'modified', 'deleted', 'renamed'] as const),
  /** For renames/moves: the base-side qualified name. */
  fromQualifiedName: Type.Optional(Type.String()),
  path: RelPath,
}, { additionalProperties: false });
export type SymbolChange = Static<typeof SymbolChange>;

export const ImpactSet = Type.Object({
  mode: closedSet(IMPACT_MODES),
  fallbackReasons: Type.Array(closedSet(IMPACT_FALLBACK_REASONS)),
  changedFiles: ChangedFiles,
  hunks: Type.Array(DiffHunk),
  changedSymbols: Type.Array(SymbolChange),
  /** base qualified name → head qualified name for renamed/moved functions (rename follow). */
  renames: Type.Array(Type.Object({ from: Type.String(), to: Type.String() }, { additionalProperties: false })),
  affectedSymbols: Type.Array(Type.Object({
    symbolId: Type.String(), distance: Type.Integer({ minimum: 0 }), viaEdgeConfidence: closedSet(['resolved', 'heuristic', 'unresolved'] as const),
  }, { additionalProperties: false })),
  affectedEntrypoints: Type.Array(Type.String()),
  affectedSinks: Type.Array(Type.String()),
  stats: Type.Object({ indexableFiles: Type.Integer(), changedIndexableFiles: Type.Integer(), unresolvedCallers: Type.Integer(), resolvedCallers: Type.Integer() }, { additionalProperties: false }),
}, { additionalProperties: false });
export type ImpactSet = Static<typeof ImpactSet>;



// ---- repository profile signals and roles ---------------------------------------------
/** Gateway configuration kinds recognized deterministically. */
export const GATEWAY_KINDS = ['spring_cloud_gateway', 'zuul', 'nginx', 'kong', 'apisix'] as const;

/**
 * Deterministic signal summary of one repository snapshot. Only paths, counts, dependency coordinates
 * and rule hits — never comments or documents of the audited repository (P8).
 */
export const RepoSignals = Type.Object({
  fileCount: Type.Integer({ minimum: 0 }),
  /** Names this service is known by: spring.application.name, dubbo application, package / module name. */
  appNames: Type.Array(Type.String()),
  languages: Type.Record(Type.String(), Type.Integer({ minimum: 0 })),
  modules: Type.Array(Type.Object({ path: Type.String(), lang: Type.String(), buildFile: Type.String() }, { additionalProperties: false })),
  /** Coordinates this repository publishes: `group:artifact`, Go module path, npm package name. */
  provides: Type.Array(Type.String()),
  dependencies: Type.Array(Type.String()),
  securityDependencies: Type.Array(Type.String()),
  frontendFrameworks: Type.Array(Type.String()),
  entrypoints: Type.Object({ http: Type.Integer(), rpc: Type.Integer(), authRoutes: Type.Integer(), authRouteSamples: Type.Array(Type.String()) }, { additionalProperties: false }),
  sinks: Type.Record(Type.String(), Type.Integer()),
  authSignals: Type.Record(Type.String(), Type.Integer()),
  persistence: Type.Object({ mapperFiles: Type.Integer(), daoOrRepositoryFiles: Type.Integer(), sqlFiles: Type.Integer() }, { additionalProperties: false }),
  gatewayConfigs: Type.Array(Type.Object({ path: Type.String(), kind: closedSet(GATEWAY_KINDS), routes: Type.Integer() }, { additionalProperties: false })),
  contracts: Type.Object({ proto: Type.Integer(), openapi: Type.Integer() }, { additionalProperties: false }),
  clientCalls: Type.Object({ fetch: Type.Integer(), axios: Type.Integer() }, { additionalProperties: false }),
  /** Other repositories of the project that declare a dependency on what this one provides. */
  referencedBy: Type.Array(Type.String()),
  indexStatus: closedSet(['complete', 'partial', 'failed', 'skipped'] as const),
}, { additionalProperties: false });
export type RepoSignals = Static<typeof RepoSignals>;

// ---- connection points and matching -------------------------------------------------------------------
export const CONNECTION_KINDS = ['http', 'grpc', 'dubbo', 'mq', 'gateway_route', 'shared_lib'] as const;
export type ConnectionKind = (typeof CONNECTION_KINDS)[number];

export const Connection = Type.Object({
  /** Stable within a repository snapshot: sha of (repo, side, kind, key, site). */
  connId: Type.String(),
  repo: Type.String(),
  side: closedSet(['provides', 'consumes'] as const),
  kind: closedSet(CONNECTION_KINDS),
  key: Type.Object({
    method: Type.Optional(Type.String()), pathTemplate: Type.Optional(Type.String()), service: Type.Optional(Type.String()),
    rpc: Type.Optional(Type.String()), interface: Type.Optional(Type.String()), topic: Type.Optional(Type.String()), module: Type.Optional(Type.String()),
    /** gateway_route: leading path segments removed before forwarding (StripPrefix, Kong strip_path, nginx proxy_pass with a path). */
    stripPrefix: Type.Optional(Type.Integer({ minimum: 0 })),
  }, { additionalProperties: false }),
  /** Feign name, gateway upstream, URL host, gRPC stub service… (not a repository name yet). */
  serviceHint: Type.Optional(Type.String()),
  site: Type.Object({ path: Type.String(), line: Type.Integer({ minimum: 0 }), symbolId: Type.Optional(Type.String()) }, { additionalProperties: false }),
  ruleId: Type.String(),
  extraction: closedSet(['literal', 'constant_folded', 'partial'] as const),
}, { additionalProperties: false });
export type Connection = Static<typeof Connection>;

/** Where a service name was mapped to a repository from (priority order). */
export const SERVICE_MAP_SOURCES = ['user', 'imported', 'app_name', 'repo_name'] as const;

export const ConnectionMatch = Type.Object({
  consumer: Type.String(),
  /** Provider connection; null when nothing in the project provides it (→ external service). */
  provider: Type.Union([Type.String(), Type.Null()]),
  /** Repository of the provider; set for repository-level matches without a concrete provider connection (gateway → service). */
  providerRepo: Type.Union([Type.String(), Type.Null()]),
  confidence: closedSet(['confirmed', 'inferred'] as const),
  reason: Type.String(),
}, { additionalProperties: false });
export type ConnectionMatch = Static<typeof ConnectionMatch>;

export const ServiceMapping = Type.Object({
  service: Type.String(), repo: Type.String(), source: closedSet(SERVICE_MAP_SOURCES),
}, { additionalProperties: false });
export type ServiceMapping = Static<typeof ServiceMapping>;
