export { Executor, ExecPolicyError, validateArgs, ALLOWED_COMMANDS, GIT_SUBCOMMANDS, DEFAULT_RESOURCE_LIMITS, type ExecRequest, type ExecOutput, type AllowedCommand, type ResourceLimits } from './exec/executor.js';
export { parsePs, processTree, listProcesses, type ProcInfo } from './exec/proctree.js';
export { spawnService, runScript, runCommand, validateService, SERVICE_MAX_LINE, type ServiceRequest, type ServiceProcess, type ScriptRequest, type CommandRequest } from './exec/service.js';
export { runGit, runGitRemote, hardenedGitArgs, GIT_ENV, type GitCredential } from './exec/git.js';
export { openBrowser, browserCommand, isLoopbackUrl } from './exec/browser.js';
export { pickFolder, folderPickerCommand, type FolderPick, type FolderPickerCommand } from './exec/folder-picker.js';
export { PathGuardError, normalizeRelPath, guardFile } from './pathguard.js';
export { createSnapshot, computeRootHash, SnapshotError, type SnapshotRequest, type SnapshotResult, type SnapshotSource } from './snapshot/snapshot.js';
export { makeExcluder, detectLang, isSensitiveName } from './snapshot/exclude.js';
export { worktreeDirty, gitBlobId } from './snapshot/dirty.js';
export { ARCHIVE_LIMITS, ArchiveError, detectArchiveFormat, normalizeEntryPath, readArchive, scanArchive, type ArchiveFormat, type ArchiveLimits, type ArchiveScan } from './snapshot/archive.js';
export {
  fetchToCache, listRemoteTree, lsRemote, parseGitUrl, remoteCacheDir, RemoteGitError, resolveRemoteRef,
  type RemoteAuth, type RemoteErrorCode, type RemoteListing, type RemoteRef, type RemoteUrl, type ResolvedRemoteRef,
} from './snapshot/remote.js';
export { SnapshotView } from './snapshot/view.js';
export {
  toolRead, toolGrep, toolGlob, toolList, toolReadArtifact, ToolInputError, OUTPUT_INLINE_LIMIT, READ_MAX_LINES,
  type ToolContext, type ReadEvent, type ReadResult, type GrepResult, type GrepArgs, type Offloaded,
} from './tools/tools.js';
export { toolEntrypoints, toolDangerousSinks, toolSymbolLookup, toolFindRefs, toolCallgraph, type IndexMap } from './tools/index-tools.js';
export { loadRules, defaultRulesDir, RULE_LANGS, POST_FUNCTION_PREFIXES, type RuleSet, type RuleDef } from './index/rules.js';
export { buildIndex, indexCacheKey, INDEXER_VERSION, type IndexResult, type BuildIndexOptions } from './index/build.js';
export { entropy, redact, scanSecretText, secretSinks } from './index/secrets.js';
export { LANGUAGE_PLUGINS, pluginFor, auditLanguagesOfView, genericResolve, type LanguagePlugin, type ResolveTables, type CallResolution } from './index/languages.js';
export { grammarVersions, loadLanguage, GRAMMARS, type GrammarLang } from './index/grammar.js';
export { Extractor, PARSE_TIMEOUT_MS } from './index/extract.js';
export { normalizeRoute, joinRoute, entryKey, eraseType } from './index/types.js';
export { scanGraphql, graphqlSchemaOf, graphqlStateOrById, type GraphqlSchema, type GraphqlField } from './index/graphql.js';
export { scanProto, type GrpcService } from './index/proto.js';
export { mergeRanges, linesCovered, overlapRatio, coverageTargets, entryDetail, sinkDetail, targetState, READ_THRESHOLD, type CoverageTarget, type Range, type TargetState } from './coverage.js';
export { diffManifests, lineHunks } from './impact/diff.js';
export { diffSymbols, hashSymbol, type SymbolDiff, type TextSource } from './impact/symbols.js';
export { computeImpact, type ImpactInput, type ImpactSide } from './impact/impact.js';
export { computeRepoSignals, linkReferences } from './profile/signals.js';
export { extractConnections, CONNECT_VERSION, MAX_CONNECT_FILES, type ConnectLimit } from './connect/extract.js';
export { comparePaths, matchConnections, normalizePath, resolveService, type MatchResult, type RepoNames } from './connect/match.js';
export { crossRepoTrace, TRACE_SNIPPET_LINES, type CrossRepoData, type TraceInput, type TraceResult } from './connect/trace.js';
export { compareVersions, declaredDependencies, locateRiskCandidates, parenOptional, parseBasisText, versionInRange, type Declared, type LocateResult } from './hunt/locate.js';
export { gitLog, GIT_LOG_MAX, type GitLogEntry, type GitLogResult } from './tools/git-log.js';
export { spawnLspProcess, LSP_BINARIES, LSP_MEMORY_BYTES, type LspProcess, type LspProcessRequest } from './exec/lsp-process.js';
export { LspSession, prepareWorkspace, javaSourceRoots, serverCommand, initializationOptions, configurationFor, GOPLS_ENV, PYRIGHT_NO_INTERPRETER, LSP_LANGUAGES, LSP_INIT_TIMEOUT_MS, LSP_REQUEST_TIMEOUT_MS, type LspLanguage, type LspServer, type LspLocation } from './lsp/client.js';
export { extractGatewayAuth, gatewayAuthFor, type GatewayAuth, type GatewayAuthKind, type GatewayAuthReport, type GatewayRoute } from './connect/gateway-auth.js';
export { checkProjectRule, matchProjectRule, hitsOrigin, projectRuleSinks, PROJECT_RULE_LIMITS, type ProjectRuleSpec, type RuleHit, type RuleMatchResult } from './index/project-rules.js';
