// Audit tool whitelist assembly. No bash/edit/write. Every result derived from the
// audited repository is wrapped as untrusted data; file reads are scanned for injection signals.
import { Type } from 'typebox';
import {
  crossRepoTrace, toolCallgraph, toolDangerousSinks, type CrossRepoData, toolEntrypoints, toolFindRefs, toolGlob, toolGrep, toolList, toolRead, toolReadArtifact,
  toolSymbolLookup, type IndexMap, type ToolContext,
} from '@xiezhi/context';
import { loadFrozenSkill, P, type FrozenKnowledge } from '@xiezhi/knowledge';
import type { ArtifactStore } from '@xiezhi/store';
import { AskUser } from '@xiezhi/contracts';
import { unverifiedKnowledgeNote, detectInjection, wrapUntrusted, type InjectionSignal } from './boundary.js';
import type { AuditTool } from './session.js';

export interface ToolHooks {
  onInjection?: (source: { repo: string; path: string }, signals: InjectionSignal[]) => void;
  onSkillRead?: (r: { name: string; layer: string; sha256: string; file: string; tokens: number; reason: string }) => void;
  onQuestion?: (q: { question: string; blocking: boolean; context?: string }) => string;
  onCrossRepo?: (summary: { repo: string; peers: number; unresolved: boolean; missing: string[] }) => void;
}

/** A read-only connector operation offered to the Agent: one exposed MCP tool of an authorized connector. */
/** `authoritative`: the user declared this system's data authoritative. */
/** `write`: the operation may change the external system (an MCP tool not declared read-only). */
export interface ConnectorOperation { connectorId: string; connector: string; tool: string; description: string; params: string; authoritative: boolean; write?: boolean }
export interface ConnectorAccess {
  operations: ConnectorOperation[];
  /**
   * `authoritative` is decided per call: an authoritative connector's result counts only when the call
   * succeeded and the content shows no injection signal; `callId` is what conclusions cite (`connectorRefs`).
   */
  call(op: ConnectorOperation, args: Record<string, unknown>, reason: string, signal?: AbortSignal): Promise<{ text: string; isError: boolean; totalBytes: number; artifactId: string | null; callId: string; authoritative: boolean; signals: string[]; pending?: boolean }>;
}

/** Fixed note in front of connector results. */
export const connectorResultNote = (): string => P('data.connector_result');
/** Note for a result of an authoritative connector: a fact source, still data, never instructions. */
export const authoritativeResultNote = (): string => P('data.connector_authoritative');

export interface ToolSetOptions {
  ctx: ToolContext;
  nonce: string;
  indexes?: IndexMap;
  knowledge?: { frozen: FrozenKnowledge; readable: Set<string>; artifacts: ArtifactStore; tokenCap: number };
  askUser?: boolean;
  hooks?: ToolHooks;
  /** Audits with more than one repository: connection points and matches for cross_repo_trace. */
  crossRepo?: () => Promise<CrossRepoData>;
  /** Authorized context connectors: read-only operations only; no URLs as parameters. */
  connectors?: ConnectorAccess;
  /**
   * Language-server symbol queries (`definition` / `references`, `tools.lsp`): the engine asks the
   * server for the snapshot and falls back to the tree-sitter index (`source: ts`) when it is unavailable.
   */
  lsp?: {
    definition(repo: string | undefined, path: string, line: number, symbol: string | undefined, signal?: AbortSignal): Promise<{ source: 'lsp' | 'ts'; locations: { path: string; startLine: number; endLine: number }[]; note?: string }>;
    references(repo: string | undefined, path: string, line: number, symbol: string | undefined, signal?: AbortSignal): Promise<{ source: 'lsp' | 'ts'; locations: { path: string; startLine: number; endLine: number }[]; note?: string }>;
  };
  /** `git_log` of the audited versions (`tools.gitHistory`); the engine resolves repo → git data + commit. */
  gitLog?: (repo: string | undefined, args: { path?: string; n?: number; grep?: string }, signal?: AbortSignal) => Promise<{ entries: { commit: string; author: string; date: string; subject: string }[]; shallow: boolean; truncated: boolean }>;
}

const J = (v: unknown) => JSON.stringify(v, null, 1);
const repoParam = Type.Optional(Type.String({ description: 'Repository name (omit for the audited repository).' }));

export function buildAuditTools(o: ToolSetOptions): AuditTool[] {
  const { ctx, nonce } = o;
  const wrap = (source: string, body: string) => wrapUntrusted(nonce, 'tool_output', source, body);
  const tools: AuditTool[] = [
    {
      name: 'read', kind: 'read',
      description: P('tool.read'),
      parameters: Type.Object({ repo: repoParam, path: Type.String(), startLine: Type.Optional(Type.Integer({ minimum: 1 })), endLine: Type.Optional(Type.Integer({ minimum: 1 })) }),
      run(args) {
        const r = toolRead(ctx, args);
        const signals = detectInjection(r.text);
        if (signals.length) o.hooks?.onInjection?.({ repo: r.repo, path: r.path }, signals.map((s) => ({ ...s, line: s.line + r.startLine - 1 })));
        const head = `${r.repo}:${r.path} lines ${r.startLine}-${r.endLine} of ${r.totalLines}${r.truncated ? ' (truncated; request the next range)' : ''}`;
        return {
          text: `${head}\n${wrapUntrusted(nonce, 'repo_file', `${r.repo}:${r.path}`, r.text)}`,
          summary: { repo: r.repo, path: r.path, startLine: r.startLine, endLine: r.endLine },
        };
      },
    },
    {
      name: 'grep', kind: 'read',
      description: P('tool.grep'),
      parameters: Type.Object({
        repo: repoParam, pattern: Type.String({ minLength: 1 }), regex: Type.Optional(Type.Boolean()), glob: Type.Optional(Type.String()),
        caseSensitive: Type.Optional(Type.Boolean()), context: Type.Optional(Type.Integer({ minimum: 0, maximum: 5 })), maxResults: Type.Optional(Type.Integer({ minimum: 1, maximum: 200 })),
      }),
      async run(args) {
        const r = await toolGrep(ctx, args);
        // Matched lines are audited content like read output — scanned for injected instructions.
        for (const m of r.matches) {
          const signals = detectInjection(m.text);
          if (signals.length) o.hooks?.onInjection?.({ repo: m.repo, path: m.path }, signals.map((s) => ({ ...s, line: m.line })));
        }
        const lines = r.matches.map((m) => `${m.repo}:${m.path}:${m.line}${m.context ? '-' : ':'} ${m.text}`).join('\n');
        const tail = r.offloaded ? `\n[truncated: ${r.total} matches; full results in artifact ${r.offloaded.artifactId}; use read_artifact]` : '';
        return { text: `${r.total} matches${r.errors ? ` (errors: ${r.errors})` : ''}${r.note ? ` (note: ${r.note})` : ''}\n${wrap('grep', lines)}${tail}`, summary: { total: r.total, truncated: r.truncated } };
      },
    },
    {
      name: 'glob', kind: 'read', description: P('tool.glob'),
      parameters: Type.Object({ repo: repoParam, pattern: Type.String({ minLength: 1 }) }),
      run(args) {
        const r = toolGlob(ctx, args);
        return { text: `${r.total} paths${r.truncated ? ' (truncated)' : ''}\n${wrap('glob', r.paths.join('\n'))}` };
      },
    },
    {
      name: 'list', kind: 'read', description: P('tool.list'),
      parameters: Type.Object({ repo: repoParam, dir: Type.Optional(Type.String()), depth: Type.Optional(Type.Integer({ minimum: 1, maximum: 3 })) }),
      run(args) {
        const r = toolList(ctx, args);
        return { text: wrap('list', r.entries.join('\n')) + (r.truncated ? '\n[truncated]' : '') };
      },
    },
    {
      name: 'read_artifact', kind: 'read', description: P('tool.read_artifact'),
      parameters: Type.Object({ artifactId: Type.String({ pattern: '^[0-9a-f]{64}$' }), offset: Type.Optional(Type.Integer({ minimum: 0 })), limit: Type.Optional(Type.Integer({ minimum: 1 })) }),
      run(args) {
        const r = toolReadArtifact(ctx, args);
        return { text: `bytes ${r.offset}-${r.offset + r.text.length} of ${r.totalBytes}${r.done ? ' (end)' : ''}\n${wrap('artifact', r.text)}` };
      },
    },
  ];

  if (o.crossRepo) {
    const load = o.crossRepo;
    tools.push({
      name: 'cross_repo_trace', kind: 'read',
      description: P('tool.cross_repo_trace'),
      parameters: Type.Object({
        repo: repoParam, path: Type.Optional(Type.String()), line: Type.Optional(Type.Integer({ minimum: 1 })),
        method: Type.Optional(Type.String()), pathTemplate: Type.Optional(Type.String()), direction: Type.Optional(Type.Enum(['callee', 'caller'] as const)),
      }),
      async run(args) {
        const r = crossRepoTrace(ctx.views, ctx.defaultRepo, await load(), args);
        o.hooks?.onCrossRepo?.({ repo: args.repo ?? ctx.defaultRepo, peers: r.peers.length, unresolved: !!r.unresolved, missing: r.unresolved?.missing ?? [] });
        const parts = [
          `start: ${r.start.length ? r.start.join('; ') : '(none)'}`,
          ...r.peers.map((p, i) => [
            `## peer ${i + 1}: ${p.repo} [${p.confidence}] via ${p.via}`, `connection: ${p.connection}`,
            ...(p.authSignals.length ? [`auth signals: ${p.authSignals.join('; ')}`] : []),
            ...p.snippets.map((sn) => `${sn.repo}:${sn.path} lines ${sn.startLine}-${sn.endLine} (${sn.why})\n${wrapUntrusted(nonce, 'repo_file', `${sn.repo}:${sn.path}`, sn.text)}`),
          ].join('\n')),
          ...(r.userEdges.length ? [`user-declared connections: ${r.userEdges.join('; ')}`] : []),
          ...(r.incomplete?.length ? [P('feedback.cross_repo.incomplete', { points: r.incomplete.join('; ') })] : []),
          ...(r.unresolved ? [`unresolved: ${r.unresolved.reason}${r.unresolved.missing.length ? `; missing: ${r.unresolved.missing.join(', ')}` : ''}. ${P('feedback.cross_repo.unresolved')}`] : []),
        ];
        return { text: parts.join('\n\n'), summary: { peers: r.peers.length, unresolved: !!r.unresolved } };
      },
    });
  }

  if (o.indexes && o.indexes.size > 0) {
    const idx = o.indexes;
    tools.push(
      {
        name: 'entrypoints', kind: 'read', description: P('tool.entrypoints'),
        parameters: Type.Object({ repo: repoParam, framework: Type.Optional(Type.String()), pathPrefix: Type.Optional(Type.String()) }),
        run(args) {
          const r = toolEntrypoints(ctx, idx, args);
          return { text: `${r.total} entry points${r.note ? ` (${r.note})` : ''}\n${wrap('entrypoints', J(r.items))}${r.offloaded ? `\n[truncated; artifact ${r.offloaded.artifactId}]` : ''}` };
        },
      },
      {
        name: 'dangerous_sinks', kind: 'read', description: P('tool.dangerous_sinks'),
        parameters: Type.Object({ repo: repoParam, category: Type.Optional(Type.String()), pathPrefix: Type.Optional(Type.String()) }),
        run(args) {
          const r = toolDangerousSinks(ctx, idx, args);
          return { text: `${r.total} sinks${r.note ? ` (${r.note})` : ''}\n${wrap('dangerous_sinks', J(r.items))}${r.offloaded ? `\n[truncated; artifact ${r.offloaded.artifactId}]` : ''}` };
        },
      },
      {
        name: 'symbol_lookup', kind: 'read', description: P('tool.symbol_lookup'),
        parameters: Type.Object({ repo: repoParam, name: Type.String({ minLength: 1 }), kind: Type.Optional(Type.String()), container: Type.Optional(Type.String()) }),
        run(args) { return { text: wrap('symbol_lookup', J(toolSymbolLookup(idx, args).symbols)) }; },
      },
      {
        name: 'find_refs', kind: 'read', description: P('tool.find_refs'),
        parameters: Type.Object({ repo: repoParam, symbolId: Type.String({ minLength: 1 }) }),
        run(args) {
          const r = toolFindRefs(ctx, idx, args);
          return { text: `${r.total} references\n${wrap('find_refs', J(r.items))}` };
        },
      },
      {
        name: 'callgraph', kind: 'read', description: P('tool.callgraph'),
        parameters: Type.Object({
          symbolId: Type.String({ minLength: 1 }), direction: Type.Enum(['callers', 'callees'] as const),
          depth: Type.Optional(Type.Integer({ minimum: 1, maximum: 4 })), minConfidence: Type.Optional(Type.Enum(['resolved', 'heuristic', 'unresolved'] as const)),
        }),
        run(args) {
          const r = toolCallgraph(ctx, idx, args);
          return { text: `${r.total} edges\n${wrap('callgraph', J(r.items))}` };
        },
      },
    );
  }

  if (o.knowledge) {
    const k = o.knowledge;
    let used = 0;
    tools.push({
      name: 'load_skill', kind: 'read',
      description: P('tool.load_skill'),
      parameters: Type.Object({ name: Type.String(), reason: Type.String({ minLength: 3, maxLength: 500 }), file: Type.Optional(Type.String()), page: Type.Optional(Type.Integer({ minimum: 1 })) }),
      run(args) {
        // Session cap: at most `tokenCap` knowledge tokens; a read that would cross it is refused.
        const exhausted = P('feedback.load_skill.exhausted');
        if (used >= k.tokenCap) throw new Error(exhausted);
        const r = loadFrozenSkill(k.frozen, k.readable, k.artifacts, args);
        if (used + r.tokens > k.tokenCap) throw new Error(`${exhausted}; this page needs ${r.tokens} tokens, ${k.tokenCap - used} left`);
        used += r.tokens;
        o.hooks?.onSkillRead?.({ name: r.name, layer: r.layer, sha256: r.sha256, file: r.file, tokens: r.tokens, reason: args.reason });
        const head = `skill ${r.name} (${r.file}, page ${r.page}/${r.pages})`;
        // Unverified business / architecture knowledge is data, not fact.
        const unverified = k.frozen.skills.find((s) => s.name === r.name)?.verified === false;
        const text = unverified ? `${head} [推测]\n${unverifiedKnowledgeNote()}\n${wrapUntrusted(nonce, 'knowledge', `skill:${r.name}/${r.file}`, r.text)}` : `${head}\n${r.text}`;
        return { text, summary: { skill: r.name, file: r.file } };
      },
    });
  }

  if (o.connectors?.operations.length) {
    const access = o.connectors;
    tools.push({
      name: 'connector_query', kind: 'read',
      description: P('tool.connector_query'),
      parameters: Type.Object({
        connector: Type.String({ description: 'Connector name as listed' }), operation: Type.String({ description: 'Operation (tool) name as listed' }),
        args: Type.Record(Type.String(), Type.Unknown(), { description: 'Structured arguments of the operation' }), reason: Type.String({ minLength: 3, maxLength: 500 }),
      }),
      async run(args, signal) {
        const op = access.operations.find((x) => (x.connector === args.connector || x.connectorId === args.connector) && x.tool === args.operation);
        if (!op) throw new Error(`operation not available; available: ${access.operations.map((x) => `${x.connector}.${x.tool}`).join(', ')}`);
        if (JSON.stringify(args.args ?? {}).length > 16 * 1024) throw new Error('arguments exceed 16 KB');
        const r = await access.call(op, (args.args ?? {}) as Record<string, unknown>, args.reason, signal);
        if (r.pending) return { text: r.text, summary: { connector: op.connector, operation: op.tool, writeRequest: r.callId } };
        const signals = detectInjection(r.text);
        if (signals.length) o.hooks?.onInjection?.({ repo: `connector:${op.connector}`, path: op.tool }, signals);
        const tail = r.artifactId ? `\n[truncated: ${r.totalBytes} bytes; full result in artifact ${r.artifactId}; use read_artifact]` : '';
        const label = r.authoritative ? '[权威数据源·已核实]' : '[外部数据·未核实]';
        const why = op.authoritative && !r.authoritative ? `（权威数据源，但本次${r.isError ? '调用出错' : `结果含疑似注入内容（${r.signals.join('、')}）`}，按未核实处理）` : '';
        const head = `connector ${op.connector}.${op.tool} call=${r.callId}${r.isError ? ' (the external system reported an error)' : ''} ${label}${why}`;
        const note = r.authoritative ? authoritativeResultNote() : connectorResultNote();
        return { text: `${head}\n${note}\n${wrapUntrusted(nonce, 'connector', `connector:${op.connector}/${op.tool}`, r.text, undefined, r.authoritative)}${tail}`, summary: { connector: op.connector, operation: op.tool } };
      },
    });
  }

  if (o.lsp) {
    const lsp = o.lsp;
    const params = Type.Object({
      repo: repoParam, path: Type.String({ minLength: 1, maxLength: 1000 }), line: Type.Integer({ minimum: 1 }),
      symbol: Type.Optional(Type.String({ maxLength: 200, description: 'The identifier on that line (locates the column)' })),
    }, { additionalProperties: false });
    for (const [name, description] of [
      ['definition', P('tool.definition')],
      ['references', P('tool.references')],
    ] as const) {
      tools.push({
        name, kind: 'read', parameters: params, description,
        async run(args: { repo?: string; path: string; line: number; symbol?: string }, signal) {
          const r = await lsp[name](args.repo, args.path, args.line, args.symbol, signal);
          return { text: wrap(`${name}:${args.repo ?? ctx.defaultRepo}/${args.path}:${args.line}`, J({ source: r.source, ...(r.note ? { note: r.note } : {}), locations: r.locations.slice(0, 100), total: r.locations.length })), summary: { source: r.source, count: r.locations.length } };
        },
      });
    }
  }

  if (o.gitLog) {
    const gitLog = o.gitLog;
    tools.push({
      name: 'git_log', kind: 'read',
      description: P('tool.git_log'),
      parameters: Type.Object({
        repo: repoParam, path: Type.Optional(Type.String({ maxLength: 500 })), n: Type.Optional(Type.Integer({ minimum: 1, maximum: 50 })),
        grep: Type.Optional(Type.String({ maxLength: 200, description: 'Fixed string matched against commit messages (case-insensitive)' })),
      }, { additionalProperties: false }),
      async run(args, signal) {
        const r = await gitLog(args.repo, { ...(args.path ? { path: args.path } : {}), ...(args.n ? { n: args.n } : {}), ...(args.grep ? { grep: args.grep } : {}) }, signal);
        const body = J({ ...r, entries: r.entries });
        // Commit messages and authors come from the audited repository.
        const signals = detectInjection(body);
        if (signals.length) o.hooks?.onInjection?.({ repo: args.repo ?? ctx.defaultRepo, path: `git_log${args.path ? `:${args.path}` : ''}` }, signals);
        return { text: wrap(`git_log:${args.repo ?? ctx.defaultRepo}${args.path ? `/${args.path}` : ''}`, body), summary: { commits: r.entries.length, shallow: r.shallow } };
      },
    });
  }

  if (o.askUser && o.hooks?.onQuestion) {
    const onQuestion = o.hooks.onQuestion;
    tools.push({
      name: 'ask_user', kind: 'meta', parameters: AskUser,
      description: P('tool.ask_user'),
      run(args) {
        const id = onQuestion(args);
        return { text: P('feedback.ask_user.recorded', { id }) };
      },
    });
  }
  return tools;
}
