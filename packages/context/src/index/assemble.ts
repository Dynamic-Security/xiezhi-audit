// Cross-file assembly: call-edge resolution (resolved / heuristic / unresolved, per language plugin),
// handler resolution for textual handler references, entry ids/keys, MyBatis XML `${}` sinks.
import type { CallEdge, EntryPoint, IndexSymbol, Sink, StructIndex } from '@xiezhi/contracts';
import { addInheritedSpringEntries } from './jvm-inherit.js';
import { pluginFor, type ResolveTables } from './languages.js';
import type { RuleDef } from './rules.js';
import { entryKey, type FileExtract, type RawEntry } from './types.js';

export interface XmlFile { path: string; text: string }

export function assemble(repo: string, rootHash: string, rulesVersion: string, files: FileExtract[], xml: XmlFile[], rules: RuleDef[]): StructIndex {
  addInheritedSpringEntries(files);
  const symbols: IndexSymbol[] = files.flatMap((f) => f.symbols);
  const byId = new Map(symbols.map((s) => [s.symbolId, s]));
  const callables = symbols.filter((s) => s.kind === 'method' || s.kind === 'func');
  const byNameArity = new Map<string, IndexSymbol[]>();
  const byClassNameArity = new Map<string, IndexSymbol[]>();
  const pkgFuncs = new Map<string, IndexSymbol[]>();
  const pkgOfFile = new Map(files.map((f) => [f.path, f.pkg]));
  for (const s of callables) {
    const arity = Number(/\((\d+)\)$/.exec(s.symbolId)?.[1] ?? 0);
    push(byNameArity, `${s.name}/${arity}`, s);
    const cls = s.container.split('.').pop() ?? s.container;
    push(byClassNameArity, `${cls}.${s.name}/${arity}`, s);
    if (s.kind === 'func') push(pkgFuncs, `${pkgOfFile.get(s.path)}|${s.name}`, s);
  }

  // ---- call edges (resolution per language plugin) ----
  const tables: ResolveTables = { byId, byNameArity, byClassNameArity, pkgFuncs };
  const callEdges: CallEdge[] = [];
  for (const f of files) {
    for (const c of f.calls) {
      const plugin = pluginFor(f.lang);
      if (!plugin) continue;
      const r = plugin.resolveCall(c, f, tables);
      if (r === 'external') continue; // outside the repository graph
      let candidates = r?.candidates ?? [];
      let exact = r?.exact ?? false;
      if (candidates.length === 0) {
        candidates = (byNameArity.get(`${c.method}/${c.arity}`) ?? []).filter((s) => s.kind === 'method' || plugin.fallbackToFuncs);
        exact = false;
      }
      const confidence: CallEdge['confidence'] = candidates.length === 1 && exact ? 'resolved' : candidates.length >= 1 && candidates.length <= 3 ? 'heuristic' : 'unresolved';
      const targets = confidence === 'unresolved' ? [null] : candidates.map((s) => s.symbolId);
      for (const to of targets) {
        callEdges.push({ from: c.from, to, calleeText: c.calleeText, site: { path: f.path, line: c.line }, confidence });
      }
    }
  }

  /** Methods named `name`; when `owner` (the text before the method, e.g. a JS `Class.method` reference) names a class, only its methods. */
  const methodsOf = (name: string, owner: string) => {
    const all = callables.filter((s) => s.name === name && s.kind === 'method');
    const typed = all.filter((s) => s.container.split('.').pop() === owner);
    return typed.length ? typed : all;
  };

  // ---- entries ----
  let signalsByTarget: Map<string, string[]> | null = null;
  const classSignals = (m: IndexSymbol): string[] => {
    if (!signalsByTarget) {
      signalsByTarget = new Map();
      for (const f of files) for (const s of f.authSignals) push(signalsByTarget, s.target, s.detail);
    }
    const classId = m.symbolId.replace(/\.[^.#]+\(\d+\)$/, '');
    return [...(signalsByTarget.get(classId) ?? []), ...(signalsByTarget.get(m.symbolId) ?? [])];
  };
  let byQualified: Map<string, IndexSymbol[]> | undefined;
  const entrypoints: EntryPoint[] = [];
  const usedIds = new Map<string, number>();
  for (const f of files) {
    for (const e of f.entries) {
      let handler = e.handler.symbolId ?? null;
      if (!handler && e.handler.qualified) {
        for (const q of e.handler.qualified) {
          const hits = (byQualified ??= qualifiedIndex(symbols)).get(q) ?? [];
          if (hits.length === 1) { handler = hits[0]!.symbolId; break; }
          if (hits.length > 1) break;
        }
      }
      if (!handler && e.handler.text && !e.handler.qualified) {
        const text = e.handler.text;
        const name = text.split('.').pop()!;
        const hinted = e.handler.typeHint
          ? callables.filter((s) => s.kind === 'method' && s.name === name && s.container.split('.').pop() === e.handler.typeHint)
          : [];
        const fqnContainer = e.handler.classFqn?.replace(/\\([^\\]+)$/, '.$1');
        const dirHint = e.handler.dirHint;
        const byFqn = (xs: IndexSymbol[]) => (fqnContainer && xs.length > 1 ? xs.filter((s) => s.container === fqnContainer)
          : dirHint !== undefined && xs.length > 1 ? xs.filter((s) => { const d = s.path.slice(0, Math.max(0, s.path.lastIndexOf('/'))); return d === dirHint || d.endsWith(`/${dirHint}`); }) : xs);
        const cands0 = hinted.length ? hinted : e.handler.anyFunction
          ? callables.filter((s) => s.kind === 'func' && s.name.toLowerCase() === name.toLowerCase())
          : e.handler.className
          ? callables.filter((s) => s.kind === 'method' && s.name.toLowerCase() === name.toLowerCase() && s.container.split('.').pop() === e.handler.className)
          : e.handler.importPath
          ? pkgFuncs.get(`${e.handler.importPath}|${name}`) ?? []
          : text.includes('.')
            ? methodsOf(name, text.split('.').slice(-2)[0]!)
            : pkgFuncs.get(`${f.pkg}|${name}`) ?? [];
        const cands = byFqn(cands0);
        // `Class.method` in another module (Python class-based views): match the method by its container.
        const owner = text.split('.').slice(-2, -1)[0];
        const methods = !cands.length && e.handler.importPath && e.handler.moduleMember
          ? callables.filter((s) => s.kind === 'method' && s.name === name && s.container.startsWith(`${e.handler.importPath}.`))
          : !cands.length && e.handler.importPath && owner
          ? callables.filter((s) => s.kind === 'method' && s.name === name && s.container === `${e.handler.importPath}.${owner}`)
          : [];
        handler = cands.length === 1 ? cands[0]!.symbolId : methods.length === 1 ? methods[0]!.symbolId : null;
        if (!handler && !cands.length && e.handler.classFallback && e.handler.className) {
          const all = symbols.filter((s) => s.kind === 'class' && s.name === e.handler.className);
          const cls = all.length > 1 && e.handler.classFqn ? all.filter((s) => s.qualifiedName === e.handler.classFqn) : all;
          if (cls.length === 1) handler = cls[0]!.symbolId;
        }
      }
      const key = e.channel ? e.channel.key : e.rpc ? `rpc:${e.rpc.service}/${e.rpc.method}` : entryKey(e.httpMethod, e.pathTemplate);
      const base = `${repo}:${key}`;
      const n = usedIds.get(base) ?? 0;
      usedIds.set(base, n + 1);
      const handlerSym = handler ? byId.get(handler) : undefined;
      // Class-qualified handlers (PHP route files): signals on the controller class or method, e.g. constructor middleware.
      const authSignals = (e.handler.className || e.handler.targetSignals) && handlerSym ? [...new Set([...e.authSignals, ...classSignals(handlerSym)])] : e.authSignals;
      entrypoints.push({
        entryId: n === 0 ? base : `${base}#${n + 1}`,
        entryKey: key,
        kind: e.channel ? e.channel.kind : e.rpc ? 'rpc' : 'http',
        protocol: e.channel ? e.channel.protocol : entryProtocol(e),
        framework: e.framework,
        // GraphQL resolvers keep their field signature; gRPC / SignalR have none.
        ...(e.channel ? { pathTemplate: e.channel.route } : e.rpc ? (e.pathTemplate ? { pathTemplate: e.pathTemplate } : {}) : { httpMethod: e.httpMethod, pathTemplate: e.pathTemplate }),
        handler: handler ?? `${repo}:${f.path}#<unresolved:${e.handler.text ?? 'anonymous'}>`,
        path: handlerSym?.path ?? e.path,
        // An inline closure (C# minimal-API lambda, Go func literal, Ktor block) carries its own range and the symbol of
        // the function that contains it; the entry is the closure, not that whole function (e.g. top-level Program.Main).
        range: (e.handler.symbolId && e.handler.range) || (handlerSym?.range ?? e.handler.range ?? e.range),
        middlewares: e.middlewares,
        authSignals,
        ruleId: e.ruleId,
      });
    }
  }

  // ---- sinks (+ MyBatis XML) ----
  const sinks: Sink[] = files.flatMap((f) => f.sinks);
  const xmlRule = rules.find((r) => r.post === 'mybatis_xml_dollar');
  if (xmlRule) {
    for (const x of xml) sinks.push(...mybatisXmlSinks(repo, x, xmlRule, symbols));
  }
  sinks.sort((a, b) => a.sinkId.localeCompare(b.sinkId));
  entrypoints.sort((a, b) => a.entryId.localeCompare(b.entryId));

  return {
    repo, rootHash, rulesVersion,
    symbols,
    callEdges,
    entrypoints,
    authSignals: files.flatMap((f) => f.authSignals),
    sinks,
    gaps: files.flatMap((f) => f.gaps),
  };
}

/** symbols by qualified name (classes and callables), for `HandlerRef.qualified`. */
function qualifiedIndex(symbols: IndexSymbol[]): Map<string, IndexSymbol[]> {
  const m = new Map<string, IndexSymbol[]>();
  for (const s of symbols) if (s.qualifiedName && (s.kind === 'class' || s.kind === 'method' || s.kind === 'func')) push(m, s.qualifiedName, s);
  return m;
}

function push<K, V>(m: Map<K, V[]>, k: K, v: V): void {
  const arr = m.get(k);
  if (arr) arr.push(v);
  else m.set(k, [v]);
}

const STMT_RE = /<(select|update|insert|delete)\b([^>]*)>([\s\S]*?)<\/\1>/g;

export function mybatisXmlSinks(repo: string, file: XmlFile, rule: RuleDef, symbols: IndexSymbol[]): Sink[] {
  const ns = /<mapper\b[^>]*\bnamespace\s*=\s*"([^"]+)"/.exec(file.text)?.[1];
  if (!ns) return [];
  const out: Sink[] = [];
  const lineAt = (idx: number) => file.text.slice(0, idx).split('\n').length;
  for (const m of file.text.matchAll(STMT_RE)) {
    const body = m[3] ?? '';
    const dollar = body.indexOf('${');
    if (dollar === -1) continue;
    const id = /\bid\s*=\s*"([^"]+)"/.exec(m[2] ?? '')?.[1] ?? '?';
    const start = lineAt(m.index!);
    const line = lineAt(m.index! + m[0].indexOf(body) + dollar);
    const handler = symbols.find((s) => s.qualifiedName.startsWith(`${ns}#${id}(`));
    out.push({
      sinkId: `${repo}:${file.path}#L${line}:1:${rule.category ?? 'sqli'}`,
      category: rule.category ?? 'sqli',
      symbolId: handler?.symbolId ?? null,
      path: file.path,
      range: { startLine: start, endLine: lineAt(m.index! + m[0].length) },
      api: `mybatis:${ns}.${id}`,
      taintHint: 'string_concat',
      ruleId: rule.id,
    });
  }
  return out;
}

/** Protocol of an HTTP or RPC-style entry: gRPC services, GraphQL resolvers and SignalR hubs by their service prefix. */
function entryProtocol(e: RawEntry): string {
  if (!e.rpc) return e.framework === 'graphql' || e.framework === 'gqlgen' ? 'graphql' : 'http';
  const prefix = /^(graphql|signalr|thrift|dubbo):/.exec(e.rpc.service)?.[1];
  return prefix ?? 'grpc';
}
