// Connection points of one repository snapshot: what it provides (HTTP routes, gRPC and
// Dubbo services, MQ topics it produces, published modules) and what it consumes (Feign / RestTemplate /
// WebClient / Go http / frontend fetch and axios calls, gRPC stubs, Dubbo references, MQ listeners,
// gateway routes, declared dependencies). Deterministic; context repositories only yield contracts.
import { parse as parseYaml } from 'yaml';
import { Parser, type Node } from 'web-tree-sitter';
import { sha256Hex, type Connection, type RepoSignals, type StructIndex } from '@xiezhi/contracts';
import { loadLanguage, type GrammarLang } from '../index/grammar.js';
import type { SnapshotView } from '../snapshot/view.js';
import { CSHARP_CLIENTS } from './clients-csharp.js';
import { KOTLIN_CLIENTS } from './clients-kotlin.js';
import { PHP_CLIENTS } from './clients-php.js';
import { PYTHON_CLIENTS } from './clients-python.js';
import { RUBY_CLIENTS } from './clients-ruby.js';
import { RUST_CLIENTS } from './clients-rust.js';

/**
 * Bump when extraction rules change (connection caches keyed by rootHash + this). 2: client plugins for the other languages.
 * 3: the file limit counts only files the extractor reads, and a cut is reported.
 * 4: Ruby / Rust clients.
 */
export const CONNECT_VERSION = 4;
const MAX_FILE_BYTES = 512 * 1024;
/** Files read per repository (source with a client grammar, proto, YAML / JSON, properties, nginx conf, XML). */
export const MAX_CONNECT_FILES = 8000;
const CONFIG_FILE = /\.(proto|ya?ml|json|properties|conf|xml)$/i;

export type Draft = Omit<Connection, 'connId' | 'repo'>;
type Extraction = Connection['extraction'];

const HTTP_VERBS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options']);
const MAPPING: Record<string, string | null> = { GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT', DeleteMapping: 'DELETE', PatchMapping: 'PATCH', RequestMapping: null };

// ---- string expression evaluation ---------------------------------------------------------------------------

interface Evaluated { text: string; extraction: Extraction }

function unq(t: string): string {
  if (t.length >= 2 && `"'\``.includes(t[0]!) && t[t.length - 1] === t[0]) return t.slice(1, -1);
  if (t.startsWith('"""') && t.endsWith('"""')) return t.slice(3, -3);
  return t;
}

/** Fold string literals, `+` concatenation, template strings and same-file constants; unknown parts become `{?}`. */
function evaluate(node: Node | null, consts: Map<string, string>): Evaluated | null {
  if (!node) return null;
  let folded = false;
  let partial = false;
  const walk = (n: Node): string => {
    switch (n.type) {
      case 'string_literal': case 'string': case 'interpreted_string_literal': case 'raw_string_literal':
        return unq(n.text);
      case 'template_string': {
        let out = '';
        for (const c of n.children) {
          if (!c) continue;
          if (c.type === 'string_fragment' || c.type === '`') out += c.type === '`' ? '' : c.text;
          else if (c.type === 'template_substitution') { partial = true; out += '{?}'; }
          else if (c.type === 'escape_sequence') out += c.text;
        }
        return out;
      }
      case 'binary_expression': {
        const op = n.childForFieldName('operator')?.text ?? n.children.find((c) => c?.text === '+')?.text;
        if (op !== '+') { partial = true; return '{?}'; }
        return walk(n.childForFieldName('left')!) + walk(n.childForFieldName('right')!);
      }
      case 'parenthesized_expression': return n.namedChildren[0] ? walk(n.namedChildren[0]) : '';
      case 'identifier': case 'field_access': case 'member_expression': case 'selector_expression': {
        const name = n.text.split('.').pop()!;
        const v = consts.get(name);
        if (v !== undefined) { folded = true; return v; }
        partial = true;
        return '{?}';
      }
      default:
        partial = true;
        return '{?}';
    }
  };
  const text = walk(node);
  if (!/[a-z0-9/]/i.test(text.replace(/\{\?\}/g, ''))) return null;
  return { text, extraction: partial ? 'partial' : folded ? 'constant_folded' : 'literal' };
}

/** Split an URL or path into host hint + path. */
function splitUrl(u: string): { host?: string; path: string } {
  const m = /^[a-z][a-z0-9+.-]*:\/\/([^/{?]+|\{\?\})(\/.*)?$/i.exec(u);
  if (m) {
    const host = m[1] === '{?}' ? undefined : m[1]!.replace(/:\d+$/, '');
    return { ...(host ? { host } : {}), path: m[2] ?? '/' };
  }
  if (u.startsWith('{?}/') ) return { path: u.slice(3) };
  return { path: u };
}

// ---- tree walking helpers -----------------------------------------------------------------------------------

function* descendants(n: Node): Generator<Node> {
  const stack: Node[] = [n];
  while (stack.length) {
    const cur = stack.pop()!;
    yield cur;
    for (let i = cur.namedChildCount - 1; i >= 0; i--) {
      const c = cur.namedChild(i);
      if (c) stack.push(c);
    }
  }
}

function line(n: Node): number {
  return n.startPosition.row + 1;
}

/** `static final String X = "..."` (Java), `const X = "..."` (Go / JS / TS). */
function constantsOf(root: Node): Map<string, string> {
  const out = new Map<string, string>();
  for (const n of descendants(root)) {
    if (n.type === 'variable_declarator') {
      const name = n.childForFieldName('name')?.text;
      const value = n.childForFieldName('value');
      if (name && value && ['string_literal', 'string', 'template_string'].includes(value.type)) {
        const e = evaluate(value, new Map());
        if (e && e.extraction === 'literal') out.set(name, e.text);
      }
    } else if (n.type === 'const_spec') {
      const name = n.childForFieldName('name')?.text;
      const value = n.childForFieldName('value')?.namedChildren[0];
      if (name && value && value.type.endsWith('string_literal')) out.set(name, unq(value.text));
    }
  }
  return out;
}

// ---- Java -------------------------------------------------------------------------------------------------

function annName(a: Node): string {
  return (a.childForFieldName('name')?.text ?? '').split('.').pop() ?? '';
}

function annotations(decl: Node): Node[] {
  const mods = decl.namedChildren.find((c) => c?.type === 'modifiers');
  return mods ? mods.namedChildren.filter((c): c is Node => !!c && (c.type === 'annotation' || c.type === 'marker_annotation')) : [];
}

function annArgs(a: Node, consts: Map<string, string>): Map<string, Evaluated[]> {
  const out = new Map<string, Evaluated[]>();
  const args = a.childForFieldName('arguments');
  if (!args) return out;
  const vals = (n: Node): Evaluated[] => (n.type === 'element_value_array_initializer'
    ? n.namedChildren.flatMap((c) => (c ? vals(c) : []))
    : [evaluate(n, consts) ?? { text: n.text, extraction: 'partial' as const }]);
  for (const c of args.namedChildren) {
    if (!c) continue;
    if (c.type === 'element_value_pair') {
      const v = c.childForFieldName('value');
      if (v) out.set(c.childForFieldName('key')?.text ?? 'value', vals(v));
    } else out.set('value', vals(c));
  }
  return out;
}

function first(m: Map<string, Evaluated[]>, ...keys: string[]): Evaluated | undefined {
  for (const k of keys) { const v = m.get(k)?.[0]; if (v) return v; }
  return undefined;
}

function joinPath(a: string, b: string): string {
  return `/${[a, b].map((s) => s.replace(/^\/+|\/+$/g, '')).filter(Boolean).join('/')}`;
}

function worse(a: Extraction, b: Extraction): Extraction {
  const rank: Record<Extraction, number> = { literal: 0, constant_folded: 1, partial: 2 };
  return (rank[a] ?? 0) >= (rank[b] ?? 0) ? a : b;
}

function extractJava(root: Node, path: string, out: Draft[]): void {
  const consts = constantsOf(root);
  for (const n of descendants(root)) {
    if (n.type === 'interface_declaration' || n.type === 'class_declaration') {
      const anns = annotations(n);
      const feign = anns.find((a) => annName(a) === 'FeignClient');
      const dubboSvc = anns.find((a) => ['DubboService'].includes(annName(a)));
      if (dubboSvc) {
        const args = annArgs(dubboSvc, consts);
        const iface = first(args, 'interfaceName', 'interfaceClass')?.text.replace(/\.class$/, '')
          ?? n.childForFieldName('interfaces')?.namedChildren[0]?.namedChildren[0]?.text;
        if (iface) out.push({ side: 'provides', kind: 'dubbo', key: { interface: iface.split('.').pop()! }, site: { path, line: line(n) }, ruleId: 'java.dubbo.service', extraction: 'literal' });
      }
      if (!feign || n.type !== 'interface_declaration') continue;
      const fa = annArgs(feign, consts);
      const hint = first(fa, 'name', 'value', 'serviceId');
      const url = first(fa, 'url');
      const prefixAnn = anns.find((a) => annName(a) === 'RequestMapping');
      const prefix = [first(fa, 'path')?.text ?? '', prefixAnn ? first(annArgs(prefixAnn, consts), 'value', 'path')?.text ?? '' : ''].join('/');
      const body = n.childForFieldName('body');
      for (const m of body?.namedChildren ?? []) {
        if (!m || m.type !== 'method_declaration') continue;
        for (const a of annotations(m)) {
          const nm = annName(a);
          if (!(nm in MAPPING)) continue;
          const args = annArgs(a, consts);
          const p = first(args, 'value', 'path') ?? { text: '', extraction: 'literal' as const };
          const method = MAPPING[nm] ?? first(args, 'method')?.text.split('.').pop()?.toUpperCase();
          const host = url ? splitUrl(url.text).host : undefined;
          out.push({
            side: 'consumes', kind: 'http', key: { ...(method ? { method } : {}), pathTemplate: joinPath(url ? splitUrl(url.text).path : '', joinPath(prefix, p.text)) },
            ...(hint ? { serviceHint: hint.text } : host ? { serviceHint: host } : {}), site: { path, line: line(m) }, ruleId: 'java.feign', extraction: worse(p.extraction, hint?.extraction ?? 'literal'),
          });
        }
      }
    } else if (n.type === 'method_invocation') {
      const name = n.childForFieldName('name')?.text ?? '';
      const obj = n.childForFieldName('object')?.text ?? '';
      const args = n.childForFieldName('arguments')?.namedChildren.filter((c): c is Node => !!c) ?? [];
      if (/resttemplate/i.test(obj) && /^(getForObject|getForEntity|postForObject|postForEntity|put|delete|exchange|patchForObject)$/.test(name)) {
        const e = evaluate(args[0] ?? null, consts);
        if (!e) continue;
        const u = splitUrl(e.text);
        const method = name === 'exchange' ? args[1]?.text.split('.').pop()?.toUpperCase() : name.startsWith('get') ? 'GET' : name.startsWith('post') ? 'POST' : name.startsWith('patch') ? 'PATCH' : name.toUpperCase();
        out.push({ side: 'consumes', kind: 'http', key: { ...(method && HTTP_VERBS.has(method.toLowerCase()) ? { method } : {}), pathTemplate: u.path }, ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: line(n) }, ruleId: 'java.resttemplate', extraction: e.extraction });
      } else if (name === 'uri' && /\b(get|post|put|delete|patch)\(\)/i.test(obj)) {
        const e = evaluate(args[0] ?? null, consts);
        if (!e) continue;
        const u = splitUrl(e.text);
        const method = /\b(get|post|put|delete|patch)\(\)\s*$/i.exec(obj)?.[1]?.toUpperCase();
        out.push({ side: 'consumes', kind: 'http', key: { ...(method ? { method } : {}), pathTemplate: u.path }, ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: line(n) }, ruleId: 'java.webclient', extraction: e.extraction });
      } else if (/^new(Blocking|Future)?Stub$/.test(name) && /Grpc$/.test(obj)) {
        out.push({ side: 'consumes', kind: 'grpc', key: { service: obj.replace(/Grpc$/, '').split('.').pop()! }, site: { path, line: line(n) }, ruleId: 'java.grpc.stub', extraction: 'literal' });
      } else if (/kafkatemplate/i.test(obj) && name === 'send' || /rocketmqtemplate/i.test(obj) && /^(convertAndSend|syncSend|asyncSend|sendOneWay|send)$/.test(name)) {
        const e = evaluate(args[0] ?? null, consts);
        if (e) out.push({ side: 'provides', kind: 'mq', key: { topic: e.text.split(':')[0]! }, site: { path, line: line(n) }, ruleId: 'java.mq.producer', extraction: e.extraction });
      }
    } else if (n.type === 'annotation' || n.type === 'marker_annotation') {
      const nm = annName(n);
      if (nm === 'KafkaListener' || nm === 'RocketMQMessageListener') {
        const args = annArgs(n, consts);
        for (const t of args.get('topics') ?? args.get('topic') ?? args.get('value') ?? []) {
          out.push({ side: 'consumes', kind: 'mq', key: { topic: t.text }, site: { path, line: line(n) }, ruleId: 'java.mq.listener', extraction: t.extraction });
        }
      } else if (nm === 'DubboReference' || nm === 'Reference') {
        const decl = n.parent?.parent;
        const type = decl?.childForFieldName('type')?.text;
        if (type && (nm === 'DubboReference' || decl?.type === 'field_declaration')) {
          out.push({ side: 'consumes', kind: 'dubbo', key: { interface: type.split('.').pop()! }, site: { path, line: line(n) }, ruleId: 'java.dubbo.reference', extraction: 'literal' });
        }
      }
    }
  }
}

// ---- Go ---------------------------------------------------------------------------------------------------

function extractGo(root: Node, path: string, out: Draft[]): void {
  const consts = constantsOf(root);
  for (const n of descendants(root)) {
    if (n.type === 'call_expression') {
      const fn = n.childForFieldName('function')?.text ?? '';
      const args = n.childForFieldName('arguments')?.namedChildren.filter((c): c is Node => !!c) ?? [];
      let method: string | undefined;
      let urlArg: Node | undefined;
      if (/^http\.NewRequest$/.test(fn)) { method = unq(args[0]?.text ?? '').toUpperCase(); urlArg = args[1]; }
      else if (/^http\.NewRequestWithContext$/.test(fn)) { method = unq(args[1]?.text ?? '').toUpperCase(); urlArg = args[2]; }
      else if (/^(http|[a-z]\w*[cC]lient)\.(Get|Post|Head|PostForm)$/.test(fn)) { method = fn.split('.').pop()!.replace('PostForm', 'Post').toUpperCase(); urlArg = args[0]; }
      const gm = /^(\w+)\.New(\w+)Client$/.exec(fn);
      if (gm && args.length >= 1) {
        out.push({ side: 'consumes', kind: 'grpc', key: { service: gm[2]! }, site: { path, line: line(n) }, ruleId: 'go.grpc.client', extraction: 'literal' });
        continue;
      }
      if (!urlArg) continue;
      const e = evaluate(urlArg, consts);
      if (!e) continue;
      const u = splitUrl(e.text);
      out.push({
        side: 'consumes', kind: 'http', key: { ...(method && HTTP_VERBS.has(method.toLowerCase()) ? { method } : {}), pathTemplate: u.path },
        ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: line(n) }, ruleId: 'go.http.client', extraction: e.extraction,
      });
    } else if (n.type === 'keyed_element') {
      const [k, v] = n.namedChildren;
      if (k?.text === 'Topic' || k?.text === 'GroupTopics') {
        const e = evaluate(v?.namedChildren[0] ?? v ?? null, consts);
        const lit = n.parent?.parent;
        const typ = lit?.childForFieldName('type')?.text ?? '';
        if (e) out.push({ side: /Reader/.test(typ) ? 'consumes' : 'provides', kind: 'mq', key: { topic: e.text }, site: { path, line: line(n) }, ruleId: /Reader/.test(typ) ? 'go.mq.reader' : 'go.mq.writer', extraction: e.extraction });
      }
    }
  }
}

// ---- JavaScript / TypeScript --------------------------------------------------------------------------------

function extractJs(root: Node, path: string, out: Draft[]): void {
  const consts = constantsOf(root);
  const instances = new Map<string, string>(); // axios instance name → baseURL
  for (const n of descendants(root)) {
    if (n.type === 'variable_declarator') {
      const value = n.childForFieldName('value');
      if (value?.type === 'call_expression' && /^axios\.create$/.test(value.childForFieldName('function')?.text ?? '')) {
        const obj = value.childForFieldName('arguments')?.namedChildren[0];
        let base = '';
        for (const p of obj?.namedChildren ?? []) {
          if (p?.type === 'pair' && /^['"]?baseURL['"]?$/.test(p.childForFieldName('key')?.text ?? '')) base = evaluate(p.childForFieldName('value'), consts)?.text ?? '{?}';
        }
        instances.set(n.childForFieldName('name')?.text ?? '', base);
      }
    }
  }
  for (const n of descendants(root)) {
    if (n.type !== 'call_expression') continue;
    const fn = n.childForFieldName('function');
    const args = n.childForFieldName('arguments')?.namedChildren.filter((c): c is Node => !!c) ?? [];
    if (!fn || !args.length) continue;
    const text = fn.text;
    let method: string | undefined;
    let base = '';
    let rule: string;
    if (text === 'fetch') {
      rule = 'js.fetch';
      const opts = args[1];
      for (const p of opts?.namedChildren ?? []) {
        if (p?.type === 'pair' && /^['"]?method['"]?$/.test(p.childForFieldName('key')?.text ?? '')) method = unq(p.childForFieldName('value')?.text ?? '').toUpperCase();
      }
      method ??= 'GET';
    } else {
      const m = /^(\w+)(?:\.(\w+))?$/.exec(text);
      if (!m) continue;
      const [, obj, verb] = m;
      const isAxios = obj === 'axios' || instances.has(obj!);
      if (!isAxios) continue;
      if (verb && !HTTP_VERBS.has(verb) && verb !== 'request') continue;
      rule = 'js.axios';
      base = instances.get(obj!) ?? '';
      method = verb && verb !== 'request' ? verb.toUpperCase() : undefined;
      if (!verb || verb === 'request') {
        const cfg = args[0]!;
        if (cfg.type === 'object') {
          let urlNode: Node | null = null;
          for (const p of cfg.namedChildren) {
            const k = p?.childForFieldName('key')?.text.replace(/['"]/g, '');
            if (k === 'url') urlNode = p!.childForFieldName('value');
            if (k === 'method') method = unq(p!.childForFieldName('value')?.text ?? '').toUpperCase();
          }
          const e = evaluate(urlNode, consts);
          if (e) out.push(jsDraft(path, n, method ?? 'GET', base, e, rule));
          continue;
        }
        method ??= 'GET';
      }
    }
    const e = evaluate(args[0]!, consts);
    if (e) out.push(jsDraft(path, n, method, base, e, rule));
  }
}

function jsDraft(path: string, n: Node, method: string | undefined, base: string, e: Evaluated, rule: string): Draft {
  const full = /^[a-z]+:\/\//i.test(e.text) ? e.text : base ? joinPath(splitUrl(base).path, e.text) : e.text;
  const u = splitUrl(full);
  const baseHost = base ? splitUrl(base).host : undefined;
  return {
    side: 'consumes', kind: 'http', key: { ...(method ? { method } : {}), pathTemplate: u.path },
    ...(u.host ?? baseHost ? { serviceHint: (u.host ?? baseHost)! } : {}), site: { path, line: line(n) }, ruleId: rule,
    extraction: base === '{?}' ? 'partial' : e.extraction,
  };
}

// ---- contracts and configuration files ----------------------------------------------------------------------

function extractProto(text: string, path: string, out: Draft[]): void {
  const clean = text.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '');
  const pkg = /\bpackage\s+([\w.]+)\s*;/.exec(clean)?.[1];
  for (const s of clean.matchAll(/\bservice\s+(\w+)\s*\{([\s\S]*?)\n\}/g)) {
    const svc = s[1]!;
    for (const r of s[2]!.matchAll(/\brpc\s+(\w+)\s*\(/g)) {
      const at = clean.slice(0, (s.index ?? 0)).split('\n').length;
      out.push({ side: 'provides', kind: 'grpc', key: { service: pkg ? `${pkg}.${svc}` : svc, rpc: r[1]! }, site: { path, line: at }, ruleId: 'proto.service', extraction: 'literal' });
    }
  }
}

function doc(text: string, path: string): unknown {
  try { return path.endsWith('.json') ? JSON.parse(text) : parseYaml(text, { maxAliasCount: 50, logLevel: 'silent' }); } catch { return null; }
}

function extractOpenApi(d: Record<string, unknown>, path: string, out: Draft[]): void {
  const paths = d.paths;
  if (!paths || typeof paths !== 'object') return;
  let prefix = typeof d.basePath === 'string' ? d.basePath : '';
  const servers = d.servers as { url?: string }[] | undefined;
  if (!prefix && Array.isArray(servers) && typeof servers[0]?.url === 'string') prefix = splitUrl(servers[0].url).path;
  for (const [p, ops] of Object.entries(paths as Record<string, unknown>)) {
    for (const m of Object.keys((ops ?? {}) as object)) {
      if (!HTTP_VERBS.has(m)) continue;
      out.push({ side: 'provides', kind: 'http', key: { method: m.toUpperCase(), pathTemplate: joinPath(prefix, p) }, site: { path, line: 0 }, ruleId: 'openapi.path', extraction: 'literal' });
    }
  }
}

/** Upstream name of `lb://svc`, `http://svc:8080/x`, `svc`. */
function upstream(uri: string): string {
  return uri.replace(/^lb:\/\//, '').replace(/^[a-z]+:\/\//i, '').replace(/[:/].*$/, '');
}

/**
 * A gateway route both exposes a path (what clients such as the frontend call) and forwards it to an
 * upstream service (what the gateway consumes).
 */
function pushRoute(out: Draft[], path: string, pattern: string, svc: string, strip: number, rule: string): void {
  const p = `/${pattern.split('/').filter(Boolean).join('/')}`;
  out.push({ side: 'provides', kind: 'http', key: { pathTemplate: p }, site: { path, line: 0 }, ruleId: `${rule}.expose`, extraction: 'literal' });
  if (svc) out.push({ side: 'consumes', kind: 'gateway_route', key: { pathTemplate: p, service: svc, ...(strip ? { stripPrefix: strip } : {}) }, serviceHint: svc, site: { path, line: 0 }, ruleId: rule, extraction: 'literal' });
}

function extractGateway(d: unknown, text: string, path: string, out: Draft[]): void {
  const push = (pattern: string, svc: string, strip: number, rule: string) => pushRoute(out, path, pattern, svc, strip, rule);
  const get = (o: unknown, keys: string[]) => keys.reduce<unknown>((c, k) => (c && typeof c === 'object' ? (c as Record<string, unknown>)[k] : undefined), o);
  const scg = get(d, ['spring', 'cloud', 'gateway', 'routes']);
  if (Array.isArray(scg)) {
    for (const r of scg as Record<string, unknown>[]) {
      const preds = (r.predicates as unknown[] | undefined) ?? [];
      const filters = (r.filters as unknown[] | undefined) ?? [];
      const strip = Number(/StripPrefix\s*=\s*(\d+)/.exec(filters.map(String).join(','))?.[1] ?? 0);
      for (const p of preds.map(String)) {
        const m = /^Path\s*=\s*(.+)$/.exec(p);
        if (m) for (const pat of m[1]!.split(',')) push(pat.trim(), upstream(String(r.uri ?? '')), strip, 'gateway.scg');
      }
    }
    return;
  }
  const zuul = get(d, ['zuul', 'routes']);
  if (zuul && typeof zuul === 'object') {
    for (const [name, r] of Object.entries(zuul as Record<string, Record<string, unknown>>)) {
      const pat = typeof r?.path === 'string' ? r.path : `/${name}/**`;
      push(pat, String(r?.serviceId ?? (r?.url ? upstream(String(r.url)) : name)), r?.stripPrefix === false ? 0 : 1, 'gateway.zuul');
    }
    return;
  }
  if (d && typeof d === 'object' && '_format_version' in (d as object)) {
    for (const s of ((d as Record<string, unknown>).services as Record<string, unknown>[] | undefined) ?? []) {
      const svc = s.host ? String(s.host) : s.url ? upstream(String(s.url)) : String(s.name ?? '');
      for (const r of (s.routes as Record<string, unknown>[] | undefined) ?? []) for (const p of (r.paths as string[] | undefined) ?? []) push(`${p.replace(/\/$/, '')}/**`, svc, r.strip_path === false ? 0 : p.split('/').filter(Boolean).length, 'gateway.kong');
    }
    return;
  }
  const routes = get(d, ['routes']);
  if (Array.isArray(routes)) {
    for (const r of routes as Record<string, unknown>[]) {
      const nodes = get(r, ['upstream', 'nodes']);
      const host = nodes && typeof nodes === 'object' ? upstream(Array.isArray(nodes) ? String((nodes[0] as Record<string, unknown>)?.host ?? '') : Object.keys(nodes)[0] ?? '') : String(r.service_id ?? r.upstream_id ?? '');
      const uris = [r.uri, ...((r.uris as unknown[] | undefined) ?? [])].filter((x): x is string => typeof x === 'string');
      for (const u of uris) push(u.replace(/\*$/, '**'), host, 0, 'gateway.apisix');
    }
  }
  if (path.endsWith('.conf')) {
    const clean = text.replace(/#[^\n]*/g, '');
    for (const m of clean.matchAll(/\blocation\s+(?:[=~^*]+\s*)?([^\s{]+)\s*\{([^{}]*)\}/g)) {
      const pp = /\bproxy_pass\s+([^;\s]+)\s*;/.exec(m[2]!);
      if (!pp) continue;
      const target = pp[1]!;
      // `proxy_pass http://up/` (with a path) replaces the location prefix — i.e. the prefix is stripped.
      const hasPath = /^[a-z]+:\/\/[^/]+\/./i.test(target) || /^[a-z]+:\/\/[^/]+\/$/i.test(target);
      push(`${m[1]!.replace(/\/$/, '')}/**`, upstream(target), hasPath ? m[1]!.split('/').filter(Boolean).length : 0, 'gateway.nginx');
    }
  }
}

function extractDubboXml(text: string, path: string, out: Draft[]): void {
  for (const m of text.matchAll(/<dubbo:(service|reference)\b[^>]*\binterface\s*=\s*"([^"]+)"/g)) {
    out.push({ side: m[1] === 'service' ? 'provides' : 'consumes', kind: 'dubbo', key: { interface: m[2]!.split('.').pop()! }, site: { path, line: text.slice(0, m.index).split('\n').length }, ruleId: `xml.dubbo.${m[1]}`, extraction: 'literal' });
  }
}

// ---- client plugins (Python, PHP, Kotlin, C#, Ruby, Rust) ------------------------------------------------------------

/** Shared helpers handed to the per-language client extractors (connect/clients-*.ts). */
export interface ConnectHelpers {
  evaluate: typeof evaluate;
  splitUrl: typeof splitUrl;
  descendants: typeof descendants;
  line: typeof line;
  unq: typeof unq;
}
const HELPERS: ConnectHelpers = { evaluate, splitUrl, descendants, line, unq };

export interface ClientPlugin {
  /** Files of this grammar. */
  ext: RegExp;
  /** Cheap text check before parsing (outbound HTTP clients, MQ, RPC stubs). */
  prefilter: RegExp;
  extract(root: Node, path: string, out: Draft[], h: ConnectHelpers): void;
}

const CLIENT_PLUGINS: Partial<Record<GrammarLang, ClientPlugin>> = {
  python: PYTHON_CLIENTS, php: PHP_CLIENTS, kotlin: KOTLIN_CLIENTS, csharp: CSHARP_CLIENTS,
  ruby: RUBY_CLIENTS, rust: RUST_CLIENTS,
};

// ---- entry ---------------------------------------------------------------------------------------------------

function grammarFor(path: string): GrammarLang | null {
  if (path.endsWith('.java')) return 'java';
  for (const [g, c] of Object.entries(CLIENT_PLUGINS)) if (c.ext.test(path)) return g as GrammarLang;
  if (path.endsWith('.go')) return 'go';
  if (/\.(tsx)$/.test(path)) return 'tsx';
  if (/\.(ts|mts|cts)$/.test(path) && !path.endsWith('.d.ts')) return 'typescript';
  if (/\.(js|jsx|mjs|cjs|vue)$/.test(path)) return 'javascript';
  return null;
}

/** Vue single-file components: only the <script> block is JavaScript. */
function scriptOf(path: string, text: string): string {
  if (!path.endsWith('.vue')) return text;
  const m = /<script\b[^>]*>([\s\S]*?)<\/script>/.exec(text);
  return m ? '\n'.repeat(text.slice(0, m.index).split('\n').length) + m[1]! : '';
}

export interface ConnectOptions {
  /** Context repositories only yield contracts — same rules; they have no index entries. */
  signal?: AbortSignal;
  /** Called once when more than the limit of files qualified: `skipped` were not read (a coverage gap). */
  onLimit?: (cut: ConnectLimit) => void;
  /** File limit (default MAX_CONNECT_FILES; tests use a small one). */
  maxFiles?: number;
}

export interface ConnectLimit { limit: number; skipped: number; firstSkipped: string }

export async function extractConnections(view: SnapshotView, index: StructIndex | null, signals: RepoSignals | null, opts: ConnectOptions = {}): Promise<Connection[]> {
  const drafts: Draft[] = [];
  // Providers from the structure index (Spring / Go routes, gRPC implementations).
  for (const e of index?.entrypoints ?? []) {
    if (e.kind === 'http' && e.pathTemplate) drafts.push({ side: 'provides', kind: 'http', key: { ...(e.httpMethod ? { method: e.httpMethod.toUpperCase() } : {}), pathTemplate: e.pathTemplate }, site: { path: e.path, line: e.range.startLine }, ruleId: `index.${e.ruleId}`, extraction: 'literal' });
    else if (e.kind === 'rpc') {
      const m = /^rpc:([\w.]+)\/(\w+)$/.exec(e.entryKey);
      if (m) drafts.push({ side: 'provides', kind: 'grpc', key: { service: m[1]!, rpc: m[2]! }, site: { path: e.path, line: e.range.startLine }, ruleId: `index.${e.ruleId}`, extraction: 'literal' });
    }
  }
  for (const m of signals?.provides ?? []) drafts.push({ side: 'provides', kind: 'shared_lib', key: { module: m }, site: { path: '', line: 0 }, ruleId: 'build.coordinate', extraction: 'literal' });
  for (const d of signals?.dependencies ?? []) drafts.push({ side: 'consumes', kind: 'shared_lib', key: { module: d }, site: { path: '', line: 0 }, ruleId: 'build.dependency', extraction: 'literal' });

  let parser: Parser | null = null;
  let n = 0;
  let cut: ConnectLimit | null = null;
  const maxFiles = opts.maxFiles ?? MAX_CONNECT_FILES;
  for (const f of view.listFiles()) {
    if (opts.signal?.aborted) break;
    if (f.size > MAX_FILE_BYTES || f.path.includes('node_modules/')) continue;
    const g = grammarFor(f.path);
    if (!g && !CONFIG_FILE.test(f.path)) continue;
    // The limit counts files that would be read, and the files past it are reported.
    if (++n > maxFiles) {
      if (cut) cut.skipped++; else cut = { limit: maxFiles, skipped: 1, firstSkipped: f.path };
      continue;
    }
    const base = f.path.split('/').pop()!.toLowerCase();
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    if (g) {
      // Java / Go are parsed only for client calls, stubs, MQ and Dubbo (routes come from the index).
      const src = scriptOf(f.path, text);
      if (g === 'java' && !/FeignClient|RestTemplate|restTemplate|WebClient|webClient|Grpc\.|KafkaListener|RocketMQ|kafkaTemplate|Dubbo|@Reference/.test(src)) continue;
      if (g === 'go' && !/http\.|Client\(|Topic/.test(src)) continue;
      if ((g === 'javascript' || g === 'typescript' || g === 'tsx') && !/fetch\s*\(|axios/.test(src)) continue;
      const client = CLIENT_PLUGINS[g as keyof typeof CLIENT_PLUGINS];
      if (client && !client.prefilter.test(src)) continue;
      const language = await loadLanguage(g);
      parser ??= new Parser();
      parser.setLanguage(language);
      const tree = parser.parse(src);
      if (!tree) continue;
      try {
        if (g === 'java') extractJava(tree.rootNode, f.path, drafts);
        else if (g === 'go') extractGo(tree.rootNode, f.path, drafts);
        else if (client) client.extract(tree.rootNode, f.path, drafts, HELPERS);
        else extractJs(tree.rootNode, f.path, drafts);
      } finally {
        tree.delete();
      }
      continue;
    }
    if (base.endsWith('.proto')) extractProto(text, f.path, drafts);
    else if (/\.(ya?ml|json)$/.test(base)) {
      const d = doc(text, f.path);
      if (d && typeof d === 'object') {
        if ('paths' in (d as object) && ('openapi' in (d as object) || 'swagger' in (d as object))) extractOpenApi(d as Record<string, unknown>, f.path, drafts);
        else extractGateway(d, text, f.path, drafts);
      }
    } else if (base.endsWith('.properties')) {
      const routes = new Map<string, { uri?: string; paths: string[]; strip: number }>();
      for (const m of text.matchAll(/^spring\.cloud\.gateway\.routes\[(\d+)\]\.(uri|predicates\[\d+\]|filters\[\d+\])\s*=\s*(.+)$/gm)) {
        const r = routes.get(m[1]!) ?? { paths: [], strip: 0 };
        if (m[2] === 'uri') r.uri = m[3]!.trim();
        else if (/^Path=/.test(m[3]!)) r.paths.push(...m[3]!.slice(5).split(',').map((s) => s.trim()));
        else if (/^StripPrefix=(\d+)/.test(m[3]!)) r.strip = Number(/\d+/.exec(m[3]!)![0]);
        routes.set(m[1]!, r);
      }
      for (const r of routes.values()) for (const p of r.paths) pushRoute(drafts, f.path, p, upstream(r.uri ?? ''), r.strip, 'gateway.scg');
    } else if (base.endsWith('.conf') && /\bproxy_pass\b/.test(text)) extractGateway(null, text, f.path, drafts);
    else if (base.endsWith('.xml') && text.includes('dubbo:')) extractDubboXml(text, f.path, drafts);
  }
  parser?.delete();
  if (cut) opts.onLimit?.(cut);
  const seen = new Set<string>();
  const out: Connection[] = [];
  for (const d of drafts) {
    const connId = sha256Hex(JSON.stringify([view.repo, d.side, d.kind, d.key, d.site.path, d.site.line])).slice(0, 16);
    if (seen.has(connId)) continue;
    seen.add(connId);
    out.push({ connId, repo: view.repo, ...d });
  }
  return out;
}
