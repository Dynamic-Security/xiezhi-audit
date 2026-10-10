// Kotlin outbound connection points: Spring `@FeignClient` interfaces, `RestTemplate`
// and `WebClient` calls (as in Java), and Ktor `HttpClient.get/post(url)` calls → consumed HTTP drafts.
import type { Node } from 'web-tree-sitter';
import type { Connection } from '@xiezhi/contracts';
import { kotlinUnits } from '../index/extract-kotlin.js';
import type { ClientPlugin, ConnectHelpers, Draft } from './extract.js';

type Extraction = Connection['extraction'];
interface Evaluated { text: string; extraction: Extraction }

const MAPPING: Record<string, string | null> = { GetMapping: 'GET', PostMapping: 'POST', PutMapping: 'PUT', DeleteMapping: 'DELETE', PatchMapping: 'PATCH', RequestMapping: null };
const REST_METHODS = /^(getForObject|getForEntity|postForObject|postForEntity|put|delete|exchange|patchForObject)$/;
const KTOR_METHODS = /^(get|post|put|delete|patch|head|request|prepareGet|preparePost)$/;
const VERBS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);

const named = (n: Node | null | undefined): Node[] => (n ? n.namedChildren.filter((c): c is Node => !!c) : []);
const childOfType = (n: Node | null | undefined, type: string): Node | null => named(n).find((c) => c.type === type) ?? null;

function worse(a: Extraction, b: Extraction): Extraction {
  const rank: Record<Extraction, number> = { literal: 0, constant_folded: 1, partial: 2 };
  return (rank[a] ?? 0) >= (rank[b] ?? 0) ? a : b;
}

/** Kotlin string folding: literals, templates (`$x` / `${x}` → constant or `{?}`), `+`, same-file constants. */
function evaluate(node: Node | null | undefined, consts: Map<string, string>): Evaluated | null {
  if (!node) return null;
  let extraction: Extraction = 'literal';
  const walk = (n: Node): string => {
    if (n.type === 'string_literal' || n.type === 'multiline_string_literal') {
      const raw = n.text.startsWith('"""') ? n.text.slice(3, -3) : n.text.slice(1, -1);
      return raw.replace(/(?<!\\)(?:\$\{\s*(\w+)\s*\}|\$\{[^}]*\}|\$([A-Za-z_]\w*))/g, (_m, a: string | undefined, b: string | undefined) => {
        const v = consts.get((a ?? b) ?? '');
        if (v !== undefined) { extraction = worse(extraction, 'constant_folded'); return v; }
        extraction = 'partial';
        return '{?}';
      }).replace(/\\\$/g, '$');
    }
    if (n.type === 'binary_expression' && n.children.some((c) => c?.type === '+')) {
      return walk(n.childForFieldName('left')!) + walk(n.childForFieldName('right')!);
    }
    if (n.type === 'parenthesized_expression' && n.namedChildren[0]) return walk(n.namedChildren[0]);
    if (n.type === 'identifier' || n.type === 'navigation_expression') {
      const v = consts.get(n.text.split('.').pop()!);
      if (v !== undefined) { extraction = worse(extraction, 'constant_folded'); return v; }
    }
    extraction = 'partial';
    return '{?}';
  };
  const text = walk(node);
  if (!/[a-z0-9/]/i.test(text.replace(/\{\?\}/g, ''))) return null;
  return { text, extraction };
}

function constantsOf(root: Node, h: ConnectHelpers): Map<string, string> {
  const out = new Map<string, string>();
  for (const n of h.descendants(root)) {
    if (n.type !== 'property_declaration') continue;
    const name = childOfType(childOfType(n, 'variable_declaration'), 'identifier')?.text;
    const value = named(n).find((c) => c.type === 'string_literal');
    if (!name || !value) continue;
    const e = evaluate(value, new Map());
    if (e?.extraction === 'literal') out.set(name, e.text);
  }
  return out;
}

function annName(a: Node): string {
  const t = childOfType(a, 'user_type') ?? childOfType(childOfType(a, 'constructor_invocation'), 'user_type');
  return named(t).filter((c) => c.type === 'identifier').pop()?.text ?? '';
}

function annotations(decl: Node): Node[] {
  return named(childOfType(decl, 'modifiers')).filter((c) => c.type === 'annotation');
}

function argExprs(args: Node | null | undefined): Node[] {
  return named(args).filter((a) => a.type === 'value_argument').map((a) => named(a).pop()!).filter(Boolean);
}

function annArgs(a: Node, consts: Map<string, string>): Map<string, Evaluated[]> {
  const out = new Map<string, Evaluated[]>();
  const vals = (n: Node): Evaluated[] => {
    if (n.type === 'collection_literal') return named(n).flatMap(vals);
    if (n.type === 'call_expression' && /^(arrayOf|listOf)$/.test(n.namedChildren[0]?.text ?? '')) return argExprs(childOfType(n, 'value_arguments')).flatMap(vals);
    if (n.type === 'navigation_expression' && !consts.has(n.text.split('.').pop()!)) return [{ text: n.text.split('.').pop()!, extraction: 'literal' }];
    return [evaluate(n, consts) ?? { text: n.text, extraction: 'partial' }];
  };
  for (const arg of named(childOfType(childOfType(a, 'constructor_invocation'), 'value_arguments'))) {
    if (arg.type !== 'value_argument') continue;
    const kids = named(arg);
    const key = arg.children.some((c) => c?.type === '=') ? kids[0]?.text ?? 'value' : 'value';
    if (kids.length) out.set(key, vals(kids[kids.length - 1]!));
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

/** Callee name / receiver text of a call (`r.m(…)`), also for `r.m<T>(…)` parsed as comparisons. */
function callOf(n: Node): { name: string; receiver: string; args: Node[] } | null {
  if (n.type === 'call_expression') {
    const callee = n.namedChildren[0];
    if (callee?.type !== 'navigation_expression') return null;
    const kids = named(callee);
    const last = kids[kids.length - 1];
    if (kids.length < 2 || last?.type !== 'identifier') return null;
    return { name: last.text, receiver: kids[0]!.text, args: argExprs(childOfType(n, 'value_arguments')) };
  }
  if (n.type === 'binary_expression') {
    const left = n.childForFieldName('left');
    const right = n.childForFieldName('right');
    if (left?.type !== 'binary_expression' || right?.type !== 'parenthesized_expression') return null;
    const callee = left.childForFieldName('left');
    if (callee?.type !== 'navigation_expression' || !/^[A-Z]/.test(left.childForFieldName('right')?.text ?? '')) return null;
    const kids = named(callee);
    return { name: kids[kids.length - 1]?.text ?? '', receiver: kids[0]?.text ?? '', args: named(right) };
  }
  return null;
}

function extractKotlinClients(root: Node, path: string, out: Draft[], h: ConnectHelpers): void {
  // Same recovery as the index for mis-parsed annotated declarations (see index/extract-kotlin.ts).
  const text = '\n'.repeat(root.startPosition.row) + ' '.repeat(root.startPosition.column) + root.text;
  const { units, trees } = kotlinUnits(text, root.tree);
  try {
    const consts = new Map<string, string>();
    for (const u of units) for (const [k, v] of constantsOf(u, h)) consts.set(k, v);
    for (const u of units) extractUnit(u, path, out, h, consts);
  } finally {
    for (const t of trees) t.delete();
  }
}

function extractUnit(root: Node, path: string, out: Draft[], h: ConnectHelpers, consts: Map<string, string>): void {
  for (const n of h.descendants(root)) {
    if (n.type === 'class_declaration' && n.children.some((c) => c?.type === 'interface')) {
      const anns = annotations(n);
      const feign = anns.find((a) => annName(a) === 'FeignClient');
      if (!feign) continue;
      const fa = annArgs(feign, consts);
      const hint = first(fa, 'name', 'value', 'serviceId');
      const url = first(fa, 'url');
      const prefixAnn = anns.find((a) => annName(a) === 'RequestMapping');
      const prefix = joinPath(first(fa, 'path')?.text ?? '', prefixAnn ? first(annArgs(prefixAnn, consts), 'value', 'path')?.text ?? '' : '');
      for (const m of named(childOfType(n, 'class_body'))) {
        if (m.type !== 'function_declaration') continue;
        for (const a of annotations(m)) {
          const nm = annName(a);
          if (!(nm in MAPPING)) continue;
          const args = annArgs(a, consts);
          const p = first(args, 'value', 'path') ?? { text: '', extraction: 'literal' as const };
          const method = MAPPING[nm] ?? first(args, 'method')?.text.split('.').pop()?.toUpperCase();
          const host = url && !url.text.startsWith('{?}') ? h.splitUrl(url.text).host : undefined;
          out.push({
            side: 'consumes', kind: 'http',
            key: { ...(method ? { method } : {}), pathTemplate: joinPath(url ? h.splitUrl(url.text).path : '', joinPath(prefix, p.text)) },
            ...(hint ? { serviceHint: hint.text } : host ? { serviceHint: host } : {}), site: { path, line: h.line(m) }, ruleId: 'kotlin.feign',
            extraction: worse(p.extraction, hint?.extraction ?? 'literal'),
          });
        }
      }
      continue;
    }
    const c = callOf(n);
    if (!c) continue;
    if (/resttemplate/i.test(c.receiver) && REST_METHODS.test(c.name)) {
      const e = evaluate(c.args[0], consts);
      if (!e) continue;
      const u = h.splitUrl(e.text);
      const method = c.name === 'exchange' ? c.args[1]?.text.split('.').pop()?.toUpperCase() : c.name.startsWith('get') ? 'GET' : c.name.startsWith('post') ? 'POST' : c.name.startsWith('patch') ? 'PATCH' : c.name.toUpperCase();
      out.push({ side: 'consumes', kind: 'http', key: { ...(method && VERBS.has(method) ? { method } : {}), pathTemplate: u.path }, ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: h.line(n) }, ruleId: 'kotlin.resttemplate', extraction: e.extraction });
    } else if (c.name === 'uri' && /\b(get|post|put|delete|patch)\(\)\s*$/i.test(c.receiver)) {
      const e = evaluate(c.args[0], consts);
      if (!e) continue;
      const u = h.splitUrl(e.text);
      const method = /\b(get|post|put|delete|patch)\(\)\s*$/i.exec(c.receiver)?.[1]?.toUpperCase();
      out.push({ side: 'consumes', kind: 'http', key: { ...(method ? { method } : {}), pathTemplate: u.path }, ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: h.line(n) }, ruleId: 'kotlin.webclient', extraction: e.extraction });
    } else if (/(^|\.)(http)?client$|HttpClient$/i.test(c.receiver) && KTOR_METHODS.test(c.name)) {
      const e = evaluate(c.args[0], consts);
      if (!e) continue;
      const u = h.splitUrl(e.text);
      const verb = c.name.replace(/^prepare/, '').toUpperCase();
      out.push({ side: 'consumes', kind: 'http', key: { ...(VERBS.has(verb) ? { method: verb } : {}), pathTemplate: u.path }, ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: h.line(n) }, ruleId: 'kotlin.ktor.client', extraction: e.extraction });
    }
  }
}

export const KOTLIN_CLIENTS: ClientPlugin = {
  ext: /\.kt$/,
  prefilter: /FeignClient|RestTemplate|restTemplate|WebClient|webClient|HttpClient|[cC]lient\.(get|post|put|delete|patch|request)/,
  extract: extractKotlinClients,
};
