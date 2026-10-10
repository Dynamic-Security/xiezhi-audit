// Ruby outbound connection points: Net::HTTP, HTTParty (module calls and classes with
// `include HTTParty` + `base_uri`), Faraday (`Faraday.new(url: …)` connections), RestClient, http.rb, Excon, Typhoeus,
// and gRPC stubs (`Pkg::Service::Stub.new`). URLs fold string literals, interpolation of constants and `+`.
import type { Node } from 'web-tree-sitter';
import type { Connection } from '@xiezhi/contracts';
import type { ClientPlugin, ConnectHelpers, Draft } from './extract.js';

type Extraction = Connection['extraction'];
interface Folded { text: string; extraction: Extraction }

const VERBS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options']);
const MODULE_CLIENTS = /^(::)?(HTTParty|Faraday|RestClient|HTTP|HTTPX|Excon|Typhoeus)$/;
const namedOf = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c && c.type !== 'comment');

function fold(node: Node | null | undefined, consts: Map<string, string>): Folded | null {
  if (!node) return null;
  let folded = false;
  let partial = false;
  const walk = (n: Node): string => {
    switch (n.type) {
      case 'string': {
        let out = '';
        for (const c of namedOf(n)) {
          if (c.type === 'string_content' || c.type === 'escape_sequence') out += c.text;
          else if (c.type === 'interpolation') {
            const e = namedOf(c)[0];
            const v = e && (e.type === 'constant' || e.type === 'scope_resolution') ? consts.get(e.text.split('::').pop()!) : undefined;
            if (v !== undefined) { folded = true; out += v; } else { partial = true; out += '{?}'; }
          }
        }
        return out;
      }
      case 'binary':
        if (n.childForFieldName('operator')?.text !== '+') { partial = true; return '{?}'; }
        return walk(n.childForFieldName('left')!) + walk(n.childForFieldName('right')!);
      case 'parenthesized_statements': return namedOf(n)[0] ? walk(namedOf(n)[0]!) : '';
      case 'constant': case 'scope_resolution': {
        const v = consts.get(n.text.split('::').pop()!);
        if (v !== undefined) { folded = true; return v; }
        partial = true;
        return '{?}';
      }
      case 'call': {
        // URI("…") / URI.parse("…") / URI.join(base, "…")
        const m = n.childForFieldName('method')?.text;
        const r = n.childForFieldName('receiver')?.text;
        const a = namedOf(n.childForFieldName('arguments'));
        if ((m === 'URI' && !r) || (r === 'URI' && (m === 'parse' || m === 'join'))) return a.map(walk).join('');
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

function kw(args: Node[], name: string): Node | undefined {
  for (const a of args) {
    if (a.type === 'pair' && a.childForFieldName('key')?.text.replace(/^:|:$/g, '') === name) return a.childForFieldName('value') ?? undefined;
    if (a.type === 'hash') { const v = kw(namedOf(a), name); if (v) return v; }
  }
  return undefined;
}

function extract(root: Node, path: string, out: Draft[], h: ConnectHelpers): void {
  const consts = new Map<string, string>();
  for (const n of h.descendants(root)) {
    if (n.type !== 'assignment' || n.childForFieldName('left')?.type !== 'constant') continue;
    const v = fold(n.childForFieldName('right'), new Map());
    if (v?.extraction === 'literal') consts.set(n.childForFieldName('left')!.text, v.text);
  }
  // Faraday connections and HTTParty classes → base URL.
  const conns = new Map<string, Folded>();
  const classBase = new Map<number, Folded>();
  for (const n of h.descendants(root)) {
    if (n.type === 'assignment') {
      const right = n.childForFieldName('right');
      if (right?.type === 'call' && /^(::)?Faraday$/.test(right.childForFieldName('receiver')?.text ?? '') && right.childForFieldName('method')?.text === 'new') {
        const a = namedOf(right.childForFieldName('arguments'));
        conns.set(n.childForFieldName('left')!.text, fold(kw(a, 'url') ?? a[0], consts) ?? { text: '', extraction: 'literal' });
      }
    }
    if (n.type === 'class' && /include\s+HTTParty/.test(n.text)) {
      const base = [...h.descendants(n)].find((c: Node) => c.type === 'call' && c.childForFieldName('method')?.text === 'base_uri' && !c.childForFieldName('receiver'));
      classBase.set(n.id, (base && fold(namedOf(base.childForFieldName('arguments'))[0], consts)) || { text: '', extraction: 'literal' });
    }
  }
  const httpartyBase = (n: Node): Folded | undefined => { for (let p = n.parent; p; p = p.parent) { const b = classBase.get(p.id); if (b) return b; } return undefined; };
  for (const n of h.descendants(root)) {
    if (n.type !== 'call') continue;
    const recv = n.childForFieldName('receiver');
    const m = n.childForFieldName('method')?.text ?? '';
    const args = namedOf(n.childForFieldName('arguments'));
    const rt = recv?.text ?? '';
    // gRPC stubs: `Helloworld::Greeter::Stub.new(host, creds)`
    if (m === 'new' && /::Stub$/.test(rt)) {
      const segs = rt.replace(/^::/, '').split('::');
      const host = fold(args[0], consts);
      out.push({ side: 'consumes', kind: 'grpc', key: { service: segs[segs.length - 2]! }, ...(host && !host.text.includes('{?}') ? { serviceHint: host.text.split(':')[0]! } : {}), site: { path, line: h.line(n) }, ruleId: 'ruby.grpc.stub', extraction: 'literal' });
      continue;
    }
    let method: string | undefined;
    let urlNode: Node | undefined;
    let base: Folded | undefined;
    let rule = 'ruby.http.client';
    if (/^(::)?Net::HTTP$/.test(rt) && /^(get|get_response|get_print|post|post_form)$/.test(m)) {
      method = m.startsWith('post') ? 'POST' : 'GET';
      urlNode = args[0];
      rule = 'ruby.net_http';
    } else if (MODULE_CLIENTS.test(rt) && VERBS.has(m)) {
      method = m.toUpperCase();
      urlNode = args[0] ?? kw(args, 'url');
    } else if (/^(::)?RestClient::Request$/.test(rt) && m === 'execute') {
      const mm = kw(args, 'method')?.text.replace(/^:/, '');
      method = mm && VERBS.has(mm) ? mm.toUpperCase() : undefined;
      urlNode = kw(args, 'url');
    } else if (recv && conns.has(rt) && VERBS.has(m)) {
      method = m.toUpperCase();
      urlNode = args[0];
      base = conns.get(rt);
      rule = 'ruby.faraday';
    } else if ((!recv || rt === 'self.class' || rt === 'self') && VERBS.has(m) && httpartyBase(n) && args[0]) {
      method = m.toUpperCase();
      urlNode = args[0];
      base = httpartyBase(n);
      rule = 'ruby.httparty.class';
    } else continue;
    const e = fold(urlNode, consts);
    if (!e) continue;
    const absolute = /^[a-z]+:\/\//i.test(e.text);
    const baseText = base?.text ?? '';
    const full = absolute || !baseText ? e.text : `${baseText.replace(/\/+$/, '')}/${e.text.replace(/^\/+/, '')}`;
    const u = h.splitUrl(full);
    const extraction: Extraction = base && !absolute && base.extraction !== 'literal' ? base.extraction : e.extraction;
    out.push({ side: 'consumes', kind: 'http', key: { ...(method ? { method } : {}), pathTemplate: u.path }, ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: h.line(n) }, ruleId: rule, extraction });
  }
}

export const RUBY_CLIENTS: ClientPlugin = {
  ext: /\.rb$/,
  prefilter: /Net::HTTP|HTTParty|Faraday|RestClient|\bHTTPX?\.|Excon|Typhoeus|::Stub\.new/,
  extract,
};
