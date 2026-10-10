// Rust outbound connection points: reqwest / ureq / surf / isahc module functions,
// client values (`client.get(url)`, `client.request(Method::POST, url)`), and tonic gRPC clients
// (`GreeterClient::connect("http://host:50051")`, `GreeterClient::new(channel)`). URLs fold string literals,
// `format!` with constants (`const BASE: &str = "…"`) and `concat!`.
import type { Node } from 'web-tree-sitter';
import type { Connection } from '@xiezhi/contracts';
import type { ClientPlugin, ConnectHelpers, Draft } from './extract.js';

type Extraction = Connection['extraction'];
interface Folded { text: string; extraction: Extraction }

const VERBS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head']);
const namedOf = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c && !/comment/.test(c.type));
const strOf = (n: Node): string | null => (n.type === 'string_literal' || n.type === 'raw_string_literal' ? namedOf(n).filter((c) => c.type === 'string_content').map((c) => c.text).join('') : null);

function fold(node: Node | null | undefined, consts: Map<string, string>): Folded | null {
  if (!node) return null;
  let folded = false;
  let partial = false;
  const walk = (n: Node): string => {
    const s = strOf(n);
    if (s !== null) return s;
    switch (n.type) {
      case 'reference_expression': case 'parenthesized_expression': return walk(namedOf(n).pop()!);
      case 'identifier': case 'scoped_identifier': {
        const v = consts.get(n.text.split('::').pop()!);
        if (v !== undefined) { folded = true; return v; }
        partial = true;
        return '{?}';
      }
      case 'macro_invocation': {
        const name = n.childForFieldName('macro')?.text;
        const parts = namedOf(namedOf(n).find((c) => c.type === 'token_tree'));
        if (name === 'concat') return parts.map(walk).join('');
        if (name !== 'format') { partial = true; return '{?}'; }
        const fmt = parts[0] ? strOf(parts[0]) : null;
        if (fmt === null) { partial = true; return '{?}'; }
        let k = 1;
        return fmt.replace(/\{([A-Za-z_]\w*)?(?::[^}]*)?\}/g, (_m, named: string | undefined) => {
          const v = named ? consts.get(named) : parts[k] ? (k++, parts[k - 1]!.type === 'identifier' ? consts.get(parts[k - 1]!.text) : undefined) : undefined;
          if (v !== undefined) { folded = true; return v; }
          partial = true;
          return '{?}';
        });
      }
      case 'call_expression': {
        const f = n.childForFieldName('function');
        if (f?.type === 'field_expression' && /^(to_string|to_owned|as_str|into)$/.test(f.childForFieldName('field')?.text ?? '')) return walk(f.childForFieldName('value')!);
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

function extract(root: Node, path: string, out: Draft[], h: ConnectHelpers): void {
  const consts = new Map<string, string>();
  for (const n of h.descendants(root)) {
    if (n.type !== 'const_item' && n.type !== 'static_item') continue;
    const v = n.childForFieldName('value');
    const s = v ? strOf(v) : null;
    if (s !== null) consts.set(n.childForFieldName('name')!.text, s);
  }
  for (const n of h.descendants(root)) {
    if (n.type !== 'call_expression') continue;
    const f = n.childForFieldName('function');
    const args = namedOf(n.childForFieldName('arguments'));
    if (!f) continue;
    // tonic clients: `GreeterClient::connect(url)` / `GreeterClient::new(channel)`
    if (f.type === 'scoped_identifier') {
      const pathText = f.childForFieldName('path')?.text ?? '';
      const name = f.childForFieldName('name')?.text ?? '';
      const typ = pathText.split('::').pop()!;
      const svc = /^(\w+)Client$/.exec(typ)?.[1];
      if (svc && /^(connect|new|with_interceptor|with_origin)$/.test(name) && /(_client|::)/.test(pathText + '::') && !/^(Http|Reqwest|Hyper|Redis|Mongo|S3|Sqs|Dynamo|Kafka)$/i.test(svc)) {
        const u = name === 'connect' ? fold(args[0], consts) : null;
        const host = u ? h.splitUrl(u.text).host : null;
        out.push({ side: 'consumes', kind: 'grpc', key: { service: svc }, ...(host && !host.includes('{?}') ? { serviceHint: host } : {}), site: { path, line: h.line(n) }, ruleId: 'rust.tonic.client', extraction: 'literal' });
        continue;
      }
      // reqwest::get(url) / ureq::post(url) / surf::get(url)
      if (/(^|::)(reqwest|reqwest::blocking|ureq|surf|isahc|attohttpc)$/.test(pathText) && VERBS.has(name)) { push(n, name.toUpperCase(), args[0], 'rust.http.module'); continue; }
      continue;
    }
    if (f.type === 'field_expression') {
      const m = f.childForFieldName('field')?.text ?? '';
      const recv = f.childForFieldName('value')?.text ?? '';
      if (!/client|http|reqwest|agent/i.test(recv.split(/[.(]/).pop() ?? recv) && !/Client::new\(\)|Client::builder\(\)/.test(recv)) continue;
      if (VERBS.has(m)) push(n, m.toUpperCase(), args[0], 'rust.http.client');
      else if (m === 'request' && args.length >= 2) {
        const mm = /Method::([A-Z]+)/.exec(args[0]!.text)?.[1];
        push(n, mm, args[1], 'rust.http.client');
      }
    }
  }
  function push(n: Node, method: string | undefined, urlNode: Node | undefined, rule: string) {
    const e = fold(urlNode, consts);
    if (!e) return;
    const u = h.splitUrl(e.text);
    out.push({ side: 'consumes', kind: 'http', key: { ...(method ? { method } : {}), pathTemplate: u.path }, ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: h.line(n) }, ruleId: rule, extraction: e.extraction });
  }
}

export const RUST_CLIENTS: ClientPlugin = {
  ext: /\.rs$/,
  prefilter: /reqwest|ureq|surf::|isahc|attohttpc|Client::connect|Client::new|client\.(get|post|put|delete|patch|request)/,
  extract,
};
