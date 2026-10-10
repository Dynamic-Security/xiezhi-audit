// Python outbound connection points: requests / httpx / aiohttp / urllib calls.
// `requests.get(url)`, `requests.request(method, url)`, `httpx.post(url)`, client instances
// (`requests.Session()`, `httpx.Client(base_url=…)`, `aiohttp.ClientSession(base_url=…)` assigned or bound by
// `with … as client`) and `urlopen(url)`. URLs fold string literals, f-strings, `+` and module constants.
import type { Node } from 'web-tree-sitter';
import type { Connection } from '@xiezhi/contracts';
import type { ClientPlugin, ConnectHelpers, Draft } from './extract.js';

type Extraction = Connection['extraction'];
interface Folded { text: string; extraction: Extraction }

const VERBS = new Set(['get', 'post', 'put', 'delete', 'patch', 'head', 'options']);
const CLIENT_CTOR = /^(requests\.Session|requests\.session|httpx\.(Async)?Client|aiohttp\.ClientSession|Session|(Async)?Client|ClientSession)$/;

const namedOf = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c && c.type !== 'comment');

/** Fold a Python string expression; unknown parts become `{?}`. */
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
            const e = c.childForFieldName('expression') ?? namedOf(c)[0];
            const v = e?.type === 'identifier' ? consts.get(e.text) : undefined;
            if (v !== undefined) { folded = true; out += v; } else { partial = true; out += '{?}'; }
          }
        }
        return out;
      }
      case 'concatenated_string': return namedOf(n).map(walk).join('');
      case 'binary_operator':
        if (n.childForFieldName('operator')?.text !== '+') { partial = true; return '{?}'; }
        return walk(n.childForFieldName('left')!) + walk(n.childForFieldName('right')!);
      case 'parenthesized_expression': return namedOf(n)[0] ? walk(namedOf(n)[0]!) : '';
      case 'identifier': {
        const v = consts.get(n.text);
        if (v !== undefined) { folded = true; return v; }
        partial = true;
        return '{?}';
      }
      case 'call': {
        const f = n.childForFieldName('function');
        if (f?.type === 'attribute' && f.childForFieldName('attribute')?.text === 'format') {
          partial = true;
          return walk(f.childForFieldName('object')!).replace(/\{[^}]*\}/g, '{?}');
        }
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

function kwArg(args: Node[], name: string): Node | undefined {
  return args.find((a) => a.type === 'keyword_argument' && a.childForFieldName('name')?.text === name)?.childForFieldName('value') ?? undefined;
}

function extract(root: Node, path: string, out: Draft[], h: ConnectHelpers): void {
  const consts = new Map<string, string>();
  for (const st of namedOf(root)) {
    const a = st.type === 'expression_statement' ? namedOf(st)[0] : null;
    if (a?.type !== 'assignment' || a.childForFieldName('left')?.type !== 'identifier') continue;
    const v = fold(a.childForFieldName('right'), new Map());
    if (v && v.extraction === 'literal') consts.set(a.childForFieldName('left')!.text, v.text);
  }
  // Client instances → base URL ('' when none).
  const clients = new Map<string, Folded>();
  const bindClient = (name: string | undefined, value: Node | null | undefined) => {
    if (!name || value?.type !== 'call') return;
    const fn = value.childForFieldName('function')?.text ?? '';
    if (!CLIENT_CTOR.test(fn)) return;
    const base = kwArg(namedOf(value.childForFieldName('arguments')), 'base_url');
    clients.set(name, (base && fold(base, consts)) || { text: '', extraction: 'literal' });
  };
  for (const n of h.descendants(root)) {
    if (n.type === 'assignment') {
      const left = n.childForFieldName('left');
      const name = left?.type === 'identifier' ? left.text : left?.type === 'attribute' && left.childForFieldName('object')?.text === 'self' ? left.text : undefined;
      bindClient(name, n.childForFieldName('right'));
    } else if (n.type === 'as_pattern') {
      const target = n.childForFieldName('alias') ?? namedOf(n).find((c) => c.type === 'as_pattern_target');
      bindClient(target?.text, namedOf(n)[0]);
    }
  }
  for (const n of h.descendants(root)) {
    if (n.type !== 'call') continue;
    const fn = n.childForFieldName('function');
    const args = namedOf(n.childForFieldName('arguments'));
    if (!fn) continue;
    let method: string | undefined;
    let urlNode: Node | undefined;
    let base: Folded | undefined;
    let rule = 'python.http.client';
    if (fn.type === 'attribute') {
      const obj = fn.childForFieldName('object')?.text ?? '';
      const verb = fn.childForFieldName('attribute')?.text ?? '';
      const isModule = obj === 'requests' || obj === 'httpx';
      const client = clients.get(obj);
      if (!isModule && !client && !(obj === 'urllib.request' && verb === 'urlopen')) continue;
      if (verb === 'urlopen') { method = 'GET'; urlNode = args[0]; rule = 'python.urllib.urlopen'; }
      else if (VERBS.has(verb)) { method = verb.toUpperCase(); urlNode = args.find((a) => a.type !== 'keyword_argument') ?? kwArg(args, 'url'); }
      else if (verb === 'request' || verb === 'stream') {
        const pos = args.filter((a) => a.type !== 'keyword_argument');
        const m = fold(pos[0] ?? kwArg(args, 'method'), consts);
        method = m && m.extraction === 'literal' ? m.text.toUpperCase() : undefined;
        urlNode = pos[1] ?? kwArg(args, 'url');
      } else continue;
      base = client;
    } else if (fn.type === 'identifier' && fn.text === 'urlopen') {
      method = 'GET';
      urlNode = args[0];
      rule = 'python.urllib.urlopen';
    } else continue;
    const e = fold(urlNode, consts);
    if (!e) continue;
    const absolute = /^[a-z]+:\/\//i.test(e.text);
    const baseText = base?.text ?? '';
    const full = absolute || !baseText ? e.text : `${baseText.replace(/\/+$/, '')}/${e.text.replace(/^\/+/, '')}`;
    const u = h.splitUrl(full);
    const extraction: Extraction = base && !absolute && base.extraction !== 'literal' ? base.extraction : e.extraction;
    out.push({
      side: 'consumes', kind: 'http', key: { ...(method && VERBS.has(method.toLowerCase()) ? { method } : {}), pathTemplate: u.path },
      ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: h.line(n) }, ruleId: rule, extraction,
    });
  }
}

export const PYTHON_CLIENTS: ClientPlugin = {
  ext: /\.pyi?$/,
  prefilter: /\brequests\b|\bhttpx\b|\baiohttp\b|\burlopen\b/,
  extract,
};
