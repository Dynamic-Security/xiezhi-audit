// php outbound connection points: Guzzle (`new Client(['base_uri' => …])`,
// `$client->request('GET', $url)`, `->get($url)`), Symfony HttpClient, Laravel `Http::get(…)`, cURL
// (`curl_init($url)`, `curl_setopt($ch, CURLOPT_URL, …)`) and `file_get_contents('http…')`. URLs are folded from
// string literals, `.` concatenation, interpolation and same-file constants; unknown parts become `{?}`.
import type { Node } from 'web-tree-sitter';
import type { ClientPlugin, ConnectHelpers, Draft } from './extract.js';

type Extraction = Draft['extraction'];
interface Evaluated { text: string; extraction: Extraction }

const VERBS = new Set(['get', 'post', 'put', 'patch', 'delete', 'head', 'options']);
const CLIENT_RECEIVER = /client|guzzle|http|curl/i;

const named = (n: Node | null | undefined): Node[] => (n?.namedChildren ?? []).filter((c): c is Node => !!c);

function argValues(args: Node | null | undefined): Node[] {
  return named(args).map((a) => (a.type === 'argument' ? named(a).filter((c) => c.id !== a.childForFieldName('name')?.id).pop() : a)).filter((c): c is Node => !!c);
}

/** `const X = '…'`, class constants and `define('X', '…')` with literal values. */
function constantsOf(root: Node, h: ConnectHelpers): Map<string, string> {
  const out = new Map<string, string>();
  for (const n of h.descendants(root)) {
    if (n.type === 'const_element') {
      const [name, value] = named(n);
      if (name && value && value.type === 'string' && !named(value).some((c) => c.type !== 'string_content')) out.set(name.text, h.unq(value.text));
    } else if (n.type === 'function_call_expression' && n.childForFieldName('function')?.text === 'define') {
      const [name, value] = argValues(n.childForFieldName('arguments'));
      if (name?.type === 'string' && value?.type === 'string') out.set(h.unq(name.text), h.unq(value.text));
    }
  }
  return out;
}

function evaluate(node: Node | null | undefined, consts: Map<string, string>, h: ConnectHelpers): Evaluated | null {
  if (!node) return null;
  let partial = false;
  let folded = false;
  const walk = (n: Node): string => {
    switch (n.type) {
      case 'string': case 'encapsed_string': case 'heredoc': case 'nowdoc': {
        const parts = named(n).filter((c) => c.type !== 'heredoc_start' && c.type !== 'heredoc_end');
        if (!parts.length) return n.type === 'string' || n.type === 'encapsed_string' ? h.unq(n.text) : '';
        let out = '';
        for (const c of parts) {
          if (c.type === 'string_content' || c.type === 'string_value' || c.type === 'nowdoc_body') out += c.text;
          else if (c.type === 'heredoc_body') out += walk(c);
          else if (c.type === 'escape_sequence') out += c.text.length === 2 ? c.text[1] : '';
          else { partial = true; out += '{?}'; }
        }
        return out;
      }
      case 'heredoc_body': return named(n).map((c) => (c.type === 'string_content' ? c.text : (partial = true, '{?}'))).join('');
      case 'binary_expression':
        if (n.childForFieldName('operator')?.text !== '.') { partial = true; return '{?}'; }
        return walk(n.childForFieldName('left')!) + walk(n.childForFieldName('right')!);
      case 'parenthesized_expression': return named(n)[0] ? walk(named(n)[0]!) : '';
      case 'name': case 'class_constant_access_expression': {
        const v = consts.get(n.text.split('::').pop()!);
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

/** Guzzle / RFC 3986 style: an absolute path replaces the base path, a relative one is appended to its directory. */
function resolveAgainst(base: string, rel: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rel) || !base) return rel;
  const m = /^([a-z][a-z0-9+.-]*:\/\/[^/]*)(\/.*)?$/i.exec(base);
  const origin = m ? m[1]! : '';
  const basePath = m ? m[2] ?? '/' : base;
  if (rel.startsWith('/')) return origin + rel;
  return origin + basePath.slice(0, basePath.lastIndexOf('/') + 1) + rel;
}

function extract(root: Node, path: string, out: Draft[], h: ConnectHelpers): void {
  const consts = constantsOf(root, h);
  const bases = new Map<string, Evaluated>(); // client variable / property text → base_uri
  for (const n of h.descendants(root)) {
    if (n.type !== 'assignment_expression') continue;
    const right = n.childForFieldName('right');
    if (right?.type !== 'object_creation_expression') continue;
    const cls = named(right).find((c) => c.type === 'name' || c.type === 'qualified_name')?.text.split('\\').pop();
    if (cls !== 'Client') continue;
    const opts = argValues(named(right).find((c) => c.type === 'arguments'))[0];
    let base: Evaluated = { text: '', extraction: 'literal' };
    for (const el of named(opts)) {
      const [k, v] = named(el);
      if (k && v && /^['"]base_uri['"]$/.test(k.text)) base = evaluate(v, consts, h) ?? { text: '{?}', extraction: 'partial' };
    }
    bases.set(n.childForFieldName('left')!.text, base);
  }
  const push = (n: Node, method: string | undefined, urlNode: Node | undefined, base: Evaluated | undefined, ruleId: string) => {
    const e = evaluate(urlNode, consts, h);
    if (!e) return;
    const full = resolveAgainst(base?.text ?? '', e.text);
    const u = h.splitUrl(full);
    // A relative URL without any known base is someone else's path (e.g. cache keys): only absolute or rooted ones count.
    if (!u.host && !full.startsWith('/') && !full.startsWith('{?}/')) return;
    const extraction: Extraction = base?.extraction === 'partial' || e.extraction === 'partial' ? 'partial' : base?.extraction === 'constant_folded' ? 'constant_folded' : e.extraction;
    out.push({
      side: 'consumes', kind: 'http', key: { ...(method ? { method } : {}), pathTemplate: u.path },
      ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: h.line(n) }, ruleId, extraction,
    });
  };
  for (const n of h.descendants(root)) {
    if (n.type === 'member_call_expression' || n.type === 'nullsafe_member_call_expression' || n.type === 'scoped_call_expression') {
      const name = n.childForFieldName('name')?.text ?? '';
      const lower = name.toLowerCase();
      const recv = (n.childForFieldName('object') ?? n.childForFieldName('scope'))?.text ?? '';
      const args = argValues(n.childForFieldName('arguments'));
      const laravel = /^\\?(Illuminate\\Support\\Facades\\)?Http(::|$)/.test(recv);
      if (n.type === 'scoped_call_expression' && !laravel) continue;
      const base = bases.get(recv);
      if (!laravel && !base && !CLIENT_RECEIVER.test(recv)) continue;
      const rule = laravel ? 'php.laravel.http' : 'php.guzzle';
      if (VERBS.has(lower) || /^(get|post|put|patch|delete|head)async$/.test(lower)) push(n, lower.replace(/async$/, '').toUpperCase(), args[0], base, rule);
      else if ((lower === 'request' || lower === 'requestasync' || lower === 'send') && args.length >= 2 && args[0]!.type === 'string') push(n, h.unq(args[0]!.text).toUpperCase(), args[1], base, rule);
    } else if (n.type === 'function_call_expression') {
      const fn = n.childForFieldName('function')?.text.replace(/^\\/, '') ?? '';
      const args = argValues(n.childForFieldName('arguments'));
      if (fn === 'curl_setopt' && args[1]?.text === 'CURLOPT_URL') push(n, undefined, args[2], undefined, 'php.curl');
      else if (fn === 'curl_init' && args[0]) push(n, undefined, args[0], undefined, 'php.curl');
      else if ((fn === 'file_get_contents' || fn === 'fopen') && args[0] && /^['"]https?:\/\//.test(args[0].text)) push(n, 'GET', args[0], undefined, 'php.file_get_contents');
    }
  }
}

export const PHP_CLIENTS: ClientPlugin = {
  ext: /\.(php|phtml)$/,
  prefilter: /curl_|Client|Http::|file_get_contents\s*\(\s*['"]https?:|fopen\s*\(\s*['"]https?:|->(request|get|post)\s*\(/,
  extract,
};
