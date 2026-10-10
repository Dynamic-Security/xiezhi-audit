// C# outbound connection points: HttpClient calls (with BaseAddress from an object
// initializer, an assignment, or `AddHttpClient("name", c => c.BaseAddress = …)` + `CreateClient("name")` in the same
// file), `new HttpRequestMessage(HttpMethod.X, url)`, RestSharp `new RestRequest("path", Method.X)` and Refit
// interfaces (`[Get("/users/{id}")]`). Only same-file facts are used.
import type { Node } from 'web-tree-sitter';
import type { ClientPlugin, ConnectHelpers, Draft } from './extract.js';

type Extraction = NonNullable<Draft['extraction']>;
interface Evaluated { text: string; extraction: Extraction }

const HTTP_CLIENT_METHODS: Record<string, string | null> = {
  GetAsync: 'GET', GetStringAsync: 'GET', GetByteArrayAsync: 'GET', GetStreamAsync: 'GET', GetFromJsonAsync: 'GET',
  PostAsync: 'POST', PostAsJsonAsync: 'POST', PutAsync: 'PUT', PutAsJsonAsync: 'PUT', PatchAsync: 'PATCH', PatchAsJsonAsync: 'PATCH',
  DeleteAsync: 'DELETE', DeleteFromJsonAsync: 'DELETE',
};
const REFIT_VERBS: Record<string, string> = { Get: 'GET', Post: 'POST', Put: 'PUT', Delete: 'DELETE', Patch: 'PATCH', Head: 'HEAD', Options: 'OPTIONS' };

const kids = (n: Node | null | undefined): Node[] => (n ? n.namedChildren.filter((c): c is Node => !!c) : []);

function argExprs(list: Node | null | undefined): Node[] {
  return kids(list).filter((a) => a.type === 'argument').map((a) => { const k = kids(a); return k[k.length - 1]; }).filter((x): x is Node => !!x);
}

function literal(n: Node): string {
  if (n.type === 'verbatim_string_literal') return n.text.slice(2, -1).replace(/""/g, '"');
  if (n.type === 'raw_string_literal') return n.text.replace(/^"{3,}/, '').replace(/"{3,}$/, '');
  return n.text.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

function worse(a: Extraction, b: Extraction): Extraction {
  const rank: Record<Extraction, number> = { literal: 0, constant_folded: 1, partial: 2 };
  return (rank[a] ?? 0) >= (rank[b] ?? 0) ? a : b;
}

/** C# string folding: literals, `+`, interpolated strings (holes → `{?}`), same-file constants, `new Uri(x)`. */
function evaluate(node: Node | null | undefined, consts: Map<string, string>): Evaluated | null {
  if (!node) return null;
  let extraction: Extraction = 'literal';
  const walk = (n: Node): string => {
    switch (n.type) {
      case 'string_literal': case 'verbatim_string_literal': case 'raw_string_literal':
        return literal(n);
      case 'interpolated_string_expression':
        return kids(n).map((c) => {
          if (c.type === 'string_content') return c.text;
          if (c.type === 'interpolation') {
            const expr = kids(c).find((x) => !/^interpolation_(brace|format_clause|alignment_clause)$/.test(x.type));
            if (expr) return walk(expr);
            extraction = 'partial';
            return '{?}';
          }
          return '';
        }).join('');
      case 'binary_expression': {
        const l = n.childForFieldName('left');
        const r = n.childForFieldName('right');
        if (!l || !r) { extraction = 'partial'; return '{?}'; }
        return walk(l) + walk(r);
      }
      case 'parenthesized_expression': return kids(n)[0] ? walk(kids(n)[0]!) : '';
      case 'object_creation_expression': {
        // new Uri("http://…") / new Uri(baseUri, "path")
        const args = argExprs(n.childForFieldName('arguments'));
        if (/(^|\.)Uri$/.test(n.childForFieldName('type')?.text ?? '') && args.length) return args.map(walk).join('');
        extraction = 'partial';
        return '{?}';
      }
      case 'identifier': case 'member_access_expression': {
        const name = n.text.split('.').pop()!;
        const v = consts.get(name);
        if (v !== undefined) { extraction = worse(extraction, 'constant_folded'); return v; }
        extraction = 'partial';
        return '{?}';
      }
      default:
        extraction = 'partial';
        return '{?}';
    }
  };
  const text = walk(node);
  if (!/[a-z0-9/]/i.test(text.replace(/\{\?\}/g, ''))) return null;
  return { text, extraction };
}

function constantsOf(root: Node, h: ConnectHelpers): Map<string, string> {
  const out = new Map<string, string>();
  for (const n of h.descendants(root)) {
    if (n.type !== 'variable_declarator') continue;
    const name = n.childForFieldName('name');
    const value = kids(n).filter((c) => c.id !== name?.id).pop();
    if (name && value && /string_literal$/.test(value.type)) out.set(name.text, literal(value));
  }
  return out;
}

function joinUrl(base: string, rel: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rel)) return rel;
  if (!base) return rel;
  return `${base.replace(/\/+$/, '')}/${rel.replace(/^\/+/, '')}`;
}

function extract(root: Node, path: string, out: Draft[], h: ConnectHelpers): void {
  const consts = constantsOf(root, h);
  const all = [...h.descendants(root)];
  const push = (method: string | null, url: Evaluated, n: Node, ruleId: string, base?: Evaluated) => {
    const full = base ? joinUrl(base.text, url.text) : url.text;
    const u = h.splitUrl(full.startsWith('/') || /^[a-z][a-z0-9+.-]*:\/\//i.test(full) || full.startsWith('{?}') ? full : `/${full}`);
    out.push({
      side: 'consumes', kind: 'http', key: { ...(method ? { method } : {}), pathTemplate: u.path },
      ...(u.host ? { serviceHint: u.host } : {}), site: { path, line: h.line(n) }, ruleId,
      extraction: base ? worse(url.extraction, base.extraction) : url.extraction,
    });
  };

  // ---- base addresses: named clients, variables / fields, file default ----
  const named = new Map<string, Evaluated>();
  const byVar = new Map<string, Evaluated>();
  const loose: Evaluated[] = [];
  for (const n of all) {
    if (n.type !== 'assignment_expression') continue;
    const left = n.childForFieldName('left');
    const lname = left?.type === 'member_access_expression' ? left.childForFieldName('name')?.text : left?.text;
    if (lname !== 'BaseAddress') continue;
    const value = evaluate(n.childForFieldName('right'), consts);
    if (!value) continue;
    // AddHttpClient("name", c => c.BaseAddress = …) / AddHttpClient<TClient>(c => …)
    let registered = false;
    for (let p: Node | null = n.parent; p; p = p.parent) {
      if (p.type !== 'invocation_expression') continue;
      const fn = p.childForFieldName('function');
      const m = fn?.type === 'member_access_expression' ? fn.childForFieldName('name') : null;
      const mName = m?.type === 'generic_name' ? m.namedChildren[0]?.text : m?.text;
      if (mName !== 'AddHttpClient') continue;
      const first = argExprs(p.childForFieldName('arguments'))[0];
      const key = first && /string_literal$/.test(first.type) ? literal(first) : m?.type === 'generic_name' ? m.namedChildren[1]?.namedChildren[0]?.text : undefined;
      if (key) { named.set(key, value); registered = true; }
      break;
    }
    if (registered) continue;
    // new HttpClient { BaseAddress = … } assigned to a variable / field, or `x.BaseAddress = …`.
    let owner: string | undefined;
    if (left?.type === 'member_access_expression') owner = left.childForFieldName('expression')?.text.replace(/^this\./, '');
    else {
      const decl = n.parent?.parent?.parent; // initializer_expression → object_creation → variable_declarator / assignment
      if (decl?.type === 'variable_declarator') owner = decl.childForFieldName('name')?.text;
      else if (decl?.type === 'assignment_expression') owner = decl.childForFieldName('left')?.text.replace(/^this\./, '');
    }
    if (owner) byVar.set(owner, value);
    loose.push(value);
  }
  // var client = factory.CreateClient("name");
  for (const n of all) {
    if (n.type !== 'variable_declarator' && n.type !== 'assignment_expression') continue;
    const target = n.type === 'variable_declarator' ? n.childForFieldName('name')?.text : n.childForFieldName('left')?.text.replace(/^this\./, '');
    const value = n.type === 'variable_declarator' ? kids(n).filter((c) => c.id !== n.childForFieldName('name')?.id).pop() : n.childForFieldName('right');
    if (!target || value?.type !== 'invocation_expression') continue;
    const fn = value.childForFieldName('function');
    if (fn?.type !== 'member_access_expression' || fn.childForFieldName('name')?.text !== 'CreateClient') continue;
    const key = argExprs(value.childForFieldName('arguments'))[0];
    const base = key && /string_literal$/.test(key.type) ? named.get(literal(key)) : undefined;
    if (base) byVar.set(target, base);
  }
  const fileBase = loose.length === 1 && named.size === 0 ? loose[0] : named.size === 1 && loose.length === 0 ? [...named.values()][0] : undefined;
  const baseFor = (receiver: Node | null): Evaluated | undefined => {
    const r = receiver?.text.replace(/^this\./, '');
    return (r ? byVar.get(r) : undefined) ?? fileBase;
  };

  for (const n of all) {
    if (n.type === 'invocation_expression') {
      const fn = n.childForFieldName('function');
      if (fn?.type !== 'member_access_expression') continue;
      const nameNode = fn.childForFieldName('name');
      const name = nameNode?.type === 'generic_name' ? nameNode.namedChildren[0]?.text : nameNode?.text;
      if (!name || !(name in HTTP_CLIENT_METHODS)) continue;
      const receiver = fn.childForFieldName('expression');
      if (!receiver || !/http|client/i.test(receiver.text)) continue;
      const url = evaluate(argExprs(n.childForFieldName('arguments'))[0], consts);
      if (url) push(HTTP_CLIENT_METHODS[name] ?? null, url, n, 'csharp.httpclient', baseFor(receiver));
    } else if (n.type === 'object_creation_expression') {
      const type = (n.childForFieldName('type')?.text ?? '').split('.').pop();
      const args = argExprs(n.childForFieldName('arguments'));
      if (type === 'HttpRequestMessage' && args.length >= 2) {
        const verb = /HttpMethod\.(\w+)/.exec(args[0]!.text)?.[1]?.toUpperCase() ?? null;
        const url = evaluate(args[1], consts);
        if (url) push(verb, url, n, 'csharp.httprequestmessage', fileBase);
      } else if (type === 'RestRequest' && args.length >= 1) {
        const verb = args.slice(1).map((a) => /Method\.(\w+)/.exec(a.text)?.[1]?.toUpperCase()).find(Boolean) ?? 'GET';
        const url = evaluate(args[0], consts);
        const client = all.find((c) => c.type === 'object_creation_expression' && /(^|\.)RestClient$/.test(c.childForFieldName('type')?.text ?? ''));
        const base = client ? evaluate(argExprs(client.childForFieldName('arguments'))[0], consts) ?? undefined : undefined;
        if (url) push(verb, url, n, 'csharp.restsharp', base);
      }
    } else if (n.type === 'method_declaration' && n.parent?.parent?.type === 'interface_declaration') {
      // Refit: [Get("/users/{id}")] Task<User> GetUser(int id);
      for (const list of kids(n)) {
        if (list.type !== 'attribute_list') continue;
        for (const a of kids(list)) {
          const verb = REFIT_VERBS[(a.childForFieldName('name')?.text ?? '').replace(/Attribute$/, '')];
          if (!verb) continue;
          const arg = kids(kids(a).find((c) => c.type === 'attribute_argument_list')).find((c) => c.type === 'attribute_argument');
          const url = evaluate(kids(arg).pop(), consts);
          if (url) push(verb, url, n, 'csharp.refit');
        }
      }
    }
  }
}

export const CSHARP_CLIENTS: ClientPlugin = {
  ext: /\.cs$/,
  prefilter: /HttpClient|GetAsync|PostAsync|PutAsync|DeleteAsync|SendAsync|GetStringAsync|HttpRequestMessage|RestRequest|Refit|\[(Get|Post|Put|Delete|Patch)\(/,
  extract,
};
