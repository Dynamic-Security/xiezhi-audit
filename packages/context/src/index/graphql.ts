// GraphQL schemas of the snapshot: SDL files (`.graphql`, `.graphqls`, `.gql`) and `gql` / `graphql`
// tagged templates in JS / TS. The resolvers the extractors find (Go gqlgen, Java Spring for GraphQL / DGS /
// graphql-java-kickstart, JS Apollo resolver maps and NestJS / TypeGraphQL decorators) become `rpc` entries keyed
// `rpc:graphql:<Type>/<field>`; the schema supplies the root types, argument lists and directives (auth signals).
// Text scan; never executed.
import type { SnapshotView } from '../snapshot/view.js';

export interface GraphqlField {
  name: string;
  /** Argument list as written, without the parentheses, whitespace collapsed (`albumID: Int!, expire: Time`). */
  args: string;
  /** Return type as written (`ShareToken!`). */
  type: string;
  /** Directives on the field and on its type (`@isAuthorized`, `@isAdmin`). */
  directives: string[];
}

export interface GraphqlSchema {
  /** Root operation types: `query` / `mutation` / `subscription` → type name. */
  roots: { query: string; mutation: string; subscription: string };
  /** Object types (and their extensions) → fields. */
  types: Record<string, GraphqlField[]>;
}

const SDL_FILE = /\.(graphqls?|gql)$/i;
const TAGGED = /\b(?:gql|graphql)\s*`([^`]*)`/g;

/** Remove comments and descriptions (`"""…"""`, `"…"` before definitions); string defaults become `""`. */
function clean(text: string): string {
  // Descriptions go; a string default value (`= "x"`) keeps an empty literal.
  return text.replace(/"""[\s\S]*?"""/g, ' ').replace(/(=\s*)?"(?:[^"\\\n]|\\.)*"/g, (_, eq: string | undefined) => (eq ? `${eq}""` : ' ')).replace(/#[^\n]*/g, '');
}

/** Index of the bracket closing the one at `open` (same kind), or -1. */
function closing(s: string, open: number): number {
  const o = s[open]!;
  const c = o === '{' ? '}' : o === '(' ? ')' : ']';
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === o) depth++;
    else if (s[i] === c && --depth === 0) return i;
  }
  return -1;
}

/** Directive uses in `s` (`@name` or `@name(…)`), as written with whitespace collapsed. */
function directivesIn(s: string): string[] {
  const out: string[] = [];
  const re = /@(\w+)/g;
  for (let m = re.exec(s); m; m = re.exec(s)) {
    let end = m.index + m[0].length;
    const after = /^\s*\(/.exec(s.slice(end));
    if (after) {
      const close = closing(s, end + after[0].length - 1);
      if (close > 0) end = close + 1;
    }
    out.push(s.slice(m.index, end).replace(/\s+/g, ' '));
    re.lastIndex = end;
  }
  return out;
}

/** Fields of a type body (between the braces). */
export function parseFields(body: string, typeDirectives: string[] = []): GraphqlField[] {
  const out: GraphqlField[] = [];
  let i = 0;
  while (i < body.length) {
    const m = /[A-Za-z_]\w*/.exec(body.slice(i));
    if (!m) break;
    const name = m[0];
    i += m.index + name.length;
    let args = '';
    const open = /^\s*\(/.exec(body.slice(i));
    if (open) {
      const start = i + open[0].length - 1;
      const close = closing(body, start);
      if (close < 0) break;
      // Commas are optional in SDL: a new `name:` starts the next argument.
      args = body.slice(start + 1, close).replace(/\s+/g, ' ').replace(/ (?=[A-Za-z_]\w*\s*:)/g, ',').split(',').map((t) => t.trim()).filter(Boolean).join(', ');
      i = close + 1;
    }
    const colon = /^\s*:\s*/.exec(body.slice(i));
    if (!colon) continue; // not a field (stray token)
    i += colon[0].length;
    const type = /^\[*\s*\w+\s*!?(\s*\]\s*!?)*/.exec(body.slice(i))?.[0] ?? '';
    i += type.length;
    // Directives (`@name` / `@name(…)`) up to the next field.
    const directives: string[] = [];
    for (let d = /^\s*@(\w+)/.exec(body.slice(i)); d; d = /^\s*@(\w+)/.exec(body.slice(i))) {
      const at = i + d[0].indexOf('@');
      i += d[0].length;
      const paren = /^\s*\(/.exec(body.slice(i));
      if (paren) {
        const close = closing(body, i + paren[0].length - 1);
        if (close < 0) break;
        i = close + 1;
      }
      directives.push(body.slice(at, i).replace(/\s+/g, ' '));
    }
    out.push({ name, args, type: type.replace(/\s+/g, ''), directives: [...typeDirectives, ...directives] });
  }
  return out;
}

export function scanGraphql(text: string, into?: GraphqlSchema): GraphqlSchema {
  const schema: GraphqlSchema = into ?? { roots: { query: 'Query', mutation: 'Mutation', subscription: 'Subscription' }, types: {} };
  const s = clean(text);
  const sch = /\b(?:extend\s+)?schema\b[^{]*\{([^}]*)\}/.exec(s);
  if (sch) {
    for (const m of sch[1]!.matchAll(/\b(query|mutation|subscription)\s*:\s*(\w+)/g)) schema.roots[m[1] as 'query' | 'mutation' | 'subscription'] = m[2]!;
  }
  const re = /\b(?:extend\s+)?type\s+([A-Za-z_]\w*)([^{]*)\{/g;
  for (let m = re.exec(s); m; m = re.exec(s)) {
    const open = m.index + m[0].length - 1;
    const close = closing(s, open);
    if (close < 0) break;
    const typeDirectives = directivesIn(m[2] ?? '');
    (schema.types[m[1]!] ??= []).push(...parseFields(s.slice(open + 1, close), typeDirectives));
    re.lastIndex = close + 1;
  }
  return schema;
}

/** The snapshot's GraphQL schema, or null when it declares none. */
export function graphqlSchemaOf(view: SnapshotView): GraphqlSchema | null {
  let schema: GraphqlSchema | null = null;
  for (const f of view.listFiles()) {
    if (f.size > 2 * 1024 * 1024) continue;
    const sdl = SDL_FILE.test(f.path);
    if (!sdl && f.lang !== 'javascript' && f.lang !== 'typescript') continue;
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    if (sdl) { schema = scanGraphql(text, schema ?? undefined); continue; }
    if (!/\b(?:gql|graphql)\s*`/.test(text)) continue;
    for (const m of text.matchAll(TAGGED)) if (/\btype\s+\w+/.test(m[1]!)) schema = scanGraphql(m[1]!, schema ?? undefined);
  }
  return schema && Object.keys(schema.types).length ? schema : null;
}

/** Field names compare without case and underscores (gqlgen `albumID` ↔ `AlbumID`, `user_id` ↔ `UserID`). */
export const fieldKey = (name: string): string => name.replace(/_/g, '').toLowerCase();

/** The schema field of `type` matching a resolver name, or null when the schema does not declare it. */
export function schemaField(schema: GraphqlSchema | undefined, type: string, name: string): GraphqlField | null {
  return schema?.types[type]?.find((f) => fieldKey(f.name) === fieldKey(name)) ?? null;
}

/** Root type of `type` (query / mutation / subscription), or null for an object type. */
export function rootKind(schema: GraphqlSchema | undefined, type: string): 'query' | 'mutation' | 'subscription' | null {
  const roots = schema?.roots ?? { query: 'Query', mutation: 'Mutation', subscription: 'Subscription' };
  return type === roots.query ? 'query' : type === roots.mutation ? 'mutation' : type === roots.subscription ? 'subscription' : null;
}

/**
 * The raw entry fields for a resolver of `Type.field`: key `rpc:graphql:<Type>/<field>` (schema spelling when the
 * schema declares it), the signature as `pathTemplate`, schema directives as middlewares. Without a schema the
 * resolver's own name is used; with a schema that does not declare the field, null (a helper, not a resolver).
 */
export function graphqlEntryOf(schema: GraphqlSchema | undefined, rawType: string, name: string): { rpc: { service: string; method: string }; pathTemplate: string; directives: string[]; root: boolean } | null {
  // Type names as the schema spells them (DGS constants `DgsConstants.SHOW.TYPE_NAME` arrive as `SHOW`).
  const type = schema && !schema.types[rawType] ? Object.keys(schema.types).find((t) => t.toLowerCase() === rawType.toLowerCase()) ?? rawType : rawType;
  const f = schemaField(schema, type, name);
  if (schema?.types[type] && !f) return null;
  const field = f?.name ?? name;
  return {
    rpc: { service: `graphql:${type}`, method: field },
    pathTemplate: f ? `${type}.${field}(${f.args}): ${f.type}` : `${type}.${field}`,
    directives: f?.directives ?? [],
    root: rootKind(schema, type) !== null,
  };
}

/** Whether a GraphQL entry changes state or addresses an object by id (`rpc:graphql:Mutation/…`, `…(id: ID!)`). */
export function graphqlStateOrById(entryKey: string, pathTemplate: string | undefined, mutationType = 'Mutation'): boolean {
  if (!entryKey.startsWith('rpc:graphql:')) return false;
  if (entryKey.startsWith(`rpc:graphql:${mutationType}/`)) return true;
  const args = /\(([^)]*)\)/.exec(pathTemplate ?? '')?.[1] ?? '';
  return /(^|,\s*)\w*(id|ids|token|key)\s*:/i.test(args);
}
