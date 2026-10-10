// Java web facts that live outside the handler's file — `web.xml` servlet / filter mappings and
// security constraints, `@WebFilter` classes, Struts 2 `struts*.xml` actions — read once per snapshot by text scan
// (no XML parser), and the JSP template sinks. Plain data in `ExtractInput.langContext`; only Java files that can use
// them get it (servlet / action classes by simple name, or files mentioning servlets / Struts), so other repositories'
// extraction inputs are unchanged.
import type { Sink } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';
import type { RuleDef } from './rules.js';

export interface UrlFilter { name: string; patterns: string[] }
export interface StrutsAction { route: string; method: string | null; interceptors: string[] }
export interface JavaWebContext {
  /** Servlet class (FQCN, or simple name) → `web.xml` url patterns. */
  servlets?: Record<string, string[]>;
  /** Filters with their url patterns (`web.xml` `<filter-mapping>` and `@WebFilter`), in declaration order. */
  filters?: UrlFilter[];
  /** `web.xml` `<security-constraint>`: url patterns and the roles required (empty = authenticated or none declared). */
  constraints?: { patterns: string[]; roles: string[] }[];
  /** Struts 2 action class (FQCN, or capitalized Spring bean name) → actions. */
  struts?: Record<string, StrutsAction[]>;
  /** Struts 2 action extension (`.action` unless `struts.action.extension` says otherwise). */
  strutsExt?: string;
}

const MAX_BYTES = 2 * 1024 * 1024;
const tag = (body: string, name: string): string[] => [...body.matchAll(new RegExp(`<${name}(?=[\\s>])[^>]*>\\s*([^<]*?)\\s*</${name}>`, 'g'))].map((m) => m[1]!);
const blocks = (text: string, name: string): string[] => [...text.matchAll(new RegExp(`<${name}(?=[\\s>])[^>]*>([\\s\\S]*?)</${name}>`, 'g'))].map((m) => m[1]!);
const attr = (open: string, name: string): string | null => new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`).exec(open)?.[1] ?? null;
const stripComments = (t: string) => t.replace(/<!--[\s\S]*?-->/g, '');

const cache = new WeakMap<SnapshotView, (path: string) => JavaWebContext | null>();

/** Module of a file: the path before its first `src/` segment ('' = repository root; multi-module builds keep facts apart). */
export function moduleOfPath(path: string): string {
  const m = /(^|\/)src\//.exec(path);
  return m ? path.slice(0, m.index) : '';
}

interface ModuleFacts {
  servlets: Record<string, string[]>;
  filters: UrlFilter[];
  constraints: { patterns: string[]; roles: string[] }[];
  struts: Record<string, StrutsAction[]>;
  strutsExt?: string;
}

export function javaWebContexts(view: SnapshotView): (path: string) => JavaWebContext | null {
  const hit = cache.get(view);
  if (hit) return hit;
  const files = view.listFiles();
  const read = (path: string, size: number): string | null => {
    if (size > MAX_BYTES) return null;
    try { return view.text(path); } catch { return null; }
  };
  const modules = new Map<string, ModuleFacts>();
  const factsOf = (path: string): ModuleFacts => {
    const mod = moduleOfPath(path);
    let m = modules.get(mod);
    if (!m) { m = { servlets: {}, filters: [], constraints: [], struts: {} }; modules.set(mod, m); }
    return m;
  };
  const extOf = (value: string) => (value.split(',')[0]!.trim() ? `.${value.split(',')[0]!.trim()}` : '');
  for (const f of files) {
    const base = f.path.split('/').pop() ?? '';
    if (base === 'web.xml' || base === 'web-fragment.xml') {
      const text = read(f.path, f.size);
      if (!text) continue;
      const t = stripComments(text);
      const mf = factsOf(f.path);
      const classOf = new Map<string, string>();
      for (const s of blocks(t, 'servlet')) {
        const name = tag(s, 'servlet-name')[0];
        const cls = tag(s, 'servlet-class')[0];
        if (name && cls) classOf.set(name, cls);
      }
      for (const m of blocks(t, 'servlet-mapping')) {
        const cls = classOf.get(tag(m, 'servlet-name')[0] ?? '');
        if (cls) mf.servlets[cls] = [...(mf.servlets[cls] ?? []), ...tag(m, 'url-pattern')];
      }
      const filterClass = new Map<string, string>();
      for (const s of blocks(t, 'filter')) {
        const name = tag(s, 'filter-name')[0];
        const cls = tag(s, 'filter-class')[0];
        if (name) filterClass.set(name, cls ?? name);
      }
      for (const m of blocks(t, 'filter-mapping')) {
        const name = tag(m, 'filter-name')[0];
        if (!name) continue;
        const cls = filterClass.get(name)?.split('.').pop() ?? name;
        const patterns = [...tag(m, 'url-pattern'), ...tag(m, 'servlet-name').map((sn) => `servlet:${sn}`)];
        mf.filters.push({ name: name === cls ? name : `${name}(${cls})`, patterns });
      }
      for (const c of blocks(t, 'security-constraint')) {
        const patterns = blocks(c, 'web-resource-collection').flatMap((w) => tag(w, 'url-pattern'));
        const authBlock = blocks(c, 'auth-constraint');
        if (!patterns.length || !authBlock.length) continue;
        mf.constraints.push({ patterns, roles: authBlock.flatMap((a) => tag(a, 'role-name')) });
      }
    } else if (/^struts[\w-]*\.xml$/.test(base)) {
      const text = read(f.path, f.size);
      if (!text || !/<struts\b/.test(text)) continue;
      const t = stripComments(text);
      const mf = factsOf(f.path);
      const ext = /<constant\s+name="struts\.action\.extension"\s+value="([^"]*)"/.exec(t)?.[1];
      if (ext !== undefined) mf.strutsExt = extOf(ext);
      for (const pkg of t.matchAll(/<package\b([^>]*)>([\s\S]*?)<\/package>/g)) {
        const ns = attr(pkg[1]!, 'namespace') ?? '';
        const pkgDefault = /<default-interceptor-ref\s+name="([^"]+)"/.exec(pkg[2]!)?.[1];
        for (const a of pkg[2]!.matchAll(/<action\b([^>]*?)(?:\/>|>([\s\S]*?)<\/action>)/g)) {
          const name = attr(a[1]!, 'name');
          const cls = attr(a[1]!, 'class') ?? 'com.opensymphony.xwork2.ActionSupport';
          if (name === null) continue;
          const refs = [...(a[2] ?? '').matchAll(/<interceptor-ref\s+name="([^"]+)"/g)].map((r) => r[1]!);
          const interceptors = refs.length ? refs : pkgDefault ? [pkgDefault] : [];
          const key = cls.includes('.') ? cls : cls.charAt(0).toUpperCase() + cls.slice(1);
          (mf.struts[key] ??= []).push({ route: `${ns.replace(/\/$/, '')}/${name}`, method: attr(a[1]!, 'method'), interceptors: interceptors.map((i) => `interceptor-ref: ${i}`) });
        }
      }
    } else if (base === 'struts.properties') {
      const text = read(f.path, f.size);
      const ext = text ? /^\s*struts\.action\.extension\s*=\s*([^\n]*)$/m.exec(text)?.[1] : undefined;
      const mf = ext !== undefined ? factsOf(f.path) : null;
      if (mf && ext !== undefined && mf.strutsExt === undefined) mf.strutsExt = extOf(ext);
    }
  }
  // `@WebFilter(urlPatterns = …)` classes, in repositories that use the servlet API.
  const javaFiles = files.filter((f) => f.lang === 'java');
  if (modules.size || javaFiles.some((f) => /Servlet|Filter/.test(f.path))) {
    for (const f of javaFiles) {
      const text = read(f.path, f.size);
      if (!text || !text.includes('@WebFilter')) continue;
      const ann = /@WebFilter\s*(\(([^)]*)\))?/.exec(text);
      const cls = /\bclass\s+(\w+)/.exec(text)?.[1] ?? f.path;
      const args = ann?.[2] ?? '';
      const patterns = [...(/(?:urlPatterns|value)\s*=\s*(\{[^}]*\}|"[^"]*")/.exec(args)?.[1] ?? (/^\s*("[^"]*"|\{[^}]*\})/.exec(args)?.[1] ?? '')).matchAll(/"([^"]*)"/g)].map((m) => m[1]!);
      factsOf(f.path).filters.push({ name: cls, patterns: patterns.length ? patterns : ['/*'] });
    }
  }
  const fn = (path: string): JavaWebContext | null => {
    if (!modules.size || !path.endsWith('.java')) return null;
    const simple = path.split('/').pop()!.replace(/\.java$/, '');
    const pick = <V>(rec: Record<string, V>, qualifiedOnly = false): Record<string, V> | undefined => {
      const keys = Object.keys(rec).filter((k) => (!qualifiedOnly && k === simple) || k.endsWith(`.${simple}`));
      return keys.length ? Object.fromEntries(keys.map((k) => [k, rec[k]!])) : undefined;
    };
    let mf = modules.get(moduleOfPath(path)) ?? modules.get('');
    let s = mf ? pick(mf.servlets) : undefined;
    let a = mf ? pick(mf.struts) : undefined;
    if (!s && !a) {
      // A class mapped by another module's descriptor (a war module packaging a servlet from a core module): by FQCN only.
      for (const other of modules.values()) {
        s = pick(other.servlets, true);
        a = pick(other.struts, true);
        if (s || a) { mf = other; break; }
      }
    }
    if (!mf) return null;
    if (!s && !a) {
      const f = javaFiles.find((x) => x.path === path);
      const text = f ? read(path, f.size) ?? '' : '';
      if (!/\bextends\s+\w*Servlet\b|@WebServlet\b|org\.apache\.struts2|com\.opensymphony\.xwork2/.test(text)) return null;
    }
    return {
      ...(s ? { servlets: s } : {}), ...(a ? { struts: a } : {}),
      ...(mf.filters.length ? { filters: mf.filters } : {}), ...(mf.constraints.length ? { constraints: mf.constraints } : {}),
      ...(mf.strutsExt !== undefined ? { strutsExt: mf.strutsExt } : {}),
    };
  };
  cache.set(view, fn);
  return fn;
}

/** Servlet url-pattern match: exact, `/prefix/*`, `*.ext`, `/` and `/*` (everything). */
export function urlPatternCovers(pattern: string, route: string): boolean {
  if (pattern === '/' || pattern === '/*') return true;
  if (pattern.endsWith('/*')) { const p = pattern.slice(0, -2); return route === p || route.startsWith(p + '/'); }
  if (pattern.startsWith('*.')) return route.endsWith(pattern.slice(1));
  return route === pattern;
}

// ---- JSP template sinks --------------------------------------------------------------------------------------------

export interface JspFile { path: string; text: string }

const REQUEST_EL = /\$\{\s*(param|paramValues|header|headerValues|cookie)\b[^}]*\}/g;
/** `<%= … %>` with request data; `<%= x %>` of other values is not reported (escaping is the template's job everywhere). */
const SCRIPTLET_OUT = /<%=([\s\S]*?)%>/g;
const REQUEST_JAVA = /\brequest\s*\.\s*(getParameter|getParameterValues|getHeader|getQueryString|getRequestURI|getAttribute|getCookies)\b/;
/** EL inside these is escaped / not output as markup. */
const SAFE_EL_CONTEXT = /<c:out\b[^>]*$|fn:escapeXml\([^)]*$|<(c:if|c:when|c:set|c:forEach|c:choose|fmt:\w+)\b[^>]*$/;

/** Scriptlet (not `<%=`, `<%@`, `<%!`, `<%--`) bodies. */
const SCRIPTLET = /<%(?![=@!-])([\s\S]*?)%>/g;
const REQUEST_VAR = /\b(\w+)\s*=\s*(?:\(\s*[\w.]+\s*\)\s*)?request\s*\.\s*(?:getParameter|getParameterValues|getHeader|getQueryString)\s*\(/g;
const SQL_CALL = /\.\s*(executeQuery|executeUpdate|execute|addBatch|prepareStatement|prepareCall)\s*\(/g;

/** The argument text of the call whose `(` is at `open` (strings and nested parentheses balanced). */
function callArgText(text: string, open: number): string | null {
  let depth = 0;
  let quote: string | null = null;
  for (let i = open; i < Math.min(text.length, open + 4000); i++) {
    const ch = text[i]!;
    if (quote) { if (ch === '\\') i++; else if (ch === quote) quote = null; continue; }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '(') depth++;
    else if (ch === ')' && --depth === 0) return text.slice(open + 1, i);
  }
  return null;
}
const CONCAT_RE = /["']\s*\+|\+\s*["']/;

/**
 * JSP templates (text scan; scriptlets are not parsed as Java, so there are no symbols or call edges):
 * - `jsp_reflected_xss`: `${param.x}` / `${header.x}` / `${cookie.x}` outside `<c:out>` / `fn:escapeXml`, and `<%= … %>`
 *   reading request data directly or through a scriptlet variable assigned from it (`String q = request.getParameter("q")`);
 * - `jsp_scriptlet_sql`: JDBC calls in scriptlets whose SQL argument is concatenated (`"… '" + q + "'"`).
 */
export function jspSinks(repo: string, files: JspFile[], rules: RuleDef[]): Sink[] {
  const out: Sink[] = [];
  const seen = new Set<string>();
  const xssRule = rules.find((r) => r.post === 'jsp_reflected_xss');
  const sqlRule = rules.find((r) => r.post === 'jsp_scriptlet_sql');
  for (const f of files) {
    const lineAt = (idx: number) => f.text.slice(0, idx).split('\n').length;
    const add = (rule: RuleDef, idx: number, len: number, api: string, taint: string) => {
      const line = lineAt(idx);
      const sinkId = `${repo}:${f.path}#L${line}:${idx - f.text.lastIndexOf('\n', idx - 1)}:${rule.category ?? 'other'}`;
      if (seen.has(sinkId)) return;
      seen.add(sinkId);
      out.push({ sinkId, category: rule.category ?? 'other', symbolId: null, path: f.path, range: { startLine: line, endLine: lineAt(idx + len) }, api, taintHint: taint, ruleId: rule.id });
    };
    const vars = new Set([...f.text.matchAll(REQUEST_VAR)].map((m) => m[1]!));
    if (xssRule) {
      for (const m of f.text.matchAll(REQUEST_EL)) {
        const before = f.text.slice(Math.max(0, m.index! - 200), m.index!);
        if (SAFE_EL_CONTEXT.test(before)) continue;
        add(xssRule, m.index!, m[0].length, `jsp:${m[0].replace(/\s+/g, '').slice(0, 80)}`, 'request_data');
      }
      for (const m of f.text.matchAll(SCRIPTLET_OUT)) {
        const expr = m[1]!;
        const direct = REQUEST_JAVA.test(expr);
        const viaVar = [...vars].some((v) => new RegExp(`(^|[^\\w.])${v}\\b`).test(expr));
        if ((!direct && !viaVar) || /\b(escape|encode|htmlEscape|escapeHtml\d?|forHtml)\w*\s*\(/i.test(expr)) continue;
        add(xssRule, m.index!, m[0].length, `jsp:<%=${expr.replace(/\s+/g, ' ').trim().slice(0, 80)}%>`, 'request_data');
      }
    }
    if (sqlRule) {
      for (const sc of f.text.matchAll(SCRIPTLET)) {
        const body = sc[1]!;
        for (const c of body.matchAll(SQL_CALL)) {
          const arg = callArgText(body, c.index! + c[0].length - 1);
          if (arg === null) continue;
          // Built in the call, or a variable built by concatenation earlier in the page (`sql += " AND x = '" + v + "'"`).
          const v = /^\s*(\w+)\s*$/.exec(arg)?.[1];
          const built = CONCAT_RE.test(arg) || (!!v && new RegExp(`\\b${v}\\s*\\+?=\\s*[^;]*(["']\\s*\\+|\\+\\s*["'])`).test(f.text.slice(0, sc.index! + 2 + c.index!)));
          if (!built) continue;
          const idx = sc.index! + 2 + c.index!;
          add(sqlRule, idx, c[0].length + arg.length + 1, `jsp:${c[1]}`, 'string_concat');
        }
      }
    }
  }
  return out;
}
