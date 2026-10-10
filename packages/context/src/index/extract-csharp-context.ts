// C# snapshot-level facts: one text pass over every `.cs` file before parsing, so that a file's
// controllers see (1) the class-level attributes and bases of their ancestors declared in other files
// (`[Route]` / `[Authorize]` on a `BaseApiController`), and (2) the conventional routes registered in
// Program.cs / Startup.cs (`MapControllerRoute("default", "{controller=Home}/{action=Index}/{id?}")`).
// Text scanning only (comments and string contents masked for the structure, values read from the original).
import type { SnapshotView } from '../snapshot/view.js';
import type { ExtractInput } from './types.js';

export interface CsAttr { name: string; args: string[]; named: Record<string, string> }
export interface CsClassFacts { name: string; bases: string[]; attrs: CsAttr[]; abstract: boolean; path: string }
export interface CsConventionalRoute {
  pattern: string;
  /** `MapAreaControllerRoute(name, areaName, pattern)`. */
  area?: string;
  /** `defaults: new { controller = "Blog", action = "Article" }` for patterns without `{controller}` / `{action}`. */
  defaults: { controller?: string; action?: string };
  /** Endpoint conventions chained on the registration, e.g. `RequireAuthorization()`. */
  conventions: string[];
  path: string;
  line: number;
}
/** a Razor page (`.cshtml` with `@page`). */
export interface CsRazorPage {
  /** Page path as conventions name it: `/Basket/Checkout`, `/Index` (area pages: path inside the area). */
  pagePath: string;
  area?: string;
  /** `@page "{id:int}"` / `@page "/custom"`; '' when `@page` has no template. */
  template: string;
  /** `@model` type (simple name). */
  model?: string;
  /** The `.cshtml` file. */
  file: string;
}
/** `AuthorizePage("/Basket/Checkout")`, `AuthorizeFolder("/Admin", "Policy")`, `AllowAnonymousToPage(…)`, area variants. */
export interface CsPageConvention { kind: 'authorize' | 'anonymous'; scope: 'page' | 'folder'; area?: string; path: string; text: string }
export interface CsharpContext {
  /** Class name → its ancestors (nearest first) as declared anywhere in the snapshot. */
  ancestors: Record<string, CsClassFacts[]>;
  routes: CsConventionalRoute[];
  /** Razor pages by their code-behind path (`<page>.cshtml.cs`) and by `@model` type name. */
  pagesByCodeBehind: Record<string, CsRazorPage>;
  pagesByModel: Record<string, CsRazorPage[]>;
  pageConventions: CsPageConvention[];
  /** Conventions chained on `MapRazorPages()` (e.g. `RequireAuthorization()`). */
  razorConventions: string[];
  /** `MapGrpcService<T>()` registrations (class name → chained conventions) and `Interceptors.Add<T>()`. */
  grpcServices: Record<string, string[]>;
  grpcInterceptors: string[];
  /** `MapHub<T>("/path")` registrations (class name → paths with chained conventions) and hub filters. */
  hubs: Record<string, { path: string; conventions: string[] }[]>;
  hubFilters: string[];
  /**
   * paths a raw WebSocket handler may be mapped on: `app.Map("/ws", b => b.UseMiddleware<T>())` (class name →
   * paths) and `app.Map("/ws", Class.Method)` (`Class.Method` → paths).
   */
  wsMiddlewares?: Record<string, string[]>;
  /** Spectre.Console `config.AddCommand<T>("name")` (class name → command names). */
  cliCommands?: Record<string, string[]>;
  /** Quartz cron schedules of a job class (`AddJob<T>(…)` / `ScheduleJob<T>(…)` followed by `WithCronSchedule("…")`). */
  quartzCrons?: Record<string, string[]>;
}

/** `src/Web/Pages/Basket/Index.cshtml` → page path `/Basket/Index`; `Areas/Identity/Pages/Account/Login.cshtml` → area Identity, `/Account/Login`. */
export function razorPageOf(path: string, text: string): CsRazorPage | null {
  const m = /(?:^|\/)(?:Areas\/([^/]+)\/)?Pages\/(.+)\.cshtml$/.exec(path);
  if (!m) return null;
  const head = text.replace(/^\uFEFF/, '').split('\n').slice(0, 30).join('\n');
  const page = /^\s*@page(?:[ \t]+"([^"]*)")?[ \t]*\r?$/m.exec(head);
  if (!page) return null; // partials, layouts, _ViewImports: not routable
  const model = /^\s*@model[ \t]+([\w.]+)/m.exec(head)?.[1]?.split('.').pop();
  return { pagePath: `/${m[2]}`, ...(m[1] ? { area: m[1] } : {}), template: page[1] ?? '', ...(model ? { model } : {}), file: path };
}

export const DEFAULT_ROUTE = '{controller=Home}/{action=Index}/{id?}';
const MAX_FILE = 2 * 1024 * 1024;

/** Blank comment bodies and string contents (quotes and newlines kept), so offsets map to the original text. */
export function maskCs(text: string): string {
  const out = text.split('');
  const blank = (a: number, b: number) => { for (let k = a; k < b && k < out.length; k++) if (out[k] !== '\n') out[k] = ' '; };
  const n = text.length;
  let i = 0;
  while (i < n) {
    const c = text[i]!;
    const d = text[i + 1];
    if (c === '/' && d === '/') { const e = text.indexOf('\n', i); const end = e < 0 ? n : e; blank(i, end); i = end; }
    else if (c === '/' && d === '*') { const e = text.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; blank(i, end); i = end; }
    else if (text.startsWith('"""', i)) { const e = text.indexOf('"""', i + 3); const end = e < 0 ? n : e + 3; blank(i + 3, end - 3); i = end; }
    else if ((c === '@' || c === '$') && (d === '"' || ((d === '@' || d === '$') && text[i + 2] === '"'))) {
      const start = text.indexOf('"', i) + 1;
      const verbatim = text.slice(i, start).includes('@');
      let j = start;
      while (j < n) {
        if (text[j] === '"') { if (verbatim && text[j + 1] === '"') { j += 2; continue; } break; }
        if (!verbatim && text[j] === '\\') { j += 2; continue; }
        j++;
      }
      blank(start, j); i = j + 1;
    } else if (c === '"' || c === '\'') {
      let j = i + 1;
      while (j < n && text[j] !== c && text[j] !== '\n') j += text[j] === '\\' ? 2 : 1;
      blank(i + 1, j); i = j + 1;
    } else i++;
  }
  return out.join('');
}

function closeOf(masked: string, open: number): number {
  const o = masked[open]!;
  const c = o === '(' ? ')' : o === '[' ? ']' : o === '{' ? '}' : o === '<' ? '>' : '';
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    if (masked[i] === o) depth++;
    else if (masked[i] === c && --depth === 0) return i;
  }
  return -1;
}

/** Split at top-level commas (masked text decides; slices are returned from the original). */
function splitTop(masked: string, original: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let from = 0;
  for (let i = 0; i < masked.length; i++) {
    const ch = masked[i]!;
    if ('([{<'.includes(ch)) depth++;
    else if (')]}>'.includes(ch)) depth--;
    else if (ch === ',' && depth === 0) { out.push(original.slice(from, i).trim()); from = i + 1; }
  }
  const last = original.slice(from).trim();
  if (last) out.push(last);
  return out;
}

const unq = (s: string): string => {
  const t = s.trim();
  const m = /^(?:@|\$)?"([\s\S]*)"$/.exec(t);
  return m ? m[1]!.replace(/""/g, '"') : t;
};

function parseArgs(masked: string, original: string): { args: string[]; named: Record<string, string> } {
  const args: string[] = [];
  const named: Record<string, string> = {};
  const m = splitTop(masked, masked);
  const o = splitTop(masked, original);
  m.forEach((mm, k) => {
    const kv = /^([A-Za-z_]\w*)\s*[:=](?!=)/.exec(mm);
    const val = o[k] ?? '';
    if (kv) named[kv[1]!] = unq(val.slice(val.search(/[:=]/) + 1));
    else args.push(unq(val));
  });
  return { args, named };
}

/** Attributes in `[A, B("x")] [C]` (masked / original slices of the same span). */
function attributesIn(masked: string, original: string): CsAttr[] {
  const out: CsAttr[] = [];
  for (const m of masked.matchAll(/\[/g)) {
    const open = m.index;
    const close = closeOf(masked, open);
    if (close < 0) break;
    const innerM = masked.slice(open + 1, close);
    const innerO = original.slice(open + 1, close);
    if (/^\s*(assembly|module)\s*:/.test(innerM)) continue;
    const partsM = splitTop(innerM, innerM);
    const partsO = splitTop(innerM, innerO);
    partsM.forEach((pm, k) => {
      const nm = /^\s*(?:\w+\s*:\s*)?([A-Za-z_][\w.]*)/.exec(pm);
      if (!nm) return;
      const name = nm[1]!.split('.').pop()!.replace(/Attribute$/, '');
      const po = partsO[k] ?? '';
      const paren = pm.indexOf('(');
      const a = paren >= 0 ? parseArgs(pm.slice(paren + 1, pm.lastIndexOf(')')), po.slice(paren + 1, po.lastIndexOf(')'))) : { args: [], named: {} };
      out.push({ name, args: a.args, named: a.named });
    });
  }
  return out;
}

const simpleType = (t: string) => t.replace(/<[^>]*>/g, '').replace(/\?$/, '').trim().split('.').pop()!;

/** Classes (with bases, class-level attributes, abstract flag) and conventional route registrations of one file. */
export function scanCsharp(text: string, path: string): {
  classes: CsClassFacts[]; routes: CsConventionalRoute[]; pageConventions: CsPageConvention[]; razorConventions: string[];
  grpcServices: Record<string, string[]>; grpcInterceptors: string[];
  hubs: Record<string, { path: string; conventions: string[] }[]>; hubFilters: string[];
  wsMiddlewares: Record<string, string[]>; cliCommands: Record<string, string[]>; quartzCrons: Record<string, string[]>;
} {
  const masked = maskCs(text);
  const classes: CsClassFacts[] = [];
  for (const m of masked.matchAll(/\b(class|record)\s+([A-Za-z_]\w*)/g)) {
    const at = m.index;
    // Declaration head: back to the previous statement / block boundary.
    let b = at - 1;
    while (b >= 0 && masked[b] !== ';' && masked[b] !== '{' && masked[b] !== '}') b--;
    const headM = masked.slice(b + 1, at);
    const headO = text.slice(b + 1, at);
    const attrs = attributesIn(headM, headO);
    const modifiers = headM.replace(/\[[^\]]*\]/g, ' ');
    let k = at + m[0].length;
    while (/\s/.test(masked[k] ?? '')) k++;
    if (masked[k] === '<') { const e = closeOf(masked, k); if (e > 0) k = e + 1; }
    while (/\s/.test(masked[k] ?? '')) k++;
    if (masked[k] === '(') { const e = closeOf(masked, k); if (e > 0) k = e + 1; }
    const stop = masked.slice(k).search(/[{;]/);
    const tailM = masked.slice(k, stop < 0 ? undefined : k + stop);
    const tailO = text.slice(k, stop < 0 ? undefined : k + stop);
    const colon = /^\s*:/.exec(tailM);
    let bases: string[] = [];
    if (colon) {
      const whereAt = tailM.search(/\bwhere\b/);
      const listM = tailM.slice(colon[0].length, whereAt < 0 ? undefined : whereAt);
      const listO = tailO.slice(colon[0].length, whereAt < 0 ? undefined : whereAt);
      bases = splitTop(listM, listO).map((x) => simpleType(x.replace(/\(.*$/s, ''))).filter(Boolean);
    }
    classes.push({ name: m[2]!, bases, attrs, abstract: /\babstract\b/.test(modifiers), path });
  }
  const routes: CsConventionalRoute[] = [];
  const re = /\b(MapControllerRoute|MapAreaControllerRoute|MapDefaultControllerRoute|MapRoute|MapAreaRoute|UseMvcWithDefaultRoute)\s*\(/g;
  for (const m of masked.matchAll(re)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(masked, open);
    if (close < 0) continue;
    const { args, named } = parseArgs(masked.slice(open + 1, close), text.slice(open + 1, close));
    const kind = m[1]!;
    let pattern: string | undefined;
    let area: string | undefined;
    if (kind === 'MapDefaultControllerRoute' || kind === 'UseMvcWithDefaultRoute') pattern = DEFAULT_ROUTE;
    else if (kind === 'MapAreaControllerRoute' || kind === 'MapAreaRoute') { area = named.areaName ?? args[1]; pattern = named.pattern ?? named.template ?? args[2]; }
    else pattern = named.pattern ?? named.template ?? args[1];
    if (pattern === undefined) continue;
    const defaultsText = named.defaults ?? (kind === 'MapControllerRoute' || kind === 'MapRoute' ? args[2] : undefined) ?? '';
    const defaults = {
      ...(/\bcontroller\s*=\s*"([^"]+)"/.exec(defaultsText) ? { controller: /\bcontroller\s*=\s*"([^"]+)"/.exec(defaultsText)![1]! } : {}),
      ...(/\baction\s*=\s*"([^"]+)"/.exec(defaultsText) ? { action: /\baction\s*=\s*"([^"]+)"/.exec(defaultsText)![1]! } : {}),
    };
    // Endpoint conventions chained after the registration: `.RequireAuthorization("Admin")`.
    const conventions: string[] = [];
    let p = close + 1;
    for (;;) {
      const c = /^\s*\.\s*([A-Za-z_]\w*)\s*\(/.exec(masked.slice(p, p + 200));
      if (!c) break;
      const o2 = p + c[0].length - 1;
      const e2 = closeOf(masked, o2);
      if (e2 < 0) break;
      conventions.push(`${c[1]}(${text.slice(o2 + 1, e2).replace(/\s+/g, ' ').trim()})`.slice(0, 160));
      p = e2 + 1;
    }
    routes.push({ pattern: pattern.trim().replace(/^\/+/, ''), ...(area ? { area } : {}), defaults, conventions, path, line: text.slice(0, m.index).split('\n').length });
  }
  // Razor Pages authorization conventions (AddRazorPages(o => o.Conventions.AuthorizePage(…))).
  const pageConventions: CsPageConvention[] = [];
  const pc = /\b(Authorize|AllowAnonymousTo)(Area)?(Page|Folder)\s*\(/g;
  for (const m of masked.matchAll(pc)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(masked, open);
    if (close < 0) continue;
    const { args, named } = parseArgs(masked.slice(open + 1, close), text.slice(open + 1, close));
    const area = m[2] ? (named.areaName ?? args[0]) : undefined;
    const p = m[2] ? (named.pageName ?? named.folderPath ?? args[1]) : (named.pageName ?? named.folderPath ?? args[0]);
    if (!p || !p.startsWith('/')) continue;
    pageConventions.push({
      kind: m[1] === 'Authorize' ? 'authorize' : 'anonymous', scope: m[3] === 'Page' ? 'page' : 'folder', ...(area ? { area } : {}), path: p,
      text: text.slice(m.index, close + 1).replace(/\s+/g, ' ').slice(0, 160),
    });
  }
  const razorConventions: string[] = [];
  for (const m of masked.matchAll(/\bMapRazorPages\s*\(\s*\)/g)) {
    let p = m.index + m[0].length;
    for (;;) {
      const c = /^\s*\.\s*([A-Za-z_]\w*)\s*\(/.exec(masked.slice(p, p + 200));
      if (!c) break;
      const o2 = p + c[0].length - 1;
      const e2 = closeOf(masked, o2);
      if (e2 < 0) break;
      razorConventions.push(`${c[1]}(${text.slice(o2 + 1, e2).replace(/\s+/g, ' ').trim()})`.slice(0, 160));
      p = e2 + 1;
    }
  }
  // gRPC: app.MapGrpcService<GreeterService>().RequireAuthorization(); AddGrpc(o => o.Interceptors.Add<AuthInterceptor>()).
  const grpcServices: Record<string, string[]> = {};
  for (const m of masked.matchAll(/\bMapGrpcService\s*<\s*([A-Za-z_][\w.]*)\s*>\s*\(\s*\)/g)) {
    const conv: string[] = [];
    let p = m.index + m[0].length;
    for (;;) {
      const c = /^\s*\.\s*([A-Za-z_]\w*)\s*\(/.exec(masked.slice(p, p + 200));
      if (!c) break;
      const o2 = p + c[0].length - 1;
      const e2 = closeOf(masked, o2);
      if (e2 < 0) break;
      conv.push(`${c[1]}(${text.slice(o2 + 1, e2).replace(/\s+/g, ' ').trim()})`.slice(0, 160));
      p = e2 + 1;
    }
    grpcServices[m[1]!.split('.').pop()!] = conv;
  }
  const grpcInterceptors = [...masked.matchAll(/\bInterceptors\s*\.\s*Add\s*<\s*([A-Za-z_][\w.]*)\s*>/g)].map((m) => m[1]!.split('.').pop()!);
  // SignalR: app.MapHub<ChatHub>("/chathub").RequireAuthorization(); AddSignalR(o => o.AddFilter<AuthHubFilter>()).
  const hubs: Record<string, { path: string; conventions: string[] }[]> = {};
  for (const m of masked.matchAll(/\bMapHub\s*<\s*([A-Za-z_][\w.]*)\s*>\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(masked, open);
    if (close < 0) continue;
    const { args, named } = parseArgs(masked.slice(open + 1, close), text.slice(open + 1, close));
    const path = named.pattern ?? args[0];
    if (!path || !/^\/?[\w\-/{}.:]*$/.test(path)) continue;
    const conventions: string[] = [];
    let p = close + 1;
    for (;;) {
      const c = /^\s*\.\s*([A-Za-z_]\w*)\s*\(/.exec(masked.slice(p, p + 200));
      if (!c) break;
      const o2 = p + c[0].length - 1;
      const e2 = closeOf(masked, o2);
      if (e2 < 0) break;
      conventions.push(`${c[1]}(${text.slice(o2 + 1, e2).replace(/\s+/g, ' ').trim()})`.slice(0, 160));
      p = e2 + 1;
    }
    (hubs[m[1]!.split('.').pop()!] ??= []).push({ path: path.startsWith('/') ? path : `/${path}`, conventions });
  }
  const hubFilters = /\bAddSignalR\s*\(/.test(masked) ? [...masked.matchAll(/\bAddFilter\s*<\s*([A-Za-z_][\w.]*)\s*>/g)].map((m) => m[1]!.split('.').pop()!) : [];
  // app.Map("/ws", b => b.UseMiddleware<WebSocketMiddleware>()); config.AddCommand<AddCommand>("add");
  // q.AddJob<CleanupJob>(…); q.AddTrigger(t => t.ForJob(key).WithCronSchedule("0 0 * * * ?")).
  const wsMiddlewares: Record<string, string[]> = {};
  for (const m of masked.matchAll(/\bMap\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(masked, open);
    if (close < 0) continue;
    const { args } = parseArgs(masked.slice(open + 1, close), text.slice(open + 1, close));
    const path = args[0];
    if (!path || !/^\/[\w\-/{}.:]*$/.test(path)) continue;
    for (const u of masked.slice(open, close).matchAll(/\bUseMiddleware\s*<\s*([A-Za-z_][\w.]*)\s*>/g)) (wsMiddlewares[u[1]!.split('.').pop()!] ??= []).push(path);
    // Method group in another file: `app.Map("/feed", Feeds.Handle)` → key `Feeds.Handle`.
    const group = /^[A-Z]\w*\.[A-Za-z_]\w*$/.test(args[1] ?? '') ? args[1]! : null;
    if (group && args.length === 2) (wsMiddlewares[group] ??= []).push(path);
  }
  const cliCommands: Record<string, string[]> = {};
  for (const m of masked.matchAll(/\bAddCommand\s*<\s*([A-Za-z_][\w.]*)\s*>\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = closeOf(masked, open);
    if (close < 0) continue;
    const name = parseArgs(masked.slice(open + 1, close), text.slice(open + 1, close)).args[0];
    if (name && /^[\w\-:.]+$/.test(name)) (cliCommands[m[1]!.split('.').pop()!] ??= []).push(name);
  }
  const quartzCrons: Record<string, string[]> = {};
  const jobs = [...masked.matchAll(/\b(?:AddJob|ScheduleJob)\s*<\s*([A-Za-z_][\w.]*)\s*>/g)];
  jobs.forEach((m, k) => {
    const end = Math.min(jobs[k + 1]?.index ?? masked.length, m.index + 1500);
    const seg = masked.slice(m.index, end);
    for (const c of seg.matchAll(/\b(?:WithCronSchedule|CronSchedule)\s*\(/g)) {
      const open = m.index + c.index + c[0].length - 1;
      const close = closeOf(masked, open);
      if (close < 0) continue;
      const cron = parseArgs(masked.slice(open + 1, close), text.slice(open + 1, close)).args[0];
      if (cron && !/^[A-Za-z_][\w.]*$/.test(cron)) (quartzCrons[m[1]!.split('.').pop()!] ??= []).push(cron);
    }
  });
  return { classes, routes, pageConventions, razorConventions, grpcServices, grpcInterceptors, hubs, hubFilters, wsMiddlewares, cliCommands, quartzCrons };
}

/** Snapshot pass: per-file context with the ancestor chains of the file's classes and the conventional routes. */
export function csharpInputContext(view: SnapshotView): (path: string) => Partial<ExtractInput> {
  const byName = new Map<string, CsClassFacts[]>();
  const declared = new Map<string, string[]>();
  const routes: CsConventionalRoute[] = [];
  const pageConventions: CsPageConvention[] = [];
  const razorConventions: string[] = [];
  const grpcServices: Record<string, string[]> = {};
  const grpcInterceptors: string[] = [];
  const hubs: Record<string, { path: string; conventions: string[] }[]> = {};
  const hubFilters: string[] = [];
  const wsMiddlewares: Record<string, string[]> = {};
  const cliCommands: Record<string, string[]> = {};
  const quartzCrons: Record<string, string[]> = {};
  const pagesByCodeBehind: Record<string, CsRazorPage> = {};
  const pagesByModel: Record<string, CsRazorPage[]> = {};
  for (const f of view.listFiles()) {
    if (f.path.endsWith('.cshtml') && f.size <= MAX_FILE) {
      let t: string;
      try { t = view.text(f.path); } catch { continue; }
      const page = razorPageOf(f.path, t);
      if (!page) continue;
      pagesByCodeBehind[`${f.path}.cs`] = page;
      if (page.model) (pagesByModel[page.model] ??= []).push(page);
      continue;
    }
    if (f.lang !== 'csharp' || f.size > MAX_FILE) continue;
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    const s = scanCsharp(text, f.path);
    for (const c of s.classes) {
      const list = byName.get(c.name) ?? [];
      list.push(c);
      byName.set(c.name, list);
    }
    declared.set(f.path, s.classes.map((c) => c.name));
    routes.push(...s.routes);
    pageConventions.push(...s.pageConventions);
    for (const c of s.razorConventions) if (!razorConventions.includes(c)) razorConventions.push(c);
    Object.assign(grpcServices, s.grpcServices);
    for (const i of s.grpcInterceptors) if (!grpcInterceptors.includes(i)) grpcInterceptors.push(i);
    for (const [k, v] of Object.entries(s.hubs)) (hubs[k] ??= []).push(...v);
    for (const f of s.hubFilters) if (!hubFilters.includes(f)) hubFilters.push(f);
    for (const [into, from] of [[wsMiddlewares, s.wsMiddlewares], [cliCommands, s.cliCommands], [quartzCrons, s.quartzCrons]] as const) {
      for (const [k, v] of Object.entries(from)) for (const x of v) if (!(into[k] ??= []).includes(x)) into[k]!.push(x);
    }
  }
  /** Nearest-first ancestors; an ambiguous base name (several classes) uses the first declaration. */
  const chain = (name: string): CsClassFacts[] => {
    const out: CsClassFacts[] = [];
    const seen = new Set([name]);
    let cur = byName.get(name)?.[0];
    for (let depth = 0; cur && depth < 8; depth++) {
      const next = cur.bases.map((b) => byName.get(b)?.[0]).find((x) => x && !/^I[A-Z]/.test(x.name) && !seen.has(x.name));
      if (!next) break;
      seen.add(next.name);
      out.push(next);
      cur = next;
    }
    return out;
  };
  return (path) => {
    const names = declared.get(path) ?? [];
    const ancestors: Record<string, CsClassFacts[]> = {};
    for (const n of names) { const c = chain(n); if (c.length) ancestors[n] = c; }
    // Only this file's pages travel to the worker: its code-behind page and the pages modelled by its classes.
    const own = pagesByCodeBehind[path];
    const byModel: Record<string, CsRazorPage[]> = {};
    for (const n of names) if (pagesByModel[n]) byModel[n] = pagesByModel[n]!;
    const ctx: CsharpContext = { ancestors, routes, pagesByCodeBehind: own ? { [path]: own } : {}, pagesByModel: byModel, pageConventions, razorConventions, grpcServices, grpcInterceptors, hubs, hubFilters, wsMiddlewares, cliCommands, quartzCrons };
    return { langContext: ctx as unknown as Record<string, unknown> };
  };
}
