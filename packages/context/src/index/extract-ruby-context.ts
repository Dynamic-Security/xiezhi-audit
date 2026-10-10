// Ruby snapshot-level facts: one text pass over every `.rb` file (plus Gemfile and config.ru)
// before parsing, so a file sees what other files declare:
// - controllers and concerns: superclass, included modules, callbacks (`before_action` and its `only` / `except` /
//   `if`, `skip_before_action`, `http_basic_authenticate_with`, CanCanCan `load_and_authorize_resource`, Rails 8
//   `allow_unauthenticated_access`), public actions and the authorization calls inside them — the routes file
//   resolves `users#show` to an action and computes the callbacks that guard it along the inheritance chain;
// - Grape APIs and Sinatra apps: the prefixes they are mounted under (`mount X => '/p'` in routes.rb or a parent
//   Grape API, `map '/p' do run X end` in config.ru);
// - Gemfile gems (rails / sinatra / grape / devise / pundit / cancancan …) for rule selection.
// Text scanning only (comments, strings and heredocs masked for the structure); nesting follows the `end` keywords.
import { parse as parseYaml } from 'yaml';
import type { SnapshotView } from '../snapshot/view.js';
import type { ExtractInput } from './types.js';

export interface RbFilter {
  /** `before` (before / around / prepend callbacks and auth macros) or `skip`. */
  kind: 'before' | 'skip';
  names: string[];
  only?: string[];
  except?: string[];
  /** `if:` / `unless:` condition text. */
  cond?: string;
  /** The declaration as written (one line). */
  text: string;
}
export interface RbClassFacts {
  qualified: string;
  kind: 'class' | 'module';
  /** Resolved qualified superclass (as declared when not found in the snapshot). */
  superclass: string | null;
  /** Resolved included / prepended modules, in order. */
  includes: string[];
  path: string;
  /** Callbacks in declaration order (for concerns: those of `included do … end`). */
  filters: RbFilter[];
  /** Public instance methods (candidate actions). */
  actions: string[];
  /** Authorization calls inside each method (`authorize @post`, `policy_scope(Post)`, `authorize! :read, @x`). */
  methodAuth: Record<string, string[]>;
  /** Grape: own `prefix` and path `version`; mounts declared in the class (`mount X => '/p'`). */
  grape?: { prefix?: string; version?: string };
  mounts: { target: string; path: string }[];
  /**
   * class-level calls of other macros (`allow_guests only: [:index]`), resolved after the scan against the
   * snapshot's skip macros — `class_methods do def allow_guests(**o) skip_before_action :require_member, **o end end`.
   */
  macroCalls?: { name: string; args: string; text: string }[];
  /** Skip macros a concern defines: macro name → callbacks it skips. */
  skipMacros?: Record<string, string[]>;
}
export interface RubyContext {
  gems: string[];
  /** Classes / modules relevant to this file (declared here, their ancestors and included modules; all controllers for routes files). */
  classes: Record<string, RbClassFacts>;
  /** Grape API / Sinatra app → path prefixes it is mounted under (from routes.rb, config.ru, parent Grape APIs). */
  mountBases: Record<string, string[]>;
  /** job class (declared in this file) → schedules from sidekiq-cron / sidekiq-scheduler YAML (`cron: "0 4 * * 1"`). */
  schedules?: Record<string, string[]>;
}

const MAX_BYTES = 1024 * 1024;
export const RB_ROUTES_RE = /(^|\/)config\/routes(\.rb|\/[\w/-]+\.rb)$/;

/** Mask comments, string / regexp contents and heredoc bodies so that structure keywords are found reliably. */
export function maskRuby(text: string): string[] {
  const lines = text.split('\n');
  const out: string[] = [];
  let heredoc: { id: string; squiggly: boolean } | null = null;
  let inBlockComment = false;
  for (const raw of lines) {
    if (inBlockComment) { out.push(''); if (/^=end\b/.test(raw)) inBlockComment = false; continue; }
    if (/^=begin\b/.test(raw)) { inBlockComment = true; out.push(''); continue; }
    if (heredoc) {
      out.push('');
      if ((heredoc.squiggly ? raw.trim() : raw.trimEnd()) === heredoc.id || raw.trim() === heredoc.id) heredoc = null;
      continue;
    }
    let s = '';
    let quote: string | null = null;
    for (let i = 0; i < raw.length; i++) {
      const ch = raw[i]!;
      if (quote) {
        if (ch === '\\') { s += '  '; i++; continue; }
        if (ch === quote) { quote = null; s += ch; } else s += ' ';
        continue;
      }
      if (ch === '#') break;
      if (ch === '"' || ch === "'" || ch === '`') { quote = ch; s += ch; continue; }
      s += ch;
    }
    const h = /<<([~-]?)(['"`]?)([A-Z_][A-Z0-9_]*)\2/.exec(s);
    if (h) heredoc = { id: h[3]!, squiggly: h[1] !== '' };
    out.push(s);
  }
  return out;
}

const OPENER_RE = /^\s*(?:(?:private|protected|public)\s+)?(module|class|def|if|unless|while|until|case|begin|for)\b/;
const ASSIGN_OPENER_RE = /(?:[^=!<>]=|\|\|=)\s*(if|unless|case|begin)\b/;
const DO_RE = /\bdo\s*(\|[^|]*\|)?\s*$/;
const END_RE = /^\s*end\b/;

/** Symbols / strings of an option value: `:a`, `[:a, :b]`, `%i[a b]`, `"a"`. */
function namesOf(v: string): string[] {
  const t = v.trim();
  const pct = /^%[iIwW][[({<]([^\])}>]*)[\])}>]/.exec(t);
  if (pct) return pct[1]!.trim().split(/\s+/).filter(Boolean);
  return [...t.matchAll(/:(\w+[?!]?)|["'](\w+[?!]?)["']/g)].map((m) => m[1] ?? m[2]!).filter(Boolean);
}

/** Parse the arguments of a callback declaration: leading names and the `only` / `except` / `if` / `unless` options. */
function parseFilterArgs(args: string): { names: string[]; only?: string[]; except?: string[]; cond?: string } {
  const opt = (key: string): string | undefined => {
    const m = new RegExp(`(?:\\b${key}:|:${key}\\s*=>)\\s*(%[iIwW][[({<][^\\])}>]*[\\])}>]|\\[[^\\]]*\\]|:[\\w?!]+|["'][^"']*["']|->\\s*(?:\\([^)]*\\))?\\s*\\{[^}]*\\}|lambda\\s*\\{[^}]*\\}|proc\\s*\\{[^}]*\\}|[\\w.?!]+)`).exec(args);
    return m?.[1];
  };
  // A lambda / proc / block callback is one unnamed callback (`before_action -> { doorkeeper_authorize! :write }`).
  if (/^\s*(->|lambda\b|proc\b|Proc\.new\b|do\b|\{)/.test(args)) {
    const rest = args.replace(/^\s*(?:->\s*(?:\([^)]*\))?\s*\{[^}]*\}|(?:lambda|proc|Proc\.new)\s*\{[^}]*\}|do\b.*|\{[^}]*\})/, '');
    const o = parseFilterArgs(rest.replace(/^\s*,/, ''));
    const body = args.slice(0, args.length - rest.length).replace(/\s+/g, ' ').trim();
    return { ...o, names: [`<${body.length > 80 ? body.slice(0, 80) + '…' : body}>`] };
  }
  const firstOpt = args.search(/\b\w+:\s|:\w+\s*=>/);
  const head = firstOpt >= 0 ? args.slice(0, firstOpt) : args;
  const names = [...head.matchAll(/:(\w+[?!]?)/g)].map((m) => m[1]!);
  const only = opt('only');
  const except = opt('except');
  const cond = opt('if') ?? opt('unless');
  return { names, ...(only ? { only: namesOf(only) } : {}), ...(except ? { except: namesOf(except) } : {}), ...(cond ? { cond: (args.includes('unless:') ? 'unless ' : 'if ') + cond } : {}) };
}

const FILTER_RE = /^\s*(prepend_before_action|prepend_around_action|before_action|around_action|before_filter|around_filter|append_before_action|skip_before_action|skip_around_action|skip_before_filter|skip_action_callback|skip_filter)\b\s*\(?\s*(.*)$/;
const AUTH_MACRO_RE = /^\s*(http_basic_authenticate_with|http_digest_authenticate_with|load_and_authorize_resource|authorize_resource|allow_unauthenticated_access|after_action\s+:verify_(?:authorized|policy_scoped))\b\s*\(?\s*(.*)$/;
const METHOD_AUTH_RE = /\b(authorize!?\s*\(?[^\n;]{0,60}|policy_scope\s*\(?[^\n;]{0,40}|authorize_resource\b|can(?:not)?\?\s*\(?[^\n;]{0,40}|authenticate_\w+!?|require_(?:login|user|admin|authentication|signed_in\w*|permission\w*)!?|head\s*\(?\s*:(?:unauthorized|forbidden)|status:\s*:(?:unauthorized|forbidden)|raise\s+[\w:]*(?:NotAuthorized|AccessDenied|Forbidden|Unauthorized)\w*)/;

interface ScanFile { path: string; masked: string[]; raw: string[] }
/** Lexical namespace a class / module statement appears in (`module Admin; class X < Base` → [Admin]; `class Admin::X < Base` at the top → []). */
const lexicalNs = new WeakMap<RbClassFacts, string[]>();

/** One pass over a Ruby file: classes / modules with their callbacks, actions and method-level authorization calls. */
export function scanRubyFile(path: string, text: string): RbClassFacts[] {
  const raw = text.split('\n');
  const masked = maskRuby(text);
  return scanMasked({ path, masked, raw });
}

function scanMasked(f: ScanFile): RbClassFacts[] {
  type Frame = { kind: 'module' | 'class' | 'sclass' | 'def' | 'block' | 'included' | 'class_methods'; facts?: RbClassFacts; def?: string; ns?: string[] };
  const stack: Frame[] = [];
  const out: RbClassFacts[] = [];
  const nsOf = (): string[] => { for (let i = stack.length - 1; i >= 0; i--) if (stack[i]!.ns) return stack[i]!.ns!; return []; };
  const owner = (): { facts: RbClassFacts; included: boolean } | null => {
    for (let i = stack.length - 1; i >= 0; i--) {
      const fr = stack[i]!;
      if (fr.kind === 'included') { const o = stack.slice(0, i).reverse().find((x) => x.facts); return o?.facts ? { facts: o.facts, included: true } : null; }
      if (fr.kind === 'def' || fr.kind === 'sclass' || fr.kind === 'class_methods') return null;
      if (fr.kind === 'block') continue;
      if (fr.facts) return { facts: fr.facts, included: false };
    }
    return null;
  };
  const currentDef = (): { facts: RbClassFacts; name: string } | null => {
    for (let i = stack.length - 1; i >= 0; i--) {
      const fr = stack[i]!;
      if (fr.kind === 'def') { const o = stack.slice(0, i).reverse().find((x) => x.facts); return o?.facts ? { facts: o.facts, name: fr.def! } : null; }
    }
    return null;
  };
  const visibility = new Map<RbClassFacts, 'public' | 'private'>();
  for (let i = 0; i < f.masked.length; i++) {
    let line = f.masked[i]!;
    let rawLine = f.raw[i] ?? '';
    // Join continuation lines of a declaration (`before_action :a,\n  only: [...]`).
    let j = i;
    while (/[,\\(]\s*$/.test(line) && j + 1 < f.masked.length && j - i < 6 && (FILTER_RE.test(f.masked[i]!) || AUTH_MACRO_RE.test(f.masked[i]!) || /^\s*mount\b/.test(f.masked[i]!))) {
      j++;
      line = line.replace(/\\\s*$/, '') + ' ' + f.masked[j]!.trim();
      rawLine = rawLine.replace(/\\\s*$/, '') + ' ' + (f.raw[j] ?? '').trim();
    }
    const opener = OPENER_RE.exec(line);
    const isOneLiner = (kw: string) => (kw === 'def' && (/\bend\s*$/.test(line) || /^\s*(?:(?:private|protected|public)\s+)?def\s+[\w.?!]+(\([^)]*\))?\s*=[^=~>]/.test(line))) || ((kw === 'class' || kw === 'module') && /;\s*end\s*$/.test(line));
    if (opener) {
      const kw = opener[1]!;
      if (kw === 'class' && /^\s*class\s*<</.test(line)) { stack.push({ kind: 'sclass' }); continue; }
      if (kw === 'module' || kw === 'class') {
        const m = new RegExp(`^\\s*${kw}\\s+((?:::)?[A-Z][\\w:]*)(?:\\s*<\\s*((?:::)?[A-Z][\\w:]*(?:\\[[^\\]]*\\])?))?`).exec(line);
        if (!m) { if (!isOneLiner(kw)) stack.push({ kind: 'block' }); continue; }
        const path = m[1]!.replace(/^::/, '');
        const ns = m[1]!.startsWith('::') ? [] : nsOf();
        const qualified = [...ns, ...path.split('::')].join('::');
        const facts: RbClassFacts = { qualified, kind: kw as 'class' | 'module', superclass: m[2] ? m[2].replace(/\[.*$/, '') : null, includes: [], path: f.path, filters: [], actions: [], methodAuth: {}, mounts: [] };
        out.push(facts);
        lexicalNs.set(facts, ns);
        if (!isOneLiner(kw)) stack.push({ kind: kw as 'class' | 'module', facts, ns: qualified.split('::') });
        continue;
      }
      if (kw === 'def') {
        const name = /def\s+(?:self\.)?([\w?!=]+|\[\]=?|[+\-*/<>=!~%&|^]+)/.exec(line)?.[1] ?? '?';
        const own = owner();
        const singleton = /def\s+self\./.test(line);
        if (own && !own.included && !singleton && (visibility.get(own.facts) ?? 'public') === 'public' && !/^\s*(private|protected)\s+def/.test(line) && !own.facts.actions.includes(name)) own.facts.actions.push(name);
        if (!isOneLiner(kw)) stack.push({ kind: 'def', def: name });
        continue;
      }
      // if / unless / while / until / case / begin / for at line start
      stack.push({ kind: 'block' });
      if (/\bend\s*$/.test(line) && !/^\s*end\b/.test(line)) stack.pop();
      continue;
    }
    if (END_RE.test(line)) {
      const n = (line.match(/(^|[\s;])end\b/g) ?? []).length;
      for (let k = 0; k < Math.max(1, n); k++) stack.pop();
      i = j;
      continue;
    }
    const own = owner();
    const def = currentDef();
    const cmIdx = stack.map((x) => x.kind).lastIndexOf('class_methods');
    if (def && cmIdx >= 0) {
      const sk = /^\s*skip_(?:before|around)_action\s*\(?\s*((?::\w+[?!]?\s*,?\s*)+)/.exec(line);
      const mod = stack.slice(0, cmIdx).reverse().find((x) => x.facts)?.facts;
      if (sk && mod) { const list = ((mod.skipMacros ??= {})[def.name] ??= []); for (const n of sk[1]!.matchAll(/:(\w+[?!]?)/g)) if (!list.includes(n[1]!)) list.push(n[1]!); }
    }
    if (def) {
      const m = METHOD_AUTH_RE.exec(line);
      if (m) {
        const at = line.indexOf(m[1]!.slice(0, 6));
        const snippet = (at >= 0 ? rawLine.slice(at, at + m[1]!.length) : m[1]!).trim().replace(/\s+/g, ' ');
        const list = (def.facts.methodAuth[def.name] ??= []);
        if (list.length < 4 && !list.includes(snippet)) list.push(snippet);
      }
    } else if (own) {
      const fl = FILTER_RE.exec(line);
      if (fl) {
        const parsed = parseFilterArgs(rawLine.slice(rawLine.indexOf(fl[1]!) + fl[1]!.length).replace(/^\s*\(?/, ''));
        if (!parsed.names.length && /\bdo\b|\{/.test(line)) parsed.names.push('<block>');
        own.facts.filters.push({ kind: /^skip_/.test(fl[1]!) ? 'skip' : 'before', ...parsed, text: oneLine(rawLine) });
      } else {
        const am = AUTH_MACRO_RE.exec(line);
        if (am) {
          const macro = am[1]!.split(/\s+/)[0]!;
          const parsed = parseFilterArgs(rawLine.slice(rawLine.indexOf(macro) + macro.length).replace(/^\s*\(?/, ''));
          if (macro === 'allow_unauthenticated_access') own.facts.filters.push({ kind: 'skip', names: ['require_authentication'], ...(parsed.only ? { only: parsed.only } : {}), ...(parsed.except ? { except: parsed.except } : {}), text: oneLine(rawLine) });
          else own.facts.filters.push({ kind: 'before', names: [macro === 'after_action' ? am[0]!.match(/verify_\w+/)![0] : macro], ...(parsed.only ? { only: parsed.only } : {}), ...(parsed.except ? { except: parsed.except } : {}), text: oneLine(rawLine) });
        } else {
          const inc = /^\s*(include|prepend)\s+([A-Z][\w:]*(?:\s*,\s*[A-Z][\w:]*)*)/.exec(line);
          if (inc) for (const n of inc[2]!.split(',')) own.facts.includes.push(n.trim());
          const call = /^\s*([a-z_]\w*[!?]?)(?:\s+|\s*\()(.*)$/.exec(line);
          if (call && !inc && !/^(private|protected|public|attr_\w+|def|end|include|extend|prepend|helper_method|layout|respond_to|rescue_from|delegate|has_\w+|belongs_to|validates?\w*|scope|before_\w+|after_\w+|around_\w+|skip_\w+|protect_from_forgery)$/.test(call[1]!) && (own.facts.macroCalls?.length ?? 0) < 20) {
            (own.facts.macroCalls ??= []).push({ name: call[1]!, args: rawLine.slice(rawLine.indexOf(call[1]!) + call[1]!.length), text: oneLine(rawLine) });
          }
          if (/^\s*(private|protected)\s*$/.test(line)) visibility.set(own.facts, 'private');
          else if (/^\s*public\s*$/.test(line)) visibility.set(own.facts, 'public');
          const pf = /^\s*prefix\s*\(?\s*['":]\/?([\w/.-]+)/.exec(rawLine);
          if (pf) (own.facts.grape ??= {}).prefix = pf[1]!;
          const vs = /^\s*version\s*\(?\s*['":]([\w.-]+)['"]?(.*)$/.exec(rawLine);
          if (vs && (!/using:/.test(vs[2]!) || /using:\s*:path/.test(vs[2]!))) (own.facts.grape ??= {}).version = vs[1]!;
          const mt = mountOf(rawLine);
          if (mt) own.facts.mounts.push(mt);
        }
      }
    }
    if (/^\s*included\s+do\b/.test(line) && own?.facts.kind === 'module') { stack.push({ kind: 'included' }); i = j; continue; }
    if (/^\s*class_methods\s+do\b/.test(line) && own?.facts.kind === 'module') { stack.push({ kind: 'class_methods' }); i = j; continue; }
    if (DO_RE.test(line) || ASSIGN_OPENER_RE.test(line)) stack.push({ kind: 'block' });
    i = j;
  }
  return out;
}

/** `mount Api::Root => '/api'`, `mount Api::Root, at: '/api'`, `mount Api::V1` (Grape, no path). */
export function mountOf(line: string): { target: string; path: string } | null {
  const m = /^\s*mount\s*\(?\s*((?:::)?[A-Z][\w:]*)(?:\.new)?\s*(?:=>\s*['"]([^'"]*)['"]|,\s*at:\s*['"]([^'"]*)['"])?/.exec(line);
  if (!m) return null;
  return { target: m[1]!.replace(/^::/, ''), path: m[2] ?? m[3] ?? '' };
}

const oneLine = (s: string) => { const t = s.replace(/\s+/g, ' ').trim(); return t.length > 200 ? t.slice(0, 200) + '…' : t; };

/** Gem names declared by Gemfile / *.gemspec files. */
function gemsOf(view: SnapshotView): string[] {
  const out = new Set<string>();
  for (const f of view.listFiles()) {
    const base = f.path.split('/').pop()!;
    if (!(base === 'Gemfile' || base === 'gems.rb' || base.endsWith('.gemspec')) || f.size > MAX_BYTES || f.path.includes('vendor/')) continue;
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    for (const m of text.matchAll(/^\s*(?:gem|s(?:pec)?\.add_(?:runtime_)?dependency|\w+\.add_dependency)\s*\(?\s*['"]([\w.-]+)['"]/gm)) out.add(m[1]!);
  }
  return [...out].sort();
}

/** Resolve a constant reference as Ruby would from a namespace (innermost first), falling back to the name as written. */
function resolveConst(name: string, ns: string[], known: Map<string, RbClassFacts>, self?: string): string {
  if (name.startsWith('::')) return name.slice(2);
  for (let k = ns.length; k > 0; k--) {
    const q = [...ns.slice(0, k), name].join('::');
    if (known.has(q) && q !== self) return q;
  }
  return name;
}

/**
 * job schedules declared in YAML — sidekiq-cron `config/schedule.yml` (`name: { cron:, class: }`), sidekiq-scheduler
 * `:schedule:` in sidekiq.yml (`cron` / `every` / `at` / `in`). Any mapping with `class` and a timing key counts.
 */
function yamlSchedules(view: SnapshotView): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const f of view.listFiles()) {
    if (!/(^|\/)config\/(schedule|sidekiq|sidekiq_cron|sidekiq_scheduler|recurring)\.ya?ml$/.test(f.path) || f.size > MAX_BYTES) continue;
    let doc: unknown;
    try { doc = parseYaml(view.text(f.path).replace(/<%[\s\S]*?%>/g, '')); } catch { continue; }
    const walk = (v: unknown, depth: number) => {
      if (!v || typeof v !== 'object' || depth > 6) return;
      const o = v as Record<string, unknown>;
      const cls = o.class ?? o[':class'];
      const timing = ['cron', 'every', 'at', 'in', 'schedule'].map((k) => o[k] ?? o[`:${k}`]).find((x) => x !== undefined);
      if (typeof cls === 'string' && timing !== undefined) { const list = out.get(cls) ?? []; list.push(String(Array.isArray(timing) ? timing.join(' ') : timing).slice(0, 80)); out.set(cls, list); }
      for (const x of Object.values(o)) walk(x, depth + 1);
    };
    walk(doc, 0);
  }
  return out;
}

/** Snapshot-level Ruby facts; per-file slices (`langContext`) keep worker messages small. */
export function rubyInputContext(view: SnapshotView): (path: string) => Partial<ExtractInput> {
  const gems = gemsOf(view);
  const schedules = yamlSchedules(view);
  const all = new Map<string, RbClassFacts>();
  const byFile = new Map<string, RbClassFacts[]>();
  const routeMounts: { target: string; path: string }[] = [];
  const ruMounts: { target: string; path: string }[] = [];
  for (const f of view.listFiles()) {
    if (f.size > MAX_BYTES || f.path.includes('vendor/') || f.path.includes('node_modules/')) continue;
    const isRu = f.path === 'config.ru' || f.path.endsWith('/config.ru');
    if (f.lang !== 'ruby' && !isRu) continue;
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    if (isRu) { ruMounts.push(...configRuMounts(text)); continue; }
    const facts = scanRubyFile(f.path, text);
    byFile.set(f.path, facts);
    for (const c of facts) {
      const prev = all.get(c.qualified);
      if (!prev) { const copy = { ...c, filters: [...c.filters], actions: [...c.actions], includes: [...c.includes], mounts: [...c.mounts], methodAuth: { ...c.methodAuth } }; lexicalNs.set(copy, lexicalNs.get(c) ?? []); all.set(c.qualified, copy); continue; }
      // Reopened class (several files): merge.
      prev.superclass ??= c.superclass;
      prev.filters.push(...c.filters);
      for (const a of c.actions) if (!prev.actions.includes(a)) prev.actions.push(a);
      prev.includes.push(...c.includes);
      prev.mounts.push(...c.mounts);
      Object.assign(prev.methodAuth, c.methodAuth);
      if (c.grape) prev.grape = { ...prev.grape, ...c.grape };
    }
    if (RB_ROUTES_RE.test(f.path)) for (const line of text.split('\n')) { const m = mountOf(line); if (m) routeMounts.push(m); }
  }
  // Custom skip macros (`allow_guests only: [...]`) become skip filters of the classes that call them.
  const skipMacros = new Map<string, string[]>();
  for (const c of all.values()) for (const [m, names] of Object.entries(c.skipMacros ?? {})) skipMacros.set(m, [...new Set([...(skipMacros.get(m) ?? []), ...names])]);
  for (const c of all.values()) {
    for (const call of c.macroCalls ?? []) {
      const names = skipMacros.get(call.name);
      if (!names || call.name === 'allow_unauthenticated_access') continue;
      const parsed = parseFilterArgs(call.args.replace(/^\s*\(?/, ''));
      c.filters.push({ kind: 'skip', names, ...(parsed.only ? { only: parsed.only } : {}), ...(parsed.except ? { except: parsed.except } : {}), text: call.text });
    }
    delete c.macroCalls;
  }
  // Resolve superclasses / includes against the namespace of the declaration.
  for (const c of all.values()) {
    // The superclass is looked up from where the statement appears (not inside the class's own compact path).
    if (c.superclass) c.superclass = resolveConst(c.superclass, lexicalNs.get(c) ?? c.qualified.split('::').slice(0, -1), all, c.qualified);
    c.includes = c.includes.map((n) => resolveConst(n, c.qualified.split('::'), all));
    c.mounts = c.mounts.map((m) => ({ ...m, target: resolveConst(m.target, c.qualified.split('::'), all) }));
  }
  const ancestors = (q: string): RbClassFacts[] => {
    const out: RbClassFacts[] = [];
    const seen = new Set<string>();
    for (let cur = all.get(q); cur && !seen.has(cur.qualified) && out.length < 12; cur = cur.superclass ? all.get(cur.superclass) : undefined) { seen.add(cur.qualified); out.push(cur); }
    return out;
  };
  const chainNames = (q: string): string[] => {
    const names: string[] = [];
    for (const a of ancestors(q)) { names.push(a.qualified); if (a.superclass && !all.has(a.superclass)) names.push(a.superclass); }
    return names;
  };
  const isMountable = (q: string) => chainNames(q).some((n) => /^(Grape::API(::Instance)?|Sinatra::(Base|Application)|Padrino::Application)$/.test(n));
  // Mount prefixes: routes.rb and config.ru at the root; parent Grape APIs recursively (own prefix + version + mount path).
  const mountBases = new Map<string, Set<string>>();
  const ownBase = (q: string) => { const g = all.get(q)?.grape; return joinPath(g?.prefix ?? '', g?.version ?? ''); };
  const basesOf = (q: string, depth = 0, seen = new Set<string>()): string[] => {
    if (depth > 8 || seen.has(q)) return [''];
    seen.add(q);
    const out = new Set<string>();
    for (const m of [...routeMounts, ...ruMounts]) if (resolveConst(m.target, [], all) === q) out.add(joinPath('', m.path));
    for (const p of all.values()) {
      for (const m of p.mounts) if (m.target === q) for (const b of basesOf(p.qualified, depth + 1, new Set(seen))) out.add(joinPath(joinPath(b, ownBase(p.qualified)), m.path));
    }
    return out.size ? [...out].sort() : [''];
  };
  for (const q of all.keys()) if (isMountable(q)) mountBases.set(q, new Set(basesOf(q)));

  const controllers = [...all.values()].filter((c) => /Controller$/.test(c.qualified) || chainNames(c.qualified).some((n) => /Controller(::Base|::API)?$/.test(n)));
  return (path) => {
    const own = byFile.get(path) ?? [];
    const routes = RB_ROUTES_RE.test(path);
    const relevant = new Map<string, RbClassFacts>();
    const addWithChain = (q: string) => {
      for (const a of ancestors(q)) {
        relevant.set(a.qualified, a);
        for (const inc of a.includes) { const m = all.get(inc); if (m) relevant.set(m.qualified, m); }
      }
    };
    for (const c of own) addWithChain(c.qualified);
    if (routes) for (const c of controllers) addWithChain(c.qualified);
    // Unknown ancestors (gems) are kept by name in the chain so `< Grape::API` / `< Sinatra::Base` are visible.
    const mb: Record<string, string[]> = {};
    for (const c of own) { const b = mountBases.get(c.qualified); if (b) mb[c.qualified] = [...b]; }
    for (const c of own) for (const n of chainNames(c.qualified)) if (!relevant.has(n)) relevant.set(n, { qualified: n, kind: 'class', superclass: null, includes: [], path: '', filters: [], actions: [], methodAuth: {}, mounts: [] });
    if (!relevant.size && !gems.length) return {};
    const sched: Record<string, string[]> = {};
    for (const c of own) { const sc = schedules.get(c.qualified) ?? schedules.get(c.qualified.split('::').pop()!); if (sc) sched[c.qualified] = sc; }
    const ctx: RubyContext = { gems, classes: Object.fromEntries(relevant), mountBases: mb, ...(Object.keys(sched).length ? { schedules: sched } : {}) };
    return { langContext: ctx as unknown as Record<string, unknown> };
  };
}

/** `map '/admin' do run AdminApp end`, `map('/x') { run X }`, `run Rack::URLMap.new('/a' => A)`, top-level `run App`. */
function configRuMounts(text: string): { target: string; path: string }[] {
  const out: { target: string; path: string }[] = [];
  const masked = text.replace(/#[^\n]*/g, '');
  for (const m of masked.matchAll(/\bmap\s*\(?\s*['"]([^'"]+)['"]\s*\)?\s*(?:do|\{)([\s\S]*?)(?:\bend\b|\})/g)) {
    const run = /\brun\s+((?:::)?[A-Z][\w:]*)/.exec(m[2]!);
    if (run) out.push({ target: run[1]!.replace(/^::/, ''), path: m[1]! });
  }
  for (const u of masked.matchAll(/Rack::URLMap\.new\s*\(\s*\{?([^)]*)\)/g)) {
    for (const p of u[1]!.matchAll(/['"]([^'"]+)['"]\s*=>\s*((?:::)?[A-Z][\w:]*)/g)) out.push({ target: p[2]!.replace(/^::/, ''), path: p[1]! });
  }
  for (const r of masked.matchAll(/^run\s+((?:::)?[A-Z][\w:]*)(?:\.new)?\s*$/gm)) if (!/^Rack::/.test(r[1]!)) out.push({ target: r[1]!.replace(/^::/, ''), path: '' });
  return out;
}

export function joinPath(a: string, b: string): string {
  const j = `/${a}/${b}`.replace(/\/{2,}/g, '/');
  return j.length > 1 ? j.replace(/\/+$/, '') : '';
}

/**
 * Callbacks guarding `action` of `controller`, along the inheritance chain (root first) with included concerns at their
 * position; `skip_*` removes earlier callbacks of the same name for the actions it covers.
 */
export function effectiveFilters(controller: string, action: string, classes: Record<string, RbClassFacts>): { name: string; detail: string }[] {
  const chain: RbClassFacts[] = [];
  const seen = new Set<string>();
  for (let cur = classes[controller]; cur && !seen.has(cur.qualified) && chain.length < 12; cur = cur.superclass ? classes[cur.superclass] : undefined) { seen.add(cur.qualified); chain.unshift(cur); }
  const applies = (f: RbFilter) => (!f.only || f.only.includes(action)) && !(f.except ?? []).includes(action);
  const active: { name: string; detail: string }[] = [];
  const apply = (owner: RbClassFacts) => {
    for (const f of owner.filters) {
      if (!applies(f)) continue;
      if (f.kind === 'skip') { for (const n of f.names) { const i = active.findIndex((a) => a.name === n); if (i >= 0) active.splice(i, 1); } continue; }
      for (const n of f.names) if (!active.some((a) => a.name === n)) active.push({ name: n, detail: `${f.text}${owner.qualified !== controller ? ` (${owner.qualified})` : ''}` });
    }
  };
  for (const c of chain) {
    for (const inc of c.includes) { const m = classes[inc]; if (m) apply(m); }
    apply(c);
  }
  return active;
}
