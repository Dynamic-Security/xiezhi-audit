// Independent function locators for Python, JS/TS, PHP, Kotlin, C#, Ruby and Rust. Same approach as locate.ts:
// lexical scanning with strings and comments masked, never the product's tree-sitter index.
// Qualified names: `Class.method` inside a class, otherwise the bare function name (Python / JS / PHP / Kotlin
// top-level functions); JS `const f = (…) => {…}` counts as function `f`.
import type { FunctionSpan } from './locate.js';

export type ExtraLang = 'python' | 'js' | 'php' | 'kotlin' | 'csharp' | 'ruby' | 'rust';

export function extraLangOf(file: string): ExtraLang | null {
  const f = file.toLowerCase();
  if (/\.pyi?$/.test(f)) return 'python';
  if (/\.([cm]?[jt]sx?)$/.test(f)) return 'js';
  if (/\.(php|phtml)$/.test(f)) return 'php';
  if (f.endsWith('.kt')) return 'kotlin';
  if (f.endsWith('.cs')) return 'csharp';
  if (/\.(rb|rake)$/.test(f)) return 'ruby';
  if (f.endsWith('.rs')) return 'rust';
  return null;
}

function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  return starts;
}

function lineOf(starts: number[], offset: number): number {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= offset) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

function matchBracket(masked: string, open: number): number {
  const o = masked[open]!;
  const c = o === '{' ? '}' : o === '(' ? ')' : o === '[' ? ']' : '';
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    if (masked[i] === o) depth++;
    else if (masked[i] === c && --depth === 0) return i;
  }
  return -1;
}

/**
 * Blank comments and string contents (newlines kept). Handles line and block comments, `#` (Python / PHP), triple-quoted
 * strings (Python, Kotlin), template literals (JS), verbatim / raw strings (C# `@"…"`, `"""…"""`).
 */
export function maskExtra(text: string, lang: ExtraLang): string {
  if (lang === 'js') return maskJs(text);
  const out = text.split('');
  const blank = (from: number, to: number) => { for (let k = from; k < to && k < out.length; k++) if (out[k] !== '\n') out[k] = ' '; };
  const n = text.length;
  const hashComments = lang === 'python' || lang === 'php';
  const slashComments = lang !== 'python';
  let i = 0;
  while (i < n) {
    const c = text[i]!;
    const d = text[i + 1];
    if (slashComments && c === '/' && d === '/') {
      const e = text.indexOf('\n', i); const end = e < 0 ? n : e; blank(i, end); i = end;
    } else if (slashComments && c === '/' && d === '*') {
      const e = text.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; blank(i, end); i = end;
    } else if (hashComments && c === '#' && !(lang === 'php' && d === '[')) {
      const e = text.indexOf('\n', i); const end = e < 0 ? n : e; blank(i, end); i = end;
    } else if ((lang === 'python' || lang === 'kotlin' || lang === 'csharp') && (text.startsWith('"""', i) || (lang === 'python' && text.startsWith("'''", i)))) {
      const q = text.slice(i, i + 3);
      const e = text.indexOf(q, i + 3); const end = e < 0 ? n : e + 3; blank(i + 3, end - 3); i = end;
    } else if (lang === 'csharp' && c === '@' && d === '"') {
      let j = i + 2;
      while (j < n && !(text[j] === '"' && text[j + 1] !== '"')) j += text[j] === '"' ? 2 : 1;
      blank(i + 2, j); i = j + 1;
    } else if (c === '"' || c === '\'') {
      let j = i + 1;
      while (j < n && text[j] !== c && text[j] !== '\n') j += text[j] === '\\' ? 2 : 1;
      blank(i + 1, j); i = j + 1;
    } else i++;
  }
  return out.join('');
}

/**
 * JS / TS masking with a context stack: template literals with `${…}` substitutions that hold code,
 * strings and further templates (Unleash nests templates inside substitutions), and regex literals (a `/` where an
 * expression may start). Comment bodies and string / template / regex contents are blanked; newlines kept.
 */
export function maskJs(text: string): string {
  const out = text.split('');
  const blank = (from: number, to: number) => { for (let k = from; k < to && k < out.length; k++) if (out[k] !== '\n') out[k] = ' '; };
  const n = text.length;
  /** Brace depth of each open `${` (innermost last). */
  const subs: number[] = [];
  let depth = 0;
  let prev = ''; // last significant code character, to tell a regex from a division
  let prevWord = '';
  let i = 0;
  const regexMayStart = () => prev === '' || '(,=:[!&|?{};+-*%<>~^'.includes(prev) || /^(return|typeof|case|do|else|in|of|new|delete|void|throw|yield|await)$/.test(prevWord);
  const template = (from: number): number => {
    // Inside a template literal starting after the opening backtick; returns the index after the closing one,
    // or the index of a `${` (leaving the template context for code).
    let j = from;
    while (j < n) {
      if (text[j] === '\\') { j += 2; continue; }
      if (text[j] === '`') { blank(from, j); return j + 1; }
      if (text[j] === '$' && text[j + 1] === '{') { blank(from, j); subs.push(depth); depth++; return j + 2; }
      j++;
    }
    blank(from, n);
    return n;
  };
  while (i < n) {
    const c = text[i]!;
    const d = text[i + 1];
    if (c === '/' && d === '/') { const e = text.indexOf('\n', i); const end = e < 0 ? n : e; blank(i, end); i = end; continue; }
    if (c === '/' && d === '*') { const e = text.indexOf('*/', i + 2); const end = e < 0 ? n : e + 2; blank(i, end); i = end; continue; }
    if (c === '`') { i = template(i + 1); prev = '`'; prevWord = ''; continue; }
    if (c === '"' || c === '\'') {
      let j = i + 1;
      while (j < n && text[j] !== c && text[j] !== '\n') j += text[j] === '\\' ? 2 : 1;
      blank(i + 1, j); i = j + 1; prev = c; prevWord = ''; continue;
    }
    if (c === '/' && regexMayStart()) {
      let j = i + 1;
      let cls = false;
      while (j < n && text[j] !== '\n') {
        const ch = text[j]!;
        if (ch === '\\') { j += 2; continue; }
        if (ch === '[') cls = true;
        else if (ch === ']') cls = false;
        else if (ch === '/' && !cls) break;
        j++;
      }
      if (j < n && text[j] === '/') { blank(i + 1, j); i = j + 1; while (/[a-z]/i.test(text[i] ?? '')) i++; prev = '/'; prevWord = ''; continue; }
    }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (subs.length && depth === subs[subs.length - 1]) { subs.pop(); i = template(i + 1); prev = '`'; prevWord = ''; continue; }
    }
    if (/[A-Za-z_$]/.test(c)) {
      let j = i;
      while (j < n && /[\w$]/.test(text[j]!)) j++;
      prevWord = text.slice(i, j); prev = 'a'; i = j; continue;
    }
    if (!/\s/.test(c)) { prev = c; prevWord = ''; }
    i++;
  }
  return out.join('');
}

// ---- Python: indentation blocks ------------------------------------------------------------------------------

function pythonFunctions(text: string): FunctionSpan[] {
  const masked = maskExtra(text, 'python');
  const lines = masked.split('\n');
  const indent = (l: string) => l.length - l.trimStart().length;
  const blockEnd = (from: number, ind: number) => {
    let last = from;
    for (let k = from + 1; k < lines.length; k++) {
      const l = lines[k]!;
      if (!l.trim()) continue;
      if (indent(l) <= ind) break;
      last = k;
    }
    return last;
  };
  /**
   * Last line of a `def` / `class` header: parentheses may span lines and close with `):` at the header's own
   * indentation (Black style), so the body starts after the line where depth returns to 0 and `:` follows.
   */
  const headerEnd = (from: number) => {
    let depth = 0;
    for (let k = from; k < lines.length && k < from + 200; k++) {
      for (const ch of lines[k]!) {
        if (ch === '(' || ch === '[' || ch === '{') depth++;
        else if (ch === ')' || ch === ']' || ch === '}') depth = Math.max(0, depth - 1);
      }
      if (depth === 0 && /:\s*$/.test(lines[k]!.replace(/#.*$/, ''))) return k;
      if (depth === 0 && k > from && /:/.test(lines[k]!)) return k;
    }
    return from;
  };
  /** First line of the decorators above a header (multi-line decorators included). */
  const decoratorsStart = (k: number, ind: number) => {
    let start = k;
    for (;;) {
      const j = start - 1;
      if (j < 0) break;
      // A decorator's closing line (`)`) belongs to a group that opened on an `@` line above.
      if (/^\s*[)\]]/.test(lines[j]!) && indent(lines[j]!) === ind) {
        let depth = 0;
        let o = j;
        for (; o >= 0; o--) {
          for (const ch of [...lines[o]!].reverse()) {
            if (ch === ')' || ch === ']') depth++;
            else if (ch === '(' || ch === '[') depth--;
          }
          if (depth <= 0) break;
        }
        if (o >= 0 && /^\s*@/.test(lines[o]!) && indent(lines[o]!) === ind) { start = o; continue; }
        break;
      }
      if (/^\s*@/.test(lines[j]!) && indent(lines[j]!) === ind) { start = j; continue; }
      break;
    }
    return start;
  };
  const classes: { name: string; ind: number; from: number; to: number }[] = [];
  lines.forEach((l, k) => {
    const m = /^(\s*)class\s+([A-Za-z_]\w*)/.exec(l);
    if (m) classes.push({ name: m[2]!, ind: m[1]!.length, from: k, to: blockEnd(headerEnd(k), m[1]!.length) });
  });
  const out: FunctionSpan[] = [];
  lines.forEach((l, k) => {
    const m = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/.exec(l);
    if (!m) return;
    const ind = m[1]!.length;
    // Decorators belong to the function (routes are declared there).
    const start = decoratorsStart(k, ind);
    const owner = classes.filter((c) => c.from < k && k <= c.to && c.ind < ind).sort((a, b) => b.ind - a.ind)[0];
    const name = m[2]!;
    out.push({ qualified: owner ? `${owner.name}.${name}` : name, name, start: start + 1, end: blockEnd(headerEnd(k), ind) + 1 });
  });
  return out;
}

// ---- brace languages ------------------------------------------------------------------------------------------

const NOT_NAMES = new Set(['if', 'for', 'foreach', 'while', 'switch', 'catch', 'using', 'lock', 'return', 'new', 'throw', 'else', 'try', 'do', 'case', 'when',
  'function', 'fun', 'typeof', 'sizeof', 'nameof', 'await', 'yield', 'super', 'this', 'base', 'constructor_', 'elseif', 'isset', 'unset', 'empty', 'array', 'list', 'echo', 'print', 'fixed', 'checked']);

interface TypeSpan { name: string; from: number; to: number }

/** Text with parenthesised groups removed (constructor parameters may contain `val` / annotations). */
function stripParens(s: string): string {
  let depth = 0;
  let out = '';
  for (const ch of s) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (depth === 0) out += ch;
  }
  return out;
}

function typeSpans(masked: string, re: RegExp): TypeSpan[] {
  const out: TypeSpan[] = [];
  for (const m of masked.matchAll(re)) {
    const brace = masked.indexOf('{', m.index + m[0].length);
    if (brace < 0) continue;
    // A `;` before the brace means a declaration without body (e.g. C# `record R(int X);`). Kotlin has no `;`: a
    // class without body (`class A(val x: Int)`) is followed by the next declaration, whose keyword appears (outside
    // the constructor's parentheses) before the brace (reposilite's JavadocContainer took the next class's body).
    const between = masked.slice(m.index + m[0].length, brace);
    if (between.includes(';')) continue;
    // The primary constructor may carry modifiers / annotations (`class A internal constructor(…)`, `@Inject constructor`).
    const head = stripParens(between).replace(/(?:\b(?:private|internal|public|protected)\s+)?(?:@[\w.]+\s*)*\bconstructor\b/g, ' ');
    if (/\b(class|interface|object|fun|val|var|typealias|enum|data|sealed|abstract|open|private|internal|public)\b|@\w/.test(head)) continue;
    const end = matchBracket(masked, brace);
    out.push({ name: m[1]!, from: brace, to: end < 0 ? masked.length : end });
  }
  return out;
}

const ownerOf = (types: TypeSpan[], at: number) => types.filter((t) => t.from < at && at < t.to).sort((a, b) => b.from - a.from)[0];

/** Body after the closing `)` of a parameter list: `{…}` (brace end), `=> expr;` / `= expr` (line / statement end). */
function bodyEnd(masked: string, close: number, lang: ExtraLang): number | null {
  const after = masked.slice(close + 1, close + 600);
  const brace = lang === 'kotlin'
    ? /^\s*(?::\s*[\w.<>?,\s*[\]()]+?)?\s*(?:where\s+[^{=]+)?\{/.exec(after)
    : lang === 'php'
      ? /^\s*(?:use\s*\([^)]*\)\s*)?(?::\s*\??[\w\\|]+\s*)?\{/.exec(after)
      : lang === 'csharp'
        ? /^\s*(?:where\s+[^{=;]+)?(?::\s*(?:base|this)\s*\([^)]*\)\s*)?\{/.exec(after)
        : /^\s*(?::\s*[^{=;]+?)?\s*\{/.exec(after);
  if (brace) {
    const open = close + 1 + brace[0].length - 1;
    const end = matchBracket(masked, open);
    return end < 0 ? null : end;
  }
  const expr = (lang === 'kotlin' ? /^\s*(?::\s*[\w.<>?,\s]+?)?\s*=(?!=)/ : lang === 'csharp' ? /^\s*=>/ : null)?.exec(after);
  if (expr) {
    const from = close + 1 + expr[0].length;
    const stop = lang === 'csharp' ? masked.indexOf(';', from) : masked.indexOf('\n', from);
    return stop < 0 ? masked.length - 1 : stop;
  }
  return null;
}

function braceFunctions(text: string, lang: Exclude<ExtraLang, 'python' | 'ruby' | 'rust'>): FunctionSpan[] {
  const masked = maskExtra(text, lang);
  const starts = lineStarts(text);
  const typeRe = lang === 'csharp' ? /\b(?:class|interface|struct|record|enum)\s+([A-Za-z_]\w*)/g
    : lang === 'kotlin' ? /\b(?:class|interface|object)\s+([A-Za-z_]\w*)/g
      : lang === 'php' ? /\b(?:class|interface|trait|enum)\s+([A-Za-z_]\w*)/g
        : /\bclass\s+([A-Za-z_$][\w$]*)/g;
  const types = typeSpans(masked, typeRe);
  const out: FunctionSpan[] = [];
  const seen = new Set<string>();
  const push = (name: string, at: number, end: number) => {
    const owner = ownerOf(types, at);
    const span = { qualified: owner ? `${owner.name}.${name}` : name, name, start: lineOf(starts, at), end: lineOf(starts, end) };
    const key = `${span.qualified}:${span.start}`;
    if (!seen.has(key)) { seen.add(key); out.push(span); }
  };
  // Keyword-introduced functions: `function f(` (JS / PHP), `fun f(` / `fun T.f(` (Kotlin).
  const kw = lang === 'kotlin' ? /\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?([A-Za-z_]\w*)\s*\(/g : lang === 'csharp' ? null : /\bfunction\s*\*?\s*&?\s*([A-Za-z_$][\w$]*)\s*\(/g;
  if (kw) {
    for (const m of masked.matchAll(kw)) {
      const open = m.index + m[0].length - 1;
      const close = matchBracket(masked, open);
      if (close < 0) continue;
      const end = bodyEnd(masked, close, lang);
      if (end !== null) push(m[1]!, m.index, end);
    }
  }
  if (lang === 'js') {
    // `const f = async (…) => {…}` / `f = function (…) {…}`.
    for (const m of masked.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:function\b[^(]*)?\(/g)) {
      const open = m.index + m[0].length - 1;
      const close = matchBracket(masked, open);
      if (close < 0) continue;
      const arrow = /^\s*(?::\s*[^=]+?)?\s*=>\s*/.exec(masked.slice(close + 1, close + 300));
      if (arrow) {
        const from = close + 1 + arrow[0].length;
        if (masked[from] === '{') { const e = matchBracket(masked, from); if (e >= 0) push(m[1]!, m.index, e); }
        else { const e = masked.indexOf('\n', from); push(m[1]!, m.index, e < 0 ? masked.length - 1 : e); }
        continue;
      }
      const end = bodyEnd(masked, close, lang);
      if (end !== null) push(m[1]!, m.index, end);
    }
  }
  if (lang === 'js' || lang === 'csharp') {
    // Class methods without a keyword: `name(…) {` (JS) / `Type Name(…) {` (C#), only directly inside a class body.
    for (const m of masked.matchAll(/([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>)?\s*\(/g)) {
      const name = m[1]!;
      if (NOT_NAMES.has(name)) continue;
      const owner = ownerOf(types, m.index);
      if (!owner) continue;
      let k = m.index - 1;
      while (k >= 0 && /\s/.test(masked[k]!)) k--;
      // C# nullable return types (`Stream? M(`) end in `?` after a type name; other `?` are operators.
      const nullableType = lang === 'csharp' && masked[k] === '?' && /[\w>\]]/.test(masked[k - 1] ?? '');
      if (k >= 0 && /[.=+\-*/%!&|?:,(]/.test(masked[k]!) && !(lang === 'csharp' && masked[k] === ']') && !nullableType) continue;
      if (lang === 'csharp' && (k < 0 || !/[\w>\]?]/.test(masked[k]!))) continue;
      if (lang === 'js' && k >= 0 && !/[;{}\s\w*]/.test(masked[k]!)) continue;
      const prevWord = /([A-Za-z_$][\w$]*)$/.exec(masked.slice(Math.max(0, k - 40), k + 1))?.[1];
      if (prevWord && ['new', 'return', 'throw', 'await', 'case', 'else', 'typeof', 'yield', 'in', 'of'].includes(prevWord)) continue;
      const open = m.index + m[0].length - 1;
      const close = matchBracket(masked, open);
      if (close < 0) continue;
      const end = bodyEnd(masked, close, lang);
      if (end === null) continue;
      // Must be a member of the innermost type, not a call inside a method body.
      if (out.some((f) => f.start < lineOf(starts, m.index) && lineOf(starts, m.index) <= f.end && ownerOf(types, m.index) === owner && f.qualified.startsWith(`${owner.name}.`))) continue;
      push(name, m.index, end);
    }
  }
  return out;
}

// ---- Ruby ------------------------------------------------------------------------------------------------

/** Ruby source with `#` comments, string / regexp contents and heredoc bodies blanked (lines kept). */
function maskRuby(text: string): string[] {
  const out: string[] = [];
  let heredoc: string | null = null;
  let block = false;
  for (const raw of text.split('\n')) {
    if (block) { out.push(''); if (/^=end\b/.test(raw)) block = false; continue; }
    if (/^=begin\b/.test(raw)) { block = true; out.push(''); continue; }
    if (heredoc) { out.push(''); if (raw.trim() === heredoc) heredoc = null; continue; }
    let line = '';
    let q: string | null = null;
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i]!;
      if (q) { if (c === '\\') { line += '  '; i++; continue; } if (c === q) { q = null; line += c; } else line += ' '; continue; }
      if (c === '#') break;
      if (c === '"' || c === "'" || c === '`') q = c;
      line += c;
    }
    const h = /<<[~-]?(['"`]?)([A-Z_][A-Z0-9_]*)\1/.exec(line);
    if (h) heredoc = h[2]!;
    out.push(line);
  }
  return out;
}

/** `def` spans by keyword nesting (`class` / `module` / `def` / block openers at line start, `do` at line end, `end`). */
function rubyFunctions(text: string): FunctionSpan[] {
  const lines = maskRuby(text);
  type Frame = { kind: 'type' | 'def' | 'block'; name: string; line: number; owner?: string };
  const stack: Frame[] = [];
  const out: FunctionSpan[] = [];
  const close = (k: number) => {
    const f = stack.pop();
    if (f?.kind === 'def') out.push({ qualified: f.owner ? `${f.owner}.${f.name}` : f.name, name: f.name, start: f.line + 1, end: k + 1 });
  };
  lines.forEach((l, k) => {
    const opener = /^\s*(?:(?:private|protected|public)\s+)?(class|module|def|if|unless|while|until|case|begin|for)\b(.*)$/.exec(l);
    if (opener) {
      const kw = opener[1]!;
      if (kw === 'class' || kw === 'module') {
        const m = /^\s*([A-Z][\w:]*)/.exec(opener[2]!);
        const oneLine = /;\s*end\s*$/.test(l);
        if (!oneLine) stack.push({ kind: m ? 'type' : 'block', name: m ? m[1]!.split('::').pop()! : '', line: k });
        return;
      }
      if (kw === 'def') {
        const name = /^\s*(?:self\.)?([\w?!=]+|\[\]=?)/.exec(opener[2]!)?.[1] ?? '?';
        const owner = [...stack].reverse().find((f) => f.kind === 'type')?.name;
        if (/\bend\s*$/.test(l) || /^\s*(?:self\.)?[\w?!]+(?:\([^)]*\))?\s*=[^=~>]/.test(opener[2]!)) { out.push({ qualified: owner ? `${owner}.${name}` : name, name, start: k + 1, end: k + 1 }); return; }
        stack.push({ kind: 'def', name, line: k, ...(owner ? { owner } : {}) });
        return;
      }
      stack.push({ kind: 'block', name: '', line: k });
      if (/\bend\s*$/.test(l)) stack.pop();
      return;
    }
    if (/^\s*end\b/.test(l)) { const n = (l.match(/(^|[\s;])end\b/g) ?? []).length; for (let i = 0; i < Math.max(1, n); i++) close(k); return; }
    if (/\bdo\s*(\|[^|]*\|)?\s*$/.test(l) || /(?:[^=!<>]=|\|\|=)\s*(if|unless|case|begin)\b/.test(l)) stack.push({ kind: 'block', name: '', line: k });
  });
  return out;
}

// ---- Rust ------------------------------------------------------------------------------------------------

/** Rust source with comments (nested block comments too), string / char contents blanked; lifetimes kept. */
function maskRustSrc(text: string): string {
  const out = text.split('');
  const blank = (a: number, b: number) => { for (let k = a; k < b; k++) if (out[k] !== '\n') out[k] = ' '; };
  let i = 0;
  while (i < text.length) {
    const c = text[i]!;
    const d = text[i + 1];
    if (c === '/' && d === '/') { const e = text.indexOf('\n', i); const end = e < 0 ? text.length : e; blank(i, end); i = end; continue; }
    if (c === '/' && d === '*') { let depth = 1; let k = i + 2; while (k < text.length && depth) { if (text[k] === '/' && text[k + 1] === '*') { depth++; k += 2; } else if (text[k] === '*' && text[k + 1] === '/') { depth--; k += 2; } else k++; } blank(i, k); i = k; continue; }
    const raw = /^b?r(#*)"/.exec(text.slice(i, i + 10));
    if (raw && !/\w/.test(text[i - 1] ?? '')) { const close = '"' + raw[1]; const s = i + raw[0].length; const e = text.indexOf(close, s); const end = e < 0 ? text.length : e; blank(s, end); i = end + close.length; continue; }
    if (c === '"') { let k = i + 1; while (k < text.length && text[k] !== '"') k += text[k] === '\\' ? 2 : 1; blank(i + 1, k); i = k + 1; continue; }
    if (c === "'") { const ch = /^'(\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'\n])'/.exec(text.slice(i, i + 14)); if (ch) { blank(i + 1, i + ch[0].length - 1); i += ch[0].length; continue; } }
    i++;
  }
  return out.join('');
}

/** `fn` items with bodies; methods of `impl T` / `impl Trait for T` are `T.method`; attributes above a fn belong to it. */
function rustFunctions(text: string): FunctionSpan[] {
  const masked = maskRustSrc(text);
  const starts = lineStarts(text);
  const impls: TypeSpan[] = [];
  for (const m of masked.matchAll(/\bimpl\b\s*(?:<[^{]*?>)?\s*([^{;]+?)\s*(?:where\b[^{]*)?\{/g)) {
    const head = m[1]!.replace(/<[^<>]*(?:<[^<>]*>[^<>]*)*>/g, '');
    const target = (/\bfor\s+(.+)$/.exec(head)?.[1] ?? head).trim().replace(/^&\s*(mut\s+)?/, '');
    const name = target.split('::').pop()!.trim();
    const open = m.index + m[0].length - 1;
    const end = matchBracket(masked, open);
    if (/^[A-Za-z_]\w*$/.test(name)) impls.push({ name, from: open, to: end < 0 ? masked.length : end });
  }
  const traits: TypeSpan[] = [];
  for (const m of masked.matchAll(/\btrait\s+([A-Za-z_]\w*)[^{;]*\{/g)) {
    const open = m.index + m[0].length - 1;
    const end = matchBracket(masked, open);
    traits.push({ name: m[1]!, from: open, to: end < 0 ? masked.length : end });
  }
  const lines = text.split('\n');
  const out: FunctionSpan[] = [];
  for (const m of masked.matchAll(/\bfn\s+([A-Za-z_]\w*)\s*(?:<[^(]*?>)?\s*\(/g)) {
    const open = m.index + m[0].length - 1;
    const close = matchBracket(masked, open);
    if (close < 0) continue;
    const brace = masked.slice(close).search(/[{;]/);
    if (brace < 0 || masked[close + brace] !== '{') continue;
    const end = matchBracket(masked, close + brace);
    if (end < 0) continue;
    const owner = ownerOf([...impls, ...traits], m.index);
    let startLine = lineOf(starts, m.index);
    while (startLine > 1 && /^\s*#\[/.test(lines[startLine - 2]!)) startLine--;
    out.push({ qualified: owner ? `${owner.name}.${m[1]}` : m[1]!, name: m[1]!, start: startLine, end: lineOf(starts, end) });
  }
  return out;
}

export function extraFunctions(text: string, lang: ExtraLang): FunctionSpan[] {
  if (lang === 'ruby') return rubyFunctions(text);
  if (lang === 'rust') return rustFunctions(text);
  return lang === 'python' ? pythonFunctions(text) : braceFunctions(text, lang);
}
