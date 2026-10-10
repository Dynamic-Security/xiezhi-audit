// Independent function locator for scoring ("危险点所在函数相同"). A lexical scanner —
// strings and comments masked, braces matched — not the product's tree-sitter index, so the scorer
// never grades the product with the product's own symbol resolution.

import { extraFunctions, extraLangOf, type ExtraLang } from './locate-extra.js';

export interface FunctionSpan {
  /** `Class.method` (Java, and class members of the other languages), `Recv.Method` or `Func` (Go), `namespace.id` (MyBatis XML), bare `func` (top-level functions). */
  qualified: string;
  name: string;
  /** 1-based inclusive line range. */
  start: number;
  end: number;
}

type Lang = 'java' | 'go' | 'xml' | ExtraLang;

export function langOf(file: string): Lang | null {
  const f = file.toLowerCase();
  if (f.endsWith('.java')) return 'java';
  if (f.endsWith('.go')) return 'go';
  if (f.endsWith('.xml')) return 'xml';
  return extraLangOf(f);
}

/** Replace string/char literals and comments by spaces (newlines kept) so offsets and lines survive. */
export function maskCode(text: string, lang: 'java' | 'go'): string {
  const out = text.split('');
  const blank = (from: number, to: number) => { for (let k = from; k < to && k < out.length; k++) if (out[k] !== '\n') out[k] = ' '; };
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    const d = text[i + 1];
    if (c === '/' && d === '/') {
      const e = text.indexOf('\n', i);
      const end = e < 0 ? n : e;
      blank(i, end);
      i = end;
    } else if (c === '/' && d === '*') {
      const e = text.indexOf('*/', i + 2);
      const end = e < 0 ? n : e + 2;
      blank(i, end);
      i = end;
    } else if (lang === 'java' && c === '"' && text.startsWith('"""', i)) {
      const e = text.indexOf('"""', i + 3);
      const end = e < 0 ? n : e + 3;
      blank(i + 1, end - 1);
      i = end;
    } else if (c === '"' || c === '\'') {
      let j = i + 1;
      while (j < n && text[j] !== c && text[j] !== '\n') j += text[j] === '\\' ? 2 : 1;
      blank(i + 1, j);
      i = j + 1;
    } else if (lang === 'go' && c === '`') {
      const e = text.indexOf('`', i + 1);
      const end = e < 0 ? n : e + 1;
      blank(i + 1, end - 1);
      i = end;
    } else i++;
  }
  return out.join('');
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

/** Offset of the bracket closing the one at `open` (masked text), or -1. */
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

const JAVA_NOT_NAMES = new Set(['if', 'for', 'while', 'switch', 'catch', 'synchronized', 'return', 'new', 'throw', 'else', 'try', 'do', 'case', 'assert', 'super', 'this']);
const JAVA_NOT_BEFORE = new Set(['new', 'return', 'throw', 'else', 'case', 'assert', 'yield']);

function javaFunctions(text: string): FunctionSpan[] {
  const masked = maskCode(text, 'java');
  const starts = lineStarts(text);
  const types: { name: string; from: number; to: number }[] = [];
  for (const m of masked.matchAll(/\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)/g)) {
    const brace = masked.indexOf('{', m.index + m[0].length);
    if (brace < 0) continue;
    const end = matchBracket(masked, brace);
    types.push({ name: m[1]!, from: brace, to: end < 0 ? masked.length : end });
  }
  const out: FunctionSpan[] = [];
  for (const m of masked.matchAll(/([A-Za-z_$][\w$]*)\s*\(/g)) {
    const name = m[1]!;
    if (JAVA_NOT_NAMES.has(name)) continue;
    const at = m.index;
    // Previous token: a type, a modifier or generic closer; never an operator, dot, `@` or `new`.
    let k = at - 1;
    while (k >= 0 && /\s/.test(masked[k]!)) k--;
    if (k < 0 || !/[\w$>\]]/.test(masked[k]!) || (masked[k] === '>' && masked[k - 1] === '-')) continue;
    const prevWord = /([A-Za-z_$][\w$]*)$/.exec(masked.slice(Math.max(0, k - 40), k + 1))?.[1];
    if (prevWord && JAVA_NOT_BEFORE.has(prevWord)) continue;
    const open = at + m[0].length - 1;
    const close = matchBracket(masked, open);
    if (close < 0) continue;
    const rest = /^\s*(?:throws\s+[\w$.<>,\s]+?)?\s*([{;])/.exec(masked.slice(close + 1, close + 400));
    if (!rest) continue;
    const bodyAt = close + 1 + rest[0].length - 1;
    let end = bodyAt;
    if (rest[1] === '{') {
      end = matchBracket(masked, bodyAt);
      if (end < 0) continue;
    }
    const owner = types.filter((t) => t.from < at && at < t.to).sort((a, b) => b.from - a.from)[0];
    if (!owner) continue;
    out.push({ qualified: `${owner.name}.${name}`, name, start: lineOf(starts, at), end: lineOf(starts, end) });
  }
  return out;
}

function goFunctions(text: string): FunctionSpan[] {
  const masked = maskCode(text, 'go');
  const starts = lineStarts(text);
  const out: FunctionSpan[] = [];
  const re = /(^|\n)func\s*(?:\(\s*(?:[A-Za-z_]\w*\s+)?\*?\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)?\(/g;
  for (const m of masked.matchAll(re)) {
    const recv = m[2];
    const name = m[3]!;
    const at = m.index + m[1]!.length;
    const open = m.index + m[0].length - 1;
    const close = matchBracket(masked, open);
    if (close < 0) continue;
    // Results may be parenthesized; the body is the first `{` outside parentheses.
    // `interface{}` / `struct{…}` result types are skipped; a newline at depth 0 means no body.
    let i = close + 1;
    let depth = 0;
    let body = -1;
    while (i < masked.length) {
      const ch = masked[i]!;
      if (ch === '(') depth++;
      else if (ch === ')') depth--;
      else if (ch === '\n' && depth === 0) break;
      else if (ch === '{' && depth === 0) {
        if (/\b(?:interface|struct)\s*$/.test(masked.slice(close + 1, i))) {
          const skip = matchBracket(masked, i);
          if (skip < 0) break;
          i = skip + 1;
          continue;
        }
        body = i;
        break;
      }
      i++;
    }
    if (body < 0) continue;
    i = body;
    const end = matchBracket(masked, i);
    if (end < 0) continue;
    out.push({ qualified: recv ? `${recv}.${name}` : name, name, start: lineOf(starts, at), end: lineOf(starts, end) });
  }
  return out;
}

function xmlFunctions(text: string): FunctionSpan[] {
  const starts = lineStarts(text);
  const ns = /<mapper\b[^>]*\bnamespace\s*=\s*"([^"]+)"/.exec(text)?.[1];
  const simpleNs = ns ? ns.split('.').pop()! : null;
  const out: FunctionSpan[] = [];
  for (const m of text.matchAll(/<(select|insert|update|delete|sql)\b[^>]*\bid\s*=\s*"([^"]+)"[^>]*>/g)) {
    const close = text.indexOf(`</${m[1]}>`, m.index);
    const end = close < 0 ? m.index + m[0].length : close;
    out.push({ qualified: simpleNs ? `${simpleNs}.${m[2]}` : m[2]!, name: m[2]!, start: lineOf(starts, m.index), end: lineOf(starts, end) });
  }
  return out;
}

/** Every function-like unit of a file (empty for languages the scanner does not know). */
export function listFunctions(text: string, file: string): FunctionSpan[] {
  const lang = langOf(file);
  if (lang === 'java') return javaFunctions(text);
  if (lang === 'go') return goFunctions(text);
  if (lang === 'xml') return xmlFunctions(text);
  if (lang) return extraFunctions(text, lang);
  return [];
}

/** Spans of a labelled function: `A.b` matches the qualified name, a bare `b` any owner. */
export function functionSpans(text: string, file: string, fn: string): FunctionSpan[] {
  const want = fn.trim();
  const tail = want.split('.').slice(-2).join('.');
  return listFunctions(text, file).filter((f) => (want.includes('.') ? f.qualified === tail || f.qualified.endsWith(`.${tail}`) : f.name === want));
}

/** Innermost function containing a line, or null. */
export function enclosingFunction(text: string, file: string, line: number): FunctionSpan | null {
  const hits = listFunctions(text, file).filter((f) => f.start <= line && line <= f.end);
  hits.sort((a, b) => (a.end - a.start) - (b.end - b.start) || a.start - b.start);
  return hits[0] ?? null;
}

export function overlaps(a: { start: number; end: number }, b: { start: number; end: number }): boolean {
  return a.start <= b.end && b.start <= a.end;
}
