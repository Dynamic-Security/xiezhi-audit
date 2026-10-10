// Shared helpers for per-language extractors.
import type { Node, Query, Language } from 'web-tree-sitter';
import { Query as TSQuery } from 'web-tree-sitter';
import type { LineRange, Sink } from '@xiezhi/contracts';
import { ruleRegex, type RuleDef, type RuleMatch } from './rules.js';

export interface CompiledRule { rule: RuleDef; query: Query | null; error?: string }

export function compileRules(rules: RuleDef[], lang: string, language: Language): CompiledRule[] {
  return rules.filter((r) => r.lang === lang).map((rule) => {
    if (!rule.query) return { rule, query: null };
    try {
      return { rule, query: new TSQuery(language, rule.query) };
    } catch (e) {
      return { rule, query: null, error: (e as Error).message };
    }
  });
}

export function rangeOf(node: Node): LineRange {
  return { startLine: node.startPosition.row + 1, endLine: node.endPosition.row + 1 };
}

/** Raw capture names plus the rule's `captures:` aliases (field → "@capture"). */
export function captureMap(captures: { name: string; node: Node }[], aliases: Record<string, string> = {}): Map<string, Node> {
  const m = new Map<string, Node>();
  for (const c of captures) if (!m.has(c.name)) m.set(c.name, c.node);
  for (const [field, ref] of Object.entries(aliases)) {
    const node = m.get(ref.replace(/^@/, '').split('.')[0]!);
    if (node && !m.has(field)) m.set(field, node);
  }
  return m;
}

export function unquote(text: string): string {
  const t = text.trim();
  if (t.startsWith('"""')) return t.slice(3, -3);
  if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith('`') && t.endsWith('`')) || (t.startsWith("'") && t.endsWith("'"))) {
    return t.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  }
  return t;
}

export interface MatchFacts {
  receiverText: string | null;
  receiverType: string | null;
  receiverImport: string | null;
  imports: ReadonlySet<string>;
  argCount: number;
}

/** Deterministic rule matching (see rules/*.yaml `match:`). */
export function ruleMatches(m: RuleMatch | undefined, f: MatchFacts): boolean {
  if (!m) return true;
  if (m.requiresImportAny && !m.requiresImportAny.some((i) => f.imports.has(i))) return false;
  if (m.notImportAny && m.notImportAny.some((i) => f.imports.has(i))) return false;
  if (m.minArgs !== undefined && f.argCount < m.minArgs) return false;
  const rt = f.receiverText ?? '';
  if (m.notReceiverTextPattern && ruleRegex(m.notReceiverTextPattern).test(rt)) return false;
  const importList = m.receiverImportAny ?? (m.receiverImport ? [m.receiverImport] : null);
  if (importList) return !!f.receiverImport && importList.includes(f.receiverImport);
  if (m.receiverTextPattern && ruleRegex(m.receiverTextPattern).test(rt)) return true;
  if (m.receiverTypes) {
    if (f.receiverType) return m.receiverTypes.includes(f.receiverType);
    if (m.receiverNamePattern) return ruleRegex(m.receiverNamePattern).test(rt);
    return false;
  }
  if (m.receiverNamePattern) return ruleRegex(m.receiverNamePattern).test(rt);
  if (m.receiverTextPattern) return false;
  return true;
}

export function fillApi(template: string, vars: Record<string, string | null | undefined>): string {
  return template.replace(/\{(\w+)\}/g, (_m, k: string) => vars[k] ?? '?');
}

const CONCAT_RE = /\+|Sprintf|String\.format|\.concat\(|StringBuilder|\.append\(|fmt\.Sprint|strings\.Join/;

export function taintHintOf(args: Node | undefined): string | undefined {
  if (!args) return undefined;
  const text = args.text;
  if (CONCAT_RE.test(text)) return 'string_concat';
  const named = args.namedChildren.filter((n): n is Node => !!n);
  if (named.length > 0 && named.every((n) => /string_literal|interpreted_string_literal|raw_string_literal/.test(n.type))) return 'constant';
  return undefined;
}

export function makeSink(repo: string, path: string, rule: RuleDef, node: Node, symbolId: string | null, api: string, taint: string | undefined): Sink {
  const r = rangeOf(node);
  return {
    sinkId: `${repo}:${path}#L${r.startLine}:${node.startPosition.column + 1}:${rule.category ?? 'other'}`,
    category: rule.category ?? 'other',
    symbolId,
    path,
    range: r,
    api,
    ...(taint ? { taintHint: taint } : {}),
    ruleId: rule.id,
  };
}

export const AUTH_NAME_RE = /auth|jwt|token|login|session|perm|rbac|acl|guard|verify|sign|secur|role|admin/i;

export function errorRatio(root: Node): number {
  let total = 0;
  let errors = 0;
  const cursor = root.walk();
  let done = false;
  while (!done) {
    total++;
    if (cursor.nodeType === 'ERROR' || cursor.nodeIsMissing) errors++;
    if (cursor.gotoFirstChild()) continue;
    while (!cursor.gotoNextSibling()) {
      if (!cursor.gotoParent()) { done = true; break; }
    }
  }
  cursor.delete();
  return total === 0 ? 0 : errors / total;
}
