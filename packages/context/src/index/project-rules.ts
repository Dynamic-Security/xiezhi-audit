// Project rules: a confirmed vulnerability solidified into a pattern — a tree-sitter query or a line
// regex — that the next audits run over the snapshot as an extra sink rule. The pattern is data from a model or a user;
// it is only compiled and matched (tree-sitter queries and JS regexes have no side effects), never executed as code.
import { Parser, Query } from 'web-tree-sitter';
import type { Sink } from '@xiezhi/contracts';
import { loadLanguage, type GrammarLang } from './grammar.js';
import { pluginFor } from './languages.js';
import type { SnapshotView } from '../snapshot/view.js';

export interface ProjectRuleSpec {
  id: string;
  lang: string;
  matcher: 'tree_sitter' | 'regex';
  pattern: string;
  category: string;
  title: string;
}

export interface RuleHit { path: string; startLine: number; endLine: number; text: string }
export interface RuleMatchResult { hits: RuleHit[]; files: number; truncated: boolean; error: string | null }

/** Limits per run: a rule that matches more than MAX_HITS places is too broad to be useful (and is cut). */
export const PROJECT_RULE_LIMITS = { maxFiles: 5000, maxFileBytes: 1_000_000, maxHits: 300, maxPatternLength: 4000 } as const;

/** The audit language of a file (by its snapshot language), or null. */
function fileLang(lang: string | undefined): string | null {
  return lang ? pluginFor(lang)?.id ?? null : null;
}

/** Same language family: a TS file matches a `javascript` rule and vice versa (they share rules). */
function sameLang(ruleLang: string, file: string): boolean {
  const norm = (x: string) => (x === 'typescript' ? 'javascript' : x);
  return norm(ruleLang) === norm(file);
}

/** Compile check only: a syntax error in the query or regex, or null. */
export async function checkProjectRule(rule: Pick<ProjectRuleSpec, 'lang' | 'matcher' | 'pattern'>): Promise<string | null> {
  if (!rule.pattern.trim()) return 'empty pattern';
  if (rule.pattern.length > PROJECT_RULE_LIMITS.maxPatternLength) return `pattern longer than ${PROJECT_RULE_LIMITS.maxPatternLength} characters`;
  if (rule.matcher === 'regex') {
    try { new RegExp(rule.pattern); return null; } catch (e) { return `regex: ${(e as Error).message}`; }
  }
  const plugin = pluginFor(rule.lang);
  if (!plugin) return `unsupported language ${rule.lang}`;
  const grammars = new Set<GrammarLang>([plugin.grammar(rule.lang === 'typescript' ? 'a.ts' : rule.lang === 'javascript' ? 'a.js' : 'a')]);
  for (const g of grammars) {
    try { new Query(await loadLanguage(g), rule.pattern).delete(); } catch (e) { return `tree-sitter query (${g}): ${(e as Error).message.slice(0, 300)}`; }
  }
  return null;
}

/** Run one rule over a snapshot: every place it matches (a tree-sitter match spans its `@sink` capture, else the whole match). */
export async function matchProjectRule(view: SnapshotView, rule: Pick<ProjectRuleSpec, 'lang' | 'matcher' | 'pattern'>): Promise<RuleMatchResult> {
  const error = await checkProjectRule(rule);
  if (error) return { hits: [], files: 0, truncated: false, error };
  const L = PROJECT_RULE_LIMITS;
  const files = view.listFiles().filter((f) => f.indexable && f.size <= L.maxFileBytes && sameLang(rule.lang, fileLang(f.lang) ?? '')).slice(0, L.maxFiles);
  const hits: RuleHit[] = [];
  const parser = rule.matcher === 'tree_sitter' ? new Parser() : null;
  const queries = new Map<GrammarLang, Query>();
  try {
    for (const f of files) {
      if (hits.length >= L.maxHits) break;
      if (rule.matcher === 'regex') {
        const re = new RegExp(rule.pattern);
        const lines = view.lines(f.path);
        for (let i = 0; i < lines.length && hits.length < L.maxHits; i++) {
          if (re.test(lines[i]!)) hits.push({ path: f.path, startLine: i + 1, endLine: i + 1, text: lines[i]!.trim().slice(0, 200) });
        }
        continue;
      }
      const g = pluginFor(fileLang(f.lang)!)!.grammar(f.path);
      const language = await loadLanguage(g);
      let q = queries.get(g);
      if (!q) {
        try { q = new Query(language, rule.pattern); } catch { continue; } // the query is valid for the rule's grammar, not this one (e.g. TSX)
        queries.set(g, q);
      }
      parser!.setLanguage(language);
      const tree = parser!.parse(view.text(f.path));
      if (!tree) continue;
      try {
        for (const m of q.matches(tree.rootNode)) {
          const node = (m.captures.find((c) => c.name === 'sink') ?? m.captures[0])?.node;
          if (!node) continue;
          hits.push({ path: f.path, startLine: node.startPosition.row + 1, endLine: node.endPosition.row + 1, text: node.text.split('\n')[0]!.trim().slice(0, 200) });
          if (hits.length >= L.maxHits) break;
        }
      } finally { tree.delete(); }
    }
  } finally {
    for (const q of queries.values()) q.delete();
    parser?.delete();
  }
  // One hit per place (a query can match the same node through several patterns).
  const seen = new Set<string>();
  const unique = hits.filter((h) => { const k = `${h.path}:${h.startLine}`; if (seen.has(k)) return false; seen.add(k); return true; });
  return { hits: unique, files: files.length, truncated: hits.length >= L.maxHits, error: null };
}

/** Does any hit fall on the original place (same file, overlapping lines with a little slack)? */
export function hitsOrigin(hits: RuleHit[], origin: { path: string; startLine: number; endLine: number }, slack = 2): boolean {
  return hits.some((h) => h.path === origin.path && h.startLine <= origin.endLine + slack && h.endLine >= origin.startLine - slack);
}

/** Hits as sinks of the structure index (rule id `project:<id>`), enclosing symbol from the index when known. */
export function projectRuleSinks(repo: string, rule: ProjectRuleSpec, hits: RuleHit[], enclosing: (path: string, line: number) => string | null): Sink[] {
  return hits.map((h) => ({
    sinkId: `${repo}:${h.path}#L${h.startLine}:project:${rule.id}`, category: rule.category, symbolId: enclosing(h.path, h.startLine),
    path: h.path, range: { startLine: h.startLine, endLine: h.endLine }, api: `项目规则：${rule.title}`.slice(0, 200), ruleId: `project:${rule.id}`,
  }));
}
