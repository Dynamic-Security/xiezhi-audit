// Rule files: rules/<lang>/<framework>/<name>.scm + .yaml. YAML is metadata only;
// cross-node logic can only call built-in named post functions (no executable code in rules).
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { parse as parseYaml } from 'yaml';
import { canonicalJson, sha256Hex, resourcePath } from '@xiezhi/contracts';

export const POST_FUNCTIONS = [
  'spring_request_mapping', 'java_annotation_auth', 'java_filter_class', 'java_security_config',
  'mybatis_annotation_dollar', 'mybatis_xml_dollar', 'go_router_route', 'go_nethttp_route', 'jaxrs_resource',
  // GORM conditions from the request / concatenated clauses.
  'go_gorm_request_condition', 'go_gorm_raw_clause',
] as const;
/**
 * The languages beyond Java / Go name their post functions `<prefix><name>` (e.g. `python_flask_route`); the extractor of that
 * language interprets them, so the whitelist stays per language without a shared list to edit.
 */
export const POST_FUNCTION_PREFIXES = ['python_', 'js_', 'php_', 'kotlin_', 'csharp_', 'java_', 'go_', 'jsp_', 'ruby_', 'rust_'] as const;
export type PostFunction = (typeof POST_FUNCTIONS)[number] | `${(typeof POST_FUNCTION_PREFIXES)[number]}${string}`;
/** Rule languages: `rules/<lang>/…` (TS files use the `javascript` rules; `xml` and `jsp` have no grammar). */
export const RULE_LANGS = ['java', 'go', 'python', 'javascript', 'php', 'kotlin', 'csharp', 'xml', 'jsp', 'ruby', 'rust'] as const;

export function isPostFunction(name: string): name is PostFunction {
  return (POST_FUNCTIONS as readonly string[]).includes(name) || POST_FUNCTION_PREFIXES.some((p) => name.startsWith(p) && /^[a-z][a-z0-9_]{2,63}$/.test(name));
}

export interface RuleMatch {
  receiverTypes?: string[];
  receiverNamePattern?: string;
  receiverTextPattern?: string;
  notReceiverTextPattern?: string;
  receiverImport?: string;
  receiverImportAny?: string[];
  requiresImportAny?: string[];
  notImportAny?: string[];
  minArgs?: number;
}

export interface RuleDef {
  id: string;
  version: number;
  kind: 'entrypoint' | 'sink' | 'auth_signal';
  lang: (typeof RULE_LANGS)[number];
  framework: string;
  file: string;
  query: string | null;
  captures: Record<string, string>;
  post?: PostFunction;
  category?: string;
  cwe?: string[];
  severityHint?: string;
  api?: string;
  match?: RuleMatch;
}

export interface RuleSet {
  rules: RuleDef[];
  version: string;
  errors: string[];
}

/** Default rules directory: `rules/` of the resource root (repository or installed package). */
export function defaultRulesDir(): string {
  return resourcePath('rules');
}

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (name.endsWith('.yaml')) out.push(p);
  }
}

export function loadRules(dir = defaultRulesDir()): RuleSet {
  const files: string[] = [];
  const errors: string[] = [];
  if (!existsSync(dir)) return { rules: [], version: sha256Hex('[]'), errors: [`rules directory not found: ${dir}`] };
  walk(dir, files);
  const rules: RuleDef[] = [];
  for (const file of files) {
    const rel = relative(dir, file);
    try {
      const meta = parseYaml(readFileSync(file, 'utf8')) as Record<string, unknown>;
      const kind = meta.kind as RuleDef['kind'];
      if (!['entrypoint', 'sink', 'auth_signal'].includes(kind)) throw new Error(`unsupported kind ${String(kind)}`);
      const post = meta.post as PostFunction | undefined;
      if (post && !isPostFunction(post)) throw new Error(`unknown post function ${post}`);
      if (!(RULE_LANGS as readonly string[]).includes(String(meta.lang))) throw new Error(`unsupported lang ${String(meta.lang)}`);
      const scm = file.replace(/\.yaml$/, '.scm');
      const query = existsSync(scm) ? readFileSync(scm, 'utf8') : null;
      if (!query && meta.lang !== 'xml' && meta.lang !== 'jsp') throw new Error('missing .scm query');
      rules.push({
        id: String(meta.id), version: Number(meta.version), kind, lang: meta.lang as RuleDef['lang'],
        framework: String(meta.framework), file: rel, query, captures: (meta.captures ?? {}) as Record<string, string>,
        ...(post ? { post } : {}),
        ...(meta.category ? { category: String(meta.category) } : {}),
        ...(meta.cwe ? { cwe: (meta.cwe as string[]).map(String) } : {}),
        ...(meta.severityHint ? { severityHint: String(meta.severityHint) } : {}),
        ...(meta.api ? { api: String(meta.api) } : {}),
        ...(meta.match ? { match: meta.match as RuleMatch } : {}),
      });
    } catch (e) {
      errors.push(`${rel}: ${(e as Error).message}`);
    }
  }
  rules.sort((a, b) => a.id.localeCompare(b.id));
  const version = sha256Hex(canonicalJson(rules.map((r) => [r.id, r.version])));
  return { rules, version, errors };
}

/** JS RegExp from a rule pattern; supports a leading `(?i)` flag. */
export function ruleRegex(pattern: string): RegExp {
  return pattern.startsWith('(?i)') ? new RegExp(pattern.slice(4), 'i') : new RegExp(pattern);
}
