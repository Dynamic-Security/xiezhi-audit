// Build (or load cached) structural index for a snapshot.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalJson, sha256Hex, type AuditLanguage, type StructIndex } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';
import { assemble, type XmlFile } from './assemble.js';
import { jspSinks, type JspFile } from './extract-java-web.js';
import { grammarVersions } from './grammar.js';
import { auditLanguagesOfView, pluginFor } from './languages.js';
import { extractAll } from './pool.js';
import { graphqlSchemaOf } from './graphql.js';
import { grpcServicesOf } from './proto.js';
import { secretSinks } from './secrets.js';
import type { RuleSet } from './rules.js';
import type { ExtractInput } from './types.js';

/**
 * Version of the extracted facts, part of the cache key (with the parsed languages): bump it when the indexer extracts
 * something new or differently, so cached indexes are rebuilt.
 */
export const INDEXER_VERSION = '2';

export interface IndexResult {
  index: StructIndex;
  status: 'complete' | 'partial' | 'failed';
  cacheKey: string;
  cached: boolean;
}

export function indexCacheKey(rootHash: string, rules: RuleSet, languages: readonly string[] = []): string {
  return sha256Hex(canonicalJson({ rootHash, rules: rules.version, grammars: grammarVersions(), indexer: INDEXER_VERSION, languages: [...languages].sort() }));
}

export interface BuildIndexOptions {
  indexesDir: string;
  workers?: number;
  signal?: AbortSignal;
  /** Languages to parse; default: the snapshot's audit languages (`auditLanguagesOfView`). */
  languages?: readonly AuditLanguage[];
}

export async function buildIndex(view: SnapshotView, rules: RuleSet, opts: BuildIndexOptions): Promise<IndexResult> {
  const languages = new Set<string>(opts.languages ?? auditLanguagesOfView(view));
  const cacheKey = indexCacheKey(view.rootHash, rules, [...languages]);
  const dir = join(opts.indexesDir, view.rootHash, cacheKey);
  const file = join(dir, 'index.json');
  const statusOf = (idx: StructIndex) => (idx.gaps.length > 0 ? 'partial' : 'complete') as IndexResult['status'];
  if (existsSync(file)) {
    const index = JSON.parse(readFileSync(file, 'utf8')) as StructIndex;
    if (index.repo === view.repo) return { index, status: statusOf(index), cacheKey, cached: true };
  }
  const contexts = new Map<string, (path: string) => Partial<ExtractInput>>();
  const grpcServices = grpcServicesOf(view);
  const graphql = graphqlSchemaOf(view);
  const inputs: ExtractInput[] = [];
  const xml: XmlFile[] = [];
  const jsp: JspFile[] = [];
  for (const f of view.listFiles()) {
    if (!f.indexable) continue;
    const plugin = f.lang && languages.has(f.lang) ? pluginFor(f.lang) : null;
    if (plugin) {
      let ctx = contexts.get(plugin.id);
      if (!ctx) { ctx = plugin.inputContext?.(view) ?? (() => ({})); contexts.set(plugin.id, ctx); }
      inputs.push({ repo: view.repo, path: f.path, lang: f.lang!, text: view.text(f.path), ...ctx(f.path), ...(grpcServices.length ? { grpcServices } : {}), ...(graphql ? { graphql } : {}) });
    } else if (f.lang === 'xml' && f.size < 2 * 1024 * 1024) {
      const text = view.text(f.path);
      if (text.includes('<mapper')) xml.push({ path: f.path, text });
    } else if (languages.has('ruby') && /(\.rake|(^|\/)Rakefile)$/.test(f.path) && f.size < 2 * 1024 * 1024) {
      // Rake tasks (not a snapshot language; parsed with the Ruby plugin by name, like JSP for Java).
      const plugin = pluginFor('ruby')!;
      let ctx = contexts.get(plugin.id);
      if (!ctx) { ctx = plugin.inputContext?.(view) ?? (() => ({})); contexts.set(plugin.id, ctx); }
      inputs.push({ repo: view.repo, path: f.path, lang: 'ruby', text: view.text(f.path), ...ctx(f.path) });
    } else if (languages.has('java') && /\.jspx?$/i.test(f.path) && f.size < 2 * 1024 * 1024) {
      // JSP templates of Java repositories (by extension; not a snapshot language, so cached snapshots work too).
      jsp.push({ path: f.path, text: view.text(f.path) });
    }
  }
  const extracts = await extractAll(inputs, rules.rules, { ...(opts.workers ? { workers: opts.workers } : {}), ...(opts.signal ? { signal: opts.signal } : {}) });
  const index = assemble(view.repo, view.rootHash, rules.version, extracts, xml, rules.rules);
  const jspRules = rules.rules.filter((r) => r.lang === 'jsp');
  if (jspRules.length && jsp.length) {
    index.sinks.push(...jspSinks(view.repo, jsp, jspRules));
    index.sinks.sort((a, b) => a.sinkId.localeCompare(b.sinkId));
  }
  // hard-coded secrets in any text file of the snapshot (not only the parsed languages).
  index.sinks.push(...secretSinks(view));
  for (const err of rules.errors) index.gaps.push({ path: '(rules)', reason: 'rule_error', detail: err });
  mkdirSync(dir, { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(index));
  renameSync(tmp, file);
  return { index, status: statusOf(index), cacheKey, cached: false };
}
