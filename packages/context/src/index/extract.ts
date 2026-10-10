// Per-file extraction dispatcher. Runs in worker threads (or inline for small repos/tests).
import { Parser, type ParseOptions } from 'web-tree-sitter';
import { compileRules, errorRatio, type CompiledRule } from './common.js';
import { loadLanguage, type GrammarLang } from './grammar.js';
import { pluginFor, type LanguagePlugin } from './languages.js';
import type { RuleDef } from './rules.js';
import { emptyExtract, type ExtractInput, type FileExtract } from './types.js';

export const MAX_PARSE_BYTES = 2 * 1024 * 1024;
const ERROR_RATIO_LIMIT = 0.3;
/** a file whose parse takes longer is recorded as a `timeout` gap. */
export const PARSE_TIMEOUT_MS = 5000;

export class Extractor {
  private parsers = new Map<GrammarLang, { parser: Parser; rules: CompiledRule[] }>();
  constructor(private readonly ruleDefs: RuleDef[], private readonly parseTimeoutMs = PARSE_TIMEOUT_MS) {}

  private async get(plugin: LanguagePlugin, grammar: GrammarLang) {
    let p = this.parsers.get(grammar);
    if (!p) {
      const language = await loadLanguage(grammar);
      const parser = new Parser();
      parser.setLanguage(language);
      p = { parser, rules: compileRules(this.ruleDefs, plugin.ruleLang, language) };
      this.parsers.set(grammar, p);
    }
    return p;
  }

  async extract(input: ExtractInput): Promise<FileExtract> {
    const plugin = pluginFor(input.lang);
    if (!plugin) return emptyExtract(input);
    if (Buffer.byteLength(input.text) > MAX_PARSE_BYTES) {
      const fx = emptyExtract(input);
      fx.gaps.push({ path: input.path, reason: 'oversize', detail: 'file larger than 2 MB was not parsed' });
      return fx;
    }
    const { parser, rules } = await this.get(plugin, plugin.grammar(input.path));
    const deadline = Date.now() + this.parseTimeoutMs;
    let timedOut = false;
    // Returning true from the progress callback cancels the parse (the typings declare `void`).
    const progressCallback = () => (timedOut ||= Date.now() > deadline);
    const tree = parser.parse(input.text, null, { progressCallback } as unknown as ParseOptions);
    if (timedOut) {
      // A cancelled parse would otherwise resume on the next call.
      parser.reset();
      tree?.delete();
      const fx = emptyExtract(input);
      fx.gaps.push({ path: input.path, reason: 'timeout', detail: `parse exceeded ${this.parseTimeoutMs / 1000} s; file not indexed` });
      return fx;
    }
    if (!tree) {
      const fx = emptyExtract(input);
      fx.gaps.push({ path: input.path, reason: 'parse_error', detail: 'parser returned no tree' });
      return fx;
    }
    try {
      const fx = plugin.extract(input, tree, rules);
      const ratio = errorRatio(tree.rootNode);
      if (ratio > ERROR_RATIO_LIMIT) fx.gaps.push({ path: input.path, reason: 'parse_error', detail: `ERROR nodes ${(ratio * 100).toFixed(0)}%; results are partial` });
      return fx;
    } catch (e) {
      const fx = emptyExtract(input);
      fx.gaps.push({ path: input.path, reason: 'rule_error', detail: (e as Error).message.slice(0, 300) });
      return fx;
    } finally {
      tree.delete();
    }
  }
}
