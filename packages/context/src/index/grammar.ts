// tree-sitter WASM grammars. Loaded once per thread and reused.
// The npm package carries the .wasm files in `grammars/` (with `versions.json`) instead of depending on the grammar
// packages, whose install scripts would try to compile native bindings; a source checkout resolves the dependencies.
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { Language, Parser } from 'web-tree-sitter';
import { resourcePath, sha256Hex } from '@xiezhi/contracts';

const require = createRequire(import.meta.url);

/** File names of the vendored grammars → their package versions; null in a source checkout. */
let vendored: Record<string, string> | null | undefined;
function vendoredVersions(): Record<string, string> | null {
  if (vendored === undefined) {
    const p = resourcePath('grammars', 'versions.json');
    vendored = existsSync(p) ? JSON.parse(readFileSync(p, 'utf8')) as Record<string, string> : null;
  }
  return vendored;
}

/** A grammar's .wasm (`tree-sitter-java/tree-sitter-java.wasm`): the vendored copy, else the dependency's. */
export function grammarWasmPath(wasm: string): string {
  return vendoredVersions()?.[basename(wasm)] ? resourcePath('grammars', basename(wasm)) : require.resolve(wasm);
}

export const GRAMMARS = {
  java: { pkg: 'tree-sitter-java', wasm: 'tree-sitter-java/tree-sitter-java.wasm' },
  go: { pkg: 'tree-sitter-go', wasm: 'tree-sitter-go/tree-sitter-go.wasm' },
  // Contract extraction only (connection points of frontend / context repositories).
  javascript: { pkg: 'tree-sitter-javascript', wasm: 'tree-sitter-javascript/tree-sitter-javascript.wasm' },
  typescript: { pkg: 'tree-sitter-typescript', wasm: 'tree-sitter-typescript/tree-sitter-typescript.wasm' },
  tsx: { pkg: 'tree-sitter-typescript', wasm: 'tree-sitter-typescript/tree-sitter-tsx.wasm' },
  // Full-audit languages beyond Java / Go. JS / TS above are also full-audit grammars now.
  python: { pkg: 'tree-sitter-python', wasm: 'tree-sitter-python/tree-sitter-python.wasm' },
  php: { pkg: 'tree-sitter-php', wasm: 'tree-sitter-php/tree-sitter-php.wasm' },
  kotlin: { pkg: '@tree-sitter-grammars/tree-sitter-kotlin', wasm: '@tree-sitter-grammars/tree-sitter-kotlin/tree-sitter-kotlin.wasm' },
  csharp: { pkg: 'tree-sitter-c-sharp', wasm: 'tree-sitter-c-sharp/tree-sitter-c_sharp.wasm' },
  // Ruby and Rust (ABI 14; only the .wasm is used, install scripts never run).
  ruby: { pkg: 'tree-sitter-ruby', wasm: 'tree-sitter-ruby/tree-sitter-ruby.wasm' },
  rust: { pkg: 'tree-sitter-rust', wasm: 'tree-sitter-rust/tree-sitter-rust.wasm' },
} as const;
export type GrammarLang = keyof typeof GRAMMARS;

let initPromise: Promise<void> | null = null;
const languages = new Map<GrammarLang, Language>();

export async function loadLanguage(lang: GrammarLang): Promise<Language> {
  initPromise ??= Parser.init();
  await initPromise;
  let l = languages.get(lang);
  if (!l) {
    l = await Language.load(grammarWasmPath(GRAMMARS[lang].wasm));
    languages.set(lang, l);
  }
  return l;
}

/** Read a dependency's version by walking up from a resolvable file (exports may hide package.json). */
function packageVersion(resolvable: string): string {
  let dir = dirname(require.resolve(resolvable));
  for (let i = 0; i < 5; i++) {
    const p = join(dir, 'package.json');
    if (existsSync(p)) return (JSON.parse(readFileSync(p, 'utf8')) as { version: string }).version;
    dir = dirname(dir);
  }
  return 'unknown';
}

let cachedVersions: Record<string, string> | null = null;

/** Grammar identity for cache keys and doctor integrity checks. */
export function grammarVersions(): Record<string, string> {
  if (cachedVersions) return cachedVersions;
  const out: Record<string, string> = {};
  for (const [lang, g] of Object.entries(GRAMMARS)) {
    out[lang] = `${vendoredVersions()?.[basename(g.wasm)] ?? packageVersion(g.wasm)}:${sha256Hex(readFileSync(grammarWasmPath(g.wasm))).slice(0, 16)}`;
  }
  out['web-tree-sitter'] = packageVersion('web-tree-sitter/web-tree-sitter.wasm');
  cachedVersions = out;
  return out;
}
