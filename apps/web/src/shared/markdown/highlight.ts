// Syntax highlighting for code blocks: shiki with the JavaScript regex engine and a fixed set of
// grammars, loaded on first use. Output is tokens (text + colours), rendered as React text nodes — never HTML.
import type { HighlighterCore, ThemedToken } from 'shiki/core';

const GRAMMARS = {
  java: () => import('shiki/langs/java.mjs'), go: () => import('shiki/langs/go.mjs'), kotlin: () => import('shiki/langs/kotlin.mjs'),
  javascript: () => import('shiki/langs/javascript.mjs'), typescript: () => import('shiki/langs/typescript.mjs'), tsx: () => import('shiki/langs/tsx.mjs'),
  sql: () => import('shiki/langs/sql.mjs'), xml: () => import('shiki/langs/xml.mjs'), html: () => import('shiki/langs/html.mjs'),
  yaml: () => import('shiki/langs/yaml.mjs'), json: () => import('shiki/langs/json.mjs'), properties: () => import('shiki/langs/properties.mjs'),
  shellscript: () => import('shiki/langs/shellscript.mjs'), diff: () => import('shiki/langs/diff.mjs'), groovy: () => import('shiki/langs/groovy.mjs'),
  proto: () => import('shiki/langs/proto.mjs'),
  python: () => import('shiki/langs/python.mjs'), php: () => import('shiki/langs/php.mjs'), csharp: () => import('shiki/langs/csharp.mjs'),
  // Ruby and Rust audit languages.
  ruby: () => import('shiki/langs/ruby.mjs'), rust: () => import('shiki/langs/rust.mjs'),
} as const;
type Grammar = keyof typeof GRAMMARS;

const ALIAS: Record<string, Grammar> = {
  js: 'javascript', mjs: 'javascript', jsx: 'tsx', ts: 'typescript', golang: 'go', kt: 'kotlin', yml: 'yaml', sh: 'shellscript', bash: 'shellscript',
  py: 'python', cs: 'csharp', 'c#': 'csharp', rb: 'ruby', rs: 'rust', shell: 'shellscript', zsh: 'shellscript', console: 'shellscript', protobuf: 'proto', gradle: 'groovy', patch: 'diff', mapper: 'xml', pom: 'xml',
};

export function grammarOf(lang: string): Grammar | null {
  const l = lang.toLowerCase();
  return l in GRAMMARS ? (l as Grammar) : ALIAS[l] ?? null;
}

/** Longer code is shown plain: highlighting is a convenience, not worth a frozen tab. */
export const HIGHLIGHT_MAX_CHARS = 20_000;

let highlighter: Promise<HighlighterCore> | null = null;
const loaded = new Set<Grammar>();

async function get(): Promise<HighlighterCore> {
  highlighter ??= (async () => {
    const [{ createHighlighterCore }, { createJavaScriptRegexEngine }] = await Promise.all([import('shiki/core'), import('shiki/engine/javascript')]);
    return createHighlighterCore({
      themes: [import('shiki/themes/github-light.mjs'), import('shiki/themes/github-dark.mjs')],
      langs: [],
      engine: createJavaScriptRegexEngine(),
    });
  })();
  return highlighter;
}

/** Tokens per line with both theme colours as CSS variables (`--shiki-light`, `--shiki-dark`). */
export async function highlight(code: string, lang: string): Promise<ThemedToken[][] | null> {
  const g = grammarOf(lang);
  if (!g || code.length > HIGHLIGHT_MAX_CHARS) return null;
  const h = await get();
  if (!loaded.has(g)) { await h.loadLanguage(GRAMMARS[g]()); loaded.add(g); }
  return h.codeToTokens(code, { lang: g, themes: { light: 'github-light', dark: 'github-dark' }, defaultColor: false }).tokens;
}
