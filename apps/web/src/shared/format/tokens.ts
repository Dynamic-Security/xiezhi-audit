// Token amounts in budget inputs are typed in millions (M); the API and the stored strategy stay in tokens.

/** Tokens → the text shown in an M input: 12000000 → "12", 1500000 → "1.5"; '' stays ''. */
export function toMillions(tokens: number | ''): string {
  if (tokens === '') return '';
  return String(Number((tokens / 1e6).toFixed(6)));
}

/** The text typed in an M input → tokens: "12" → 12000000, "0.25" → 250000; empty or not a number → ''. */
export function fromMillions(text: string): number | '' {
  const t = text.trim().replace(/m$/i, '').trim();
  if (!t) return '';
  const m = Number(t);
  return Number.isFinite(m) ? Math.round(m * 1e6) : '';
}

/** A token count for display, always in millions: 119297808 → "119.3M", 18000000 → "18M", 34000 → "0.034M", 0 → "0". */
export function formatTokens(tokens: number): string {
  if (!tokens) return '0';
  const m = tokens / 1e6;
  return `${Number(Math.abs(m) >= 1 ? m.toFixed(2) : m.toPrecision(2))}M`;
}

/** The tokens one budget top-up may add, as the API checks it (same as contracts TOP_UP_TOKENS_MIN / _MAX). */
export const TOP_UP_TOKENS_MIN = 1_000_000;
export const TOP_UP_TOKENS_MAX = 10_000_000_000;
