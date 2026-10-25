// Token counts shown to people are always in millions; apps/web keeps the same rule in shared/format/tokens.ts.

/** 119297808 → "119.3M", 18000000 → "18M", 34000 → "0.034M", 0 → "0". */
export function formatTokens(tokens: number): string {
  if (!tokens) return '0';
  const m = tokens / 1e6;
  return `${Number(Math.abs(m) >= 1 ? m.toFixed(2) : m.toPrecision(2))}M`;
}

/** The tokens one budget top-up may add: 1M–10,000M. The API checks it; the CLI and the web dialog take M. */
export const TOP_UP_TOKENS_MIN = 1_000_000;
export const TOP_UP_TOKENS_MAX = 10_000_000_000;

/** `--add-tokens` in millions: "5" / "5M" / "0.5" → tokens; undefined when not a number or outside the top-up range. */
export function parseTopUpMillions(text: string): number | undefined {
  const t = text.trim().replace(/m$/i, '').trim();
  const tokens = t && /^\d+(\.\d+)?$/.test(t) ? Math.round(Number(t) * 1e6) : NaN;
  return tokens >= TOP_UP_TOKENS_MIN && tokens <= TOP_UP_TOKENS_MAX ? tokens : undefined;
}

/** A suggested top-up as an `--add-tokens` argument in M, rounded up to 0.01M and at least the minimum: 2_345_678 → "2.35". */
export function topUpMillionsArg(tokens: number): string {
  return String(Math.max(TOP_UP_TOKENS_MIN, Math.ceil(tokens / 10_000) * 10_000) / 1e6);
}
