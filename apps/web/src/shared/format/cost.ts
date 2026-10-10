// Approximate cost of a token budget: budgets stay in tokens; next to a token amount the form shows
// what it would roughly cost at the model's price from settings › 通用 › 价格表, or "unknown — price missing".
import type { ModelRef } from '@xiezhi/contracts';

export interface PriceEntry { currency: string; input: number; output: number; cacheRead?: number }

/** Share of a budget assumed to be input tokens — the same split the plan's cost estimate uses (estimates.ts). */
export const INPUT_SHARE = 0.8;

export type TokenCost =
  | { known: true; amount: number; currency: string; key: string }
  | { known: false; key: string | null };

/** Price key of a model in the pricing table: `provider/model`, as the engine charges it. */
export const priceKey = (m: Pick<ModelRef, 'provider' | 'model'> | null | undefined): string | null => (m ? `${m.provider}/${m.model}` : null);

/** Rough cost of `tokens` at `model`'s price (80% input, 20% output; cache reads, which cost less, are not separated). */
export function tokenCost(tokens: number, model: Pick<ModelRef, 'provider' | 'model'> | null | undefined, pricing: Record<string, PriceEntry> | undefined): TokenCost {
  const key = priceKey(model);
  const p = key ? pricing?.[key] : undefined;
  if (!key || !p) return { known: false, key };
  return { known: true, key, currency: p.currency, amount: (tokens * INPUT_SHARE * p.input + tokens * (1 - INPUT_SHARE) * p.output) / 1e6 };
}

const SYMBOL: Record<string, string> = { USD: '$', CNY: '¥', EUR: '€', GBP: '£', JPY: '¥' };

/** "约 $1.23" (two decimals; three below one cent). */
export function formatCost(c: { amount: number; currency: string }): string {
  const sym = SYMBOL[c.currency.toUpperCase()];
  const n = c.amount >= 0.01 || c.amount === 0 ? c.amount.toFixed(2) : c.amount.toFixed(3);
  return `约 ${sym ?? ''}${n}${sym ? '' : ` ${c.currency}`}`;
}
