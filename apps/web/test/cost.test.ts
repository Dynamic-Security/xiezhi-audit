// Approximate cost next to a token budget; unknown when the price is missing.
import { describe, expect, it } from 'vitest';
import { formatCost, tokenCost } from '../src/shared/format/cost';

const pricing = { 'gw/google-antigravity/gemini-3.8-flash': { currency: 'USD', input: 0.75, output: 3.75, cacheRead: 0.075 } };
const gemini = { provider: 'gw', model: 'google-antigravity/gemini-3.8-flash' };

describe('token cost hint', () => {
  it('prices a budget at 80% input and 20% output, like the plan estimate', () => {
    const c = tokenCost(12_000_000, gemini, pricing);
    expect(c).toMatchObject({ known: true, currency: 'USD', key: 'gw/google-antigravity/gemini-3.8-flash' });
    expect(c.known && c.amount).toBeCloseTo((12e6 * 0.8 * 0.75 + 12e6 * 0.2 * 3.75) / 1e6, 6); // 7.2 + 9 = 16.2
    expect(c.known && formatCost(c)).toBe('约 $16.20');
  });
  it('is unknown when the pricing table has no entry for the model, or no model is chosen', () => {
    expect(tokenCost(1_000_000, { provider: 'gw', model: 'other' }, pricing)).toEqual({ known: false, key: 'gw/other' });
    expect(tokenCost(1_000_000, null, pricing)).toEqual({ known: false, key: null });
    expect(tokenCost(1_000_000, gemini, undefined)).toMatchObject({ known: false });
  });
  it('formats small amounts and other currencies', () => {
    expect(formatCost({ amount: 0.004, currency: 'USD' })).toBe('约 $0.004');
    expect(formatCost({ amount: 3.5, currency: 'CNY' })).toBe('约 ¥3.50');
    expect(formatCost({ amount: 2, currency: 'CHF' })).toBe('约 2.00 CHF');
  });
});
