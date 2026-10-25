// Triage scores a listing larger than the model's window in parts, one session each.
import { describe, expect, it } from 'vitest';
import { LISTING_CHARS_PER_TOKEN, TRIAGE_LISTING_SHARE, splitListing } from '../src/steps/triage.js';

describe('triage listing split', () => {
  it('a listing within the budget stays one part', () => {
    expect(splitListing(['- a', '- b'], 100)).toEqual([['- a', '- b']]);
    expect(splitListing([], 100)).toEqual([]);
  });

  it('parts keep the order and stay within the budget; an oversized line is a part of its own', () => {
    const lines = ['aaaa', 'bbbb', 'cccc', 'x'.repeat(30), 'dd'];
    const parts = splitListing(lines, 10);
    expect(parts).toEqual([['aaaa', 'bbbb'], ['cccc'], ['x'.repeat(30)], ['dd']]);
    expect(parts.flat()).toEqual(lines);
  });

  it('the failing triage listing (~255k characters) is split for a 128k window and kept whole for 1M', () => {
    const lines = Array.from({ length: 2_400 }, (_, i) => `- cand-${i} | repo:src/module${i % 97}/handler.ts:${i} | [entry] POST /api/v1/items/{id} → handler${i}`);
    const chars = lines.join('\n').length;
    expect(chars > 200_000, `listing ${chars}`).toBe(true);
    const budget = (window) => Math.floor(window * TRIAGE_LISTING_SHARE * LISTING_CHARS_PER_TOKEN);
    const small = splitListing(lines, budget(128_000));
    expect(small.length >= 3, `parts ${small.length}`).toBe(true);
    for (const p of small) expect(p.join('\n').length).toBeLessThanOrEqual(budget(128_000));
    expect(small.flat()).toEqual(lines);
    expect(splitListing(lines, budget(1_000_000)).length).toBe(1);
  });
});
