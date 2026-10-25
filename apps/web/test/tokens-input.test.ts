// Token budgets are typed in millions (M) and sent in tokens.
import { describe, expect, it } from 'vitest';
import { formatTokens as contractsFormat } from '../../../packages/contracts/src/format';
import { fmt } from '../src/shared/format/messages';
import { formatTokens, fromMillions, toMillions } from '../src/shared/format/tokens';

describe('token budget in millions', () => {
  it('shows tokens as millions without trailing zeros', () => {
    expect(toMillions(12_000_000)).toBe('12');
    expect(toMillions(1_500_000)).toBe('1.5');
    expect(toMillions(60_000)).toBe('0.06');
    expect(toMillions(1)).toBe('0.000001');
    expect(toMillions('')).toBe('');
  });
  it('reads millions back as whole tokens', () => {
    expect(fromMillions('12')).toBe(12_000_000);
    expect(fromMillions('0.25')).toBe(250_000);
    expect(fromMillions('2.1M')).toBe(2_100_000);
    expect(fromMillions(' 0.1 ')).toBe(100_000);
    expect(fromMillions('')).toBe('');
    expect(fromMillions('abc')).toBe('');
  });
  it('round-trips', () => {
    for (const t of [1000, 60_000, 2_060_000, 12_000_000, 123_456_789]) expect(fromMillions(toMillions(t))).toBe(t);
  });
});

describe('token counts on display', () => {
  it('always shows millions', () => {
    expect(formatTokens(119_297_808)).toBe('119.3M');
    expect(formatTokens(120_000_000)).toBe('120M');
    expect(formatTokens(18_000_000)).toBe('18M');
    expect(formatTokens(2_060_000)).toBe('2.06M');
    expect(formatTokens(34_000)).toBe('0.034M');
    expect(formatTokens(1_234)).toBe('0.0012M');
    expect(formatTokens(0)).toBe('0');
  });
  it('a range writes M once and whole millions from 10M up', () => {
    expect(fmt.tokensRange(36_433_000, 67_661_000)).toBe('36–68M');
    expect(fmt.tokensRange(800_000, 1_500_000)).toBe('0.8–1.5M');
  });
  it('matches the copy in contracts used by the engine, reports and CLI', () => {
    for (const t of [0, 1, 999, 34_000, 2_060_000, 119_297_808]) expect(formatTokens(t)).toBe(contractsFormat(t));
  });
});
