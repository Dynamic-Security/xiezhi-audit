import { describe, expect, it } from 'vitest';
import { CliExit } from '../src/io.js';
import { addTokensArg } from '../src/modes.js';

describe('--add-tokens', () => {
  it('takes M: 5 → 5M tokens', () => {
    expect(addTokensArg('5')).toBe(5_000_000);
    expect(addTokensArg('1.25M')).toBe(1_250_000);
  });
  it('refuses values outside 1–10000M with a message naming the unit and range', () => {
    for (const t of ['abc', '0', '-500000', '0.5', '10001', '']) {
      expect(() => addTokensArg(t), t).toThrow(CliExit);
      expect(() => addTokensArg(t), t).toThrow(/以 M（百万 tokens）为单位，范围 1–10000/);
    }
  });
});
