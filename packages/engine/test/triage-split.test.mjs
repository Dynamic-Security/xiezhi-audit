// Triage scores a listing larger than the model's window in parts, one session each.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LISTING_CHARS_PER_TOKEN, TRIAGE_LISTING_SHARE, splitListing } from '../dist/steps/triage.js';

test('a listing within the budget stays one part', () => {
  assert.deepEqual(splitListing(['- a', '- b'], 100), [['- a', '- b']]);
  assert.deepEqual(splitListing([], 100), []);
});

test('parts keep the order and stay within the budget; an oversized line is a part of its own', () => {
  const lines = ['aaaa', 'bbbb', 'cccc', 'x'.repeat(30), 'dd'];
  const parts = splitListing(lines, 10);
  assert.deepEqual(parts, [['aaaa', 'bbbb'], ['cccc'], ['x'.repeat(30)], ['dd']]);
  assert.deepEqual(parts.flat(), lines);
});

test('the failing triage listing (~255k characters) is split for a 128k window and kept whole for 1M', () => {
  const lines = Array.from({ length: 2_400 }, (_, i) => `- cand-${i} | repo:src/module${i % 97}/handler.ts:${i} | [entry] POST /api/v1/items/{id} → handler${i}`);
  const chars = lines.join('\n').length;
  assert.ok(chars > 200_000, `listing ${chars}`);
  const budget = (window) => Math.floor(window * TRIAGE_LISTING_SHARE * LISTING_CHARS_PER_TOKEN);
  const small = splitListing(lines, budget(128_000));
  assert.ok(small.length >= 3, `parts ${small.length}`);
  for (const p of small) assert.ok(p.join('\n').length <= budget(128_000));
  assert.deepEqual(small.flat(), lines);
  assert.equal(splitListing(lines, budget(1_000_000)).length, 1);
});
