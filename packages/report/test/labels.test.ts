// Reports show why an audit is partial in words, with the code kept for reference (seen raw in a real-model run).
import { describe, expect, it } from 'vitest';
import { PARTIAL_REASONS } from '@xiezhi/contracts';
import { PARTIAL_REASON_ZH, partialReasonText } from '../src/labels.js';

describe('partial reason labels', () => {
  it('every partial reason has a label; the text keeps the code', () => {
    for (const r of PARTIAL_REASONS) expect(PARTIAL_REASON_ZH[r], r).toBeTruthy();
    expect(partialReasonText('COVERAGE_GAP')).toBe('覆盖未达标（COVERAGE_GAP）');
    expect(partialReasonText('SOMETHING_NEW')).toBe('SOMETHING_NEW');
  });
});
