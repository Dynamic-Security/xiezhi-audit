// The completion gate stores English details (engine); the workbench renders every check in Chinese.
// The cache hit rate is cache reads over all prompt tokens (pi's `input` excludes cache reads).
import { describe, expect, it } from 'vitest';
import { cacheHitText, gateCheckText } from '../src/shared/format/messages';

const DETAILS: Record<string, string> = {
  verdicts: '1/2 vulnerabilities have a verdict', finding_set: 'reconciled finding set present', steps: '2 failed step(s), 1 only noted',
  reconciled: '0 unreconciled finding(s)', blocking_questions: '0 open blocking question(s)', unconcluded: '0 item(s) without a conclusion',
  coverage: 'entry 6/6, sink 10/10', hypotheses: '11/11 risk hypotheses verified', obligations: '39/41 obligations settled (entry 6/6, checklist 12/14)',
};

describe('completion gate text', () => {
  it('every check reads in Chinese', () => {
    for (const [name, detail] of Object.entries(DETAILS)) {
      const t = gateCheckText({ name, ok: true, detail });
      expect(t, name).not.toMatch(/[a-z]{3,}/);
    }
    expect(gateCheckText({ name: 'hypotheses', ok: false, detail: '3/11 risk hypotheses verified' })).toBe('风险假设 3/11 已验证');
    // Only blocking questions count; open non-blocking ones stayed in the header (“6 个提问待回答”).
    expect(gateCheckText({ name: 'blocking_questions', ok: true, detail: '0 open blocking question(s)' })).toBe('没有影响结论的未回答提问');
  });
});

describe('cache hit rate', () => {
  it('never exceeds 100%', () => {
    expect(cacheHitText(63_915, 191_480)).toBe('75%');
    expect(cacheHitText(100, 0)).toBe('0%');
    expect(cacheHitText(0, 0)).toBe('—');
  });
});
