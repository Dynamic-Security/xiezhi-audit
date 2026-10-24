// Denial-of-service / robustness labels can be matched; Precision is withheld, with bounds,
// when little of the unlabelled output has been adjudicated.
import { describe, expect, it } from 'vitest';
import { VULN_CATEGORIES, defaultCweFor, resolveCategory } from '@xiezhi/contracts';
import { classesIntersect, findingClasses, labelClasses } from '../src/categories.js';
import { emptyCounts, MIN_ADJUDICATION_COVERAGE, qualityMetrics, type QualityCounts } from '../src/score.js';
import { precisionText } from '../src/report.js';

const matches = (f: [string, string | null], l: [string, string[]]) => classesIntersect(findingClasses(f[0], f[1]), labelClasses(l[0], l[1]));

describe('denial of service / robustness category', () => {
  it('is a product category with its own CWE mapping', () => {
    expect(VULN_CATEGORIES).toContain('dos');
    expect(VULN_CATEGORIES.at(-1)).toBe('other');
    for (const cwe of ['CWE-400', 'CWE-770', 'CWE-835', 'CWE-674', 'CWE-1333', 'CWE-476']) expect(resolveCategory(null, cwe), cwe).toBe('dos');
    expect(defaultCweFor('dos')).toBe('CWE-400');
  });

  it('matches labels whose category is other but whose CWE is a robustness weakness', () => {
    for (const cwe of ['CWE-476', 'CWE-20', 'CWE-400', 'CWE-770', 'CWE-835']) {
      expect(matches(['dos', null], ['other', [cwe]]), `dos finding vs other/${cwe}`).toBe(true);
      expect(matches(['other', cwe], ['other', [cwe]]), `other/${cwe} finding vs other/${cwe}`).toBe(true);
    }
    expect(matches(['other', 'CWE-400'], ['dos', []])).toBe(true);
    expect(matches(['dos', null], ['dos', []])).toBe(true);
    // `other` alone still never matches, and dos does not match unrelated classes.
    expect(matches(['dos', null], ['other', []])).toBe(false);
    expect(matches(['other', null], ['other', ['CWE-476']])).toBe(false);
    expect(matches(['dos', null], ['sqli', ['CWE-89']])).toBe(false);
  });
});

const counts = (over: Partial<QualityCounts>): QualityCounts => ({ ...emptyCounts(), ...over });

describe('Precision and adjudication coverage', () => {
  it('no adjudication at all: Precision is unknown, not 100%; the bounds span the undecided findings', () => {
    // One known advisory hit, 9 unlabelled findings nobody adjudicated.
    const m = qualityMetrics(counts({ tp: 1, undecided: 9, queue: 9, labels_total: 1, labels_hit: 1 }));
    expect(m.adjudication_coverage).toBe(0);
    expect(m.precision).toBeNull();
    expect(m.f1).toBeNull();
    expect(m.precision_low).toBe(0.1); // all 9 false positives
    expect(m.precision_high).toBe(1); // all 9 true
    expect(m.recall).toBe(1);
    expect(precisionText(m)).toBe('未知（裁定覆盖 0.0%，区间 [10.0%, 100.0%]）');
  });

  it('below the coverage threshold: withheld; at or above it: a point estimate with bounds', () => {
    expect(MIN_ADJUDICATION_COVERAGE).toBe(0.8);
    const low = qualityMetrics(counts({ tp: 2, adj_tp: 3, adj_fp: 4, undecided: 3 })); // 7 / 10
    expect(low.adjudication_coverage).toBe(0.7);
    expect(low.precision).toBeNull();
    expect([low.precision_low, low.precision_high]).toEqual([0.4167, 0.6667]); // 5/12, 8/12
    const ok = qualityMetrics(counts({ tp: 2, adj_tp: 3, adj_fp: 4, undecided: 1 })); // 7 / 8
    expect(ok.adjudication_coverage).toBe(0.875);
    expect(ok.precision).toBe(0.5556); // 5 / 9
    expect([ok.precision_low, ok.precision_high]).toEqual([0.5, 0.6]);
    expect(precisionText(ok)).toBe('55.6%（部分结论：裁定覆盖 87.5%，区间 [50.0%, 60.0%]）');
  });

  it('completely labelled output (nothing undecided) keeps the plain Precision', () => {
    const m = qualityMetrics(counts({ tp: 3, fp: 1, queue: 2 })); // queue of complete samples is not "undecided"
    expect(m).toMatchObject({ precision: 0.75, precision_low: 0.75, precision_high: 0.75, adjudication_coverage: null });
    expect(precisionText(m)).toBe('75.0%');
    // Score files written by older versions have no `undecided`.
    const legacy = { ...counts({ tp: 1 }) } as Partial<QualityCounts>;
    delete legacy.undecided;
    expect(qualityMetrics(legacy as QualityCounts).precision).toBe(1);
  });
});
