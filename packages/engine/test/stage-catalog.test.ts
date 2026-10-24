// The stage catalog replaces four classifications of steps (model stage, budget stage, overview phase,
// status bar segment). The catalog must give the same answers as they did, except the two corrections it makes.
import { describe, expect, it } from 'vitest';
import { EXECUTION_SEGMENTS, STAGE_CATALOG, STAGE_IDS, STEP_KINDS, STEP_ROLES, sceneDefaults, sceneStages, stepRole } from '@xiezhi/contracts';
import { estimatePipeline, stageShortfalls } from '../src/estimates.js';
import { expectedSegments } from '../src/execution.js';
import { budgetStage, stepStage } from '../src/stages.js';

const M = { provider: 'gw', model: 'm1' };

// The classifications as they were before the stage catalog (engine/src/stages.ts and engine/src/execution.ts).
function legacyModel(kind: string, lineage: string | null) {
  switch (kind) {
    case 'plan': case 'profile': return 'profile';
    case 'scope': return 'scope';
    case 'triage': return 'triage';
    case 'threat-model': return 'logic';
    case 'hunt': return lineage?.startsWith('LOGIC') || lineage?.startsWith('HYP') ? 'logic' : lineage?.startsWith('R') ? 'explore' : 'hunt';
    case 'coverage-gap': return 'hunt';
    case 'decide': return 'explore';
    case 'challenge': case 'review': return 'challenge';
    case 'reconcile': return 'merge';
    case 'verify-fix': case 'hunt-risk': return 'verify';
    default: return null;
  }
}
function legacyBudget(kind: string, lineage: string | null) {
  switch (kind) {
    case 'plan': case 'scope': case 'profile': return 'prepare';
    case 'triage': return 'triage';
    case 'threat-model': return 'hypotheses';
    case 'hunt': return lineage?.startsWith('HYP') ? 'hypotheses' : lineage?.startsWith('GAP') ? 'gap' : /^R\d/.test(lineage ?? '') ? 'explore' : 'hunt';
    case 'hunt-risk': return 'hunt';
    case 'coverage-gap': return 'gap';
    case 'decide': return 'explore';
    case 'challenge': case 'review': return 'review';
    case 'reconcile': return 'merge';
    case 'verify-fix': return 'verify';
    default: return null;
  }
}
function legacyPhase(kind: string, lineage: string | null) {
  switch (kind) {
    case 'triage': return 'triage';
    case 'hunt': return lineage?.startsWith('R') ? 'explore' : 'hunt';
    case 'coverage-gap': return 'hunt';
    case 'decide': return 'explore';
    case 'challenge': case 'review': return 'challenge';
    case 'verify-fix': return 'verify';
    case 'hunt-risk': return 'risk';
    case 'reconcile': case 'report': case 'finalize': return 'finalize';
    default: return 'prepare';
  }
}
function legacySegment(kind: string, lineage: string | null) {
  switch (kind) {
    case 'snapshot': case 'index': case 'plan': case 'profile': case 'scope': case 'triage': return kind;
    case 'threat-model': return 'threat';
    case 'hunt': return lineage?.startsWith('R') ? 'explore' : 'hunt';
    case 'coverage-gap': return lineage?.startsWith('CHK-') ? 'checklist' : lineage?.startsWith('RCK-') ? 'recheck' : lineage?.startsWith('EXT-') ? 'external' : 'hunt';
    case 'decide': return 'explore';
    case 'challenge': case 'review': return 'challenge';
    case 'verify-fix': return 'verify';
    case 'hunt-risk': return lineage === 'LOCATE' ? 'locate' : 'judge';
    default: return 'finalize';
  }
}

// Every lineage shape the engine creates (ensureStep call sites), plus none.
const SAMPLES: [string, string | null][] = [
  ['snapshot', null], ['index', null], ['plan', null], ['scope', null], ['profile', null], ['profile', 'SYSTEM'],
  ['threat-model', 'THREAT-app'], ['threat-model', 'THREAT-M2-app'], ['triage', null],
  ['hunt', 'HUNT-B1'], ['hunt', 'HUNT-M2-B3-S1'], ['hunt', 'LEAD-1'], ['hunt', 'LEAD-M2-3'], ['hunt', 'DOM-D4-R1'], ['hunt', 'DOM-D1-R2-M2'],
  ['hunt', 'HYP-B1'], ['hunt', 'HYP-R-B1'], ['hunt', 'HYP-R-M2-B1'], ['hunt', 'LOGIC-B1'], ['hunt', 'GAP-B1'], ['hunt', 'R3-C1'], ['hunt', null],
  ['coverage-gap', 'GAP-B1'], ['coverage-gap', 'CHK-B1'], ['coverage-gap', 'CHK-F-B2'], ['coverage-gap', 'RCK-B1'],
  ['coverage-gap', 'EXT-B1'], ['coverage-gap', 'EXT-F-B1'], ['coverage-gap', null],
  ['decide', 'R1'], ['challenge', null], ['challenge', 'CH-F1-M2'], ['review', null], ['reconcile', null],
  ['hunt-risk', 'LOCATE'], ['hunt-risk', 'JUDGE-app'], ['verify-fix', null], ['report', null], ['finalize', null], ['unknown-kind', null],
];

describe('stage catalog', () => {
  it('gives the same model stage as before, except the recheck and the external triage (adversarial review model)', () => {
    for (const [kind, lineage] of SAMPLES) {
      const corrected = kind === 'coverage-gap' && (lineage?.startsWith('RCK-') || (lineage?.startsWith('EXT-') && !lineage.startsWith('EXT-F')));
      expect(stepStage(kind, lineage), `${kind} ${lineage}`).toBe(corrected ? 'challenge' : legacyModel(kind, lineage));
    }
  });

  it('gives the same budget stage, overview phase and status bar segment as before', () => {
    for (const [kind, lineage] of SAMPLES) {
      const role = stepRole(kind, lineage);
      expect(budgetStage(kind, lineage), `${kind} ${lineage}`).toBe(legacyBudget(kind, lineage));
      expect(role?.phase ?? 'prepare', `${kind} ${lineage}`).toBe(legacyPhase(kind, lineage));
      expect(role?.segment ?? 'finalize', `${kind} ${lineage}`).toBe(legacySegment(kind, lineage));
    }
  });

  it('knows every step kind and every segment, and every role names a catalog stage', () => {
    for (const k of STEP_KINDS) expect(STEP_ROLES.some((r) => r.kind === k), k).toBe(true);
    for (const seg of EXECUTION_SEGMENTS) expect(STEP_ROLES.some((r) => r.segment === seg), seg).toBe(true);
    const ids = new Set(STAGE_CATALOG.map((s) => s.id));
    expect([...ids].sort()).toEqual([...STAGE_IDS].sort());
    for (const r of STEP_ROLES) expect(ids.has(r.stage), r.stage).toBe(true);
  });

  it('lists the stages of each scene in pipeline order', () => {
    expect(sceneStages('full').map((s) => s.id)).toEqual(['gateway', 'understand', 'triage', 'surface', 'lead', 'hunt', 'external', 'checklist', 'recheck', 'gap', 'reconcile', 'explore', 'review', 'publish', 'finish']);
    expect(sceneStages('incremental').map((s) => s.id)).not.toContain('checklist');
    expect(sceneStages('risk_hunt').map((s) => s.id)).toEqual(['locate', 'judge', 'reconcile', 'finish']);
    expect(sceneStages('reverify').map((s) => s.id)).toEqual(['verify', 'finish']);
  });

  it('announces the checklist check, the conclusion recheck and the external triage before their steps exist', () => {
    const full = sceneDefaults('full', { defaultModel: M });
    const seg = expectedSegments('full', full, '{}', false);
    expect(seg.slice(seg.indexOf('hunt'))).toEqual(['hunt', 'checklist', 'recheck', 'challenge', 'finalize']);
    expect(expectedSegments('full', full, '{}', true)).toContain('external');
    const inc = expectedSegments('incremental', sceneDefaults('incremental', { defaultModel: M }), '{}', false);
    expect(inc).toContain('recheck');
    expect(inc).not.toContain('checklist');
    expect(expectedSegments('full', full, JSON.stringify({ backfill: { units: [] } }), true)).not.toEqual(expect.arrayContaining(['checklist']));
  });

  it('estimates the checklist check, the recheck and the external triage, charged to the coverage-completion quota', () => {
    const s = sceneDefaults('full', { defaultModel: M });
    const without = estimatePipeline(s, 100, 10, undefined);
    const withAll = estimatePipeline(s, 100, 10, undefined, undefined, { checklist: true, recheck: true, external: 25 });
    expect(without.byStep.checklist).toBeUndefined();
    expect(withAll.byStep.checklist).toBeGreaterThan(0);
    // 15% of 100 candidates = 15 units, 3 batches of 5.
    expect(withAll.byStep.recheck).toBe(3 * 54_000);
    expect(withAll.byStep.external).toBeGreaterThan(0);
    expect(withAll.tokens.p50).toBeGreaterThan(without.tokens.p50);
    // A tiny coverage-completion share: the shortfall names `gap` because of these three.
    const tight = { ...s, budget: { ...s.budget, stages: { ...s.budget.stages, gap: 0.01 }, stageLimits: true } };
    expect(stageShortfalls(tight, withAll).map((x) => x.stage)).toContain('gap');
    expect(stageShortfalls(tight, without).map((x) => x.stage)).not.toContain('gap');
  });
});
