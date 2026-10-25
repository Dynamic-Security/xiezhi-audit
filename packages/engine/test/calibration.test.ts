// Estimates are calibrated from this data directory's finished steps — per kind and
// model, else per kind, else the constant — against the uncalibrated estimate, so calibration never feeds on itself.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { sceneDefaults } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { createProject, estimatePipeline, estimateStep, getStep } from '@xiezhi/engine';
import { calibrationRatio, resetCalibration } from '../src/calibration.js';
import { ensureStep } from '../src/step-runner.js';

let store: Store;
let auditId: string;
const M = { provider: 'gw', model: 'm1' };

beforeEach(() => {
  store = Store.open({ dataDir: join(mkdtempSync(join(tmpdir(), 'ca-cal-')), 'data'), role: 'test' });
  const p = createProject(store, 'demo');
  auditId = 'aud_cal';
  store.insert('audit', {
    id: auditId, project_id: p.id, title: 't', scene: 'full', mode: 'single', status: 'running', origin: 'cli',
    strategy_draft: {}, strategy_sources: {}, budget_initial: {}, budget_effective: {}, budget_consumed: {},
  });
});
afterEach(() => store.close());

/** A finished step that used `used` tokens against an uncalibrated estimate of `base`. */
function finished(kind: string, base: number, used: number, model = M, n = 0) {
  const row = ensureStep(store, auditId, { kind: kind as never, identity: { kind, n, base, used, model }, estimateTokens: base, model });
  store.update('step', { id: row.id }, { status: 'succeeded', tokens_in: Math.round(used * 0.6), tokens_out: Math.round(used * 0.1), tokens_cached: used - Math.round(used * 0.6) - Math.round(used * 0.1), ended_at: Date.now() + n });
}

describe('estimate calibration', () => {
  it('uses the constant until three steps of a kind have finished', () => {
    finished('hunt', 18_000, 54_000, M, 1);
    finished('hunt', 18_000, 54_000, M, 2);
    resetCalibration(store);
    expect(calibrationRatio(store, 'hunt', M)).toBe(1);
    finished('hunt', 18_000, 54_000, M, 3);
    resetCalibration(store);
    expect(calibrationRatio(store, 'hunt', M)).toBe(3);
  });

  it('takes the median per kind and model, falls back to the kind, and clamps outliers', () => {
    for (const [i, used] of [36_000, 54_000, 72_000, 900_000].entries()) finished('hunt', 18_000, used, M, i);
    for (const [i, used] of [9_000, 9_000, 9_000].entries()) finished('challenge', 20_000, used, { provider: 'gw', model: 'm2' }, 10 + i);
    resetCalibration(store);
    expect(calibrationRatio(store, 'hunt', M)).toBe(3.5); // median of 2, 3, 4, 50
    expect(calibrationRatio(store, 'hunt', { provider: 'other', model: 'x' })).toBe(3.5); // kind-level
    expect(calibrationRatio(store, 'challenge', { provider: 'gw', model: 'm2' })).toBe(0.5); // 0.45 clamped
    expect(calibrationRatio(store, 'triage', M)).toBe(1);
  });

  it('a new step reserves the calibrated estimate and keeps the constant-based one to calibrate against', () => {
    for (let i = 0; i < 3; i++) finished('hunt', 18_000, 45_000, M, i);
    resetCalibration(store);
    const row = getStep(store, ensureStep(store, auditId, { kind: 'hunt', identity: { fresh: true }, estimateTokens: estimateStep('hunt', 4), model: M }).id);
    expect(row.estimate_tokens).toBe(Math.ceil(72_000 * 2.5));
    expect((row as unknown as { estimate_base: number }).estimate_base).toBe(72_000);
    // Calibration reads the base, so new steps do not shift it.
    store.update('step', { id: row.id }, { status: 'succeeded', tokens_in: 180_000, ended_at: Date.now() + 99 });
    resetCalibration(store);
    expect(calibrationRatio(store, 'hunt', M)).toBe(2.5);
  });

  it('the plan estimate applies the ratio per stage', () => {
    const s = sceneDefaults('full', { defaultModel: M });
    const plain = estimatePipeline(s, 100, 10, undefined);
    const cal = estimatePipeline(s, 100, 10, undefined, (kind) => (kind === 'hunt' ? 2 : 1));
    expect(cal.byStep.hunt).toBe(plain.byStep.hunt! * 2);
    expect(cal.byStep.challenge).toBe(plain.byStep.challenge);
    expect(cal.tokens.p50).toBeGreaterThan(plain.tokens.p50);
  });

  it('the domain-expert hunt estimate is not scaled by the per-candidate hunt ratio', () => {
    const s = sceneDefaults('full', { defaultModel: M });
    const opts = { domainHunt: true, gapFill: true };
    const plain = estimatePipeline(s, 100, 10, undefined, undefined, opts);
    const cal = estimatePipeline(s, 100, 10, undefined, (kind) => (kind === 'hunt' || kind === 'coverage-gap' ? 5 : 1), opts);
    expect(cal.byStep.hunt).toBe(plain.byStep.hunt);
    expect(cal.byStep.gap).toBe(plain.byStep.gap! * 5);
  });

  it('an incremental audit\'s experts are estimated from the change set, not the full-audit constant', () => {
    const s = sceneDefaults('incremental', { defaultModel: M });
    const full = estimatePipeline(s, 3, 1, undefined, undefined, { domainHunt: true });
    const inc = estimatePipeline(s, 3, 1, undefined, undefined, { domainHunt: true, incremental: true });
    // Before: 6 × 600k + 150k = 3.75M for a 3-file change that used 0.5M on real models.
    expect(full.byStep.hunt).toBe(3_750_000);
    expect(inc.byStep.hunt).toBe(6 * 54_000 + 54_000);
    // Calibrated like a per-candidate hunt, and never above the full-audit constant.
    expect(estimatePipeline(s, 3, 1, undefined, (k) => (k === 'hunt' ? 5 : 1), { domainHunt: true, incremental: true }).byStep.hunt).toBe(6 * 270_000 + 150_000);
    expect(estimatePipeline(s, 400, 1, undefined, undefined, { domainHunt: true, incremental: true }).byStep.hunt).toBe(3_750_000);
  });
});
