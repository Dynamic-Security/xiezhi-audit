import { describe, expect, it } from 'vitest';
import {
  AuditStrategy, DEFAULT_BUDGET_SHARES, check, checkStrategy, mergeStrategy, sceneDefaults, upgradeStrategy, stageFallback, stageModel, strategyHash, sortPartialReasons,
  resolveCategory, redact, SubmitFindings, SubmitPlan, AskUser, answerOptions, contextItem, placeholderPendingIssues, type PendingCondition, ulid, canonicalJson, AppConfig, defaultAppConfig, maskSecret, upgradeConfig, configStageModel,
  parseTopUpMillions, topUpMillionsArg, TOP_UP_TOKENS_MAX,
} from '@xiezhi/contracts';
import type { TSchema } from 'typebox';

const M = { provider: 'gw', model: 'big' };
const C = { provider: 'gw', model: 'small' };
const known = new Set(['gw/big', 'gw/small']);

describe('strategy', () => {
  it('full scene defaults are schema-valid and consistent', () => {
    const s = sceneDefaults('full', { defaultModel: M, stageModels: { triage: C, merge: C } });
    expect(check(AuditStrategy, s).ok).toBe(true);
    expect(checkStrategy(s, 'full', known)).toEqual([]);
    expect(s.models.triage).toEqual(C);
    expect(s.stages.deepExplore).toBe(false);
  });

  it('unset stages follow the default model; triage / merge run without a model only when set to null', () => {
    const s = sceneDefaults('full', { defaultModel: M });
    expect(s.models.triage).toEqual(M);
    expect(s.models.merge).toEqual(M);
    expect(s.models.report).toEqual(M);
    const none = sceneDefaults('incremental', { defaultModel: M, stageModels: { triage: null, merge: null, explore: null } });
    expect(none.models.triage).toBeNull();
    expect(none.models.merge).toBeNull();
    expect(none.models.explore).toEqual(M); // null means “no model” only for triage and merge
    // An increment also runs the threat model the lead needs; 300k did not cover it.
    expect(none.budget).toMatchObject({ tokens: 3_000_000, durationSec: 1_800 });
  });

  it('old configs — a light model stays on triage / merge, the chat model becomes the chat stage; otherwise the default model', () => {
    expect(upgradeConfig({ defaultModel: M, cheapModel: C, chatModel: C }))
      .toEqual({ defaultModel: M, stageModels: { triage: C, merge: C, chat: C } });
    // No light model before: triage and merge follow the default model like every other stage (user decision).
    expect(upgradeConfig({ defaultModel: M })).toEqual({ defaultModel: M, stageModels: {} });
    // A config written by a current version is left as it is (an unset stage follows the default model).
    expect(upgradeConfig({ defaultModel: M, stageModels: { hunt: C } })).toEqual({ defaultModel: M, stageModels: { hunt: C } });
    expect(upgradeConfig({ defaultModel: M, stageModels: { merge: M }, cheapModel: C })).toEqual({ defaultModel: M, stageModels: { triage: C, merge: M } });
    const c = { defaultModel: M, stageModels: { triage: null, chat: C, explore: null } };
    expect(configStageModel(c, 'triage')).toBeNull();
    expect(configStageModel(c, 'chat')).toEqual(C);
    expect(configStageModel(c, 'explore')).toEqual(M);
    expect(configStageModel(c, 'report')).toEqual(M);
    expect(check(AppConfig, { ...defaultAppConfig(), ...upgradeConfig({ defaultModel: M, cheapModel: C }) }).ok).toBe(true);
  });

  it('merges system < settings < task; arrays replace except scope.exclude unions', () => {
    const sys = sceneDefaults('full', { defaultModel: M, stageModels: { triage: C, merge: C } });
    sys.scope.exclude = ['**/test/**'];
    const { strategy, sources } = mergeStrategy(sys,
      { budget: { tokens: 10 }, scope: { exclude: ['docs/**'] }, focus: { categories: ['sqli'] } },
      { budget: { durationSec: 5 }, scope: { exclude: ['gen/**'] }, focus: { categories: ['ssrf'] }, models: { triage: null } });
    expect(strategy.budget).toEqual({ tokens: 10, durationSec: 5, stages: DEFAULT_BUDGET_SHARES, stageLimits: false });
    expect(strategy.scope.exclude).toEqual(['**/test/**', 'docs/**', 'gen/**']);
    expect(strategy.focus.categories).toEqual(['ssrf']);
    expect(strategy.models.triage).toBeNull();
    expect(sources['budget.tokens']).toBe('settings');
    expect(sources['budget.durationSec']).toBe('task');
    expect(sources['models.triage']).toBe('task');
    expect(sources['stages.adversarialReview']).toBe('system');
  });

  it('the old review switches of a layer become stages.adversarialReview', () => {
    const sys = sceneDefaults('full', { defaultModel: { provider: 'gw', model: 'm1' } });
    const off = mergeStrategy(sys, { stages: { challenge: false } }, undefined).strategy.stages;
    expect(off.adversarialReview).toBe(false);
    expect('challenge' in off).toBe(false);
    expect(mergeStrategy({ ...sys, stages: { ...sys.stages, adversarialReview: false } }, undefined, { stages: { independentReview: true } }).strategy.stages.adversarialReview).toBe(true);
    // An explicit new switch wins over the old ones in the same layer.
    expect(mergeStrategy(sys, undefined, { stages: { challenge: true, adversarialReview: false } }).strategy.stages.adversarialReview).toBe(false);
    // Frozen strategies from older versions.
    const old = upgradeStrategy({ ...sys, stages: { challenge: true, independentReview: false, deepExplore: false } });
    expect(old.stages).toEqual({ adversarialReview: true, deepExplore: false });
  });

  it('drops the removed cost cap from frozen strategies and override layers', () => {
    const sys = sceneDefaults('full', { defaultModel: { provider: 'gw', model: 'm1' } });
    expect(sys.budget).not.toHaveProperty('costCap');
    const old = upgradeStrategy({ ...sys, budget: { ...sys.budget, costCap: { amount: 5, currency: 'USD' } } });
    expect(old.budget).not.toHaveProperty('costCap');
    const { strategy } = mergeStrategy(sys, { budget: { costCap: { amount: 1, currency: 'USD' } } }, { budget: { tokens: 99, costCap: null } });
    expect(strategy.budget).not.toHaveProperty('costCap');
    expect(strategy.budget.tokens).toBe(99);
  });

  it('flags inconsistencies and unknown models (every capability is implemented)', () => {
    const s = sceneDefaults('full', { defaultModel: M, stageModels: { triage: C, merge: C } });
    s.tools.ast = false;
    s.stages.deepExplore = true;
    s.limits.maxRounds = 0;
    s.multiModel = { enabled: true, models: [M] };
    s.models.challenge = { provider: 'x', model: 'y' };
    const paths = checkStrategy(s, 'risk_hunt', known).map((i) => i.path);
    expect(paths).toEqual(expect.arrayContaining(['tools.coverageCompare', 'models.challenge', 'limits.maxRounds', 'multiModel.models']));
    const deep = sceneDefaults('full', { defaultModel: M, stageModels: { triage: C, merge: C } });
    deep.stages = { challenge: true, independentReview: true, deepExplore: true };
    deep.multiModel = { enabled: true, models: [M, C] };
    expect(checkStrategy(deep, 'full', known)).toEqual([]);
    // Risk hunting is implemented: its own defaults are valid.
    expect(checkStrategy(sceneDefaults('risk_hunt', { defaultModel: M }), 'risk_hunt', known)).toEqual([]);
    // Incremental is implemented; the diff-seeded variant search was removed: an old frozen
    // strategy that still carries it reads without it.
    const inc = sceneDefaults('incremental', { defaultModel: M });
    expect(checkStrategy(inc, 'incremental', known)).toEqual([]);
    expect(inc.impact).not.toHaveProperty('variantSearch');
    expect(upgradeStrategy({ ...inc, impact: { ...inc.impact, variantSearch: true } }).impact).toEqual(inc.impact);
  });

  it('stage models: a task layer replaces a stage model whole; the scene layer sets no models and no layer sets per-stage fallbacks', () => {
    const sys = sceneDefaults('full', { defaultModel: M, stageModels: { triage: C, merge: C } });
    expect(stageModel(sys, 'logic')).toEqual(M);
    expect(stageModel(sys, 'triage')).toEqual(C);
    expect(sys.models.report).toEqual(M);
    const { strategy } = mergeStrategy(sys,
      { models: { logic: { ...C, thinking: 'high' } }, modelFallbacks: { hunt: { ...C, thinking: 'low' } } },
      { models: { explore: { ...C, thinking: 'high' } }, modelFallbacks: { hunt: C } });
    expect(stageModel(strategy, 'logic')).toEqual(M); // the scene layer's model is ignored
    expect(stageModel(strategy, 'explore')).toEqual({ ...C, thinking: 'high' });
    expect(strategy.modelFallbacks).toBeUndefined();
    expect(stageFallback(strategy, 'logic', M, M)).toBeNull(); // never the model it replaces
    expect(stageFallback(strategy, 'logic', C, M)).toEqual(C);
    // Strategies frozen by older versions keep their per-stage fallbacks.
    const old = { ...strategy, modelFallbacks: { hunt: C } };
    expect(stageFallback(old, 'hunt', M, M)).toEqual(C);
    const bad = { ...strategy, modelFallbacks: { verify: { provider: 'x', model: 'y' } } };
    expect(checkStrategy(bad, 'full', known).map((i) => i.path)).toEqual(['modelFallbacks.verify']);
  });

  it('strategy hash is stable under key order', () => {
    const s = sceneDefaults('full', { defaultModel: M });
    const shuffled = JSON.parse(canonicalJson(s));
    expect(strategyHash(shuffled)).toBe(strategyHash(s));
  });
});

describe('closed sets', () => {
  it('partial reasons are sorted by fixed priority', () => {
    expect(sortPartialReasons(['COVERAGE_GAP', 'STEP_FAILED', 'BUDGET_EXHAUSTED', 'STEP_FAILED'])).toEqual(['BUDGET_EXHAUSTED', 'STEP_FAILED', 'COVERAGE_GAP']);
  });
  it('maps CWE to internal categories', () => {
    expect(resolveCategory(undefined, 'CWE-639')).toBe('authz_object');
    expect(resolveCategory('bogus', '89')).toBe('sqli');
    expect(resolveCategory('ssrf', 'CWE-89')).toBe('ssrf');
    expect(resolveCategory(null, null)).toBe('other');
  });
});

describe('submit schema', () => {
  it('rejects unknown fields and accepts explicit empty submission', () => {
    expect(check(SubmitFindings, { findings: [], reviewedTargets: [], ruledOut: [], scopeReviewed: 'all' }).ok).toBe(true);
    const bad = check(SubmitFindings, { findings: [], reviewedTargets: [], ruledOut: [], scopeReviewed: 'x', extra: 1 });
    expect(bad.ok).toBe(false);
  });

  it('a pending condition that names nothing missing is rejected; a concrete one passes', () => {
    const cond = (ref: string, hint?: string): PendingCondition => ({
      missing: [{ kind: 'repo', ref, ...(hint ? { hint } : {}) }], holdsIf: [{ statement: 'a' }], refutedIf: [{ statement: 'b' }], severityIfHolds: 'high', suggestedActions: ['add_repo'],
    });
    expect(placeholderPendingIssues(undefined, 'f')).toEqual([]);
    for (const ref of ['不存在必要缺失条件', '无', 'none', 'N/A', '没有缺失']) expect(placeholderPendingIssues(cond(ref), 'findings[0]')).toHaveLength(1);
    expect(placeholderPendingIssues(cond('x', '该问题由已审阅的本仓库代码直接确认，无需补充'), 'f')).toHaveLength(1);
    expect(placeholderPendingIssues(cond('edge-gateway', '网关是否比对路径 userId 与令牌主体'), 'f')).toEqual([]);
    // One concrete item among placeholders keeps the condition.
    const mixed = cond('无');
    mixed.missing.push({ kind: 'gateway_policy', ref: 'gateway' });
    expect(placeholderPendingIssues(mixed, 'f')).toEqual([]);
  });
});

describe('redactor', () => {
  it('removes known secrets, tokens, auth headers, url credentials and paths', () => {
    const secret = 'my-super-secret-value-123';
    const text = [
      `key=${secret}`, `b64=${Buffer.from(secret).toString('base64')}`,
      'Authorization: Bearer abc.def.ghi', 'sk-ant-api03-abcdefghijklmnop', 'https://u:p@host/x?token=zzz&a=1',
      '/Users/alice/.xiezhi-code-audit/db.sqlite', 'AKIAABCDEFGHIJKLMNOP',
    ].join('\n');
    const out = redact(text, { secrets: [secret], homeDir: '/Users/alice', dataDir: '/Users/alice/.xiezhi-code-audit' });
    expect(out).not.toContain(secret);
    expect(out).not.toContain(Buffer.from(secret).toString('base64'));
    expect(out).not.toContain('abc.def.ghi');
    expect(out).not.toContain('sk-ant-api03');
    expect(out).not.toContain('u:p@');
    expect(out).not.toContain('zzz');
    expect(out).toContain('<data-dir>/db.sqlite');
    expect(out).not.toContain('AKIAABCDEFGHIJKLMNOP');
  });
  it('masks secrets for display', () => {
    expect(maskSecret('sk-1234567890abcd')).toEqual({ configured: true, hint: 'sk-…abcd' });
    expect(maskSecret('short')).toEqual({ configured: true });
    expect(maskSecret(undefined)).toEqual({ configured: false });
  });
});

describe('misc', () => {
  it('ulid is monotonic and 26 chars', () => {
    const a = ulid(1000), b = ulid(1000);
    expect(a).toHaveLength(26);
    expect(b > a).toBe(true);
  });
  it('default config is schema-valid', () => {
    expect(check(AppConfig, defaultAppConfig()).ok).toBe(true);
  });
});

describe('suggested answers with questions', () => {
  const ok = (schema: TSchema, v: unknown) => check(schema, v).ok;
  it('submit_plan context items carry 2–4 short options; ask_user takes the same', () => {
    const plan = (contextNeeded: unknown[]) => ({ summary: 's', focusDirections: [], plannedKnowledge: [], contextNeeded, limitations: [] });
    expect(ok(SubmitPlan, plan([{ question: '内部服务是否只对网关开放？', options: ['是，仅网关可达', '否，部分可直接访问', '不确定'] }]))).toBe(true);
    expect(ok(SubmitPlan, plan([{ question: '部署方式？' }]))).toBe(true); // open-ended: no options
    expect(ok(SubmitPlan, plan([{ question: 'q', options: ['只有一个'] }]))).toBe(false);
    expect(ok(SubmitPlan, plan([{ question: 'q', options: ['a', 'b', 'c', 'd', 'e'] }]))).toBe(false);
    expect(ok(SubmitPlan, plan([{ question: 'q', options: ['a', 'x'.repeat(41)] }]))).toBe(false);
    expect(ok(AskUser, { question: 'q', blocking: false, options: ['是', '否'] })).toBe(true);
    expect(ok(AskUser, { question: 'q', blocking: false })).toBe(true);
    // Older stored plans hold strings.
    expect(contextItem('网关是否做鉴权')).toEqual({ question: '网关是否做鉴权' });
    expect(answerOptions([' 是 ', '是', '否', ''])).toEqual(['是', '否']);
    expect(answerOptions(['是', '是'])).toBeNull();
    expect(answerOptions(undefined)).toBeNull();
  });
});

describe('top-up amount in M', () => {
  it('parses 1–10000M, with an optional M suffix and decimals', () => {
    expect(parseTopUpMillions('5')).toBe(5_000_000);
    expect(parseTopUpMillions(' 2.5m ')).toBe(2_500_000);
    expect(parseTopUpMillions('1')).toBe(1_000_000);
    expect(parseTopUpMillions('10000M')).toBe(TOP_UP_TOKENS_MAX);
  });
  it('rejects what the API would: not a number, zero, negative, below 1M, above 10000M', () => {
    for (const t of ['', 'abc', '0', '-5', '0.5', '10000.01', '1e3', '5MM', 'Infinity']) expect(parseTopUpMillions(t), t).toBeUndefined();
  });
  it('suggests an argument in M, rounded up to 0.01M and at least 1M', () => {
    expect(topUpMillionsArg(2_345_678)).toBe('2.35');
    expect(topUpMillionsArg(12_000)).toBe('1');
    expect(topUpMillionsArg(0)).toBe('1');
    expect(parseTopUpMillions(topUpMillionsArg(7_777_777))).toBe(7_780_000);
  });
});
