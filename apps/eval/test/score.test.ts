// Scorer math on hand-written finding sets: matching, duplicates, FP on clean samples,
// adjudication queue, mixed caliber, category / localization / entry accuracy, G10 pending, cost
// with unknown prices, stability, risk hunt, reverification and identity.
import { join } from 'node:path';
import { describe, expect, it, beforeAll } from 'vitest';
import { classifyReason, entryMatches, scoreRunDir, type ScoreResult } from '../src/score.js';
import { renderReport } from '../src/report.js';
import { META_FORMAT, RUN_FORMAT, type AuditRec, type FindingRec, type RunRecord } from '../src/record.js';
import { writeJson } from '../src/util.js';
import { MINI_JAVA, makeBench, sample, tmp } from './helpers.js';

const API = 'src/main/java/com/t/Api.java';
const REPO = 'src/main/java/com/t/Repo.java';
const RENAMED = { ...MINI_JAVA, [API]: MINI_JAVA[API]!.replace('public String search(', 'public String searchByName(') };

let n = 0;
function F(category: string, path: string, line: number, extra: Partial<FindingRec> = {}): FindingRec {
  n++;
  return {
    id: `f${n}`, display_no: n, title: `finding ${n}`, category, cwe: null, severity: 'high', confidence: 0.8, repo: 'app', path, start_line: line, end_line: line,
    entries: [], status: 'confirmed', vulnerability_id: null, match_level: null, pending: null, ...extra,
  };
}

function audit(findings: FindingRec[], extra: Partial<AuditRec> = {}): AuditRec {
  return {
    audit_id: `a${++n}`, role: 'base', version: 'base', scene: 'full', status: 'completed', partial_reasons: [], error_class: null, budget_declined: false,
    wall_ms: 1000, model_ms: 800, steps: [{ seq: 1, kind: 'hunt', status: 'succeeded', attempts: 1, error_class: null }],
    attempts: [{ step: 'hunt', seq: 1, provider: 'gw', model: 'm1', attempt: 1, outcome: 'succeeded', error_class: null, tokens_in: 1000, tokens_out: 100, tokens_cached: 0, cost_micros: 1200, currency: 'USD', duration_ms: 800 }],
    findings, snapshot_hashes: {}, reverify: [], ...extra,
  };
}

function rec(sampleId: string, kind: string, repeat: number, audits: AuditRec[], extra: Partial<RunRecord> = {}): RunRecord {
  return {
    format: RUN_FORMAT, sample_id: sampleId, project: 'demo', kind, language: 'java', partition: 'dev', scene: 'full', dataset: 'self-built', repeat,
    status: 'completed', error: null, wall_ms: 2000, audits, risk: null, integrity: [], ...extra,
  };
}

const repo = (name: string, origin = 'sources/demo/v/app') => ({ name, role: 'auditable', origin, root_hash: 'auto' });

let score: ScoreResult;

beforeAll(async () => {
  const dir = await makeBench({
    trees: { 'sources/demo/v/app': MINI_JAVA, 'sources/demo/renamed/app': RENAMED },
    samples: [
      sample('demo-vuln', { repos: [repo('app')], labels: ['D-SQLI', 'D-IDOR'] }),
      sample('demo-fixed', { kind: 'fixed', repos: [repo('app')], labels: ['D-FIX'] }),
      sample('demo-neg', { kind: 'negative', repos: [repo('app')], labels: ['D-NEG'] }),
      sample('demo-missing', { repos: [repo('app')], labels: ['D-PEND'] }),
      sample('demo-risk', { kind: 'risk_hunt', scene: 'risk_hunt', repos: [repo('app'), repo('app2'), repo('app3')], labels: ['D-RISK'], scene_input: { basis_ref: 'sources/demo/v/app/src/main/java/com/t/Api.java' } }),
      sample('demo-rv', { kind: 'reverify', scene: 'reverify', repos: [repo('app')], labels: ['D-RV', 'D-SQLI'],
        scene_input: { target_label: 'D-SQLI', versions: [{ name: 'fixed', repos: [{ name: 'app', origin: 'sources/demo/renamed/app', root_hash: 'auto' }] }, { name: 'regress', repos: [{ name: 'app', origin: 'sources/demo/v/app', root_hash: 'auto' }] }] } }),
      sample('demo-id', { kind: 'identity', repos: [repo('app')], labels: ['D-ID', 'D-SQLI', 'D-SQLI-R'],
        scene_input: { versions: [{ name: 'renamed', repos: [{ name: 'app', origin: 'sources/demo/renamed/app', root_hash: 'auto' }] }] } }),
    ],
    labels: {
      demo: [
        { label_id: 'D-SQLI', kind: 'vuln', category: 'sqli', cwe: ['CWE-89'], root_cause: 'q 拼接进 SQL', depth: 'cross_file', sink: { repo: 'app', file: API, function: 'Api.search' }, entries: [{ repo: 'app', route: 'GET /search' }], expected: { verdict: 'confirmed', severity: ['high'] } },
        { label_id: 'D-IDOR', kind: 'vuln', category: 'authz_object', cwe: ['CWE-639'], root_cause: '按 id 读取不校验归属', depth: 'cross_file', sink: { repo: 'app', file: REPO, function: 'Repo.find' },
          alt_sinks: [{ repo: 'app', file: API, function: 'Api.get' }], entries: [{ repo: 'app', route: 'GET /api/items/{id}' }], expected: { verdict: 'confirmed' } },
        { label_id: 'D-PEND', kind: 'vuln', category: 'authz_object', cwe: ['CWE-639'], root_cause: '依赖网关', depth: 'cross_repo', sink: { repo: 'app', file: REPO, function: 'Repo.find' },
          entries: [{ repo: 'app', route: 'GET /items/{id}' }], expected: { verdict: 'pending', missing: ['gateway'] } },
        { label_id: 'D-FIX', kind: 'negative', expected: { verdict: 'none' }, guard: 'fix', category: 'sqli', decoys: [{ repo: 'app', file: API, function: 'Api.search', note: 'fixed' }] },
        { label_id: 'D-NEG', kind: 'negative', expected: { verdict: 'none' }, guard: 'local', category: 'sqli', decoys: [{ repo: 'app', file: API, function: 'Api.search', note: 'guarded' }] },
        { label_id: 'D-RISK', kind: 'risk_hunt', targets: [
          { repo: 'app', expected: 'affected', locations: [{ repo: 'app', file: API, function: 'Api.search' }] },
          { repo: 'app2', expected: 'not_affected', reason_type: 'guarded', reason_evidence: [{ repo: 'app2', file: REPO, function: 'Repo.query' }] },
          { repo: 'app3', expected: 'not_affected', reason_type: 'version_out_of_range', reason_evidence: [{ repo: 'app3', file: REPO, line_range: [1, 3] }] },
        ] },
        { label_id: 'D-RV', kind: 'reverify', target_label: 'D-SQLI', expected: ['fixed', 'regressed'] },
        { label_id: 'D-SQLI-R', kind: 'vuln', category: 'sqli', cwe: ['CWE-89'], root_cause: 'q 拼接进 SQL', depth: 'cross_file', sink: { repo: 'app', file: API, function: 'Api.searchByName' }, entries: [{ repo: 'app', route: 'GET /search' }], expected: { verdict: 'confirmed' } },
        { label_id: 'D-ID', kind: 'identity', a: 'D-SQLI', b: 'D-SQLI-R', version: 'renamed', expected: 'same', refactor: 'rename' },
      ],
    },
  });

  const run = tmp('ca-evalrun-');
  const pending = { missing: ['gateway_policy:gateway'], holds_if: ['网关只校验登录'], refuted_if: ['网关校验归属'] };
  const unknownPrice = { step: 'challenge', seq: 2, provider: 'gw', model: 'm2', attempt: 1, outcome: 'succeeded', error_class: null, tokens_in: 500, tokens_out: 50, tokens_cached: 0, cost_micros: null, currency: null, duration_ms: 100 };
  const records: RunRecord[] = [
    rec('demo-vuln', 'vuln', 1, [audit([
      F('sqli', API, 17, { confidence: 0.9, entries: ['GET /search'] }),
      F('sqli', API, 16, { confidence: 0.5 }),
      F('authz_function', REPO, 5, { cwe: 'CWE-639', entries: ['GET /items/{}'] }),
      F('xss', API, 12),
      F('sqli', REPO, 9),
    ], { attempts: [audit([]).attempts[0]!, unknownPrice] })]),
    rec('demo-vuln', 'vuln', 2, [audit([F('sqli', API, 17, { entries: ['GET /search'] }), F('sqli', API, 17, { status: 'pending' })])]),
    rec('demo-vuln', 'vuln', 3, [audit([], { status: 'failed', error_class: 'PROVIDER_TRANSIENT', steps: [{ seq: 1, kind: 'hunt', status: 'failed', attempts: 2, error_class: 'PROVIDER_TRANSIENT' }],
      attempts: [{ ...audit([]).attempts[0]!, outcome: 'failed', error_class: 'PROVIDER_TRANSIENT' }] })], { status: 'failed' }),
    rec('demo-fixed', 'fixed', 1, [audit([F('sqli', API, 17), F('sqli', API, 16, { status: 'pending' })])]),
    rec('demo-neg', 'negative', 1, [audit([])]),
    rec('demo-missing', 'vuln', 1, [audit([F('authz_object', REPO, 5, { status: 'pending', pending })])]),
    rec('demo-risk', 'risk_hunt', 1, [audit([F('sqli', API, 16)], { role: 'hunt', scene: 'risk_hunt' })], {
      scene: 'risk_hunt',
      risk: { basis_status: 'ready', basis_model: 'gw/m1', basis_tokens: 300, basis_cost_micros: 600, basis_currency: 'USD', targets: [
        { repo: 'app', verdict: 'affected', reason: '命中', verdict_source: 'ai', evidence: [] },
        { repo: 'app2', verdict: 'not_affected', reason: '查询前做了白名单校验', verdict_source: 'ai', evidence: [{ path: REPO, start_line: 9, end_line: 10, verified: true }] },
        { repo: 'app3', verdict: 'pending', reason: '无法确定版本', verdict_source: 'ai', evidence: [] },
      ] },
    }),
    ...[1, 2].map((r) => rec('demo-rv', 'reverify', r, [
      audit([F('sqli', API, 17, { vulnerability_id: 'V1' })]),
      audit([], { role: 'reverify', version: 'fixed', scene: 'reverify', reverify: [{ vulnerability_id: 'V1', verdict: 'fixed', lifecycle_after: 'fixed_verified' }] }),
      audit([], { role: 'reverify', version: 'regress', scene: 'reverify', reverify: [{ vulnerability_id: 'V1', verdict: r === 1 ? 'still_present' : 'fixed', lifecycle_after: r === 1 ? 'regressed' : 'fixed_verified' }] }),
    ], { scene: 'reverify' })),
    ...[1, 2].map((r) => rec('demo-id', 'identity', r, [
      audit([F('sqli', API, 17, { vulnerability_id: 'V1' })]),
      audit([F('sqli', API, 17, { vulnerability_id: r === 1 ? 'V1' : 'V2', match_level: 'exact' })], { role: 'version', version: 'renamed' }),
    ])),
  ];
  writeJson(join(run, 'run.json'), {
    format: META_FORMAT, name: 'unit', bench: { root: dir, version: '0.0.1', manifest_hash: 'x', labels_hash: 'y' }, partition: 'dev', filter: {}, repeats: 3,
    selected: [], invalid: {}, skipped: [], stopped_reason: null,
    config: { sha256: 'c'.repeat(64), providers: [], default_model: 'gw/m1', cheap_model: null, priced_models: ['gw/m1'] },
    strategy_override: {}, knowledge: { dir: null, skills: [] }, code: { revision: 'abc', dirty: false }, pi_version: '0', node: '22', platform: 'test', model_mode: 'live', started_at: '', ended_at: '',
  });
  for (const r of records) writeJson(join(run, 'samples', r.sample_id, `r${r.repeat}.json`), r);
  score = await scoreRunDir(run);
});

describe('quality', () => {
  it('counts hits, duplicates, false positives, pending and the adjudication queue', () => {
    expect(score.quality.counts).toEqual({ runs: 5, tp: 3, duplicate: 1, fp: 1, queue: 2, undecided: 0, pending: 3, pending_hit: 1, pending_fp: 1, adj_tp: 0, adj_fp: 0, labels_total: 5, labels_hit: 4, labels_hit_loose: 4, labels_total_all: 7 });
    // Completely labelled samples: the queue is not "undecided" output, so Precision stays a number.
    expect(score.quality).toMatchObject({ precision: 0.6, precision_low: 0.6, precision_high: 0.6, adjudication_coverage: null });
    expect(score.quality.recall).toBe(0.8);
    expect(score.quality.f1).toBe(0.6857);
    expect(score.quality.recall_mixed).toBe(0.5714);
    expect(score.quality.f1_mixed).toBe(0.5854);
  });

  it('computes category, localization, entry and G10 accuracy', () => {
    expect(score.quality.category_accuracy).toBe(0.7143);
    expect(score.quality.localization_accuracy).toBe(0.8571);
    expect(score.quality.entry_hit_rate).toBe(0.75);
    expect(score.quality.verdict_accuracy).toBe(0.8);
    expect(score.quality.pending_accuracy).toBe(1);
    expect(score.quality.false_positives_on_clean).toEqual({ fix: { runs: 1, runs_with_fp: 1, fp: 1, fp_rate: 1 }, local: { runs: 1, runs_with_fp: 0, fp: 0, fp_rate: 0 } });
    expect(score.quality.by_category.sqli).toEqual({ labels: 2, hit: 2, recall: 1, recall_mixed: 0.6667, hit_loose: 2, recall_loose: 1 });
    expect(score.quality.by_depth.cross_repo).toEqual({ labels: 1, hit: 1, recall: 1, recall_mixed: 1, hit_loose: 1, recall_loose: 1 });
  });

  it('sends unlabelled findings to adjudication, not to false positives', () => {
    expect(score.adjudication.map((a) => [a.reason, a.finding.category])).toEqual([['危险点对齐但类别不一致', 'xss'], ['未标注的发现', 'sqli']]);
    const r1 = score.runs.find((r) => r.sample_id === 'demo-vuln' && r.repeat === 1)!;
    expect(r1.findings.map((f) => f.outcome)).toEqual(['tp', 'tp', 'queue', 'queue', 'duplicate']);
  });
});

describe('availability, cost and stability', () => {
  it('reports completion and error classes', () => {
    expect(score.availability).toMatchObject({ runs: 11, completed: 10, failed: 1, completion_rate: 0.9091 });
    expect(score.availability.error_classes.PROVIDER_TRANSIENT).toEqual({ attempts: 1, samples: ['demo-vuln'] });
    expect(score.availability.retry_recovery).toEqual({ steps_with_errors: 1, recovered: 0, rate: 0 });
  });

  it('never prices unknown calls as 0', () => {
    expect(score.cost.total.unknown_calls).toBe(1); // one unpriced model; the basis draft is priced from its usage split
    expect(score.cost.total.known.USD).toBeCloseTo(0.0012 * 17 + 0.0006, 6); // failed attempts are charged too
    expect(score.cost.cost_per_tp).toEqual({ usd: 0.007, partial: true });
  });

  it('computes Jaccard over (equivalence class, sink function) and lists unstable findings', () => {
    expect(score.stability.per_sample['demo-vuln']).toEqual({ runs: 2, jaccard: 0.25 });
    expect(score.stability.unstable_findings.map((u) => u.key)).toEqual(['access_control|app:src/main/java/com/t/Repo.java:Repo.find', 'sql|app:src/main/java/com/t/Repo.java:Repo.query', 'xss|app:src/main/java/com/t/Api.java:Api.get']);
  });
});

describe('risk hunt, reverify, identity', () => {
  it('risk hunt: confusion matrix, location recall and deterministic reason checks', () => {
    expect(score.risk_hunt).toMatchObject({ targets: 3, accuracy: 0.6667, location_recall: 1, not_affected_reason: { checked: 1, type_accuracy: 1, evidence_ok_rate: 1 } });
    expect(score.risk_hunt.confusion).toEqual({ affected: { affected: 1 }, not_affected: { not_affected: 1, pending: 1 } });
    expect(classifyReason('未引入 snakeyaml 依赖', 'ai')).toBe('not_imported');
    expect(classifyReason('声明的版本 2.2 不在受影响范围', 'ai')).toBe('version_out_of_range');
    expect(classifyReason('使用 SafeConstructor', 'ai')).toBe('guarded');
    expect(classifyReason('未搜索到候选', 'rule')).toBe('not_imported');
  });

  it('reverify: accuracy, definite rate and false release rate', () => {
    expect(score.reverify).toMatchObject({ steps: 4, accuracy: 0.75, definite_rate: 1, false_release_rate: 0.5 });
    expect(score.reverify.confusion).toEqual({ fixed: { fixed: 2 }, regressed: { regressed: 1, fixed: 1 } });
  });

  it('identity: exact precision / coverage and false splits', () => {
    expect(score.identity).toMatchObject({ pairs: 2, undetected: 0, exact_precision: 1, exact_coverage: 0.5, false_split_rate: 0.5, false_merge_rate: null });
    expect(score.identity.by_refactor.rename).toMatchObject({ pairs: 2, exact_coverage: 0.5 });
  });
});

describe('entries and rendering', () => {
  it('matches entries across parameter syntaxes and gateway prefixes', () => {
    expect(entryMatches('GET /api/order/{}', 'GET /order/{orderId}')).toBe(true);
    expect(entryMatches('GET /v1/invoices/:id', 'GET /v1/invoices/{id}')).toBe(true);
    expect(entryMatches('ANY /api/diag/ping', 'GET /api/diag/ping')).toBe(true);
    expect(entryMatches('POST /order/{}', 'GET /order/{id}')).toBe(false);
  });

  it('renders the same Markdown for the same score (deterministic)', () => {
    const a = renderReport(score);
    expect(renderReport(JSON.parse(JSON.stringify(score)))).toBe(a);
    expect(a).toContain('Precision');
    expect(a).toContain('unknown');
    expect(a).not.toMatch(/NaN|undefined/);
  });

});
