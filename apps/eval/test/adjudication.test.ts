// Completely labelled projects may record true positives found on their fixed / negative samples (an
// unplanned real issue of the sample code, e.g. kt-loan self-approval): those findings are not false positives.
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { stringify } from 'yaml';
import { loadBench, staticChecks } from '../src/bench.js';
import { META_FORMAT, RUN_FORMAT, type FindingRec, type RunRecord } from '../src/record.js';
import { scoreRunDir } from '../src/score.js';
import { writeJson } from '../src/util.js';
import { MINI_JAVA, makeBench, sample, tmp, writeFiles } from './helpers.js';

const API = 'src/main/java/com/t/Api.java';
const REPO = 'src/main/java/com/t/Repo.java';
let n = 0;
const F = (category: string, path: string, line: number): FindingRec => ({
  id: `f${++n}`, display_no: n, title: `finding ${n}`, category, cwe: null, severity: 'high', confidence: 0.8, repo: 'app', path, start_line: line, end_line: line,
  entries: [], status: 'confirmed', vulnerability_id: null, match_level: null, pending: null,
});
const record = (sampleId: string, kind: string, findings: FindingRec[]): RunRecord => ({
  format: RUN_FORMAT, sample_id: sampleId, project: 'demo', kind, language: 'java', partition: 'dev', scene: 'full', dataset: 'self-built', repeat: 1,
  status: 'completed', error: null, wall_ms: 1000, risk: null, integrity: [],
  audits: [{ audit_id: `a-${sampleId}`, role: 'base', version: 'base', scene: 'full', status: 'completed', partial_reasons: [], error_class: null, budget_declined: false,
    wall_ms: 1000, model_ms: 800, steps: [], attempts: [], findings, snapshot_hashes: {}, reverify: [] }],
});
const repo = () => [{ name: 'app', role: 'auditable', origin: 'sources/demo/v/app', root_hash: 'auto' }];
const LABELS = [
  { label_id: 'D-SQLI', kind: 'vuln', category: 'sqli', cwe: ['CWE-89'], root_cause: 'q 拼接进 SQL', depth: 'single_point', sink: { repo: 'app', file: API, function: 'Api.search' }, entries: [{ repo: 'app', route: 'GET /search' }], expected: { verdict: 'confirmed' } },
  { label_id: 'D-FIX', kind: 'negative', expected: { verdict: 'none' }, guard: 'fix', category: 'sqli', decoys: [{ repo: 'app', file: API, function: 'Api.search', note: 'fix' }] },
];

async function bench(decisions: unknown[]) {
  const dir = await makeBench({
    trees: { 'sources/demo/v/app': MINI_JAVA },
    samples: [sample('d-vuln', { repos: repo(), labels: ['D-SQLI'] }), sample('d-fixed', { kind: 'fixed', repos: repo(), labels: ['D-FIX'] })],
    labels: { demo: LABELS },
  });
  writeFiles(dir, { 'adjudication/demo.yaml': stringify({ project: 'demo', decisions }) });
  return dir;
}

describe('decided true positives on fixed / negative samples of completely labelled projects', () => {
  it('validate accepts only true_positive decisions limited to fixed / negative samples', async () => {
    const key = `access_control|app:${REPO}:Repo.find`;
    const ok = loadBench(await bench([{ key, verdict: 'true_positive', note: 'unplanned real issue', samples: ['d-fixed'] }]));
    expect(staticChecks(ok).filter((i) => i.level === 'error')).toEqual([]);
    const bad = loadBench(await bench([
      { key, verdict: 'false_positive', note: 'x', samples: ['d-fixed'] },
      { key: `sqli|app:${API}:Api.get`, verdict: 'true_positive', note: 'y' },
      { key: `xss|app:${API}:Api.get`, verdict: 'true_positive', note: 'z', samples: ['d-vuln'] },
    ]));
    const errors = staticChecks(bad).filter((i) => i.level === 'error').map((i) => i.message);
    expect(errors.some((m) => m.includes('只能是 fixed / negative 样本上的 true_positive'))).toBe(true);
    expect(errors.some((m) => m.includes('必须用 samples 限定'))).toBe(true);
    expect(errors.some((m) => m.includes('样本 d-vuln 不是项目 demo 的 known_only 样本'))).toBe(true);
  });

  it('scoring: the decided finding is adj_tp; decoys and undecided findings stay false positives', async () => {
    const dir = await bench([{ key: `access_control|app:${REPO}:Repo.find`, verdict: 'true_positive', note: 'unplanned real issue', samples: ['d-fixed'] }]);
    const run = tmp('ca-evalrun-');
    writeJson(join(run, 'run.json'), {
      format: META_FORMAT, name: 'adj', bench: { root: dir, version: '0.0.1', manifest_hash: 'x', labels_hash: loadBench(dir).labelsHash }, partition: 'dev', filter: {}, repeats: 1,
      selected: [], invalid: {}, skipped: [], stopped_reason: null, results: {},
      config: { sha256: 'c'.repeat(64), providers: [], default_model: 'gw/m1', cheap_model: null, priced_models: [] },
      strategy_override: {}, knowledge: { dir: null, skills: [] }, code: { revision: 'abc', dirty: false }, pi_version: '0', node: '22', platform: 'test', model_mode: 'live', started_at: '', ended_at: '',
    });
    for (const r of [record('d-vuln', 'vuln', [F('sqli', API, 17)]), record('d-fixed', 'fixed', [F('sqli', API, 17), F('authz_object', REPO, 5), F('xss', API, 11)])]) {
      writeJson(join(run, 'samples', r.sample_id, 'r1.json'), r);
    }
    const score = await scoreRunDir(run);
    const fixed = score.runs.find((r) => r.sample_id === 'd-fixed')!;
    expect(fixed.findings.map((f) => f.outcome)).toEqual(['fp', 'adj_tp', 'fp']);
    expect(score.quality.counts).toMatchObject({ tp: 1, adj_tp: 1, fp: 2 });
  }, 60_000);
});
