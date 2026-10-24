// Labels carry a service-boundary class (own / upstream / cross_service, absent = own); the score
// gives Recall per class and how often a hitting finding named the label's class (findings without one count as own).
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { scoreRunDir, type ScoreResult } from '../src/score.js';
import { renderReport } from '../src/report.js';
import { META_FORMAT, RUN_FORMAT, type AuditRec, type FindingRec, type RunRecord } from '../src/record.js';
import { writeJson } from '../src/util.js';
import { MINI_JAVA, makeBench, sample, tmp } from './helpers.js';

const API = 'src/main/java/com/t/Api.java';
const lineOf = (needle: string) => MINI_JAVA[API]!.split('\n').findIndex((l) => l.includes(needle)) + 1;

function F(id: string, category: string, line: number, extra: Partial<FindingRec> = {}): FindingRec {
  return {
    id, display_no: 1, title: id, category, cwe: null, severity: 'high', confidence: 0.8, repo: 'app', path: API, start_line: line, end_line: line,
    entries: [], status: 'confirmed', vulnerability_id: null, match_level: null, pending: null, ...extra,
  };
}

let score: ScoreResult;

beforeAll(async () => {
  const dir = await makeBench({
    trees: { 'sources/demo/v/app': MINI_JAVA },
    samples: [sample('demo-vuln', { repos: [{ name: 'app', role: 'auditable', origin: 'sources/demo/v/app', root_hash: 'auto' }], labels: ['D-SQLI', 'D-HDR', 'D-INNER'] })],
    labels: {
      demo: [
        { label_id: 'D-SQLI', kind: 'vuln', category: 'sqli', cwe: ['CWE-89'], root_cause: 'q 拼接进 SQL', depth: 'cross_file', sink: { repo: 'app', file: API, function: 'Api.search' }, entries: [{ repo: 'app', route: 'GET /search' }], expected: { verdict: 'confirmed' } },
        { label_id: 'D-HDR', kind: 'vuln', category: 'authn', cwe: ['CWE-290'], root_cause: '信任上游身份头', depth: 'cross_repo', boundary: 'upstream', sink: { repo: 'app', file: API, function: 'Api.get' }, entries: [{ repo: 'app', route: 'GET /get' }], expected: { verdict: 'confirmed' } },
        { label_id: 'D-INNER', kind: 'vuln', category: 'authz_function', cwe: ['CWE-306'], root_cause: '内部接口无服务间认证', depth: 'cross_repo', boundary: 'cross_service', sink: { repo: 'app', file: 'src/main/java/com/t/Repo.java', function: 'Repo.find' }, entries: [{ repo: 'app', route: 'GET /x' }], expected: { verdict: 'confirmed' } },
      ],
    },
  });
  const run = tmp('ca-evalrun-');
  // SQL hit without a class (counts as own: right); header hit named `own` (wrong); the internal endpoint is missed.
  const findings = [F('f1', 'sqli', lineOf('SELECT * FROM t')), F('f2', 'authn', lineOf('return repo.find(id)'), { boundary: 'own' })];
  const audit: AuditRec = {
    audit_id: 'a1', role: 'base', version: 'base', scene: 'full', status: 'completed', partial_reasons: [], error_class: null, budget_declined: false,
    wall_ms: 1000, model_ms: 800, steps: [], attempts: [], findings, snapshot_hashes: {}, reverify: [],
  };
  const r: RunRecord = {
    format: RUN_FORMAT, sample_id: 'demo-vuln', project: 'demo', kind: 'vuln', language: 'java', partition: 'dev', scene: 'full', dataset: 'self-built', repeat: 1,
    status: 'completed', error: null, wall_ms: 2000, audits: [audit], risk: null, integrity: [],
  };
  writeJson(join(run, 'run.json'), {
    format: META_FORMAT, name: 'boundary', bench: { root: dir, version: '0.0.1', manifest_hash: 'x', labels_hash: 'y' }, partition: 'dev', filter: {}, repeats: 1,
    selected: [], invalid: {}, skipped: [], stopped_reason: null,
    config: { sha256: 'c'.repeat(64), providers: [], default_model: 'gw/m1', cheap_model: null, priced_models: [] },
    strategy_override: {}, knowledge: { dir: null, skills: [] }, code: { revision: 'abc', dirty: false }, pi_version: '0', node: '22', platform: 'test', model_mode: 'live', started_at: '', ended_at: '',
  });
  writeJson(join(run, 'samples', r.sample_id, 'r1.json'), r);
  score = await scoreRunDir(run);
});

describe('service-boundary classes', () => {
  it('gives Recall per class and the class accuracy of hits', () => {
    expect(score.quality.by_boundary.own).toMatchObject({ labels: 1, hit: 1 });
    expect(score.quality.by_boundary.upstream).toMatchObject({ labels: 1, hit: 1 });
    expect(score.quality.by_boundary.cross_service).toMatchObject({ labels: 1, hit: 0 });
    const byId = Object.fromEntries(score.runs[0]!.labels.map((l) => [l.label_id, [l.hit, l.boundary, l.boundary_ok]]));
    expect(byId).toEqual({ 'D-SQLI': [true, 'own', true], 'D-HDR': [true, 'upstream', false], 'D-INNER': [false, 'cross_service', null] });
    expect(score.quality.boundary_accuracy).toBe(0.5);
  });

  it('shows the boundary table in the report only when a non-own label exists', () => {
    expect(renderReport(score)).toContain('按服务边界');
  });
});
