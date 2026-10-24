// The loose criterion is reported next to the strict one — a label without a strict hit
// is loosely hit by an unused category-equivalent finding in the file of its sink / an alternative sink that also
// shares one of its entries; strict Recall and Precision do not change; per-sample hits carry median / min / max.
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { hitSpread, scoreRunDir, type ScoreResult } from '../src/score.js';
import { renderReport } from '../src/report.js';
import { META_FORMAT, RUN_FORMAT, type AuditRec, type FindingRec, type RunRecord } from '../src/record.js';
import { writeJson } from '../src/util.js';
import { MINI_JAVA, makeBench, sample, tmp } from './helpers.js';

const API = 'src/main/java/com/t/Api.java';
const lineOf = (needle: string) => MINI_JAVA[API]!.split('\n').findIndex((l) => l.includes(needle)) + 1;

let n = 0;
function F(category: string, path: string, line: number, extra: Partial<FindingRec> = {}): FindingRec {
  n++;
  return {
    id: `f${n}`, display_no: n, title: `finding ${n}`, category, cwe: null, severity: 'high', confidence: 0.8, repo: 'app', path, start_line: line, end_line: line,
    entries: [], status: 'confirmed', vulnerability_id: null, match_level: null, pending: null, ...extra,
  };
}

function rec(repeat: number, findings: FindingRec[]): RunRecord {
  const audit: AuditRec = {
    audit_id: `a${repeat}`, role: 'base', version: 'base', scene: 'full', status: 'completed', partial_reasons: [], error_class: null, budget_declined: false,
    wall_ms: 1000, model_ms: 800, steps: [], attempts: [], findings, snapshot_hashes: {}, reverify: [],
  };
  return {
    format: RUN_FORMAT, sample_id: 'demo-vuln', project: 'demo', kind: 'vuln', language: 'java', partition: 'dev', scene: 'full', dataset: 'self-built', repeat,
    status: 'completed', error: null, wall_ms: 2000, audits: [audit], risk: null, integrity: [],
  };
}

let score: ScoreResult;

beforeAll(async () => {
  const dir = await makeBench({
    trees: { 'sources/demo/v/app': MINI_JAVA },
    samples: [sample('demo-vuln', { repos: [{ name: 'app', role: 'auditable', origin: 'sources/demo/v/app', root_hash: 'auto' }], labels: ['D-SQLI', 'D-IDOR'] })],
    labels: {
      demo: [
        { label_id: 'D-SQLI', kind: 'vuln', category: 'sqli', cwe: ['CWE-89'], root_cause: 'q 拼接进 SQL', depth: 'cross_file', sink: { repo: 'app', file: API, function: 'Api.search' }, entries: [{ repo: 'app', route: 'GET /search' }], expected: { verdict: 'confirmed' } },
        { label_id: 'D-IDOR', kind: 'vuln', category: 'authz_object', cwe: ['CWE-639'], root_cause: '按 id 读取不校验归属', depth: 'cross_file', sink: { repo: 'app', file: 'src/main/java/com/t/Repo.java', function: 'Repo.find' },
          entries: [{ repo: 'app', route: 'GET /api/items/{id}' }], expected: { verdict: 'confirmed' } },
      ],
    },
  });
  const run = tmp('ca-evalrun-');
  const records = [
    // Strict misses. Loose: the SQL finding in Api.get (sink file) on the label's entry. Not loose: an IDOR finding on
    // the label's entry in another file, and one in the sink file without a shared entry.
    rec(1, [
      F('sqli', API, lineOf('return repo.find(id)'), { entries: ['GET /search'] }),
      F('authz_object', 'src/main/java/com/t/Other.java', 3, { entries: ['GET /api/items/{}'] }),
      F('authz_object', 'src/main/java/com/t/Repo.java', 9, { entries: ['GET /other'] }),
    ]),
    // A strict hit; a second SQL finding in the same file must not loosely hit the IDOR label (category differs).
    rec(2, [F('sqli', API, lineOf('SELECT * FROM t')), F('sqli', API, lineOf('return repo.find(id)'))]),
  ];
  writeJson(join(run, 'run.json'), {
    format: META_FORMAT, name: 'loose', bench: { root: dir, version: '0.0.1', manifest_hash: 'x', labels_hash: 'y' }, partition: 'dev', filter: {}, repeats: 2,
    selected: [], invalid: {}, skipped: [], stopped_reason: null,
    config: { sha256: 'c'.repeat(64), providers: [], default_model: 'gw/m1', cheap_model: null, priced_models: [] },
    strategy_override: {}, knowledge: { dir: null, skills: [] }, code: { revision: 'abc', dirty: false }, pi_version: '0', node: '22', platform: 'test', model_mode: 'live', started_at: '', ended_at: '',
  });
  for (const r of records) writeJson(join(run, 'samples', r.sample_id, `r${r.repeat}.json`), r);
  score = await scoreRunDir(run);
});

describe('loose criterion', () => {
  it('counts loose hits beside the strict ones without changing strict Recall', () => {
    expect(score.quality.counts).toMatchObject({ labels_total: 4, labels_hit: 1, labels_hit_loose: 2 });
    expect(score.quality.recall).toBe(0.25);
    expect(score.quality.recall_loose).toBe(0.5);
    expect(score.quality.loose_hits).toEqual([{ sample_id: 'demo-vuln', repeat: 1, label_id: 'D-SQLI', finding_id: 'f1' }]);
    expect(score.quality.by_category.sqli).toMatchObject({ labels: 2, hit: 1, hit_loose: 2, recall_loose: 1 });
  });

  it('reports per-sample hits with median, min and max', () => {
    expect(score.quality.by_sample_hits['demo-vuln']).toEqual({
      runs: 2, labels: 2,
      strict: { values: [0, 1], median: 0.5, min: 0, max: 1 },
      loose: { values: [1, 1], median: 1, min: 1, max: 1 },
    });
    expect(hitSpread([3, 1, 2])).toMatchObject({ median: 2, min: 1, max: 3 });
    expect(hitSpread([])).toMatchObject({ median: null, min: null, max: null });
  });

  it('renders Recall_loose, the per-sample table and each loose hit', () => {
    const md = renderReport(score);
    expect(md).toContain('Recall_loose');
    expect(md).toContain('各样本命中');
    expect(md).toContain('| demo-vuln | 1 | D-SQLI | f1 |');
  });
});
