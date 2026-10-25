// The regression gate compares a candidate run with a baseline run of the same samples.
import { join } from 'node:path';
import { beforeAll, describe, expect, it } from 'vitest';
import { scoreRunDir, type ScoreResult } from '../src/score.js';
import { gateScores, renderGate } from '../src/gate.js';
import { META_FORMAT, RUN_FORMAT, type FindingRec, type RunRecord } from '../src/record.js';
import { writeJson } from '../src/util.js';
import { H, makeBench, sample, tmp } from './helpers.js';

const N = 20;
const API = 'src/main/java/com/t/Api.java';
const methods = Array.from({ length: N }, (_, i) => `    public String m${i}(String q) {\n        return run("SELECT * FROM t${i} WHERE name = '" + q + "'");\n    }\n`);
const SRC = `${H}package com.t;\n\npublic class Api {\n${methods.join('\n')}\n    private String run(String sql) {\n        return sql;\n    }\n}\n`;
const lineOf = (i: number) => SRC.split('\n').findIndex((l) => l.includes(`FROM t${i} `)) + 1;

let bench: string;
beforeAll(async () => {
  bench = await makeBench({
    trees: { 'sources/demo/v/app': { [API]: SRC } },
    samples: [sample('demo-vuln', { repos: [{ name: 'app', role: 'auditable', origin: 'sources/demo/v/app', root_hash: 'auto' }], labels: Array.from({ length: N }, (_, i) => `L${i}`) })],
    labels: {
      demo: Array.from({ length: N }, (_, i) => ({
        label_id: `L${i}`, kind: 'vuln', category: 'sqli', cwe: ['CWE-89'], root_cause: 'q 拼接进 SQL', depth: 'single_point',
        sink: { repo: 'app', file: API, function: `Api.m${i}` }, entries: [{ repo: 'app', route: `GET /m${i}` }], expected: { verdict: 'confirmed' },
      })),
    },
  });
});

/** A run directory with one record per repeat; `hits[r]` = how many labels repeat r finds (the first ones). */
async function runDir(name: string, hits: number[]): Promise<ScoreResult> {
  const dir = tmp('ca-gate-');
  writeJson(join(dir, 'run.json'), {
    format: META_FORMAT, name, bench: { root: bench, version: '0.0.1', manifest_hash: 'x', labels_hash: 'y' }, partition: 'dev', filter: {}, repeats: hits.length,
    selected: [], invalid: {}, skipped: [], stopped_reason: null,
    config: { sha256: 'c'.repeat(64), providers: [], default_model: 'gw/m1', cheap_model: null, priced_models: [] },
    strategy_override: {}, knowledge: { dir: null, skills: [] }, code: { revision: name, dirty: false }, pi_version: '0', node: '22', platform: 'test', model_mode: 'live', started_at: '', ended_at: '',
  });
  hits.forEach((h, r) => {
    const findings: FindingRec[] = Array.from({ length: h }, (_, i) => ({
      id: `f${i}`, display_no: i + 1, title: `sqli ${i}`, category: 'sqli', cwe: null, severity: 'high', confidence: 0.8, repo: 'app', path: API,
      start_line: lineOf(i), end_line: lineOf(i), entries: [], status: 'confirmed', vulnerability_id: null, match_level: null, pending: null,
    }));
    const rec: RunRecord = {
      format: RUN_FORMAT, sample_id: 'demo-vuln', project: 'demo', kind: 'vuln', language: 'java', partition: 'dev', scene: 'full', dataset: 'self-built', repeat: r + 1,
      status: 'completed', error: null, wall_ms: 600_000, risk: null, integrity: [],
      audits: [{ audit_id: `a${r}`, role: 'base', version: 'base', scene: 'full', status: 'completed', partial_reasons: [], error_class: null, budget_declined: false, wall_ms: 600_000, model_ms: 0, steps: [], attempts: [], findings, snapshot_hashes: {}, reverify: [] }],
    };
    writeJson(join(dir, 'samples', 'demo-vuln', `r${r + 1}.json`), rec);
  });
  return scoreRunDir(dir);
}

describe('regression gate', () => {
  it('passes a candidate within the baseline spread', async () => {
    const g = gateScores(await runDir('base', [20, 19, 20]), await runDir('cand', [19, 20, 19]));
    expect(g.verdict).toBe('不降');
    expect(g.samples[0]).toMatchObject({ sample_id: 'demo-vuln', labels: N, baseline: { runs: 3, median: 20, min: 19 }, candidate: { runs: 3, median: 19 }, below_baseline_range: false });
    expect(g.labels).toBe(N);
    expect(g.cost.candidate.wall_minutes_per_run).toBe(10);
    expect(renderGate(g)).toContain('# 回归门禁：不降');
  });

  it('fails a candidate whose median hits fall below the baseline minimum', async () => {
    const g = gateScores(await runDir('base', [20, 19, 20]), await runDir('cand', [12, 13, 11]));
    expect(g.verdict).toBe('下降');
    expect(g.samples[0]!.below_baseline_range).toBe(true);
    expect(g.reasons.join('\n')).toContain('低于基线最小值');
  });

  it('reports 样本不足 with fewer completed repeats than required', async () => {
    const g = gateScores(await runDir('base', [20, 20, 20]), await runDir('cand', [20, 20]));
    expect(g.verdict).toBe('样本不足');
    expect(g.reasons[0]).toContain('完成的运行不足 3 次');
    expect(gateScores(await runDir('base', [20, 20]), await runDir('cand', [20, 20]), { minRepeats: 2 }).verdict).toBe('不降');
  });
});
