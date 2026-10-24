// Test helpers: tiny benchmarks written to a temporary directory.
import { cpSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { stringify } from 'yaml';
import { defaultAppConfig } from '@xiezhi/contracts';
import { TreeHasher } from '../src/bench.js';

export const ROOT = resolve(__dirname, '../../..');
export const tmp = (p = 'ca-evaltest-') => mkdtempSync(join(tmpdir(), p));

export function writeFiles(root: string, files: Record<string, string>): void {
  for (const [rel, content] of Object.entries(files)) {
    const p = join(root, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, content);
  }
}

export const H = '// Benchmark fixture. Never built.\n';

/** A small Java repository with two functions and a mapper. */
export const MINI_JAVA: Record<string, string> = {
  'src/main/java/com/t/Api.java': `${H}package com.t;

public class Api {
    private final Repo repo;

    public Api(Repo repo) {
        this.repo = repo;
    }

    public String get(long id) {
        return repo.find(id);
    }

    public String search(String q) {
        String s = "{ not a brace }";
        return repo.query("SELECT * FROM t WHERE name = '" + q + "'");
    }
}
`,
  'src/main/java/com/t/Repo.java': `${H}package com.t;

public class Repo {
    public String find(long id) {
        return "row" + id;
    }

    public String query(String sql) {
        return sql;
    }
}
`,
};

export interface BenchSpec {
  version?: string;
  /** repo trees: origin (under sources/) → files */
  trees: Record<string, Record<string, string>>;
  samples: Record<string, unknown>[];
  labels: Record<string, unknown[]>;
  sources?: Record<string, unknown>[];
}

/** Write a benchmark; `root_hash: auto` entries are filled from the written trees. */
export async function makeBench(spec: BenchSpec, dir = tmp('ca-bench-')): Promise<string> {
  for (const [origin, files] of Object.entries(spec.trees)) writeFiles(join(dir, origin), files);
  const h = new TreeHasher();
  const fill = async (r: Record<string, unknown>) => {
    if (r.root_hash === 'auto') r.root_hash = await h.hash(join(dir, String(r.origin)));
  };
  for (const s of spec.samples) {
    for (const r of s.repos as Record<string, unknown>[]) await fill(r);
    const si = s.scene_input as { versions?: { repos: Record<string, unknown>[] }[] } | undefined;
    for (const v of si?.versions ?? []) for (const r of v.repos) await fill(r);
  }
  h.dispose();
  writeFileSync(join(dir, 'manifest.yaml'), stringify({
    bench_version: spec.version ?? '0.0.1',
    sources: spec.sources ?? [{ dataset: 'self-built', status: 'active', license: 'test' }],
    samples: spec.samples,
  }));
  mkdirSync(join(dir, 'labels'), { recursive: true });
  for (const [project, labels] of Object.entries(spec.labels)) writeFileSync(join(dir, 'labels', `${project}.yaml`), stringify({ project, labels }));
  return dir;
}

export function copyTree(from: string, to: string): void {
  mkdirSync(to, { recursive: true });
  cpSync(from, to, { recursive: true });
}

export function writeConfig(baseUrl: string, dir = tmp('ca-evalcfg-'), pricing = true): string {
  const path = join(dir, 'config.json');
  writeFileSync(path, JSON.stringify({
    ...defaultAppConfig(),
    modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl, apiKey: 'test-key-123456', models: [{ id: 'm1', contextWindow: 64_000, maxTokens: 4096 }] }],
    defaultModel: { provider: 'gw', model: 'm1' },
    pricing: pricing ? { 'gw/m1': { currency: 'USD', input: 1, output: 2 } } : {},
  }, null, 2));
  return path;
}

export function sample(id: string, extra: Record<string, unknown>): Record<string, unknown> {
  return {
    sample_id: id, project: 'demo', partition: 'dev', kind: 'vuln', language: 'java',
    source: { dataset: 'self-built', license: 'test' }, scene: 'full', labels: [], tags: [], ...extra,
  };
}
