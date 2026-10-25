// public dataset import: CWE-Bench-Java CSV rows and OSV Go records become
// URL + commit vuln / fixed sample drafts with sinks from the fix diff; labels without entries are allowed
// only for imported datasets and are skipped by the entry-hit metric. Remotes are local file:// repositories.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse, stringify } from 'yaml';
import { loadBench, prepareTrees, staticChecks } from '../src/bench.js';
import { changedFunctions, importDataset, parseCsv, writeImport } from '../src/import.js';
import { main } from '../src/main.js';
import { META_FORMAT, RUN_FORMAT, type FindingRec, type RunRecord } from '../src/record.js';
import { scoreRunDir } from '../src/score.js';
import { materializeRemote } from '../src/trees.js';
import { writeJson } from '../src/util.js';
import { MINI_JAVA, makeBench, sample, tmp, writeFiles } from './helpers.js';

function git(dir: string, ...args: string[]): string {
  return execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'init.defaultBranch=main', ...args], { cwd: dir, encoding: 'utf8' }).trim();
}

function upstream(files: Record<string, string>, fix: Record<string, string>): { url: string; vuln: string; fixed: string } {
  const dir = tmp('ca-upstream-');
  git(dir, 'init', '-q');
  writeFiles(dir, files);
  git(dir, 'add', '.');
  git(dir, 'commit', '-qm', 'vuln');
  const vuln = git(dir, 'rev-parse', 'HEAD');
  writeFiles(dir, fix);
  git(dir, 'add', '.');
  git(dir, 'commit', '-qm', 'fix');
  return { url: `file://${dir}`, vuln, fixed: git(dir, 'rev-parse', 'HEAD') };
}

// ---- CWE-Bench-Java ----

const SVC = 'core/src/main/java/org/x/FileService.java';
const JAVA_VULN = {
  [SVC]: `package org.x;

public class FileService {
    public String read(String name) {
        return load("/data/" + name);
    }

    public String list(String dir) {
        return load("/data/" + dir + "/");
    }

    String load(String p) {
        return p;
    }

    public int size() {
        return 1;
    }
}
`,
  'core/src/main/java/org/x/Web.java': `package org.x;

public class Web {
    private final FileService files = new FileService();

    public String get(String q) {
        return files.read(q);
    }
}
`,
};
const JAVA_FIX = {
  [SVC]: JAVA_VULN[SVC]!.replace('return load("/data/" + name);', 'return load("/data/" + Paths.clean(name));').replace('return load("/data/" + dir + "/");', 'return load("/data/" + Paths.clean(dir) + "/");'),
  'core/src/main/java/org/x/Paths.java': 'package org.x;\n\npublic class Paths {\n    static String clean(String s) {\n        return s.replace("..", "");\n    }\n}\n',
  'core/src/test/java/org/x/FileServiceTest.java': 'package org.x;\n\npublic class FileServiceTest {\n    void testRead() {\n    }\n}\n',
};

function cweData(up: { url: string; vuln: string; fixed: string }): string {
  const dir = tmp('ca-cwedata-');
  const slug = 'x__files_CVE-2099-0001_1.0';
  writeFiles(dir, {
    'data/project_info.csv': [
      'id,project_slug,cve_id,cwe_id,cwe_name,github_username,github_repository_name,github_tag,github_url,advisory_id,buggy_commit_id,fix_commit_ids',
      `1,${slug},CVE-2099-0001,CWE-022,"Path Traversal, relative",x,files,1.0,${up.url},GHSA-aaaa-bbbb-cccc,${up.vuln},${'0'.repeat(40)};${up.fixed}`,
    ].join('\n') + '\n',
    'data/fix_info.csv': [
      'project_slug,cve_id,github_username,github_repository_name,commit,file,class,class_start,class_end,method,method_start,method_end,signature',
      `${slug},CVE-2099-0001,x,files,${up.fixed},core/src/main/java/org/x/Paths.java,Paths,1,6,clean,3,5,String clean(String)`,
      `${slug},CVE-2099-0001,x,files,${up.fixed},${SVC},FileService,3,19,read,4,6,String read(String)`,
      `${slug},CVE-2099-0001,x,files,${up.fixed},core/src/test/java/org/x/FileServiceTest.java,FileServiceTest,3,6,testRead,4,5,void testRead()`,
      `${slug},CVE-2099-0001,x,files,${up.fixed},${SVC},FileService,3,19,,,,`,
    ].join('\n') + '\n',
    [`advisory/${slug}.json`]: JSON.stringify({ id: 'GHSA-aaaa-bbbb-cccc', published: '2099-03-04T00:00:00Z', summary: 'Path traversal in FileService', aliases: ['CVE-2099-0001'] }),
    'select.yaml': stringify({
      dataset: 'cwe-bench-java', dataset_ref: 'test@1',
      entries: [{ id: slug, project: 'x-files', partition: 'holdout', label_prefix: 'XF', license: 'MIT' }],
    }),
  });
  return dir;
}

describe('CSV', () => {
  it('parses quoted fields, doubled quotes, embedded newlines and CRLF', () => {
    expect(parseCsv('a,b,c\r\n1,"x, ""y""",\n2,"l1\nl2",z\n\n')).toEqual([{ a: '1', b: 'x, "y"', c: '' }, { a: '2', b: 'l1\nl2', c: 'z' }]);
  });
});

describe('import cwe-bench-java', () => {
  it('builds a vuln + fixed pair: named method as sink, other changed methods as alternatives, fix location as decoy', async () => {
    const up = upstream(JAVA_VULN, JAVA_FIX);
    const data = cweData(up);
    const cache = tmp('ca-srccache-');
    const trees = { allowFileProtocol: true, cacheDir: cache };
    const r = await importDataset({ dataset: 'cwe-bench-java', dataDir: data, selectPath: join(data, 'select.yaml'), trees });
    expect(r.pairs).toHaveLength(1);
    const p = r.pairs[0]!;
    const vt = await materializeRemote({ origin: up.url, commit: up.vuln }, cache, trees);
    const ft = await materializeRemote({ origin: up.url, commit: up.fixed }, cache, trees);
    // Fixed version = the last fix commit; root hashes are the product snapshot's.
    expect(p.samples.map((s) => [s.sample_id, s.kind, s.repos[0]!.commit, s.repos[0]!.root_hash, s.label_policy, s.partition])).toEqual([
      ['x-files-vuln', 'vuln', up.vuln, vt.rootHash, 'known_only', 'holdout'],
      ['x-files-fixed', 'fixed', up.fixed, ft.rootHash, 'known_only', 'holdout'],
    ]);
    expect(p.samples[0]!.tags).toEqual(['public_dataset', 'cwe_bench_java', 'disclosed_2099']);
    expect(p.samples[0]!.source).toEqual({ dataset: 'cwe-bench-java', ref: 'CVE-2099-0001; GHSA-aaaa-bbbb-cccc; cwe-bench-java x__files_CVE-2099-0001_1.0', license: 'MIT' });
    const [vuln, neg] = p.labels as Record<string, any>[];
    // Paths.clean is new in the fix (not a sink); test methods are never sinks; list changed in the same file.
    expect(vuln).toMatchObject({
      label_id: 'XF-PATH-01', kind: 'vuln', category: 'path_traversal', cwe: ['CWE-22'], entries: [], depth: 'single_point',
      sink: { repo: 'x-files', file: SVC, function: 'FileService.read' },
      alt_sinks: [{ repo: 'x-files', file: SVC, function: 'FileService.list' }],
    });
    expect(vuln.root_cause).toContain('Path traversal in FileService');
    expect(neg).toMatchObject({ label_id: 'XF-FIX', kind: 'negative', guard: 'fix', category: 'path_traversal', decoys: [{ repo: 'x-files', file: SVC, function: 'FileService.read' }] });
    expect(p.review.join('\n')).toContain('Paths.clean');

    // The draft validates as a benchmark (anchors resolve in the fetched trees), and the output is deterministic.
    const out1 = tmp('ca-import-');
    const out2 = tmp('ca-import-');
    const files = writeImport(r, out1);
    writeImport(await importDataset({ dataset: 'cwe-bench-java', dataDir: data, selectPath: join(data, 'select.yaml'), trees: { ...trees, offline: true } }), out2);
    for (const f of files) expect(readFileSync(join(out2, f), 'utf8')).toBe(readFileSync(join(out1, f), 'utf8'));
    expect(readFileSync(join(out1, 'IMPORT.md'), 'utf8')).toMatch(/data\/project_info\.csv` sha256 `[0-9a-f]{64}`/);
    const bench = await benchFrom(out1, 'cwe-bench-java');
    await prepareTrees(bench, bench.samples, trees);
    expect(staticChecks(bench, trees).filter((i) => i.level === 'error')).toEqual([]);
  }, 60_000);

  it('rejects an unknown slug, a primary that is not in the vulnerable version, and datasets without an importer', async () => {
    const up = upstream(JAVA_VULN, JAVA_FIX);
    const data = cweData(up);
    const trees = { allowFileProtocol: true, cacheDir: tmp('ca-srccache-') };
    const sel = parse(readFileSync(join(data, 'select.yaml'), 'utf8'));
    writeFileSync(join(data, 'bad.yaml'), stringify({ ...sel, entries: [{ ...sel.entries[0], id: 'nope' }] }));
    await expect(importDataset({ dataset: 'cwe-bench-java', dataDir: data, selectPath: join(data, 'bad.yaml'), trees })).rejects.toThrow('project_info.csv 中没有 nope');
    writeFileSync(join(data, 'prim.yaml'), stringify({ ...sel, entries: [{ ...sel.entries[0], primary: 'Paths.clean' }] }));
    await expect(importDataset({ dataset: 'cwe-bench-java', dataDir: data, selectPath: join(data, 'prim.yaml'), trees })).rejects.toThrow('primary Paths.clean 在漏洞版本中找不到');
    // A reviewer-chosen primary among the named / changed methods is accepted.
    writeFileSync(join(data, 'list.yaml'), stringify({ ...sel, entries: [{ ...sel.entries[0], primary: 'FileService.list' }] }));
    const r = await importDataset({ dataset: 'cwe-bench-java', dataDir: data, selectPath: join(data, 'list.yaml'), trees });
    expect((r.pairs[0]!.labels[0] as any).sink.function).toBe('FileService.list');
    expect((r.pairs[0]!.labels[0] as any).alt_sinks.map((a: any) => a.function)).toEqual(['FileService.read']);
    await expect(importDataset({ dataset: 'owasp-benchmark-java', dataDir: data, selectPath: join(data, 'select.yaml') })).rejects.toThrow('未实现');
    await expect(main(['import', 'nope'])).rejects.toThrow('未知数据集');
    await expect(main(['import', 'osv-go'])).rejects.toThrow('--data');
  }, 60_000);
});

// ---- OSV Go ----

const GO_H = `package http

import "net/http"

type handler struct{}
`;
const GO_VULN = {
  'go.mod': 'module example.com/fb/v2\n\ngo 1.22\n',
  'http/share.go': `${GO_H}
func withPermShare(fn func()) func() {
	return func() {
		fn()
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	withPermShare(func() {})()
}

func helper() int {
	return 1
}
`,
  'http/share_test.go': 'package http\n\nfunc TestX() {}\n',
};
const GO_FIX = { 'http/share.go': GO_VULN['http/share.go']!.replace('\t\tfn()\n', '\t\tif allowed() {\n\t\t\tfn()\n\t\t}\n').replace('func helper() int {\n\treturn 1\n}', 'func helper() int {\n\treturn 2\n}\n\nfunc allowed() bool {\n\treturn false\n}') };

function osvData(up: { url: string; vuln: string; fixed: string }, extra: Record<string, unknown> = {}): string {
  const dir = tmp('ca-osvdata-');
  writeFiles(dir, {
    'GO-2099-0001.json': JSON.stringify({
      id: 'GO-2099-0001', published: '2099-05-06T00:00:00Z', summary: 'Share permission bypass', aliases: ['GHSA-zzzz-yyyy-xxxx', 'CVE-2099-0002'],
      database_specific: { cwe_ids: ['CWE-863'] },
      affected: [{
        package: { name: 'example.com/fb/v2', ecosystem: 'Go' },
        ranges: [{ type: 'GIT', repo: up.url, events: [{ introduced: '0' }, { fixed: up.fixed }] }, { type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.1.0' }] }],
        ecosystem_specific: { imports: [{ path: 'example.com/fb/v2/http', symbols: ['handler.ServeHTTP', 'withPermShare'] }] },
      }],
      ...extra,
    }),
    'select.yaml': stringify({ dataset: 'osv-go', dataset_ref: 'osv.dev test', entries: [{ id: 'GO-2099-0001', project: 'fb', partition: 'dev', label_prefix: 'FB', license: 'Apache-2.0', vuln_commit: up.vuln }] }),
  });
  return dir;
}

describe('import osv-go', () => {
  it('takes the fix from the GIT range, the sink from the listed symbols in changed files, and the CWE from the record', async () => {
    const up = upstream(GO_VULN, GO_FIX);
    const data = osvData(up);
    const trees = { allowFileProtocol: true, cacheDir: tmp('ca-srccache-') };
    const r = await importDataset({ dataset: 'osv-go', dataDir: data, selectPath: join(data, 'select.yaml'), trees });
    const p = r.pairs[0]!;
    expect(p.samples.map((s) => [s.sample_id, s.language, s.repos[0]!.commit])).toEqual([['fb-vuln', 'go', up.vuln], ['fb-fixed', 'go', up.fixed]]);
    expect(p.samples[0]!.source.ref).toBe('CVE-2099-0002; GHSA-zzzz-yyyy-xxxx; GO-2099-0001');
    // ServeHTTP is listed first but did not change; withPermShare did. helper changed too (same file) and
    // comes before the unchanged named symbol.
    expect(p.labels[0]).toMatchObject({
      label_id: 'FB-IDOR-01', category: 'authz_object', cwe: ['CWE-863'], entries: [],
      sink: { repo: 'fb', file: 'http/share.go', function: 'withPermShare' },
      alt_sinks: [{ file: 'http/share.go', function: 'helper' }, { file: 'http/share.go', function: 'handler.ServeHTTP' }],
    });
    expect(p.labels[1]).toMatchObject({ decoys: [{ file: 'http/share.go', function: 'withPermShare' }] });
    const out = tmp('ca-import-');
    writeImport(r, out);
    const bench = await benchFrom(out, 'osv-go');
    await prepareTrees(bench, bench.samples, trees);
    expect(staticChecks(bench, trees).filter((i) => i.level === 'error')).toEqual([]);
  }, 60_000);

  it('without symbols takes the first changed function and the changed functions of the other changed files', async () => {
    const up = upstream({ ...GO_VULN, 'cmd/main.go': 'package main\n\nfunc run() int {\n\treturn 3\n}\n' }, { ...GO_FIX, 'cmd/main.go': 'package main\n\nfunc run() int {\n\treturn 4\n}\n' });
    const data = osvData(up, { affected: [{ package: { name: 'example.com/fb/v2', ecosystem: 'Go' }, ranges: [{ type: 'GIT', repo: up.url, events: [{ fixed: up.fixed }] }] }] });
    const r = await importDataset({ dataset: 'osv-go', dataDir: data, selectPath: join(data, 'select.yaml'), trees: { allowFileProtocol: true, cacheDir: tmp('ca-srccache-') } });
    const [vuln] = r.pairs[0]!.labels as Record<string, any>[];
    // Changed files in path order: cmd/main.go (run), http/share.go (withPermShare, helper).
    expect(vuln!.sink).toEqual({ repo: 'fb', file: 'cmd/main.go', function: 'run' });
    expect(vuln!.alt_sinks.map((a: any) => a.function)).toEqual(['withPermShare', 'helper']);
    expect(vuln!.depth).toBe('cross_file');
    expect(r.pairs[0]!.review.join('\n')).toContain('需人工确认');
  }, 60_000);

  it('needs the vulnerable commit and a CWE; several fix commits need fixed_commit', async () => {
    const up = upstream(GO_VULN, GO_FIX);
    const trees = { allowFileProtocol: true, cacheDir: tmp('ca-srccache-') };
    const noCwe = osvData(up, { database_specific: {} });
    await expect(importDataset({ dataset: 'osv-go', dataDir: noCwe, selectPath: join(noCwe, 'select.yaml'), trees })).rejects.toThrow('需在选择文件中给出 cwe');
    const two = osvData(up, { references: [{ type: 'FIX', url: `https://example.com/o/r/commit/${'a'.repeat(40)}` }] });
    await expect(importDataset({ dataset: 'osv-go', dataDir: two, selectPath: join(two, 'select.yaml'), trees })).rejects.toThrow('有 2 个修复提交');
    const data = osvData(up);
    const sel = parse(readFileSync(join(data, 'select.yaml'), 'utf8'));
    writeFileSync(join(data, 'nov.yaml'), stringify({ ...sel, entries: [{ ...sel.entries[0], vuln_commit: undefined }] }));
    await expect(importDataset({ dataset: 'osv-go', dataDir: data, selectPath: join(data, 'nov.yaml'), trees })).rejects.toThrow('需要 vuln_commit');
  }, 60_000);

  it('compares functions by qualified name', () => {
    const a = tmp('ca-a-');
    const b = tmp('ca-b-');
    writeFiles(a, GO_VULN);
    writeFiles(b, { ...GO_VULN, ...GO_FIX });
    const ch = changedFunctions(a, b, 'http/share.go');
    expect(ch.vuln.map((f) => f.qualified)).toEqual(['withPermShare', 'helper']);
    expect(ch.fixed.map((f) => f.qualified)).toEqual(['withPermShare', 'helper', 'allowed']);
  });
});

// ---- labels without entries ----

async function benchFrom(importDir: string, dataset: string) {
  const dir = tmp('ca-bench-');
  const samples = parse(readFileSync(join(importDir, 'samples.yaml'), 'utf8'));
  writeFileSync(join(dir, 'manifest.yaml'), stringify({ bench_version: '0.0.1', sources: [{ dataset, status: 'active', license: 'test' }], samples }));
  for (const s of samples as { project: string }[]) writeFiles(dir, { [`labels/${s.project}.yaml`]: readFileSync(join(importDir, 'labels', `${s.project}.yaml`), 'utf8') });
  return loadBench(dir);
}

const API = 'src/main/java/com/t/Api.java';
const repos = () => [{ name: 'app', role: 'auditable', origin: 'sources/demo/v/app', root_hash: 'auto' }];
const lab = (id: string, entries: unknown[]) => ({ label_id: id, kind: 'vuln', category: 'sqli', cwe: ['CWE-89'], root_cause: 'q 拼接', depth: 'single_point', sink: { repo: 'app', file: API, function: 'Api.search' }, entries, expected: { verdict: 'confirmed' } });

describe('labels without entries', () => {
  it('are rejected on self-built / real-oss samples and accepted on imported datasets', async () => {
    const dir = await makeBench({
      trees: { 'sources/demo/v/app': MINI_JAVA },
      sources: [{ dataset: 'self-built', status: 'active', license: 't' }, { dataset: 'cwe-bench-java', status: 'active', license: 't' }],
      samples: [
        sample('own-vuln', { repos: repos(), labels: ['OWN-01'] }),
        sample('pub-vuln', { project: 'pub', repos: repos(), labels: ['PUB-01'], source: { dataset: 'cwe-bench-java', license: 't' }, label_policy: 'known_only' }),
      ],
      labels: { demo: [lab('OWN-01', [])], pub: [lab('PUB-01', [])] },
    });
    const errors = staticChecks(loadBench(dir)).filter((i) => i.level === 'error');
    expect(errors.map((i) => `${i.where}: ${i.message}`)).toEqual([expect.stringMatching(/^sample own-vuln \/ OWN-01: 来源 self-built 的漏洞标注至少需要一个入口/)]);
  });

  it('are skipped by the entry-hit metric', async () => {
    const dir = await makeBench({
      trees: { 'sources/demo/v/app': MINI_JAVA },
      sources: [{ dataset: 'self-built', status: 'active', license: 't' }, { dataset: 'osv-go', status: 'active', license: 't' }],
      samples: [
        sample('own-vuln', { repos: repos(), labels: ['OWN-01'] }),
        sample('pub-vuln', { project: 'pub', repos: repos(), labels: ['PUB-01'], source: { dataset: 'osv-go', license: 't' }, label_policy: 'known_only' }),
      ],
      labels: { demo: [lab('OWN-01', [{ repo: 'app', route: 'GET /search' }])], pub: [lab('PUB-01', [])] },
    });
    const f = (entries: string[]): FindingRec => ({ id: 'f1', display_no: 1, title: 't', category: 'sqli', cwe: null, severity: 'high', confidence: 0.9, repo: 'app', path: API, start_line: 16, end_line: 16, entries, status: 'confirmed', vulnerability_id: null, match_level: null, pending: null });
    const rec = (sid: string, project: string, findings: FindingRec[]): RunRecord => ({
      format: RUN_FORMAT, sample_id: sid, project, kind: 'vuln', language: 'java', partition: 'dev', scene: 'full', dataset: 'x', repeat: 1, status: 'completed', error: null, wall_ms: 1, risk: null, integrity: [],
      audits: [{ audit_id: `a-${sid}`, role: 'base', version: 'base', scene: 'full', status: 'completed', partial_reasons: [], error_class: null, budget_declined: false, wall_ms: 1, model_ms: 1, steps: [], attempts: [], findings, snapshot_hashes: {}, reverify: [] }],
    });
    const score = async (records: RunRecord[]) => {
      const run = tmp('ca-evalrun-');
      writeJson(join(run, 'run.json'), {
        format: META_FORMAT, name: 'u', bench: { root: dir, version: '0.0.1', manifest_hash: 'x', labels_hash: 'y' }, partition: 'dev', filter: {}, repeats: 1, selected: [], invalid: {}, skipped: [], stopped_reason: null,
        config: { sha256: 'c'.repeat(64), providers: [], default_model: 'gw/m1', cheap_model: null, priced_models: [] }, strategy_override: {}, knowledge: { dir: null, skills: [] },
        code: { revision: 'abc', dirty: false }, pi_version: '0', node: '22', platform: 'test', model_mode: 'live', started_at: '', ended_at: '',
      });
      for (const r of records) writeJson(join(run, 'samples', r.sample_id, `r${r.repeat}.json`), r);
      return (await scoreRunDir(run)).quality;
    };
    // Both labels hit; only the one with an entry counts (1/1, not diluted to 1/2 or inflated).
    const q = await score([rec('own-vuln', 'demo', [f(['GET /search'])]), rec('pub-vuln', 'pub', [f([])])]);
    expect(q.counts.labels_hit).toBe(2);
    expect(q.entry_hit_rate).toBe(1);
    // Only the entry-less label hit: the rate is not applicable rather than 0 %.
    expect((await score([rec('pub-vuln', 'pub', [f(['GET /x'])])])).entry_hit_rate).toBeNull();
  });
});
