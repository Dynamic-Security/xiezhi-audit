// `eval import osv` for any OSV ecosystem — fix commit from GIT ranges, FIX references or the
// only commit link; the sink from the functions the fix changed (the function locators); the language from the ecosystem
// or the entry. Remotes are local file:// repositories (never built or run).
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { stringify } from 'yaml';
import { importDataset } from '../src/import.js';
import { tmp, writeFiles } from './helpers.js';

function git(dir: string, ...args: string[]): string {
  return execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'init.defaultBranch=main', ...args], { cwd: dir, encoding: 'utf8' }).trim();
}
function upstream(files: Record<string, string>, fix: Record<string, string>) {
  const dir = tmp('ca-upstream-');
  git(dir, 'init', '-q');
  writeFiles(dir, files); git(dir, 'add', '.'); git(dir, 'commit', '-qm', 'vuln');
  const vuln = git(dir, 'rev-parse', 'HEAD');
  writeFiles(dir, fix); git(dir, 'add', '.'); git(dir, 'commit', '-qm', 'fix');
  return { url: `file://${dir}`, vuln, fixed: git(dir, 'rev-parse', 'HEAD'), dir };
}
const trees = () => ({ allowFileProtocol: true, cacheDir: tmp('ca-srccache-') });

const PY_VULN = {
  'app/recipes/views.py': `from .service import RecipeService

def get_recipe(request, slug):
    return RecipeService().get(slug)

def list_recipes(request):
    return []
`,
  'app/recipes/service.py': `class RecipeService:
    def get(self, slug):
        return db.query(f"SELECT * FROM recipe WHERE slug = '{slug}'")

    def count(self):
        return 1
`,
  'tests/test_service.py': 'def test_x():\n    pass\n',
};
const PY_FIX = {
  'app/recipes/service.py': PY_VULN['app/recipes/service.py']!.replace(`db.query(f"SELECT * FROM recipe WHERE slug = '{slug}'")`, 'db.query("SELECT * FROM recipe WHERE slug = %s", [slug])'),
  'tests/test_service.py': 'def test_x():\n    assert True\n',
};

describe('import osv', () => {
  it('PyPI: fix commit from a FIX reference, sink = the changed function (tests ignored), language python', async () => {
    const up = upstream(PY_VULN, PY_FIX);
    const data = tmp('ca-osvdata-');
    writeFiles(data, {
      'GHSA-aaaa-bbbb-cccc.json': JSON.stringify({
        id: 'GHSA-aaaa-bbbb-cccc', published: '2026-03-02T00:00:00Z', summary: 'SQL injection in recipe lookup', aliases: ['CVE-2026-1111'],
        database_specific: { cwe_ids: ['CWE-89'] },
        affected: [{ package: { name: 'mealie', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.1.0' }] }] }],
        references: [{ type: 'WEB', url: 'https://example.com/advisory' }, { type: 'FIX', url: `https://github.com/mealie-recipes/mealie/commit/${up.fixed}` }],
      }),
      'select.yaml': stringify({ dataset: 'osv', ecosystem: 'PyPI', dataset_ref: 'osv test', entries: [{ id: 'GHSA-aaaa-bbbb-cccc', project: 'mealie-sqli', partition: 'holdout', label_prefix: 'ML', license: 'AGPL-3.0', vuln_commit: up.vuln, url: up.url }] }),
    });
    const r = await importDataset({ dataset: 'osv', dataDir: data, selectPath: join(data, 'select.yaml'), trees: trees() });
    const p = r.pairs[0]!;
    expect(p.samples.map((s) => [s.sample_id, s.language, s.partition, s.repos[0]!.commit])).toEqual([['mealie-sqli-vuln', 'python', 'holdout', up.vuln], ['mealie-sqli-fixed', 'python', 'holdout', up.fixed]]);
    expect(p.samples[0]!.tags).toEqual(expect.arrayContaining(['public_dataset', 'osv_pypi', 'disclosed_2026']));
    expect(p.labels[0]).toMatchObject({ label_id: 'ML-SQLI-01', category: 'sqli', sink: { file: 'app/recipes/service.py', function: 'RecipeService.get' }, entries: [] });
    expect(p.labels[1]).toMatchObject({ decoys: [{ file: 'app/recipes/service.py', function: 'RecipeService.get' }] });
  }, 60_000);

  it('npm with language typescript: the only commit link among the references; primary chosen by the reviewer', async () => {
    const vuln = {
      'src/routes/files.ts': "export function download(req: any, res: any) {\n  res.sendFile('/data/' + req.query.name);\n}\n\nexport function upload(req: any, res: any) {\n  res.send('ok');\n}\n",
      'src/util/path.ts': "export function clean(p: string) {\n  return p;\n}\n",
    };
    const fix = {
      'src/routes/files.ts': vuln['src/routes/files.ts'].replace("'/data/' + req.query.name", "'/data/' + clean(req.query.name)"),
      'src/util/path.ts': "export function clean(p: string) {\n  return p.replace(/\\.\\./g, '');\n}\n",
    };
    const up = upstream(vuln, fix);
    const data = tmp('ca-osvdata-');
    writeFiles(data, {
      'GHSA-dddd-eeee-ffff.json': JSON.stringify({
        id: 'GHSA-dddd-eeee-ffff', published: '2025-11-20T00:00:00Z', summary: 'Path traversal in download', database_specific: { cwe_ids: ['CWE-22'] },
        affected: [{ package: { name: 'outline', ecosystem: 'npm' } }],
        references: [{ type: 'WEB', url: `https://github.com/o/outline/commit/${up.fixed}` }],
      }),
      'select.yaml': stringify({ dataset: 'osv', ecosystem: 'npm', dataset_ref: 'osv test', entries: [{ id: 'GHSA-dddd-eeee-ffff', project: 'outline-path', partition: 'dev', label_prefix: 'OL', license: 'BSL-1.1', vuln_commit: up.vuln, url: up.url, language: 'typescript', primary: 'download' }] }),
    });
    const r = await importDataset({ dataset: 'osv', dataDir: data, selectPath: join(data, 'select.yaml'), trees: trees() });
    const p = r.pairs[0]!;
    expect(p.samples[0]!.language).toBe('typescript');
    expect(p.labels[0]).toMatchObject({ label_id: 'OL-PATH-01', sink: { file: 'src/routes/files.ts', function: 'download' }, alt_sinks: [{ file: 'src/util/path.ts', function: 'clean' }] });
  }, 60_000);

  it('requires the ecosystem and refuses records without any fix commit', async () => {
    const data = tmp('ca-osvdata-');
    writeFiles(data, {
      'GHSA-x.json': JSON.stringify({ id: 'GHSA-x', database_specific: { cwe_ids: ['CWE-79'] }, references: [{ type: 'WEB', url: 'https://example.com' }] }),
      'a.yaml': stringify({ dataset: 'osv', dataset_ref: 'r', entries: [{ id: 'GHSA-x', project: 'p', partition: 'dev', label_prefix: 'P', license: 'MIT', vuln_commit: 'a'.repeat(40) }] }),
      'b.yaml': stringify({ dataset: 'osv', ecosystem: 'Packagist', dataset_ref: 'r', entries: [{ id: 'GHSA-x', project: 'p', partition: 'dev', label_prefix: 'P', license: 'MIT', vuln_commit: 'a'.repeat(40) }] }),
    });
    await expect(importDataset({ dataset: 'osv', dataDir: data, selectPath: join(data, 'a.yaml'), trees: trees() })).rejects.toThrow('ecosystem');
    await expect(importDataset({ dataset: 'osv', dataDir: data, selectPath: join(data, 'b.yaml'), trees: trees() })).rejects.toThrow('没有修复提交');
  });
});
