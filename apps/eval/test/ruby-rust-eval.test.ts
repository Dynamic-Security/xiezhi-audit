// The scorer's function locators for Ruby and Rust (independent lexical scanners), and `eval import
// osv` for RubyGems and crates.io advisories (remotes are local file:// repositories; never built or run).
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { stringify } from 'yaml';
import { importDataset } from '../src/import.js';
import { enclosingFunction, listFunctions } from '../src/locate.js';
import { tmp, writeFiles } from './helpers.js';

const names = (text: string, file: string) => listFunctions(text, file).map((f) => `${f.qualified}:${f.start}-${f.end}`);

describe('locators', () => {
  it('Ruby: methods in nested modules / classes, self methods, blocks and heredocs, one-line and endless defs', () => {
    const src = [
      '# Benchmark fixture. Never built.',
      'module Admin',
      '  class UsersController < BaseController',
      '    before_action :require_admin!',
      '    def show',
      '      @user = User.find(params[:id])',
      '      if @user.admin?',
      '        sql = <<~SQL',
      '          def fake; end',
      '        SQL',
      '      end',
      '      [1, 2].each do |x|',
      '        puts "end #{x}"',
      '      end',
      '    end',
      '',
      '    def self.policy; :admin; end',
      '    def ping = "pong"',
      '  end',
      'end',
      'def helper(x)',
      '  x',
      'end',
    ].join('\n');
    expect(names(src, 'app/controllers/admin/users_controller.rb')).toEqual(['UsersController.show:5-15', 'UsersController.policy:17-17', 'UsersController.ping:18-18', 'helper:21-23']);
    expect(enclosingFunction(src, 'x.rb', 13)?.qualified).toBe('UsersController.show');
  });

  it('Rust: free functions with attributes, impl and trait-impl methods, strings with braces, lifetimes', () => {
    const src = [
      '// Benchmark fixture. Never built.',
      'pub struct Repo<\'a> { db: &\'a str }',
      'impl<\'a> Repo<\'a> {',
      '    pub fn find(&self, id: i64) -> String {',
      '        format!("{{}} {}", id)',
      '    }',
      '}',
      'impl Greeter for MyGreeter {',
      '    async fn say_hello(&self, r: Request<()>) -> Result<(), Status> { let c = \'}\'; Ok(()) }',
      '}',
      '#[get("/users/{id}")]',
      '#[allow(unused)]',
      'async fn show(path: web::Path<i64>) -> impl Responder {',
      '    /* } nested /* } */ */',
      '    HttpResponse::Ok()',
      '}',
      'trait Store { fn get(&self) -> u8; fn default_get(&self) -> u8 { 1 } }',
    ].join('\n');
    expect(names(src, 'src/routes.rs')).toEqual(['Repo.find:4-6', 'MyGreeter.say_hello:9-9', 'show:11-16', 'Store.default_get:17-17']);
  });
});

function git(dir: string, ...args: string[]): string {
  return execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=t', '-c', 'init.defaultBranch=main', ...args], { cwd: dir, encoding: 'utf8' }).trim();
}
function upstream(files: Record<string, string>, fix: Record<string, string>) {
  const dir = tmp('ca-upstream-');
  git(dir, 'init', '-q');
  writeFiles(dir, files); git(dir, 'add', '.'); git(dir, 'commit', '-qm', 'vuln');
  const vuln = git(dir, 'rev-parse', 'HEAD');
  writeFiles(dir, fix); git(dir, 'add', '.'); git(dir, 'commit', '-qm', 'fix');
  return { url: `file://${dir}`, vuln, fixed: git(dir, 'rev-parse', 'HEAD') };
}

describe('import osv', () => {
  for (const c of [
    { eco: 'RubyGems', lang: 'ruby', file: 'app/controllers/notes_controller.rb', fn: 'NotesController.show', tag: 'osv_rubygems',
      vuln: 'class NotesController < ApplicationController\n  def show\n    Note.where("id = #{params[:id]}").first\n  end\n\n  def index\n    Note.all\n  end\nend\n',
      fix: 'class NotesController < ApplicationController\n  def show\n    Note.where(id: params[:id]).first\n  end\n\n  def index\n    Note.all\n  end\nend\n' },
    { eco: 'crates.io', lang: 'rust', file: 'src/handlers.rs', fn: 'show', tag: 'osv_crates_io',
      vuln: 'pub async fn show(id: String) -> String {\n    let q = format!("SELECT * FROM n WHERE id = {}", id);\n    sqlx::query(&q);\n    q\n}\n\npub fn other() {}\n',
      fix: 'pub async fn show(id: String) -> String {\n    sqlx::query("SELECT * FROM n WHERE id = $1").bind(&id);\n    id\n}\n\npub fn other() {}\n' },
  ]) {
    it(`${c.eco}: language ${c.lang}, sink = the changed function`, async () => {
      const up = upstream({ [c.file]: c.vuln }, { [c.file]: c.fix });
      const data = tmp('ca-osvdata-');
      writeFiles(data, {
        'GHSA-rrrr-ssss-tttt.json': JSON.stringify({
          id: 'GHSA-rrrr-ssss-tttt', published: '2026-05-02T00:00:00Z', summary: 'SQL injection in note lookup', database_specific: { cwe_ids: ['CWE-89'] },
          affected: [{ package: { name: 'notes', ecosystem: c.eco }, ranges: [{ type: 'GIT', repo: up.url, events: [{ introduced: '0' }, { fixed: up.fixed }] }] }],
          references: [],
        }),
        'select.yaml': stringify({ dataset: 'osv', ecosystem: c.eco, dataset_ref: 'osv test', entries: [{ id: 'GHSA-rrrr-ssss-tttt', project: 'notes-sqli', partition: 'holdout', label_prefix: 'NS', license: 'MIT', vuln_commit: up.vuln, url: up.url }] }),
      });
      const r = await importDataset({ dataset: 'osv', dataDir: data, selectPath: join(data, 'select.yaml'), trees: { allowFileProtocol: true, cacheDir: tmp('ca-srccache-') } });
      const p = r.pairs[0]!;
      expect(p.samples.map((s) => s.language)).toEqual([c.lang, c.lang]);
      expect(p.samples[0]!.tags).toContain(c.tag);
      expect(p.labels[0]).toMatchObject({ category: 'sqli', sink: { file: c.file, function: c.fn } });
    }, 60_000);
  }
});
