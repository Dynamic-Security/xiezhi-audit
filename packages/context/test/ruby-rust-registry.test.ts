// Ruby and Rust registered as full-audit languages — grammars load, Rust repositories count
// only with a declared server framework, Ruby by share; the base extractors give symbols and resolved calls.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { auditLanguagesOf, cargoDependencyNames, isRustBackend, type StructIndex } from '@xiezhi/contracts';
import { auditLanguagesOfView, buildIndex, createSnapshot, Executor, loadLanguage, loadRules, SnapshotView } from '@xiezhi/context';

async function viewOf(files: Record<string, string>): Promise<{ view: SnapshotView; root: string }> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1130-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return { view: new SnapshotView('repo', s.root, s.manifest), root };
}
async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const { view, root } = await viewOf(files);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}
const edges = (idx: StructIndex) => idx.callEdges.filter((e) => e.to).map((e) => `${e.from.split('#').pop()} -> ${e.to!.split('#').pop()} (${e.confidence})`).sort();

const CARGO_AXUM = `[package]
name = "api"
version = "0.1.0"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }

[dev-dependencies]
reqwest = "0.12"
`;

describe('registry', () => {
  it('grammars load', async () => {
    expect((await loadLanguage('ruby')).abiVersion).toBeGreaterThanOrEqual(14);
    expect((await loadLanguage('rust')).abiVersion).toBeGreaterThanOrEqual(14);
  });

  it('Cargo.toml dependencies and the Rust server rule', () => {
    expect(cargoDependencyNames(CARGO_AXUM).sort()).toEqual(['axum', 'tokio']);
    expect(cargoDependencyNames('[workspace.dependencies]\nactix-web = "4"\n[dependencies.rocket]\nversion = "0.5"\n[build-dependencies]\ncc = "1"\n').sort()).toEqual(['actix-web', 'rocket']);
    expect(isRustBackend(['clap', 'serde'])).toBe(false);
    expect(isRustBackend(['tonic'])).toBe(true);
    expect(auditLanguagesOf({ rust: 40 })).toEqual([]);
    expect(auditLanguagesOf({ rust: 40 }, false, true)).toEqual(['rust']);
    expect(auditLanguagesOf({ ruby: 30, python: 1 })).toEqual(['ruby']);
    // A Java service with a few Ruby scripts stays Java (any Java file counts; Ruby below the minor share).
    expect(auditLanguagesOf({ java: 200, ruby: 5 })).toEqual(['java']);
  });

  it('snapshot rule: Rails app and axum service are auditable, a Rust CLI is not', async () => {
    const rails = await viewOf({ Gemfile: "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\n", 'app/controllers/users_controller.rb': 'class UsersController < ApplicationController\nend\n' });
    expect(auditLanguagesOfView(rails.view)).toEqual(['ruby']);
    const cli = await viewOf({ 'Cargo.toml': '[package]\nname = "tool"\n[dependencies]\nclap = "4"\n', 'src/main.rs': 'fn main() {}\n' });
    expect(auditLanguagesOfView(cli.view)).toEqual([]);
    const api = await viewOf({ 'Cargo.toml': CARGO_AXUM, 'src/main.rs': 'fn main() {}\n' });
    expect(auditLanguagesOfView(api.view)).toEqual(['rust']);
  });
});

describe('base extractors', () => {
  it('Ruby: classes in modules, instance and singleton methods, resolved calls', async () => {
    const idx = await indexOf({
      'Gemfile': "gem 'rails'\n",
      'app/services/billing/invoice_service.rb': `module Billing
  class InvoiceService
    def self.call(user, params)
      new.issue(user, params[:amount])
    end

    def issue(user, amount)
      validate(amount)
      Notifier.deliver(user)
    end

    private

    def validate(amount)
      raise ArgumentError if amount.to_i <= 0
    end
  end
end
`,
      'app/services/notifier.rb': `class Notifier
  def self.deliver(user)
    user.email
  end
end
`,
    });
    const names = idx.symbols.map((s) => `${s.kind}:${s.symbolId.split('#').pop()}`).sort();
    expect(names).toEqual([
      'class:Billing.InvoiceService', 'class:app/services/notifier.rb.Notifier', 'interface:app/services/billing/invoice_service.rb.Billing',
      'method:Billing.InvoiceService.call(2)', 'method:Billing.InvoiceService.issue(2)', 'method:Billing.InvoiceService.validate(1)',
      'method:app/services/notifier.rb.Notifier.deliver(1)',
    ]);
    expect(edges(idx)).toEqual(expect.arrayContaining([
      'Billing.InvoiceService.issue(2) -> Billing.InvoiceService.validate(1) (resolved)',
      'Billing.InvoiceService.issue(2) -> app/services/notifier.rb.Notifier.deliver(1) (resolved)',
    ]));
  });

  it('Rust: module paths, impl methods, use aliases and Self calls', async () => {
    const idx = await indexOf({
      'Cargo.toml': CARGO_AXUM,
      'src/main.rs': `mod db;
mod handlers;

#[tokio::main]
async fn main() {
    handlers::serve().await;
}
`,
      'src/db.rs': `pub struct UserRepo { pool: String }

impl UserRepo {
    pub fn new(pool: String) -> Self { Self { pool } }
    pub fn find(&self, id: i64) -> Option<String> { self.query(id) }
    fn query(&self, id: i64) -> Option<String> { Some(format!("{}{}", self.pool, id)) }
}

pub fn connect(url: &str) -> UserRepo { UserRepo::new(url.to_string()) }
`,
      'src/handlers/mod.rs': `use crate::db::{connect, UserRepo};

pub async fn serve() {
    let repo = connect("postgres://");
    show(&repo, 1);
}

fn show(repo: &UserRepo, id: i64) -> Option<String> { repo.find(id) }
`,
    });
    const names = idx.symbols.map((s) => `${s.kind}:${s.symbolId.split('#').pop()}`).sort();
    expect(names).toEqual(expect.arrayContaining([
      'class:db.UserRepo', 'func:.main(0)', 'func:db.connect(1)', 'func:handlers.serve(0)', 'func:handlers.show(2)',
      'method:db.UserRepo.find(1)', 'method:db.UserRepo.new(1)', 'method:db.UserRepo.query(1)',
    ]));
    expect(edges(idx)).toEqual(expect.arrayContaining([
      'db.UserRepo.find(1) -> db.UserRepo.query(1) (resolved)',
      'db.connect(1) -> db.UserRepo.new(1) (resolved)',
      'handlers.serve(0) -> db.connect(1) (resolved)',
      'handlers.serve(0) -> handlers.show(2) (resolved)',
    ]));
  });
});
