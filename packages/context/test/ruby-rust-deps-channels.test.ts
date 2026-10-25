// Ruby and Rust dependencies (Gemfile / Gemfile.lock, Cargo.toml / Cargo.lock), outbound connection
// points (Net::HTTP, HTTParty, Faraday, gRPC stubs; reqwest, tonic clients) and non-HTTP entries (Ruby gRPC services,
// Sidekiq / ActiveJob / Resque jobs and their schedules, whenever, Rake tasks; tonic services with interceptors, lapin /
// rdkafka consumers, tokio-cron-scheduler jobs, clap subcommands).
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Connection, StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, declaredDependencies, Executor, extractConnections, loadRules, matchConnections, SnapshotView } from '@xiezhi/context';

async function viewOf(files: Record<string, string>): Promise<{ view: SnapshotView; root: string }> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1133-'));
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
const channels = (idx: StructIndex) => idx.entrypoints.filter((e) => e.kind !== 'http').map((e) => `${e.kind} ${e.entryKey} [${e.pathTemplate ?? ''}] -> ${e.handler.slice(e.handler.indexOf('#') + 1)}${e.authSignals.length ? ` ${JSON.stringify(e.authSignals)}` : ''}`).sort();

describe('dependencies', () => {
  it('Gemfile.lock supersedes the Gemfile; GIT / PATH gems and platforms handled', async () => {
    const { view } = await viewOf({
      Gemfile: "source 'https://rubygems.org'\ngem 'rails', '~> 7.1'\ngem 'nokogiri', '1.15.4'\ngem 'local', path: 'vendor/local'\n",
      'Gemfile.lock': `GIT
  remote: https://github.com/x/forked.git
  specs:
    forked (0.1.0)

GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.4-x86_64-linux)
      racc (~> 1.4)
    rails (7.1.3)
    racc (1.7.3)

PLATFORMS
  x86_64-linux
`,
    });
    expect(declaredDependencies(view).filter((d) => d.ecosystem === 'rubygems').map((d) => `${d.name}@${d.version} ${d.path}:${d.line}`).sort()).toEqual([
      'nokogiri@1.15.4 Gemfile.lock:9', 'racc@1.7.3 Gemfile.lock:12', 'rails@7.1.3 Gemfile.lock:11',
    ]);
  });

  it('Cargo.lock registry packages; workspace members, git sources and path dependencies skipped', async () => {
    const { view } = await viewOf({
      'Cargo.toml': '[package]\nname = "api"\nversion = "0.1.0"\n[dependencies]\naxum = "0.7"\nserde = { version = "=1.0.200", features = ["derive"] }\nlocal = { path = "../local" }\n',
      'Cargo.lock': `version = 3

[[package]]
name = "api"
version = "0.1.0"

[[package]]
name = "axum"
version = "0.7.5"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "forked"
version = "0.2.0"
source = "git+https://github.com/x/forked#abc"
`,
      'tools/Cargo.toml': '[package]\nname = "tools"\n[dependencies]\nclap = "=4.5.4"\n',
    });
    expect(declaredDependencies(view).filter((d) => d.ecosystem === 'cargo').map((d) => `${d.name}@${d.version ?? '?'} ${d.path}`).sort()).toEqual([
      // serde is pinned in the manifest but absent from this lock file: the manifest entry stays.
      'axum@0.7.5 Cargo.lock', 'clap@4.5.4 tools/Cargo.toml', 'serde@1.0.200 Cargo.toml',
    ]);
  });
});

describe('connection points', () => {
  it('Ruby: Net::HTTP, HTTParty module and class base_uri, Faraday connection, gRPC stub', async () => {
    const { view } = await viewOf({
      'app/clients.rb': `BILLING = "http://billing-svc:8080"
class StockClient
  include HTTParty
  base_uri "http://stock-svc"
  def fetch(id)
    self.class.get("/api/stock/#{id}")
  end
end
def pay
  Net::HTTP.post(URI("#{BILLING}/api/payments"), "{}")
  HTTParty.get("http://audit-svc/api/events")
  conn = Faraday.new(url: "http://user-svc")
  conn.post("/api/users")
  stub = Helloworld::Greeter::Stub.new("greeter-svc:50051", :this_channel_is_insecure)
end
`,
    });
    const cs = (await extractConnections(view, null, null)).filter((c) => c.side === 'consumes');
    expect(cs.map((c) => `${c.kind} ${c.key.method ?? '-'} ${c.key.pathTemplate ?? c.key.service} @${c.serviceHint ?? '-'} ${c.extraction}`).sort()).toEqual([
      'grpc - Greeter @greeter-svc literal',
      'http GET /api/events @audit-svc literal',
      'http GET /api/stock/{?} @stock-svc partial',
      'http POST /api/payments @billing-svc constant_folded',
      'http POST /api/users @user-svc literal',
    ]);
  });

  it('Rust: reqwest module and client calls with format! constants, tonic client', async () => {
    const { view } = await viewOf({
      'src/clients.rs': `const BILLING: &str = "http://billing-svc:8080";
async fn run(client: reqwest::Client, id: u64) {
    reqwest::get("http://audit-svc/api/events").await;
    client.post(format!("{}/api/payments", BILLING)).send().await;
    client.get(format!("{BILLING}/api/invoices/{}", id)).send().await;
    let mut g = GreeterClient::connect("http://greeter-svc:50051").await.unwrap();
}
`,
    });
    const cs = (await extractConnections(view, null, null)).filter((c) => c.side === 'consumes');
    expect(cs.map((c) => `${c.kind} ${c.key.method ?? '-'} ${c.key.pathTemplate ?? c.key.service} @${c.serviceHint ?? '-'} ${c.extraction}`).sort()).toEqual([
      'grpc - Greeter @greeter-svc literal',
      'http GET /api/events @audit-svc literal',
      'http GET /api/invoices/{?} @billing-svc partial',
      'http POST /api/payments @billing-svc constant_folded',
    ]);
  });
});

describe('non-HTTP entries', () => {
  it('Ruby: gRPC service with proto names, Sidekiq / ActiveJob / Resque jobs, sidekiq-cron YAML, whenever, Rake tasks', async () => {
    const idx = await indexOf({
      Gemfile: "gem 'rails'\ngem 'sidekiq'\n",
      'protos/greeter.proto': 'syntax = "proto3";\npackage helloworld;\nservice Greeter {\n  rpc SayHello (HelloRequest) returns (HelloReply);\n}\n',
      'app/grpc/greeter_server.rb': 'class GreeterServer < Helloworld::Greeter::Service\n  def say_hello(req, _call)\n    Helloworld::HelloReply.new(message: req.name)\n  end\nend\n',
      'app/workers/hard_worker.rb': "class HardWorker\n  include Sidekiq::Job\n  sidekiq_options queue: :critical\n  def perform(id)\n  end\nend\n",
      'app/jobs/application_job.rb': 'class ApplicationJob < ActiveJob::Base\nend\n',
      'app/jobs/report_job.rb': "class ReportJob < ApplicationJob\n  queue_as :reports\n  def perform(user_id)\n  end\nend\n",
      'app/jobs/legacy_job.rb': "class LegacyJob\n  @queue = :legacy\n  def self.perform(x)\n  end\nend\n",
      'app/models/report.rb': 'class Report\n  def self.generate\n  end\nend\n',
      'config/schedule.yml': 'hard_work:\n  cron: "0 4 * * *"\n  class: "HardWorker"\n',
      'config/schedule.rb': "every 1.day, at: '4:30 am' do\n  runner \"Report.generate\"\n  rake \"db:cleanup\"\nend\n",
      'lib/tasks/db.rake': "namespace :db do\n  desc 'clean'\n  task cleanup: :environment do\n    Report.generate\n  end\nend\n",
    });
    expect(channels(idx)).toEqual([
      'cli cli:rake db:cleanup [rake db:cleanup] -> lib/tasks/db.rake.<rake db:cleanup>(0)',
      'message mq:activejob:ReportJob [reports] -> app/jobs/report_job.rb.ReportJob.perform(1)',
      'message mq:resque:LegacyJob [legacy] -> app/jobs/legacy_job.rb.LegacyJob.perform(1)',
      'message mq:sidekiq:HardWorker [critical] -> app/workers/hard_worker.rb.HardWorker.perform(1)',
      'rpc rpc:helloworld.Greeter/SayHello [] -> app/grpc/greeter_server.rb.GreeterServer.say_hello(2)',
      'schedule cron:HardWorker [0 4 * * *] -> app/workers/hard_worker.rb.HardWorker.perform(1)',
      'schedule cron:Report.generate [1.day, at: \'4:30 am\'] -> app/models/report.rb.Report.generate(0)',
      'schedule cron:rake db:cleanup [1.day, at: \'4:30 am\'] -> <unresolved:rake db:cleanup>',
    ]);
    // Calls inside a Rake task have a caller.
    expect(idx.callEdges.some((e) => e.from.endsWith('<rake db:cleanup>(0)') && e.to?.endsWith('Report.generate(0)'))).toBe(true);
  });

  it('Rust: tonic service with interceptor, lapin / rdkafka consumers, tokio-cron-scheduler job, clap subcommands', async () => {
    const idx = await indexOf({
      'Cargo.toml': '[package]\nname = "svc"\n[dependencies]\ntonic = "0.12"\nlapin = "2"\nrdkafka = "0.36"\nclap = "4"\n',
      'proto/greeter.proto': 'syntax = "proto3";\npackage helloworld;\nservice Greeter {\n  rpc SayHello (HelloRequest) returns (HelloReply);\n}\n',
      'src/main.rs': `mod greeter;
use tonic::transport::Server;
#[tokio::main]
async fn main() {
    Server::builder()
        .add_service(GreeterServer::with_interceptor(greeter::MyGreeter::default(), check_auth))
        .serve(addr).await;
}
fn check_auth(req: Request<()>) -> Result<Request<()>, Status> { Ok(req) }
`,
      'src/greeter.rs': `pub struct MyGreeter;
#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(&self, request: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> { todo!() }
}
`,
      'src/workers.rs': `async fn consume(channel: lapin::Channel, consumer: StreamConsumer) {
    channel.basic_consume("orders", "svc", BasicConsumeOptions::default(), FieldTable::default()).await;
    consumer.subscribe(&["payments", "refunds"]).unwrap();
    sched.add(Job::new_async("0 0 * * * *", |_id, _l| Box::pin(async move { cleanup().await; })).unwrap()).await;
}
async fn cleanup() {}
#[derive(Subcommand)]
enum Commands { Serve, ImportUsers { path: String } }
`,
    });
    expect(channels(idx)).toEqual([
      'cli cli:import-users [import-users] -> workers.Commands',
      'cli cli:serve [serve] -> workers.Commands',
      'message mq:kafka:payments [payments] -> workers.consume(2)',
      'message mq:kafka:refunds [refunds] -> workers.consume(2)',
      'message mq:rabbitmq:orders [orders] -> workers.consume(2)',
      'rpc rpc:helloworld.Greeter/SayHello [] -> greeter.MyGreeter.say_hello(1) ["with_interceptor(check_auth)"]',
      'schedule cron:0 0 * * * *:src/workers.rs:4 [0 0 * * * *] -> workers.<cron 0 0 * * * *>(2)',
    ]);
  });
});

describe('cross-repository gRPC', () => {
  it('a Ruby stub matches a Rust tonic service, and a Rust client matches a Ruby grpc service', async () => {
    const proto = 'syntax = "proto3";\npackage shop;\nservice Inventory {\n  rpc Reserve (R) returns (R);\n}\nservice Billing {\n  rpc Charge (C) returns (C);\n}\n';
    const rs = await viewOf({
      'Cargo.toml': '[package]\nname = "inventory"\n[dependencies]\ntonic = "0.12"\n',
      'proto/shop.proto': proto,
      'src/main.rs': '#[tonic::async_trait]\nimpl Inventory for Svc {\n    async fn reserve(&self, r: Request<R>) -> Result<Response<R>, Status> { todo!() }\n}\nasync fn bill() { let c = BillingClient::connect("http://billing:50051").await; }\n',
    });
    const rb = await viewOf({
      Gemfile: "gem 'grpc'\n",
      'proto/shop.proto': proto,
      'app/billing_server.rb': 'class BillingServer < Shop::Billing::Service\n  def charge(req, _call)\n  end\nend\n',
      'app/reserve.rb': 'def reserve\n  Shop::Inventory::Stub.new("inventory:50051", :this_channel_is_insecure)\nend\n',
    });
    const conns: Connection[] = [];
    for (const [name, v] of [['inventory', rs], ['billing', rb]] as const) {
      const sv = new SnapshotView(name, v.view.root, v.view.manifest);
      const idx = (await buildIndex(sv, loadRules(), { indexesDir: join(v.root, 'indexes') })).index;
      conns.push(...(await extractConnections(sv, idx, null)));
    }
    const r = matchConnections(conns, [{ repo: 'inventory', appNames: [] }, { repo: 'billing', appNames: [] }]);
    const byId = new Map(conns.map((c) => [c.connId, c]));
    // Each service is provided twice per repository (the .proto declaration and the implementation entry), as for every language.
    expect(r.matches.filter((m) => m.provider).map((m) => { const p = byId.get(m.provider!)!; return `${byId.get(m.consumer)!.repo} → ${p.repo} ${p.key.service}/${p.key.rpc}`; }).filter((x, i, a) => a.indexOf(x) === i).sort()).toEqual([
      'billing → inventory shop.Inventory/Reserve',
      'inventory → billing shop.Billing/Charge',
    ]);
  });
});

