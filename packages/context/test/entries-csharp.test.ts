// C# entries that are not HTTP routes — raw WebSockets, message consumers (MassTransit, NServiceBus, Kafka,
// Azure Service Bus, Azure Functions triggers), schedules (Hangfire, Quartz, BackgroundService, TimerTrigger) and
// CLI commands (System.CommandLine, CommandLineParser, Spectre.Console) — on small inline sources.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';

async function viewOf(files: Record<string, string>): Promise<SnapshotView> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m10cs-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return new SnapshotView('repo', s.root, s.manifest);
}
const indexOf = async (files: Record<string, string>) => (await buildIndex(await viewOf(files), loadRules(), { indexesDir: mkdtempSync(join(tmpdir(), 'ca-m10cs-i-')) })).index;
const CSPROJ = '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>\n';
const keysOf = (idx: StructIndex, kind: string) => idx.entrypoints.filter((e) => e.kind === kind).map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => {
  const e = idx.entrypoints.find((x) => x.entryKey === key);
  if (!e) throw new Error(`no entry ${key}; have ${idx.entrypoints.map((x) => x.entryKey).join(', ')}`);
  return e;
};
const short = (id: string) => id.replace(/^repo:[^#]*#/, '');

describe('C# WebSocket entries', () => {
  it('mapped lambdas, pipeline middleware, method groups, middleware classes and controller actions', async () => {
    const idx = await indexOf({
      'App/App.csproj': CSPROJ,
      'App/Program.cs': `var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.UseWebSockets();
app.Map("/ws", async context => {
    using var socket = await context.WebSockets.AcceptWebSocketAsync();
    await Echo(socket);
});
app.Use(async (context, next) => {
    if (context.Request.Path == "/live") {
        using var ws = await context.WebSockets.AcceptWebSocketAsync();
    } else await next(context);
});
app.Map("/feed", Feeds.Handle);
app.Map("/notify", b => b.UseMiddleware<NotifySocketMiddleware>());
app.MapGet("/plain", () => "hi");
app.Run();
static Task Echo(System.Net.WebSockets.WebSocket s) => Task.CompletedTask;
`,
      'App/Feeds.cs': `namespace App;
public static class Feeds {
    public static async Task Handle(HttpContext ctx) { var s = await ctx.WebSockets.AcceptWebSocketAsync(); }
}
`,
      'App/NotifySocketMiddleware.cs': `namespace App;
public class NotifySocketMiddleware {
    public async Task InvokeAsync(HttpContext context) {
        if (context.WebSockets.IsWebSocketRequest) { var ws = await context.WebSockets.AcceptWebSocketAsync(); }
    }
}
`,
      'App/StreamController.cs': `using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace App;
[ApiController]
[Authorize]
public class StreamController : ControllerBase {
    [Route("/stream")]
    public async Task Get() { using var ws = await HttpContext.WebSockets.AcceptWebSocketAsync(); }
}
`,
    });
    expect(keysOf(idx, 'socket')).toEqual(['ws:/feed', 'ws:/live', 'ws:/notify', 'ws:/stream', 'ws:/ws']);
    const ws = entry(idx, 'ws:/ws');
    expect(ws).toMatchObject({ kind: 'socket', protocol: 'websocket', pathTemplate: '/ws', framework: 'aspnetcore', ruleId: 'csharp.websocket' });
    expect(short(ws.handler)).toBe('Program.Main(0)');
    expect(short(entry(idx, 'ws:/live').handler)).toBe('Program.Main(0)');
    expect(short(entry(idx, 'ws:/feed').handler)).toBe('App.Feeds.Handle(1)');
    expect(short(entry(idx, 'ws:/notify').handler)).toBe('App.NotifySocketMiddleware.InvokeAsync(1)');
    const stream = entry(idx, 'ws:/stream');
    expect(short(stream.handler)).toBe('App.StreamController.Get(0)');
    expect(stream.authSignals).toContain('[Authorize]');
    expect(idx.entrypoints.filter((e) => e.kind === 'socket').every((e) => e.httpMethod === undefined)).toBe(true);
    expect(keysOf(idx, 'http')).toContain('GET /plain');
  });
});

describe('C# message consumers', () => {
  it('MassTransit consumers, NServiceBus handlers, Confluent Kafka and Azure Service Bus processors', async () => {
    const idx = await indexOf({
      'Svc/Svc.csproj': CSPROJ,
      'Svc/Consumers.cs': `using MassTransit;
using NServiceBus;
namespace Svc;
public class OrderConsumer : IConsumer<Contracts.OrderSubmitted>, IConsumer<OrderCancelled> {
    public Task Consume(ConsumeContext<OrderCancelled> context) => Task.CompletedTask;
    public Task Consume(ConsumeContext<Contracts.OrderSubmitted> context) => Task.CompletedTask;
}
public class PaymentHandler : IHandleMessages<PaymentReceived> {
    public Task Handle(PaymentReceived message, IMessageHandlerContext context) => Task.CompletedTask;
}
public abstract class BaseConsumer<T> : IConsumer<T> where T : class {
    public abstract Task Consume(ConsumeContext<T> context);
}
`,
      'Svc/Workers.cs': `using Confluent.Kafka;
using Azure.Messaging.ServiceBus;
namespace Svc;
public class KafkaWorker {
    public void Run(IConsumer<string, string> consumer) {
        consumer.Subscribe("orders");
        consumer.Subscribe(new[] { "audit", "billing" });
    }
}
public class BusWorker {
    private readonly ServiceBusClient _client;
    public async Task Start() {
        var processor = _client.CreateProcessor("invoices", "mailer");
        processor.ProcessMessageAsync += OnMessage;
        await processor.StartProcessingAsync();
    }
    private Task OnMessage(ProcessMessageEventArgs args) => Task.CompletedTask;
}
`,
      'Svc/Rx.cs': `namespace Svc;
public class Ticker {
    public void Watch(System.IObservable<int> source) { source.Subscribe(x => System.Console.WriteLine(x)); }
}
`,
    });
    expect(keysOf(idx, 'message')).toEqual([
      'mq:azure-servicebus:invoices/mailer', 'mq:kafka:audit', 'mq:kafka:billing', 'mq:kafka:orders',
      'mq:masstransit:OrderCancelled', 'mq:masstransit:OrderSubmitted', 'mq:nservicebus:PaymentReceived',
    ]);
    const mt = entry(idx, 'mq:masstransit:OrderSubmitted');
    expect(mt).toMatchObject({ kind: 'message', protocol: 'masstransit', pathTemplate: 'OrderSubmitted', framework: 'masstransit', ruleId: 'csharp.masstransit.consumer' });
    // Overloads share one symbol id (`Consume(1)`), as for every C# method of the same arity.
    expect(short(mt.handler)).toBe('Svc.OrderConsumer.Consume(1)');
    expect(entry(idx, 'mq:nservicebus:PaymentReceived')).toMatchObject({ protocol: 'nservicebus', framework: 'nservicebus', ruleId: 'csharp.nservicebus.handler' });
    expect(short(entry(idx, 'mq:nservicebus:PaymentReceived').handler)).toBe('Svc.PaymentHandler.Handle(2)');
    expect(entry(idx, 'mq:kafka:orders')).toMatchObject({ protocol: 'kafka', pathTemplate: 'orders' });
    expect(short(entry(idx, 'mq:kafka:orders').handler)).toBe('Svc.KafkaWorker.Run(1)');
    const sb = entry(idx, 'mq:azure-servicebus:invoices/mailer');
    expect(sb).toMatchObject({ protocol: 'azure-servicebus', pathTemplate: 'invoices/mailer' });
    expect(short(sb.handler)).toBe('Svc.BusWorker.OnMessage(1)');
  });
});

describe('C# Azure Functions', () => {
  it('queue / Service Bus / Kafka triggers as messages, TimerTrigger as schedule, HttpTrigger as http', async () => {
    const idx = await indexOf({
      'Fn/Fn.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><AzureFunctionsVersion>v4</AzureFunctionsVersion></PropertyGroup></Project>\n',
      'Fn/Functions.cs': `using Microsoft.Azure.Functions.Worker;
namespace Fn;
public class Functions {
    [Function("ProcessOrder")]
    public void ProcessOrder([ServiceBusTrigger("orders", Connection = "Bus")] string body) { }
    [Function("Thumb")]
    public void Thumb([QueueTrigger("thumbnails")] string msg) { }
    [Function("Clicks")]
    public void Clicks([KafkaTrigger("Brokers", "clicks", ConsumerGroup = "fn")] string evt) { }
    [Function("Nightly")]
    public void Nightly([TimerTrigger("0 0 2 * * *")] TimerInfo timer) { }
    [Function("GetOrder")]
    public object GetOrder([HttpTrigger(AuthorizationLevel.Function, "get", Route = "orders/{id:int}")] HttpRequestData req, int id) => null;
    [Function("Ping")]
    public object Ping([HttpTrigger(AuthorizationLevel.Anonymous, "get", "post")] HttpRequestData req) => null;
}
`,
    });
    expect(keysOf(idx, 'message')).toEqual(['mq:azure-servicebus:orders', 'mq:azure-storage-queue:thumbnails', 'mq:kafka:clicks']);
    const sb = entry(idx, 'mq:azure-servicebus:orders');
    expect(sb).toMatchObject({ protocol: 'azure-servicebus', pathTemplate: 'orders', framework: 'azure-functions', ruleId: 'csharp.azure.function' });
    expect(short(sb.handler)).toBe('Fn.Functions.ProcessOrder(1)');
    const timer = entry(idx, 'cron:Functions.Nightly');
    expect(timer).toMatchObject({ kind: 'schedule', protocol: 'cron', pathTemplate: '0 0 2 * * *', framework: 'azure-functions' });
    expect(short(timer.handler)).toBe('Fn.Functions.Nightly(1)');
    const get = entry(idx, 'GET /api/orders/{}');
    expect(get).toMatchObject({ kind: 'http', httpMethod: 'GET', pathTemplate: '/api/orders/{id}', authSignals: ['[HttpTrigger(AuthorizationLevel.Function)]'] });
    expect(entry(idx, 'POST /api/Ping').authSignals).toEqual([]);
  });
});

describe('C# scheduled jobs', () => {
  it('Hangfire recurring jobs, Quartz jobs with their cron, BackgroundService', async () => {
    const idx = await indexOf({
      'Jobs/Jobs.csproj': CSPROJ,
      'Jobs/Program.cs': `using Hangfire;
using Quartz;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddQuartz(q => {
    var key = new JobKey("cleanup");
    q.AddJob<CleanupJob>(o => o.WithIdentity(key));
    q.AddTrigger(t => t.ForJob(key).WithCronSchedule("0 0/5 * * * ?"));
});
var app = builder.Build();
RecurringJob.AddOrUpdate("daily-report", () => Reports.Send(), Cron.Daily);
RecurringJob.AddOrUpdate<InvoiceJob>("invoices", j => j.Run(), "0 3 * * *");
app.Run();
`,
      'Jobs/Work.cs': `using Quartz;
namespace Jobs;
public static class Reports { public static void Send() { } }
public class InvoiceJob { public Task Run() => Task.CompletedTask; }
public class CleanupJob : IJob {
    public Task Execute(IJobExecutionContext context) => Task.CompletedTask;
}
public class OutboxWorker : BackgroundService {
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => Task.CompletedTask;
}
`,
    });
    expect(keysOf(idx, 'schedule')).toEqual(['cron:CleanupJob.Execute', 'cron:OutboxWorker.ExecuteAsync', 'cron:daily-report', 'cron:invoices']);
    const daily = entry(idx, 'cron:daily-report');
    expect(daily).toMatchObject({ protocol: 'cron', pathTemplate: 'Cron.Daily', framework: 'hangfire', ruleId: 'csharp.hangfire.recurring' });
    expect(short(daily.handler)).toBe('Jobs.Reports.Send(0)');
    expect(entry(idx, 'cron:invoices')).toMatchObject({ pathTemplate: '0 3 * * *' });
    expect(short(entry(idx, 'cron:invoices').handler)).toBe('Jobs.InvoiceJob.Run(0)');
    const quartz = entry(idx, 'cron:CleanupJob.Execute');
    expect(quartz).toMatchObject({ protocol: 'cron', pathTemplate: '0 0/5 * * * ?', framework: 'quartz', ruleId: 'csharp.quartz.job' });
    expect(short(quartz.handler)).toBe('Jobs.CleanupJob.Execute(1)');
    const hosted = entry(idx, 'cron:OutboxWorker.ExecuteAsync');
    expect(hosted).toMatchObject({ protocol: 'hosted-service', pathTemplate: '', ruleId: 'csharp.hosted.service' });
    expect(short(hosted.handler)).toBe('Jobs.OutboxWorker.ExecuteAsync(1)');
  });
});

describe('C# CLI commands', () => {
  it('System.CommandLine (instances and subclasses), CommandLineParser verbs, Spectre.Console commands', async () => {
    const idx = await indexOf({
      'Cli/Cli.csproj': '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType></PropertyGroup></Project>\n',
      'Cli/Program.cs': `using System.CommandLine;
using CommandLine;
using Spectre.Console.Cli;
namespace Cli;
public static class Program {
    public static int Main(string[] args) {
        var root = new RootCommand("tool");
        var deploy = new Command("deploy", "Deploy it");
        deploy.SetHandler(Deploy);
        var group = new Command("db");
        root.AddCommand(deploy);
        Parser.Default.ParseArguments<AddOptions>(args).WithParsed<AddOptions>(RunAdd);
        var app = new CommandApp();
        app.Configure(c => c.AddCommand<SyncCommand>("sync"));
        return 0;
    }
    static void Deploy() { }
    static void RunAdd(AddOptions o) { }
}
[Verb("add", HelpText = "Add files")]
public class AddOptions { }
public class PurgeCommand : Command {
    public PurgeCommand() : base("purge", "Purge caches") { this.SetHandler(Purge); }
    private void Purge() { }
}
public class SyncCommand : Command<SyncCommand.Settings> {
    public class Settings : CommandSettings { }
    public override int Execute(CommandContext context, Settings settings) => 0;
}
`,
    });
    expect(keysOf(idx, 'cli')).toEqual(['cli:add', 'cli:deploy', 'cli:purge', 'cli:sync']);
    const deploy = entry(idx, 'cli:deploy');
    expect(deploy).toMatchObject({ kind: 'cli', protocol: 'cli', pathTemplate: 'deploy', framework: 'system-commandline', ruleId: 'csharp.cli.command' });
    expect(short(deploy.handler)).toBe('Cli.Program.Deploy(0)');
    expect(short(entry(idx, 'cli:purge').handler)).toBe('Cli.PurgeCommand.Purge(0)');
    expect(entry(idx, 'cli:add')).toMatchObject({ framework: 'commandlineparser', pathTemplate: 'add' });
    expect(short(entry(idx, 'cli:add').handler)).toBe('Cli.Program.RunAdd(1)');
    expect(entry(idx, 'cli:sync')).toMatchObject({ framework: 'spectre-console', pathTemplate: 'sync' });
    expect(short(entry(idx, 'cli:sync').handler)).toBe('Cli.SyncCommand.Execute(2)');
  });
});

describe('C# negatives', () => {
  it('look-alikes stay out: Rx Subscribe, IJob without Quartz, plain Command classes, non-Hangfire AddOrUpdate', async () => {
    const idx = await indexOf({
      'Lib/Lib.csproj': CSPROJ,
      'Lib/Things.cs': `namespace Lib;
public interface IJob { void Execute(); }
public class Chore : IJob { public void Execute() { } }
public class Command { public Command(string name) { } }
public class Uses {
    public void Go(System.IObservable<string> src, Cache cache) {
        src.Subscribe(s => { });
        var c = new Command("noop");
        cache.AddOrUpdate("k", () => Load(), 5);
    }
    static int Load() => 1;
}
public class Cache { public void AddOrUpdate(string k, System.Func<int> f, int ttl) { } }
`,
    });
    expect(idx.entrypoints.filter((e) => e.kind !== 'http')).toEqual([]);
  });
});
