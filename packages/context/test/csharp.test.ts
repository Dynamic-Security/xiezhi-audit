// C# / ASP.NET Core: symbols, calls, controller and minimal-API entries, sinks with taint hints,
// auth signals, NuGet declared dependencies and outbound HTTP clients — on small inline sources.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Connection, StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, declaredDependencies, Executor, extractConnections, loadRules, SnapshotView } from '@xiezhi/context';

async function viewOf(files: Record<string, string>): Promise<SnapshotView> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m11cs-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return new SnapshotView('repo', s.root, s.manifest);
}

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const v = await viewOf(files);
  return (await buildIndex(v, loadRules(), { indexesDir: join(mkdtempSync(join(tmpdir(), 'ca-m11cs-idx-')), 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key)!;
const sinksOf = (idx: StructIndex, category: string) => idx.sinks.filter((s) => s.category === category);
const short = (id: string | null | undefined) => (id ?? '').replace(/^repo:[^#]*#/, '');

const CONTROLLER = `using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace Shop.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Staff")]
public class OrdersController : ControllerBase
{
    private readonly IOrderService _orders;
    public OrdersController(IOrderService orders) { _orders = orders; }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id) => Ok(await _orders.LoadAsync(id));

    [HttpPost]
    [AllowAnonymous]
    public IActionResult Create([FromBody] OrderDto dto) { Validate(dto); return Ok(); }

    [HttpDelete("/admin/orders/{id}")]
    [Authorize(Policy = "Admin")]
    public IActionResult Remove(int id) => this.Delete(id);

    [Route("[action]")]
    [AcceptVerbs("GET", "HEAD")]
    public IActionResult ExportAsync() => Ok();

    private void Validate(OrderDto dto) { }
    private IActionResult Delete(int id) => NoContent();
}
`;

describe('C# symbols and calls', () => {
  it('namespaces, constructors named after the class, extension methods without `this`, typed receivers', async () => {
    const idx = await indexOf({
      'Controllers/OrdersController.cs': CONTROLLER,
      'Services/OrderService.cs': `namespace Shop.Api.Services
{
    public interface IOrderService { Task<Order> LoadAsync(int id); }
    public class OrderService(ShopDb db) : IOrderService
    {
        public Task<Order> LoadAsync(int id) => db.Orders.FindAsync(id).AsTask();
        public void Touch() { var audit = new AuditLog(); audit.Write("x"); Helper(); this.Helper(); }
        private void Helper() { }
    }
    public class AuditLog { public void Write(string m) { } }
    public static class OrderExtensions { public static int Total(this Order o, int tax) => tax; }
}
`,
    });
    const sym = (name: string) => idx.symbols.find((s) => s.name === name)!;
    expect(short(sym('OrdersController').symbolId)).toBe('Shop.Api.Controllers.OrdersController');
    expect(idx.symbols.filter((s) => s.name === 'OrdersController').map((s) => [s.kind, short(s.symbolId)])).toEqual([
      ['class', 'Shop.Api.Controllers.OrdersController'], ['method', 'Shop.Api.Controllers.OrdersController.OrdersController(1)'],
    ]);
    expect(short(sym('LoadAsync').symbolId)).toMatch(/^Shop\.Api\.Services\.IOrderService\.LoadAsync\(1\)$/);
    expect(sym('IOrderService').kind).toBe('interface');
    expect(short(sym('Total').symbolId)).toBe('Shop.Api.Services.OrderExtensions.Total(1)');
    expect(sym('Get').signature).toBe('public async Task<IActionResult> Get(int id)');
    const edge = (from: string, callee: string) => idx.callEdges.filter((e) => short(e.from).endsWith(from) && e.calleeText === callee).map((e) => [e.confidence, short(e.to)]);
    // Field typed by an interface → the interface method; bare / this calls → same class; `var x = new T()` → T.
    expect(edge('OrdersController.Get(1)', '_orders.LoadAsync')).toEqual([['resolved', 'Shop.Api.Services.IOrderService.LoadAsync(1)']]);
    expect(edge('OrdersController.Create(1)', 'Validate')).toEqual([['resolved', 'Shop.Api.Controllers.OrdersController.Validate(1)']]);
    expect(edge('OrdersController.Remove(1)', 'this.Delete')).toEqual([['resolved', 'Shop.Api.Controllers.OrdersController.Delete(1)']]);
    expect(edge('OrderService.Touch(0)', 'audit.Write')).toEqual([['resolved', 'Shop.Api.Services.AuditLog.Write(1)']]);
    expect(edge('OrderService.Touch(0)', 'Helper')).toEqual([['resolved', 'Shop.Api.Services.OrderService.Helper(0)']]);
  });
});

describe('ASP.NET Core entries', () => {
  it('attribute routing: [controller] / [action] tokens, constraints, absolute templates, AcceptVerbs; attribute auth signals', async () => {
    const idx = await indexOf({ 'Controllers/OrdersController.cs': CONTROLLER });
    expect(keys(idx)).toEqual([
      'DELETE /admin/orders/{}', 'GET /api/orders/export', 'GET /api/orders/{}', 'HEAD /api/orders/export', 'POST /api/orders',
    ]);
    expect(entry(idx, 'GET /api/orders/{}').pathTemplate).toBe('/api/orders/{id}');
    expect(short(entry(idx, 'GET /api/orders/{}').handler)).toBe('Shop.Api.Controllers.OrdersController.Get(1)');
    expect(entry(idx, 'GET /api/orders/{}').authSignals).toEqual(['[Authorize(Roles = "Staff")]']);
    expect(entry(idx, 'POST /api/orders').authSignals).toEqual(expect.arrayContaining(['[AllowAnonymous]', '[Authorize(Roles = "Staff")]']));
    expect(entry(idx, 'DELETE /admin/orders/{}').authSignals).toContain('[Authorize(Policy = "Admin")]');
    expect(idx.entrypoints.every((e) => e.framework === 'aspnetcore')).toBe(true);
  });

  it('minimal APIs: MapGroup prefix and RequireAuthorization inherit, endpoint AllowAnonymous, method groups resolve, lambdas belong to Program.Main', async () => {
    const idx = await indexOf({
      'Program.cs': `var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<ApiKeyMiddleware>();
var api = app.MapGroup("/api").RequireAuthorization();
var admin = api.MapGroup("/admin");
admin.RequireAuthorization("AdminOnly");
api.MapGet("/items/{id:int}", async (int id, ShopDb db) => await db.Items.FindAsync(id));
admin.MapDelete("/items/{id}", ItemHandlers.Delete);
app.MapGet("/health", () => "ok").AllowAnonymous();
app.MapMethods("/ping", new[] { "GET", "HEAD" }, Ping);
app.Run();
static string Ping() => "pong";
`,
      'ItemHandlers.cs': `namespace Shop;
public static class ItemHandlers { public static IResult Delete(int id) => Results.NoContent(); }
`,
    });
    expect(keys(idx)).toEqual(['DELETE /api/admin/items/{}', 'GET /api/items/{}', 'GET /health', 'GET /ping', 'HEAD /ping']);
    const items = entry(idx, 'GET /api/items/{}');
    expect(short(items.handler)).toBe('Program.Main(0)');
    // An inline lambda keeps its own lines, not the whole top-level Program.Main.
    expect(items.range).toEqual({ startLine: 9, endLine: 9 });
    expect(entry(idx, 'GET /health').range).toEqual({ startLine: 11, endLine: 11 });
    expect(items.authSignals).toEqual(['RequireAuthorization()']);
    expect(items.middlewares).toEqual(['UseAuthentication()', 'UseAuthorization()', 'UseMiddleware<ApiKeyMiddleware>()', 'RequireAuthorization()']);
    const del = entry(idx, 'DELETE /api/admin/items/{}');
    expect(short(del.handler)).toBe('Shop.ItemHandlers.Delete(1)');
    expect(del.authSignals).toEqual(['RequireAuthorization()', 'RequireAuthorization("AdminOnly")']);
    expect(entry(idx, 'GET /health').authSignals).toEqual(['AllowAnonymous()']);
    expect(short(entry(idx, 'GET /ping').handler)).toBe('Program.Ping(0)');
    expect(idx.authSignals.filter((s) => s.kind === 'middleware').map((s) => s.detail)).toEqual(expect.arrayContaining(['app.UseAuthentication()', 'app.UseMiddleware<ApiKeyMiddleware>()']));
    expect(sinksOf(idx, 'authz_object').map((s) => short(s.symbolId))).toEqual(['Program.Main(0)']);
  });

  it('negatives: non-controller classes, interfaces and non-route Map calls produce no entries', async () => {
    const idx = await indexOf({
      'Clients/IUserApi.cs': `namespace Shop.Clients;
public interface IUserApi { [HttpGet("/users/{id}")] Task<User> Get(int id); }
public class Mapper { public void Configure(Profile p) { p.Map("x"); p.MapFrom("y"); } }
public class ReportJob { [Route("x")] public void Run() { } }
`,
    });
    expect(idx.entrypoints).toEqual([]);
  });
});

describe('C# sinks', () => {
  it('SQL: Dapper / ADO.NET / EF raw with taint hints; FromSqlInterpolated is not a sink', async () => {
    const idx = await indexOf({
      'Data/ReportRepository.cs': `using Dapper;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
namespace Shop.Data;
public class ReportRepository
{
    private const string AllSql = "SELECT * FROM Orders";
    private readonly IDbConnection _conn;
    private readonly ShopDb _db;
    public IEnumerable<Order> Search(string status, string sort)
    {
        var sql = "SELECT * FROM Orders WHERE Status = '" + status + "'";
        sql += " ORDER BY " + sort;
        return _conn.Query<Order>(sql);
    }
    public IEnumerable<Order> All() => _conn.Query<Order>(AllSql, new { });
    public Order? One(int id) => _conn.QueryFirstOrDefault<Order>("SELECT * FROM Orders WHERE Id = @id", new { id });
    public List<Order> Raw(string name) => _db.Orders.FromSqlRaw($"SELECT * FROM Orders WHERE Name = '{name}'").ToList();
    public List<Order> Safe(string name) => _db.Orders.FromSqlInterpolated($"SELECT * FROM Orders WHERE Name = {name}").ToList();
    public int Legacy(string name) => _db.Database.ExecuteSqlCommand($"DELETE FROM Orders WHERE Name = {name}");
    public int Count(string table)
    {
        using var cmd = new SqlCommand(string.Format("SELECT COUNT(*) FROM {0}", table), new SqlConnection("x"));
        return (int)cmd.ExecuteScalar();
    }
}
`,
    });
    const sql = sinksOf(idx, 'sqli').map((s) => [short(s.symbolId), s.taintHint ?? '-']).sort();
    expect(sql).toEqual([
      ['Shop.Data.ReportRepository.All(0)', 'constant'],
      ['Shop.Data.ReportRepository.Count(1)', 'string_concat'],
      ['Shop.Data.ReportRepository.One(1)', 'constant'],
      ['Shop.Data.ReportRepository.Raw(1)', 'string_concat'],
      ['Shop.Data.ReportRepository.Search(2)', 'string_concat'],
    ]);
  });

  it('cmdi, deserialization, ssrf, path traversal, redirect, xss, xxe, code injection', async () => {
    const idx = await indexOf({
      'Web/ToolsController.cs': `using System.Diagnostics;
using Newtonsoft.Json;
namespace Shop.Web;
public class ToolsController : Controller
{
    private readonly HttpClient _http;
    public void Run(string host)
    {
        Process.Start("ping", "-c 1 " + host);
        var psi = new ProcessStartInfo { FileName = "tar", Arguments = $"-xf {host}" };
        Process.Start("git", "status");
    }
    public object Load(Stream s, string json)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        new BinaryFormatter().Deserialize(s);
        return JsonConvert.DeserializeObject(json, settings);
    }
    public async Task Fetch(string url) { await _http.GetStringAsync(url); await _http.GetAsync("https://status.example.com/ping"); }
    public IActionResult Doc(string name) => PhysicalFile(Path.Combine("/data", name), "application/pdf");
    public string Read(string name) => System.IO.File.ReadAllText(Path.Combine(_root, name));
    public IActionResult Back(string returnUrl) => Redirect(returnUrl);
    public IActionResult BackLocal(string returnUrl) => Url.IsLocalUrl(returnUrl) ? Redirect(returnUrl) : Redirect("/");
    public IActionResult Page(string html) => Content("<p>" + html + "</p>", "text/html");
    public void Xml(string x) { var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() }; var off = new XmlDocument { XmlResolver = null }; }
    public Task<object> Eval(string code) => CSharpScript.EvaluateAsync(code);
    private readonly string _root = "/srv";
}
`,
    });
    const got = idx.sinks.filter((s) => !s.ruleId.includes('.business.')).map((s) => `${s.category} ${short(s.symbolId).split('.').pop()} ${s.taintHint ?? '-'}`).sort();
    expect(got).toEqual([
      'cmdi Run(1) constant',
      'cmdi Run(1) string_concat',
      'cmdi Run(1) string_concat',
      'code_injection Eval(1) -',
      'deserialization Load(2) -',
      'deserialization Load(2) -',
      'open_redirect Back(1) -',
      'path_traversal Doc(1) string_concat',
      'path_traversal Read(1) string_concat',
      'ssrf Fetch(1) -',
      'ssrf Fetch(1) constant',
      'xss Page(1) string_concat',
      'xxe Xml(1) -',
    ]);
  });

  it('business points: EF lookups by id and state / amount writes in saving methods', async () => {
    const idx = await indexOf({
      'Services/WalletService.cs': `namespace Shop.Services;
public class WalletService
{
    private readonly ShopDb _db;
    public async Task Pay(int orderId, decimal amount)
    {
        var order = await _db.Orders.FindAsync(orderId);
        var wallet = await _db.Wallets.FirstOrDefaultAsync(w => w.Id == order.WalletId);
        var named = await _db.Wallets.FirstOrDefaultAsync(w => w.Name == "main");
        wallet.Balance = wallet.Balance - amount;
        order.Status = OrderStatus.Paid;
        await _db.SaveChangesAsync();
    }
    public Order Draft() { var o = new Order { Status = OrderStatus.Draft }; o.Status = OrderStatus.Draft; return o; }
}
`,
    });
    const biz = idx.sinks.filter((s) => s.ruleId.includes('.business.')).map((s) => `${s.category} ${s.api} ${short(s.symbolId).split('.').pop()}`).sort();
    expect(biz).toEqual([
      'authz_object 按 ID 访问资源 FindAsync(…) Pay(2)',
      'authz_object 按 ID 访问资源 FirstOrDefaultAsync(…) Pay(2)',
      'business_logic 业务状态写入 Status = … Pay(2)',
      'business_logic 金额/数量写入 Balance = … Pay(2)',
    ]);
    expect(idx.sinks.every((s) => s.taintHint === undefined)).toBe(true);
  });
});

describe('auth configuration signals', () => {
  it('filters, authorization handlers, convention middlewares and MapControllers().RequireAuthorization()', async () => {
    const idx = await indexOf({
      'Auth/Filters.cs': `namespace Shop.Auth;
public class ApiKeyFilter : IAsyncAuthorizationFilter { public Task OnAuthorizationAsync(AuthorizationFilterContext c) => Task.CompletedTask; }
public class OwnerHandler : AuthorizationHandler<OwnerRequirement, Order> { }
public class TenantMiddleware { public Task InvokeAsync(HttpContext ctx) => Task.CompletedTask; }
public class NotAMiddleware { }
`,
      'Program.cs': `var app = WebApplication.CreateBuilder(args).Build();
app.MapControllers().RequireAuthorization();
app.Run();
`,
    });
    const sig = idx.authSignals.map((s) => `${s.kind} ${s.detail}`).sort();
    expect(sig).toEqual([
      'filter ApiKeyFilter : IAsyncAuthorizationFilter',
      'filter OwnerHandler : AuthorizationHandler',
      'middleware TenantMiddleware (middleware)',
      'security_config app.MapControllers().RequireAuthorization()',
    ]);
  });
});

describe('NuGet dependencies', () => {
  it('csproj (attribute and nested Version), central versions, packages.config and packages.lock.json', async () => {
    const v = await viewOf({
      'src/Api/Api.csproj': `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><JsonVersion>13.0.1</JsonVersion></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Dapper" Version="2.1.28" />
    <PackageReference Include="Newtonsoft.Json" Version="$(JsonVersion)" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
    <!-- <PackageReference Include="Commented.Out" Version="1.0.0" /> -->
  </ItemGroup>
</Project>
`,
      'central/Directory.Packages.props': `<Project>
  <ItemGroup>
    <PackageVersion Include="Microsoft.EntityFrameworkCore" Version="8.0.4" />
  </ItemGroup>
</Project>
`,
      'central/Data/Data.csproj': `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Microsoft.EntityFrameworkCore" /><PackageReference Include="Polly" /></ItemGroup></Project>`,
      'legacy/packages.config': `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="log4net" version="2.0.8" targetFramework="net48" />
</packages>
`,
      'locked/App.csproj': `<Project><ItemGroup><PackageReference Include="System.Text.Json" Version="8.*" /></ItemGroup></Project>`,
      'locked/packages.lock.json': JSON.stringify({ version: 1, dependencies: { 'net8.0': { 'System.Text.Json': { type: 'Direct', requested: '[8.0.0, )', resolved: '8.0.4' } }, 'net6.0': { 'System.Text.Json': { type: 'Direct', resolved: '8.0.4' } } } }, null, 2),
    });
    const deps = declaredDependencies(v).filter((d) => d.ecosystem === 'nuget');
    const of = (n: string) => deps.filter((d) => d.name === n).map((d) => [d.path, d.version]);
    expect(of('Dapper')).toEqual([['src/Api/Api.csproj', '2.1.28']]);
    expect(of('Newtonsoft.Json')).toEqual([['src/Api/Api.csproj', '13.0.1']]);
    expect(of('Serilog')).toEqual([['src/Api/Api.csproj', '3.1.1']]);
    expect(of('Commented.Out')).toEqual([]);
    expect(of('Microsoft.EntityFrameworkCore')).toEqual([['central/Directory.Packages.props', '8.0.4']]);
    expect(of('Polly')).toEqual([['central/Data/Data.csproj', null]]);
    expect(of('log4net')).toEqual([['legacy/packages.config', '2.0.8']]);
    expect(of('System.Text.Json')).toEqual([['locked/packages.lock.json', '8.0.4']]);
    expect(deps.find((d) => d.name === 'Serilog')!.line).toBe(6);
  });
});

describe('C# outbound HTTP clients', () => {
  it('HttpClient with BaseAddress / named clients, HttpRequestMessage, RestSharp and Refit', async () => {
    const files = {
      'Clients/BillingClient.cs': `namespace Shop.Clients;
public class BillingClient
{
    private const string InvoicePath = "/api/invoices";
    private readonly HttpClient _http = new HttpClient { BaseAddress = new Uri("http://billing-service/") };
    public Task<string> Invoice(int id) => _http.GetStringAsync($"{InvoicePath}/{id}");
    public Task Pay(object body) => _http.PostAsJsonAsync("api/payments", body);
    public Task Send(int id) => _http.SendAsync(new HttpRequestMessage(HttpMethod.Delete, "https://audit.example.com/v1/events/" + id));
}
`,
      'Startup/Clients.cs': `namespace Shop.Startup;
public class Registrar
{
    public void Register(IServiceCollection services) => services.AddHttpClient("users", c => c.BaseAddress = new Uri("http://user-service"));
    public async Task Load(IHttpClientFactory factory) { var client = factory.CreateClient("users"); await client.GetAsync("/api/users/me"); }
    public void Rest() { var rc = new RestClient("http://stock-service"); var req = new RestRequest("api/stock/{sku}", Method.Put); }
}
`,
      'Clients/IUserApi.cs': `using Refit;
namespace Shop.Clients;
public interface IUserApi { [Get("/users/{id}")] Task<User> GetUser(int id); [Post("/users")] Task Create(User u); }
`,
    };
    const cs: Connection[] = await extractConnections(await viewOf(files), null, null);
    const fmt = cs.map((c) => `${c.side} ${c.kind} ${JSON.stringify(c.key)}${c.serviceHint ? ` @${c.serviceHint}` : ''} ${c.extraction}`).sort();
    expect(fmt).toEqual([
      'consumes http {"method":"DELETE","pathTemplate":"/v1/events/{?}"} @audit.example.com partial',
      'consumes http {"method":"GET","pathTemplate":"/api/invoices/{?}"} @billing-service partial',
      'consumes http {"method":"GET","pathTemplate":"/api/users/me"} @user-service literal',
      'consumes http {"method":"GET","pathTemplate":"/users/{id}"} literal',
      'consumes http {"method":"POST","pathTemplate":"/api/payments"} @billing-service literal',
      'consumes http {"method":"POST","pathTemplate":"/users"} literal',
      'consumes http {"method":"PUT","pathTemplate":"/api/stock/{sku}"} @stock-service literal',
    ]);
  });
});

describe('inherited controller attributes and conventional routes', () => {
  it('[Route] and [Authorize] on a base controller in another file apply to derived controllers', async () => {
    const idx = await indexOf({
      'Api/BaseApiController.cs': `using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace Shop.Api;
[ApiController]
[Route("api/[controller]")]
[Authorize(Policy = "Staff")]
public abstract class BaseApiController : ControllerBase { }
`,
      'Api/OrdersController.cs': `using Microsoft.AspNetCore.Mvc;
namespace Shop.Api;
public class OrdersController : BaseApiController
{
    [HttpGet("{id:int}")]
    public IActionResult Get(int id) => Ok(id);
    [HttpPost]
    public IActionResult Create() => Ok();
}
`,
      'Api/PublicController.cs': `using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace Shop.Api;
[AllowAnonymous]
public class PublicController : BaseApiController
{
    [HttpGet("ping")]
    public string Ping() => "ok";
}
`,
    });
    expect(keys(idx)).toEqual(['GET /api/orders/{}', 'GET /api/public/ping', 'POST /api/orders']);
    expect(entry(idx, 'GET /api/orders/{}').authSignals).toEqual(['[Authorize(Policy = "Staff")]（继承自 BaseApiController）']);
    expect(entry(idx, 'GET /api/public/ping').authSignals).toEqual(expect.arrayContaining(['[AllowAnonymous]', '[Authorize(Policy = "Staff")]（继承自 BaseApiController）']));
    expect(short(entry(idx, 'POST /api/orders').handler)).toBe('Shop.Api.OrdersController.Create(0)');
  });

  it('conventional routes from Program.cs: slugify, verb attributes, RequireAuthorization, areas and fixed-default routes', async () => {
    const idx = await indexOf({
      'Program.cs': `var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.MapControllerRoute("areas", "{area:exists}/{controller=Home}/{action=Index}/{id?}");
app.MapControllerRoute("default", "{controller:slugify=Home}/{action:slugify=Index}/{id?}").RequireAuthorization();
app.MapControllerRoute(name: "blog", pattern: "blog/{*slug}", defaults: new { controller = "Blog", action = "Article" });
app.Run();
`,
      'Controllers/ManageController.cs': `using Microsoft.AspNetCore.Mvc;
namespace Web.Controllers;
public class ManageController : Controller
{
    public IActionResult Index() => View();
    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> ChangePassword(string id) => View();
    [NonAction]
    public void Helper() { }
    private void Hidden() { }
    public static void Util() { }
}
`,
      'Controllers/BlogController.cs': `using Microsoft.AspNetCore.Mvc;
namespace Web.Controllers;
public class BlogController : Controller
{
    public IActionResult Article(string slug) => View();
}
`,
      'Areas/Admin/UsersController.cs': `using Microsoft.AspNetCore.Mvc;
namespace Web.Areas.Admin;
[Area("Admin")]
public class UsersController : Controller
{
    public IActionResult Delete(int id) => View();
}
`,
      'Controllers/ApiStyleController.cs': `using Microsoft.AspNetCore.Mvc;
namespace Web.Controllers;
[ApiController]
public class ApiStyleController : ControllerBase
{
    [HttpGet]
    public string Get() => "x";
}
`,
    });
    expect(keys(idx)).toEqual([
      'ANY /admin/users/delete/{}',
      'ANY /blog/article/{}',
      'ANY /blog/{}',
      'ANY /manage/index/{}',
      'POST /manage/change-password/{}',
    ]);
    const cp = entry(idx, 'POST /manage/change-password/{}');
    expect(cp.ruleId).toBe('csharp.aspnetcore.conventional-route');
    expect(cp.middlewares).toEqual(['RequireAuthorization()']);
    expect(cp.authSignals).toEqual(expect.arrayContaining(['RequireAuthorization()', '[ValidateAntiForgeryToken]']));
    expect(short(cp.handler)).toBe('Web.Controllers.ManageController.ChangePassword(1)');
    // The area route carries no RequireAuthorization (only the default route does).
    expect(entry(idx, 'ANY /admin/users/delete/{}').authSignals).toEqual([]);
  });

  it('without a conventional route, a bare [HttpPost] on an MVC action is not an entry at "/"', async () => {
    const idx = await indexOf({
      'Controllers/HomeController.cs': `using Microsoft.AspNetCore.Mvc;
namespace Web.Controllers;
public class HomeController : Controller
{
    [HttpPost]
    public IActionResult Save() => View();
}
`,
    });
    expect(keys(idx)).toEqual([]);
  });
});

describe('Razor Pages', () => {
  it('page handlers become entries: page path, @page templates, named handlers, conventions and attributes', async () => {
    const pm = (ns: string, cls: string, body: string, attrs = '') => `using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;
namespace ${ns};
${attrs}public class ${cls} : PageModel
{
${body}
}
`;
    const idx = await indexOf({
      'src/Web/Program.cs': `var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages(options =>
{
    options.Conventions.AuthorizePage("/Basket/Checkout");
    options.Conventions.AuthorizeFolder("/Admin", "AdminOnly");
    options.Conventions.AllowAnonymousToPage("/Admin/Login");
    options.Conventions.AuthorizeAreaFolder("Identity", "/Account/Manage");
});
var app = builder.Build();
app.MapRazorPages();
app.Run();
`,
      'src/Web/Pages/Index.cshtml': '﻿@page\n@model IndexModel\n<h1>Home</h1>\n',
      'src/Web/Pages/Index.cshtml.cs': pm('Web.Pages', 'IndexModel', '    public void OnGet() { }'),
      'src/Web/Pages/Basket/Index.cshtml': '@page "{handler?}"\n@model IndexModel\n',
      'src/Web/Pages/Basket/Index.cshtml.cs': pm('Web.Pages.Basket', 'IndexModel', '    public async Task OnGet() { }\n    public async Task<IActionResult> OnPost(int id) => Page();\n    public async Task OnPostUpdate(int[] items) { }'),
      'src/Web/Pages/Basket/Checkout.cshtml': '@page\n@model CheckoutModel\n',
      'src/Web/Pages/Basket/Checkout.cshtml.cs': pm('Web.Pages.Basket', 'CheckoutModel', '    public async Task<IActionResult> OnPostAsync(string address) => Page();'),
      'src/Web/Pages/Admin/EditCatalogItem.cshtml': '@page "{id:int}"\n@model EditCatalogItemModel\n',
      'src/Web/Pages/Admin/EditCatalogItem.cshtml.cs': pm('Web.Pages.Admin', 'EditCatalogItemModel', '    public void OnGet(int id) { }\n    public IActionResult OnPostDelete(int id) => Page();'),
      'src/Web/Pages/Admin/Login.cshtml': '@page\n@model LoginModel\n',
      'src/Web/Pages/Admin/Login.cshtml.cs': pm('Web.Pages.Admin', 'LoginModel', '    public void OnPost() { }'),
      'src/Web/Pages/Reports/Export.cshtml': '@page "/exports/{name}"\n@model ExportModel\n',
      'src/Web/Pages/Reports/Export.cshtml.cs': pm('Web.Pages.Reports', 'ExportModel', '    public IActionResult OnGet(string name) => Page();', '[Authorize(Roles = "Finance")]\n'),
      'src/Web/Pages/Shared/_Layout.cshtml': '<html>@RenderBody()</html>\n',
      'src/Web/Areas/Identity/Pages/Account/Manage/Email.cshtml': '@page\n@model EmailModel\n',
      'src/Web/Areas/Identity/Pages/Account/Manage/Email.cshtml.cs': pm('Web.Areas.Identity.Pages.Account.Manage', 'EmailModel', '    public Task OnPostChangeEmailAsync(string email) => Task.CompletedTask;\n    public static void Helper() { }\n    public void Load() { }'),
    });
    expect(keys(idx)).toEqual([
      'DELETE /admin/editcatalogitem/{}'.replace('DELETE', 'POST') + '?handler=delete',
      'GET /',
      'GET /admin/editcatalogitem/{}',
      'GET /basket',
      'GET /exports/{}',
      'POST /admin/login',
      'POST /basket',
      'POST /basket/checkout',
      'POST /basket/update',
      'POST /identity/account/manage/email?handler=changeemail',
    ].sort());
    expect(entry(idx, 'POST /basket/checkout').authSignals).toEqual(['AuthorizePage("/Basket/Checkout")']);
    expect(entry(idx, 'POST /basket').authSignals).toEqual([]);
    expect(entry(idx, 'GET /admin/editcatalogitem/{}').authSignals).toEqual(['AuthorizeFolder("/Admin", "AdminOnly")']);
    expect(entry(idx, 'POST /admin/login').authSignals).toEqual(expect.arrayContaining(['AuthorizeFolder("/Admin", "AdminOnly")', 'AllowAnonymousToPage("/Admin/Login")']));
    expect(entry(idx, 'GET /exports/{}').authSignals).toEqual(['[Authorize(Roles = "Finance")]']);
    expect(entry(idx, 'POST /identity/account/manage/email?handler=changeemail').authSignals).toEqual(['AuthorizeAreaFolder("Identity", "/Account/Manage")']);
    expect(short(entry(idx, 'POST /basket/update').handler)).toBe('Web.Pages.Basket.IndexModel.OnPostUpdate(1)');
    expect(entry(idx, 'POST /basket').ruleId).toBe('csharp.aspnetcore.razor-page');
  });
});

describe('SignalR hubs', () => {
  it('hub methods become rpc entries under the MapHub path, with hub auth and conventions; lifecycle methods are not entries', async () => {
    const idx = await indexOf({
      'Program.cs': `var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSignalR(o => o.AddFilter<TenantAuthHubFilter>());
var app = builder.Build();
app.MapHub<ChatHub>("/hubs/chat").RequireAuthorization("Members");
app.MapHub<NotificationHub>("notify");
app.Run();
`,
      'Hubs/BaseHub.cs': `using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Authorization;
namespace Chat.Hubs;
[Authorize]
public abstract class BaseHub : Hub<IChatClient> { }
`,
      'Hubs/ChatHub.cs': `using Microsoft.AspNetCore.SignalR;
namespace Chat.Hubs;
public class ChatHub : BaseHub
{
    private readonly IRoomStore _rooms;
    public ChatHub(IRoomStore rooms) { _rooms = rooms; }
    public async Task SendMessage(string roomId, string text) => await Clients.Group(roomId).Receive(text);
    [HubMethodName("join")]
    public Task JoinRoom(string roomId) => Groups.AddToGroupAsync(Context.ConnectionId, roomId);
    public override Task OnConnectedAsync() => base.OnConnectedAsync();
    private void Audit() { }
}
`,
      'Hubs/NotificationHub.cs': `using Microsoft.AspNetCore.SignalR;
namespace Chat.Hubs;
public class NotificationHub : Hub
{
    public Task Ack(int id) => Task.CompletedTask;
}
`,
      'Hubs/OrphanHub.cs': `using Microsoft.AspNetCore.SignalR;
namespace Chat.Hubs;
public class OrphanHub : Hub { public void Ping() { } }
`,
    });
    const hubs = idx.entrypoints.filter((e) => e.framework === 'signalr');
    expect(hubs.map((e) => e.entryKey).sort()).toEqual([
      'rpc:signalr:/hubs/chat/SendMessage', 'rpc:signalr:/hubs/chat/join', 'rpc:signalr:/notify/Ack', 'rpc:signalr:OrphanHub/Ping',
    ]);
    const send = entry(idx, 'rpc:signalr:/hubs/chat/SendMessage');
    expect(send.kind).toBe('rpc');
    expect(send.authSignals).toEqual(expect.arrayContaining(['[Authorize]（继承自 BaseHub）', 'RequireAuthorization("Members")', 'TenantAuthHubFilter']));
    expect(short(send.handler)).toBe('Chat.Hubs.ChatHub.SendMessage(2)');
    expect(entry(idx, 'rpc:signalr:/notify/Ack').authSignals).toEqual(['TenantAuthHubFilter']);
    // Not gRPC: hub entries never become gRPC provider connections.
    expect(send.entryKey).not.toMatch(/^rpc:[\w.]+\/\w+$/);
  });
});
