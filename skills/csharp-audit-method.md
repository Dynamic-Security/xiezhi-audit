---
name: csharp-audit-method
description: C# / ASP.NET Core 审计方法：控制器与 minimal API 入口、[Authorize] 与授权策略、EF Core / Dapper / ADO.NET 的 SQL、文件与反序列化等危险 API、常见误报。审计 .NET 项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [csharp]
  frameworks: [aspnetcore]
---
# C# / ASP.NET Core 审计要点

## 入口
- **控制器**：`[ApiController]` 或继承 `ControllerBase` / `Controller` 的类；类上 `[Route("api/[controller]")]` 是前缀（`[controller]` = 类名去掉 `Controller`，路由不区分大小写），动作上 `[HttpGet("{id:int}")]`、`[HttpPost]`、`[Route]`、`[AcceptVerbs]`；以 `/` 或 `~/` 开头的模板不拼类前缀。`[NonAction]` 与非 public 方法不是入口。
- **minimal API**：`app.MapGet/MapPost/MapPut/MapDelete/MapPatch/MapMethods("/x", handler)`；`MapGroup("/api")` 的前缀与 `.RequireAuthorization()` 会被组内路由继承。处理器可以是 lambda 或方法组（`Handlers.GetOrder`）；参数来自路由、查询串、请求体或 DI（`[FromServices]`、DbContext 类型参数）。
- 约定路由（`MapControllerRoute("{controller}/{action}/{id?}")`）下没有特性的 public 动作也是入口，结构索引不列出这类入口，需要人工补查。

## 鉴权
- `[Authorize]`、`[Authorize(Roles = …)]`、`[Authorize(Policy = …)]` 写在类或动作上；`[AllowAnonymous]` 会覆盖类和全局要求，先看入口上是否有它。
- 全局要求：`MapControllers().RequireAuthorization()`、`AuthorizationOptions.FallbackPolicy`、`AddControllers(o => o.Filters.Add(new AuthorizeFilter()))`。只调用 `UseAuthentication()` / `UseAuthorization()` **不会**保护任何端点，还需要端点元数据或兜底策略。
- `UseAuthorization()` 必须位于 `UseRouting()` 之后、端点之前；自定义中间件（`UseMiddleware<ApiKeyMiddleware>()`）要看它放行的路径与失败时是否短路（未写响应就调用 `next`）。
- 对象级授权：`[Authorize]` 只说明“已登录”。按 id 读取的 `FindAsync(id)`、`FirstOrDefaultAsync(x => x.Id == id)` 需要比对当前用户（`User.FindFirstValue(...)`），或调用 `IAuthorizationService.AuthorizeAsync(User, resource, policy)` 并检查 `Succeeded`；`AuthorizationHandler<TRequirement, TResource>` 只在被调用时才生效。
- 状态 / 金额写入（`order.Status = …`、`wallet.Balance -= …` 后 `SaveChanges`）要看调用者能否越权或跳过前置状态。

## 危险 API
- **SQL**：`FromSqlRaw` / `ExecuteSqlRaw` / `SqlQueryRaw` 传入插值字符串或拼接字符串；Dapper `Query/Execute*(sql)` 的 sql 由 `+`、`$"…"`、`string.Format`、`StringBuilder` 构造；`new SqlCommand(sql)`、`cmd.CommandText = …`。`FromSqlInterpolated`、EF Core 7+ 的 `FromSql($"…")`、Dapper 的匿名对象参数与 `@p` 占位符是参数化的。`ORDER BY` 列名无法参数化，要看是否经过白名单映射。
- **命令**：`Process.Start(file, args)`、`new ProcessStartInfo { FileName, Arguments }`；`UseShellExecute = true` 或 `cmd.exe /c`、`/bin/sh -c` 拼接时风险最高。
- **反序列化**：`BinaryFormatter`、`SoapFormatter`、`NetDataContractSerializer`、`LosFormatter`、`ObjectStateFormatter` 的 `Deserialize`；Json.NET `TypeNameHandling` 不为 `None`（含 `Auto`）且类型来自请求；`new XmlSerializer(Type.GetType(input))`；`JavaScriptSerializer(new SimpleTypeResolver())`。
- **SSRF**：`HttpClient.GetAsync/PostAsync/SendAsync(url)`、`WebRequest.Create(url)`、`WebClient.DownloadString(url)`、`new RestClient(url)`；`BaseAddress` 固定而只拼路径时通常不构成 SSRF，但要注意以 `http://` 开头的相对值会覆盖基址。
- **路径**：`File.ReadAllText/OpenRead/WriteAllBytes/Delete`、`new FileStream(path)`、`PhysicalFile(path)`、`Results.File(path)`；`Path.Combine(root, input)` 在 input 为绝对路径时直接返回 input。安全写法：`Path.GetFileName` 去目录，或 `Path.GetFullPath` 后校验仍在根目录下（比较时加目录分隔符）。
- **重定向 / XSS / XXE / 代码执行**：`Redirect(url)` 未经 `Url.IsLocalUrl` 或 `LocalRedirect`；控制器里的 `Html.Raw`、`new HtmlString(x)`、`Content(html, "text/html")`；`XmlDocument.XmlResolver` 非 null、`DtdProcessing.Parse`（.NET Framework 4.5.2 之前 `XmlDocument` 默认解析外部实体）；`CSharpScript.EvaluateAsync(code)`、`DynamicExpressionParser.ParseLambda`、RazorEngine `RunCompile(template)`。

## 常见误报
- Razor 视图中的 `@value` 默认 HTML 编码；只有 `@Html.Raw` 与 `MarkupString` 需要看。
- 模型绑定到 `int` / `Guid` / 枚举的参数不能携带 SQL 或路径片段；拼接这类值不构成注入。
- `[ApiController]` 自动校验 `[Required]`、`[RegularExpression]` 等特性，失败时返回 400，处理器不会执行。
- 常量 SQL、`const string` 或只由字面量拼成的 SQL 不是注入点；`LocalRedirect` 与 `Url.IsLocalUrl` 通过后的 `Redirect` 不是开放重定向。
