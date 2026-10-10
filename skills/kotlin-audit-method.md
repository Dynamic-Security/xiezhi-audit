---
name: kotlin-audit-method
description: Kotlin 后端（Spring Boot Kotlin、Ktor）的审计方法：入口位置、鉴权机制、各类危险 API 与常见误报。审计 Kotlin 项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [kotlin]
  frameworks: [spring, ktor]
---
# Kotlin 后端审计要点

## 入口
- **Spring MVC（Kotlin）**：与 Java 相同的注解。`@RestController` / `@Controller` 类上的 `@RequestMapping` 是前缀；方法上的 `@GetMapping("/x")`、`@PostMapping(value = ["/a", "/b"])`、`@RequestMapping(method = [RequestMethod.GET], path = arrayOf("/c"))`。数组写成 `[...]` 或 `arrayOf(...)`。`@FeignClient` 接口上的映射是出站调用，不是入口。
- **Ktor**：`routing { get("/x") { … } }`、嵌套 `route("/api") { … }` 拼接前缀；`fun Route.orderRoutes()` 扩展函数在别处的 `route(...) { orderRoutes() }` 中注册，前缀要沿调用处确认（跨文件时索引看不到，需要 grep 调用处）。处理函数是 lambda，入口的 handler 是外层函数。
- 请求数据来源：Spring 的 `@PathVariable`、`@RequestParam`、`@RequestBody`（data class 字段）；Ktor 的 `call.parameters[...]`、`call.request.queryParameters[...]`、`call.receive<T>()`、`call.receiveText()`。

## 鉴权
- **Spring Security**：Kotlin DSL `http { authorizeHttpRequests { authorize("/admin/**", hasRole("ADMIN")) } }` 与流式 `http.authorizeHttpRequests { it.requestMatchers(...) }`。规则按顺序先匹配先生效，注意 `permitAll` 过宽与兜底的 `anyRequest`。
- **方法注解**：`@PreAuthorize` / `@PostAuthorize` / `@Secured` / `@RolesAllowed` 需要 `@EnableMethodSecurity`；Kotlin 类默认 `final`，若未使用 `kotlin("plugin.spring")`（all-open），代理无法生成，注解可能不生效；同类内部调用同样不经代理。
- **Filter / Interceptor**：`OncePerRequestFilter`、`HandlerInterceptor` 子类，检查 `shouldNotFilter`、路径匹配与失败时是否真正中断。
- **Ktor**：`install(Authentication) { jwt("name") { validate { … } } }` 定义认证方式；只有包在 `authenticate("name") { … }` 块中的路由受保护，块外注册的同级路由不受保护。`validate` 返回 `null` 才拒绝，检查是否只验签不校验声明。
- 归属（IDOR）：`repository.findByIdOrNull(id)`、`findById(id)`、`getReferenceById(id)` 之后是否比对当前用户；`@PostAuthorize("returnObject.ownerId == authentication.principal.id")` 也是有效的归属校验。

## 危险 API
- **SQL**：字符串模板 `"… $x …"` / `"${x}"` 与 `+` 拼接进入 `jdbcTemplate.query/queryForObject/update/execute`、`createStatement().executeQuery`、`entityManager.createNativeQuery/createQuery`、Exposed `exec("…")`。`ORDER BY`、列名、表名无法绑定参数，是模板拼接的高发处。
- **命令**：`Runtime.getRuntime().exec(...)`、`ProcessBuilder(...)`、`ProcessBuilder(listOf(...)).start()`；`sh -c` 加拼接字符串最危险。
- **反序列化**：`ObjectInputStream(...).readObject()`、`XStream.fromXML`、Jackson `activateDefaultTyping` / `enableDefaultTyping`、SnakeYAML `Yaml().load`。
- **SSRF**：`restTemplate.getForObject/getForEntity/exchange(url)`、`webClient.get().uri(url)`、`URL(url).openStream()/readText()`、Ktor `HttpClient.get(url)`。
- **路径**：`File(base, name)`、`Paths.get` / `Path.of`、`Files.readAllBytes`、`FileInputStream`；Ktor `call.respondFile(File(...))`。
- **表达式 / 代码**：`SpelExpressionParser().parseExpression(x)`、`ScriptEngine.eval(x)`。
- **XXE**：`DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory` 未设置 `disallow-doctype-decl` 或禁用外部实体。
- **重定向 / XSS**：`"redirect:" + url`、`"redirect:$url"`、`response.sendRedirect(url)`、Ktor `call.respondRedirect(url)`；Ktor `call.respondText(x, ContentType.Text.Html)` 输出未转义内容。
- **业务**：`loan.status = …`、`copy(status = …)`、`amount` / `balance` 字段写入是业务逻辑审查点，需确认状态机前置条件与操作者权限。

## 常见误报
- 模板里插入的是枚举、常量、白名单映射结果（`SORT_COLUMNS[sort] ?: error(...)`、`enum.column`），或只插入 `?` 占位符数量。
- `jdbcTemplate.query("… where id = ?", mapper, id)`：SQL 为字面量，参数绑定。
- `ProcessBuilder(listOf("gzip", fixedPath))`：参数列表固定、不经 shell、路径由服务端生成。
- Kotlin DSL 中的同名函数（`get("/x") { }` 是路由，`client.get(url)` 是出站请求，`map.get(k)` 两者都不是）。
- 结论写法：说明入口、数据如何到达危险点（经过哪些 Kotlin 函数 / 扩展函数），以及查找了哪些位置的鉴权与校验。
