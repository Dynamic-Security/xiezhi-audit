---
name: go-frameworks-audit-method
description: Go 框架 beego、go-zero、kratos 与 grpc-gateway 的入口（路由注册、生成的 routes.go、proto HTTP 绑定）、鉴权机制（InsertFilter、rest.WithJwt、中间件）、危险 API 与常见误报。审计这些框架的项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [go]
  frameworks: [beego, go-zero, kratos, grpc-gateway]
checklist:
  - id: beego-filter-coverage
    vuln_class: authz_function
    title: beego InsertFilter 覆盖
    check: InsertFilter 的 pattern 是否覆盖全部需要登录的路由（/admin/* 不覆盖 /admin 本身）；BeforeRouter 与 BeforeExec 的位置不同，部分过滤器在路由匹配失败时不执行；控制器的 Prepare() 中的登录检查是否真正中止请求（StopRun / Abort）。
    applies_to:
      frameworks: [beego]
  - id: beego-orm-raw
    vuln_class: sqli
    title: beego ORM 原始 SQL
    check: o.Raw(sql) 与 QueryTable 的 Filter 条件中的字段名、ORDER BY 是否拼接请求参数；Raw 带 ? 占位时安全。
    applies_to:
      frameworks: [beego]
  - id: gozero-jwt-scope
    vuln_class: authz_function
    title: go-zero JWT 与中间件声明
    check: '.api 文件中 @server(jwt: Auth) 与 middleware 声明只作用于该 server 块中的路由；同一服务中未加 jwt 的路由是公开的，确认它们不应受保护；jwt 只证明身份，logic 层仍需按 ctx 中的用户 id 校验资源归属。'
    applies_to:
      frameworks: [go-zero]
  - id: gozero-logic-ownership
    vuln_class: authz_object
    title: go-zero logic 层的资源归属
    check: logic 层从请求结构体取资源 id 查询 model 时，是否结合 ctxdata.GetUidFromCtx 等当前用户信息过滤；RPC 层直接接受 user_id 参数而不校验调用方身份时，任何能访问 RPC 的服务都可越权。
    applies_to:
      frameworks: [go-zero]
  - id: grpc-http-auth-parity
    vuln_class: authz_function
    title: gRPC 与 HTTP 转码的鉴权一致
    check: kratos / grpc-gateway 把同一 rpc 同时暴露为 gRPC 与 HTTP；gRPC 拦截器（grpc.UnaryInterceptor）不作用于 HTTP 转码路径，kratos 的 http.Middleware 与 grpc.Middleware 需要分别配置。检查 HTTP 绑定的接口是否经过与 gRPC 相同的鉴权，selector.Server 的白名单是否漏掉了新增 rpc。
    applies_to:
      frameworks: [kratos, grpc-gateway]
---
# beego / go-zero / kratos / grpc-gateway 审计要点

## 入口在哪里
- **beego**：`beego.Router(path, &C{}, "get:Fn;post:Fn2")`（不写映射时按 HTTP 方法调用控制器的 Get / Post 等方法）、`Include(&C{})` 加 `// @router` 注释路由、`AutoRouter`、`NSNamespace` 嵌套、函数路由 `beego.Get(path, fn)`。
- **go-zero**：`.api` 文件生成 `internal/handler/routes.go` 中的 `server.AddRoutes([]rest.Route{...}, rest.WithJwt(...), rest.WithPrefix(...))`；handler 解析请求后调用 `internal/logic` 中的业务逻辑。
- **kratos**：proto 中 `option (google.api.http)` 生成 `*_http.pb.go`，HTTP 路由调用 service 层实现（同时实现 gRPC 接口）。
- **grpc-gateway**：同样由 `google.api.http` 生成反向代理，把 HTTP 请求转为 gRPC 调用。

## 鉴权机制
- beego：`InsertFilter(pattern, pos, filterFunc)`、控制器 `Prepare()`。
- go-zero：`rest.WithJwt`、`rest.WithMiddlewares`、`.api` 中的 `@server(jwt:, middleware:)`。
- kratos：`http.Middleware(jwt.Server(...), selector.Server(...).Match(...))` 与 `grpc.Middleware`。
- grpc-gateway：gRPC 拦截器与 gateway 的 `runtime.WithIncomingHeaderMatcher` / 自定义 HTTP 中间件。

## 危险 API
- beego ORM `Raw`、go-zero `sqlx` / `sqlc` 拼接 SQL、gorm 的字符串条件；`http.Get(用户URL)`；`exec.Command`；`os.Open(拼接路径)`。

## 常见误报
- go-zero 生成的 handler 只做参数绑定，漏洞通常在 logic 层。
- `?` 占位的 Raw / Exec 调用。
