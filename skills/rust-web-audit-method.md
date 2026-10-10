---
name: rust-web-audit-method
description: Rust Web 框架 axum、actix-web、Rocket 的入口（Router 链、路由宏、scope / mount）、鉴权机制（layer / route_layer 顺序、wrap 中间件、提取器与请求守卫）、危险 API 与常见误报。审计 Rust 服务端项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [rust]
  frameworks: [axum, actix-web, rocket]
checklist:
  - id: axum-layer-order
    vuln_class: authz_function
    title: axum 中间件的作用范围
    check: .layer / .route_layer 只作用于链上在它之前加入的路由；在 layer 之后 .route / .nest / .merge 的路由不受保护。nest 的子路由器自带的 layer 不影响父路由器。确认每个需要登录的路由在鉴权 layer 之前加入，或处理函数参数中有鉴权提取器（Claims、AuthUser 等）。
    applies_to:
      frameworks: [axum]
  - id: actix-scope-wrap
    vuln_class: authz_function
    title: actix-web wrap 与 scope
    check: .wrap 作用于所在 App / scope 的全部服务，不作用于同级的其他 scope；用 #[get] 宏定义、通过 .service 注册到 App 而不在受保护 scope 内的处理函数是公开的；HttpAuthentication 的 validator 是否真正拒绝无效凭据（而不是放行）。
    applies_to:
      frameworks: [actix-web]
  - id: rocket-request-guard
    vuln_class: authz_function
    title: Rocket 请求守卫
    check: 需要登录的路由是否带鉴权守卫参数（FromRequest 实现返回 Outcome::Error((Status::Unauthorized, …))）；Option<Guard> 允许匿名访问；守卫失败时的 Outcome::Forward 会落到下一个同路径路由（rank），确认后备路由没有放宽权限。
    applies_to:
      frameworks: [rocket]
  - id: rust-object-ownership
    vuln_class: authz_object
    title: 资源归属
    check: 处理函数从 Path / Query 取 id 后查询（sqlx 绑定、diesel find、sea-orm find_by_id）时，是否结合守卫中的用户 id 过滤或比较；只有鉴权提取器、没有归属比较的写操作是 IDOR 的常见位置。
    applies_to:
      frameworks: [axum, actix-web, rocket]
  - id: rust-sql-builder
    vuln_class: sqli
    title: 运行时拼接的 SQL
    check: sqlx::query(&format!(…))、query_as 的 SQL 文本由 format! / push_str 构造，diesel::sql_query、sea-orm Statement::from_string、tokio-postgres / rusqlite 的 execute / query 拼接请求值；sqlx 的 query! 宏与 .bind() 参数安全；QueryBuilder 的 push 与 push_bind 区分。ORDER BY 列名需要白名单。
    applies_to:
      frameworks: [axum, actix-web, rocket]
  - id: rust-command-path-ssrf
    vuln_class: ssrf
    title: 命令、文件路径与出站请求
    check: Command::new 的程序或 sh -c 的脚本来自请求；std::fs / tokio::fs / NamedFile::open 的路径由请求值拼接（Path::join 遇到绝对路径会替换基路径）；reqwest / hyper 客户端的 URL 来自请求且未限制主机与协议；Redirect::to 的目标来自请求。
    applies_to:
      frameworks: [axum, actix-web, rocket]
---
# axum / actix-web / Rocket 审计要点

## 入口在哪里
- **axum**：
  - `Router::new().route("/p", get(h).post(h2))`，`nest("/api", api::routes())` 与 `merge` 组合，处理函数可以是闭包。
  - 路由器常在其他文件的函数中构造后返回。
- **actix-web**：
  - `#[get("/p")]` 等宏，经 `App::new().service(h)` 或 `web::scope("/api").service(h)` 注册。
  - 也可以用 `.configure(fn)` 在其他文件中注册。
  - 构建器写法 `.route("/p", web::get().to(h))`、`web::resource("/p").route(…)`。
- **Rocket**：`#[get("/p/<id>")]` 宏（查询部分不是路径），`rocket::build().mount("/api", routes![…])`，路由列表常由各模块的 `routes()` 函数返回。
- 非 HTTP 入口：tonic 服务实现、lapin / rdkafka 消费者、tokio-cron-scheduler 任务、clap 子命令。

## 鉴权机制
- axum：`middleware::from_fn(auth)` / `RequireAuthorizationLayer` / tower-http `ValidateRequestHeaderLayer`，作为 `layer` / `route_layer`，注意加入顺序；提取器类型（`Claims`、`AuthUser`、`Extension<CurrentUser>`）实现 `FromRequestParts`，失败时拒绝请求。
- actix-web：`.wrap(HttpAuthentication::bearer(validator))`、自定义中间件、宏参数 `wrap = "…"`、`web::ReqData<Claims>` 与 `FromRequest` 提取器。
- Rocket：请求守卫（处理函数参数类型实现 `FromRequest`），可以委托给其他守卫组合（管理员守卫先取用户守卫）。
- tonic：`XxxServer::with_interceptor(svc, check)`、`Server::builder().layer(…)`。

## 危险 API
- SQL：运行时构造 SQL 文本的 `sqlx::query*`、驱动的 `execute` / `query` / `prepare`、`diesel::sql_query`。
- 命令与文件：`Command::new`、`std::fs` / `tokio::fs` / `NamedFile`。
- 出站与跳转：`reqwest` / `ureq` / 客户端 `.get(url)`、`Redirect::to`。
- 输出：`PreEscaped` / `Html(format!(…))`、`Tera::one_off`。
- 其他：嵌入脚本引擎（rhai / mlua）；`unsafe` 块（内存安全复核）。

## 常见误报
- `query!` / `query_as!` 宏（编译期校验）与 `.bind()` 参数。
- 常量 SQL 文本。
- 测试模块（`#[cfg(test)]`）与 CLI crate 中的文件操作。
- 只在启动时读取配置的 `fs` 调用。
- `Option<AuthUser>` 守卫的公开接口本就允许匿名访问，应看业务是否预期如此。
