---
name: node-frameworks-audit-method
description: Node.js 服务端框架 Egg、Midway、hapi、Restify 的入口位置、鉴权机制（中间件配置、守卫、auth 策略）、危险 API 与常见误报。审计这些框架的项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [javascript, typescript]
  frameworks: [egg, midway, hapi, restify]
checklist:
  - id: egg-middleware-scope
    vuln_class: authz_function
    title: Egg 中间件的作用范围
    check: config.middleware 中的全局鉴权中间件是否通过 match / ignore 漏掉了需要登录的路由；router.js 中按路由挂载的 middleware.auth() 是否覆盖全部敏感接口（特别是 router.resources 展开的 create / update / destroy）。
    applies_to:
      frameworks: [egg]
  - id: egg-csrf-ssrf
    vuln_class: csrf
    title: Egg 安全插件配置
    check: config.security.csrf 是否被关闭（enable false）或 ignore 了带 Cookie 会话的接口；ctx.curl / app.httpclient 的 URL 是否来自请求，且 config.security.ssrf.ipBlackList 未配置；ctx.redirect 在未配置 domainWhiteList 时不校验目标域名。
    applies_to:
      frameworks: [egg]
  - id: midway-guard-scope
    vuln_class: authz_function
    title: Midway 守卫与中间件覆盖
    check: '@Controller 的 middleware 选项、全局中间件（app.useMiddleware）与 @UseGuard 是否覆盖全部敏感方法；守卫的 canActivate 是否只检查登录而不检查角色；@Get 等装饰器上单独声明的 middleware 是否遗漏。'
    applies_to:
      frameworks: [midway]
  - id: hapi-auth-false
    vuln_class: authz_function
    title: hapi 路由的 auth 配置
    check: 设置了 server.auth.default 时，options.auth = false 或 mode 'try' / 'optional' 的路由允许匿名访问，确认这些路由确实应当公开；没有默认策略时，每条路由都需要显式 auth。scope 配置是否与操作敏感度匹配。
    applies_to:
      frameworks: [hapi]
  - id: hapi-restify-object-authz
    vuln_class: authz_object
    title: 路径参数的资源归属
    check: hapi 的 request.params / Restify 的 req.params 中的资源 id 在查询时是否带上当前用户条件（request.auth.credentials / req.user）；只靠认证插件不防止横向越权。
    applies_to:
      frameworks: [hapi, restify]
---
# Egg / Midway / hapi / Restify 审计要点

## 入口在哪里
- **Egg**：`app/router.js`（或 `app/router/*.js`）中的 `router.get / post / …(name?, path, ...middleware, controller.x.y)`、`router.resources(name, prefix, controller.x)`（index / new / show / edit / create / update / destroy）、`router.namespace(prefix)`；控制器在 `app/controller/**`，文件名 `user_info.js` 对应 `controller.userInfo`。
- **Midway**：`@Controller(prefix, { middleware })` 类中的 `@Get / @Post / @Put / @Del / @Patch / @All(path, { middleware })` 方法。
- **hapi**：`server.route({ method, path, options: { auth, pre, handler } })`，也常写成导出的路由数组；插件注册时 `routes.prefix` 加前缀。
- **Restify**：`server.get / post / put / del / patch(path | { path }, ...handlers)`。

## 鉴权机制
- Egg：`config.middleware` 全局中间件（配合 `match` / `ignore`），router 上的 `middleware.xxx()`，egg-passport / egg-jwt。
- Midway：`@UseGuard`、中间件、`@midwayjs/passport` / `@midwayjs/jwt`。
- hapi：`server.auth.strategy` + `server.auth.default`，路由 `options.auth`（`false` 表示公开），`scope` 授权。
- Restify：`server.use(authMiddleware)`（按注册顺序作用于其后的路由）与路由级 handler 链。

## 危险 API
- SQL：egg-mysql `app.mysql.query(sql)` 拼接、Sequelize / TypeORM 的 raw query；Egg / Midway 的 `ctx.curl`、`app.httpclient.request`（SSRF）；`ctx.unsafeRedirect`、`h.redirect`、`res.redirect`（开放重定向）；hapi `h.file(path)`（@hapi/inert，路径遍历）；模板 `ctx.render` 的不转义输出。

## 常见误报
- Egg 默认开启 CSRF 与安全头；`ctx.redirect` 在配置了 `domainWhiteList` 时只允许白名单域名。
- hapi 路由的 `options.validate` 使用 Joi 校验了参数类型与格式。
