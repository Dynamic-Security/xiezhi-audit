---
name: python-async-web-audit-method
description: Python Web 框架 tornado、aiohttp、Sanic、falcon 的入口（Application 路由表、RouteTableDef、蓝图、资源类）、鉴权机制（装饰器、中间件、hook）、危险 API 与常见误报。审计这些框架的项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [python]
  frameworks: [tornado, aiohttp, sanic, falcon]
checklist:
  - id: tornado-authenticated
    vuln_class: authz_function
    title: tornado 方法级鉴权
    check: '@tornado.web.authenticated 只装饰了某些 HTTP 方法时，同一 Handler 的其他方法（如 post / delete）是否也需要；get_current_user 的实现是否校验 secure cookie 签名（get_secure_cookie）而不是读普通 cookie；check_xsrf_cookie 是否因 xsrf_cookies=False 而关闭。'
    applies_to:
      frameworks: [tornado]
  - id: aiohttp-middleware-scope
    vuln_class: authz_function
    title: aiohttp 中间件与子应用
    check: web.Application(middlewares=[...]) 的鉴权中间件是否对公开路径做了白名单判断，白名单是否用前缀匹配（/static 可匹配 /staticx）；add_subapp 挂载的子应用不继承父应用的中间件。
    applies_to:
      frameworks: [aiohttp]
  - id: sanic-protected
    vuln_class: authz_function
    title: Sanic 路由与蓝图的鉴权
    check: sanic-jwt 的 @protected / @scoped、自定义装饰器或 @app.middleware('request') 是否覆盖全部敏感路由与蓝图；蓝图级中间件只作用于该蓝图；request.ctx 上的用户是否真正校验。
    applies_to:
      frameworks: [sanic]
  - id: falcon-hooks
    vuln_class: authz_function
    title: falcon hook 与中间件
    check: falcon.App(middleware=[...]) 中鉴权中间件的 process_request / process_resource 是否对所有资源生效（只检查部分 req.path 时易漏）；@falcon.before 只装饰类或部分 responder 时，同一资源的其他 on_* 方法是否缺少检查。
    applies_to:
      frameworks: [falcon]
  - id: async-web-object-authz
    vuln_class: authz_object
    title: 路径参数的资源归属
    check: tornado 正则分组参数、aiohttp request.match_info、Sanic 路由参数、falcon 的 URI 模板参数中的资源 id，在查询时是否带上当前用户（或租户）条件。
    applies_to:
      frameworks: [tornado, aiohttp, sanic, falcon]
---
# tornado / aiohttp / Sanic / falcon 审计要点

## 入口在哪里
- **tornado**：`tornado.web.Application([(r"/users/(\d+)", UserHandler), url(...)])`，Handler 的 `get / post / put / delete / patch` 方法，正则分组作为位置参数。
- **aiohttp**：`app.router.add_get(path, handler)`、`app.add_routes([web.get(...), web.view(...)])`、`routes = web.RouteTableDef()` + `@routes.get(path)`，`request.match_info` 取路径参数。
- **Sanic**：`@app.route(path, methods=[...])`、`@app.get(path)`、`Blueprint(name, url_prefix=...)` + `app.blueprint(bp)`。
- **falcon**：`app.add_route(uri_template, Resource(), suffix=...)`，资源类的 `on_get / on_post / …`（有 suffix 时为 `on_get_<suffix>`）。

## 鉴权机制
- tornado：`@tornado.web.authenticated` + `get_current_user`、`xsrf_cookies`。
- aiohttp：中间件，以及 aiohttp-security 库提供的 `check_authorized` / `check_permission`。
- Sanic：sanic-jwt `@protected` / `@scoped`、请求中间件。
- falcon：中间件 `process_request` / `process_resource`、`@falcon.before(hook)`。

## 危险 API
- 与通用 Python 相同：DB-API `cursor.execute` 拼接、`subprocess` / `os.system`、`pickle` / `yaml.load`、`open(拼接路径)`、`requests` / `aiohttp.ClientSession` 的用户 URL；tornado `self.redirect(用户输入)`、`self.render_string` / `Template(用户输入)`（SSTI）；aiohttp `web.HTTPFound(用户输入)`。

## 常见误报
- tornado 模板默认转义（`{% raw %}` 除外）；aiohttp_jinja2 开启 autoescape。
- `cursor.execute(sql, params)` 参数化查询。
