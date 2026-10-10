---
name: go-gin-middleware-method
description: gin/echo 中间件顺序与路由组鉴权遗漏的审计方法。审计 Go Web 项目的认证授权时读取。
category: audit_method
scope: global
applies_to:
  languages: [go]
  frameworks: [gin, echo, nethttp]
---
# Go 路由鉴权审计要点

- **注册顺序**：gin 中 `group.Use(mw)` 只对之后注册的路由生效；在 `Use` 之前注册的路由不受该中间件保护。
- **分组继承**：`r.Group("/admin", AdminOnly())` 的中间件只作用于该组；在父组或根路由上注册的同名路径不受保护。
- **中间件实现**：检查中间件失败时是否 `c.Abort()`/`return`；只写响应不 Abort 会继续执行后续 handler。
- **echo**：`e.Pre` 与 `e.Use` 的区别；路由级中间件是 handler 之后的参数。
- **net/http**：包装顺序 `auth(mux)` 与 `mux.Handle(p, auth(h))`；Go 1.22 模式中方法与路径的匹配。
