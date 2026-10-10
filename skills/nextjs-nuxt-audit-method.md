---
name: nextjs-nuxt-audit-method
description: 全栈框架 Next.js（API 路由、App Router route handler、Server Actions、middleware）与 Nuxt / Nitro（server/api、server/routes、server/middleware）的入口、鉴权写法、危险 API 与常见误报。审计 Next.js / Nuxt 项目的服务端代码时读取。
category: audit_method
scope: global
applies_to:
  languages: [javascript, typescript]
  frameworks: [nextjs, nuxt]
# checklist items settled after the exploration (stable ids).
checklist:
  - id: next-server-action-auth
    vuln_class: authz_function
    title: Server Action 自行鉴权
    check: 每个 'use server' 导出函数与内联 Server Action 都可以被任意客户端直接 POST 调用（只需 action id），页面是否展示按钮、middleware 的 matcher 都不能保护它。检查函数体内是否调用 auth() / getServerSession() / currentUser() 等并校验角色或资源归属；只在页面组件中鉴权而 action 内不鉴权即为越权。
    applies_to:
      frameworks: [nextjs]
  - id: next-route-handler-auth
    vuln_class: authz_function
    title: API 路由与 route handler 的鉴权
    check: pages/api/** 与 app/**/route.ts 的每个导出方法是否鉴权。middleware.ts 只在其 matcher 覆盖该路径时生效，matcher 漏掉 /api 或使用排除式正则时，API 不受保护；同一路由文件中 GET 鉴权而 POST / DELETE 未鉴权是常见遗漏。
    applies_to:
      frameworks: [nextjs]
  - id: next-object-ownership
    vuln_class: authz_object
    title: 动态段参数的资源归属
    check: '[id] / [...slug] 动态段、searchParams 与 Server Action 参数中的资源 id，在查询数据库时是否带上当前用户（或租户）条件；只校验已登录不足以防止越权。'
    applies_to:
      frameworks: [nextjs, nuxt]
  - id: next-redirect-ssrf
    vuln_class: ssrf
    title: 服务端 fetch 与重定向目标
    check: route handler、Server Action、getServerSideProps 与 Nuxt server 路由中的 fetch / $fetch / axios 的 URL 是否来自请求（SSRF，含内网元数据地址）；redirect()、NextResponse.redirect、sendRedirect 的目标是否可由用户控制（开放重定向）。new URL('/x', req.url) 这类固定路径不是问题。
    applies_to:
      frameworks: [nextjs, nuxt]
  - id: nuxt-server-auth
    vuln_class: authz_function
    title: Nuxt server 路由的鉴权
    check: server/api/** 与 server/routes/** 的 handler 是否调用 requireUserSession / getServerSession 等；server/middleware 中的鉴权是否真的拒绝请求（只设置 event.context.user 而不返回 401 时，后续 handler 仍需自行检查）。页面的 definePageMeta({ middleware }) 只保护页面，不保护 server 路由。
    applies_to:
      frameworks: [nuxt]
  - id: fullstack-secret-exposure
    vuln_class: info_leak
    title: 服务端密钥泄漏到客户端
    check: NEXT_PUBLIC_ / NUXT_PUBLIC_ 前缀的环境变量、runtimeConfig.public、以及被客户端组件（'use client'）导入的模块中，是否包含 API 密钥、数据库连接串或内部地址；Server Action 与 route handler 的返回值是否带出了不该给前端的字段（如密码哈希、内部 id）。
    applies_to:
      frameworks: [nextjs, nuxt]
---
# Next.js / Nuxt 审计要点

## 入口在哪里
- **Next.js Pages Router**：`pages/api/**`（或 `src/pages/api/**`）的默认导出是一个处理全部方法的 handler，按 `req.method` 分支。
- **Next.js App Router**：`app/**/route.ts` 导出的 `GET / POST / PUT / PATCH / DELETE / …`。路由组 `(x)` 与插槽 `@x` 不进 URL，`_private` 目录不路由，`[id]` / `[...slug]` 是参数。
- **Server Actions**：`'use server'` 文件的全部导出函数，以及函数体以 `'use server'` 开头的内联函数。它们没有固定 URL，但任何客户端都可以 POST 调用，参数完全可控。
- **middleware.ts**：在匹配的请求之前运行，常用来做登录跳转；它的 `config.matcher` 决定覆盖范围。
- **Nuxt / Nitro**：`server/api/**` → `/api/**`，`server/routes/**` → `/**`；文件名后缀 `.get.ts` / `.post.ts` 决定方法，默认导出 `defineEventHandler(...)`；`server/middleware/*` 对每个请求运行。

## 鉴权写法
- Next.js 没有路由级中间件链：鉴权写在 handler / action 体内（`auth()`、`getServerSession(authOptions)`、`currentUser()`、Clerk `auth().protect()`），或写在 middleware.ts 中。
- Nuxt：`requireUserSession(event)`（nuxt-auth-utils）、`getServerSession(event)`（sidebase/nuxt-auth），或 server/middleware 中的统一检查。

## 危险 API
- 数据库：Prisma `$queryRawUnsafe` / `$executeRawUnsafe`、拼接 SQL 的 `sql.unsafe`；Drizzle `sql.raw`。
- SSRF：服务端 `fetch` / `$fetch` / `ofetch` 的 URL 来自请求。
- 开放重定向：`redirect(x)`、`permanentRedirect(x)`、`NextResponse.redirect(x)`、`sendRedirect(event, x)`。
- XSS：`dangerouslySetInnerHTML`、`v-html` 渲染用户内容。

## 常见误报
- `redirect('/login')`、`new URL('/dashboard', req.url)` 等固定目标。
- 只有页面、没有 API 路由 / route handler / Server Action 的应用没有服务端入口。
- Server Action 内已调用 `auth()` 并按 `session.user.id` 过滤查询。
