---
name: javascript-audit-method
description: Node.js 后端（Express / Koa / Fastify / NestJS，JS 与 TS）的审计方法：入口与中间件链、鉴权机制、各类危险 API 与常见误报。审计 JavaScript / TypeScript 服务端代码时读取；Egg / Midway / hapi / Restify / Next.js / Nuxt 另见专门的审计方法。
category: audit_method
scope: global
applies_to:
  languages: [javascript, typescript]
  frameworks: [express, koa, nestjs, fastify, hapi, restify, egg, midway, nextjs, nuxt]
---
# 入口在哪里

- **Express**：`app.get/post/put/delete/patch/all(path, ...mw, handler)`、`express.Router()` 上的同名方法、`router.route('/p').get(h).post(h)`。完整路径 = 各级 `app.use('/prefix', router)` 前缀拼接；挂载常在另一个文件（`app.ts` / `routes/index.ts`），要沿 import 找到。
- **Koa**：`@koa/router` / `koa-router` 的 `router.get([name,] path, ...mw, handler)`；前缀来自 `new Router({ prefix })`、`router.prefix()`、`parent.use('/p', child.routes())`。
- **Fastify**：`fastify.get(path, [opts], handler)`、`fastify.route({ method, url, handler, preHandler })`；插件经 `register(plugin, { prefix })` 挂载，插件内的 `fastify` 是参数。
- **NestJS**：`@Controller('prefix')` 类中带 `@Get/@Post/...` 的方法；`app.setGlobalPrefix()` 与版本前缀（`enableVersioning`）不在索引路径里，需要到 `main.ts` 确认。
- 处理函数常是内联箭头函数（索引里是 `<anonymous METHOD path>` 合成符号），或 `asyncHandler(fn)`、`ctrl.method.bind(ctrl)` 包装后的函数。

# 鉴权机制（逐层确认）

- **中间件顺序**：Express / Koa 中 `app.use(auth)` 只对之后注册的路由和之后挂载的 router 生效；`router.use(auth)` 只作用于该 router。路由级中间件在 path 与 handler 之间（`requireAuth`、`passport.authenticate('jwt')`、`expressjwt({...})`、`checkRole('admin')`）。
- **路径作用域**：`app.use('/admin', requireAdmin)` 只保护前缀下的路由；注意大小写、尾斜杠、`/api/v1` 与 `/api/v2` 双挂载时漏掉一处。
- **Fastify**：`addHook('onRequest', fastify.authenticate)` 作用于该插件作用域（封装上下文），不作用于兄弟插件；路由级 `preHandler` / `onRequest`。
- **NestJS**：`@UseGuards(AuthGuard('jwt'))` 在类或方法上；全局 `app.useGlobalGuards()` 或 `{ provide: APP_GUARD }`；`@Public()` / `@SkipAuth()` 这类元数据会让全局守卫放行——逐个核对被标注为公开的方法。`@Roles()` 只有在 RolesGuard 真正注册时才生效。
- **对象归属（IDOR）**：`findById(req.params.id)`、`findOne({ where: { id } })`、`findUnique({ where: { id } })` 之后是否比较 `owner === req.user.id`，或查询条件带上当前用户。鉴权只校验“已登录”不等于校验归属。

# 危险 API（按类别）

- **SQL 注入**：`pool/client/connection.query(sql)`、`sequelize.query`、`knex.raw` / `whereRaw`、TypeORM `repository.query` / `createQueryBuilder().where(\`...${x}\`)`、Prisma `$queryRawUnsafe` / `$executeRawUnsafe`。模板字符串 `${}` 或 `+` 拼接为高危；`query('... $1', [x])`、`?` 占位符、Prisma 的带标签模板 `` $queryRaw`...${x}` `` 是参数化的。
- **NoSQL 注入**：`find(req.body)`、`findOne({ user: req.body.user })`（对象可带 `$ne` / `$gt`），`$where` 字符串。
- **命令注入**：`child_process.exec/execSync`（经 shell）、`spawn(cmd, { shell: true })`；`execFile(常量程序, [参数])` 不经 shell，但仍需看参数是否能注入选项（`--output=...`）。
- **代码执行**：`eval`、`new Function`、`vm.runInNewContext`（vm 不是沙箱）、`setTimeout(字符串)`。
- **SSRF**：`axios` / `got` / `node-fetch` / `fetch` / `http.request` 的 URL 来自请求；检查协议与主机白名单、DNS 重绑定、重定向跟随。
- **路径穿越**：`fs.readFile/createReadStream/writeFile`、`res.sendFile/res.download`；`path.join(base, input)` 不能阻止 `../`，需要 `path.resolve` 后校验前缀，或 `sendFile(name, { root })`。
- **开放重定向**：`res.redirect(req.query.next)`、`ctx.redirect(...)`。
- **模板注入 / XSS**：用户可控的模板源传给 `ejs.render`、`pug.compile`、`Handlebars.compile`、`_.template`；`res.send('<div>' + input)` 拼接 HTML。
- **反序列化**：`node-serialize.unserialize`（函数复活，可 RCE）、旧版 `js-yaml.load`、`serialize-to-js`、`funcster`。
- **XXE**：`libxmljs.parseXml(xml, { noent: true })`。
- **原型污染**：`_.merge` / `_.defaultsDeep` / `_.set` / 自写深拷贝合并请求体（`__proto__`、`constructor.prototype`）。
- **业务逻辑**：`update({ status | amount | balance | role })`、实体赋值后 `save()`：确认状态机前置条件、金额来源（不能取自请求体）、并发（先读后写无锁或无条件更新）。

# 常见误报

- 参数化查询（`$1`、`?`、`:name` 绑定、Prisma 标签模板、ORM 的 `where: { id }` 对象条件）。
- 拼接的是常量或枚举白名单（`ORDER BY ${allowed[col]}`，且 `allowed` 为常量表）。
- `execFile` / `spawn` 常量程序 + 常量参数；`fetch` 固定内部地址。
- 路由挂在带鉴权的父 router 下，或 NestJS 全局守卫已覆盖（确认没有 `@Public()`）。
- 测试、脚本、`seed` 与迁移文件中的危险调用（不可从 HTTP 入口到达）。
- 前端代码（React / Vue 组件中的 `fetch`、`innerHTML` 属于前端审计范畴，不是服务端入口）。
