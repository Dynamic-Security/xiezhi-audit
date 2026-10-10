---
name: session-transport-checklist
description: 会话、传输与健壮性检查清单：WebSocket 升级的 Origin 与会话、Cookie 属性、CSRF、CORS、会话失效、未认证可触发的崩溃与资源耗尽。审计认证、会话、跨站与拒绝服务类问题时读取。
category: audit_method
scope: global
applies_to:
  vuln_classes: [authn, csrf, cors, dos, authz_function]
# the items the checklist check settles one by one after the exploration (stable ids).
checklist:
  - id: ws-origin
    vuln_class: cors
    title: WebSocket 升级校验 Origin
    check: 升级时是否校验 Origin（gorilla Upgrader.CheckOrigin、Spring setAllowedOrigins / setAllowedOriginPatterns、Node verifyClient）；恒为 true、允许 *、缺少 Origin 头或未配置允许列表时放行即为跨站 WebSocket 劫持。CheckOrigin 为 nil 时 gorilla 默认同源检查，不是问题。没有 WebSocket / 长连接时为不适用。
  - id: ws-session-revalidate
    vuln_class: authn
    title: 长连接期间会话失效生效
    check: 升级时依据 cookie / token 建立的用户上下文在整个连接期间是否再校验；令牌删除、退出登录、改密后订阅或连接是否仍继续（如 gqlgen transport.Websocket 没有 InitFunc 或不校验 token）。没有长连接时为不适用。
  - id: ws-message-authz
    vuln_class: authz_object
    title: 长连接每条消息的授权
    check: 通过 WebSocket / SSE 订阅或发送的每条消息，是否校验所涉资源属于当前用户（只在握手时鉴权不够）。没有长连接时为不适用。
  - id: cookie-flags
    vuln_class: authn
    title: 会话 Cookie 属性
    check: 会话 / 记住我 Cookie 是否设置 HttpOnly、Secure、SameSite；是否把敏感数据明文放在 Cookie。不使用 Cookie 维持会话时为不适用。
  - id: session-lifecycle
    vuln_class: authn
    title: 会话固定与失效
    check: 登录后是否更换会话标识；退出、改密、禁用用户后服务端会话或令牌是否失效。
  - id: token-expiry
    vuln_class: authn
    title: 令牌过期检查
    check: 分享链接、重置密码链接、邀请链接、API 令牌保存了过期时间（expire / expiresAt）时，读取时是否真的比较；保存了却从不比较是常见缺陷。
  - id: token-randomness
    vuln_class: authn
    title: 令牌生成与比较
    check: 记住我、分享令牌、API Key、重置令牌是否用安全随机数生成（不可预测），校验时是否恒定时间比较。
  - id: csrf-state-changing
    vuln_class: csrf
    title: 状态修改接口的 CSRF 防护
    check: 以 Cookie 维持会话的状态修改接口（POST / PUT / DELETE，以及用 GET 改状态的接口）是否有 CSRF 防护（框架令牌、SameSite=Lax/Strict、自定义请求头校验）。Spring Security 关闭 csrf 只有在纯 Authorization 头认证、不使用 Cookie 会话时才合理。
  - id: csrf-graphql
    vuln_class: csrf
    title: GraphQL 的跨站执行
    check: GraphQL 是否接受 application/x-www-form-urlencoded 或 GET 执行 mutation；接受时是否同样有 CSRF 防护。没有 GraphQL 时为不适用。
  - id: cors-credentials
    vuln_class: cors
    title: CORS 反射与凭据
    check: Access-Control-Allow-Origin 是否反射请求的 Origin、允许 * 或任意子域，同时 Allow-Credentials 为 true；是否允许 null Origin；开发模式的宽松配置是否可能在生产生效（由环境变量控制时看缺省值）。
  - id: dos-nil-deref
    vuln_class: dos
    title: 未认证请求触发崩溃
    check: 查询未命中时返回 nil / 空对象而不报错、随后直接解引用（如 GORM Find / Scan 未命中不返回 ErrRecordNotFound），未认证请求即可触发 panic；框架是否 recover、是否影响整个进程或连接。
  - id: dos-unbounded-input
    vuln_class: dos
    title: 无上限的读取与解析
    check: io.ReadAll(r.Body)、无大小限制的上传、解压（zip bomb）、图片 / 视频 / 元数据解析（超大尺寸、畸形 EXIF）是否有上限。
  - id: dos-input-driven-cost
    vuln_class: dos
    title: 输入控制的计算量
    check: 外部输入是否进入正则（ReDoS）、循环次数、分页大小、批量接口的条目数而没有上限。
  - id: input-range
    vuln_class: business_logic
    title: 解析后的取值范围
    check: 解析外部数据后是否校验取值范围再入库或参与计算（NaN、越界坐标、负数数量、超大金额）。
---
# 会话、传输与健壮性检查清单

这类问题大多是“缺少检查”，没有危险调用可以锚定。从机制出发逐项确认，每项都要读到实际代码再下结论。

## WebSocket / 长连接

1. **Origin 校验**：升级时是否校验 Origin（gorilla `Upgrader.CheckOrigin`、Spring `setAllowedOrigins` / `setAllowedOriginPatterns`、Node `verifyClient`）。
   - 返回恒为 true、`*`、或缺少 Origin 头 / 未配置允许列表时直接放行（fail open）→ 跨站 WebSocket 劫持（带 cookie 的连接被第三方页面建立）。归类 `cors`（或 `csrf`）。
   - `CheckOrigin` 为 nil 时 gorilla 默认做同源检查，不是问题。
2. **连接期间的会话**：升级时依据 cookie / token 建立的用户上下文，在整个连接期间是否再校验。
   - gqlgen `transport.Websocket` 没有 `InitFunc`（或在其中不校验 token），订阅在令牌删除、退出登录、密码修改后仍然继续 → 会话失效不生效。归类 `authn`。
   - 每条消息是否重新做授权（订阅的资源是否属于当前用户）。
3. **认证方式**：只依赖 cookie 的 WebSocket 必须同时有 Origin 校验；只依赖 URL 中的 token 时注意日志泄露。

## Cookie 与会话

1. 会话 / 记住我 Cookie 是否设置 `HttpOnly`、`Secure`、`SameSite`；是否把敏感数据明文放在 Cookie。
2. 登录后是否更换会话标识（会话固定）；退出、改密、禁用用户后服务端会话或令牌是否失效。
3. 令牌是否检查过期时间：保存了 `expire` / `expiresAt` 字段但读取时从不比较，是常见缺陷（分享链接、重置密码链接、邀请链接）。
4. 记住我、分享令牌、API Key 的生成是否可预测，比较是否恒定时间。

## CSRF

1. 以 Cookie 维持会话的状态修改接口（POST / PUT / DELETE，以及用 GET 改状态的接口）是否有 CSRF 防护：框架 CSRF 令牌、`SameSite=Lax/Strict`、自定义请求头校验。
2. Spring Security `csrf().disable()` / `csrf(AbstractHttpConfigurer::disable)`：只有纯 token（Authorization 头）认证、不使用 Cookie 会话时才合理。
3. GraphQL 接受 `application/x-www-form-urlencoded` 或 GET 执行 mutation 时同样需要防护。

## CORS

1. `Access-Control-Allow-Origin` 反射请求的 Origin，或允许 `*` / 任意子域，同时 `Allow-Credentials: true` → 第三方页面可带凭据读取响应。
2. 开发模式的宽松配置是否可能在生产生效（由环境变量控制时，看缺省值）。
3. `null` Origin 被允许。

## 未认证可触发的健壮性问题（`dos`）

1. 查询未命中时返回 nil / 空对象而不报错，随后直接解引用（Go 中 GORM `Find` / `Scan` 未命中不返回 `ErrRecordNotFound`）→ 未认证请求触发 panic。确认框架是否 recover：即使 recover，也要看是否影响整个进程或连接。
2. 无上限的读取：`io.ReadAll(r.Body)`、无大小限制的上传、解压（zip bomb）、图片 / 视频 / 元数据解析（超大尺寸、畸形 EXIF）。
3. 外部输入进入正则（ReDoS）、循环次数、分页大小、批量接口的条目数。
4. 解析外部数据后不校验取值范围就入库（NaN、越界坐标、负数数量），属于输入校验缺陷，按影响归类。

## 归类

- 会话、令牌失效、Cookie 属性、连接期间不校验 → `authn`。
- 跨站请求伪造 → `csrf`；跨域读取 / WebSocket Origin → `cors`。
- 崩溃与资源耗尽 → `dos`。
