---
name: java-legacy-web-audit-method
description: Java Web 非 Spring 注解路由的项目：Servlet（web.xml、@WebServlet、Filter、security-constraint）、Struts 2（struts.xml、OGNL）、JSP 模板，以及 Spring 函数式路由（WebFlux）与 Vert.x 的入口、鉴权与危险点。审计这些项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [java]
  frameworks: [servlet, struts2, jsp, webflux, vertx]
checklist:
  - id: servlet-filter-coverage
    vuln_class: authz_function
    title: Filter 与 security-constraint 覆盖
    check: 鉴权 Filter（web.xml filter-mapping、@WebFilter）与 <security-constraint> 的 url-pattern 是否覆盖每个 Servlet 的映射；*.do 与 /admin/* 这类模式混用时，同一 Servlet 换个路径（如 /admin;jsessionid=x、大小写、多余斜杠、路径参数）是否能绕过前缀匹配；Filter 内部按 getRequestURI() 做白名单时是否先规范化。
    applies_to:
      frameworks: [servlet, struts2, jsp]
  - id: servlet-dispatch-method
    vuln_class: authz_function
    title: BaseServlet 反射分发
    check: 继承统一 BaseServlet、按请求参数（method / action / op）反射调用方法的 Servlet，所有 public 方法都可被直接调用；确认管理类方法有独立的权限检查，而不是只在页面上隐藏入口。
    applies_to:
      frameworks: [servlet]
  - id: struts2-ognl
    vuln_class: expression_injection
    title: Struts 2 OGNL 求值
    check: 用户输入是否进入 OGNL 求值（ValueStack.findValue / OgnlUtil.getValue / TextParseUtil.translateVariables、标签中的 %{…} 或 ${…} 拼接请求参数、结果配置中的 ${param}）；Struts 版本与 S2-045 / S2-057 / S2-061 / S2-062 等历史漏洞的影响范围；struts.mapper.alwaysSelectFullNamespace、DMI（action!method）是否开启。
    applies_to:
      frameworks: [struts2]
  - id: struts2-action-authz
    vuln_class: authz_function
    title: Struts 2 Action 的拦截器栈
    check: 鉴权拦截器是否在每个 package 的默认拦截器栈中；单个 action 声明自己的 interceptor-ref 时会替换默认栈，常导致鉴权拦截器丢失；通配 action（name="x_*" method="{1}"）会暴露类中全部 public 无参方法。
    applies_to:
      frameworks: [struts2]
  - id: jsp-output-escaping
    vuln_class: xss
    title: JSP 输出转义
    check: <%= %> 输出、未包在 <c:out> 或 fn:escapeXml 中的 ${param.x} / ${header.x}、以及脚本片段中由 request.getParameter 赋值的变量被直接输出时，构成反射型 XSS；存储型数据（数据库字段）同样需要转义。
    applies_to:
      frameworks: [jsp, servlet, struts2]
  - id: jsp-scriptlet-sql
    vuln_class: sqli
    title: JSP 脚本片段中的 SQL
    check: JSP 脚本片段中用字符串拼接构造 SQL 再调用 Statement.executeQuery / executeUpdate 时，参数来自 request 即为 SQL 注入；改为 PreparedStatement 占位符。
    applies_to:
      frameworks: [jsp]
  - id: reactive-route-auth
    vuln_class: authz_function
    title: 函数式路由与 Vert.x 路由的鉴权
    check: WebFlux RouterFunction 的 filter(...)、SecurityWebFilterChain 的 pathMatchers，以及 Vert.x 的 router.route("/x/*").handler(authHandler)，是否覆盖全部敏感路由；Vert.x 的 handler 注册顺序决定是否先经过鉴权 handler，子路由（subRouter）上的路由不继承父 router 后注册的 handler。
    applies_to:
      frameworks: [webflux, vertx]
---
# Servlet / Struts 2 / JSP / 函数式路由 / Vert.x 审计要点

## 入口在哪里
- **Servlet**：`@WebServlet(urlPatterns)` 或 `web.xml` 的 `<servlet>` + `<servlet-mapping>`；`doGet / doPost / …` 是各方法的入口，`service` 接收全部方法；继承 `BaseServlet` 按参数反射分发的，所有 public 方法都可访问。
- **Struts 2**：`struts.xml` 的 `<package namespace>` + `<action name class method>`，URL 为 `namespace/name.action`（扩展名可配置）；通配 `name="user_*" method="{1}"`；Convention 插件的 `@Action` / `@Namespace` 与按类名的零配置约定。
- **JSP**：每个 `.jsp` 文件都可以被直接请求（除非放在 `WEB-INF` 下）。
- **WebFlux / WebMvc.fn**：`route().GET("/x", handler::m)`、`RouterFunctions.route(GET("/x"), h)`、`nest(path("/api"), …)`。
- **Vert.x**：`router.get("/x").handler(...)`，`router.route("/api/*").subRouter(api)`。

## 鉴权机制
- `web.xml` 的 `<filter-mapping>`、`@WebFilter`、`<security-constraint>` + `<login-config>`；Shiro `ShiroFilter` 与 `[urls]` 配置；Struts 拦截器栈；Vert.x `JWTAuthHandler` / `BasicAuthHandler` / `AuthorizationHandler`；WebFlux `SecurityWebFilterChain`。

## 危险 API
- OGNL：`ValueStack.findValue / setValue`、`OgnlUtil.getValue`、`TextParseUtil.translateVariables`。
- JSP：`<%= request.getParameter(...) %>`、未转义的 EL，脚本片段中的 JDBC 拼接、`Runtime.exec`、文件读写。
- Servlet：`request.getRequestDispatcher(用户路径).forward`（任意文件读取 / 鉴权绕过），`response.sendRedirect(用户输入)`。

## 常见误报
- `<c:out value="${param.q}"/>` 与 `fn:escapeXml` 已转义；`${param.x}` 出现在 `<c:if test>` 等不输出的属性中。
- OGNL 表达式是字面量（如 `stack.findValue("user")`）。
- 放在 `WEB-INF/` 下的 JSP 不能被直接请求，只能经 Servlet / Action 转发。
