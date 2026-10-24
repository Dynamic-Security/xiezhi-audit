// Java framework coverage — servlets (@WebServlet, web.xml, filters, security constraints),
// Struts 2 (struts.xml, wildcards, Convention annotations, OGNL), Spring functional routes, Vert.x Web, JSP sinks.
// Small inline sources, never executed.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { Executor, SnapshotView, buildIndex, createSnapshot, loadRules } from '@xiezhi/context';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1121-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const view = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key)!;
const sinksOf = (idx: StructIndex, category: string) => idx.sinks.filter((s) => s.category === category);

const WEB_XML = `<?xml version="1.0" encoding="UTF-8"?>
<web-app>
  <servlet><servlet-name>orders</servlet-name><servlet-class>com.shop.web.OrderServlet</servlet-class></servlet>
  <servlet-mapping><servlet-name>orders</servlet-name><url-pattern>/orders/*</url-pattern></servlet-mapping>
  <!-- <servlet-mapping><servlet-name>orders</servlet-name><url-pattern>/old</url-pattern></servlet-mapping> -->
  <servlet><servlet-name>legacy</servlet-name><servlet-class>com.shop.web.LegacyServlet</servlet-class></servlet>
  <servlet-mapping><servlet-name>legacy</servlet-name><url-pattern>*.do</url-pattern></servlet-mapping>
  <filter><filter-name>loginFilter</filter-name><filter-class>com.shop.web.LoginFilter</filter-class></filter>
  <filter-mapping><filter-name>loginFilter</filter-name><url-pattern>/orders/*</url-pattern></filter-mapping>
  <security-constraint>
    <web-resource-collection><url-pattern>/admin/*</url-pattern></web-resource-collection>
    <auth-constraint><role-name>admin</role-name></auth-constraint>
  </security-constraint>
</web-app>
`;

describe('servlets', () => {
  it('@WebServlet and web.xml mappings, do* methods, inherited dispatch, filters and security constraints', async () => {
    const idx = await indexOf({
      'src/main/webapp/WEB-INF/web.xml': WEB_XML,
      'src/main/java/com/shop/web/OrderServlet.java': `package com.shop.web;
import javax.servlet.http.*;
public class OrderServlet extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse resp) {}
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) {}
}
`,
      'src/main/java/com/shop/web/LegacyServlet.java': `package com.shop.web;
public class LegacyServlet extends BaseServlet {
  public void list(javax.servlet.http.HttpServletRequest req, javax.servlet.http.HttpServletResponse resp) {}
}
`,
      'src/main/java/com/shop/web/AdminServlet.java': `package com.shop.web;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.*;
@WebServlet(urlPatterns = {"/admin/users", "/admin/roles"})
public class AdminServlet extends HttpServlet {
  @Override protected void service(HttpServletRequest req, HttpServletResponse resp) {}
}
`,
      'src/main/java/com/shop/web/AuditFilter.java': `package com.shop.web;
import javax.servlet.*;
import javax.servlet.annotation.WebFilter;
@WebFilter("/admin/*")
public class AuditFilter implements Filter {}
`,
      'src/main/java/com/shop/web/Util.java': `package com.shop.web;
public class Util { public void doGet() {} }
`,
    });
    expect(keys(idx)).toEqual(['ANY /admin/roles', 'ANY /admin/users', 'ANY /{}', 'GET /orders/{}', 'POST /orders/{}']);
    const get = entry(idx, 'GET /orders/{}');
    expect(get.framework).toBe('servlet');
    expect(get.handler).toBe('repo:src/main/java/com/shop/web/OrderServlet.java#OrderServlet.doGet(2)');
    expect(get.middlewares).toEqual(['filter: loginFilter(LoginFilter)']);
    expect(get.authSignals).toEqual(['filter: loginFilter(LoginFilter)']);
    const admin = entry(idx, 'ANY /admin/users');
    expect(admin.middlewares).toEqual(['filter: AuditFilter', 'security-constraint: roles(admin)']);
    expect(admin.authSignals).toEqual(['security-constraint: roles(admin)']);
    const legacy = entry(idx, 'ANY /{}');
    expect(legacy.pathTemplate).toBe('/*.do');
    expect(legacy.handler).toBe('repo:src/main/java/com/shop/web/LegacyServlet.java#LegacyServlet');
  });
});

describe('Struts 2', () => {
  it('struts.xml actions (namespace, wildcard methods, interceptors, extension) and Convention annotations; OGNL sinks', async () => {
    const idx = await indexOf({
      'src/main/resources/struts.xml': `<struts>
  <constant name="struts.action.extension" value="do,," />
  <package name="user" namespace="/user" extends="struts-default">
    <default-interceptor-ref name="authStack"/>
    <action name="login" class="com.app.action.LoginAction"><interceptor-ref name="defaultStack"/></action>
    <action name="profile_*" class="com.app.action.ProfileAction" method="{1}"/>
  </package>
</struts>
`,
      'src/main/java/com/app/action/LoginAction.java': `package com.app.action;
import com.opensymphony.xwork2.ActionSupport;
public class LoginAction extends ActionSupport {
  public String execute() { return SUCCESS; }
}
`,
      'src/main/java/com/app/action/ProfileAction.java': `package com.app.action;
import com.opensymphony.xwork2.ActionSupport;
import com.opensymphony.xwork2.util.ValueStack;
public class ProfileAction extends ActionSupport {
  private ValueStack stack;
  private String expr;
  public String view() { stack.findValue("user"); return SUCCESS; }
  public String update() { stack.findValue(expr); return SUCCESS; }
  public void setExpr(String e) { this.expr = e; }
  private String helper() { return ""; }
}
`,
      'src/main/java/com/app/action/ReportAction.java': `package com.app.action;
import org.apache.struts2.convention.annotation.Action;
import org.apache.struts2.convention.annotation.Namespace;
import org.apache.struts2.convention.annotation.InterceptorRef;
@Namespace("/report")
public class ReportAction {
  @Action(value = "daily", interceptorRefs = @InterceptorRef("permissionCheck"))
  public String daily() { return "ok"; }
  @Action("/export/csv")
  public String csv() { return "ok"; }
}
`,
    });
    expect(keys(idx)).toEqual(['ANY /export/csv.do', 'ANY /report/daily.do', 'ANY /user/login.do', 'ANY /user/profile_update.do', 'ANY /user/profile_view.do']);
    const login = entry(idx, 'ANY /user/login.do');
    expect(login.framework).toBe('struts2');
    expect(login.handler).toBe('repo:src/main/java/com/app/action/LoginAction.java#LoginAction.execute(0)');
    expect(login.middlewares).toEqual(['interceptor-ref: defaultStack']);
    expect(entry(idx, 'ANY /user/profile_view.do').authSignals).toEqual(['interceptor-ref: authStack']);
    expect(entry(idx, 'ANY /report/daily.do').authSignals).toEqual(['interceptor-ref: permissionCheck']);
    expect(sinksOf(idx, 'expression_injection').map((s) => `${s.api}@${s.range.startLine}`)).toEqual(['ValueStack.findValue@8']);
  });
});

describe('Spring functional routes and Vert.x', () => {
  it('WebFlux builder / predicate routes with nest and path prefixes', async () => {
    const idx = await indexOf({
      'src/main/java/com/app/Routes.java': `package com.app;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.function.server.*;
import static org.springframework.web.reactive.function.server.RequestPredicates.*;
import static org.springframework.web.reactive.function.server.RouterFunctions.*;
public class Routes {
  @Bean
  public RouterFunction<ServerResponse> api(UserHandler userHandler) {
    return route()
      .path("/api", b -> b
        .GET("/users/{id}", userHandler::get)
        .POST("/users", userHandler::create))
      .build();
  }
  @Bean
  public RouterFunction<ServerResponse> legacy(UserHandler h) {
    return nest(path("/v1"), route(GET("/ping"), h::ping).andRoute(DELETE("/users/{id}"), req -> ServerResponse.ok().build()));
  }
}
`,
      'src/main/java/com/app/UserHandler.java': `package com.app;
public class UserHandler {
  public Object get(Object req) { return null; }
  public Object create(Object req) { return null; }
  public Object ping(Object req) { return null; }
}
`,
    });
    expect(keys(idx)).toEqual(['DELETE /v1/users/{}', 'GET /api/users/{}', 'GET /v1/ping', 'POST /api/users']);
    expect(entry(idx, 'GET /api/users/{}').framework).toBe('webflux');
    expect(entry(idx, 'GET /api/users/{}').handler).toBe('repo:src/main/java/com/app/UserHandler.java#UserHandler.get(1)');
    expect(entry(idx, 'DELETE /v1/users/{}').handler).toBe('repo:src/main/java/com/app/Routes.java#Routes.legacy(1)');
  });

  it('Vert.x routes, handler chains, router-wide auth handlers and sub-routers', async () => {
    const idx = await indexOf({
      'src/main/java/com/app/Api.java': `package com.app;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.*;
public class Api {
  void mount(io.vertx.core.Vertx vertx, Router router) {
    Router api = Router.router(vertx);
    router.route().handler(BodyHandler.create());
    api.route("/secure/*").handler(JWTAuthHandler.create(provider));
    api.get("/public/info").handler(this::info);
    api.post("/secure/orders").handler(ctx -> ctx.end());
    api.get("/secure/orders/:id").handler(BodyHandler.create()).handler(this::order);
    router.route("/api/*").subRouter(api);
  }
  void info(Object ctx) {}
  void order(Object ctx) {}
}
`,
    });
    expect(keys(idx)).toEqual(['GET /api/public/info', 'GET /api/secure/orders/{}', 'POST /api/secure/orders']);
    const order = entry(idx, 'GET /api/secure/orders/{}');
    expect(order.framework).toBe('vertx');
    expect(order.handler).toBe('repo:src/main/java/com/app/Api.java#Api.order(1)');
    expect(order.middlewares).toEqual(['JWTAuthHandler.create(provider)', 'BodyHandler.create()']);
    expect(order.authSignals).toEqual(['JWTAuthHandler.create(provider)']);
    expect(entry(idx, 'GET /api/public/info').authSignals).toEqual([]);
  });
});

describe('JSP', () => {
  it('request EL and <%= %> request output outside escaping are XSS sinks', async () => {
    const idx = await indexOf({
      'src/main/java/com/app/A.java': 'package com.app;\npublic class A {}\n',
      'src/main/webapp/search.jsp': `<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<h1>Results for ${'${param.q}'}</h1>
<p><c:out value="${'${param.q}'}"/></p>
<p>${'${fn:escapeXml(param.q)}'}</p>
<p><%= request.getParameter("page") %></p>
<p><%= StringEscapeUtils.escapeHtml4(request.getParameter("x")) %></p>
<p>${'${user.name}'}</p>
<%
  String q = (String) request.getParameter("q");
  java.sql.Statement stmt = conn.createStatement();
  java.sql.ResultSet rs = stmt.executeQuery("SELECT * FROM p WHERE name LIKE '%" + q + "%'");
  stmt.executeQuery("SELECT count(*) FROM p");
  java.sql.PreparedStatement ps = conn.prepareStatement("SELECT * FROM p WHERE t LIKE ?"); ps.setString(1, "%" + q + "%");
  String sql = "SELECT * FROM o WHERE 1 = 1";
  if (q != null) sql += " AND s = '" + q + "'";
  stmt.executeQuery(sql);
%>
<b>You searched for:</b> <%= q %>
`,
    });
    const xss = sinksOf(idx, 'xss').filter((s) => s.ruleId === 'jsp.template.reflected-xss');
    expect(xss.map((s) => `${s.range.startLine}:${s.api}`)).toEqual(['18:jsp:<%=q%>', '2:jsp:${param.q}', '5:jsp:<%=request.getParameter("page")%>']);
    expect(sinksOf(idx, 'sqli').map((s) => `${s.range.startLine}:${s.ruleId}`)).toEqual(['11:jsp.template.scriptlet-sql', '16:jsp.template.scriptlet-sql']);
  });
});
