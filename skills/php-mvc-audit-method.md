---
name: php-mvc-audit-method
description: PHP MVC 框架 Yii 2、CodeIgniter 3 / 4、Slim 的入口（约定路由、Routes.php、路由组）、鉴权机制（AccessControl、filter、中间件、基类构造函数）、危险 API 与常见误报。审计这些框架的项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [php]
  frameworks: [yii, codeigniter, slim]
checklist:
  - id: yii-access-control
    vuln_class: authz_function
    title: Yii AccessControl 覆盖
    check: 控制器 behaviors() 的 AccessControl 是否覆盖全部敏感 action；'only' 列表之外的 action 不受规则约束；rules 中 roles ['?'] 表示游客；未列出的 action 在没有默认 deny 规则时放行。actions() 返回的外部 action（如 ErrorAction、文件上传类）同样需要覆盖。
    applies_to:
      frameworks: [yii]
  - id: yii-sql
    vuln_class: sqli
    title: Yii 原始 SQL 与条件
    check: createCommand($sql)、findBySql($sql)、where("id = $id") 等字符串条件、orderBy($sort) 是否拼接请求参数；数组形式 where(['id' => $id]) 与 bindValue 是安全的。
    applies_to:
      frameworks: [yii]
  - id: ci-route-exposure
    vuln_class: authz_function
    title: CodeIgniter 约定路由暴露
    check: CI3 的 controllers/ 下所有不以 _ 开头的 public 方法都可经 /class/method 访问，包括只想在内部调用的方法；CI4 开启 autoRoute（Routing.php / setAutoRoute(true)）时同理。检查这些方法是否都有登录与权限检查（基类构造函数、filter）。
    applies_to:
      frameworks: [codeigniter]
  - id: ci-filter-coverage
    vuln_class: authz_function
    title: CodeIgniter 4 filter 覆盖
    check: Config/Filters.php 的 globals / filters 中鉴权 filter 的 except 列表，与 Routes.php 中 group 的 filter 选项，是否覆盖全部敏感路由；CI3 依赖基类构造函数做登录检查时，检查后是否 return / exit（redirect() 本身会结束请求，但自定义跳转可能不会）。
    applies_to:
      frameworks: [codeigniter]
  - id: ci-db-query
    vuln_class: sqli
    title: CodeIgniter 查询构造
    check: $this->db->query("... $x") 拼接、where("name = '$x'") 字符串条件、order_by($用户输入) 是否可注入；query($sql, [$x]) 绑定与 where('name', $x) 是安全的；escape_str 不处理数字上下文。
    applies_to:
      frameworks: [codeigniter]
  - id: slim-middleware-order
    vuln_class: authz_function
    title: Slim 中间件作用范围
    check: 鉴权中间件是加在 $app（全局）、group 还是单个 route 上；group 外的路由不受 group 中间件保护；Slim 4 中间件后进先出，路由级与组级中间件只作用于匹配后的请求，检查公开路由与受保护路由的划分。
    applies_to:
      frameworks: [slim]
---
# Yii 2 / CodeIgniter / Slim 审计要点

## 入口在哪里
- **Yii 2**：控制器 `XxxController` 的 `actionFooBar()` → `/xxx/foo-bar`（模块下加模块 id）；`config/web.php` 的 `urlManager.rules` 可以改写 URL；`actions()` 返回的外部 action。
- **CodeIgniter 3**：`application/controllers/` 下继承 `CI_Controller` / `MY_Controller` 的类，public 方法 → `/class/method/参数`；`config/routes.php` 的 `$route[...]`。
- **CodeIgniter 4**：`app/Config/Routes.php` 的 `$routes->get / post / match / resource / group(...)`，可选的 autoRoute。
- **Slim**：`$app->get / post / map / any(...)`、`$app->group('/api', fn)`，handler 为闭包、`Class:method` 或可调用类。

## 鉴权机制
- Yii：`AccessControl` behavior、RBAC（`Yii::$app->user->can()`）、`VerbFilter`（只限制方法）。
- CodeIgniter：CI4 filter（`Config/Filters.php`、路由 `filter` 选项）；CI3 多在基类构造函数中检查 session。
- Slim：`->add(Middleware)`，常见 slim-jwt-auth（`path` / `ignore` 配置）。

## 危险 API
- Yii：`createCommand($sql)`、`findBySql`、字符串 `where`、`$this->render` 的模板中直接输出变量（应 `Html::encode`）、`unserialize`。
- CodeIgniter：`$this->db->query` 拼接、`$this->load->view($用户输入)`、`$this->input->get(null, false)` 关闭 XSS 过滤后直接输出。
- Slim：handler 中的 PDO 拼接、`$response->withHeader('Location', $x)`。

## 常见误报
- Yii 数组条件与参数绑定；`Html::encode` / `{{ }}`（Twig）已转义。
- CodeIgniter 查询构造器 `where('col', $x)`、`get_where('t', ['id' => $id])`。
