---
name: ruby-rails-audit-method
description: Ruby Web 框架 Rails、Sinatra、Grape 的入口（routes.rb DSL、控制器 action、路由块）、鉴权机制（before_action 继承与 skip、Devise、Pundit、CanCanCan、Rack 中间件、Grape before）、危险 API 与常见误报。审计 Ruby 项目时读取。
category: audit_method
scope: global
applies_to:
  languages: [ruby]
  frameworks: [rails, sinatra, grape]
checklist:
  - id: rails-callback-skip
    vuln_class: authz_function
    title: Rails 鉴权回调被跳过或未覆盖
    check: 沿继承链确认 action 实际生效的 before_action（含 concern 的 included do）；skip_before_action / allow_unauthenticated_access 的 only / except 是否放过了写操作；before_action 的 only 列表是否漏掉新加的 action；if / unless 条件是否可被请求参数影响。
    applies_to:
      frameworks: [rails]
  - id: rails-object-scope
    vuln_class: authz_object
    title: Rails 记录归属
    check: Model.find(params[:id]) / find_by(id:) 直接在模型类上查询时，是否另有 authorize / policy_scope / 归属比较；安全写法是经当前用户的关联查询（current_user.posts.find(params[:id])）。Pundit 项目确认 after_action :verify_authorized 覆盖了该 action，没有被 skip_after_action 跳过。
    applies_to:
      frameworks: [rails]
  - id: rails-mass-assignment
    vuln_class: business_logic
    title: 批量赋值
    check: params.permit! 或 permit 列表中出现 role / admin / user_id / account_id / balance 等权限或归属字段；update(params[:x]) 绕过 strong parameters 的写法（to_unsafe_h、permit!）。
    applies_to:
      frameworks: [rails, sinatra, grape]
  - id: rails-sql-string
    vuln_class: sqli
    title: ActiveRecord 字符串条件
    check: where / having / order / pluck / select / joins / find_by_sql / connection.execute 的第一个参数是否插值或拼接请求值；order(params[:sort]) 类排序参数需要白名单；数组条件 where("a = ?", x) 与哈希条件安全；sanitize_sql_like 只处理 LIKE 通配符。
    applies_to:
      frameworks: [rails, sinatra, grape]
  - id: rails-render-and-redirect
    vuln_class: ssti
    title: render 与跳转
    check: 'render inline: 使用请求数据（服务端模板注入）；render file: / render params[:x] 读取任意文件；redirect_to params[:url] 或 request.referer 未限制主机（allow_other_host）；html_safe / raw 用在拼接了用户数据的字符串上。'
    applies_to:
      frameworks: [rails]
  - id: ruby-dangerous-calls
    vuln_class: code_injection
    title: Ruby 动态执行与反序列化
    check: send / public_send / constantize / const_get 的名字来自请求；eval / instance_eval 的字符串可控；YAML.load（Psych 4 之前）/ Marshal.load / Oj.load（object 模式）处理外部数据；system / 反引号 / Open3 / Kernel#open 带请求值（open("|cmd") 会执行命令）。
    applies_to:
      frameworks: [rails, sinatra, grape]
  - id: sinatra-filter-coverage
    vuln_class: authz_function
    title: Sinatra 过滤器与 helper 鉴权
    check: before '/admin/*' 的模式不覆盖 /admin 本身与其他前缀；鉴权写在 helper（protected!）中时逐个路由确认是否调用；模块化应用通过 config.ru map 挂载时，Rack 鉴权中间件只作用于所在应用。
    applies_to:
      frameworks: [sinatra]
  - id: grape-before-scope
    vuln_class: authz_function
    title: Grape 鉴权作用域
    check: before 块与 authenticate! helper 的作用范围是所在 namespace 及其后定义的端点；mount 到父 API 的子 API 是否继承了鉴权；route_param 的资源 id 是否校验归属；desc 中的 security 只是文档，不做校验。
    applies_to:
      frameworks: [grape]
---
# Rails / Sinatra / Grape 审计要点

## 入口在哪里
- **Rails**：`config/routes.rb` 与 `config/routes/*.rb`。
  - `resources` / `resource` 展开为 7 / 6 个 action，`only` / `except` 收窄。
  - `member` / `collection`、嵌套资源（`:post_id`）、`namespace`（路径 + 模块）、`scope`、`concerns`、`match … via:`。
  - 处理函数是控制器的公开方法；没有方法的 action 只渲染模板。
  - `devise_for` 与引擎的 `mount` 由 gem 提供路由。
  - 后台任务（Sidekiq / ActiveJob `perform`）、Rake 任务、定时任务也是入口。
- **Sinatra**：`get '/x' do … end`（经典式或 `Sinatra::Base` 子类），`namespace`，前缀来自 config.ru 的 `map` 或 Rails `mount`。
- **Grape**：`Grape::API` 子类的 `prefix` / `version` / `resource` / `route_param` 与动词块，经 `mount` 组合。

## 鉴权机制
- Rails：
  - `before_action` 沿继承链生效，concern 的 `included do` 中也可声明；`skip_before_action` 与 Rails 8 的 `allow_unauthenticated_access` 会取消它。
  - Devise `authenticate_user!` 与路由中的 `authenticate :user do`；Pundit `authorize` / `policy_scope` / `verify_authorized`；CanCanCan `load_and_authorize_resource` / `authorize!`；`http_basic_authenticate_with`。
- Sinatra：`before` 过滤器（可带路径模式）、`use Rack::Auth::Basic` / Warden、路由块内的 helper。
- Grape：`before do authenticate! end`、`http_basic`、helper 中的 `current_user`。

## 危险 API
- SQL：AR 字符串条件、`find_by_sql`、`connection.execute`、`Arel.sql`、Sequel `lit`。
- 命令：`system` / `exec` / 反引号 / `%x` / `Open3` / `IO.popen` / `Kernel#open`。
- 代码：`eval` 系列、`send` / `constantize`。
- 反序列化：`YAML.load` / `Marshal.load` / `Oj.load`。
- 模板与文件：`render inline:` / `render file:` / `send_file`。
- 其他：跳转 `redirect_to`；`html_safe` / `raw`；Net::HTTP / HTTParty / Faraday 的 URL；Nokogiri `NOENT`；关闭 CSRF。

## 常见误报
- ERB 视图默认转义；`h()` / `sanitize` 之后的 `html_safe`。
- 插值的是表名、常量或 `quote` 结果的 SQL。
- `current_user.xxx.find(id)` 已按归属限定。
- `redirect_to` 到 `*_path` / `*_url` 辅助方法或模型对象。
- API 控制器（`ActionController::API`）不使用 Cookie 会话时，CSRF 跳过通常无害。
