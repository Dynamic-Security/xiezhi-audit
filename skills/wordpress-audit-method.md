---
name: wordpress-audit-method
description: WordPress 插件与主题的审计方法：AJAX / admin-post 动作、REST 路由的 permission_callback、后台页面与请求钩子、capability 与 nonce、$wpdb 与常见危险 API、误报。审计 WordPress 代码时读取。
category: audit_method
scope: global
applies_to:
  languages: [php]
  frameworks: [wordpress]
checklist:
  - id: wp-ajax-capability
    vuln_class: authz_function
    title: AJAX / admin-post 动作的 capability 检查
    check: wp_ajax_x 只要求登录（订阅者也可调用），wp_ajax_nopriv_x 与 admin_post_nopriv_x 完全公开；处理函数是否调用 current_user_can(具体能力) 再执行敏感操作（改设置、删数据、导出用户、上传文件）。只有 is_admin() 不是权限检查（admin-ajax.php 上恒为真）。
  - id: wp-nonce
    vuln_class: csrf
    title: nonce 校验
    check: 修改状态的 AJAX、admin-post、表单处理与 REST 写接口是否校验 nonce（check_ajax_referer / check_admin_referer / wp_verify_nonce，REST 依赖 X-WP-Nonce）；nonce 只防 CSRF，不能代替 capability 检查，也不能用 nonce 存在与否判断权限。
  - id: wp-rest-permission
    vuln_class: authz_function
    title: REST 路由的 permission_callback
    check: register_rest_route 缺少 permission_callback 或为 __return_true 时路由公开；确认这些路由不返回敏感数据、不修改状态；permission_callback 是否检查与操作相符的 capability，以及请求参数中的资源是否属于当前用户。
  - id: wp-admin-init-hook
    vuln_class: authz_function
    title: init / admin_init 钩子中的请求处理
    check: 在 init、admin_init、wp_loaded、template_redirect 钩子中读取 $_GET / $_POST 并执行操作的代码，admin_init 在未登录访问 admin-ajax.php / admin-post.php 时也会触发；检查是否先校验 capability 与 nonce。
  - id: wp-sqli
    vuln_class: sqli
    title: $wpdb 查询参数化
    check: $wpdb->query / get_results / get_row / get_var / get_col 的 SQL 是否经 $wpdb->prepare 占位；esc_sql 只转义引号，用在未加引号的数字或 ORDER BY 位置时仍可注入；LIKE 需要 $wpdb->esc_like。
  - id: wp-option-update
    vuln_class: business_logic
    title: 任意选项更新与权限提升
    check: update_option / update_user_meta / wp_update_user / add_user_meta 的键或值来自请求时，是否能修改 users_can_register、default_role、wp_capabilities 等，导致注册管理员或权限提升。
  - id: wp-object-injection
    vuln_class: deserialization
    title: 对象注入
    check: unserialize / maybe_unserialize 的数据是否来自请求、Cookie，或可由低权限用户写入的 meta / option；配合插件或主题中的 __destruct / __wakeup gadget 可执行代码。
  - id: wp-output-escaping
    vuln_class: xss
    title: 输出转义
    check: echo 请求参数或数据库内容时是否经 esc_html / esc_attr / esc_url / wp_kses；短代码属性（贡献者可以写入文章）与设置页字段是存储型 XSS 的常见来源。
---
# WordPress 审计要点

## 入口在哪里
- `add_action('wp_ajax_X', cb)` → `/wp-admin/admin-ajax.php?action=X`（需要登录，任何角色）；`wp_ajax_nopriv_X` → 未登录用户。
- `add_action('admin_post_X', cb)` → `/wp-admin/admin-post.php?action=X`；`admin_post_nopriv_X` 同理。
- `register_rest_route('ns/v1', '/route', [...])` → `/wp-json/ns/v1/route`，参数在 `$request['x']`。
- 后台页面：`add_menu_page / add_submenu_page / add_options_page(..., capability, slug, cb)` → `admin.php?page=slug`。
- 请求钩子：`init`、`admin_init`、`wp_loaded`、`template_redirect`、`parse_request` 中处理 `$_GET / $_POST` 的代码。
- 短代码 `add_shortcode`：属性来自文章内容（贡献者可写）。
- 插件目录下的独立 PHP 文件若没有 `defined('ABSPATH') || exit` 也能被直接请求。

## 鉴权机制
- capability：`current_user_can('manage_options')` 等；`is_user_logged_in()` 只判断登录。
- nonce：`wp_create_nonce` / `check_ajax_referer` / `wp_verify_nonce`（防 CSRF，不是授权）。
- REST：`permission_callback`。

## 危险 API
- SQL：`$wpdb->query / get_results / get_row / get_var / get_col` 拼接（未经 `prepare`）。
- 文件：`move_uploaded_file`、`wp_handle_upload` 关闭类型检查、`file_put_contents`、`unlink`、`include $_GET[...]`。
- SSRF：`wp_remote_get / wp_remote_post / download_url`（`wp_safe_remote_*` 会拒绝内网地址，但仍可访问任意公网地址）。
- 重定向：`wp_redirect`（`wp_safe_redirect` 只允许白名单主机）。
- 反序列化：`unserialize / maybe_unserialize`。
- 配置篡改：`update_option`、`update_user_meta`、`wp_update_user`、`wp_set_current_user`、`wp_set_auth_cookie`。

## 常见误报
- `$wpdb->prepare("... %d", $id)`，以及只把 `$wpdb->prefix` 插值进表名的 SQL。
- `maybe_unserialize(get_option(...))`：读取 WordPress 自己存储的数据（除非低权限用户能写入该选项）。
- 已在回调开头 `current_user_can` + `check_admin_referer` 的后台表单处理。
