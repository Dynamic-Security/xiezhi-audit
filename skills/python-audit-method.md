---
name: python-audit-method
description: Python Web 项目（Django / DRF、Flask、FastAPI）的入口、鉴权机制、危险 API 与常见误报。审计 Python 仓库时读取；tornado / aiohttp / Sanic / falcon 另见专门的审计方法。
category: audit_method
scope: global
applies_to:
  languages: [python]
  frameworks: [django, flask, fastapi, tornado, aiohttp, sanic, falcon]
---
# Python Web 审计要点

## 入口在哪里
- **Django**：`urls.py` 的 `urlpatterns`（`path` / `re_path` / `url`），`include('app.urls')` 逐层拼接前缀；函数视图、`View.as_view()`（按类中定义的 `get/post/…` 分方法）、DRF `router.register(prefix, ViewSet)`（`list/create/retrieve/update/partial_update/destroy` 与 `@action`）。`ModelViewSet` 继承的动作没有显式方法体，处理逻辑在 `get_queryset` / `get_object` / serializer 中。
- **Flask**：`@app.route` / `@bp.get…`、`add_url_rule`、`MethodView.as_view`、Flask-RESTful `add_resource`；蓝图前缀以 `register_blueprint(url_prefix=…)` 为准（覆盖 `Blueprint(url_prefix=…)`）。
- **FastAPI**：`@app.get` / `@router.post…`，`APIRouter(prefix=…)` 与 `include_router(prefix=…)` 叠加。

## 鉴权机制（逐入口确认，不要只看全局）
- Django：`@login_required`、`@permission_required`、`@user_passes_test`、`LoginRequiredMixin` 等；`MIDDLEWARE` 中的 `AuthenticationMiddleware` 只负责识别用户，**不拦截匿名请求**。
- DRF：`permission_classes`（视图级覆盖 `REST_FRAMEWORK.DEFAULT_PERMISSION_CLASSES`；`AllowAny` 表示公开）；`IsAuthenticated` 只判断登录，**不判断对象归属**——对象级授权看 `has_object_permission` 与 `get_queryset` 是否按当前用户过滤（`get_object()` 才会调用对象级权限，自定义 `retrieve` 里直接 `Model.objects.get(pk=…)` 会绕过）。
- Flask：`@login_required`（flask-login）、`@jwt_required()`、`before_request` 钩子（只作用于所属 app / 蓝图；钩子返回 `None` 即放行）。
- FastAPI：`Depends(get_current_user)` / `Security(...)` 作为参数或 `dependencies=[…]`；依赖函数必须在失败时抛 `HTTPException`，只返回 `None` 不会拦截。
- IDOR：`Model.objects.get(pk=…)`、`get_object_or_404(Model, pk=…)`、`session.get(Model, id)`、`Model.query.get(id)` 之后是否比对 `owner / user / tenant`；过滤条件中是否带当前用户。

## 危险 API（按类别）
- sqli：`cursor.execute(f"…{x}")`、`"…" % x`、`"…" + x`、`"…".format(x)`；`Model.objects.raw` / `.extra` / `RawSQL`；SQLAlchemy `text(f"…")`。`cursor.execute(sql, params)` 占位符参数化是安全的；`ORDER BY` / 列名 / 表名无法参数化，要看是否白名单映射。
- cmdi：`os.system`、`os.popen`、`subprocess.*(…, shell=True)`；列表参数且 `shell=False` 时只剩参数注入风险（如以 `-` 开头的文件名）。
- code_injection：`eval` / `exec` / `compile`；ssti：`render_template_string(用户输入)`、`jinja2.Template(用户输入)`；`render_template('x.html', v=用户输入)` 自动转义，不是 SSTI。
- deserialization：`pickle.loads`、`yaml.load`（无 `SafeLoader`）、`jsonpickle.decode`、`marshal`、`shelve`。
- ssrf：`requests` / `httpx` / `urllib.request.urlopen` / `aiohttp` 的 URL 来自请求；检查 scheme / host 白名单与重定向（`allow_redirects`）。
- path_traversal：`open(os.path.join(base, name))`（`os.path.join` 遇到绝对路径会丢弃前缀）、`send_file`、`FileResponse`；`send_from_directory` 自带目录约束。
- open_redirect：`redirect(request.args['next'])`；`url_for` / `reverse` 生成的地址安全。xss：`Markup(x)`、`mark_safe(x)`、模板 `|safe`。xxe：`lxml.etree` 未设置 `resolve_entities=False`。

## 常见误报
- 参数化查询、常量命令（`subprocess.run(["pg_isready"])`）、`yaml.safe_load`、`ast.literal_eval`。
- Django ORM 普通查询（`filter(field=value)`）自动参数化；`extra()` 只有 `params=` 占位符时安全。
- 管理命令（`management/commands`）、迁移文件、测试与脚本不是 HTTP 入口。
- `request.GET.get('id')`、`dict.get` 不是按 ID 取对象。
