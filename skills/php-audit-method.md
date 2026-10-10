---
name: php-audit-method
description: PHP（Laravel / Symfony / ThinkPHP / 原生脚本）入口、鉴权机制、各类危险 API 与常见误报的审计方法。审计 PHP 项目时读取；WordPress、Yii / CodeIgniter / Slim 另见专门的审计方法。
category: audit_method
scope: global
applies_to:
  languages: [php]
  frameworks: [laravel, symfony, thinkphp, php, wordpress, yii, codeigniter, slim]
---
# PHP 审计要点

## 入口在哪里
- **Laravel**：`routes/api.php`（框架默认加 `/api` 前缀与 `api` 中间件组）、`routes/web.php`（`web` 组，含 session 与 CSRF）。`Route::get/post/.../match/any`、`Route::resource / apiResource`（index、store、show、update、destroy…）、`Route::prefix()->middleware()->group(fn)` 与 `Route::group([...], fn)` 嵌套；处理函数写作 `[Ctrl::class, 'm']`、`'Ctrl@m'` 或闭包。
- **Symfony**：控制器方法上的 `#[Route('/x/{id}', methods: ['GET'])]`，类上的 `#[Route('/prefix')]` 是前缀；旧项目用 docblock `@Route`，或 `config/routes.yaml`。
- **ThinkPHP**：`route/*.php` 的 `Route::get('hello/:name', 'index/hello')`、`Route::rule`、`Route::group('blog', fn)`；未开启强制路由时 `/模块/控制器/方法` 也可直接访问（所有 public 方法都是入口）。
- **原生 PHP**：文件本身就是入口。顶层代码读 `$_GET / $_POST / $_REQUEST / $_COOKIE / $_FILES / php://input` 的脚本可被直接请求；被 `include` 的片段若放在 Web 根目录下同样可以直接访问。

## 鉴权机制
- Laravel：路由或组上的 `auth`、`auth:sanctum`、`can:ability,model`、`verified` 中间件；控制器构造函数 `$this->middleware('auth')->except([...])`（注意 except / only 漏掉的动作）；动作内 `$this->authorize('view', $model)`、`Gate::authorize`、Policy、FormRequest 的 `authorize()`。**只有认证中间件而没有 Policy / 归属条件时要查对象级越权。**
- Symfony：`#[IsGranted]`、`#[Security]`、`denyAccessUnlessGranted()`、Voter，`security.yaml` 的 `access_control`（按路径正则，注意顺序与前缀遗漏）。
- ThinkPHP：路由或全局中间件、控制器 `$middleware` 属性、基类 `initialize()` 中的登录检查。
- 原生脚本：文件开头的 `if (!isset($_SESSION['user'])) { header(...); exit; }`，或 `require 'check_login.php'`。**检查后缺少 `exit` 时后续代码照常执行。**

## 各类危险 API
- SQL 注入：`mysqli_query`、`$pdo->query / exec`、拼接后再 `prepare`；Laravel `DB::select / statement / unprepared` 与 `DB::raw`、`whereRaw / orderByRaw / selectRaw / havingRaw`（第二个参数的绑定数组是安全的，拼进第一个参数的不是）；Doctrine `createQuery("... $x")`；ThinkPHP `Db::query`、字符串形式的 `where("id=$id")`、`order($sort)`。排序、列名无法参数化，只能白名单。
- 命令执行：`system / exec / shell_exec / passthru / popen / proc_open`、反引号、`Process::fromShellCommandline`。`escapeshellarg` 包裹每个参数才安全；`escapeshellcmd` 不能防参数注入。
- 代码执行：`eval`、`assert(字符串)`、`create_function`、`preg_replace` 的 `/e`、`call_user_func($用户输入)`、动态 `$func()` / `new $class`。
- 文件包含与路径：`include / require` 带变量（LFI，配合日志 / 上传 / `php://filter`）；`file_get_contents / fopen / readfile / unlink / copy`、`response()->download`、`Storage::get`；`basename()` 可去掉目录部分。
- 反序列化：`unserialize`（POP 链、Laravel / Monolog / Guzzle gadget），以及 `phar://` 包装器触发的隐式反序列化（`file_exists`、`getimagesize` 等接收用户路径时）。
- SSRF：Guzzle `$client->request / get`、`Http::get`、`curl_setopt(CURLOPT_URL)`、`file_get_contents($url)`；注意 `gopher://`、`file://` 等协议与重定向跟随。
- 上传：`move_uploaded_file`、`$file->move / storeAs` 使用客户端文件名或扩展名；可执行目录下的 `.php / .phtml / .phar`。
- XSS：`echo $_GET[...]`、Blade `{!! $x !!}`（`{{ }}` 默认转义）、Twig `|raw`。SSTI：`Blade::render($字符串)`、`$twig->createTemplate($字符串)`。
- 开放重定向：`header('Location: ' . $x)`、`redirect($x)`、`redirect()->away($x)`、`new RedirectResponse($x)`。
- XXE：`simplexml_load_string` / `DOMDocument::loadXML` 带 `LIBXML_NOENT`、`LIBXML_DTDLOAD`。
- 变量覆盖：`extract($_GET)`、`parse_str($s)`（无第二参数）、`$$name`。
- 业务：Eloquent `Model::find($id) / findOrFail($id)`、`where('id', $id)->first()` 缺少归属条件；批量赋值 `$model->fill($request->all())` 且 `$guarded = []`；`->update(['status' | 'amount' | 'balance' => ...])`。

## 常见误报
- `DB::select('... ?', [$x])`、`where('col', $x)`、`where('name', 'like', '%'.$x.'%')`（值被绑定）。
- `orderByRaw` / `whereRaw` 的参数来自常量或白名单映射。
- 已由 `(int)`、`intval`、验证规则 `integer`、路由模型绑定（`{contract}` 自动 `findOrFail`，但仍需检查归属）约束的数值 id。
- 命令字符串虽由拼接构成，但每个变量都经 `escapeshellarg`。
- `include __DIR__ . '/x.php'`、`require $config['path']` 中的路径来自部署配置而非请求。
- 路由组已挂 `can:` 中间件或全局中间件，或控制器构造函数已统一 `authorize`。
