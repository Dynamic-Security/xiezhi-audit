// PHP full audit — symbols / calls, Laravel / Symfony / ThinkPHP / native entries, sinks, auth signals,
// Composer dependencies and outbound HTTP clients, on small inline sources (never executed).
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createSnapshot, declaredDependencies, Executor, extractConnections, SnapshotView, buildIndex, loadRules } from '@xiezhi/context';
import type { StructIndex } from '@xiezhi/contracts';

async function viewOf(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'ca-m11php-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return { view: new SnapshotView('repo', s.root, s.manifest), root };
}

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const { view, root } = await viewOf(files);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const byKey = (idx: StructIndex, k: string) => idx.entrypoints.find((e) => e.entryKey === k)!;
const sinksOf = (idx: StructIndex, category: string) => idx.sinks.filter((s) => s.category === category);

const CONTROLLER = `<?php
namespace App\\Http\\Controllers;

use App\\Services\\CustomerService;
use Illuminate\\Http\\Request;

class CustomerController extends Controller
{
    public function __construct(private CustomerService $customers)
    {
        $this->middleware('auth:sanctum')->except(['index']);
    }

    public function index(Request $request)
    {
        return $this->customers->list($request->input('sort'));
    }

    public function show(Request $request, $id)
    {
        return $this->present($this->customers->find($id));
    }

    public function update(Request $request, $id)
    {
        $this->authorize('update', $id);
        return $this->customers->find($id);
    }

    private function present($c)
    {
        return $c;
    }
}
`;

const SERVICE = `<?php
namespace App\\Services;

use App\\Models\\Customer;
use Illuminate\\Support\\Facades\\DB;

class CustomerService
{
    public function find($id)
    {
        return Customer::findOrFail($id);
    }

    public function list($sort)
    {
        $rows = DB::select("select * from customers order by $sort");
        $safe = DB::select('select * from customers where owner_id = ?', [1]);
        return Customer::query()->orderByRaw($sort)->get();
    }

    public function close($id)
    {
        $c = Customer::where('id', $id)->first();
        $c->status = 'closed';
        $c->save();
        Customer::where('id', $id)->update(['balance' => 0]);
        return helper_total($c);
    }
}

function helper_total($c)
{
    return 1;
}
`;

describe('PHP index', () => {
  it('symbols: namespaces, classes, methods, functions; qualified names and arity', async () => {
    const idx = await indexOf({ 'app/Services/CustomerService.php': SERVICE });
    const find = idx.symbols.find((s) => s.name === 'find')!;
    expect(find).toMatchObject({ kind: 'method', container: 'App\\Services.CustomerService', qualifiedName: 'App\\Services\\CustomerService::find' });
    expect(find.symbolId).toBe('repo:app/Services/CustomerService.php#App\\Services.CustomerService.find(1)');
    expect(idx.symbols.find((s) => s.name === 'CustomerService')).toMatchObject({ kind: 'class', qualifiedName: 'App\\Services\\CustomerService' });
    expect(idx.symbols.find((s) => s.name === 'helper_total')).toMatchObject({ kind: 'func', container: 'App\\Services' });
    expect(idx.symbols.some((s) => s.name === '<main>')).toBe(false);
  });

  it('calls: typed promoted properties, $this, static calls and same-namespace functions resolve', async () => {
    const idx = await indexOf({
      'app/Http/Controllers/CustomerController.php': CONTROLLER,
      'app/Services/CustomerService.php': SERVICE,
    });
    const edge = (from: string, callee: string) => idx.callEdges.find((e) => e.from.includes(from) && e.calleeText === callee);
    expect(edge('CustomerController.show(2)', '$this->customers->find')).toMatchObject({ confidence: 'resolved', to: expect.stringContaining('CustomerService.find(1)') });
    expect(edge('CustomerController.show(2)', '$this->present')).toMatchObject({ confidence: 'resolved', to: expect.stringContaining('CustomerController.present(1)') });
    expect(edge('CustomerService.close(1)', 'helper_total')).toMatchObject({ confidence: 'resolved', to: expect.stringContaining('App\\Services.helper_total(1)') });
    // Framework facades are outside the repository graph (no edge at all).
    expect(idx.callEdges.some((e) => e.calleeText === 'DB::select')).toBe(false);
  });

  it('Laravel: routes/api.php prefix, groups, middleware chains, resource expansion, handlers across files', async () => {
    const idx = await indexOf({
      'routes/api.php': `<?php
use App\\Http\\Controllers\\CustomerController;
use App\\Http\\Controllers\\ReportController;
use Illuminate\\Support\\Facades\\Route;

Route::get('/health', fn () => ['ok' => true]);
Route::middleware('auth:sanctum')->prefix('v1')->group(function () {
    Route::get('/customers/{id}', [CustomerController::class, 'show']);
    Route::prefix('admin')->group(function () {
        Route::post('/reports', 'ReportController@export')->middleware('can:export-reports');
    });
    Route::apiResource('customers', CustomerController::class)->only(['index', 'update']);
});
Route::group(['prefix' => 'public', 'middleware' => ['throttle:60,1']], function () {
    Route::match(['get', 'post'], '/ping', [ReportController::class, 'ping']);
});
$request->get('/not-a-route', 'x');
`,
      'app/Http/Controllers/CustomerController.php': CONTROLLER,
      'app/Http/Controllers/ReportController.php': `<?php
namespace App\\Http\\Controllers;
class ReportController extends Controller
{
    public function export() { return 1; }
    public function ping() { return 1; }
    public function show() { return 1; }
}
`,
      'app/Services/CustomerService.php': SERVICE,
    });
    expect(keys(idx)).toEqual([
      'GET /api/health', 'GET /api/public/ping', 'GET /api/v1/customers', 'GET /api/v1/customers/{}',
      'PATCH /api/v1/customers/{}', 'POST /api/public/ping', 'POST /api/v1/admin/reports', 'PUT /api/v1/customers/{}',
    ]);
    const show = byKey(idx, 'GET /api/v1/customers/{}');
    expect(show.framework).toBe('laravel');
    expect(show.handler).toBe('repo:app/Http/Controllers/CustomerController.php#App\\Http\\Controllers.CustomerController.show(2)');
    expect(show.path).toBe('app/Http/Controllers/CustomerController.php');
    expect(show.middlewares).toEqual(['auth:sanctum']);
    // Group middleware + constructor middleware (except index) of the controller.
    expect(show.authSignals).toContain('auth:sanctum');
    const exp = byKey(idx, 'POST /api/v1/admin/reports');
    expect(exp.handler).toContain('ReportController.export(0)');
    expect(exp.middlewares).toEqual(['auth:sanctum', 'can:export-reports']);
    expect(exp.authSignals).toEqual(['auth:sanctum', 'can:export-reports']);
    expect(byKey(idx, 'GET /api/public/ping').authSignals).toEqual([]);
    expect(byKey(idx, 'GET /api/health').handler).toBe('repo:routes/api.php#<main>(0)');
    // Resource actions map to controller methods; `update` also carries the in-action authorize() check.
    expect(byKey(idx, 'PUT /api/v1/customers/{}').handler).toContain('CustomerController.update(2)');
    expect(byKey(idx, 'PUT /api/v1/customers/{}').authSignals.join()).toContain("$this->authorize('update', $id)");
    expect(byKey(idx, 'GET /api/v1/customers').handler).toContain('CustomerController.index(1)');
    // Constructor middleware with ->except(['index']) targets the other actions only.
    const ctorSignals = idx.authSignals.filter((s) => s.ruleId === 'php.laravel.controller-middleware');
    expect(ctorSignals.map((s) => s.target.split('.').pop()).sort()).toEqual(['present(1)', 'show(2)', 'update(2)']);
  });

  it('Laravel sinks: DB raw strings with interpolation, orderByRaw, bindings as constant; business points', async () => {
    const idx = await indexOf({ 'app/Services/CustomerService.php': SERVICE });
    const sqli = sinksOf(idx, 'sqli');
    const at = (line: number) => sqli.find((s) => s.range.startLine === line);
    expect(at(16)).toMatchObject({ ruleId: 'php.laravel.db-raw', taintHint: 'string_concat', api: 'DB::select', symbolId: expect.stringContaining('CustomerService.list(1)') });
    expect(at(17)).toMatchObject({ ruleId: 'php.laravel.db-raw', taintHint: 'constant' });
    expect(at(18)).toMatchObject({ ruleId: 'php.laravel.raw-expr', api: 'orderByRaw' });
    const authz = sinksOf(idx, 'authz_object').map((s) => `${s.ruleId}:${s.range.startLine}`).sort();
    expect(authz).toEqual(['php.business.find-by-id:11', 'php.business.first-by-id:23']);
    const biz = sinksOf(idx, 'business_logic').map((s) => `${s.ruleId}:${s.range.startLine}`).sort();
    expect(biz).toEqual(['php.business.state-save:25', 'php.business.state-update:26']);
  });

  it('Symfony: #[Route] class prefix + method routes, methods list, #[IsGranted] on class / action', async () => {
    const idx = await indexOf({
      'src/Controller/InvoiceController.php': `<?php
namespace App\\Controller;

use Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController;
use Symfony\\Component\\Routing\\Attribute\\Route;
use Symfony\\Component\\Security\\Http\\Attribute\\IsGranted;

#[Route('/invoices')]
class InvoiceController extends AbstractController
{
    #[Route('/{id}', name: 'invoice_show', methods: ['GET'])]
    public function show(int $id): Response
    {
        $q = $this->em->createQuery("SELECT i FROM Invoice i WHERE i.id = " . $id);
        return $this->redirect($this->params['next']);
    }

    #[Route('/{id}/pay', methods: ['POST', 'PUT'])]
    #[IsGranted('ROLE_ACCOUNTANT')]
    public function pay(int $id): Response
    {
        $this->denyAccessUnlessGranted('ROLE_USER');
        return new Response('');
    }

    /**
     * @Route("/legacy", methods={"GET"})
     */
    public function legacy(): Response { return new Response(''); }

    public function helper(): void {}
}
`,
    });
    expect(keys(idx)).toEqual(['GET /invoices/legacy', 'GET /invoices/{}', 'POST /invoices/{}/pay', 'PUT /invoices/{}/pay']);
    expect(byKey(idx, 'GET /invoices/{}')).toMatchObject({ framework: 'symfony', handler: expect.stringContaining('InvoiceController.show(1)'), authSignals: [] });
    expect([...byKey(idx, 'POST /invoices/{}/pay').authSignals].sort()).toEqual(["$this->denyAccessUnlessGranted('ROLE_USER')", "IsGranted('ROLE_ACCOUNTANT')"]);
    expect(sinksOf(idx, 'sqli')[0]).toMatchObject({ ruleId: 'php.doctrine.query', taintHint: 'string_concat' });
    expect(sinksOf(idx, 'open_redirect')[0]).toMatchObject({ ruleId: 'php.symfony.redirect' });
  });

  it('ThinkPHP: Route::get / rule / group with controller/action handlers', async () => {
    const idx = await indexOf({
      'route/app.php': `<?php
use think\\facade\\Route;

Route::get('hello/:name', 'index/hello');
Route::rule('order/[:id]', 'Order/read', 'GET|POST');
Route::group('blog', function () {
    Route::post('save', 'blog/save');
})->middleware(\\app\\middleware\\Auth::class);
`,
      'app/controller/Index.php': `<?php
namespace app\\controller;
class Index { public function hello($name) { return Db::query("select * from t where name = '" . $name . "'"); } }
`,
      'app/controller/Blog.php': `<?php
namespace app\\controller;
class Blog { public function save() { return 1; } }
`,
    });
    expect(keys(idx)).toEqual(['GET /hello/{}', 'GET /order/{}', 'POST /blog/save', 'POST /order/{}']);
    expect(byKey(idx, 'GET /hello/{}')).toMatchObject({ framework: 'thinkphp', handler: expect.stringContaining('Index.hello(1)') });
    expect(byKey(idx, 'POST /blog/save')).toMatchObject({ handler: expect.stringContaining('Blog.save(0)'), middlewares: ['Auth'], authSignals: ['Auth'] });
    expect(sinksOf(idx, 'sqli')[0]).toMatchObject({ ruleId: 'php.thinkphp.db-query', taintHint: 'string_concat' });
  });

  it('native scripts: top-level superglobal reads are entries; session checks are auth signals; sinks in top-level code have a symbol', async () => {
    const idx = await indexOf({
      'public/admin/export.php': `<?php
session_start();
if (!isset($_SESSION['admin_id'])) {
    header('Location: /login.php');
    exit;
}
$table = $_GET['table'];
$rows = mysqli_query($conn, "SELECT * FROM " . $table);
system('tar czf /tmp/export.tgz ' . $_GET['dir']);
echo $_GET['msg'];
echo htmlspecialchars($_GET['msg']);
include 'pages/' . $_GET['page'] . '.php';
require __DIR__ . '/../lib/db.php';
$data = unserialize($_COOKIE['prefs']);
header('Location: ' . $_GET['next']);
`,
      'public/lib/db.php': `<?php
function db_connect() { return mysqli_connect('localhost', 'app', '', 'crm'); }
`,
      'public/ping.php': `<?php
echo 'ok';
`,
    });
    expect(keys(idx)).toEqual(['ANY /admin/export.php']);
    const e = byKey(idx, 'ANY /admin/export.php');
    expect(e).toMatchObject({ framework: 'php', handler: 'repo:public/admin/export.php#<main>(0)' });
    expect(e.authSignals).toEqual(["if (!isset($_SESSION['admin_id']))"]);
    const main = idx.symbols.find((s) => s.symbolId === e.handler)!;
    expect(main.range).toEqual({ startLine: 1, endLine: 16 });
    const cats = idx.sinks.filter((s) => s.path === 'public/admin/export.php').map((s) => `${s.category}:${s.range.startLine}`).sort();
    expect(cats).toEqual(['cmdi:9', 'deserialization:14', 'open_redirect:15', 'open_redirect:4', 'path_traversal:12', 'sqli:8', 'xss:10']);
    expect(idx.sinks.every((s) => s.symbolId)).toBe(true);
    expect(idx.sinks.find((s) => s.category === 'open_redirect' && s.range.startLine === 4)!.taintHint).toBe('constant');
  });

  it('native sinks: command / code / file / ssrf / xxe variants and their negatives', async () => {
    const idx = await indexOf({
      'src/Tools.php': `<?php
namespace App\\Tools;
class Tools
{
    public function run($host, $file, $url, $xml, $cb)
    {
        $a = shell_exec("ping -c 1 $host");
        $b = \`nslookup {$host}\`;
        $c = exec('uptime');
        eval($cb);
        call_user_func($cb, 1);
        call_user_func('strtoupper', 'x');
        $d = file_get_contents('/var/data/' . $file);
        $e = file_get_contents('https://api.example.com/rates');
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        $f = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
        $g = simplexml_load_string($xml);
        $h = $this->client->request('GET', $url);
        $this->pdo->prepare('SELECT * FROM t WHERE id = ?');
        $this->pdo->prepare("SELECT * FROM t ORDER BY $file");
        $this->db->where('name', 'like', '%' . $file . '%');
        move_uploaded_file($_FILES['f']['tmp_name'], '/uploads/' . $file);
        parse_str($url);
        parse_str($url, $out);
    }
}
`,
    });
    const s = idx.sinks.map((x) => `${x.range.startLine}:${x.category}:${x.taintHint ?? '-'}`).sort((a, b) => parseInt(a) - parseInt(b));
    expect(s).toEqual([
      '7:cmdi:string_concat', '8:cmdi:string_concat', '9:cmdi:constant', '10:code_injection:-', '11:code_injection:-',
      '13:path_traversal:string_concat', '14:ssrf:constant', '16:ssrf:-', '17:xxe:-', '19:ssrf:-',
      '21:sqli:string_concat', '23:file_upload:string_concat', '24:other:-',
    ]);
  });

  it('parse robustness: broken files and HTML templates never throw', async () => {
    const idx = await indexOf({
      'views/list.phtml': `<html><body><?php foreach ($rows as $r): ?><td><?= $r['name'] ?></td><?php endforeach; ?></body></html>\n`,
      'broken.php': `<?php\nclass { function ( { $x = ; \n`,
    });
    expect(idx.entrypoints).toEqual([]);
    expect(idx.gaps.filter((g) => g.reason === 'rule_error')).toEqual([]);
  });
});

describe('Composer dependencies', () => {
  it('composer.json require / require-dev (no php / ext-*), exact versions only; composer.lock wins', async () => {
    const { view } = await viewOf({
      'composer.json': JSON.stringify({
        require: { php: '^8.1', 'ext-json': '*', 'laravel/framework': '^10.0', 'guzzlehttp/guzzle': '7.5.0' },
        'require-dev': { 'phpunit/phpunit': '^10.0' },
      }, null, 2),
      'tools/composer.json': JSON.stringify({ require: { 'monolog/monolog': 'v2.9.1' } }, null, 2),
      'tools/composer.lock': JSON.stringify({ packages: [{ name: 'monolog/monolog', version: 'v2.9.1' }], 'packages-dev': [{ name: 'phpunit/php-timer', version: '6.0.0' }] }),
    });
    const deps = declaredDependencies(view).filter((d) => d.ecosystem === 'composer');
    const by = (n: string) => deps.filter((d) => d.name === n);
    expect(by('php')).toEqual([]);
    expect(by('ext-json')).toEqual([]);
    expect(by('laravel/framework')[0]).toMatchObject({ version: null, path: 'composer.json', line: 5 });
    expect(by('guzzlehttp/guzzle')[0]).toMatchObject({ version: '7.5.0' });
    expect(by('phpunit/phpunit')[0]).toMatchObject({ version: null });
    expect(by('monolog/monolog')).toEqual([expect.objectContaining({ version: '2.9.1', path: 'tools/composer.lock' })]);
    expect(by('phpunit/php-timer')[0]).toMatchObject({ version: '6.0.0' });
  });
});

describe('PHP outbound HTTP clients', () => {
  it('Guzzle, base_uri clients, Laravel Http, curl and file_get_contents(URL)', async () => {
    const { view } = await viewOf({
      'app/Clients/Billing.php': `<?php
namespace App\\Clients;
use GuzzleHttp\\Client;
use Illuminate\\Support\\Facades\\Http;
class Billing
{
    public function run($id)
    {
        $client = new Client(['base_uri' => 'http://billing-svc/api/']);
        $client->request('GET', 'invoices/' . $id);
        $client->post('/api/charges');
        Http::get('http://user-svc/api/users/' . $id);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'http://audit-svc/api/events');
        file_get_contents('http://rates-svc/latest');
        $this->cache->get('invoices/1');
    }
}
`,
    });
    const conns = (await extractConnections(view, null, null)).filter((c) => c.kind === 'http' && c.side === 'consumes');
    const got = conns.map((c) => `${c.key.method ?? '*'} ${c.serviceHint ?? '-'} ${c.key.pathTemplate} ${c.extraction}`).sort();
    expect(got).toEqual([
      '* audit-svc /api/events literal',
      'GET billing-svc /api/invoices/{?} partial',
      'GET rates-svc /latest literal',
      'GET user-svc /api/users/{?} partial',
      'POST billing-svc /api/charges literal',
    ]);
  });
});
