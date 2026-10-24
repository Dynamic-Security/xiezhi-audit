// PHP framework coverage — WordPress (AJAX / admin-post actions, request hooks, REST routes,
// admin pages, $wpdb and WP API sinks), Yii 2, CodeIgniter 3 / 4, Slim. Small inline sources, never executed.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { Executor, SnapshotView, buildIndex, createSnapshot, loadRules } from '@xiezhi/context';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1122-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const view = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const entries = (idx: StructIndex, key: string) => idx.entrypoints.filter((e) => e.entryKey === key);
const entry = (idx: StructIndex, key: string) => entries(idx, key)[0]!;
const sinkApis = (idx: StructIndex, category: string) => idx.sinks.filter((s) => s.category === category).map((s) => s.api).sort();

describe('WordPress', () => {
  it('AJAX and admin-post actions, request hooks, REST routes, admin pages, capability / nonce checks and WP sinks', async () => {
    const idx = await indexOf({
      'wp-content/plugins/shop/shop.php': `<?php
/** Plugin Name: Shop */
if (!defined('ABSPATH')) exit;
require_once __DIR__ . '/includes/handlers.php';
add_action('wp_ajax_shop_export', 'shop_export');
add_action('wp_ajax_nopriv_shop_track', 'shop_track');
add_action('admin_post_shop_save', array(__CLASS__, 'save'));
add_action('admin_init', 'shop_admin_init');
add_action('init', 'shop_boot');
add_action('rest_api_init', function () {
  register_rest_route('shop/v1', '/orders/(?P<id>\\d+)', array(
    array('methods' => WP_REST_Server::READABLE, 'callback' => 'shop_get_order', 'permission_callback' => '__return_true'),
    array('methods' => 'DELETE', 'callback' => 'shop_delete_order', 'permission_callback' => function () { return current_user_can('manage_options'); }),
  ));
  register_rest_route('shop/v1', '/coupons', array('methods' => 'POST', 'callback' => 'shop_coupon'));
});
add_action('admin_menu', function () {
  add_menu_page('Shop', 'Shop', 'manage_options', 'shop-settings', 'shop_settings_page');
});
function shop_track() {
  global $wpdb;
  $wpdb->get_results("SELECT * FROM {$wpdb->prefix}orders WHERE id = " . $_GET['id']);
  $wpdb->get_results($wpdb->prepare("SELECT * FROM t WHERE id = %d", $_GET['id']));
}
function shop_admin_init() {
  if (isset($_POST['shop_option'])) update_option($_POST['name'], $_POST['value']);
}
function shop_boot() { load_plugin_textdomain('shop'); }
function shop_settings_page() {}
`,
      'wp-content/plugins/shop/includes/handlers.php': `<?php
function shop_export() {
  check_ajax_referer('shop', 'nonce');
  if (!current_user_can('export')) wp_die();
  wp_redirect($_GET['back']);
}
function shop_get_order($req) { return wp_remote_get($req['url']); }
function shop_delete_order($req) {}
function shop_coupon($req) { return maybe_unserialize($req['data']); }
`,
    });
    expect(keys(idx)).toEqual([
      'ANY /wp-admin/admin-ajax.php?action=shop_export', 'ANY /wp-admin/admin-ajax.php?action=shop_track', 'ANY /wp-admin/admin-post.php?action=shop_save',
      'ANY /wp-admin/admin.php?page=shop-settings', 'ANY /{}?wp_hook=admin_init', 'DELETE /wp-json/shop/v1/orders/{}', 'GET /wp-json/shop/v1/orders/{}', 'POST /wp-json/shop/v1/coupons',
    ]);
    const exp = entry(idx, 'ANY /wp-admin/admin-ajax.php?action=shop_export');
    expect(exp.framework).toBe('wordpress');
    expect(exp.handler).toBe('repo:wp-content/plugins/shop/includes/handlers.php#wp-content/plugins/shop/includes/handlers.php.shop_export(0)');
    expect(exp.authSignals).toEqual(['wp_ajax: requires login']);
    const track = entry(idx, 'ANY /wp-admin/admin-ajax.php?action=shop_track');
    expect(track.middlewares).toEqual(['wp_ajax_nopriv: no login required']);
    expect(track.authSignals).toEqual([]);
    expect(entry(idx, 'ANY /{}?wp_hook=admin_init').authSignals).toEqual([]);
    expect(entry(idx, 'GET /wp-json/shop/v1/orders/{}').authSignals).toEqual([]);
    expect(entry(idx, 'GET /wp-json/shop/v1/orders/{}').middlewares).toEqual(['permission_callback: __return_true (public)']);
    expect(entry(idx, 'DELETE /wp-json/shop/v1/orders/{}').authSignals).toContain("auth call: current_user_can('manage_options')");
    expect(entry(idx, 'POST /wp-json/shop/v1/coupons').middlewares).toEqual(['permission_callback: missing (public)']);
    expect(entry(idx, 'ANY /wp-admin/admin.php?page=shop-settings').authSignals).toEqual(['capability: manage_options']);
    expect(sinkApis(idx, 'sqli')).toEqual(['$wpdb->get_results']);
    expect(sinkApis(idx, 'open_redirect')).toEqual(['wp_redirect']);
    expect(sinkApis(idx, 'ssrf')).toEqual(['wp_remote_get']);
    expect(sinkApis(idx, 'business_logic')).toContain('update_option');
  });
});

describe('Yii 2', () => {
  it('controller actions, modules, VerbFilter and AccessControl', async () => {
    const idx = await indexOf({
      'modules/admin/controllers/UserProfileController.php': `<?php
namespace app\\modules\\admin\\controllers;
use yii\\web\\Controller;
use yii\\filters\\AccessControl;
use yii\\filters\\VerbFilter;
class UserProfileController extends Controller {
  public function behaviors() {
    return [
      'access' => ['class' => AccessControl::class, 'rules' => [
        ['actions' => ['view'], 'allow' => true, 'roles' => ['?']],
        ['actions' => ['delete-all', 'index'], 'allow' => true, 'roles' => ['admin']],
      ]],
      'verbs' => ['class' => VerbFilter::class, 'actions' => ['delete-all' => ['POST']]],
    ];
  }
  public function actionIndex() {}
  public function actionView($id) { return \\Yii::$app->db->createCommand("SELECT * FROM u WHERE id = $id")->queryOne(); }
  public function actionDeleteAll() {}
  protected function actionHidden() {}
}
`,
    });
    expect(keys(idx)).toEqual(['ANY /admin/user-profile/index', 'ANY /admin/user-profile/view', 'POST /admin/user-profile/delete-all']);
    expect(entry(idx, 'POST /admin/user-profile/delete-all').framework).toBe('yii');
    expect(entry(idx, 'POST /admin/user-profile/delete-all').authSignals).toEqual(['AccessControl roles(admin)']);
    expect(entry(idx, 'ANY /admin/user-profile/view').authSignals).toEqual([]);
    expect(sinkApis(idx, 'sqli')).toContain('createCommand');
  });
});

describe('CodeIgniter', () => {
  it('CodeIgniter 3 controllers, constructor login checks and config/routes.php', async () => {
    const idx = await indexOf({
      'application/controllers/Blog.php': `<?php
class Blog extends CI_Controller {
  public function index() {}
  public function view($id) { $this->db->query("SELECT * FROM posts WHERE id = " . $id); }
  private function _helper() {}
}
`,
      'application/controllers/admin/Users.php': `<?php
class Users extends MY_Controller {
  public function __construct() {
    parent::__construct();
    if (!$this->session->userdata('logged_in')) redirect('login');
  }
  public function delete($id) {}
}
`,
      'application/config/routes.php': `<?php
$route['default_controller'] = 'blog';
$route['posts/(:num)'] = 'blog/view/$1';
$route['api/users']['post'] = 'admin/users/delete';
`,
    });
    expect(keys(idx)).toEqual(['ANY /admin/users/delete', 'ANY /blog/index', 'ANY /blog/view', 'ANY /posts/{}', 'POST /api/users']);
    const del = entry(idx, 'ANY /admin/users/delete');
    expect(del.framework).toBe('codeigniter');
    expect(del.authSignals).toEqual(['auth check in __construct']);
    expect(entry(idx, 'ANY /posts/{}').handler).toBe('repo:application/controllers/Blog.php#application/controllers/Blog.php.Blog.view(1)');
  });

  it('CodeIgniter 4 routes with groups, filters and resources', async () => {
    const idx = await indexOf({
      'composer.json': JSON.stringify({ require: { 'codeigniter4/framework': '^4.4' } }),
      'app/Config/Routes.php': `<?php
use CodeIgniter\\Router\\RouteCollection;
/** @var RouteCollection $routes */
$routes->get('/', 'Home::index');
$routes->get('news/(:segment)', 'News::show/$1');
$routes->group('admin', ['filter' => 'auth'], static function ($routes) {
  $routes->post('users/(:num)/delete', '\\App\\Controllers\\Admin\\Users::delete/$1', ['filter' => 'role:admin']);
  $routes->resource('photos');
});
$routes->match(['get', 'post'], 'contact', 'Pages::contact');
`,
      'app/Controllers/News.php': `<?php
namespace App\\Controllers;
class News extends BaseController { public function show($slug) {} }
`,
    });
    expect(keys(idx)).toContain('POST /admin/users/{}/delete');
    expect(keys(idx)).toContain('DELETE /admin/photos/{}');
    expect(keys(idx)).toContain('GET /news/{}');
    expect(keys(idx)).toContain('POST /contact');
    const del = entry(idx, 'POST /admin/users/{}/delete');
    expect(del.framework).toBe('codeigniter');
    expect(del.authSignals).toEqual(['filter: auth', 'filter: role:admin']);
    expect(entry(idx, 'GET /news/{}').handler).toBe('repo:app/Controllers/News.php#App\\Controllers.News.show(1)');
  });
});

describe('Slim', () => {
  it('routes, groups, route / group / app middleware and handler forms', async () => {
    const idx = await indexOf({
      'composer.json': JSON.stringify({ require: { 'slim/slim': '^4.12' } }),
      'app/routes.php': `<?php
use App\\Action\\UserAction;
use Slim\\Routing\\RouteCollectorProxy;
return function ($app) {
  $app->add(SessionMiddleware::class);
  $app->get('/health', function ($request, $response) { return $response; });
  $app->group('/api', function (RouteCollectorProxy $group) {
    $group->get('/users/{id}', UserAction::class . ':view');
    $group->map(['PUT', 'PATCH'], '/users/{id}', [UserAction::class, 'update'])->add(new AdminOnly());
  })->add(JwtAuthMiddleware::class);
};
`,
      'src/Action/UserAction.php': `<?php
namespace App\\Action;
class UserAction { public function view($req, $res, $args) {} public function update($req, $res, $args) {} }
`,
    });
    expect(keys(idx)).toEqual(['GET /api/users/{}', 'GET /health', 'PATCH /api/users/{}', 'PUT /api/users/{}']);
    const put = entry(idx, 'PUT /api/users/{}');
    expect(put.framework).toBe('slim');
    expect(put.middlewares).toEqual(['SessionMiddleware', 'JwtAuthMiddleware', 'new AdminOnly()']);
    expect(put.authSignals).toEqual(['SessionMiddleware', 'JwtAuthMiddleware', 'new AdminOnly()']);
    expect(put.handler).toBe('repo:src/Action/UserAction.php#App\\Action.UserAction.update(3)');
  });
});
