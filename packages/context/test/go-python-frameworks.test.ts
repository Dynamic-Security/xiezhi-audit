// Go (beego, go-zero, kratos / grpc-gateway HTTP bindings) and Python (tornado, aiohttp, sanic,
// falcon) framework coverage. Small inline sources, never executed.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { Executor, SnapshotView, buildIndex, createSnapshot, loadRules, scanProto } from '@xiezhi/context';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1123-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const view = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key)!;

describe('proto HTTP bindings', () => {
  it('scanProto reads google.api.http bindings and keeps rpcs after option blocks', () => {
    const [svc] = scanProto(`syntax = "proto3";
package shop.v1;
import "google/api/annotations.proto";
service Orders {
  rpc GetOrder (GetOrderRequest) returns (Order) {
    option (google.api.http) = {
      get: "/v1/orders/{id}"
      additional_bindings { post: "/v1/orders/{id}:query" body: "*" }
    };
  }
  rpc ListOrders (ListOrdersRequest) returns (ListOrdersReply);
  rpc Rename (RenameRequest) returns (Order) {
    option (google.api.http) = { patch: "/v1/{name=orders/*}" body: "*" };
  }
}
`);
    expect(svc!.rpcs).toEqual(['GetOrder', 'ListOrders', 'Rename']);
    expect(svc!.http).toEqual({
      GetOrder: [{ method: 'GET', path: '/v1/orders/{id}' }, { method: 'POST', path: '/v1/orders/{id}:query' }],
      Rename: [{ method: 'PATCH', path: '/v1/{name}' }],
    });
  });

  it('kratos services get HTTP entries next to their gRPC entries', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/shop\n\ngo 1.22\n',
      'api/order.proto': `syntax = "proto3";
package shop.v1;
service Orders {
  rpc GetOrder (GetOrderRequest) returns (Order) { option (google.api.http) = { get: "/v1/orders/{id}" }; }
  rpc ListOrders (ListOrdersRequest) returns (ListOrdersReply);
}
`,
      'internal/service/order.go': `package service

import (
	"context"

	v1 "example.com/shop/api"
	"github.com/go-kratos/kratos/v2/log"
)

type OrderService struct {
	v1.UnimplementedOrdersServer
	log *log.Helper
}

func (s *OrderService) GetOrder(ctx context.Context, req *v1.GetOrderRequest) (*v1.Order, error) { return nil, nil }
func (s *OrderService) ListOrders(ctx context.Context, req *v1.ListOrdersRequest) (*v1.ListOrdersReply, error) { return nil, nil }
`,
    });
    expect(keys(idx)).toEqual(['GET /v1/orders/{}', 'rpc:shop.v1.Orders/GetOrder', 'rpc:shop.v1.Orders/ListOrders']);
    expect(entry(idx, 'GET /v1/orders/{}').framework).toBe('kratos');
    expect(entry(idx, 'GET /v1/orders/{}').handler).toBe(entry(idx, 'rpc:shop.v1.Orders/GetOrder').handler);
  });
});

describe('beego', () => {
  it('Router with and without mappings, namespaces, Include annotations, function routes and filters', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/blog\n\ngo 1.20\n',
      'routers/router.go': `package routers

import (
	"example.com/blog/controllers"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/context"
)

func init() {
	beego.InsertFilter("/v1/admin/*", beego.BeforeRouter, controllers.AuthFilter)
	beego.Router("/", &controllers.MainController{})
	beego.Router("/post/:id", &controllers.PostController{}, "get:Show;post,put:Save")
	ns := beego.NewNamespace("/v1",
		beego.NSNamespace("/admin", beego.NSInclude(&controllers.AdminController{})),
		beego.NSGet("/ping", func(ctx *context.Context) { ctx.Output.Body([]byte("pong")) }),
	)
	beego.AddNamespace(ns)
}
`,
      'controllers/main.go': `package controllers

import beego "github.com/beego/beego/v2/server/web"

type MainController struct{ beego.Controller }

func (c *MainController) Get()  {}
func (c *MainController) Post() {}

type PostController struct{ beego.Controller }

func (c *PostController) Show() {}
func (c *PostController) Save() {}

type AdminController struct{ beego.Controller }

// @router /users/:id [get]
func (c *AdminController) GetUser() {}

// @router /users [post,delete]
func (c *AdminController) EditUsers() {}
`,
    });
    expect(keys(idx)).toEqual(['DELETE /v1/admin/users', 'GET /', 'GET /post/{}', 'GET /v1/admin/users/{}', 'GET /v1/ping', 'POST /', 'POST /post/{}', 'POST /v1/admin/users', 'PUT /post/{}']);
    const show = entry(idx, 'GET /post/{}');
    expect(show.framework).toBe('beego');
    expect(show.handler).toMatch(/controllers\/main\.go#.*PostController\.Show\(0\)$/);
    expect(entry(idx, 'GET /v1/admin/users/{}').handler).toMatch(/AdminController\.GetUser\(0\)$/);
    expect(entry(idx, 'GET /v1/admin/users/{}').authSignals).toEqual(['InsertFilter(/v1/admin/*): controllers.AuthFilter']);
    expect(entry(idx, 'GET /').authSignals).toEqual([]);
  });
});

describe('go-zero', () => {
  it('generated routes.go: AddRoutes with prefix, JWT and middlewares', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/mall\n\ngo 1.21\n',
      'internal/handler/routes.go': `package handler

import (
	"net/http"

	user "example.com/mall/internal/handler/user"
	"example.com/mall/internal/svc"

	"github.com/zeromicro/go-zero/rest"
)

func RegisterHandlers(server *rest.Server, serverCtx *svc.ServiceContext) {
	server.AddRoutes(
		[]rest.Route{
			{Method: http.MethodPost, Path: "/user/login", Handler: user.LoginHandler(serverCtx)},
		},
		rest.WithPrefix("/api"),
	)
	server.AddRoutes(
		rest.WithMiddlewares(
			[]rest.Middleware{serverCtx.AdminCheck},
			[]rest.Route{
				{Method: http.MethodGet, Path: "/user/:id", Handler: user.UserInfoHandler(serverCtx)},
			}...,
		),
		rest.WithJwt(serverCtx.Config.Auth.AccessSecret),
		rest.WithPrefix("/api"),
	)
}
`,
      'internal/handler/user/userinfohandler.go': `package user

import (
	"net/http"

	"example.com/mall/internal/svc"
)

func UserInfoHandler(svcCtx *svc.ServiceContext) http.HandlerFunc { return func(w http.ResponseWriter, r *http.Request) {} }
func LoginHandler(svcCtx *svc.ServiceContext) http.HandlerFunc { return func(w http.ResponseWriter, r *http.Request) {} }
`,
    });
    expect(keys(idx)).toEqual(['GET /api/user/{}', 'POST /api/user/login']);
    const info = entry(idx, 'GET /api/user/{}');
    expect(info.framework).toBe('go-zero');
    expect(info.handler).toMatch(/userinfohandler\.go#.*UserInfoHandler\(1\)$/);
    expect(info.middlewares).toEqual(['serverCtx.AdminCheck', 'rest.WithJwt(serverCtx.Config.Auth.AccessSecret)']);
    expect(info.authSignals).toEqual(['serverCtx.AdminCheck', 'rest.WithJwt(serverCtx.Config.Auth.AccessSecret)']);
    expect(entry(idx, 'POST /api/user/login').authSignals).toEqual([]);
  });
});

describe('Python frameworks', () => {
  it('tornado Application handlers (regex patterns, @authenticated, handlers in another module)', async () => {
    const idx = await indexOf({
      'app.py': `import tornado.web
from handlers import UserHandler, LoginHandler

def make_app():
    return tornado.web.Application([
        (r"/users/([0-9]+)", UserHandler),
        tornado.web.url(r"/login", LoginHandler, name="login"),
    ])
`,
      'handlers.py': `import tornado.web

class UserHandler(tornado.web.RequestHandler):
    @tornado.web.authenticated
    def get(self, user_id):
        self.write(user_id)

    def delete(self, user_id):
        pass

class LoginHandler(tornado.web.RequestHandler):
    def post(self):
        pass
`,
    });
    expect(keys(idx)).toEqual(['DELETE /users/{}', 'GET /users/{}', 'POST /login']);
    const get = entry(idx, 'GET /users/{}');
    expect(get.framework).toBe('tornado');
    expect(get.authSignals).toEqual(['@tornado.web.authenticated']);
    expect(entry(idx, 'DELETE /users/{}').authSignals).toEqual([]);
  });

  it('aiohttp router calls, add_routes / web.* routes, RouteTableDef and app middlewares', async () => {
    const idx = await indexOf({
      'server.py': `from aiohttp import web
from views import list_items, ItemView

routes = web.RouteTableDef()

@routes.get('/health')
async def health(request):
    return web.Response(text='ok')

@routes.view('/items/{id}')
class ItemDetail(web.View):
    async def get(self):
        pass
    async def put(self):
        pass

def create_app():
    app = web.Application(middlewares=[auth_middleware])
    app.router.add_get('/items', list_items)
    app.add_routes([web.post('/items', create_item), web.view('/item-view', ItemView)])
    app.add_routes(routes)
    return app

async def create_item(request):
    pass
`,
      'views.py': `from aiohttp import web

async def list_items(request):
    pass

class ItemView(web.View):
    async def delete(self):
        pass
`,
    });
    expect(keys(idx)).toEqual(['DELETE /item-view', 'GET /health', 'GET /items', 'GET /items/{}', 'POST /items', 'PUT /items/{}']);
    expect(entry(idx, 'GET /items').framework).toBe('aiohttp');
    expect(entry(idx, 'GET /items').authSignals).toEqual(['auth_middleware']);
    expect(entry(idx, 'POST /items').handler).toMatch(/#server\.create_item\(1\)$/);
  });

  it('sanic routes and blueprints; falcon resources with suffixes and hooks', async () => {
    const idx = await indexOf({
      'sanic_app.py': `from sanic import Sanic, Blueprint
from sanic.response import json
from sanic_jwt.decorators import protected

app = Sanic("shop")
bp = Blueprint("orders", url_prefix="/orders")

@app.route("/", methods=["GET", "POST"])
async def index(request):
    return json({})

@bp.get("/<order_id:int>")
@protected()
async def get_order(request, order_id):
    return json({})

app.blueprint(bp)
`,
      'falcon_app.py': `import falcon
from resources import ThingsResource

app = falcon.App(middleware=[AuthMiddleware()])
things = ThingsResource()
app.add_route('/things', ThingsResource())
app.add_route('/things/{thing_id}', ThingsResource(), suffix='item')
`,
      'resources.py': `import falcon

class ThingsResource:
    def on_get(self, req, resp):
        pass

    @falcon.before(validate_token)
    def on_post(self, req, resp):
        pass

    def on_get_item(self, req, resp, thing_id):
        pass
`,
    });
    expect(keys(idx)).toEqual(['GET /', 'GET /orders/{}', 'GET /things', 'GET /things/{}', 'POST /', 'POST /things']);
    expect(entry(idx, 'GET /orders/{}').framework).toBe('sanic');
    expect(entry(idx, 'GET /orders/{}').authSignals).toEqual(['@protected()']);
    expect(entry(idx, 'POST /things').framework).toBe('falcon');
    expect(entry(idx, 'POST /things').authSignals).toEqual(['AuthMiddleware()', '@falcon.before(validate_token)']);
    expect(entry(idx, 'GET /things/{}').handler).toBe('repo:resources.py#resources.ThingsResource.on_get_item(3)');
  });
});
