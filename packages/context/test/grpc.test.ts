// GRPC service implementations as `rpc` entries in Java, Go and C#, named after the .proto.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { buildIndex, createSnapshot, Executor, extractConnections, loadRules, SnapshotView } from '@xiezhi/context';

async function viewOf(files: Record<string, string>): Promise<SnapshotView> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m11grpc-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return new SnapshotView('repo', s.root, s.manifest);
}
const indexOf = async (files: Record<string, string>) => (await buildIndex(await viewOf(files), loadRules(), { indexesDir: mkdtempSync(join(tmpdir(), 'ca-m11grpc-i-')) })).index;
const rpcs = (idx: StructIndex) => idx.entrypoints.filter((e) => e.kind === 'rpc').map((e) => e.entryKey).sort();
const rpc = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key)!;

const PROTO = `syntax = "proto3";
package shop.orders.v1;
// service Fake { rpc Nope(A) returns (B); }
service OrderService {
  rpc GetOrder (GetOrderRequest) returns (Order);
  rpc CancelOrder (CancelOrderRequest) returns (Order);
}
`;

describe('gRPC service entries', () => {
  it('Java: ImplBase subclasses, proto rpc names, @GrpcService interceptors and method annotations', async () => {
    const idx = await indexOf({
      'proto/orders.proto': PROTO,
      'src/main/java/shop/OrderGrpcService.java': `package shop;
import io.grpc.stub.StreamObserver;
@GrpcService(interceptors = { JwtAuthInterceptor.class, LoggingInterceptor.class })
public class OrderGrpcService extends OrderServiceGrpc.OrderServiceImplBase {
    @Override
    public void getOrder(GetOrderRequest req, StreamObserver<Order> obs) { obs.onNext(repo.find(req.getId())); }
    @Override
    @PreAuthorize("hasRole('ADMIN')")
    public void cancelOrder(CancelOrderRequest req, StreamObserver<Order> obs) { }
    public void helper() { }
}
`,
    });
    expect(rpcs(idx)).toEqual(['rpc:shop.orders.v1.OrderService/CancelOrder', 'rpc:shop.orders.v1.OrderService/GetOrder']);
    const get = rpc(idx, 'rpc:shop.orders.v1.OrderService/GetOrder');
    expect(get).toMatchObject({ kind: 'rpc', framework: 'grpc', middlewares: ['JwtAuthInterceptor', 'LoggingInterceptor'], authSignals: ['JwtAuthInterceptor'] });
    expect(get.httpMethod).toBeUndefined();
    expect(get.handler).toMatch(/OrderGrpcService\.getOrder\(2\)$/);
    expect(rpc(idx, 'rpc:shop.orders.v1.OrderService/CancelOrder').authSignals).toEqual(expect.arrayContaining(['@PreAuthorize("hasRole(\'ADMIN\')")', 'JwtAuthInterceptor']));
  });

  it('Go: embedded Unimplemented…Server with methods in another file, Register… with &T{}, server interceptors', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/shop\n\ngo 1.22\n',
      'api/orders.proto': PROTO,
      'internal/grpcsrv/server.go': `package grpcsrv

import pb "example.com/shop/gen/orders/v1"

type orderServer struct {
	pb.UnimplementedOrderServiceServer
	repo Repo
}
`,
      'internal/grpcsrv/orders.go': `package grpcsrv

import (
	"context"
	pb "example.com/shop/gen/orders/v1"
)

func (s *orderServer) GetOrder(ctx context.Context, req *pb.GetOrderRequest) (*pb.Order, error) { return s.repo.Find(req.Id), nil }
func (s *orderServer) CancelOrder(ctx context.Context, req *pb.CancelOrderRequest) (*pb.Order, error) { return nil, nil }
func (s *orderServer) Close() error { return nil }
`,
      'cmd/server/main.go': `package main

import (
	"google.golang.org/grpc"
	pb "example.com/shop/gen/orders/v1"
	"example.com/shop/internal/grpcsrv"
	"example.com/shop/internal/auth"
)

func main() {
	s := grpc.NewServer(grpc.ChainUnaryInterceptor(auth.UnaryAuthInterceptor, logging.Unary()))
	pb.RegisterOrderServiceServer(s, grpcsrv.New())
}
`,
      'legacy/legacy.go': `package legacy

import pb "example.com/shop/gen/legacy"

type legacyServer struct{}

func (l *legacyServer) Ping(ctx context.Context, in *pb.PingRequest) (*pb.Pong, error) { return nil, nil }
func (l *legacyServer) unexported() {}

func Register(s *grpc.Server) { pb.RegisterLegacyServer(s, &legacyServer{}) }
`,
    });
    expect(rpcs(idx)).toEqual(['rpc:Legacy/Ping', 'rpc:shop.orders.v1.OrderService/CancelOrder', 'rpc:shop.orders.v1.OrderService/GetOrder']);
    const get = rpc(idx, 'rpc:shop.orders.v1.OrderService/GetOrder');
    expect(get.handler).toMatch(/internal\/grpcsrv\/orders\.go#grpcsrv\.orderServer\.GetOrder\(2\)$/);
    expect(get.middlewares).toEqual(['grpc.ChainUnaryInterceptor(auth.UnaryAuthInterceptor, logging.Unary())']);
    expect(get.authSignals).toEqual(get.middlewares);
  });

  it('Go: interceptors stay with the server they are installed on (several servers in one repository)', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/ex\n\ngo 1.22\n',
      'secure/main.go': `package main

import "google.golang.org/grpc"

type server struct{ pb.UnimplementedEchoServer }

func (s *server) UnaryEcho(ctx context.Context, in *pb.EchoRequest) (*pb.EchoResponse, error) { return nil, nil }

func main() {
	s := grpc.NewServer(grpc.UnaryInterceptor(ensureValidToken))
	pb.RegisterEchoServer(s, &server{})
}
`,
      'plain/main.go': `package main

import "google.golang.org/grpc"

type server struct{ pb.UnimplementedEchoServer }

func (s *server) UnaryEcho(ctx context.Context, in *pb.EchoRequest) (*pb.EchoResponse, error) { return nil, nil }

func main() {
	s := grpc.NewServer()
	pb.RegisterEchoServer(s, &server{})
}
`,
    });
    const byDir = Object.fromEntries(idx.entrypoints.filter((e) => e.kind === 'rpc').map((e) => [e.path.split('/')[0], e.authSignals]));
    expect(byDir).toEqual({ secure: ['grpc.UnaryInterceptor(ensureValidToken)'], plain: [] });
  });

  it('C#: XxxBase overrides with MapGrpcService conventions, [Authorize] and interceptors; ControllerBase is not a gRPC base', async () => {
    const idx = await indexOf({
      'Protos/orders.proto': PROTO,
      'Program.cs': `var builder = WebApplication.CreateBuilder(args);
builder.Services.AddGrpc(o => o.Interceptors.Add<TenantAuthInterceptor>());
var app = builder.Build();
app.MapGrpcService<OrderGrpcService>().RequireAuthorization("Orders");
app.Run();
`,
      'Services/OrderGrpcService.cs': `using Grpc.Core;
using Microsoft.AspNetCore.Authorization;
namespace Shop.Services;
public class OrderGrpcService : OrderService.OrderServiceBase
{
    public override Task<Order> GetOrder(GetOrderRequest request, ServerCallContext context) => Task.FromResult(new Order());
    [Authorize(Roles = "Admin")]
    public override Task<Order> CancelOrder(CancelOrderRequest request, ServerCallContext context) => Task.FromResult(new Order());
    public Task Helper() => Task.CompletedTask;
}
`,
      'Controllers/HomeController.cs': `using Microsoft.AspNetCore.Mvc;
namespace Shop.Controllers;
[ApiController]
[Route("home")]
public class HomeController : ControllerBase
{
    [HttpGet] public override string ToString() => "x";
}
`,
    });
    expect(rpcs(idx)).toEqual(['rpc:shop.orders.v1.OrderService/CancelOrder', 'rpc:shop.orders.v1.OrderService/GetOrder']);
    const get = rpc(idx, 'rpc:shop.orders.v1.OrderService/GetOrder');
    expect(get.middlewares).toEqual(['RequireAuthorization("Orders")', 'TenantAuthInterceptor']);
    expect(get.authSignals).toEqual(['RequireAuthorization("Orders")', 'TenantAuthInterceptor']);
    expect(rpc(idx, 'rpc:shop.orders.v1.OrderService/CancelOrder').authSignals).toEqual(expect.arrayContaining(['[Authorize(Roles = "Admin")]']));
  });

  it('rpc entries become gRPC provider connections next to the proto contract', async () => {
    const view = await viewOf({
      'proto/orders.proto': PROTO,
      'src/main/java/shop/OrderGrpcService.java': `package shop;
public class OrderGrpcService extends OrderServiceGrpc.OrderServiceImplBase {
    @Override public void getOrder(GetOrderRequest r, StreamObserver<Order> o) { }
}
`,
    });
    const idx = (await buildIndex(view, loadRules(), { indexesDir: mkdtempSync(join(tmpdir(), 'ca-m11grpc-i-')) })).index;
    const conns = await extractConnections(view, idx, null);
    const impl = conns.filter((c) => c.kind === 'grpc' && c.ruleId === 'index.java.grpc.service');
    expect(impl.map((c) => c.key)).toEqual([{ service: 'shop.orders.v1.OrderService', rpc: 'GetOrder' }]);
    expect(impl[0]!.site.path).toBe('src/main/java/shop/OrderGrpcService.java');
  });
});
