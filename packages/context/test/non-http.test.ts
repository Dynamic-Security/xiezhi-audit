// Non-HTTP entries — gRPC servers in Kotlin (grpc-kotlin / grpc-java bases), Python (servicers) and
// JS / TS (@grpc/grpc-js addService, NestJS @GrpcMethod), Go asynq task handlers; Kotlin Spring listeners / schedules
// (already shared with Java) checked here. Small inline sources, never executed.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { StructIndex } from '@xiezhi/contracts';
import { Executor, SnapshotView, buildIndex, createSnapshot, loadRules } from '@xiezhi/context';

async function indexOf(files: Record<string, string>): Promise<StructIndex> {
  const root = mkdtempSync(join(tmpdir(), 'ca-m1124-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  const view = new SnapshotView('repo', s.root, s.manifest);
  return (await buildIndex(view, loadRules(), { indexesDir: join(root, 'indexes') })).index;
}

const keys = (idx: StructIndex) => idx.entrypoints.map((e) => e.entryKey).sort();
const entry = (idx: StructIndex, key: string) => idx.entrypoints.find((e) => e.entryKey === key)!;

const PROTO = `syntax = "proto3";
package demo;
service Greeter {
  rpc SayHello (HelloRequest) returns (HelloReply);
  rpc SayBye (HelloRequest) returns (HelloReply);
}
`;

describe('gRPC servers', () => {
  it('Kotlin: grpc-kotlin coroutine and grpc-java bases; Spring listeners and schedules', async () => {
    const idx = await indexOf({
      'proto/greeter.proto': PROTO,
      'src/main/kotlin/demo/GreeterService.kt': `package demo

import net.devh.boot.grpc.server.service.GrpcService

@GrpcService(interceptors = [AuthInterceptor::class])
class GreeterService : GreeterGrpcKt.GreeterCoroutineImplBase() {
    override suspend fun sayHello(request: HelloRequest): HelloReply = HelloReply.getDefaultInstance()
    private fun helper() {}
}
`,
      'src/main/kotlin/demo/Jobs.kt': `package demo

import org.springframework.kafka.annotation.KafkaListener
import org.springframework.scheduling.annotation.Scheduled

class Jobs {
    @KafkaListener(topics = ["orders"])
    fun onOrder(msg: String) {}

    @Scheduled(cron = "0 0 * * * *")
    fun nightly() {}
}
`,
    });
    expect(keys(idx)).toEqual(['cron:Jobs.nightly', 'mq:kafka:orders', 'rpc:demo.Greeter/SayHello']);
    const rpc = entry(idx, 'rpc:demo.Greeter/SayHello');
    expect(rpc.kind).toBe('rpc');
    expect(rpc.handler).toBe('repo:src/main/kotlin/demo/GreeterService.kt#GreeterService.sayHello(1)');
    expect(rpc.authSignals).toEqual(['AuthInterceptor']);
  });

  it('Python servicers (with and without the .proto)', async () => {
    const idx = await indexOf({
      'proto/greeter.proto': PROTO,
      'server.py': `import grpc
import greeter_pb2_grpc

class Greeter(greeter_pb2_grpc.GreeterServicer):
    def SayHello(self, request, context):
        return None

    def SayBye(self, request, context):
        return None

    def _log(self, x):
        pass

def serve():
    server = grpc.server(None)
    greeter_pb2_grpc.add_GreeterServicer_to_server(Greeter(), server)
`,
      'mail.py': `import greeter_pb2_grpc

class BaseGreeter(greeter_pb2_grpc.GreeterServicer):
    def Check(self, request, context):
        return None

class Greeter2(BaseGreeter):
    def SayBye(self, request, context):
        return None
`,
      'inventory.py': `import inventory_pb2_grpc

class Inventory(inventory_pb2_grpc.StockServicer):
    def Reserve(self, request, context):
        return None

    def helper(self):
        return None
`,
    });
    expect(keys(idx)).toEqual(['rpc:Stock/Reserve', 'rpc:demo.Greeter/SayBye', 'rpc:demo.Greeter/SayBye', 'rpc:demo.Greeter/SayHello']);
    expect(idx.entrypoints.filter((e) => e.entryKey === 'rpc:demo.Greeter/SayBye').map((e) => e.handler.split('#').pop()).sort()).toEqual(['mail.Greeter2.SayBye(2)', 'server.Greeter.SayBye(2)']);
    expect(entry(idx, 'rpc:demo.Greeter/SayHello').handler).toBe('repo:server.py#server.Greeter.SayHello(2)');
  });

  it('JS / TS: grpc-js addService with object, shorthand and class implementations; NestJS @GrpcMethod', async () => {
    const idx = await indexOf({
      'package.json': JSON.stringify({ dependencies: { '@grpc/grpc-js': '1', '@nestjs/core': '10', '@nestjs/microservices': '10' } }),
      'proto/greeter.proto': PROTO,
      'src/server.js': `const grpc = require('@grpc/grpc-js');
const proto = grpc.loadPackageDefinition(def).demo;
function sayHello(call, callback) { callback(null, {}); }
const server = new grpc.Server();
server.addService(proto.Greeter.service, { sayHello, sayBye: (call, cb) => cb(null, {}) });
`,
      'src/heroes.controller.ts': `import { Controller, UseGuards } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
@Controller()
export class HeroesController {
  @GrpcMethod('Greeter', 'SayHello')
  @UseGuards(AuthGuard)
  sayHello(data: any) { return {}; }
}
`,
    });
    const k = keys(idx);
    expect(k.filter((x) => x.startsWith('rpc:'))).toEqual(['rpc:demo.Greeter/SayBye', 'rpc:demo.Greeter/SayHello', 'rpc:demo.Greeter/SayHello']);
    const byFw = idx.entrypoints.filter((e) => e.entryKey === 'rpc:demo.Greeter/SayHello').map((e) => `${e.framework}:${e.handler.split('#').pop()}`).sort();
    expect(byFw).toEqual(['grpc:src/server.sayHello(2)', 'nestjs:src/heroes.controller.HeroesController.sayHello(1)']);
    expect(idx.entrypoints.find((e) => e.framework === 'nestjs' && e.kind === 'rpc')!.authSignals).toEqual(['@UseGuards(AuthGuard)']);
  });
});

describe('Go asynq', () => {
  it('task handlers are message entries and not net/http routes', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/worker\n\ngo 1.21\n',
      'worker.go': `package main

import (
	"context"
	"net/http"

	"github.com/hibiken/asynq"
)

type ImageProcessor struct{}

func (p *ImageProcessor) ProcessTask(ctx context.Context, t *asynq.Task) error { return nil }

func handleEmail(ctx context.Context, t *asynq.Task) error { return nil }

func main() {
	mux := asynq.NewServeMux()
	mux.HandleFunc("email:deliver", handleEmail)
	mux.Handle("image:resize", &ImageProcessor{})
	_ = http.StatusOK
}
`,
    });
    expect(keys(idx)).toEqual(['mq:asynq:email:deliver', 'mq:asynq:image:resize']);
    expect(entry(idx, 'mq:asynq:image:resize').handler).toMatch(/ImageProcessor\.ProcessTask\(2\)$/);
  });
});
