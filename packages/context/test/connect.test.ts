// connection extraction on synthetic snippets: gateway configs, contracts, clients.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createSnapshot, crossRepoTrace, Executor, extractConnections, matchConnections, SnapshotView, type ConnectLimit, type RepoNames } from '@xiezhi/context';
import type { Connection } from '@xiezhi/contracts';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-conn-'));

async function conns(name: string, files: Record<string, string>): Promise<Connection[]> {
  const dir = tmp();
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), t);
  }
  const snap = await createSnapshot({ source: { kind: 'local', path: dir }, snapshotsDir: tmp(), tmpDir: tmp(), executor: new Executor({ scratchDir: tmp() }) });
  return extractConnections(new SnapshotView(name, snap.root, snap.manifest), null, null);
}
const fmt = (cs: Connection[]) => cs.map((c) => `${c.side} ${c.kind} ${JSON.stringify(c.key)}${c.serviceHint ? ` @${c.serviceHint}` : ''} ${c.extraction}`).sort();

describe('gateway configurations', () => {
  it('nginx: proxy_pass with a path strips the location prefix', async () => {
    const cs = await conns('edge', { 'conf/nginx.conf': 'http { server {\n location /api/order/ { proxy_pass http://order-service/; }\n location /static { root /var/www; }\n # location /x { proxy_pass http://x; }\n location /api/pay { proxy_pass http://pay:9000; }\n} }\n' });
    expect(fmt(cs.filter((c) => c.kind === 'gateway_route'))).toEqual([
      'consumes gateway_route {"pathTemplate":"/api/order/**","service":"order-service","stripPrefix":2} @order-service literal',
      'consumes gateway_route {"pathTemplate":"/api/pay/**","service":"pay"} @pay literal',
    ]);
  });
  it('Kong, APISIX and Zuul routes', async () => {
    const kong = await conns('kong', { 'kong.yml': '_format_version: "3.0"\nservices:\n  - name: users\n    url: http://user-svc:8080\n    routes:\n      - paths: [/users]\n' });
    expect(fmt(kong.filter((c) => c.kind === 'gateway_route'))).toEqual(['consumes gateway_route {"pathTemplate":"/users/**","service":"user-svc","stripPrefix":1} @user-svc literal']);
    const apisix = await conns('apisix', { 'apisix.yaml': 'routes:\n  - uri: /api/v1/*\n    upstream:\n      nodes:\n        "billing:8080": 1\n' });
    expect(fmt(apisix.filter((c) => c.kind === 'gateway_route'))).toEqual(['consumes gateway_route {"pathTemplate":"/api/v1/**","service":"billing"} @billing literal']);
    const zuul = await conns('zuul', { 'src/main/resources/application.yml': 'zuul:\n  routes:\n    orders:\n      path: /orders/**\n      serviceId: order-service\n' });
    expect(fmt(zuul.filter((c) => c.kind === 'gateway_route'))).toEqual(['consumes gateway_route {"pathTemplate":"/orders/**","service":"order-service","stripPrefix":1} @order-service literal']);
  });
});

describe('contracts and clients', () => {
  it('proto services, OpenAPI paths with servers prefix, Dubbo XML', async () => {
    const cs = await conns('api', {
      'proto/inventory.proto': 'syntax = "proto3";\npackage shop.inv;\n// service Fake { rpc X(A) returns (B); }\nservice Stock {\n  rpc Get (Req) returns (Resp);\n  rpc Reserve (Req) returns (Resp);\n}\n',
      'openapi.yaml': 'openapi: 3.0.0\nservers: [{ url: "https://api.example.com/v2" }]\npaths:\n  /pets/{id}:\n    get: {}\n    delete: {}\n',
      'src/main/resources/dubbo.xml': '<beans><dubbo:service interface="com.shop.PayService" ref="pay"/><dubbo:reference interface="com.shop.UserService" id="u"/></beans>',
    });
    expect(fmt(cs)).toEqual([
      'consumes dubbo {"interface":"UserService"} literal',
      'provides dubbo {"interface":"PayService"} literal',
      'provides grpc {"service":"shop.inv.Stock","rpc":"Get"} literal',
      'provides grpc {"service":"shop.inv.Stock","rpc":"Reserve"} literal',
      'provides http {"method":"DELETE","pathTemplate":"/v2/pets/{id}"} literal',
      'provides http {"method":"GET","pathTemplate":"/v2/pets/{id}"} literal',
    ]);
  });
  it('Go http clients, gRPC stubs, Java RestTemplate / WebClient / @DubboReference / @KafkaListener', async () => {
    const cs = await conns('svc', {
      'client.go': 'package main\nimport "net/http"\nconst base = "http://user-service"\nfunc f(id string) {\n req, _ := http.NewRequest("GET", base+"/api/user/"+id, nil)\n _ = req\n http.Get("https://pay.example.com/v1/charge")\n c := pb.NewStockClient(conn)\n _ = c\n}\n',
      'src/main/java/A.java': 'class A {\n @DubboReference private UserService users;\n void f(String id) {\n  restTemplate.getForObject("http://bill-service/api/bill/" + id, String.class);\n  webClient.post().uri("/api/audit").retrieve();\n  StockGrpc.newBlockingStub(ch);\n }\n @KafkaListener(topics = {"a", "b"}) void on(String m) {}\n}\n',
    });
    expect(fmt(cs)).toEqual([
      'consumes dubbo {"interface":"UserService"} literal',
      'consumes grpc {"service":"Stock"} literal',
      'consumes grpc {"service":"Stock"} literal',
      'consumes http {"method":"GET","pathTemplate":"/api/bill/{?}"} @bill-service partial',
      'consumes http {"method":"GET","pathTemplate":"/api/user/{?}"} @user-service partial',
      'consumes http {"method":"GET","pathTemplate":"/v1/charge"} @pay.example.com literal',
      'consumes http {"method":"POST","pathTemplate":"/api/audit"} literal',
      'consumes mq {"topic":"a"} literal',
      'consumes mq {"topic":"b"} literal',
    ]);
  });
  it('Vue SFC script blocks and axios request configs', async () => {
    const cs = await conns('web', {
      'src/App.vue': '<template><div/></template>\n<script setup lang="ts">\nimport axios from "axios";\naxios({ url: "/api/cart", method: "put" });\n</script>\n',
    });
    expect(fmt(cs)).toEqual(['consumes http {"method":"PUT","pathTemplate":"/api/cart"} literal']);
  });
  it('matching: several providers make the match inferred; unknown hosts stay unmatched', () => {
    const c = (repo: string, side: 'provides' | 'consumes', key: Connection['key'], hint?: string): Connection => ({ connId: `${repo}-${side}-${JSON.stringify(key)}`, repo, side, kind: 'http', key, ...(hint ? { serviceHint: hint } : {}), site: { path: 'x', line: 1 }, ruleId: 'test', extraction: 'literal' });
    const repos: RepoNames[] = [{ repo: 'a', appNames: [] }, { repo: 'b', appNames: [] }, { repo: 'web', appNames: [] }];
    const r = matchConnections([
      c('a', 'provides', { method: 'GET', pathTemplate: '/x/{id}' }), c('b', 'provides', { method: 'GET', pathTemplate: '/x/{id}' }),
      c('web', 'consumes', { method: 'GET', pathTemplate: '/x/1' }), c('web', 'consumes', { method: 'GET', pathTemplate: '/y' }, 'stripe.com'),
    ], repos);
    expect(r.matches.filter((m) => m.provider).map((m) => m.confidence)).toEqual(['inferred', 'inferred']);
    expect(r.matches.find((m) => !m.provider)).toMatchObject({ providerRepo: null, confidence: 'inferred' });
  });
});

// The file limit counts only files the extractor reads; a cut is reported, and
// cross_repo_trace says the repository's connection points are incomplete.
describe('file limit', () => {
  const FILES: Record<string, string> = {
    // Sorted before the configs: these must not use up the limit.
    'docs/a.md': '# a\n', 'docs/b.md': '# b\n', 'docs/c.md': '# c\n', 'docs/d.txt': 'd\n',
    'gw/a.yml': 'routes:\n  - id: order\n    uri: lb://order-service\n    predicates:\n      - Path=/api/order/**\n',
    'gw/b.yml': 'x: 1\n',
    'gw/c.yml': 'x: 2\n',
  };
  async function view() {
    const dir = tmp();
    for (const [p, t] of Object.entries(FILES)) {
      mkdirSync(join(dir, p, '..'), { recursive: true });
      writeFileSync(join(dir, p), t);
    }
    const snap = await createSnapshot({ source: { kind: 'local', path: dir }, snapshotsDir: tmp(), tmpDir: tmp(), executor: new Executor({ scratchDir: tmp() }) });
    return new SnapshotView('edge', snap.root, snap.manifest);
  }

  it('counts read files only and reports the files past the limit', async () => {
    const v = await view();
    const cuts: ConnectLimit[] = [];
    const cs = await extractConnections(v, null, null, { maxFiles: 2, onLimit: (l) => cuts.push(l) });
    expect(cuts).toEqual([{ limit: 2, skipped: 1, firstSkipped: 'gw/c.yml' }]);
    // gw/a.yml was read although four other files come before it.
    expect(cs.some((c) => c.site.path === 'gw/a.yml')).toBe(true);
    const none: ConnectLimit[] = [];
    await extractConnections(v, null, null, { maxFiles: 3, onLimit: (l) => none.push(l) });
    expect(none).toEqual([]);

    const r = crossRepoTrace(new Map([['edge', v]]), 'edge', { connections: cs, matches: [], indexes: new Map(), userEdges: [], limits: [{ repo: 'edge', ...cuts[0]! }] }, {});
    expect(r.incomplete).toEqual(['edge: connection points from the first 2 files only; 1 files not read (from gw/c.yml)']);
    expect(crossRepoTrace(new Map([['edge', v]]), 'edge', { connections: cs, matches: [], indexes: new Map(), userEdges: [] }, {}).incomplete).toBeUndefined();
  });
});
