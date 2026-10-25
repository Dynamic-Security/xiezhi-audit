// Triage candidate ids as real cheap models return them (dev baseline, 2026-09-28: mimo-v2.6-flash failed the
// triage contract in 4 of 66 runs by copying the listing line instead of the id).
import { describe, expect, it } from 'vitest';
import type { EntryPoint, StructIndex } from '@xiezhi/contracts';
import { logicEntries } from '../src/business.js';
import { candidateResolver, entryScore, hasPathParam, type Candidate } from '../src/steps/triage.js';

const c = (id: string, path: string, line: number): Candidate => ({ id, kind: 'entry', repo: 'order-service', path, line, label: id, score: 1 });
const listed = [
  c('order-service:GET /api/orders/{}', 'src/main/java/com/mall/order/web/OrderController.java', 30),
  c('order-service:POST /api/orders/{}/cancel', 'src/main/java/com/mall/order/web/OrderController.java', 35),
  c('order-service:GET /api/admin/orders', 'src/main/java/com/mall/order/web/AdminOrderController.java', 21),
];

describe('triage candidate ids', () => {
  const resolve = candidateResolver(listed);
  it('accepts the id, the id with the location appended, or a location naming one candidate', () => {
    expect(resolve('order-service:GET /api/orders/{}')).toBe('order-service:GET /api/orders/{}');
    expect(resolve('order-service:GET /api/orders/{} | order-service:src/main/java/com/mall/order/web/OrderController.java:30')).toBe('order-service:GET /api/orders/{}');
    expect(resolve('order-service:src/main/java/com/mall/order/web/OrderController.java:35')).toBe('order-service:POST /api/orders/{}/cancel');
    expect(resolve('src/main/java/com/mall/order/web/AdminOrderController.java:21')).toBe('order-service:GET /api/admin/orders');
  });
  it('refuses anything else, and a location shared by several candidates', () => {
    expect(resolve('order-service:admin-order-search')).toBeNull();
    const shared = candidateResolver([...listed, c('order-service:sink#L30', 'src/main/java/com/mall/order/web/OrderController.java', 30)]);
    expect(shared('order-service:src/main/java/com/mall/order/web/OrderController.java:30')).toBeNull();
  });
});

describe('object ids in HTTP paths', () => {
  const http = (key: string, tpl: string, auth: string[] = ['@UseGuards(AuthGuard)']) => ({ entryKey: key, pathTemplate: tpl, authSignals: auth }) as unknown as EntryPoint;
  it('counts a NestJS / Express `:id` like a `{id}`: a gateway\'s by-id routes ranked as plain ones', () => {
    const nest = http('GET /api/v1/gateway/deposits/{}', '/api/v1/gateway/deposits/:depositId');
    const spring = http('GET /api/orders/{}', '/api/orders/{id}');
    const plain = http('GET /api/v1/gateway/deposits', '/api/v1/gateway/deposits');
    expect(hasPathParam(nest)).toBe(true);
    expect(entryScore(nest, new Set())).toBe(entryScore(spring, new Set()));
    expect(entryScore(nest, new Set())).toBeGreaterThan(entryScore(plain, new Set()));
    // A colon inside a segment is no parameter (`/v1/items:batchGet`, Google-style custom methods).
    expect(hasPathParam(http('POST /v1/items:batchGet', '/v1/items:batchGet'))).toBe(false);
  });
});

// GraphQL resolver entries (`rpc:graphql:<Type>/<field>`) are IDOR candidates and threat-model entries like
// HTTP routes with an id in the path.
describe('GraphQL entries in triage and the threat model', () => {
  const e = (entryKey: string, pathTemplate: string, authSignals: string[] = []): EntryPoint => ({
    entryId: `photo:${entryKey}`, entryKey, kind: 'rpc', framework: 'gqlgen', pathTemplate, handler: 'photo:r.go#resolvers.x(1)', path: 'r.go',
    range: { startLine: 1, endLine: 2 }, middlewares: authSignals, authSignals, ruleId: 'go.gqlgen.operation',
  });
  const share = e('rpc:graphql:Mutation/shareAlbum', 'Mutation.shareAlbum(albumId: ID!): ShareToken!', ['@isAuthorized']);
  const album = e('rpc:graphql:Query/album', 'Query.album(id: ID!, tokenCredentials: ShareTokenCredentials): Album!');
  const info = e('rpc:graphql:Query/siteInfo', 'Query.siteInfo(): SiteInfo!');
  const http = (entryKey: string, pathTemplate: string): EntryPoint => ({ ...info, entryId: `photo:${entryKey}`, entryKey, kind: 'http', httpMethod: entryKey.split(' ')[0]!, pathTemplate });

  it('scores id arguments and mutations like an id in the path; public entries get the usual bonus', () => {
    expect(entryScore(share, new Set())).toBe(4);
    expect(entryScore(album, new Set())).toBe(5);
    expect(entryScore(info, new Set())).toBe(3);
    expect(entryScore(http('GET /albums/{}', '/albums/{id}'), new Set())).toBe(5);
  });

  it('puts mutations and by-id operations on the threat model list, not plain queries', () => {
    const idx = { entrypoints: [share, album, info, http('GET /health', '/health'), http('POST /login', '/login')] } as unknown as StructIndex;
    expect(logicEntries(idx, 60).map((x) => x.entryKey)).toEqual(['rpc:graphql:Mutation/shareAlbum', 'rpc:graphql:Query/album', 'POST /login']);
  });
});
