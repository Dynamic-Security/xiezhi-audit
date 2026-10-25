// Gateway authentication and header rewriting read from the gateways' own configuration.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createSnapshot, Executor, extractGatewayAuth, gatewayAuthFor, SnapshotView, type GatewayAuthReport } from '@xiezhi/context';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-gwauth-'));

async function report(files: Record<string, string>): Promise<GatewayAuthReport> {
  const dir = tmp();
  for (const [p, t] of Object.entries(files)) {
    mkdirSync(join(dir, p, '..'), { recursive: true });
    writeFileSync(join(dir, p), t);
  }
  const snap = await createSnapshot({ source: { kind: 'local', path: dir }, snapshotsDir: tmp(), tmpDir: tmp(), executor: new Executor({ scratchDir: tmp() }) });
  return extractGatewayAuth(new SnapshotView('gw', snap.root, snap.manifest));
}
const brief = (r: GatewayAuthReport) => r.routes.map((x) => `${x.pathTemplate} → ${x.upstream} strip=${x.stripPrefix} auth=${x.auth?.kind ?? '-'}${x.setHeaders.length ? ` set=${x.setHeaders.join(',')}` : ''}${x.removeHeaders.length ? ` rm=${x.removeHeaders.join(',')}` : ''}`);

describe('gateway authentication', () => {
  it('Spring Cloud Gateway: route filters, default filters, header filters, a legacy route without auth', async () => {
    const r = await report({
      'src/main/resources/application.yml': [
        'spring:', '  cloud:', '    gateway:', '      default-filters:', '        - RemoveRequestHeader=X-User-Id', '      routes:',
        '        - id: orders-v1', '          uri: lb://order-service', '          predicates:', '            - Path=/api/v1/orders/**', '          filters:', '            - JwtAuth', '            - AddRequestHeader=X-User-Id, 1', '            - StripPrefix=2',
        '        - id: orders-legacy', '          uri: lb://order-service', '          predicates:', '            - Path=/api/legacy/orders/**', '          filters:', '            - StripPrefix=2',
      ].join('\n'),
    });
    expect(brief(r)).toEqual(['/api/v1/orders/** → order-service strip=2 auth=jwt set=X-User-Id', '/api/legacy/orders/** → order-service strip=2 auth=-']);
    expect(r.global).toEqual([]);
    expect(r.routes[0]!.auth!.site.line).toBeGreaterThan(1);
  });

  it('a GlobalFilter class, a Zuul pre filter and a WebFlux security chain authenticate every route', async () => {
    const r = await report({
      'src/main/resources/application.yml': 'spring:\n  cloud:\n    gateway:\n      routes:\n        - id: order\n          uri: lb://order-service\n          predicates:\n            - Path=/api/order/**\n',
      'src/main/java/gw/TokenPresenceFilter.java': 'package gw;\nimport org.springframework.cloud.gateway.filter.GlobalFilter;\npublic class TokenPresenceFilter implements GlobalFilter, Ordered {}\n',
      'src/main/java/gw/AccessLogFilter.java': 'public class AccessLogFilter implements GlobalFilter {}\n',
      'src/main/java/gw/Security.java': 'class Security { SecurityWebFilterChain chain(ServerHttpSecurity h) { return h.authorizeExchange().anyExchange().authenticated().and().oauth2ResourceServer().jwt().and().build(); } }\n',
    });
    expect(r.global.map((g) => `${g.kind} ${g.mechanism}`).sort()).toEqual(['custom Spring Cloud Gateway 全局过滤器 TokenPresenceFilter', 'jwt Spring WebFlux 安全配置 Security（anyExchange().authenticated()）']);
    expect(gatewayAuthFor(r, '/api/order/1')).toMatchObject({ route: { upstream: 'order-service' }, auth: { kind: expect.stringMatching(/custom|jwt/) } });
  });

  it('Kong plugins at service and route level, request-transformer headers', async () => {
    const r = await report({
      'kong.yml': [
        '_format_version: "3.0"', 'services:', '  - name: users', '    url: http://user-svc:8080', '    plugins:', '      - name: jwt', '      - name: request-transformer', '        config:', '          add:', '            headers: ["X-Consumer:$(consumer)"]', '          remove:', '            headers: ["X-Internal"]',
        '    routes:', '      - name: users', '        paths: [/users]', '  - name: health', '    url: http://health:8080', '    routes:', '      - name: health', '        paths: [/health]', '        strip_path: false',
      ].join('\n'),
    });
    expect(brief(r)).toEqual(['/users/** → user-svc strip=1 auth=jwt set=X-Consumer rm=X-Internal', '/health/** → health strip=0 auth=-']);
  });

  it('APISIX route and global plugins', async () => {
    const r = await report({ 'apisix.yaml': 'global_rules:\n  - plugins:\n      key-auth: {}\nroutes:\n  - uri: /api/v1/*\n    plugins:\n      openid-connect: {}\n    upstream:\n      nodes:\n        "billing:8080": 1\n  - uri: /public/*\n    upstream:\n      nodes:\n        "cms:80": 1\n' });
    expect(brief(r)).toEqual(['/api/v1/** → billing strip=0 auth=oauth2', '/public/** → cms strip=0 auth=-']);
    expect(r.global.map((g) => g.kind)).toEqual(['key']);
    expect(gatewayAuthFor(r, '/public/page').auth?.kind).toBe('key');
  });

  it('Nginx: server-level auth_request, a location turning it off, proxy_set_header', async () => {
    const r = await report({
      'conf/nginx.conf': 'http { server {\n auth_request /_auth;\n location = /_auth { internal; proxy_pass http://auth-svc/check; }\n location /api/ { proxy_set_header X-User $auth_user; proxy_set_header Authorization ""; proxy_pass http://app/; }\n location /open/ { auth_request off; proxy_pass http://app; }\n} }\n',
    });
    expect(r.global.map((g) => g.mechanism)).toEqual(['Nginx auth_request /_auth（server）']);
    expect(brief(r).filter((x) => !x.startsWith('/_auth'))).toEqual(['/api/** → app strip=1 auth=- set=X-User rm=Authorization', '/open/** → app strip=0 auth=off']);
    expect(gatewayAuthFor(r, '/api/orders').auth?.kind).toBe('external');
    expect(gatewayAuthFor(r, '/open/x').auth).toBeNull();
  });

  it('Kubernetes Ingress annotations', async () => {
    const r = await report({
      'k8s/ingress.yaml': [
        'apiVersion: networking.k8s.io/v1', 'kind: Ingress', 'metadata:', '  name: shop', '  annotations:', '    nginx.ingress.kubernetes.io/auth-url: "http://auth.svc/verify"', '    nginx.ingress.kubernetes.io/auth-response-headers: X-User-Id',
        'spec:', '  rules:', '    - http:', '        paths:', '          - path: /api', '            backend:', '              service:', '                name: order-service', '---',
        'apiVersion: networking.k8s.io/v1', 'kind: Ingress', 'metadata:', '  name: public', 'spec:', '  rules:', '    - http:', '        paths:', '          - path: /static', '            backend:', '              service:', '                name: cdn',
      ].join('\n'),
    });
    expect(brief(r)).toEqual(['/api/** → order-service strip=0 auth=external set=X-User-Id', '/static/** → cdn strip=0 auth=-']);
  });

  it('Zuul routes strip their prefix; sensitive headers are removed', async () => {
    const r = await report({ 'src/main/resources/application.yml': 'zuul:\n  sensitive-headers: Cookie,Set-Cookie\n  routes:\n    orders:\n      path: /orders/**\n      serviceId: order-service\n' });
    expect(brief(r)).toEqual(['/orders/** → order-service strip=1 auth=- rm=Cookie,Set-Cookie']);
  });
});
