// Session / transport rules — a gorilla WebSocket Upgrader, a gqlgen WebSocket transport,
// Spring CORS origins, @CrossOrigin, Spring Security CSRF configuration and servlet cookies become sinks of the
// authn / cors / csrf categories, so the domain experts and the coverage ledger get anchors for “missing check” issues.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';

async function indexOf(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'ca-m17-06-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return (await buildIndex(new SnapshotView('repo', s.root, s.manifest), loadRules(), { indexesDir: join(root, 'idx') })).index;
}

const sinks = (idx: Awaited<ReturnType<typeof indexOf>>, prefix: string) =>
  idx.sinks.filter((s) => s.ruleId.startsWith(prefix)).map((s) => `${s.ruleId}@${s.range.startLine}:${s.category}`).sort();

describe('session / transport rules', () => {
  it('Go: the gorilla Upgrader and the gqlgen WebSocket transport, only with their imports', async () => {
    const idx = await indexOf({
      'go.mod': 'module example.com/x\n\ngo 1.22\n',
      'server/websocket.go': `package server

import (
	"net/http"

	"github.com/gorilla/websocket"
)

func WebsocketUpgrader(dev bool) websocket.Upgrader {
	return websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
}
`,
      'graphql/endpoint.go': `package endpoint

import (
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
)

func Endpoint(srv *handler.Server) {
	srv.AddTransport(transport.Websocket{KeepAlivePingInterval: 10})
}
`,
      'other/types.go': `package other

type Upgrader struct{ X int }
type Websocket struct{}

var u = Upgrader{X: 1}
var w = Websocket{}
`,
    });
    expect(sinks(idx, 'go.websocket')).toEqual(['go.websocket.upgrader@10:cors']);
    expect(sinks(idx, 'go.gqlgen')).toEqual(['go.gqlgen.websocket-transport@9:authn']);
  });

  it('Java: CORS origins, @CrossOrigin, CSRF configuration and servlet cookies', async () => {
    const idx = await indexOf({
      'pom.xml': '<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>x</artifactId><version>1</version></project>',
      'src/main/java/x/WebConfig.java': `package x;

import jakarta.servlet.http.Cookie;
import org.springframework.web.bind.annotation.CrossOrigin;

@CrossOrigin(origins = "*")
public class WebConfig {
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true);
    }
    public void registerStompEndpoints(StompEndpointRegistry r) {
        r.addEndpoint("/ws").setAllowedOrigins("*");
    }
    public void filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
    public Cookie remember(String v) {
        return new Cookie("rememberMe", v);
    }
}
`,
    });
    expect(sinks(idx, 'java.spring.cors')).toEqual(['java.spring.cors-origins@12:cors', 'java.spring.cors-origins@9:cors']);
    expect(sinks(idx, 'java.spring.cross')).toEqual(['java.spring.cross-origin@6:cors']);
    expect(sinks(idx, 'java.spring.csrf')).toEqual(['java.spring.csrf-config@15:csrf']);
    expect(sinks(idx, 'java.servlet')).toEqual(['java.servlet.cookie@18:authn']);
  });
});
