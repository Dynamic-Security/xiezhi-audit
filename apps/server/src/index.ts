// `xiezhi serve` entry: data-dir init + migrations + single-writer lock, listen on
// 127.0.0.1 only, discovery file for the CLI, one-time bootstrap URL for the browser.
import { AppError } from '@xiezhi/contracts';
import { Store, resolveDataDir } from '@xiezhi/store';
import { Engine } from '@xiezhi/engine';
import type { ModelMode } from '@xiezhi/agent';
import { buildApp } from './app.js';
import { SERVER_VERSION } from './context.js';
import { removeDiscovery, writeDiscovery } from './security.js';

export { buildApp, defaultWebRoot, type BuildOptions } from './app.js';
export { SERVER_VERSION, type AppContext } from './context.js';
export { AuthState } from './security.js';
export { ROUTE_DOCS } from './spec.js';
export { draftDto } from './routes/knowledge.js';

export const DEFAULT_PORT = 4820;

export interface StartOptions {
  dataDir?: string;
  port?: number;
  webRoot?: string | null;
  mode?: ModelMode;
  heartbeatMs?: number;
  /** Test-only: accept file:// remote Git sources (EngineOptions.testAllowFileRemotes). */
  testAllowFileRemotes?: boolean;
  /** Test-only: full and incremental audits hunt with the generalist batches (EngineOptions.testGeneralistHunt). */
  testGeneralistHunt?: boolean;
}

export interface RunningServer {
  url: string;
  bootstrapUrl: string;
  port: number;
  dataDir: string;
  close(): Promise<void>;
}

export async function startServer(opts: StartOptions = {}): Promise<RunningServer> {
  const port = opts.port ?? DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new AppError('CONFIG_INVALID', 'invalid port');
  const store = Store.open({ dataDir: resolveDataDir(opts.dataDir), role: 'serve' });
  let engine: Engine;
  try {
    engine = await Engine.open({ store, ...(opts.mode ? { mode: opts.mode } : {}), ...(opts.testAllowFileRemotes ? { testAllowFileRemotes: true } : {}), ...(opts.testGeneralistHunt ? { testGeneralistHunt: true } : {}) });
  } catch (e) {
    store.close();
    throw e;
  }
  const { app, ctx } = await buildApp({ store, engine, port, ...(opts.webRoot !== undefined ? { webRoot: opts.webRoot } : {}), ...(opts.heartbeatMs ? { heartbeatMs: opts.heartbeatMs } : {}) });
  try {
    await app.listen({ host: '127.0.0.1', port });
  } catch (e) {
    await app.close().catch(() => undefined);
    store.close();
    if ((e as NodeJS.ErrnoException).code === 'EADDRINUSE') throw new AppError('CONFIG_INVALID', `port ${port} is in use; choose another with --port`);
    throw e;
  }
  writeDiscovery(store.paths.root, { port, pid: process.pid, token: ctx.auth.cliToken, startedAt: ctx.startedAt, version: SERVER_VERSION });
  ctx.log('info', 'server started', { port, version: SERVER_VERSION });
  ctx.scheduler.kick();
  let closed = false;
  return {
    url: `http://127.0.0.1:${port}/`,
    bootstrapUrl: ctx.auth.bootstrapUrl(ctx.auth.issueBootstrap()),
    port,
    dataDir: store.paths.root,
    async close() {
      if (closed) return;
      closed = true;
      removeDiscovery(store.paths.root);
      await ctx.scheduler.stop();
      await engine.stopAnalyses();
      await app.close();
      ctx.log('info', 'server stopped');
      store.close();
    },
  };
}
