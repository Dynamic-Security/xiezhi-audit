// LSP client for symbol queries. One server per (snapshot root, language),
// over a writable copy of the snapshot (the snapshot store stays read-only). gopls runs with module
// downloads, toolchain switching, cgo and custom package drivers off; jdtls opens the copy with build-tool
// import disabled and a generated .project/.classpath (source view only, no dependencies, no network).
// pyright gets a non-existent interpreter path (it never runs Python to find search paths);
// typescript-language-server runs with automatic type acquisition off (no npm) and the copy has no
// node_modules, so tsconfig plugins cannot load. PHP / Kotlin / C# servers evaluate Composer / Gradle /
// MSBuild projects and are not used (tree-sitter only).
// Only definition and references are used; nothing is ever built or run.
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import type { Executor } from '../exec/executor.js';
import { spawnLspProcess, type LspProcess } from '../exec/lsp-process.js';
import type { SnapshotView } from '../snapshot/view.js';

export type LspLanguage = 'go' | 'java' | 'python' | 'typescript';
export const LSP_LANGUAGES: readonly LspLanguage[] = ['go', 'java', 'python', 'typescript'];
export interface LspServer { language: LspLanguage; file: string; pathDirs: string[] }
export interface LspLocation { path: string; startLine: number; endLine: number }

export const LSP_INIT_TIMEOUT_MS = 120_000;
/** 20 s per LSP query (the governance limit). */
export const LSP_REQUEST_TIMEOUT_MS = 20_000;

/** gopls environment: no downloads, no toolchain switch, no cgo, no custom drivers. */
export const GOPLS_ENV: Record<string, string> = {
  GOFLAGS: '-mod=readonly', GOPROXY: 'off', GOTOOLCHAIN: 'local', CGO_ENABLED: '0', GOWORK: 'off', GOENV: 'off',
  GOPACKAGESDRIVER: 'off', GOTELEMETRY: 'off', GONOSUMDB: '*',
};

const COPY_EXT = /\.(go|java|kt|xml|gradle|kts|properties|mod|sum|py|pyi|js|jsx|mjs|cjs|ts|tsx|mts|cts)$/i;
/** Project descriptors the Python / TS servers read as data (never executed). */
const COPY_NAMES = new Set(['tsconfig.json', 'jsconfig.json', 'package.json', 'pyproject.toml', 'pyrightconfig.json']);
/** A path that never exists: pyright must not start an interpreter. */
export const PYRIGHT_NO_INTERPRETER = '/nonexistent/xiezhi/python';

/**
 * Writable workspace copy for a language server. Only sources and build descriptors are
 * copied; for Java a minimal .project/.classpath replaces whatever the repository ships.
 */
export function prepareWorkspace(view: SnapshotView, dir: string, language: LspLanguage): void {
  if (existsSync(join(dir, '.ca-ready'))) return;
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  for (const f of view.manifest.files) {
    if (!COPY_EXT.test(f.path) && !COPY_NAMES.has(f.path.split('/').pop()!)) continue;
    const target = join(dir, f.path);
    mkdirSync(join(target, '..'), { recursive: true });
    cpSync(join(view.root, f.path), target);
  }
  if (language === 'python') {
    // Our own config wins over the repository's (copied read-only, so replaced): fixed interpreter path, no venv discovery.
    rmSync(join(dir, 'pyrightconfig.json'), { force: true });
    writeFileSync(join(dir, 'pyrightconfig.json'), JSON.stringify({ pythonPath: PYRIGHT_NO_INTERPRETER, venvPath: dir, venv: '.ca-no-venv', typeCheckingMode: 'off', useLibraryCodeForTypes: false }));
  }
  if (language === 'java') {
    const roots = javaSourceRoots(dir);
    writeFileSync(join(dir, '.project'), `<?xml version="1.0" encoding="UTF-8"?>\n<projectDescription><name>audit</name><comment></comment><projects></projects><buildSpec><buildCommand><name>org.eclipse.jdt.core.javabuilder</name><arguments></arguments></buildCommand></buildSpec><natures><nature>org.eclipse.jdt.core.javanature</nature></natures></projectDescription>\n`);
    const entries = roots.map((r) => `  <classpathentry kind="src" path="${r.replace(/"/g, '')}"/>`).join('\n');
    writeFileSync(join(dir, '.classpath'), `<?xml version="1.0" encoding="UTF-8"?>\n<classpath>\n${entries}\n  <classpathentry kind="con" path="org.eclipse.jdt.launching.JRE_CONTAINER"/>\n  <classpathentry kind="output" path=".ca-bin"/>\n</classpath>\n`);
  }
  writeFileSync(join(dir, '.ca-ready'), 'ok');
}

/** Source roots: every `src/main/java` / `src/test/java`, else the repository root. */
export function javaSourceRoots(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string, depth: number) => {
    if (depth > 6) return;
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (!e.isDirectory() || e.name.startsWith('.')) continue;
      const p = join(d, e.name);
      const rel = relative(dir, p).split(sep).join('/');
      if (/(^|\/)src\/(main|test)\/java$/.test(rel)) { out.push(rel); continue; }
      walk(p, depth + 1);
    }
  };
  walk(dir, 0);
  return out.length ? out.sort() : ['.'];
}

/** Command line and environment per server. */
export function serverCommand(language: LspLanguage, scratch: string): { args: string[]; env: Record<string, string> } {
  switch (language) {
    case 'go': return { args: ['serve'], env: { ...GOPLS_ENV, GOCACHE: join(scratch, 'gocache'), GOMODCACHE: join(scratch, 'gomodcache') } };
    case 'java': return { args: ['-configuration', join(scratch, 'jdtls-config'), '-data', join(scratch, 'jdtls-data')], env: { JAVA_TOOL_OPTIONS: '-Xmx2g' } };
    case 'python': return { args: ['--stdio'], env: { PYTHONNOUSERSITE: '1', PYTHONDONTWRITEBYTECODE: '1' } };
    case 'typescript': return { args: ['--stdio'], env: { NODE_OPTIONS: '--max-old-space-size=3072', TSS_LOG: '' } };
  }
}

export function initializationOptions(language: LspLanguage): unknown {
  switch (language) {
    case 'go': return { codelenses: {}, analyses: {}, staticcheck: false, vulncheck: 'Off', 'ui.diagnostic.analyses': {}, directoryFilters: ['-**/node_modules'] };
    case 'java': return { settings: { java: { import: { maven: { enabled: false }, gradle: { enabled: false } }, autobuild: { enabled: false }, configuration: { updateBuildConfiguration: 'disabled' } } } };
    case 'python': return {};
    case 'typescript': return { disableAutomaticTypingAcquisition: true, preferences: { includePackageJsonAutoImports: 'off' }, tsserver: { logVerbosity: 'off' } };
  }
}

/** Answers to `workspace/configuration`: pyright gets the fixed non-existent interpreter; others the defaults. */
export function configurationFor(language: LspLanguage, section: string | undefined): unknown {
  if (language === 'python' && section === 'python') return { pythonPath: PYRIGHT_NO_INTERPRETER };
  if (language === 'python' && section === 'python.analysis') return { autoSearchPaths: false, useLibraryCodeForTypes: false, diagnosticMode: 'openFilesOnly' };
  return null;
}

function languageIdOf(language: LspLanguage, path: string): string {
  if (language !== 'typescript') return language;
  if (/\.tsx$/.test(path)) return 'typescriptreact';
  if (/\.(ts|mts|cts)$/.test(path)) return 'typescript';
  return /\.jsx$/.test(path) ? 'javascriptreact' : 'javascript';
}

export class LspSession {
  private nextId = 1;
  private readonly pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private readonly opened = new Set<string>();
  private ended: string | null = null;
  lastUsed = Date.now();

  private constructor(private readonly proc: LspProcess, readonly root: string, readonly language: LspLanguage) {
    proc.onMessage((m) => this.onMessage(m));
    proc.onExit((r) => {
      this.ended = r;
      for (const p of this.pending.values()) { clearTimeout(p.timer); p.reject(new Error(`language server ended: ${r}`)); }
      this.pending.clear();
    });
  }

  static async start(executor: Executor, server: LspServer, root: string, scratch: string, signal?: AbortSignal): Promise<LspSession> {
    const { args, env } = serverCommand(server.language, scratch);
    const proc = spawnLspProcess(executor, { file: server.file, args, env, cwd: root, pathDirs: server.pathDirs });
    const s = new LspSession(proc, root, server.language);
    const onAbort = () => void s.close();
    signal?.addEventListener('abort', onAbort, { once: true });
    try {
      await s.request('initialize', {
        processId: null, rootUri: pathToFileURL(root).href, workspaceFolders: [{ uri: pathToFileURL(root).href, name: 'audit' }],
        capabilities: { textDocument: { definition: { linkSupport: false }, references: {}, synchronization: {} }, workspace: { configuration: true, workspaceFolders: true } },
        initializationOptions: initializationOptions(server.language),
      }, LSP_INIT_TIMEOUT_MS);
      s.notify('initialized', {});
      return s;
    } catch (e) {
      await s.close();
      throw e;
    } finally {
      signal?.removeEventListener('abort', onAbort);
    }
  }

  get alive(): boolean { return !this.ended; }

  private onMessage(m: Record<string, unknown>): void {
    if (typeof m.id === 'number' && ('result' in m || 'error' in m) && !('method' in m)) {
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      clearTimeout(p.timer);
      if (m.error) p.reject(new Error(`LSP error: ${JSON.stringify(m.error).slice(0, 300)}`)); else p.resolve(m.result);
      return;
    }
    // Requests from the server (configuration, progress, registration): answer minimally.
    if ('method' in m && 'id' in m) {
      const method = String(m.method);
      const result = method === 'workspace/configuration'
        ? ((m.params as { items?: { section?: string }[] })?.items ?? []).map((i) => configurationFor(this.language, i?.section))
        : null;
      try { this.proc.send({ jsonrpc: '2.0', id: m.id, result }); } catch { /* ended */ }
    }
  }

  private request(method: string, params: unknown, timeoutMs = LSP_REQUEST_TIMEOUT_MS): Promise<unknown> {
    if (this.ended) return Promise.reject(new Error(`language server ended: ${this.ended}`));
    const id = this.nextId++;
    this.lastUsed = Date.now();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`LSP ${method} timed out after ${timeoutMs} ms`)); }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.proc.send({ jsonrpc: '2.0', id, method, params });
    });
  }

  private notify(method: string, params: unknown): void {
    this.proc.send({ jsonrpc: '2.0', method, params });
  }

  private open(path: string): string {
    const uri = pathToFileURL(join(this.root, path)).href;
    if (!this.opened.has(uri)) {
      this.notify('textDocument/didOpen', { textDocument: { uri, languageId: languageIdOf(this.language, path), version: 1, text: readFileSync(join(this.root, path), 'utf8') } });
      this.opened.add(uri);
    }
    return uri;
  }

  /** Column of `symbol` on the (1-based) line, else the first non-blank character. */
  private position(path: string, line: number, symbol?: string): { line: number; character: number } {
    const text = readFileSync(join(this.root, path), 'utf8').split('\n')[line - 1] ?? '';
    const at = symbol ? text.indexOf(symbol) : -1;
    return { line: line - 1, character: at >= 0 ? at : Math.max(0, text.search(/\S/)) };
  }

  private locations(result: unknown): LspLocation[] {
    const arr = Array.isArray(result) ? result : result ? [result] : [];
    const out: LspLocation[] = [];
    for (const r of arr as { uri?: string; targetUri?: string; range?: { start: { line: number }; end: { line: number } }; targetRange?: { start: { line: number }; end: { line: number } } }[]) {
      const uri = r.uri ?? r.targetUri;
      const range = r.range ?? r.targetRange;
      if (!uri || !range || !uri.startsWith('file:')) continue;
      const abs = fileURLToPath(uri);
      const rel = relative(this.root, abs).split(sep).join('/');
      if (rel.startsWith('..')) continue; // outside the audited code (SDK, module cache): not citeable
      out.push({ path: rel, startLine: range.start.line + 1, endLine: range.end.line + 1 });
    }
    return out;
  }

  async definition(path: string, line: number, symbol?: string): Promise<LspLocation[]> {
    const uri = this.open(path);
    return this.locations(await this.request('textDocument/definition', { textDocument: { uri }, position: this.position(path, line, symbol) }));
  }

  async references(path: string, line: number, symbol?: string, includeDeclaration = false): Promise<LspLocation[]> {
    const uri = this.open(path);
    return this.locations(await this.request('textDocument/references', { textDocument: { uri }, position: this.position(path, line, symbol), context: { includeDeclaration } }));
  }

  async close(): Promise<void> {
    if (!this.ended) {
      try { await this.request('shutdown', null, 5000); this.notify('exit', null); } catch { /* best effort */ }
    }
    await this.proc.close();
  }
}
