// Language servers for audits: found from settings or the usual install places,
// started lazily on the first definition / references request (“按需”), one per (snapshot root, language),
// over a writable copy of the snapshot under indexes/<rootHash>/; reclaimed after 10 idle minutes and on
// shutdown. When a server is missing or fails, the audit falls back to the tree-sitter index (source: ts).
import { statSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { LspSession, prepareWorkspace, type Executor, type LspLanguage, type LspServer, type SnapshotView } from '@xiezhi/context';
import type { AppConfig } from '@xiezhi/contracts';

export const LSP_IDLE_MS = 10 * 60_000;
const SEARCH_DIRS = () => [...(process.env.PATH ?? '').split(':').filter((d) => d.startsWith('/')), join(homedir(), 'go/bin'), '/opt/homebrew/bin', '/usr/local/bin', '/usr/local/go/bin', '/usr/bin'];

function executable(p: string | undefined): string | null {
  if (!p || !p.startsWith('/')) return null;
  try { return statSync(p).isFile() ? p : null; } catch { return null; }
}

function find(name: string): string | null {
  for (const d of SEARCH_DIRS()) { const p = executable(join(d, name)); if (p) return p; }
  return null;
}

export const LSP_SERVER_NAMES: Record<LspLanguage, string> = { go: 'gopls', java: 'jdtls', python: 'pyright', typescript: 'typescript-language-server' };

/** The LSP language serving a snapshot file language (PHP / Kotlin / C# have none). */
export function lspLanguageOfLang(lang: string): LspLanguage | null {
  if (lang === 'go' || lang === 'java' || lang === 'python') return lang;
  if (lang === 'javascript' || lang === 'typescript') return 'typescript';
  return null;
}

/** How to point the service at a tool it did not find (settings page, or the CLI with the service stopped). */
const setHint = (key: string) => `可在 设置 › 通用 › 外部工具路径 中指定（命令行：xiezhi config set tools.${key} <路径>），或加入 PATH`;

/** The server for a language, or why there is none (doctor and plan use the same answer). */
export function lspServer(config: AppConfig, language: LspLanguage): { server: LspServer | null; reason: string | null } {
  if (language === 'python' || language === 'typescript') {
    const [bin, key] = language === 'python' ? ['pyright-langserver', 'pyrightPath'] as const : ['typescript-language-server', 'tsLspPath'] as const;
    const file = executable(config.tools[key]) ?? find(bin);
    if (!file) return { server: null, reason: `未找到 ${bin}（${setHint(key)}）` };
    const node = executable(config.tools.nodePath) ?? find('node');
    if (!node) return { server: null, reason: `未找到 node（${bin} 需要它运行）` };
    return { server: { language, file, pathDirs: [dirname(node)] }, reason: null };
  }
  if (language === 'go') {
    const gopls = executable(config.tools.goplsPath) ?? find('gopls');
    const go = executable(config.tools.goPath) ?? find('go');
    if (!gopls) return { server: null, reason: `未找到 gopls（${setHint('goplsPath')}）` };
    if (!go) return { server: null, reason: '未找到 go 工具链（gopls 需要它加载包）' };
    return { server: { language, file: gopls, pathDirs: [dirname(go)] }, reason: null };
  }
  const jdtls = executable(config.tools.jdtlsPath) ?? find('jdtls');
  if (!jdtls) return { server: null, reason: `未找到 jdtls（${setHint('jdtlsPath')}）` };
  const java = find('java');
  return { server: { language, file: jdtls, pathDirs: java ? [dirname(java)] : [] }, reason: null };
}

export function languageOf(path: string): LspLanguage | null {
  if (path.endsWith('.go')) return 'go';
  if (path.endsWith('.java')) return 'java';
  if (/\.pyi?$/.test(path)) return 'python';
  if (/\.([cm]?[jt]sx?)$/.test(path) && !path.endsWith('.d.ts')) return 'typescript';
  return null;
}

export class LspPool {
  private readonly sessions = new Map<string, Promise<LspSession>>();
  private readonly timer: NodeJS.Timeout;

  constructor(private readonly deps: { executor: Executor; config: () => AppConfig; indexesDir: string; tmpDir: string }) {
    this.timer = setInterval(() => void this.reclaimIdle(), 60_000);
    this.timer.unref?.();
  }

  async session(view: SnapshotView, language: LspLanguage, signal?: AbortSignal): Promise<LspSession> {
    const key = `${view.rootHash}:${language}`;
    const existing = this.sessions.get(key);
    if (existing) {
      const s = await existing.catch(() => null);
      if (s?.alive) return s;
      this.sessions.delete(key);
    }
    const { server, reason } = lspServer(this.deps.config(), language);
    if (!server) throw new Error(reason ?? 'language server unavailable');
    const ws = join(this.deps.indexesDir, view.rootHash, `lsp-${language}`);
    const started = (async () => {
      prepareWorkspace(view, ws, language);
      return LspSession.start(this.deps.executor, server, ws, join(this.deps.tmpDir, 'lsp', view.rootHash, language), signal);
    })();
    this.sessions.set(key, started);
    started.catch(() => this.sessions.delete(key));
    return started;
  }

  private async reclaimIdle(): Promise<void> {
    for (const [key, p] of [...this.sessions]) {
      const s = await p.catch(() => null);
      if (!s || !s.alive || Date.now() - s.lastUsed > LSP_IDLE_MS) { this.sessions.delete(key); await s?.close(); }
    }
  }

  /** Close the servers of these snapshot roots (an audit ended), or all. */
  async close(rootHashes?: string[]): Promise<void> {
    for (const [key, p] of [...this.sessions]) {
      if (rootHashes && !rootHashes.some((h) => key.startsWith(`${h}:`))) continue;
      this.sessions.delete(key);
      const s = await p.catch(() => null);
      await s?.close();
    }
    if (!rootHashes) clearInterval(this.timer);
  }
}

