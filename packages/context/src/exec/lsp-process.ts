// Language server processes: jdtls / gopls started only through here — absolute,
// allow-listed binary, no shell, minimal environment plus explicit variables (e.g. GOFLAGS=-mod=readonly,
// GOPROXY=off), private HOME/TMPDIR, own process group killed as a group, resource sampling with a memory
// cap. Messages use LSP framing (Content-Length headers), not lines.
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { basename, delimiter, dirname, isAbsolute, join } from 'node:path';
import { ExecPolicyError, type Executor } from './executor.js';
import { listProcesses, processTree } from './proctree.js';
import { validateService } from './service.js';

/**
 * Language server executables that may be started (whitelist: jdtls/java, gopls/go;
 * pyright-langserver, typescript-language-server — node scripts, so `node` must be on their PATH).
 */
export const LSP_BINARIES = ['gopls', 'jdtls', 'java', 'pyright-langserver', 'typescript-language-server'] as const;
/** 4 GB for language servers (jdtls also gets -Xmx). */
export const LSP_MEMORY_BYTES = 4 * 1024 * 1024 * 1024;
const MAX_MESSAGE = 64 * 1024 * 1024;
const KILL_GRACE_MS = 2000;

export interface LspProcessRequest {
  file: string;
  args: string[];
  env: Record<string, string>;
  cwd: string;
  /** Extra PATH directories (e.g. the Go toolchain's bin for gopls). */
  pathDirs?: string[];
}

export interface LspProcess {
  readonly pid: number | undefined;
  send(msg: unknown): void;
  onMessage(cb: (msg: Record<string, unknown>) => void): void;
  onExit(cb: (reason: string) => void): void;
  close(): Promise<void>;
}

export function spawnLspProcess(executor: Executor, req: LspProcessRequest): LspProcess {
  const name = basename(req.file);
  if (!(LSP_BINARIES as readonly string[]).includes(name)) throw new ExecPolicyError(`language server not allowed: ${name}`);
  validateService({ file: req.file, args: req.args, env: req.env, cwd: req.cwd });
  for (const d of req.pathDirs ?? []) if (!isAbsolute(d)) throw new ExecPolicyError('PATH entries must be absolute');
  mkdirSync(req.cwd, { recursive: true, mode: 0o700 });
  const lease = mkdtempSync(join(executor.scratchDir, 'lsp-'));
  const home = join(lease, 'home');
  const tmp = join(lease, 'tmp');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(tmp, { mode: 0o700 });
  const env: Record<string, string> = {
    ...req.env,
    PATH: [dirname(req.file), ...(req.pathDirs ?? []), '/usr/bin', '/bin'].join(delimiter),
    HOME: home, TMPDIR: tmp, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
  };
  const child = spawn(req.file, req.args, { cwd: req.cwd, env, shell: false, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const pid = child.pid;
  const known = new Set<number>(pid ? [pid] : []);
  const listeners: ((m: Record<string, unknown>) => void)[] = [];
  const exits: ((r: string) => void)[] = [];
  let ended: string | null = null;
  let buf = Buffer.alloc(0);
  let stderr = '';
  const killGroup = (sig: NodeJS.Signals) => { try { if (pid) process.kill(-pid, sig); } catch { /* gone */ } };
  const finish = (reason: string) => {
    if (ended) return;
    ended = reason;
    unwatch();
    for (const cb of exits) cb(reason);
    rmSync(lease, { recursive: true, force: true });
  };
  const unwatch = pid ? executor.watchService({ pid, known, limits: { maxRssBytes: LSP_MEMORY_BYTES, maxProcesses: 64 }, onLimit: (detail) => { killGroup('SIGKILL'); finish(detail); } }) : () => undefined;
  child.stdout!.on('data', (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk]);
    for (;;) {
      const sep = buf.indexOf('\r\n\r\n');
      if (sep < 0) { if (buf.length > 8192) { killGroup('SIGKILL'); finish('malformed header'); } return; }
      const header = buf.subarray(0, sep).toString('ascii');
      const m = /Content-Length:\s*(\d+)/i.exec(header);
      if (!m) { killGroup('SIGKILL'); finish('missing Content-Length'); return; }
      const len = Number(m[1]);
      if (len > MAX_MESSAGE) { killGroup('SIGKILL'); finish('message too large'); return; }
      if (buf.length < sep + 4 + len) return;
      const body = buf.subarray(sep + 4, sep + 4 + len).toString('utf8');
      buf = buf.subarray(sep + 4 + len);
      let msg: Record<string, unknown>;
      try { msg = JSON.parse(body) as Record<string, unknown>; } catch { continue; }
      for (const cb of listeners) { try { cb(msg); } catch { /* a listener never breaks the stream */ } }
    }
  });
  child.stderr!.setEncoding('utf8');
  child.stderr!.on('data', (c: string) => { stderr = (stderr + c).slice(-16 * 1024); });
  child.stdin!.on('error', () => { /* process gone */ });
  child.on('error', (e) => finish(`spawn error: ${e.message}`));
  child.on('close', (code, signal) => finish(`exited (${signal ?? code})${stderr.trim() ? `: ${stderr.trim().split('\n').slice(-3).join(' | ').slice(0, 500)}` : ''}`));
  return {
    pid,
    send(msg: unknown) {
      if (ended) throw new Error(`language server ended: ${ended}`);
      const body = Buffer.from(JSON.stringify(msg), 'utf8');
      child.stdin!.write(Buffer.concat([Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, 'ascii'), body]));
    },
    onMessage(cb) { listeners.push(cb); },
    onExit(cb) { if (ended) cb(ended); else exits.push(cb); },
    async close() {
      if (ended) return;
      try { child.stdin!.end(); } catch { /* ignore */ }
      killGroup('SIGTERM');
      await new Promise<void>((resolve) => {
        const t = setTimeout(async () => {
          killGroup('SIGKILL');
          const procs = await listProcesses();
          if (procs && pid) for (const p of processTree(procs, pid, pid, known)) { try { process.kill(p.pid, 'SIGKILL'); } catch { /* gone */ } }
          resolve();
        }, KILL_GRACE_MS);
        exits.push(() => { clearTimeout(t); resolve(); });
        if (ended) { clearTimeout(t); resolve(); }
      });
    },
  };
}
