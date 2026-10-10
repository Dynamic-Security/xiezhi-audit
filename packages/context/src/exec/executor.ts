// The ONLY place allowed to spawn processes (enforced by eslint).
// Command whitelist, no shell, minimal env, process-group kill, streamed hashing, output caps,
// process-tree sampling (descendant count / RSS) and reaping of descendants that escaped the group.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { accessSync, constants, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { delimiter, dirname, isAbsolute, join } from 'node:path';
import { EXEC_EXIT_CODES, type ExecResult, type ExecStatus } from '@xiezhi/contracts';
import { listProcesses, processTree, samplingSupported } from './proctree.js';

export const ALLOWED_COMMANDS = ['rg', 'git'] as const;
export type AllowedCommand = (typeof ALLOWED_COMMANDS)[number];

/** git subcommands that may be run. */
export const GIT_SUBCOMMANDS = new Set([
  'rev-parse', 'ls-tree', 'cat-file', 'diff-tree', 'diff', 'log', 'show', 'ls-remote', 'fetch', 'clone', 'for-each-ref', 'status', 'ls-files', '--version', 'version',
  // Creates the empty bare cache repository for remote sources; never run inside an audited repository.
  'init',
]);
const RG_FORBIDDEN = [/^--pre(=|$)/, /^--pre-glob(=|$)/, /^--search-zip$/, /^-z$/, /^-L$/, /^--follow$/, /^--hostname-bin/];

export const INLINE_PREVIEW_BYTES = 50 * 1024;
export const DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024 * 1024;
const KILL_GRACE_MS = 3000;
const MAX_CONCURRENT = 8;
/** more than 64 descendants or 1 GB summed RSS (non-LSP) kills the whole group. */
export const DEFAULT_RESOURCE_LIMITS: ResourceLimits = { maxProcesses: 64, maxRssBytes: 1024 * 1024 * 1024 };
const DEFAULT_SAMPLE_INTERVAL_MS = 1000;

export interface ResourceLimits {
  /** Maximum number of descendants (the started process itself not counted). */
  maxProcesses: number;
  /** Maximum RSS summed over the started process and its descendants. */
  maxRssBytes: number;
}

export class ExecPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ExecPolicyError';
  }
}

export interface ExecRequest {
  command: AllowedCommand;
  args: string[];
  /** Fixed working directory chosen by the caller type (snapshot root, index dir, private empty dir). */
  cwd: string;
  timeoutMs: number;
  signal?: AbortSignal;
  /** Tool-specific environment additions (e.g. GIT_* hardening). Never credentials. */
  env?: Record<string, string>;
  input?: string | Buffer;
  /** Keep the full stdout in memory (up to maxOutputBytes) for the caller to parse. */
  collectStdout?: boolean;
  maxOutputBytes?: number;
  /** Overrides of the executor's resource limits for this process tree. */
  limits?: Partial<ResourceLimits>;
}

export interface ExecOutput extends ExecResult {
  stdoutData?: Buffer;
}

export interface ExecutorOptions {
  /** Explicit binary paths from settings (`tools.rgPath` / `tools.gitPath`). */
  paths?: Partial<Record<AllowedCommand, string>>;
  /** Private scratch root; per-process HOME/TMPDIR directories are created under it. */
  scratchDir: string;
  /** Process-tree sampling period (default 1 s). Processes that end sooner are never sampled. */
  sampleIntervalMs?: number;
  limits?: Partial<ResourceLimits>;
}

/** A running process tree watched by the sampler. */
interface Watch {
  pid: number;
  limits: ResourceLimits;
  /** Every pid seen in this tree, so descendants re-parented after their parent died are still found. */
  known: Set<number>;
  onLimit: (detail: string) => void;
}

function findOnPath(name: string): string | null {
  for (const dir of (process.env.PATH ?? '').split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, name);
    try {
      accessSync(candidate, constants.X_OK);
      return candidate;
    } catch { /* keep looking */ }
  }
  return null;
}

export function validateArgs(command: AllowedCommand, args: string[]): void {
  for (const a of args) {
    if (a.includes('\0') || a.includes('\n') || a.includes('\r')) throw new ExecPolicyError('argument contains NUL or newline');
  }
  if (command === 'git') {
    // Skip leading `-c key=value` pairs to find the subcommand.
    let i = 0;
    while (i < args.length && args[i] === '-c') i += 2;
    const sub = args[i];
    if (!sub || !GIT_SUBCOMMANDS.has(sub)) throw new ExecPolicyError(`git subcommand not allowed: ${sub ?? '(none)'}`);
    if (sub === 'diff' && args.includes('--no-index')) throw new ExecPolicyError('git diff --no-index is not allowed');
    if (args.some((a) => /^--upload-pack|^--receive-pack|^--exec(=|$)/.test(a))) throw new ExecPolicyError('git program override is not allowed');
  }
  if (command === 'rg') {
    const dashDash = args.indexOf('--');
    const opts = dashDash === -1 ? args : args.slice(0, dashDash);
    for (const a of opts) {
      if (RG_FORBIDDEN.some((re) => re.test(a))) throw new ExecPolicyError(`rg option not allowed: ${a}`);
    }
  }
}

export class Executor {
  private readonly binaries = new Map<AllowedCommand, string | null>();
  private running = 0;
  private readonly waiters: (() => void)[] = [];
  private readonly watches = new Set<Watch>();
  private sampleTimer: NodeJS.Timeout | null = null;
  private sampling = false;
  private readonly sampleIntervalMs: number;
  private readonly limits: ResourceLimits;
  readonly scratchDir: string;

  constructor(opts: ExecutorOptions) {
    this.scratchDir = opts.scratchDir;
    this.sampleIntervalMs = opts.sampleIntervalMs ?? DEFAULT_SAMPLE_INTERVAL_MS;
    this.limits = { ...DEFAULT_RESOURCE_LIMITS, ...opts.limits };
    mkdirSync(this.scratchDir, { recursive: true, mode: 0o700 });
    // Resolve once at startup; never re-resolve through PATH at run time.
    for (const cmd of ALLOWED_COMMANDS) {
      const configured = opts.paths?.[cmd];
      if (configured && !isAbsolute(configured)) throw new ExecPolicyError(`configured ${cmd} path must be absolute`);
      this.binaries.set(cmd, configured ?? findOnPath(cmd));
    }
  }

  binaryPath(cmd: AllowedCommand): string | null {
    return this.binaries.get(cmd) ?? null;
  }

  async run(req: ExecRequest): Promise<ExecOutput> {
    if (!(ALLOWED_COMMANDS as readonly string[]).includes(req.command)) throw new ExecPolicyError(`command not allowed: ${req.command}`);
    validateArgs(req.command, req.args);
    const bin = this.binaries.get(req.command);
    if (!bin) return spawnError(`${req.command} not found`);
    await this.acquire();
    try {
      return await this.spawnOnce(bin, req);
    } finally {
      this.release();
    }
  }

  private acquire(): Promise<void> {
    if (this.running < MAX_CONCURRENT) {
      this.running++;
      return Promise.resolve();
    }
    return new Promise((resolve) => this.waiters.push(() => { this.running++; resolve(); }));
  }

  private release(): void {
    this.running--;
    this.waiters.shift()?.();
  }

  /** Resource sampling for long-running service processes (stdio connectors, `service.ts`). */
  watchService(w: { pid: number; known: Set<number>; onLimit: (detail: string) => void; limits?: Partial<ResourceLimits> }): () => void {
    return this.watch({ pid: w.pid, known: w.known, limits: { ...this.limits, ...w.limits }, onLimit: w.onLimit });
  }

  /** One shared sampler for all running trees: a single process-table read per tick. */
  private watch(w: Watch): () => void {
    if (!samplingSupported()) return () => undefined;
    this.watches.add(w);
    if (!this.sampleTimer) {
      this.sampleTimer = setInterval(() => void this.sample(), this.sampleIntervalMs);
      this.sampleTimer.unref();
    }
    return () => {
      this.watches.delete(w);
      if (this.watches.size === 0 && this.sampleTimer) {
        clearInterval(this.sampleTimer);
        this.sampleTimer = null;
      }
    };
  }

  private async sample(): Promise<void> {
    if (this.sampling || this.watches.size === 0) return;
    this.sampling = true;
    try {
      const procs = await listProcesses();
      if (!procs) return;
      for (const w of [...this.watches]) {
        const tree = processTree(procs, w.pid, w.pid, w.known);
        for (const p of tree) w.known.add(p.pid);
        const descendants = tree.filter((p) => p.pid !== w.pid).length;
        const rss = tree.reduce((n, p) => n + p.rssBytes, 0);
        if (descendants > w.limits.maxProcesses) w.onLimit(`resource limit: ${descendants} descendant processes > ${w.limits.maxProcesses}`);
        else if (rss > w.limits.maxRssBytes) w.onLimit(`resource limit: RSS ${Math.round(rss / 1048576)} MB > ${Math.round(w.limits.maxRssBytes / 1048576)} MB`);
      }
    } finally {
      this.sampling = false;
    }
  }

  private spawnOnce(bin: string, req: ExecRequest): Promise<ExecOutput> {
    const lease = mkdtempSync(join(this.scratchDir, 'lease-'));
    const home = join(lease, 'home');
    const tmp = join(lease, 'tmp');
    mkdirSync(home, { mode: 0o700 });
    mkdirSync(tmp, { mode: 0o700 });
    const env: Record<string, string> = {
      PATH: [dirname(bin), '/usr/bin', '/bin'].join(delimiter),
      HOME: home,
      TMPDIR: tmp,
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      ...req.env,
    };
    const maxOutput = req.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
    const started = Date.now();

    return new Promise<ExecOutput>((resolve) => {
      let child;
      try {
        child = spawn(bin, req.args, { cwd: req.cwd, env, shell: false, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) {
        rmSync(lease, { recursive: true, force: true });
        resolve(spawnError(String((e as Error).message)));
        return;
      }
      const out = new StreamCollector(req.collectStdout ?? false);
      const err = new StreamCollector(false);
      let status: ExecStatus | null = null;
      let killTimer: NodeJS.Timeout | undefined;
      const pid = child.pid;
      const known = new Set<number>(pid ? [pid] : []);

      const killGroup = (why: ExecStatus, detail?: string) => {
        if (status) return;
        status = why;
        if (detail) err.push(Buffer.from(`\n${detail}\n`));
        // Resource limits kill at once (fork bombs must not get a grace period); others get SIGTERM first.
        try { process.kill(-pid!, why === 'resource_limit' ? 'SIGKILL' : 'SIGTERM'); } catch { /* already exited */ }
        killTimer = setTimeout(() => {
          try { process.kill(-pid!, 'SIGKILL'); } catch { /* already exited */ }
          void reap(pid!, known);
        }, why === 'resource_limit' ? 0 : KILL_GRACE_MS);
      };
      const unwatch = pid
        ? this.watch({ pid, known, limits: { ...this.limits, ...req.limits }, onLimit: (detail) => killGroup('resource_limit', detail) })
        : () => undefined;

      const timer = setTimeout(() => killGroup('timeout'), req.timeoutMs);
      const onAbort = () => killGroup('cancelled');
      if (req.signal?.aborted) onAbort();
      req.signal?.addEventListener('abort', onAbort, { once: true });

      const onData = (collector: StreamCollector) => (chunk: Buffer) => {
        collector.push(chunk);
        if (out.bytes + err.bytes > maxOutput) killGroup('output_limit');
      };
      child.stdout!.on('data', onData(out));
      child.stderr!.on('data', onData(err));
      child.stdin!.on('error', () => { /* child may close stdin early */ });
      if (req.input !== undefined) child.stdin!.end(req.input);
      else child.stdin!.end();

      child.on('error', (e) => {
        if (!status) status = 'spawn_error';
        err.push(Buffer.from(String(e.message)));
      });
      child.on('close', async (code, signal) => {
        clearTimeout(timer);
        if (killTimer) clearTimeout(killTimer);
        req.signal?.removeEventListener('abort', onAbort);
        unwatch();
        // Make sure nothing of the group survives, then reap descendants that left the group (setsid).
        // Only needed when the tree was killed or the sampler saw descendants: short, clean runs skip it.
        try { process.kill(-pid!, 'SIGKILL'); } catch { /* group gone */ }
        if (pid && (status || known.size > 1)) await reap(pid, known);
        rmSync(lease, { recursive: true, force: true });
        const final: ExecStatus = status ?? (code === 0 ? 'ok' : 'exit_nonzero');
        const exitCode = EXEC_EXIT_CODES[final] ?? (code ?? 1);
        resolve({
          status: final,
          exitCode: final === 'ok' ? 0 : exitCode,
          ...(signal ? { signal } : {}),
          stdout: out.summary(),
          stderr: err.summary(),
          durationMs: Date.now() - started,
          ...(req.collectStdout && final !== 'output_limit' ? { stdoutData: out.data() } : {}),
        });
      });
    });
  }
}

/** SIGKILL every process of the tree (by ppid), the group, and remembered re-parented descendants. */
async function reap(pid: number, known: Set<number>): Promise<void> {
  const procs = await listProcesses();
  if (!procs) return;
  for (const p of processTree(procs, pid, pid, known)) {
    try { process.kill(p.pid, 'SIGKILL'); } catch { /* gone */ }
  }
}

class StreamCollector {
  bytes = 0;
  private hash = createHash('sha256');
  private preview: Buffer[] = [];
  private previewBytes = 0;
  private all: Buffer[] = [];
  constructor(private readonly keepAll: boolean) {}

  push(chunk: Buffer): void {
    this.bytes += chunk.length;
    this.hash.update(chunk);
    if (this.previewBytes < INLINE_PREVIEW_BYTES) {
      const slice = chunk.subarray(0, INLINE_PREVIEW_BYTES - this.previewBytes);
      this.preview.push(slice);
      this.previewBytes += slice.length;
    }
    if (this.keepAll) this.all.push(chunk);
  }

  data(): Buffer {
    return Buffer.concat(this.all);
  }

  summary() {
    return { bytes: this.bytes, sha256: this.hash.digest('hex'), inlinePreview: Buffer.concat(this.preview).toString('utf8') };
  }
}

function spawnError(message: string): ExecOutput {
  const empty = createHash('sha256').digest('hex');
  return {
    status: 'spawn_error', exitCode: 127,
    stdout: { bytes: 0, sha256: empty, inlinePreview: '' },
    stderr: { bytes: message.length, sha256: createHash('sha256').update(message).digest('hex'), inlinePreview: message },
    durationMs: 0,
  };
}
