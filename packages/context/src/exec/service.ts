// Long-running service processes (stdio MCP connectors): the command is an absolute path the
// user confirmed (the caller checks the confirmation hash); no shell; environment = minimal set plus the
// connector's explicit variables; private empty cwd; its own process group, killed as a group; resource
// sampling like one-shot commands; stdout delivered line by line with a per-line cap.
import { spawn } from 'node:child_process';
import { accessSync, constants, mkdirSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, isAbsolute, join } from 'node:path';
import { ExecPolicyError, type Executor } from './executor.js';
import { listProcesses, processTree } from './proctree.js';

export const SERVICE_MAX_LINE = 8 * 1024 * 1024;
const STDERR_TAIL = 16 * 1024;
const KILL_GRACE_MS = 2000;

export interface ServiceRequest {
  file: string;
  args: string[];
  /** Explicit variables (already secret-substituted by the caller); nothing is inherited. */
  env: Record<string, string>;
  /** Private empty directory chosen by the caller (`<data-dir>/tmp/connectors/<id>`). */
  cwd: string;
}

export interface ServiceProcess {
  readonly pid: number | undefined;
  write(line: string): void;
  onLine(cb: (line: string) => void): void;
  onExit(cb: (reason: string) => void): void;
  close(): Promise<void>;
}

const RESERVED_ENV = /^(PATH|HOME|TMPDIR|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_.*|NODE_OPTIONS)$/;

export function validateService(req: ServiceRequest): void {
  if (!isAbsolute(req.file)) throw new ExecPolicyError('service command must be an absolute path');
  try {
    if (!statSync(req.file).isFile()) throw new Error('not a file');
    accessSync(req.file, constants.X_OK);
  } catch {
    throw new ExecPolicyError(`service command is not an executable file: ${req.file}`);
  }
  for (const a of [req.file, ...req.args, ...Object.keys(req.env), ...Object.values(req.env)]) {
    if (a.includes('\0') || a.includes('\n') || a.includes('\r')) throw new ExecPolicyError('argument or environment contains NUL or newline');
  }
  for (const k of Object.keys(req.env)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) || RESERVED_ENV.test(k)) throw new ExecPolicyError(`environment variable ${k} is not allowed`);
  }
  if (!isAbsolute(req.cwd)) throw new ExecPolicyError('service cwd must be absolute');
}

/** Start a service process through the executor's governance (limits, sampling, group kill). */
export function spawnService(executor: Executor, req: ServiceRequest): ServiceProcess {
  validateService(req);
  mkdirSync(req.cwd, { recursive: true, mode: 0o700 });
  const lease = mkdtempSync(join(executor.scratchDir, 'svc-'));
  const home = join(lease, 'home');
  const tmp = join(lease, 'tmp');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(tmp, { mode: 0o700 });
  const env: Record<string, string> = {
    ...req.env,
    PATH: [dirname(req.file), '/usr/local/bin', '/usr/bin', '/bin'].join(delimiter),
    HOME: home, TMPDIR: tmp, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8',
  };
  const child = spawn(req.file, req.args, { cwd: req.cwd, env, shell: false, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const lines: ((l: string) => void)[] = [];
  const exits: ((r: string) => void)[] = [];
  let buf = '';
  let stderr = '';
  let ended: string | null = null;
  const pid = child.pid;
  const known = new Set<number>(pid ? [pid] : []);
  const finish = (reason: string) => {
    if (ended) return;
    ended = reason;
    unwatch();
    for (const cb of exits) cb(reason);
    rmSync(lease, { recursive: true, force: true });
  };
  const killGroup = (sig: NodeJS.Signals) => { try { if (pid) process.kill(-pid, sig); } catch { /* gone */ } };
  const unwatch = pid ? executor.watchService({ pid, known, onLimit: (detail) => { killGroup('SIGKILL'); finish(detail); } }) : () => undefined;
  child.stdout!.setEncoding('utf8');
  child.stdout!.on('data', (chunk: string) => {
    buf += chunk;
    if (buf.length > SERVICE_MAX_LINE && !buf.includes('\n')) { killGroup('SIGKILL'); finish('output line too long'); return; }
    let i: number;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).replace(/\r$/, '');
      buf = buf.slice(i + 1);
      for (const cb of lines) cb(line);
    }
  });
  child.stderr!.setEncoding('utf8');
  child.stderr!.on('data', (c: string) => { stderr = (stderr + c).slice(-STDERR_TAIL); });
  child.stdin!.on('error', () => { /* process gone */ });
  child.on('error', (e) => finish(`spawn error: ${e.message}`));
  child.on('close', (code, signal) => finish(`exited (${signal ?? code})${stderr.trim() ? `: ${stderr.trim().split('\n').slice(-3).join(' | ').slice(0, 500)}` : ''}`));
  return {
    pid,
    write(line: string) {
      if (ended) throw new Error(`service ended: ${ended}`);
      child.stdin!.write(`${line}\n`);
    },
    onLine(cb) { lines.push(cb); },
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

export interface ScriptRequest {
  /** Absolute interpreter (e.g. node, python3) the user confirmed together with the script contents. */
  interpreter: string;
  /** Absolute path of the script inside a connector pack. */
  script: string;
  cwd: string;
  env: Record<string, string>;
  input: string;
  timeoutMs: number;
}

const SCRIPT_MAX_OUTPUT = 1024 * 1024;

/**
 * One run of a connector pack script: same governance as service processes — confirmed
 * absolute interpreter, no shell, minimal environment plus explicit variables, private cwd, own process
 * group killed on timeout, output capped. stdin carries the JSON input; stdout must be JSON.
 */
export function runScript(executor: Executor, req: ScriptRequest): Promise<{ ok: boolean; stdout: string; error: string | null }> {
  validateService({ file: req.interpreter, args: [req.script], env: req.env, cwd: req.cwd });
  if (!isAbsolute(req.script)) return Promise.resolve({ ok: false, stdout: '', error: 'script path must be absolute' });
  return runOnce(executor, { file: req.interpreter, args: [req.script], cwd: req.cwd, env: req.env, input: req.input, timeoutMs: req.timeoutMs, pathDirs: [dirname(req.interpreter)], userHome: false });
}

/**
 * A command of a connector pack: a CLI the user installed and logged in to (e.g. lark-cli).
 * Same limits as pack scripts — no shell, own process group killed as a group, resource watch, timeout, output cap —
 * but `home: user` runs it with the user's HOME so the CLI finds its own login; the pack declares it and the user
 * confirms the program and the command templates before anything runs.
 */
export interface CommandRequest {
  program: string;
  args: string[];
  cwd: string;
  env: Record<string, string>;
  input: string;
  timeoutMs: number;
  home: 'user' | 'private';
}

export function runCommand(executor: Executor, req: CommandRequest): Promise<{ ok: boolean; stdout: string; error: string | null }> {
  validateService({ file: req.program, args: req.args, env: req.env, cwd: req.cwd });
  return runOnce(executor, { file: req.program, args: req.args, cwd: req.cwd, env: req.env, input: req.input, timeoutMs: req.timeoutMs, pathDirs: [dirname(req.program)], userHome: req.home === 'user' });
}

function runOnce(executor: Executor, req: { file: string; args: string[]; cwd: string; env: Record<string, string>; input: string; timeoutMs: number; pathDirs: string[]; userHome: boolean }): Promise<{ ok: boolean; stdout: string; error: string | null }> {
  mkdirSync(req.cwd, { recursive: true, mode: 0o700 });
  const lease = mkdtempSync(join(executor.scratchDir, 'scr-'));
  const home = join(lease, 'home');
  const tmp = join(lease, 'tmp');
  mkdirSync(home, { mode: 0o700 });
  mkdirSync(tmp, { mode: 0o700 });
  const env: Record<string, string> = { ...req.env, PATH: [...req.pathDirs, '/usr/bin', '/bin'].join(delimiter), HOME: req.userHome ? homedir() : home, TMPDIR: tmp, LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8' };
  return new Promise((resolve) => {
    const child = spawn(req.file, req.args, { cwd: req.cwd, env, shell: false, detached: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const pid = child.pid;
    const known = new Set<number>(pid ? [pid] : []);
    let out = '';
    let err = '';
    let failed: string | null = null;
    const kill = (why: string) => {
      if (failed) return;
      failed = why;
      try { if (pid) process.kill(-pid, 'SIGKILL'); } catch { /* gone */ }
    };
    const unwatch = pid ? executor.watchService({ pid, known, onLimit: (d) => kill(d) }) : () => undefined;
    const timer = setTimeout(() => kill(`timeout after ${req.timeoutMs} ms`), req.timeoutMs);
    child.stdout!.setEncoding('utf8');
    child.stdout!.on('data', (c: string) => { out += c; if (out.length > SCRIPT_MAX_OUTPUT) kill('output limit'); });
    child.stderr!.setEncoding('utf8');
    child.stderr!.on('data', (c: string) => { err = (err + c).slice(-4096); });
    child.stdin!.on('error', () => undefined);
    child.stdin!.end(req.input);
    child.on('error', (e) => kill(`spawn error: ${e.message}`));
    child.on('close', async (code) => {
      clearTimeout(timer);
      unwatch();
      try { if (pid) process.kill(-pid, 'SIGKILL'); } catch { /* group gone */ }
      const procs = known.size > 1 ? await listProcesses() : null;
      if (procs && pid) for (const p of processTree(procs, pid, pid, known)) { try { process.kill(p.pid, 'SIGKILL'); } catch { /* gone */ } }
      rmSync(lease, { recursive: true, force: true });
      const error = failed ?? (code !== 0 ? `exit ${code}${err.trim() ? `: ${err.trim().split('\n').slice(-3).join(' | ')}` : ''}` : null);
      resolve({ ok: !error, stdout: out, error });
    });
  });
}
