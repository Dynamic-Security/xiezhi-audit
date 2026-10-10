// Hardened git invocation. The audited repository's .git/config and
// .gitattributes are attacker controlled, so every relevant knob is overridden with `-c`.
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ExecOutput, Executor } from './executor.js';

export interface GitOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
  input?: string | Buffer;
  collectStdout?: boolean;
  maxOutputBytes?: number;
}

function emptyHooksDir(executor: Executor): string {
  const dir = join(executor.scratchDir, 'empty-hooks');
  mkdirSync(dir, { recursive: true, mode: 0o500 });
  chmodSync(dir, 0o500);
  return dir;
}

export interface HardenOptions {
  /** Test-only: allow `file://` remotes (fixtures). Never reachable from configuration or the API. */
  allowFileProtocol?: boolean;
  /** Test-only: extra CA bundle for a local HTTPS test server. Never reachable from configuration or the API. */
  caInfo?: string;
}

export function hardenedGitArgs(executor: Executor, repoPath: string, sub: string, args: string[], opts: HardenOptions = {}): string[] {
  const c = (kv: string) => ['-c', kv];
  return [
    ...c(`core.hooksPath=${emptyHooksDir(executor)}`),
    ...c('core.fsmonitor=false'),
    ...c('core.untrackedCache=false'),
    ...c('diff.external='),
    ...c('core.pager=cat'),
    ...c('core.sshCommand=ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new'),
    ...c('credential.helper='),
    ...c('submodule.recurse=false'),
    ...c('filter.lfs.smudge='),
    ...c('filter.lfs.process='),
    ...c('filter.lfs.required=false'),
    ...c('protocol.allow=never'),
    ...c('protocol.https.allow=always'),
    ...c('protocol.ssh.allow=always'),
    ...(opts.allowFileProtocol ? c('protocol.file.allow=always') : []),
    ...(opts.caInfo ? c(`http.sslCAInfo=${opts.caInfo}`) : []),
    ...c(`safe.directory=${repoPath}`),
    ...c('core.quotePath=false'),
    sub,
    ...args,
  ];
}

export const GIT_ENV: Record<string, string> = {
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_ATTR_NOSYSTEM: '1',
  GIT_TERMINAL_PROMPT: '0',
  GIT_LFS_SKIP_SMUDGE: '1',
  GIT_EDITOR: 'true',
  GIT_PAGER: 'cat',
  GIT_OPTIONAL_LOCKS: '0',
};

/** Diff/log/show must never run external diff drivers or textconv filters. */
const SAFE_DIFF_FLAGS = ['--no-ext-diff', '--no-textconv'];

export function runGit(executor: Executor, repoPath: string, sub: string, args: string[], opts: GitOptions = {}): Promise<ExecOutput> {
  const extra = ['diff', 'log', 'show', 'diff-tree'].includes(sub) ? SAFE_DIFF_FLAGS : [];
  return executor.run({
    command: 'git',
    args: hardenedGitArgs(executor, repoPath, sub, [...extra, ...args]),
    cwd: repoPath,
    timeoutMs: opts.timeoutMs ?? 60_000,
    env: GIT_ENV,
    ...(opts.signal ? { signal: opts.signal } : {}),
    ...(opts.input !== undefined ? { input: opts.input } : {}),
    ...(opts.collectStdout ? { collectStdout: true } : {}),
    ...(opts.maxOutputBytes ? { maxOutputBytes: opts.maxOutputBytes } : {}),
  });
}

/** HTTPS credential for one host (config.json `gitCredentials[]`). */
export interface GitCredential {
  username: string;
  token: string;
}

export interface GitRemoteOptions extends GitOptions {
  credential?: GitCredential | undefined;
  /** SSH remotes only: the user's agent socket. A socket path, not a secret. */
  sshAuthSock?: string | undefined;
  allowFileProtocol?: boolean | undefined;
  /** Test-only, see HardenOptions.caInfo. */
  caInfo?: string | undefined;
}

/**
 * Network git (`ls-remote` / `fetch`). The credential reaches git only through a one-shot askpass
 * program reading 0600 files in a private directory that is removed afterwards — never argv, never
 * the environment, never a remote URL or config file.
 */
export async function runGitRemote(executor: Executor, cwd: string, sub: 'ls-remote' | 'fetch', args: string[], opts: GitRemoteOptions = {}): Promise<ExecOutput> {
  const env: Record<string, string> = { ...GIT_ENV };
  let secretDir: string | null = null;
  if (opts.credential) {
    secretDir = mkdtempSync(join(executor.scratchDir, 'askpass-'));
    if (/['\\\n]/.test(secretDir)) { rmSync(secretDir, { recursive: true, force: true }); throw new Error('scratch directory path is not usable for askpass'); }
    chmodSync(secretDir, 0o700);
    writeFileSync(join(secretDir, 'u'), opts.credential.username, { mode: 0o600 });
    writeFileSync(join(secretDir, 'p'), opts.credential.token, { mode: 0o600 });
    const helper = join(secretDir, 'askpass.sh');
    writeFileSync(helper, `#!/bin/sh\ncase "$1" in\n  [Uu]sername*) cat '${secretDir}/u' ;;\n  *) cat '${secretDir}/p' ;;\nesac\n`, { mode: 0o700 });
    env.GIT_ASKPASS = helper;
  }
  if (opts.sshAuthSock) env.SSH_AUTH_SOCK = opts.sshAuthSock;
  try {
    return await executor.run({
      command: 'git',
      args: hardenedGitArgs(executor, cwd, sub, args, { allowFileProtocol: !!opts.allowFileProtocol, ...(opts.caInfo ? { caInfo: opts.caInfo } : {}) }),
      cwd,
      timeoutMs: opts.timeoutMs ?? 120_000,
      env,
      ...(opts.signal ? { signal: opts.signal } : {}),
      ...(opts.collectStdout ? { collectStdout: true } : {}),
      ...(opts.maxOutputBytes ? { maxOutputBytes: opts.maxOutputBytes } : {}),
    });
  } finally {
    if (secretDir) rmSync(secretDir, { recursive: true, force: true });
  }
}
