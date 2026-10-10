// Remote Git sources. URL validation, ls-remote,
// ref resolution and a per-URL bare cache fetched one commit at a time (`--depth 1`).
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { sha256Hex } from '@xiezhi/contracts';
import type { Executor } from '../exec/executor.js';
import { runGit, runGitRemote, type GitCredential } from '../exec/git.js';

export type RemoteErrorCode = 'invalid_url' | 'auth' | 'unreachable' | 'not_found' | 'ref_not_found' | 'fetch_failed';

export class RemoteGitError extends Error {
  constructor(readonly code: RemoteErrorCode, message: string, readonly suggestions: string[] = []) {
    super(message);
    this.name = 'RemoteGitError';
  }
}

export interface RemoteUrl {
  /** Normalized URL passed to git (no credentials). */
  url: string;
  kind: 'https' | 'ssh' | 'file';
  /** `host[:port]`, lowercase; the key of `gitCredentials[]`. */
  host: string;
  suggestedName: string;
}

export interface RemoteAuth {
  /** HTTPS credential for this host, if configured. */
  credential?: GitCredential | undefined;
  /** SSH agent socket forwarded to ssh remotes only. */
  sshAuthSock?: string | undefined;
  /** Test-only: accept file:// remotes. */
  allowFileProtocol?: boolean | undefined;
  /** Test-only: CA bundle trusted for a local HTTPS test server. */
  testCaInfo?: string | undefined;
}

function nameFromPath(path: string): string {
  const last = path.replace(/\/+$/, '').split('/').pop() ?? '';
  return last.replace(/\.git$/, '').replace(/[^A-Za-z0-9._-]/g, '-').replace(/^[^A-Za-z0-9]+/, '').slice(0, 100) || 'repo';
}

const SCP_LIKE = /^(?:([A-Za-z0-9._-]+)@)?([A-Za-z0-9.-]+):(?!\/\/)([^\s]+)$/;

export function parseGitUrl(input: string, opts: { allowFile?: boolean } = {}): RemoteUrl {
  const s = input.trim();
  if (!s || s.length > 2000 || /[\s\0]/.test(s) || s.startsWith('-')) throw new RemoteGitError('invalid_url', 'invalid Git URL');
  if (/^(ext|fd)::/i.test(s)) throw new RemoteGitError('invalid_url', 'transport helpers are not allowed');
  if (/^https:\/\//i.test(s)) {
    let u: URL;
    try { u = new URL(s); } catch { throw new RemoteGitError('invalid_url', 'invalid Git URL'); }
    if (u.username || u.password) throw new RemoteGitError('invalid_url', 'credentials must not be embedded in the URL; configure them under Settings › Git credentials');
    if (u.search || u.hash) throw new RemoteGitError('invalid_url', 'query strings and fragments are not allowed in a Git URL');
    const path = u.pathname.replace(/\/+$/, '');
    if (!path || path === '') throw new RemoteGitError('invalid_url', 'Git URL has no repository path');
    const host = u.host.toLowerCase();
    return { url: `https://${host}${path}`, kind: 'https', host, suggestedName: nameFromPath(path) };
  }
  if (/^ssh:\/\//i.test(s)) {
    let u: URL;
    try { u = new URL(s); } catch { throw new RemoteGitError('invalid_url', 'invalid Git URL'); }
    if (u.password) throw new RemoteGitError('invalid_url', 'passwords must not be embedded in the URL');
    const path = u.pathname.replace(/\/+$/, '');
    if (!path) throw new RemoteGitError('invalid_url', 'Git URL has no repository path');
    const host = u.host.toLowerCase();
    return { url: `ssh://${u.username ? `${u.username}@` : ''}${host}${path}`, kind: 'ssh', host, suggestedName: nameFromPath(path) };
  }
  if (/^file:\/\//i.test(s)) {
    if (!opts.allowFile) throw new RemoteGitError('invalid_url', 'file:// URLs are not allowed; add a local directory instead');
    return { url: s, kind: 'file', host: '', suggestedName: nameFromPath(s.slice(7)) };
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) throw new RemoteGitError('invalid_url', 'only https:// and ssh:// Git URLs are supported');
  const m = SCP_LIKE.exec(s);
  if (m && !m[3]!.startsWith('-')) {
    const host = m[2]!.toLowerCase();
    return { url: `${m[1] ? `${m[1]}@` : ''}${host}:${m[3]!.replace(/\/+$/, '')}`, kind: 'ssh', host, suggestedName: nameFromPath(m[3]!) };
  }
  throw new RemoteGitError('invalid_url', 'unrecognized Git URL (use https://host/path or git@host:path)');
}

function classify(stderr: string): RemoteGitError {
  const e = stderr.slice(0, 600);
  if (/Authentication failed|could not read (Username|Password)|terminal prompts disabled|Permission denied \(publickey|HTTP Basic: Access denied|returned error: 40[13]|Invalid username or password/i.test(e)) {
    return new RemoteGitError('auth', 'authentication failed: configure a token for this host (Settings › Git credentials) or check your SSH key');
  }
  if (/Repository not found|repository '.*' not found|does not appear to be a git repository|returned error: 404|project you were looking for could not be found/i.test(e)) {
    return new RemoteGitError('not_found', 'repository not found (or no access with the configured credential)');
  }
  if (/Could not resolve host|Connection refused|Connection timed out|Operation timed out|unable to access|Network is unreachable|Host key verification failed|timeout/i.test(e)) {
    return new RemoteGitError('unreachable', `remote not reachable: ${e.split('\n').find((l) => l.trim())?.trim().slice(0, 200) ?? 'network error'}`);
  }
  return new RemoteGitError('fetch_failed', `git failed: ${e.split('\n').find((l) => l.trim())?.trim().slice(0, 200) ?? 'unknown error'}`);
}

function netDir(executor: Executor): string {
  const d = join(executor.scratchDir, 'net-empty');
  mkdirSync(d, { recursive: true, mode: 0o700 });
  return d;
}

function remoteOpts(remote: RemoteUrl, auth: RemoteAuth) {
  return {
    credential: remote.kind === 'https' ? auth.credential : undefined,
    sshAuthSock: remote.kind === 'ssh' ? auth.sshAuthSock : undefined,
    allowFileProtocol: remote.kind === 'file' && !!auth.allowFileProtocol,
    caInfo: remote.kind === 'https' ? auth.testCaInfo : undefined,
  };
}

export interface RemoteRef { kind: 'branch' | 'tag'; name: string; commit: string }
export interface RemoteListing { defaultBranch: string | null; headCommit: string | null; refs: RemoteRef[] }

export async function lsRemote(executor: Executor, remote: RemoteUrl, auth: RemoteAuth = {}, signal?: AbortSignal): Promise<RemoteListing> {
  const r = await runGitRemote(executor, netDir(executor), 'ls-remote', ['--symref', '--', remote.url, 'HEAD', 'refs/heads/*', 'refs/tags/*'], {
    ...remoteOpts(remote, auth), collectStdout: true, timeoutMs: 60_000, ...(signal ? { signal } : {}),
  });
  if (r.status !== 'ok') throw r.status === 'timeout' ? new RemoteGitError('unreachable', 'remote did not answer within 60 s') : classify(r.stderr.inlinePreview);
  let defaultBranch: string | null = null;
  let headCommit: string | null = null;
  const tags = new Map<string, string>();
  const branches = new Map<string, string>();
  for (const line of r.stdoutData!.toString('utf8').split('\n')) {
    if (!line) continue;
    const sym = /^ref: refs\/heads\/(\S+)\tHEAD$/.exec(line);
    if (sym) { defaultBranch = sym[1]!; continue; }
    const [sha, ref] = line.split('\t');
    if (!sha || !ref || !/^[0-9a-f]{40,64}$/.test(sha)) continue;
    if (ref === 'HEAD') headCommit = sha;
    else if (ref.startsWith('refs/heads/')) branches.set(ref.slice(11), sha);
    else if (ref.startsWith('refs/tags/')) {
      const name = ref.slice(10);
      // Annotated tags: the peeled `^{}` line carries the commit.
      if (name.endsWith('^{}')) tags.set(name.slice(0, -3), sha);
      else if (!tags.has(name)) tags.set(name, sha);
    }
  }
  const refs: RemoteRef[] = [
    ...[...branches].map(([name, commit]) => ({ kind: 'branch' as const, name, commit })),
    ...[...tags].map(([name, commit]) => ({ kind: 'tag' as const, name, commit })),
  ];
  return { defaultBranch, headCommit, refs };
}

function distance(a: string, b: string): number {
  const dp = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    let prev = dp[0]!;
    dp[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = dp[j]!;
      dp[j] = Math.min(dp[j]! + 1, dp[j - 1]! + 1, prev + (a[i - 1] === b[j - 1] ? 0 : 1));
      prev = tmp;
    }
  }
  return dp[b.length]!;
}

export interface ResolvedRemoteRef {
  commit: string;
  /** Full ref name used as the fallback fetch source; null for a bare commit. */
  refName: string | null;
  /** What the user asked for (default branch name when none). */
  display: string;
}

export function resolveRemoteRef(listing: RemoteListing, ref: string | undefined | null): ResolvedRemoteRef {
  if (!ref) {
    if (!listing.headCommit) throw new RemoteGitError('ref_not_found', 'remote has no default branch; choose a branch, tag or commit');
    return { commit: listing.headCommit, refName: listing.defaultBranch ? `refs/heads/${listing.defaultBranch}` : null, display: listing.defaultBranch ?? 'HEAD' };
  }
  if (ref.startsWith('-') || /[\s\0]/.test(ref)) throw new RemoteGitError('ref_not_found', 'invalid ref');
  if (/^[0-9a-f]{40}$/.test(ref)) return { commit: ref, refName: null, display: ref };
  const full = listing.refs.find((r) => `refs/${r.kind === 'branch' ? 'heads' : 'tags'}/${r.name}` === ref);
  const hit = full ?? listing.refs.find((r) => r.kind === 'branch' && r.name === ref) ?? listing.refs.find((r) => r.kind === 'tag' && r.name === ref);
  if (hit) return { commit: hit.commit, refName: `refs/${hit.kind === 'branch' ? 'heads' : 'tags'}/${hit.name}`, display: ref };
  if (/^[0-9a-f]{7,39}$/.test(ref)) {
    const commits = new Map(listing.refs.filter((r) => r.commit.startsWith(ref)).map((r) => [r.commit, r]));
    if (commits.size === 1) {
      const r = [...commits.values()][0]!;
      return { commit: r.commit, refName: `refs/${r.kind === 'branch' ? 'heads' : 'tags'}/${r.name}`, display: ref };
    }
    throw new RemoteGitError('ref_not_found', commits.size > 1 ? `short hash ${ref} is ambiguous; use the full 40-character hash` : `short hash ${ref} does not match a branch or tag tip; use the full 40-character commit hash`);
  }
  const suggestions = listing.refs
    .map((r) => ({ name: r.name, d: r.name.toLowerCase().includes(ref.toLowerCase()) ? 0 : distance(r.name.toLowerCase(), ref.toLowerCase()) }))
    .filter((x) => x.d <= Math.max(2, Math.floor(ref.length / 3)))
    .sort((a, b) => a.d - b.d || a.name.localeCompare(b.name))
    .slice(0, 5).map((x) => x.name);
  throw new RemoteGitError('ref_not_found', `branch or tag "${ref}" does not exist on the remote`, suggestions);
}

export function remoteCacheDir(cacheRoot: string, remote: RemoteUrl): string {
  return join(cacheRoot, `${sha256Hex(remote.url).slice(0, 32)}.git`);
}

const locks = new Map<string, Promise<unknown>>();
async function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve();
  const next = prev.catch(() => undefined).then(fn);
  locks.set(key, next);
  try {
    return await next;
  } finally {
    if (locks.get(key) === next) locks.delete(key);
  }
}

async function hasCommit(executor: Executor, dir: string, commit: string): Promise<boolean> {
  const r = await runGit(executor, dir, 'cat-file', ['-e', `${commit}^{commit}`], { timeoutMs: 15_000 });
  return r.status === 'ok';
}

async function initBare(executor: Executor, dir: string, parent: string): Promise<void> {
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const r = await runGit(executor, parent, 'init', ['--bare', '--quiet', '--', dir], { timeoutMs: 15_000 });
  if (r.status !== 'ok') throw new RemoteGitError('fetch_failed', `cannot create the local cache: ${r.stderr.inlinePreview.slice(0, 200)}`);
}

async function fetchCommit(executor: Executor, dir: string, remote: RemoteUrl, auth: RemoteAuth, src: string, commit: string, filter: boolean, signal?: AbortSignal) {
  return runGitRemote(executor, dir, 'fetch', [
    '--depth', '1', '--no-tags', '--no-recurse-submodules', '--no-write-fetch-head', '--quiet', ...(filter ? ['--filter=blob:none'] : []),
    '--', remote.url, `+${src}:refs/snap/${commit}`,
  ], { ...remoteOpts(remote, auth), timeoutMs: 15 * 60_000, ...(signal ? { signal } : {}) });
}

/**
 * Make `resolved.commit` available in the per-URL bare cache and return the cache path.
 * Fetch by commit first; servers that refuse unadvertised SHAs are retried with the ref name, and the
 * result must still be that commit (a branch that moved in between is reported, not silently used).
 */
export async function fetchToCache(executor: Executor, cacheRoot: string, remote: RemoteUrl, resolved: ResolvedRemoteRef, auth: RemoteAuth = {}, signal?: AbortSignal): Promise<string> {
  const dir = remoteCacheDir(cacheRoot, remote);
  return withLock(dir, async () => {
    if (!existsSync(join(dir, 'HEAD'))) await initBare(executor, dir, cacheRoot);
    if (await hasCommit(executor, dir, resolved.commit)) return dir;
    let r = await fetchCommit(executor, dir, remote, auth, resolved.commit, resolved.commit, false, signal);
    if (r.status !== 'ok' && resolved.refName && r.status !== 'cancelled') {
      r = await fetchCommit(executor, dir, remote, auth, resolved.refName, resolved.commit, false, signal);
    }
    if (r.status === 'cancelled') throw new RemoteGitError('fetch_failed', 'cancelled');
    if (r.status === 'timeout') throw new RemoteGitError('unreachable', 'fetch did not finish within 15 minutes');
    if (r.status !== 'ok') throw classify(r.stderr.inlinePreview);
    if (!(await hasCommit(executor, dir, resolved.commit))) {
      throw new RemoteGitError('fetch_failed', `the remote ref moved while fetching (expected ${resolved.commit.slice(0, 12)}); retry`);
    }
    return dir;
  });
}

/**
 * File names at a commit without downloading blobs (`--filter=blob:none` into a throwaway bare repo),
 * for the add-repository probe's language summary. Servers without filter support send full objects.
 */
export async function listRemoteTree(executor: Executor, remote: RemoteUrl, commit: string, auth: RemoteAuth = {}, signal?: AbortSignal): Promise<string[]> {
  const parent = join(executor.scratchDir, 'probe');
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const tmp = mkdtempSync(join(parent, 'p-'));
  const dir = join(tmp, 'r.git');
  try {
    await initBare(executor, dir, tmp);
    const f = await fetchCommit(executor, dir, remote, auth, commit, commit, true, signal);
    if (f.status !== 'ok') throw classify(f.stderr.inlinePreview);
    const t = await runGit(executor, dir, 'ls-tree', ['-r', '-z', '--name-only', '--full-tree', commit], { collectStdout: true, timeoutMs: 60_000, ...(signal ? { signal } : {}) });
    if (t.status !== 'ok') throw new RemoteGitError('fetch_failed', 'cannot list the remote tree');
    return t.stdoutData!.toString('utf8').split('\0').filter(Boolean);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
