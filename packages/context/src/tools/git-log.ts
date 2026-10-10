// git_log: commit metadata of the audited version from the repository's local
// git data — never a checkout, never file contents. Runs only through the hardened git wrapper.
import { normalizeRelPath } from '../pathguard.js';
import { runGit } from '../exec/git.js';
import type { Executor } from '../exec/executor.js';

export interface GitLogEntry { commit: string; author: string; date: string; subject: string }
export interface GitLogResult { entries: GitLogEntry[]; shallow: boolean; truncated: boolean }

export const GIT_LOG_MAX = 50;

/**
 * `gitDir`: the repository (work tree or bare cache) holding `commit`. `path` is relative to the repository
 * root; `grep` matches commit messages as a fixed string (no regex, no pathspec magic).
 */
export async function gitLog(executor: Executor, gitDir: string, commit: string, opts: { path?: string; n?: number; grep?: string; signal?: AbortSignal } = {}): Promise<GitLogResult> {
  if (!/^[0-9a-f]{7,64}$/i.test(commit)) throw new Error('git_log needs a resolved commit of the audited version');
  const n = Math.max(1, Math.min(GIT_LOG_MAX, opts.n ?? 20));
  const path = opts.path ? normalizeRelPath(gitDir, opts.path) : null;
  const args = ['-n', String(n + 1), '--format=%H%x1f%an%x1f%aI%x1f%s', '--no-color', '--no-decorate', '--no-show-signature'];
  if (opts.grep) args.push('--fixed-strings', '--regexp-ignore-case', `--grep=${opts.grep.slice(0, 200)}`);
  args.push(commit, '--');
  if (path) args.push(`:(literal)${path}`);
  const out = await runGit(executor, gitDir, 'log', args, { collectStdout: true, timeoutMs: 20_000, maxOutputBytes: 256 * 1024, ...(opts.signal ? { signal: opts.signal } : {}) });
  if (out.exitCode !== 0) throw new Error(`git log failed (exit ${out.exitCode})`);
  const lines = (out.stdoutData?.toString('utf8') ?? '').split('\n').filter(Boolean);
  const entries = lines.slice(0, n).map((l) => {
    const [c, a, d, ...s] = l.split('\x1f');
    return { commit: c ?? '', author: a ?? '', date: d ?? '', subject: s.join('\x1f').slice(0, 300) };
  });
  const sh = await runGit(executor, gitDir, 'rev-parse', ['--is-shallow-repository'], { collectStdout: true, timeoutMs: 10_000 });
  return { entries, shallow: (sh.stdoutData?.toString('utf8') ?? '').trim() === 'true', truncated: lines.length > n };
}
