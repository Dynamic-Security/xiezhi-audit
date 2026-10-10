// Working-tree dirty detection without `git status`. `git status` hashes modified
// files through the repository's clean filters (`filter.<driver>.clean` / `.process` from the audited
// repository's .git/config and .gitattributes), which would run a program the repository chose. Here git
// only lists (HEAD tree, untracked names); every content hash is computed in-process.
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readlinkSync } from 'node:fs';
import { join } from 'node:path';
import type { Executor } from '../exec/executor.js';
import { runGit } from '../exec/git.js';

/** Git blob id of some content: sha1("blob <len>\0" + content) (sha256 repositories use sha256). */
export function gitBlobId(content: Buffer, algo: 'sha1' | 'sha256' = 'sha1'): string {
  return createHash(algo).update(`blob ${content.length}\0`).update(content).digest('hex');
}

/**
 * Whether the working tree differs from HEAD: a tracked file changed, was removed or changed type, or an
 * untracked file that is not ignored exists. Submodules are ignored (like `--ignore-submodules=all`). Content is
 * compared byte for byte with the committed blob, so a file that only differs through an attribute conversion
 * (`text` / `eol` / a filter) counts as changed; a mode-only change does not (core.fileMode varies). null when git cannot answer (no HEAD, git failure).
 */
export async function worktreeDirty(executor: Executor, repo: string, opts: { signal?: AbortSignal; timeoutMs?: number } = {}): Promise<boolean | null> {
  const common = { collectStdout: true, timeoutMs: opts.timeoutMs ?? 60_000, ...(opts.signal ? { signal: opts.signal } : {}) };
  const tree = await runGit(executor, repo, 'ls-tree', ['-r', '-z', '--full-tree', 'HEAD'], common);
  if (tree.status !== 'ok') return null;
  for (const rec of tree.stdoutData!.toString('utf8').split('\0')) {
    if (!rec) continue;
    const tab = rec.indexOf('\t');
    const [mode, type, id] = rec.slice(0, tab).split(/ +/);
    const rel = rec.slice(tab + 1);
    if (type !== 'blob' || !id) continue;
    const abs = join(repo, ...rel.split('/'));
    let st;
    try {
      st = lstatSync(abs);
    } catch {
      return true; // deleted
    }
    const algo = id.length === 64 ? 'sha256' : 'sha1';
    if (mode === '120000') {
      if (!st.isSymbolicLink()) return true;
      if (gitBlobId(Buffer.from(readlinkSync(abs, { encoding: 'buffer' })), algo) !== id) return true;
      continue;
    }
    if (!st.isFile()) return true;
    if (gitBlobId(readFileSync(abs), algo) !== id) return true;
  }
  const others = await runGit(executor, repo, 'ls-files', ['-z', '--others', '--exclude-standard', '--directory', '--no-empty-directory'], common);
  if (others.status !== 'ok') return null;
  return others.stdoutData!.length > 0;
}
