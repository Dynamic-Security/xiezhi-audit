// git_log: commit metadata of the audited version through the hardened git wrapper — path
// filter, fixed-string message filter, cap, shallow flag; a non-commit argument is refused.
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Executor, gitLog } from '@xiezhi/context';

function repo(): { dir: string; head: string } {
  const dir = mkdtempSync(join(tmpdir(), 'ca-gitlog-'));
  const git = (...a: string[]) => execFileSync('git', ['-c', 'user.email=t@t', '-c', 'user.name=Tester', '-c', 'init.defaultBranch=main', ...a], { cwd: dir, encoding: 'utf8', env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null' } }).trim();
  git('init', '-q');
  mkdirSync(join(dir, 'src'));
  writeFileSync(join(dir, 'src/A.java'), 'class A {}\n');
  git('add', '.'); git('commit', '-q', '-m', 'add A');
  writeFileSync(join(dir, 'README.md'), 'x\n');
  git('add', '.'); git('commit', '-q', '-m', 'docs: readme');
  writeFileSync(join(dir, 'src/A.java'), 'class A { void f() {} }\n');
  git('add', '.'); git('commit', '-q', '-m', 'fix: sanitize order id in A');
  return { dir, head: git('rev-parse', 'HEAD') };
}

describe('git_log', () => {
  const executor = new Executor({ scratchDir: mkdtempSync(join(tmpdir(), 'ca-gitlog-x-')) });
  it('lists commits of the audited version, by path and by message', async () => {
    const { dir, head } = repo();
    const all = await gitLog(executor, dir, head);
    expect(all.entries.map((e) => e.subject)).toEqual(['fix: sanitize order id in A', 'docs: readme', 'add A']);
    expect(all.entries[0]).toMatchObject({ commit: head, author: 'Tester' });
    expect(all.shallow).toBe(false);
    expect((await gitLog(executor, dir, head, { path: 'src/A.java' })).entries.map((e) => e.subject)).toEqual(['fix: sanitize order id in A', 'add A']);
    expect((await gitLog(executor, dir, head, { grep: 'SANITIZE' })).entries.map((e) => e.subject)).toEqual(['fix: sanitize order id in A']);
    // Fixed string, not a regex: a regex metacharacter pattern matches literally only.
    expect((await gitLog(executor, dir, head, { grep: '.*' })).entries).toEqual([]);
    const one = await gitLog(executor, dir, head, { n: 1 });
    expect([one.entries.length, one.truncated]).toEqual([1, true]);
  });

  it('refuses a ref that is not a commit id and paths outside the repository', async () => {
    const { dir, head } = repo();
    await expect(gitLog(executor, dir, '--output=/tmp/x')).rejects.toThrow(/resolved commit/);
    await expect(gitLog(executor, dir, 'HEAD')).rejects.toThrow(/resolved commit/);
    await expect(gitLog(executor, dir, head, { path: '../../etc/passwd' })).rejects.toThrow(/escapes/);
  });
});
