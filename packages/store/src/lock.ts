// Single-writer lock for a data-dir. Stale locks are reclaimed once the
// recorded pid is confirmed dead.
import { closeSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs';
import { AppError } from '@xiezhi/contracts';

export interface LockInfo { pid: number; startedAt: number; role: string; port?: number }

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === 'EPERM';
  }
}

export function readLock(path: string): LockInfo | null {
  try {
    return JSON.parse(readFileSync(path, 'utf8')) as LockInfo;
  } catch {
    return null;
  }
}

export class WriterLock {
  private released = false;
  private constructor(readonly path: string, readonly info: LockInfo) {}

  static acquire(path: string, role: string): WriterLock {
    const info: LockInfo = { pid: process.pid, startedAt: Date.now(), role };
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const fd = openSync(path, 'wx', 0o600);
        writeSync(fd, JSON.stringify(info));
        closeSync(fd);
        return new WriterLock(path, info);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
        const holder = readLock(path);
        if (holder && holder.pid !== process.pid && alive(holder.pid)) {
          throw new AppError('LOCK_HELD', `held by pid ${holder.pid} (${holder.role}) since ${new Date(holder.startedAt).toISOString()}`);
        }
        try { unlinkSync(path); } catch { /* raced with another reclaimer */ }
      }
    }
    throw new AppError('LOCK_HELD', 'could not acquire writer lock');
  }

  release(): void {
    if (this.released) return;
    this.released = true;
    const holder = readLock(this.path);
    if (holder?.pid === process.pid) {
      try { unlinkSync(this.path); } catch { /* already gone */ }
    }
  }
}
