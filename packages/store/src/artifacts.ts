// Content-addressed artifact store. Writes are atomic and idempotent:
// tmp → fsync → link → fsync dir; EEXIST means the same bytes already exist.
import { randomBytes } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, linkSync, openSync, readFileSync, unlinkSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { AppError, sha256Hex } from '@xiezhi/contracts';
import type { Db } from './db.js';

export class ArtifactStore {
  constructor(readonly dir: string, private readonly db?: Db) {}

  path(sha: string): string {
    if (!/^[0-9a-f]{64}$/.test(sha)) throw new AppError('ARTIFACT_CORRUPT', 'invalid artifact id');
    return join(this.dir, sha);
  }

  put(content: string | Uint8Array, mediaType = 'application/octet-stream'): string {
    const bytes = typeof content === 'string' ? Buffer.from(content, 'utf8') : Buffer.from(content);
    const sha = sha256Hex(bytes);
    const target = this.path(sha);
    if (!existsSync(target)) {
      const tmp = join(this.dir, '.tmp', randomBytes(12).toString('hex'));
      const fd = openSync(tmp, 'wx', 0o600);
      try {
        writeSync(fd, bytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      try {
        linkSync(tmp, target);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      } finally {
        unlinkSync(tmp);
      }
      const dfd = openSync(this.dir, 'r');
      try { fsyncSync(dfd); } finally { closeSync(dfd); }
    }
    this.db?.run(
      `INSERT INTO artifact(sha256, size, media_type, created_at, updated_at) VALUES (?,?,?,?,?)
       ON CONFLICT(sha256) DO UPDATE SET updated_at = excluded.updated_at`,
      sha, bytes.length, mediaType, Date.now(), Date.now(),
    );
    return sha;
  }

  putJson(value: unknown): string {
    return this.put(JSON.stringify(value), 'application/json');
  }

  get(sha: string, verify = false): Buffer {
    const buf = readFileSync(this.path(sha));
    if (verify && sha256Hex(buf) !== sha) throw new AppError('ARTIFACT_CORRUPT', sha);
    return buf;
  }

  getText(sha: string): string {
    return this.get(sha).toString('utf8');
  }

  getJson<T>(sha: string): T {
    return JSON.parse(this.getText(sha)) as T;
  }

  has(sha: string): boolean {
    return existsSync(this.path(sha));
  }
}
