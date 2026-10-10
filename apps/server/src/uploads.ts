// Archive upload staging (`/uploads`): `<data-dir>/tmp/uploads/<id>/`, 0700,
// streamed to disk with a hard size cap, removed after 24 hours (at startup and hourly).
import { randomBytes } from 'node:crypto';
import { createWriteStream, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { AppError, type UploadDto } from '@xiezhi/contracts';
import { cleanFileName } from '@xiezhi/engine';

export const UPLOAD_MAX_BYTES = 2 * 1024 ** 3;
export const UPLOAD_TTL_MS = 24 * 3600_000;
const ID = /^upl_[0-9a-f]{24}$/;

interface Meta { fileName: string; size: number; createdAt: number }

export class Uploads {
  constructor(readonly dir: string, private readonly maxBytes = UPLOAD_MAX_BYTES) {}

  async save(body: Readable, rawName: string): Promise<UploadDto> {
    const id = `upl_${randomBytes(12).toString('hex')}`;
    const dir = join(this.dir, id);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    let size = 0;
    const max = this.maxBytes;
    const cap = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        size += chunk.length;
        if (size > max) cb(new AppError('UPLOAD_TOO_LARGE', `limit ${Math.round(max / 1024 ** 2)} MB`));
        else cb(null, chunk);
      },
    });
    try {
      await pipeline(body, cap, createWriteStream(join(dir, 'archive'), { mode: 0o600 }));
    } catch (e) {
      rmSync(dir, { recursive: true, force: true });
      if (e instanceof AppError) throw e;
      throw new AppError('COMMON_VALIDATION', 'upload interrupted');
    }
    if (size === 0) {
      rmSync(dir, { recursive: true, force: true });
      throw new AppError('COMMON_VALIDATION', 'empty upload');
    }
    const meta: Meta = { fileName: cleanFileName(rawName), size, createdAt: Date.now() };
    writeFileSync(join(dir, 'meta.json'), JSON.stringify(meta), { mode: 0o600 });
    return { uploadId: id, fileName: meta.fileName, size, expiresAt: new Date(meta.createdAt + UPLOAD_TTL_MS).toISOString() };
  }

  get(id: string): { file: string; fileName: string; size: number } {
    if (!ID.test(id)) throw new AppError('UPLOAD_NOT_FOUND', id);
    const dir = join(this.dir, id);
    const metaFile = join(dir, 'meta.json');
    if (!existsSync(metaFile)) throw new AppError('UPLOAD_NOT_FOUND', id);
    const meta = JSON.parse(readFileSync(metaFile, 'utf8')) as Meta;
    if (Date.now() - meta.createdAt > UPLOAD_TTL_MS) throw new AppError('UPLOAD_NOT_FOUND', `${id} expired`);
    return { file: join(dir, 'archive'), fileName: meta.fileName, size: meta.size };
  }

  remove(id: string): void {
    if (ID.test(id)) rmSync(join(this.dir, id), { recursive: true, force: true });
  }

  /** Remove expired or half-written uploads. */
  sweep(now = Date.now()): number {
    if (!existsSync(this.dir)) return 0;
    let n = 0;
    for (const name of readdirSync(this.dir)) {
      const dir = join(this.dir, name);
      let createdAt: number;
      try {
        createdAt = (JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')) as Meta).createdAt;
      } catch {
        // No meta yet: still being written, or a partial write left by a crash — judge by its age.
        try { createdAt = statSync(dir).mtimeMs; } catch { continue; }
      }
      if (now - createdAt > UPLOAD_TTL_MS) {
        rmSync(dir, { recursive: true, force: true });
        n++;
      }
    }
    return n;
  }
}
