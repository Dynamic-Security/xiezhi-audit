// Uploaded archives. zip via yauzl, tar / tar.gz via
// tar-stream; no system tar/unzip. Every entry is checked by us: path shape, type, per-file and total
// size, entry count and compression ratio. Nothing is ever written outside the caller's staging.
import { closeSync, createReadStream, openSync, readSync, statSync } from 'node:fs';
import { createGunzip } from 'node:zlib';
import * as tar from 'tar-stream';
import * as yauzl from 'yauzl';

export const ARCHIVE_LIMITS = {
  maxEntries: 200_000,
  maxTotalBytes: 2 * 1024 ** 3,
  maxFileBytes: 100 * 1024 ** 2,
  maxRatio: 100,
  /** The ratio check applies once the uncompressed total exceeds this (tiny text archives compress well). */
  ratioFloorBytes: 1024 ** 2,
};
export type ArchiveLimits = typeof ARCHIVE_LIMITS;

export type ArchiveFormat = 'zip' | 'tar' | 'tgz';

export class ArchiveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ArchiveError';
  }
}

export type EntryType = 'file' | 'dir' | 'symlink';

export interface ArchiveEntry {
  /** Normalized POSIX path, common top-level directory removed. */
  path: string;
  type: EntryType;
  size: number;
  /** Content of a `file` entry, size-checked. Not calling it skips the entry. */
  read(): Promise<Buffer>;
}

export interface ArchiveScan {
  format: ArchiveFormat;
  fileCount: number;
  totalBytes: number;
  /** Paths (after prefix removal) of every file entry, for quick language detection. */
  files: string[];
  stripPrefix: string | null;
  /** HEAD commit read from an embedded `.git/`, display only. */
  headCommit: string | null;
}

export function detectArchiveFormat(file: string): ArchiveFormat | null {
  const fd = openSync(file, 'r');
  try {
    const head = Buffer.alloc(512);
    const n = readSync(fd, head, 0, 512, 0);
    if (n >= 4 && head[0] === 0x50 && head[1] === 0x4b && (head[2] === 3 || head[2] === 5) ) return 'zip';
    if (n >= 2 && head[0] === 0x1f && head[1] === 0x8b) return 'tgz';
    if (n >= 262 && head.subarray(257, 262).toString('latin1') === 'ustar') return 'tar';
    return null;
  } finally {
    closeSync(fd);
  }
}

/** Normalize an entry name; throws on shapes that only malicious or broken archives contain. */
export function normalizeEntryPath(raw: string): string {
  // eslint-disable-next-line no-control-regex -- rejecting control characters is the point
  if (/[\0-\x1f]/.test(raw)) throw new ArchiveError(`entry name contains control characters: ${JSON.stringify(raw.slice(0, 80))}`);
  const s = raw.replace(/\\/g, '/').normalize('NFC');
  if (s.startsWith('/') || /^[A-Za-z]:/.test(s)) throw new ArchiveError(`absolute path in archive: ${s.slice(0, 200)}`);
  const parts = s.split('/').filter((p) => p !== '' && p !== '.');
  if (parts.includes('..')) throw new ArchiveError(`path traversal in archive: ${s.slice(0, 200)}`);
  return parts.join('/');
}

interface RawEntry {
  path: string;
  type: EntryType;
  size: number;
  read(): Promise<Buffer>;
}

async function collect(stream: AsyncIterable<unknown> & { destroy(): unknown }, max: number, what: string): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let n = 0;
  for await (const c of stream) {
    n += (c as Buffer).length;
    if (n > max) {
      stream.destroy();
      throw new ArchiveError(`${what} exceeds ${Math.round(max / 1048576)} MB`);
    }
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}

/** Iterate raw entries in archive order; `visit` may call `read()` once for files. */
async function iterate(file: string, format: ArchiveFormat, limits: ArchiveLimits, visit: (e: RawEntry) => Promise<void>): Promise<void> {
  if (format === 'zip') return iterateZip(file, limits, visit);
  return iterateTar(file, format === 'tgz', limits, visit);
}

function iterateZip(file: string, limits: ArchiveLimits, visit: (e: RawEntry) => Promise<void>): Promise<void> {
  return new Promise((resolve, reject) => {
    yauzl.open(file, { lazyEntries: true, autoClose: true, decodeStrings: true, validateEntrySizes: true, strictFileNames: false }, (err, zip) => {
      if (err || !zip) { reject(new ArchiveError(`not a readable zip: ${err?.message ?? 'unknown'}`)); return; }
      if (zip.entryCount > limits.maxEntries) { zip.close(); reject(new ArchiveError(`archive has ${zip.entryCount} entries (limit ${limits.maxEntries})`)); return; }
      let failed = false;
      const fail = (e: unknown) => { if (failed) return; failed = true; try { zip.close(); } catch { /* already closed */ } reject(e instanceof ArchiveError ? e : new ArchiveError(String((e as Error)?.message ?? e))); };
      zip.on('error', fail);
      zip.on('end', () => { if (!failed) resolve(); });
      zip.on('entry', (entry: yauzl.Entry) => {
        const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
        const isDir = entry.fileName.endsWith('/') || mode === 0o040000;
        const type: EntryType | 'other' = isDir ? 'dir' : mode === 0o120000 ? 'symlink' : mode === 0 || mode === 0o100000 ? 'file' : 'other';
        if (type === 'other') { fail(new ArchiveError(`special file in archive: ${entry.fileName.slice(0, 200)}`)); return; }
        let read = false;
        const raw: RawEntry = {
          path: entry.fileName, type, size: entry.uncompressedSize,
          read: () => {
            if (read) throw new Error('entry already read');
            read = true;
            if (entry.uncompressedSize > limits.maxFileBytes) return Promise.reject(new ArchiveError(`${entry.fileName} exceeds ${limits.maxFileBytes / 1048576} MB`));
            return new Promise<Buffer>((res, rej) => zip.openReadStream(entry, (e, s) => {
              if (e || !s) { rej(new ArchiveError(`cannot read ${entry.fileName}: ${e?.message}`)); return; }
              collect(s, limits.maxFileBytes, entry.fileName).then(res, rej);
            }));
          },
        };
        visit(raw).then(() => { if (!failed) zip.readEntry(); }, fail);
      });
      zip.readEntry();
    });
  });
}

function iterateTar(file: string, gz: boolean, limits: ArchiveLimits, visit: (e: RawEntry) => Promise<void>): Promise<void> {
  return new Promise((resolve, reject) => {
    const extract = tar.extract();
    const input = createReadStream(file);
    let failed = false;
    const fail = (e: unknown) => {
      if (failed) return;
      failed = true;
      input.destroy();
      extract.destroy();
      reject(e instanceof ArchiveError ? e : new ArchiveError(`not a readable tar archive: ${String((e as Error)?.message ?? e)}`));
    };
    extract.on('entry', (header, stream, next) => {
      const t = header.type;
      const type: EntryType | 'other' = t === 'file' || t === 'contiguous-file' ? 'file' : t === 'directory' ? 'dir' : t === 'symlink' || t === 'link' ? 'symlink' : 'other';
      if (type === 'other') { stream.resume(); fail(new ArchiveError(`special file in archive: ${header.name.slice(0, 200)} (${t})`)); return; }
      let consumed = false;
      const size = header.size ?? 0;
      const raw: RawEntry = {
        path: header.name, type, size,
        read: () => {
          consumed = true;
          if (size > limits.maxFileBytes) { stream.resume(); return Promise.reject(new ArchiveError(`${header.name} exceeds ${limits.maxFileBytes / 1048576} MB`)); }
          return collect(stream, limits.maxFileBytes, header.name);
        },
      };
      visit(raw).then(() => {
        if (failed) return;
        if (!consumed) { stream.on('end', () => next()); stream.resume(); } else next();
      }, (e) => { stream.resume(); fail(e); });
    });
    extract.on('finish', () => { if (!failed) resolve(); });
    extract.on('error', fail);
    input.on('error', fail);
    if (gz) {
      const gunzip = createGunzip();
      gunzip.on('error', fail);
      input.pipe(gunzip).pipe(extract);
    } else input.pipe(extract);
  });
}

const GIT_META = /^(?:(.+)\/)?\.git\/(HEAD|packed-refs|refs\/.+)$/;
const JUNK = /^__MACOSX(\/|$)/;

function resolveHead(meta: Map<string, string>): string | null {
  const head = meta.get('HEAD')?.trim();
  if (!head) return null;
  if (/^[0-9a-f]{40}$/.test(head)) return head;
  const m = /^ref: (refs\/[^\s]+)$/.exec(head);
  if (!m) return null;
  const loose = meta.get(m[1]!)?.trim();
  if (loose && /^[0-9a-f]{40}$/.test(loose)) return loose;
  for (const line of (meta.get('packed-refs') ?? '').split('\n')) {
    const [sha, name] = line.trim().split(' ');
    if (name === m[1] && sha && /^[0-9a-f]{40}$/.test(sha)) return sha;
  }
  return null;
}

/**
 * First pass: validate every entry (paths, types, sizes, count, ratio, case collisions), decide the
 * common prefix and read the embedded HEAD. Throws ArchiveError on any violation.
 */
export async function scanArchive(file: string, limits: ArchiveLimits = ARCHIVE_LIMITS): Promise<ArchiveScan> {
  const format = detectArchiveFormat(file);
  if (!format) throw new ArchiveError('unsupported archive format (zip, tar, tar.gz only)');
  const archiveBytes = statSync(file).size;
  const seen = new Map<string, string>();
  const paths: { path: string; type: EntryType; size: number }[] = [];
  const gitMeta = new Map<string, Map<string, string>>();
  let count = 0;
  let total = 0;
  await iterate(file, format, limits, async (e) => {
    const path = normalizeEntryPath(e.path);
    if (!path || JUNK.test(path)) return;
    if (++count > limits.maxEntries) throw new ArchiveError(`archive has more than ${limits.maxEntries} entries`);
    if (e.type === 'file') {
      if (e.size > limits.maxFileBytes) throw new ArchiveError(`${path} exceeds ${limits.maxFileBytes / 1048576} MB`);
      total += e.size;
      if (total > limits.maxTotalBytes) throw new ArchiveError(`archive expands beyond ${limits.maxTotalBytes / 1024 ** 3} GB`);
      if (total > limits.ratioFloorBytes && total > archiveBytes * limits.maxRatio) throw new ArchiveError(`compression ratio exceeds ${limits.maxRatio}:1`);
    }
    const key = path.toLowerCase();
    const prev = seen.get(key);
    if (prev !== undefined && !(e.type === 'dir' && prev === path)) {
      throw new ArchiveError(prev === path ? `duplicate entry in archive: ${path}` : `entries differ only in case: ${prev} / ${path}`);
    }
    seen.set(key, path);
    paths.push({ path, type: e.type, size: e.size });
    const g = e.type === 'file' && e.size <= 64 * 1024 ? GIT_META.exec(path) : null;
    if (g) {
      const root = g[1] ?? '';
      const m = gitMeta.get(root) ?? new Map<string, string>();
      m.set(g[2]!, (await e.read()).toString('utf8'));
      gitMeta.set(root, m);
    }
  });
  const tops = new Set(paths.map((p) => p.path.split('/')[0]!));
  const top = tops.size === 1 ? [...tops][0]! : null;
  const stripPrefix = top && paths.some((p) => p.path.startsWith(`${top}/`)) && !paths.some((p) => p.path === top && p.type !== 'dir') ? top : null;
  const strip = (p: string) => (stripPrefix ? p.slice(stripPrefix.length + 1) : p);
  const files = paths.filter((p) => p.type === 'file').map((p) => strip(p.path));
  return {
    format, fileCount: files.length, totalBytes: total, files, stripPrefix,
    headCommit: resolveHead(gitMeta.get(stripPrefix ?? '') ?? new Map()),
  };
}

/** Second pass: yield entries with the prefix removed. Call scanArchive first (it enforces the limits). */
export async function readArchive(file: string, scan: ArchiveScan, visit: (e: ArchiveEntry) => Promise<void>, limits: ArchiveLimits = ARCHIVE_LIMITS): Promise<void> {
  await iterate(file, scan.format, limits, async (e) => {
    let path = normalizeEntryPath(e.path);
    if (!path || JUNK.test(path)) return;
    if (scan.stripPrefix) {
      if (path === scan.stripPrefix) return;
      path = path.slice(scan.stripPrefix.length + 1);
    }
    await visit({ path, type: e.type, size: e.size, read: e.read });
  });
}
