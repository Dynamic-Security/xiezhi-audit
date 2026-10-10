// Immutable, content-addressed snapshots. resolve → stage → walk+exclude → hash →
// manifest → rootHash → reuse or atomic rename → read-only.
import { randomBytes } from 'node:crypto';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { canonicalJson, sha256Hex, type ExcludeReason, type SnapshotManifest } from '@xiezhi/contracts';
import type { Executor } from '../exec/executor.js';
import { runGit } from '../exec/git.js';
import { worktreeDirty } from './dirty.js';
import { ArchiveError, readArchive, scanArchive } from './archive.js';
import { detectLang, isBinary, makeExcluder, MAX_FILE_BYTES, type ExcludeOptions } from './exclude.js';
import { fetchToCache, lsRemote, RemoteGitError, resolveRemoteRef, type RemoteAuth, type RemoteUrl } from './remote.js';

export type SnapshotSource =
  | { kind: 'local'; path: string; ref?: string | undefined }
  /** Remote Git: resolved via ls-remote, fetched into the per-URL cache under `cacheRoot`. */
  | { kind: 'remote'; remote: RemoteUrl; ref?: string | undefined; cacheRoot: string; auth?: RemoteAuth }
  /** Uploaded archive; `fileName` is only the display locator. */
  | { kind: 'archive'; file: string; fileName: string };

export interface SnapshotRequest {
  source: SnapshotSource;
  snapshotsDir: string;
  tmpDir: string;
  executor: Executor;
  exclude?: ExcludeOptions;
  signal?: AbortSignal;
}

export interface SnapshotResult {
  manifest: SnapshotManifest;
  root: string;
  reused: boolean;
}

export class SnapshotError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SnapshotError';
  }
}

type FileEntry = SnapshotManifest['files'][number];

interface Staging {
  dir: string;
  files: FileEntry[];
  excluded: SnapshotManifest['excluded'];
  missing: SnapshotManifest['missing'];
}

function countLines(buf: Buffer): number {
  if (buf.length === 0) return 0;
  let n = 0;
  for (const b of buf) if (b === 10) n++;
  return buf[buf.length - 1] === 10 ? n : n + 1;
}

function stageFile(st: Staging, rel: string, content: Buffer): void {
  const lang = detectLang(rel);
  if (content.length > MAX_FILE_BYTES) {
    st.excluded.push({ path: rel, reason: 'oversize' });
    return;
  }
  if (isBinary(content)) {
    st.excluded.push({ path: rel, reason: 'binary' });
    return;
  }
  const target = join(st.dir, ...rel.split('/'));
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
  st.files.push({
    path: rel, sha256: sha256Hex(content), size: content.length, lines: countLines(content),
    ...(lang ? { lang } : {}), indexable: true,
  });
}

function walkLocal(root: string, st: Staging, excl: ReturnType<typeof makeExcluder>, signal?: AbortSignal): void {
  const realRoot = realpathSync(root);
  const visit = (absDir: string) => {
    if (signal?.aborted) throw new SnapshotError('cancelled');
    const entries = readdirSync(absDir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    const fileNames = entries.filter((e) => !e.isDirectory()).map((e) => e.name);
    for (const ent of entries) {
      const abs = join(absDir, ent.name);
      const rel = relative(root, abs).split(sep).join('/');
      const lst = lstatSync(abs);
      if (lst.isSymbolicLink()) {
        let target: string;
        try {
          target = realpathSync(abs);
        } catch {
          st.excluded.push({ path: rel, reason: 'symlink_escape' });
          continue;
        }
        const inside = target === realRoot || target.startsWith(realRoot + sep);
        if (!inside) { st.excluded.push({ path: rel, reason: 'symlink_escape' }); continue; }
        if (statSync(target).isDirectory()) { st.excluded.push({ path: rel, reason: 'skipped_symlink' }); continue; }
        const reason = excl.file(rel, ent.name);
        if (reason) { st.excluded.push({ path: rel, reason }); continue; }
        stageFile(st, rel, readFileSync(target));
        continue;
      }
      if (lst.isDirectory()) {
        const reason = excl.dir(rel, ent.name, fileNames);
        if (reason) { st.excluded.push({ path: rel, reason }); continue; }
        visit(abs);
      } else if (lst.isFile()) {
        const reason = excl.file(rel, ent.name);
        if (reason) { st.excluded.push({ path: rel, reason }); continue; }
        stageFile(st, rel, readFileSync(abs));
      }
    }
  };
  visit(root);
}

/** File names per directory of a listing ('' is the root), for the module-root test of the excluder. */
function filesByDir(paths: Iterable<string>): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const p of paths) {
    const cut = p.lastIndexOf('/');
    const dir = cut < 0 ? '' : p.slice(0, cut);
    const list = m.get(dir);
    if (list) list.push(p.slice(cut + 1)); else m.set(dir, [p.slice(cut + 1)]);
  }
  return m;
}

/** Directory-level exclusion for a listing-style walk: the first excluded ancestor, recorded once. */
function excludedAncestor(parts: string[], st: Staging, excl: ReturnType<typeof makeExcluder>, recorded: Set<string>, files: Map<string, string[]>): ExcludeReason | null {
  for (let i = 0; i < parts.length - 1; i++) {
    const dirPath = parts.slice(0, i + 1).join('/');
    const reason = excl.dir(dirPath, parts[i]!, files.get(parts.slice(0, i).join('/')) ?? []);
    if (reason) {
      if (!recorded.has(dirPath)) {
        recorded.add(dirPath);
        st.excluded.push({ path: dirPath, reason });
      }
      return reason;
    }
  }
  return null;
}

async function gitOut(executor: Executor, repo: string, sub: string, args: string[], signal?: AbortSignal): Promise<string> {
  const r = await runGit(executor, repo, sub, args, { collectStdout: true, ...(signal ? { signal } : {}) });
  if (r.status !== 'ok') throw new SnapshotError(`git ${sub} failed (${r.status}): ${r.stderr.inlinePreview.slice(0, 300)}`);
  return r.stdoutData!.toString('utf8');
}

async function walkGitRef(repo: string, ref: string, st: Staging, excl: ReturnType<typeof makeExcluder>, executor: Executor, signal?: AbortSignal): Promise<{ commit: string }> {
  if (ref.startsWith('-')) throw new SnapshotError('invalid ref');
  const commit = (await gitOut(executor, repo, 'rev-parse', ['--verify', '--end-of-options', `${ref}^{commit}`], signal)).trim();
  if (!/^[0-9a-f]{40,64}$/.test(commit)) throw new SnapshotError('could not resolve ref to a commit');
  // `-l` adds blob sizes: oversize blobs are excluded without reading them (a batch of large binaries
  // overflowed the executor's 64 MB output cap), and batches are bounded by bytes as well as by count.
  const tree = await gitOut(executor, repo, 'ls-tree', ['-r', '-z', '-l', '--full-tree', commit], signal);
  const blobs: { rel: string; sha: string; size: number }[] = [];
  const excludedDirs = new Set<string>();
  const records = tree.split('\0');
  const files = filesByDir(records.filter((r) => r && r.slice(0, r.indexOf('\t')).split(/ +/)[1] === 'blob').map((r) => r.slice(r.indexOf('\t') + 1)));
  for (const rec of records) {
    if (!rec) continue;
    const tab = rec.indexOf('\t');
    const [mode, type, sha, sizeText] = rec.slice(0, tab).split(/ +/);
    const rel = rec.slice(tab + 1);
    const parts = rel.split('/');
    if (excludedAncestor(parts, st, excl, excludedDirs, files)) continue;
    if (type === 'commit') { st.missing.push({ path: rel, kind: 'submodule', commit: sha! }); continue; }
    if (mode === '120000') { st.excluded.push({ path: rel, reason: 'skipped_symlink' }); continue; }
    if (type !== 'blob') continue;
    const reason = excl.file(rel, parts[parts.length - 1]!);
    if (reason) { st.excluded.push({ path: rel, reason }); continue; }
    blobs.push({ rel, sha: sha!, size: Number(sizeText) });
  }
  // Raw blobs only (cat-file --batch never runs filters/textconv). Consecutive slices of the tree order, at most
  // BATCH blobs and BATCH_BYTES of content each; an oversize blob is recorded in its place without being read.
  const BATCH = 500;
  const BATCH_BYTES = 48 * 1024 * 1024;
  for (let i = 0; i < blobs.length;) {
    const chunk: typeof blobs = [];
    let bytes = 0;
    while (i < blobs.length && chunk.length < BATCH) {
      const b = blobs[i]!;
      const fetched = Number.isFinite(b.size) && b.size > MAX_FILE_BYTES ? 0 : (Number.isFinite(b.size) ? b.size : 0);
      if (chunk.length && bytes + fetched > BATCH_BYTES) break;
      chunk.push(b);
      bytes += fetched;
      i++;
    }
    const wanted = chunk.filter((b) => !(Number.isFinite(b.size) && b.size > MAX_FILE_BYTES));
    let data: Buffer = Buffer.alloc(0);
    if (wanted.length) {
      const r = await runGit(executor, repo, 'cat-file', ['--batch'], {
        input: wanted.map((b) => b.sha).join('\n') + '\n', collectStdout: true, timeoutMs: 120_000, ...(signal ? { signal } : {}),
      });
      if (r.status !== 'ok') throw new SnapshotError(`git cat-file failed (${r.status})`);
      data = r.stdoutData!;
    }
    let off = 0;
    for (const b of chunk) {
      if (Number.isFinite(b.size) && b.size > MAX_FILE_BYTES) { st.excluded.push({ path: b.rel, reason: 'oversize' }); continue; }
      const nl = data.indexOf(10, off);
      const header = data.subarray(off, nl).toString('utf8');
      const size = Number(header.split(' ')[2]);
      if (!Number.isFinite(size)) throw new SnapshotError(`unexpected cat-file header: ${header.slice(0, 80)}`);
      const content = data.subarray(nl + 1, nl + 1 + size);
      off = nl + 1 + size + 1;
      if (content.length >= 40 && content.subarray(0, 40).toString('utf8').startsWith('version https://git-lfs')) {
        st.missing.push({ path: b.rel, kind: 'lfs' });
      }
      stageFile(st, b.rel, Buffer.from(content));
    }
  }
  return { commit };
}

async function walkArchive(file: string, st: Staging, excl: ReturnType<typeof makeExcluder>, signal?: AbortSignal): Promise<{ headCommit: string | null }> {
  const scan = await scanArchive(file);
  const excludedDirs = new Set<string>();
  const files = filesByDir(scan.files);
  await readArchive(file, scan, async (e) => {
    if (signal?.aborted) throw new SnapshotError('cancelled');
    const parts = e.path.split('/');
    if (excludedAncestor(parts, st, excl, excludedDirs, files)) return;
    const name = parts[parts.length - 1]!;
    if (e.type === 'dir') {
      const reason = excl.dir(e.path, name, files.get(parts.slice(0, -1).join('/')) ?? []);
      if (reason && !excludedDirs.has(e.path)) { excludedDirs.add(e.path); st.excluded.push({ path: e.path, reason }); }
      return;
    }
    const reason = excl.file(e.path, name);
    if (reason) { st.excluded.push({ path: e.path, reason }); return; }
    // Links inside archives are never restored.
    if (e.type === 'symlink') { st.excluded.push({ path: e.path, reason: 'skipped_symlink' }); return; }
    stageFile(st, e.path, await e.read());
  });
  return { headCommit: scan.headCommit };
}

async function worktreeInfo(executor: Executor, path: string): Promise<{ commit?: string; dirty?: boolean }> {
  if (!existsSync(join(path, '.git'))) return {};
  try {
    const commit = (await gitOut(executor, path, 'rev-parse', ['--verify', 'HEAD'])).trim();
    // Never `git status` here; it runs the repository's clean filters on modified files.
    const dirty = await worktreeDirty(executor, path);
    return { commit, ...(dirty === null ? {} : { dirty }) };
  } catch {
    return {};
  }
}

function makeReadOnly(dir: string): void {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) makeReadOnly(p);
    else chmodSync(p, 0o444);
  }
  chmodSync(dir, 0o555);
}

export function computeRootHash(files: FileEntry[]): string {
  return sha256Hex(canonicalJson(files.map((f) => [f.path, f.sha256])));
}

export async function createSnapshot(req: SnapshotRequest): Promise<SnapshotResult> {
  const { source } = req;
  if (source.kind === 'local' && (!existsSync(source.path) || !statSync(source.path).isDirectory())) throw new SnapshotError('source directory does not exist');
  if (source.kind === 'archive' && !existsSync(source.file)) throw new SnapshotError('uploaded archive no longer exists');
  const stageDir = join(req.tmpDir, `stage-${randomBytes(8).toString('hex')}`);
  mkdirSync(stageDir, { recursive: true, mode: 0o700 });
  mkdirSync(req.snapshotsDir, { recursive: true, mode: 0o700 });
  const st: Staging = { dir: stageDir, files: [], excluded: [], missing: [] };
  const excl = makeExcluder(req.exclude);
  try {
    let src: SnapshotManifest['source'];
    if (source.kind === 'remote') {
      const listing = await lsRemote(req.executor, source.remote, source.auth, req.signal);
      const resolved = resolveRemoteRef(listing, source.ref);
      const dir = await fetchToCache(req.executor, source.cacheRoot, source.remote, resolved, source.auth, req.signal);
      const { commit } = await walkGitRef(dir, resolved.commit, st, excl, req.executor, req.signal);
      src = { kind: 'git', locator: source.remote.url, ref: resolved.display, commit, worktree: false };
    } else if (source.kind === 'archive') {
      const { headCommit } = await walkArchive(source.file, st, excl, req.signal);
      src = { kind: 'archive', locator: source.fileName, ...(headCommit ? { commit: headCommit } : {}) };
    } else if (source.ref) {
      const { commit } = await walkGitRef(source.path, source.ref, st, excl, req.executor, req.signal);
      src = { kind: 'git', locator: source.path, ref: source.ref, commit, worktree: false };
    } else {
      walkLocal(source.path, st, excl, req.signal);
      const info = await worktreeInfo(req.executor, source.path);
      // A snapshot without a ref is always the working-tree version; HEAD is informative only.
      src = { kind: 'local', locator: source.path, worktree: true, ...(info.commit ? { commit: info.commit } : {}), ...(info.dirty !== undefined ? { dirty: info.dirty } : {}) };
    }
    const byPath = (a: { path: string }, b: { path: string }) => (Buffer.compare(Buffer.from(a.path), Buffer.from(b.path)));
    st.files.sort(byPath);
    st.excluded.sort(byPath);
    st.missing.sort(byPath);
    const rootHash = computeRootHash(st.files);
    const byLang: Record<string, number> = {};
    for (const f of st.files) if (f.lang) byLang[f.lang] = (byLang[f.lang] ?? 0) + 1;
    const manifest: SnapshotManifest = {
      rootHash, source: src, files: st.files, excluded: st.excluded, missing: st.missing,
      stats: { fileCount: st.files.length, totalBytes: st.files.reduce((n, f) => n + f.size, 0), byLang },
      createdAt: Date.now(),
    };
    const finalDir = join(req.snapshotsDir, rootHash);
    let reused = true;
    if (!existsSync(finalDir)) {
      try {
        renameSync(stageDir, finalDir);
        makeReadOnly(finalDir);
        reused = false;
      } catch (e) {
        if (!existsSync(finalDir)) throw e;
      }
    }
    return { manifest, root: finalDir, reused };
  } catch (e) {
    if (e instanceof RemoteGitError || e instanceof ArchiveError) throw new SnapshotError(e.message);
    throw e;
  } finally {
    if (existsSync(stageDir)) rmSync(stageDir, { recursive: true, force: true });
  }
}
