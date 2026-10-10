// Read-side view of an immutable snapshot: manifest lookups and guarded file access.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ManifestFile, SnapshotManifest } from '@xiezhi/contracts';
import { guardFile, type ManifestLookup } from '../pathguard.js';

export class SnapshotView implements ManifestLookup {
  private readonly files = new Map<string, ManifestFile>();
  private readonly excluded = new Map<string, string>();
  private readonly excludedDirs: [string, string][] = [];
  private readonly lineCache = new Map<string, string[]>();

  constructor(readonly repo: string, readonly root: string, readonly manifest: SnapshotManifest) {
    for (const f of manifest.files) this.files.set(f.path, f);
    for (const e of manifest.excluded) {
      this.excluded.set(e.path, e.reason);
      this.excludedDirs.push([e.path + '/', e.reason]);
    }
  }

  get rootHash(): string {
    return this.manifest.rootHash;
  }

  hasFile(path: string): boolean {
    return this.files.has(path);
  }

  file(path: string): ManifestFile | undefined {
    return this.files.get(path);
  }

  isExcluded(path: string): string | null {
    const direct = this.excluded.get(path);
    if (direct) return direct;
    for (const [prefix, reason] of this.excludedDirs) if (path.startsWith(prefix)) return reason;
    return null;
  }

  listFiles(): ManifestFile[] {
    return this.manifest.files;
  }

  /** Guarded path resolution; throws PathGuardError for traversal, excluded or unknown paths. */
  guard(input: string): string {
    return guardFile(this.root, input, this);
  }

  lines(relPath: string): string[] {
    let cached = this.lineCache.get(relPath);
    if (!cached) {
      const text = readFileSync(join(this.root, ...relPath.split('/')), 'utf8');
      cached = text.split(/\r?\n/);
      if (cached.length > 0 && cached[cached.length - 1] === '') cached.pop();
      if (this.lineCache.size > 200) this.lineCache.clear();
      this.lineCache.set(relPath, cached);
    }
    return cached;
  }

  text(relPath: string): string {
    return readFileSync(join(this.root, ...relPath.split('/')), 'utf8');
  }

  /** Check that a line range exists in a file (submit validation). */
  validRange(relPath: string, start: number, end: number): boolean {
    const f = this.files.get(relPath);
    if (!f) return false;
    return Number.isInteger(start) && Number.isInteger(end) && start >= 1 && end >= start && end <= Math.max(f.lines, 1);
  }
}
