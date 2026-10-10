// Path guard: model-supplied paths must resolve inside the snapshot root and
// hit the manifest. Returns a normalized POSIX relative path or throws.
import { isAbsolute, posix, relative, resolve, sep } from 'node:path';

export class PathGuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PathGuardError';
  }
}

export function normalizeRelPath(root: string, input: string): string {
  if (typeof input !== 'string' || input.length === 0) throw new PathGuardError('empty path');
  if (input.includes('\0')) throw new PathGuardError('path contains NUL');
  const cleaned = input.replace(/\\/g, '/').replace(/^\.\/+/, '');
  if (isAbsolute(cleaned) || /^[A-Za-z]:\//.test(cleaned)) throw new PathGuardError('absolute paths are not allowed');
  const abs = resolve(root, cleaned);
  const rel = relative(root, abs);
  if (rel === '' ) return '';
  if (rel.startsWith('..') || isAbsolute(rel)) throw new PathGuardError('path escapes the snapshot root');
  return rel.split(sep).join(posix.sep);
}

export interface ManifestLookup {
  hasFile(path: string): boolean;
  isExcluded(path: string): string | null;
}

/** Guard + manifest hit: returns the relative path of an existing, non-excluded file. */
export function guardFile(root: string, input: string, manifest: ManifestLookup): string {
  const rel = normalizeRelPath(root, input);
  const excluded = manifest.isExcluded(rel);
  if (excluded) throw new PathGuardError(`path is excluded from the snapshot (${excluded})`);
  if (!manifest.hasFile(rel)) throw new PathGuardError('path is not in the snapshot manifest');
  return rel;
}
