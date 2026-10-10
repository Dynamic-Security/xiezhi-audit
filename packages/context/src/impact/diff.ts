// Snapshot-to-snapshot change detection: which files changed between two manifests and
// which line ranges changed inside them. Works on snapshots only (never the live working tree), so it
// needs no git and treats local directories, archives and commits the same way.
import type { ChangedFiles, DiffHunk, SnapshotManifest } from '@xiezhi/contracts';

/** Compare two manifests by path and content hash; equal content under a new path is a rename. */
export function diffManifests(base: SnapshotManifest, head: SnapshotManifest): ChangedFiles {
  const b = new Map(base.files.map((f) => [f.path, f.sha256]));
  const h = new Map(head.files.map((f) => [f.path, f.sha256]));
  const modified: string[] = [];
  let added: string[] = [];
  let deleted: string[] = [];
  for (const [path, sha] of h) {
    const was = b.get(path);
    if (was === undefined) added.push(path);
    else if (was !== sha) modified.push(path);
  }
  for (const path of b.keys()) if (!h.has(path)) deleted.push(path);
  // A deleted file whose exact content reappears under an added path is a move (1:1, first come).
  const renamed: { from: string; to: string }[] = [];
  const addedBySha = new Map<string, string[]>();
  for (const p of added) {
    const sha = h.get(p)!;
    addedBySha.set(sha, [...(addedBySha.get(sha) ?? []), p]);
  }
  for (const from of [...deleted].sort()) {
    const candidates = addedBySha.get(b.get(from)!);
    const to = candidates?.shift();
    if (to) renamed.push({ from, to });
  }
  const moved = new Set(renamed.flatMap((r) => [r.from, r.to]));
  added = added.filter((p) => !moved.has(p));
  deleted = deleted.filter((p) => !moved.has(p));
  const sort = (xs: string[]) => xs.sort();
  return { added: sort(added), modified: sort(modified), deleted: sort(deleted), renamed: renamed.sort((x, y) => x.to.localeCompare(y.to)) };
}

/** Above this many differing lines a file is reported as one hunk (keeps Myers bounded). */
const MAX_EDIT_DISTANCE = 4000;

/**
 * Changed line ranges between two versions of a file (Myers O(ND) diff over lines). Hunks use 1-based
 * starts; a pure insertion has baseCount 0 and baseStart = the base line it follows.
 */
export function lineHunks(path: string, a: readonly string[], b: readonly string[]): DiffHunk[] {
  // Trim the common prefix and suffix first: most edits are local.
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const A = a.slice(pre, a.length - suf);
  const B = b.slice(pre, b.length - suf);
  if (A.length === 0 && B.length === 0) return [];
  const ops = myers(A, B);
  if (!ops) return [{ path, baseStart: A.length ? pre + 1 : pre, baseCount: A.length, headStart: B.length ? pre + 1 : pre, headCount: B.length }];
  // Group consecutive non-equal operations into hunks.
  const hunks: DiffHunk[] = [];
  let i = 0; // position in A
  let j = 0; // position in B
  let k = 0;
  while (k < ops.length) {
    if (ops[k] === '=') { i++; j++; k++; continue; }
    const si = i;
    const sj = j;
    while (k < ops.length && ops[k] !== '=') {
      if (ops[k] === '-') i++; else j++;
      k++;
    }
    const baseCount = i - si;
    const headCount = j - sj;
    hunks.push({
      path,
      baseStart: baseCount ? pre + si + 1 : pre + si, baseCount,
      headStart: headCount ? pre + sj + 1 : pre + sj, headCount,
    });
  }
  return hunks;
}

type Op = '=' | '-' | '+';

function myers(a: readonly string[], b: readonly string[]): Op[] | null {
  const n = a.length;
  const m = b.length;
  const max = n + m;
  const offset = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace: Int32Array[] = [];
  for (let d = 0; d <= max; d++) {
    if (d > MAX_EDIT_DISTANCE) return null;
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[offset + k - 1]! < v[offset + k + 1]!) ? v[offset + k + 1]! : v[offset + k - 1]! + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) { x++; y++; }
      v[offset + k] = x;
      if (x >= n && y >= m) return backtrack(trace, a.length, b.length, offset, d);
    }
  }
  return null;
}

function backtrack(trace: Int32Array[], n: number, m: number, offset: number, dEnd: number): Op[] {
  const ops: Op[] = [];
  let x = n;
  let y = m;
  for (let d = dEnd; d > 0; d--) {
    const v = trace[d]!;
    const k = x - y;
    const prevK = k === -d || (k !== d && v[offset + k - 1]! < v[offset + k + 1]!) ? k + 1 : k - 1;
    const prevX = v[offset + prevK]!;
    const prevY = prevX - prevK;
    while (x > prevX && y > prevY) { ops.push('='); x--; y--; }
    if (x === prevX) { ops.push('+'); y--; } else { ops.push('-'); x--; }
  }
  while (x > 0 && y > 0) { ops.push('='); x--; y--; }
  return ops.reverse();
}
