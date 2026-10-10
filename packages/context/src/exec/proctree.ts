// Process-tree sampling for the executor's resource limits: descendant count
// (fork bombs) and summed RSS, plus finding descendants that escaped the process group. No cgroups or
// prlimit: Linux reads /proc, other POSIX systems ask `ps` (fixed absolute path,
// fixed arguments, no shell). Windows has no process groups here; sampling is disabled there.
import { spawn } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';

export interface ProcInfo {
  pid: number;
  ppid: number;
  pgid: number;
  rssBytes: number;
}

const PS = ['/bin/ps', '/usr/bin/ps'].find((p) => existsSync(p)) ?? null;
const PAGE = 4096;

export function samplingSupported(): boolean {
  if (process.platform === 'win32') return false;
  return process.platform === 'linux' ? existsSync('/proc/self/stat') : PS !== null;
}

/** One snapshot of the process table; null when it cannot be read. */
export async function listProcesses(): Promise<ProcInfo[] | null> {
  if (process.platform === 'linux' && existsSync('/proc/self/stat')) return fromProc();
  if (!PS || process.platform === 'win32') return null;
  return fromPs(PS);
}

function fromProc(): ProcInfo[] {
  const out: ProcInfo[] = [];
  for (const name of readdirSync('/proc')) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const stat = readFileSync(`/proc/${name}/stat`, 'utf8');
      // Field 2 (comm) may contain spaces and parentheses; the rest starts after the last ')'.
      const rest = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
      const rssPages = Number(rest[21]);
      out.push({ pid: Number(name), ppid: Number(rest[1]), pgid: Number(rest[2]), rssBytes: (Number.isFinite(rssPages) ? rssPages : 0) * PAGE });
    } catch { /* process exited while reading */ }
  }
  return out;
}

function fromPs(ps: string): Promise<ProcInfo[] | null> {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(ps, ['-A', '-o', 'pid=,ppid=,pgid=,rss='], { shell: false, stdio: ['ignore', 'pipe', 'ignore'], env: { PATH: '/usr/bin:/bin', LANG: 'C' } });
    } catch {
      resolve(null);
      return;
    }
    const chunks: Buffer[] = [];
    const timer = setTimeout(() => child.kill('SIGKILL'), 2000);
    child.stdout!.on('data', (c: Buffer) => chunks.push(c));
    child.on('error', () => { clearTimeout(timer); resolve(null); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) { resolve(null); return; }
      resolve(parsePs(Buffer.concat(chunks).toString('utf8')));
    });
  });
}

/** Parse `ps -o pid=,ppid=,pgid=,rss=` output (RSS in KiB). Exported for tests. */
export function parsePs(text: string): ProcInfo[] {
  const out: ProcInfo[] = [];
  for (const line of text.split('\n')) {
    const f = line.trim().split(/\s+/);
    if (f.length < 4) continue;
    const [pid, ppid, pgid, rss] = f.map(Number) as [number, number, number, number];
    if ([pid, ppid, pgid].every(Number.isInteger)) out.push({ pid, ppid, pgid, rssBytes: (Number.isFinite(rss) ? rss : 0) * 1024 });
  }
  return out;
}

/**
 * The tree rooted at `rootPid` (by ppid) plus every member of process group `pgid` and their
 * descendants, and any `known` pid still alive and re-parented to init (descendants seen earlier whose
 * parent died). The root itself is included.
 */
export function processTree(procs: ProcInfo[], rootPid: number, pgid: number, known: ReadonlySet<number> = new Set()): ProcInfo[] {
  const byParent = new Map<number, ProcInfo[]>();
  for (const p of procs) {
    const list = byParent.get(p.ppid);
    if (list) list.push(p);
    else byParent.set(p.ppid, [p]);
  }
  const seen = new Map<number, ProcInfo>();
  // A remembered pid only counts if it was re-parented to init; otherwise it may be a reused pid.
  const queue = procs.filter((p) => p.pid === rootPid || p.pgid === pgid || (known.has(p.pid) && p.ppid === 1));
  while (queue.length) {
    const p = queue.pop()!;
    if (seen.has(p.pid) || p.pid === process.pid) continue;
    seen.set(p.pid, p);
    for (const c of byParent.get(p.pid) ?? []) queue.push(c);
  }
  return [...seen.values()];
}
