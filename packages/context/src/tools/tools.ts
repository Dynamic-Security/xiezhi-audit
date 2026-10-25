// Read-only audit tool implementations. Every tool acts only on the audit's fixed
// snapshots; outputs above the inline limit are written to artifacts with a preview.
import picomatch from 'picomatch';
import type { ArtifactStore } from '@xiezhi/store';
import type { Executor } from '../exec/executor.js';
import { PathGuardError } from '../pathguard.js';
import type { SnapshotView } from '../snapshot/view.js';

export const OUTPUT_INLINE_LIMIT = 50 * 1024;
const PREVIEW_BYTES = 8 * 1024;
export const READ_MAX_LINES = 800;

export class ToolInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ToolInputError';
  }
}

export interface ReadEvent { repo: string; path: string; startLine: number; endLine: number }

export interface ToolContext {
  views: ReadonlyMap<string, SnapshotView>;
  defaultRepo: string;
  executor: Executor;
  artifacts: ArtifactStore;
  /** Artifacts produced in this audit (read_artifact may only read these). */
  auditArtifacts: Set<string>;
  onRead?: (e: ReadEvent) => void;
  signal?: AbortSignal;
}

export interface Offloaded { preview: string; artifactId: string; totalItems?: number; totalBytes: number; hint: string }

function view(ctx: ToolContext, repo?: string): SnapshotView {
  const name = repo ?? ctx.defaultRepo;
  const v = ctx.views.get(name);
  if (!v) throw new ToolInputError(`unknown repo "${name}"; available: ${[...ctx.views.keys()].join(', ')}`);
  return v;
}

function offload(ctx: ToolContext, full: string, totalItems: number | undefined, hint: string): Offloaded {
  const artifactId = ctx.artifacts.put(full, 'text/plain');
  ctx.auditArtifacts.add(artifactId);
  return { preview: full.slice(0, PREVIEW_BYTES), artifactId, ...(totalItems !== undefined ? { totalItems } : {}), totalBytes: Buffer.byteLength(full), hint };
}

// ---- read -------------------------------------------------------------------

export interface ReadResult { repo: string; path: string; startLine: number; endLine: number; totalLines: number; truncated: boolean; text: string }

/**
 * A path given with the wrong repository (gpt-6-luna read orders-api's `app/main.py` as files-gateway's
 * in 6 of 86 reads) names the repository that has it.
 */
function guardInRepo(ctx: ToolContext, v: SnapshotView, path: string): string {
  try {
    return v.guard(path);
  } catch (e) {
    if (!(e instanceof PathGuardError) || !/not in the snapshot manifest/.test(e.message)) throw e;
    const has = (o: SnapshotView) => { try { o.guard(path); return true; } catch { return false; } };
    const other = [...ctx.views.values()].find((o) => o !== v && has(o));
    if (other) throw new PathGuardError(`path is not in ${v.repo}; it is in ${other.repo} (pass repo "${other.repo}")`);
    throw e;
  }
}

export function toolRead(ctx: ToolContext, args: { repo?: string; path: string; startLine?: number; endLine?: number }): ReadResult {
  const v = view(ctx, args.repo);
  const rel = guardInRepo(ctx, v, args.path);
  const lines = v.lines(rel);
  const total = lines.length;
  const start = Math.max(1, Math.floor(args.startLine ?? 1));
  if (total > 0 && start > total) throw new ToolInputError(`startLine ${start} is beyond end of file (${total} lines)`);
  const requestedEnd = Math.min(total, Math.floor(args.endLine ?? total));
  if (requestedEnd < start && total > 0) throw new ToolInputError('endLine must be ≥ startLine');
  let end = Math.min(requestedEnd, start + READ_MAX_LINES - 1);
  let truncated = end < requestedEnd;
  const out: string[] = [];
  let bytes = 0;
  for (let i = start; i <= end; i++) {
    const line = `${String(i).padStart(5)}  ${lines[i - 1] ?? ''}`;
    bytes += Buffer.byteLength(line) + 1;
    if (bytes > OUTPUT_INLINE_LIMIT) {
      end = i - 1;
      truncated = true;
      break;
    }
    out.push(line);
  }
  if (end >= start) ctx.onRead?.({ repo: v.repo, path: rel, startLine: start, endLine: end });
  return { repo: v.repo, path: rel, startLine: start, endLine: Math.max(end, start - 1), totalLines: total, truncated, text: out.join('\n') };
}

// ---- grep (ripgrep wrapper) ---------------------------------------------------

export interface GrepMatch { repo: string; path: string; line: number; text: string; context?: boolean }
export interface GrepResult { matches: GrepMatch[]; total: number; truncated: boolean; offloaded?: Offloaded; errors?: string; note?: string }

export interface GrepArgs { repo?: string; pattern: string; regex?: boolean; glob?: string; caseSensitive?: boolean; context?: number; maxResults?: number }

/** Regex syntax a literal search would take as plain characters (`A|B`, `foo.*bar`, `\bword`, `(?i)`). */
const REGEX_LIKE = /\||\.\*|\\[bswd]|\(\?/;

export async function toolGrep(ctx: ToolContext, args: GrepArgs): Promise<GrepResult> {
  if (!args.pattern) throw new ToolInputError('pattern is required');
  const result = await grepOnce(ctx, args);
  // A literal search for `A|B` or `foo.*bar` finds nothing, and models read that as “not in the repository”; with
  // only a note they mostly move on instead of retrying, so search again as a regex right away.
  if (args.regex || result.total || !REGEX_LIKE.test(args.pattern)) return result;
  const again = await grepOnce(ctx, { ...args, regex: true });
  if (again.errors && !again.total) {
    return { ...result, note: 'the pattern was searched as a literal string (regex is off) and is not a valid regex either' };
  }
  return { ...again, note: `no literal matches; the pattern looks like a regex, so it was searched again with regex: true (${again.total} matches)` };
}

async function grepOnce(ctx: ToolContext, args: GrepArgs): Promise<GrepResult> {
  const targets = args.repo ? [view(ctx, args.repo)] : [...ctx.views.values()];
  const context = Math.min(5, Math.max(0, Math.floor(args.context ?? 0)));
  const maxResults = Math.min(200, Math.max(1, Math.floor(args.maxResults ?? 100)));
  const all: GrepMatch[] = [];
  const errors: string[] = [];
  for (const v of targets) {
    const rgArgs = ['--no-config', '--no-follow', '--json', '--max-filesize', '5M', '--max-columns', '500', '--hidden'];
    if (!args.regex) rgArgs.push('--fixed-strings');
    if (!args.caseSensitive) rgArgs.push('--ignore-case');
    if (context) rgArgs.push('--context', String(context));
    if (args.glob) rgArgs.push('--glob', args.glob);
    rgArgs.push('--regexp', args.pattern, '--', '.');
    const r = await ctx.executor.run({
      command: 'rg', args: rgArgs, cwd: v.root, timeoutMs: 60_000, collectStdout: true, maxOutputBytes: 32 * 1024 * 1024,
      ...(ctx.signal ? { signal: ctx.signal } : {}),
    });
    if (r.status === 'timeout') throw new ToolInputError('grep timed out; narrow the pattern or add a glob');
    if (r.status === 'output_limit') throw new ToolInputError('grep output too large; narrow the pattern or add a glob');
    if (r.status !== 'ok' && !(r.status === 'exit_nonzero' && r.exitCode === 1)) {
      errors.push(`${v.repo}: ${r.stderr.inlinePreview.slice(0, 300)}`);
      continue;
    }
    for (const line of (r.stdoutData ?? Buffer.alloc(0)).toString('utf8').split('\n')) {
      if (!line) continue;
      let msg: { type: string; data: { path?: { text?: string }; line_number?: number; lines?: { text?: string } } };
      try { msg = JSON.parse(line); } catch { continue; }
      if (msg.type !== 'match' && msg.type !== 'context') continue;
      const p = (msg.data.path?.text ?? '').replace(/^\.\//, '');
      if (!v.hasFile(p)) continue;
      all.push({ repo: v.repo, path: p, line: msg.data.line_number ?? 0, text: (msg.data.lines?.text ?? '').replace(/\n$/, '').slice(0, 500), ...(msg.type === 'context' ? { context: true } : {}) });
    }
  }
  all.sort((a, b) => (a.repo + a.path).localeCompare(b.repo + b.path) || a.line - b.line);
  const matchCount = all.filter((m) => !m.context).length;
  const result: GrepResult = { matches: all, total: matchCount, truncated: false, ...(errors.length ? { errors: errors.join('\n') } : {}) };
  let kept = 0;
  const limited: GrepMatch[] = [];
  for (const m of all) {
    if (!m.context) kept++;
    if (kept > maxResults) break;
    limited.push(m);
  }
  const serialized = JSON.stringify(all);
  if (limited.length < all.length || Buffer.byteLength(serialized) > OUTPUT_INLINE_LIMIT) {
    result.truncated = true;
    result.matches = limited.slice(0, 200);
    result.offloaded = offload(ctx, all.map((m) => `${m.repo}:${m.path}:${m.line}${m.context ? '-' : ':'}${m.text}`).join('\n'), matchCount,
      'Full results saved; page with read_artifact(artifactId, offset, limit) or narrow the pattern/glob.');
  }
  return result;
}

// ---- glob / list -------------------------------------------------------------

export function toolGlob(ctx: ToolContext, args: { repo?: string; pattern: string }): { paths: string[]; total: number; truncated: boolean } {
  const isMatch = picomatch(args.pattern, { dot: true });
  const views = args.repo ? [view(ctx, args.repo)] : [...ctx.views.values()];
  const multi = views.length > 1;
  const paths: string[] = [];
  for (const v of views) for (const f of v.listFiles()) if (isMatch(f.path)) paths.push(multi ? `${v.repo}:${f.path}` : f.path);
  return { paths: paths.slice(0, 2000), total: paths.length, truncated: paths.length > 2000 };
}

export function toolList(ctx: ToolContext, args: { repo?: string; dir?: string; depth?: number }): { entries: string[]; truncated: boolean } {
  const v = view(ctx, args.repo);
  const depth = Math.min(3, Math.max(1, Math.floor(args.depth ?? 1)));
  let dir = '';
  if (args.dir && args.dir !== '.' && args.dir !== '/') {
    try {
      dir = v.guard(args.dir);
    } catch (e) {
      if (!(e instanceof PathGuardError) || /escapes|absolute|NUL/.test(e.message)) throw e;
      dir = args.dir.replace(/^\.\/+/, '').replace(/\/+$/, '');
    }
  }
  const prefix = dir ? `${dir}/` : '';
  const seen = new Set<string>();
  const add = (p: string, suffix: string) => {
    const rest = p.slice(prefix.length).split('/');
    for (let d = 1; d <= Math.min(depth, rest.length); d++) {
      const isLeaf = d === rest.length;
      seen.add(rest.slice(0, d).join('/') + (isLeaf ? suffix : '/'));
    }
  };
  for (const f of v.listFiles()) if (f.path.startsWith(prefix)) add(f.path, '');
  for (const e of v.manifest.excluded) if (e.path.startsWith(prefix)) add(e.path, `  [excluded: ${e.reason}]`);
  const entries = [...seen].sort();
  return { entries: entries.slice(0, 2000), truncated: entries.length > 2000 };
}

export function toolReadArtifact(ctx: ToolContext, args: { artifactId: string; offset?: number; limit?: number }): { text: string; offset: number; totalBytes: number; done: boolean } {
  if (!ctx.auditArtifacts.has(args.artifactId)) throw new ToolInputError('artifact not available in this audit');
  const buf = ctx.artifacts.get(args.artifactId);
  const offset = Math.max(0, Math.floor(args.offset ?? 0));
  const limit = Math.min(OUTPUT_INLINE_LIMIT, Math.max(1, Math.floor(args.limit ?? 16 * 1024)));
  const text = buf.subarray(offset, offset + limit).toString('utf8');
  return { text, offset, totalBytes: buf.length, done: offset + limit >= buf.length };
}
