// Audit mode flags and the top-up amount, shared by headless and client mode (审计模式).
import { parseTopUpMillions, type IncrementalSummaryDto } from '@xiezhi/contracts';
import { CliExit, EXIT_ERROR } from './io.js';

/** `--mode single|multi`, `--repos a,b` (multi targets), `--related x,y` (single: evidence-only repositories). */
export function modeArgs(mode: string | undefined, repos: string | undefined, related: string | undefined): { mode?: 'single' | 'multi'; repositories?: string[]; related?: string[] } {
  if (mode && mode !== 'single' && mode !== 'multi') throw new CliExit(EXIT_ERROR, '--mode 只能是 single 或 multi');
  const list = (v: string | undefined) => (v ? v.split(',').map((x) => x.trim()).filter(Boolean) : undefined);
  if (repos && mode !== 'multi') throw new CliExit(EXIT_ERROR, '--repos 用于多仓库合并审计（--mode multi）');
  if (related && mode === 'multi') throw new CliExit(EXIT_ERROR, '--related 用于单仓库审计');
  return { ...(mode ? { mode: mode as 'single' | 'multi' } : {}), ...(list(repos) ? { repositories: list(repos)! } : {}), ...(list(related) ? { related: list(related)! } : {}) };
}


/** `--add-tokens N` in M: 1–10000, the top-up range of the API. */
export function addTokensArg(text: string): number {
  const tokens = parseTopUpMillions(text);
  if (tokens === undefined) throw new CliExit(EXIT_ERROR, `--add-tokens 以 M（百万 tokens）为单位，范围 1–10000，例如 --add-tokens 5 追加 5M；收到 ${text}`);
  return tokens;
}

/** The plan's incremental lines: one, or one per target of a multi-repository audit. */
export function incrementalLines(i: IncrementalSummaryDto): string[] {
  const base = (b: IncrementalSummaryDto['base'] | null) => (b ? b.ref ?? (b.commit ? b.commit.slice(0, 12) : '上次审计的版本') : '没有基线，按全量审计');
  const line = (x: Omit<IncrementalSummaryDto, 'base' | 'repos'>, b: IncrementalSummaryDto['base'] | null) =>
    `对比 ${base(b)}；变更文件 新增 ${x.changedFiles.added} / 修改 ${x.changedFiles.modified} / 删除 ${x.changedFiles.deleted} / 移动 ${x.changedFiles.renamed}；影响分析 ${x.mode}${x.fallbackReasons.length ? `（${x.fallbackReasons.join(', ')}）` : ''}`;
  return i.repos?.length ? ['增量（逐仓库）：', ...i.repos.map((r) => `  ${r.repo}：${line(r, r.base)}`)] : [`增量：${line(i, i.base)}`];
}

/**
 * `--base`: the incremental baseline — a ref for a single-repository audit; `repo=ref,repo=ref` per repository for a
 * multi-repository one (repositories left out compare with their last audited version).
 */
export function baseArgs(mode: string | undefined, base: string | undefined): { baseRef?: string; baseRefs?: Record<string, string> } {
  if (!base) return {};
  if (mode !== 'multi') return { baseRef: base };
  const pairs = base.split(',').map((x) => x.trim()).filter(Boolean).map((x) => x.split('='));
  if (pairs.some((p) => p.length !== 2 || !p[0]!.trim() || !p[1]!.trim())) throw new CliExit(EXIT_ERROR, '多仓库增量审计的 --base 写成 仓库=分支或提交，多个用逗号分隔');
  return { baseRefs: Object.fromEntries(pairs.map(([k, v]) => [k!.trim(), v!.trim()])) };
}
