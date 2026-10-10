// Audit mode flags shared by headless and client mode.
import { CliExit, EXIT_ERROR } from './io.js';

/** `--mode single|multi`, `--repos a,b` (multi targets), `--related x,y` (single: evidence-only repositories). */
export function modeArgs(mode: string | undefined, repos: string | undefined, related: string | undefined): { mode?: 'single' | 'multi'; repositories?: string[]; related?: string[] } {
  if (mode && mode !== 'single' && mode !== 'multi') throw new CliExit(EXIT_ERROR, '--mode 只能是 single 或 multi');
  const list = (v: string | undefined) => (v ? v.split(',').map((x) => x.trim()).filter(Boolean) : undefined);
  if (repos && mode !== 'multi') throw new CliExit(EXIT_ERROR, '--repos 用于多仓库合并审计（--mode multi）');
  if (related && mode === 'multi') throw new CliExit(EXIT_ERROR, '--related 用于单仓库审计');
  return { ...(mode ? { mode: mode as 'single' | 'multi' } : {}), ...(list(repos) ? { repositories: list(repos)! } : {}), ...(list(related) ? { related: list(related)! } : {}) };
}

