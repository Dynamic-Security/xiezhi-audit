// Small helpers shared by the eval commands.
import { chmodSync, existsSync, lstatSync, readdirSync, readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { parse } from 'yaml';
import { check, type AppConfig, type ValidationIssue } from '@xiezhi/contracts';
import type { TSchema, Static } from 'typebox';

export type EvalErrorCode =
  | 'BENCH_INVALID' | 'CONFIG_INVALID' | 'HOLDOUT_REFUSED' | 'HOLDOUT_LEAK' | 'PROVIDER_UNREACHABLE'
  | 'EXPERIMENT_INVALID' | 'RUN_INVALID' | 'NOT_IMPLEMENTED' | 'USAGE';

export class EvalError extends Error {
  constructor(readonly code: EvalErrorCode, message: string, readonly details: string[] = []) {
    super(message);
    this.name = 'EvalError';
  }
}

export function readYamlFile(path: string): unknown {
  try {
    return parse(readFileSync(path, 'utf8'), { uniqueKeys: true, maxAliasCount: 0 });
  } catch (e) {
    throw new EvalError('BENCH_INVALID', `无法解析 ${path}：${(e as Error).message.split('\n')[0]}`);
  }
}

export function validated<S extends TSchema>(schema: S, value: unknown, what: string): Static<S> {
  const r = check(schema, value);
  if (!r.ok) throw new EvalError('BENCH_INVALID', `${what} 不符合 schema`, r.issues.slice(0, 20).map((i: ValidationIssue) => `${i.path} ${i.message}`));
  return r.value;
}

/** Regular files under a directory (POSIX relative paths, sorted); symlinks are not followed. */
export function walkFiles(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string) => {
    for (const ent of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
      const abs = join(dir, ent.name);
      if (ent.isDirectory()) visit(abs);
      else if (ent.isFile()) out.push(relative(root, abs).split(sep).join('/'));
    }
  };
  if (existsSync(root)) visit(root);
  return out;
}

/** Remove a tree that may contain read-only snapshot directories. */
export function removeTree(path: string): void {
  if (!existsSync(path)) return;
  const unlock = (p: string) => {
    const st = lstatSync(p);
    if (st.isSymbolicLink()) return;
    try { chmodSync(p, st.isDirectory() ? 0o700 : 0o600); } catch { /* best effort */ }
    if (st.isDirectory()) for (const n of readdirSync(p)) unlock(join(p, n));
  };
  unlock(path);
  rmSync(path, { recursive: true, force: true });
}

export function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(value, null, 2) + '\n');
}

export function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

export const byString = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

export function round(x: number, digits = 4): number {
  const f = 10 ** digits;
  return Math.round(x * f) / f;
}

/** Safe ratio: null when the denominator is 0 (reported as "不适用", never as 100%). */
export function ratio(num: number, den: number): number | null {
  return den > 0 ? round(num / den) : null;
}

export function f1(p: number | null, r: number | null): number | null {
  if (p === null || r === null) return null;
  return p + r > 0 ? round((2 * p * r) / (p + r)) : 0;
}

/** Price a call from config.pricing (per million tokens → micro-units); null = unknown price (never 0). */
export function priced(cfg: AppConfig, provider: string | null, model: string | null, t: { in: number; out: number; cached: number }): { cost: number | null; currency: string | null } {
  if (t.in + t.out + t.cached === 0) return { cost: 0, currency: null };
  if (!model) return { cost: null, currency: null };
  // Same key as the engine (`provider/model`); a bare model id is accepted for model ids that carry a vendor prefix.
  const p = (provider ? cfg.pricing[`${provider}/${model}`] : undefined) ?? cfg.pricing[model];
  if (!p) return { cost: null, currency: null };
  // Pricing is per million tokens → micro-units per token.
  return { cost: Math.round(t.in * p.input + t.out * p.output + t.cached * (p.cacheRead ?? p.input)), currency: p.currency };
}
