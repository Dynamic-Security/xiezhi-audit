// Run result cache: a run is reused when nothing that can change it has changed — the sample
// (repositories and root hashes, scene input), the strategy override, the configuration (secrets and prices
// excluded), the knowledge set, the pi version, the product code under test and the repeat index. The code
// identity is the Git commit of a clean working tree; with uncommitted changes nothing is cached. Only
// completed and partial runs are stored: failures may be transient (gateway down, 429) and are re-run.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalJson, sha256Hex, type AppConfig } from '@xiezhi/contracts';
import { isFormat, type RunRecord } from './record.js';
import type { Sample } from './schema.js';
import { priced } from './util.js';

export const CACHE_FORMAT = 'xiezhi-eval-cache/1';
/** The key keeps the tag from before the rename, so results cached earlier are still hits. */
const CACHE_KEY_FORMAT = 'code-audit-eval-cache/1';

export interface CacheParts {
  code: string;
  pi: string;
  config: Record<string, unknown>;
  strategy: Record<string, unknown>;
  knowledge: { name: string; sha256: string }[];
  sample: Sample;
  repeat: number;
}

/** Labels, tags, tier and label policy only matter to selection and scoring, never to what the product does. */
function runInputs(s: Sample): Record<string, unknown> {
  const { labels: _l, tags: _t, tier: _r, label_policy: _p, partition: _q, ...rest } = s;
  return rest;
}

export function cacheKey(p: CacheParts): string {
  return sha256Hex(canonicalJson({
    format: CACHE_KEY_FORMAT, code: p.code, pi: p.pi, config: p.config, strategy: p.strategy, knowledge: p.knowledge, sample: runInputs(p.sample), repeat: p.repeat,
  }));
}

export function cacheStatus(o: { dir: string | undefined; mode: string; code: { revision: string | null; dirty: boolean | null }; codeId?: string }): { enabled: boolean; reason: string | null; codeId: string | null } {
  if (!o.dir) return { enabled: false, reason: '未指定缓存目录', codeId: null };
  if (o.mode !== 'live') return { enabled: false, reason: '回放模式不缓存', codeId: null };
  if (o.codeId) return { enabled: true, reason: null, codeId: o.codeId };
  if (!o.code.revision) return { enabled: false, reason: '无法确定被测代码的提交', codeId: null };
  if (o.code.dirty !== false) return { enabled: false, reason: '被测代码有未提交改动，无法确定代码身份', codeId: null };
  return { enabled: true, reason: null, codeId: o.code.revision };
}

const fileOf = (dir: string, key: string) => join(dir, key.slice(0, 2), `${key}.json`);

/**
 * A cached record, re-priced with the current configuration (prices are not part of the key). The record
 * says it came from the cache; its measured tokens and times are those of the original run.
 */
export function readCached(dir: string, key: string, cfg: AppConfig): RunRecord | null {
  const file = fileOf(dir, key);
  if (!existsSync(file)) return null;
  let entry: { format?: string; key?: string; record?: RunRecord };
  try {
    entry = JSON.parse(readFileSync(file, 'utf8')) as typeof entry;
  } catch {
    return null;
  }
  if (!isFormat(entry.format, CACHE_FORMAT) || entry.key !== key || !entry.record) return null;
  const rec = entry.record;
  for (const a of rec.audits) {
    for (const x of a.attempts) {
      const p = priced(cfg, x.provider, x.model, { in: x.tokens_in, out: x.tokens_out, cached: x.tokens_cached });
      x.cost_micros = p.cost;
      x.currency = p.currency;
    }
  }
  return { ...rec, cache: { key, hit: true } };
}

export function writeCached(dir: string, key: string, rec: RunRecord): boolean {
  if (rec.status !== 'completed' && rec.status !== 'partial') return false;
  const file = fileOf(dir, key);
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify({ format: CACHE_FORMAT, key, stored_at: new Date().toISOString(), record: { ...rec, cache: { key, hit: false } } }));
  renameSync(tmp, file);
  rec.cache = { key, hit: false };
  return true;
}
