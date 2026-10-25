// Run directories and result caches written before the rename (`code-audit-eval-*`) are still read;
// new files carry `xiezhi-eval-*`.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { AppConfig } from '@xiezhi/contracts';
import { CACHE_FORMAT, readCached } from '../src/cache.js';
import { isFormat, META_FORMAT, RUN_FORMAT, type RunRecord } from '../src/record.js';
import { readRun } from '../src/score.js';
import { tmp } from './helpers.js';

describe('format tags from before the rename', () => {
  it('accepts the current and the old tag, nothing else', () => {
    expect(RUN_FORMAT).toBe('xiezhi-eval-run/1');
    expect(isFormat('xiezhi-eval-run/1', RUN_FORMAT)).toBe(true);
    expect(isFormat('code-audit-eval-run/1', RUN_FORMAT)).toBe(true);
    expect(isFormat('code-audit-eval-meta/1', RUN_FORMAT)).toBe(false);
    expect(isFormat(undefined, RUN_FORMAT)).toBe(false);
  });

  it('reads a run directory written with the old tags', () => {
    const dir = tmp();
    writeFileSync(join(dir, 'run.json'), JSON.stringify({ format: META_FORMAT.replace('xiezhi-', 'code-audit-'), name: 'old' }));
    mkdirSync(join(dir, 'samples', 's1'), { recursive: true });
    writeFileSync(join(dir, 'samples', 's1', 'r1.json'), JSON.stringify({ format: 'code-audit-eval-run/1', sample_id: 's1' }));
    const { meta, records } = readRun(dir);
    expect(meta.name).toBe('old');
    expect(records.map((r) => r.sample_id)).toEqual(['s1']);
  });

  it('hits a cache entry stored with the old tag', () => {
    const dir = tmp();
    const key = 'ab' + '0'.repeat(62);
    const rec = { sample_id: 's1', status: 'completed', audits: [] } as unknown as RunRecord;
    mkdirSync(join(dir, 'ab'), { recursive: true });
    writeFileSync(join(dir, 'ab', `${key}.json`), JSON.stringify({ format: 'code-audit-eval-cache/1', key, record: rec }));
    expect(CACHE_FORMAT).toBe('xiezhi-eval-cache/1');
    expect(readCached(dir, key, {} as AppConfig)?.cache).toEqual({ key, hit: true });
  });
});
