// regression: a source tree reached through a symlink (merged / shared cache) is copied as a directory.
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { copyTreeForRun } from '../src/runner.js';

describe('copyTree through a symlinked cache entry', () => {
  it('copies the real directory', () => {
    const root = mkdtempSync(join(tmpdir(), 'ca-symtree-'));
    mkdirSync(join(root, 'real/src'), { recursive: true });
    writeFileSync(join(root, 'real/src/a.py'), 'x = 1\n');
    symlinkSync(join(root, 'real'), join(root, 'link'));
    copyTreeForRun(join(root, 'link'), join(root, 'work/app'));
    expect(readFileSync(join(root, 'work/app/src/a.py'), 'utf8')).toBe('x = 1\n');
  });
});
