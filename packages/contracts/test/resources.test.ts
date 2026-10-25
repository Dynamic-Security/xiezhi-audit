// Resource root and version of an install: the repository root in a checkout, XIEZHI_AUDIT_HOME when set.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { appVersion, resourcePath, resourceRoot } from '@xiezhi/contracts';

const repo = join(import.meta.dirname, '..', '..', '..');

describe('resourceRoot / appVersion', () => {
  afterEach(() => { delete process.env.XIEZHI_AUDIT_HOME; });
  it('finds the checkout root by its rules/ and skills/, and reads the version from its package.json', () => {
    expect(resourceRoot()).toBe(repo);
    expect(resourcePath('rules')).toBe(join(repo, 'rules'));
    expect(appVersion()).toBe((JSON.parse(readFileSync(join(repo, 'package.json'), 'utf8')) as { version: string }).version);
  });
  it('XIEZHI_AUDIT_HOME wins; a home without package.json has version unknown', () => {
    process.env.XIEZHI_AUDIT_HOME = join(repo, 'rules');
    expect(resourceRoot()).toBe(join(repo, 'rules'));
    expect(appVersion()).toBe('unknown');
  });
});
