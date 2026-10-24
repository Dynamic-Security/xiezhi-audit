// A conversation audit card is checked with the same strategy merge as audit creation, so a wrong
// strategyOverride (e.g. focus as a string) goes back to the model instead of failing when the user confirms.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { defaultAppConfig } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { strategyOverrideIssues } from '@xiezhi/engine';

function store() {
  const s = Store.open({ dataDir: join(mkdtempSync(join(tmpdir(), 'ca-so-')), 'data'), role: 'test' });
  s.saveConfig({
    ...defaultAppConfig(),
    modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl: 'http://127.0.0.1:9', apiKey: 'k-test-0000', models: [{ id: 'm1' }] }],
    defaultModel: { provider: 'gw', model: 'm1' },
  });
  return s;
}

describe('strategyOverrideIssues', () => {
  it('accepts no override and a well-formed focus/budget override', () => {
    const s = store();
    expect(strategyOverrideIssues(s, 'full', undefined)).toEqual([]);
    expect(strategyOverrideIssues(s, 'full', { focus: { categories: ['authz_object'], text: '订单越权' }, budget: { tokens: 2_000_000 } })).toEqual([]);
  });
  it('reports a focus given as a string with its path', () => {
    const issues = strategyOverrideIssues(store(), 'full', { focus: '越权' });
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.join('\n')).toContain('strategyOverride.focus');
  });
});
