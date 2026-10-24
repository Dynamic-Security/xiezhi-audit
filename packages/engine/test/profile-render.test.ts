// A profile stored without one of its lists (restored raw from a transcript before the fix) crashed the
// threat-model section of every later session of its audit; rendering tolerates it.
import { describe, expect, it } from 'vitest';
import { renderThreatModel } from '../src/steps/profile.js';

describe('threat-model section of the system prompt', () => {
  it('renders a profile with a missing list instead of throwing', () => {
    const p = { summary: 's', techStack: ['go'], modules: [], authModel: '无', assets: [], roles: [], externalDependencies: [], assumptions: ['a'] } as never;
    const text = renderThreatModel(p);
    expect(text).toContain('鉴权模型：无');
    expect(text).toContain('前提假设');
    expect(text).not.toContain('信任边界');
  });
});
