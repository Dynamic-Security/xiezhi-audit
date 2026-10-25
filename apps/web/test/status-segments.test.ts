// The status bar shows 画像 and 威胁建模 as one item “画像与威胁建模” (both are the system-understanding stage).
import { describe, expect, it } from 'vitest';
import { segmentItems, segmentMembers } from '../src/features/audits/segments';

describe('status-bar segment items', () => {
  it('a full audit: profile absorbs threat, the rest stay in order', () => {
    const segs = ['snapshot', 'index', 'plan', 'profile', 'threat', 'triage', 'hunt', 'finalize'];
    expect(segmentItems(segs)).toEqual([
      { key: 'snapshot', members: ['snapshot'] }, { key: 'index', members: ['index'] }, { key: 'plan', members: ['plan'] },
      { key: 'profile', members: ['profile', 'threat'] }, { key: 'triage', members: ['triage'] }, { key: 'hunt', members: ['hunt'] }, { key: 'finalize', members: ['finalize'] },
    ]);
    expect(segmentMembers('profile', segs)).toEqual(['profile', 'threat']);
  });

  it('incremental (no profile) keeps the threat model on its own; profile without a threat model covers only itself', () => {
    expect(segmentItems(['snapshot', 'plan', 'scope', 'threat', 'hunt']).map((i) => i.key)).toEqual(['snapshot', 'plan', 'scope', 'threat', 'hunt']);
    expect(segmentItems(['plan', 'profile', 'triage'])).toContainEqual({ key: 'profile', members: ['profile'] });
    expect(segmentMembers('hunt', ['plan', 'hunt'])).toEqual(['hunt']);
  });
});
