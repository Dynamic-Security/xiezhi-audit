// follow-up: built-in skills reach existing global layers — unmodified copies (by the install
// record or a known earlier version) are updated, user-edited copies are kept, missing ones are installed.
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BUILTIN_HISTORY, BUILTIN_RECORD, builtinSkillsDir, scanLayer, skillEntryHash, syncBuiltinSkills } from '@xiezhi/knowledge';

const skill = (name: string, body: string) => `---\nname: ${name}\ndescription: a long enough description for ${name}\ncategory: audit_method\n---\n${body}\n`;

function layout() {
  const root = mkdtempSync(join(tmpdir(), 'ca-builtin-'));
  const from = join(root, 'skills');
  const g = join(root, 'global');
  mkdirSync(from, { recursive: true });
  return { root, from, g };
}

describe('built-in skill sync', () => {
  it('installs, updates unmodified copies, keeps edited ones and records what it wrote', () => {
    const { from, g } = layout();
    writeFileSync(join(from, 'a-method.md'), skill('a-method', 'v1'));
    writeFileSync(join(from, 'b-method.md'), skill('b-method', 'v1'));
    mkdirSync(join(from, 'c-pack'));
    writeFileSync(join(from, 'c-pack', 'SKILL.md'), skill('c-pack', 'v1'));
    expect(syncBuiltinSkills(g, from)).toEqual({ installed: ['a-method.md', 'b-method.md', 'c-pack'], updated: [], kept: [] });
    expect(JSON.parse(readFileSync(join(g, BUILTIN_RECORD), 'utf8'))['a-method.md']).toBe(skillEntryHash(join(from, 'a-method.md')));
    // New release changes all three; the user edited b and the directory c.
    writeFileSync(join(g, 'b-method.md'), skill('b-method', 'my notes'));
    writeFileSync(join(g, 'c-pack', 'SKILL.md'), skill('c-pack', 'my case'));
    for (const [n, p] of [['a-method', 'a-method.md'], ['b-method', 'b-method.md']] as const) writeFileSync(join(from, p), skill(n, 'v2'));
    writeFileSync(join(from, 'c-pack', 'SKILL.md'), skill('c-pack', 'v2'));
    expect(syncBuiltinSkills(g, from)).toEqual({ installed: [], updated: ['a-method.md'], kept: ['b-method.md', 'c-pack'] });
    expect(readFileSync(join(g, 'a-method.md'), 'utf8')).toContain('v2');
    expect(readFileSync(join(g, 'b-method.md'), 'utf8')).toContain('my notes');
    // Nothing to do on the next start; the record file is not a skill.
    expect(syncBuiltinSkills(g, from)).toEqual({ installed: [], updated: [], kept: ['b-method.md', 'c-pack'] });
    expect(scanLayer(g, 'global').invalid).toEqual([]);
  });

  it('a layer installed before the record existed is updated when its copy is a known earlier version', () => {
    const { from, g } = layout();
    mkdirSync(g, { recursive: true });
    writeFileSync(join(g, 'a-method.md'), skill('a-method', 'v1'));
    writeFileSync(join(g, 'b-method.md'), skill('b-method', 'edited long ago'));
    const v1 = join(from, 'old.md');
    writeFileSync(v1, skill('a-method', 'v1'));
    const historyHash = skillEntryHash(v1);
    rmSync(v1);
    writeFileSync(join(from, 'a-method.md'), skill('a-method', 'v2'));
    writeFileSync(join(from, 'b-method.md'), skill('b-method', 'v2'));
    writeFileSync(join(from, BUILTIN_HISTORY), JSON.stringify({ 'a-method.md': [historyHash] }));
    expect(syncBuiltinSkills(g, from)).toEqual({ installed: [], updated: ['a-method.md'], kept: ['b-method.md'] });
    expect(readFileSync(join(g, 'a-method.md'), 'utf8')).toContain('v2');
  });

  it('the shipped history covers the earlier versions of the language skills', () => {
    const history = JSON.parse(readFileSync(join(builtinSkillsDir(), BUILTIN_HISTORY), 'utf8')) as Record<string, string[]>;
    for (const n of ['javascript-audit-method.md', 'php-audit-method.md', 'python-audit-method.md']) expect(history[n]?.length, n).toBeGreaterThan(0);
  });
});
