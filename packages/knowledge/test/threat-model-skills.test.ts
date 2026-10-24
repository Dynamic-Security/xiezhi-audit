// Built-in threat-modeling skills, the `phase:threat_model` load phase, and push-guide targets.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { installBuiltinSkills, prefilter, scanLayer, validateSkillText, type TaskFacts } from '@xiezhi/knowledge';

const facts = (o: Partial<TaskFacts> = {}): TaskFacts => ({
  scene: 'full', phase: 'hunt', languages: [], frameworks: [], vulnClasses: [], repoRoles: [], include: [], exclude: [], ...o,
});
const THREAT_SKILLS = ['feishu-doc-read', 'threat-model-report-template', 'threat-model-style', 'threat-modeling-method'];

function builtin() {
  const g = join(mkdtempSync(join(tmpdir(), 'xz-m15k-')), 'global');
  installBuiltinSkills(g);
  return scanLayer(g, 'global');
}

describe('threat-model knowledge', () => {
  it('the built-in threat-model skills are valid and load only in the threat_model phase', () => {
    const scan = builtin();
    expect(scan.invalid).toEqual([]);
    for (const name of THREAT_SKILLS) expect(scan.skills.find((s) => s.name === name)?.load).toEqual({ mode: 'phase', phases: ['threat_model'] });

    const generation = prefilter(scan.skills, facts({ phase: 'threat_model' }));
    expect(generation.filter((s) => s.mode === 'body').map((s) => s.skill.name).sort()).toEqual(THREAT_SKILLS);
    for (const phase of ['plan', 'profile', 'hunt', 'challenge', 'reconcile', 'verify', 'report', 'conversation'] as const) {
      expect(prefilter(scan.skills, facts({ phase })).map((s) => s.skill.name).filter((n) => THREAT_SKILLS.includes(n)), phase).toEqual([]);
    }
  });

  it('the Feishu sync guide targets threat models; guides without a target push vulnerabilities', () => {
    const scan = builtin();
    expect(scan.skills.find((s) => s.name === 'feishu-doc-threat-model-sync')?.push).toMatchObject({
      target: 'threat_model', connector: 'Feishu', operation: 'create_doc', confirm: true, updateKey: 'doc', externalId: '$..document_id', updateOperations: ['overwrite_doc'],
    });
    expect(scan.skills.find((s) => s.name === 'jira-issue-push')?.push?.target).toBe('vulnerability');
    // Push guides never enter a session, the threat-model one included.
    expect(prefilter(scan.skills, facts({ phase: 'threat_model' })).some((s) => s.skill.category === 'push_guide')).toBe(false);
  });

  it('rejects an unknown phase or push target', () => {
    const head = (extra: string) => `---\nname: x-guide\ndescription: a push guide used only by the tests here\ncategory: push_guide\n${extra}---\nbody`;
    expect(validateSkillText(head('push:\n  connector: C\n  operation: op\n  target: wiki\n'), 'global', 'x-guide', 'file').errors)
      .toContain('push.target must be one of vulnerability, threat_model');
    const bad = '---\nname: y-method\ndescription: a method used only by the tests here\ncategory: audit_method\nload: phase:threat\n---\nbody';
    expect(validateSkillText(bad, 'global', 'y-method', 'file').errors).toContain('unknown phase threat');
  });
});
