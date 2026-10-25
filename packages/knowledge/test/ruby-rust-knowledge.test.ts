// Built-in knowledge for Ruby (Rails / Sinatra / Grape) and Rust (axum / actix-web / Rocket) — every
// framework has authorization and injection checklist items, the skills validate and are picked by language / framework.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AUDIT_LANGUAGE_INFO, KNOWLEDGE_FRAMEWORKS } from '@xiezhi/contracts';
import { installBuiltinSkills, prefilter, scanLayer, type TaskFacts } from '@xiezhi/knowledge';

const FRAMEWORKS = ['rails', 'sinatra', 'grape', 'axum', 'actix-web', 'rocket'];
const INJECTION = ['sqli', 'code_injection', 'ssti', 'ssrf', 'xss', 'deserialization', 'cmdi'];
const facts = (o: Partial<TaskFacts>): TaskFacts => ({ scene: 'full', phase: 'hunt', languages: [], frameworks: [], vulnClasses: [], repoRoles: [], include: [], exclude: [], ...o });
function builtin() {
  const g = join(mkdtempSync(join(tmpdir(), 'ca-m1135-')), 'global');
  installBuiltinSkills(g);
  return scanLayer(g, 'global');
}

describe('Ruby / Rust knowledge', () => {
  it('framework ids are in the language table and vocabulary; every framework has authorization and injection items', () => {
    expect(AUDIT_LANGUAGE_INFO.ruby.frameworks).toEqual(['rails', 'sinatra', 'grape']);
    expect(AUDIT_LANGUAGE_INFO.rust.frameworks).toEqual(['axum', 'actix-web', 'rocket']);
    const scan = builtin();
    expect(scan.invalid).toEqual([]);
    for (const f of FRAMEWORKS) {
      expect(KNOWLEDGE_FRAMEWORKS).toContain(f);
      const items = scan.skills.filter((s) => s.appliesTo.frameworks?.includes(f)).flatMap((s) => s.checklist ?? []).filter((i) => !i.appliesTo.frameworks || i.appliesTo.frameworks.includes(f));
      expect(items.some((i) => /^authz_/.test(i.vulnClass)), `${f} authz`).toBe(true);
      expect(items.some((i) => INJECTION.includes(i.vulnClass)), `${f} injection`).toBe(true);
    }
  });

  it('prefilter picks the language-family skill only for its language', () => {
    const { skills } = builtin();
    const names = (t: TaskFacts) => prefilter(skills, t).map((s) => s.skill.name);
    expect(names(facts({ languages: ['ruby'], frameworks: ['rails'] }))).toContain('ruby-rails-audit-method');
    expect(names(facts({ languages: ['rust'], frameworks: ['axum'] }))).toContain('rust-web-audit-method');
    expect(names(facts({ languages: ['rust'], frameworks: ['axum'] }))).not.toContain('ruby-rails-audit-method');
    expect(names(facts({ languages: ['python'], frameworks: ['flask'] }))).not.toContain('rust-web-audit-method');
  });
});
