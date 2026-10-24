// Built-in knowledge for the added frameworks — every new framework id has a skill whose
// applies_to names it and checklist items for authorization and injection; the skills validate and prefilter by
// framework.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AUDIT_LANGUAGE_INFO, KNOWLEDGE_FRAMEWORKS } from '@xiezhi/contracts';
import { installBuiltinSkills, prefilter, scanLayer, type TaskFacts } from '@xiezhi/knowledge';

const NEW_FRAMEWORKS = [
  'hapi', 'restify', 'egg', 'midway', 'nextjs', 'nuxt', 'servlet', 'struts2', 'jsp', 'webflux', 'vertx',
  'wordpress', 'yii', 'codeigniter', 'slim', 'beego', 'go-zero', 'kratos', 'grpc-gateway', 'tornado', 'aiohttp', 'sanic', 'falcon',
];
const facts = (o: Partial<TaskFacts>): TaskFacts => ({ scene: 'full', phase: 'hunt', languages: [], frameworks: [], vulnClasses: [], repoRoles: [], include: [], exclude: [], ...o });

function builtin() {
  const g = join(mkdtempSync(join(tmpdir(), 'ca-m1125-')), 'global');
  installBuiltinSkills(g);
  return scanLayer(g, 'global');
}

describe('framework knowledge', () => {
  it('the new framework ids are in the language table and the knowledge vocabulary', () => {
    for (const f of NEW_FRAMEWORKS) expect(KNOWLEDGE_FRAMEWORKS).toContain(f);
    expect(AUDIT_LANGUAGE_INFO.javascript.frameworks).toEqual(expect.arrayContaining(['nextjs', 'nuxt', 'egg', 'midway', 'hapi', 'restify']));
  });

  it('every new framework has a skill and authorization / injection checklist items; all built-in skills validate', () => {
    const scan = builtin();
    expect(scan.invalid).toEqual([]);
    for (const f of NEW_FRAMEWORKS) {
      const skills = scan.skills.filter((s) => s.appliesTo.frameworks?.includes(f));
      expect(skills.length, f).toBeGreaterThan(0);
      const items = skills.flatMap((s) => s.checklist ?? []).filter((i) => !i.appliesTo.frameworks || i.appliesTo.frameworks.includes(f));
      expect(items.some((i) => /^authz_/.test(i.vulnClass)), `${f} authz item`).toBe(true);
    }
    const injection = ['sqli', 'expression_injection', 'xss', 'ssrf', 'deserialization'];
    for (const name of ['wordpress-audit-method', 'php-mvc-audit-method', 'java-legacy-web-audit-method', 'go-frameworks-audit-method', 'nextjs-nuxt-audit-method']) {
      const s = scan.skills.find((x) => x.name === name)!;
      expect(s.checklist!.some((i) => injection.includes(i.vulnClass)), name).toBe(true);
    }
  });

  it('prefilter picks the framework skill and the language skill, not other frameworks’ skills', () => {
    const { skills } = builtin();
    const names = (t: TaskFacts) => prefilter(skills, t).map((s) => s.skill.name);
    const wp = names(facts({ languages: ['php'], frameworks: ['wordpress'] }));
    expect(wp).toEqual(expect.arrayContaining(['wordpress-audit-method', 'php-audit-method']));
    expect(wp).not.toContain('php-mvc-audit-method');
    expect(wp).not.toContain('nextjs-nuxt-audit-method');
    const next = names(facts({ languages: ['typescript'], frameworks: ['nextjs'] }));
    expect(next).toEqual(expect.arrayContaining(['nextjs-nuxt-audit-method', 'javascript-audit-method']));
    expect(next).not.toContain('node-frameworks-audit-method');
  });
});
