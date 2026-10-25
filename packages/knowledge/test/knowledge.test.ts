import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ArtifactStore } from '@xiezhi/store';
import {
  effectiveSkills, freezeSkills, installBuiltinSkills, loadFrozenSkill, prefilter, scanLayer, sessionKnowledge, validateSkillText, type TaskFacts,
} from '@xiezhi/knowledge';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-kn-'));
const facts = (o: Partial<TaskFacts> = {}): TaskFacts => ({
  scene: 'full', phase: 'hunt', languages: ['java'], frameworks: ['spring'], vulnClasses: [], repoRoles: [], include: [], exclude: [], ...o,
});

function artifacts() {
  const d = tmp();
  mkdirSync(join(d, '.tmp'));
  return new ArtifactStore(d);
}

describe('knowledge', () => {
  it('installs builtin skills once and they are all valid', () => {
    const g = join(tmp(), 'global');
    const first = installBuiltinSkills(g);
    expect(first.length).toBeGreaterThanOrEqual(7);
    writeFileSync(join(g, 'ssrf-method.md'), 'user edited');
    expect(installBuiltinSkills(g)).toEqual([]);
    const scan = scanLayer(g, 'global');
    expect(scan.invalid.map((i) => i.path)).toEqual([join(g, 'ssrf-method.md')]);
    expect(scan.skills.length).toBe(first.length - 1);
  });

  it('validates frontmatter and detects name conflicts', () => {
    const d = tmp();
    writeFileSync(join(d, 'bad-name.md'), '---\nname: other\ndescription: short\ncategory: nope\n---\nx');
    writeFileSync(join(d, 'dup.md'), '---\nname: dup\ndescription: a long enough description here\ncategory: audit_method\n---\n');
    mkdirSync(join(d, 'dup'));
    writeFileSync(join(d, 'dup', 'SKILL.md'), 'x');
    writeFileSync(join(d, 'biz.md'), '---\nname: biz\ndescription: business knowledge about orders\ncategory: 业务知识\n---\n');
    mkdirSync(join(d, '.drafts'));
    writeFileSync(join(d, '.drafts', 'x.md'), 'ignored');
    const scan = scanLayer(d, 'global');
    expect(scan.skills).toEqual([]);
    const errs = scan.invalid.map((i) => i.errors.join(';')).join('\n');
    expect(errs).toMatch(/must equal/);
    expect(errs).toMatch(/description/);
    expect(errs).toMatch(/both/);
    expect(errs).toMatch(/source is required/);
  });

  it('applies_to uses closed sets and known ids: free text is refused or warned, ids match case-insensitively', () => {
    const skill = (at: string) => `---\nname: shop-arch\ndescription: shop 系统架构：网关路由与服务调用，审计订单接口时加载\ncategory: architecture\nsource: "user:"\nverified: false\n${at}---\n正文\n`;
    // Seen with a real model: the organizer wrote business scenes and service names.
    const bad = validateSkillText(skill('applies_to:\n  scenes: [shop 系统架构审计]\n  repo_roles: [order-service]\n  frameworks: [Spring Cloud Gateway]\n'), 'project', 'shop-arch', 'file');
    expect(bad.errors).toEqual([expect.stringContaining('applies_to.scenes: shop 系统架构审计 not in full'), expect.stringContaining('applies_to.repo_roles: order-service not in')]);
    expect(bad.warnings).toEqual([expect.stringContaining('applies_to.frameworks: Spring Cloud Gateway is not a known id')]);
    const ok = validateSkillText(skill('applies_to:\n  scenes: [full, reverify]\n  languages: [Java]\n  frameworks: [spring]\n'), 'project', 'shop-arch', 'file');
    expect(ok.errors).toEqual([]);
    expect(ok.warnings).toEqual([]);
    const d = tmp();
    writeFileSync(join(d, 'shop-arch.md'), skill('applies_to:\n  languages: [Java]\n'));
    expect(prefilter(scanLayer(d, 'project').skills, facts()).map((x) => x.skill.name)).toEqual(['shop-arch']);
  });

  it('computes the effective set: project overrides global, disabled by name and category', () => {
    const g = tmp();
    const p = tmp();
    const skill = (dir: string, name: string, cat = 'audit_method', body = 'body') =>
      writeFileSync(join(dir, `${name}.md`), `---\nname: ${name}\ndescription: description of ${name} skill for tests\ncategory: ${cat}\nscope: x\n---\n${body}`);
    skill(g, 'aa-method'); skill(g, 'bb-method'); skill(g, 'cc-case', 'vuln_case'); skill(g, 'gone');
    skill(p, 'aa-method', 'audit_method', 'project version');
    writeFileSync(join(g, '_settings.json'), JSON.stringify({ disabled: ['gone'] }));
    writeFileSync(join(p, '_settings.json'), JSON.stringify({ disabled: ['bb-method'], disabled_categories: ['vuln_case'] }));
    const eff = effectiveSkills(scanLayer(g, 'global'), scanLayer(p, 'project'));
    expect(eff.map((s) => `${s.layer}:${s.name}`)).toEqual(['project:aa-method']);
  });

  it('prefilters by applies_to and phase, budgets bodies, freezes content and reads only allowed skills', () => {
    const g = join(tmp(), 'global');
    installBuiltinSkills(g);
    const a = artifacts();
    const frozen = freezeSkills(effectiveSkills(scanLayer(g, 'global'), null), a);
    const hunt = sessionKnowledge(frozen, facts(), a, [{ topic: 'ssrf redirect handling' }]);
    expect(hunt.bodies.map((b) => b.name)).toEqual(['fp-precedents-and-exclusions']);
    expect(hunt.indexText).toContain('spring-authz-method');
    expect(hunt.indexText).not.toContain('go-gin-middleware-method');
    expect(hunt.indexText).not.toContain('report-default-template');
    expect(hunt.indexText).toMatch(/ssrf-method.*建议阅读/);
    const report = sessionKnowledge(frozen, facts({ phase: 'report' }), a);
    expect(report.bodies.map((b) => b.name)).toEqual(['report-default-template']);
    const excluded = sessionKnowledge(frozen, facts({ exclude: ['spring-authz-method'], include: ['go-gin-middleware-method'] }), a);
    expect(excluded.readable.has('spring-authz-method')).toBe(false);
    expect(excluded.bodies.map((b) => b.name)).toContain('go-gin-middleware-method');
    const r = loadFrozenSkill(frozen, hunt.readable, a, { name: 'spring-authz-method' });
    expect(r.text).toContain('SecurityFilterChain');
    expect(loadFrozenSkill(frozen, hunt.readable, a, { name: 'spring-authz-method', file: '' }).file).toBe(r.file); // empty = omitted
    expect(() => loadFrozenSkill(frozen, excluded.readable, a, { name: 'spring-authz-method' })).toThrow(/not available/);
    // A one-file skill reads its body whatever file the model guessed (gpt-6-luna: its category, its name, "index").
    for (const file of ['authz', 'spring-authz-method', 'index', '../x']) {
      expect(loadFrozenSkill(frozen, hunt.readable, a, { name: 'spring-authz-method', file }).file).toBe(r.file);
    }
    // Frozen: later disk edits do not change what the audit reads.
    writeFileSync(join(g, 'spring-authz-method.md'), 'changed');
    expect(loadFrozenSkill(frozen, hunt.readable, a, { name: 'spring-authz-method' }).text).toContain('SecurityFilterChain');
  });
});
