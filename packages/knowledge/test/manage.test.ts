// Knowledge management on disk: edits with content-hash concurrency, sub-files, overrides,
// annotated listing, generated case index, watcher.
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { sha256Hex } from '@xiezhi/contracts';
import {
  deleteSkill, deleteSkillFile, effectiveSkills, installBuiltinSkills, INDEX_BEGIN, INDEX_END, KnowledgeError, listKnowledge, readSkill, readSkillFile,
  regenerateCaseIndexes, scanLayer, setOverride, watchKnowledge, writeSkillEntry, writeSkillFile, type KnowledgeChange,
} from '@xiezhi/knowledge';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-km-'));
const text = (name: string, extra = '', body = '正文') => `---\nname: ${name}\ndescription: 用于测试的审计方法说明，足够长的描述文字\ncategory: audit_method\n${extra}---\n${body}\n`;
const kerr = (fn: () => unknown) => { try { fn(); } catch (e) { return e as KnowledgeError; } throw new Error('expected a KnowledgeError'); };

describe('skill edits', () => {
  it('creates, edits with the entry hash, refuses stale or invalid writes, deletes', () => {
    const d = tmp();
    const created = writeSkillEntry(d, 'global', 'spring-x', text('spring-x'), null);
    expect(created).toMatchObject({ valid: true, form: 'file', entryFile: 'spring-x.md', category: 'audit_method', load: 'on_demand' });
    expect(kerr(() => writeSkillEntry(d, 'global', 'spring-x', text('spring-x'), null)).kind).toBe('exists');
    // Stale base → conflict carrying the disk version for the three-way view.
    const stale = kerr(() => writeSkillEntry(d, 'global', 'spring-x', text('spring-x', '', 'mine'), sha256Hex('old')));
    expect(stale.kind).toBe('conflict');
    expect(stale.detail.current).toEqual({ sha256: created.entrySha256, text: text('spring-x') });
    // Invalid text is never written.
    const bad = kerr(() => writeSkillEntry(d, 'global', 'spring-x', text('other-name'), created.entrySha256));
    expect(bad.kind).toBe('invalid');
    expect(bad.detail.errors!.join()).toMatch(/must equal/);
    expect(readFileSync(join(d, 'spring-x.md'), 'utf8')).toBe(text('spring-x'));
    const edited = writeSkillEntry(d, 'global', 'spring-x', text('spring-x', 'scope: project\n', '新正文'), created.entrySha256);
    expect(edited.warnings).toEqual([expect.stringMatching(/layer wins/)]);
    expect(readdirSync(d).filter((f) => f.startsWith('.'))).toEqual([]);
    expect(() => deleteSkill(d, 'spring-x', created.entrySha256)).toThrow(/changed on disk/);
    deleteSkill(d, 'spring-x', edited.entrySha256);
    expect(readSkill(d, 'global', 'spring-x')).toBeNull();
    expect(kerr(() => readSkill(d, 'global', '../x')).kind).toBe('bad_path');
  });

  it('turns a single-file skill into a directory on its first sub-file and guards sub-file paths', () => {
    const d = tmp();
    writeSkillEntry(d, 'project', 'orders', text('orders'), null);
    const withFile = writeSkillFile(d, 'project', 'orders', 'examples/Bad.java', 'class Bad {}', null);
    expect(withFile).toMatchObject({ form: 'dir', entryFile: 'SKILL.md', valid: true });
    expect(withFile.files.map((f) => f.path)).toEqual(['SKILL.md', 'examples/Bad.java']);
    expect(existsSync(join(d, 'orders.md'))).toBe(false);
    const f = readSkillFile(d, 'orders', 'examples/Bad.java');
    expect(f.text).toBe('class Bad {}');
    for (const p of ['../x.md', '.hidden.md', '_x.md', 'SKILL.md', 'a.exe']) expect(kerr(() => writeSkillFile(d, 'project', 'orders', p, 'x', null)).kind).toBe('bad_path');
    expect(kerr(() => writeSkillFile(d, 'project', 'orders', 'examples/Bad.java', 'y', null)).kind).toBe('conflict');
    const after = deleteSkillFile(d, 'project', 'orders', 'examples/Bad.java', f.sha256);
    expect(after.files.map((x) => x.path)).toEqual(['SKILL.md']);
  });
});

describe('overrides and listing', () => {
  it('annotates offline, project-disabled, category-disabled, overriding and invalid skills', () => {
    const g = tmp();
    const p = tmp();
    for (const n of ['aa-method', 'bb-method', 'cc-method']) writeSkillEntry(g, 'global', n, text(n), null);
    writeSkillEntry(p, 'project', 'aa-method', text('aa-method', '', 'project copy'), null);
    writeFileSync(join(p, 'broken.md'), '---\nname: broken\n---\n');
    setOverride(g, { name: 'cc-method' }, true);
    setOverride(p, { name: 'bb-method' }, true);
    setOverride(p, { category: 'audit_method' }, true);
    setOverride(p, { category: 'audit_method' }, false);
    expect(JSON.parse(readFileSync(join(p, '_settings.json'), 'utf8'))).toEqual({ disabled: ['bb-method'], disabled_categories: [] });

    const globalView = listKnowledge(g, new Map([['p1', p]]), {});
    expect(globalView.map((i) => [i.name, i.disabled, i.overriddenBy])).toEqual([['aa-method', false, ['p1']], ['bb-method', false, []], ['cc-method', true, []]]);

    const projectView = listKnowledge(g, new Map([['p1', p]]), { projectId: 'p1' });
    const row = (layer: string, name: string) => projectView.find((i) => i.layer === layer && i.name === name)!;
    expect(row('project', 'aa-method')).toMatchObject({ overridesGlobal: true, disabled: false });
    expect(row('global', 'aa-method')).toMatchObject({ overriddenBy: ['p1'] });
    expect(row('global', 'bb-method')).toMatchObject({ disabled: true, disabledBy: ['project_name'] });
    expect(row('global', 'cc-method')).toMatchObject({ disabled: true, disabledBy: ['global'] });
    expect(row('project', 'broken')).toMatchObject({ valid: false, path: 'broken.md' });
    expect(row('project', 'broken').errors.join()).toMatch(/description/);
    // The listing agrees with the effective set used by audits.
    const eff = effectiveSkills(scanLayer(g, 'global'), scanLayer(p, 'project')).map((s) => `${s.layer}:${s.name}`);
    expect(projectView.filter((i) => i.valid && !i.disabled && !(i.layer === 'global' && i.overriddenBy.length)).map((i) => `${i.layer}:${i.name}`).sort()).toEqual(eff.sort());
  });
});

describe('case library index', () => {
  it('regenerates only between the markers, by class, idempotently, listing invalid cases', () => {
    const g = tmp();
    installBuiltinSkills(g);
    const lib = join(g, 'vuln-cases');
    const kase = (file: string, cls: string, desc: string, when = '') => writeFileSync(join(lib, file), `---\nname: ${file.replace('.md', '')}\ndescription: ${desc}\nvuln_class: ${cls}\n${when ? `applies_when: ${when}\n` : ''}---\n## 漏洞模式\n`);
    kase('ssrf-webhook.md', 'ssrf', 'Webhook 回调地址未限制内网', '用户可配置回调 URL 的功能');
    kase('idor-order-2025.md', 'idor', '按订单 ID 查询未校验归属', 'Spring MVC，按资源 ID 读写的接口');
    kase('broken.md', 'nonsense', 'x');
    const [r] = regenerateCaseIndexes(g, 'global');
    expect(r).toMatchObject({ skill: 'vuln-cases', written: true, invalid: ['broken.md'] });
    const skillMd = readFileSync(join(lib, 'SKILL.md'), 'utf8');
    const generated = skillMd.slice(skillMd.indexOf(INDEX_BEGIN) + INDEX_BEGIN.length, skillMd.indexOf(INDEX_END));
    expect(generated).toBe([
      '', '## SSRF', '- `ssrf-webhook.md` — Webhook 回调地址未限制内网。适用：用户可配置回调 URL 的功能', '',
      '## 越权（IDOR）', '- `idor-order-2025.md` — 按订单 ID 查询未校验归属。适用：Spring MVC，按资源 ID 读写的接口', '',
      '## 无效案例', '- `broken.md` — （无效：unknown vuln_class "nonsense"）', '', '',
    ].join('\n'));
    expect(skillMd.startsWith('---\nname: vuln-cases')).toBe(true);
    expect(regenerateCaseIndexes(g, 'global')[0]!.written).toBe(false);
    expect(scanLayer(g, 'global').invalid).toEqual([]);
  });
});

describe('watcher', () => {
  it('batches changes per layer and ignores drafts and temp files', async () => {
    const root = tmp();
    const g = join(root, 'global');
    const projects = join(root, 'projects');
    mkdirSync(join(projects, 'p1', 'knowledge'), { recursive: true });
    const seen: KnowledgeChange[][] = [];
    const w = watchKnowledge(g, projects, (c) => seen.push(c), 100);
    try {
      // FSEvents may still report the directories created just before watching started.
      await new Promise((r) => setTimeout(r, 400));
      seen.length = 0;
      mkdirSync(join(g, '.drafts'), { recursive: true });
      writeFileSync(join(g, '.drafts', 'x.md'), 'draft');
      await new Promise((r) => setTimeout(r, 400));
      expect(seen).toEqual([]);
      writeSkillEntry(g, 'global', 'aa-method', text('aa-method'), null);
      writeSkillEntry(join(projects, 'p1', 'knowledge'), 'project', 'bb-method', text('bb-method'), null);
      writeFileSync(join(projects, 'p1', 'other.txt'), 'not knowledge');
      await new Promise((r) => setTimeout(r, 500));
      expect(w.active).toBe(true);
      expect(seen.flat().sort((a, b) => a.layer.localeCompare(b.layer))).toEqual([{ layer: 'global', projectId: null }, { layer: 'project', projectId: 'p1' }]);
    } finally {
      w.close();
    }
  });
});
