// The 安全规范 category holds the enterprise's own security rules (KMS use, service-to-service
// authentication); it loads like an audit method, through the index on demand.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { prefilter, scanLayer, validateSkillText, type TaskFacts } from '@xiezhi/knowledge';

const facts = (o: Partial<TaskFacts> = {}): TaskFacts => ({
  scene: 'full', phase: 'hunt', languages: [], frameworks: [], vulnClasses: [], repoRoles: [], include: [], exclude: [], ...o,
});
const text = (category: string) => `---\nname: kms-usage\ndescription: 企业 KMS 使用规范，审计密钥、加解密与配置读取代码时加载\ncategory: ${category}\nload: on_demand\n---\n# KMS 使用规范\n`;

describe('security_spec category', () => {
  it('accepts security_spec and the Chinese aliases 安全规范 / 报告规范', () => {
    expect(validateSkillText(text('security_spec'), 'global', 'kms-usage', 'file')).toMatchObject({ errors: [], meta: { category: 'security_spec' } });
    expect(validateSkillText(text('安全规范'), 'global', 'kms-usage', 'file').meta?.category).toBe('security_spec');
    expect(validateSkillText(text('报告规范'), 'global', 'kms-usage', 'file').meta?.category).toBe('report');
  });

  it('enters audit sessions as an index entry', () => {
    const g = join(mkdtempSync(join(tmpdir(), 'xz-m1028-')), 'global');
    mkdirSync(g, { recursive: true });
    writeFileSync(join(g, 'kms-usage.md'), text('安全规范'));
    const scan = scanLayer(g, 'global');
    expect(scan.invalid).toEqual([]);
    expect(prefilter(scan.skills, facts()).map((s) => [s.skill.name, s.skill.category, s.mode])).toEqual([['kms-usage', 'security_spec', 'index']]);
  });
});
