// Quick-start templates: placeholders the user fills in (Tab order), the page object standing in for
// its placeholder, and every group rendering its templates.
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { QuickStart, TEMPLATE_GROUPS, fillContext, nextPlaceholder } from '../src/features/conversations/Templates';

describe('chat templates', () => {
  it('selects placeholders in order and wraps to the first', () => {
    const t = '新建项目【项目名】，添加仓库【Git 地址或本机目录】';
    const first = nextPlaceholder(t, 0)!;
    expect(t.slice(...first)).toBe('【项目名】');
    const second = nextPlaceholder(t, first[1])!;
    expect(t.slice(...second)).toBe('【Git 地址或本机目录】');
    expect(nextPlaceholder(t, second[1])).toEqual(first);
    expect(nextPlaceholder('没有待填写项', 0)).toBeNull();
  });

  it('uses the page object for its placeholder only', () => {
    const project = { kind: 'project' as const, id: 'prj_1', label: '订单系统', valid: true };
    expect(fillContext('对 @【项目】 做一次全量审计', project)).toBe('对当前项目做一次全量审计');
    expect(fillContext('为 @【漏洞】 生成修复建议', project)).toBe('为 @【漏洞】 生成修复建议');
    expect(fillContext('为 @【漏洞】 生成修复建议', { kind: 'vuln', id: 'vul_1', label: 'V-1', valid: true })).toBe('为这个漏洞生成修复建议');
  });

  it('covers project creation, threat modeling and audits, each template with something to fill in', () => {
    expect(TEMPLATE_GROUPS.map((g) => g.key)).toEqual(expect.arrayContaining(['project', 'threat', 'audit', 'hunt', 'vuln']));
    for (const g of TEMPLATE_GROUPS) for (const t of g.items) expect(nextPlaceholder(t.text), t.title).not.toBeNull();
    const html = renderToStaticMarkup(createElement(QuickStart, { onPick: () => {} }));
    expect(html).toContain('新建项目并全量审计');
    expect(html).toContain('威胁建模');
  });
});
