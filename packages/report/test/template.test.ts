// Report templates: reorder and retitle, never drop.
import { describe, expect, it } from 'vitest';
import { applyReportTemplate } from '@xiezhi/report';

const md = [
  '# 代码安全审计报告：订单服务', '', '> 静态审计：未构建、未运行、未测试目标代码。', '', '- 项目：shop', '',
  '## 审计范围与版本', '', '- order-service@abc', '',
  '## 结论摘要', '', '高危 1', '',
  '## 发现详情', '', '### V-1 SQL 注入', '',
  '## 使用的知识', '', '| skill |', '',
].join('\n');

describe('report templates', () => {
  it('places sections where the template says, with its own titles, and appends what it omits', () => {
    const out = applyReportTemplate(md, '# 安全评审报告\n\n## 一、结论\n\n{{summary}}\n\n## 二、问题清单\n\n{{findings}}\n\n{{unknown_slot}}');
    expect(out.indexOf('静态审计')).toBeLessThan(out.indexOf('# 安全评审报告'));
    expect(out).toContain('## 一、结论\n\n高危 1');
    expect(out.indexOf('## 一、结论')).toBeLessThan(out.indexOf('## 二、问题清单'));
    expect(out).toContain('## 二、问题清单\n\n### V-1 SQL 注入');
    // Sections the template does not place are kept with their default headings.
    expect(out).toContain('## 审计范围与版本\n\n- order-service@abc');
    expect(out).toContain('## 使用的知识');
    expect(out).not.toContain('{{');
  });

  it('keeps the header where the template puts it and marks missing known sections', () => {
    const out = applyReportTemplate(md, '{{header}}\n\n## 覆盖\n\n{{coverage}}');
    expect(out.startsWith('# 代码安全审计报告：订单服务')).toBe(true);
    expect(out).toContain('## 覆盖\n\n（本次没有该部分）');
  });
});
