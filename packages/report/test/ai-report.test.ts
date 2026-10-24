// AI report checks: every conclusion present with its recorded severity and confirmation status,
// no invented numbers; the annotated delivery when the check fails; Markdown rendered without passing markup through.
import { describe, expect, it } from 'vitest';
import { annotateAiReport, markdownToHtml, verifyAiReport, type ReportFact } from '@xiezhi/report';

const FACTS: ReportFact[] = [
  { id: 'F-1', vuln: 'V-3', title: '订单查询 SQL 注入', severity: '高', confirmStatus: '已确认' },
  { id: 'F-2', vuln: 'V-4', title: 'ping 命令注入', severity: '中', confirmStatus: '待确认' },
  { id: 'I-1', vuln: null, title: '疑似越权', severity: '低', confirmStatus: '待确认' },
];
const GOOD = [
  '# 审计报告', '', '> 静态审计：未构建、未运行、未测试目标代码。', '', '## 主要发现',
  '### F-1 订单查询 SQL 注入', '严重度：高｜确认状态：已确认', '', '#### 修复', '参数化查询。',
  '### F-2 · V-4 ping 命令注入', '**严重度**：中 | **确认状态**：待确认', '',
  '## 证据不足', '### I-1 疑似越权', '严重度：低｜确认状态：待确认',
].join('\n');

describe('AI report verification', () => {
  it('accepts a report that keeps every conclusion as recorded (bold labels, sub-headings allowed)', () => {
    expect(verifyAiReport(GOOD, FACTS)).toEqual([]);
  });

  it('reports a missing conclusion, an invented number, a changed severity and a changed status', () => {
    const bad = GOOD.replace('严重度：高｜确认状态：已确认', '严重度：严重｜确认状态：待确认')
      .replace('### I-1 疑似越权\n严重度：低｜确认状态：待确认', '')
      .concat('\n### F-9 编造的漏洞\n严重度：高｜确认状态：已确认');
    expect(verifyAiReport(bad, FACTS)).toEqual([
      'F-1 严重度写成了“严重”，记录为“高”', 'F-1 确认状态写成了“待确认”，记录为“已确认”', '缺少 I-1（疑似越权）', '出现了记录中没有的编号 F-9',
    ]);
    expect(verifyAiReport('### F-1 x\n正文\n### F-2 y\n严重度：中｜确认状态：待确认\n### I-1 z\n严重度：低｜确认状态：待确认', FACTS))
      .toEqual(['F-1 没有写严重度（应为“高”）', 'F-1 没有写确认状态（应为“已确认”）']);
  });

  it('delivers a failing report with the differences on top and the fact list at the end; keeps the static-audit note', () => {
    const out = annotateAiReport('### F-1 x', ['缺少 F-2（ping 命令注入）'], FACTS);
    expect(out.startsWith('> **自动校验未通过**')).toBe(true);
    expect(out).toContain('> - 缺少 F-2（ping 命令注入）');
    expect(out).toContain('静态审计：未构建、未运行、未测试目标代码。');
    expect(out).toContain('## 附：事实清单（程序生成，以此为准）');
    expect(out).toContain('| F-2 | V-4 | ping 命令注入 | 中 | 待确认 |');
    expect(annotateAiReport(GOOD, [], FACTS)).toBe(`${GOOD}\n`);
  });

  it('renders Markdown to HTML without passing through any markup the model wrote', () => {
    const html = markdownToHtml([
      '### F-1 <script>alert(1)</script>', 'text **bold** and `<b>x</b>` [ok](https://example.com/a?b=1&c=2) [bad](javascript:alert(1))',
      '', '| a | b |', '| --- | --- |', '| <i>1</i> | 2 |', '', '```', '<img src=x onerror=alert(1)>', '```', '> quote', '- one', '- two',
    ].join('\n'));
    expect(html).not.toMatch(/<script|<img|<i>|<b>|javascript:alert\(1\)"/);
    expect(html).toContain('<h3 id="F-1">F-1 &lt;script&gt;alert(1)&lt;/script&gt;</h3>');
    expect(html).toContain('<strong>bold</strong>');
    expect(html).toContain('<code>&lt;b&gt;x&lt;/b&gt;</code>');
    expect(html).toContain('<a href="https://example.com/a?b=1&amp;c=2" rel="noopener noreferrer">ok</a>');
    expect(html).toContain('<td>&lt;i&gt;1&lt;/i&gt;</td>');
    expect(html).toContain('<pre><code>&lt;img src=x onerror=alert(1)&gt;</code></pre>');
    expect(html).toContain('<blockquote><p>quote</p></blockquote>');
    expect(html).toContain('<ul><li>one</li><li>two</li></ul>');
  });
});
