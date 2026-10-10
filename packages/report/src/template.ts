// Report templates from report skills: a logic-less Markdown template
// with `{{placeholder}}` slots. It can only reorder the sections of the deterministic report and give them
// its own titles and connecting text; it cannot drop conclusions — sections the template does not place
// are appended with their default headings, and the scope / static-audit note always stays on top.
import { STATIC_AUDIT_NOTE } from './model.js';

/** Section placeholders and the default headings they correspond to. */
export const TEMPLATE_SECTIONS: Record<string, string> = {
  scope: '审计范围与版本', summary: '结论摘要', coverage: '覆盖对照', findings: '发现详情',
  insufficient: '证据不足（不计入正式结论）', security: '安全提示', knowledge: '使用的知识',
};

function split(markdown: string): { header: string; sections: Map<string, { heading: string; body: string }> } {
  const parts = markdown.split(/^(?=## )/m);
  const header = parts[0]!.trimEnd();
  const byHeading = new Map(Object.entries(TEMPLATE_SECTIONS).map(([k, h]) => [h, k]));
  const sections = new Map<string, { heading: string; body: string }>();
  for (const p of parts.slice(1)) {
    const heading = /^## (.*)$/m.exec(p)![1]!.trim();
    const key = byHeading.get(heading) ?? heading;
    sections.set(key, { heading, body: p.replace(/^## .*\n?/, '').trim() });
  }
  return { header, sections };
}

export function applyReportTemplate(markdown: string, template: string): string {
  const { header, sections } = split(markdown);
  const used = new Set<string>();
  let out = template.replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (_, key: string) => {
    if (key === 'header') { used.add('header'); return header; }
    const s = sections.get(key);
    if (!s) return TEMPLATE_SECTIONS[key] !== undefined ? '（本次没有该部分）' : '';
    used.add(key);
    return s.body;
  });
  // The scope, completeness and the static-audit statement are mandatory.
  if (!used.has('header')) out = `${header}\n\n${out}`;
  if (!out.includes(STATIC_AUDIT_NOTE)) out = `> ${STATIC_AUDIT_NOTE}\n\n${out}`;
  const rest = [...sections.entries()].filter(([k]) => !used.has(k)).map(([, s]) => `## ${s.heading}\n\n${s.body}`);
  return `${[out.trimEnd(), ...rest].join('\n\n').replace(/\n{3,}/g, '\n\n')}\n`;
}
