// Risk hunt report (导出排查报告 — multi-project summary plus per-project detail).
// Deterministic rendering of a model the caller assembles; the redactor runs on the output like other exports.
export interface HuntReportModel {
  title: string;
  status: string;
  basis: { summary: string; affectedIf: string[]; notAffectedIf: string[]; remediation: string; references: string[] };
  summary: { projects: number; repositories: number; affected: number; notAffected: number; pending: number; unfinished: number; hits: number };
  startedAt: string | null;
  endedAt: string | null;
  targets: { projectName: string; repoName: string | null; verdict: string | null; reason: string | null; verdictSource: string | null; delta: string | null; evidence: { path: string | null; startLine: number | null; note: string | null }[] }[];
  hits: { projectName: string; repoName: string; title: string; severity: string; location: { path: string; startLine: number; endLine: number }; reasoning: string; promotedDisplayNo: number | null }[];
}

const VERDICT: Record<string, string> = { affected: '受影响', not_affected: '不受影响', pending: '待确认' };
const DELTA: Record<string, string> = { new_affected: '新增受影响', cleared: '已消除', changed: '结论变化', unchanged: '无变化', new: '新纳入' };

function md(m: HuntReportModel): string {
  const s = m.summary;
  const lines = [
    `# 风险排查报告：${m.title}`, '',
    `状态：${m.status}${m.startedAt ? ` · 开始 ${m.startedAt}` : ''}${m.endedAt ? ` · 结束 ${m.endedAt}` : ''}`, '',
    '## 汇总', '',
    `排查 ${s.projects} 个项目、${s.repositories} 个仓库：受影响 ${s.affected}，不受影响 ${s.notAffected}，待确认 ${s.pending}${s.unfinished ? `，未完成 ${s.unfinished}` : ''}；命中位置 ${s.hits} 个。`, '',
    '## 排查依据', '', m.basis.summary, '', '判定为受影响：', ...m.basis.affectedIf.map((x) => `- ${x}`), '', '判定为不受影响：', ...m.basis.notAffectedIf.map((x) => `- ${x}`), '',
    '## 各项目结论', '', '| 项目 | 仓库 | 结论 | 理由 | 变化 |', '| --- | --- | --- | --- | --- |',
    ...m.targets.map((t) => `| ${t.projectName} | ${t.repoName ?? '—'} | ${t.verdict ? VERDICT[t.verdict] ?? t.verdict : '未完成'}${t.verdictSource === 'human' ? '（人工改判）' : ''} | ${(t.reason ?? '').replace(/\|/g, '\\|')} | ${t.delta ? DELTA[t.delta] ?? t.delta : ''} |`),
    '', '## 受影响位置', '',
    ...(m.hits.length ? m.hits.map((h) => `- **${h.projectName} / ${h.repoName}** \`${h.location.path}:${h.location.startLine}-${h.location.endLine}\` [${h.severity}] ${h.title}${h.promotedDisplayNo ? `（已转为 V-${h.promotedDisplayNo}）` : ''}\n  ${h.reasoning.replace(/\n/g, ' ')}`) : ['（无）']),
    '', '## 不受影响 / 待确认的依据', '',
    ...m.targets.filter((t) => t.verdict !== 'affected').flatMap((t) => [`- ${t.projectName}${t.repoName ? ` / ${t.repoName}` : ''}：${t.reason ?? ''}`, ...t.evidence.slice(0, 5).map((e) => `  - ${e.path ? `\`${e.path}${e.startLine ? `:${e.startLine}` : ''}\` ` : ''}${e.note ?? ''}`)]),
    '', '## 修复方式', '', m.basis.remediation, '',
    ...(m.basis.references.length ? ['## 参考', '', ...m.basis.references.map((r) => `- ${r}`), ''] : []),
    '> 静态排查：未构建、未运行、未测试目标代码。结论由 AI 研判、按规则核实，需人工确认。', '',
  ];
  return lines.join('\n');
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function html(m: HuntReportModel): string {
  // Plain Markdown-in-HTML rendering: no scripts, no external resources (same policy as the audit report).
  const body = md(m).split('\n').map((l) => {
    if (l.startsWith('# ')) return `<h1>${esc(l.slice(2))}</h1>`;
    if (l.startsWith('## ')) return `<h2>${esc(l.slice(3))}</h2>`;
    if (l.startsWith('|')) return `<pre class="row">${esc(l)}</pre>`;
    if (l.startsWith('- ') || l.startsWith('  - ')) return `<div class="li">${esc(l)}</div>`;
    return l ? `<p>${esc(l)}</p>` : '';
  }).join('\n');
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${esc(`风险排查报告：${m.title}`)}</title>
<style>body{font:14px/1.6 -apple-system,system-ui,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#1f2328}pre.row{margin:0;white-space:pre-wrap;font:12px ui-monospace,monospace}.li{margin-left:12px}h2{border-bottom:1px solid #d0d7de;padding-bottom:4px}@media (prefers-color-scheme:dark){body{background:#0d1117;color:#e6edf3}}</style></head><body>
${body}
</body></html>
`;
}

export function renderHuntReport(m: HuntReportModel, format: 'md' | 'html' | 'json'): string {
  if (format === 'json') return `${JSON.stringify(m, null, 1)}\n`;
  return format === 'html' ? html(m) : md(m);
}
