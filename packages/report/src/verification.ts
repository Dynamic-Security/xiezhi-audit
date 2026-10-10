// Verification cases and fix suggestions of a vulnerability, for the report: the cases written for the
// user (with the result they recorded) and the latest patch suggestion. Read from the store; nothing is executed.
import { fromJson, type Store } from '@xiezhi/store';

export interface ReportVerificationCase {
  preconditions: string[];
  steps: { kind: string; title: string; content: string }[];
  expected: { vulnerable: string; fixed: string } | null;
  outcome: string | null;
  outcomeNote: string | null;
}
export interface ReportFix { summary: string; patches: { path: string; diff: string }[]; verify: string | null }
export interface ReportVerification { cases: ReportVerificationCase[]; fix: ReportFix | null }

export function reportVerification(store: Store, vulnId: string | null): ReportVerification | undefined {
  if (!vulnId) return undefined;
  const cases = store.all<{ preconditions: string | null; steps: string | null; expected: string | null; outcome: string | null; outcome_note: string | null }>(
    `SELECT preconditions, steps, expected, outcome, outcome_note FROM verification_case WHERE vulnerability_id = ? AND status = 'ready' ORDER BY created_at DESC, id LIMIT 3`, vulnId)
    .map((c) => ({
      preconditions: fromJson<string[]>(c.preconditions, []), steps: fromJson<ReportVerificationCase['steps']>(c.steps, []).map((s) => ({ kind: s.kind, title: s.title, content: s.content })),
      expected: fromJson<ReportVerificationCase['expected']>(c.expected, null), outcome: c.outcome, outcomeNote: c.outcome_note,
    }));
  const f = store.get<{ summary: string | null; patches: string | null; verify: string | null }>(
    `SELECT summary, patches, verify FROM fix_suggestion WHERE vulnerability_id = ? AND status = 'ready' ORDER BY created_at DESC, id LIMIT 1`, vulnId);
  const fix = f ? { summary: f.summary ?? '', patches: fromJson<ReportFix['patches']>(f.patches, []), verify: f.verify } : null;
  return cases.length || fix ? { cases, fix } : undefined;
}

const OUTCOME_ZH: Record<string, string> = { reproduced: '已复现', not_reproduced: '未复现', inconclusive: '无法判断' };
const KIND_ZH: Record<string, string> = { http: 'HTTP 请求', test: '测试代码', manual: '手工操作' };

/** Markdown: ⑤ 验证用例与补丁建议. */
export function verificationMarkdown(v: ReportVerification | undefined): string[] {
  if (!v) return [];
  const out: string[] = ['#### ⑤ 验证用例与补丁建议（由 AI 生成，引擎不执行）', ''];
  v.cases.forEach((c, i) => {
    out.push(`**验证用例 ${i + 1}**${c.outcome ? `（用户回填：${OUTCOME_ZH[c.outcome] ?? c.outcome}${c.outcomeNote ? `；${c.outcomeNote}` : ''}）` : '（未回填结果）'}`, '');
    if (c.preconditions.length) out.push(...c.preconditions.map((p) => `- 前置条件：${p}`), '');
    c.steps.forEach((s, k) => out.push(`${k + 1}. ${s.title}（${KIND_ZH[s.kind] ?? s.kind}）`, '', '```', s.content, '```', ''));
    if (c.expected) out.push(`- 存在漏洞时：${c.expected.vulnerable}`, `- 修复后：${c.expected.fixed}`, '');
  });
  if (v.fix) {
    out.push(`**补丁建议：** ${v.fix.summary}`, '');
    for (const p of v.fix.patches) out.push('```diff', p.diff, '```', '');
    if (v.fix.verify) out.push(`复验方式：${v.fix.verify}`, '');
  }
  return out;
}

/** HTML: the same section (escaped by the caller's escape function). */
export function verificationHtml(v: ReportVerification | undefined, e: (s: string) => string): string[] {
  if (!v) return [];
  const out: string[] = ['<h4>⑤ 验证用例与补丁建议（由 AI 生成，引擎不执行）</h4>'];
  v.cases.forEach((c, i) => {
    out.push(`<p><b>验证用例 ${i + 1}</b>${c.outcome ? `（用户回填：${e(OUTCOME_ZH[c.outcome] ?? c.outcome)}${c.outcomeNote ? `；${e(c.outcomeNote)}` : ''}）` : '（未回填结果）'}</p>`);
    if (c.preconditions.length) out.push(`<ul>${c.preconditions.map((p) => `<li>前置条件：${e(p)}</li>`).join('')}</ul>`);
    out.push(`<ol>${c.steps.map((s) => `<li>${e(s.title)}（${e(KIND_ZH[s.kind] ?? s.kind)}）<pre><code>${e(s.content)}</code></pre></li>`).join('')}</ol>`);
    if (c.expected) out.push(`<p>存在漏洞时：${e(c.expected.vulnerable)}<br>修复后：${e(c.expected.fixed)}</p>`);
  });
  if (v.fix) {
    out.push(`<p><b>补丁建议：</b>${e(v.fix.summary)}</p>`);
    for (const p of v.fix.patches) out.push(`<pre><code>${e(p.diff)}</code></pre>`);
    if (v.fix.verify) out.push(`<p>复验方式：${e(v.fix.verify)}</p>`);
  }
  return out;
}
