// Candidates of a step: status labels, category, one-line batch summary and the list row,
// shared by the execution overview and the trajectory tree.
import type { ExecCandidateDto } from '@xiezhi/contracts';
import { categoryLabel } from '../../shared/format/messages';
import { Badge, cx, ui } from '../../shared/ui';
import E from './execution.module.css';

/** Per-candidate statuses: progress marks by the Agent and the settled verdicts. */
export const CANDIDATE_STATUS: Record<string, string> = {
  pending: '待查', investigating: '查看中', finding: '发现问题', suspicious: '可疑', no_issue: '未发现问题', ruled_out: '已排除', unreviewed: '未审查',
};
const OPEN = ['pending', 'investigating'];

/** The risk category of a candidate: `[sink:sqli] …` labels, the category suffix of sink ids, or an HTTP entry. */
export function categoryOf(c: ExecCandidateDto): string {
  const m = /\[(?:sink|hyp):([\w-]+)\]/.exec(c.label) ?? /#L\d+:\d+:([\w-]+)$/.exec(c.id);
  if (m) return categoryLabel(m[1]!);
  return c.kind === 'entry' ? '入口' : c.kind === 'dependency' ? '依赖' : c.kind === 'change' ? '变更' : c.kind === 'hypothesis' ? '风险假设' : '代码位置';
}

/** “订单模块 · SQL 注入、越权 · 8 个候选”: the most common directory and the categories of the batch. */
export function headline(cands: ExecCandidateDto[]): string {
  if (!cands.length) return '';
  // a hypothesis-verification batch has no code location until it is verified.
  if (cands.every((c) => c.kind === 'hypothesis')) {
    const cats = [...new Set(cands.map(categoryOf))];
    return [`${cands.length} 条风险假设`, cats.slice(0, 3).join('、') + (cats.length > 3 ? ' 等' : '')].join(' · ');
  }
  const dirs = new Map<string, number>();
  for (const c of cands) {
    const parts = c.path.split('/');
    const d = parts.length > 1 ? parts[parts.length - 2]! : c.repo;
    dirs.set(d, (dirs.get(d) ?? 0) + 1);
  }
  const dir = [...dirs.entries()].sort((a, b) => b[1] - a[1])[0]![0];
  const cats = [...new Set(cands.map(categoryOf))];
  return [dirs.size > 1 ? `${dir} 等 ${dirs.size} 处` : dir, cats.slice(0, 3).join('、') + (cats.length > 3 ? ' 等' : ''), `${cands.length} 个候选`].join(' · ');
}

export function CandidateRow({ c }: { c: ExecCandidateDto }) {
  const tone = c.status === 'finding' ? 'danger' : c.status === 'suspicious' ? 'warn' : c.status === 'investigating' ? 'accent' : OPEN.includes(c.status) || c.status === 'unreviewed' ? 'neutral' : 'ok';
  return (
    <li className={E.cand}>
      <Badge tone={tone} {...(c.status === 'investigating' ? { dot: true, pulse: true } : {})}>{CANDIDATE_STATUS[c.status] ?? c.status}</Badge>
      {c.preliminary && !OPEN.includes(c.status) && <span className={E.pre} title="Agent 的逐项结论，以最终提交为准">初步</span>}
      <span className={E.candCat}>{categoryOf(c)}</span>
      {c.kind !== 'hypothesis' && <span className={cx(ui.mono, E.candLoc)} title={`${c.repo}:${c.path}:${c.line}`}>{c.path.split('/').pop()}:{c.line}</span>}
      <span className={E.candLabel} title={c.label}>{c.label.replace(/^\[[^\]]+\]\s*/, '')}</span>
      {(c.note || c.changedFrom) && (
        <div className={E.candNote}>
          {c.changedFrom && <span className={E.changed}>初步为「{CANDIDATE_STATUS[c.changedFrom] ?? c.changedFrom}」，以提交为准。</span>}
          {c.note}
        </div>
      )}
    </li>
  );
}

