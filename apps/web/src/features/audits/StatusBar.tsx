// Trajectory status bar: which job segment the audit is in, how far each got, what is running right
// now, overall progress and a rough remaining time. Sticks to the top while the trajectory scrolls; a segment
// can be clicked to show only its steps.
import type { AuditDetailDto, ExecStepDto, ExecutionDto } from '@xiezhi/contracts';
import { STEP_KIND, fmt } from '../../shared/format/messages';
import { ConcurrencyChips, SessionLimit, StageQuotaSwitch, agentDoing } from './Running';
import { Icon, cx } from '../../shared/ui';
import S from './statusbar.module.css';

export const SEGMENT_LABEL: Record<string, string> = {
  snapshot: '固定版本', index: '结构索引', plan: '生成计划', profile: '画像', scope: '影响范围', threat: '威胁建模', triage: '初筛', hunt: '并行追查', external: '外部结果', checklist: '清单核对', recheck: '结论复查',
  explore: '深度探索', challenge: '对抗复核', verify: '定向复验', locate: '定位', judge: '研判', finalize: '汇总',
};
const TERMINAL_STEP = ['succeeded', 'failed', 'skipped', 'cancelled'];
const TERMINAL_AUDIT = ['completed', 'partial', 'failed', 'cancelled'];

type SegState = 'pending' | 'running' | 'done' | 'failed' | 'skipped';

function segmentState(steps: ExecStepDto[]): SegState {
  if (!steps.length) return 'pending';
  if (steps.some((s) => s.status === 'running')) return 'running';
  if (steps.every((s) => TERMINAL_STEP.includes(s.status))) {
    if (steps.some((s) => s.status === 'failed')) return 'failed';
    return steps.every((s) => s.status === 'skipped') ? 'skipped' : 'done';
  }
  return steps.some((s) => TERMINAL_STEP.includes(s.status)) ? 'running' : 'pending';
}

/** “1 分 20 秒 · 3.4 万 tokens” for a segment: from its first start to its last end (or now). */
function segmentMeta(steps: ExecStepDto[]): string {
  const starts = steps.map((s) => s.startedAt).filter(Boolean).map((t) => new Date(t!).getTime());
  if (!starts.length) return '尚未开始';
  const running = steps.some((s) => s.status === 'running');
  const ends = steps.map((s) => s.endedAt).filter(Boolean).map((t) => new Date(t!).getTime());
  const end = running || !ends.length ? Date.now() : Math.max(...ends);
  const tokens = steps.reduce((n, s) => n + s.tokens, 0);
  return [fmt.duration(end - Math.min(...starts)), tokens ? `${fmt.compact(tokens)} tokens` : ''].filter(Boolean).join(' · ');
}

/** One running step in a few words: its batch or kind, and what its main agent does or waits for. */
function activity(s: ExecStepDto): string {
  const who = s.lineage ?? STEP_KIND[s.kind] ?? s.kind;
  const main = s.agents.find((a) => a.role === 'main' && a.status === 'running') ?? s.agents.find((a) => a.status === 'running');
  const subs = s.agents.filter((a) => a.role === 'task' && a.status === 'running').length;
  return `${who} ${main ? agentDoing(main) : '准备中'}${subs ? `（子 Agent ${subs}）` : ''}`;
}

/** Overall progress from the plan's token estimate; the remaining time from the pace so far (rough). */
function overall(x: ExecutionDto, audit: AuditDetailDto): string {
  if (TERMINAL_AUDIT.includes(audit.status)) return `已结束 · 用时 ${fmt.duration(audit.budget.consumed.durationMs)}`;
  const est = x.estimate.tokens;
  const used = audit.budget.consumed.tokens;
  const elapsed = audit.budget.consumed.durationMs;
  const doneSegs = x.segments.filter((k) => ['done', 'skipped', 'failed'].includes(segmentState(x.phases.flatMap((p) => p.steps).filter((s) => s.segment === k)))).length;
  // Tokens track the heavy segments; finished segments keep the figure from lagging while tokens are few.
  const p = Math.min(0.99, Math.max(est ? used / est : 0, doneSegs / Math.max(1, x.segments.length)));
  const pct = `总进度约 ${Math.round(p * 100)}%`;
  if (p < 0.05 || elapsed < 20_000) return `${pct} · 正在估算剩余时间`;
  return `${pct} · 预计还需约 ${fmt.duration(Math.max(0, (elapsed * (1 - p)) / p))}`;
}

export function StatusBar({ x, audit, selected, onSelect }: {
  x: ExecutionDto; audit: AuditDetailDto; selected: string | null; onSelect: (segment: string | null) => void;
}) {
  const live = !TERMINAL_AUDIT.includes(audit.status);
  const steps = x.phases.flatMap((p) => p.steps);
  const running = steps.filter((s) => s.status === 'running');
  // Parallel work at a glance: running jobs (steps), their running sub-agents, jobs not started yet.
  const subs = running.flatMap((s) => s.agents).filter((a) => a.role === 'task' && a.status === 'running').length;
  const pending = steps.filter((s) => !TERMINAL_STEP.includes(s.status) && s.status !== 'running').length;
  return (
    <div className={S.bar} role="region" aria-label="作业进度">
      <ol className={S.segments}>
        {x.segments.map((k) => {
          const own = steps.filter((s) => s.segment === k);
          const st = segmentState(own);
          const done = own.filter((s) => TERMINAL_STEP.includes(s.status)).length;
          return (
            <li key={k} className={S.item}>
              <button className={cx(S.seg, S[st], selected === k && S.selected)} aria-pressed={selected === k} disabled={!own.length}
                title={`${SEGMENT_LABEL[k] ?? k}：${segmentMeta(own)}${own.length ? '。点击只看这个环节的轨迹' : ''}`}
                onClick={() => onSelect(selected === k ? null : k)}>
                <span className={S.dot}>{st === 'done' ? <Icon name="check" size={10} /> : st === 'failed' ? '!' : null}</span>
                <span>{SEGMENT_LABEL[k] ?? k}</span>
                {own.length > 1 && <span className={S.count}>{done}/{own.length}</span>}
              </button>
            </li>
          );
        })}
      </ol>
      <div className={S.now}>
        {live && (running.length > 0 || pending > 0) && (
          <span className={S.parallel} aria-label="并行任务数" title="作业：正在运行的步骤（如每个 hunt 批次）；子 Agent：这些作业派出、正在运行的子 Agent；待开始：已排好、尚未开始的作业">
            并行 <b>{running.length}</b> 个作业{subs > 0 && <> · 子 Agent <b>{subs}</b> 个</>}{pending > 0 && <> · 待开始 <b>{pending}</b> 个</>}
          </span>
        )}
        <span className={S.overall}>{overall(x, audit)}</span>
        {running.length > 0 && (
          <span className={S.doing} title={running.map(activity).join('\n')}>
            正在：{running.slice(0, 3).map(activity).join(' · ')}{running.length > 3 ? ` 等 ${running.length} 个作业` : ''}
          </span>
        )}
        {selected && <button className={S.clear} onClick={() => onSelect(null)}>只显示「{SEGMENT_LABEL[selected] ?? selected}」· 显示全部</button>}
        {live && <span className={S.right}><ConcurrencyChips x={x} /><SessionLimit aid={audit.id} x={x} /><StageQuotaSwitch audit={audit} /></span>}
      </div>
    </div>
  );
}
