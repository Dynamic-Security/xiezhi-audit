// What runs now, at the top of the trajectory (replaces the separate execution overview tab):
// one line per running job — its batch or subject, candidate progress, what its main agent does or waits for — with
// its sub-agents under it; plus the audit's concurrency and the limit control shown in the status bar.
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { AuditDetailDto, ExecAgentDto, ExecStepDto, ExecutionDto } from '@xiezhi/contracts';
import { api, newIdempotencyKey } from '../../shared/api/client';
import { qk } from '../../shared/api/queries';
import { STEP_KIND, fmt, toolArgs, toolLabel } from '../../shared/format/messages';
import { Badge, Button, ConfirmDialog, Icon, cx, ui, useToast } from '../../shared/ui';
import { CANDIDATE_STATUS, headline } from './candidates';
import E from './execution.module.css';

const WAITING: Record<string, string> = { slot: '等待会话名额', model: '等待模型', question: '等你回答' };
const OPEN = ['pending', 'investigating'];
/** Running jobs shown before “展开其余”. */
const FIRST = 4;

/** Why a step switched to its fallback model. */
export const FALLBACK_REASON: Record<string, string> = { MODEL_NOT_FOUND: '模型不存在', AUTH_INVALID: '鉴权失败', RATE_LIMITED: '持续限流', PROVIDER_TRANSIENT: '服务持续异常', CONTENT_FILTERED: '内容被过滤拦截', PROVIDER_QUOTA: '余额或额度不足' };

/** The step's model, and its fallback switch or cross-review degradation. */
export function ModelBadge({ s }: { s: ExecStepDto }) {
  const f = s.fallback;
  if (f?.degraded) return <span title={`${f.from} ${FALLBACK_REASON[f.reason] ?? f.reason}；备用模型也在交叉审查组里，没有替换，这一路结果缺失`}><Badge tone="warn">交叉审查降级</Badge></span>;
  if (f?.later) return <span title={`之后原本使用 ${f.from} 的步骤按你的选择改用 ${s.model ?? ''}`}><Badge tone="warn">切换 {s.model ?? ''}</Badge></span>;
  if (f?.manual) return <span title={`${f.from} ${FALLBACK_REASON[f.reason] ?? f.reason}，已按你的选择切换模型重试`}><Badge tone="warn">切换 {s.model ?? ''}</Badge></span>;
  if (f) return <span title={`${f.from} ${FALLBACK_REASON[f.reason] ?? f.reason}，已切换到备用模型`}><Badge tone="warn">备用 {s.model ?? ''}</Badge></span>;
  return s.model ? <span className={E.runModel}>{s.model}</span> : null;
}

/** What an agent does right now, in a few words. */
export function agentDoing(a: ExecAgentDto): string {
  if (a.waiting) return WAITING[a.waiting]!;
  const t = a.lastTool;
  if (!t) return '思考中';
  if (t.tool === 'mark_candidate') return `标记候选（${CANDIDATE_STATUS[String((t.args as { status?: string } | null)?.status)] ?? '进度'}）`;
  return `${toolLabel(t.tool)} ${toolArgs(t.tool, t.args)}`.trim();
}

function RunningRow({ s, onFocus }: { s: ExecStepDto; onFocus: (stepId: string) => void }) {
  const main = s.agents.find((a) => a.role === 'main' && a.status === 'running') ?? s.agents.find((a) => a.role === 'main');
  const subs = s.agents.filter((a) => a.role === 'task' && a.status === 'running');
  const done = s.candidates.filter((c) => !OPEN.includes(c.status)).length;
  const what = s.candidates.length ? headline(s.candidates) : s.subject ?? s.repo ?? '';
  return (
    <li className={E.runItem}>
      <button className={E.runRow} onClick={() => onFocus(s.id)} title="在下方轨迹中定位到这个作业">
        <b className={E.runWho}>{s.lineage ?? STEP_KIND[s.kind] ?? s.kind}</b>
        <span className={E.runWhat}>{what}</span>
        {s.candidates.length > 0 && <span className={E.runCount}>候选 {done}/{s.candidates.length}</span>}
        <ModelBadge s={s} />
        <span className={E.runDoing}>
          {main?.waiting ? <Badge tone="warn">{WAITING[main.waiting]}</Badge> : <><span className={cx(ui.spinner, E.runSpin)} />{main ? agentDoing(main) : '准备中'}</>}
        </span>
      </button>
      {subs.map((a) => (
        <div key={a.id} className={E.runSub}>
          <Icon name="layers" size={12} />
          <span className={E.runSubGoal}>子 Agent：{a.goal ?? ''}</span>
          <span className={E.runDoing}>{a.waiting ? <Badge tone="warn">{WAITING[a.waiting]}</Badge> : agentDoing(a)}</span>
        </div>
      ))}
    </li>
  );
}

export function RunningPanel({ x, onFocus }: { x: ExecutionDto; onFocus: (stepId: string) => void }) {
  const [open, setOpen] = useState(true);
  const [all, setAll] = useState(false);
  const running = x.phases.flatMap((p) => p.steps).filter((s) => s.status === 'running');
  if (!running.length) return null;
  const shown = all ? running : running.slice(0, FIRST);
  return (
    <section className={E.running} aria-label="进行中的作业">
      <button className={E.runHead} aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name={open ? 'chevronDown' : 'chevronRight'} size={13} />
        进行中 {running.length} 个作业
        {running.flatMap((s) => s.agents).some((a) => a.role === 'task' && a.status === 'running') && <span className={E.runHint}>含子 Agent</span>}
      </button>
      {open && (
        <ul className={E.runList}>
          {shown.map((s) => <RunningRow key={s.id} s={s} onFocus={onFocus} />)}
          {running.length > FIRST && (
            <li><button className={E.link} onClick={() => setAll(!all)}>{all ? '收起' : `展开其余 ${running.length - FIRST} 个`}</button></li>
          )}
        </ul>
      )}
    </section>
  );
}

/** Change the audit's parallel sessions while it runs: 1 to the global model-request limit. */
export function SessionLimit({ aid, x }: { aid: string; x: ExecutionDto }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const cur = x.concurrency.sessions.limit;
  const max = Math.min(16, x.concurrency.model.capacity);
  const set = async (n: number) => {
    setBusy(true);
    try {
      const r = await api.post<{ from: number; to: number; live: boolean }>(`/audits/${aid}/concurrency`, { sessions: n });
      toast.ok(`并发会话数已调整为 ${r.to}${r.live ? '，之后开始的会话按新上限运行' : ''}`);
    } catch (e) { toast.error(e); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: qk.execution(aid) });
  };
  return (
    <span className={E.limit} title="本次审计同时运行的 Agent 会话上限（含子 Agent）。调整后，之后开始的会话按新上限运行，进行中的不受影响。">
      并发上限
      <Button size="sm" variant="ghost" icon="minus" aria-label="减少并发" disabled={busy || cur <= 1} onClick={() => void set(cur - 1)} />
      <b>{cur}</b>
      <Button size="sm" variant="ghost" icon="plus" aria-label="增加并发" disabled={busy || cur >= max} onClick={() => void set(cur + 1)} />
    </span>
  );
}

/**
 * The stage quotas of a confirmed, unfinished audit can be dropped while it runs — from then on only the total
 * token budget limits it. Shown only while the audit has stage quotas.
 */
export function StageQuotaSwitch({ audit }: { audit: AuditDetailDto }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [key] = useState(newIdempotencyKey);
  if (!(audit.budget.stages ?? []).length || ['planning', 'awaiting_confirm'].includes(audit.status)) return null;
  const lift = async () => {
    setConfirm(false);
    setBusy(true);
    try { await api.post(`/audits/${audit.id}/budget-grants`, { liftStageQuotas: true }, { idempotencyKey: key }); toast.ok('已取消阶段额度，之后只受总 token 预算限制'); } catch (e) { toast.error(e); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['audit', audit.id] });
  };
  return (
    <span className={E.limit} title="本次审计按阶段限制 token 额度：某个阶段用完额度时审计暂停，等你追加。取消后只受总 token 预算限制。">
      阶段额度
      <Button size="sm" variant="ghost" loading={busy} onClick={() => setConfirm(true)}>取消</Button>
      <ConfirmDialog open={confirm} onClose={() => setConfirm(false)} title="取消阶段额度" confirmText="取消阶段额度" onConfirm={() => void lift()}>
        本次审计不再按阶段限制 token，之后只受总预算（{fmt.tokens(audit.budget.effective.tokens)} tokens）限制；不能再恢复。
      </ConfirmDialog>
    </span>
  );
}

export function ConcurrencyChips({ x }: { x: ExecutionDto }) {
  const c = x.concurrency;
  return (
    <span className={E.chips}>
      <span className={E.chip} title="本次审计同时运行的 Agent 会话（含子 Agent）/ 上限">Agent 会话 {c.sessions.running}/{c.sessions.limit}{c.sessions.queued ? ` · 排队 ${c.sessions.queued}` : ''}</span>
      <span className={E.chip} title="整个服务同时进行的模型请求 / 全局上限（设置 → 通用）">模型请求 {c.model.active}/{c.model.capacity}{c.model.queued ? ` · 排队 ${c.model.queued}` : ''}</span>
    </span>
  );
}
