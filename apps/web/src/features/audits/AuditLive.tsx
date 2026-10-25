// Live audit card: progress, Agent questions with quick answers, your interventions with
// their receipts, and the outcome — shown in the conversation an audit was started from and at the bottom of
// the audit page's AI tab. Questions can still be answered after the audit ended: the answer is recorded and
// the pending vulnerabilities of the audit can be reverified with it.
import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { QuestionDto } from '@xiezhi/contracts';
import { api, newIdempotencyKey } from '../../shared/api/client';
import { useAudit, useExecution, useFindings, useQuestions, useTrajectory } from '../../shared/api/queries';
import { AUDIT_STATUS, INTERVENTION, PARTIAL_REASON, PHASE, SCENE, fmt, reasonsLabel } from '../../shared/format/messages';
import { AuditStatusBadge, Badge, Button, Icon, Progress, cx, ui, useToast } from '../../shared/ui';
import S from './audit-live.module.css';
import { DEFER_TO_AGENT_ANSWER } from './questionAnswers';

const TERMINAL = ['completed', 'partial', 'failed', 'cancelled'];

function QuestionItem({ q, auditEnded, onRecorded }: { q: QuestionDto; auditEnded: boolean; onRecorded: (note: string) => void }) {
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['audit', q.auditId, 'questions'] }); void qc.invalidateQueries({ queryKey: ['dashboard'] }); };
  const answer = async (a: string) => {
    setBusy(true);
    try {
      const r = await api.post<{ routed: string }>(`/questions/${q.id}/answer`, { answer: a });
      if (r.routed === 'closed_audit') onRecorded(`对提问「${q.text}」的回答：${a}`);
      else toast.ok(r.routed === 'steer' ? '已发送给正在运行的 Agent' : '已记录，后续分析会使用这条信息');
      setText('');
    } catch (e) { toast.error(e); }
    setBusy(false);
    refresh();
  };
  const dismiss = async () => { try { await api.post(`/questions/${q.id}/dismiss`); } catch (e) { toast.error(e); } refresh(); };
  if (q.status !== 'open') {
    return (
      <div className={S.q}>
        <div className={S.qText}><Icon name="help" size={13} />{q.text}</div>
        <div className={S.qAnswer}>{q.status === 'dismissed' ? '已忽略' : q.status === 'expired' ? '审计已取消，提问已失效' : `你的回答：${q.answer ?? ''}`}</div>
      </div>
    );
  }
  return (
    <div className={cx(S.q, S.qOpen)}>
      <div className={S.qText}><Icon name="help" size={13} />{q.text}{q.blocking && <Badge tone="warn">影响结论</Badge>}{q.asFact && <Badge tone="info" title="计划需要补充的上下文：回答会存为项目的企业事实，本次与以后的审计都会用到">回答存为事实</Badge>}</div>
      {q.asFact
        ? <div className={S.qNote}>回答会存为项目的企业事实，以后的审计直接使用。</div>
        : auditEnded && <div className={S.qNote}>审计已结束，相关结论暂按假设处理并保持待确认；回答后可以定向复验。</div>}
      <div className={S.quick}>
        {/* The answers the Agent suggested for this question; picking one is the same as typing it (a context
            question saves it as a fact). Older questions have none: an Agent question falls back to “是 / 否”; a context
            question (kept as a fact) asks for information — “是 / 否” is no answer there, and next to “回答会存为项目的企业事实”
            it read as a switch for saving it — clicking it stored the fact “答：是”. */}
        {(q.options.length ? q.options : q.asFact ? [] : ['是', '否']).map((a) => <button key={a} className={cx(ui.chip, S.option)} disabled={busy} onClick={() => void answer(a)}>{a}</button>)}
        {/* contracts DEFER_TO_AGENT_ANSWER: never saved as a fact. */}
        {!auditEnded && <button className={ui.chip} disabled={busy} onClick={() => void answer(DEFER_TO_AGENT_ANSWER)}>让 Agent 自行查询</button>}
        <button className={ui.chip} disabled={busy} onClick={() => void dismiss()}>忽略</button>
      </div>
      <div className={S.answerRow}>
        <input className={ui.input} aria-label="回答提问" placeholder="输入回答…" value={text} onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.nativeEvent.isComposing && text.trim()) void answer(text.trim()); }} />
        <Button size="sm" variant="primary" icon="send" aria-label="发送回答" disabled={!text.trim()} loading={busy} onClick={() => void answer(text.trim())} />
      </div>
    </div>
  );
}

/** After answering a question of a finished audit: reverify its pending vulnerabilities with the answer. */
function ReverifyOffer({ auditId, note }: { auditId: string; note: string }) {
  const findings = useFindings(auditId);
  const [key] = useState(newIdempotencyKey);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const toast = useToast();
  const ids = [...new Set((findings.data ?? []).filter((f) => f.state === 'canonical' && f.confirmStatus === 'pending' && f.vulnId).map((f) => f.vulnId!))];
  if (!ids.length) return <div className={ui.faint} style={{ fontSize: 12 }}>回答已记录。</div>;
  const start = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ auditId: string }>('/reverifications', { vulnIds: ids, note: note.slice(0, 4000) }, { idempotencyKey: key });
      toast.ok('已开始定向复验');
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) { toast.error(e, '无法开始复验'); }
    setBusy(false);
  };
  return (
    <div className={S.offer}>
      <span>回答已记录。本次审计有 {ids.length} 个待确认漏洞可以用这条回答定向复验。</span>
      <Button size="sm" variant="primary" icon="play" loading={busy} onClick={() => void start()}>定向复验</Button>
    </div>
  );
}

/** While the audit runs: parallel work at a glance, with a link to the full overview. */
function ExecutionLine({ auditId }: { auditId: string }) {
  const x = useExecution(auditId, true).data;
  if (!x) return null;
  const steps = x.phases.flatMap((p) => p.steps);
  const cands = steps.flatMap((s) => s.candidates);
  const done = cands.filter((c) => !['pending', 'investigating'].includes(c.status)).length;
  const agents = steps.flatMap((s) => s.agents).filter((a) => a.status === 'running');
  const subs = agents.filter((a) => a.role === 'task').length;
  const waiting = agents.filter((a) => a.waiting && a.waiting !== 'question').length;
  return (
    <div className={S.meta}>
      {[`并行 ${agents.length - subs} 个 Agent${subs ? `，子 Agent ${subs} 个` : ''}`, waiting ? `${waiting} 个排队中` : '', cands.length ? `候选 ${done}/${cands.length} 已有结论` : '', `会话 ${x.concurrency.sessions.running}/${x.concurrency.sessions.limit}`].filter(Boolean).join(' · ')}
      {' · '}<Link to="/audits/$aid" params={{ aid: auditId }} search={{ tab: 'trajectory' }}>查看执行情况</Link>
    </div>
  );
}

function Interventions({ auditId }: { auditId: string }) {
  const t = useTrajectory(auditId, ['intervention'], '');
  const items = t.data?.items ?? [];
  const applied = new Map<string, string[]>();
  for (const e of items) if (e.type === 'intervention.applied') applied.set(String(e.payload.ref), (e.payload.applied as string[]) ?? []);
  const received = items.filter((e) => e.type === 'intervention.received' && e.payload.kind !== 'pause');
  if (!received.length) return null;
  return (
    <div className={S.section}>
      <div className={S.sectionHead}>你的介入</div>
      {received.map((e) => {
        const ap = applied.get(`I${e.seq}`);
        return (
          <div key={e.seq} className={S.intervention}>
            <div><span className={S.tag}>{INTERVENTION[String(e.payload.kind)] ?? String(e.payload.kind)}</span>{String(e.payload.text ?? '')}</div>
            <div className={S.receipt}>
              <Icon name={ap ? 'check' : 'clock'} size={12} />
              {!ap ? '等待送达…' : ap.includes('steer') ? '已送达正在运行的分析，并记入认知状态；尚未开始的步骤也会读到' : '已记入认知状态，之后的步骤会使用'}
              <span className={ui.faint}> · {fmt.time(e.ts)}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function AuditLiveCard({ auditId, title, showInterventions }: { auditId: string; title?: string; showInterventions?: boolean }) {
  const a = useAudit(auditId, { refetchInterval: (q) => (q.state.data && TERMINAL.includes(q.state.data.status) ? false : 3000) });
  const questions = useQuestions(auditId);
  const qc = useQueryClient();
  const toast = useToast();
  const [key] = useState(newIdempotencyKey);
  const [busy, setBusy] = useState(false);
  const [recorded, setRecorded] = useState<string | null>(null);
  const d = a.data;
  const ended = !!d && TERMINAL.includes(d.status);
  // the Agent's questions (about this audit's conclusions) before the plan's context questions (kept as facts).
  const open = (questions.data ?? []).filter((q) => q.status === 'open').sort((a, b) => Number(a.asFact) - Number(b.asFact));
  const recent = (questions.data ?? []).filter((q) => q.status !== 'open').slice(-3);
  const confirm = async () => {
    setBusy(true);
    try { await api.post(`/audit-plans/${auditId}/confirm`, {}, { idempotencyKey: key }); toast.ok('已确认，审计进入队列'); } catch (e) { toast.error(e); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['audit', auditId] });
  };
  return (
    <div className={S.card} aria-label="审计进度">
      <div className={S.head}>
        <Icon name="activity" size={14} />
        <b className={ui.ellipsis}>{title ?? d?.title ?? '审计'}</b>
        {d && <AuditStatusBadge status={d.status} />}
        <span className={ui.grow} />
        <Link to="/audits/$aid" params={{ aid: auditId }} className={S.link}>打开审计 <Icon name="chevronRight" size={12} /></Link>
      </div>
      {d && (
        <>
          <div className={S.meta}>
            {SCENE[d.scene] ?? d.scene} · {PHASE[d.phase] ?? d.phase} · 发现 {d.findingCount} · {fmt.tokens(d.budget.consumed.tokens)}/{fmt.tokens(d.budget.effective.tokens)} tokens · {fmt.duration(d.budget.consumed.durationMs)}
          </div>
          {!ended && d.status !== 'planning' && d.status !== 'awaiting_confirm' && <Progress value={d.budget.consumed.tokens} max={d.budget.effective.tokens} />}
          {d.status === 'running' && <ExecutionLine auditId={auditId} />}
          {d.status === 'planning' && <div className={S.note}><span className={ui.spinner} /> 正在生成计划，完成后自动开始</div>}
          {d.status === 'awaiting_confirm' && (
            <div className={S.note}>
              计划已生成，等你确认后开始。
              <Link to="/audits/$aid" params={{ aid: auditId }} search={{ tab: 'plan' }}>查看计划</Link>
              <Button size="sm" variant="primary" icon="play" loading={busy} onClick={() => void confirm()}>确认并开始</Button>
            </div>
          )}
          {d.status === 'waiting_budget' && <div className={S.note}>预算不足，已暂停。<Link to="/audits/$aid" params={{ aid: auditId }}>去追加预算</Link></div>}
          {(d.status === 'interrupted' || d.status === 'paused') && <div className={S.note}>{AUDIT_STATUS[d.status]}。<Link to="/audits/$aid" params={{ aid: auditId }}>去继续</Link></div>}
          {ended && (
            <div className={S.note}>
              {d.status === 'completed' ? '审计已完成' : AUDIT_STATUS[d.status]}：{d.findingCount} 个发现{open.length ? `，${open.length} 个提问待回答（相关结论保持待确认）` : ''}。
              {d.partialReasons.length > 0 && <span className={ui.faint}>{reasonsLabel(d.status)}：{d.partialReasons.map((r) => PARTIAL_REASON[r] ?? r).join('、')}。</span>}
              <Link to="/audits/$aid" params={{ aid: auditId }} search={{ tab: 'results' }}>查看结果</Link>
            </div>
          )}
        </>
      )}
      {open.length > 0 && (
        <div className={S.section}>
          <div className={S.sectionHead}>Agent 的提问（{open.length}）</div>
          {open.map((q) => <QuestionItem key={q.id} q={q} auditEnded={ended} onRecorded={setRecorded} />)}
        </div>
      )}
      {recent.length > 0 && (
        <div className={S.section}>
          <div className={S.sectionHead}>已回答</div>
          {recent.map((q) => <QuestionItem key={q.id} q={q} auditEnded={ended} onRecorded={setRecorded} />)}
        </div>
      )}
      {recorded && <ReverifyOffer auditId={auditId} note={recorded} />}
      {showInterventions && <Interventions auditId={auditId} />}
    </div>
  );
}
