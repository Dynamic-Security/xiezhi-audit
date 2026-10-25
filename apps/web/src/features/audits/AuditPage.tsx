// Audit detail: header with real phases and budget, controls, plan card,
// trajectory / results / coverage tabs, and the context panel (Agent chat or vulnerability).
import { useEffect, useRef, useState } from 'react';
import { useNavigate, useParams, useSearch } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { AuditCompareDto, AuditDetailDto, FilteredStepDto, ModelRef, StepDto } from '@xiezhi/contracts';
import { api, newIdempotencyKey } from '../../shared/api/client';
import { useAudit, useAudits, useFindings, useModelSettings, usePlan, useProviders, useQuestions } from '../../shared/api/queries';
import { useAuditStream } from '../../shared/stream/streams';
import { BUDGET_STAGE, PARTIAL_REASON, PHASE, PHASE_ORDER, SCENE, fmt, reasonsLabel } from '../../shared/format/messages';
import { TOP_UP_TOKENS_MAX, TOP_UP_TOKENS_MIN } from '../../shared/format/tokens';
import {
  AuditStatusBadge, Badge, Button, ConfirmDialog, Dialog, ErrorState, Field, Icon, Loading, Progress, Tabs, TokenCostHint, TokenInput, cx, ui, useToast,
} from '../../shared/ui';
import type { AuditSearch } from '../../router';
import { PageLayout, TopBar } from '../layout/AppShell';
import { VulnPanel, VulnPanelTitle } from '../vulns/VulnPanel';
import { PlanCard } from './PlanCard';
import { DomainPlanCard } from './DomainPlan';
import { CoverageStrip, CoverageView, ExportDialog, ResultsView } from './Results';
import { TrajectoryView } from './Trajectory';
import { EgressView } from './Egress';
import A from './audits.module.css';
import { useAi, useAiScope } from '../assistant/ai';

const TERMINAL = ['completed', 'partial', 'failed', 'cancelled'];

function PhaseBar({ a }: { a: AuditDetailDto }) {
  if (a.status === 'planning' || a.status === 'awaiting_confirm') return null;
  const cur = PHASE_ORDER.indexOf(a.phase as never);
  // An audit that ended without ever running (cancelled at its plan) went through none of the phases.
  const neverRan = a.phase === 'done' && !a.startedAt;
  return (
    <ol className={A.phases} aria-label="阶段">
      {PHASE_ORDER.map((p, i) => {
        const last = i === PHASE_ORDER.length - 1;
        const state = a.phase === 'done' ? (a.status === 'completed' ? 'done' : last ? 'warn' : neverRan ? 'todo' : 'done') : i < cur ? 'done' : i === cur ? 'cur' : 'todo';
        return (
          <li key={p} className={cx(A.phase, A[`phase_${state}`])}>
            <span className={A.phaseDot}>{state === 'done' ? <Icon name="check" size={11} /> : null}</span>
            {p === 'done' ? (a.status === 'completed' ? '已完成' : TERMINAL.includes(a.status) ? '结束' : '完成') : PHASE[p]}
          </li>
        );
      })}
    </ol>
  );
}

function BudgetDialog({ a, open, onClose }: { a: AuditDetailDto; open: boolean; onClose: () => void }) {
  const remaining = Math.max(0, a.budget.consumed.tokens - a.budget.effective.tokens);
  /** The server's suggestion covers the usage past the limit and the steps not run yet. Rounded up
   * to 0.1M and kept inside the top-up range. */
  const round = (n: number) => Math.min(TOP_UP_TOKENS_MAX, Math.max(TOP_UP_TOKENS_MIN, Math.ceil(n / 100_000) * 100_000));
  const fallback = round(remaining + a.budget.effective.tokens * 0.3);
  const [tokens, setTokens] = useState(fallback);
  const [minutes, setMinutes] = useState(0);
  // a stage that used up its quota is offered first; '' = the total only.
  const stages = a.budget.stages ?? [];
  const [stage, setStage] = useState<string>('');
  const stoppedStage = stages.find((x) => x.stopped)?.stage ?? '';
  // the audit detail refreshes while the dialog is open (polling and SSE); a refresh must not overwrite what
  // the user chose or typed. Suggestions fill in on opening and when the user picks another stage, until edited.
  const stageEdited = useRef(false);
  const tokensEdited = useRef(false);
  // Cleared on closing, not on opening: an opening effect could run after the first keystroke and drop it.
  useEffect(() => { if (!open) { stageEdited.current = false; tokensEdited.current = false; } }, [open]);
  useEffect(() => { if (open && !stageEdited.current) setStage(stoppedStage); }, [open, stoppedStage]);
  useEffect(() => {
    if (!open || tokensEdited.current) return;
    const own = stages.find((x) => x.stage === stage)?.suggestedTopUp;
    const s = stage ? own : a.budget.suggestedTopUp;
    setTokens(s ? round(s) : fallback);
  }, [open, stage, a.budget.suggestedTopUp]);
  // The API takes 1–10000M per top-up and whole minutes up to 7 days; say so here rather than after a 400.
  const tokensError = tokens < TOP_UP_TOKENS_MIN || tokens > TOP_UP_TOKENS_MAX ? `每次追加 ${fmt.tokens(TOP_UP_TOKENS_MIN)}–${fmt.tokens(TOP_UP_TOKENS_MAX)}` : null;
  const minutesError = !Number.isInteger(minutes) || minutes < 0 || minutes > 7 * 24 * 60 ? '时长为 0–10080 的整数分钟（最多 7 天）' : null;
  const [key] = useState(newIdempotencyKey);
  const [busy, setBusy] = useState(false);
  // the audit's frozen strategy names the model whose price the cost hint uses.
  const plan = usePlan(a.id, open);
  const qc = useQueryClient();
  const toast = useToast();
  const grant = async () => {
    setBusy(true);
    try {
      await api.post(`/audits/${a.id}/budget-grants`, { tokens, ...(minutes ? { durationSec: minutes * 60 } : {}), ...(stage ? { stage } : {}) }, { idempotencyKey: key });
      toast.ok('已追加预算，审计将继续');
      onClose();
    } catch (e) { toast.error(e); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['audit', a.id] });
  };
  // A stage quota stopped the audit → drop all stage quotas instead (only the total limits it from then on).
  const [liftKey] = useState(newIdempotencyKey);
  const lift = async () => {
    setBusy(true);
    try {
      await api.post(`/audits/${a.id}/budget-grants`, { liftStageQuotas: true }, { idempotencyKey: liftKey });
      toast.ok(a.budget.consumed.tokens < a.budget.effective.tokens ? '已取消阶段额度，审计将继续' : '已取消阶段额度；总预算也已用完，请追加总预算');
      onClose();
    } catch (e) { toast.error(e); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['audit', a.id] });
  };
  return (
    <Dialog open={open} onClose={onClose} title="追加预算" footer={<><Button onClick={onClose}>取消</Button>
      {stoppedStage && <Button loading={busy} onClick={() => void lift()} title="取消本次审计的全部阶段额度，之后只受总 token 预算限制">取消阶段额度并继续</Button>}
      <Button variant="primary" loading={busy} disabled={!!tokensError || !!minutesError} onClick={() => void grant()}>追加并继续</Button></>}>
      <p className={ui.muted}>已用 {fmt.tokens(a.budget.consumed.tokens)} / {fmt.tokens(a.budget.effective.tokens)} tokens。追加后审计从断点继续：已完成的步骤不重复，停下的会话从停下的地方接着做。</p>
      {stages.length > 0 && (
        <div className={ui.stack} style={{ gap: 4, margin: '8px 0 12px' }}>
          {stages.map((x) => (
            <div key={x.stage} className={ui.spread} style={{ fontSize: 13 }}>
              <span>{BUDGET_STAGE[x.stage] ?? x.stage}</span>
              <span className={ui.mono} style={{ color: x.stopped ? 'var(--danger)' : undefined }}>{fmt.tokens(x.consumed)} / {fmt.tokens(x.limit)}{x.stopped ? ' · 额度不足' : ''}</span>
            </div>
          ))}
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {stages.length > 0 && (
          <Field label="追加到" hint="追加到某个阶段时，这些 tokens 同时计入总预算">
            <select className={ui.select} value={stage} onChange={(e) => { stageEdited.current = true; tokensEdited.current = false; setStage(e.target.value); }}>
              <option value="">只追加总预算</option>
              {stages.map((x) => <option key={x.stage} value={x.stage}>{BUDGET_STAGE[x.stage] ?? x.stage}</option>)}
            </select>
          </Field>
        )}
        <Field label="追加 tokens" error={tokensError} hint={<>{fmt.tokens(TOP_UP_TOKENS_MIN)}–{fmt.tokens(TOP_UP_TOKENS_MAX)} · <TokenCostHint tokens={tokens} model={plan.data?.strategy.models.audit} /></>}><TokenInput value={tokens} onChange={(t) => { tokensEdited.current = true; setTokens(t || 0); }} /></Field>
        <Field label="追加时长（分钟，可选）" error={minutesError}><input className={ui.input} type="number" min={0} max={10080} step={1} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} /></Field>
      </div>
    </Dialog>
  );
}

function Header({ a, onExport }: { a: AuditDetailDto; onExport: () => void }) {
  const b = a.budget;
  const ratio = b.effective.tokens ? b.consumed.tokens / b.effective.tokens : 0;
  return (
    <div className={A.header}>
      <div className={ui.spread} style={{ alignItems: 'flex-start' }}>
        <div className={ui.grow}>
          <div className={cx(ui.row, ui.wrap)}><AuditStatusBadge status={a.status} /><Badge>{SCENE[a.scene] ?? a.scene} · {a.mode === 'single' ? '单仓库' : '多仓库'}</Badge>
            {a.repos.map((r) => <Badge key={r.id} tone={r.roleInAudit === 'target' ? 'neutral' : 'info'}><Icon name="git" size={12} />{r.name}{r.roleInAudit !== 'target' ? `（${r.roleInAudit === 'related' ? '关联' : '上下文'}）` : ''} {r.worktree ? '工作区版本' : `${r.ref ?? ''} ${r.commit?.slice(0, 7) ?? ''}`}</Badge>)}</div>
          <h1 className={A.title}>{a.title}</h1>
        </div>
        {TERMINAL.includes(a.status) && <div className={cx(ui.row, ui.wrap)} style={{ justifyContent: 'flex-end', gap: 4 }}>
          <CompareButton a={a} />
          <RerunButton a={a} />
          <Button size="sm" icon="download" onClick={onExport}>导出报告</Button>
        </div>}
      </div>
      <PhaseBar a={a} />
      <div className={A.meters}>
        <div className={A.meter}>
          <div className={ui.spread}><span className={ui.faint}>tokens</span><span><b>{fmt.tokens(b.consumed.tokens)}</b> / {fmt.tokens(b.effective.tokens)}</span></div>
          <Progress value={b.consumed.tokens} max={b.effective.tokens} {...(ratio > 1 ? { tone: 'danger' as const } : ratio > 0.8 ? { tone: 'warn' as const } : {})} />
        </div>
        <div className={A.meter}>
          <div className={ui.spread}><span className={ui.faint}>运行时长</span><span><b>{fmt.duration(b.consumed.durationMs)}</b> / {fmt.duration(b.effective.durationMs)}</span></div>
          <Progress value={b.consumed.durationMs} max={b.effective.durationMs} />
        </div>
        <div className={A.meterSmall}><span className={ui.faint}>成本</span><b>{fmt.cost(b.consumed.costMicros)}</b></div>
        <div className={A.meterSmall}><span className={ui.faint}>发现</span><b>{a.findingCount}</b></div>
      </div>
      {a.partialReasons.length > 0 && <div className={cx(ui.row, ui.wrap)} style={{ marginTop: 10 }}><span className={ui.faint} style={{ fontSize: 12 }}>{reasonsLabel(a.status)}：</span>{a.partialReasons.map((r) => <Badge key={r} tone="warn">{PARTIAL_REASON[r] ?? r}</Badge>)}</div>}
    </div>
  );
}

/** Rerun with the same configuration: scene, version, strategy, baseline or targets. */
function RerunButton({ a }: { a: AuditDetailDto }) {
  const [busy, setBusy] = useState(false);
  const [key] = useState(newIdempotencyKey);
  const navigate = useNavigate();
  const toast = useToast();
  if (a.title.startsWith('补审：')) return null;
  const rerun = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ auditId: string }>(`/audits/${a.id}/rerun`, {}, { idempotencyKey: key });
      toast.ok('已按原配置新建审计');
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) { toast.error(e); }
    setBusy(false);
  };
  return <Button size="sm" variant="ghost" icon="refresh" loading={busy} onClick={() => void rerun()}>重新审计</Button>;
}

/** Compare with another finished audit of the project: appeared, disappeared, changed. */
function CompareButton({ a }: { a: AuditDetailDto }) {
  const [open, setOpen] = useState(false);
  const [other, setOther] = useState('');
  const audits = useAudits({ projectId: a.projectId }, { enabled: open });
  const candidates = (audits.data?.items ?? []).filter((x) => x.id !== a.id && TERMINAL.includes(x.status) && x.scene !== 'reverify');
  const cmp = useQuery({ queryKey: ['audit', a.id, 'compare', other], queryFn: () => api.get<AuditCompareDto>(`/audits/${a.id}/compare?with=${encodeURIComponent(other)}`), enabled: open && !!other });
  const PRESENCE: Record<string, string> = { not_found_verified: '已修复（经验证）', not_found_unverified: '覆盖到但未找到（未验证修复）', not_covered: '本次未覆盖', absent: '本次未涉及' };
  return (
    <>
      <Button size="sm" variant="ghost" icon="layers" onClick={() => setOpen(true)}>对比</Button>
      <Dialog open={open} onClose={() => setOpen(false)} title="审计对比" footer={<Button onClick={() => setOpen(false)}>关闭</Button>}>
        <Field label="与哪次审计对比（较早的一次）">
          <select className={ui.select} value={other} onChange={(e) => setOther(e.target.value)}>
            <option value="">选择审计</option>
            {candidates.map((x) => <option key={x.id} value={x.id}>{x.title} · {fmt.date(x.createdAt)}</option>)}
          </select>
        </Field>
        {cmp.data && (
          <div className={ui.stack} style={{ gap: 12 }} aria-label="对比结果">
            <div><b>新增（{cmp.data.added.length}）</b>{cmp.data.added.map((v) => <div key={v.vulnId}>V-{v.displayNo} {v.title}</div>)}</div>
            <div><b>消失（{cmp.data.removed.length}）</b>{cmp.data.removed.map((v) => <div key={v.vulnId}>V-{v.displayNo} {v.title} <span className={ui.faint}>— {PRESENCE[v.presence] ?? v.presence}</span></div>)}</div>
            <div><b>变化（{cmp.data.changed.length}）</b>{cmp.data.changed.map((v) => <div key={v.vulnId}>V-{v.displayNo} {v.title} <span className={ui.faint}>— {v.changes.join('；')}</span></div>)}</div>
            <div className={ui.faint}>未变化 {cmp.data.unchanged} 个。“消失”不等于已修复：只有“已修复（经验证）”经过定向验证。</div>
          </div>
        )}
      </Dialog>
    </>
  );
}

const THINKING_OPTS: [NonNullable<ModelRef['thinking']> | '', string][] = [['', '默认'], ['off', '关'], ['low', '低'], ['medium', '中'], ['high', '高']];

type SwitchScope = 'filtered' | 'later';

/**
 * “切换模型重试”: the content-filtered steps continue on a model the user picks — preselected: the fallback model
 * from 设置 › 模型 (unless it is the model that was refused), else the first other configured model.
 */
function SwitchModelDialog({ open, onClose, refused, count, onConfirm }: { open: boolean; onClose: () => void; refused: string[]; count: number; onConfirm: (m: ModelRef, scope: SwitchScope) => void }) {
  const providers = useProviders();
  const ms = useModelSettings();
  const all = (providers.data ?? []).flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`));
  const fb = ms.data?.fallbackModel ?? null;
  const fbKey = fb ? `${fb.provider}/${fb.model}` : '';
  const initial = fb && all.includes(fbKey) && !refused.includes(fbKey) ? fbKey : all.find((m) => !refused.includes(m)) ?? all[0] ?? '';
  const [model, setModel] = useState('');
  const [thinking, setThinking] = useState<string>('');
  const [scope, setScope] = useState<SwitchScope>('later');
  useEffect(() => { if (open) { setModel(initial); setThinking(initial === fbKey ? fb?.thinking ?? '' : ''); setScope('later'); } }, [open, initial]);
  const confirm = () => {
    const i = model.indexOf('/');
    onConfirm({ provider: model.slice(0, i), model: model.slice(i + 1), ...(thinking ? { thinking: thinking as NonNullable<ModelRef['thinking']> } : {}) }, scope);
  };
  const names = refused.join('、') || '未知';
  const hint = !fbKey ? '还没有配置备用模型，可在“设置 › 模型”中配置'
    : refused.includes(fbKey) ? `备用模型 ${fbKey} 也被拦截过，默认改选其他模型` : `默认选中备用模型 ${fbKey}`;
  const SCOPES: [SwitchScope, string, string][] = [
    ['later', '被拦截的步骤和之后的步骤', `这 ${count} 个步骤从停下的地方接着做；之后原本使用 ${names} 的步骤也都改用所选模型。交叉审查中所选模型已是另一路时，那一路不切换。`],
    ['filtered', '只切换被拦截的步骤', `这 ${count} 个步骤改用所选模型，从停下的地方接着做；其他步骤仍用原来的模型，再被拦截时会再次暂停。`],
  ];
  return (
    <Dialog open={open} onClose={onClose} title="切换模型重试" footer={<><Button onClick={onClose}>取消</Button><Button variant="primary" icon="play" disabled={!model} onClick={confirm}>切换并继续</Button></>}>
      <div className={ui.stack}>
        <p className={ui.muted} style={{ margin: 0 }}>本次审计被拦截的模型：{names}</p>
        <div className={ui.stack} style={{ gap: 6 }} role="radiogroup" aria-label="切换范围">
          {SCOPES.map(([k, label, note]) => (
            <label key={k} className={ui.checkbox} style={{ alignItems: 'flex-start' }}>
              <input type="radio" name="switch-scope" checked={scope === k} onChange={() => setScope(k)} />
              <span><b>{label}</b><span className={ui.faint} style={{ fontSize: 12, display: 'block' }}>{note}</span></span>
            </label>
          ))}
        </div>
        <div className={ui.row} style={{ gap: 8, alignItems: 'flex-end' }}>
          <div className={ui.grow}><Field label="模型" hint={hint}>
            <select aria-label="切换到的模型" className={ui.select} value={model} onChange={(e) => setModel(e.target.value)}>
              {all.map((m) => <option key={m} value={m}>{m}{m === fbKey ? '（备用模型）' : ''}{refused.includes(m) ? '（被拦截）' : ''}</option>)}
            </select>
          </Field></div>
          <div style={{ width: 110, alignSelf: 'flex-start' }}><Field label="思考强度">
            <select aria-label="切换到的模型思考强度" className={ui.select} value={thinking} onChange={(e) => setThinking(e.target.value)}>
              {THINKING_OPTS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
          </Field></div>
        </div>
      </div>
    </Dialog>
  );
}

/** The switches the user chose for later steps, shown with the content-filter banners. */
function ModelSwitches({ a }: { a: AuditDetailDto }) {
  if (!a.modelSwitches.length) return null;
  return <div style={{ marginTop: 6, fontSize: 12 }}>之后的步骤已切换：{a.modelSwitches.map((x) => `${x.from} → ${x.to.provider}/${x.to.model}`).join('；')}</div>;
}

/** The refused steps — which provider/model refused each, and on demand what was sent and what came back. */
function FilteredSteps({ auditId, steps }: { auditId: string; steps: StepDto[] }) {
  const models = [...new Set(steps.map((s) => s.model ?? '未知模型'))];
  return (
    <div style={{ marginTop: 6, fontSize: 12 }}>
      <div>被拦截的模型：<b>{models.join('、')}</b></div>
      <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>{steps.map((s) => <FilteredStep key={s.id} auditId={auditId} s={s} />)}</ul>
    </div>
  );
}

const ROLE: Record<string, string> = { user: '发送（任务 / 用户消息）', toolResult: '发送（工具结果）', assistant: '模型回复', system: '系统提示' };

function FilteredStep({ auditId, s }: { auditId: string; s: StepDto }) {
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ['audit', auditId, 'filtered', s.id, s.attempt], queryFn: () => api.get<FilteredStepDto>(`/audits/${auditId}/steps/${s.id}/filtered`), enabled: open });
  const pre = { margin: '4px 0 8px', padding: 8, maxHeight: 240, overflow: 'auto', whiteSpace: 'pre-wrap' as const, wordBreak: 'break-word' as const, background: 'var(--bg-code)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', fontFamily: 'var(--font-mono)', fontSize: 12 };
  return (
    <li>
      <span>{s.lineage ?? s.kind} · <code>{s.model ?? '未知模型'}</code>：{(s.errorSummary ?? '').slice(0, 120)}</span>
      {' '}<Button size="sm" variant="ghost" onClick={() => setOpen(!open)}>{open ? '收起' : '查看拦截详情'}</Button>
      {open && (
        <div style={{ marginTop: 4 }}>
          {q.isLoading && <div className={ui.muted}>读取中…</div>}
          {q.error && <div className={ui.muted}>读取失败：{String((q.error as Error).message)}</div>}
          {q.data && (<>
            <div><b>服务返回</b>{q.data.reply?.model ? `（${q.data.reply.model}）` : ''}</div>
            <pre style={pre}>{q.data.reply ? [q.data.reply.text, q.data.reply.errorMessage].filter(Boolean).join('\n\n') : q.data.error ?? '没有记录'}</pre>
            <div><b>拦截前发送的最后 {q.data.request.length} 条消息</b>（第 {q.data.attempt} 次尝试；被审代码与文档原样展示，只作查看）</div>
            {q.data.request.length ? q.data.request.map((m, i) => (
              <div key={i}>
                <div className={ui.muted}>{ROLE[m.role] ?? m.role}{m.chars > m.text.length ? `（共 ${m.chars} 字，显示前 ${m.text.length} 字）` : `（${m.chars} 字）`}</div>
                <pre style={pre}>{m.text}</pre>
              </div>
            )) : <div className={ui.muted}>没有保存的会话记录（可能已选择“从头开始”）</div>}
          </>)}
        </div>
      )}
    </li>
  );
}

function StatusBanner({ a }: { a: AuditDetailDto }) {
  const [budget, setBudget] = useState(false);
  const [switching, setSwitching] = useState(false);
  const [decline, setDecline] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const post = async (path: string, ok: string, body?: unknown) => {
    try { await api.post(`/audits/${a.id}/${path}`, body); toast.ok(ok); } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['audit', a.id] });
  };
  if (a.status === 'waiting_budget') {
    return (
      <div className={cx(A.banner, A.bannerWarn)}>
        <Icon name="clock" /><div className={ui.grow}><b>预算不足，审计已暂停等待。</b> 追加预算后从断点继续；也可以放弃，以已有结果结束（标为未完成）。</div>
        <Button size="sm" onClick={() => setDecline(true)}>放弃并收尾</Button>
        <Button size="sm" variant="primary" onClick={() => setBudget(true)}>追加预算</Button>
        <BudgetDialog a={a} open={budget} onClose={() => setBudget(false)} />
        <ConfirmDialog open={decline} onClose={() => setDecline(false)} title="放弃追加预算" confirmText="以已有结果结束" onConfirm={() => { setDecline(false); void post('budget-grants/decline', '将以已有结果收尾'); }}>
          审计会跳过剩余分析，用已有结果完成对账与报告，并标记为“未完成（预算耗尽）”。
        </ConfirmDialog>
      </div>
    );
  }
  // a step the model's content filter refused, with no fallback model, paused the audit for a person.
  const filtered = a.steps.filter((s) => s.status === 'interrupted' && s.errorClass === 'CONTENT_FILTERED');
  if ((a.status === 'interrupted' || a.status === 'paused') && filtered.length) {
    return (
      <div className={cx(A.banner, A.bannerWarn)}>
        <Icon name="pause" /><div className={ui.grow}><b>审计已暂停：{filtered.length} 个步骤被模型的内容过滤拦截。</b> 安全审计内容有时会被误判。可以切换到另一个模型接着做，也可以让这些步骤从头开始一次新的对话，或原样重试。配置了备用模型时，被拦截会先自动切换一次；备用模型也被拦截、与被拦截的模型相同，或这一步是交叉审查的一路而备用模型是另一路时才停下来。交叉审查中只有一个模型被拦截时，按审计设置继续运行（默认，同一任务的模型都被拦截才暂停）或暂停。
          <FilteredSteps auditId={a.id} steps={filtered} />
          <ModelSwitches a={a} />
        </div>
        <Button size="sm" onClick={() => void post('resume', '已继续：原样重试')}>原样重试</Button>
        <Button size="sm" onClick={() => void post('resume', '已继续：被拦截的步骤从头开始', { restartFiltered: true })}>从头开始这些步骤</Button>
        <Button size="sm" variant="primary" icon="play" onClick={() => setSwitching(true)}>切换模型重试</Button>
        <SwitchModelDialog open={switching} onClose={() => setSwitching(false)} count={filtered.length}
          refused={[...new Set([...a.filteredModels, ...filtered.map((s) => s.model).filter((m): m is string => !!m)])]}
          onConfirm={(m, scope) => {
            setSwitching(false);
            void post('resume', `已继续：${scope === 'later' ? '被拦截的步骤和之后的步骤' : '被拦截的步骤'}改用 ${m.provider}/${m.model}`, { switchModel: m, switchScope: scope });
          }} />
      </div>
    );
  }
  // In cross review a refused lane does not pause the audit while another model goes on with the task.
  if (a.status === 'running' && filtered.length) {
    return (
      <div className={cx(A.banner, A.bannerWarn)}>
        <Icon name="alert" /><div className={ui.grow}><b>{filtered.length} 个交叉审查步骤被模型的内容过滤拦截，审计继续。</b> 这些任务先用其他模型的结果；同一任务的模型都被拦截时审计才暂停。要换模型补做，可以暂停后选择“切换模型重试”；不处理的话，审计结束时这些步骤记为跳过，报告中注明。
          <FilteredSteps auditId={a.id} steps={filtered} />
          <ModelSwitches a={a} />
        </div>
        <Button size="sm" icon="pause" onClick={() => void post('pause', '已请求暂停：进行中的会话做完这一轮后停下，之后可以切换模型重试')}>暂停并处理</Button>
      </div>
    );
  }
  // Paused by the model service breaker (probed, continues by itself) or by a used-up balance / quota.
  const down = a.steps.filter((s) => s.status === 'interrupted' && s.errorClass === 'PROVIDER_TRANSIENT');
  const quota = a.steps.filter((s) => s.status === 'interrupted' && s.errorClass === 'PROVIDER_QUOTA');
  if (a.status === 'paused' && (quota.length || down.length)) {
    const list = quota.length ? quota : down;
    return (
      <div className={cx(A.banner, A.bannerWarn)}>
        <Icon name="pause" /><div className={ui.grow}>
          {quota.length
            ? <><b>审计已暂停：模型服务的余额或额度不足。</b> 充值或提高额度后点“继续”，进行中的会话从停下的地方接着做。</>
            : <><b>审计已暂停：模型服务连续无响应。</b> 系统每隔 1、2、4、8、10 分钟探测一次，服务恢复后自动继续；也可以现在手动继续。</>}
          <ul style={{ margin: '6px 0 0', paddingLeft: 18, fontSize: 12 }}>{list.slice(0, 5).map((s) => <li key={s.id}>{s.lineage ?? s.kind}：{(s.errorSummary ?? '').slice(0, 160)}</li>)}</ul>
        </div>
        <Button size="sm" variant="primary" icon="play" onClick={() => void post('resume', '已继续')}>继续</Button>
      </div>
    );
  }
  if (a.status === 'interrupted' || a.status === 'paused') {
    return (
      <div className={cx(A.banner, A.bannerWarn)}>
        <Icon name="pause" /><div className={ui.grow}><b>{a.status === 'paused' ? '审计已暂停。' : '审计已中断（服务重启或进程退出）。'}</b> 继续后已完成的步骤不重复，进行中的会话从停下的地方接着做（服务重启后同样可以继续），代码版本不变，预算累计不清零。</div>
        <Button size="sm" variant="primary" icon="play" onClick={() => void post('resume', '已继续')}>继续</Button>
      </div>
    );
  }
  if (a.status === 'failed') {
    return <div className={cx(A.banner, A.bannerDanger)}><Icon name="alert" /><div className={ui.grow}><b>审计失败</b>{a.errorClass ? `（${a.errorClass}）` : ''}。详情见轨迹中的错误事件。</div></div>;
  }
  return null;
}

export function AuditPage() {
  const { aid } = useParams({ from: '/audits/$aid' });
  const search = useSearch({ from: '/audits/$aid' });
  const navigate = useNavigate({ from: '/audits/$aid' });
  const q = useAudit(aid);
  const a = q.data;
  useAiScope(a ? { kind: 'audit', id: aid, label: `${a.projectName} · ${a.title}` } : null);
  const live = !!a && !TERMINAL.includes(a.status);
  const stream = useAuditStream(aid, live);
  const questions = useQuestions(aid);
  const findings = useFindings(aid);
  const [exportOpen, setExportOpen] = useState(false);
  const [cancel, setCancel] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const setSearch = (patch: Partial<AuditSearch>, replace = false) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace });
  const ai = useAi();
  const { setOpen: openAi } = ai;
  // Links from the inbox (“去回答”) carry panel=chat: the questions are in the audit's AI tab.
  useEffect(() => {
    if (search.panel === 'chat') { openAi(true); void navigate({ search: (prev) => ({ ...prev, panel: undefined }), replace: true }); }
  }, [search.panel, openAi, navigate]);

  if (q.isLoading) return <><TopBar crumbs={[{ label: '工作台', to: '/' }, { label: '审计' }]} /><Loading rows={8} /></>;
  if (q.error || !a) return <><TopBar crumbs={[{ label: '工作台', to: '/' }, { label: '审计' }]} /><ErrorState error={q.error} onRetry={() => void q.refetch()} /></>;

  // While it runs the audit opens on its trajectory, which carries the execution status; finished ones
  // on their results. `tab=execution` (the former overview tab) opens the trajectory.
  const tab = search.tab === 'execution' ? 'trajectory' : search.tab ?? (a.status === 'planning' || a.status === 'awaiting_confirm' ? 'plan' : TERMINAL.includes(a.status) ? 'results' : 'trajectory');
  const vid = search.panel?.startsWith('vuln:') ? search.panel.slice(5) : null;
  const openQ = questions.data?.filter((x) => x.status === 'open').length ?? 0;
  const control = async (path: string, ok: string) => {
    try { await api.post(`/audits/${aid}/${path}`); toast.ok(ok); } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['audit', aid] });
  };
  // The audit's conversation, questions and interventions live in the AI tab; the detail tab shows a vulnerability.
  const panel = vid ? <VulnPanel vid={vid} /> : undefined;
  const panelTitle = vid ? <VulnPanelTitle vid={vid} /> : undefined;

  return (
    <>
      <TopBar crumbs={[{ label: '工作台', to: '/' }, { label: a.projectName, to: '/projects/$pid', params: { pid: a.projectId } }, { label: a.title }]} actions={<>
        {live && <span className={A.streamState} title="实时连接状态">{stream.state === 'live' ? <><span className={A.liveDot} />实时</> : stream.state === 'polling' ? '实时连接已断开，正在轮询' : stream.state === 'connecting' ? '连接中…' : ''}</span>}
        {a.status === 'running' && <Button size="sm" icon="pause" onClick={() => void control('pause', '已请求暂停：进行中的会话做完这一轮后停下，继续时从这里接着做')}>暂停</Button>}
        {!TERMINAL.includes(a.status) && a.status !== 'cancelling' && <Button size="sm" variant="danger" icon="stop" onClick={() => setCancel(true)}>取消</Button>}
        {openQ > 0 && <Button size="sm" variant="primary" icon="help" onClick={() => ai.setOpen(true)}>{openQ} 个提问待回答</Button>}
      </>} />
      <PageLayout panel={panel} panelTitle={panelTitle} panelKey={vid ?? undefined} onClosePanel={() => setSearch({ panel: undefined })}>
        <Header a={a} onExport={() => setExportOpen(true)} />
        <StatusBanner a={a} />
        {!['planning', 'awaiting_confirm', 'queued'].includes(a.status) && tab !== 'coverage' && <CoverageStrip aid={aid} live={!TERMINAL.includes(a.status)} onOpen={() => setSearch({ tab: 'coverage' })} />}
        {(a.status === 'planning' || a.status === 'awaiting_confirm') && tab !== 'plan' && <div style={{ marginTop: 16 }}><PlanCard aid={aid} status={a.status} /></div>}
        <div style={{ margin: '20px 0 16px' }}>
          <Tabs value={tab} onChange={(t) => setSearch({ tab: t })} items={[
            { key: 'plan', label: '计划' }, { key: 'trajectory', label: '行为轨迹' },
            { key: 'results', label: '结果', count: findings.data?.filter((f) => f.state === 'canonical').length }, { key: 'coverage', label: '覆盖对照' }, { key: 'egress', label: '外发记录' },
          ]} />
        </div>
        {tab === 'plan' && <PlanCard aid={aid} status={a.status} onConfirmed={() => setSearch({ tab: 'trajectory' })} />}
        {(tab === 'plan' || tab === 'trajectory') && !['planning', 'awaiting_confirm', 'queued'].includes(a.status) && <DomainPlanCard key={tab} aid={aid} live={!TERMINAL.includes(a.status)} folded={tab === 'trajectory'} />}
        {tab === 'trajectory' && (
          <TrajectoryView aid={aid} audit={a} types={search.type ?? []} q={search.q ?? ''} step={search.step} onStep={(st) => setSearch({ step: st })}
            onTypes={(t) => setSearch({ type: t })} onQ={(x) => setSearch({ q: x || undefined }, true)} onVuln={(v) => setSearch({ panel: `vuln:${v}` })} />
        )}
        {tab === 'results' && <ResultsView audit={a} onVuln={(v) => setSearch({ panel: `vuln:${v}` })} />}
        {tab === 'egress' && <EgressView aid={aid} live={!TERMINAL.includes(a.status)} />}
        {tab === 'coverage' && <CoverageView aid={aid} finished={['completed', 'partial'].includes(a.status)} onVuln={(v) => setSearch({ panel: `vuln:${v}` })} />}
      </PageLayout>
      <ExportDialog audit={a} open={exportOpen} onClose={() => setExportOpen(false)} />
      <ConfirmDialog open={cancel} onClose={() => setCancel(false)} title="取消审计" level="destructive" confirmText="取消审计"
        onConfirm={() => { setCancel(false); void control('cancel', '已取消，已得出的结果会保留'); }}>
        正在运行的分析会被中止。已得出的结果保留，但审计会标记为“已取消”。
      </ConfirmDialog>
    </>
  );
}
