// Audit plan card: scope, versions, entries, focus directions with reasons, planned
// knowledge, context to supply, estimate, limitations. Editable (budget/focus) before confirmation.
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { PlanDto } from '@xiezhi/contracts';
import { api, newIdempotencyKey } from '../../shared/api/client';
import { useConnectors, useModelSettings, usePlan } from '../../shared/api/queries';
import { IMPACT_MODE, IMPACT_REASON, fmt } from '../../shared/format/messages';
import { Badge, Button, ConfirmDialog, Dialog, ErrorState, Field, Icon, Loading, TokenInput, cx, ui, useToast } from '../../shared/ui';
import A from './audits.module.css';
import { AnalysisOptions, analysisChoiceOf, analysisOverride } from './AnalysisOptions';
import { StageModelsSummary } from './StageModels';

function EditPlanDialog({ plan, open, onClose }: { plan: PlanDto; open: boolean; onClose: () => void }) {
  const [tokens, setTokens] = useState(plan.strategy.budget.tokens);
  const [minutes, setMinutes] = useState(Math.round(plan.strategy.budget.durationSec / 60));
  const [focus, setFocus] = useState(plan.strategy.focus.text ?? '');
  // The stage-quota switch, shown when the plan has shares to switch on.
  const hasShares = Object.values(plan.strategy.budget.stages ?? {}).some((r) => r !== undefined && r < 1);
  const [stageLimits, setStageLimits] = useState(plan.strategy.budget.stageLimits !== false && hasShares);
  const [challenge, setChallenge] = useState(plan.strategy.stages.adversarialReview);
  const [analyses, setAnalyses] = useState(analysisChoiceOf(plan.scene, plan.strategy.stages));
  const optional = plan.scene === 'full' || plan.scene === 'incremental';
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const save = async () => {
    setBusy(true);
    try {
      await api.patch(`/audit-plans/${plan.auditId}`, {
        strategyOverride: (() => {
          const a = optional ? analysisOverride(plan.scene, analyses) : null;
          return { budget: { tokens, durationSec: minutes * 60, ...(hasShares ? { stageLimits } : {}) }, focus: { ...plan.strategy.focus, text: focus }, stages: { adversarialReview: challenge, ...(a?.stages ?? {}) } };
        })(),
      }, { ifMatch: plan.revision });
      toast.ok('计划已更新');
      onClose();
    } catch (e) { toast.error(e); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['audit', plan.auditId] });
  };
  return (
    <Dialog open={open} onClose={onClose} title="调整计划" footer={<><Button onClick={onClose}>取消</Button><Button variant="primary" loading={busy} onClick={() => void save()}>保存</Button></>}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Field label="token 预算"><TokenInput value={tokens} onChange={(t) => setTokens(t || 0)} /></Field>
        <Field label="时长上限（分钟）"><input className={ui.input} type="number" min={1} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} /></Field>
      </div>
      {hasShares && <label className={ui.checkbox}><input type="checkbox" checked={stageLimits} onChange={(e) => setStageLimits(e.target.checked)} />限制各阶段额度{stageLimits ? '' : '（已关闭：各阶段只受总 token 预算限制）'}</label>}
      <Field label="业务关注点"><textarea className={ui.textarea} value={focus} onChange={(e) => setFocus(e.target.value)} maxLength={4000} /></Field>
      <label className={ui.checkbox}><input type="checkbox" checked={challenge} onChange={(e) => setChallenge(e.target.checked)} />对抗复核</label>
      {optional && <AnalysisOptions value={analyses} onChange={setAnalyses} maxCandidates={plan.strategy.limits.maxCandidates} />}
      <p className={ui.faint} style={{ fontSize: 12 }}>预估值基于生成计划时的规模，修改预算不会重新生成计划叙述。</p>
    </Dialog>
  );
}

export function PlanCard({ aid, status, onConfirmed }: { aid: string; status: string; onConfirmed?: () => void }) {
  const q = usePlan(aid, status !== 'planning');
  const connectors = useConnectors();
  const ms = useModelSettings();
  const [edit, setEdit] = useState(false);
  const [cancel, setCancel] = useState(false);
  const [busy, setBusy] = useState(false);
  const [key] = useState(newIdempotencyKey);
  const qc = useQueryClient();
  const toast = useToast();
  if (status === 'planning') {
    return (
      <div className={cx(ui.card, A.planPending)}>
        <span className={ui.spinner} />
        <div><b>Agent 正在生成审计计划</b><div className={ui.muted} style={{ fontSize: 13 }}>固定代码版本 → 结构索引 → 快速浏览仓库。通常需要一两分钟，右侧轨迹会实时更新。</div></div>
      </div>
    );
  }
  if (q.isLoading) return <Loading rows={6} />;
  if (q.error || !q.data) return <ErrorState error={q.error} />;
  const p = q.data;
  if (!p.plan) return <div className={cx(ui.card, ui.cardPad)}><p className={ui.muted}>没有生成计划（审计可能在计划阶段中断或失败）。</p></div>;
  const pl = p.plan;
  const e = pl.estimate;
  const awaiting = status === 'awaiting_confirm';
  const confirm = async () => {
    setBusy(true);
    try {
      await api.post(`/audit-plans/${aid}/confirm`, {}, { idempotencyKey: key });
      toast.ok('已确认，审计进入队列');
      onConfirmed?.();
    } catch (err) { toast.error(err); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['audit', aid] });
  };
  return (
    <div className={cx(ui.card, A.plan)}>
      <div className={A.planHead}>
        <div className={ui.row}><Icon name="sparkle" /><b>审计计划</b>{awaiting ? <Badge tone="warn">待你确认</Badge> : <Badge tone="ok">已确认</Badge>}</div>
        {awaiting && <div className={ui.row}>
          <Button size="sm" variant="ghost" onClick={() => setCancel(true)}>取消审计</Button>
          <Button size="sm" icon="edit" onClick={() => setEdit(true)}>调整</Button>
          <SarifImport aid={aid} />
          <Button size="sm" variant="primary" icon="play" loading={busy} onClick={() => void confirm()}>确认并开始</Button>
        </div>}
      </div>
      <p className={ui.pre} style={{ marginTop: 10 }}>{pl.summary}</p>
      <div className={A.planStats}>
        <div><span className={ui.faint}>文件</span><b>{fmt.n(pl.scale.files)}</b></div>
        <div><span className={ui.faint}>入口</span><b>{pl.scale.entrypoints}</b></div>
        <div><span className={ui.faint}>危险点</span><b>{pl.scale.sinks}</b></div>
        <div><span className={ui.faint}>候选</span><b>{pl.scale.candidates}</b></div>
        <div><span className={ui.faint}>预计 tokens</span><b>{fmt.tokensRange(e.tokens.p50, e.tokens.p90)}</b></div>
        <div><span className={ui.faint}>预计耗时</span><b>{Math.round(e.durationSec.p50 / 60)}–{Math.round(e.durationSec.p90 / 60)} 分钟</b></div>
        <div><span className={ui.faint}>预计成本</span><b>{e.cost ? `${e.cost.p50.toFixed(2)}–${e.cost.p90.toFixed(2)} ${e.cost.currency}` : '未知'}</b></div>
        <div><span className={ui.faint}>预算</span><b>{fmt.tokens(p.strategy.budget.tokens)} · {Math.round(p.strategy.budget.durationSec / 60)} 分钟</b></div>
        {(p.strategy.connectors ?? []).length > 0 && (
          <div><span className={ui.faint}>可使用的连接器</span><b>{(p.strategy.connectors ?? []).map((id) => connectors.data?.find((c) => c.id === id || c.name === id)?.name ?? id).join('、')}</b></div>
        )}
      </div>
      {/* each stage's share of the median tokens; a stage with a strategy switch can be turned off under 调整. */}
      {(e.stages ?? []).length > 0 && (
        <div className={ui.muted} style={{ fontSize: 13, marginTop: 6 }} aria-label="各阶段预计 tokens">
          各阶段预计（中位数）：{e.stages!.map((x) => `${x.label} ${fmt.tokens(x.tokens)}${x.switch ? '（可关闭）' : ''}`).join(' · ')}
        </div>
      )}
      {pl.incremental && (
        <div className={A.planIncremental} aria-label="增量对比">
          {/* A multi-repository incremental audit shows each target's baseline and change. */}
          {(pl.incremental.repos ?? [{ ...pl.incremental, repo: null }]).map((x) => (
            <div key={x.repo ?? ''} className={ui.stack} style={{ gap: 2 }}>
              <div className={ui.row}><Icon name="git" size={14} /><b>{x.repo ? `${x.repo} · 对比基线` : '对比基线'}</b>
                <span className={ui.muted}>{x.base ? `${x.base.ref ?? (x.base.auditId ? '上次审计的版本' : '')} ${x.base.commit ? x.base.commit.slice(0, 7) : x.base.worktree ? '工作区版本' : ''}` : '没有基线'}</span>
                <Badge tone={x.mode === 'precise' ? 'ok' : 'warn'}>{IMPACT_MODE[x.mode]}</Badge>
              </div>
              {x.base && (
                <div className={ui.muted} style={{ fontSize: 13 }}>
                  {x.repo && !x.changedFiles.added && !x.changedFiles.modified && !x.changedFiles.deleted && !x.changedFiles.renamed ? '没有变更：只作为跨仓调用链的依据' : <>
                    变更文件：新增 {x.changedFiles.added} · 修改 {x.changedFiles.modified} · 删除 {x.changedFiles.deleted} · 移动 {x.changedFiles.renamed}
                    {x.mode !== 'heuristic' || x.affectedEntrypoints ? ` ；受影响入口 ${x.affectedEntrypoints} · 危险点 ${x.affectedSinks}` : ''}
                  </>}
                </div>
              )}
              {x.fallbackReasons.length > 0 && <div className={ui.faint} style={{ fontSize: 12 }}>{x.fallbackReasons.map((r) => IMPACT_REASON[r] ?? r).join('；')}</div>}
            </div>
          ))}
        </div>
      )}
      <div className={A.planGrid}>
        <div>
          <h4>审计对象与版本</h4>
          {p.repos.map((r) => <div key={r.id} className={ui.row}><Icon name="git" size={14} /><b>{r.name}</b>{p.repos.length > 1 && <Badge tone={r.roleInAudit === 'target' ? 'accent' : 'info'}>{r.roleInAudit === 'target' ? '审计目标' : r.roleInAudit === 'related' ? '关联（证据）' : '上下文（契约）'}</Badge>}<span className={ui.faint}>{r.worktree ? `工作区版本${r.commit ? `（基于 ${r.commit.slice(0, 7)}）` : ''}` : `${r.ref ?? ''} ${r.commit?.slice(0, 7) ?? ''}`}</span></div>)}
          {/* Only when a working tree had uncommitted changes (it showed for every working-tree version). */}
          {p.repos.some((r) => r.worktree && r.dirty) && <div className={ui.faint} style={{ fontSize: 12, marginTop: 4 }}>本次审计包含未提交改动，记录会标注为“工作区版本”。</div>}
        </div>
        <div>
          <h4>重点方向</h4>
          <ul className={A.planList}>{pl.focusDirections.map((f, i) => <li key={i}><b>{f.direction}</b><div className={ui.muted}>{f.reason}</div></li>)}</ul>
        </div>
        {pl.plannedKnowledge.length > 0 && <div>
          <h4>计划加载的知识</h4>
          <ul className={A.planList}>{pl.plannedKnowledge.map((k, i) => <li key={i}><span className={ui.mono}>{k.skill}</span> — <span className={ui.muted}>{k.reason}</span></li>)}</ul>
        </div>}
        {pl.contextNeeded.length > 0 && <div>
          <h4>待补充的上下文 <span className={ui.faint} style={{ fontWeight: 400 }}>（可在右侧对话中回答，也可留给 Agent 自行查询）</span></h4>
          <ul className={A.planList}>{pl.contextNeeded.map((c, i) => <li key={i}>{c}</li>)}</ul>
        </div>}
        <div>
          <h4>各阶段模型 <span className={ui.faint} style={{ fontWeight: 400 }}>（启动时冻结）</span></h4>
          <StageModelsSummary s={p.strategy} scene={p.scene} globalFallback={ms.data?.fallbackModel ?? null} />
        </div>
        <div>
          <h4>已知限制</h4>
          <ul className={A.planList}>{pl.limitations.map((l, i) => <li key={i} className={ui.muted}>{l}</li>)}</ul>
        </div>
      </div>
      {awaiting && <EditPlanDialog plan={p} open={edit} onClose={() => setEdit(false)} />}
      <ConfirmDialog open={cancel} onClose={() => setCancel(false)} title="取消审计" confirmText="取消审计" level="destructive"
        onConfirm={async () => { try { await api.post(`/audits/${aid}/cancel`); toast.ok('已取消'); } catch (err) { toast.error(err); } setCancel(false); await qc.invalidateQueries({ queryKey: ['audit', aid] }); }}>
        计划将被丢弃，不会开始审计。
      </ConfirmDialog>
    </div>
  );
}

/**
 * import external scanner results (SARIF 2.1.0 — Semgrep, CodeQL …) before the audit starts; each
 * result becomes an obligation the audit settles (duplicate of a finding, false positive, or a finding of its own).
 */
function SarifImport({ aid }: { aid: string }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const pick = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    try {
      const r = await api.post<{ results: number; added: number; skipped: number }>(`/audits/${aid}/external-results`, { sarif: await file.text() });
      toast.ok(`已导入 ${file.name}：${r.results} 条结果，新增 ${r.added} 条待核对${r.skipped ? `（超出上限未导入 ${r.skipped} 条）` : ''}`);
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <label className={cx(ui.btn, ui.sm)} title="导入 Semgrep、CodeQL 等工具的 SARIF 结果：审计会逐条核对，与自有发现去重" aria-busy={busy}>
      {busy ? '正在导入…' : '导入 SARIF'}
      <input type="file" accept=".sarif,.json,application/json" aria-label="导入 SARIF" style={{ display: 'none' }} onChange={(e) => { void pick(e.target.files?.[0]); e.target.value = ''; }} />
    </label>
  );
}
