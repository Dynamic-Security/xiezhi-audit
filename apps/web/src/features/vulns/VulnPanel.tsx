// Vulnerability detail panel: four layers, review actions with optimistic
// concurrency, revision history, trajectory links. All model text is rendered as plain text.
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { VulnDetailDto, VulnSummaryDto } from '@xiezhi/contracts';
import { api, ApiError, newIdempotencyKey } from '../../shared/api/client';
import { useConnectors, usePushGuides, useRepos, useRevisions, useSource, useVuln, useVulnLinks, useVulnSync } from '../../shared/api/queries';
import { RefPicker, versionLabel } from '../projects/RepoDialogs';
import { CONFIDENCE, CONFIRM, HANDLING, LIFECYCLE, PENDING_KIND, SEVERITY, SEVERITY_ORDER, SOURCE, categoryLabel, fmt, sourceLabel } from '../../shared/format/messages';
import {
  Badge, Button, CodeView, ConfirmBadge, ConfirmDialog, Dialog, ErrorState, Field, HandlingBadge, Icon, LifecycleBadge, Loading, SeverityBadge, Spinner, cx, ui, useDismiss, useToast,
  type IconName,
} from '../../shared/ui';
import V from './vulns.module.css';
import { useAi, useAiScope } from '../assistant/ai';
import { DraftDialog, ImportDialog } from '../knowledge/drafts';
import { ConnectorQueryDialog } from './ConnectorQueryDialog';
import { PushDialog } from './PushDialog';
import { FactEditor } from '../facts/FactsTab';
import { BOUNDARY } from '../services/Trust';
import { FixSection, ProjectRulesSection, VerificationSection } from './Solidify';
import { refreshConversationCards } from './reviewRefresh';

const COND: Record<string, { label: string; tone: 'ok' | 'warn' | 'neutral' }> = {
  confirmed: { label: '已确认', tone: 'ok' }, unconfirmed: { label: '未确认', tone: 'warn' }, unsatisfied: { label: '不满足', tone: 'neutral' },
};

function EvidenceItem({ ev, open, onToggle }: { ev: VulnDetailDto['layers']['evidence'][number]; open: boolean; onToggle: () => void }) {
  // Knowledge and connector evidence are not code locations.
  const external = ev.kind === 'connector' ? '连接器' : ev.kind === 'knowledge' ? '知识' : null;
  const canShow = !external && !!(ev.auditId && ev.repo && ev.path && ev.startLine);
  const from = Math.max(1, (ev.startLine ?? 1) - 6);
  const to = (ev.endLine ?? ev.startLine ?? 1) + 6;
  const src = useSource(ev.auditId ?? '', ev.repo ?? '', ev.path ?? '', from, to, open && canShow);
  return (
    <div className={V.evidence}>
      <button className={V.evidenceHead} onClick={onToggle} disabled={!canShow} aria-expanded={open}>
        <Icon name={open ? 'chevronDown' : 'chevronRight'} size={14} />
        <span className={cx(ui.mono, ui.ellipsis)}>{external ? `${external} ${ev.path?.replace(/^connector:/, '') ?? ''}` : ev.path ? fmt.loc({ repo: ev.repo ?? '', path: ev.path, startLine: ev.startLine ?? 1, endLine: ev.endLine ?? ev.startLine ?? 1 }) : ev.kind}</span>
        {ev.verified ? <Badge tone="ok">{ev.kind === 'connector' ? '权威数据源' : '已核实'}</Badge> : <Badge tone="warn">未核实</Badge>}
      </button>
      {ev.note && <div className={V.evidenceNote}>{ev.note}</div>}
      {open && canShow && (src.isLoading ? <div style={{ padding: 12 }}><Spinner /></div> : src.data ? (
        <CodeView lines={src.data.lines} from={src.data.from} highlight={[ev.startLine!, ev.endLine ?? ev.startLine!]} maxHeight={280}
          title={<>审计快照 <span className={ui.mono}>{src.data.rootHash.slice(0, 10)}</span></>} />
      ) : src.error ? <div className={ui.error} style={{ padding: 8 }}>{(src.error as ApiError).message}</div> : null)}
    </div>
  );
}

/** Review time for G1: from opening a vulnerability's panel to a decision; restarts after each decision. */
export interface ReviewClock { elapsed: () => number; restart: () => void }
export function useReviewClock(key: string | null): ReviewClock {
  const since = useRef(Date.now());
  useEffect(() => { since.current = Date.now(); }, [key]);
  return useMemo(() => ({ elapsed: () => Math.max(0, Math.round(Date.now() - since.current)), restart: () => { since.current = Date.now(); } }), []);
}

function ReviewDialog({ v, mode, onClose, clock }: { v: VulnDetailDto; mode: 'false_positive' | 'severity' | 'handling' | 'confirm' | null; onClose: () => void; clock: ReviewClock }) {
  const [reason, setReason] = useState('');
  const [severity, setSeverity] = useState(v.severity);
  const [handling, setHandling] = useState(v.handlingStatus);
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  if (!mode) return null;
  // confirming without complete evidence is a human override and needs a reason.
  const needReason = mode === 'false_positive' || (mode === 'handling' && handling === 'risk_accepted') || (mode === 'confirm' && !v.evidenceComplete);
  const submit = async () => {
    setBusy(true);
    const patch = mode === 'false_positive' ? { confirmStatus: 'false_positive' } : mode === 'confirm' ? { confirmStatus: 'confirmed' } : mode === 'severity' ? { severity } : { handlingStatus: handling };
    try {
      await api.patch(`/vulnerabilities/${v.id}`, { ...patch, ...(reason.trim() ? { reason: reason.trim() } : {}), reviewMs: clock.elapsed() }, { ifMatch: v.revision });
      clock.restart();
      toast.ok('已保存');
      onClose();
    } catch (e) {
      toast.error(e, '保存失败');
      if (e instanceof ApiError && e.code === 'COMMON_REVISION_CONFLICT') onClose();
    } finally {
      setBusy(false);
      await qc.invalidateQueries({ queryKey: ['vuln', v.id] });
      await qc.invalidateQueries({ queryKey: ['vulns'] });
      await refreshConversationCards(qc);
    }
  };
  const title = { false_positive: '标记为误报', severity: '调整严重度', handling: '设置处理状态', confirm: '确认漏洞' }[mode];
  const bigChange = mode === 'severity' && SEVERITY_ORDER.indexOf(severity as never) > SEVERITY_ORDER.indexOf(v.severity as never) && (v.severity === 'critical' || v.severity === 'high');
  return (
    <Dialog open onClose={onClose} title={`${title} · V-${v.displayNo}`} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant={mode === 'false_positive' ? 'dangerSolid' : 'primary'} loading={busy} disabled={needReason && !reason.trim()} onClick={() => void submit()}>保存</Button>
    </>}>
      {mode === 'confirm' && (v.evidenceComplete
        ? <p className={ui.muted}>证据完整：危险点已核实、入口已知、调用链逐段核实且没有缺失的上下文。确认后会记入修订历史（来源：人工）。</p>
        : <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)', display: 'block' }}>证据不完整（例如对抗复核提出了反驳、或链路未逐段核实）。你仍可以确认，但需要写明依据；修订历史会记为“证据不完整，人工确认”。</div>)}
      {mode === 'severity' && (
        <Field label="严重度" hint={`原值会被保留：${SEVERITY[v.severityOriginal ?? v.severity]}`}>
          <select className={ui.select} value={severity} onChange={(e) => setSeverity(e.target.value as never)}>
            {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{SEVERITY[s]}</option>)}
          </select>
        </Field>
      )}
      {mode === 'handling' && (
        <Field label="处理状态">
          <select className={ui.select} value={handling} onChange={(e) => setHandling(e.target.value as never)}>
            {Object.entries(HANDLING).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </Field>
      )}
      <Field label={needReason ? '原因（必填）' : '原因（可选）'} hint={mode === 'false_positive' ? '说明为什么不成立，便于日后追溯' : mode === 'confirm' && !v.evidenceComplete ? '说明为什么成立（读过的代码、复现结果、对反驳的回应等）' : undefined}>
        <textarea className={ui.textarea} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
      </Field>
      {bigChange && <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)' }}><Icon name="alert" />高危漏洞降级属于重大改动。保存后建议点“复验”，让 Agent 沿原链路确认。</div>}
    </Dialog>
  );
}

/** Pending "suspected same" links: show why the model linked them; a human decides. */
function SuspectedMatches({ v }: { v: VulnDetailDto }) {
  const [pending, setPending] = useState<{ occurrenceId: string; decision: 'confirm' | 'separate' } | null>(null);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  if (!v.suspectedMatches.length) return null;
  const decide = async () => {
    if (!pending) return;
    setBusy(true);
    try {
      const r = await api.post<{ created: { id: string; displayNo: number } | null }>(`/vulnerabilities/${v.id}/match-decision`, { ...pending, ...(reason.trim() ? { reason: reason.trim() } : {}) }, { ifMatch: v.revision });
      toast.ok(r.created ? `已拆开为新漏洞 V-${r.created.displayNo}` : '已确认为同一漏洞');
      setPending(null);
      setReason('');
    } catch (e) {
      toast.error(e, '操作失败');
    } finally {
      setBusy(false);
      await qc.invalidateQueries({ queryKey: ['vuln'] });
      await qc.invalidateQueries({ queryKey: ['vulns'] });
    }
  };
  return (
    <section className={V.suspected} aria-label="疑似同一">
      <div className={ui.row}><Icon name="help" size={14} /><b>疑似同一，待你确认</b></div>
      <p className={ui.muted} style={{ fontSize: 12, margin: '4px 0 8px' }}>危险点函数无法直接对应（例如被重构、拆分），归并模型判断根因一致后关联到这里。确认前只记为“仍存在”，不会判为回归。</p>
      {v.suspectedMatches.map((m) => (
        <div key={m.occurrenceId} className={V.suspectedItem}>
          <div className={cx(ui.row, ui.wrap)}>
            <span>{m.auditTitle}</span>{m.findingNo !== null && <Badge>F-{m.findingNo}</Badge>}
            <span className={cx(ui.mono, ui.ellipsis)}>{fmt.loc(m.location)}</span>
          </div>
          <div className={ui.muted} style={{ fontSize: 12 }}>危险点 <span className={ui.mono}>{m.sinkSymbol ?? '—'}</span>；当前漏洞 <span className={ui.mono}>{v.sinkSymbol ?? '—'}</span></div>
          <div style={{ fontSize: 13 }}>匹配依据：{m.reason}</div>
          <div className={ui.row} style={{ marginTop: 6 }}>
            <Button size="sm" variant="primary" icon="check" onClick={() => setPending({ occurrenceId: m.occurrenceId, decision: 'confirm' })}>确认是同一漏洞</Button>
            <Button size="sm" onClick={() => setPending({ occurrenceId: m.occurrenceId, decision: 'separate' })}>拆开为新漏洞</Button>
          </div>
        </div>
      ))}
      <Dialog open={!!pending} onClose={() => setPending(null)} title={pending?.decision === 'confirm' ? `确认是同一漏洞 · V-${v.displayNo}` : `拆开为新漏洞 · V-${v.displayNo}`}
        footer={<><Button onClick={() => setPending(null)}>取消</Button><Button variant="primary" loading={busy} onClick={() => void decide()}>确定</Button></>}>
        <p className={ui.muted}>{pending?.decision === 'confirm'
          ? '该发现的危险点指纹和入口会并入本漏洞，之后的审计可以直接匹配；如果本漏洞曾“已修复（经验证）”，会记为回归。'
          : '该发现会成为一个新漏洞（新编号），本漏洞因这次关联产生的状态变化会撤回。'}</p>
        <Field label="原因（可选）"><textarea className={ui.textarea} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} /></Field>
      </Dialog>
    </section>
  );
}

/** Start a reverification: default version or a chosen ref (e.g. the fix branch). */
export function ReverifyDialog({ vulns, projectId, repoName, open, onClose, pending }: { vulns: { id: string; displayNo: number }[]; projectId: string; repoName: string; open: boolean; onClose: () => void; pending?: boolean }) {
  const [note, setNote] = useState('');
  const repos = useRepos(projectId);
  const repo = repos.data?.find((r) => r.name === repoName);
  const [ref, setRef] = useState<string | null | undefined>(undefined);
  const [pick, setPick] = useState(false);
  const [busy, setBusy] = useState(false);
  const [key] = useState(newIdempotencyKey);
  const navigate = useNavigate();
  const toast = useToast();
  const start = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ auditId: string }>('/reverifications', {
        vulnIds: vulns.map((v) => v.id), ...(repo && ref !== undefined && ref !== null ? { refs: { [repo.id]: ref } } : {}), ...(note.trim() ? { note: note.trim() } : {}),
      }, { idempotencyKey: key });
      toast.ok('已开始复验');
      onClose();
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) { toast.error(e, '无法开始复验'); }
    setBusy(false);
  };
  return (
    <Dialog open={open} onClose={onClose} title={vulns.length === 1 ? `复验 V-${vulns[0]!.displayNo}` : `复验 ${vulns.length} 条漏洞`}
      footer={<><Button onClick={onClose}>取消</Button><Button variant="primary" icon="play" loading={busy} onClick={() => void start()}>开始复验</Button></>}>
      <p className={ui.muted}>Agent 会沿每个漏洞的原链路在指定版本上定向验证，给出“已修复（经验证）/ 仍存在 / 修复不完整 / 待确认”，结论写回跨审计状态与修订历史。处理状态只会给出建议。</p>
      <Field group label="代码版本" hint="默认使用仓库的默认审计版本；也可以选修复分支或提交">
        <div className={ui.row}>
          <span className={ui.chip} style={{ cursor: 'default' }}><Icon name="git" size={12} />{!repo ? '默认版本' : ref === undefined ? `${versionLabel(repo, repo.defaultRef)}（默认）` : versionLabel(repo, ref)}</span>
          {repo && repo.sourceKind !== 'archive' && <Button size="sm" variant="ghost" onClick={() => setPick(!pick)}>{pick ? '收起' : '更改'}</Button>}
        </div>
        {pick && repo && <div style={{ marginTop: 8 }}><RefPicker repoId={repo.id} sourceKind={repo.sourceKind} value={ref ?? repo.defaultRef} onPick={(r) => { setRef(r); setPick(false); }} /></div>}
      </Field>
      {pending && (
        <Field label="补充信息（可选）" hint="回答待确认条件中的问题，例如业务规则、网关或部署策略；定向复验会把它作为你提供的依据">
          <textarea aria-label="补充信息" className={ui.input} rows={3} value={note} onChange={(e) => setNote(e.target.value)} placeholder="例如：订单只允许下单用户本人读取，owner 与 sku 属于用户隐私数据" />
        </Field>
      )}
    </Dialog>
  );
}

/** Proposed revisions (e.g. from a reverification): a human applies them. */
function Proposals({ v, clock }: { v: VulnDetailDto; clock: ReviewClock }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [busy, setBusy] = useState<string | null>(null);
  const proposals = v.proposals.filter((p) => ['handling', 'confirm', 'severity'].includes(p.dimension));
  if (!proposals.length) return null;
  const apply = async (p: VulnDetailDto['proposals'][number]) => {
    setBusy(p.revisionId);
    try {
      const field = p.dimension === 'confirm' ? { confirmStatus: p.to } : p.dimension === 'severity' ? { severity: p.to } : { handlingStatus: p.to };
      await api.patch(`/vulnerabilities/${v.id}`, { ...field, reason: `采纳建议：${p.reason ?? ''}`.slice(0, 2000), reviewMs: clock.elapsed() }, { ifMatch: v.revision });
      clock.restart();
      toast.ok('已采纳建议');
    } catch (e) { toast.error(e); }
    setBusy(null);
    await qc.invalidateQueries({ queryKey: ['vuln', v.id] });
    await qc.invalidateQueries({ queryKey: ['vulns'] });
    await refreshConversationCards(qc);
  };
  return (
    <div className={V.proposal}>
      {proposals.map((p) => (
        <div key={p.revisionId} className={ui.row}>
          <Icon name="sparkle" size={14} />
          <div className={ui.grow}><b>建议修订：</b>{p.dimension === 'confirm' ? `确认状态改为「${CONFIRM[String(p.to)] ?? String(p.to)}」` : p.dimension === 'severity' ? `严重度改为「${SEVERITY[String(p.to)] ?? String(p.to)}」` : `处理状态改为「${HANDLING[String(p.to)] ?? String(p.to)}」`}<span className={ui.muted}>（{p.reason}）</span></div>
          <Button size="sm" variant="primary" loading={busy === p.revisionId} onClick={() => void apply(p)}>采纳</Button>
        </div>
      ))}
    </div>
  );
}

const RISK_STATUS: Record<string, string> = { accepted: '接受风险', false_positive: '误报 / 不适用', mitigated: '已规避' };
/** the status was set by rule from a requirement risk's human decision — name that source. */
export function riskDecisionSource(v: VulnSummaryDto): string | null {
  const r = v.threatRisk;
  if (!r) return null;
  if (v.confirmStatus === 'false_positive' && (r.status === 'false_positive' || r.status === 'mitigated')) return `误报来源：需求风险 ${r.code}（${RISK_STATUS[r.status]}）`;
  if (v.handlingStatus === 'risk_accepted' && r.status === 'accepted') return `接受来源：需求风险 ${r.code}（接受风险）`;
  return null;
}
const MISSING_KIND: Record<string, string> = { repo: '仓库', gateway_policy: '网关策略', config: '配置', business_rule: '业务规则', external_service: '外部服务' };

export function VulnPanelTitle({ vid }: { vid: string }) {
  const v = useVuln(vid);
  return v.data ? <div className={ui.row}><b>V-{v.data.displayNo}</b><SeverityBadge severity={v.data.severity} original={v.data.severityOriginal} /></div> : <span className={ui.faint}>漏洞详情</span>;
}

/** Actions that are not the everyday review (primary actions stay visible, the rest go in “更多”). */
function MoreActions({ items }: { items: { label: string; icon?: IconName; disabled?: boolean; title?: string; onClick: () => void }[] }) {
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  return (
    <div style={{ position: 'relative' }} ref={ref}>
      <Button size="sm" icon="more" aria-expanded={open} onClick={() => setOpen(!open)}>更多</Button>
      {open && (
        <div className={ui.menu} style={{ left: 0, top: 32 }} role="menu">
          {items.map((it) => (
            <button key={it.label} role="menuitem" className={ui.menuItem} disabled={it.disabled} title={it.title} onClick={() => { setOpen(false); it.onClick(); }}>
              {it.icon ? <Icon name={it.icon} size={14} /> : <span style={{ width: 14 }} />}{it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** `scoped`: the panel is the object in view, so the AI panel talks about it (off when shown inside the AI panel). */
export function VulnPanel({ vid, scoped = true }: { vid: string; scoped?: boolean }) {
  const q = useVuln(vid);
  const ai = useAi();
  // “追问” continues this vulnerability's conversation in the AI panel.
  useAiScope(scoped && q.data ? { kind: 'vuln', id: vid, label: `V-${q.data.displayNo} ${q.data.title}` } : null);
  const revisions = useRevisions(vid);
  const links = useVulnLinks(vid);
  const [openEv, setOpenEv] = useState<number | null>(0);
  const [mode, setMode] = useState<'false_positive' | 'severity' | 'handling' | 'confirm' | null>(null);
  const [showRev, setShowRev] = useState(false);
  const [reverify, setReverify] = useState(false);
  const navigate = useNavigate();
  const [split, setSplit] = useState(false);
  const [undo, setUndo] = useState<string | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const [draft, setDraft] = useState<string | null>(null);
  const [supplement, setSupplement] = useState(false);
  const [querying, setQuerying] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [distilling, setDistilling] = useState(false);
  // a review ruling (e.g. what the gateway really checks) saved as an enterprise fact.
  const [asFact, setAsFact] = useState(false);
  const clock = useReviewClock(vid);
  if (q.isLoading) return <Loading rows={8} />;
  if (q.error || !q.data) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const v = q.data;
  const distill = async () => {
    setDistilling(true);
    try {
      const d = await api.post<{ id: string }>(`/vulnerabilities/${v.id}/distill-case`, { layer: 'project' });
      setDraft(d.id);
    } catch (e) { toast.error(e); } finally { setDistilling(false); }
  };
  const supplementPreset = {
    category: 'architecture', label: `V-${v.displayNo} 待确认条件的补充信息`,
    text: `补充 V-${v.displayNo}「${v.title}」待确认条件所需的信息（系统架构 / 业务规则）：\n\n${(v.pendingCondition?.holdsIf ?? []).map((c) => `- 是否：${c.statement}`).join('\n')}\n\n在这里写明实际情况与依据（配置位置、文档、负责人确认等）：\n`,
  };
  return (
    <div className={V.panel}>
      <h2 className={V.title}>{v.title}</h2>
      <div className={cx(ui.row, ui.wrap)}>
        <ConfirmBadge status={v.confirmStatus} />
        <HandlingBadge status={v.handlingStatus} />
        <LifecycleBadge status={v.lifecycle} />
        {riskDecisionSource(v) && <Badge tone="info" title={`需求威胁模型「${v.threatRisk!.title}」的人工研判，由规则自动标注；可以改回`}>{riskDecisionSource(v)}</Badge>}
        <Badge>置信度 {CONFIDENCE[v.confidence]}</Badge>
        {v.confirmStatus === 'confirmed' && v.confirmOverride && <Badge tone="warn">人工确认（证据不完整）</Badge>}
        <Badge>来源 {v.sources.map((x) => SOURCE[x] ?? x).join('·') || '—'}</Badge>
        {v.suspectedLink && <Badge tone="warn">疑似同一</Badge>}
        {v.reverifySuggested && <Badge tone="accent">建议复验</Badge>}
      </div>
      {v.status === 'merged' && (
        <div className={V.proposal}>已合并到 {v.mergedIntoId ? <Link to="." search={(prev: Record<string, unknown>) => ({ ...prev, panel: `vuln:${v.mergedIntoId}` })}>V-{v.mergedIntoNo}</Link> : '其他漏洞'}；之后的审计会记在该漏洞上。</div>
      )}
      {v.mergedFrom.length > 0 && <div className={ui.faint} style={{ fontSize: 12, marginTop: 8 }}>由 {v.mergedFrom.map((m) => `V-${m.displayNo}`).join('、')} 合并而来</div>}
      <SuspectedMatches v={v} />
      <Proposals v={v} clock={clock} />
      {v.confirmStatus === 'pending' && v.pendingKind && (
        <div className={V.pending}>
          <b>{PENDING_KIND[v.pendingKind]}</b>
          {v.pendingCondition ? (
            <>
              <span> — 缺少：{v.pendingCondition.missing.map((m) => `${MISSING_KIND[m.kind] ?? m.kind} ${m.ref}${m.hint ? `（${m.hint}）` : ''}`).join('；')}</span>
              <ul style={{ margin: '6px 0 0', paddingLeft: 18, fontSize: 13 }}>
                {v.pendingCondition.holdsIf.map((c, i) => <li key={`h${i}`}>如果{c.statement} → 漏洞成立（严重度：{SEVERITY[v.pendingCondition!.severityIfHolds] ?? v.pendingCondition!.severityIfHolds}）</li>)}
                {v.pendingCondition.refutedIf.map((c, i) => <li key={`r${i}`}>如果{c.statement} → 漏洞不成立</li>)}
              </ul>
              <div className={cx(ui.row, ui.wrap)} style={{ gap: 6, marginTop: 8 }}>
                {v.pendingCondition.suggestedActions.includes('add_repo') && (
                  <Button size="sm" icon="plus" onClick={() => void navigate({ to: '/projects/$pid', params: { pid: v.projectId }, search: { tab: 'repos', addRepo: 1 } })}>添加仓库</Button>
                )}
                <Button size="sm" icon="book" onClick={() => setSupplement(true)}>补充知识</Button>
                <Button size="sm" icon="link" onClick={() => setQuerying(true)}>通过连接器查询</Button>
                <Button size="sm" icon="database" title="把你确认的实际情况（如网关是否鉴权）存为项目的企业事实，以后的审计直接引用" onClick={() => setAsFact(true)}>存为企业事实</Button>
                <Button size="sm" variant="primary" icon="play" onClick={() => setReverify(true)}>定向复验</Button>
              </div>
              <div className={ui.faint} style={{ fontSize: 12, marginTop: 6 }}>补充信息（添加仓库、回答问题）后，定向复验只沿上述条件所指的链路检查，结论作为建议写入修订历史，由你采纳。</div>
            </>
          ) : <> — 证据尚未完整：可以复验，或写明原因后人工确认</>}
        </div>
      )}
      <PushPrompt v={v} onPush={() => setPushing(true)} />
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
        <Button size="sm" variant="primary" icon="check" disabled={v.confirmStatus === 'confirmed'} title={!v.evidenceComplete && v.confirmStatus !== 'confirmed' ? '证据不完整：确认时需要写明原因' : undefined} onClick={() => setMode('confirm')}>确认</Button>
        <Button size="sm" variant="danger" disabled={v.confirmStatus === 'false_positive'} onClick={() => setMode('false_positive')}>误报</Button>
        <Button size="sm" icon="play" onClick={() => setReverify(true)}>复验</Button>
        {scoped && <Button size="sm" icon="sparkle" title="在右侧 AI 面板里继续调查这个漏洞（基于审计时的代码）" onClick={() => ai.ask()}>追问</Button>}
        <MoreActions items={[
          { label: '调整严重度', icon: 'alert', onClick: () => setMode('severity') },
          { label: '处理状态', icon: 'check', onClick: () => setMode('handling') },
          { label: '拆分', icon: 'layers', disabled: v.status !== 'active', onClick: () => setSplit(true) },
          { label: distilling ? '正在整理…' : '沉淀为案例', icon: 'book', disabled: distilling, title: 'AI 按案例模板整理成项目案例库的草稿，审核后启用', onClick: () => void distill() },
          { label: '推送到…', icon: 'send', title: '按知识库中的推送指引，通过连接器写入工单等外部系统', onClick: () => setPushing(true) },
          { label: '复核裁定存为事实', icon: 'database', title: '把复核中确认的企业环境事实存入项目的企业事实', onClick: () => setAsFact(true) },
        ]} />
      </div>
      <DraftDialog id={draft} onClose={() => setDraft(null)} />
      {asFact && <FactEditor pid={v.projectId} review={v.id} onClose={() => setAsFact(false)} initial={{
        topic: v.pendingCondition?.missing.some((m) => m.kind === 'gateway_policy') ? 'gateway' : v.pendingCondition?.missing.some((m) => m.kind === 'business_rule') ? 'business_rule' : 'other',
        statement: v.pendingCondition ? `（V-${v.displayNo} 复核确认）${v.pendingCondition.missing.map((m) => m.ref).join('；')}：` : `（V-${v.displayNo} 复核确认）`,
      }} />}
      <ConnectorQueryDialog open={querying} onClose={() => setQuerying(false)} projectId={v.projectId} onDraft={(id) => setDraft(id)}
        context={`V-${v.displayNo}「${v.title}」：${(v.pendingCondition?.holdsIf ?? []).map((c) => c.statement).join('；') || v.title}`} />
      <PushDialog open={pushing} onClose={() => setPushing(false)} projectId={v.projectId} vulns={[{ id: v.id, displayNo: v.displayNo }]} />
      <ImportDialog open={supplement} onClose={() => setSupplement(false)} pid={v.projectId} preset={supplementPreset} onCreated={(id) => setDraft(id)} />
      {reverify && <ReverifyDialog vulns={[{ id: v.id, displayNo: v.displayNo }]} projectId={v.projectId} repoName={v.repo} open onClose={() => setReverify(false)} pending={v.confirmStatus === 'pending'} />}
      <dl className={ui.kv}>
        <dt>类别</dt><dd>{categoryLabel(v.category)}{v.cwe ? ` · ${v.cwe}` : ''}</dd>
        {v.boundary && v.boundary !== 'own' && <><dt>责任归属</dt><dd>{BOUNDARY[v.boundary] ?? v.boundary}</dd></>}
        <dt>仓库</dt><dd>{v.repo}{v.module ? ` · ${v.module}` : ''}</dd>
        {v.sinkSymbol && <><dt>危险点</dt><dd className={ui.mono}>{v.sinkSymbol}{v.sinkApi ? ` → ${v.sinkApi}` : ''}</dd></>}
        {v.rootCause && <><dt>根因</dt><dd>{v.rootCause}</dd></>}
        <dt>受影响入口</dt><dd>{v.entries.length ? v.entries.map((e) => <div key={e.key} className={ui.mono}>{fmt.entry(e.key)}</div>) : '—'}</dd>
        {v.handlingReason && <><dt>处理说明</dt><dd>{v.handlingReason}</dd></>}
        <SyncRows vid={v.id} />
      </dl>

      <section className={V.layer}>
        <h3 className={V.layerTitle}><span className={V.num}>1</span>证据</h3>
        {v.layers.evidence.length === 0 && <p className={ui.faint}>无</p>}
        {v.layers.evidence.map((ev, i) => <EvidenceItem key={i} ev={ev} open={openEv === i} onToggle={() => setOpenEv(openEv === i ? null : i)} />)}
      </section>
      <section className={V.layer}>
        <h3 className={V.layerTitle}><span className={V.num}>2</span>推理与链路</h3>
        {v.layers.reasoning.chain.length > 0 && (
          <ol className={V.chain}>
            {v.layers.reasoning.chain.map((c, i) => <li key={i}><span className={ui.mono}>{fmt.loc(c)}</span>{c.note && <div className={ui.muted}>{c.note}</div>}</li>)}
          </ol>
        )}
        <p className={ui.pre}>{v.layers.reasoning.reasoning}</p>
        {v.layers.reasoning.counterCheck && <p className={ui.pre} style={{ marginTop: 8 }}><b>反证检查：</b>{v.layers.reasoning.counterCheck}</p>}
        {v.layers.reasoning.consensus && (
          <div className={V.challenge} aria-label="交叉审查">
            <b>交叉审查：</b>{v.layers.reasoning.consensus.support.length}/{v.layers.reasoning.consensus.models.length} 个模型认同
            <span className={ui.faint}>（{v.layers.reasoning.consensus.models.map((m) => `${m}${v.layers.reasoning.consensus!.support.includes(m) ? ' ✓' : ''}`).join('、')}）</span>
            {v.layers.reasoning.consensus.unavailable.length > 0 && <div className={ui.faint}>交叉审查降级：{v.layers.reasoning.consensus.unavailable.join('、')} 未能运行，不计入</div>}
            {v.layers.reasoning.consensus.conflicts.map((c, i) => (
              <div key={i} className={ui.pre}>{c.model} {c.verdict === 'ruled_out' ? '排除' : '认为无问题'}：{c.reason}</div>
            ))}
          </div>
        )}
        {v.layers.reasoning.challenge && (
          <div className={V.challenge}>
            <b>对抗复核：</b>{v.layers.reasoning.challenge.verdict === 'pending' ? '转为待确认' : v.layers.reasoning.challenge.verdict === 'refuted' ? '反驳（转为待确认，由人裁决）' : '维持'}（置信度 {v.layers.reasoning.challenge.confidenceDelta >= 0 ? '+' : ''}{v.layers.reasoning.challenge.confidenceDelta}）
            <div className={ui.pre}>{v.layers.reasoning.challenge.reason}</div>
            {v.layers.reasoning.challenge.against && <div className={ui.faint} style={{ fontSize: 12, marginTop: 4 }}>反方：<span className={ui.pre}>{v.layers.reasoning.challenge.against}</span></div>}
            {v.layers.reasoning.challenge.affirm && <div className={ui.faint} style={{ fontSize: 12, marginTop: 4 }}>正方：<span className={ui.pre}>{v.layers.reasoning.challenge.affirm}</span></div>}
          </div>
        )}
      </section>
      <section className={V.layer}>
        <h3 className={V.layerTitle}><span className={V.num}>3</span>利用条件</h3>
        {v.layers.attack && (
          <div style={{ marginBottom: 8 }}>
            <div><b>攻击路径：</b><span className={ui.pre}>{v.layers.attack.path}</span></div>
            {v.layers.attack.impact && <div style={{ marginTop: 4 }}><b>影响：</b>{v.layers.attack.impact}</div>}
          </div>
        )}
        {v.layers.exploit.length === 0 ? <p className={ui.faint}>未列出</p> : (
          <ul className={V.conds}>
            {v.layers.exploit.map((c, i) => (
              <li key={i}><Badge tone={COND[c.status]?.tone ?? 'neutral'}>{COND[c.status]?.label ?? c.status}</Badge> <span>{c.condition}</span><div className={ui.faint} style={{ fontSize: 12 }}>来源：{sourceLabel(c.source)}</div></li>
            ))}
          </ul>
        )}
      </section>
      <section className={V.layer}>
        <h3 className={V.layerTitle}><span className={V.num}>4</span>修复建议 <Badge tone="info">AI 生成</Badge></h3>
        <p className={ui.pre}>{v.layers.fix.approach}</p>
        {v.layers.fix.suggestion && <pre className={ui.code} style={{ padding: 12, whiteSpace: 'pre-wrap' }}>{v.layers.fix.suggestion}</pre>}
        {v.layers.fix.verification && <p className={ui.muted} style={{ marginTop: 8 }}>验证方式：{v.layers.fix.verification}</p>}
      </section>
      <VerificationSection v={v} />
      <FixSection v={v} />
      <ProjectRulesSection v={v} />

      <section className={V.layer}>
        <h3 className={V.layerTitle}>来源轨迹</h3>
        {links.data?.map((l) => (
          <Link key={l.findingId} to="/audits/$aid" params={{ aid: l.auditId }} search={{ tab: 'trajectory', step: l.stepId }} className={V.linkRow}>
            <Icon name="activity" size={14} /> {l.auditTitle}{l.findingNo ? ` · F-${l.findingNo}` : ''} <Icon name="chevronRight" size={14} />
          </Link>
        ))}
      </section>
      <section className={V.layer}>
        <button className={V.layerTitle} style={{ border: 'none', background: 'none', padding: 0, cursor: 'pointer' }} onClick={() => setShowRev(!showRev)}>
          <Icon name={showRev ? 'chevronDown' : 'chevronRight'} size={14} /> 修订历史（{revisions.data?.length ?? 0}）
        </button>
        {showRev && (
          <ul className={V.revs}>
            {revisions.data?.map((r) => (
              <li key={r.id}>
                <div className={ui.row}><Badge tone={r.source === 'human' ? 'accent' : r.source === 'ai' ? 'info' : 'neutral'}>{SOURCE[r.source]}</Badge>
                  {r.dimension === 'identity' ? <span className={ui.grow}>身份：{r.reason}</span> : (
                    <span className={ui.grow}>{({ confirm: '确认状态', handling: '处理状态', lifecycle: '跨审计状态', severity: '严重度', identity: '身份', entries: '入口' } as Record<string, string>)[r.dimension] ?? r.dimension}：
                      {labelOf(r.dimension, r.from)} → <b>{labelOf(r.dimension, r.to)}</b></span>
                  )}
                  {r.state !== 'applied' && <Badge tone="neutral">{r.state === 'proposed' ? '建议' : '已拒绝'}</Badge>}
                  {r.undoable && <Button size="sm" variant="ghost" onClick={() => setUndo(r.id)}>撤销</Button>}
                </div>
                <div className={ui.faint} style={{ fontSize: 12 }}>{fmt.date(r.createdAt)} · {r.actor}{r.dimension !== 'identity' && r.reason ? ` · ${r.reason}` : ''}
                  {r.reviewMs !== null && ` · 复核用时 ${r.reviewBatch ? `约 ${fmt.duration(r.reviewMs)}（批量 ${r.reviewBatch} 条平分）` : fmt.duration(r.reviewMs)}`}</div>
              </li>
            ))}
          </ul>
        )}
      </section>
      <ReviewDialog v={v} mode={mode} onClose={() => setMode(null)} clock={clock} />
      {split && <SplitDialog v={v} onClose={() => setSplit(false)} />}
      <ConfirmDialog open={!!undo} onClose={() => setUndo(null)} title="撤销这次身份变更" confirmText="撤销"
        onConfirm={async () => {
          try { await api.post(`/vulnerabilities/${v.id}/identity-undo`, { revisionId: undo }, { ifMatch: v.revision }); toast.ok('已撤销'); } catch (e) { toast.error(e); }
          setUndo(null);
          await qc.invalidateQueries({ queryKey: ['vuln'] });
          await qc.invalidateQueries({ queryKey: ['vulns'] });
        }}>
        合并会拆回原来的两个漏洞，拆分会把拆出的漏洞并回。之后的审计按撤销后的结果继续追踪。
      </ConfirmDialog>
    </div>
  );
}

/** Split: move chosen entries and/or fingerprints to a new vulnerability. */
function SplitDialog({ v, onClose }: { v: VulnDetailDto; onClose: () => void }) {
  const [entries, setEntries] = useState<string[]>([]);
  const [fps, setFps] = useState<string[]>([]);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const active = v.fingerprints.filter((f) => f.active);
  const toggle = (xs: string[], x: string) => (xs.includes(x) ? xs.filter((y) => y !== x) : [...xs, x]);
  const submit = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ created: { displayNo: number } }>(`/vulnerabilities/${v.id}/split`, { entryKeys: entries, fingerprints: fps, reason: reason.trim() }, { ifMatch: v.revision });
      toast.ok(`已拆出 V-${r.created.displayNo}`);
      onClose();
    } catch (e) { toast.error(e, '拆分失败'); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['vuln'] });
    await qc.invalidateQueries({ queryKey: ['vulns'] });
  };
  return (
    <Dialog open onClose={onClose} title={`拆分 V-${v.displayNo}`} footer={<><Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!reason.trim() || (!entries.length && !fps.length)} onClick={() => void submit()}>拆分</Button></>}>
      <p className={ui.muted}>选中的入口和危险点指纹会移到一个新漏洞。只移入口时，两者共用同一危险点，之后的审计按入口归属；落在未归属入口上的发现会标为“疑似同一”交给你判断。</p>
      <Field group label="受影响入口">
        <div className={ui.stack} style={{ gap: 4 }}>{v.entries.map((e) => (
          <label key={e.key} className={ui.checkbox}><input type="checkbox" checked={entries.includes(e.key)} onChange={() => setEntries(toggle(entries, e.key))} /><span className={ui.mono}>{fmt.entry(e.key)}</span></label>
        ))}</div>
      </Field>
      {active.length > 1 && (
        <Field group label="危险点指纹" hint="合并过的漏洞会有多个指纹，每个对应一个危险点">
          <div className={ui.stack} style={{ gap: 4 }}>{active.map((f) => (
            <label key={f.fp} className={ui.checkbox}><input type="checkbox" checked={fps.includes(f.fp)} onChange={() => setFps(toggle(fps, f.fp))} /><span className={ui.mono}>{f.fp.slice(0, 16)}…</span><Badge>{FP_KIND[f.kind] ?? f.kind}</Badge></label>
          ))}</div>
        </Field>
      )}
      <Field label="原因（必填）"><textarea className={ui.textarea} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} /></Field>
    </Dialog>
  );
}

const FP_KIND: Record<string, string> = { anchor: '首次', rename: '重命名跟随', merged: '合并而来', manual: '人工' };

function labelOf(dim: string, v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (Array.isArray(v)) return `${v.length} 项`;
  const s = String(v);
  const map = dim === 'confirm' ? CONFIRM : dim === 'handling' ? HANDLING : dim === 'lifecycle' ? LIFECYCLE : dim === 'severity' ? SEVERITY : {};
  return map[s] ?? s;
}

/**
 * After a risk is confirmed or accepted: offer the push guides that can write now, or a re-push when
 * the vulnerability was pushed before and its state changed since. Nothing is written until the user pushes.
 */
function PushPrompt({ v, onPush }: { v: VulnDetailDto; onPush: () => void }) {
  const guides = usePushGuides(v.projectId);
  const sync = useVulnSync(v.id);
  const ready = (guides.data ?? []).filter((g) => g.available);
  const settled = v.confirmStatus === 'confirmed' || v.confirmStatus === 'false_positive' || ['risk_accepted', 'fixed'].includes(v.handlingStatus);
  if (!settled || !ready.length || !sync.data) return null;
  const pushed = sync.data.length > 0;
  const where = [...new Set(ready.map((g) => g.connector))].join('、');
  return (
    <div className={ui.banner} style={{ background: 'var(--accent-soft)', color: 'var(--accent-text)' }} role="note" aria-label="推送提示">
      <Icon name="send" />
      <span className={ui.grow}>{pushed ? `已推送到 ${sync.data.map((r) => `${r.connectorName} ${r.externalId}`).join('、')}；状态有变化时可以再次推送（追加评论、更新字段、流转状态）` : `${v.confirmStatus === 'confirmed' ? '已确认' : '已有结论'}，可以推送到 ${where}`}</span>
      <Button size="sm" variant="primary" icon="send" onClick={onPush}>{pushed ? '再次推送' : `推送到 ${where}`}</Button>
    </div>
  );
}

/** External records this vulnerability was pushed to (sync_record); an existing record can be linked by hand. */
function SyncRows({ vid }: { vid: string }) {
  const q = useVulnSync(vid);
  const connectors = useConnectors();
  const qc = useQueryClient();
  const toast = useToast();
  const [linking, setLinking] = useState(false);
  const [cid, setCid] = useState('');
  const [ext, setExt] = useState('');
  const [url, setUrl] = useState('');
  // a connector can take a write when one of its tools is not read-only.
  const writable = (connectors.data ?? []).filter((c) => c.tools.some((t) => t.readOnlyHint !== true));
  if (!q.data) return null;
  const save = async () => {
    try {
      await api.put(`/vulnerabilities/${vid}/sync`, { connectorId: cid || writable[0]!.id, externalId: ext, ...(url.trim() ? { externalUrl: url.trim() } : {}) });
      toast.ok('已关联，之后推送会更新这条记录');
      setLinking(false); setExt(''); setUrl('');
    } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['vuln', vid, 'sync'] });
  };
  if (!q.data.length && !writable.length) return null;
  return (
    <><dt>外部记录</dt><dd>
      {q.data.map((r) => (
        <div key={r.connectorId}>{r.connectorName} · {r.externalUrl ? <a href={r.externalUrl} target="_blank" rel="noreferrer noopener">{r.externalId}</a> : r.externalId}</div>
      ))}
      {writable.length > 0 && !linking && <button style={{ border: 'none', background: 'none', padding: 0, color: 'var(--accent-text)', fontSize: 12, cursor: 'pointer' }} onClick={() => setLinking(true)}>关联已有外部记录</button>}
      {linking && (
        <div className={ui.stack} style={{ gap: 6, marginTop: 4 }} aria-label="关联已有外部记录">
          <select aria-label="连接器" className={ui.select} value={cid || writable[0]?.id || ''} onChange={(e) => setCid(e.target.value)}>
            {writable.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <input aria-label="外部 ID" className={ui.input} placeholder="外部系统中的 ID，例如工作项 ID" value={ext} onChange={(e) => setExt(e.target.value)} />
          <input aria-label="链接（可选）" className={ui.input} placeholder="https://…（可选）" value={url} onChange={(e) => setUrl(e.target.value)} />
          <div className={ui.row} style={{ gap: 6 }}>
            <Button size="sm" variant="primary" disabled={!ext.trim()} onClick={() => void save()}>关联</Button>
            <Button size="sm" onClick={() => setLinking(false)}>取消</Button>
          </div>
        </div>
      )}
    </dd></>
  );
}
