// Project vulnerability list: URL-bound filters and sort (incl. confidence), batch review
// (handling status, confirm, false positive with one shared reason; skipped items listed with reasons),
// batch reverify / merge / push / export. Batch decisions carry the batch's review time (G1).
import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { VulnSummaryDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { useVulns } from '../../shared/api/queries';
import { CONFIDENCE, CONFIRM, HANDLING, LIFECYCLE, SEVERITY, SEVERITY_ORDER, categoryLabel, fmt } from '../../shared/format/messages';
import { ReverifyDialog, riskDecisionSource } from './VulnPanel';
import { PushDialog } from './PushDialog';
import { ProjectExportDialog } from '../projects/ProjectExport';
import {
  Badge, Button, ConfirmBadge, Dialog, EmptyState, ErrorState, Field, HandlingBadge, Icon, LifecycleBadge, Loading, SeverityBadge, cx, ui, useToast,
} from '../../shared/ui';
import V from './vulns.module.css';
import { refreshConversationCards } from './reviewRefresh';

export interface VulnFilters { severity?: string[]; confirmation?: string[]; handling?: string[]; lifecycle?: string[]; q?: string; sort?: string }

/** Sort presets (sort keys); the value goes to the URL and the API unchanged. */
const SORTS: { value: string; label: string }[] = [
  { value: '', label: '严重度（默认）' },
  { value: '-confidence,-severity,displayNo', label: '置信度从高到低' },
  { value: 'confidence,-severity,displayNo', label: '置信度从低到高' },
  { value: 'displayNo', label: '编号' },
  { value: '-updatedAt', label: '最近更新' },
];

/** Why a batch item was skipped (codes from the single-item review rules). */
const SKIP_REASON: Record<string, string> = {
  VULN_EVIDENCE_INCOMPLETE: '证据不完整，跳过（可在详情中写明原因后单独确认）', VULN_REASON_REQUIRED: '需要填写原因', COMMON_REVISION_CONFLICT: '已被修改，请刷新后重试',
  VULN_NOT_FOUND: '漏洞不存在', COMMON_VALIDATION: '取值无效', unchanged: '已是该状态，未改动',
};

interface BatchOutcome { title: string; done: number; skipped: { no: number; reason: string }[] }
interface BatchRow { id: string; ok: boolean; code?: string; unchanged?: boolean }

function ChipGroup({ label, options, value, onChange }: { label: string; options: Record<string, string>; value: string[] | undefined; onChange: (v: string[]) => void }) {
  const cur = value ?? [];
  return (
    <>
      <span className={V.filterLabel}>{label}</span>
      {Object.entries(options).map(([k, l]) => {
        const on = cur.includes(k);
        return <button key={k} className={cx(ui.chip, on && ui.chipOn)} aria-pressed={on} onClick={() => onChange(on ? cur.filter((x) => x !== k) : [...cur, k])}>{l}</button>;
      })}
    </>
  );
}

export function VulnList({ pid, filters, onFilters, selected, onSelect }: {
  pid: string; filters: VulnFilters; onFilters: (f: Partial<VulnFilters>) => void; selected: string | null; onSelect: (vid: string) => void;
}) {
  const [q, setQ] = useState(filters.q ?? '');
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [batch, setBatch] = useState('');
  const [reverify, setReverify] = useState(false);
  const [merge, setMerge] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [review, setReview] = useState<'confirm' | 'false_positive' | null>(null);
  const [outcome, setOutcome] = useState<BatchOutcome | null>(null);
  // G1: a batch's review time runs from the first selection to the action.
  const batchSince = useRef<number | null>(null);
  useEffect(() => {
    if (checked.size === 0) batchSince.current = null;
    else if (batchSince.current === null) batchSince.current = Date.now();
  }, [checked.size]);
  const qc = useQueryClient();
  const toast = useToast();
  // Debounced text filter (replaceState semantics are handled by the router caller).
  useEffect(() => {
    const t = setTimeout(() => { if ((filters.q ?? '') !== q) onFilters({ q: q || undefined }); }, 300);
    return () => clearTimeout(t);
  }, [q]);
  const list = useVulns(pid, { severity: filters.severity, confirmation: filters.confirmation, handling: filters.handling, lifecycle: filters.lifecycle, q: filters.q, sort: filters.sort });
  const items = list.data?.items ?? [];
  // related to a requirement risk a person accepted or ruled out, and marked so — folded.
  const isFolded = (v: VulnSummaryDto) => !!riskDecisionSource(v);
  const shown = items.filter((v) => !isFolded(v));
  const folded = items.filter(isFolded);
  const [showFolded, setShowFolded] = useState(false);
  const sevOpts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, SEVERITY[s]!]));
  const selectedRows = items.filter((v) => checked.has(v.id));
  const repos = new Set(selectedRows.map((v) => v.repo));

  /** One batch request; the outcome (done / skipped with reasons) stays on screen until dismissed. */
  const runBatch = async (title: string, change: Record<string, string>): Promise<boolean> => {
    const rows = selectedRows;
    try {
      const r = await api.post<{ results: BatchRow[] }>('/vulnerabilities/batch-updates', {
        items: rows.map((v) => ({ id: v.id, revision: v.revision })), ...change,
        ...(batchSince.current !== null ? { reviewMs: Math.max(0, Date.now() - batchSince.current) } : {}),
      });
      const no = new Map(rows.map((v) => [v.id, v.displayNo]));
      const skipped = r.results.filter((x) => !x.ok || x.unchanged)
        .map((x) => ({ no: no.get(x.id) ?? 0, reason: SKIP_REASON[x.unchanged ? 'unchanged' : x.code ?? ''] ?? x.code ?? '未知原因' }));
      const done = r.results.length - skipped.length;
      setOutcome({ title, done, skipped });
      void refreshConversationCards(qc);
      if (skipped.length) toast.info(`${title}：${done} 条已完成，${skipped.length} 条跳过`);
      else toast.ok(`${title}：已完成 ${done} 条`);
      setChecked(new Set());
      setBatch('');
      return true;
    } catch (e) {
      toast.error(e);
      return false;
    } finally {
      await qc.invalidateQueries({ queryKey: ['vulns', pid] });
      await qc.invalidateQueries({ queryKey: ['vuln'] });
    }
  };
  const applyBatch = () => runBatch(`设置处理状态为「${HANDLING[batch] ?? batch}」`, { handlingStatus: batch });

  return (
    <div>
      <div className={V.filters}>
        <input className={ui.input} style={{ width: 220, height: 30 }} placeholder="搜索编号、标题、类别" value={q} onChange={(e) => setQ(e.target.value)} />
        <ChipGroup label="严重度" options={sevOpts} value={filters.severity} onChange={(v) => onFilters({ severity: v })} />
        <ChipGroup label="确认" options={CONFIRM} value={filters.confirmation} onChange={(v) => onFilters({ confirmation: v })} />
        <ChipGroup label="处理" options={HANDLING} value={filters.handling} onChange={(v) => onFilters({ handling: v })} />
        <ChipGroup label="跨审计" options={LIFECYCLE} value={filters.lifecycle} onChange={(v) => onFilters({ lifecycle: v })} />
        <span className={V.filterLabel}>排序</span>
        <select className={ui.select} aria-label="排序" style={{ width: 150, height: 30 }} value={SORTS.some((x) => x.value === (filters.sort ?? '')) ? filters.sort ?? '' : ''}
          onChange={(e) => onFilters({ sort: e.target.value || undefined })}>
          {SORTS.map((x) => <option key={x.value} value={x.value}>{x.label}</option>)}
        </select>
      </div>
      {outcome && (
        <div className={cx(ui.card, ui.cardPad)} role="status" aria-label="批量操作结果" style={{ marginBottom: 10, fontSize: 13 }}>
          <div className={ui.spread}>
            <b>{outcome.title}：已完成 {outcome.done} 条{outcome.skipped.length ? `，跳过 ${outcome.skipped.length} 条` : ''}</b>
            <Button size="sm" variant="ghost" onClick={() => setOutcome(null)}>知道了</Button>
          </div>
          {outcome.skipped.length > 0 && (
            <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
              {outcome.skipped.map((x) => <li key={x.no}>V-{x.no}：{x.reason}</li>)}
            </ul>
          )}
        </div>
      )}
      {checked.size > 0 && (
        <div className={cx(ui.card, ui.row, ui.wrap)} style={{ padding: '8px 12px', marginBottom: 10 }}>
          <span>已选 {checked.size} 条</span>
          <select className={ui.select} style={{ width: 160, height: 30 }} value={batch} onChange={(e) => setBatch(e.target.value)}>
            <option value="">设置处理状态…</option>
            {Object.entries(HANDLING).filter(([k]) => k !== 'risk_accepted').map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
          <Button size="sm" variant="primary" disabled={!batch} onClick={() => void applyBatch()}>应用</Button>
          <Button size="sm" icon="check" onClick={() => setReview('confirm')}>批量确认…</Button>
          <Button size="sm" variant="danger" onClick={() => setReview('false_positive')}>标为误报…</Button>
          <Button size="sm" icon="play" disabled={repos.size > 1} title={repos.size > 1 ? '一次复验只能针对一个仓库的漏洞' : undefined} onClick={() => setReverify(true)}>复验所选</Button>
          <Button size="sm" disabled={checked.size < 2} title={checked.size < 2 ? '至少选择两个漏洞' : undefined} onClick={() => setMerge(true)}>合并…</Button>
          <Button size="sm" icon="send" disabled={checked.size > 50} title={checked.size > 50 ? '一次最多推送 50 条' : undefined} onClick={() => setPushing(true)}>推送到…</Button>
          <Button size="sm" icon="download" onClick={() => setExporting(true)}>导出所选…</Button>
          <Button size="sm" variant="ghost" onClick={() => setChecked(new Set())}>取消选择</Button>
        </div>
      )}
      {review && (
        <BatchReviewDialog mode={review} rows={selectedRows} onClose={() => setReview(null)}
          onSubmit={(reason) => runBatch(review === 'confirm' ? '批量确认' : '批量标为误报', { confirmStatus: review === 'confirm' ? 'confirmed' : 'false_positive', ...(reason ? { reason } : {}) })} />
      )}
      {exporting && <ProjectExportDialog pid={pid} open onClose={() => setExporting(false)} selected={selectedRows.map((v) => ({ id: v.id, displayNo: v.displayNo }))} />}
      {pushing && <PushDialog open projectId={pid} vulns={selectedRows.map((v) => ({ id: v.id, displayNo: v.displayNo }))} onClose={() => setPushing(false)} />}
      {merge && <MergeDialog vulns={selectedRows} onClose={(done) => { setMerge(false); if (done) setChecked(new Set()); }} />}
      {reverify && (
        <ReverifyDialog vulns={selectedRows.map((v) => ({ id: v.id, displayNo: v.displayNo }))} projectId={pid}
          repoName={selectedRows[0]?.repo ?? ''} open onClose={() => { setReverify(false); setChecked(new Set()); }} />
      )}
      {list.isLoading ? <Loading rows={6} /> : list.error ? <ErrorState error={list.error} onRetry={() => void list.refetch()} /> : items.length === 0 ? (
        <EmptyState icon="shield" title="没有符合条件的漏洞">调整筛选条件，或发起一次审计。</EmptyState>
      ) : (
        <div className={ui.card} style={{ overflow: 'auto' }}>
          <table className={ui.table}>
            <thead><tr>
              <th style={{ width: 32 }}><input type="checkbox" aria-label="全选" checked={checked.size === items.length} onChange={(e) => setChecked(e.target.checked ? new Set(items.map((v) => v.id)) : new Set())} /></th>
              <th>编号</th><th>严重度</th><th>置信度</th><th>标题</th><th>确认</th><th>处理</th><th>跨审计</th><th>更新</th>
            </tr></thead>
            <tbody>
              {[...shown, ...(showFolded ? folded : [])].map((v: VulnSummaryDto) => (
                <tr key={v.id} className={cx('rowLink', ui.rowLink, selected === v.id && ui.rowSel)} onClick={() => onSelect(v.id)}>
                  <td onClick={(e) => e.stopPropagation()}><input type="checkbox" aria-label={`选择 V-${v.displayNo}`} checked={checked.has(v.id)} onChange={(e) => {
                    const n = new Set(checked);
                    if (e.target.checked) n.add(v.id); else n.delete(v.id);
                    setChecked(n);
                  }} /></td>
                  <td className={ui.mono}>V-{v.displayNo}</td>
                  <td><SeverityBadge severity={v.severity} original={v.severityOriginal} /></td>
                  <td className={ui.muted} style={{ whiteSpace: 'nowrap' }}>{CONFIDENCE[v.confidence] ?? v.confidence}</td>
                  <td style={{ maxWidth: 360 }}><div className={ui.ellipsis}>{v.title}</div><div className={ui.faint} style={{ fontSize: 12 }}>{categoryLabel(v.category)} · {v.repo}{v.entryCount > 1 ? ` · ${v.entryCount} 个入口` : ''}{v.threatRisk && <> · <Badge tone="info" title={`需求威胁模型「${v.threatRisk.title}」`}>需求风险 {v.threatRisk.code}</Badge></>}</div></td>
                  <td><ConfirmBadge status={v.confirmStatus} />{riskDecisionSource(v) && <div className={ui.faint} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{riskDecisionSource(v)}</div>}</td>
                  <td><HandlingBadge status={v.handlingStatus} /></td>
                  <td><LifecycleBadge status={v.lifecycle} />{v.suspectedLink && <> <Badge tone="warn">疑似同一</Badge></>}{v.reverifySuggested && <> <Badge tone="accent">建议复验</Badge></>}</td>
                  <td className={ui.faint} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{fmt.ago(v.updatedAt)}</td>
                </tr>
              ))}
              {folded.length > 0 && (
                <tr>
                  <td colSpan={9}>
                    <button className={ui.ghost} aria-expanded={showFolded} onClick={() => setShowFolded(!showFolded)}>
                      <Icon name={showFolded ? 'chevronDown' : 'chevronRight'} /> 按需求风险处理（{folded.length}）<span className={ui.faint} style={{ fontSize: 12 }}>：关联到已接受、误报或已规避的需求风险，已按人工研判自动标注（已规避按误报处理）</span>
                    </button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      {list.data && list.data.totalEstimate > items.length && <p className={ui.faint} style={{ marginTop: 8 }}>显示前 {items.length} 条，共 {list.data.totalEstimate} 条</p>}
      <Badge>共 {list.data?.totalEstimate ?? 0} 条</Badge>
    </div>
  );
}

/**
 * Batch confirm / false positive. Confirming applies only to items with complete evidence
 * (the same rule as a single confirm, enforced by the service); a false positive needs one reason
 * shared by the whole batch. The preview lists what will be skipped before anything is sent.
 */
function BatchReviewDialog({ mode, rows, onClose, onSubmit }: {
  mode: 'confirm' | 'false_positive'; rows: VulnSummaryDto[]; onClose: () => void; onSubmit: (reason: string) => Promise<boolean>;
}) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const target = mode === 'confirm' ? 'confirmed' : 'false_positive';
  const already = rows.filter((v) => v.confirmStatus === target);
  const incomplete = mode === 'confirm' ? rows.filter((v) => v.confirmStatus !== target && !v.evidenceComplete) : [];
  const eligible = rows.length - already.length - incomplete.length;
  const needReason = mode === 'false_positive';
  const submit = async () => {
    setBusy(true);
    const ok = await onSubmit(reason.trim());
    setBusy(false);
    if (ok) onClose();
  };
  return (
    <Dialog open onClose={onClose} title={mode === 'confirm' ? `批量确认 ${rows.length} 个漏洞` : `批量标为误报 ${rows.length} 个漏洞`} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant={mode === 'confirm' ? 'primary' : 'dangerSolid'} loading={busy} disabled={eligible === 0 || (needReason && !reason.trim())} onClick={() => void submit()}>
        {mode === 'confirm' ? `确认 ${eligible} 条` : `标为误报 ${eligible} 条`}
      </Button>
    </>}>
      <p className={ui.muted}>
        {mode === 'confirm'
          ? '只确认证据完整的漏洞（危险点已核实、入口已知、调用链逐段核实且没有缺失的上下文），与单条确认的规则相同；其余跳过并列出原因。每条各自记入修订历史（来源：人工）。'
          : '所选漏洞共用下面的原因，每条各自记入修订历史（来源：人工）。'}
      </p>
      {(incomplete.length > 0 || already.length > 0) && (
        <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)', display: 'block' }}>
          {incomplete.length > 0 && <div>将跳过 {incomplete.length} 条证据不完整的漏洞（可在详情中写明原因后单独确认）：{incomplete.map((v) => `V-${v.displayNo}`).join('、')}</div>}
          {already.length > 0 && <div>{already.length} 条已是“{CONFIRM[target]}”，不会改动：{already.map((v) => `V-${v.displayNo}`).join('、')}</div>}
        </div>
      )}
      <Field label={needReason ? '原因（必填，整批共用）' : '原因（可选，整批共用）'} hint={needReason ? '说明为什么不成立，便于日后追溯' : undefined}>
        <textarea className={ui.textarea} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} />
      </Field>
    </Dialog>
  );
}

/** Merge: the chosen target keeps its number; the others fold into it. */
function MergeDialog({ vulns, onClose }: { vulns: VulnSummaryDto[]; onClose: (done: boolean) => void }) {
  const [target, setTarget] = useState(vulns[0]!.id);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const t = vulns.find((v) => v.id === target)!;
  const submit = async () => {
    setBusy(true);
    try {
      await api.post('/vulnerabilities/merge', { sourceIds: vulns.filter((v) => v.id !== target).map((v) => v.id), targetId: target, reason: reason.trim() }, { ifMatch: t.revision });
      toast.ok(`已合并到 V-${t.displayNo}`);
      onClose(true);
    } catch (e) { toast.error(e, '合并失败'); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['vulns'] });
    await qc.invalidateQueries({ queryKey: ['vuln'] });
  };
  return (
    <Dialog open onClose={() => onClose(false)} title={`合并 ${vulns.length} 个漏洞`} footer={<><Button onClick={() => onClose(false)}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!reason.trim()} onClick={() => void submit()}>合并</Button></>}>
      <p className={ui.muted}>保留一个漏洞，其余并入它：危险点指纹与入口合并，之后的审计命中任何一个都记在保留的漏洞上。原有的出现记录、证据和修订保留，可以撤销。</p>
      <Field group label="保留哪一个">
        <div className={ui.stack} style={{ gap: 4 }}>{vulns.map((v) => (
          <label key={v.id} className={ui.checkbox}><input type="radio" name="merge-target" checked={target === v.id} onChange={() => setTarget(v.id)} />V-{v.displayNo} {v.title}</label>
        ))}</div>
      </Field>
      <Field label="原因（必填）"><textarea className={ui.textarea} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} /></Field>
    </Dialog>
  );
}
