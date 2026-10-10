// "未排除的假设": hypotheses a hunt could neither prove nor refute. They are not findings and
// not false positives: listed next to the results with the refutation attempts; a reviewer converts one to a
// pending vulnerability, dismisses it with a reason, or continues the investigation in the AI panel.
// The threat model's risk hypotheses in the coverage view — what was proposed, how each was
// verified and why — and the optional analyses that can be run afterwards (追加执行).
import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { CoverageDto, HypothesisDecisionResult, HypothesisDto, HypothesisList } from '@xiezhi/contracts';
import { api, newIdempotencyKey } from '../../shared/api/client';
import { categoryLabel, VULN_CATEGORY } from '../../shared/format/messages';
import { AuditStatusBadge, Badge, Button, Dialog, EmptyState, Field, Segmented, cx, ui, useToast } from '../../shared/ui';
import { useAi } from '../assistant/ai';

export function useHypotheses(aid: string) {
  return useQuery({ queryKey: ['audit', aid, 'hypotheses'], queryFn: () => api.get<HypothesisList>(`/audits/${aid}/hypotheses`) });
}

export function HypothesesSection({ aid, onVuln }: { aid: string; onVuln: (vid: string) => void }) {
  const q = useHypotheses(aid);
  const [showRefuted, setShowRefuted] = useState(false);
  const [acting, setActing] = useState<{ h: HypothesisDto; action: 'convert' | 'dismiss' } | null>(null);
  const ai = useAi();
  const toast = useToast();
  if (!q.data || q.data.items.length === 0) return null;
  const c = q.data.counts;
  const open = q.data.items.filter((h) => h.status === 'open');
  // Threat-model hypotheses set aside before verification are shown in the coverage view, not here.
  const decided = q.data.items.filter((h) => (h.status === 'converted' || h.status === 'dismissed') && h.location);
  const refuted = q.data.items.filter((h) => h.status === 'refuted');
  if (!open.length && !decided.length && !refuted.length) return null;
  const follow = async (h: HypothesisDto) => {
    try { await navigator.clipboard.writeText(`请继续调查这个未排除的假设：${h.statement}${h.location ? `（${h.location.repo}:${h.location.path}:${h.location.startLine}）` : ''}。已尝试的反驳：${h.attempts}`); } catch { /* clipboard may be unavailable */ }
    ai.ask();
    toast.info('已打开 AI 面板，假设内容已复制，可直接粘贴');
  };
  return (
    <div data-testid="hypotheses">
      <div className={ui.spread} style={{ marginBottom: 6 }}>
        <b>未排除的假设（{c.open}）</b>
        <span className={ui.faint} style={{ fontSize: 12 }}>已转为漏洞 {c.converted} · 已排除 {c.dismissed} · 已被证据反驳 {c.refuted}</span>
      </div>
      <p className={ui.faint} style={{ fontSize: 12, margin: '0 0 10px' }}>
        AI 按业务含义提出、但既没有证实也没有被代码证据反驳的风险假设。它们不是漏洞，也不计为误报；请人工判断。
      </p>
      {open.length > 0 ? (
        <div className={ui.stack} style={{ gap: 8 }}>
          {open.map((h) => (
            <div key={h.id} className={cx(ui.card, ui.cardPad)} data-testid="hypothesis">
              <div className={ui.spread}>
                <div className={ui.row}><Badge tone="warn">{categoryLabel(h.category)}</Badge>{h.threatRiskId ? <Badge tone="info">需求风险</Badge> : h.origin === 'threat_model' && <Badge tone="info">威胁建模</Badge>}<b>{h.statement}</b></div>
                <div className={ui.row}>
                  <Button size="sm" icon="sparkle" onClick={() => void follow(h)}>追问</Button>
                  <Button size="sm" onClick={() => setActing({ h, action: 'dismiss' })}>排除</Button>
                  <Button size="sm" variant="primary" onClick={() => setActing({ h, action: 'convert' })}>转为漏洞</Button>
                </div>
              </div>
              {h.location && <div className={ui.mono} style={{ fontSize: 12, marginTop: 6 }}>{h.location.repo}:{h.location.path}:{h.location.startLine}{h.entry ? ` · ${h.entry}` : ''}</div>}
              <p className={ui.muted} style={{ fontSize: 13, margin: '6px 0 0' }}>已尝试的反驳：{h.attempts}</p>
            </div>
          ))}
        </div>
      ) : <p className={ui.muted} style={{ fontSize: 13 }}>没有待处理的假设。</p>}
      {decided.length > 0 && (
        <p className={ui.faint} style={{ fontSize: 12, marginTop: 8 }}>
          已处理：{decided.map((h) => h.status === 'converted' && h.vulnerabilityId
            ? <a key={h.id} href="#" onClick={(e) => { e.preventDefault(); onVuln(h.vulnerabilityId!); }} style={{ marginRight: 8 }}>{h.statement.slice(0, 30)}（已转为漏洞）</a>
            : <span key={h.id} style={{ marginRight: 8 }}>{h.statement.slice(0, 30)}（已排除：{h.decidedReason}）</span>)}
        </p>
      )}
      {refuted.length > 0 && (
        <div style={{ marginTop: 8 }}>
          <Button size="sm" onClick={() => setShowRefuted(!showRefuted)}>{showRefuted ? '收起' : '查看'}已被证据反驳的假设（{refuted.length}）</Button>
          {showRefuted && <ul className={ui.muted} style={{ fontSize: 13 }}>{refuted.map((h) => <li key={h.id}>{h.statement} — {h.attempts}</li>)}</ul>}
        </div>
      )}
      {acting && <DecisionDialog aid={aid} h={acting.h} action={acting.action} onClose={() => setActing(null)} onVuln={onVuln} />}
    </div>
  );
}

function DecisionDialog({ aid, h, action, onClose, onVuln }: { aid: string; h: HypothesisDto; action: 'convert' | 'dismiss'; onClose: () => void; onVuln: (vid: string) => void }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const submit = async () => {
    setBusy(true);
    try {
      const r = await api.post<HypothesisDecisionResult>(`/hypotheses/${h.id}/decision`, { action, reason });
      await qc.invalidateQueries({ queryKey: ['audit', aid] });
      onClose();
      if (r.vulnerability) { toast.info(`已转为漏洞 V-${r.vulnerability.displayNo}（待确认）`); onVuln(r.vulnerability.id); }
    } catch (e) { toast.error(e, '处理失败'); }
    setBusy(false);
  };
  return (
    <Dialog open onClose={onClose} title={action === 'convert' ? '转为漏洞' : '排除假设'} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!reason.trim()} onClick={() => void submit()}>{action === 'convert' ? '转为漏洞（待确认）' : '排除'}</Button>
    </>}>
      <p className={ui.muted} style={{ fontSize: 13 }}>{h.statement}</p>
      <Field label={action === 'convert' ? '为什么成立（会写入修订记录）' : '为什么不成立（会记录在假设上）'}>
        <textarea className={ui.textarea} value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} autoFocus />
      </Field>
      {action === 'convert' && <p className={ui.faint} style={{ fontSize: 12 }}>转为漏洞后状态为“待确认”：证据只有假设所在位置，需要补充证据或复验后才能确认。</p>}
    </Dialog>
  );
}

// ---- risk hypotheses in the coverage view -------------------------------------------------------------

const HYP_STATUS: Record<HypothesisDto['status'], { l: string; t: 'ok' | 'warn' | 'danger' | 'neutral' | 'info' }> = {
  proposed: { l: '未验证', t: 'danger' }, confirmed: { l: '已证实', t: 'warn' }, refuted: { l: '已排除', t: 'ok' }, open: { l: '无法判定', t: 'info' },
  converted: { l: '人工转为漏洞', t: 'warn' }, dismissed: { l: '人工排除', t: 'neutral' },
};
type HypFilter = 'all' | 'proposed' | 'confirmed' | 'refuted' | 'open' | 'decided';

function threatHypotheses(aid: string, live: boolean) {
  return { queryKey: ['audit', aid, 'hypotheses', 'threat'] as const, queryFn: () => api.get<HypothesisList>(`/audits/${aid}/hypotheses?origin=threat_model`), ...(live ? { refetchInterval: 4000 } : {}) };
}

/** add a risk hypothesis to the list, also while the audit runs (non-blocking). */
function AddHypothesis({ aid, finished }: { aid: string; finished: boolean }) {
  const [open, setOpen] = useState(false);
  const [statement, setStatement] = useState('');
  const [category, setCategory] = useState('business_logic');
  const [basis, setBasis] = useState('');
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const submit = async () => {
    setBusy(true);
    try {
      await api.post(`/audits/${aid}/hypotheses`, { statement: statement.trim(), category, ...(basis.trim() ? { basis: basis.trim() } : {}) });
      toast.ok(finished ? '已加入清单：可选中后“验证所选”' : '已加入清单：本次审计的覆盖补齐环节会验证它');
      setStatement(''); setBasis(''); setOpen(false);
      await qc.invalidateQueries({ queryKey: ['audit', aid] });
    } catch (e) { toast.error(e, '无法补充'); }
    setBusy(false);
  };
  if (!open) return <Button size="sm" icon="plus" onClick={() => setOpen(true)}>补充假设</Button>;
  return (
    <div className={cx(ui.card, ui.cardPad)} style={{ marginBottom: 10 }} aria-label="补充风险假设">
      <Field label="风险假设（一句可以被代码证实或反驳的陈述）">
        <textarea className={ui.textarea} value={statement} onChange={(e) => setStatement(e.target.value)} maxLength={1000} placeholder="例如：退款接口只按订单号查询，未校验订单属于当前用户" />
      </Field>
      <div className={ui.row} style={{ gap: 12, alignItems: 'flex-end' }}>
        <Field label="类别">
          <select className={ui.select} value={category} onChange={(e) => setCategory(e.target.value)}>
            {Object.entries(VULN_CATEGORY).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </Field>
        <Field label="依据（可选）"><input className={ui.input} value={basis} onChange={(e) => setBasis(e.target.value)} maxLength={1000} placeholder="资产 / 角色 / 业务流程" /></Field>
      </div>
      <div className={ui.row} style={{ marginTop: 8 }}>
        <Button size="sm" variant="primary" loading={busy} disabled={statement.trim().length < 4} onClick={() => void submit()}>加入清单</Button>
        <Button size="sm" onClick={() => setOpen(false)}>取消</Button>
      </div>
    </div>
  );
}

/**
 * 威胁建模风险假设 (coverage view): every hypothesis the threat model proposed, its verification and the reason
 * (排查理由). Unverified ones can be verified afterwards (a supplement) or set aside with a reason.
 */
export function ThreatHypothesesCoverage({ aid, finished, supplementable, enabled, onVuln }: { aid: string; finished: boolean; supplementable: boolean; enabled?: boolean; onVuln?: (vid: string) => void }) {
  const q = useQuery(threatHypotheses(aid, !finished));
  const [filter, setFilter] = useState<HypFilter>('all');
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [acting, setActing] = useState<{ h: HypothesisDto; action: 'convert' | 'dismiss' } | null>(null);
  const [key] = useState(newIdempotencyKey);
  const navigate = useNavigate();
  const toast = useToast();
  if (!q.data || (q.data.items.length === 0 && !enabled)) return null;
  if (q.data.items.length === 0) {
    return (
      <div data-testid="threat-hypotheses">
        <div className={ui.spread} style={{ marginBottom: 6 }}><b>威胁建模风险假设</b><AddHypothesis aid={aid} finished={finished} /></div>
        <p className={ui.muted} style={{ fontSize: 13 }}>{finished ? '本次审计没有列出风险假设。' : '威胁建模完成后，风险假设清单会在这里列出；你可以随时排除或补充，不会阻塞审计。'}</p>
      </div>
    );
  }
  const items = q.data.items;
  const c = q.data.counts;
  const unverified = items.filter((h) => h.status === 'proposed');
  const list = items.filter((h) => filter === 'all' || (filter === 'decided' ? ['converted', 'dismissed'].includes(h.status) : h.status === filter));
  const verify = async () => {
    const ids = picked.size ? [...picked] : unverified.map((h) => h.id);
    setBusy(true);
    try {
      const r = await api.post<{ auditId: string }>(`/audits/${aid}/supplements`, { kind: 'threat_hypotheses', hypothesisIds: ids }, { idempotencyKey: `${key}-${[...ids].sort().join(',')}` });
      toast.ok(`已开始验证 ${ids.length} 条风险假设`);
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) { toast.error(e, '无法开始验证'); }
    setBusy(false);
  };
  const toggle = (id: string) => setPicked((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const reviewed = items.length - c.proposed;
  return (
    <div data-testid="threat-hypotheses">
      <div className={ui.spread} style={{ marginBottom: 6 }}>
        <b>威胁建模风险假设（已验证 {reviewed}/{items.length}）</b>
        <span className={ui.faint} style={{ fontSize: 12 }}>已证实 {c.confirmed} · 已排除 {c.refuted} · 无法判定 {c.open} · 未验证 {c.proposed}{c.converted + c.dismissed ? ` · 人工处理 ${c.converted + c.dismissed}` : ''}</span>
      </div>
      <p className={ui.faint} style={{ fontSize: 12, margin: '0 0 10px' }}>
        风险假设先行：先按项目画像与威胁模型列出仓库可能面临的风险，再逐条用代码验证。“已排除”与“无法判定”都附排查理由与所依据的代码位置；未验证的是覆盖缺口，不代表没有风险。{finished ? '' : '审计进行中也可以排除或补充假设，不会阻塞审计。'}
      </p>
      <div style={{ marginBottom: 10 }}><AddHypothesis aid={aid} finished={finished} /></div>
      <div className={ui.spread} style={{ marginBottom: 10 }}>
        <Segmented value={filter} onChange={setFilter} items={[
          { key: 'all', label: `全部 ${items.length}` }, { key: 'proposed', label: `未验证 ${c.proposed}` }, { key: 'confirmed', label: `已证实 ${c.confirmed}` },
          { key: 'refuted', label: `已排除 ${c.refuted}` }, { key: 'open', label: `无法判定 ${c.open}` }, { key: 'decided', label: `人工处理 ${c.converted + c.dismissed}` },
        ]} />
        {supplementable && unverified.length > 0 && (
          <Button size="sm" variant="primary" icon="play" loading={busy} disabled={!finished} title={!finished ? '审计结束后才能追加验证' : undefined} onClick={() => void verify()}>
            {picked.size ? `验证所选（${picked.size}）` : `验证全部未验证（${unverified.length}）`}
          </Button>
        )}
      </div>
      {list.length === 0 ? <p className={ui.muted} style={{ fontSize: 13 }}>没有符合条件的假设。</p> : (
        <div className={ui.card} style={{ overflow: 'auto', maxHeight: 640 }}>
          <table className={ui.table}>
            <thead><tr><th aria-label="选择" /><th>优先级</th><th>假设</th><th>状态</th><th>排查理由</th></tr></thead>
            <tbody>{list.map((h) => {
              const st = HYP_STATUS[h.status] ?? { l: h.status, t: 'neutral' as const };
              const reason = h.status === 'converted' || h.status === 'dismissed' ? `人工：${h.decidedReason ?? ''}${h.attempts ? `（验证：${h.attempts}）` : ''}` : h.attempts;
              return (
                <tr key={h.id} data-testid="threat-hypothesis">
                  <td>{h.status === 'proposed' && finished && supplementable && <input type="checkbox" aria-label={`选择 ${h.statement}`} checked={picked.has(h.id)} onChange={() => toggle(h.id)} />}</td>
                  <td>{h.priority ?? '—'}</td>
                  <td style={{ maxWidth: 420 }}>
                    <div className={ui.row} style={{ flexWrap: 'wrap' }}><Badge>{categoryLabel(h.category)}</Badge><b>{h.statement}</b></div>
                    {h.basis && <div className={ui.faint} style={{ fontSize: 12, marginTop: 4 }}>依据：{h.basis}</div>}
                    {h.relatedEntries.length > 0 && <div className={ui.mono} style={{ fontSize: 12, marginTop: 2 }}>{h.relatedEntries.join(' · ')}</div>}
                  </td>
                  <td><Badge tone={st.t}>{st.l}</Badge></td>
                  <td style={{ maxWidth: 420, fontSize: 13 }}>
                    {reason ? <div>{reason}</div> : <span className={ui.faint}>尚未验证</span>}
                    {h.location && <div className={ui.mono} style={{ fontSize: 12, marginTop: 2 }} title={`${h.location.repo}:${h.location.path}:${h.location.startLine}-${h.location.endLine}`}>{h.location.path.split('/').pop()}:{h.location.startLine}</div>}
                    {h.status === 'confirmed' && (h.vulnerabilityId && onVuln
                      ? <a href="#" style={{ fontSize: 12 }} onClick={(e) => { e.preventDefault(); onVuln(h.vulnerabilityId!); }}>查看对应漏洞</a>
                      : h.findingState && h.findingState !== 'canonical' ? <div className={ui.faint} style={{ fontSize: 12 }}>对应发现在汇总或复核后为：{h.findingState === 'dropped' ? '已丢弃' : h.findingState === 'insufficient' ? '证据不足' : h.findingState}</div> : null)}
                    {(h.status === 'open' || h.status === 'proposed') && (
                      <div className={ui.row} style={{ marginTop: 4 }}>
                        <Button size="sm" onClick={() => setActing({ h, action: 'dismiss' })}>排除</Button>
                        {h.status === 'open' && <Button size="sm" onClick={() => setActing({ h, action: 'convert' })}>转为漏洞</Button>}
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      )}
      {acting && <DecisionDialog aid={aid} h={acting.h} action={acting.action} onClose={() => setActing(null)} onVuln={onVuln ?? (() => undefined)} />}
    </div>
  );
}

// the per-entry logic review is part of risk-hypothesis-first.
const ANALYSES: { kind: 'threat_hypotheses'; label: string; hint: string }[] = [
  { kind: 'threat_hypotheses', label: '风险假设先行', hint: '结合项目画像与威胁模型列出风险假设清单（改变状态或按 id 访问资源的入口逐个考虑），再逐条用代码验证；结果计入本次的风险假设覆盖' },
];

/** The optional analyses of this audit and 追加执行 for those it did not run (finished full / incremental audits). */
export function AnalysesPanel({ aid, coverage, finished }: { aid: string; coverage: CoverageDto; finished: boolean }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [key] = useState(newIdempotencyKey);
  const navigate = useNavigate();
  const toast = useToast();
  const ran = { threat_hypotheses: coverage.analyses.threatHypotheses };
  if (!coverage.supplementable && !coverage.supplements.length && !ran.threat_hypotheses) return null;
  const start = async (kind: 'threat_hypotheses') => {
    setBusy(kind);
    try {
      const r = await api.post<{ auditId: string }>(`/audits/${aid}/supplements`, { kind }, { idempotencyKey: `${key}-${kind}` });
      toast.ok('已开始追加执行');
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) { toast.error(e, '无法追加执行'); }
    setBusy(null);
  };
  return (
    <div className={cx(ui.card, ui.cardPad)} aria-label="可选分析" data-testid="analyses">
      <b>可选分析</b>
      {ANALYSES.map((x) => {
        const subs = coverage.supplements;
        return (
          <div key={x.kind} className={ui.spread} style={{ marginTop: 10, alignItems: 'flex-start', gap: 12 }}>
            <div>
              <div className={ui.row}><span>{x.label}</span>{ran[x.kind] ? <Badge tone="ok">本次已执行</Badge> : <Badge>本次未开启</Badge>}</div>
              <div className={ui.faint} style={{ fontSize: 12, marginTop: 2 }}>{x.hint}</div>
              {subs.map((s) => (
                <div key={s.auditId} className={ui.row} style={{ fontSize: 12, marginTop: 4 }}>
                  <Link to="/audits/$aid" params={{ aid: s.auditId }}>{s.title}</Link><AuditStatusBadge status={s.status} />
                  {s.kind === 'threat_hypotheses' && <span className={ui.faint}>假设 {s.hypotheses} 条</span>}
                </div>
              ))}
            </div>
            {coverage.supplementable && (
              <Button size="sm" icon="play" loading={busy === x.kind} disabled={!finished || busy !== null}
                title={ran[x.kind] ? '本次已执行；可以再追加一次（例如换了模型或知识）' : undefined} onClick={() => void start(x.kind)}>追加执行</Button>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function NoCoverageCompare() {
  return <EmptyState icon="target" title="本次审计未开启覆盖对照">全量审计默认开启（需要 AST 结构解析）。</EmptyState>;
}
