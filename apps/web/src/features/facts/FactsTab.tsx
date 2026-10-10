// Enterprise facts of a project: what the enterprise is like — gateway and auth policies,
// deployment, business rules, trust between services. Audits query them (facts_query) and findings cite them as
// premises; a change writes a new version and marks the vulnerabilities that relied on the old one for reverification.
import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { FactDetailDto, FactDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { Badge, Button, Dialog, EmptyState, Field, Loading, cx, ui, useToast } from '../../shared/ui';
import { fmt } from '../../shared/format/messages';

export const FACT_TOPIC: Record<string, string> = {
  gateway: '网关', auth: '鉴权', deployment: '部署', network: '网络边界', business_rule: '业务规则', architecture: '架构', data: '数据', integration: '集成', other: '其他',
};
const TRUST: Record<string, [string, 'ok' | 'info' | 'warn']> = { authoritative: ['权威', 'ok'], verified: ['已核实', 'info'], unverified: ['未核实', 'warn'] };
const SENS: Record<string, string> = { public: '公开', internal: '内部', confidential: '机密' };
const SOURCE: Record<string, string> = {
  user: '手工', knowledge: '知识库', architecture_import: '架构导入', topology: '系统拓扑', question: '计划提问的回答', requirement_risk: '需求风险裁定',
  profile: '画像假设', review: '复核裁定', gateway_config: '网关配置',
};

function TrustBadge({ f }: { f: FactDto }) {
  const [label, tone] = TRUST[f.trust] ?? [f.trust, 'info'];
  return <Badge tone={tone}>{label}</Badge>;
}

export function FactsTab({ pid }: { pid: string }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [topic, setTopic] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [history, setHistory] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const params = new URLSearchParams({ ...(history ? { status: 'all' } : {}), ...(topic ? { topic } : {}), ...(q.trim() ? { q: q.trim() } : {}) }).toString();
  const facts = useQuery({ queryKey: ['facts', pid, params], queryFn: () => api.get<FactDto[]>(`/projects/${pid}/facts${params ? `?${params}` : ''}`) });
  const stale = (facts.data ?? []).filter((f) => f.status === 'active' && f.affected.stale > 0).reduce((n, f) => n + f.affected.stale, 0);
  const runImport = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ added: number; updated: number; unchanged: number; kept: number }>(`/projects/${pid}/facts/import`, {});
      toast.ok(`导入完成：新增 ${r.added} 条，更新 ${r.updated} 条，未变 ${r.unchanged} 条，人工修改过的保留 ${r.kept} 条`);
      await qc.invalidateQueries({ queryKey: ['facts', pid] });
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <section aria-label="企业事实">
      <div className={ui.spread} style={{ gap: 12, alignItems: 'flex-start' }}>
        <p className={ui.muted} style={{ margin: 0 }}>
          企业事实描述代码看不到的前提：网关与鉴权策略、部署与网络边界、业务规则、服务间信任等。审计按需查询，发现可以引用它们作为前提；
          事实修改或作废后，依赖它的漏洞会标记为需要复验。“权威”“已核实”的事实可作为结论依据，“未核实”的只能作为推测。
        </p>
        <div className={ui.row} style={{ gap: 6 }}>
          <Button size="sm" icon="download" loading={busy} onClick={() => void runImport()} title="从业务 / 架构知识、系统拓扑与架构导入、需求风险裁定、画像假设、已回答的提问导入">导入已有资料</Button>
          <Button size="sm" variant="primary" icon="plus" onClick={() => setAdding(true)}>新增事实</Button>
        </div>
      </div>
      {stale > 0 && <div className={ui.banner} role="alert" style={{ marginTop: 10 }}>有 {stale} 个漏洞依赖的事实已经修改或作废，建议复验（打开对应事实查看）。</div>}
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 6, marginTop: 12 }} aria-label="按主题筛选">
        <button className={cx(ui.chip, !topic && ui.chipOn)} aria-pressed={!topic} onClick={() => setTopic(null)}>全部主题</button>
        {Object.entries(FACT_TOPIC).map(([k, v]) => <button key={k} className={cx(ui.chip, topic === k && ui.chipOn)} aria-pressed={topic === k} onClick={() => setTopic(k)}>{v}</button>)}
        <input className={ui.input} style={{ width: 200, marginLeft: 'auto' }} placeholder="搜索陈述" aria-label="搜索事实" value={q} onChange={(e) => setQ(e.target.value)} />
        <label className={ui.checkbox}><input type="checkbox" checked={history} onChange={(e) => setHistory(e.target.checked)} />含历史版本</label>
      </div>
      {facts.isLoading ? <Loading /> : !(facts.data ?? []).length ? <EmptyState icon="database" title="还没有企业事实">可以手工新增，或从知识库、系统拓扑等已有资料导入；计划中“需要补充的上下文”的回答也会存为事实。</EmptyState> : (
        <div className={ui.card} style={{ overflow: 'auto', marginTop: 12 }}>
          <table className={ui.table} aria-label="事实列表">
            <tbody>{(facts.data ?? []).map((f) => (
              <tr key={f.id} className={cx(ui.rowLink, open === f.id && ui.rowSel)} style={f.status !== 'active' ? { opacity: 0.6 } : undefined} onClick={() => setOpen(f.id)}>
                <td style={{ whiteSpace: 'nowrap' }}><Badge>{FACT_TOPIC[f.topic] ?? f.topic}</Badge></td>
                <td>
                  <div style={{ whiteSpace: 'pre-wrap' }}>{f.statement}</div>
                  <div className={cx(ui.row, ui.wrap, ui.faint)} style={{ gap: 6, fontSize: 12, marginTop: 4 }}>
                    <TrustBadge f={f} />
                    {f.sensitivity === 'confidential' && <Badge tone="danger">机密</Badge>}
                    <span>{SOURCE[f.sourceKind] ?? f.sourceKind} · v{f.version}{f.status === 'superseded' ? ' · 已被新版本取代' : f.status === 'retracted' ? ' · 已作废' : ''}</span>
                    {f.affected.vulns > 0 && <span>· {f.affected.vulns} 个漏洞引用</span>}
                    {f.affected.stale > 0 && <Badge tone="warn">{f.affected.stale} 个需复验</Badge>}
                  </div>
                </td>
                <td className={ui.faint} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{fmt.ago(f.updatedAt)}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      {open && <FactDialog id={open} pid={pid} onClose={() => setOpen(null)} />}
      {adding && <FactEditor pid={pid} onClose={() => setAdding(false)} />}
    </section>
  );
}

/** Add a fact (also from a review ruling: `review` = the vulnerability id), or change one (a new version). */
export function FactEditor({ pid, fact, review, initial, onClose }: { pid: string; fact?: FactDto; review?: string; initial?: { topic?: string; statement?: string }; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [topic, setTopic] = useState(fact?.topic ?? initial?.topic ?? 'gateway');
  const [statement, setStatement] = useState(fact?.statement ?? initial?.statement ?? '');
  const [trust, setTrust] = useState<'verified' | 'unverified'>(fact?.trust === 'unverified' ? 'unverified' : 'verified');
  const [sensitivity, setSensitivity] = useState(fact?.sensitivity ?? 'internal');
  const [scope, setScope] = useState([...(fact?.scope.repos ?? []), ...(fact?.scope.services ?? [])].join('、'));
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    try {
      const services = scope.split(/[、,，\s]+/).map((s) => s.trim()).filter(Boolean);
      const body = { topic, statement, trust, sensitivity, ...(services.length ? { scope: { services } } : {}), ...(reason.trim() ? { reason: reason.trim() } : {}) };
      if (fact) await api.put(`/facts/${fact.id}`, body);
      else await api.post(`/projects/${pid}/facts`, { ...body, ...(review ? { sourceKind: 'review', sourceRef: review } : {}) });
      toast.ok(fact ? '已保存为新版本' : '已新增事实');
      await qc.invalidateQueries({ queryKey: ['facts', pid] });
      await qc.invalidateQueries({ queryKey: ['fact'] });
      onClose();
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <Dialog open onClose={onClose} title={fact ? `修改事实（v${fact.version} → v${fact.version + 1}）` : review ? '把复核裁定存为企业事实' : '新增企业事实'} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!statement.trim()} onClick={() => void save()}>保存</Button>
    </>}>
      <Field label="主题"><select className={ui.input} aria-label="主题" value={topic} onChange={(e) => setTopic(e.target.value)}>{Object.entries(FACT_TOPIC).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
      <Field label="陈述" hint="一句话写清事实，例如“所有 /api/** 请求经 edge-gateway，网关校验 JWT 并把用户 id 写入 X-User-Id”"><textarea className={ui.textarea} aria-label="陈述" rows={4} value={statement} onChange={(e) => setStatement(e.target.value)} /></Field>
      <Field label="作用范围" hint="服务或仓库名，用顿号分隔；留空表示整个项目"><input className={ui.input} aria-label="作用范围" value={scope} onChange={(e) => setScope(e.target.value)} /></Field>
      <div className={ui.row} style={{ gap: 12 }}>
        <Field label="可信级别"><select className={ui.input} aria-label="可信级别" value={trust} onChange={(e) => setTrust(e.target.value as 'verified' | 'unverified')}><option value="verified">已核实（可作为结论依据）</option><option value="unverified">未核实（只作推测）</option></select></Field>
        <Field label="敏感级别"><select className={ui.input} aria-label="敏感级别" value={sensitivity} onChange={(e) => setSensitivity(e.target.value)}>{Object.entries(SENS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
      </div>
      {fact && <Field label="修改理由（可选）"><input className={ui.input} aria-label="修改理由" value={reason} onChange={(e) => setReason(e.target.value)} /></Field>}
    </Dialog>
  );
}

function FactDialog({ id, pid, onClose }: { id: string; pid: string; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const d = useQuery({ queryKey: ['fact', id], queryFn: () => api.get<FactDetailDto>(`/facts/${id}`) });
  const [editing, setEditing] = useState(false);
  const [retracting, setRetracting] = useState(false);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const f = d.data?.fact;
  const stale = (d.data?.impact ?? []).filter((i) => i.stale);
  const retract = async () => {
    setBusy(true);
    try {
      await api.post(`/facts/${id}/retract`, { reason });
      toast.ok('已作废，依赖它的漏洞已标记为需要复验');
      await qc.invalidateQueries({ queryKey: ['facts', pid] });
      await qc.invalidateQueries({ queryKey: ['fact', id] });
      setRetracting(false);
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  const reverify = async () => {
    setBusy(true);
    try {
      const ids = [...new Set(stale.map((i) => i.vulnerabilityId))];
      const r = await api.post<{ auditId: string }>('/reverifications', { vulnIds: ids }, { idempotencyKey: `fact-${id}-${ids.join(',')}` });
      toast.ok(`已发起 ${ids.length} 个漏洞的复验`);
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <Dialog open onClose={onClose} wide title={f ? `${FACT_TOPIC[f.topic] ?? f.topic} · v${f.version}` : '事实'} footer={f?.status === 'active' ? <>
      <Button variant="danger" onClick={() => setRetracting(true)} style={{ marginRight: 'auto' }}>作废</Button>
      <Button onClick={onClose}>关闭</Button>
      <Button variant="primary" icon="edit" onClick={() => setEditing(true)}>修改</Button>
    </> : <Button onClick={onClose}>关闭</Button>}>
      {!f ? <Loading /> : (
        <>
          <p style={{ whiteSpace: 'pre-wrap', marginTop: 0 }}>{f.statement}</p>
          <div className={cx(ui.row, ui.wrap, ui.faint)} style={{ gap: 6, fontSize: 12 }}>
            <TrustBadge f={f} /><span>敏感级别：{SENS[f.sensitivity]}</span><span>来源：{SOURCE[f.sourceKind] ?? f.sourceKind}{f.sourceRef ? `（${f.sourceRef}）` : ''}</span>
            {[...(f.scope.repos ?? []), ...(f.scope.services ?? []), ...(f.scope.paths ?? [])].length > 0 && <span>范围：{[...(f.scope.repos ?? []), ...(f.scope.services ?? []), ...(f.scope.paths ?? [])].join('、')}</span>}
          </div>
          {stale.length > 0 && (
            <div className={ui.banner} role="alert" style={{ marginTop: 12 }}>
              {new Set(stale.map((i) => i.vulnerabilityId)).size} 个漏洞依赖的是已不再生效的版本。
              <Button size="sm" variant="primary" loading={busy} onClick={() => void reverify()}>一键复验</Button>
            </div>
          )}
          <h3 style={{ fontSize: 14, marginTop: 16 }}>引用它的漏洞（{d.data!.impact.length}）</h3>
          {d.data!.impact.length === 0 ? <p className={ui.faint}>还没有发现引用这条事实。</p> : (
            <ul style={{ margin: 0, paddingLeft: 18 }} aria-label="引用它的漏洞">{d.data!.impact.map((i) => <li key={`${i.vulnerabilityId}-${i.version}`}>V-{i.displayNo} {i.title} · 依赖 v{i.version}{i.stale ? <Badge tone="warn">需复验</Badge> : null}</li>)}</ul>
          )}
          <h3 style={{ fontSize: 14, marginTop: 16 }}>版本</h3>
          <ul style={{ margin: 0, paddingLeft: 18 }} aria-label="版本">{d.data!.versions.map((v) => <li key={v.id} className={v.status !== 'active' ? ui.faint : undefined}>v{v.version} · {v.status === 'active' ? '生效' : v.status === 'superseded' ? '已取代' : '已作废'} · {v.createdBy} · {fmt.ago(v.updatedAt)}{v.reason ? ` · ${v.reason}` : ''}<div style={{ whiteSpace: 'pre-wrap' }}>{v.statement}</div></li>)}</ul>
          {retracting && (
            <div style={{ marginTop: 12 }}>
              <Field label="作废理由"><input className={ui.input} aria-label="作废理由" value={reason} onChange={(e) => setReason(e.target.value)} autoFocus /></Field>
              <Button variant="danger" loading={busy} disabled={!reason.trim()} onClick={() => void retract()}>确认作废</Button>
            </div>
          )}
        </>
      )}
      {editing && f && <FactEditor pid={pid} fact={f} onClose={() => setEditing(false)} />}
    </Dialog>
  );
}
