// 领域规划: the risk domains the threat model planned for the domain experts, shown once planned
// and adjustable while the audit runs without blocking it — add a domain, remove one, add focus to one. A domain added
// after the expert phase runs in a supplement (追加执行) once the audit is finished.
import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { DomainPlanDto } from '@xiezhi/contracts';
import { api, newIdempotencyKey } from '../../shared/api/client';
import { categoryLabel, VULN_CATEGORY } from '../../shared/format/messages';
import { Badge, Button, Field, cx, ui, useToast } from '../../shared/ui';

type Domain = DomainPlanDto['domains'][number];

const SOURCE: Record<Domain['source'], string> = { threat_model: '威胁建模', fallback: '兜底领域', completion: '引擎补全', user: '审计员新增' };
const ROUND_STATUS: Record<string, string> = { succeeded: '完成', running: '进行中', failed: '失败', skipped: '跳过', pending: '等待', ready: '等待', waiting_budget: '等待额度' };

export function useDomainPlan(aid: string, live: boolean) {
  return useQuery({ queryKey: ['audit', aid, 'domain-plan'], queryFn: () => api.get<DomainPlanDto>(`/audits/${aid}/domain-plan`), ...(live ? { refetchInterval: 4000 } : {}) });
}

/**
 * `folded`: start as one line per domain (6 domains: the cards took two screens above the trajectory the
 * page is opened for); the plan tab shows them in full.
 */
export function DomainPlanCard({ aid, live, folded = false }: { aid: string; live: boolean; folded?: boolean }) {
  const q = useDomainPlan(aid, live);
  const [open, setOpen] = useState(!folded);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const [key] = useState(newIdempotencyKey);
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  if (!q.data?.planned) return null;
  const plan = q.data;
  const edit = async (body: Record<string, unknown>, done: string) => {
    setBusy(true);
    try {
      await api.post(`/audits/${aid}/domain-plan/edits`, body);
      toast.ok(done);
      await qc.invalidateQueries({ queryKey: ['audit', aid, 'domain-plan'] });
    } catch (e) { toast.error(e, '无法修改领域规划'); }
    setBusy(false);
  };
  const supplement = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ auditId: string }>(`/audits/${aid}/supplements`, { kind: 'domains' }, { idempotencyKey: `${key}-domains` });
      toast.ok('已开始追加执行新增的领域');
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) { toast.error(e, '无法追加执行'); }
    setBusy(false);
  };
  const live_ = plan.domains.filter((d) => !d.removed);
  return (
    <div className={cx(ui.card, ui.cardPad)} style={{ marginBottom: 16 }} data-testid="domain-plan">
      <div className={ui.spread} style={{ marginBottom: 6 }}>
        <b>领域规划（{live_.length} 个领域）</b>
        <div className={ui.row}>
          {plan.supplementable && <Button size="sm" variant="primary" icon="play" loading={busy} onClick={() => void supplement()}>追加执行新增的领域</Button>}
          {open && plan.editable && !adding && <Button size="sm" icon="plus" onClick={() => setAdding(true)}>新增领域</Button>}
          <Button size="sm" variant="ghost" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? '收起' : '展开调整'}</Button>
        </div>
      </div>
      {!open && (
        <div className={ui.row} style={{ flexWrap: 'wrap', gap: 6 }} data-testid="domain-plan-summary">
          {live_.map((d) => {
            const last = d.rounds.at(-1);
            const found = d.rounds.reduce((n, r) => n + (r.findings ?? 0), 0);
            return <Badge key={d.id} tone={last?.status === 'running' ? 'info' : 'neutral'}>{d.id} {d.name}{last ? ` · 第 ${last.round} 轮${ROUND_STATUS[last.status] ?? last.status}` : ' · 未开始'}{found ? ` · ${found} 条发现` : ''}</Badge>;
          })}
        </div>
      )}
      {open && <p className={ui.faint} style={{ fontSize: 12, margin: '0 0 10px' }}>
        威胁建模把系统划分为风险领域，每个领域由一位专家自主探索。{plan.phase === 'experts'
          ? '修改不会阻塞审计：新增的领域会追加一位专家，删除的领域不再开始新的一轮，补充的关注点从该领域的下一轮起生效。'
          : '专家阶段已结束：新增的领域会在审计结束后追加执行。'}
      </p>}
      {open && adding && <AddDomain busy={busy} onCancel={() => setAdding(false)} onAdd={async (body) => { await edit({ op: 'add', ...body }, plan.phase === 'experts' ? '已新增领域：下一轮开始时会运行它的专家' : '已新增领域：审计结束后可追加执行'); setAdding(false); }} />}
      {open && <div className={ui.stack} style={{ gap: 8 }}>
        {plan.domains.map((d) => <DomainRow key={d.id} d={d} plan={plan} busy={busy} onEdit={edit} />)}
      </div>}
    </div>
  );
}

function DomainRow({ d, plan, busy, onEdit }: { d: Domain; plan: DomainPlanDto; busy: boolean; onEdit: (body: Record<string, unknown>, done: string) => Promise<void> }) {
  const [focusing, setFocusing] = useState(false);
  const [text, setText] = useState('');
  // After the expert phase only a late domain that has not run yet can still change.
  const changeable = plan.editable && !d.removed && !d.supplementAuditId && (plan.phase === 'experts' || d.late);
  return (
    <div className={cx(ui.card, ui.cardPad)} style={d.removed ? { opacity: 0.55 } : undefined} data-testid="domain">
      <div className={ui.spread}>
        <div className={ui.row} style={{ flexWrap: 'wrap' }}>
          <span className={ui.mono} style={{ fontSize: 12 }}>{d.id}</span>
          <b>{d.name}</b>
          <Badge tone={d.source === 'user' ? 'accent' : 'neutral'}>{SOURCE[d.source]}</Badge>
          {d.removed && <Badge>已删除</Badge>}
          {d.late && !d.removed && <Badge tone="warn">{d.supplementAuditId ? '已追加执行' : '待追加执行'}</Badge>}
        </div>
        {changeable && (
          <div className={ui.row}>
            <Button size="sm" onClick={() => setFocusing(!focusing)}>补充关注点</Button>
            <Button size="sm" loading={busy} onClick={() => void onEdit({ op: 'remove', domainId: d.id }, `已删除领域：${d.name}`)}>删除</Button>
          </div>
        )}
      </div>
      <p className={ui.muted} style={{ fontSize: 13, margin: '6px 0 0' }}>{d.focus}</p>
      {d.userFocus.length > 0 && <ul style={{ fontSize: 13, margin: '4px 0 0' }}>{d.userFocus.map((f, i) => <li key={i}>审计员补充：{f}</li>)}</ul>}
      <div className={ui.row} style={{ flexWrap: 'wrap', marginTop: 6 }}>{d.categories.map((c) => <Badge key={c}>{categoryLabel(c)}</Badge>)}</div>
      {d.rounds.length > 0 && (
        <div className={ui.faint} style={{ fontSize: 12, marginTop: 6 }}>
          {/* A crossed hunt: each model has its own rounds, so name the model (it read “第 1 轮 … 第 1 轮”). */}
          {d.rounds.map((r, i) => <span key={i} style={{ marginRight: 10 }}>{r.model ? `${r.model.split('/').at(-1)} ` : ''}第 {r.round} 轮：{ROUND_STATUS[r.status] ?? r.status}{r.findings ? `，${r.findings} 条发现` : ''}</span>)}
        </div>
      )}
      {focusing && (
        <div className={ui.row} style={{ marginTop: 8 }}>
          <input className={ui.input} aria-label={`补充 ${d.name} 的关注点`} value={text} onChange={(e) => setText(e.target.value)} maxLength={800} placeholder="例如：重点看导出接口的租户隔离" />
          <Button size="sm" variant="primary" loading={busy} disabled={!text.trim()} onClick={() => void onEdit({ op: 'focus', domainId: d.id, text: text.trim() }, '已补充关注点').then(() => { setText(''); setFocusing(false); })}>保存</Button>
        </div>
      )}
    </div>
  );
}

function AddDomain({ busy, onAdd, onCancel }: { busy: boolean; onAdd: (body: { name: string; focus: string; categories: string[] }) => Promise<void>; onCancel: () => void }) {
  const [name, setName] = useState('');
  const [focus, setFocus] = useState('');
  const [cats, setCats] = useState<Set<string>>(new Set());
  const toggle = (c: string) => setCats((p) => { const n = new Set(p); if (n.has(c)) n.delete(c); else n.add(c); return n; });
  return (
    <div className={cx(ui.card, ui.cardPad)} style={{ marginBottom: 10 }} aria-label="新增风险领域">
      <Field label="领域名称"><input className={ui.input} value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="例如：多租户隔离" /></Field>
      <Field label="关注点（这个系统中具体看什么）"><textarea className={ui.textarea} value={focus} onChange={(e) => setFocus(e.target.value)} maxLength={800} placeholder="例如：租户 id 从哪里来、每个查询是否带租户条件、后台任务是否跨租户" /></Field>
      <div role="group" aria-label="负责的漏洞类别" style={{ marginTop: 8 }}>
        <div className={ui.faint} style={{ fontSize: 12, marginBottom: 4 }}>负责的漏洞类别</div>
        <div className={ui.row} style={{ flexWrap: 'wrap', gap: 8 }}>
          {Object.entries(VULN_CATEGORY).map(([k, l]) => (
            <label key={k} style={{ fontSize: 13 }}><input type="checkbox" checked={cats.has(k)} onChange={() => toggle(k)} /> {l}</label>
          ))}
        </div>
      </div>
      <div className={ui.row} style={{ marginTop: 8 }}>
        <Button size="sm" variant="primary" loading={busy} disabled={!name.trim() || !focus.trim() || !cats.size} onClick={() => void onAdd({ name: name.trim(), focus: focus.trim(), categories: [...cats] })}>新增</Button>
        <Button size="sm" onClick={onCancel}>取消</Button>
      </div>
    </div>
  );
}
