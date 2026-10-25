// 同步到在线文档: pick a sync guide (push guides with target threat_model), preview the
// operations, confirm once; the document link is shown on the threat model afterwards.
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { PushGuideDto, ThreatSyncDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { fmt } from '../../shared/format/messages';
import { Badge, Button, Dialog, EmptyState, Field, Icon, Loading, cx, ui, useToast } from '../../shared/ui';

export function ThreatSyncButton({ pid, tid, disabled }: { pid: string; tid: string; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button size="sm" icon="external" disabled={disabled} title={disabled ? '先生成威胁模型' : undefined} onClick={() => setOpen(true)}>同步到在线文档</Button>
      {open && <SyncDialog pid={pid} tid={tid} onClose={() => setOpen(false)} />}
    </>
  );
}

function SyncDialog({ pid, tid, onClose }: { pid: string; tid: string; onClose: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const guides = useQuery({ queryKey: ['threat-sync-guides', pid], queryFn: () => api.get<PushGuideDto[]>(`/projects/${pid}/threat-sync-guides`) });
  const [skill, setSkill] = useState('');
  const [doc, setDoc] = useState('');
  const [plan, setPlan] = useState<ThreatSyncDto | null>(null);
  const [busy, setBusy] = useState(false);
  const list = guides.data ?? [];
  const chosen = skill || (list.length === 1 ? list[0]!.name : '');
  const guide = list.find((g) => g.name === chosen);
  const preview = async () => {
    setBusy(true);
    try { setPlan(await api.post<ThreatSyncDto>(`/threat-models/${tid}/sync`, { skill: chosen, ...(doc.trim() ? { document: doc.trim() } : {}) })); } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  const confirm = async () => {
    if (!plan?.token) return;
    setBusy(true);
    try {
      const done = await api.post<ThreatSyncDto>(`/threat-syncs/${plan.id}/confirm`, { token: plan.token, payloadHash: plan.payloadHash });
      setPlan(done);
      if (done.result?.ok) toast.ok('已同步');
      await qc.invalidateQueries({ queryKey: ['threat-model', tid] });
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  const close = () => { if (plan?.status === 'awaiting_confirm') void api.del(`/threat-syncs/${plan.id}`).catch(() => undefined); onClose(); };
  const awaiting = plan?.status === 'awaiting_confirm';
  return (
    <Dialog open onClose={close} wide title="同步到在线文档" footer={<>
      <Button onClick={close}>{plan?.status === 'done' ? '关闭' : '取消'}</Button>
      {!plan && <Button variant="primary" loading={busy} disabled={!guide?.available} onClick={() => void preview()}>生成预览</Button>}
      {awaiting && <Button variant="primary" loading={busy} onClick={() => void confirm()}>确认写入</Button>}
    </>}>
      {guides.isLoading ? <Loading /> : !list.length ? (
        <EmptyState icon="external" title="没有同步指引">在知识库中添加“推送指引”类知识并设置 <code>push.target: threat_model</code>；内置示例 feishu-doc-threat-model-sync 需要名为 Feishu 的飞书 MCP 连接器。</EmptyState>
      ) : !plan ? (
        <>
          <Field label="同步指引" hint={guide ? `${guide.connector} · ${guide.operation}${guide.updateOperation ? ` / 更新：${guide.updateOperation}` : ''}` : undefined}>
            <select className={ui.input} value={chosen} onChange={(e) => setSkill(e.target.value)}>
              {list.length > 1 && <option value="">选择同步指引…</option>}
              {list.map((g) => <option key={g.name} value={g.name}>{g.name}{g.available ? '' : '（不可用）'}</option>)}
            </select>
          </Field>
          {guide && !guide.available && <div className={ui.banner} role="status"><Icon name="alert" />{guide.reason}</div>}
          {guide && <p className={ui.muted} style={{ margin: 0 }}>{guide.description}</p>}
          <Field label="同步到已有文档（可选）" hint="填写后写入这份文档（会覆盖其正文），不新建；不填时按同步指引新建文档（内置飞书指引经 lark-cli 以你的身份新建在你的云空间）。之后再次同步会覆盖同一份文档。">
            <input className={ui.input} value={doc} maxLength={2000} placeholder="https://xxx.feishu.cn/docx/…" onChange={(e) => setDoc(e.target.value)} />
          </Field>
          <p className={ui.faint} style={{ fontSize: 12, margin: 0 }}>同步按当前的研判状态渲染报告；先生成预览，确认后才写入外部文档。只推送，不会从文档回写风险状态。</p>
        </>
      ) : plan.action === 'skip' ? (
        <p>{plan.skipReason}</p>
      ) : (
        <div className={ui.stack}>
          <div className={ui.row} style={{ gap: 8 }}>
            <Badge tone={plan.action === 'create' ? 'accent' : 'info'}>{plan.action === 'create' ? '新建文档' : `更新文档 ${plan.existing?.externalId ?? ''}`}</Badge>
            <span className={ui.faint} style={{ fontSize: 12 }}>{plan.connectorName} · {plan.skill}{plan.tokens ? ` · ${fmt.tokens(plan.tokens)} tokens` : ''}</span>
          </div>
          {plan.reasons.length > 0 && <div className={ui.faint} style={{ fontSize: 12 }}>{plan.reasons.join('；')}</div>}
          {plan.steps.map((st, i) => (
            <div key={i} className={cx(ui.card, ui.cardPad)}>
              <div className={ui.row} style={{ gap: 6 }}><b className={ui.mono}>{st.operation}</b>{st.ok === true && <Badge tone="ok">成功</Badge>}{st.ok === false && <Badge tone="danger">失败</Badge>}</div>
              {st.error && <div className={ui.error}>{st.error}</div>}
              <pre className={cx(ui.pre, ui.mono)} style={{ maxHeight: 260, overflow: 'auto', whiteSpace: 'pre-wrap', fontSize: 12 }}>{JSON.stringify(st.args, null, 2).slice(0, 20_000)}</pre>
            </div>
          ))}
          {plan.result && (plan.result.ok
            ? <div role="status"><Badge tone="ok">已同步</Badge> {plan.result.externalUrl ? <a href={plan.result.externalUrl} target="_blank" rel="noreferrer">{plan.result.externalUrl}</a> : plan.result.externalId}{plan.result.error && <div className={ui.faint} style={{ fontSize: 12 }}>{plan.result.error}</div>}</div>
            : <div className={ui.error} role="alert">同步失败：{plan.result.error}</div>)}
        </div>
      )}
    </Dialog>
  );
}
