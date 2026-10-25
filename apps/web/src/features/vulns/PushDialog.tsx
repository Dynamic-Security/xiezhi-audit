// “推送到…”: push vulnerabilities to an external system following a push guide
// from the knowledge base. By default the push runs at once; a preview must be confirmed when the guide
// asks for it or the payload carries suspected injected instructions. “先预览” always previews.
import { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { PushDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { usePushGuides } from '../../shared/api/queries';
import { fmt } from '../../shared/format/messages';
import { Badge, Button, Dialog, EmptyState, Field, cx, ui } from '../../shared/ui';

const ACTION: Record<string, string> = { create: '新建', update: '更新', skip: '跳过' };

export function PushDialog({ open, onClose, projectId, vulns }: { open: boolean; onClose: () => void; projectId: string; vulns: { id: string; displayNo: number }[] }) {
  const qc = useQueryClient();
  const guides = usePushGuides(projectId, open);
  const [name, setName] = useState('');
  const [res, setRes] = useState<PushDto | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const list = guides.data ?? [];
  const g = list.find((x) => x.name === name) ?? list.find((x) => x.available) ?? list[0];
  useEffect(() => { if (!open) { setRes(null); setErr(null); } }, [open]);
  const fail = (e: unknown) => setErr(e instanceof Error ? ((e as { hint?: string }).hint ?? e.message) : String(e));
  const finish = async (r: PushDto) => {
    setRes(r);
    if (r.status === 'done') await Promise.all(vulns.map((v) => qc.invalidateQueries({ queryKey: ['vuln', v.id, 'sync'] })));
  };
  const start = async (preview: boolean) => {
    setErr(null);
    setBusy(preview ? 'preview' : 'push');
    try { await finish(await api.post<PushDto>(`/projects/${projectId}/pushes`, { skill: g!.name, vulnIds: vulns.map((v) => v.id), ...(preview ? { preview: true } : {}) })); } catch (e) { fail(e); } finally { setBusy(null); }
  };
  const confirm = async () => {
    setErr(null);
    setBusy('confirm');
    try { await finish(await api.post<PushDto>(`/pushes/${res!.id}/confirm`, { token: res!.token, payloadHash: res!.payloadHash })); } catch (e) { fail(e); } finally { setBusy(null); }
  };
  const close = () => {
    if (res?.status === 'awaiting_confirm') void api.del(`/pushes/${res.id}`).catch(() => undefined);
    onClose();
  };
  const awaiting = res?.status === 'awaiting_confirm';
  return (
    <Dialog open={open} onClose={close} wide title={`推送 ${vulns.map((v) => `V-${v.displayNo}`).join('、')}`} footer={<>
      {err && <div role="alert" className={ui.error} style={{ marginRight: 'auto' }}>{err}</div>}
      <Button onClick={close}>{res && !awaiting ? '完成' : '取消'}</Button>
      {!res && <Button loading={busy === 'preview'} disabled={!g?.available || !!busy} onClick={() => void start(true)}>先预览</Button>}
      {!res && <Button variant="primary" icon="send" loading={busy === 'push'} disabled={!g?.available || !!busy} onClick={() => void start(false)}>推送</Button>}
      {awaiting && <Button variant="primary" icon="check" loading={busy === 'confirm'} onClick={() => void confirm()}>确认推送</Button>}
    </>}>
      {!list.length ? (
        <EmptyState icon="send" title="没有推送指引">在 知识管理 中新建“推送指引”类 skill，写明目标连接器与写操作（可参考内置的 jira-issue-push）。</EmptyState>
      ) : !res ? (
        <>
          <Field label="推送指引">
            <select className={ui.input} value={g?.name ?? ''} onChange={(e) => setName(e.target.value)}>
              {list.map((x) => <option key={x.name} value={x.name}>{x.name}{x.available ? '' : '（不可用）'}</option>)}
            </select>
          </Field>
          {g && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 13 }}>
              <div>{g.description}</div>
              <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
                <Badge>连接器 {g.connector}</Badge><Badge>操作 {g.operation}{g.updateOperation ? ` / 再次推送 ${g.updateOperation}` : ''}</Badge>
                <Badge tone={g.template ? 'ok' : 'accent'}>{g.template ? '模板渲染' : 'AI 按指引填写'}</Badge>
                {g.confirm && <Badge tone="warn">每次需确认</Badge>}
              </div>
              {!g.available && <div role="alert" className={ui.error}>{g.reason}</div>}
              <div className={ui.faint} style={{ fontSize: 12 }}>已推送过的漏洞按指引的更新操作处理；内容未变化的会跳过。内容疑似含面向 AI 的指令时会先预览。</div>
            </div>
          )}
        </>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {awaiting && <div className={ui.banner} role="note">需要确认后才会写入 {res.connectorName}：{res.confirmReasons.join('；') || '你选择了先预览'}。确认在 5 分钟内有效。</div>}
          {res.tokens > 0 && <div className={ui.faint} style={{ fontSize: 12 }}>参数由对话模型按指引填写（{fmt.tokens(res.tokens)} tokens），请核对。</div>}
          {res.items.map((i) => (
            <div key={i.vulnId} className={ui.card} style={{ padding: 10, display: 'flex', flexDirection: 'column', gap: 6 }} aria-label={`推送 V-${i.displayNo}`}>
              <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
                <b>V-{i.displayNo}</b><span className={ui.ellipsis}>{i.title}</span>
                <Badge tone={i.action === 'skip' ? 'neutral' : 'accent'}>{ACTION[i.action]}{i.operation ? ` · ${i.operation}` : ''}</Badge>
                {i.reasons.map((r) => <Badge key={r} tone="warn">{r}</Badge>)}
                {i.result && (i.result.ok ? <Badge tone="ok">已推送</Badge> : <Badge tone="danger">失败</Badge>)}
              </div>
              {i.skipReason && <div className={ui.faint} style={{ fontSize: 12 }}>{i.skipReason}</div>}
              {i.result?.externalId && <div style={{ fontSize: 13 }}>外部记录：{i.result.externalUrl ? <a href={i.result.externalUrl} target="_blank" rel="noreferrer noopener">{i.result.externalId}</a> : i.result.externalId}</div>}
              {i.result?.error && <div className={ui.error} style={{ fontSize: 12 }}>{i.result.error}</div>}
              {i.action !== 'skip' && !i.result && i.steps.map((st, k) => (
                <div key={k}>
                  {i.steps.length > 1 && <div className={ui.faint} style={{ fontSize: 12 }}>{k + 1}. {st.operation}</div>}
                  <pre className={cx(ui.mono, ui.pre)} style={{ fontSize: 12, maxHeight: 220, overflow: 'auto', margin: 0 }}>{JSON.stringify(st.args, null, 2)}</pre>
                </div>
              ))}
              {i.result && i.steps.length > 1 && <div className={ui.faint} style={{ fontSize: 12 }}>{i.steps.map((st) => `${st.operation}${st.ok === true ? ' ✓' : st.ok === false ? ' ✗' : ' —'}`).join(' → ')}</div>}
            </div>
          ))}
        </div>
      )}
    </Dialog>
  );
}
