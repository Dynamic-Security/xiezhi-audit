// Connector calls held for approval: the Agent's call carried instructions from the audited code (in its
// arguments, or read by its session). Shows what it wants to call, where, why and from which audit or conversation; the
// user approves (it runs at once) or rejects (nothing runs).
import { useState } from 'react';
import { Link } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { ConnectorWriteDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { fmt } from '../../shared/format/messages';
import { Badge, Button, Icon, cx, ui, useToast } from '../../shared/ui';
import H from './home.module.css';

export function ConnectorWriteItem({ w }: { w: ConnectorWriteDto }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<'approve' | 'reject' | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const decide = async (d: 'approve' | 'reject') => {
    setBusy(d);
    try {
      const r = await api.post<ConnectorWriteDto>(`/connector-writes/${w.id}/${d}`, {});
      if (d === 'reject') toast.ok('已拒绝，未执行');
      else if (r.status === 'executed') toast.ok(`已执行 ${r.connector}.${r.tool}`);
      else toast.error(new Error(r.error ?? '外部系统返回错误'), `${r.connector}.${r.tool} 执行失败`);
    } catch (e) { toast.error(e); }
    setBusy(null);
    await qc.invalidateQueries({ queryKey: ['dashboard'] });
  };
  const from = w.source === 'audit' && w.auditId
    ? <Link to="/audits/$aid" params={{ aid: w.auditId }}>{w.auditTitle ?? '审计'}</Link>
    : w.source === 'conversation' && w.conversationId
      ? <Link to="/conversations/$cid" params={{ cid: w.conversationId }}>{w.conversationTitle ?? '会话'}</Link>
      : <span>推送</span>;
  return (
    <div className={cx(H.item, H.writeItem)} aria-label={`待批准的调用 ${w.connector}.${w.tool}`}>
      <div className={H.itemIcon} style={{ color: 'var(--warn)' }}><Icon name="link" /></div>
      <div className={ui.grow}>
        <div className={H.itemTitle}>
          待批准的调用 {w.connector} · <span className={ui.mono}>{w.tool}</span>
          {w.signals.length > 0
            ? <> <Badge tone="danger" title={`参数中有疑似注入指令：${w.signals.join('、')}`}>参数含疑似注入</Badge></>
            : <> <Badge tone="warn" title="发起调用的会话读到过被审代码中的疑似注入指令">会话读到疑似注入</Badge></>}
        </div>
        <div className={H.itemMeta}>来自 {from} · {fmt.ago(w.createdAt)}{w.reason ? ` · ${w.reason}` : ''}</div>
        <button className={H.writeToggle} onClick={() => setOpen(!open)} aria-expanded={open}>{open ? '收起参数' : '查看参数'}</button>
        {open && (
          <>
            {w.toolDescription && <div className={H.itemMeta} style={{ marginTop: 4 }}>工具说明（来自外部服务）：{w.toolDescription.slice(0, 300)}</div>}
            <pre className={cx(ui.mono, H.writeArgs)}>{JSON.stringify(w.args, null, 2)}</pre>
          </>
        )}
      </div>
      <div className={ui.row} style={{ gap: 6, alignSelf: 'flex-start' }}>
        <Button size="sm" loading={busy === 'reject'} disabled={!!busy} onClick={() => void decide('reject')}>拒绝</Button>
        <Button size="sm" variant="primary" loading={busy === 'approve'} disabled={!!busy} onClick={() => void decide('approve')}>批准执行</Button>
      </div>
    </div>
  );
}
