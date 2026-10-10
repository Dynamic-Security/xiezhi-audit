// AI conversation as a full page: the shared thread (Thread.tsx),
// per-conversation model, rename / archive / delete; cards open the vulnerability or audit in the side panel.
// The AI panel shows the same threads next to other pages.
import { useState } from 'react';
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { ConversationDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { qk, useAudit, useConversation, useConversationSearch, useConversations, useModelSettings, useProviders } from '../../shared/api/queries';
import { AUDIT_STATUS, fmt } from '../../shared/format/messages';
import { AuditStatusBadge, Badge, Button, ConfirmDialog, Icon, Loading, cx, ui, useToast } from '../../shared/ui';
import { PageLayout, TopBar } from '../layout/AppShell';
import { VulnPanel, VulnPanelTitle } from '../vulns/VulnPanel';
import { ConversationThread } from './Thread';
import C from './conversations.module.css';

export { clientId } from './Thread';

function ModelPicker({ conv }: { conv: ConversationDto }) {
  const providers = useProviders();
  const settings = useModelSettings();
  const qc = useQueryClient();
  const toast = useToast();
  const def = settings.data?.stageModels.chat ?? settings.data?.defaultModel ?? null;
  const options = (providers.data ?? []).flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`));
  const change = async (v: string) => {
    try {
      const [provider, ...rest] = v.split('/');
      await api.patch(`/conversations/${conv.id}`, { model: v ? { provider, model: rest.join('/') } : null });
      await qc.invalidateQueries({ queryKey: qk.conversation(conv.id) });
    } catch (e) { toast.error(e); }
  };
  return (
    <select className={ui.select} style={{ height: 30, width: 220, textOverflow: 'ellipsis' }} aria-label="对话模型" value={conv.model ?? ''} onChange={(e) => void change(e.target.value)}>
      <option value="">默认{def ? `（${def.provider}/${def.model}）` : ''}</option>
      {options.map((o) => <option key={o} value={o}>{o}</option>)}
    </select>
  );
}

function AuditMini({ aid }: { aid: string }) {
  const a = useAudit(aid);
  if (!a.data) return <Loading rows={2} />;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 16 }}>
      <div className={ui.row}><b>{a.data.title}</b><AuditStatusBadge status={a.data.status} /></div>
      <div className={ui.muted} style={{ fontSize: 13 }}>{AUDIT_STATUS[a.data.status]}</div>
      <Link to="/audits/$aid" params={{ aid }}>打开审计详情</Link>
    </div>
  );
}

export function ConversationPage() {
  const { cid } = useParams({ from: '/conversations/$cid' });
  const search = useSearch({ from: '/conversations/$cid' });
  const navigate = useNavigate();
  const conv = useConversation(cid);
  const qc = useQueryClient();
  const toast = useToast();
  const [renaming, setRenaming] = useState(false);
  const [title, setTitle] = useState('');
  const [deleting, setDeleting] = useState(false);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: qk.conversation(cid) });
    void qc.invalidateQueries({ queryKey: ['conversations'] });
  };
  const open = (panel: string) => void navigate({ to: '/conversations/$cid', params: { cid }, search: { panel }, replace: true });
  const archive = async (status: 'active' | 'archived') => {
    try { await api.patch(`/conversations/${cid}`, { status }); refresh(); toast.ok(status === 'archived' ? '已归档' : '已恢复'); } catch (e) { toast.error(e); }
  };
  const rename = async () => {
    try { await api.patch(`/conversations/${cid}`, { title }); setRenaming(false); refresh(); } catch (e) { toast.error(e); }
  };

  const panel = search.panel;
  const panelNode = panel?.startsWith('vuln:') ? <VulnPanel vid={panel.slice(5)} /> : panel?.startsWith('audit:') ? <AuditMini aid={panel.slice(6)} /> : undefined;
  const panelTitle = panel?.startsWith('vuln:') ? <VulnPanelTitle vid={panel.slice(5)} /> : panel ? <b>审计</b> : undefined;
  const c = conv.data;

  return (
    <>
      <TopBar ai={false} crumbs={[{ label: '会话', to: '/conversations' }, { label: c?.title ?? '…' }]} actions={c && (
        <>
          <ModelPicker conv={c} />
          <Button size="sm" variant="ghost" icon="edit" aria-label="重命名" onClick={() => { setTitle(c.title); setRenaming(true); }} />
          <Button size="sm" variant="ghost" icon="archive" onClick={() => void archive(c.status === 'archived' ? 'active' : 'archived')}>{c.status === 'archived' ? '取消归档' : '归档'}</Button>
          <Button size="sm" variant="ghost" icon="trash" aria-label="删除会话" onClick={() => setDeleting(true)} />
        </>
      )} />
      <PageLayout flush noAi panel={panelNode} panelTitle={panelTitle} panelKey={panel}
        onClosePanel={() => void navigate({ to: '/conversations/$cid', params: { cid }, search: {}, replace: true })}>
        <div className={C.pageWrap}>
          {renaming && (
            <div className={ui.row} style={{ padding: '10px 16px', borderBottom: '1px solid var(--border)' }}>
              <input className={ui.input} value={title} onChange={(e) => setTitle(e.target.value)} aria-label="会话标题" onKeyDown={(e) => { if (e.key === 'Enter') void rename(); }} />
              <Button size="sm" variant="primary" onClick={() => void rename()}>保存</Button>
              <Button size="sm" variant="ghost" onClick={() => setRenaming(false)}>取消</Button>
            </div>
          )}
          <ConversationThread cid={cid} onOpen={open} />
        </div>
      </PageLayout>
      <ConfirmDialog open={deleting} onClose={() => setDeleting(false)} level="destructive" title="删除会话" confirmText="删除"
        onConfirm={async () => { try { await api.del(`/conversations/${cid}`); setDeleting(false); void qc.invalidateQueries({ queryKey: ['conversations'] }); void navigate({ to: '/conversations' }); } catch (e) { toast.error(e); } }}>
        删除后消息与卡片都会移除；尚未处理的 AI 建议会记为驳回。已应用的修订保留在漏洞的修订历史中。
      </ConfirmDialog>
    </>
  );
}

/** A new conversation as a full page: created by its first message, then the address becomes its own. */
export function NewConversationPage() {
  const navigate = useNavigate();
  return (
    <>
      <TopBar ai={false} crumbs={[{ label: '会话', to: '/conversations' }, { label: '新会话' }]} />
      <PageLayout flush noAi>
        <div className={C.pageWrap}>
          <ConversationThread cid={null} onCreated={(c) => void navigate({ to: '/conversations/$cid', params: { cid: c.id }, replace: true })} />
        </div>
      </PageLayout>
    </>
  );
}

/** Conversation list (最近 / 已归档, search by title or message text). */
export function ConversationsPage() {
  const [tab, setTab] = useState<'active' | 'archived'>('active');
  const [q, setQ] = useState('');
  const list = useConversations(tab);
  const found = useConversationSearch(q);
  const rows = q.trim() ? found.data?.filter((c) => c.status === tab) : list.data;
  const navigate = useNavigate();
  return (
    <>
      <TopBar crumbs={[{ label: '会话' }]} actions={<Button size="sm" variant="primary" icon="plus" onClick={() => void navigate({ to: '/conversations/new' })}>新建会话</Button>} />
      <PageLayout narrow>
        <div className={ui.row} style={{ gap: 6, margin: '8px 0 14px' }}>
          {(['active', 'archived'] as const).map((t) => <button key={t} className={cx(ui.chip, tab === t && ui.chipOn)} onClick={() => setTab(t)}>{t === 'active' ? '最近' : '已归档'}</button>)}
          <span className={ui.grow} />
          <input className={ui.input} style={{ width: 260, height: 30 }} placeholder="搜索标题或消息内容" aria-label="搜索会话" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        {(q.trim() ? found.isLoading : list.isLoading) && <Loading rows={4} />}
        {rows && rows.length === 0 && <div className={ui.card} style={{ padding: 24, textAlign: 'center' }}><span className={ui.muted}>{q.trim() ? '没有匹配的会话' : tab === 'active' ? '还没有会话。可以在任意页面打开右侧的 AI 面板，或新建一个会话。' : '没有已归档的会话'}</span></div>}
        {rows && rows.length > 0 && (
          <div className={cx(ui.card, C.list)}>
            {rows.map((c) => (
              <Link key={c.id} to="/conversations/$cid" params={{ cid: c.id }} className={C.row}>
                <Icon name="message" />
                <div className={ui.grow} style={{ minWidth: 0 }}>
                  <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.title}</div>
                  <div className={ui.faint} style={{ fontSize: 12 }}>{c.lastMessageAt ? fmt.ago(c.lastMessageAt) : fmt.ago(c.createdAt)}{c.mentions.length ? ` · ${c.mentions.map((m) => m.label).join('、')}` : ''}</div>
                </div>
                {c.streaming && <Badge tone="accent" pulse dot>回复中</Badge>}
                {c.pendingCards > 0 && <Badge tone="warn">{c.pendingCards} 待确认</Badge>}
              </Link>
            ))}
          </div>
        )}
      </PageLayout>
    </>
  );
}
