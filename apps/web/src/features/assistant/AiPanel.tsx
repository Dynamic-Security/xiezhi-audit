// The AI tab of the right-hand panel. Which conversation it shows:
// - a vulnerability or audit in view → the latest conversation that references it, else a new one;
// - anything else → the general conversation, with the current object offered as a reference;
// - the user can switch to a recent conversation, start a new one, or open it as a full page.
// Cards that point to a vulnerability open it inside the panel, with a way back.
import { useEffect, useState } from 'react';
import { Link } from '@tanstack/react-router';
import { latestConversationAbout, useAudit, useConversation, useConversations } from '../../shared/api/queries';
import { ApiError } from '../../shared/api/client';
import { fmt } from '../../shared/format/messages';
import { Button, Icon, cx, ui, useDismiss } from '../../shared/ui';
import { ConversationThread } from '../conversations/Thread';
import { VulnPanel } from '../vulns/VulnPanel';
import { scopeKey, useAi } from './ai';
import { AuditConversation } from './AuditConversation';
import S from './assistant.module.css';

function History({ current, onPick }: { current: string | null; onPick: (cid: string | null) => void }) {
  const [open, setOpen] = useState(false);
  const list = useConversations('active');
  const ref = useDismiss(open, () => setOpen(false));
  return (
    <div className={S.menuWrap} ref={ref}>
      <Button size="sm" variant="ghost" icon="clock" aria-label="最近会话" aria-expanded={open} onClick={() => setOpen(!open)} />
      {open && (
        <div className={cx(ui.menu, S.menu)} role="menu">
          <button className={ui.menuItem} role="menuitem" onClick={() => { onPick(null); setOpen(false); }}><Icon name="plus" size={14} />新建会话</button>
          {(list.data ?? []).slice(0, 12).map((c) => (
            <button key={c.id} role="menuitem" className={cx(ui.menuItem, c.id === current && S.menuOn)} onClick={() => { onPick(c.id); setOpen(false); }}>
              <span className={ui.ellipsis} style={{ flex: 1 }}>{c.title}</span><span className={ui.faint} style={{ fontSize: 11 }}>{fmt.ago(c.lastMessageAt ?? c.createdAt)}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function AuditPanel({ auditId, label }: { auditId: string; label: string }) {
  const a = useAudit(auditId);
  const cid = a.data?.conversationId ?? null;
  return (
    <div className={S.body}>
      <div className={S.bar}>
        <span className={cx(ui.ellipsis, S.title)}>审计会话 · {label}</span>
        {cid && <Link to="/conversations/$cid" params={{ cid }} className={S.expand} title="展开为整页" aria-label="展开为整页"><Icon name="external" size={14} /></Link>}
      </div>
      <AuditConversation auditId={auditId} />
    </div>
  );
}

export function AiPanelBody() {
  const ai = useAi();
  const key = scopeKey(ai.scope);
  const assigned = ai.assigned(key);
  const [peek, setPeek] = useState<string | null>(null);

  // Continue the object's latest conversation, or start a new one.
  const { assign, scope } = ai;
  const scopeKind = scope?.kind;
  const scopeId = scope?.id;
  useEffect(() => {
    if (assigned !== undefined) return;
    if (key === 'general' || !scopeKind || !scopeId) { assign(key, null); return; }
    let live = true;
    latestConversationAbout(scopeKind, scopeId).then((c) => { if (live) assign(key, c?.id ?? null); }, () => { if (live) assign(key, null); });
    return () => { live = false; };
  }, [key, assigned, assign, scopeKind, scopeId]);
  useEffect(() => { setPeek(null); }, [key, assigned]);

  const cid = assigned ?? null;
  const conv = useConversation(cid ?? '', { enabled: !!cid });
  // The remembered conversation is gone (deleted, or another data directory behind the same address): start a new one
  // instead of showing “已失效或已删除” in the panel for good.
  const gone = !!cid && conv.error instanceof ApiError && conv.error.status === 404;
  useEffect(() => { if (gone) assign(key, null); }, [gone, key, assign]);
  const context = ai.scope ? { kind: ai.scope.kind, id: ai.scope.id, label: ai.scope.label, valid: true } : null;

  if (ai.scope?.kind === 'audit') {
    // An audit's AI tab is its own conversation plus the live card.
    return <AuditPanel auditId={ai.scope.id} label={ai.scope.label} />;
  }
  if (peek?.startsWith('vuln:')) {
    return (
      <div className={S.body}>
        <div className={S.bar}><Button size="sm" variant="ghost" icon="chevronLeft" onClick={() => setPeek(null)}>返回对话</Button></div>
        <div className={S.peek}><VulnPanel vid={peek.slice(5)} scoped={false} /></div>
      </div>
    );
  }
  return (
    <div className={S.body}>
      <div className={S.bar}>
        <span className={cx(ui.ellipsis, S.title)} title={conv.data?.title}>{cid ? conv.data?.title ?? '…' : '新会话'}</span>
        <History current={cid} onPick={(id) => ai.assign(key, id)} />
        <Button size="sm" variant="ghost" icon="plus" aria-label="新建会话" onClick={() => ai.assign(key, null)} />
        {cid && <Link to="/conversations/$cid" params={{ cid }} className={S.expand} title="展开为整页" aria-label="展开为整页"><Icon name="external" size={14} /></Link>}
      </div>
      {assigned === undefined
        ? <div className={S.loading}><span className={ui.spinner} /></div>
        : <ConversationThread key={cid ?? `draft:${key}`} cid={cid} compact context={context}
            onCreated={(c) => ai.assign(key, c.id)} onOpen={(p) => { if (p.startsWith('vuln:')) setPeek(p); }} />}
    </div>
  );
}
