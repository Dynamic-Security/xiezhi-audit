// The AI tab of an audit: the audit's own conversation — ask the Agent about progress and
// judgements (read-only, on the audit's snapshot), or steer the running audit (补充信息 / 调整重点 / 深入分析,
// sent as interventions, whose receipts appear on the live card at the end of the thread). The conversation is
// created on the first message (the one the audit was started from, or a new one bound to it).
import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { ConversationDto, InterventionKind } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { useAudit } from '../../shared/api/queries';
import { INTERVENTION } from '../../shared/format/messages';
import { cx, ui, useToast } from '../../shared/ui';
import { AuditLiveCard } from '../audits/AuditLive';
import { ConversationThread } from '../conversations/Thread';
import S from './assistant.module.css';

const TERMINAL = ['completed', 'partial', 'failed', 'cancelled'];
type Kind = 'ask' | Exclude<InterventionKind, 'skip' | 'pause'>;
const PLACEHOLDER: Record<Kind, string> = {
  ask: '问问 Agent：现在进展如何？V-1 为什么判定成立？',
  supplement: '补充业务或部署信息，例如：网关已对 /admin/** 统一鉴权',
  refocus: '例如：先别看日志模块，优先支付回调',
  deep_dive: '例如：深入分析 /order/export 的归属校验',
};

export function AuditConversation({ auditId }: { auditId: string }) {
  const a = useAudit(auditId);
  const qc = useQueryClient();
  const toast = useToast();
  const [kind, setKind] = useState<Kind>('ask');
  const live = !!a.data && !TERMINAL.includes(a.data.status);
  const cid = a.data?.conversationId ?? null;
  const steer = live ? kind : 'ask';

  const ensure = async () => {
    const c = await api.post<ConversationDto>(`/audits/${auditId}/conversation`);
    await qc.invalidateQueries({ queryKey: ['audit', auditId] });
    return c;
  };
  const before = async (text: string): Promise<'handled' | 'continue' | 'failed'> => {
    if (steer === 'ask') return 'continue';
    try {
      await api.post(`/audits/${auditId}/interventions`, { kind: steer, text });
      await qc.invalidateQueries({ queryKey: ['audit', auditId, 'trajectory'] });
      return 'handled';
    } catch (e) { toast.error(e); return 'failed'; }
  };
  if (!a.data) return <div className={S.loading}><span className={ui.spinner} /></div>;
  return (
    <ConversationThread key={cid ?? 'draft'} cid={cid} compact ensureConversation={ensure} onBeforeSend={before}
      context={{ kind: 'audit', id: auditId, label: `${a.data.projectName} · ${a.data.title}`, valid: true }}
      footer={<AuditLiveCard auditId={auditId} showInterventions />} footerAuditId={auditId}
      placeholder={PLACEHOLDER[steer]}
      suggestions={live ? ['现在进展如何？', '目前有哪些疑点还没有结论？', '为什么这么安排审计重点？'] : ['总结这次审计的结论和未完成的部分', '哪些漏洞还需要人工确认？为什么？']}
      composerTop={live ? (
        <div className={S.kinds} role="radiogroup" aria-label="消息类型">
          {(['ask', 'supplement', 'refocus', 'deep_dive'] as const).map((k) => (
            <button key={k} role="radio" aria-checked={kind === k} className={cx(ui.chip, kind === k && ui.chipOn)} onClick={() => setKind(k)}>
              {k === 'ask' ? '提问' : INTERVENTION[k]}
            </button>
          ))}
          <span className={S.kindHint}>{kind === 'ask' ? 'Agent 基于本次审计回答' : '作为数据送给正在运行的分析，不改变已冻结的配置'}</span>
        </div>
      ) : undefined} />
  );
}
