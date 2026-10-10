// Conversation cards: investigation, revision suggestion (also merge / split),
// audit / reverify / hunt plan, live audit status, connector draft. Only the user applies a card; revision
// cards send the vulnerability revision they were made against (If-Match), a changed vulnerability is refused.
import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { CardDto } from '@xiezhi/contracts';
import { ApiError, api } from '../../shared/api/client';
import { CONFIRM, HANDLING, SEVERITY, categoryLabel, fmt } from '../../shared/format/messages';
import { Badge, Button, Icon, cx, ui, useToast } from '../../shared/ui';
import { AuditLiveCard } from '../audits/AuditLive';
import { askNotifyPermission } from '../../shared/notify';
import C from './conversations.module.css';

const SCENE: Record<string, string> = { full: '全量审计', incremental: '增量审计', reverify: '漏洞复验', risk_hunt: '风险排查' };

/** The strategy override of an audit card as readable lines (was raw JSON). */
function strategyLines(o: unknown): [string, string][] {
  if (!o || typeof o !== 'object') return [];
  const s = o as { focus?: { categories?: string[]; text?: string }; scope?: { include?: string[]; exclude?: string[] }; budget?: { tokens?: number; durationSec?: number }; stages?: { challenge?: boolean; adversarialReview?: boolean; logicReview?: boolean; threatHypotheses?: boolean; domainHunt?: boolean } };
  const out: [string, string][] = [];
  if (s.focus?.categories?.length) out.push(['关注类别', s.focus.categories.map(categoryLabel).join('、')]);
  if (s.focus?.text) out.push(['关注点', s.focus.text]);
  if (s.scope?.include?.length) out.push(['只审计', s.scope.include.join('、')]);
  if (s.scope?.exclude?.length) out.push(['排除', s.scope.exclude.join('、')]);
  if (s.budget?.tokens || s.budget?.durationSec) out.push(['预算', [s.budget.tokens ? `${fmt.compact(s.budget.tokens)} tokens` : '', s.budget.durationSec ? `${Math.round(s.budget.durationSec / 60)} 分钟` : ''].filter(Boolean).join(' · ')]);
  const review = s.stages?.adversarialReview ?? s.stages?.challenge;
  if (review !== undefined) out.push(['对抗复核', review ? '开启' : '关闭']);
  if (s.stages?.threatHypotheses !== undefined) out.push(['风险假设先行', s.stages.threatHypotheses ? '开启' : '关闭']);
  return out;
}

type AnyCard = Pick<CardDto, 'kind' | 'state' | 'data'> & { id: string; result?: CardDto['result']; targetRevision?: number | null; progress?: CardDto['progress'] };

function refs(ev: unknown): string[] {
  return Array.isArray(ev) ? ev.map((e: { repo?: string; path: string; startLine: number; endLine: number }) => `${e.repo ? `${e.repo}:` : ''}${e.path}:${e.startLine}-${e.endLine}`) : [];
}

function StateBadge({ state, card }: { state: CardDto['state']; card?: AnyCard }) {
  // every proposed value was set elsewhere (detail panel, list, another card) — the card is settled.
  if (state === 'applied' && (card?.result as { via?: string } | null | undefined)?.via === 'elsewhere') return <Badge tone="ok" dot>已在别处处理</Badge>;
  if (state === 'pending' && card?.progress?.conflict.length) return <Badge tone="warn" dot>漏洞已在别处修改</Badge>;
  if (state === 'applied') return <Badge tone="ok" dot>已应用</Badge>;
  if (state === 'dismissed') return <Badge>已驳回</Badge>;
  if (state === 'expired') return <Badge>已失效</Badge>;
  if (state === 'pending') return <Badge tone="accent" dot>待你确认</Badge>;
  return null;
}

function change(to: Record<string, string>, from: Record<string, string>, progress?: CardDto['progress']): string[] {
  // A pending card says which proposed values were already set elsewhere and which were changed to something else.
  const note = (k: string) => (progress?.done.includes(k) ? '（已在别处完成）' : progress?.conflict.includes(k) ? '（已在别处改为其他值，改回后才能应用）' : '');
  const out: string[] = [];
  if (to.confirmStatus) out.push(`确认状态：${CONFIRM[from.confirmStatus ?? ''] ?? from.confirmStatus} → ${CONFIRM[to.confirmStatus] ?? to.confirmStatus}${note('confirmStatus')}`);
  if (to.handlingStatus) out.push(`处理状态：${HANDLING[from.handlingStatus ?? ''] ?? from.handlingStatus} → ${HANDLING[to.handlingStatus] ?? to.handlingStatus}${note('handlingStatus')}`);
  if (to.severity) out.push(`严重度：${SEVERITY[from.severity ?? ''] ?? from.severity} → ${SEVERITY[to.severity] ?? to.severity}${note('severity')}`);
  return out;
}

export function ConversationCard({ card, live, onOpen, onChanged }: {
  card: AnyCard; live?: boolean; onOpen?: (panel: string) => void; onChanged?: () => void;
}) {
  const d = card.data as Record<string, unknown>;
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const decide = async (how: 'apply' | 'dismiss') => {
    setBusy(true);
    if (how === 'apply' && card.kind === 'audit_plan') askNotifyPermission(); // the audit will run in the background
    try {
      const r = await api.post<CardDto>(`/cards/${card.id}/${how}`, {}, how === 'apply' && card.targetRevision != null ? { ifMatch: card.targetRevision } : {});
      toast.ok(how === 'apply' ? '已应用' : '已驳回');
      void qc.invalidateQueries({ queryKey: ['vuln'] });
      void qc.invalidateQueries({ queryKey: ['vulns'] });
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
      onChanged?.();
      const res = r.result ?? {};
      if (how === 'apply' && typeof res.basisId === 'string') {
        void navigate({ to: '/hunts/new', search: { basis: res.basisId, ...((res.projectIds as string[] | undefined)?.length ? { projects: res.projectIds as string[] } : {}) } });
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 412) toast.error(new Error('漏洞在建议之后已被修改，请重新查看后再决定（可以让 AI 基于最新状态重新评估）'));
      else toast.error(e);
    }
    setBusy(false);
  };
  const conflict = !!card.progress?.conflict.length;
  const actions = (applyText: string, dismissable = true) => card.state === 'pending' && (
    <div className={C.cardActions}>
      <Button size="sm" variant="primary" icon="check" loading={busy} disabled={live || conflict} title={live ? '回复生成中' : conflict ? '漏洞已在别处改为其他值，改回后才能应用' : undefined} onClick={() => void decide('apply')}>{applyText}</Button>
      {dismissable && <Button size="sm" variant="ghost" disabled={busy || live} onClick={() => void decide('dismiss')}>驳回</Button>}
    </div>
  );

  if (card.kind === 'investigation') {
    return (
      <div className={cx(C.card, C.cardInfo)}>
        <div className={C.cardHead}><Icon name="search" size={14} /><b>调查结果</b><span className={ui.grow}>{String(d.title ?? '')}</span></div>
        <div className={ui.pre} style={{ fontSize: 13 }}>{String(d.conclusion ?? '')}</div>
        {refs(d.evidence).length > 0 && <div className={C.cardRefs}>{refs(d.evidence).map((r) => <code key={r} className={ui.mono}>{r}</code>)}</div>}
        {typeof d.vulnId === 'string' && onOpen && <button className={C.cardLink} onClick={() => onOpen(`vuln:${String(d.vulnId)}`)}>查看漏洞详情 <Icon name="chevronRight" size={12} /></button>}
      </div>
    );
  }
  if (card.kind === 'revision_suggestion') {
    const action = String(d.action ?? 'revision');
    const lines = action === 'merge' ? [`把 ${(d.sourceIds as string[]).length} 个漏洞合并到目标漏洞`] : action === 'split' ? [
      ...(((d.entryKeys as string[]) ?? []).length ? [`拆出入口：${(d.entryKeys as string[]).join('、')}`] : []),
      ...(((d.fingerprints as string[]) ?? []).length ? [`拆出指纹 ${(d.fingerprints as string[]).length} 个`] : []),
    ] : change((d.to ?? {}) as Record<string, string>, (d.from ?? {}) as Record<string, string>, card.progress);
    const vid = String(d.vulnId ?? d.targetId ?? '');
    return (
      <div className={cx(C.card, card.state === 'pending' && C.cardPending)}>
        <div className={C.cardHead}><Icon name="sparkle" size={14} /><b>{action === 'merge' ? '建议合并' : action === 'split' ? '建议拆分' : '建议修订'}</b><span className={ui.grow}>{String(d.title ?? '')}</span><StateBadge state={card.state} card={card} /></div>
        <ul className={C.cardList}>{lines.map((l) => <li key={l}>{l}</li>)}</ul>
        <div className={ui.muted} style={{ fontSize: 13 }}>理由：{String(d.reason ?? '')}</div>
        {refs(d.evidence).length > 0 && <div className={C.cardRefs}>{refs(d.evidence).map((r) => <code key={r} className={ui.mono}>{r}</code>)}</div>}
        {Array.isArray(d.connectors) && d.connectors.length > 0 && (
          <div className={ui.faint} style={{ fontSize: 12 }}>外部依据：{(d.connectors as { connector: string; operation: string; authoritative: boolean }[]).map((c) => `${c.connector}/${c.operation}${c.authoritative ? '（权威）' : '（未核实）'}`).join('、')}</div>
        )}
        {vid && onOpen && <button className={C.cardLink} onClick={() => onOpen(`vuln:${vid}`)}>查看漏洞详情 <Icon name="chevronRight" size={12} /></button>}
        {actions(action === 'merge' ? '合并' : action === 'split' ? '拆分' : '应用修订')}
        {card.state === 'pending' && <div className={ui.faint} style={{ fontSize: 11 }}>应用后以你的名义写入修订历史；AI 的建议本身不会改变漏洞。</div>}
      </div>
    );
  }
  if (card.kind === 'audit_plan') {
    const action = String(d.action ?? 'audit');
    const req = (d.request ?? {}) as Record<string, unknown>;
    const res = card.result ?? {};
    return (
      <div className={cx(C.card, card.state === 'pending' && C.cardPending)}>
        <div className={C.cardHead}><Icon name={action === 'hunt' ? 'target' : 'play'} size={14} /><b>{action === 'hunt' ? '风险排查' : action === 'reverify' ? '复验计划' : '审计计划'}</b><span className={ui.grow}>{String(d.title ?? '')}</span><StateBadge state={card.state} /></div>
        {action === 'audit' && (
          <dl className={ui.kv} style={{ fontSize: 13 }}>
            <dt>项目</dt><dd>{String(d.project ?? req.projectId)}</dd>
            <dt>场景</dt><dd>{SCENE[String(req.scene ?? 'full')]}{req.mode === 'multi' ? ' · 多仓库合并' : ''}</dd>
            {typeof req.repository === 'string' && <><dt>仓库</dt><dd>{req.repository}{req.ref ? ` @ ${String(req.ref)}` : ''}</dd></>}
            {Array.isArray(req.related) && req.related.length > 0 && <><dt>关联仓库</dt><dd>{(req.related as string[]).join('、')}</dd></>}
            {strategyLines(req.strategyOverride).map(([k, v]) => <span key={k} style={{ display: 'contents' }}><dt>{k}</dt><dd>{v}</dd></span>)}
          </dl>
        )}
        {action === 'reverify' && <div style={{ fontSize: 13 }}>{((d.vulns as { displayNo: number; title: string }[]) ?? []).map((v) => `V-${v.displayNo} ${v.title}`).join('；')}{d.note ? <div className={ui.muted}>补充信息：{String(d.note)}</div> : null}</div>}
        {action === 'hunt' && (
          <div style={{ fontSize: 13 }}>
            <div>依据：{(d.basis as { kind: string; skill?: string; text?: string }).kind === 'skill' ? `知识 ${String((d.basis as { skill: string }).skill)}` : String((d.basis as { text: string }).text).slice(0, 200)}</div>
            <div className={ui.muted}>范围：{d.allProjects ? '全部项目' : `${((d.projectIds as string[]) ?? []).length} 个项目`}</div>
          </div>
        )}
        {typeof d.rationale === 'string' && <div className={ui.muted} style={{ fontSize: 13 }}>{d.rationale}</div>}
        {Array.isArray(d.recommended) && d.recommended.length > 0 && <ul className={C.cardList}>{(d.recommended as string[]).map((r) => <li key={r}>推荐：{r}</li>)}</ul>}
        {actions(action === 'hunt' ? '整理依据并选择范围' : action === 'audit' ? '确认并开始' : '开始复验')}
        {card.state === 'pending' && action === 'audit' && (
          <button className={C.cardLink} onClick={() => void navigate({ to: '/audits/new', search: { projectId: String(req.projectId), ...(typeof req.repository === 'string' ? { repo: req.repository } : {}), ...(req.scene === 'incremental' ? { scene: 'incremental' } : {}) } })}>
            参数不对？在表单中修改 <Icon name="chevronRight" size={12} />
          </button>
        )}
        {card.state === 'applied' && typeof res.auditId === 'string' && <Link to="/audits/$aid" params={{ aid: res.auditId }} className={C.cardLink}>打开审计 <Icon name="chevronRight" size={12} /></Link>}
        {card.state === 'applied' && typeof res.basisId === 'string' && <Link to="/hunts/new" search={{ basis: res.basisId }} className={C.cardLink}>继续确认排查依据 <Icon name="chevronRight" size={12} /></Link>}
      </div>
    );
  }
  if (card.kind === 'audit_status') return <AuditStatusCard auditId={String(d.auditId)} title={String(d.title ?? '')} />;
  if (card.kind === 'connector_draft') {
    return (
      <div className={cx(C.card, card.state === 'pending' && C.cardPending)}>
        <div className={C.cardHead}><Icon name="link" size={14} /><b>连接器配置草稿</b><span className={ui.grow}>{String(d.name ?? '')}</span><StateBadge state={card.state} /></div>
        <dl className={ui.kv} style={{ fontSize: 13 }}>
          <dt>协议</dt><dd>{String(d.protocol)}</dd>
          <dt>配置</dt><dd className={ui.mono} style={{ fontSize: 12, whiteSpace: 'pre-wrap' }}>{JSON.stringify(d.config, null, 1)}</dd>
          {Array.isArray(d.secrets) && d.secrets.length > 0 && <><dt>凭证</dt><dd>{(d.secrets as string[]).join('、')}（创建后在设置中填写，不要在对话里发送）</dd></>}
        </dl>
        {typeof d.notes === 'string' && <div className={ui.muted} style={{ fontSize: 13 }}>{d.notes}</div>}
        {actions('创建连接器')}
        {card.state === 'applied' && <Link to="/settings/$section" params={{ section: 'connectors' }} className={C.cardLink}>去设置填写凭证并测试连接 <Icon name="chevronRight" size={12} /></Link>}
      </div>
    );
  }
  return null;
}

/** Live audit status: the shared live card (progress, questions, outcome). */
function AuditStatusCard({ auditId, title }: { auditId: string; title: string }) {
  return <AuditLiveCard auditId={auditId} title={title} />;
}
