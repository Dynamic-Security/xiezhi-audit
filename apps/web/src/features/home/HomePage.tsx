// Workbench home: to-do inbox, running audits, project risk overview, quick start.
import { useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import type { AuditSummaryDto, ConversationDto, MentionDto, ProjectDto } from '@xiezhi/contracts';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../../shared/api/client';
import { useAi } from '../assistant/ai';
import { Composer, clientId } from '../conversations/Thread';
import { QuickStart } from '../conversations/Templates';
import { attachmentsBody, type PendingFile } from '../conversations/attachments';
import { useConversations, useDashboard } from '../../shared/api/queries';
import { AUDIT_STATUS, CONFIRM, HANDLING, PHASE, SEVERITY, SEVERITY_ORDER, fmt } from '../../shared/format/messages';
import { AuditStatusBadge, Badge, Button, EmptyState, ErrorState, Icon, Loading, Progress, SeverityBadge, ui, useToast } from '../../shared/ui';
import { PageLayout, Section, TopBar } from '../layout/AppShell';
import { NewProjectDialog } from '../projects/NewProjectDialog';
import { groupQuestions, inboxCount } from './inbox';
import { ConnectorWriteItem } from './ConnectorWrites';
import H from './home.module.css';

/** “建议修订” text per dimension (confirm / handling / severity / lifecycle …). */
function proposalText(dimension: string, to: unknown): string {
  const v = String(to);
  if (dimension === 'confirm') return `确认状态改为「${CONFIRM[v] ?? v}」`;
  if (dimension === 'severity') return `严重度改为「${SEVERITY[v] ?? v}」`;
  if (dimension === 'handling') return `处理状态改为「${HANDLING[v] ?? v}」`;
  return `${dimension} → ${v}`;
}

function AuditRow({ a, action }: { a: AuditSummaryDto; action?: string }) {
  const b = a.budget;
  return (
    <Link to="/audits/$aid" params={{ aid: a.id }} className={H.item}>
      <div className={H.itemIcon}><Icon name={a.status === 'waiting_budget' ? 'clock' : a.status === 'awaiting_confirm' ? 'check' : 'activity'} /></div>
      <div className={ui.grow}>
        <div className={H.itemTitle}>{a.title}</div>
        <div className={H.itemMeta}>{a.projectName} · {PHASE[a.phase]} · {fmt.tokens(b.consumed.tokens)}/{fmt.tokens(b.effective.tokens)} tokens · {fmt.ago(a.createdAt)}</div>
      </div>
      {action ? <Badge tone="accent">{action}</Badge> : <AuditStatusBadge status={a.status} />}
    </Link>
  );
}

function RiskCard({ p }: { p: ProjectDto }) {
  const total = SEVERITY_ORDER.reduce((n, s) => n + p.openVulns[s], 0);
  return (
    <Link to="/projects/$pid" params={{ pid: p.id }} className={H.risk}>
      <div className={ui.spread}>
        <div className={H.riskName}><Icon name="folder" /> {p.name}</div>
        <span className={ui.faint} style={{ fontSize: 12 }}>{p.repoCount} 个仓库</span>
      </div>
      <div className={H.riskNums}>
        {total === 0 ? <span className={ui.faint}>暂无未处理漏洞</span> : SEVERITY_ORDER.filter((s) => p.openVulns[s] > 0).map((s) => (
          <span key={s} className={H.riskNum}><SeverityBadge severity={s} /> <b>{p.openVulns[s]}</b></span>
        ))}
      </div>
      <div className={H.itemMeta}>
        {p.lastAudit ? <>最近审计：{AUDIT_STATUS[p.lastAudit.status]} · {fmt.ago(p.lastAudit.endedAt)}</> : '尚未审计'}
      </div>
      {p.coverage && (
        <div className={H.itemMeta} title="最近一次开启覆盖对照的全量审计（含补审）">
          覆盖：入口 {p.coverage.entry.reviewed}/{p.coverage.entry.total} · 危险点 {p.coverage.sink.reviewed}/{p.coverage.sink.total}
          {' '}{p.coverage.complete ? <span style={{ color: 'var(--ok)' }}>· 达到目标</span> : <span style={{ color: 'var(--warn)' }}>· 未达目标</span>}
        </div>
      )}
    </Link>
  );
}

export function HomePage() {
  const d = useDashboard();
  const conversations = useConversations('active');
  const navigate = useNavigate();
  const [newProject, setNewProject] = useState(false);
  const [text, setText] = useState('');
  const [templates, setTemplates] = useState(false);
  const [fill, setFill] = useState(0);
  const ai = useAi();
  const qc = useQueryClient();
  const toast = useToast();
  // The home input starts a conversation and continues it in the AI panel.
  const send = async (content: string, mentions: MentionDto[], files: PendingFile[]) => {
    try {
      const refs = mentions.map((m) => ({ kind: m.kind, id: m.id }));
      const c = await api.post<ConversationDto>('/conversations', {});
      await api.post(`/conversations/${c.id}/messages`, { clientMessageId: clientId(), content, mentions: refs, ...attachmentsBody(files) });
      ai.show(c.id);
      void qc.invalidateQueries({ queryKey: ['conversations'] });
      return true;
    } catch (e) { toast.error(e); return false; }
  };
  const inbox = d.data?.inbox;
  const todo = inboxCount(inbox);
  return (
    <>
      <TopBar crumbs={[{ label: '工作台' }]} />
      <PageLayout narrow>
        <div className={H.hero}>
          <h1 className={H.heroTitle}>今天要审计什么？</h1>
          <div className={H.composer}>
            <Composer text={text} setText={setText} fillSignal={fill} onSend={send} hint={false} placeholder="问点什么，或让 Agent 审计 @项目、复验漏洞、排查某个 CVE…" />
          </div>
          <div className={H.quick}>
            <button className={H.quickBtn} onClick={() => void navigate({ to: '/audits/new', search: {} })}><Icon name="play" size={14} /> 全量审计</button>
            <button className={H.quickBtn} onClick={() => void navigate({ to: '/hunts/new', search: {} })}><Icon name="target" size={14} /> 风险排查</button>
            <button className={H.quickBtn} onClick={() => setText('复验所有标为已修复的漏洞')}><Icon name="refresh" size={14} /> 复验已修复</button>
            <button className={H.quickBtn} onClick={() => setNewProject(true)}><Icon name="plus" size={14} /> 新建项目</button>
            <button className={H.quickBtn} aria-expanded={templates} onClick={() => setTemplates(!templates)}><Icon name="sparkle" size={14} /> 用 AI 开始</button>
          </div>
          {templates && <QuickStart onPick={(t) => { setText(t); setFill((n) => n + 1); }} />}
        </div>
        {d.isLoading && <Loading rows={5} />}
        {d.error && <ErrorState error={d.error} onRetry={() => void d.refetch()} />}
        {d.data && (
          <>
            <Section title={<>待我处理 {todo > 0 && <Badge tone="warn">{todo}</Badge>}</>}>
              {todo === 0 ? (
                <div className={`${ui.card} ${H.emptyLine}`}><Icon name="checkCircle" /> 没有需要处理的事项</div>
              ) : (
                <div className={`${ui.card} ${H.list}`}>
                  {inbox!.connectorWrites.map((w) => <ConnectorWriteItem key={w.id} w={w} />)}
                  {groupQuestions(inbox!.questions).map(({ latest: q, count, blocking }) => (
                    <Link key={q.id} to="/audits/$aid" params={{ aid: q.auditId }} search={{ panel: 'chat' }} className={H.item}>
                      <div className={H.itemIcon} style={{ color: 'var(--accent)' }}><Icon name="help" /></div>
                      <div className={ui.grow}>
                        <div className={H.itemTitle}>{q.text}</div>
                        <div className={H.itemMeta}>
                          {q.projectName} · {count > 1 ? `${count} 次审计提出 · 最近：${q.auditTitle}` : q.auditTitle} · {fmt.ago(q.createdAt)}{blocking ? ' · 影响结论' : ''}
                        </div>
                      </div>
                      {count > 1 && <Badge>×{count}</Badge>}
                      <Badge tone="accent">去回答</Badge>
                    </Link>
                  ))}
                  {inbox!.awaitingConfirm.map((a) => <AuditRow key={a.id} a={a} action="确认计划" />)}
                  {inbox!.waitingBudget.map((a) => <AuditRow key={a.id} a={a} action="追加预算" />)}
                  {inbox!.interrupted.map((a) => <AuditRow key={a.id} a={a} action="继续" />)}
                  {inbox!.proposals.map((p) => {
                    const body = (
                      <>
                        <div className={H.itemIcon} style={{ color: 'var(--accent)' }}><Icon name="sparkle" /></div>
                        <div className={ui.grow}>
                          <div className={H.itemTitle}>建议修订：V-{p.displayNo} {proposalText(p.dimension, p.to)}</div>
                          <div className={H.itemMeta}>{p.projectName} · {p.title}{p.conversationId ? ' · 来自会话' : ''}{p.reason ? ` · ${p.reason}` : ''}</div>
                        </div>
                        <Badge tone="accent">去处理</Badge>
                      </>
                    );
                    const key = `${p.vulnId}-${p.dimension}-${String(p.to)}`;
                    return p.conversationId
                      ? <Link key={key} to="/conversations/$cid" params={{ cid: p.conversationId }} className={H.item}>{body}</Link>
                      : <Link key={key} to="/projects/$pid" params={{ pid: p.projectId }} search={{ tab: 'vulns', panel: `vuln:${p.vulnId}` }} className={H.item}>{body}</Link>;
                  })}
                  {inbox!.pendingVulns.map((v) => (
                    <Link key={v.projectId} to="/projects/$pid" params={{ pid: v.projectId }} search={{ tab: 'vulns', confirmation: ['pending'] }} className={H.item}>
                      <div className={H.itemIcon} style={{ color: 'var(--warn)' }}><Icon name="bug" /></div>
                      <div className={ui.grow}>
                        <div className={H.itemTitle}>{v.projectName}：{v.count} 个漏洞待确认</div>
                        <div className={H.itemMeta}>{v.missing.length ? `缺：${v.missing.join('、')} — 补充后可定向复验` : '复核证据后确认或标为误报'}</div>
                      </div>
                      <Badge tone="warn">去复核</Badge>
                    </Link>
                  ))}
                </div>
              )}
            </Section>
            {conversations.data && conversations.data.length > 0 && (
              <Section title="最近会话" actions={<Link to="/conversations" style={{ fontSize: 13 }}>全部会话</Link>}>
                <div className={`${ui.card} ${H.list}`}>
                  {conversations.data.slice(0, 5).map((c) => (
                    <Link key={c.id} to="/conversations/$cid" params={{ cid: c.id }} className={H.item}>
                      <div className={H.itemIcon}><Icon name="message" /></div>
                      <div className={ui.grow}>
                        <div className={H.itemTitle}>{c.title}</div>
                        <div className={H.itemMeta}>{fmt.ago(c.lastMessageAt ?? c.createdAt)}{c.mentions.length ? ` · ${c.mentions.map((m) => m.label).join('、')}` : ''}</div>
                      </div>
                      {c.pendingCards > 0 && <Badge tone="warn">{c.pendingCards} 待确认</Badge>}
                    </Link>
                  ))}
                </div>
              </Section>
            )}
            <Section title="进行中">
              {d.data.running.length === 0 ? (
                <div className={`${ui.card} ${H.emptyLine}`}><Icon name="clock" /> 当前没有运行中的审计</div>
              ) : (
                <div className={`${ui.card} ${H.list}`}>
                  {d.data.running.map((a) => (
                    <div key={a.id}>
                      <AuditRow a={a} />
                      <div style={{ padding: '0 16px 12px 60px' }}><Progress value={a.budget.consumed.tokens} max={a.budget.effective.tokens} /></div>
                    </div>
                  ))}
                </div>
              )}
            </Section>
            <Section title="项目风险概况" actions={<Button size="sm" icon="plus" onClick={() => setNewProject(true)}>新建项目</Button>}>
              {d.data.projects.length === 0 ? (
                <div className={ui.card}>
                  <EmptyState icon="folder" title="还没有项目" action={<Button variant="primary" icon="plus" onClick={() => setNewProject(true)}>新建项目</Button>}>
                    项目对应一个业务系统。添加 Java、Go、Python、JavaScript/TypeScript、PHP、Kotlin 或 C# 仓库后即可发起审计。
                  </EmptyState>
                </div>
              ) : (
                <div className={H.riskGrid}>{d.data.projects.map((p) => <RiskCard key={p.id} p={p} />)}</div>
              )}
            </Section>
            <p className={ui.faint} style={{ fontSize: 12, marginTop: 32, textAlign: 'center' }}>
              静态审计：未构建、未运行、未测试目标代码 · 严重度：{SEVERITY_ORDER.map((s) => SEVERITY[s]).join(' / ')}
            </p>
          </>
        )}
      </PageLayout>
      <NewProjectDialog open={newProject} onClose={() => setNewProject(false)} />
    </>
  );
}
