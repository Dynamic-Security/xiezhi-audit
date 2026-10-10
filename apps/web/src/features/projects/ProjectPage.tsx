// Project page: overview, repositories, audit records, vulnerability list, threat models, knowledge.
import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { RepoDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { useAnalysis, useAudits, useProject, useRepos, useReviewStats, useVulns } from '../../shared/api/queries';
import { ANALYSIS_STATUS, AUDIT_STATUS, LIFECYCLE, PHASE, REPO_ANALYSIS_STATUS, ROLE, SCENE, SOURCE_KIND, SEVERITY, SEVERITY_ORDER, fmt } from '../../shared/format/messages';
import {
  AuditStatusBadge, Badge, Button, ConfirmDialog, Dialog, EmptyState, ErrorState, Field, Icon, Loading, Spinner, Tabs, cx, ui, useDismiss, useToast,
} from '../../shared/ui';
import type { ProjectSearch } from '../../router';
import { PageLayout, Section, TopBar } from '../layout/AppShell';
import { VulnList } from '../vulns/VulnList';
import { VulnPanel, VulnPanelTitle } from '../vulns/VulnPanel';
import { TopologyView } from '../topology/TopologyView';
import { ProjectKnowledge } from '../knowledge/ProjectKnowledge';
import { ThreatModelsTab } from '../threat-models/ThreatModels';
import { FactsTab } from '../facts/FactsTab';
import { InternalTrust, ServiceCardDialog } from '../services/Trust';
import { AddRepoDialog, EditRefDialog, versionLabel } from './RepoDialogs';
import { ProjectExportDialog } from './ProjectExport';
import P from './projects.module.css';
import { useAiScope } from '../assistant/ai';

type Tab = NonNullable<ProjectSearch['tab']>;

function Overview({ pid }: { pid: string }) {
  const project = useProject(pid);
  const vulns = useVulns(pid, {});
  const audits = useAudits({ projectId: pid });
  const all = vulns.data?.items ?? [];
  const bySev = SEVERITY_ORDER.map((s) => ({ s, n: all.filter((v) => v.severity === s && v.confirmStatus !== 'false_positive').length }));
  const max = Math.max(1, ...bySev.map((x) => x.n));
  const byLife = Object.keys(LIFECYCLE).map((k) => ({ k, n: all.filter((v) => v.lifecycle === k).length }));
  return (
    <>
      <div className={P.stats}>
        <div className={P.stat}><div className={P.statNum}>{project.data?.repoCount ?? '—'}</div><div className={P.statLabel}>仓库</div></div>
        <div className={P.stat}><div className={P.statNum}>{audits.data?.totalEstimate ?? '—'}</div><div className={P.statLabel}>审计</div></div>
        <div className={P.stat}><div className={P.statNum}>{all.length}</div><div className={P.statLabel}>漏洞（含已处理）</div></div>
        <div className={P.stat}><div className={P.statNum}>{all.filter((v) => v.confirmStatus === 'pending').length}</div><div className={P.statLabel}>待确认</div></div>
      </div>
      {project.data && <InternalTrust project={project.data} />}
      <ReviewTime pid={pid} />
      <div className={P.twoCol}>
        <Section title="严重度分布">
          <div className={cx(ui.card, ui.cardPad, ui.stack)}>
            {bySev.map(({ s, n }) => (
              <div key={s} className={P.bar}>
                <span className={P.barLabel}>{SEVERITY[s]}</span>
                <div className={P.barTrack}><div className={P.barFill} style={{ width: `${(n / max) * 100}%`, background: `var(--sev-${s})` }} /></div>
                <span className={P.barNum}>{n}</span>
              </div>
            ))}
          </div>
        </Section>
        <Section title="跨审计状态">
          <div className={cx(ui.card, ui.cardPad, ui.stack)}>
            {byLife.map(({ k, n }) => <div key={k} className={ui.spread}><span className={ui.muted}>{LIFECYCLE[k]}</span><b>{n}</b></div>)}
          </div>
        </Section>
      </div>
      <Section title="审计时间线">
        {audits.data?.items.length ? (
          <div className={P.timeline}>
            {audits.data.items.slice(0, 10).map((a) => (
              <Link key={a.id} to="/audits/$aid" params={{ aid: a.id }} className={P.tlItem}>
                <span className={P.tlDot} />
                <div className={ui.grow}>
                  <div className={ui.row}><b className={ui.ellipsis}>{a.title}</b><AuditStatusBadge status={a.status} /></div>
                  <div className={ui.faint} style={{ fontSize: 12 }}>{fmt.date(a.createdAt)} · {a.findingCount} 个发现 · {fmt.compact(a.budget.consumed.tokens)} tokens</div>
                </div>
              </Link>
            ))}
          </div>
        ) : <p className={ui.faint}>还没有审计记录</p>}
      </Section>
    </>
  );
}

/** G1 “人工复核耗时”: one unobtrusive line; single and batch decisions are kept apart. */
function ReviewTime({ pid }: { pid: string }) {
  const q = useReviewStats(pid);
  const r = q.data;
  if (!r) return null;
  const parts: string[] = [];
  if (r.single.count) parts.push(`单条判定 ${r.single.count} 次，中位 ${fmt.duration(r.single.medianMs ?? 0)}、平均 ${fmt.duration(r.single.meanMs ?? 0)}`);
  if (r.batch.count) parts.push(`批量 ${r.batch.batches} 批共 ${r.batch.count} 条，每条中位 ${fmt.duration(r.batch.medianMs ?? 0)}`);
  const decided = r.decisions.confirmed + r.decisions.falsePositive;
  if (decided) parts.push(`人工判定 ${decided} 条，其中误报 ${r.decisions.falsePositive} 条`);
  return (
    <p className={ui.faint} style={{ fontSize: 12, margin: '-8px 0 16px' }} aria-label="人工复核耗时">
      人工复核耗时：{parts.length ? parts.join(' · ') : '暂无记录（在漏洞详情或批量操作中作出判定后开始统计）'}
    </p>
  );
}

const ROLE_OPTIONS = ['gateway', 'auth', 'business', 'api_def', 'frontend', 'shared_lib', 'unknown'] as const;

/** Manual repository analysis: status line, trigger, per-repository evidence. */
function AnalysisBar({ pid, hasRepos }: { pid: string; hasRepos: boolean }) {
  const analysis = useAnalysis(pid);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const a = analysis.data?.analysis ?? null;
  const running = a?.status === 'running';
  const prev = useRef(a?.status);
  useEffect(() => {
    if (prev.current === 'running' && a && a.status !== 'running') {
      void qc.invalidateQueries({ queryKey: ['project', pid, 'repos'] });
      void qc.invalidateQueries({ queryKey: ['project', pid, 'topology'] });
      if (a.status === 'succeeded') toast.ok('仓库分析完成');
    }
    prev.current = a?.status;
  }, [a, pid, qc, toast]);
  const start = async () => {
    setBusy(true);
    try {
      await api.post(`/projects/${pid}/analyze`);
      await qc.invalidateQueries({ queryKey: ['project', pid, 'analysis'] });
    } catch (e) { toast.error(e); }
    setBusy(false);
  };
  const REASON: Record<string, string> = { model_not_configured: '未配置模型，只完成了语言、模块与是否可审计的识别', cancelled: '已中断', 'service restart': '服务重启中断' };
  return (
    <div className={ui.card} style={{ padding: 12, marginBottom: 12 }}>
      <div className={ui.spread}>
        <div className={ui.faint} style={{ fontSize: 13 }}>
          {running ? <><Spinner /> 正在分析仓库角色…</> : a
            ? <>上次分析 {fmt.date(a.endedAt ?? a.startedAt)} · <Badge tone={a.status === 'succeeded' ? 'ok' : a.status === 'failed' ? 'danger' : 'warn'}>{ANALYSIS_STATUS[a.status] ?? a.status}</Badge>
              {a.reason && ` · ${REASON[a.reason] ?? a.reason}`}{a.model && ` · ${a.model} · ${fmt.compact(a.tokens.input + a.tokens.output)} tokens`}</>
            : 'AI 仓库分析：识别每个仓库的角色（网关、鉴权、业务、接口定义、前端、共享库），用于计划、拓扑和知识筛选。'}
        </div>
        <div className={ui.row}>
          {a && a.repos.length > 0 && <Button size="sm" variant="ghost" onClick={() => setOpen(!open)}>{open ? '收起详情' : '查看依据'}</Button>}
          <Button size="sm" icon="sparkle" loading={busy || running} disabled={!hasRepos} onClick={() => void start()}>{a ? '重新分析' : '分析仓库'}</Button>
        </div>
      </div>
      {!running && <div className={ui.faint} style={{ fontSize: 12, marginTop: 4 }}>手动触发；使用“初筛”阶段的模型（设置 › 模型；不使用模型时用默认模型），每个仓库约几千 tokens，代码与模型不变时直接复用上次结果。人工修正的角色不会被覆盖。</div>}
      {open && a && (
        <div className={ui.stack} style={{ marginTop: 10 }}>
          {a.repos.map((r) => (
            <div key={r.repositoryId} style={{ borderTop: '1px solid var(--border)', paddingTop: 8 }}>
              <div className={ui.row}><b>{r.name}</b><Badge>{REPO_ANALYSIS_STATUS[r.status] ?? r.status}</Badge>{r.roles.map((x) => <Badge key={x.role} tone="accent">{ROLE[x.role] ?? x.role} {x.confidence.toFixed(2)}</Badge>)}</div>
              {r.error && <div className={ui.error} style={{ marginTop: 4 }}>{r.error}</div>}
              {r.rationale && <div className={ui.muted} style={{ fontSize: 13, marginTop: 4 }}>{r.rationale}</div>}
              {r.roles.flatMap((x) => x.evidence.map((e, i) => <div key={`${x.role}-${i}`} className={cx(ui.faint, ui.mono)} style={{ fontSize: 12 }}>· {ROLE[x.role] ?? x.role}：{e.signal}{e.path ? ` · ${e.path}` : ''}{e.count !== undefined ? ` · ${e.count}` : ''}</div>))}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** auditable / context only, with the automatic judgement and a way back to it. */
function AuditableCell({ repo }: { repo: RepoDto }) {
  const qc = useQueryClient();
  const toast = useToast();
  const set = async (auditable: boolean | 'auto') => {
    try {
      await api.patch(`/repos/${repo.id}`, { auditable });
      await qc.invalidateQueries({ queryKey: ['project', repo.projectId] });
    } catch (e) { toast.error(e); }
  };
  const autoLabel = repo.auditableAuto ? '可审计' : '仅当做上下文';
  return (
    <div>
      <select aria-label={`${repo.name} 是否可审计`} className={ui.input} style={{ height: 28, fontSize: 13, padding: '0 6px', width: 'auto' }}
        value={repo.auditable ? 'auditable' : 'context'} onChange={(e) => void set(e.target.value === 'auditable')}>
        <option value="auditable">可审计</option>
        <option value="context">仅当做上下文</option>
      </select>
      <div className={ui.faint} style={{ fontSize: 11, marginTop: 2, whiteSpace: 'nowrap' }} title={repo.auditableReason ?? undefined}>
        {repo.auditableSource === 'user'
          ? <>人工设置 · <button style={{ background: 'none', border: 0, padding: 0, color: 'var(--accent)', cursor: 'pointer', font: 'inherit' }} onClick={() => void set('auto')}>改回自动</button>{repo.auditableAuto !== repo.auditable && `（自动判定：${autoLabel}）`}</>
          : <>自动判定{!repo.auditable && repo.auditableReason ? ' · 悬停查看原因' : ''}</>}
      </div>
    </div>
  );
}

/** `analyzed`: the latest repository analysis judged this repository (it may have found no role it is sure of). */
function RoleCell({ repo, analyzed }: { repo: RepoDto; analyzed: boolean }) {
  const qc = useQueryClient();
  const toast = useToast();
  const set = async (role: string) => {
    try {
      await api.patch(`/repos/${repo.id}`, { role });
      await qc.invalidateQueries({ queryKey: ['project', repo.projectId, 'repos'] });
    } catch (e) { toast.error(e); }
  };
  const ai = repo.aiRoles.filter((r) => r.role !== repo.role || repo.roleSource === 'user');
  return (
    <div>
      <select aria-label={`${repo.name} 的角色`} className={ui.input} style={{ height: 28, fontSize: 13, padding: '0 6px', width: 'auto' }} value={repo.role} onChange={(e) => void set(e.target.value)}>
        {ROLE_OPTIONS.map((r) => <option key={r} value={r}>{ROLE[r]}</option>)}
      </select>
      <div className={ui.faint} style={{ fontSize: 11, marginTop: 2, whiteSpace: 'nowrap' }}>
        {repo.roleSource === 'user' ? <>人工修正 · <button style={{ background: 'none', border: 0, padding: 0, color: 'var(--accent)', cursor: 'pointer', font: 'inherit' }} onClick={() => void set('auto')}>改回 AI</button></> : repo.aiRoles.length ? 'AI 识别' : analyzed ? 'AI 未能判定角色' : '未分析'}
        {ai.length > 0 && ` · AI：${ai.map((r) => `${ROLE[r.role] ?? r.role} ${r.confidence.toFixed(2)}`).join('、')}`}
      </div>
    </div>
  );
}

function Repos({ pid, addOpen, setAddOpen }: { pid: string; addOpen: boolean; setAddOpen: (v: boolean) => void }) {
  const [card, setCard] = useState<string | null>(null);
  const repos = useRepos(pid);
  const analysis = useAnalysis(pid);
  // A repository the analysis judged with no role it is sure of is not “未分析”.
  const analyzed = new Set((analysis.data?.analysis?.repos ?? []).filter((x) => x.status === 'succeeded' || x.status === 'reused').map((x) => x.repositoryId));
  const [editRef, setEditRef] = useState<RepoDto | null>(null);
  const [removing, setRemoving] = useState<RepoDto | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  return (
    <>
      <div className={ui.spread} style={{ marginBottom: 12 }}>
        <p className={ui.muted}>仓库的增删、默认版本和“可审计 / 仅当做上下文”只影响之后的审计；已完成的审计保持不变。</p>
        <Button variant="primary" icon="plus" onClick={() => setAddOpen(true)}>添加仓库</Button>
      </div>
      <AnalysisBar pid={pid} hasRepos={(repos.data?.length ?? 0) > 0} />
      {repos.isLoading ? <Loading /> : repos.error ? <ErrorState error={repos.error} /> : repos.data!.length === 0 ? (
        <div className={ui.card}><EmptyState icon="git" title="还没有仓库" action={<Button variant="primary" icon="plus" onClick={() => setAddOpen(true)}>添加仓库</Button>}>添加仓库（Java、Go、Python、JavaScript/TypeScript、PHP、Kotlin、C#）：本地目录、Git 地址或压缩包。</EmptyState></div>
      ) : (
        <div className={ui.card} style={{ overflow: 'auto' }}>
          <table className={ui.table}>
            <thead><tr><th>仓库</th><th>语言</th><th>类型</th><th>角色</th><th>默认版本</th><th>最近审计版本</th><th /></tr></thead>
            <tbody>
              {repos.data!.map((r) => (
                <tr key={r.id}>
                  <td><b>{r.name}</b> <Badge>{SOURCE_KIND[r.sourceKind]}</Badge>
                    <div className={cx(ui.faint, ui.mono, ui.ellipsis)} style={{ fontSize: 12, maxWidth: 320 }} title={r.locator}>
                      {r.locator}{r.sourceKind === 'archive' && r.sourceDetail.rootHash ? ` · ${r.sourceDetail.rootHash.slice(0, 12)}` : ''}{r.sourceDetail.headCommit ? ` · 包内 Git ${r.sourceDetail.headCommit.slice(0, 7)}` : ''}
                    </div></td>
                  <td title={r.languages.join(', ')} style={{ whiteSpace: 'nowrap' }}>{r.languages.slice(0, 3).join(', ') || '—'}{r.languages.length > 3 ? ` +${r.languages.length - 3}` : ''}</td>
                  <td><AuditableCell repo={r} /></td>
                  <td><RoleCell repo={r} analyzed={analyzed.has(r.id)} /></td>
                  <td style={{ whiteSpace: 'nowrap' }}>{r.sourceKind === 'archive'
                    ? <span className={ui.chip} style={{ cursor: 'default' }}><Icon name="git" size={12} />{versionLabel(r, null)}</span>
                    : <button className={ui.chip} onClick={() => setEditRef(r)}><Icon name="git" size={12} />{versionLabel(r, r.defaultRef)}</button>}</td>
                  <td className={ui.faint} style={{ fontSize: 12 }}>{r.lastSnapshot ? (r.lastSnapshot.worktree ? `工作区${r.lastSnapshot.commit ? `（${r.lastSnapshot.commit.slice(0, 7)}）` : ''}` : `${r.lastSnapshot.ref ?? ''} ${r.lastSnapshot.commit?.slice(0, 7) ?? ''}`) : '—'}</td>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    <Button size="sm" icon="play" disabled={!r.auditable} onClick={() => void navigate({ to: '/audits/new', search: { projectId: pid, repo: r.id } })}>审计</Button>{' '}
                    <Button size="sm" variant="ghost" onClick={() => setCard(r.name)}>责任卡</Button>{' '}
                    <Button size="sm" variant="ghost" icon="trash" aria-label="移除" onClick={() => setRemoving(r)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <AddRepoDialog pid={pid} open={addOpen} onClose={() => setAddOpen(false)} />
      {editRef && <EditRefDialog repo={editRef} open onClose={() => setEditRef(null)} />}
      {card && <ServiceCardDialog pid={pid} repo={card} onClose={() => setCard(null)} />}
      <ConfirmDialog open={!!removing} onClose={() => setRemoving(null)} title={`移除仓库 ${removing?.name ?? ''}`} confirmText="移除" level="destructive"
        onConfirm={async () => {
          try { await api.del(`/repos/${removing!.id}`); toast.ok('已移除'); await qc.invalidateQueries({ queryKey: ['project', pid] }); } catch (e) { toast.error(e); }
          setRemoving(null);
        }}>
        之后的审计不再包含该仓库；已完成的审计及其结果保持不变。
      </ConfirmDialog>
    </>
  );
}

function Audits({ pid }: { pid: string }) {
  const audits = useAudits({ projectId: pid });
  const navigate = useNavigate();
  if (audits.isLoading) return <Loading />;
  if (audits.error) return <ErrorState error={audits.error} />;
  const items = audits.data!.items;
  if (!items.length) return <div className={ui.card}><EmptyState icon="activity" title="还没有审计" action={<Button variant="primary" icon="play" onClick={() => void navigate({ to: '/audits/new', search: { projectId: pid } })}>发起审计</Button>} /></div>;
  return (
    <div className={ui.card} style={{ overflow: 'auto' }}>
      <table className={ui.table}>
        <thead><tr><th>审计</th><th>场景</th><th>仓库与版本</th><th>状态</th><th>发现</th><th>用量</th><th>时间</th></tr></thead>
        <tbody>
          {items.map((a) => (
            <tr key={a.id} className={ui.rowLink} onClick={() => void navigate({ to: '/audits/$aid', params: { aid: a.id } })}>
              <td style={{ maxWidth: 280 }}><div className={ui.ellipsis}><b>{a.title}</b></div><div className={cx(ui.faint, ui.mono)} style={{ fontSize: 11 }}>{a.id}</div></td>
              <td>{SCENE[a.scene] ?? a.scene} · {a.mode === 'single' ? '单仓' : '多仓'}</td>
              <td>{a.repos.map((r) => <div key={r.id} style={{ fontSize: 12 }}>{r.name} <span className={ui.faint}>{r.worktree ? '工作区版本' : `${r.ref ?? ''} ${r.commit?.slice(0, 7) ?? ''}`}</span></div>)}</td>
              <td><AuditStatusBadge status={a.status} />{a.status === 'running' && <div className={ui.faint} style={{ fontSize: 12 }}>{PHASE[a.phase]}</div>}</td>
              <td>{a.findingCount}</td>
              <td style={{ fontSize: 12 }}>{fmt.compact(a.budget.consumed.tokens)} tokens<div className={ui.faint}>{fmt.duration(a.budget.consumed.durationMs)} · 成本 {fmt.cost(a.budget.consumed.costMicros)}</div></td>
              <td className={ui.faint} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{fmt.date(a.createdAt)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ProjectMenu({ pid, name, onRename }: { pid: string; name: string; onRename: () => void }) {
  const [open, setOpen] = useState(false);
  const [del, setDel] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  return (
    <div style={{ position: 'relative' }} ref={ref}>
      <Button variant="ghost" size="sm" icon="more" aria-label="项目菜单" onClick={() => setOpen(!open)} />
      {open && (
        <div className={ui.menu} style={{ right: 0, top: 32 }}>
          <button className={ui.menuItem} onClick={() => { setOpen(false); onRename(); }}><Icon name="edit" />重命名</button>
          <button className={ui.menuItem} onClick={async () => { setOpen(false); try { await api.patch(`/projects/${pid}`, { status: 'archived' }); toast.ok('已归档'); await qc.invalidateQueries({ queryKey: ['projects'] }); void navigate({ to: '/' }); } catch (e) { toast.error(e); } }}><Icon name="inbox" />归档</button>
          <button className={cx(ui.menuItem, ui.menuDanger)} onClick={() => { setOpen(false); setDel(true); }}><Icon name="trash" />删除项目…</button>
        </div>
      )}
      <ConfirmDialog open={del} onClose={() => setDel(false)} title="删除项目" level="destructive" confirmText="永久删除" typeToConfirm={name}
        onConfirm={async () => {
          try { await api.del(`/projects/${pid}?confirmName=${encodeURIComponent(name)}`); toast.ok('项目已删除'); await qc.invalidateQueries({ queryKey: ['projects'] }); void navigate({ to: '/' }); } catch (e) { toast.error(e); }
          setDel(false);
        }}>
        将删除该项目下的所有仓库记录、审计、漏洞与报告，且无法恢复。
      </ConfirmDialog>
    </div>
  );
}

export function ProjectPage() {
  const { pid } = useParams({ from: '/projects/$pid' });
  const search = useSearch({ from: '/projects/$pid' });
  const navigate = useNavigate({ from: '/projects/$pid' });
  const project = useProject(pid);
  const repos = useRepos(pid);
  useAiScope(project.data ? { kind: 'project', id: pid, label: project.data.name } : null);
  const tab: Tab = search.tab ?? 'overview';
  const [renaming, setRenaming] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [newName, setNewName] = useState('');
  const qc = useQueryClient();
  const toast = useToast();
  const setSearch = (patch: Partial<ProjectSearch>, replace = false) => void navigate({ search: (prev) => ({ ...prev, ...patch }), replace });
  const panelVid = search.panel?.startsWith('vuln:') ? search.panel.slice(5) : null;
  if (project.error) return <><TopBar crumbs={[{ label: '工作台', to: '/' }, { label: '项目' }]} /><ErrorState error={project.error} /></>;
  const name = project.data?.name ?? '…';
  return (
    <>
      <TopBar crumbs={[{ label: '工作台', to: '/' }, { label: name }]} actions={<>
        <Button size="sm" icon="download" title="导出项目内全部活跃漏洞（跨审计）" onClick={() => setExporting(true)}>导出</Button>
        <Button variant="primary" size="sm" icon="play" disabled={!repos.data?.some((r) => r.auditable)} onClick={() => void navigate({ to: '/audits/new', search: { projectId: pid } })}>发起审计</Button>
        <ProjectMenu pid={pid} name={name} onRename={() => { setNewName(name); setRenaming(true); }} />
      </>} />
      <PageLayout panel={panelVid ? <VulnPanel vid={panelVid} /> : undefined} panelTitle={panelVid ? <VulnPanelTitle vid={panelVid} /> : undefined} panelKey={panelVid ?? undefined} onClosePanel={() => setSearch({ panel: undefined })}>
        <h1 className={P.title}>{name}</h1>
        <div style={{ margin: '16px 0 20px' }}>
          <Tabs value={tab} onChange={(t) => setSearch({ tab: t, panel: undefined, tm: undefined })} items={[
            { key: 'overview', label: '概览' }, { key: 'repos', label: '仓库', count: repos.data?.length }, { key: 'topology', label: '系统拓扑' }, { key: 'audits', label: '审计记录' },
            { key: 'vulns', label: '漏洞清单', count: project.data ? Object.values(project.data.openVulns).reduce((a, b) => a + b, 0) : undefined }, { key: 'threats', label: '威胁建模' }, { key: 'facts', label: '企业事实' }, { key: 'knowledge', label: '知识库' },
          ]} />
        </div>
        {tab === 'overview' && <Overview pid={pid} />}
        {tab === 'repos' && <Repos pid={pid} addOpen={!!search.addRepo} setAddOpen={(v) => setSearch({ addRepo: v ? 1 : undefined }, true)} />}
        {tab === 'topology' && <TopologyView pid={pid} />}
        {tab === 'audits' && <Audits pid={pid} />}
        {tab === 'vulns' && (
          <VulnList pid={pid} filters={search} selected={panelVid}
            onFilters={(f) => setSearch(f, 'q' in f)} onSelect={(vid) => setSearch({ panel: `vuln:${vid}` })} />
        )}
        {tab === 'threats' && <ThreatModelsTab pid={pid} selected={search.tm} onSelect={(tm) => setSearch({ tm })} />}
        {tab === 'facts' && <FactsTab pid={pid} />}
        {tab === 'knowledge' && <ProjectKnowledge pid={pid} />}
        <p className={ui.faint} style={{ fontSize: 12, marginTop: 32 }}>最近审计：{project.data?.lastAudit ? `${AUDIT_STATUS[project.data.lastAudit.status]} · ${fmt.ago(project.data.lastAudit.endedAt)}` : '无'}</p>
      </PageLayout>
      {exporting && <ProjectExportDialog pid={pid} open onClose={() => setExporting(false)} />}
      <Dialog open={renaming} onClose={() => setRenaming(false)} title="重命名项目" footer={<>
        <Button onClick={() => setRenaming(false)}>取消</Button>
        <Button variant="primary" disabled={!newName.trim()} onClick={async () => {
          try { await api.patch(`/projects/${pid}`, { name: newName.trim() }); await qc.invalidateQueries({ queryKey: ['projects'] }); await qc.invalidateQueries({ queryKey: ['project', pid] }); toast.ok('已重命名'); setRenaming(false); } catch (e) { toast.error(e); }
        }}>保存</Button>
      </>}>
        <Field label="项目名称"><input className={ui.input} value={newName} onChange={(e) => setNewName(e.target.value)} autoFocus /></Field>
      </Dialog>
    </>
  );
}
