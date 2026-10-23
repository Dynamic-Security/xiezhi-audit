// Start an audit from the form: required items up front, optional ones folded; defaults
// come from settings (scene defaults). Submitting creates a plan draft (202) and opens the audit.
import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearch } from '@tanstack/react-router';
import type { AuditStrategy, ThreatModelSummaryDto } from '@xiezhi/contracts';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError, newIdempotencyKey } from '../../shared/api/client';
import { useAudits, useConnectors, useModelSettings, useProjectConnectors, useProjects, useProviders, useRepos, useSceneDefaults } from '../../shared/api/queries';
import { fmt, ROLE, VULN_CATEGORY } from '../../shared/format/messages';
import { Button, Field, Icon, Segmented, cx, ui, useToast, TokenCostHint } from '../../shared/ui';
import { askNotifyPermission } from '../../shared/notify';
import { PageLayout, TopBar } from '../layout/AppShell';
import { RefPicker, versionLabel } from '../projects/RepoDialogs';
import A from './audits.module.css';
import { AnalysisOptions, analysisChoiceOf, analysisOverride, type AnalysisChoice } from './AnalysisOptions';
import { StageModelsEditor, stageCrossed, stageModelsDiff, stageModelsOf, type StageModelsValue } from './StageModels';
import { BudgetStagesEditor, LimitsEditor, limitsOf, limitsOverride, type LimitsValue, type StageShares } from './BudgetLimits';

const CATEGORIES = (['authz_object', 'authz_function', 'sqli', 'cmdi', 'ssrf', 'path_traversal', 'deserialization', 'xxe', 'hardcoded_secret', 'business_logic'] as const)
  .map((k) => [k, VULN_CATEGORY[k]] as const);

/** A task sets stage fallbacks on top of the scene defaults' (shown as “默认”), so it starts without any of its own. */
const taskBase = (eff: AuditStrategy): StageModelsValue => stageModelsOf(eff);

export function NewAuditPage() {
  const search = useSearch({ from: '/audits/new' });
  const navigate = useNavigate();
  const projects = useProjects();
  const [projectId, setProjectId] = useState(search.projectId ?? '');
  const repos = useRepos(projectId);
  const [repoId, setRepoId] = useState(search.repo ?? '');
  const [ref, setRef] = useState<string | null | undefined>(undefined);
  const [pickRef, setPickRef] = useState(false);
  const [title, setTitle] = useState('');
  /** requirement threat models the audit references (generated ones of the project). */
  const [tms, setTms] = useState<string[]>(search.tm ?? []);
  const [showMore, setShowMore] = useState(false);
  /** the form starts the audit once the plan is ready, unless the user wants to confirm the plan first. */
  const [planFirst, setPlanFirst] = useState(false);
  const [cats, setCats] = useState<string[]>([]);
  const [focusText, setFocusText] = useState('');
  const [include, setInclude] = useState('');
  const [exclude, setExclude] = useState('');
  const [tokens, setTokens] = useState<number | ''>('');
  const [minutes, setMinutes] = useState<number | ''>('');
  const [challenge, setChallenge] = useState<boolean | null>(null);
  /** stage quotas, candidate limit and coverage for this task; null = the scene defaults. */
  const [shares, setShares] = useState<StageShares | null>(null);
  /** The stage-quota switch for this task; null = the scene default. */
  const [stageLimits, setStageLimits] = useState<boolean | null>(null);
  const [limits, setLimits] = useState<LimitsValue | null>(null);
  /** optional analyses; null = the scene default. */
  const [analyses, setAnalyses] = useState<AnalysisChoice | null>(null);
  /** null = the project's bound connectors; a list = the user's choice for this task. */
  const [conns, setConns] = useState<string[] | null>(null);
  const allConnectors = useConnectors();
  const bound = useProjectConnectors(projectId || undefined);
  /** The stage models of this audit; null = the scene defaults, untouched. */
  const [stageModels, setStageModels] = useState<StageModelsValue | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [key] = useState(newIdempotencyKey);
  const [sceneKind, setSceneKind] = useState<'full' | 'incremental'>(search.scene === 'incremental' ? 'incremental' : 'full');
  /** 审计模式: single (+ related evidence repositories) or multi (equal targets). */
  const [mode, setMode] = useState<'single' | 'multi'>('single');
  const [related, setRelated] = useState<string[]>([]);
  const [targets, setTargets] = useState<string[] | null>(null);
  /** Incremental baseline: undefined = the last finished audit's version; a string = a ref. */
  const [baseRef, setBaseRef] = useState<string | undefined>(undefined);
  const [pickBase, setPickBase] = useState(false);
  const scene = useSceneDefaults(sceneKind);
  const finished = useAudits({ projectId: projectId || undefined, status: undefined }, { enabled: !!projectId && sceneKind === 'incremental' });
  const providers = useProviders();
  const modelSettings = useModelSettings();
  const toast = useToast();
  const threatModels = useQuery({ queryKey: ['threat-models', projectId], enabled: !!projectId, queryFn: () => api.get<{ items: ThreatModelSummaryDto[] }>(`/projects/${projectId}/threat-models`) });
  const usableTms = (threatModels.data?.items ?? []).filter((t) => t.generatedAt && t.status !== 'generating');

  const auditable = useMemo(() => (repos.data ?? []).filter((r) => r.auditable), [repos.data]);
  useEffect(() => { if (!projectId && projects.data?.length === 1) setProjectId(projects.data[0]!.id); }, [projects.data, projectId]);
  useEffect(() => {
    if (auditable.length && !auditable.some((r) => r.id === repoId)) setRepoId(auditable[0]!.id);
  }, [auditable, repoId]);
  const repo = auditable.find((r) => r.id === repoId);
  const multiTargets = targets ?? auditable.map((r) => r.id);
  const contextRepos = (repos.data ?? []).filter((r) => !r.auditable);
  const canMulti = auditable.length >= 2 && sceneKind === 'full';
  useEffect(() => { if (!canMulti && mode === 'multi') setMode('single'); }, [canMulti, mode]);
  // Default baseline: the latest finished full/incremental audit of this repository.
  const lastAudit = (finished.data?.items ?? []).find((a) => ['completed', 'partial'].includes(a.status) && ['full', 'incremental'].includes(a.scene) && a.repos.some((r) => r.id === repoId));
  const eff = scene.data?.effective as AuditStrategy | null | undefined;
  const allModels = (providers.data ?? []).flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`));
  const noModel = providers.data && (!allModels.length || !modelSettings.data?.defaultModel);

  const submit = async () => {
    setBusy(true);
    setErr(null);
    const override: Record<string, unknown> = {};
    if (cats.length || focusText.trim()) override.focus = { categories: cats, modules: [], ...(focusText.trim() ? { text: focusText.trim() } : {}) };
    const inc = include.split('\n').map((x) => x.trim()).filter(Boolean);
    const exc = exclude.split('\n').map((x) => x.trim()).filter(Boolean);
    if (inc.length || exc.length) override.scope = { include: inc, exclude: exc };
    if (tokens || minutes || shares || stageLimits !== null) override.budget = { ...(tokens ? { tokens: Number(tokens) } : {}), ...(minutes ? { durationSec: Number(minutes) * 60 } : {}), ...(shares ? { stages: shares } : {}), ...(stageLimits !== null ? { stageLimits } : {}) };
    if (limits && eff) {
      const l = limitsOverride(limits, limitsOf(eff));
      if (l.limits) override.limits = l.limits;
      if (l.coverageTarget && sceneKind === 'full') override.coverageTarget = l.coverageTarget;
    }
    if (challenge !== null) override.stages = { adversarialReview: challenge };
    if (analyses) {
      const a = analysisOverride(sceneKind, analyses);
      override.stages = { ...(override.stages as object | undefined), ...a.stages };
    }
    if (conns !== null) override.connectors = conns;
    const chosenTms = tms.filter((t) => usableTms.some((x) => x.id === t));
    if (chosenTms.length) override.threatModels = chosenTms;
    if (stageModels && eff) Object.assign(override, stageModelsDiff(taskBase(eff), stageModels));
    try {
      const modeBody = mode === 'multi'
        ? { mode: 'multi', repositories: multiTargets }
        : { repository: repoId, ...(ref !== undefined && ref !== null ? { ref } : {}), ...(related.filter((x) => x !== repoId).length ? { related: related.filter((x) => x !== repoId) } : {}) };
      const r = await api.post<{ auditId: string }>('/audit-plans', {
        projectId, ...modeBody, ...(title.trim() ? { title: title.trim() } : {}),
        scene: sceneKind, ...(sceneKind === 'incremental' && baseRef ? { baseRef } : {}),
        ...(Object.keys(override).length ? { strategyOverride: override } : {}), ...(planFirst ? {} : { autoStart: true }),
      }, { idempotencyKey: key });
      askNotifyPermission();
      toast.ok(planFirst ? '正在生成审计计划，生成后等你确认' : '审计已开始：计划生成后自动运行');
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <TopBar crumbs={[{ label: '工作台', to: '/' }, { label: '新建审计' }]} />
      <PageLayout narrow>
        <h1 className={A.pageTitle}>新建审计</h1>
        <p className={ui.muted} style={{ marginTop: 6 }}>提交后 Agent 先快速浏览仓库生成计划，随即开始审计；预算在启动时冻结，用完会暂停等你追加。需要先看计划的话，勾选下方选项。</p>
        {noModel && (
          <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)', marginTop: 16 }}>
            <Icon name="alert" /> 尚未配置可用模型。<a href="/settings/models">前往设置 › 模型</a>
          </div>
        )}
        <div className={cx(ui.card, A.form)}>
          <div className={A.formGrid}>
            <Field label="项目">
              <select className={ui.select} value={projectId} onChange={(e) => { setProjectId(e.target.value); setRepoId(''); setRef(undefined); }}>
                <option value="" disabled>选择项目</option>
                {projects.data?.filter((p) => p.status === 'active').map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </Field>
            <Field label="场景" hint={sceneKind === 'incremental' ? '只审计相对基线的变更及其影响范围' : '复验从漏洞详情或清单发起；风险排查从“风险排查”页发起'}>
              <select aria-label="场景" className={ui.select} value={sceneKind} onChange={(e) => { if (e.target.value === 'risk_hunt') { void navigate({ to: '/hunts/new' }); return; } setSceneKind(e.target.value as 'full' | 'incremental'); setChallenge(null); setStageModels(null); setAnalyses(null); setShares(null); setLimits(null); }}>
                <option value="full">全量审计</option>
                <option value="incremental">增量审计 · 单仓库</option>
                <option value="risk_hunt">风险排查（可跨项目）→</option>
              </select>
            </Field>
          </div>
          <Field group label="审计模式" hint={mode === 'multi' ? '多个仓库地位平等，发现可以落在任一仓库，调用链可以跨仓库' : '一个目标仓库，可以加关联仓库作为跨仓确认的依据'}>
            <Segmented value={mode} onChange={(m) => { if (m === 'multi' && !canMulti) return; setMode(m); }} items={[{ key: 'single', label: '单仓库审计' }, { key: 'multi', label: canMulti ? '多仓库合并审计' : '多仓库合并审计（需 ≥2 个可审计仓库，仅全量）' }]} />
          </Field>
          {mode === 'multi' ? (
            <Field group label="审计对象" hint={contextRepos.length ? `上下文仓库 ${contextRepos.map((r) => r.name).join('、')} 自动加入，只提取接口契约；各仓库使用默认版本` : '各仓库使用默认版本'}>
              <div className={A.repoList}>
                {auditable.map((r) => {
                  const on = multiTargets.includes(r.id);
                  return (
                    <button key={r.id} role="checkbox" aria-checked={on} className={cx(A.repoOpt, on && A.repoOptOn)} onClick={() => setTargets(on ? multiTargets.filter((x) => x !== r.id) : [...multiTargets, r.id])}>
                      <Icon name="git" /><div className={ui.grow} style={{ textAlign: 'left' }}><b>{r.name}</b><div className={ui.faint} style={{ fontSize: 12 }}>{ROLE[r.role] ?? r.role} · {versionLabel(r, r.defaultRef)}</div></div>
                      {on && <Icon name="check" />}
                    </button>
                  );
                })}
              </div>
            </Field>
          ) : null}
          {mode === 'single' && <Field group label="审计对象" hint={projectId && auditable.length === 0 ? '该项目还没有可审计的仓库（Java、Go、Python、JavaScript/TypeScript 后端、PHP、Kotlin、C#、Ruby、Rust）' : undefined}>
            <div className={A.repoList}>
              {auditable.map((r) => (
                <button key={r.id} className={cx(A.repoOpt, r.id === repoId && A.repoOptOn)} onClick={() => { setRepoId(r.id); setRef(undefined); }}>
                  <Icon name="git" /><div className={ui.grow} style={{ textAlign: 'left' }}><b>{r.name}</b><div className={ui.faint} style={{ fontSize: 12 }}>{r.languages.join(', ')}</div></div>
                  {r.id === repoId && <Icon name="check" />}
                </button>
              ))}
            </div>
          </Field>}
          {mode === 'single' && (repos.data ?? []).length > 1 && (
            <Field group label="关联仓库（可选）" hint="只作为跨仓确认的证据来源（网关、鉴权服务、接口定义等），不产生它们自己的发现">
              <div className={cx(ui.row, ui.wrap)}>
                {(repos.data ?? []).filter((r) => r.id !== repoId).map((r) => (
                  <label key={r.id} className={ui.chip} style={{ cursor: 'pointer' }}>
                    <input type="checkbox" checked={related.includes(r.id)} onChange={(e) => setRelated(e.target.checked ? [...related, r.id] : related.filter((x) => x !== r.id))} />
                    {r.name}<span className={ui.faint}>{ROLE[r.role] ?? ''}</span>
                  </label>
                ))}
              </div>
            </Field>
          )}
          {repo && mode === 'single' && (
            <Field group label="版本" hint="分支会在启动时解析为具体 commit 并固定">
              <div className={ui.row}>
                <span className={ui.chip} style={{ cursor: 'default' }}><Icon name="git" size={12} />{ref === undefined ? `${versionLabel(repo, repo.defaultRef)}（默认）` : versionLabel(repo, ref)}</span>
                {repo.sourceKind !== 'archive' && <Button size="sm" variant="ghost" onClick={() => setPickRef(!pickRef)}>{pickRef ? '收起' : '更改'}</Button>}
              </div>
              {pickRef && <div style={{ marginTop: 8 }}><RefPicker repoId={repo.id} sourceKind={repo.sourceKind} value={ref ?? repo.defaultRef} onPick={(r) => { setRef(r); setPickRef(false); }} /></div>}
            </Field>
          )}
          {repo && mode === 'single' && sceneKind === 'incremental' && (
            <Field group label="对比基线" hint={baseRef === undefined && !lastAudit ? '这个仓库还没有已完成的审计：请指定基线分支或提交，或先做一次全量审计' : '默认是上次审计的版本，也可以选择任意分支或提交（例如 feature 分支对比 main）'}>
              <div className={ui.row}>
                <span className={ui.chip} style={{ cursor: 'default' }}>
                  <Icon name="git" size={12} />
                  {baseRef !== undefined ? baseRef : lastAudit ? `上次审计的版本：${lastAudit.title} · ${lastAudit.repos.find((r) => r.id === repoId)?.commit?.slice(0, 7) ?? '工作区版本'} · ${fmt.date(lastAudit.endedAt ?? lastAudit.createdAt)}` : '未指定'}
                </span>
                {repo.sourceKind !== 'archive' && <Button size="sm" variant="ghost" onClick={() => setPickBase(!pickBase)}>{pickBase ? '收起' : '更改'}</Button>}
                {baseRef !== undefined && <Button size="sm" variant="ghost" onClick={() => setBaseRef(undefined)}>改回上次审计的版本</Button>}
              </div>
              {pickBase && <div style={{ marginTop: 8 }}><RefPicker repoId={repo.id} sourceKind={repo.sourceKind} nullLabel={null} value={baseRef ?? null} onPick={(r) => { if (r) setBaseRef(r); setPickBase(false); }} /></div>}
            </Field>
          )}
          <Field label="标题（可选）"><input className={ui.input} value={title} placeholder={mode === 'multi' ? `全量审计 · ${auditable.filter((r) => multiTargets.includes(r.id)).map((r) => r.name).join(', ')}` : repo ? `${sceneKind === 'incremental' ? '增量审计' : '全量审计'} · ${repo.name}` : ''} onChange={(e) => setTitle(e.target.value)} /></Field>

          {usableTms.length > 0 && (
            <Field group label="关联需求威胁模型" hint="审计据此理解功能需求：设计如此的功能不报；需规避 / 已规避的风险逐条验证；与已接受或误报风险相关的问题自动标注并折叠。按审计开始时的研判状态固定。">
              <div className={cx(ui.row, ui.wrap)}>
                {usableTms.map((t) => {
                  const on = tms.includes(t.id);
                  return <button key={t.id} className={cx(ui.chip, on && ui.chipOn)} aria-pressed={on} onClick={() => setTms(on ? tms.filter((x) => x !== t.id) : [...tms, t.id])}
                    title={`需规避 ${t.riskCounts.to_mitigate} · 已规避 ${t.riskCounts.mitigated} · 接受风险 ${t.riskCounts.accepted} · 误报 ${t.riskCounts.false_positive} · 待研判 ${t.riskCounts.pending}`}>{t.title}</button>;
                })}
              </div>
            </Field>
          )}
          <button className={A.more} onClick={() => setShowMore(!showMore)} aria-expanded={showMore}>
            <Icon name={showMore ? 'chevronDown' : 'chevronRight'} /> 可选项：关注点、范围、模型、预算与额度、候选与覆盖、复核、风险假设
            <span className={ui.faint} style={{ fontSize: 12, marginLeft: 'auto' }}>默认取自 设置 › 任务创建默认值</span>
          </button>
          {showMore && (
            <div className={ui.stack} style={{ gap: 16 }}>
              <Field group label="关注的漏洞类别">
                <div className={cx(ui.row, ui.wrap)}>
                  {CATEGORIES.map(([k, l]) => {
                    const on = cats.includes(k);
                    return <button key={k} className={cx(ui.chip, on && ui.chipOn)} aria-pressed={on} onClick={() => setCats(on ? cats.filter((c) => c !== k) : [...cats, k])}>{l}</button>;
                  })}
                </div>
              </Field>
              {(allConnectors.data ?? []).length > 0 && (
                <Field group label="可使用的连接器" hint="Agent 可以调用这些连接器中已开放的工具（读和写），写调用直接执行并记录；默认是项目绑定的连接器">
                  <div className={cx(ui.row, ui.wrap)}>
                    {(allConnectors.data ?? []).map((c) => {
                      const chosen = conns ?? (bound.data ?? []).map((b) => b.connectorId);
                      const on = chosen.includes(c.id);
                      return <button key={c.id} className={cx(ui.chip, on && ui.chipOn)} aria-pressed={on} disabled={c.status !== 'ready' || !c.enabled} title={c.status !== 'ready' ? '连接器未就绪（需要确认或测试）' : undefined}
                        onClick={() => setConns(on ? chosen.filter((x) => x !== c.id) : [...chosen, c.id])}>{c.name}</button>;
                    })}
                  </div>
                </Field>
              )}
              <Field label="业务关注点（自然语言）"><textarea className={ui.textarea} value={focusText} placeholder="例如：重点看订单导出与支付回调的越权" onChange={(e) => setFocusText(e.target.value)} maxLength={4000} /></Field>
              <div className={A.formGrid}>
                <Field label="只审计这些路径" hint="每行一个 glob，例如 src/main/**"><textarea className={cx(ui.textarea, ui.mono)} value={include} onChange={(e) => setInclude(e.target.value)} /></Field>
                <Field label="排除路径" hint="每行一个 glob，例如 **/test/**"><textarea className={cx(ui.textarea, ui.mono)} value={exclude} onChange={(e) => setExclude(e.target.value)} /></Field>
              </div>
              {eff && (
                <Field group label="各阶段模型" hint="默认取自 设置 › 模型；只在本次审计生效，点 ? 查看各阶段的作用">
                  <StageModelsEditor scene={sceneKind} value={stageModels ?? taskBase(eff)} onChange={setStageModels} models={allModels}
                    globalFallback={modelSettings.data?.fallbackModel ?? null}
                    enabled={{ challenge: challenge ?? eff.stages.adversarialReview ?? true, logic: (analyses ?? analysisChoiceOf(sceneKind, eff.stages)).threatHypotheses }} />
                </Field>
              )}
              <div className={A.formGrid}>
                <Field label="token 预算" hint={eff ? <>默认 {eff.budget.tokens.toLocaleString('zh-CN')} · <TokenCostHint tokens={Number(tokens || eff.budget.tokens)} model={eff.models.audit} /></> : undefined}>
                  <input className={ui.input} type="number" min={1000} step={10000} value={tokens} placeholder={eff ? String(eff.budget.tokens) : ''} onChange={(e) => setTokens(e.target.value ? Number(e.target.value) : '')} />
                </Field>
                <Field label="时长上限（分钟）" hint={eff ? `默认 ${Math.round(eff.budget.durationSec / 60)} 分钟` : undefined}>
                  <input className={ui.input} type="number" min={1} value={minutes} placeholder={eff ? String(Math.round(eff.budget.durationSec / 60)) : ''} onChange={(e) => setMinutes(e.target.value ? Number(e.target.value) : '')} />
                </Field>
              </div>
              {eff && <BudgetStagesEditor scene={sceneKind} value={shares ?? eff.budget.stages ?? {}} total={tokens || eff.budget.tokens} onChange={setShares} targets={mode === 'multi' ? multiTargets.length : 1}
                on={stageLimits ?? (eff.budget.stageLimits !== false && Object.keys(eff.budget.stages ?? {}).length > 0)} onToggle={setStageLimits}
                reviewers={(() => { const mm = (stageModels ?? taskBase(eff)).multiModel; return stageCrossed(mm, 'challenge') ? mm.models.length : 1; })()}
                hypothesisModels={(() => { const mm = (stageModels ?? taskBase(eff)).multiModel; return stageCrossed(mm, 'logic') ? mm.models.length : 1; })()} />}
              {eff && <LimitsEditor value={limits ?? limitsOf(eff)} onChange={setLimits} coverage={sceneKind === 'full'} />}
              <label className={ui.checkbox}><input type="checkbox" checked={challenge ?? eff?.stages.adversarialReview ?? true} onChange={(e) => setChallenge(e.target.checked)} />对抗复核：汇总后对每个正式发现做一次独立的反向论证（带本次审计的反向证据），降低误报</label>
              <AnalysisOptions maxCandidates={eff?.limits.maxCandidates}
                value={analyses ?? analysisChoiceOf(sceneKind, eff?.stages ?? {})} onChange={setAnalyses} />
            </div>
          )}
          {err && <div className={ui.banner} style={{ background: 'var(--danger-soft)', color: 'var(--danger)' }}><Icon name="alert" />{err}</div>}
          <div className={ui.spread} style={{ marginTop: 4 }}>
            <div className={ui.stack} style={{ gap: 4 }}>
              <label className={ui.checkbox}><input type="checkbox" checked={planFirst} onChange={(e) => setPlanFirst(e.target.checked)} />先生成计划，确认后再开始</label>
              <span className={ui.faint} style={{ fontSize: 12 }}>静态审计：不构建、不运行、不测试目标代码</span>
            </div>
            <Button variant="primary" icon={planFirst ? 'sparkle' : 'play'} loading={busy} disabled={!projectId || (mode === 'single' ? !repoId : multiTargets.length < 2) || !!noModel || (sceneKind === 'incremental' && baseRef === undefined && !lastAudit)} onClick={() => void submit()}>{planFirst ? '生成审计计划' : '开始审计'}</Button>
          </div>
        </div>
      </PageLayout>
    </>
  );
}
