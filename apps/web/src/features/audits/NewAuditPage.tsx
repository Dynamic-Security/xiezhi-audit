// Start an audit from the form: required items up front, optional ones folded; defaults
// come from settings (scene defaults). Submitting creates a plan draft (202) and opens the audit.
import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearch } from '@tanstack/react-router';
import type { AuditStrategy, AuditSummaryDto, RepoDto, ThreatModelSummaryDto } from '@xiezhi/contracts';
import { useQuery } from '@tanstack/react-query';
import { api, ApiError, newIdempotencyKey } from '../../shared/api/client';
import { useAudits, useConnectors, useModelSettings, useProjectConnectors, useProjects, useProviders, useRepos, useSceneDefaults } from '../../shared/api/queries';
import { fmt, ROLE, VULN_CATEGORY } from '../../shared/format/messages';
import { Button, Field, Icon, Segmented, cx, ui, useToast, TokenCostHint, TokenInput } from '../../shared/ui';
import { askNotifyPermission } from '../../shared/notify';
import { PageLayout, TopBar } from '../layout/AppShell';
import { RefPicker, versionLabel } from '../projects/RepoDialogs';
import A from './audits.module.css';
import { analysisChoiceOf, analysisOverride, type AnalysisChoice } from './AnalysisOptions';
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
  /** Deep exploration's full mode; null = the scene default (unchecked = on demand). */
  const [explore, setExplore] = useState<boolean | null>(null);
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
  /** Multi mode: version and incremental baseline per target id; absent = the default version / last audited version. */
  const [multiRefs, setMultiRefs] = useState<Record<string, string | null>>({});
  const [multiBases, setMultiBases] = useState<Record<string, string>>({});
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
  const canMulti = auditable.length >= 2;
  useEffect(() => { if (!canMulti && mode === 'multi') setMode('single'); }, [canMulti, mode]);
  // Default baseline: the latest finished full/incremental audit of the repository.
  const lastAuditOf = (id: string) => (finished.data?.items ?? []).find((a) => ['completed', 'partial'].includes(a.status) && ['full', 'incremental'].includes(a.scene) && a.repos.some((r) => r.id === id));
  const lastAudit = lastAuditOf(repoId);
  const chosenTargets = auditable.filter((r) => multiTargets.includes(r.id));
  // A multi-repository incremental audit needs a baseline for at least one target; the others are audited in full.
  const multiNoBase = mode === 'multi' && sceneKind === 'incremental' && !chosenTargets.some((r) => multiBases[r.id] || lastAuditOf(r.id));
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
    // Checked = the full mode; unchecked leaves the on-demand runs, unless a lower layer turned the full mode on.
    if (explore !== null && eff && explore !== eff.stages.deepExplore) override.stages = { ...(override.stages as object | undefined), deepExplore: explore };
    if (conns !== null) override.connectors = conns;
    const chosenTms = tms.filter((t) => usableTms.some((x) => x.id === t));
    if (chosenTms.length) override.threatModels = chosenTms;
    if (stageModels && eff) Object.assign(override, stageModelsDiff(taskBase(eff), stageModels));
    try {
      const pick = <T,>(m: Record<string, T>) => Object.fromEntries(Object.entries(m).filter(([id]) => multiTargets.includes(id)));
      // A ref is a string; the “default” choice (null) is the repository's default version anyway.
      const refs = Object.fromEntries(Object.entries(pick(multiRefs)).filter((e): e is [string, string] => e[1] !== null));
      const baseRefs = sceneKind === 'incremental' ? pick(multiBases) : {};
      const modeBody = mode === 'multi'
        ? { mode: 'multi', repositories: multiTargets, ...(Object.keys(refs).length ? { refs } : {}), ...(Object.keys(baseRefs).length ? { baseRefs } : {}) }
        : { repository: repoId, ...(ref !== undefined && ref !== null ? { ref } : {}), ...(related.filter((x) => x !== repoId).length ? { related: related.filter((x) => x !== repoId) } : {}) };
      const r = await api.post<{ auditId: string }>('/audit-plans', {
        projectId, ...modeBody, ...(title.trim() ? { title: title.trim() } : {}),
        scene: sceneKind, ...(sceneKind === 'incremental' && baseRef && mode === 'single' ? { baseRef } : {}),
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
              <select aria-label="场景" className={ui.select} value={sceneKind} onChange={(e) => { if (e.target.value === 'risk_hunt') { void navigate({ to: '/hunts/new' }); return; } setSceneKind(e.target.value as 'full' | 'incremental'); setChallenge(null); setExplore(null); setStageModels(null); setAnalyses(null); setShares(null); setLimits(null); }}>
                <option value="full">全量审计</option>
                <option value="incremental">增量审计</option>
                <option value="risk_hunt">风险排查（可跨项目）→</option>
              </select>
            </Field>
          </div>
          <Field group label="审计模式" hint={mode === 'multi' ? (sceneKind === 'incremental' ? '一次发布涉及的多个仓库一起做增量审计：每个仓库对比自己的基线，调用链可以跨仓库' : '多个仓库地位平等，发现可以落在任一仓库，调用链可以跨仓库') : '一个目标仓库，可以加关联仓库作为跨仓确认的依据'}>
            <Segmented value={mode} onChange={(m) => { if (m === 'multi' && !canMulti) return; setMode(m); }} items={[{ key: 'single', label: '单仓库审计' }, { key: 'multi', label: canMulti ? '多仓库合并审计' : '多仓库合并审计（需 ≥2 个可审计仓库）' }]} />
          </Field>
          {mode === 'multi' ? (
            <Field group label="审计对象" hint={contextRepos.length ? `上下文仓库 ${contextRepos.map((r) => r.name).join('、')} 自动加入，只提取接口契约` : undefined}>
              <div className={A.repoList}>
                {auditable.map((r) => {
                  const on = multiTargets.includes(r.id);
                  return (
                    <button key={r.id} role="checkbox" aria-checked={on} className={cx(A.repoOpt, on && A.repoOptOn)} onClick={() => setTargets(on ? multiTargets.filter((x) => x !== r.id) : [...multiTargets, r.id])}>
                      <Icon name="git" /><div className={ui.grow} style={{ textAlign: 'left' }}><b>{r.name}</b><div className={ui.faint} style={{ fontSize: 12 }}>{ROLE[r.role] ?? r.role}</div></div>
                      {on && <Icon name="check" />}
                    </button>
                  );
                })}
              </div>
            </Field>
          ) : null}
          {mode === 'multi' && chosenTargets.length > 0 && (
            <Field group label={sceneKind === 'incremental' ? '版本与对比基线' : '版本'} hint={sceneKind === 'incremental'
              ? (multiNoBase ? '所选仓库都还没有已完成的审计：至少为一个仓库指定基线分支或提交，或先做一次全量审计' : '每个仓库默认对比自己上次审计的版本；没有审计过、也没有指定基线的仓库（例如本次新增的服务）按全量审计')
              : '分支会在启动时解析为具体 commit 并固定'}>
              <MultiVersions repos={chosenTargets} incremental={sceneKind === 'incremental'} refs={multiRefs} bases={multiBases} lastAuditOf={lastAuditOf}
                onRef={(id, r) => setMultiRefs((m) => { const n = { ...m }; if (r === undefined) delete n[id]; else n[id] = r; return n; })}
                onBase={(id, r) => setMultiBases((m) => { const n = { ...m }; if (r === undefined) delete n[id]; else n[id] = r; return n; })} />
            </Field>
          )}
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
          <Field label="标题（可选）"><input className={ui.input} value={title} placeholder={mode === 'multi' ? `${sceneKind === 'incremental' ? '增量审计' : '全量审计'} · ${chosenTargets.map((r) => r.name).join(', ')}` : repo ? `${sceneKind === 'incremental' ? '增量审计' : '全量审计'} · ${repo.name}` : ''} onChange={(e) => setTitle(e.target.value)} /></Field>

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
            <Icon name={showMore ? 'chevronDown' : 'chevronRight'} /> 可选项：关注点、范围、审计流程与模型、预算与额度、候选与覆盖
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
                <Field group label="审计流程与模型" hint="模型默认取自 设置 › 模型，可选阶段的开关默认取自 设置 › 任务创建默认值；只在本次审计生效，点 ⓘ 查看各阶段的作用">
                  <StageModelsEditor scene={sceneKind} value={stageModels ?? taskBase(eff)} onChange={setStageModels} models={allModels}
                    globalFallback={modelSettings.data?.fallbackModel ?? null}
                    switches={{
                      value: { challenge: challenge ?? eff.stages.adversarialReview, logic: (analyses ?? analysisChoiceOf(sceneKind, eff.stages)).threatHypotheses, explore: explore ?? eff.stages.deepExplore },
                      onChange: (v) => { setChallenge(v.challenge); setAnalyses({ threatHypotheses: v.logic }); setExplore(v.explore); },
                      maxCandidates: (limits ?? limitsOf(eff)).maxCandidates, rounds: eff.limits.maxRounds, exploreBaseOn: eff.stages.deepExplore,
                    }} />
                </Field>
              )}
              <div className={A.formGrid}>
                <Field label="token 预算" hint={eff ? <>默认 {fmt.tokens(eff.budget.tokens)} · <TokenCostHint tokens={Number(tokens || eff.budget.tokens)} model={eff.models.audit} /></> : undefined}>
                  <TokenInput value={tokens} placeholder={eff?.budget.tokens} onChange={setTokens} />
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
            </div>
          )}
          {err && <div className={ui.banner} style={{ background: 'var(--danger-soft)', color: 'var(--danger)' }}><Icon name="alert" />{err}</div>}
          <div className={ui.spread} style={{ marginTop: 4 }}>
            <div className={ui.stack} style={{ gap: 4 }}>
              <label className={ui.checkbox}><input type="checkbox" checked={planFirst} onChange={(e) => setPlanFirst(e.target.checked)} />先生成计划，确认后再开始</label>
              <span className={ui.faint} style={{ fontSize: 12 }}>静态审计：不构建、不运行、不测试目标代码</span>
            </div>
            <Button variant="primary" icon={planFirst ? 'sparkle' : 'play'} loading={busy} disabled={!projectId || (mode === 'single' ? !repoId : multiTargets.length < 2) || !!noModel || (sceneKind === 'incremental' && (mode === 'multi' ? multiNoBase : baseRef === undefined && !lastAudit))} onClick={() => void submit()}>{planFirst ? '生成审计计划' : '开始审计'}</Button>
          </div>
        </div>
      </PageLayout>
    </>
  );
}

/** Multi mode: each target's version and, for an incremental audit, its baseline — both changeable per repository. */
function MultiVersions({ repos, incremental, refs, bases, lastAuditOf, onRef, onBase }: {
  repos: RepoDto[]; incremental: boolean; refs: Record<string, string | null>; bases: Record<string, string>;
  lastAuditOf: (id: string) => AuditSummaryDto | undefined;
  /** undefined = back to the default. */
  onRef: (id: string, ref: string | null | undefined) => void; onBase: (id: string, ref: string | undefined) => void;
}) {
  const [picking, setPicking] = useState<{ id: string; kind: 'ref' | 'base' } | null>(null);
  return (
    <div className={ui.stack} style={{ gap: 8 }}>
      {repos.map((r) => {
        const last = lastAuditOf(r.id);
        const canPick = r.sourceKind !== 'archive';
        const open = picking?.id === r.id ? picking.kind : null;
        const toggle = (kind: 'ref' | 'base') => setPicking(open === kind ? null : { id: r.id, kind });
        return (
          <div key={r.id} className={ui.stack} style={{ gap: 6 }}>
            <div className={cx(ui.row, ui.wrap)}>
              <b style={{ minWidth: 140 }}>{r.name}</b>
              <span className={ui.chip} style={{ cursor: 'default' }}><Icon name="git" size={12} />{r.id in refs ? versionLabel(r, refs[r.id] ?? null) : `${versionLabel(r, r.defaultRef)}（默认）`}</span>
              {canPick && <Button size="sm" variant="ghost" onClick={() => toggle('ref')}>{open === 'ref' ? '收起' : '更改版本'}</Button>}
              {incremental && (
                <>
                  <span className={ui.faint}>对比</span>
                  <span className={ui.chip} style={{ cursor: 'default' }}>
                    {bases[r.id] ?? (last ? `上次审计的版本 · ${last.repos.find((x) => x.id === r.id)?.commit?.slice(0, 7) ?? '工作区版本'} · ${fmt.date(last.endedAt ?? last.createdAt)}` : '没有基线：按全量审计')}
                  </span>
                  {canPick && <Button size="sm" variant="ghost" onClick={() => toggle('base')}>{open === 'base' ? '收起' : '更改基线'}</Button>}
                  {bases[r.id] !== undefined && <Button size="sm" variant="ghost" onClick={() => onBase(r.id, undefined)}>{last ? '改回上次审计的版本' : '不指定基线'}</Button>}
                </>
              )}
            </div>
            {open === 'ref' && <RefPicker repoId={r.id} sourceKind={r.sourceKind} value={refs[r.id] ?? r.defaultRef} onPick={(x) => { onRef(r.id, x); setPicking(null); }} />}
            {open === 'base' && <RefPicker repoId={r.id} sourceKind={r.sourceKind} nullLabel={null} value={bases[r.id] ?? null} onPick={(x) => { if (x) onBase(r.id, x); setPicking(null); }} />}
          </div>
        );
      })}
    </div>
  );
}
