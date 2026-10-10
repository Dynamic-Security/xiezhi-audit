// Settings: model providers (keys write-only), model settings (default, per stage, fallback), Git HTTPS credentials (tokens
// write-only), per-scene task defaults, general (concurrency, export, pricing), system diagnostics.
import { useEffect, useState } from 'react';
import { Link, useParams } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { AuditStrategy, GitCredentialDto, ModelRef, ProviderDto } from '@xiezhi/contracts';
import { api, ApiError } from '../../shared/api/client';
import { useDiagnostics, useGeneral, useGitCredentials, useKnowledge, useModelSettings, useProviders, useSceneDefaults } from '../../shared/api/queries';
import { askNotifyPermission, notifyEnabled, notifyPermission, setNotifyEnabled } from '../../shared/notify';
import { fmt } from '../../shared/format/messages';
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Field, Icon, Loading, Segmented, cx, ui, useToast, TokenCostHint } from '../../shared/ui';
import { PageLayout, Section, TopBar } from '../layout/AppShell';
import S from './settings.module.css';
import { ConnectorsSection } from './ConnectorsSection';
import { ProviderDialog } from './ProviderDialog';
import { AnalysisOptions, analysisChoiceOf, analysisOverride, type AnalysisChoice } from '../audits/AnalysisOptions';
import { BudgetStagesEditor, LimitsEditor, limitsOf, limitsOverride, type LimitsValue, type StageShares } from '../audits/BudgetLimits';
import { CHAT_LABEL, CrossModelsEditor, STAGE_LABEL, StageHelp, type GuideStage } from '../audits/StageModels';
import SM from '../audits/stagemodels.module.css';

const SECTIONS = [
  { key: 'models', label: '模型', icon: 'sparkle' as const },
  { key: 'git', label: 'Git 凭证', icon: 'git' as const },
  { key: 'connectors', label: '连接器', icon: 'link' as const },
  { key: 'defaults', label: '任务创建默认值', icon: 'layers' as const },
  { key: 'general', label: '通用', icon: 'settings' as const },
  { key: 'diagnostics', label: '系统诊断', icon: 'activity' as const },
];

type StageMap = Partial<Record<GuideStage, ModelRef | null>>;
/**
 * Settings stages in execution order (engine `runAudit` ④–⑫): plan and profile, the incremental impact slice,
 * the threat model (risk hypotheses, alongside triage), triage, hunt, reconcile, deep exploration, adversarial review;
 * then reverification / risk hunting (their own scenes), the report and conversations.
 */
const SETTINGS_STAGES: GuideStage[] = ['profile', 'scope', 'logic', 'triage', 'hunt', 'merge', 'explore', 'challenge', 'verify', 'report', 'chat'];
const NO_MODEL: GuideStage[] = ['triage', 'merge'];
const THINKING_OPTS: [NonNullable<ModelRef['thinking']> | '', string][] = [['', '默认'], ['off', '关'], ['low', '低'], ['medium', '中'], ['high', '高']];
const NONE = '__none__';
const refKey = (m: ModelRef | null | undefined) => (m ? `${m.provider}/${m.model}` : '');
const parseRef = (x: string): ModelRef | null => { const i = x.indexOf('/'); return x ? { provider: x.slice(0, i), model: x.slice(i + 1) } : null; };
const withThinking = (m: ModelRef, t: string): ModelRef => { const { thinking: _, ...rest } = m; return t ? { ...rest, thinking: t as NonNullable<ModelRef['thinking']> } : rest; };

/**
 * Model settings: the default model, a model per stage (absent = the default; triage and merge
 * can also run without a model) and one fallback for any stage whose model is unavailable.
 */
function ModelRoles() {
  const ms = useModelSettings();
  const providers = useProviders();
  const [draft, setDraft] = useState<{ defaultModel: ModelRef | null; stageModels: StageMap; fallbackModel: ModelRef | null; confidentialModels: string[] } | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  useEffect(() => { if (ms.data) setDraft({ defaultModel: ms.data.defaultModel, stageModels: { ...ms.data.stageModels }, fallbackModel: ms.data.fallbackModel, confidentialModels: [...(ms.data.confidentialModels ?? [])] }); }, [ms.data]);
  if (!draft || !ms.data) return <Loading />;
  const all = (providers.data ?? []).flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`));
  const options = (cur: ModelRef | null | undefined) => [...(!cur || all.includes(refKey(cur)) ? [] : [refKey(cur)]), ...all].map((m) => <option key={m} value={m}>{m}{all.includes(m) ? '' : '（未配置）'}</option>);
  const setStage = (st: GuideStage, v: ModelRef | null | undefined) => {
    const next = { ...draft.stageModels };
    if (v === undefined) delete next[st]; else next[st] = v;
    setDraft({ ...draft, stageModels: next });
  };
  const thinkingSel = (label: string, m: ModelRef | null | undefined, set: (m: ModelRef) => void, disabled = false, title?: string) => (
    <select aria-label={label} className={cx(ui.select, SM.think)} disabled={disabled || !m} title={title} value={m?.thinking ?? ''} onChange={(e) => set(withThinking(m!, e.target.value))}>
      {THINKING_OPTS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
    </select>
  );
  const save = async () => {
    try { await api.put('/settings/models', { ...draft, revision: ms.data!.revision }); toast.ok('已保存，之后新建的审计按这里的模型执行'); } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['settings'] });
  };
  const def = draft.defaultModel;
  const fb = draft.fallbackModel;
  const row = (st: GuideStage) => {
    const label = st === 'chat' ? CHAT_LABEL : STAGE_LABEL[st];
    const own = draft.stageModels[st];
    const value = own === undefined ? '' : own === null ? NONE : refKey(own);
    return (
      <tr key={st}>
        <th scope="row" className={SM.stage}><span className={SM.stageName}>{label}<StageHelp stage={st} label={label} /></span></th>
        <td>
          <select aria-label={`${label}模型`} className={cx(ui.select, SM.sel)} value={value} onChange={(e) => {
            const x = e.target.value;
            setStage(st, x === '' ? undefined : x === NONE ? null : parseRef(x));
          }}>
            <option value="">{def ? `跟随默认模型（${refKey(def)}）` : '跟随默认模型'}</option>
            {NO_MODEL.includes(st) && <option value={NONE}>不使用模型（确定性处理）</option>}
            {options(own)}
          </select>
        </td>
        <td>{own ? thinkingSel(`${label}思考强度`, own, (m) => setStage(st, m)) : thinkingSel(`${label}思考强度`, own === null ? null : def, () => undefined, true, own === null ? '不使用模型' : '跟随默认模型的思考强度')}</td>
      </tr>
    );
  };
  return (
    <div className={cx(ui.card, ui.cardPad, ui.stack)}>
      <div className={S.modelPairs}>
        <div className={S.modelPair}>
          <Field label="默认模型" hint="各阶段未单独指定时都用它">
            <select aria-label="默认模型" className={ui.select} value={refKey(def)} onChange={(e) => { const m = parseRef(e.target.value); setDraft({ ...draft, defaultModel: m && def?.thinking ? { ...m, thinking: def.thinking } : m }); }}>
              <option value="">未设置</option>
              {options(def)}
            </select>
          </Field>
          <Field label="思考强度">{thinkingSel('默认模型思考强度', def, (m) => setDraft({ ...draft, defaultModel: m }))}</Field>
        </div>
        <div className={S.modelPair}>
          <Field label="备用模型" hint="任一阶段的模型不存在、鉴权失败或重试用尽时切换到它；每个作业最多切换一次">
            <select aria-label="备用模型" className={ui.select} value={refKey(fb)} onChange={(e) => { const m = parseRef(e.target.value); setDraft({ ...draft, fallbackModel: m && fb?.thinking ? { ...m, thinking: fb.thinking } : m }); }}>
              <option value="">不切换</option>
              {options(fb)}
            </select>
          </Field>
          <Field label="思考强度">{thinkingSel('备用模型思考强度', fb, (m) => setDraft({ ...draft, fallbackModel: m }), false, fb ? undefined : '未设置备用模型')}</Field>
        </div>
      </div>
      <Field group label="各阶段模型" hint="未单独指定的阶段跟随默认模型；点 ? 查看每个阶段做什么、适合什么模型。发起审计时还可以只对本次调整">
        <div className={SM.scroll}>
          <table className={cx(ui.table, SM.table)}>
            <colgroup><col className={SM.cStage} /><col /><col className={SM.cThink} /></colgroup>
            <thead><tr><th>阶段</th><th>模型</th><th>思考强度</th></tr></thead>
            <tbody>{SETTINGS_STAGES.map(row)}</tbody>
          </table>
        </div>
      </Field>
      <Field group label="可接收机密事实的模型" hint="标为“机密”的企业事实只发给这里勾选的模型（例如内网部署的模型）；其他模型的会话里不出现这些事实，外发记录中计为“未发送的机密事实”">
        <div className={cx(ui.row, ui.wrap)} style={{ gap: 12 }}>
          {all.length === 0 ? <span className={ui.faint}>还没有配置模型</span> : all.map((k) => (
            <label key={k} className={ui.row} style={{ gap: 6 }}>
              <input type="checkbox" aria-label={`机密事实 ${k}`} checked={draft.confidentialModels.includes(k)}
                onChange={(e) => setDraft({ ...draft, confidentialModels: e.target.checked ? [...draft.confidentialModels, k] : draft.confidentialModels.filter((x) => x !== k) })} />
              <span className={ui.mono}>{k}</span>
            </label>
          ))}
        </div>
      </Field>
      <div><Button variant="primary" onClick={() => void save()}>保存</Button></div>
    </div>
  );
}

function ModelsSection() {
  const providers = useProviders();
  const [edit, setEdit] = useState<ProviderDto | null | 'new'>(null);
  /** The dialog was opened by a card's “探测可用模型”: it probes at once. */
  const [probeOnOpen, setProbeOnOpen] = useState(false);
  const [del, setDel] = useState<ProviderDto | null>(null);
  const [testing, setTesting] = useState<string | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const test = async (id: string) => {
    setTesting(id);
    try {
      const r = await api.post<{ ok: boolean; detail: string }>(`/settings/model-providers/${id}/test`);
      if (r.ok) toast.ok(`${id}：${r.detail}`); else toast.error(new Error(r.detail), `${id} 连通性测试失败`);
    } catch (e) { toast.error(e); }
    setTesting(null);
    await qc.invalidateQueries({ queryKey: ['settings', 'providers'] });
  };
  return (
    <>
      <Section title="模型服务" actions={<Button variant="primary" size="sm" icon="plus" onClick={() => setEdit('new')}>添加</Button>}>
        {providers.isLoading ? <Loading /> : providers.data!.length === 0 ? (
          <div className={ui.card}><EmptyState icon="sparkle" title="还没有模型服务" action={<Button variant="primary" icon="plus" onClick={() => setEdit('new')}>添加模型服务</Button>}>支持 OpenAI 兼容接口与 Anthropic Messages 接口。</EmptyState></div>
        ) : (
          <div className={ui.stack}>
            {providers.data!.map((p) => (
              <div key={p.id} className={cx(ui.card, S.provider)}>
                <div className={ui.grow}>
                  <div className={ui.row}><b>{p.id}</b><Badge>{p.api}</Badge>{p.apiKey.configured ? <Badge tone="ok">密钥已配置{p.apiKey.hint ? ` · ${p.apiKey.hint}` : ''}</Badge> : <Badge tone="warn">未配置密钥</Badge>}
                    {p.lastTest && <Badge tone={p.lastTest.ok ? 'ok' : 'danger'}>{p.lastTest.ok ? '连通' : '不通'} · {fmt.time(p.lastTest.at)}</Badge>}</div>
                  <div className={cx(ui.mono, ui.faint)} style={{ fontSize: 12, marginTop: 4 }}>{p.baseUrl}</div>
                  <div className={cx(ui.row, ui.wrap)} style={{ marginTop: 8, gap: 4 }}>{p.models.map((m) => <span key={m.id} className={ui.chip} style={{ cursor: 'default', height: 24 }}>{m.id}</span>)}</div>
                </div>
                <div className={ui.row} style={{ alignSelf: 'flex-start' }}>
                  <Button size="sm" icon="search" onClick={() => { setProbeOnOpen(true); setEdit(p); }}>探测可用模型</Button>
                  <Button size="sm" loading={testing === p.id} onClick={() => void test(p.id)}>测试连通性</Button>
                  <Button size="sm" icon="edit" aria-label="编辑" onClick={() => setEdit(p)} />
                  <Button size="sm" variant="ghost" icon="trash" aria-label="删除" onClick={() => setDel(p)} />
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
      <Section title="模型配置"><ModelRoles /></Section>
      <ProviderDialog open={edit !== null} existing={edit === 'new' ? null : edit} autoProbe={probeOnOpen} onClose={() => { setEdit(null); setProbeOnOpen(false); }} />
      <ConfirmDialog open={!!del} onClose={() => setDel(null)} title={`删除模型服务 ${del?.id ?? ''}`} level="destructive" confirmText="删除"
        onConfirm={async () => { try { await api.del(`/settings/model-providers/${del!.id}`); toast.ok('已删除'); } catch (e) { toast.error(e); } setDel(null); await qc.invalidateQueries({ queryKey: ['settings'] }); }}>
        删除后配置文件中的密钥一并清除。已冻结策略的审计不受影响，但无法再继续运行使用该服务的审计。
      </ConfirmDialog>
    </>
  );
}

const SCENE_TABS = [{ key: 'full', label: '全量审计' }, { key: 'incremental', label: '增量审计' }, { key: 'risk_hunt', label: '风险排查' }, { key: 'reverify', label: '漏洞复验' }] as const;
type SceneKey = (typeof SCENE_TABS)[number]['key'];

/** Task defaults per scene (the API took all four scenes, the page only showed “全量”). */
function DefaultsSection() {
  const [scene, setScene] = useState<SceneKey>('full');
  const sd = useSceneDefaults(scene);
  const [tokens, setTokens] = useState<number>(0);
  const [minutes, setMinutes] = useState<number>(0);
  const [challenge, setChallenge] = useState(true);
  const [analyses, setAnalyses] = useState<AnalysisChoice>({ threatHypotheses: false });
  const [sessions, setSessions] = useState(4);
  const [exclude, setExclude] = useState('');
  const [limits, setLimits] = useState<LimitsValue | null>(null);
  const [shares, setShares] = useState<StageShares | null>(null);
  const [stageLimits, setStageLimits] = useState(false);
  const [cross, setCross] = useState<AuditStrategy['multiModel'] | null>(null);
  const providers = useProviders();
  const allModels = (providers.data ?? []).flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`));
  const qc = useQueryClient();
  const toast = useToast();
  const eff = sd.data?.effective as AuditStrategy | null | undefined;
  useEffect(() => {
    if (!eff) return;
    setTokens(eff.budget.tokens); setMinutes(Math.round(eff.budget.durationSec / 60)); setChallenge(eff.stages.adversarialReview); setSessions(eff.concurrency.sessions);
    setAnalyses(analysisChoiceOf(scene, eff.stages));
    setExclude(eff.scope.exclude.join('\n')); setLimits(limitsOf(eff)); setShares(scene === 'full' || scene === 'incremental' ? { ...eff.budget.stages } : null);
    setStageLimits(eff.budget.stageLimits !== false && Object.keys(eff.budget.stages ?? {}).length > 0);
    setCross(structuredClone(eff.multiModel));
  }, [sd.data]);
  if (sd.isLoading) return <Loading />;
  if (!eff) return <EmptyState icon="sparkle" title="先配置模型">任务默认值依赖默认模型。<Link to="/settings/$section" params={{ section: 'models' }}>前往模型设置</Link></EmptyState>;
  const optional = scene === 'full' || scene === 'incremental';
  const save = async () => {
    // stage models live in settings → 模型; a scene layer keeps only the multi-model group.
    const a = optional ? analysisOverride(scene, analyses) : null;
    const { models: _m, modelFallbacks: _f, ...prev } = sd.data!.override as Record<string, unknown>;
    const lim = optional && limits ? limitsOverride(limits) : {};
    const override = {
      ...prev,
      ...(cross && JSON.stringify(cross) !== JSON.stringify(eff.multiModel) ? { multiModel: cross } : {}),
      budget: { tokens, durationSec: minutes * 60, ...(shares && Object.keys(shares).length ? { stages: shares } : {}), ...(shares ? { stageLimits } : {}) }, stages: { adversarialReview: challenge, ...(a?.stages ?? {}) }, concurrency: { sessions },
      scope: { exclude: exclude.split('\n').map((x) => x.trim()).filter(Boolean) },
      // candidate limit for full and incremental; coverage targets and shortfall handling for full.
      ...(lim.limits ? { limits: lim.limits } : {}), ...(scene === 'full' && lim.coverageTarget ? { coverageTarget: lim.coverageTarget } : {}),
    };
    try { await api.put(`/settings/scene-defaults/${scene}`, { override, revision: sd.data!.revision }); toast.ok(`已保存，之后新建的${SCENE_TABS.find((x) => x.key === scene)!.label}会使用这些默认值`); } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['settings', 'scene'] });
  };
  return (
    <Section title="任务创建默认值">
      <div className={cx(ui.card, ui.cardPad, ui.stack)} style={{ gap: 16 }}>
        <Segmented value={scene} onChange={(s) => setScene(s)} items={SCENE_TABS.map((x) => ({ key: x.key, label: x.label }))} />
        <p className={ui.muted} style={{ fontSize: 13 }}>按场景分别设置。审计启动时，这些默认值与发起时的调整合并后冻结；之后修改设置不影响已开始的审计。各阶段模型在“模型”里设置。</p>
        <div className={S.grid3}>
          <Field label="token 预算" hint={<TokenCostHint tokens={tokens} model={eff?.models.audit} />}><input className={ui.input} type="number" min={1000} step={10000} value={tokens} onChange={(e) => setTokens(Number(e.target.value))} /></Field>
          <Field label="时长上限（分钟）"><input className={ui.input} type="number" min={1} value={minutes} onChange={(e) => setMinutes(Number(e.target.value))} /></Field>
          <Field label="并行会话数"><input className={ui.input} type="number" min={1} max={16} value={sessions} onChange={(e) => setSessions(Number(e.target.value))} /></Field>
        </div>
        {shares && <BudgetStagesEditor scene={scene} value={shares} total={tokens} onChange={setShares} on={stageLimits} onToggle={setStageLimits} />}
        {optional && limits && <LimitsEditor value={limits} onChange={setLimits} coverage={scene === 'full'} />}
        <label className={ui.checkbox}><input type="checkbox" checked={challenge} onChange={(e) => setChallenge(e.target.checked)} />对抗复核：汇总后对每个正式发现做一次独立的反向论证</label>
        {optional && <AnalysisOptions value={analyses} onChange={setAnalyses} maxCandidates={eff.limits.maxCandidates} />}
        {optional && cross && (
          <Field group label="多模型交叉" hint="各阶段用哪个模型在 设置 › 模型 中配置">
            <CrossModelsEditor value={cross} onChange={setCross} models={allModels} hunt={eff.models.audit} />
          </Field>
        )}
        <Field label="默认排除路径" hint="每行一个 glob"><textarea className={cx(ui.textarea, ui.mono)} value={exclude} onChange={(e) => setExclude(e.target.value)} /></Field>
        <div><Button variant="primary" onClick={() => void save()}>保存</Button></div>
      </div>
    </Section>
  );
}

/** Browser-side preference: not part of the server settings. */
function NotificationSetting() {
  const [on, setOn] = useState(notifyEnabled());
  const [perm, setPerm] = useState(notifyPermission());
  const toggle = (v: boolean) => { setOn(v); setNotifyEnabled(v); setTimeout(() => setPerm(notifyPermission()), 1500); };
  return (
    <div className={cx(ui.card, ui.cardPad, ui.stack)} style={{ gap: 8, marginTop: 12 }}>
      <label className={ui.checkbox}><input type="checkbox" checked={on} onChange={(e) => toggle(e.target.checked)} />系统通知：审计结束、Agent 提问、预算不足时提醒（页面在后台时）</label>
      <span className={ui.faint} style={{ fontSize: 12 }}>
        {perm === 'unsupported' ? '当前浏览器不支持系统通知。' : perm === 'granted' ? '浏览器已允许。标签页标题会显示待处理数量。' : perm === 'denied' ? '浏览器已拒绝通知，需要在浏览器的网站设置中允许。' : '尚未授权：开启后浏览器会询问一次。'}
      </span>
      {on && perm === 'default' && <div><Button size="sm" onClick={() => { askNotifyPermission(); setTimeout(() => setPerm(notifyPermission()), 1500); }}>请求授权</Button></div>}
    </div>
  );
}

function GeneralSection() {
  const g = useGeneral();
  const [draft, setDraft] = useState<{ audits: number; modelRequests: number; pauseGraceSec: number; snippets: boolean; localRoots: boolean; reportSkill: string; pricing: string } | null>(null);
  const skills = useKnowledge();
  const qc = useQueryClient();
  const toast = useToast();
  useEffect(() => {
    if (g.data) setDraft({ audits: g.data.concurrency.audits, modelRequests: g.data.concurrency.modelRequests, pauseGraceSec: g.data.engine.pauseGraceSec, snippets: g.data.export.snippets, localRoots: g.data.export.localRoots, reportSkill: g.data.export.reportSkill ?? '', pricing: JSON.stringify(g.data.pricing, null, 2) });
  }, [g.data]);
  if (!draft || !g.data) return <Loading />;
  const save = async () => {
    let pricing: unknown;
    try { pricing = JSON.parse(draft.pricing || '{}'); } catch { toast.error(new Error('价格表不是有效的 JSON')); return; }
    try {
      await api.patch('/settings/general', {
        revision: g.data!.revision, concurrency: { audits: draft.audits, modelRequests: draft.modelRequests }, engine: { pauseGraceSec: draft.pauseGraceSec },
        export: { snippets: draft.snippets, localRoots: draft.localRoots, reportSkill: draft.reportSkill || null }, pricing,
      });
      toast.ok('已保存');
    } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['settings', 'general'] });
  };
  return (
    <Section title="通用">
      <div className={cx(ui.card, ui.cardPad, ui.stack)} style={{ gap: 16 }}>
        <div className={S.grid3}>
          <Field label="同时运行的审计数" hint="其余排队"><input className={ui.input} type="number" min={1} max={8} value={draft.audits} onChange={(e) => setDraft({ ...draft, audits: Number(e.target.value) })} /></Field>
          <Field label="全局模型并发上限"><input className={ui.input} type="number" min={1} max={64} value={draft.modelRequests} onChange={(e) => setDraft({ ...draft, modelRequests: Number(e.target.value) })} /></Field>
          <Field label="暂停宽限期（秒）" hint="超时后中止进行中的会话"><input className={ui.input} type="number" min={0} value={draft.pauseGraceSec} onChange={(e) => setDraft({ ...draft, pauseGraceSec: Number(e.target.value) })} /></Field>
        </div>
        <label className={ui.checkbox}><input type="checkbox" checked={draft.snippets} onChange={(e) => setDraft({ ...draft, snippets: e.target.checked })} />导出默认包含代码片段</label>
        <label className={ui.checkbox}><input type="checkbox" checked={draft.localRoots} onChange={(e) => setDraft({ ...draft, localRoots: e.target.checked })} />SARIF 默认写入本机绝对路径</label>
        <Field label="默认报告规范 skill" hint="导出 Markdown 时使用；报告 skill 可附带 template.md 调整章节顺序与标题">
          <select className={ui.input} value={draft.reportSkill} onChange={(e) => setDraft({ ...draft, reportSkill: e.target.value })}>
            <option value="">内置默认布局</option>
            {(skills.data ?? []).filter((s) => s.valid && s.category === 'report').map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
          </select>
        </Field>
        <Field label="价格表（每百万 token）" hint={'键为 provider/model，例如 {"gw/openai/gpt-6-luna": {"currency": "USD", "input": 1.25, "output": 10}}；缺失的模型成本显示为“未知”'}>
          <textarea className={cx(ui.textarea, ui.mono)} style={{ minHeight: 140 }} value={draft.pricing} onChange={(e) => setDraft({ ...draft, pricing: e.target.value })} />
        </Field>
        <div><Button variant="primary" onClick={() => void save()}>保存</Button></div>
      </div>
      <NotificationSetting />
    </Section>
  );
}

function DiagnosticsSection() {
  const d = useDiagnostics();
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const rerun = async () => {
    setBusy(true);
    try { const r = await api.post('/diagnostics/run'); qc.setQueryData(['diagnostics'], r); } catch { /* shown by query */ }
    setBusy(false);
  };
  if (d.isLoading) return <Loading rows={6} />;
  const x = d.data!;
  const TONE = { ok: 'ok', fatal: 'danger', block: 'danger', warn: 'warn', info: 'info' } as const;
  return (
    <>
      <Section title="环境与依赖" actions={<Button size="sm" icon="refresh" loading={busy} onClick={() => void rerun()}>重新检查</Button>}>
        <div className={ui.card} style={{ overflow: 'auto' }}>
          <table className={ui.table}>
            <thead><tr><th>检查项</th><th>状态</th><th>详情</th><th>影响 / 修复</th></tr></thead>
            <tbody>{x.checks.map((c) => (
              <tr key={c.name}><td><b>{c.name}</b></td><td><Badge tone={TONE[c.level as keyof typeof TONE]}>{c.level.toUpperCase()}</Badge></td><td className={ui.mono} style={{ fontSize: 12, maxWidth: 380, overflowWrap: 'anywhere' }}>{c.detail}</td><td style={{ fontSize: 12 }}>{c.impact}{c.fix ? <div className={ui.faint}>{c.fix}</div> : null}</td></tr>
            ))}</tbody>
          </table>
        </div>
        <p className={ui.faint} style={{ fontSize: 12, marginTop: 6 }}>检查时间：{fmt.date(x.checkedAt)}</p>
      </Section>
      <Section title="存储占用">
        <div className={S.storage}>{Object.entries(x.storage).map(([k, v]) => <div key={k} className={ui.card} style={{ padding: 12 }}><div className={ui.faint} style={{ fontSize: 12 }}>{k}</div><b>{(v / 1024 / 1024).toFixed(1)} MB</b></div>)}</div>
      </Section>
      <Section title="运行状态">
        <dl className={cx(ui.kv, ui.card, ui.cardPad)}>
          <dt>应用版本</dt><dd>{x.runtime.version}</dd><dt>Agent 运行时（pi）</dt><dd>{x.runtime.piVersion}</dd><dt>进程</dt><dd>pid {x.runtime.pid} · 已运行 {fmt.duration(x.runtime.uptimeSec * 1000)}</dd>
          <dt>审计队列</dt><dd>排队 {x.runtime.queued} · 运行 {x.runtime.running}</dd>
        </dl>
      </Section>
      <Section title="最近错误">
        {x.recentErrors.length === 0 ? <p className={ui.faint}>无</p> : (
          <div className={ui.card} style={{ overflow: 'auto' }}><table className={ui.table}><thead><tr><th>时间</th><th>请求 ID</th><th>错误</th></tr></thead>
            <tbody>{x.recentErrors.map((e) => <tr key={e.requestId}><td>{fmt.date(e.ts)}</td><td className={ui.mono} style={{ fontSize: 12 }}>{e.requestId}</td><td style={{ fontSize: 12 }}>{e.code} · {e.message}</td></tr>)}</tbody></table></div>
        )}
      </Section>
    </>
  );
}

function GitCredentialDialog({ open, onClose, existing }: { open: boolean; onClose: () => void; existing: GitCredentialDto | null }) {
  const [host, setHost] = useState('');
  const [username, setUsername] = useState('');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  useEffect(() => { if (open) { setHost(existing?.host ?? ''); setUsername(existing?.username ?? ''); setToken(''); setErr(null); } }, [open, existing]);
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.put(`/settings/git-credentials/${encodeURIComponent(host.trim().toLowerCase())}`, { username: username.trim(), ...(token ? { token } : {}) });
      setToken('');
      toast.ok('已保存');
      await qc.invalidateQueries({ queryKey: ['settings', 'git-credentials'] });
      onClose();
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : String(e));
    }
    setBusy(false);
  };
  return (
    <Dialog open={open} onClose={onClose} title={existing ? `编辑 Git 凭证 · ${existing.host}` : '添加 Git 凭证'} footer={<>
      <Button onClick={onClose}>取消</Button><Button variant="primary" loading={busy} disabled={!host.trim() || !username.trim() || (!existing && !token)} onClick={() => void save()}>保存</Button>
    </>}>
      <Field label="域名" hint="例如 github.com、gitlab.example.com:8443；只用于该域名的 HTTPS 地址">
        <input className={cx(ui.input, ui.mono)} value={host} disabled={!!existing} onChange={(e) => setHost(e.target.value)} placeholder="gitlab.example.com" />
      </Field>
      <Field label="用户名" hint="GitHub 可填任意非空值；GitLab 个人访问令牌可填 oauth2">
        <input className={ui.input} value={username} onChange={(e) => setUsername(e.target.value)} />
      </Field>
      <Field label="Token" hint={existing?.token.configured ? `已配置${existing.token.hint ? `（${existing.token.hint}）` : ''}；留空表示不变` : '只读权限即可；保存后不再显示原值'}>
        <input className={cx(ui.input, ui.mono)} type="password" autoComplete="off" value={token} onChange={(e) => setToken(e.target.value)} />
      </Field>
      {err && <div className={ui.error}>{err}</div>}
    </Dialog>
  );
}

function GitSection() {
  const creds = useGitCredentials();
  const [edit, setEdit] = useState<GitCredentialDto | null | 'new'>(null);
  const [del, setDel] = useState<GitCredentialDto | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  return (
    <>
      <Section title="Git 凭证" actions={<Button variant="primary" size="sm" icon="plus" onClick={() => setEdit('new')}>添加</Button>}>
        <p className={ui.muted}>用于拉取私有 HTTPS 仓库。token 只保存在本机配置文件中，只在 git 拉取时通过一次性通道传给 git，不写入仓库配置、日志或快照。SSH 地址（git@…）使用本机 SSH 密钥与 ssh-agent，无需在此配置。</p>
        {creds.isLoading ? <Loading /> : creds.data!.length === 0 ? (
          <div className={ui.card}><EmptyState icon="git" title="还没有 Git 凭证" action={<Button variant="primary" icon="plus" onClick={() => setEdit('new')}>添加 Git 凭证</Button>}>公开仓库不需要凭证。</EmptyState></div>
        ) : (
          <div className={ui.stack}>
            {creds.data!.map((c) => (
              <div key={c.host} className={cx(ui.card, S.provider)}>
                <div className={ui.grow}>
                  <div className={ui.row}><b className={ui.mono}>{c.host}</b><Badge>{c.username}</Badge>{c.token.configured ? <Badge tone="ok">token 已配置{c.token.hint ? ` · ${c.token.hint}` : ''}</Badge> : <Badge tone="warn">未配置 token</Badge>}</div>
                </div>
                <div className={ui.row} style={{ alignSelf: 'flex-start' }}>
                  <Button size="sm" icon="edit" aria-label="编辑" onClick={() => setEdit(c)} />
                  <Button size="sm" variant="ghost" icon="trash" aria-label="删除" onClick={() => setDel(c)} />
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>
      <GitCredentialDialog open={edit !== null} existing={edit === 'new' ? null : edit} onClose={() => setEdit(null)} />
      <ConfirmDialog open={!!del} onClose={() => setDel(null)} title={`删除 ${del?.host ?? ''} 的 Git 凭证`} level="destructive" confirmText="删除"
        onConfirm={async () => { try { await api.del(`/settings/git-credentials/${encodeURIComponent(del!.host)}`); toast.ok('已删除'); } catch (e) { toast.error(e); } setDel(null); await qc.invalidateQueries({ queryKey: ['settings', 'git-credentials'] }); }}>
        之后拉取该域名下的私有仓库会认证失败，直到重新配置。
      </ConfirmDialog>
    </>
  );
}

export function SettingsPage() {
  const { section } = useParams({ from: '/settings/$section' });
  const cur = SECTIONS.find((s) => s.key === section) ?? SECTIONS[0]!;
  return (
    <>
      <TopBar crumbs={[{ label: '设置' }, { label: cur.label }]} />
      <PageLayout>
        <div className={S.layout}>
          <nav className={S.nav}>
            {SECTIONS.map((s) => (
              <Link key={s.key} to="/settings/$section" params={{ section: s.key }} className={cx(S.navItem, s.key === cur.key && S.navOn)}><Icon name={s.icon} />{s.label}</Link>
            ))}
          </nav>
          <div className={ui.grow} style={{ marginTop: -28 }}>
            {cur.key === 'models' && <ModelsSection />}
            {cur.key === 'git' && <GitSection />}
            {cur.key === 'connectors' && <ConnectorsSection />}
            {cur.key === 'defaults' && <DefaultsSection />}
            {cur.key === 'general' && <GeneralSection />}
            {cur.key === 'diagnostics' && <DiagnosticsSection />}
          </div>
        </div>
      </PageLayout>
    </>
  );
}
