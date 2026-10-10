// Per-stage models, thinking levels and cross review (per-stage cross).
// the stage table's defaults live in settings → 模型 (default model + per-stage models, one
// fallback); this editor is a new audit's “各阶段模型” (the task override's differences), and the cross-review part
// is also used by the scene defaults. Every stage has a “?” with its role and tasks.
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import type { AuditStrategy, ModelRef, ModelStageKey } from '@xiezhi/contracts';
import { Icon, cx, ui } from '../../shared/ui';
import M from './stagemodels.module.css';

type Thinking = NonNullable<ModelRef['thinking']>;
export type StageModelsValue = Pick<AuditStrategy, 'models' | 'multiModel'>;
/** Settings stages (contracts `CONFIG_MODEL_STAGES`): the audit stages plus conversations. */
export type GuideStage = ModelStageKey | 'chat';
type Scene = 'full' | 'incremental' | 'risk_hunt' | 'reverify';

export const STAGE_LABEL: Record<ModelStageKey, string> = {
  profile: '计划与画像', scope: '影响范围', triage: '初筛', hunt: '深入审计', logic: '风险假设', explore: '深度探索',
  challenge: '对抗复核', merge: '归并', verify: '复验与风险研判', report: '报告',
};
export const CHAT_LABEL = '对话';

/** What each stage is for (the “?” next to it): role, tasks, and how to choose its model. */
export const STAGE_GUIDE: Record<GuideStage, { role: string; tasks: string[]; pick: string }> = {
  profile: { role: '审计开始时理解项目，决定审什么、怎么审。', tasks: ['生成审计计划（范围、重点、预算）', '仓库画像：技术栈、入口、信任边界与敏感数据'], pick: '读得多、推理中等，中等能力的模型即可。' },
  scope: { role: '增量审计专用：判断这次代码变更影响到哪里。', tasks: ['从变更文件出发追调用链，找出受影响的入口与危险点', '决定本次增量审计的候选范围'], pick: '需要理解调用关系，建议中等以上的模型。' },
  triage: { role: '在大量候选里排优先级，决定先审哪些。', tasks: ['给入口与危险点打风险分并排序', '超出候选上限的部分声明为覆盖缺口', '项目页的仓库角色识别（不使用模型时改用默认模型）'], pick: '调用次数多、单次简单，适合便宜快速的模型；选“不使用模型”时按规则打分，零成本。' },
  hunt: { role: '主力阶段：自下而上追查漏洞，决定召回率与准确率。', tasks: ['分批阅读代码、追踪数据从入口到危险点的路径', '提交发现：攻击路径、影响、利用条件与代码证据', '对每个候选给出“发现 / 无问题 / 排除”的结论'], pick: '对质量影响最大，建议用最强的模型。' },
  logic: { role: '先想清楚可能出什么事（风险假设），再逐条验证。', tasks: ['威胁建模：结合画像与入口列出风险假设（越权、业务逻辑等）', '自上而下逐条验证：已证实 / 已排除 / 无法判定，并给出排查理由'], pick: '需要业务理解与安全推理，建议强模型。需开启“风险假设先行”。' },
  explore: { role: '汇总之后，只针对还不确定的地方再深挖。', tasks: ['每轮从无法判定的假设、模型间冲突、待确认发现中选一个方向', '派生一次专门调查，直到没有进展或达到轮数上限'], pick: '需要判断“下一步查什么”，建议强模型。需开启“深度探索”。' },
  challenge: { role: '站在反方，专门找每个发现不成立的证据，压低误报。', tasks: ['对每个正式发现独立寻找反证（防护、不可达、前置条件不满足）', '给出维持 / 降低置信度 / 已驳倒，正反论据都保留'], pick: '与深入审计换一个同等能力的模型，更容易发现盲点。需开启“对抗复核”。' },
  merge: { role: '把重复的发现合成一条，并与历史漏洞对上号。', tasks: ['按根因把描述同一问题的发现分组', '新发现与已跟踪漏洞的疑似匹配判断'], pick: '只看摘要、不读代码，便宜模型即可；选“不使用模型”时只按位置和危险点指纹合并。' },
  verify: { role: '复验与研判：确认问题是否还在。', tasks: ['漏洞复验：判断已报漏洞是否已修复、部分修复或仍存在', '风险排查：判断各仓库是否受某个风险影响'], pick: '需要读代码下结论，建议中等以上的模型。' },
  report: { role: '把审计结果写成报告。', tasks: ['导出时选“AI 生成”才使用：按报告模板写全文', '程序会校验编号、严重度与确认状态，不一致时让它修正'], pick: '写作与归纳能力好的模型即可；导出时还可以临时更换。' },
  chat: { role: '审计流程之外的 AI 助手。', tasks: ['AI 会话（追问、解释、发起操作）', '知识整理、规则包与架构导入的草稿', '推送到外部系统时填写参数'], pick: '交互为主，响应快、表达好的模型更合适。' },
};

/** The “?” next to a stage: opens its role, tasks and how to choose (in a portal, so tables neither clip nor cover it). */
export function StageHelp({ stage, label }: { stage: GuideStage; label: string }) {
  const [open, setOpen] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number; ready: boolean } | null>(null);
  const [layout, setLayout] = useState(0);
  const pop = useRef<HTMLDivElement>(null);
  // Close on a click outside both the button and the popover (which lives in a portal), or on Escape; follow the
  // button when the page scrolls or resizes.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { const t = e.target as Node; if (!btn.current?.contains(t) && !pop.current?.contains(t)) setOpen(false); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { setOpen(false); btn.current?.focus(); } };
    const relayout = () => setLayout((n) => n + 1);
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('scroll', relayout, true);
    window.addEventListener('resize', relayout);
    return () => {
      document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey);
      window.removeEventListener('scroll', relayout, true); window.removeEventListener('resize', relayout);
    };
  }, [open]);
  // Below the button; once rendered (hidden) and measured, above it instead when there is no room below.
  useLayoutEffect(() => {
    if (!open || !btn.current) { setPos(null); return; }
    const r = btn.current.getBoundingClientRect();
    const w = Math.min(320, window.innerWidth - 32);
    setPos({ top: r.bottom + 6, left: Math.max(16, Math.min(r.left, window.innerWidth - w - 16)), ready: false });
  }, [open, layout]);
  useLayoutEffect(() => {
    if (!pos || pos.ready || !pop.current || !btn.current) return;
    const h = pop.current.offsetHeight;
    const top = pos.top + h > window.innerHeight - 8 ? Math.max(8, btn.current.getBoundingClientRect().top - h - 6) : pos.top;
    setPos({ ...pos, top, ready: true });
  }, [pos]);
  const g = STAGE_GUIDE[stage];
  return (
    <span className={M.help}>
      <button ref={btn} type="button" className={M.helpBtn} aria-label={`${label}阶段说明`} aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="help" size={14} />
      </button>
      {open && pos && createPortal(
        <div ref={pop} role="dialog" aria-label={`${label}阶段说明`} className={M.helpPop} style={{ top: pos.top, left: pos.left, visibility: pos.ready ? 'visible' : 'hidden' }}>
          <b>{label}</b>
          <p>{g.role}</p>
          <ul>{g.tasks.map((t) => <li key={t}>{t}</li>)}</ul>
          <p className={M.helpPick}>选型建议：{g.pick}</p>
        </div>,
        document.body,
      )}
    </span>
  );
}

const STAGE_HINT: Partial<Record<ModelStageKey, string>> = {
  // explore: there is no switch on the new-audit form; the lead's directions left open are explored on demand.
  scope: '增量审计的影响分析', logic: '需开启风险假设先行', explore: '追查遗留的方向时使用（按需）', challenge: '需开启对抗复核',
  verify: '漏洞复验、风险排查的研判', report: 'AI 生成报告时使用，导出时可调整',
};
/** Stages each scene goes through (engine `stepStage`), in execution order (settings `SETTINGS_STAGES`). */
const SCENE_STAGES: Record<Scene, ModelStageKey[]> = {
  full: ['profile', 'logic', 'triage', 'hunt', 'merge', 'explore', 'challenge', 'report'],
  incremental: ['profile', 'scope', 'logic', 'triage', 'hunt', 'merge', 'explore', 'challenge', 'report'],
  risk_hunt: ['profile', 'verify', 'report'],
  reverify: ['profile', 'verify', 'report'],
};
const THINKING: [Thinking | '', string][] = [['', '默认'], ['off', '关'], ['low', '低'], ['medium', '中'], ['high', '高']];
/** Stages that can run without a model (deterministic processing; contracts `NO_MODEL_STAGES`). */
const NONE_STAGES: ModelStageKey[] = ['triage', 'merge'];

const key = (m: ModelRef | null | undefined) => (m ? `${m.provider}/${m.model}` : '');

type CrossKey = 'threat' | 'hunt' | 'verify' | 'review';
/** Stages that can run crossed, each its own switch; mirrors contracts `crossModels`. */
const CROSS: { key: CrossKey; label: string; stage: ModelStageKey }[] = [
  { key: 'threat', label: '威胁建模：每个模型各列一份风险假设，合并去重', stage: 'logic' },
  { key: 'hunt', label: '自下而上追查（深入审计）：发现按“几个模型认同”调整置信度', stage: 'hunt' },
  { key: 'verify', label: '自上而下验证：每条风险假设由每个模型各验证一次，保留各模型结论', stage: 'logic' },
  { key: 'review', label: '对抗复核：每个正式发现由每个模型各复核一次，正反论据都保留', stage: 'challenge' },
];
export function crossStagesOf(mm: AuditStrategy['multiModel']): Partial<Record<CrossKey, boolean>> {
  return mm.stages ?? { hunt: true, verify: true };
}
/** Whether a model stage runs crossed under this multi-model setting. */
export function stageCrossed(mm: AuditStrategy['multiModel'], s: ModelStageKey): boolean {
  if (!mm.enabled || mm.models.length < 2) return false;
  const st = crossStagesOf(mm);
  return CROSS.some((c) => c.stage === s && st[c.key]);
}
const parse = (x: string): ModelRef | null => { const i = x.indexOf('/'); return x ? { provider: x.slice(0, i), model: x.slice(i + 1) } : null; };
const slot = (s: ModelStageKey): keyof AuditStrategy['models'] => (s === 'hunt' ? 'audit' : s);
export const sameModel = (a: ModelRef | null | undefined, b: ModelRef | null | undefined) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

/** The model a stage runs with (contracts `stageModel`; the web imports only types from contracts). */
export function effectiveStageModel(v: Pick<AuditStrategy, 'models'>, s: ModelStageKey): ModelRef | null {
  if (s === 'triage' || s === 'merge') return v.models[s];
  if (s === 'hunt') return v.models.audit;
  return v.models[slot(s)] ?? v.models.audit;
}

export function scenesStages(scene: Scene): ModelStageKey[] { return SCENE_STAGES[scene]; }

export function StageModelsEditor({ scene, value, onChange, models, globalFallback, enabled }: {
  scene: Scene; value: StageModelsValue; onChange: (v: StageModelsValue) => void; models: string[];
  /** Settings → 模型 → 备用模型 (the only fallback). */
  globalFallback: ModelRef | null;
  /** The form's switches: a stage whose switch is on drops its “需开启…” hint. */
  enabled?: Partial<Record<'logic' | 'challenge', boolean>>;
}) {
  const known = (m: ModelRef | null | undefined) => !m || models.includes(key(m));
  const options = (cur: ModelRef | null | undefined) => [...(known(cur) ? [] : [key(cur)]), ...models].map((m) => <option key={m} value={m}>{m}{known(parse(m)) ? '' : '（未配置）'}</option>);
  const setModel = (s: ModelStageKey, m: ModelRef | null) => onChange({ ...value, models: { ...value.models, [slot(s)]: m } as AuditStrategy['models'] });
  const crossable = scene === 'full' || scene === 'incremental';

  const row = (s: ModelStageKey) => {
    // Current strategies name every stage's model; older ones may leave a stage to follow the hunt model.
    const eff = effectiveStageModel(value, s);
    const byCross = crossable && stageCrossed(value.multiModel, s);
    return (
      <tr key={s}>
        <th scope="row" className={M.stage}>
          <span className={M.stageName}>{STAGE_LABEL[s]}<StageHelp stage={s} label={STAGE_LABEL[s]} /></span>
          {STAGE_HINT[s] && !(s === 'logic' || s === 'challenge' ? enabled?.[s] : false) && <div className={M.hint}>{STAGE_HINT[s]}</div>}
        </th>
        <td>
          <select aria-label={`${STAGE_LABEL[s]}模型`} className={cx(ui.select, M.sel)} value={key(eff)} onChange={(e) => {
            const m = parse(e.target.value);
            setModel(s, m && eff?.thinking ? { ...m, thinking: eff.thinking } : m);
          }}>
            {NONE_STAGES.includes(s) && <option value="">不使用模型（确定性处理）</option>}
            {options(eff)}
          </select>
          {byCross && <div className={M.hint}>由下方多模型交叉的模型各做一遍</div>}
        </td>
        <td>
          <select aria-label={`${STAGE_LABEL[s]}思考强度`} className={cx(ui.select, M.think)} disabled={!eff} value={eff?.thinking ?? ''}
            title={eff ? undefined : '不使用模型'}
            onChange={(e) => { const t = e.target.value as Thinking | ''; const { thinking: _, ...rest } = eff!; setModel(s, t ? { ...rest, thinking: t } : rest); }}>
            {THINKING.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
        </td>
      </tr>
    );
  };

  return (
    <div className={M.wrap}>
      <div className={M.scroll}>
        <table className={cx(ui.table, M.table)}>
          <colgroup><col className={M.cStage} /><col /><col className={M.cThink} /></colgroup>
          <thead><tr><th>阶段</th><th>模型</th><th>思考强度</th></tr></thead>
          <tbody>{SCENE_STAGES[scene].map(row)}</tbody>
        </table>
      </div>
      <p className={M.hint}>默认取自 设置 › 模型。{globalFallback ? `模型不可用时切换到备用模型 ${key(globalFallback)}。` : '未设置备用模型（设置 › 模型），模型不可用时不切换。'}</p>
      {crossable && <CrossModelsEditor value={value.multiModel} onChange={(multiModel) => onChange({ ...value, multiModel })} models={models} hunt={value.models.audit} />}
    </div>
  );
}

/** Multi-model cross-checking: a group of 2–4 models and the stages they each run. */
export function CrossModelsEditor({ value: cross, onChange, models, hunt }: {
  value: AuditStrategy['multiModel']; onChange: (v: AuditStrategy['multiModel']) => void; models: string[];
  /** The first model of a new group. */
  hunt: ModelRef;
}) {
  // The same model may be chosen more than once — it then simply runs more than once.
  const addCross = (m: string) => {
    if (cross.models.length >= 4) return;
    onChange({ ...cross, models: [...cross.models, parse(m)!] });
  };
  const removeCross = (i: number) => onChange({ ...cross, models: cross.models.filter((_, j) => j !== i) });
  const repeated = cross.models.some((m, i) => cross.models.findIndex((x) => key(x) === key(m)) !== i);
  const setCrossThinking = (i: number, t: Thinking | '') => {
    const next = cross.models.map((x, j) => { if (j !== i) return x; const { thinking: _, ...rest } = x; return t ? { ...rest, thinking: t } : rest; });
    onChange({ ...cross, models: next });
  };
  return (
    <div className={M.cross}>
      <label className={ui.checkbox}>
        <input type="checkbox" checked={cross.enabled} onChange={(e) => onChange({ enabled: e.target.checked, models: e.target.checked && !cross.models.length ? [{ ...hunt }] : cross.models, stages: e.target.checked && !cross.stages ? {} : crossStagesOf(cross) })} />
        多模型交叉：选一组 2–4 个模型，下面勾选的环节由每个模型各做一遍（每个环节单独选择，缺省都不交叉）
      </label>
      {cross.enabled && (
        <>
          <div className={cx(ui.row, ui.wrap)} role="group" aria-label="交叉审查模型">
            {models.map((m) => {
              const n = cross.models.filter((x) => key(x) === m).length;
              return <button key={m} type="button" className={cx(ui.chip, n > 0 && ui.chipOn)} aria-label={`添加 ${m}`} disabled={cross.models.length >= 4} onClick={() => addCross(m)}>{m}{n > 1 ? ` ×${n}` : ''}</button>;
            })}
          </div>
          {cross.models.length > 0 && (
            <ul className={M.crossList}>
              {cross.models.map((m, i) => (
                <li key={`${i}:${key(m)}`}>
                  <span className={ui.mono}>{key(m)}</span>
                  <span className={ui.faint}>思考强度</span>
                  <select aria-label={`第 ${i + 1} 个 ${key(m)} 思考强度`} className={cx(ui.select, M.think)} value={m.thinking ?? ''} onChange={(e) => setCrossThinking(i, e.target.value as Thinking | '')}>
                    {THINKING.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
                  </select>
                  <button type="button" className={cx(ui.btn, ui.sm)} aria-label={`移除第 ${i + 1} 个 ${key(m)}`} onClick={() => removeCross(i)}>移除</button>
                </li>
              ))}
            </ul>
          )}
          <div className={ui.stack} style={{ gap: 4 }} role="group" aria-label="交叉的环节">
            {CROSS.map((c) => {
              const st = crossStagesOf(cross);
              return (
                <label key={c.key} className={ui.checkbox}>
                  <input type="checkbox" checked={st[c.key] === true} onChange={(e) => onChange({ ...cross, stages: { ...st, [c.key]: e.target.checked } })} />
                  {c.label}
                </label>
              );
            })}
          </div>
          <p className={cross.models.length < 2 || !CROSS.some((c) => crossStagesOf(cross)[c.key]) ? M.warn : M.hint}>
            {cross.models.length < 2 ? '至少选 2 个模型（最多 4 个）'
              : !CROSS.some((c) => crossStagesOf(cross)[c.key]) ? '还没有勾选要交叉的环节'
                : `${repeated ? '同一模型选了多次：它会在勾选的环节各自独立运行多次。' : ''}勾选环节的 token 消耗约 ×${cross.models.length}，请按需选择。威胁建模与自上而下验证需开启风险假设先行，对抗复核需开启对抗复核。备用模型若也在这组里，出错的一方不会切换，该作业记为“交叉审查降级”。`}
          </p>
        </>
      )}
    </div>
  );
}

/** The resolved editor value of a strategy. */
export function stageModelsOf(s: AuditStrategy): StageModelsValue {
  return { models: structuredClone(s.models), multiModel: structuredClone(s.multiModel) };
}

/** What changed against `base`, as a strategy override fragment (unchanged keys are left to the lower layer). */
export function stageModelsDiff(base: StageModelsValue, v: StageModelsValue): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const models = Object.fromEntries(Object.entries(v.models).filter(([k, m]) => !sameModel(m, base.models[k as keyof AuditStrategy['models']])));
  if (Object.keys(models).length) out.models = models;
  if (JSON.stringify(v.multiModel) !== JSON.stringify(base.multiModel)) out.multiModel = v.multiModel;
  return out;
}

/** One line per stage for the plan card: the effective model and fallback. */
export function StageModelsSummary({ s, scene: sc, globalFallback }: { s: AuditStrategy; scene: string; globalFallback?: ModelRef | null }) {
  const scene: Scene = sc in SCENE_STAGES ? (sc as Scene) : 'full';
  const crossOn = scene === 'full' || scene === 'incremental';
  return (
    <ul className={M.summary} aria-label="各阶段模型">
      {SCENE_STAGES[scene].filter((st) => (st !== 'logic' || s.stages.threatHypotheses || scene === 'full' || scene === 'incremental') && (st !== 'explore' || s.stages.deepExplore) && (st !== 'challenge' || s.stages.adversarialReview)).map((st) => {
        const m = effectiveStageModel(s, st);
        const fb = s.modelFallbacks?.[st] ?? globalFallback ?? null;
        const multi = crossOn && stageCrossed(s.multiModel, st);
        return (
          <li key={st}>
            <span className={ui.faint}>{STAGE_LABEL[st]}</span>
            <b className={ui.mono}>{multi ? s.multiModel.models.map(key).join(' + ') : m ? key(m) : '不使用'}{!multi && m?.thinking && m.thinking !== 'off' ? ` · 思考${THINKING.find(([k]) => k === m.thinking)![1]}` : ''}</b>
            {multi && <span className={ui.faint}>交叉审查 ×{s.multiModel.models.length}</span>}
            {multi && fb && <span className={ui.faint}>备用 {key(fb)}{s.multiModel.models.some((x) => sameModel({ provider: x.provider, model: x.model }, { provider: fb.provider, model: fb.model })) ? '（已在交叉组内，出错时不替换，记为降级）' : ''}</span>}
            {!multi && m && fb && !sameModel(fb, m) && <span className={ui.faint}>备用 {key(fb)}</span>}
          </li>
        );
      })}
    </ul>
  );
}
