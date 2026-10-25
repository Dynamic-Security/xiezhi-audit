// Stage quotas, candidate limit and coverage settings: shared by settings › 任务创建默认值
// and the new-audit form. Shares are fractions of the total token budget; the form shows them as percentages.
import type { AuditStrategy, BudgetStage } from '@xiezhi/contracts';
import { BUDGET_STAGE, ON_SHORTFALL, fmt } from '../../shared/format/messages';
import { Field, InfoTip, cx, ui } from '../../shared/ui';
import { BUDGET_INFO } from './stageInfo';

export type StageShares = Partial<Record<BudgetStage, number>>;

/** Cap of the prepare share scaled by target repositories; mirrors contracts `PREPARE_SHARE_CAP`. */
const PREPARE_SHARE_CAP = 0.3;

/** Which stages a scene runs, so the editor does not show quotas that can never be used. */
const SCENE_STAGES: Record<string, readonly BudgetStage[]> = {
  full: ['prepare', 'hypotheses', 'triage', 'hunt', 'gap', 'merge', 'explore', 'review'],
  incremental: ['prepare', 'hypotheses', 'hunt', 'merge', 'review'],
};

const pct = (r: number | undefined) => (r === undefined ? '' : String(Math.round(r * 1000) / 10));

/**
 * `targets`: target repositories of the audit; the plan-and-profile quota is the share per repository.
 * `reviewers` / `hypothesisModels`: models of a crossed adversarial review / threat model or verification; those quotas
 * are the share per model.
 */
export function BudgetStagesEditor({ scene, value, total, onChange, on, onToggle, targets = 1, reviewers = 1, hypothesisModels = 1 }: {
  scene: string; value: StageShares; total: number; onChange: (v: StageShares) => void;
  /** The stage-quota switch; off = only the total limits the audit (the shares stay for when it is on). */
  on: boolean; onToggle: (on: boolean) => void;
  targets?: number; reviewers?: number; hypothesisModels?: number;
}) {
  const stages = SCENE_STAGES[scene] ?? (Object.keys(BUDGET_STAGE) as BudgetStage[]);
  const times = (k: BudgetStage) => (k === 'review' ? reviewers : k === 'hypotheses' ? hypothesisModels : 1);
  const tokensOf = (k: BudgetStage, r: number) => Math.floor((k === 'prepare' && targets > 1 ? Math.min(r * targets, Math.max(r, PREPARE_SHARE_CAP))
    : times(k) > 1 ? Math.min(r * times(k), 1) : r) * total);
  const note = (k: BudgetStage) => (k === 'prepare' ? (targets > 1 ? `（${targets} 个目标仓库，每个仓库按此份额）` : '（每个目标仓库按此份额）')
    : times(k) > 1 ? `（${times(k)} 个交叉模型，每个模型按此份额）` : '');
  const toggle = (
    <label className={ui.checkbox}>
      <input type="checkbox" checked={on} onChange={(e) => onToggle(e.target.checked)} />
      限制各阶段额度{on ? '' : '（已关闭：各阶段只受总 token 预算限制）'}
    </label>
  );
  if (!on) return toggle;
  return (
    <Field group label="各阶段额度（占 token 预算的百分比）" hint="一个阶段的所有步骤共用它的额度。额度用完时审计暂停，等你追加该阶段的额度。份额之和可以超过 100%：未开启的阶段不使用额度，总预算仍是整体上限。留空或 100% 表示不限。">
      {toggle}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))', gap: 10 }}>
        {stages.map((k) => (
          // A div, not a label: the ⓘ is a button and would become the label's control (the input has its own aria-label).
          <div key={k} className={ui.stack} style={{ gap: 4 }}>
            <span style={{ fontSize: 13, display: 'inline-flex', alignItems: 'center', gap: 2 }}>
              {BUDGET_STAGE[k]}
              {BUDGET_INFO[k] && <InfoTip label={`「${BUDGET_STAGE[k]}」额度说明`}><b>{BUDGET_STAGE[k]}</b><div>{BUDGET_INFO[k].does}</div><div>进度条：{BUDGET_INFO[k].shows}</div></InfoTip>}
            </span>
            <input className={ui.input} type="number" min={0} max={100} step={1} aria-label={`${BUDGET_STAGE[k]}额度百分比`} value={pct(value[k])}
              placeholder="不限" onChange={(e) => onChange({ ...value, [k]: e.target.value === '' ? 1 : Math.min(100, Math.max(0, Number(e.target.value))) / 100 })} />
            <span className={ui.faint} style={{ fontSize: 12 }}>{value[k] === undefined || value[k] === 1 ? '不限（只受总预算限制）' : `${fmt.tokens(tokensOf(k, value[k]!))} tokens${note(k)}`}</span>
          </div>
        ))}
      </div>
    </Field>
  );
}

export interface LimitsValue { maxCandidates: number; entry: number; sink: number; onShortfall: 'declare' | 'gap_fill' }

export const limitsOf = (s: AuditStrategy): LimitsValue => ({
  maxCandidates: s.limits.maxCandidates, entry: Math.round(s.coverageTarget.entry * 100), sink: Math.round(s.coverageTarget.sink * 100), onShortfall: s.coverageTarget.onShortfall as LimitsValue['onShortfall'],
});

/** Strategy override for the limits that differ from `base` (all of them when `base` is absent). */
export function limitsOverride(v: LimitsValue, base?: LimitsValue): Record<string, unknown> {
  const o: Record<string, unknown> = {};
  if (!base || v.maxCandidates !== base.maxCandidates) o.limits = { maxCandidates: v.maxCandidates };
  if (!base || v.entry !== base.entry || v.sink !== base.sink || v.onShortfall !== base.onShortfall) o.coverageTarget = { entry: v.entry / 100, sink: v.sink / 100, onShortfall: v.onShortfall };
  return o;
}

/** Candidate limit for every scene with candidates; coverage targets and shortfall handling for full audits. */
export function LimitsEditor({ value, onChange, coverage }: { value: LimitsValue; onChange: (v: LimitsValue) => void; coverage: boolean }) {
  return (
    <div className={cx(ui.stack)} style={{ gap: 12 }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: 12 }}>
        <Field label="候选上限" hint="追查的候选最多这么多个，其余记为覆盖缺口">
          <input className={ui.input} type="number" min={1} max={5000} step={50} value={value.maxCandidates} onChange={(e) => onChange({ ...value, maxCandidates: Math.max(1, Number(e.target.value) || 1) })} />
        </Field>
        {coverage && <Field label="入口覆盖目标（%）"><input className={ui.input} type="number" min={0} max={100} value={value.entry} onChange={(e) => onChange({ ...value, entry: Number(e.target.value) })} /></Field>}
        {coverage && <Field label="危险点覆盖目标（%）"><input className={ui.input} type="number" min={0} max={100} value={value.sink} onChange={(e) => onChange({ ...value, sink: Number(e.target.value) })} /></Field>}
        {coverage && (
          <Field label="覆盖不足时">
            <select className={ui.select} value={value.onShortfall} onChange={(e) => onChange({ ...value, onShortfall: e.target.value as LimitsValue['onShortfall'] })}>
              {(['declare', 'gap_fill'] as const).map((k) => <option key={k} value={k}>{ON_SHORTFALL[k]}</option>)}
            </select>
          </Field>
        )}
      </div>
    </div>
  );
}
