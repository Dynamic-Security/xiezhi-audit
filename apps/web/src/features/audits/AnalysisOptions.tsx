// Optional analysis of full and incremental audits: risk-hypothesis-first — a threat
// model (which must go through the state-changing / by-id entries, the former per-entry logic review), then each
// hypothesis verified against the code. Shared by the new-audit form, the plan card and the scene defaults; off
// unless chosen, and it adds cost. There is no domain-expert switch — every full and incremental
// audit explores with the lead, so it is shown as a fact, not a choice.
import { ui } from '../../shared/ui';

export interface AnalysisChoice { threatHypotheses: boolean }

/** The strategy override for the choice. */
export function analysisOverride(_scene: string, c: AnalysisChoice): { stages: AnalysisChoice } {
  return { stages: { ...c } };
}

/** The choice a strategy makes for a scene. */
export function analysisChoiceOf(_scene: string, stages: { threatHypotheses?: boolean }): AnalysisChoice {
  return { threatHypotheses: stages.threatHypotheses === true };
}

export function AnalysisOptions({ value, onChange, maxCandidates }: { value: AnalysisChoice; onChange: (v: AnalysisChoice) => void; maxCandidates?: number }) {
  return (
    <div className={ui.stack} style={{ gap: 6 }} role="group" aria-label="可选分析">
      <label className={ui.checkbox}>
        <input type="checkbox" checked={value.threatHypotheses} onChange={(e) => onChange({ ...value, threatHypotheses: e.target.checked })} />
        风险假设先行：先按威胁模型列出仓库可能面临的风险假设{maxCandidates ? `（最多 ${maxCandidates} 条）` : ''}（改变状态或按 id 访问资源的入口逐个考虑，即原“按入口的逻辑审查”），再逐条用代码验证并给出排查理由，计入覆盖对照
      </label>
      <span className={ui.faint} style={{ fontSize: 12, paddingLeft: 24 }}>会增加 token 消耗与耗时；审计结束后也可以在“覆盖对照”中追加执行。</span>
      <span className={ui.faint} style={{ fontSize: 12 }}>
        漏洞探索由主控会话调度：威胁建模把系统划分为若干风险领域，主控按领域派发子任务读代码，未结论的必答项与缺口再由补审兜底。
      </span>
    </div>
  );
}
