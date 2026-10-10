// coverage-gap: review the entrypoints/sinks a full audit left uncovered.
// Two uses: a backfill audit on the original snapshot started from the coverage view ("一键补审"), and
// the automatic `coverageTarget.onShortfall = gap_fill` round inside a full audit. Only appends
// conclusions — the original audit's artifacts are never changed.
import { calibrated } from '../calibration.js';
import { fromJson } from '@xiezhi/store';
import { loadState, renderSlice } from '../cognitive.js';
import { estimateStep } from '../estimates.js';
import type { AuditRuntime } from '../runtime.js';
import type { StepResult } from '../step-runner.js';
import type { AuditPlan } from './plan.js';
import { engineLimitations } from './plan.js';
import { buildCandidates, makeBatches, rankCandidates, type Candidate, type TriageOutput } from './triage.js';
import { P } from '@xiezhi/knowledge';

export interface BackfillScope { auditId: string; targets: string[] }

export function backfillScope(rt: AuditRuntime): BackfillScope | null {
  return fromJson<{ backfill?: BackfillScope }>(rt.audit.scope, {}).backfill ?? null;
}

const REASON: Record<string, string> = { uncovered: '未读到', read: '读过但没有给出结论', failed: '解析缺口' };

/**
 * Candidates for the given coverage targets, in the triage shape (so batching is shared). `triaged`: the audit's own
 * triage candidates — their scores order the round, highest first; unscored ones follow.
 */
export function gapSelection(rt: AuditRuntime, targetIds: ReadonlySet<string>, statusOf: Map<string, string>, triaged?: ReadonlyMap<string, Candidate>): TriageOutput {
  const candidates: Candidate[] = rankCandidates(buildCandidates(rt).filter((c) => targetIds.has(c.id))
    .map((c) => { const t = triaged?.get(c.id); return t?.llmScore !== undefined ? { ...c, llmScore: t.llmScore } : c; }))
    .map((c) => ({ ...c, reason: `原审计中${REASON[statusOf.get(c.id) ?? 'uncovered'] ?? '未覆盖'}` }));
  // Not capped by limits.maxCandidates: that cap is what left these targets over; budget bounds the round.
  return { candidates, selected: candidates.map((c) => c.id), overflow: [], batches: makeBatches(candidates) };
}

/**
 * Prior context for a gap session (`priorContext`): the cognitive state slice and the
 * findings of the audit whose coverage is being filled, for the batch's files.
 */
export function gapPreface(rt: AuditRuntime, sourceAuditId: string, batch: Candidate[]): string[] {
  const paths = [...new Set(batch.map((c) => c.path))];
  const { state } = loadState(rt.store, sourceAuditId);
  const slice = renderSlice(state, paths);
  // Inside a full audit the gap round runs before ⑩ reconcile, so this audit's findings are still
  // `submitted`; a finished source audit (backfill) has only canonical ones that matter.
  const related = rt.store.all<{ display_no: number | null; title: string; location: string; severity: string }>(
    `SELECT display_no, title, location, severity FROM finding WHERE audit_id = ? AND state IN ('canonical', 'submitted') ORDER BY display_no, created_at`, sourceAuditId)
    .filter((f) => paths.includes(fromJson<{ path: string }>(f.location, { path: '' }).path));
  return [
    P('hunt.gap.intro'),
    ...(related.length ? ['', P('hunt.gap.prior_findings_heading'), ...related.map((f) => `- ${f.display_no ? `F-${f.display_no} ` : ''}[${f.severity}] ${f.title} @ ${fromJson<{ path: string; startLine: number }>(f.location, { path: '', startLine: 0 }).path}:${fromJson<{ startLine: number }>(f.location, { startLine: 0 }).startLine}`)] : []),
    ...(slice.trim() ? ['', P('hunt.gap.prior_state_heading'), slice] : []),
    '',
  ];
}

/** Deterministic plan for a backfill audit: the targets are known; it starts at once. */
export function backfillPlan(rt: AuditRuntime, scope: BackfillScope): StepResult {
  const store = rt.store;
  const source = store.get<{ title: string }>('SELECT title FROM audit WHERE id = ?', scope.auditId);
  const s = rt.strategy;
  const v = rt.views.get(rt.targetRepo.name)!;
  const n = scope.targets.length;
  const tokens = calibrated(store, estimateStep('hunt', n), 'coverage-gap', s.models.audit);
  const pricing = store.config.pricing[`${s.models.audit.provider}/${s.models.audit.model}`];
  const cost = (t: number) => (pricing ? (t * 0.8 * pricing.input + t * 0.2 * pricing.output) / 1e6 : 0);
  const plan: AuditPlan = {
    submitted: {
      summary: `补审「${source?.title ?? scope.auditId}」中未覆盖的 ${n} 个入口/危险点，使用同一代码快照；只追加结论，不修改原审计。`,
      focusDirections: [{ direction: '未覆盖的入口与危险点', reason: '原审计的覆盖对照显示它们没有被审查到' }], plannedKnowledge: [], contextNeeded: [], limitations: [],
    },
    scale: { files: v.manifest.stats.fileCount, byLang: v.manifest.stats.byLang, entrypoints: 0, sinks: 0, candidates: n, sinksByCategory: {} },
    estimate: {
      tokens: { p50: Math.ceil(tokens * 0.7), p90: Math.ceil(tokens * 1.3) }, durationSec: { p50: 60 * n, p90: 180 * n },
      cost: pricing ? { p50: cost(tokens * 0.7), p90: cost(tokens * 1.3), currency: pricing.currency } : null, byStep: { 'coverage-gap': tokens },
    },
    strategySources: JSON.parse(rt.audit.strategy_sources) as Record<string, string>,
    limitations: [...engineLimitations(rt), '补审只覆盖选中的目标；覆盖不等于检出率。'],
    knowledge: rt.knowledge.skills.map((k) => k.name),
  };
  const ref = store.artifacts.putJson(plan);
  return { outputRef: ref, apply: () => store.update('audit', { id: rt.auditId }, { plan_ref: ref }) };
}
