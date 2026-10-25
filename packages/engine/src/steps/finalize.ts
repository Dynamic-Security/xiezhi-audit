// Completion gate and report rendering. The agent saying "done" never counts: the reconciled finding
// set and the mainline decide the status; everything else is recorded as a process issue.
import { sortPartialReasons, stepRole, type PartialReason, type StageId } from '@xiezhi/contracts';
import { exportAudit } from '@xiezhi/report';
import { fromJson } from '@xiezhi/store';
import { finalizeCoverage, mergeBackfill, unconcludedSummary, type UnconcludedSummary } from '../coverage.js';
import type { AuditRuntime } from '../runtime.js';
import { listSteps, NOT_RUN_MARK } from '../state.js';
import { addRevision } from '../vulns.js';
import { obligationSummary, type ObligationSummary } from '../obligations.js';
import { threatHypothesesOn, verificationTargets } from '../threat.js';
import { backfillScope } from './coverage-gap.js';
import type { AttemptContext, StepResult } from '../step-runner.js';

export interface GateResult {
  status: 'completed' | 'partial' | 'failed';
  partialReasons: PartialReason[];
  checks: { name: string; ok: boolean; detail: string }[];
  coverage: { entry: { total: number; reviewed: number }; sink: { total: number; reviewed: number } } | null;
  gaps: string[];
  /** items without a conclusion and why, whether or not coverage targets apply (absent in older audits). */
  unconcluded?: UnconcludedSummary;
  /**
   * problems that no longer make the audit partial on their own — a few failed reviews, a failed deep-
   * exploration step, an LSP fallback — said in the report instead (absent in older audits).
   */
  notices?: string[];
  /** findings whose adversarial review failed (only when the failed share stays within the tolerance). */
  unreviewed?: string[];
  /** everything the audit had to settle, by kind and source (absent in older audits). */
  obligations?: ObligationSummary;
}

/** failed review steps above this share of all review steps make the audit partial. */
export const REVIEW_FAILURE_TOLERANCE = 0.1;

/**
 * The stages that do the audit's main work. Any of them with a step that never ran (budget declined,
 * running time used up, audit ended first) or with only failed steps leaves the audit partial; everything else that
 * went wrong is a process issue on a completed audit.
 */
const MAINLINE_STAGES: readonly StageId[] = ['lead', 'hunt', 'locate', 'judge', 'verify'];

/** Deep exploration (⑪): decide steps and its hunts (`R<n>-C1`). */
const isExploreStep = (s: { kind: string; lineage_id: string | null }) => s.kind === 'decide' || (s.kind === 'hunt' && /^R\d+-/.test(s.lineage_id ?? ''));

export function evaluateGate(rt: AuditRuntime, stepId: string, carried: PartialReason[], overflow: string[]): GateResult {
  const reasons = new Set<PartialReason>(carried);
  const checks: GateResult['checks'] = [];
  const steps = listSteps(rt.store, rt.auditId);
  // Reverification produces verdicts, not a finding set: each target needs a verdict.
  const reverify = rt.audit.scene === 'reverify';
  let reconciled: boolean;
  if (reverify) {
    const targets = fromJson<{ reverify?: string[] }>(rt.audit.scope, {}).reverify ?? [];
    const decided = rt.store.get<{ n: number }>(`SELECT COUNT(DISTINCT vulnerability_id) AS n FROM vuln_occurrence WHERE audit_id = ? AND reverify_verdict IS NOT NULL`, rt.auditId)!.n;
    reconciled = targets.length > 0;
    checks.push({ name: 'verdicts', ok: decided === targets.length, detail: `${decided}/${targets.length} vulnerabilities have a verdict` });
    if (decided < targets.length && !steps.some((s) => s.status === 'failed')) reasons.add('STEP_FAILED');
  } else {
    // The first reconcile step, or the deterministic step that superseded it after a merge-model failure.
    const first = steps.find((s) => s.kind === 'reconcile');
    const replacement = first && steps.find((s) => s.kind === 'reconcile' && s.status === 'succeeded' && (() => { try { return (JSON.parse(s.input || '{}') as { supersedes?: string }).supersedes === first.id; } catch { return false; } })());
    reconciled = first?.status === 'succeeded' || !!replacement;
    checks.push({ name: 'finding_set', ok: reconciled, detail: reconciled ? (replacement ? 'reconciled finding set present (deterministic fallback)' : 'reconciled finding set present') : 'no reconciled finding set' });
  }
  // A failed step is superseded when its replacement succeeded: a hunt batch split after a context
  // overflow (every part succeeded or was itself superseded), or a triage model failure followed by the
  // deterministic fallback. It stays in the trajectory but no longer makes the audit partial.
  const inputOf = (x: (typeof steps)[number]) => { try { return JSON.parse(x.input || '{}') as { splitFrom?: string; supersedes?: string }; } catch { return {}; } };
  const superseded = new Set<string>();
  const settle = (id: string): boolean => {
    if (superseded.has(id)) return true;
    const parts = steps.filter((x) => inputOf(x).splitFrom === id);
    const replaced = steps.some((x) => inputOf(x).supersedes === id && x.status === 'succeeded');
    const ok = replaced || (parts.length > 0 && parts.every((x) => x.status === 'succeeded' || (x.status === 'failed' && settle(x.id))));
    if (ok) superseded.add(id);
    return ok;
  };
  const failed = steps.filter((s) => s.status === 'failed' && !settle(s.id));
  // failed review steps within the tolerance only mark their findings unreviewed; a failed deep-
  // exploration step leaves its direction open. Both are said in the report but no longer make the audit partial.
  const notices: string[] = [];
  const reviews = steps.filter((s) => s.kind === 'challenge');
  const failedReviews = failed.filter((s) => s.kind === 'challenge');
  const reviewTolerated = failedReviews.length > 0 && failedReviews.length <= reviews.length * REVIEW_FAILURE_TOLERANCE;
  const unreviewed = reviewTolerated ? [...new Set(failedReviews.map((s) => fromJson<{ findingId?: string }>(s.input, {}).findingId).filter((x): x is string => !!x))] : [];
  if (reviewTolerated) notices.push(`${failedReviews.length}/${reviews.length} 个复核步骤失败，${unreviewed.length} 条发现未复核`);
  const failedExplore = failed.filter(isExploreStep);
  if (failedExplore.length) notices.push(`${failedExplore.length} 个深度探索步骤失败，对应方向未调查完`);
  const filteredLanes = steps.filter((s) => s.status === 'skipped' && s.error_class === 'CONTENT_FILTERED');
  if (filteredLanes.length) notices.push(`${filteredLanes.length} 个交叉审查步骤被模型的内容过滤拦截，只采用了其他模型的结果`);
  const counted = failed.filter((s) => !(reviewTolerated && s.kind === 'challenge') && !isExploreStep(s));
  for (const s of counted) {
    if (s.error_class === 'OUTPUT_CONTRACT') reasons.add('OUTPUT_CONTRACT_FAILED');
    else if (s.error_class === 'MODEL_NOT_FOUND' || s.error_class === 'AUTH_INVALID') reasons.add('MODEL_UNAVAILABLE');
    else reasons.add('STEP_FAILED');
  }
  checks.push({ name: 'steps', ok: counted.length === 0, detail: `${failed.length} failed step(s)${failed.length > counted.length ? `, ${failed.length - counted.length} only noted` : ''}` });
  const unreconciled = rt.store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM finding WHERE audit_id = ? AND state = 'submitted'`, rt.auditId)!.n;
  checks.push({ name: 'reconciled', ok: unreconciled === 0, detail: `${unreconciled} unreconciled finding(s)` });
  if (unreconciled > 0) reasons.add('STEP_FAILED');

  // The mainline ran through when every mainline stage ran all its steps and at least one of each
  // succeeded (a failure replaced by its split parts or fallback counts as succeeded), findings were all reconciled
  // and a reverification has a verdict for each target.
  const mainline = steps.filter((s) => MAINLINE_STAGES.includes(stepRole(s.kind, s.lineage_id)?.stage as StageId));
  const notRun = mainline.filter((s) => s.status === 'skipped' && (s.error_summary ?? '').startsWith(NOT_RUN_MARK));
  const allFailed = [...new Set(mainline.map((s) => stepRole(s.kind, s.lineage_id)!.stage))].filter((st) => {
    const own = mainline.filter((s) => stepRole(s.kind, s.lineage_id)!.stage === st && s.status !== 'skipped');
    return own.length > 0 && own.every((s) => s.status === 'failed' && !superseded.has(s.id));
  });
  const verdictsMissing = reverify && checks.some((c) => c.name === 'verdicts' && !c.ok);
  const mainlineOk = !notRun.length && !allFailed.length && unreconciled === 0 && !verdictsMissing;
  checks.push({ name: 'mainline', ok: mainlineOk, detail: `${notRun.length} mainline step(s) not run${allFailed.length ? `, every step failed in ${allFailed.join(', ')}` : ''}` });

  // Open blocking questions: no longer a reason for “partial”. The analysis went on under the
  // assumption the Agent stated; conclusions that depend on the answer stay pending and the revision says which
  // question they wait for. The question stays in the inbox; answering it offers a targeted reverification.
  const open = rt.store.all<{ id: string; step_id: string; text: string }>(`SELECT id, step_id, text FROM question WHERE audit_id = ? AND status = 'open' AND blocking = 1`, rt.auditId);
  checks.push({ name: 'blocking_questions', ok: open.length === 0, detail: `${open.length} open blocking question(s)` });
  if (open.length) {
    for (const q of open) {
      const vulns = rt.store.all<{ id: string; confirm_status: string }>(
        `SELECT v.id, v.confirm_status FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id JOIN vulnerability v ON v.id = o.vulnerability_id
         WHERE o.audit_id = ? AND f.step_id = ?`, rt.auditId, q.step_id);
      for (const v of vulns) {
        if (v.confirm_status === 'confirmed') {
          rt.store.update('vulnerability', { id: v.id }, { confirm_status: 'pending', pending_kind: 'missing_context' });
          addRevision(rt.store, v.id, { dimension: 'confirm', source: 'rule', actor: 'engine', from: 'confirmed', to: 'pending', reason: `依据的提问未回答（${q.id}）：${q.text.slice(0, 200)}`, auditId: rt.auditId });
        }
      }
    }
  }

  let coverage: GateResult['coverage'] = null;
  const gaps: string[] = [];
  // statuses are settled against all reads in every audit with coverage items, not only with coverage targets,
  // and every item without a conclusion is listed with its reason. Only a missed target still makes the audit partial.
  let unconcluded: UnconcludedSummary | undefined;
  if (rt.store.get('SELECT 1 FROM coverage_item WHERE audit_id = ? LIMIT 1', rt.auditId)) {
    const totals = finalizeCoverage(rt, stepId);
    if (rt.strategy.tools.coverageCompare) {
      coverage = totals;
      mergeBackfill(rt, stepId);
    }
    unconcluded = unconcludedSummary(rt, overflow);
    const reasons = Object.entries(unconcluded.byReason).filter(([, n]) => n > 0).map(([r, n]) => `${r} ${n}`).join(', ');
    checks.push({ name: 'unconcluded', ok: unconcluded.total === 0, detail: `${unconcluded.total} item(s) without a conclusion${reasons ? ` (${reasons})` : ''}` });
  }
  if (coverage) {
    const ratio = (x: { total: number; reviewed: number }) => (x.total === 0 ? 1 : x.reviewed / x.total);
    const entryOk = ratio(coverage.entry) >= rt.strategy.coverageTarget.entry;
    const sinkOk = ratio(coverage.sink) >= rt.strategy.coverageTarget.sink;
    checks.push({ name: 'coverage', ok: entryOk && sinkOk, detail: `entry ${coverage.entry.reviewed}/${coverage.entry.total}, sink ${coverage.sink.reviewed}/${coverage.sink.total}` });
    if (!entryOk || !sinkOk) {
      reasons.add('COVERAGE_GAP');
      const unc = rt.store.all<{ kind: string; target_id: string; status: string }>(`SELECT kind, target_id, status FROM coverage_item WHERE audit_id = ? AND status != 'concluded' AND status != 'excluded' ORDER BY kind, target_id`, rt.auditId);
      gaps.push(...unc.map((u) => `${u.kind}:${u.target_id}:${u.status}`));
    }
  }
  // Risk hypotheses: every hypothesis the threat model listed needs a verdict; the rest is a declared
  // gap (never silently “no risk”).
  if (threatHypothesesOn(rt.strategy) && !backfillScope(rt)) {
    const targets = verificationTargets(rt);
    const left = targets.filter((h) => rt.store.get<{ status: string }>('SELECT status FROM hypothesis WHERE id = ?', h.id)?.status === 'proposed');
    checks.push({ name: 'hypotheses', ok: left.length === 0, detail: `${targets.length - left.length}/${targets.length} risk hypotheses verified` });
    if (left.length) {
      reasons.add('COVERAGE_GAP');
      gaps.push(...left.map((h) => `hypothesis:${h.id}:proposed`));
    }
  }
  // the obligation ledger. Entry points, sinks and hypotheses are judged above as before; checklist
  // items and external-scanner results still open after the review rounds are a declared gap.
  const obligations = obligationSummary(rt);
  if (obligations.total) {
    checks.push({ name: 'obligations', ok: obligations.settled === obligations.total, detail: `${obligations.settled}/${obligations.total} obligations settled (${Object.entries(obligations.byKind).map(([k, v]) => `${k} ${v!.settled}/${v!.total}`).join(', ')})` });
    const openRows = obligations.open.filter((o) => o.kind === 'checklist' || o.kind === 'external');
    if (openRows.length) {
      reasons.add('COVERAGE_GAP');
      gaps.push(...openRows.map((o) => `obligation:${o.kind}:${o.id}`));
    }
  }
  // Candidates over the limit that a later round concluded anyway (domain experts, gap fill) are not
  // missed; only those whose coverage item is still open (or that have none) are a gap.
  const settled = new Set(rt.store.all<{ target_id: string }>(`SELECT target_id FROM coverage_item WHERE audit_id = ? AND status IN ('concluded','excluded')`, rt.auditId).map((r) => r.target_id));
  const missed = overflow.filter((o) => !settled.has(o));
  if (missed.length) {
    reasons.add('COVERAGE_GAP');
    gaps.push(...missed.map((o) => `over_limit:${o}`));
  }
  // LSP degrades to tree-sitter when the language server is unavailable — only a query that
  // actually fell back counts (“按需”: an audit that never needed the server is not degraded).
  // the structure index stays available, so the fallback is said in the report but is not a reason.
  if (rt.strategy.tools.lsp && rt.store.listEvents(rt.auditId, 0, ['judgement.made']).some((e) => e.payload.kind === 'lsp_fallback')) notices.push('语言服务器不可用，定义与引用查询退回结构索引');
  // only gaps in a target repository's index make its coverage incomplete.
  for (const r of rt.targets) if (rt.indexes.get(r.name)?.gaps.length) reasons.add('INDEX_DEGRADED');
  const partialReasons = sortPartialReasons(reasons);
  // The reasons stay on a completed audit as process issues; only the mainline makes it partial.
  const status: GateResult['status'] = !reconciled ? 'failed' : mainlineOk ? 'completed' : 'partial';
  rt.event('gate.evaluated', { status, partial_reasons: partialReasons, checks, ...(notices.length ? { notices } : {}) }, stepId);
  return {
    status, partialReasons, checks, coverage, gaps: gaps.slice(0, 500), ...(unconcluded ? { unconcluded } : {}),
    ...(notices.length ? { notices } : {}), ...(unreviewed.length ? { unreviewed } : {}), ...(obligations.total ? { obligations } : {}),
  };
}

export function reportStep(rt: AuditRuntime, ctx: AttemptContext, carried: PartialReason[], overflow: string[]): StepResult {
  const gate = evaluateGate(rt, ctx.stepId, carried, overflow);
  const gateRef = rt.store.artifacts.putJson(gate);
  const refs: Record<string, string> = {};
  if (gate.status !== 'failed') {
    for (const format of ['md', 'html', 'json', 'sarif'] as const) {
      const media = format === 'md' ? 'text/markdown' : format === 'html' ? 'text/html' : 'application/json';
      // A format that fails to render is left out (it can be exported again later); the completion gate
      // still decides the audit's status.
      try {
        refs[format] = rt.store.artifacts.put(exportAudit(rt.store, rt.auditId, format, { override: {
          status: gate.status, partialReasons: gate.partialReasons, ...(gate.unconcluded ? { unconcluded: gate.unconcluded } : {}),
          ...(gate.notices ? { notices: gate.notices } : {}), ...(gate.unreviewed ? { unreviewed: gate.unreviewed } : {}),
          ...(gate.obligations ? { obligations: gate.obligations } : {}),
        } }), media);
      } catch (e) {
        rt.event('judgement.made', { kind: 'report_render_failed', format, error: (e as Error).message.slice(0, 500) }, ctx.stepId);
      }
    }
  }
  const outputRef = rt.store.artifacts.putJson({ gateRef, reports: refs });
  return { outputRef, apply: () => rt.store.update('audit', { id: rt.auditId }, { gate_ref: gateRef, report_refs: refs }) };
}
