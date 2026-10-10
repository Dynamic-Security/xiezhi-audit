// hunt-risk: locate candidates deterministically, judge each repository's
// candidates with one session, then settle the per-repository verdict: `affected`
// needs a canonical hit with verified evidence, `not_affected` needs a reason and evidence, anything
// else is `pending`. Hits are findings of this audit; they become vulnerabilities only when promoted.
import {
  type FindingDraft, type HitDraft, canonicalJson, newId, sha256Hex, SubmitRiskVerdicts, type HuntBasis, type RiskCandidate, type SubmitRiskVerdicts as Verdicts, stageModel } from '@xiezhi/contracts';
import { locateRiskCandidates, type LocateResult } from '@xiezhi/context';
import type { AuditTool } from '@xiezhi/agent';
import { fromJson } from '@xiezhi/store';
import { verifyCodeRef } from '../identity.js';
import type { AuditRuntime } from '../runtime.js';
import { sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { applyHunt, validateFindings } from './hunt.js';
import { reviewVerdict } from './verdict-review.js';
import { P } from '@xiezhi/knowledge';

export interface HuntScope { hunt: { id: string; basisRef: string } }

export function huntScope(rt: AuditRuntime): HuntScope['hunt'] | null {
  return fromJson<Partial<HuntScope>>(rt.audit.scope, {}).hunt ?? null;
}

export function huntBasis(rt: AuditRuntime): HuntBasis {
  return rt.store.artifacts.getJson<HuntBasis>(huntScope(rt)!.basisRef);
}

export function basisHash(b: HuntBasis): string {
  return sha256Hex(canonicalJson(b));
}

export async function riskLocateStep(rt: AuditRuntime, ctx: AttemptContext): Promise<StepResult> {
  const basis = huntBasis(rt);
  const repos = rt.targets.map((r) => r.name);
  const r = await locateRiskCandidates(rt.toolContext(ctx.signal, ctx.stepId), repos, basis, { maxCandidates: rt.strategy.limits.maxCandidates || 100 });
  rt.event('judgement.made', { kind: 'risk_locate', candidates: r.candidates.length, truncated: r.truncated }, ctx.stepId);
  return { outputRef: rt.store.artifacts.putJson(r) };
}

export interface JudgeOutput { repo: string; candidates: string[]; verdicts: Verdicts; deterministic: boolean; checks: string[] }

function renderBasis(b: HuntBasis): string[] {
  const f = b.features;
  return [
    `## 排查依据：${b.title}`, b.summary,
    ...(f.dependencies.length ? ['受影响组件：', ...f.dependencies.map((d) => `- ${d.ecosystem} ${d.name} ${d.affectedVersions}${d.fixedVersion ? `（修复版本 ${d.fixedVersion}）` : ''}`)] : []),
    ...(f.apis.length ? ['危险 API：', ...f.apis.map((a) => `- \`${a.pattern}\` ${a.description}`)] : []),
    ...(f.codePatterns.length ? ['代码模式：', ...f.codePatterns.map((p) => `- ${p.description}`)] : []),
    '判定为“受影响”：', ...b.affectedIf.map((x) => `- ${x}`),
    '判定为“不受影响”：', ...b.notAffectedIf.map((x) => `- ${x}`),
  ];
}

/** One session per repository over its candidates; no candidates → settled by rule without a model. */
export async function riskJudgeStep(rt: AuditRuntime, repo: string, candidates: RiskCandidate[], checks: string[], lineage: string, ctx: AttemptContext): Promise<StepResult> {
  const basis = huntBasis(rt);
  if (!candidates.length) {
    const out: JudgeOutput = {
      repo, candidates: [], deterministic: true, checks,
      verdicts: { hits: [], ruledOut: [], repoVerdict: { verdict: 'not_affected', reason: '未发现受影响的依赖、危险 API 或代码模式', evidence: [] } },
    };
    const outputRef = rt.store.artifacts.putJson(out);
    return { outputRef };
  }
  const known = new Set(candidates.map((c) => c.id));
  const submit: AuditTool = {
    name: 'submit_risk_verdicts', kind: 'submit', parameters: SubmitRiskVerdicts,
    description: P('tool.submit_risk_verdicts'),
    validate: (a: Verdicts) => {
      const issues = validateFindings(rt, { findings: a.hits.map(asFinding), reviewedTargets: [], ruledOut: [] });
      for (const h of a.hits) if (h.location.repo && h.location.repo !== repo) issues.push(P('feedback.risk.hit_repo', { repo }));
      for (const r of a.ruledOut) if (!known.has(r.candidateId)) issues.push(P('feedback.risk.unknown_candidate', { candidateId: r.candidateId }));
      const v = a.repoVerdict;
      if (v.verdict === 'affected' && a.hits.length === 0) issues.push(P('feedback.risk.affected_hit'));
      if (v.verdict === 'not_affected' && v.evidence.length === 0 && checks.length === 0) issues.push(P('feedback.risk.not_affected_evidence'));
      if (v.verdict === 'pending' && !v.pendingCondition) issues.push(P('feedback.risk.pending_condition'));
      return issues.slice(0, 20);
    },
    run: (a: Verdicts) => ({ text: `recorded: ${a.repoVerdict.verdict}, ${a.hits.length} hit(s)` }),
  };
  const prompt = [
    P('risk.task', { repo }),
    ...renderBasis(basis),
    '', `## 定位到的候选点（${candidates.length} 个）`,
    ...candidates.map((c) => `- id=\`${c.id}\`\n  位置：${c.repo}:${c.path}${c.line ? `:${c.line}` : ''}\n  ${c.label}${c.detail ? `\n  ${c.detail}` : ''}`),
    ...(checks.length ? ['', '## 已做的确定性检查', ...checks.slice(0, 30).map((x) => `- ${x}`)] : []),
    '', P('risk.rules'),
  ].join('\n');
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'hunt-risk', phase: 'hunt', model: stageModel(rt.strategy, 'verify')!, signal: ctx.signal,
    prompt, submitTools: [submit], requiredSubmits: ['submit_risk_verdicts'], maxTurns: rt.strategy.limits.maxTurnsPerStep, withIndex: false,
  });
  const err = sessionError(outcome);
  if (err) throw err;
  let verdicts = (outcome.submissions.submit_risk_verdicts as Verdicts[]).at(-1)!;
  // Optional review of “受影响” only (risk_hunt, stages.adversarialReview): a doubt makes it “待确认”.
  if (rt.strategy.stages.adversarialReview && verdicts.repoVerdict.verdict === 'affected') {
    const review = await reviewVerdict(rt, ctx, 'affected', [
      ...renderBasis(basis), '', P('risk.review_affected_heading', { repo }),
      '命中位置：', ...verdicts.hits.map((h) => `- ${h.location.path}:${h.location.startLine}-${h.location.endLine} ${h.title}`),
    ], verdicts.repoVerdict.reason);
    if (review.decision === 'doubt') {
      verdicts = { ...verdicts, repoVerdict: { ...verdicts.repoVerdict, verdict: 'pending', reason: `${verdicts.repoVerdict.reason}（复核存疑：${review.reason.slice(0, 500)}）`, ...(review.pendingCondition ? { pendingCondition: review.pendingCondition } : {}) } };
    }
  }
  const out: JudgeOutput = { repo, candidates: candidates.map((c) => c.id), verdicts, deterministic: false, checks };
  const outputRef = rt.store.artifacts.putJson(out);
  return {
    outputRef,
    apply: () => applyHunt(rt, ctx.stepId, lineage, { batch: [], findings: verdicts.hits.map((h) => asFinding({ ...h, location: { ...h.location, repo } })), reviewedTargets: [], ruledOut: [], scopeReviewed: [], stateOps: [] }),
  };
}

/** A hit becomes a finding; it is pending exactly when it carries a pending condition (the pre-verdict rule). */
function asFinding(h: HitDraft): FindingDraft {
  return { ...h, verdict: h.pendingCondition ? 'pending' : 'confirmed' };
}

/** Settle per-repository verdicts from the judge outputs and the canonical hits. */
export function settleRiskTargets(rt: AuditRuntime, outputs: JudgeOutput[]): void {
  const store = rt.store;
  const hunt = huntScope(rt);
  if (!hunt) return;
  store.tx(() => {
    for (const o of outputs) {
      const repo = rt.repoByName(o.repo);
      if (!repo) continue;
      const target = store.get<{ id: string }>('SELECT id FROM risk_hunt_target WHERE risk_hunt_id = ? AND audit_id = ? AND repository_id = ?', hunt.id, rt.auditId, repo.id);
      if (!target) continue;
      const verifiedHit = store.get<{ n: number }>(
        `SELECT COUNT(*) AS n FROM finding f JOIN evidence e ON e.owner_kind = 'finding' AND e.owner_id = f.id AND e.ord = 0 AND e.verified = 1
         WHERE f.audit_id = ? AND f.repository_id = ? AND f.state = 'canonical'`, rt.auditId, repo.id)!.n > 0;
      const v = o.verdicts.repoVerdict;
      let verdict = v.verdict;
      let reason = v.reason;
      // a verified canonical hit is necessary for `affected`, not sufficient. A hit next to a
      // pending verdict is the place to confirm; next to `not_affected` it is a contradiction.
      if (verifiedHit && verdict === 'not_affected') {
        verdict = 'pending';
        reason = `${reason}（存在已核实的命中位置，与“不受影响”矛盾，暂列待确认）`;
      } else if (!verifiedHit && verdict === 'affected') {
        verdict = 'pending';
        reason = `${reason}（命中位置的证据未通过核实，暂列待确认）`;
      }
      if (verdict === 'not_affected' && !reason.trim()) verdict = 'pending';
      const evidence = v.evidence.map((e) => ({ e, check: verifyCodeRef(rt.views.get(e.repo ?? o.repo), e) }));
      if (verdict === 'not_affected' && !evidence.some((x) => x.check.verified) && !o.checks.length) {
        verdict = 'pending';
        reason = `${reason}（缺少可核实的依据）`;
      }
      store.db.run(`DELETE FROM evidence WHERE owner_kind = 'risk_hunt_target' AND owner_id = ?`, target.id);
      evidence.forEach(({ e, check }, ord) => store.insert('evidence', {
        id: newId('evidence'), owner_kind: 'risk_hunt_target', owner_id: target.id, kind: 'code_range', snapshot_id: (rt.repoByName(e.repo ?? o.repo) ?? repo).snapshotId,
        path: e.path, start_line: e.startLine, end_line: e.endLine, content_hash: check.contentHash, verified: check.verified ? 1 : 0, note: e.note ?? null, ord, origin_label: 'risk_verdict',
      }));
      o.checks.filter((c) => c.startsWith(`${o.repo}：`)).slice(0, 20).forEach((c, i) => store.insert('evidence', {
        id: newId('evidence'), owner_kind: 'risk_hunt_target', owner_id: target.id, kind: 'tool_output', note: c.slice(o.repo.length + 1), ord: evidence.length + i, verified: 1, origin_label: 'locate_check',
      }));
      store.update('risk_hunt_target', { id: target.id }, {
        verdict, reason: reason.slice(0, 1000), verdict_source: o.deterministic ? 'rule' : 'ai',
        pending_condition: verdict === 'pending' ? v.pendingCondition ?? null : null,
      });
      rt.event('judgement.made', { kind: 'risk_verdict', repo: o.repo, verdict }, null);
    }
  });
}

export function locateOutput(rt: AuditRuntime, ref: string): LocateResult {
  return rt.store.artifacts.getJson<LocateResult>(ref);
}
