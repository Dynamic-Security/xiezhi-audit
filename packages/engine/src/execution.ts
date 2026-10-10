// Execution overview: every step of an audit by phase, with what it works on (the
// candidates and their progress), the agent sessions it runs (sub-agents included) and what they wait for,
// and the live concurrency. Derived from the steps and the trajectory; nothing new is stored.
import { EXECUTION_SEGMENTS, stepRole, upgradeStrategy, type AuditEvent, type AuditStrategy, type ExecAgentDto, type ExecCandidateDto, type ExecStepDto, type ExecutionDto, type EXECUTION_PHASES } from '@xiezhi/contracts';
import { modelGate } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import { getAudit, listSteps, sessionLimit, type StepRow } from './state.js';

type Phase = (typeof EXECUTION_PHASES)[number];
const ORDER: Phase[] = ['prepare', 'triage', 'hunt', 'explore', 'challenge', 'verify', 'risk', 'finalize'];

// phase and segment come from the stage catalog's step roles.
const phaseOf = (s: StepRow): Phase => stepRole(s.kind, s.lineage_id)?.phase ?? 'prepare';

type Segment = (typeof EXECUTION_SEGMENTS)[number];

const segmentOf = (s: StepRow): Segment => stepRole(s.kind, s.lineage_id)?.segment ?? 'finalize';

/** The segments an audit of this scene and strategy goes through (before its steps exist). */
export function expectedSegments(scene: string, st: AuditStrategy, scope: string, hasExternal: boolean): Segment[] {
  // Supplements (追加执行): no triage; a hypothesis-only supplement has no threat model either.
  const sc = fromJson<{ supplement?: { kind: string; hypothesisIds?: string[] }; backfill?: unknown }>(scope, {});
  const sup = sc.supplement;
  if (sup) {
    const threat: Segment[] = sup.kind === 'threat_hypotheses' && !sup.hypothesisIds?.length ? ['threat'] : [];
    return ['snapshot', 'index', 'plan', 'profile', ...threat, 'hunt', ...(st.stages.adversarialReview ? ['challenge' as const] : []), 'finalize'];
  }
  const index: Segment[] = st.tools.ast ? ['index'] : [];
  const minimal = !st.models.triage && !st.stages.adversarialReview && !st.tools.coverageCompare;
  const deep: Segment[] = st.stages.deepExplore && st.limits.maxRounds > 0 ? ['explore'] : [];
  const challenge: Segment[] = st.stages.adversarialReview ? ['challenge'] : [];
  const threat: Segment[] = st.stages.threatHypotheses ? ['threat'] : [];
  // the stages after the exploration — external triage (when results were imported), the checklist check
  // (full audits) and the conclusion recheck — are announced too (not for a coverage backfill).
  const after = (full: boolean): Segment[] => sc.backfill ? [] : [...(hasExternal ? ['external' as const] : []), ...(full ? ['checklist' as const] : []), 'recheck'];
  switch (scene) {
    case 'reverify': return ['snapshot', ...index, 'plan', 'verify', 'finalize'];
    case 'risk_hunt': return ['snapshot', ...index, 'plan', 'locate', 'judge', 'finalize'];
    case 'incremental': return ['snapshot', ...index, 'plan', 'scope', ...threat, 'hunt', ...after(false), ...deep, ...challenge, 'finalize'];
    default: return ['snapshot', ...index, 'plan', ...(minimal ? [] : ['profile' as const]), ...threat, 'triage', 'hunt', ...after(true), ...deep, ...challenge, 'finalize'];
  }
}

const EVENT_TYPES = [
  'session.started', 'session.turn', 'session.ended', 'session.queued', 'session.dequeued', 'task.started', 'task.finished',
  'tool.called', 'candidate.marked', 'candidate.settled', 'question.asked', 'question.answered', 'model.fallback',
] as const;
const iso = (ms: number | null | undefined) => (ms ? new Date(ms).toISOString() : null);
const TERMINAL_STEP = ['succeeded', 'failed', 'skipped', 'cancelled'];

interface SessionAcc {
  id: string; role: 'main' | 'task'; parent: string | null; goal: string | null; startedAt: number; endedAt: number | null;
  ended: string | null; waiting: 'slot' | 'model' | null; lastTool: ExecAgentDto['lastTool']; turns: number; tokens: number;
}

export function executionOverview(store: Store, auditId: string): ExecutionDto {
  const audit = getAudit(store, auditId);
  const steps = listSteps(store, auditId);
  const events = store.listEvents(auditId, 0, [...EVENT_TYPES]);
  const auditRunning = ['running', 'cancelling'].includes(audit.status);

  const sessions = new Map<string, SessionAcc>();
  const byStep = new Map<string, SessionAcc[]>();
  const marks = new Map<string, Map<string, { status: string; note: string | null }>>();
  const settled = new Map<string, Map<string, { status: string; note: string | null; changedFrom: string | null }>>();
  const openQuestions = new Map<string, Set<string>>();
  const fallbacks = new Map<string, ExecStepDto['fallback']>();
  const session = (e: AuditEvent): SessionAcc | null => {
    const s = e.payload.session as { id: string; role: 'main' | 'task'; parent?: string } | undefined;
    if (!s?.id || !e.stepId) return null;
    let acc = sessions.get(s.id);
    if (!acc) {
      acc = { id: s.id, role: s.role, parent: s.parent ?? null, goal: null, startedAt: e.ts, endedAt: null, ended: null, waiting: null, lastTool: null, turns: 0, tokens: 0 };
      sessions.set(s.id, acc);
      byStep.set(e.stepId, [...(byStep.get(e.stepId) ?? []), acc]);
    }
    return acc;
  };
  for (const e of events) {
    const p = e.payload;
    if (e.type === 'candidate.marked' || e.type === 'candidate.settled') {
      if (!e.stepId) continue;
      const m = e.type === 'candidate.marked' ? marks : settled;
      const per = m.get(e.stepId) ?? new Map();
      m.set(e.stepId, per);
      per.set(String(p.candidate), { status: String(p.status), note: p.note ? String(p.note) : null, changedFrom: p.changedFrom ? String(p.changedFrom) : null });
      continue;
    }
    if (e.type === 'model.fallback' && e.stepId) {
      fallbacks.set(e.stepId, { from: String(p.from), reason: String(p.reason), degraded: p.degraded === true, manual: p.manual === true });
      continue;
    }
    if (e.type === 'question.asked' && e.stepId && p.blocking) {
      openQuestions.set(e.stepId, (openQuestions.get(e.stepId) ?? new Set()).add(String(p.question_id)));
      continue;
    }
    if (e.type === 'question.answered') {
      for (const set of openQuestions.values()) set.delete(String(p.question_id));
      continue;
    }
    const acc = session(e);
    if (!acc) continue;
    switch (e.type) {
      case 'task.started': acc.goal = String(p.goal ?? ''); break;
      case 'session.queued': acc.waiting = p.wait === 'slot' ? 'slot' : 'model'; break;
      case 'session.dequeued': acc.waiting = null; if (p.gaveUp) { acc.ended = 'failed'; acc.endedAt = e.ts; } break;
      case 'session.turn': acc.turns++; acc.tokens += Number(p.input ?? 0) + Number(p.output ?? 0); break;
      case 'tool.called': acc.lastTool = { tool: String(p.tool), args: p.args ?? null, at: iso(e.ts)! }; break;
      case 'session.ended': if (!acc.ended) { acc.ended = String(p.status ?? 'completed'); acc.endedAt = e.ts; } break;
      case 'task.finished': acc.ended = p.status === 'completed' ? 'completed' : 'failed'; acc.endedAt = e.ts; break;
      default: break;
    }
  }

  const agentOf = (a: SessionAcc, step: StepRow): ExecAgentDto => {
    const running = !a.ended && auditRunning && step.status === 'running';
    const status: ExecAgentDto['status'] = a.ended ? (['completed', 'max_turns'].includes(a.ended) ? 'completed' : a.ended === 'aborted' ? 'interrupted' : 'failed') : running ? 'running' : 'interrupted';
    const asking = running && a.role === 'main' && (openQuestions.get(step.id)?.size ?? 0) > 0;
    return {
      id: a.id, role: a.role, parent: a.parent, goal: a.goal, status, waiting: running ? (a.waiting ?? (asking ? 'question' : null)) : null,
      lastTool: a.lastTool, turns: a.turns, tokens: a.tokens, startedAt: iso(a.startedAt)!, endedAt: iso(a.endedAt),
    };
  };
  const candidatesOf = (s: StepRow): { repo: string | null; list: ExecCandidateDto[] } => {
    const input = JSON.parse(s.input || '{}') as { repo?: string; base?: boolean; candidates?: { id: string; kind: string; repo: string; path: string; line: number; label: string; reason?: string; score?: number }[] };
    const done = settled.get(s.id);
    const marked = marks.get(s.id);
    const list = (input.candidates ?? []).map((c): ExecCandidateDto => {
      const fin = done?.get(c.id);
      const m = marked?.get(c.id);
      const status = (fin?.status ?? m?.status ?? 'pending') as ExecCandidateDto['status'];
      return {
        id: c.id, kind: c.kind, repo: c.repo, path: c.path, line: c.line, label: c.label, reason: c.reason ?? null, score: c.score ?? null,
        status, preliminary: !fin && !!m, note: fin?.note ?? m?.note ?? null, changedFrom: fin?.changedFrom ?? null,
      };
    });
    return { repo: input.repo ? `${input.repo}${input.base ? '（基线）' : ''}` : null, list };
  };

  /** The finding (challenge / review) or vulnerability (reverify) a step works on, as one line. */
  const subjectOf = (s: StepRow): string | null => {
    const input = JSON.parse(s.input || '{}') as { findingId?: string; vulnId?: string; domain?: { name: string }; round?: number; light?: boolean };
    // A domain expert names its domain and round; the generalist fallback (older audits) says so.
    if (input.domain) return `领域：${input.domain.name} · 第 ${input.round ?? 1} 轮`;
    // a check batch names its class and size; a fill batch its size.
    const chk = JSON.parse(s.input || '{}') as { vulnClass?: string; keys?: string[] };
    if (s.lineage_id?.startsWith('CHK-F-') && chk.keys) return `清单补审：${chk.keys.length} 个未覆盖条目`;
    if (s.lineage_id?.startsWith('CHK-B') && chk.keys) return `清单核对：${chk.vulnClass ?? ''} · ${chk.keys.length} 个条目`;
    const rck = JSON.parse(s.input || '{}') as { units?: { reason: string }[] };
    if (s.lineage_id?.startsWith('RCK-') && rck.units) return `结论复查：${rck.units.length} 个“无问题”单元（索引矛盾 ${rck.units.filter((u) => u.reason === 'index_fact').length}）`;
    // the lead dispatches the domain subtasks; a later session took over from an earlier one at its context cap.
    if (/^LEAD(-M\d+)?-\d+$/.test(s.lineage_id ?? '')) return `主控：派发领域子任务 · 第 ${(JSON.parse(s.input || '{}') as { session?: number }).session ?? 1} 个会话`;
    if (s.lineage_id?.startsWith('HUNT-F')) return '兜底追查：专家未覆盖的高分候选';
    if (input.findingId) {
      const title = store.get<{ title: string }>('SELECT title FROM finding WHERE id = ?', input.findingId)?.title ?? null;
      // a light review says so.
      return title && input.light ? `简化复核：${title}` : title;
    }
    if (input.vulnId) {
      const v = store.get<{ display_no: number; title: string }>('SELECT display_no, title FROM vulnerability WHERE id = ?', input.vulnId);
      return v ? `V-${v.display_no} ${v.title}` : null;
    }
    return null;
  };
  const phases = new Map<Phase, ExecStepDto[]>();
  for (const s of steps) {
    const { repo, list } = candidatesOf(s);
    const dto: ExecStepDto = {
      id: s.id, kind: s.kind, lineage: s.lineage_id, status: s.status, startedAt: iso(s.started_at), endedAt: iso(s.ended_at),
      tokens: s.tokens_in + s.tokens_out, repo, subject: subjectOf(s), segment: segmentOf(s),
      model: s.provider && s.model ? `${s.provider}/${s.model}` : null, fallback: fallbacks.get(s.id) ?? null, candidates: list, agents: (byStep.get(s.id) ?? []).map((a) => agentOf(a, s)),
    };
    const ph = phaseOf(s);
    phases.set(ph, [...(phases.get(ph) ?? []), dto]);
  }

  const all = [...phases.values()].flat();
  // the lead's own session takes no session slot (its subtasks do), so it is not counted against the limit.
  const isLead = (s: ExecStepDto) => /^LEAD(-M\d+)?-\d+$/.test(s.lineage ?? '');
  const liveAgents = all.flatMap((s) => s.agents.filter((a) => !(isLead(s) && a.role === 'main'))).filter((a) => a.status === 'running');
  const strategy = upgradeStrategy(JSON.parse(audit.strategy_frozen ?? audit.strategy_draft));
  const gate = modelGate.stats();
  // Segments: expected by scene and strategy plus those that ran; a finished audit shows only what ran.
  const ran = new Set(all.map((s) => s.segment));
  const expected = new Set(['completed', 'partial', 'failed', 'cancelled'].includes(audit.status) ? [] : expectedSegments(audit.scene, strategy, audit.scope, !!store.get(`SELECT 1 FROM obligation WHERE audit_id = ? AND kind = 'external' LIMIT 1`, auditId)));
  const plan = audit.plan_ref ? store.artifacts.getJson<{ estimate?: { tokens?: { p50?: number }; durationSec?: { p50?: number } } }>(audit.plan_ref) : null;
  return {
    auditId, status: audit.status,
    phases: ORDER.filter((k) => phases.has(k)).map((key) => ({ key, steps: phases.get(key)! })),
    concurrency: {
      sessions: { running: liveAgents.filter((a) => a.waiting !== 'slot').length, limit: sessionLimit(store, auditId, strategy.concurrency.sessions), queued: liveAgents.filter((a) => a.waiting === 'slot').length },
      model: { active: gate.active, queued: gate.queued, capacity: gate.capacity },
    },
    segments: EXECUTION_SEGMENTS.filter((k) => ran.has(k) || expected.has(k)),
    estimate: { tokens: plan?.estimate?.tokens?.p50 != null ? Math.round(plan.estimate.tokens.p50) : null, durationSec: plan?.estimate?.durationSec?.p50 != null ? Math.round(plan.estimate.durationSec.p50) : null },
    counts: {
      running: all.filter((s) => s.status === 'running').length,
      waiting: all.filter((s) => !TERMINAL_STEP.includes(s.status) && s.status !== 'running').length,
      done: all.filter((s) => TERMINAL_STEP.includes(s.status)).length,
      total: all.length,
    },
  };
}
