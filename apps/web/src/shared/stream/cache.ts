// Event → cache updates: status and budget events patch the audit snapshot directly,
// trajectory events are appended to the cached trajectory pages they match; results, coverage and
// questions are only invalidated. Pure functions, so they are unit tested without a browser.
//
// The web app may import contract *types* only (the contracts runtime needs Node). The tables below
// mirror the contracts ones and are typed as `typeof <contract table>` (literal types), so any drift
// is a compile error rather than a silent behaviour difference.
import type {
  AuditDetailDto, AuditPhase, AuditStatus, EVENT_CACHE_HANDLING, EventDto, PHASE_OF_KIND, StepDto, StepStatus, TRAJECTORY_GROUPS, TRAJECTORY_NOISE,
} from '@xiezhi/contracts';

export const HANDLING: typeof EVENT_CACHE_HANDLING = {
  'audit.status_changed': 'patch_audit', 'step.status_changed': 'patch_audit', 'step.attempt_started': 'append_trajectory',
  'plan.generated': 'patch_audit', 'plan.confirmed': 'patch_audit',
  'session.started': 'append_trajectory', 'session.turn': 'append_trajectory', 'session.compacted': 'append_trajectory', 'session.ended': 'append_trajectory',
  'agent.note': 'append_trajectory',
  'session.queued': 'append_trajectory', 'session.dequeued': 'append_trajectory', 'session.paused': 'append_trajectory', 'session.resumed': 'append_trajectory', 'task.started': 'append_trajectory', 'task.finished': 'append_trajectory',
  'candidate.marked': 'append_trajectory', 'candidate.settled': 'append_trajectory',
  'model.fallback': 'append_trajectory',
  'tool.called': 'append_trajectory', 'tool.result': 'append_trajectory', 'file.read': 'append_trajectory', 'cross_repo.traced': 'append_trajectory',
  'knowledge.loaded': 'append_trajectory', 'knowledge.changed': 'append_trajectory', 'connector.queried': 'append_trajectory', 'connector.write_requested': 'append_trajectory', 'connector.write_decided': 'append_trajectory',
  'hypothesis.proposed': 'append_trajectory', 'hypothesis.retired': 'append_trajectory', 'state.updated': 'append_trajectory', 'decide.chosen': 'append_trajectory',
  'question.asked': 'invalidate_questions', 'question.answered': 'invalidate_questions', 'intervention.received': 'append_trajectory', 'intervention.applied': 'append_trajectory',
  'judgement.made': 'append_trajectory', 'finding.submitted': 'invalidate_results', 'finding.challenged': 'invalidate_results', 'finding.reconciled': 'invalidate_results',
  'vuln.created': 'invalidate_results', 'vuln.matched': 'invalidate_results', 'vuln.impact_changed': 'invalidate_results',
  'contract.violation': 'append_trajectory', 'security.blocked': 'append_trajectory', 'injection_suspected': 'append_trajectory',
  'budget.reserved': 'patch_audit', 'budget.charged': 'patch_audit', 'budget.exhausted': 'patch_audit', 'budget.topped_up': 'patch_audit',
  'coverage.updated': 'invalidate_coverage', 'gate.evaluated': 'patch_audit', 'error': 'append_trajectory',
};

export const GROUPS: typeof TRAJECTORY_GROUPS = {
  note: ['agent.note'],
  plan: ['plan.generated', 'plan.confirmed'],
  read: ['file.read'],
  tool: ['tool.called', 'tool.result', 'task.started', 'task.finished'],
  knowledge: ['knowledge.loaded', 'knowledge.changed'],
  question: ['question.asked', 'question.answered', 'connector.write_requested', 'connector.write_decided'],
  intervention: ['intervention.received', 'intervention.applied'],
  judgement: ['candidate.marked', 'candidate.settled', 'judgement.made', 'finding.submitted', 'finding.challenged', 'finding.reconciled', 'hypothesis.proposed', 'hypothesis.retired', 'state.updated'],
  vuln: ['vuln.created', 'vuln.matched', 'vuln.impact_changed'],
  budget: ['budget.exhausted', 'budget.topped_up'],
  step: ['audit.status_changed', 'step.status_changed', 'session.started', 'session.ended', 'session.queued', 'session.dequeued', 'session.paused', 'session.resumed', 'model.fallback', 'gate.evaluated', 'coverage.updated'],
  security: ['contract.violation', 'security.blocked', 'injection_suspected', 'error'],
};

export const NOISE: typeof TRAJECTORY_NOISE = ['budget.reserved', 'budget.charged', 'session.turn', 'step.attempt_started'];

const PHASES: typeof PHASE_OF_KIND = {
  snapshot: 'preparing', index: 'preparing', plan: 'planning', triage: 'analyzing', hunt: 'analyzing', scope: 'analyzing', profile: 'analyzing',
  challenge: 'verifying', review: 'verifying', reconcile: 'verifying', report: 'reporting', finalize: 'reporting',
};

const TERMINAL_AUDIT: readonly string[] = ['completed', 'partial', 'failed', 'cancelled'];
const TERMINAL_STEP: readonly string[] = ['succeeded', 'failed', 'skipped', 'cancelled'];

/** Same rule as the server's `derivePhase` (contracts); a unit test compares the two. */
export function derivePhase(status: string, steps: readonly { kind: string; status: string }[]): AuditPhase {
  if (TERMINAL_AUDIT.includes(status)) return 'done';
  if (status === 'planning') return steps.some((s) => s.kind === 'plan' && s.status === 'running') ? 'planning' : steps.some((s) => s.status === 'running') ? 'preparing' : 'planning';
  if (status === 'awaiting_confirm') return 'awaiting_confirm';
  if (status === 'queued') return 'queued';
  const running = steps.filter((s) => s.status === 'running').at(-1);
  const last = running ?? [...steps].reverse().find((s) => s.status !== 'pending' && s.kind !== 'plan' && s.kind !== 'snapshot' && s.kind !== 'index');
  return last ? (PHASES as Record<string, AuditPhase>)[last.kind] ?? 'analyzing' : 'analyzing';
}

type P = Record<string, unknown>;
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

/** Apply a step.status_changed event to a step list; null when the step is unknown (refetch). */
export function patchSteps(steps: StepDto[], e: EventDto): StepDto[] | null {
  if (e.type !== 'step.status_changed') return steps;
  const i = steps.findIndex((s) => s.id === e.stepId);
  if (i === -1) return null;
  const p = e.payload as P;
  const s = steps[i]!;
  const to = String(p.to) as StepStatus;
  const next: StepDto = {
    ...s, status: to,
    attempt: num(p.attempt) ?? s.attempt,
    // Mirrors the step runner: a new attempt resets start time and error; end time is written on
    // success, failure and interruption.
    errorClass: typeof p.error_class === 'string' ? p.error_class : to === 'running' ? null : s.errorClass,
    errorSummary: to === 'running' ? null : s.errorSummary,
    startedAt: to === 'running' ? e.ts : s.startedAt,
    endedAt: ['succeeded', 'failed', 'interrupted'].includes(to) ? e.ts : s.endedAt,
    ...(TERMINAL_STEP.includes(to) ? { tokensIn: num(p.tokens_in) ?? s.tokensIn, tokensOut: num(p.tokens_out) ?? s.tokensOut, costMicros: p.cost_micros === undefined ? s.costMicros : num(p.cost_micros) } : {}),
  };
  const out = [...steps];
  out[i] = next;
  return out;
}

/**
 * Apply a `patch_audit` event to the cached audit detail. Returns null when the event cannot be
 * applied from its payload alone (unknown step): the caller refetches instead.
 */
export function patchAudit(a: AuditDetailDto, e: EventDto): AuditDetailDto | null {
  if (e.seq <= a.lastEventSeq) return a;
  const p = e.payload as P;
  let next: AuditDetailDto = { ...a, lastEventSeq: e.seq };
  switch (e.type) {
    case 'audit.status_changed': {
      const to = String(p.to) as AuditStatus;
      next = {
        ...next, status: to,
        ...(Array.isArray(p.partial_reasons) ? { partialReasons: p.partial_reasons as AuditDetailDto['partialReasons'] } : {}),
        ...(typeof p.error_class === 'string' ? { errorClass: p.error_class } : {}),
        startedAt: to === 'running' && !a.startedAt ? e.ts : a.startedAt,
        endedAt: TERMINAL_AUDIT.includes(to) ? e.ts : a.endedAt,
      };
      break;
    }
    case 'step.status_changed': {
      const steps = patchSteps(a.steps, e);
      if (!steps) return null;
      next = { ...next, steps };
      break;
    }
    case 'budget.charged': {
      const consumed = num(p.consumed);
      const cost = num(p.cost_micros);
      next = {
        ...next,
        budget: {
          ...a.budget,
          consumed: {
            ...a.budget.consumed,
            ...(consumed !== null ? { tokens: consumed } : {}),
            ...(cost !== null ? { costMicros: (a.budget.consumed.costMicros ?? 0) + cost } : {}),
          },
        },
      };
      break;
    }
    case 'budget.topped_up': {
      const eff = (p.effective ?? {}) as P;
      next = {
        ...next,
        budget: {
          ...a.budget,
          effective: {
            tokens: num(eff.tokens) ?? a.budget.effective.tokens,
            durationMs: num(eff.durationMs) ?? a.budget.effective.durationMs,
            costMicros: eff.costMicros === undefined ? a.budget.effective.costMicros : num(eff.costMicros),
          },
        },
      };
      break;
    }
    default:
      break;
  }
  return { ...next, phase: derivePhase(next.status, next.steps) };
}

/**
 * Events after which the audit snapshot also holds data the payload does not carry (plan, gate,
 * finding counts, exports): patch at once, then refetch once in the background.
 */
export function needsRefetch(e: EventDto): boolean {
  if (e.type === 'plan.generated' || e.type === 'plan.confirmed' || e.type === 'gate.evaluated' || e.type === 'budget.exhausted') return true;
  // The payload carries the error class, not the summary shown with it.
  if (e.type === 'step.status_changed') return ['failed', 'interrupted'].includes(String((e.payload as P).to));
  if (e.type === 'audit.status_changed') return TERMINAL_AUDIT.includes(String((e.payload as P).to)) || ['awaiting_confirm', 'waiting_budget'].includes(String((e.payload as P).to));
  return false;
}

export interface TrajectoryFilter {
  types: readonly string[];
  q: string;
}
export interface TrajectoryPage {
  items: EventDto[];
  nextAfter: number;
  hasMore: boolean;
}

/** Whether the server's trajectory query with this filter would return the event. */
export function matchesTrajectory(f: TrajectoryFilter, e: EventDto): boolean {
  if (f.types.length) {
    const groups = GROUPS as Record<string, readonly string[]>;
    if (!f.types.some((g) => groups[g]?.includes(e.type))) return false;
  } else if ((NOISE as readonly string[]).includes(e.type)) {
    return false;
  }
  return !f.q || JSON.stringify(e.payload).toLowerCase().includes(f.q.toLowerCase());
}

/**
 * Append a live event to a cached trajectory page. Unchanged when it does not match, is already there,
 * or the page is truncated (`hasMore`: the event belongs to a later page).
 */
export function appendTrajectory(page: TrajectoryPage, f: TrajectoryFilter, e: EventDto): TrajectoryPage {
  if (page.hasMore || !matchesTrajectory(f, e)) return page;
  const last = page.items.at(-1)?.seq ?? 0;
  if (e.seq <= last) return page;
  return { ...page, items: [...page.items, e], nextAfter: e.seq };
}

/**
 * The event cursor of one audit's stream. Sequence numbers are per audit and the audit page
 * component is reused when the route switches audits, so a cursor left over from audit A (seq 3000) would
 * subscribe to audit B with `after=3000` and drop B's events. A different audit gets a fresh cursor object;
 * callbacks of the previous subscription keep (and can only advance) the old one.
 */
export interface SeqCursor { readonly aid: string; seq: number }

export function cursorFor(prev: SeqCursor | null, aid: string): SeqCursor {
  return prev && prev.aid === aid ? prev : { aid, seq: 0 };
}

/** De-duplicate by seq: true (and the cursor advances) only for an event newer than the cursor. */
export function advanceCursor(c: SeqCursor, seq: number): boolean {
  if (seq <= c.seq) return false;
  c.seq = seq;
  return true;
}
