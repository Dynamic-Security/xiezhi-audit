// Event type names — the authoritative list (including `injection_suspected`).
export const EVENT_TYPES = [
  'audit.status_changed', 'step.status_changed', 'step.attempt_started',
  'plan.generated', 'plan.confirmed',
  'session.started', 'session.turn', 'session.compacted', 'session.ended',
  // the assistant's text and usage of one turn (redacted like every payload; text ≤ 2000 chars).
  'agent.note',
  // waiting for an audit session slot or the global model gate; `task` sub-agent lifecycle.
  'session.queued', 'session.dequeued', 'task.started', 'task.finished',
  // A session stopped between turns (pause, used-up stage quota) and one continued from its
  // saved transcript on a later attempt.
  'session.paused', 'session.resumed',
  // per-candidate progress reported by the Agent, and the verdict of the final submission.
  'candidate.marked', 'candidate.settled',
  // a step switched to its fallback model (or could not: `degraded`, cross review).
  'model.fallback',
  'tool.called', 'tool.result', 'file.read', 'cross_repo.traced',
  'knowledge.loaded', 'knowledge.changed', 'connector.queried', 'connector.write_requested', 'connector.write_decided',
  'hypothesis.proposed', 'hypothesis.retired', 'state.updated', 'decide.chosen',
  'question.asked', 'question.answered', 'intervention.received', 'intervention.applied',
  'judgement.made', 'finding.submitted', 'finding.challenged', 'finding.reconciled',
  'vuln.created', 'vuln.matched', 'vuln.impact_changed',
  'contract.violation', 'security.blocked', 'injection_suspected',
  'budget.reserved', 'budget.charged', 'budget.exhausted', 'budget.topped_up',
  'coverage.updated', 'gate.evaluated',
  'error',
] as const;
export type EventType = (typeof EVENT_TYPES)[number];

export interface AuditEvent {
  auditId: string;
  seq: number;
  type: EventType;
  stepId: string | null;
  ts: number;
  payload: Record<string, unknown>;
  payloadRef: string | null;
}

/** Events whose payload exceeds this size are moved to an artifact. */
export const EVENT_PAYLOAD_INLINE_LIMIT = 8 * 1024;
