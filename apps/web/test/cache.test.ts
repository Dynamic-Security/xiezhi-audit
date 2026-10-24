// Web event → cache logic. The mirrors of the contracts tables are compile-checked;
// here they are also compared at run time, and the web phase rule is compared with the server's.
import { describe, expect, it } from 'vitest';
import {
  AUDIT_STATUSES, EVENT_CACHE_HANDLING, PHASE_OF_KIND, STEP_STATUSES, TRAJECTORY_GROUPS, TRAJECTORY_NOISE, derivePhase as serverPhase,
  type AuditDetailDto, type EventDto, type StepDto,
} from '@xiezhi/contracts';
import { GROUPS, HANDLING, NOISE, appendTrajectory, derivePhase, matchesTrajectory, needsRefetch, patchAudit, patchSteps } from '../src/shared/stream/cache';

const ev = (seq: number, type: string, payload: Record<string, unknown> = {}, stepId: string | null = null): EventDto =>
  ({ seq, type: type as EventDto['type'], stepId, ts: `2026-09-27T00:00:${String(seq).padStart(2, '0')}.000Z`, payload });

const step = (id: string, kind: string, status: StepDto['status'], extra: Partial<StepDto> = {}): StepDto => ({
  id, seq: 0, kind, lineage: null, status, attempt: 1, maxAttempts: 3, model: 'gw/m1', tokensIn: 0, tokensOut: 0, costMicros: null,
  errorClass: null, errorSummary: null, startedAt: null, endedAt: null, ...extra,
});

function audit(extra: Partial<AuditDetailDto> = {}): AuditDetailDto {
  return {
    id: 'aud_1', projectId: 'prj_1', projectName: 'p', title: 't', scene: 'full', mode: 'single', status: 'queued', phase: 'queued',
    partialReasons: [], errorClass: null, origin: 'ui', createdAt: '2026-09-27T00:00:00.000Z', startedAt: null, endedAt: null,
    budget: { effective: { tokens: 1000, durationMs: 60_000, costMicros: null }, consumed: { tokens: 0, durationMs: 0, costMicros: 0 } },
    repos: [], findingCount: 0, openQuestions: 0, strategyHash: 'h', gate: null, lastEventSeq: 10, exports: { md: false, json: false, sarif: false },
    steps: [step('s_plan', 'plan', 'succeeded'), step('s_triage', 'triage', 'pending'), step('s_hunt', 'hunt', 'pending')],
    ...extra,
  } as AuditDetailDto;
}

describe('contract mirrors', () => {
  it('equal the contracts tables', () => {
    expect(HANDLING).toEqual(EVENT_CACHE_HANDLING);
    expect(GROUPS).toEqual(TRAJECTORY_GROUPS);
    expect(NOISE).toEqual(TRAJECTORY_NOISE);
  });

  it('derive the same phase as the server for every status and step state', () => {
    const kinds = [...Object.keys(PHASE_OF_KIND), 'unknown_kind'];
    for (const status of AUDIT_STATUSES) {
      for (const kind of kinds) {
        for (const st of STEP_STATUSES) {
          const steps = [{ kind: 'plan', status: 'succeeded' as const }, { kind, status: st }, { kind: 'report', status: 'pending' as const }];
          expect(derivePhase(status, steps), `${status}/${kind}/${st}`).toBe(serverPhase(status, steps));
        }
      }
    }
  });
});

describe('patchAudit', () => {
  it('applies status, step and budget events in place of a refetch', () => {
    let a = audit();
    a = patchAudit(a, ev(11, 'audit.status_changed', { from: 'queued', to: 'running' }))!;
    expect([a.status, a.startedAt, a.phase, a.lastEventSeq]).toEqual(['running', '2026-09-27T00:00:11.000Z', 'analyzing', 11]);
    a = patchAudit(a, ev(12, 'step.status_changed', { kind: 'hunt', from: 'pending', to: 'running', attempt: 2 }, 's_hunt'))!;
    expect(a.steps[2]).toMatchObject({ status: 'running', attempt: 2, startedAt: '2026-09-27T00:00:12.000Z' });
    a = patchAudit(a, ev(13, 'budget.charged', { tokens: 120, cost_micros: 5, consumed: 620, effective: 1000 }, 's_hunt'))!;
    expect(a.budget.consumed).toEqual({ tokens: 620, durationMs: 0, costMicros: 5 });
    a = patchAudit(a, ev(14, 'step.status_changed', { kind: 'hunt', from: 'running', to: 'succeeded', attempt: 2, tokens_in: 400, tokens_out: 220, cost_micros: 5 }, 's_hunt'))!;
    expect(a.steps[2]).toMatchObject({ status: 'succeeded', tokensIn: 400, tokensOut: 220, costMicros: 5, endedAt: '2026-09-27T00:00:14.000Z' });
    a = patchAudit(a, ev(15, 'budget.topped_up', { delta: { tokens: 500 }, effective: { tokens: 1500, durationMs: 60_000, costMicros: null } }))!;
    expect(a.budget.effective).toEqual({ tokens: 1500, durationMs: 60_000, costMicros: null });
    a = patchAudit(a, ev(16, 'audit.status_changed', { from: 'running', to: 'partial', partial_reasons: ['BUDGET_EXHAUSTED'] }))!;
    expect([a.status, a.phase, a.endedAt, a.partialReasons]).toEqual(['partial', 'done', '2026-09-27T00:00:16.000Z', ['BUDGET_EXHAUSTED']]);
  });

  it('is idempotent by seq and asks for a refetch when a step is unknown', () => {
    const a = audit({ lastEventSeq: 20 });
    expect(patchAudit(a, ev(20, 'audit.status_changed', { to: 'failed' }))).toBe(a);
    expect(patchAudit(a, ev(21, 'step.status_changed', { to: 'running' }, 's_new'))).toBeNull();
    expect(patchSteps(a.steps, ev(21, 'step.status_changed', { to: 'running' }, 's_new'))).toBeNull();
  });

  it('flags events whose effects the payload does not carry', () => {
    expect(needsRefetch(ev(1, 'gate.evaluated'))).toBe(true);
    expect(needsRefetch(ev(1, 'audit.status_changed', { to: 'completed' }))).toBe(true);
    expect(needsRefetch(ev(1, 'audit.status_changed', { to: 'running' }))).toBe(false);
    expect(needsRefetch(ev(1, 'step.status_changed', { to: 'failed' }))).toBe(true);
    expect(needsRefetch(ev(1, 'budget.charged'))).toBe(false);
  });
});

describe('trajectory append', () => {
  const page = { items: [ev(5, 'file.read', { path: 'a.java' })], nextAfter: 5, hasMore: false };

  it('matches the server filter: groups, hidden bookkeeping, text search', () => {
    expect(matchesTrajectory({ types: [], q: '' }, ev(6, 'budget.charged'))).toBe(false);
    expect(matchesTrajectory({ types: [], q: '' }, ev(6, 'tool.called'))).toBe(true);
    expect(matchesTrajectory({ types: ['read'], q: '' }, ev(6, 'tool.called'))).toBe(false);
    expect(matchesTrajectory({ types: ['budget'], q: '' }, ev(6, 'budget.exhausted'))).toBe(true);
    expect(matchesTrajectory({ types: ['read'], q: 'ORDERDAO' }, ev(6, 'file.read', { path: 'dao/OrderDao.java' }))).toBe(true);
    expect(matchesTrajectory({ types: ['read'], q: 'nope' }, ev(6, 'file.read', { path: 'dao/OrderDao.java' }))).toBe(false);
  });

  it('appends new matching events once; leaves truncated pages alone', () => {
    const next = appendTrajectory(page, { types: [], q: '' }, ev(6, 'tool.called'));
    expect(next.items.map((e) => e.seq)).toEqual([5, 6]);
    expect(next.nextAfter).toBe(6);
    expect(appendTrajectory(next, { types: [], q: '' }, ev(6, 'tool.called'))).toBe(next);
    expect(appendTrajectory(page, { types: ['read'], q: '' }, ev(7, 'tool.called'))).toBe(page);
    const truncated = { ...page, hasMore: true };
    expect(appendTrajectory(truncated, { types: [], q: '' }, ev(8, 'tool.called'))).toBe(truncated);
  });
});
