// Step identity in run records and the per-stage telemetry of a score.
import { describe, expect, it } from 'vitest';
import { stepRec } from '../src/runner.js';
import { stagesSection } from '../src/stages.js';
import type { AuditRec, RunRecord } from '../src/record.js';

const row = (o: Partial<Parameters<typeof stepRec>[0]>): Parameters<typeof stepRec>[0] => ({
  id: 's', seq: 1, kind: 'hunt', status: 'succeeded', attempt: 1, error_class: null, lineage_id: null, input: '{}', model: 'gw/m1', started_at: 1000, ended_at: 61_000, findings: 0, ...o,
});

describe('step identity', () => {
  it('names the budget stage, the expert domain and round, and the review tier', () => {
    expect(stepRec(row({ lineage_id: 'DOM-D2-R3', input: JSON.stringify({ domain: { id: 'd2', name: '授权' }, round: 3 }) }))).toMatchObject({ stage: 'hunt', domain: '授权', round: 3, lineage: 'DOM-D2-R3' });
    expect(stepRec(row({ kind: 'hunt', lineage_id: 'GAP-B4' })).stage).toBe('gap');
    expect(stepRec(row({ kind: 'challenge', input: JSON.stringify({ findingId: 'f', light: true }) }))).toMatchObject({ stage: 'review', tier: 'light' });
    expect(stepRec(row({ kind: 'challenge', input: JSON.stringify({ findingId: 'f', vote: true }) })).tier).toBe('vote');
    expect(stepRec(row({ kind: 'challenge', input: '{"findingId":"f"}' })).tier).toBe('full');
    expect(stepRec(row({ input: 'not json' })).domain).toBeUndefined();
  });
});

function audit(o: Partial<AuditRec>): AuditRec {
  return {
    audit_id: 'a', role: 'base', version: 'base', scene: 'full', status: 'completed', partial_reasons: [], error_class: null, budget_declined: false, wall_ms: 0, model_ms: 0,
    steps: [], attempts: [], findings: [], snapshot_hashes: {}, reverify: [], ...o,
  };
}
const rec = (audits: AuditRec[]): RunRecord => ({
  format: 'xiezhi-eval-run/1', sample_id: 's', project: 'p', kind: 'real', language: 'go', partition: 'dev', scene: 'full', dataset: 'd', repeat: 1,
  status: 'completed', error: null, wall_ms: 0, audits, risk: null, integrity: [],
});

describe('stage telemetry of a score', () => {
  it('sums steps, times and findings per stage and aggregates sessions and push usage', () => {
    const a = audit({
      steps: [
        { seq: 1, kind: 'hunt', status: 'succeeded', attempts: 1, error_class: null, stage: 'hunt', started_at: 0, ended_at: 120_000, findings: 2 },
        { seq: 2, kind: 'hunt', status: 'failed', attempts: 2, error_class: 'STEP_TIMEOUT', stage: 'hunt', started_at: 0, ended_at: 60_000, findings: 0 },
        { seq: 3, kind: 'challenge', status: 'succeeded', attempts: 1, error_class: null, stage: 'review', started_at: 0, ended_at: 30_000, findings: 0 },
      ],
      sessions: [
        { step_seq: 1, role: 'main', status: 'completed', turns: 10, prompt: { system: { role: 400, cognitive: 9000 }, task: 3000, tools: 18, tool_schema: 20_000 }, peak_context: 80_000, compactions: 1, pushed: [{ kind: 'lead', n: 60, referenced: 6 }] },
        { step_seq: 1, role: 'task', status: 'completed', turns: 5, peak_context: 20_000, compactions: 0, pushed: [] },
        { step_seq: 2, role: 'main', status: 'max_turns', turns: 80, prompt: { system: { role: 400, cognitive: 1000 }, task: 1000, tools: 18, tool_schema: 20_000 }, peak_context: 120_000, compactions: 2, pushed: [{ kind: 'lead', n: 40, referenced: 14 }] },
      ],
      coverage: { entry: { total: 10, reviewed: 8 }, sink: { total: 10, reviewed: 6 }, sinks: [], concluded: 14, concluded_read: 14 },
    });
    const old = audit({ steps: [{ seq: 1, kind: 'triage', status: 'succeeded', attempts: 1, error_class: null }] });
    const st = stagesSection([rec([a]), rec([old])]);
    expect(st.audits_with_telemetry).toBe(1);
    expect(st.by_stage.hunt).toMatchObject({ steps: 2, failed: 1, step_ms: 180_000, longest_ms: 120_000, findings: 2, sessions: 3, task_sessions: 1, compactions: 3, peak_context_max: 120_000, peak_context_median: 80_000 });
    expect(st.by_stage.hunt!.prompt_chars).toEqual({ role: 400, cognitive: 5000, task: 2000, tool_schema: 20_000 });
    expect(st.by_stage.review).toMatchObject({ steps: 1, sessions: 0, peak_context_median: null });
    // A record from older versions still counts its steps under the step kind.
    expect(st.by_stage.triage).toMatchObject({ steps: 1, step_ms: 0 });
    expect(st.push).toEqual([{ kind: 'lead', pushed: 100, referenced: 20, rate: 0.2 }]);
    expect(st.obligations).toEqual({ tracked: 20, concluded: 14, rate: 0.7 });
  });
});
