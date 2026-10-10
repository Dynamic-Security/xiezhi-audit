// Stage telemetry of a run: per budget stage how many steps ran, how long they took,
// what they produced, and what the agent sessions of the stage saw — prompt sizes, peak context, compactions and how
// much of what was pushed into the prompt the model actually used. Records without telemetry (older runs) only
// contribute step counts.
import type { RunRecord, SessionRec } from './record.js';

export interface StageRow {
  steps: number;
  failed: number;
  /** Sum of step durations (steps of a stage run in parallel, so this is model work, not wall time). */
  step_ms: number;
  longest_ms: number;
  findings: number;
  sessions: number;
  task_sessions: number;
  /** Peak context of the stage's sessions (tokens): median and maximum. */
  peak_context_median: number | null;
  peak_context_max: number | null;
  compactions: number;
  /** Mean characters per system-prompt section and of the task prompt over the stage's main sessions. */
  prompt_chars: Record<string, number>;
}

export interface PushRow { kind: string; pushed: number; referenced: number; rate: number | null }

export interface StagesSection {
  /** Audits whose records carry session telemetry. */
  audits_with_telemetry: number;
  by_stage: Record<string, StageRow>;
  /** Push usage over all sessions, by kind of pushed item. */
  push: PushRow[];
  /** Obligations: units concluded / units tracked (coverage items), over audits with coverage. */
  obligations: { tracked: number; concluded: number; rate: number | null };
}

function median(xs: number[]): number | null {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m]! : Math.round((s[m - 1]! + s[m]!) / 2);
}

export function stagesSection(recs: RunRecord[]): StagesSection {
  const rows = new Map<string, StageRow & { peaks: number[]; promptN: number; promptSum: Record<string, number> }>();
  const push = new Map<string, { pushed: number; referenced: number }>();
  let withTelemetry = 0, tracked = 0, concluded = 0;
  const row = (k: string) => rows.get(k) ?? rows.set(k, {
    steps: 0, failed: 0, step_ms: 0, longest_ms: 0, findings: 0, sessions: 0, task_sessions: 0,
    peak_context_median: null, peak_context_max: null, compactions: 0, prompt_chars: {}, peaks: [], promptN: 0, promptSum: {},
  }).get(k)!;
  for (const r of recs) {
    for (const a of r.audits) {
      const stageOf = new Map<number, string>();
      for (const s of a.steps) {
        const k = s.stage ?? s.kind;
        stageOf.set(s.seq, k);
        const x = row(k);
        x.steps++;
        if (s.status === 'failed') x.failed++;
        const ms = s.started_at != null && s.ended_at != null ? Math.max(0, s.ended_at - s.started_at) : 0;
        x.step_ms += ms;
        x.longest_ms = Math.max(x.longest_ms, ms);
        x.findings += s.findings ?? 0;
      }
      if (a.sessions?.length) withTelemetry++;
      for (const se of a.sessions ?? []) addSession(row(se.step_seq !== null ? stageOf.get(se.step_seq) ?? 'other' : 'other'), se, push);
      if (a.coverage) {
        tracked += a.coverage.entry.total + a.coverage.sink.total;
        concluded += a.coverage.entry.reviewed + a.coverage.sink.reviewed;
      }
    }
  }
  const by_stage: Record<string, StageRow> = {};
  for (const [k, x] of [...rows].sort((a, b) => a[0].localeCompare(b[0]))) {
    const { peaks, promptN, promptSum, ...rest } = x;
    by_stage[k] = {
      ...rest,
      peak_context_median: median(peaks), peak_context_max: peaks.length ? Math.max(...peaks) : null,
      prompt_chars: Object.fromEntries(Object.entries(promptSum).map(([s, v]) => [s, Math.round(v / Math.max(1, promptN))])),
    };
  }
  return {
    audits_with_telemetry: withTelemetry,
    by_stage,
    push: [...push].sort((a, b) => a[0].localeCompare(b[0])).map(([kind, v]) => ({ kind, ...v, rate: v.pushed ? v.referenced / v.pushed : null })),
    obligations: { tracked, concluded, rate: tracked ? concluded / tracked : null },
  };
}

function addSession(x: StageRow & { peaks: number[]; promptN: number; promptSum: Record<string, number> }, se: SessionRec, push: Map<string, { pushed: number; referenced: number }>): void {
  x.sessions++;
  if (se.role === 'task') x.task_sessions++;
  x.peaks.push(se.peak_context);
  x.compactions += se.compactions;
  if (se.role === 'main' && se.prompt) {
    x.promptN++;
    for (const [k, v] of Object.entries(se.prompt.system)) x.promptSum[k] = (x.promptSum[k] ?? 0) + v;
    x.promptSum.task = (x.promptSum.task ?? 0) + se.prompt.task + (se.prompt.untrusted ?? 0);
    x.promptSum.tool_schema = (x.promptSum.tool_schema ?? 0) + se.prompt.tool_schema;
  }
  for (const p of se.pushed) {
    const v = push.get(p.kind) ?? push.set(p.kind, { pushed: 0, referenced: 0 }).get(p.kind)!;
    v.pushed += p.n;
    v.referenced += p.referenced;
  }
}
