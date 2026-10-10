// Run output records (one per sample × repeat) and run metadata. The scorer reads only these files
// plus the benchmark; it never opens the product database.

export const RUN_FORMAT = 'xiezhi-eval-run/1';
export const META_FORMAT = 'xiezhi-eval-meta/1';

/**
 * Whether a stored format tag is `current` or the tag it had before the product was renamed: run
 * directories and caches written as `code-audit-eval-*` are still read.
 */
export function isFormat(actual: unknown, current: string): boolean {
  return actual === current || actual === current.replace(/^xiezhi-/, 'code-audit-');
}

export interface FindingRec {
  id: string;
  display_no: number | null;
  title: string;
  category: string;
  cwe: string | null;
  severity: string;
  confidence: number;
  repo: string;
  path: string;
  start_line: number;
  end_line: number;
  entries: string[];
  /** Product status: confirmed, pending (待确认), or dismissed by the product itself (false_positive). */
  status: 'confirmed' | 'pending' | 'dismissed';
  vulnerability_id: string | null;
  match_level: string | null;
  pending: { missing: string[]; holds_if: string[]; refuted_if: string[] } | null;
  /**
   * G3 traceability: the sink and every chain / evidence range verified against the snapshot;
   * the finding's submission is in the trajectory; a decision source is recorded. Absent in older runs.
   */
  trace?: { evidence: boolean; trajectory: boolean; source: boolean };
  /** The finding's service-boundary class when the product reports one; absent = `own`. */
  boundary?: 'own' | 'upstream' | 'cross_service';
}

export interface AttemptRec {
  step: string;
  seq: number;
  provider: string | null;
  model: string | null;
  attempt: number;
  outcome: string | null;
  error_class: string | null;
  tokens_in: number;
  tokens_out: number;
  tokens_cached: number;
  /** Priced from config.pricing (per million tokens); null = unknown price (never 0). */
  cost_micros: number | null;
  currency: string | null;
  duration_ms: number;
}

export interface StepRec {
  seq: number; kind: string; status: string; attempts: number; error_class: string | null;
  /** Stage telemetry (absent in older runs): lineage, budget stage, start / end (epoch ms), findings the step submitted. */
  lineage?: string | null;
  stage?: string | null;
  model?: string | null;
  started_at?: number | null;
  ended_at?: number | null;
  findings?: number;
  /** Domain experts: domain name and round; reviews: `full` / `light` / `vote`. */
  domain?: string;
  round?: number;
  tier?: string;
}

/** One agent session (main or `task` sub-agent) of a step, from its `session.ended` event. */
export interface SessionRec {
  step_seq: number | null;
  role: 'main' | 'task';
  status: string;
  turns: number;
  /** Characters per system-prompt section, the task prompt, audited content after it, tool count and schema size. */
  prompt?: { system: Record<string, number>; task: number; untrusted?: number; tools: number; tool_schema: number };
  /** Largest context of one model request (input + cache read + cache write tokens). */
  peak_context: number;
  compactions: number;
  /** Items pushed into the prompt by kind and how many the model referenced in a tool call. */
  pushed: { kind: string; n: number; referenced: number }[];
}

/** An engine judgement (`judgement.made`) with its scalar fields. */
export interface JudgementRec { step_seq: number | null; kind: string; fields: Record<string, string | number | boolean | null> }

export interface AuditRec {
  audit_id: string;
  /** base: first audit of the sample; version: a later version (identity); reverify; hunt; incremental: the change audited incrementally. */
  role: 'base' | 'version' | 'reverify' | 'hunt' | 'incremental';
  version: string;
  scene: string;
  status: string;
  partial_reasons: string[];
  error_class: string | null;
  budget_declined: boolean;
  /** The stages whose quota stopped the audit when the budget wait was declined; absent = the total. */
  budget_stopped_stages?: string[];
  wall_ms: number;
  model_ms: number;
  steps: StepRec[];
  attempts: AttemptRec[];
  findings: FindingRec[];
  snapshot_hashes: Record<string, string | null>;
  reverify: { vulnerability_id: string; verdict: string | null; lifecycle_after: string | null }[];
  /**
   * Coverage: counts, the tree-sitter sink list (for the labeled-sink hit rate) and how many
   * concluded targets were actually read (numerator accuracy). Absent when coverage comparison was off.
   */
  coverage?: { entry: { total: number; reviewed: number }; sink: { total: number; reviewed: number }; sinks: { repo: string; path: string; line: number }[]; concluded: number; concluded_read: number };
  /** Hypotheses of this audit ("未排除的假设" = open; refuted kept for the record). Absent in older runs. */
  hypotheses?: { category: string; repo: string; path: string; start_line: number; end_line: number; status: string; origin?: 'hunt' | 'threat_model' }[];
  /** Agent sessions with their context telemetry; absent in older runs. */
  sessions?: SessionRec[];
  /** Engine judgements (gaps asked, candidates unanswered, fallbacks …); absent in older runs. */
  judgements?: JudgementRec[];
  /** The hash of the prompt overrides the audit ran with (`default` = the built-in prompts); absent in older runs. */
  prompts?: string;
}

export interface RiskTargetRec {
  repo: string | null;
  verdict: string | null;
  reason: string | null;
  verdict_source: string | null;
  evidence: { path: string | null; start_line: number | null; end_line: number | null; verified: boolean }[];
}

export type RunStatus = 'completed' | 'partial' | 'failed' | 'cancelled' | 'error' | 'invalid';

export interface RunRecord {
  format: typeof RUN_FORMAT;
  sample_id: string;
  project: string;
  kind: string;
  language: string;
  partition: string;
  scene: string;
  dataset: string;
  repeat: number;
  status: RunStatus;
  error: { code: string; message: string } | null;
  wall_ms: number;
  audits: AuditRec[];
  /** `basis_cost_micros`: priced from the drafting usage split (null = unknown price, never 0). */
  risk: { basis_status: string; basis_model: string | null; basis_tokens: number; basis_cost_micros?: number | null; basis_currency?: string | null; targets: RiskTargetRec[] } | null;
  /** Snapshot root hashes that differ from the manifest (sample invalid when non-empty). */
  integrity: { version: string; repo: string; expected: string; actual: string | null }[];
  /** Result cache: `hit` = reused from an earlier identical run (tokens and times are that run's). */
  cache?: { key: string; hit: boolean };
}

export interface RunMeta {
  format: typeof META_FORMAT;
  name: string | null;
  /** `commit`: revision of the benchmark repository (it is separate from the product). */
  bench: { root: string; version: string; manifest_hash: string; labels_hash: string; commit?: { revision: string | null; dirty: boolean | null } };
  partition: string;
  filter: Record<string, string[]>;
  repeats: number;
  selected: string[];
  invalid: Record<string, string[]>;
  skipped: string[];
  stopped_reason: string | null;
  /** Run records written, by status. */
  results: Record<string, number>;
  config: {
    sha256: string;
    providers: { id: string; api: string; origin: string; models: string[] }[];
    default_model: string | null;
    cheap_model: string | null;
    priced_models: string[];
  };
  strategy_override: Record<string, unknown>;
  knowledge: { dir: string | null; skills: { name: string; sha256: string }[] };
  code: { revision: string | null; dirty: boolean | null };
  pi_version: string;
  node: string;
  platform: string;
  model_mode: string;
  started_at: string;
  ended_at: string | null;
  /** Result cache; absent in older runs. */
  cache?: { dir: string | null; enabled: boolean; reason: string | null; hits: number; stored: number };
}
