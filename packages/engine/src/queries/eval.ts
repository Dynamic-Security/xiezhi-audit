// Read queries for the evaluation harness: what one audit produced, read back for scoring.
// Moved out of apps/eval so the applications contain no SQL.
import type { Store } from '@xiezhi/store';

export interface EvalFindingRow {
  id: string; display_no: number | null; title: string; category: string; cwe: string | null; severity: string; confidence_score: number; location: string;
  entry_keys: string; confirmation: string; repo: string; vulnerability_id: string | null; match_level: string | null; confirm_status: string | null; missing_context: string | null;
}

/** Canonical findings of an audit with the vulnerability each was matched to. */
export function evalFindings(store: Store, auditId: string): EvalFindingRow[] {
  return store.all<EvalFindingRow>(`SELECT f.id, f.display_no, f.title, f.category, f.cwe, f.severity, f.confidence_score, f.location, f.entry_keys, f.confirmation, r.name AS repo,
       o.vulnerability_id, o.match_level, v.confirm_status, v.missing_context
     FROM finding f JOIN repository r ON r.id = f.repository_id
     LEFT JOIN vuln_occurrence o ON o.finding_id = f.id AND o.audit_id = f.audit_id
     LEFT JOIN vulnerability v ON v.id = o.vulnerability_id
     WHERE f.audit_id = ? AND f.state = 'canonical' ORDER BY f.display_no, f.id`, auditId);
}

/** Hypotheses of the audit. */
export function evalHypotheses(store: Store, auditId: string): { category: string; repo: string; location: string | null; status: string; origin: 'hunt' | 'threat_model' }[] {
  return store.all<{ category: string; repo: string; location: string | null; status: string; origin: 'hunt' | 'threat_model' }>(
    'SELECT h.category, r.name AS repo, h.location, h.status, h.origin FROM hypothesis h JOIN repository r ON r.id = h.repository_id WHERE h.audit_id = ? ORDER BY h.created_at, h.id', auditId);
}

/** Coverage items of the audit with the repository name. */
export function evalCoverageItems(store: Store, auditId: string): { kind: string; status: string; repo: string; path: string; start_line: number; end_line: number; repository_id: string }[] {
  return store.all<{ kind: string; status: string; repo: string; path: string; start_line: number; end_line: number; repository_id: string }>(
    `SELECT c.kind, c.status, r.name AS repo, c.path, c.start_line, c.end_line, c.repository_id FROM coverage_item c JOIN repository r ON r.id = c.repository_id WHERE c.audit_id = ?`, auditId);
}

/** Ranges the audit read, per file. */
export function readCoverage(store: Store, auditId: string): { repository_id: string; path: string; ranges: string }[] {
  return store.all<{ repository_id: string; path: string; ranges: string }>('SELECT repository_id, path, ranges FROM read_coverage WHERE audit_id = ?', auditId);
}

export function findingEvidenceFlags(store: Store, findingId: string): { kind: string; ord: number; verified: number }[] {
  return store.all<{ kind: string; ord: number; verified: number }>(`SELECT kind, ord, verified FROM evidence WHERE owner_kind = 'finding' AND owner_id = ?`, findingId);
}

export function findingSource(store: Store, findingId: string): string | null | undefined {
  return store.get<{ source: string | null }>('SELECT source FROM finding WHERE id = ?', findingId)?.source;
}

export function vulnSources(store: Store, vulnId: string): string[] {
  return JSON.parse(store.get<{ sources: string }>('SELECT sources FROM vulnerability WHERE id = ?', vulnId)?.sources ?? '[]') as string[];
}

export function evalAuditHead(store: Store, auditId: string): { scene: string; status: string; partial_reasons: string; error_class: string | null } {
  return store.get<{ scene: string; status: string; partial_reasons: string; error_class: string | null }>('SELECT scene, status, partial_reasons, error_class FROM audit WHERE id = ?', auditId)!;
}

export interface EvalStepRow {
  id: string; seq: number; kind: string; status: string; attempt: number; error_class: string | null;
  /** identity of the step for the stage telemetry. */
  lineage_id: string | null; input: string; model: string | null; started_at: number | null; ended_at: number | null; findings: number;
}

export function evalSteps(store: Store, auditId: string): EvalStepRow[] {
  return store.all<EvalStepRow>(
    `SELECT s.id, s.seq, s.kind, s.status, s.attempt, s.error_class, s.lineage_id, s.input, s.model, s.started_at, s.ended_at,
       (SELECT COUNT(*) FROM finding f WHERE f.step_id = s.id) AS findings
     FROM step s WHERE s.audit_id = ? ORDER BY s.seq`, auditId);
}

/** events of the given types with their step id (payloads moved to an artifact are read back). */
export function evalEvents(store: Store, auditId: string, types: string[]): { step_id: string | null; type: string; ts: number; payload: Record<string, unknown> }[] {
  const marks = types.map(() => '?').join(', ');
  return store.all<{ step_id: string | null; type: string; ts: number; payload: string; payload_ref: string | null }>(
    `SELECT step_id, type, ts, payload, payload_ref FROM event WHERE audit_id = ? AND type IN (${marks}) ORDER BY seq`, auditId, ...types,
  ).map((r) => ({
    step_id: r.step_id, type: r.type, ts: r.ts,
    payload: (r.payload_ref ? store.artifacts.getJson<Record<string, unknown>>(r.payload_ref) : null) ?? (JSON.parse(r.payload) as Record<string, unknown>),
  }));
}

export interface EvalAttemptRow { seq: number; kind: string; provider: string | null; model: string | null; attempt: number; outcome: string | null; error_class: string | null; tokens_in: number; tokens_out: number; tokens_cached: number; started_at: number; ended_at: number | null }

export function evalAttempts(store: Store, auditId: string): EvalAttemptRow[] {
  return store.all<EvalAttemptRow>(
    `SELECT s.seq, s.kind, s.provider, s.model, a.attempt, a.outcome, a.error_class, a.tokens_in, a.tokens_out, a.tokens_cached, a.started_at, a.ended_at
     FROM step_attempt a JOIN step s ON s.id = a.step_id WHERE s.audit_id = ? ORDER BY s.seq, a.attempt`, auditId);
}

/** The snapshot root of each repository of the audit, by repository name. */
export function snapshotHashes(store: Store, auditId: string): { name: string; root_hash: string | null }[] {
  return store.all<{ name: string; root_hash: string | null }>(
    `SELECT r.name, sn.root_hash FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id LEFT JOIN snapshot sn ON sn.id = ar.snapshot_id WHERE ar.audit_id = ? ORDER BY r.name`, auditId);
}

/** Verdicts of a reverification audit. */
export function reverifyVerdicts(store: Store, auditId: string): { vulnerability_id: string; reverify_verdict: string | null; lifecycle_after: string | null }[] {
  return store.all<{ vulnerability_id: string; reverify_verdict: string | null; lifecycle_after: string | null }>(
    'SELECT vulnerability_id, reverify_verdict, lifecycle_after FROM vuln_occurrence WHERE audit_id = ? AND reverify_verdict IS NOT NULL ORDER BY vulnerability_id', auditId);
}

/** Evidence of a risk hunt target. */
export function huntTargetEvidence(store: Store, targetId: string): { path: string | null; start_line: number | null; end_line: number | null; verified: number }[] {
  return store.all<{ path: string | null; start_line: number | null; end_line: number | null; verified: number }>(
    `SELECT path, start_line, end_line, verified FROM evidence WHERE owner_kind = 'risk_hunt_target' AND owner_id = ? ORDER BY ord`, targetId);
}

/** Active vulnerabilities of a project, by number. */
export function activeVulnIds(store: Store, projectId: string): string[] {
  return store.all<{ id: string }>(`SELECT id FROM vulnerability WHERE project_id = ? AND status = 'active' ORDER BY display_no`, projectId).map((x) => x.id);
}

/** the hash of the prompt overrides the audit froze (`default` without overrides or for older audits). */
export function evalPromptsHash(store: Store, auditId: string): string {
  const ref = store.get<{ knowledge_ref: string | null }>('SELECT knowledge_ref FROM audit WHERE id = ?', auditId)?.knowledge_ref;
  return (ref ? store.artifacts.getJson<{ prompts?: { hash: string } }>(ref).prompts?.hash : undefined) ?? 'default';
}
