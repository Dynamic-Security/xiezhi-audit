// Read queries on vulnerabilities, findings, revisions and hypotheses for the API:
// the applications shape responses; the SQL lives here.
import type { Store } from '@xiezhi/store';

/** A vulnerability (raw row). */
export function getVulnerability<T = Record<string, unknown>>(store: Store, id: string): T | undefined {
  return store.get<T>('SELECT * FROM vulnerability WHERE id = ?', id);
}

/** Active vulnerabilities of a project (raw rows). */
export function activeVulnerabilities<T = Record<string, unknown>>(store: Store, projectId: string): T[] {
  return store.all<T>(`SELECT * FROM vulnerability WHERE project_id = ? AND status = 'active'`, projectId);
}

/** Display fields of a vulnerability (CLI list, reverification items). */
export function vulnHeader(store: Store, id: string): { display_no: number; title: string; severity: string; category: string; confirm_status: string; lifecycle: string } | undefined {
  return store.get('SELECT display_no, title, severity, category, confirm_status, lifecycle FROM vulnerability WHERE id = ?', id);
}

export function vulnDisplayNo(store: Store, id: string): number | undefined {
  return store.get<{ display_no: number }>('SELECT display_no FROM vulnerability WHERE id = ?', id)?.display_no;
}

/** Vulnerabilities of a project for the CLI list. */
export function projectVulnList(store: Store, projectId: string): { display_no: number; severity: string; title: string; confirm_status: string; lifecycle: string }[] {
  return store.all('SELECT display_no, severity, title, confirm_status, lifecycle FROM vulnerability WHERE project_id = ? AND status = \'active\' ORDER BY display_no', projectId);
}

/** The vulnerability a finding of an audit was matched to. */
export function findingVulnId(store: Store, auditId: string, findingId: string): string | undefined {
  return store.get<{ vulnerability_id: string }>('SELECT vulnerability_id FROM vuln_occurrence WHERE audit_id = ? AND finding_id = ?', auditId, findingId)?.vulnerability_id;
}

export function activeEntryCount(store: Store, vulnId: string): number {
  return store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM vuln_entry WHERE vulnerability_id = ? AND state = 'active'`, vulnId)!.n;
}

/** How the latest audit that covered the vulnerability saw it (`found`, `not_found_unverified`, …). */
export function latestPresence(store: Store, vulnId: string): string | undefined {
  return store.get<{ presence: string }>('SELECT presence FROM vuln_occurrence WHERE vulnerability_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1', vulnId)?.presence;
}

export interface SuspectedMatchRow {
  occurrence_id: string; audit_id: string; match_basis: string; created_at: number; audit_title: string; finding_id: string; display_no: number | null; title: string; location: string;
  sink_symbol: string | null; sink_api: string | null; entry_keys: string | null; root_cause: string | null;
}

/** Pending "suspected same" links of a vulnerability with the linked finding. */
export function suspectedMatchRows(store: Store, vulnId: string): SuspectedMatchRow[] {
  return store.all<SuspectedMatchRow>(
    `SELECT o.id AS occurrence_id, o.audit_id, o.match_basis, o.created_at, a.title AS audit_title, f.id AS finding_id, f.display_no, f.title, f.location,
            f.sink_symbol, f.sink_api, f.entry_keys, f.root_cause
     FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id JOIN audit a ON a.id = o.audit_id
     WHERE o.vulnerability_id = ? AND o.match_level = 'suspected' ORDER BY o.created_at`, vulnId);
}

/** The finding the vulnerability was first created from. */
export function firstFinding(store: Store, vulnId: string): { challenge_ref: string | null; audit_id: string } | undefined {
  return store.get<{ challenge_ref: string | null; audit_id: string }>(
    `SELECT f.challenge_ref, f.audit_id FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id WHERE o.vulnerability_id = ? ORDER BY o.created_at LIMIT 1`, vulnId);
}

export interface EvidenceRow { kind: string; snapshot_id: string | null; path: string | null; start_line: number | null; end_line: number | null; verified: number; note: string | null }

export function vulnEvidence(store: Store, vulnId: string): EvidenceRow[] {
  return store.all<EvidenceRow>(`SELECT kind, snapshot_id, path, start_line, end_line, verified, note FROM evidence WHERE owner_kind = 'vulnerability' AND owner_id = ? ORDER BY ord`, vulnId);
}

export function snapshotRepoName(store: Store, snapshotId: string): string | undefined {
  return store.get<{ name: string }>('SELECT r.name FROM snapshot s JOIN repository r ON r.id = s.repository_id WHERE s.id = ?', snapshotId)?.name;
}

/** The latest audit that used a snapshot. */
export function snapshotAudit(store: Store, snapshotId: string): string | undefined {
  return store.get<{ audit_id: string }>('SELECT audit_id FROM audit_repository WHERE snapshot_id = ? ORDER BY created_at DESC LIMIT 1', snapshotId)?.audit_id;
}

export function vulnEntries(store: Store, vulnId: string): { entry_key: string; state: string }[] {
  return store.all<{ entry_key: string; state: string }>('SELECT entry_key, state FROM vuln_entry WHERE vulnerability_id = ? ORDER BY entry_key', vulnId);
}

export function vulnFingerprints(store: Store, vulnId: string): { fp: string; kind: string; active: number }[] {
  return store.all<{ fp: string; kind: string; active: number }>('SELECT fp, kind, active FROM vuln_fingerprint WHERE vulnerability_id = ? ORDER BY created_at, rowid', vulnId);
}

/** Vulnerabilities merged into this one. */
export function mergedFrom(store: Store, vulnId: string): { id: string; display_no: number; title: string }[] {
  return store.all<{ id: string; display_no: number; title: string }>(`SELECT id, display_no, title FROM vulnerability WHERE merged_into_id = ? AND status = 'merged' ORDER BY display_no`, vulnId);
}

export interface ProposalRow { id: string; dimension: string; to_value: string | null; reason: string | null; audit_id: string | null; created_at: number }

/** Revisions proposed on a vulnerability and not decided yet. */
export function proposals(store: Store, vulnId: string): ProposalRow[] {
  return store.all<ProposalRow>(`SELECT id, dimension, to_value, reason, audit_id, created_at FROM revision WHERE vulnerability_id = ? AND state = 'proposed' ORDER BY seq`, vulnId);
}

/** Finding details of the latest occurrences, newest first. */
export function recentDetailRefs(store: Store, vulnId: string, limit = 20): string[] {
  return store.all<{ detail_ref: string }>(
    `SELECT f.detail_ref FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id WHERE o.vulnerability_id = ? ORDER BY o.created_at DESC, o.rowid DESC LIMIT ?`, vulnId, limit).map((r) => r.detail_ref);
}

/** The latest identity change (merge / split) of a vulnerability, as stored. */
export function latestIdentityChange(store: Store, vulnId: string): string | null | undefined {
  return store.get<{ to_value: string | null }>(`SELECT to_value FROM revision WHERE vulnerability_id = ? AND dimension = 'identity' ORDER BY seq DESC LIMIT 1`, vulnId)?.to_value;
}

/** Revisions of a vulnerability, newest first (raw rows). */
export function vulnRevisions<T = Record<string, unknown>>(store: Store, vulnId: string): T[] {
  return store.all<T>('SELECT * FROM revision WHERE vulnerability_id = ? ORDER BY seq DESC', vulnId);
}

export interface TrajectoryLinkRow { audit_id: string; finding_id: string; step_id: string; display_no: number | null; presence: string; title: string }

/** Where the vulnerability was seen; merged vulnerabilities are read through their target. */
export function trajectoryLinks(store: Store, vulnId: string): TrajectoryLinkRow[] {
  return store.all<TrajectoryLinkRow>(
    `SELECT o.audit_id, o.finding_id, f.step_id, f.display_no, o.presence, a.title FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id
     JOIN audit a ON a.id = o.audit_id WHERE o.vulnerability_id = ? OR o.vulnerability_id IN (SELECT id FROM vulnerability WHERE merged_into_id = ? AND status = 'merged')
     ORDER BY o.created_at`, vulnId, vulnId);
}

/** The finding that proves a confirmed hypothesis, followed through a merge, and its vulnerability. */
export function provingFinding(store: Store, findingId: string): { state: string | null; vulnerabilityId: string | null } {
  const id = store.get<{ t: string }>('SELECT target_finding_id AS t FROM finding_merge WHERE source_finding_id = ?', findingId)?.t ?? findingId;
  return {
    state: store.get<{ state: string }>('SELECT state FROM finding WHERE id = ?', id)?.state ?? null,
    vulnerabilityId: store.get<{ v: string }>('SELECT vulnerability_id AS v FROM vuln_occurrence WHERE finding_id = ? LIMIT 1', id)?.v ?? null,
  };
}

export function auditExists(store: Store, auditId: string): boolean {
  return !!store.get('SELECT 1 FROM audit WHERE id = ?', auditId);
}

export function getHypothesis<T = Record<string, unknown>>(store: Store, id: string): T | undefined {
  return store.get<T>('SELECT * FROM hypothesis WHERE id = ?', id);
}
