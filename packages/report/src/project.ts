// Project-level report model: one entry per active
// vulnerability of the project, across audits. The vulnerability supplies the review state
// (confirmation, handling, severity, lifecycle, sources); its most recent canonical finding supplies
// the location, fingerprint and the four detail layers of the latest analysis. Same renderers and
// the same determinism rule as the audit report: fixed ordering, no clock, no LLM.
import type { Severity } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { compareFindings, REPORT_SCHEMA_VERSION, STATIC_AUDIT_NOTE, type CodeLoc, type FindingDetail, type ReportFilter, type ReportFinding, type ReportModel, type ReportRepo, withVerification } from './model.js';

interface LatestFinding {
  audit_id: string; audit_title: string; ended_at: number | null; id: string; display_no: number | null; repository_id: string; location: string;
  fp_sink: string | null; detail_ref: string; challenge_ref: string | null;
}

export function buildProjectReportModel(store: Store, projectId: string, filter: Omit<ReportFilter, 'trajectory'> = {}): ReportModel {
  const project = store.get<{ id: string; name: string }>('SELECT id, name FROM project WHERE id = ?', projectId);
  if (!project) throw new Error(`project ${projectId} not found`);
  const selected = filter.vulnIds ? new Set(filter.vulnIds) : null;
  const vulns = store.all<Record<string, any>>(`SELECT * FROM vulnerability WHERE project_id = ? AND status = 'active' ORDER BY display_no`, projectId)
    .filter((v) => (!selected || selected.has(v.id)) && (filter.includePending !== false || v.confirm_status !== 'pending'));
  const repoRows = new Map(store.all<{ id: string; name: string; role: string; source_uri: string }>('SELECT id, name, role, source_uri FROM repository WHERE project_id = ?', projectId).map((r) => [r.id, r]));
  const snapOf = (auditId: string, repoId: string) => store.get<{ root_hash: string; resolved_commit: string | null; requested_ref: string | null; is_worktree: number; role_in_audit: string }>(
    `SELECT s.root_hash, s.resolved_commit, s.requested_ref, s.is_worktree, ar.role_in_audit FROM audit_repository ar JOIN snapshot s ON s.id = ar.snapshot_id
     WHERE ar.audit_id = ? AND ar.repository_id = ?`, auditId, repoId);

  // Newest audit per repository among the findings used: the version table and the SARIF base of that repository.
  const newest = new Map<string, { auditId: string; at: number }>();
  const audits = new Map<string, { id: string; title: string; endedAt: number | null }>();
  const findings: ReportFinding[] = vulns.map((v) => {
    // Merged vulnerabilities are read through their target.
    const f = store.get<LatestFinding>(
      `SELECT o.audit_id, a.title AS audit_title, a.ended_at, f.id, f.display_no, f.repository_id, f.location, f.fp_sink, f.detail_ref, f.challenge_ref
       FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id JOIN audit a ON a.id = o.audit_id
       WHERE (o.vulnerability_id = ? OR o.vulnerability_id IN (SELECT id FROM vulnerability WHERE merged_into_id = ? AND status = 'merged')) AND f.state = 'canonical'
       ORDER BY o.created_at DESC, o.rowid DESC LIMIT 1`, v.id, v.id);
    const detail = store.artifacts.getJson<FindingDetail>(f?.detail_ref ?? v.detail_ref);
    if (f?.challenge_ref) detail.challenge = store.artifacts.getJson(f.challenge_ref);
    if (f) {
      const ext = store.all<{ path: string; verified: number; note: string | null }>(`SELECT path, verified, note FROM evidence WHERE owner_kind = 'finding' AND owner_id = ? AND kind = 'connector' ORDER BY ord`, f.id);
      if (ext.length) detail.externalEvidence = ext.map((x) => ({ source: x.path.replace(/^connector:/, ''), authoritative: x.verified === 1, note: x.note }));
    }
    const repoName = repoRows.get(v.repository_id)?.name ?? '';
    const sinkEv = f ? null : store.get<{ path: string | null; start_line: number | null; end_line: number | null }>(
      `SELECT path, start_line, end_line FROM evidence WHERE owner_kind = 'vulnerability' AND owner_id = ? ORDER BY ord LIMIT 1`, v.id);
    const loc = f ? fromJson<CodeLoc>(f.location, { repo: repoName, path: '', startLine: 1, endLine: 1 })
      : { repo: repoName, path: sinkEv?.path ?? '', startLine: sinkEv?.start_line ?? 1, endLine: sinkEv?.end_line ?? sinkEv?.start_line ?? 1 };
    let rootHash: string | null = null;
    if (f) {
      audits.set(f.audit_id, { id: f.audit_id, title: f.audit_title, endedAt: f.ended_at });
      rootHash = snapOf(f.audit_id, v.repository_id)?.root_hash ?? null;
      const at = f.ended_at ?? 0;
      const cur = newest.get(v.repository_id);
      if (!cur || at > cur.at || (at === cur.at && f.audit_id > cur.auditId)) newest.set(v.repository_id, { auditId: f.audit_id, at });
    }
    const fingerprint = f?.fp_sink ?? store.get<{ fp: string }>('SELECT fp FROM vuln_fingerprint WHERE vulnerability_id = ? AND active = 1 ORDER BY created_at, rowid LIMIT 1', v.id)?.fp ?? null;
    return {
      displayNo: v.display_no, vulnId: v.id, vulnDisplayNo: v.display_no, title: v.title, category: v.category, cwe: v.cwe,
      severity: v.severity as Severity, severityOriginal: v.severity_original ?? null, confidence: v.confidence, confirmStatus: v.confirm_status,
      handlingStatus: v.handling_status, handlingReason: v.handling_reason ?? null, lifecycle: v.lifecycle, sources: fromJson<string[]>(v.sources, []),
      repo: repoName, location: { ...loc, repo: repoName || loc.repo }, sinkSymbol: v.sink_symbol ?? null, sinkApi: v.sink_api ?? null,
      entries: store.all<{ entry_key: string }>(`SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ? AND state = 'active' ORDER BY entry_key`, v.id).map((e) => e.entry_key),
      rootCause: v.root_cause ?? '', fingerprint, pendingKind: v.pending_kind ?? null, detail, ...withVerification(store, v.id),
      origin: { auditId: f?.audit_id ?? null, auditTitle: f?.audit_title ?? null, findingNo: f?.display_no ?? null, rootHash },
    };
  }).sort(compareFindings);

  const repositories: ReportRepo[] = [...newest.entries()].map(([repoId, n]) => {
    const r = repoRows.get(repoId)!;
    const s = snapOf(n.auditId, repoId);
    return {
      id: repoId, name: r.name, role: r.role, roleInAudit: s?.role_in_audit ?? 'target', locator: r.source_uri, rootHash: s?.root_hash ?? '',
      commit: s?.resolved_commit ?? null, ref: s?.requested_ref ?? null, worktree: !!s?.is_worktree,
    };
  }).sort((a, b) => a.name.localeCompare(b.name));
  const auditList = [...audits.values()].sort((a, b) => (a.endedAt ?? 0) - (b.endedAt ?? 0) || a.id.localeCompare(b.id));
  const ended = auditList.map((a) => a.endedAt).filter((x): x is number => x !== null);
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    audit: {
      // The project stands in for the audit header; no run-level status, strategy or usage applies.
      id: project.id, title: project.name, scene: 'project', mode: 'project', status: 'completed', partialReasons: [], strategyHash: null,
      startedAt: null, endedAt: ended.length ? Math.max(...ended) : null, usage: { tokens: 0, durationMs: 0, costMicros: null }, executionNote: STATIC_AUDIT_NOTE,
    },
    project,
    repositories,
    findings,
    insufficient: [],
    coverage: null,
    knowledge: [],
    injectionNotices: [],
    excludedControlFiles: [],
    scope: { kind: 'project', vulns: findings.length, audits: auditList },
    ...(selected || filter.includePending === false ? { selection: { vulns: selected ? selected.size : null, includePending: filter.includePending !== false } } : {}),
  };
}
