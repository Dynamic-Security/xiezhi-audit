// Read queries on enterprise facts for the API: the facts of a project, the versions of one key, and the
// vulnerabilities whose findings relied on a fact version that has since changed (they should be reverified).
import type { Store } from '@xiezhi/store';
import type { FactRow } from '../facts.js';

export function listFacts(store: Store, projectId: string, f: { status?: string; topic?: string; q?: string } = {}): FactRow[] {
  const where = ['project_id = ?'];
  const args: string[] = [projectId];
  if (f.status && f.status !== 'all') { where.push('status = ?'); args.push(f.status); } else if (!f.status) where.push(`status = 'active'`);
  if (f.topic) { where.push('topic = ?'); args.push(f.topic); }
  if (f.q) { where.push('(statement LIKE ? OR fact_key LIKE ?)'); args.push(`%${f.q}%`, `%${f.q}%`); }
  return store.all<FactRow>(`SELECT * FROM fact WHERE ${where.join(' AND ')} ORDER BY topic, fact_key, version DESC`, ...args);
}

export function factVersions(store: Store, projectId: string, key: string): FactRow[] {
  return store.all<FactRow>('SELECT * FROM fact WHERE project_id = ? AND fact_key = ? ORDER BY version DESC', projectId, key);
}

export interface FactImpactRow { vulnerability_id: string; display_no: number; title: string; audit_id: string; finding_id: string; fact_id: string; version: number; stale: number }

/** Vulnerabilities whose findings rely on any version of the key; `stale` = the version they used is no longer in force. */
export function factImpact(store: Store, projectId: string, key: string): FactImpactRow[] {
  return store.all<FactImpactRow>(
    `SELECT DISTINCT o.vulnerability_id, v.display_no, v.title, r.audit_id, r.finding_id, r.fact_id, f.version, r.stale
     FROM fact_ref r JOIN fact f ON f.id = r.fact_id JOIN vuln_occurrence o ON o.finding_id = r.finding_id JOIN vulnerability v ON v.id = o.vulnerability_id
     WHERE f.project_id = ? AND f.fact_key = ? ORDER BY v.display_no`, projectId, key);
}

/** Per project: how many vulnerabilities rely on a fact version no longer in force. */
export function staleFactVulnCount(store: Store, projectId: string): number {
  return store.get<{ n: number }>(
    `SELECT COUNT(DISTINCT o.vulnerability_id) AS n FROM fact_ref r JOIN fact f ON f.id = r.fact_id JOIN vuln_occurrence o ON o.finding_id = r.finding_id
     WHERE f.project_id = ? AND r.stale = 1`, projectId)!.n;
}
