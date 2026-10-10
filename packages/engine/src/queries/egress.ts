// Outbound records for the API: per audit or per project, newest first.
import type { Store } from '@xiezhi/store';

export interface EgressRow {
  id: string; kind: string; audit_id: string | null; step_id: string | null; conversation_id: string | null; project_id: string | null; ref: string | null;
  provider: string; model: string; endpoint: string | null; status: string; turns: number; tokens_in: number; tokens_out: number; tokens_cached: number;
  files: string; facts: string; withheld_facts: number; tools: string; started_at: number; ended_at: number; lineage_id: string | null;
}

export function egressOfAudit(store: Store, auditId: string): EgressRow[] {
  return store.all<EgressRow>(`SELECT e.*, s.lineage_id FROM egress_record e LEFT JOIN step s ON s.id = e.step_id WHERE e.audit_id = ? ORDER BY e.started_at, e.id`, auditId);
}

export function egressOfProject(store: Store, projectId: string, limit = 2000): EgressRow[] {
  return store.all<EgressRow>(`SELECT e.*, s.lineage_id FROM egress_record e LEFT JOIN step s ON s.id = e.step_id WHERE e.project_id = ? ORDER BY e.started_at DESC, e.id LIMIT ?`, projectId, limit);
}
