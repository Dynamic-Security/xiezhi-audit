// Read queries on risk hunts, connectors, conversations and architecture imports for the API and the CLI:
// the applications shape responses; the SQL lives here.
import { revisionCardProgress } from '../vulns.js';
import type { Store } from '@xiezhi/store';

// ---- risk hunts ----

/** Risk hunts, newest first (raw rows). */
export function listHuntRows<T = Record<string, unknown>>(store: Store, limit = 200): T[] {
  return store.all<T>('SELECT * FROM risk_hunt ORDER BY created_at DESC LIMIT ?', limit);
}

/** The audits a risk hunt started. */
export function huntAuditIds(store: Store, huntId: string): string[] {
  return store.all<{ audit_id: string }>('SELECT DISTINCT audit_id FROM risk_hunt_target WHERE risk_hunt_id = ? AND audit_id IS NOT NULL ORDER BY audit_id', huntId).map((r) => r.audit_id);
}

export function huntTargetPendingCondition(store: Store, targetId: string): string | null {
  return store.get<{ pending_condition: string | null }>('SELECT pending_condition FROM risk_hunt_target WHERE id = ?', targetId)!.pending_condition;
}

export interface OwnedEvidenceRow { kind: string; path: string | null; start_line: number | null; end_line: number | null; note: string | null; verified: number; snapshot_id: string | null; repo: string | null }

/** Evidence of an owner (a finding, a hunt target, …) with the repository of its snapshot. */
export function evidenceWithRepo(store: Store, ownerKind: string, ownerId: string): OwnedEvidenceRow[] {
  return store.all<OwnedEvidenceRow>(
    `SELECT e.kind, e.path, e.start_line, e.end_line, e.note, e.verified, e.snapshot_id, r.name AS repo FROM evidence e LEFT JOIN snapshot s ON s.id = e.snapshot_id
     LEFT JOIN repository r ON r.id = s.repository_id WHERE e.owner_kind = ? AND e.owner_id = ? ORDER BY e.ord`, ownerKind, ownerId);
}

export interface HuntHitRow {
  id: string; project_id: string; project_name: string; repo_name: string; title: string; severity: string; category: string; confidence: string; location: string; detail_ref: string;
  promoted_vulnerability_id: string | null;
}

/** Canonical findings of one audit of a risk hunt, with project and repository names. */
export function huntHitRows(store: Store, auditId: string): HuntHitRow[] {
  return store.all<HuntHitRow>(
    `SELECT f.id, a.project_id, p.name AS project_name, r.name AS repo_name, f.title, f.severity, f.category, f.confidence, f.location, f.detail_ref, f.promoted_vulnerability_id
     FROM finding f JOIN audit a ON a.id = f.audit_id JOIN project p ON p.id = a.project_id JOIN repository r ON r.id = f.repository_id
     WHERE f.audit_id = ? AND f.state = 'canonical' ORDER BY f.display_no`, auditId);
}

export interface LocalHitRow { id: string; project_name: string; repo_name: string; title: string; severity: string; location: string; promoted: number | null }

/** Canonical findings of all audits of a risk hunt (CLI). */
export function huntLocalHits(store: Store, huntId: string): LocalHitRow[] {
  return store.all<LocalHitRow>(
    `SELECT f.id, p.name AS project_name, r.name AS repo_name, f.title, f.severity, f.location, v.display_no AS promoted FROM finding f
     JOIN audit a ON a.id = f.audit_id JOIN project p ON p.id = a.project_id JOIN repository r ON r.id = f.repository_id LEFT JOIN vulnerability v ON v.id = f.promoted_vulnerability_id
     WHERE f.state = 'canonical' AND f.audit_id IN (SELECT audit_id FROM risk_hunt_target WHERE risk_hunt_id = ?) ORDER BY p.name, f.display_no`, huntId);
}

// ---- connectors ----

/** A connector (raw row), or undefined. */
export function findConnector<T = Record<string, unknown>>(store: Store, id: string): T | undefined {
  return store.get<T>('SELECT * FROM connector WHERE id = ?', id);
}

/** Connectors by name (raw rows). */
export function listConnectorRows<T = Record<string, unknown>>(store: Store): T[] {
  return store.all<T>('SELECT * FROM connector ORDER BY name');
}

export interface ConnectorCallRow { id: string; operation: string; kind: string; status: string; duration_ms: number; response_bytes: number; error: string | null; audit_id: string | null; created_at: number }

/** The latest calls of a connector. */
export function connectorCalls(store: Store, connectorId: string, limit = 50): ConnectorCallRow[] {
  return store.all<ConnectorCallRow>('SELECT * FROM connector_call WHERE connector_id = ? ORDER BY created_at DESC LIMIT ?', connectorId, limit);
}

// ---- conversations and architecture imports ----

export function conversationTitle(store: Store, conversationId: string): string | null | undefined {
  return store.get<{ title: string | null }>('SELECT title FROM conversation WHERE id = ?', conversationId)?.title;
}

/** Cards waiting for the user; a revision card in conflict with a change made elsewhere cannot apply and is not counted. */
export function pendingCardCount(store: Store, conversationId: string): number {
  return store.all<{ tool: string | null; target_id: string | null; data: string }>(
    `SELECT tool, target_id, data FROM conversation_card WHERE conversation_id = ? AND state = 'pending'`, conversationId)
    .filter((c) => c.tool !== 'propose_revision' || !revisionCardProgress(store, c).conflict.length).length;
}

/** The latest architecture imports of a project (raw rows). */
export function architectureImports<T = Record<string, unknown>>(store: Store, projectId: string, limit = 20): T[] {
  return store.all<T>('SELECT * FROM architecture_import WHERE project_id = ? ORDER BY created_at DESC LIMIT ?', projectId, limit);
}
