// Read queries on requirement threat models for the API and the CLI; the SQL lives here.
import { THREAT_RISK_STATUSES, type ThreatModelDto, type ThreatModelSummaryDto, type ThreatRiskCounts, type ThreatRiskDto, type ThreatSourceDto } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { listSourceRows, type RiskHistoryEntry, type ThreatModelRow, type ThreatRiskRow, type ThreatSourceRow } from '../threat-models.js';

const iso = (ms: number | null | undefined): string | null => (ms ? new Date(ms).toISOString() : null);
const isoReq = (ms: number): string => new Date(ms).toISOString();

export function threatSourceDto(r: ThreatSourceRow): ThreatSourceDto {
  return {
    id: r.id, threatModelId: r.threat_model_id, no: r.seq, ord: r.ord, kind: r.kind, title: r.title, note: r.note,
    connectorId: r.connector_id, docRef: r.doc_ref, bytes: r.bytes, contentHash: r.content_hash,
    fetchStatus: r.fetch_status, fetchError: r.fetch_error, fetchedAt: iso(r.fetched_at),
    injection: fromJson<ThreatSourceDto['injection']>(r.injection, []), injectionAck: r.injection_ack === 1,
    createdAt: isoReq(r.created_at), updatedAt: isoReq(r.updated_at),
  };
}

export function threatRiskDto(r: ThreatRiskRow, store?: Store): ThreatRiskDto {
  return {
    id: r.id, threatModelId: r.threat_model_id, no: r.no, code: `R${r.no}`, category: r.category, level: r.level,
    statement: r.statement, impact: r.impact, mitigation: r.mitigation, features: fromJson<string[]>(r.features, []),
    sources: fromJson<number[]>(r.sources, []), status: r.status, reason: r.reason, decidedBy: r.decided_by, decidedAt: iso(r.decided_at),
    stale: r.stale === 1,
    history: fromJson<RiskHistoryEntry[]>(r.history, []).map((h) => ({ at: isoReq(h.at), actor: h.actor, from: h.from, to: h.to, reason: h.reason })),
    createdAt: isoReq(r.created_at), updatedAt: isoReq(r.updated_at),
    verifications: store ? store.all<{ audit_id: string; title: string; status: string; attempts: string; finding_id: string | null; verified_at: number | null }>(
      `SELECT h.audit_id, a.title, h.status, h.attempts, h.finding_id, h.verified_at FROM hypothesis h JOIN audit a ON a.id = h.audit_id
       WHERE h.threat_risk_id = ? ORDER BY h.created_at DESC LIMIT 10`, r.id)
      .map((h) => ({ auditId: h.audit_id, auditTitle: h.title, status: h.status, reason: h.attempts || null, findingId: h.finding_id, verifiedAt: iso(h.verified_at) })) : [],
    vulnerabilities: store ? store.all<{ id: string; display_no: number; title: string; confirm_status: string; handling_status: string }>(
      `SELECT id, display_no, title, confirm_status, handling_status FROM vulnerability WHERE json_extract(threat_risk, '$.riskId') = ? ORDER BY display_no`, r.id)
      .map((v) => ({ id: v.id, displayNo: v.display_no, title: v.title, confirmStatus: v.confirm_status, handlingStatus: v.handling_status })) : [],
  };
}

function riskCounts(store: Store, threatModelId: string): ThreatRiskCounts {
  const counts = Object.fromEntries(THREAT_RISK_STATUSES.map((s) => [s, 0])) as ThreatRiskCounts;
  for (const r of store.all<{ status: keyof ThreatRiskCounts; n: number }>('SELECT status, COUNT(*) AS n FROM threat_risk WHERE threat_model_id = ? GROUP BY status', threatModelId)) counts[r.status] = r.n;
  return counts;
}

function summary(store: Store, r: ThreatModelRow): ThreatModelSummaryDto {
  return {
    id: r.id, projectId: r.project_id, title: r.title, status: r.status as ThreatModelSummaryDto['status'],
    sourceCount: store.get<{ n: number }>('SELECT COUNT(*) AS n FROM threat_model_source WHERE threat_model_id = ?', r.id)!.n,
    riskCounts: riskCounts(store, r.id), generatedAt: iso(r.generated_at),
    sourcesChanged: r.generated_at != null && (r.sources_updated_at ?? 0) > r.generated_at,
    createdAt: isoReq(r.created_at), updatedAt: isoReq(r.updated_at),
  };
}

/** A project's threat models, newest first. */
export function listThreatModels(store: Store, projectId: string): ThreatModelSummaryDto[] {
  return store.all<ThreatModelRow>('SELECT * FROM threat_model WHERE project_id = ? ORDER BY created_at DESC, id DESC', projectId).map((r) => summary(store, r));
}

export function threatModelDetail(store: Store, id: string): ThreatModelDto | undefined {
  const r = store.get<ThreatModelRow>('SELECT * FROM threat_model WHERE id = ?', id);
  if (!r) return undefined;
  return {
    ...summary(store, r),
    clarification: r.clarification_ref ? store.artifacts.getText(r.clarification_ref) : null, clarifiedAt: iso(r.clarified_at),
    model: r.model, tokensIn: r.tokens_in, tokensOut: r.tokens_out, costMicros: r.cost_micros, error: r.error,
    sources: listSourceRows(store, r.id).map(threatSourceDto),
    risks: store.all<ThreatRiskRow>('SELECT * FROM threat_risk WHERE threat_model_id = ? ORDER BY no', r.id).map((x) => threatRiskDto(x, store)),
    syncs: store.all<{ connector_id: string; name: string; external_id: string; external_url: string | null; updated_at: number }>(
      `SELECT s.connector_id, c.name, s.external_id, s.external_url, s.updated_at FROM sync_record s JOIN connector c ON c.id = s.connector_id
       WHERE s.local_kind = 'threat_model' AND s.local_id = ? ORDER BY s.updated_at DESC`, r.id)
      .map((x) => ({ connectorId: x.connector_id, connectorName: x.name, externalId: x.external_id, externalUrl: x.external_url, updatedAt: isoReq(x.updated_at) })),
  };
}

/** The text of a source (uploaded, typed, or the copy fetched from an online document); null when there is none yet. */
export function threatSourceText(store: Store, sourceId: string): string | null {
  const r = store.get<{ content_ref: string | null }>('SELECT content_ref FROM threat_model_source WHERE id = ?', sourceId);
  return r?.content_ref ? store.artifacts.getText(r.content_ref) : null;
}
