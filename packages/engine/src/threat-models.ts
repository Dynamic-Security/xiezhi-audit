// Requirement threat models: a project's threat model built from any number of input sources (uploaded
// document, online document read through a connector, text), and the risks a person triages. Generation
// and the audit reference build on the rows kept here; this file holds the changes people make.
import { AppError, newId, THREAT_RISK_STATUSES, THREAT_SOURCE_MAX_BYTES, type ThreatRiskStatus, type ThreatSourceKind } from '@xiezhi/contracts';
import { detectInjection } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import { getProject } from './services.js';

export interface ThreatModelRow {
  id: string; project_id: string; title: string; status: string; clarification_ref: string | null; report_ref: string | null;
  clarified_at: number | null; model: string | null; tokens_in: number; tokens_out: number; cost_micros: number | null;
  error: string | null; generated_at: number | null; sources_updated_at: number | null; next_source_no: number; next_risk_no: number;
  created_at: number; updated_at: number;
}
export interface ThreatSourceRow {
  id: string; threat_model_id: string; seq: number; ord: number; kind: ThreatSourceKind; title: string; note: string | null;
  connector_id: string | null; doc_ref: string | null; content_ref: string | null; content_hash: string | null; bytes: number;
  fetch_status: 'pending' | 'ok' | 'failed' | null; fetch_error: string | null; fetched_at: number | null;
  injection: string; injection_ack: number; created_at: number; updated_at: number;
}
export interface ThreatRiskRow {
  id: string; threat_model_id: string; no: number; category: string; level: 'high' | 'medium' | 'low' | null; statement: string;
  impact: string | null; mitigation: string | null; features: string; sources: string; status: ThreatRiskStatus; reason: string | null;
  decided_by: string | null; decided_at: number | null; stale: number; history: string; created_at: number; updated_at: number;
}
export interface RiskHistoryEntry { at: number; actor: string; from: ThreatRiskStatus; to: ThreatRiskStatus; reason: string | null }

const TITLE_MAX = 200;
const NOTE_MAX = 1000;
const DOC_REF_MAX = 2000;

const invalid = (hint: string) => new AppError('COMMON_VALIDATION', hint);

function text(value: string | undefined, field: string, max: number, required = true): string | null {
  const v = value?.trim() ?? '';
  if (!v) {
    if (required) throw invalid(`${field} is required`);
    return null;
  }
  if (v.length > max) throw invalid(`${field} is longer than ${max} characters`);
  return v;
}

export function getThreatModelRow(store: Store, id: string): ThreatModelRow {
  const row = store.get<ThreatModelRow>('SELECT * FROM threat_model WHERE id = ?', id);
  if (!row) throw new AppError('THREAT_MODEL_NOT_FOUND', id);
  return row;
}

/** A threat model whose sources and risks may change now: not while a generation runs. */
function editable(store: Store, id: string): ThreatModelRow {
  const row = getThreatModelRow(store, id);
  if (row.status === 'generating') throw new AppError('THREAT_MODEL_BUSY', id);
  return row;
}

function getSource(store: Store, id: string): ThreatSourceRow {
  const row = store.get<ThreatSourceRow>('SELECT * FROM threat_model_source WHERE id = ?', id);
  if (!row) throw new AppError('THREAT_SOURCE_NOT_FOUND', id);
  return row;
}

const touchSources = (store: Store, threatModelId: string) =>
  store.update('threat_model', { id: threatModelId }, { sources_updated_at: Date.now() });

export function createThreatModel(store: Store, projectId: string, input: { title: string }): ThreatModelRow {
  const project = getProject(store, projectId);
  const id = newId('threatModel');
  store.insert('threat_model', { id, project_id: project.id, title: text(input.title, 'title', TITLE_MAX), status: 'draft' });
  return getThreatModelRow(store, id);
}

/** Rename, or mark the clarification as confirmed by a person (`clarified`) / not confirmed. */
export function updateThreatModel(store: Store, id: string, patch: { title?: string; clarified?: boolean }): ThreatModelRow {
  const row = getThreatModelRow(store, id);
  const set: Record<string, unknown> = {};
  if (patch.title !== undefined) set.title = text(patch.title, 'title', TITLE_MAX);
  if (patch.clarified !== undefined) {
    if (patch.clarified && !row.clarification_ref) throw invalid('the threat model has no clarification yet');
    set.clarified_at = patch.clarified ? (row.clarified_at ?? Date.now()) : null;
  }
  if (Object.keys(set).length) store.update('threat_model', { id }, set);
  return getThreatModelRow(store, id);
}

/** Sources and risks go with it; what audits froze stays in their artifacts. */
export function deleteThreatModel(store: Store, id: string): void {
  editable(store, id);
  store.db.run('DELETE FROM threat_model WHERE id = ?', id);
}

// ---- sources ------------------------------------------------------------------------------------------------

export type AddThreatSourceInput =
  | { kind: 'upload'; title: string; content: string; note?: string }
  | { kind: 'text'; title?: string; text: string; note?: string }
  | { kind: 'online'; title: string; connectorId: string; docRef: string; note?: string };

/** Text kept for a source: within the size limit, not binary. */
function sourceContent(store: Store, content: string): { content_ref: string; content_hash: string; bytes: number; injection: unknown[] } {
  if (!content.trim()) throw invalid('the source is empty');
  if (content.includes('\0')) throw invalid('the source is not text (Markdown or plain text only)');
  const bytes = Buffer.byteLength(content, 'utf8');
  if (bytes > THREAT_SOURCE_MAX_BYTES) throw new AppError('UPLOAD_TOO_LARGE', `${bytes} bytes; one source holds at most ${THREAT_SOURCE_MAX_BYTES}`);
  const ref = store.artifacts.put(content, 'text/markdown');
  return { content_ref: ref, content_hash: ref, bytes, injection: detectInjection(content) };
}

function onlineTarget(store: Store, connectorId: string, docRef: string): { connector_id: string; doc_ref: string } {
  if (!store.get('SELECT 1 FROM connector WHERE id = ?', connectorId)) throw invalid(`unknown connector ${connectorId}`);
  return { connector_id: connectorId, doc_ref: text(docRef, 'docRef', DOC_REF_MAX)! };
}

/** Append one source (S-number and position at the end). The number of sources is not limited. */
export function addThreatSource(store: Store, threatModelId: string, input: AddThreatSourceInput): ThreatSourceRow {
  const id = newId('threatSource');
  store.tx(() => {
    const tm = editable(store, threatModelId);
    const ord = (store.get<{ n: number | null }>('SELECT MAX(ord) AS n FROM threat_model_source WHERE threat_model_id = ?', tm.id)?.n ?? 0) + 1;
    const note = text(input.note, 'note', NOTE_MAX, false);
    const base = { id, threat_model_id: tm.id, seq: tm.next_source_no, ord, kind: input.kind, note };
    if (input.kind === 'online') {
      store.insert('threat_model_source', { ...base, title: text(input.title, 'title', TITLE_MAX), ...onlineTarget(store, input.connectorId, input.docRef), fetch_status: 'pending' });
    } else {
      const content = input.kind === 'upload' ? input.content : input.text;
      const title = input.kind === 'upload' ? text(input.title, 'title', TITLE_MAX) : (text(input.title, 'title', TITLE_MAX, false) ?? `补充描述 ${tm.next_source_no}`);
      store.insert('threat_model_source', { ...base, title, ...sourceContent(store, content) });
    }
    store.update('threat_model', { id: tm.id }, { next_source_no: tm.next_source_no + 1, sources_updated_at: Date.now() });
  });
  return getSource(store, id);
}

/**
 * Change a source's title or note; a text source's text; an online source's connector or document (its fetched copy
 * is dropped and it is read again at the next generation). An uploaded document is replaced by deleting and adding.
 */
export function updateThreatSource(store: Store, sourceId: string, patch: { title?: string; note?: string | null; text?: string; connectorId?: string; docRef?: string }): ThreatSourceRow {
  const src = getSource(store, sourceId);
  editable(store, src.threat_model_id);
  const set: Record<string, unknown> = {};
  if (patch.title !== undefined) set.title = text(patch.title, 'title', TITLE_MAX);
  if (patch.note !== undefined) set.note = text(patch.note ?? undefined, 'note', NOTE_MAX, false);
  if (patch.text !== undefined) {
    if (src.kind !== 'text') throw invalid('only a text source has editable text');
    Object.assign(set, sourceContent(store, patch.text), { injection_ack: 0 });
  }
  if (patch.connectorId !== undefined || patch.docRef !== undefined) {
    if (src.kind !== 'online') throw invalid('only an online source has a connector and a document');
    Object.assign(set, onlineTarget(store, patch.connectorId ?? src.connector_id ?? '', patch.docRef ?? src.doc_ref ?? ''), {
      content_ref: null, content_hash: null, bytes: 0, fetch_status: 'pending', fetch_error: null, fetched_at: null, injection: [], injection_ack: 0,
    });
  }
  if (Object.keys(set).length) {
    store.tx(() => {
      store.update('threat_model_source', { id: src.id }, set);
      if (patch.text !== undefined || set.doc_ref !== undefined) touchSources(store, src.threat_model_id);
    });
  }
  return getSource(store, src.id);
}

/** New display order: `ids` must be exactly the threat model's sources. S-numbers do not change. */
export function reorderThreatSources(store: Store, threatModelId: string, ids: string[]): ThreatSourceRow[] {
  editable(store, threatModelId);
  const current = store.all<{ id: string }>('SELECT id FROM threat_model_source WHERE threat_model_id = ?', threatModelId).map((r) => r.id);
  if (ids.length !== current.length || new Set(ids).size !== ids.length || !ids.every((x) => current.includes(x))) {
    throw invalid('the order must list every source of the threat model once');
  }
  store.tx(() => ids.forEach((sid, i) => store.update('threat_model_source', { id: sid }, { ord: i + 1 })));
  return listSourceRows(store, threatModelId);
}

export function deleteThreatSource(store: Store, sourceId: string): void {
  const src = getSource(store, sourceId);
  editable(store, src.threat_model_id);
  store.tx(() => {
    store.db.run('DELETE FROM threat_model_source WHERE id = ?', src.id);
    touchSources(store, src.threat_model_id);
  });
}

/** A person read the injection signals and lets the source be used for generation. */
export function acknowledgeSourceInjection(store: Store, sourceId: string): ThreatSourceRow {
  const src = getSource(store, sourceId);
  store.update('threat_model_source', { id: src.id }, { injection_ack: 1 });
  return getSource(store, src.id);
}

export function listSourceRows(store: Store, threatModelId: string): ThreatSourceRow[] {
  return store.all<ThreatSourceRow>('SELECT * FROM threat_model_source WHERE threat_model_id = ? ORDER BY ord, seq', threatModelId);
}

// ---- risk triage --------------------------------------------------------------------------------------------

export interface RiskDecision { status: ThreatRiskStatus; reason?: string | null; actor: string }

function decide(store: Store, risk: ThreatRiskRow, d: RiskDecision): boolean {
  if (!THREAT_RISK_STATUSES.includes(d.status)) throw invalid(`unknown risk status ${String(d.status)}`);
  const reason = text(d.reason ?? undefined, 'reason', 2000, false);
  if (d.status !== 'pending' && !reason) throw new AppError('THREAT_REASON_REQUIRED', `R${risk.no}`);
  if (risk.status === d.status && (risk.reason ?? null) === reason) return false;
  const now = Date.now();
  const history = [...fromJson<RiskHistoryEntry[]>(risk.history, []), { at: now, actor: d.actor, from: risk.status, to: d.status, reason }];
  store.update('threat_risk', { id: risk.id }, { status: d.status, reason, decided_by: d.actor, decided_at: now, history });
  return true;
}

function getRisk(store: Store, id: string): ThreatRiskRow {
  const row = store.get<ThreatRiskRow>('SELECT * FROM threat_risk WHERE id = ?', id);
  if (!row) throw new AppError('THREAT_RISK_NOT_FOUND', id);
  return row;
}

/** Set one risk's state; a state other than pending needs a reason, and every change is kept in its history. */
export function setThreatRiskStatus(store: Store, riskId: string, d: RiskDecision): ThreatRiskRow {
  const risk = getRisk(store, riskId);
  editable(store, risk.threat_model_id);
  decide(store, risk, d);
  return getRisk(store, risk.id);
}

/** The same state and reason for several risks of one threat model, all or nothing. */
export function setThreatRiskStatuses(store: Store, threatModelId: string, riskIds: string[], d: RiskDecision): { id: string; changed: boolean }[] {
  editable(store, threatModelId);
  if (!riskIds.length) throw invalid('no risks selected');
  return store.tx(() => [...new Set(riskIds)].map((rid) => {
    const risk = getRisk(store, rid);
    if (risk.threat_model_id !== threatModelId) throw new AppError('THREAT_RISK_NOT_FOUND', rid);
    return { id: rid, changed: decide(store, risk, d) };
  }));
}
