// Obligation ledger: everything an audit must reach a conclusion on, settled together. Each kind keeps
// its own state where it already had one — entry points and sinks in the coverage ledger, risk hypotheses in `hypothesis`,
// access-policy differences as the conclusion on their entry point — and checklist items and external-scanner results in
// `obligation`. The coverage states keep their meaning; this is a view over them.
import { newId, type ObligationKind, type ObligationStatus } from '@xiezhi/contracts';
import { accessChecks } from './access.js';
import type { AuditRuntime } from './runtime.js';
import { SURFACE_RULE } from './surface.js';
import { verificationTargets } from './threat.js';

/** Where an obligation came from: a structure-index rule, the model (surface / threat model), a checklist, a scanner, a person. */
export type ObligationSource = 'rule' | 'model' | 'threat_model' | 'requirement' | 'access_policy' | 'checklist' | 'external' | 'user';

export interface ObligationItem { kind: ObligationKind; id: string; source: ObligationSource; settled: boolean; title: string }

export interface ObligationSummary {
  total: number;
  settled: number;
  byKind: Partial<Record<ObligationKind, { total: number; settled: number }>>;
  bySource: Partial<Record<ObligationSource, { total: number; settled: number }>>;
  /** Open items, at most OPEN_LISTED. */
  open: { kind: ObligationKind; id: string; source: ObligationSource; title: string }[];
}

const OPEN_LISTED = 200;
const SETTLED_ROW: ReadonlySet<ObligationStatus> = new Set(['covered', 'not_applicable', 'concluded']);

type Rt = Pick<AuditRuntime, 'store' | 'auditId' | 'repos' | 'indexes' | 'audit'>;

export function obligationItems(rt: Rt): ObligationItem[] {
  const out: ObligationItem[] = [];
  const cov = rt.store.all<{ kind: 'entry' | 'sink'; target_id: string; status: string; rule_id: string | null; path: string; start_line: number }>(
    `SELECT kind, target_id, status, rule_id, path, start_line FROM coverage_item WHERE audit_id = ? AND status != 'excluded'`, rt.auditId);
  const concludedEntry = new Set(cov.filter((c) => c.kind === 'entry' && c.status === 'concluded').map((c) => c.target_id));
  for (const c of cov) out.push({ kind: c.kind, id: c.target_id, source: c.rule_id === SURFACE_RULE ? 'model' : 'rule', settled: c.status === 'concluded', title: `${c.path}:${c.start_line}` });
  for (const h of verificationTargets(rt as AuditRuntime)) {
    out.push({ kind: 'hypothesis', id: h.id, source: (h as { threat_risk_id?: string | null }).threat_risk_id ? 'requirement' : 'threat_model', settled: h.status !== 'proposed', title: h.statement.slice(0, 200) });
  }
  for (const a of accessChecks(rt)) out.push({ kind: 'access', id: a.entryId, source: 'access_policy', settled: concludedEntry.has(a.entryId), title: a.entryKey });
  for (const o of rt.store.all<{ kind: 'checklist' | 'external'; item_key: string; source: ObligationSource; status: ObligationStatus; title: string }>(
    'SELECT kind, item_key, source, status, title FROM obligation WHERE audit_id = ? ORDER BY kind, item_key', rt.auditId)) {
    out.push({ kind: o.kind, id: o.item_key, source: o.source, settled: SETTLED_ROW.has(o.status), title: o.title });
  }
  return out;
}

export function obligationSummary(rt: Rt): ObligationSummary {
  const items = obligationItems(rt);
  const byKind: ObligationSummary['byKind'] = {};
  const bySource: ObligationSummary['bySource'] = {};
  for (const i of items) {
    const k = (byKind[i.kind] ??= { total: 0, settled: 0 });
    const s = (bySource[i.source] ??= { total: 0, settled: 0 });
    k.total++; s.total++;
    if (i.settled) { k.settled++; s.settled++; }
  }
  return {
    total: items.length, settled: items.filter((i) => i.settled).length, byKind, bySource,
    open: items.filter((i) => !i.settled).slice(0, OPEN_LISTED).map(({ kind, id, source, title }) => ({ kind, id, source, title })),
  };
}

/** Add (or keep) an `obligation` row — checklist items and external-scanner results. */
export function addObligation(rt: Pick<AuditRuntime, 'store' | 'auditId'>, o: {
  kind: 'checklist' | 'external'; itemKey: string; source: ObligationSource; title: string; category?: string;
  repositoryId?: string; path?: string; startLine?: number; detail?: Record<string, unknown>;
}): void {
  rt.store.db.run(
    `INSERT OR IGNORE INTO obligation(id, audit_id, kind, item_key, source, title, category, repository_id, path, start_line, status, detail, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)`,
    newId('obligation'), rt.auditId, o.kind, o.itemKey, o.source, o.title.slice(0, 500), o.category ?? null, o.repositoryId ?? null, o.path ?? null, o.startLine ?? null,
    JSON.stringify(o.detail ?? {}), Date.now(), Date.now(),
  );
}

export function settleObligation(rt: Pick<AuditRuntime, 'store' | 'auditId'>, kind: 'checklist' | 'external', itemKey: string, status: ObligationStatus, reason: string, stepId: string | null): void {
  rt.store.db.run(`UPDATE obligation SET status = ?, reason = ?, step_id = ?, updated_at = ? WHERE audit_id = ? AND kind = ? AND item_key = ?`,
    status, reason.slice(0, 1000), stepId, Date.now(), rt.auditId, kind, itemKey);
}
