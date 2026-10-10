// External SAST / SCA results: SARIF 2.1.0 (Semgrep, CodeQL, others) imported into an audit become
// `external` obligations — one per result — that the audit must settle: the engine marks results outside the snapshot
// as not applicable and duplicates of the audit's own findings as covered; a model triages the rest (false positive with
// a reason, or true positive), and the true positives are investigated by a hunt that writes proper findings (merged
// with the audit's own by the reconcile step). No data-flow layer of our own.
import { AppError, normalizeCwe, resolveCategory, type VulnCategory } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { getAudit } from './state.js';
import { addObligation } from './obligations.js';

export interface ExternalResult {
  tool: string; ruleId: string; level: string; message: string; uri: string; line: number; endLine: number;
  cwe: string | null; category: VulnCategory;
}

/** At most this many results per import (a scanner can report thousands; the triage is per result). */
export const MAX_EXTERNAL_RESULTS = 500;
const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);

function cweOf(...tags: unknown[]): string | null {
  for (const t of tags.flat()) {
    const m = /CWE[-_ ]?(\d+)/i.exec(String(t ?? ''));
    if (m) return normalizeCwe(`CWE-${m[1]}`);
  }
  return null;
}

/** Normalise a SARIF artifact URI to a path relative to the repository root. */
export function sarifPath(uri: string): string {
  return decodeURIComponent(uri.replace(/^file:\/\/(localhost)?/i, '')).replace(/^\.?\//, '').replace(/\\/g, '/');
}

/** Parse SARIF 2.1.0 text into results (all runs). */
export function parseSarif(text: string): ExternalResult[] {
  let doc: { runs?: unknown[] };
  try { doc = JSON.parse(text) as { runs?: unknown[] }; } catch (e) { throw new AppError('COMMON_VALIDATION', `not JSON: ${(e as Error).message.slice(0, 200)}`); }
  if (!Array.isArray(doc.runs)) throw new AppError('COMMON_VALIDATION', 'not a SARIF log: no "runs"');
  const out: ExternalResult[] = [];
  for (const run of doc.runs as Record<string, any>[]) {
    const driver = run?.tool?.driver ?? {};
    const tool = String(driver.name ?? 'external');
    const rules = new Map<string, Record<string, any>>();
    for (const r of [...(driver.rules ?? []), ...((run?.tool?.extensions ?? []).flatMap((x: Record<string, any>) => x.rules ?? []))]) if (r?.id) rules.set(String(r.id), r);
    for (const res of (run.results ?? []) as Record<string, any>[]) {
      const ruleId = String(res.ruleId ?? res.rule?.id ?? 'unknown');
      const rule = rules.get(ruleId) ?? (typeof res.ruleIndex === 'number' ? driver.rules?.[res.ruleIndex] : undefined) ?? {};
      const loc = res.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri;
      if (typeof uri !== 'string') continue;
      const line = Number(loc?.region?.startLine ?? 1);
      const cwe = cweOf(rule.properties?.tags ?? [], rule.properties?.cwe ?? [], res.properties?.tags ?? [], rule.relationships?.map((x: Record<string, any>) => x?.target?.id) ?? []);
      const text = String(res.message?.text ?? rule.shortDescription?.text ?? rule.fullDescription?.text ?? ruleId);
      out.push({
        tool, ruleId, level: String(res.level ?? rule.defaultConfiguration?.level ?? 'warning'), message: text.slice(0, 1000), uri: sarifPath(uri),
        line: Number.isFinite(line) && line > 0 ? line : 1, endLine: Number(loc?.region?.endLine ?? line) || line, cwe, category: resolveCategory(null, cwe),
      });
    }
  }
  return out;
}

export const externalKey = (r: ExternalResult) => `${r.tool}:${r.ruleId}:${r.uri}:${r.line}`;

/** Import SARIF into an audit that has not finished: one `external` obligation per result (kept when re-imported). */
export function importSarif(store: Store, auditId: string, text: string): { results: number; added: number; skipped: number } {
  const a = getAudit(store, auditId);
  if (TERMINAL.has(a.status)) throw new AppError('AUDIT_TERMINAL', `audit is ${a.status}; import external results before it finishes`);
  const all = parseSarif(text);
  const results = all.slice(0, MAX_EXTERNAL_RESULTS);
  const before = store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM obligation WHERE audit_id = ? AND kind = 'external'`, auditId)!.n;
  store.tx(() => {
    for (const r of results) {
      addObligation({ store, auditId }, {
        kind: 'external', itemKey: externalKey(r), source: 'external', title: `[${r.tool} ${r.ruleId}] ${r.message}`.slice(0, 500), category: r.category,
        path: r.uri, startLine: r.line, detail: { ...r },
      });
    }
  });
  const after = store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM obligation WHERE audit_id = ? AND kind = 'external'`, auditId)!.n;
  store.appendEvent(auditId, 'judgement.made', { kind: 'external_import', tools: [...new Set(results.map((r) => r.tool))], results: all.length, added: after - before, truncated: all.length - results.length });
  return { results: all.length, added: after - before, skipped: all.length - results.length };
}
