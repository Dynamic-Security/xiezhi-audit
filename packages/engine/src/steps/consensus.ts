// Multi-model consensus, applied after reconcile groups the findings of all models:
// - support: the models whose findings are in the cluster;
// - a single-source finding keeps its place but drops one confidence tier and is labelled;
// - conflict: another model reviewed the same dangerous place and explicitly ruled it out (or found no
//   issue) → the finding becomes “待确认”, both sides' arguments are kept for a person to decide.
// Votes never confirm anything by themselves: they only move the confidence tier.
import { crossKeys, crossModels } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import type { AuditRuntime } from '../runtime.js';
import type { HuntOutput } from './hunt.js';

const DOWN: Record<string, string> = { high: 'medium', medium: 'low', low: 'low' };
/** A reviewed target counts as the same place when it is within this many lines of the finding's sink. */
const NEAR_LINES = 5;

interface Group { canonical: string; members: string[] }

/** `repo:path#L<line>:…` (sink candidate ids) → place; entry ids have no location. */
function targetPlace(id: string): { repo: string; path: string; line: number } | null {
  const m = /^([^:]+):(.+?)#L(\d+)/.exec(id);
  return m ? { repo: m[1]!, path: m[2]!, line: Number(m[3]) } : null;
}

export function applyConsensus(rt: AuditRuntime, groups: Group[], stepId: string): void {
  const store: Store = rt.store;
  // Findings of the crossed stages (hunt and / or verification) are counted across models.
  const crossed = crossModels(rt.strategy, 'hunt') ?? crossModels(rt.strategy, 'verify');
  if (!crossed) return;
  // Slot keys — a model chosen twice is two voters (its outputs carry `provider/model#n`).
  const configured = crossKeys(crossed);
  const outputs = store.all<{ output_ref: string }>(`SELECT output_ref FROM step WHERE audit_id = ? AND kind = 'hunt' AND status = 'succeeded' AND output_ref IS NOT NULL AND (lineage_id IS NULL OR lineage_id NOT LIKE 'LEAD-%')`, rt.auditId)
    .map((r) => store.artifacts.getJson<HuntOutput>(r.output_ref));
  // A cross model none of whose hunts succeeded (unavailable, cross review degraded) did not look at
  // anything: it is not a vote against, and with fewer than two models left there is no single-source penalty.
  const ran = new Set(outputs.map((o) => o.model).filter((m): m is string => !!m));
  const models = configured.filter((m) => ran.has(m));
  const unavailable = configured.filter((m) => !ran.has(m));
  for (const g of groups) {
    const members = g.members.map((id) => store.get<{ id: string; model: string | null; repository_id: string; location: string; confidence: string; detail_ref: string; state: string; confirmation: string }>(
      'SELECT id, model, repository_id, location, confidence, detail_ref, state, confirmation FROM finding WHERE id = ?', id)!);
    const c = members[0]!;
    if (c.state !== 'canonical') continue;
    const support = [...new Set(members.map((m) => m.model).filter((m): m is string => !!m))].sort();
    const loc = fromJson<{ repo?: string; path: string; startLine: number; endLine: number }>(c.location, { path: '', startLine: 0, endLine: 0 });
    const conflicts: { model: string; target: string; verdict: string; reason: string }[] = [];
    for (const o of outputs) {
      const model = o.model ?? null;
      if (!model || support.includes(model)) continue;
      const near = (id: string) => {
        const p = targetPlace(id);
        return !!p && p.path === loc.path && Math.abs(p.line - loc.startLine) <= NEAR_LINES;
      };
      for (const r of o.ruledOut) if (near(r.targetId)) conflicts.push({ model, target: r.targetId, verdict: 'ruled_out', reason: r.reason.slice(0, 500) });
      for (const r of o.reviewedTargets) if (r.verdict === 'no_issue' && near(r.targetId)) conflicts.push({ model, target: r.targetId, verdict: 'no_issue', reason: '该模型审查了同一危险点，结论为无问题' });
    }
    const singleSource = support.length === 1 && models.length >= 2;
    const detail = store.artifacts.getJson<Record<string, unknown>>(c.detail_ref);
    const consensus = { models, support, singleSource, conflicts, unavailable };
    const patch: Record<string, unknown> = { detail_ref: store.artifacts.putJson({ ...detail, consensus }) };
    if (singleSource) patch.confidence = DOWN[c.confidence] ?? c.confidence;
    if (conflicts.length) patch.confirmation = 'pending';
    store.update('finding', { id: c.id }, patch);
    rt.event('judgement.made', { kind: 'consensus', finding_id: c.id, support: support.length, of: models.length, single_source: singleSource, conflicts: conflicts.length, ...(unavailable.length ? { unavailable } : {}) }, stepId);
  }
}
