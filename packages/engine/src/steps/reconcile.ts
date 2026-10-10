// reconcile: prepare → deterministic clusters (hard by fp_sink, soft by location) →
// optional semantic grouping (labels only; code owns ids) → materialize with total order.
// Loss is attributable: canonical + insufficient + merged + dropped must equal sent.
// A later round (after deep exploration) also sees the audit's canonical and insufficient findings as anchors: a new
// finding with the same root cause merges into the existing one, which keeps its number; anchors never merge with each
// other. A new finding that meets the threshold is not hidden behind an insufficient anchor: it becomes canonical and
// the insufficient finding merges into it.
// Vulnerabilities are not published here — the adversarial review runs on the
// reconciled findings first, then `publishStep` creates / matches the vulnerabilities once per audit.
import { SubmitMergeGroups } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import { fromJson } from '@xiezhi/store';
import { applyConsensus } from './consensus.js';
import type { AuditRuntime } from '../runtime.js';
import { StepError, sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { matchVulnerabilities, planMatches, type CanonicalFinding, type MatchPlan } from '../vulns.js';
import { P } from '@xiezhi/knowledge';
import { planBoundaries } from '../boundary.js';
import { projectGateways } from '../gateway.js';

interface Row {
  id: string; step_id: string; repository_id: string; category: string; severity: string; confidence_score: number; confidence: string;
  fp_sink: string | null; location: string; title: string; sink_symbol: string | null; sink_api: string | null; entry_keys: string;
  root_cause: string | null; cwe: string | null; module: string | null; detail_ref: string; confirmation: string; state: string;
}

const SEV: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

/**
 * Order of a group's members; the first represents the group (canonical). A member that meets the confidence
 * threshold comes before any that does not: the group is insufficient only when no member
 * reaches it, so a confident report is never hidden behind a more severe but uncertain one.
 */
export function canonicalOrder<R extends Pick<Row, 'id' | 'severity' | 'confidence_score'>>(
  minConf: number, evidenceCount: (id: string) => number, seq: (r: R) => number,
): (a: R, b: R) => number {
  const meets = (r: R) => (r.confidence_score >= minConf ? 1 : 0);
  return (a, b) => meets(b) - meets(a) || (SEV[b.severity] ?? 0) - (SEV[a.severity] ?? 0) || b.confidence_score - a.confidence_score
    || evidenceCount(b.id) - evidenceCount(a.id) || seq(a) - seq(b) || a.id.localeCompare(b.id);
}

/**
 * The canonical finding is picked by severity and confidence; when it says only `other` and members name the class
 * (an SSTI reported as `other` by one model and `ssti` by six), it takes the members' most common class.
 */
export function specificCategory(c: Pick<Row, 'category'>, members: Pick<Row, 'category' | 'cwe'>[]): { category?: string; cwe?: string | null } {
  if (c.category !== 'other') return {};
  const counts = new Map<string, number>();
  for (const m of members) if (m.category !== 'other') counts.set(m.category, (counts.get(m.category) ?? 0) + 1);
  const best = [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0];
  if (!best) return {};
  return { category: best, cwe: members.find((m) => m.category === best && m.cwe)?.cwe ?? null };
}

class UnionFind {
  private p = new Map<string, string>();
  /** Roots that hold an anchor (an already canonical finding): two of them are never joined. */
  private anchored = new Set<string>();
  anchor(x: string): void { this.anchored.add(this.find(x)); }
  find(x: string): string {
    if (!this.p.has(x)) this.p.set(x, x);
    const r = this.p.get(x)!;
    if (r === x) return x;
    const root = this.find(r);
    this.p.set(x, root);
    return root;
  }
  union(a: string, b: string): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra === rb || (this.anchored.has(ra) && this.anchored.has(rb))) return;
    const [root, child] = rb < ra ? [rb, ra] : [ra, rb];
    this.p.set(child, root);
    if (this.anchored.delete(child)) this.anchored.add(root);
  }
}

export interface ReconcileOutput {
  sent: number;
  groups: { canonical: string; members: string[]; method: 'deterministic' | 'semantic'; label?: string }[];
  /** New findings that joined an already canonical finding of the audit (a later round): anchor id → new member ids. */
  joined?: { canonical: string; members: string[]; method: 'deterministic' | 'semantic' }[];
  /** Insufficient findings of the audit that merge into a new canonical finding of the same root cause. */
  superseded?: { canonical: string; members: string[]; method: 'deterministic' | 'semantic' }[];
  dropped: { id: string; reason: string; detail: string }[];
  insufficient: string[];
  /** Formerly: vulnerability matching decided in reconcile. Now always empty (see PublishOutput). */
  matches: Record<string, MatchPlan>;
  /** cross-service risks kept as hints (trusted internal network), lowered ones, the trust setting used. */
  hints?: string[];
  lowered?: string[];
  trust?: string;
}

export interface PublishOutput {
  published: string[];
  /** Canonical findings whose confidence fell below minConfidence in the adversarial review. */
  demoted: string[];
  /** Vulnerability matching decided before publishing: finding id → plan. */
  matches: Record<string, MatchPlan>;
}

/**
 * Publish: the canonical findings of the audit that are not linked to a vulnerability yet become or match
 * vulnerabilities (exact → rename following → suspected judgement), after the adversarial review changed their
 * confidence and confirmation; those that fell below minConfidence become “证据不足” instead. Runs once per audit
 * (also after a coverage-gap round), so findings are never published twice.
 */
export async function publishStep(rt: AuditRuntime, ctx: AttemptContext, opts: { deterministic?: boolean } = {}): Promise<StepResult> {
  const store = rt.store;
  const rows = store.all<CanonicalFinding & { confidence_score: number }>(
    `SELECT f.* FROM finding f WHERE f.audit_id = ? AND f.state = 'canonical' AND NOT EXISTS (SELECT 1 FROM vuln_occurrence o WHERE o.finding_id = f.id) ORDER BY f.display_no`, rt.auditId);
  const above = rows.filter((f) => f.confidence_score >= rt.strategy.minConfidence);
  const demoted = rows.filter((f) => f.confidence_score < rt.strategy.minConfidence).map((f) => f.id);
  // The boundary class of each finding and what the project's internal trust does to it —
  // a cross-service risk on a trusted internal network is a hint, not a vulnerability; with the gateway as the
  // boundary it is published one severity lower. Risk hunts are not classed.
  const boundaries = rt.audit.scene === 'risk_hunt' ? null
    : planBoundaries(store, rt.audit.project_id, above as never, rt.indexes, rt.repos, projectGateways(store, rt.audit.project_id, rt.views));
  const hinted = new Set(boundaries?.hints ?? []);
  const keep = above.filter((f) => !hinted.has(f.id));
  // Risk hunt hits are not vulnerabilities until promoted: no matching.
  const plans = rt.audit.scene === 'risk_hunt' ? new Map<string, MatchPlan>() : await planMatches(rt, keep, ctx, !opts.deterministic);
  const out: PublishOutput = { published: keep.map((f) => f.id), demoted, matches: Object.fromEntries(plans), ...(boundaries ? { hints: boundaries.hints, lowered: boundaries.lowered, trust: boundaries.trust } : {}) };
  return {
    outputRef: store.artifacts.putJson(out),
    apply: () => {
      for (const id of demoted) store.update('finding', { id }, { state: 'insufficient' });
      if (demoted.length) rt.event('finding.reconciled', { demoted: demoted.length, reason: 'confidence below threshold after adversarial review' }, ctx.stepId);
      boundaries?.commit();
      if (boundaries && (boundaries.hints.length || boundaries.lowered.length)) rt.event('judgement.made', { kind: 'internal_trust', trust: boundaries.trust, hints: boundaries.hints.length, lowered: boundaries.lowered.length }, ctx.stepId);
      if (rt.audit.scene !== 'risk_hunt') {
        // Lowered findings are matched with their new severity.
        const fresh = boundaries?.lowered.length ? keep.map((f) => (boundaries.lowered.includes(f.id) ? { ...f, severity: store.get<{ severity: string }>('SELECT severity FROM finding WHERE id = ?', f.id)!.severity } : f)) : keep;
        matchVulnerabilities(rt, fresh as typeof keep, ctx.stepId, plans);
        // The vulnerability carries the class of the finding it came from.
        store.db.run(`UPDATE vulnerability SET boundary = (SELECT f.boundary FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id WHERE o.vulnerability_id = vulnerability.id AND o.audit_id = ? AND f.boundary IS NOT NULL ORDER BY o.created_at DESC LIMIT 1)
          WHERE id IN (SELECT vulnerability_id FROM vuln_occurrence WHERE audit_id = ?)`, rt.auditId, rt.auditId);
      }
    },
  };
}

/**
 * `deterministic`: the model step failed; group by fingerprint and location only, so the audit
 * still has a reconciled finding set and a report instead of failing outright.
 */
export async function reconcileStep(rt: AuditRuntime, ctx: AttemptContext, opts: { deterministic?: boolean } = {}): Promise<StepResult> {
  const store = rt.store;
  const fresh = store.all<Row>(`SELECT f.*, s.seq AS step_seq FROM finding f JOIN step s ON s.id = f.step_id WHERE f.audit_id = ? AND f.state = 'submitted' ORDER BY s.seq, f.id`, rt.auditId);
  const anchors = fresh.length ? store.all<Row>(`SELECT f.*, s.seq AS step_seq FROM finding f JOIN step s ON s.id = f.step_id WHERE f.audit_id = ? AND f.state IN ('canonical', 'insufficient') ORDER BY f.display_no`, rt.auditId) : [];
  const anchorIds = new Set(anchors.map((r) => r.id));
  const rows = [...anchors, ...fresh];
  const sent = fresh.length;
  const uf = new UnionFind();
  const loc = (r: Row) => fromJson<{ path: string; startLine: number; endLine: number }>(r.location, { path: '', startLine: 0, endLine: 0 });
  for (const r of rows) uf.find(r.id);
  for (const id of anchorIds) uf.anchor(id);
  // Hard clusters: identical sink fingerprint.
  const byFp = new Map<string, string>();
  for (const r of rows) {
    if (!r.fp_sink) continue;
    const first = byFp.get(r.fp_sink);
    if (first) uf.union(first, r.id); else byFp.set(r.fp_sink, r.id);
  }
  // Soft clusters: no fingerprint, same category/repo/file, ranges overlapping or within 5 lines.
  const soft = rows.filter((r) => !r.fp_sink);
  for (let i = 0; i < soft.length; i++) {
    for (let j = i + 1; j < soft.length; j++) {
      const a = soft[i]!, b = soft[j]!;
      const la = loc(a), lb = loc(b);
      if (a.category === b.category && a.repository_id === b.repository_id && la.path === lb.path
        && la.startLine <= lb.endLine + 5 && lb.startLine <= la.endLine + 5) uf.union(a.id, b.id);
    }
  }
  const clusters = new Map<string, Row[]>();
  const detCluster = new Map<string, string>();
  for (const r of rows) {
    const k = uf.find(r.id);
    detCluster.set(r.id, k);
    (clusters.get(k) ?? clusters.set(k, []).get(k)!).push(r);
  }

  // Optional semantic grouping over cluster representatives (labels only).
  const dropped: ReconcileOutput['dropped'] = [];
  const model = opts.deterministic ? null : rt.strategy.models.merge;
  const isAnchored = (key: string) => clusters.get(key)!.some((r) => anchorIds.has(r.id));
  const reps = [...clusters.keys()].filter((k) => !isAnchored(k)).sort();
  const anchorReps = [...clusters.keys()].filter(isAnchored).sort((a, b) => a.localeCompare(b));
  if (model && reps.length >= 1 && reps.length + anchorReps.length > 1) {
    const labels = new Map<string, string>([...reps.map((k, i) => [`L${i + 1}`, k] as const), ...anchorReps.map((k, i) => [`E${i + 1}`, k] as const)]);
    const isE = (l: string) => l.startsWith('E');
    const projection = [...labels].map(([label, key]) => {
      const r = clusters.get(key)!.find((x) => anchorIds.has(x.id)) ?? clusters.get(key)![0]!;
      const l = loc(r);
      return `${label} | ${r.category} | sink=${r.sink_symbol ?? '?'} api=${r.sink_api ?? '?'} | entries=${fromJson<string[]>(r.entry_keys, []).join(',')} | ${r.root_cause ?? ''} | ${l.path}:${l.startLine}`;
    }).join('\n');
    const submit: AuditTool = {
      name: 'submit_merge_groups', kind: 'submit', parameters: SubmitMergeGroups,
      description: P('tool.submit_merge_groups'),
      validate: (a: { groups: { labels: string[] }[]; dropped: { label: string }[] }) => {
        const seen = [...a.groups.flatMap((g) => g.labels), ...a.dropped.map((d) => d.label)];
        const issues: string[] = [];
        for (const l of seen) if (!labels.has(l)) issues.push(P('feedback.reconcile.unknown_label', { label: l }));
        for (const l of labels.keys()) {
          const n = seen.filter((x) => x === l).length;
          // Existing findings (E*) only appear when a new finding joins them.
          if (isE(l) ? n > 1 : n !== 1) issues.push(isE(l) ? P('feedback.reconcile.anchor_once', { label: l }) : P('feedback.reconcile.label_once', { label: l }));
        }
        for (const g of a.groups) if (g.labels.filter(isE).length > 1) issues.push(P('feedback.reconcile.multi_anchor', { labels: g.labels.join(',') }));
        for (const d of a.dropped) if (isE(d.label)) issues.push(P('feedback.reconcile.anchor_dropped', { label: d.label }));
        return issues;
      },
      run: () => ({ text: 'accepted' }),
    };
    const outcome = await rt.session({
      stepId: ctx.stepId, attempt: ctx.attempt, kind: 'reconcile', phase: 'reconcile', model, signal: ctx.signal, withIndex: false, submitOnly: true,
      prompt: `${P('reconcile.intro')}${anchorReps.length ? `\n\n${P('reconcile.anchors')}` : ''}\n\n${projection}`,
      submitTools: [submit], requiredSubmits: ['submit_merge_groups'], maxTurns: 6,
    });
    const err = sessionError(outcome);
    if (err) throw err; // fail-closed: never silently skip grouping
    const res = (outcome.submissions.submit_merge_groups as { groups: { labels: string[] }[]; dropped: { label: string; reason: string; detail: string }[] }[]).at(-1)!;
    for (const g of res.groups) {
      const keys = g.labels.map((l) => labels.get(l)!);
      for (const k of keys.slice(1)) uf.union(keys[0]!, k);
    }
    for (const d of res.dropped) for (const r of clusters.get(labels.get(d.label)!)!) dropped.push({ id: r.id, reason: d.reason, detail: d.detail });
  }
  const droppedIds = new Set(dropped.map((d) => d.id));
  const groupsMap = new Map<string, Row[]>();
  const joinedMap = new Map<string, { anchor: Row; members: Row[] }>();
  const supersededMap = new Map<string, Row>();
  const minConf = rt.strategy.minConfidence;
  for (const r of rows) {
    if (droppedIds.has(r.id)) continue;
    const root = uf.find(r.id);
    (groupsMap.get(root) ?? groupsMap.set(root, []).get(root)!).push(r);
  }
  for (const [root, members] of [...groupsMap]) {
    const anchor = members.find((m) => anchorIds.has(m.id));
    if (!anchor) continue;
    groupsMap.delete(root);
    const added = members.filter((m) => m !== anchor);
    if (!added.length) continue;
    // An insufficient anchor does not hide a new finding that meets the threshold — the new findings form a
    // group of their own and the anchor merges into its canonical finding.
    if (anchor.state === 'insufficient' && added.some((m) => m.confidence_score >= minConf)) {
      groupsMap.set(root, added);
      supersededMap.set(root, anchor);
    } else joinedMap.set(root, { anchor, members: added });
  }
  const joined = [...joinedMap.values()];
  const evidenceCount = (id: string) => store.get<{ n: number }>('SELECT COUNT(*) AS n FROM evidence WHERE owner_kind = ? AND owner_id = ?', 'finding', id)!.n;
  const stepSeq = (r: Row) => (r as unknown as { step_seq: number }).step_seq;
  const order = canonicalOrder(minConf, evidenceCount, stepSeq);
  const groups = [...groupsMap].map(([root, members]) => {
    const sorted = [...members].sort(order);
    return { canonical: sorted[0]!, members: sorted, superseded: supersededMap.get(root) };
  });
  groups.sort((x, y) => {
    const a = x.canonical, b = y.canonical;
    const la = loc(a), lb = loc(b);
    return (SEV[b.severity] ?? 0) - (SEV[a.severity] ?? 0) || a.category.localeCompare(b.category) || a.repository_id.localeCompare(b.repository_id)
      || la.path.localeCompare(lb.path) || la.startLine - lb.startLine || (a.fp_sink ?? '').localeCompare(b.fp_sink ?? '');
  });
  const canonicalIds = groups.filter((g) => g.canonical.confidence_score >= minConf).map((g) => g.canonical.id);
  const insufficientIds = groups.filter((g) => g.canonical.confidence_score < minConf).map((g) => g.canonical.id);
  const mergedCount = groups.reduce((n, g) => n + g.members.length - 1, 0) + joined.reduce((n, j) => n + j.members.length, 0);
  if (canonicalIds.length + insufficientIds.length + mergedCount + dropped.length !== sent) {
    rt.event('error', { error_class: 'INTERNAL', summary: 'reconcile conservation check failed', sent }, ctx.stepId);
    throw new StepError('INTERNAL', `reconcile lost findings: sent=${sent}`);
  }
  const out: ReconcileOutput = {
    matches: {},
    sent,
    groups: groups.map((g) => ({
      canonical: g.canonical.id, members: g.members.map((m) => m.id),
      // Semantic when the model joined members from more than one deterministic cluster.
      method: new Set(g.members.map((m) => detCluster.get(m.id))).size > 1 ? 'semantic' : 'deterministic',
    })),
    dropped, insufficient: insufficientIds,
    ...(joined.length ? { joined: joined.map((j) => ({
      canonical: j.anchor.id, members: j.members.map((m) => m.id),
      method: j.members.some((m) => detCluster.get(m.id) !== detCluster.get(j.anchor.id)) ? 'semantic' as const : 'deterministic' as const,
    })) } : {}),
    ...(supersededMap.size ? { superseded: groups.filter((g) => g.superseded).map((g) => ({
      canonical: g.canonical.id, members: [g.superseded!.id],
      method: detCluster.get(g.superseded!.id) !== detCluster.get(g.canonical.id) ? 'semantic' as const : 'deterministic' as const,
    })) } : {}),
  };
  const outputRef = store.artifacts.putJson(out);
  return {
    outputRef,
    apply: () => {
      // A second round (coverage-gap) continues the audit's F-numbers.
      let no = store.get<{ m: number | null }>('SELECT MAX(display_no) AS m FROM finding WHERE audit_id = ?', rt.auditId)?.m ?? 0;
      const ordered = [...groups.filter((g) => canonicalIds.includes(g.canonical.id)), ...groups.filter((g) => insufficientIds.includes(g.canonical.id))];
      for (const g of ordered) {
        const c = g.canonical;
        const entries = [...new Set([...g.members, ...(g.superseded ? [g.superseded] : [])].flatMap((m) => fromJson<string[]>(m.entry_keys, [])))].sort();
        store.update('finding', { id: c.id }, { state: canonicalIds.includes(c.id) ? 'canonical' : 'insufficient', display_no: ++no, entry_keys: entries, ...specificCategory(c, g.members) });
        for (const m of g.members.slice(1)) {
          store.update('finding', { id: m.id }, { state: 'merged' });
          const method = out.groups.find((x) => x.canonical === c.id)?.method ?? 'deterministic';
          store.insert('finding_merge', { audit_id: rt.auditId, source_finding_id: m.id, target_finding_id: c.id, method, group_label: null, reason: method === 'semantic' ? 'same root cause (model)' : 'same sink fingerprint or location' });
        }
      }
      // A later round: new findings with the root cause of an existing canonical finding join it (its F-number,
      // state and review stay; the entry points are united).
      for (const j of out.joined ?? []) {
        const a = joined.find((x) => x.anchor.id === j.canonical)!;
        const entries = [...new Set([a.anchor, ...a.members].flatMap((m) => fromJson<string[]>(m.entry_keys, [])))].sort();
        store.update('finding', { id: j.canonical }, { entry_keys: entries });
        for (const id of j.members) {
          store.update('finding', { id }, { state: 'merged' });
          store.insert('finding_merge', { audit_id: rt.auditId, source_finding_id: id, target_finding_id: j.canonical, method: j.method, group_label: null, reason: j.method === 'semantic' ? 'same root cause as an existing finding (model)' : 'same sink fingerprint or location as an existing finding' });
        }
      }
      // An insufficient finding superseded by a new canonical one of the same root cause.
      for (const s of out.superseded ?? []) {
        for (const id of s.members) {
          store.update('finding', { id }, { state: 'merged', display_no: null });
          store.insert('finding_merge', { audit_id: rt.auditId, source_finding_id: id, target_finding_id: s.canonical, method: s.method, group_label: null, reason: 'insufficient finding superseded by a new finding that meets the threshold' });
        }
      }
      for (const d of dropped) store.update('finding', { id: d.id }, { state: 'dropped', drop_reason: `${d.reason}: ${d.detail}`.slice(0, 500) });
      rt.event('finding.reconciled', { sent, canonical: canonicalIds.length, insufficient: insufficientIds.length, merged: mergedCount, dropped: dropped.length, ...(joined.length ? { joinedExisting: joined.reduce((n, j) => n + j.members.length, 0) } : {}), ...(supersededMap.size ? { supersededExisting: supersededMap.size } : {}) }, ctx.stepId);
      applyConsensus(rt, ordered.map((g) => ({ canonical: g.canonical.id, members: g.members.map((m) => m.id) })), ctx.stepId);
    },
  };
}
