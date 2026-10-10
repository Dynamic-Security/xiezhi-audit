// Independent scorer. Matching: a finding hits a label when its category is equivalent
// (categories.ts, incl. CWE) and its location lies in the label's sink function (locate.ts); a label
// is hit at most once, extra hits are duplicates. Findings on fixed / negative samples are false
// positives; unlabelled findings on vulnerable samples go to the adjudication queue, not to FP.
// `known_only` samples (real projects) label only the known advisories: every other finding —
// also on the fixed version, except on the fix itself — is looked up in the adjudication decisions and
// counts as a true / false positive once decided, or stays in the queue.
// A loose criterion is reported next to the strict one — a label no finding hit
// strictly counts as loosely hit by an unused category-equivalent finding in the file of its sink / an
// alternative sink that also shares one of its entries. Precision and the strict Recall do not change.
// Same file alone or a shared entry alone is not enough: on earlier real-model runs either one credited different bugs
// (a CORS finding on /graphql for the WebSocket Origin label, another IDOR in share_token_actions.go).
import { stagesSection } from './stages.js';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { labelVersion, loadBench, prepareTrees, sampleLabels, sampleTrees, treeDir, TreeHasher, type Bench, type LocatedLabel } from './bench.js';
import { classesIntersect, classOfCategory, findingClasses, labelClasses } from './categories.js';
import { enclosingFunction, functionSpans, overlaps, type FunctionSpan } from './locate.js';
import { isFormat, META_FORMAT, RUN_FORMAT, type AuditRec, type FindingRec, type RunMeta, type RunRecord } from './record.js';
import type { AdjudicationDecision, CodeAnchor, LabelPolicy, NegativeLabel, ReasonType, RiskHuntLabel, Sample, VulnLabel } from './schema.js';
import { isRemoteOrigin, remoteKey, type RemoteOptions } from './trees.js';
import { byString, EvalError, f1, ratio, readJson, round } from './util.js';

export const SCORE_FORMAT = 'xiezhi-eval-score/1';

type Outcome = 'tp' | 'pending_hit' | 'duplicate' | 'pending_duplicate' | 'fp' | 'pending_fp' | 'queue' | 'pending_queue' | 'dismissed'
  | 'adj_tp' | 'pending_adj_tp' | 'adj_fp' | 'pending_adj_fp';

/** Counted fields of a run's quality counts (summed across runs, averaged across repeats). */
export const COUNT_KEYS = ['tp', 'duplicate', 'fp', 'queue', 'undecided', 'pending', 'pending_hit', 'pending_fp', 'adj_tp', 'adj_fp', 'labels_total', 'labels_hit', 'labels_hit_loose'] as const;

/** How unlabelled findings are judged: complete labels (hand-built) or known advisories + decisions. */
export interface Adjudicator { knownOnly: boolean; decide: (key: string) => AdjudicationDecision['verdict'] | null }
const COMPLETE: Adjudicator = { knownOnly: false, decide: () => null };

export interface FindingOutcome {
  finding_id: string;
  title: string;
  category: string;
  status: FindingRec['status'];
  outcome: Outcome;
  label_id: string | null;
  reason: string | null;
  /** Stability key: equivalence class + sink function (independent locator). */
  key: string;
  location: string;
}

export interface LabelOutcome {
  label_id: string;
  category: string;
  depth: string;
  /** Service-boundary class of the label (`own` when not labelled) and whether the hitting finding agreed. */
  boundary?: string;
  boundary_ok?: boolean | null;
  hit: boolean;
  hit_status: 'confirmed' | 'pending' | null;
  finding_id: string | null;
  expected_verdict: 'confirmed' | 'pending';
  /** G10: the right kind of conclusion (and, for pending, the missing service named with conditions). */
  verdict_ok: boolean;
  severity_ok: boolean | null;
  entries_hit: number;
  entries_total: number;
  /** Not hit strictly, but a category-equivalent finding lies in a sink file and shares an entry (absent in older score files). */
  loose?: { finding_id: string } | null;
}

export interface RunScore {
  sample_id: string;
  repeat: number;
  kind: string;
  language: string;
  dataset: string;
  project: string;
  status: RunRecord['status'];
  completed: boolean;
  labels: LabelOutcome[];
  findings: FindingOutcome[];
  label_policy: LabelPolicy;
  /** `undecided` (absent in older score files): the `queue` findings of a known_only sample, i.e. unlabelled output awaiting adjudication. */
  counts: { tp: number; duplicate: number; fp: number; queue: number; undecided?: number; pending: number; pending_hit: number; pending_fp: number; adj_tp: number; adj_fp: number; labels_total: number; labels_hit: number; labels_hit_loose?: number };
  category_aligned: { n: number; correct: number };
  localization: { n: number; correct: number };
  guard: string | null;
  /** Open / refuted hypotheses of the scored audit, and missed labels lying on an open hypothesis. */
  hypotheses?: { open: number; refuted: number; labels_on_open: number; threat?: { total: number; confirmed: number; refuted: number; open: number; proposed: number } };
}

export interface Adjudication { sample_id: string; project: string; label_policy: LabelPolicy; repeat: number; reason: string; finding: Pick<FindingRec, 'title' | 'category' | 'cwe' | 'severity' | 'repo' | 'path' | 'start_line' | 'end_line' | 'entries' | 'status'>; key: string }

// ---- source access ----------------------------------------------------------------------------

export class Sources {
  private readonly texts = new Map<string, string | null>();
  constructor(readonly bench: Bench) {}

  text(s: Sample, version: string, repo: string, file: string): string | null {
    const ref = sampleTrees(s).get(version)?.get(repo);
    const dir = ref ? treeDir(this.bench, ref) : null;
    if (!dir) return null;
    const path = join(dir, file);
    if (!this.texts.has(path)) this.texts.set(path, existsSync(path) ? readFileSync(path, 'utf8') : null);
    return this.texts.get(path)!;
  }

  spans(s: Sample, version: string, a: CodeAnchor): FunctionSpan[] | { start: number; end: number }[] {
    if (a.function) {
      const t = this.text(s, version, a.repo, a.file);
      const sp = t ? functionSpans(t, a.file, a.function) : [];
      if (sp.length) return sp;
    }
    return a.line_range ? [{ start: a.line_range[0]!, end: a.line_range[1]! }] : [];
  }

  enclosing(s: Sample, version: string, f: FindingRec): string {
    const t = this.text(s, version, f.repo, normPath(f.path));
    const fn = t ? enclosingFunction(t, normPath(f.path), f.start_line) : null;
    return fn ? fn.qualified : `L${f.start_line}`;
  }
}

export function normPath(p: string): string {
  return p.replace(/\\/g, '/').replace(/^\.?\/+/, '');
}

function aligned(src: Sources, s: Sample, version: string, f: FindingRec, a: CodeAnchor): boolean {
  if (f.repo !== a.repo || normPath(f.path) !== normPath(a.file)) return false;
  const r = { start: f.start_line, end: Math.max(f.start_line, f.end_line) };
  return src.spans(s, version, a).some((sp) => overlaps(r, sp));
}

/** Entry keys: METHOD + path with parameters as `{}`; gateway prefixes tolerated as a path suffix. */
export function normEntry(e: string): { method: string; path: string } | null {
  const m = /^\s*([A-Za-z]+)\s+(\S+)/.exec(e);
  if (!m) return null;
  let p = m[2]!.split('?')[0]!.replace(/\/{2,}/g, '/');
  if (!p.startsWith('/')) p = `/${p}`;
  if (p.length > 1) p = p.replace(/\/+$/, '');
  p = p.split('/').map((seg) => (/^\{[^}]*\}$/.test(seg) || /^:.+/.test(seg) || /^<[^>]*>$/.test(seg) || seg.startsWith('*') ? '{}' : seg)).join('/');
  return { method: m[1]!.toUpperCase(), path: p };
}

export function entryMatches(finding: string, label: string): boolean {
  const a = normEntry(finding);
  const b = normEntry(label);
  if (!a || !b || (a.method !== b.method && a.method !== 'ANY' && b.method !== 'ANY')) return false;
  return a.path === b.path || a.path.endsWith(b.path) || b.path.endsWith(a.path);
}

function categoryOk(f: FindingRec, l: VulnLabel): boolean {
  return classesIntersect(findingClasses(f.category, f.cwe), labelClasses(l.category, l.cwe, l.category_equivalents ?? []));
}

function findingOrder(a: FindingRec, b: FindingRec): number {
  const rank = (f: FindingRec) => (f.status === 'confirmed' ? 0 : 1);
  return rank(a) - rank(b) || b.confidence - a.confidence || (a.display_no ?? 1e9) - (b.display_no ?? 1e9) || byString(a.id, b.id);
}

function pendingOk(f: FindingRec, l: VulnLabel): boolean {
  if (!f.pending || !f.pending.holds_if.length || !f.pending.refuted_if.length) return false;
  const named = f.pending.missing.join(' ').toLowerCase();
  return (l.expected.missing ?? []).some((m) => named.includes(m.toLowerCase()));
}

/** Match one audit's findings against labels. */
export function matchAudit(src: Sources, s: Sample, version: string, findings: FindingRec[], vuln: VulnLabel[], negative: NegativeLabel[], clean: boolean, adj: Adjudicator = COMPLETE) {
  const out: FindingOutcome[] = [];
  const hitBy = new Map<string, FindingRec>();
  const base = (f: FindingRec) => ({
    finding_id: f.id, title: f.title, category: f.category, status: f.status,
    key: `${classOfCategory(f.category)}|${f.repo}:${normPath(f.path)}:${src.enclosing(s, version, f)}`,
    location: `${f.repo}:${normPath(f.path)}:${f.start_line}`,
  });
  let catN = 0, catOk = 0, locN = 0, locOk = 0;
  const decidedTrue = new Set<string>();
  for (const f of [...findings].sort(findingOrder)) {
    if (f.status === 'dismissed') { out.push({ ...base(f), outcome: 'dismissed', label_id: null, reason: '产品自行判为误报' }); continue; }
    const pending = f.status === 'pending';
    const sinkAligned = vuln.filter((l) => [l.sink, ...(l.alt_sinks ?? [])].some((a) => aligned(src, s, version, f, a)));
    const catAligned = vuln.filter((l) => categoryOk(f, l));
    if (sinkAligned.length) { catN++; if (sinkAligned.some((l) => l.category === f.category || (l.category_equivalents ?? []).includes(f.category as never))) catOk++; }
    if (catAligned.length) { locN++; if (catAligned.some((l) => sinkAligned.includes(l))) locOk++; }
    const decoy = negative.find((n) => n.decoys.some((d) => aligned(src, s, version, f, d)));
    if (clean && (!adj.knownOnly || decoy)) {
      // A finding on a fixed / negative sample that a person decided is a real (unplanned) issue of the sample
      // code is not a false positive (decisions in adjudication/<project>.yaml, limited to the listed samples).
      if (!decoy && !adj.knownOnly && adj.decide(base(f).key) === 'true_positive') { out.push(decided(base(f), pending, null)); continue; }
      out.push({ ...base(f), outcome: pending ? 'pending_fp' : 'fp', label_id: decoy?.label_id ?? null, reason: decoy ? '命中诱饵点' : '修复版本 / 负例上的发现' });
      continue;
    }
    if (clean) {
      out.push(decided(base(f), pending, sinkAligned[0]?.label_id ?? null));
      continue;
    }
    const hits = sinkAligned.filter((l) => catAligned.includes(l));
    const free = hits.find((l) => !hitBy.has(l.label_id));
    if (free) {
      hitBy.set(free.label_id, f);
      out.push({ ...base(f), outcome: pending ? 'pending_hit' : 'tp', label_id: free.label_id, reason: null });
    } else if (hits.length) {
      out.push({ ...base(f), outcome: pending ? 'pending_duplicate' : 'duplicate', label_id: hits[0]!.label_id, reason: '同一标注已被命中' });
    } else if (decoy) {
      out.push({ ...base(f), outcome: pending ? 'pending_fp' : 'fp', label_id: decoy.label_id, reason: '命中已裁定的诱饵点' });
    } else if (adj.knownOnly) {
      out.push(decided(base(f), pending, sinkAligned[0]?.label_id ?? null));
    } else {
      out.push({ ...base(f), outcome: pending ? 'pending_queue' : 'queue', label_id: sinkAligned[0]?.label_id ?? null, reason: sinkAligned.length ? '危险点对齐但类别不一致' : '未标注的发现' });
    }
  }

  /** known_only: a human decision on the stability key, or the adjudication queue. */
  function decided(b: ReturnType<typeof base>, pending: boolean, labelId: string | null): FindingOutcome {
    const v = adj.decide(b.key);
    if (v === 'true_positive') {
      if (decidedTrue.has(b.key)) return { ...b, outcome: pending ? 'pending_duplicate' : 'duplicate', label_id: labelId, reason: '同一裁定已被命中' };
      decidedTrue.add(b.key);
      return { ...b, outcome: pending ? 'pending_adj_tp' : 'adj_tp', label_id: labelId, reason: '已裁定为真问题' };
    }
    if (v === 'false_positive') return { ...b, outcome: pending ? 'pending_adj_fp' : 'adj_fp', label_id: labelId, reason: '已裁定为误报' };
    return { ...b, outcome: pending ? 'pending_queue' : 'queue', label_id: labelId, reason: '未裁定（只标注已知漏洞的样本）' };
  }
  const looseBy = clean ? new Map<string, FindingRec>() : looseHits(findings, vuln, out);
  return { outcomes: out, hitBy, looseBy, category: { n: catN, correct: catOk }, localization: { n: locN, correct: locOk } };
}

/**
 * Loose criterion: for each label without a strict hit, the first unused category-equivalent finding (same
 * order as strict matching) in the file of its sink or an alternative sink that shares one of its entries. Findings
 * that hit or duplicate a label strictly, or that the product dismissed, are not used; each finding is used once.
 */
function looseHits(findings: FindingRec[], vuln: VulnLabel[], outcomes: FindingOutcome[]): Map<string, FindingRec> {
  const strict = new Set(outcomes.filter((o) => ['tp', 'pending_hit', 'duplicate', 'pending_duplicate', 'dismissed'].includes(o.outcome)).map((o) => o.finding_id));
  const pool = [...findings].sort(findingOrder).filter((f) => !strict.has(f.id));
  const used = new Set<string>();
  const loose = new Map<string, FindingRec>();
  for (const l of vuln) {
    if (outcomes.some((o) => o.label_id === l.label_id && (o.outcome === 'tp' || o.outcome === 'pending_hit'))) continue;
    const anchors = [l.sink, ...(l.alt_sinks ?? [])];
    const sameFile = (f: FindingRec) => anchors.some((a) => f.repo === a.repo && normPath(f.path) === normPath(a.file));
    const sharedEntry = (f: FindingRec) => f.entries.some((e) => l.entries.some((x) => entryMatches(e, x.route)));
    const f = pool.find((x) => !used.has(x.id) && categoryOk(x, l) && sameFile(x) && sharedEntry(x));
    if (f) { used.add(f.id); loose.set(l.label_id, f); }
  }
  return loose;
}

function labelOutcomes(vuln: VulnLabel[], hitBy: Map<string, FindingRec>, looseBy: Map<string, FindingRec>): LabelOutcome[] {
  return vuln.map((l) => {
    const f = hitBy.get(l.label_id) ?? null;
    const lo = f ? null : looseBy.get(l.label_id) ?? null;
    const entriesHit = f ? l.entries.filter((e) => f.entries.some((x) => entryMatches(x, e.route))).length : 0;
    const verdictOk = !!f && (l.expected.verdict === 'confirmed' ? f.status === 'confirmed' : f.status === 'pending' && pendingOk(f, l));
    return {
      label_id: l.label_id, category: l.category, depth: l.depth, boundary: l.boundary ?? 'own', boundary_ok: f ? (f.boundary ?? 'own') === (l.boundary ?? 'own') : null, hit: !!f, hit_status: f ? (f.status === 'pending' ? 'pending' : 'confirmed') : null,
      finding_id: f?.id ?? null, expected_verdict: l.expected.verdict as LabelOutcome['expected_verdict'], verdict_ok: verdictOk,
      severity_ok: f && l.expected.severity ? (l.expected.severity as string[]).includes(f.severity) : null,
      entries_hit: f ? entriesHit : 0, entries_total: f ? l.entries.length : 0,
      loose: lo ? { finding_id: lo.id } : null,
    };
  });
}

// ---- per-run scoring ---------------------------------------------------------------------------

/** The adjudicator of a sample: decisions of its project that apply to it (all samples, or listed). */
export function adjudicatorOf(bench: Bench, s: Sample): Adjudicator {
  const ds = (bench.decisions.get(s.project) ?? []).filter((d) => !d.samples || d.samples.includes(s.sample_id));
  const byKey = new Map(ds.map((d) => [d.key, d.verdict] as const));
  // Completely labelled samples consult decisions only for true positives on fixed / negative samples (matchAudit).
  if (s.label_policy !== 'known_only') return ds.length ? { knownOnly: false, decide: (key) => byKey.get(key) ?? null } : COMPLETE;
  return { knownOnly: true, decide: (key) => byKey.get(key) ?? null };
}

function scoreRun(src: Sources, bench: Bench, s: Sample, rec: RunRecord): RunScore {
  const L = sampleLabels(bench, s);
  const clean = s.kind === 'fixed' || s.kind === 'negative';
  // Incremental (G5): the incremental audit of the changed version is scored against the labels of that version.
  const incremental = s.kind === 'incremental';
  const version = incremental ? (s.scene_input?.versions?.[0]?.name ?? 'base') : 'base';
  const scored = rec.audits.find((a) => a.role === (incremental ? 'incremental' : 'base'));
  const vulnHere = L.vuln.filter((l) => labelVersion(bench, s, l.label_id) === version);
  const m = matchAudit(src, s, version, scored?.findings ?? [], vulnHere, incremental ? [] : L.negative, clean, adjudicatorOf(bench, s));
  const labels = ['vuln', 'fixed', 'negative', 'incremental'].includes(s.kind) ? labelOutcomes(vulnHere, m.hitBy, m.looseBy) : [];
  const c = (o: Outcome) => m.outcomes.filter((x) => x.outcome === o).length;
  return {
    sample_id: s.sample_id, repeat: rec.repeat, kind: s.kind, language: s.language, dataset: s.source.dataset, project: s.project,
    status: rec.status, completed: rec.status === 'completed', labels, findings: m.outcomes, label_policy: (s.label_policy ?? 'complete') as LabelPolicy,
    counts: {
      tp: c('tp'), duplicate: c('duplicate'), fp: c('fp'), queue: c('queue'), undecided: s.label_policy === 'known_only' ? c('queue') : 0,
      pending: m.outcomes.filter((x) => x.status === 'pending').length, pending_hit: c('pending_hit'), pending_fp: c('pending_fp'),
      adj_tp: c('adj_tp'), adj_fp: c('adj_fp'),
      labels_total: labels.length, labels_hit: labels.filter((l) => l.hit).length, labels_hit_loose: labels.filter((l) => l.hit || l.loose).length,
    },
    category_aligned: m.category, localization: m.localization,
    guard: clean ? (L.negative[0]?.guard ?? null) : null,
    ...(scored?.hypotheses ? { hypotheses: hypothesisOutcome(src, s, version, scored.hypotheses, vulnHere, labels) } : {}),
  };
}

function hypothesisOutcome(src: Sources, s: Sample, version: string, hs: NonNullable<AuditRec['hypotheses']>, vuln: VulnLabel[], labels: LabelOutcome[]) {
  const open = hs.filter((h) => h.status === 'open');
  const missed = vuln.filter((l) => !labels.find((x) => x.label_id === l.label_id)?.hit);
  const asFinding = (h: (typeof hs)[number]): FindingRec => ({
    id: '', display_no: null, title: '', category: h.category, cwe: null, severity: 'medium', confidence: 0, repo: h.repo, path: h.path,
    start_line: h.start_line, end_line: h.end_line, entries: [], status: 'pending', vulnerability_id: null, match_level: null, pending: null,
  });
  const onOpen = missed.filter((l) => open.some((h) => categoryOk(asFinding(h), l) && [l.sink, ...(l.alt_sinks ?? [])].some((a) => aligned(src, s, version, asFinding(h), a)))).length;
  // The threat model's hypotheses and how their verification ended (not part of Precision / Recall).
  const t = hs.filter((h) => h.origin === 'threat_model');
  const n = (st: string) => t.filter((h) => h.status === st).length;
  return {
    open: open.length, refuted: hs.filter((h) => h.status === 'refuted').length, labels_on_open: onOpen,
    ...(t.length ? { threat: { total: t.length, confirmed: n('confirmed'), refuted: n('refuted'), open: n('open'), proposed: n('proposed') } } : {}),
  };
}

// ---- aggregation --------------------------------------------------------------------------------

export interface QualityCounts { runs: number; tp: number; duplicate: number; fp: number; queue: number; undecided: number; pending: number; pending_hit: number; pending_fp: number; adj_tp: number; adj_fp: number; labels_total: number; labels_hit: number; labels_hit_loose: number; labels_total_all: number }

export function emptyCounts(): QualityCounts {
  return { runs: 0, tp: 0, duplicate: 0, fp: 0, queue: 0, undecided: 0, pending: 0, pending_hit: 0, pending_fp: 0, adj_tp: 0, adj_fp: 0, labels_total: 0, labels_hit: 0, labels_hit_loose: 0, labels_total_all: 0 };
}

/** Quality counts of scored runs: completed runs count fully; the rest only add their labels to the mixed denominator. */
export function sumCounts(runs: RunScore[]): QualityCounts {
  const q = emptyCounts();
  for (const r of runs) {
    q.labels_total_all += r.counts.labels_total;
    if (!r.completed) continue;
    q.runs++;
    for (const k of COUNT_KEYS) q[k] += r.counts[k] ?? (k === 'labels_hit_loose' ? r.counts.labels_hit : 0); // older score files have no `undecided` / `labels_hit_loose`
  }
  return q;
}

export interface QualityMetrics {
  /** null when the known_only adjudication coverage is below MIN_ADJUDICATION_COVERAGE: see the bounds. */
  precision: number | null;
  /** Bounds over the undecided findings: all of them false positives (low) / all true positives (high). */
  precision_low: number | null;
  precision_high: number | null;
  /** Adjudicated / (adjudicated + undecided) unlabelled findings of known_only samples; null when there are none. */
  adjudication_coverage: number | null;
  recall: number | null; f1: number | null; recall_mixed: number | null; f1_mixed: number | null;
  /** Recall with loosely hit labels added (completed runs). */
  recall_loose: number | null;
}

/** Below this adjudication coverage Precision is not reported as a number, only as bounds. */
export const MIN_ADJUDICATION_COVERAGE = 0.8;

/**
 * Precision counts adjudicated findings of known_only samples; Recall stays on the labels.
 * Undecided findings are outside the point estimate; with little of the output adjudicated the estimate says
 * nothing (no adjudication at all gave 100%), so it is withheld and the bounds carry the information.
 */
export function qualityMetrics(q: QualityCounts): QualityMetrics {
  const good = q.tp + q.adj_tp;
  const decidedDen = good + q.duplicate + q.fp + q.adj_fp;
  const undecided = q.undecided ?? 0;
  const adjudicated = q.adj_tp + q.adj_fp;
  const coverage = undecided > 0 ? ratio(adjudicated, adjudicated + undecided) : null;
  const point = ratio(good, decidedDen);
  const precision = coverage !== null && coverage < MIN_ADJUDICATION_COVERAGE ? null : point;
  const precisionLow = undecided > 0 ? ratio(good, decidedDen + undecided) : point;
  const precisionHigh = undecided > 0 ? ratio(good + undecided, decidedDen + undecided) : point;
  const recall = ratio(q.labels_hit, q.labels_total);
  const recallMixed = ratio(q.labels_hit, q.labels_total_all);
  return {
    precision, precision_low: precisionLow, precision_high: precisionHigh, adjudication_coverage: coverage,
    recall, f1: f1(precision, recall), recall_mixed: recallMixed, f1_mixed: f1(precision, recallMixed),
    recall_loose: ratio(q.labels_hit_loose ?? q.labels_hit, q.labels_total),
  };
}

function group<T>(items: T[], key: (t: T) => string): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const it of items) m.set(key(it), [...(m.get(key(it)) ?? []), it]);
  return new Map([...m.entries()].sort((a, b) => byString(a[0], b[0])));
}

function qualitySection(runs: RunScore[]) {
  const scored = runs.filter((r) => ['vuln', 'fixed', 'negative'].includes(r.kind));
  const q = sumCounts(scored);
  const done = scored.filter((r) => r.completed);
  const labels = done.flatMap((r) => r.labels);
  const labelsAll = scored.flatMap((r) => r.labels.map((l) => ({ ...l, completed: r.completed, r })));
  const byLabel = (key: (l: (typeof labelsAll)[number]) => string) => Object.fromEntries([...group(labelsAll, key)].map(([k, ls]) => {
    const total = ls.filter((l) => l.completed).length;
    const hit = ls.filter((l) => l.completed && l.hit).length;
    const hitLoose = ls.filter((l) => l.completed && (l.hit || l.loose)).length;
    // `labels` counts label outcomes (labels × completed repeats); the experiment's sufficiency rule counts
    // distinct labels instead (experiment.ts distinctLabels).
    return [k, { labels: total, hit, recall: ratio(hit, total), recall_mixed: ratio(hit, ls.length), hit_loose: hitLoose, recall_loose: ratio(hitLoose, total) }];
  }));
  const bySample = (key: (r: RunScore) => string) => Object.fromEntries([...group(scored, key)].map(([k, rs]) => [k, { ...qualityMetrics(sumCounts(rs)), counts: sumCounts(rs) }]));
  const cleanRuns = done.filter((r) => r.kind === 'fixed' || r.kind === 'negative');
  const verdictLabels = labels;
  const known = done.filter((r) => r.label_policy === 'known_only');
  const decidedN = known.reduce((n, r) => n + r.findings.filter((f) => /adj_/.test(f.outcome)).length, 0);
  const undecidedN = known.reduce((n, r) => n + r.findings.filter((f) => f.outcome === 'queue' || f.outcome === 'pending_queue').length, 0);
  const entries = labels.filter((l) => l.hit);
  // Labels without entries (imported public datasets) are not part of the entry-hit rate.
  const withEntries = entries.filter((l) => l.entries_total > 0);
  return {
    counts: q,
    ...qualityMetrics(q),
    category_accuracy: ratio(done.reduce((n, r) => n + r.category_aligned.correct, 0), done.reduce((n, r) => n + r.category_aligned.n, 0)),
    localization_accuracy: ratio(done.reduce((n, r) => n + r.localization.correct, 0), done.reduce((n, r) => n + r.localization.n, 0)),
    entry_hit_rate: ratio(withEntries.reduce((n, l) => n + l.entries_hit, 0), withEntries.reduce((n, l) => n + l.entries_total, 0)),
    severity_in_range: ratio(entries.filter((l) => l.severity_ok === true).length, entries.filter((l) => l.severity_ok !== null).length),
    /** Hits whose finding named the label's service-boundary class (findings without one count as `own`). */
    boundary_accuracy: ratio(entries.filter((l) => l.boundary_ok === true).length, entries.filter((l) => l.boundary_ok != null).length),
    /** G10: confirmed where the repositories are complete, pending (naming the missing service) where not. */
    verdict_accuracy: ratio(verdictLabels.filter((l) => l.verdict_ok).length, verdictLabels.length),
    pending_accuracy: ratio(verdictLabels.filter((l) => l.expected_verdict === 'pending' && l.verdict_ok).length, verdictLabels.filter((l) => l.expected_verdict === 'pending').length),
    false_positives_on_clean: Object.fromEntries([...group(cleanRuns, (r) => r.guard ?? 'unknown')].map(([g, rs]) => [g, {
      runs: rs.length, runs_with_fp: rs.filter((r) => r.counts.fp > 0).length, fp: rs.reduce((n, r) => n + r.counts.fp, 0), fp_rate: ratio(rs.filter((r) => r.counts.fp > 0).length, rs.length),
    }])),
    /** known_only samples: how much of the unlabelled output has been adjudicated (Precision is partial until 100%). */
    adjudication: { runs: known.length, decided: decidedN, undecided: undecidedN, coverage: ratio(decidedN, decidedN + undecidedN) },
    /** Labels hit per completed run of each sample, strict and loose (median / min / max across repeats). */
    by_sample_hits: Object.fromEntries([...group(done.filter((r) => r.labels.length), (r) => r.sample_id)].map(([k, rs]) => [k, {
      runs: rs.length, labels: rs[0]!.labels.length,
      strict: hitSpread(rs.map((r) => r.labels.filter((l) => l.hit).length)),
      loose: hitSpread(rs.map((r) => r.labels.filter((l) => l.hit || l.loose).length)),
    }])),
    /** Each loose hit, so a person can check it (not counted in the strict Recall). */
    loose_hits: done.flatMap((r) => r.labels.filter((l) => l.loose).map((l) => ({ sample_id: r.sample_id, repeat: r.repeat, label_id: l.label_id, finding_id: l.loose!.finding_id }))),
    by_category: byLabel((l) => l.category),
    by_depth: byLabel((l) => l.depth),
    // Recall by service-boundary class (own / upstream / cross_service).
    by_boundary: byLabel((l) => l.boundary ?? 'own'),
    by_language: bySample((r) => r.language),
    by_dataset: bySample((r) => r.dataset),
    by_label_policy: bySample((r) => r.label_policy),
    /**
     * Open hypotheses are neither findings nor false positives. Reported separately: how many,
     * and how many labels no finding hit lie on an open hypothesis (category-equivalent, same sink function) —
     * the recall a reviewer could recover by adjudicating the hypotheses.
     */
    hypotheses: {
      runs: done.filter((r) => r.hypotheses).length,
      open: done.reduce((n, r) => n + (r.hypotheses?.open ?? 0), 0),
      refuted: done.reduce((n, r) => n + (r.hypotheses?.refuted ?? 0), 0),
      labels_missed_but_hypothesised: done.reduce((n, r) => n + (r.hypotheses?.labels_on_open ?? 0), 0),
      recall_with_hypotheses: ratio(done.reduce((n, r) => n + r.counts.labels_hit + (r.hypotheses?.labels_on_open ?? 0), 0), q.labels_total),
      threat: (['total', 'confirmed', 'refuted', 'open', 'proposed'] as const).reduce((o, k) => ({ ...o, [k]: done.reduce((n, r) => n + (r.hypotheses?.threat?.[k] ?? 0), 0) }), {} as Record<'total' | 'confirmed' | 'refuted' | 'open' | 'proposed', number>),
    },
  };
}

function availabilitySection(recs: RunRecord[]) {
  const status = (st: string) => recs.filter((r) => r.status === st).length;
  const partialReasons: Record<string, number> = {};
  const errorClasses: Record<string, { attempts: number; samples: string[] }> = {};
  let failedSteps = 0, recovered = 0;
  for (const r of recs) {
    for (const a of r.audits) {
      if (a.status !== 'completed') for (const p of a.partial_reasons) partialReasons[p] = (partialReasons[p] ?? 0) + 1;
      for (const x of a.attempts) {
        if (!x.error_class) continue;
        const e = errorClasses[x.error_class] ??= { attempts: 0, samples: [] };
        e.attempts++;
        if (!e.samples.includes(r.sample_id)) e.samples.push(r.sample_id);
      }
      for (const st of a.steps) {
        if (!a.attempts.some((x) => x.seq === st.seq && x.error_class)) continue;
        failedSteps++;
        if (st.status === 'succeeded') recovered++;
      }
      if (a.error_class) {
        const e = errorClasses[a.error_class] ??= { attempts: 0, samples: [] };
        if (!e.samples.includes(r.sample_id)) e.samples.push(r.sample_id);
      }
    }
  }
  for (const e of Object.values(errorClasses)) e.samples.sort(byString);
  const errors: Record<string, number> = {};
  for (const r of recs) if (r.error) errors[r.error.code] = (errors[r.error.code] ?? 0) + 1;
  return {
    runs: recs.length, completed: status('completed'), partial: status('partial'), failed: status('failed'), cancelled: status('cancelled'), error: status('error'), invalid: status('invalid'),
    completion_rate: ratio(status('completed'), recs.length),
    partial_reasons: Object.fromEntries(Object.entries(partialReasons).sort((a, b) => byString(a[0], b[0]))),
    error_classes: Object.fromEntries(Object.entries(errorClasses).sort((a, b) => byString(a[0], b[0]))),
    run_errors: Object.fromEntries(Object.entries(errors).sort((a, b) => byString(a[0], b[0]))),
    retry_recovery: { steps_with_errors: failedSteps, recovered, rate: ratio(recovered, failedSteps) },
  };
}

// ---- cost -------------------------------------------------------------------------------

/** The risk-hunt basis drafting: priced when the usage split and a price are known, else an unknown-price call. */
function addBasis(c: CostTotals, risk: NonNullable<RunRecord['risk']>): void {
  c.tokens_in += risk.basis_tokens;
  c.calls++;
  if (risk.basis_cost_micros == null || !risk.basis_currency) { c.unknown_calls++; return; }
  c.known[risk.basis_currency] = round((c.known[risk.basis_currency] ?? 0) + risk.basis_cost_micros / 1e6, 6);
}

export interface CostTotals { tokens_in: number; tokens_out: number; tokens_cached: number; wall_ms: number; model_ms: number; known: Record<string, number>; unknown_calls: number; calls: number }

function emptyCost(): CostTotals {
  return { tokens_in: 0, tokens_out: 0, tokens_cached: 0, wall_ms: 0, model_ms: 0, known: {}, unknown_calls: 0, calls: 0 };
}

function addAudit(c: CostTotals, a: AuditRec, withTime = true): void {
  if (withTime) { c.wall_ms += a.wall_ms; c.model_ms += a.model_ms; }
  for (const x of a.attempts) addAttempt(c, x);
}

function addAttempt(c: CostTotals, x: AuditRec['attempts'][number]): void {
  const t = x.tokens_in + x.tokens_out + x.tokens_cached;
  c.tokens_in += x.tokens_in; c.tokens_out += x.tokens_out; c.tokens_cached += x.tokens_cached;
  if (t > 0) c.calls++;
  if (x.cost_micros === null) { if (t > 0) c.unknown_calls++; } else if (x.currency) c.known[x.currency] = round((c.known[x.currency] ?? 0) + x.cost_micros / 1e6, 6);
}

export function runCost(r: RunRecord): CostTotals {
  const c = emptyCost();
  for (const a of r.audits) addAudit(c, a);
  if (r.risk?.basis_tokens) addBasis(c, r.risk);
  c.wall_ms = r.wall_ms;
  return c;
}

/**
 * G5: incremental samples audit the baseline in full and then the change incrementally,
 * in the same run. Quality of the incremental audit on the change, and incremental / full ratios of tokens
 * (input + output + cached), known USD and wall time — pooled over completed runs and per sample.
 */
function incrementalSection(runs: RunScore[], recs: RunRecord[]) {
  const scored = runs.filter((r) => r.kind === 'incremental');
  const done = scored.filter((r) => r.completed);
  const pair = (r: RunRecord) => {
    const full = r.audits.find((a) => a.role === 'base');
    const inc = r.audits.find((a) => a.role === 'incremental');
    if (!full || !inc || full.status !== 'completed' || inc.status !== 'completed') return null;
    const cost = (a: AuditRec) => { const c = emptyCost(); addAudit(c, a); return c; };
    return { full: cost(full), inc: cost(inc) };
  };
  const tokens = (c: CostTotals) => c.tokens_in + c.tokens_out + c.tokens_cached;
  const pairs = recs.filter((r) => r.kind === 'incremental').map((r) => ({ r, p: pair(r) })).filter((x): x is { r: RunRecord; p: NonNullable<ReturnType<typeof pair>> } => !!x.p);
  const sum = (f: (c: CostTotals) => number | undefined, k: 'full' | 'inc') => pairs.reduce((n, x) => n + (f(x.p[k]) ?? 0), 0);
  const usdKnown = pairs.every((x) => x.p.full.unknown_calls === 0 && x.p.inc.unknown_calls === 0);
  const perSample = Object.fromEntries([...group(pairs, (x) => x.r.sample_id)].map(([sid, xs]) => [sid, {
    runs: xs.length,
    token_ratio: ratio(xs.reduce((n, x) => n + tokens(x.p.inc), 0), xs.reduce((n, x) => n + tokens(x.p.full), 0)),
    wall_ratio: ratio(xs.reduce((n, x) => n + x.p.inc.wall_ms, 0), xs.reduce((n, x) => n + x.p.full.wall_ms, 0)),
  }]));
  return {
    runs: scored.length, completed: done.length, pairs: pairs.length,
    ...qualityMetrics(sumCounts(scored)), counts: sumCounts(scored),
    token_ratio: ratio(sum(tokens, 'inc'), sum(tokens, 'full')),
    usd_ratio: usdKnown ? ratio(sum((c) => c.known.USD, 'inc'), sum((c) => c.known.USD, 'full')) : null,
    wall_ratio: ratio(sum((c) => c.wall_ms, 'inc'), sum((c) => c.wall_ms, 'full')),
    per_sample: perSample,
  };
}

function costSection(recs: RunRecord[], tp: number) {
  const total = emptyCost();
  const byScene: Record<string, CostTotals> = {};
  const byStep: Record<string, CostTotals> = {};
  for (const r of recs) {
    const rc = runCost(r);
    for (const k of ['tokens_in', 'tokens_out', 'tokens_cached', 'wall_ms', 'model_ms', 'unknown_calls', 'calls'] as const) total[k] += rc[k];
    for (const [cur, v] of Object.entries(rc.known)) total.known[cur] = round((total.known[cur] ?? 0) + v, 6);
    for (const a of r.audits) {
      addAudit(byScene[a.scene] ??= emptyCost(), a);
      for (const x of a.attempts) addAttempt(byStep[x.step] ??= emptyCost(), x);
    }
    if (r.risk?.basis_tokens) addBasis(byStep.basis ??= emptyCost(), r.risk);
  }
  const usd = total.known.USD;
  return {
    total, by_scene: sortObj(byScene), by_step: sortObj(byStep),
    /** Known cost per true positive; `partial` when some calls had no price (never priced as 0). */
    cost_per_tp: usd !== undefined && tp > 0 ? { usd: round(usd / tp, 6), partial: total.unknown_calls > 0 } : null,
  };
}

function sortObj<T>(o: Record<string, T>): Record<string, T> {
  return Object.fromEntries(Object.entries(o).sort((a, b) => byString(a[0], b[0])));
}

// ---- stability ----------------------------------------------------------------------------

/** Per-run hit counts with median / min / max. */
export function hitSpread(xs: number[]) {
  const v = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(v.length / 2);
  const median = v.length ? (v.length % 2 ? v[mid]! : (v[mid - 1]! + v[mid]!) / 2) : null;
  return { values: xs, median, min: v.length ? v[0]! : null, max: v.length ? v.at(-1)! : null };
}

function std(xs: number[]): number | null {
  if (xs.length < 2) return null;
  const m = xs.reduce((a, b) => a + b, 0) / xs.length;
  return round(Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1)));
}

function spread(xs: (number | null)[]) {
  const v = xs.filter((x): x is number => x !== null);
  return { values: xs, std: std(v), range: v.length ? round(Math.max(...v) - Math.min(...v)) : null };
}

export function jaccard(a: Set<string>, b: Set<string>): number {
  if (!a.size && !b.size) return 1;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

function stabilitySection(runs: RunScore[], recs: RunRecord[]) {
  const perSample: Record<string, { runs: number; jaccard: number | null }> = {};
  const unstable: { sample_id: string; key: string; present_in: number; runs: number; hit: boolean }[] = [];
  const scored = runs.filter((r) => ['vuln', 'fixed', 'negative'].includes(r.kind) && r.completed);
  for (const [sid, rs] of group(scored, (r) => r.sample_id)) {
    const sets = rs.map((r) => new Set(r.findings.filter((f) => f.outcome !== 'dismissed').map((f) => f.key)));
    let sum = 0, n = 0;
    for (let i = 0; i < sets.length; i++) for (let j = i + 1; j < sets.length; j++) { sum += jaccard(sets[i]!, sets[j]!); n++; }
    perSample[sid] = { runs: rs.length, jaccard: n ? round(sum / n) : null };
    if (rs.length < 2) continue;
    const all = new Set(sets.flatMap((x) => [...x]));
    for (const key of [...all].sort(byString)) {
      const present = sets.filter((x) => x.has(key)).length;
      if (present < sets.length) {
        const hit = rs.some((r) => r.findings.some((f) => f.key === key && (f.outcome === 'tp' || f.outcome === 'pending_hit')));
        unstable.push({ sample_id: sid, key, present_in: present, runs: sets.length, hit });
      }
    }
  }
  const js = Object.values(perSample).map((x) => x.jaccard).filter((x): x is number => x !== null);
  const repeats = [...new Set(scored.map((r) => r.repeat))].sort((a, b) => a - b);
  const perRepeat = repeats.map((k) => qualityMetrics(sumCounts(runs.filter((r) => r.repeat === k && ['vuln', 'fixed', 'negative'].includes(r.kind)))));
  const costPerRepeat = repeats.map((k) => {
    const usd = recs.filter((r) => r.repeat === k).reduce((n, r) => n + (runCost(r).known.USD ?? 0), 0);
    return round(usd, 6);
  });
  return {
    mean_jaccard: js.length ? round(js.reduce((a, b) => a + b, 0) / js.length) : null,
    per_sample: perSample,
    variation: {
      precision: spread(perRepeat.map((m) => m.precision)), recall: spread(perRepeat.map((m) => m.recall)), f1: spread(perRepeat.map((m) => m.f1)),
      cost_usd: spread(costPerRepeat),
    },
    unstable_findings: unstable,
  };
}

// ---- risk hunt -----------------------------------------------------------------------------

export function classifyReason(reason: string, source: string | null): ReasonType | null {
  const r = reason.toLowerCase();
  if (/版本|version|不在.{0,12}范围|已升级|upgrade/.test(r)) return 'version_out_of_range';
  if (/不可达|无法到达|未暴露|没有暴露|不对外|unreachable|not exposed|dead code|没有调用方|无调用方/.test(r)) return 'unreachable';
  if (/未引入|没有引入|未使用|没有使用|未依赖|没有依赖|未搜索到|没有搜索到|未找到|没有找到|no dependency|not used|not imported|not referenced/.test(r)) return 'not_imported';
  if (/校验|防护|过滤|白名单|safeconstructor|限制|guard|sanitiz|validat|whitelist|allowlist|安全的/.test(r)) return 'guarded';
  return source === 'rule' ? 'not_imported' : null;
}

function riskSection(src: Sources, bench: Bench, samples: Map<string, Sample>, recs: RunRecord[]) {
  const confusion: Record<string, Record<string, number>> = {};
  const details: unknown[] = [];
  let targets = 0, correct = 0, locTotal = 0, locHit = 0, reasonN = 0, reasonOk = 0, evidenceOk = 0;
  for (const r of recs.filter((x) => x.kind === 'risk_hunt')) {
    const s = samples.get(r.sample_id)!;
    const label = sampleLabels(bench, s).risk[0] as RiskHuntLabel | undefined;
    if (!label) continue;
    const hits = r.audits.flatMap((a) => a.findings);
    for (const t of label.targets) {
      const got = r.risk?.targets.find((x) => x.repo === t.repo);
      const verdict = got?.verdict ?? 'missing';
      (confusion[t.expected] ??= {})[verdict] = (confusion[t.expected]![verdict] ?? 0) + 1;
      targets++;
      if (verdict === t.expected) correct++;
      const locs = t.locations ?? [];
      const found = locs.filter((a) => hits.some((f) => aligned(src, s, 'base', f, a))).length;
      locTotal += locs.length;
      locHit += found;
      let reasonType: ReasonType | null = null, typeOk: boolean | null = null, evOk: boolean | null = null;
      if (t.expected === 'not_affected' && verdict === 'not_affected' && got) {
        reasonType = classifyReason(got.reason ?? '', got.verdict_source);
        typeOk = reasonType === t.reason_type;
        evOk = got.evidence.some((e) => e.verified && e.path && (t.reason_evidence ?? []).some((a) => aligned(src, s, 'base', {
          repo: t.repo, path: e.path!, start_line: e.start_line ?? 0, end_line: e.end_line ?? e.start_line ?? 0,
        } as FindingRec, a)));
        reasonN++;
        if (typeOk) reasonOk++;
        if (evOk) evidenceOk++;
      }
      details.push({ sample_id: r.sample_id, repeat: r.repeat, repo: t.repo, expected: t.expected, got: verdict, locations: { total: locs.length, found }, reason_type: { expected: t.reason_type ?? null, got: reasonType, ok: typeOk }, evidence_ok: evOk });
    }
  }
  return {
    targets, accuracy: ratio(correct, targets), confusion, location_recall: ratio(locHit, locTotal),
    not_affected_reason: { checked: reasonN, type_accuracy: ratio(reasonOk, reasonN), evidence_ok_rate: ratio(evidenceOk, reasonN) },
    wall_ms: recs.filter((x) => x.kind === 'risk_hunt').reduce((n, x) => n + x.wall_ms, 0),
    details,
  };
}

// ---- reverify -------------------------------------------------------------------------------

function reverifySection(src: Sources, bench: Bench, samples: Map<string, Sample>, recs: RunRecord[]) {
  const confusion: Record<string, Record<string, number>> = {};
  const details: unknown[] = [];
  let steps = 0, correct = 0, definite = 0, withVerdict = 0, mustNotRelease = 0, released = 0;
  for (const r of recs.filter((x) => x.kind === 'reverify')) {
    const s = samples.get(r.sample_id)!;
    const L = sampleLabels(bench, s);
    const label = L.reverify[0];
    if (!label) continue;
    const target = L.vuln.find((l) => l.label_id === label.target_label);
    const base = r.audits.find((a) => a.role === 'base');
    const m = base && target ? matchAudit(src, s, 'base', base.findings, [target], [], false) : null;
    const vulnId = m?.hitBy.get(label.target_label)?.vulnerability_id ?? null;
    (s.scene_input?.versions ?? []).forEach((v, i) => {
      const expected = label.expected[i]!;
      const audit = r.audits.find((a) => a.role === 'reverify' && a.version === v.name);
      const entry = vulnId ? audit?.reverify.find((x) => x.vulnerability_id === vulnId) : undefined;
      const got = !vulnId ? 'base_missed' : !audit ? 'not_run' : !entry?.verdict ? 'no_verdict'
        : entry.verdict === 'still_present' && entry.lifecycle_after === 'regressed' ? 'regressed' : entry.verdict === 'partially_fixed' ? 'partially_fixed' : entry.verdict;
      (confusion[expected] ??= {})[got] = (confusion[expected]![got] ?? 0) + 1;
      steps++;
      if (got === expected) correct++;
      if (['fixed', 'still_present', 'partially_fixed', 'regressed', 'undetermined'].includes(got)) { withVerdict++; if (got !== 'undetermined') definite++; }
      if (['still_present', 'partially_fixed', 'regressed'].includes(expected)) { mustNotRelease++; if (got === 'fixed') released++; }
      details.push({ sample_id: r.sample_id, repeat: r.repeat, version: v.name, expected, got });
    });
  }
  return {
    steps, accuracy: ratio(correct, steps), confusion,
    definite_rate: ratio(definite, withVerdict),
    /** Expected still present / incomplete / regressed but judged fixed: the costliest error. */
    false_release_rate: ratio(released, mustNotRelease),
    details,
  };
}

// ---- identity -------------------------------------------------------------------------------

function identitySection(src: Sources, bench: Bench, samples: Map<string, Sample>, recs: RunRecord[]) {
  const pairs: { sample_id: string; repeat: number; label_id: string; refactor: string; expected: string; got: string }[] = [];
  for (const r of recs.filter((x) => x.kind === 'identity')) {
    const s = samples.get(r.sample_id)!;
    const L = sampleLabels(bench, s);
    for (const idl of L.identity) {
      const la = L.vuln.find((l) => l.label_id === idl.a);
      const lb = L.vuln.find((l) => l.label_id === idl.b);
      const A = r.audits.find((a) => a.role === 'base');
      const B = r.audits.find((a) => a.role === 'version' && a.version === idl.version);
      const fa = A && la ? matchAudit(src, s, 'base', A.findings, [la], [], false).hitBy.get(la.label_id) : undefined;
      const fb = B && lb ? matchAudit(src, s, idl.version, B.findings, [lb], [], false).hitBy.get(lb.label_id) : undefined;
      const got = !fa || !fb ? 'undetected' : fb.vulnerability_id && fb.vulnerability_id === fa.vulnerability_id ? (fb.match_level === 'suspected' ? 'suspected' : 'same') : 'different';
      pairs.push({ sample_id: r.sample_id, repeat: r.repeat, label_id: idl.label_id, refactor: idl.refactor, expected: idl.expected, got });
    }
  }
  const metrics = (ps: typeof pairs) => {
    const d = ps.filter((p) => p.got !== 'undetected');
    const n = (pred: (p: (typeof pairs)[number]) => boolean) => d.filter(pred).length;
    return {
      pairs: ps.length, undetected: ps.length - d.length,
      exact_precision: ratio(n((p) => p.got === 'same' && p.expected === 'same'), n((p) => p.got === 'same')),
      exact_coverage: ratio(n((p) => p.got === 'same' && p.expected === 'same'), n((p) => p.expected === 'same')),
      suspected_precision: ratio(n((p) => p.got === 'suspected' && p.expected !== 'different'), n((p) => p.got === 'suspected')),
      suspected_recall: ratio(n((p) => p.expected === 'suspected' && p.got !== 'different'), n((p) => p.expected === 'suspected')),
      false_merge_rate: ratio(n((p) => p.expected === 'different' && p.got !== 'different'), n((p) => p.expected === 'different')),
      false_split_rate: ratio(n((p) => p.expected !== 'different' && p.got === 'different'), n((p) => p.expected !== 'different')),
    };
  };
  return { ...metrics(pairs), by_refactor: Object.fromEntries([...group(pairs, (p) => p.refactor)].map(([k, ps]) => [k, metrics(ps)])), details: pairs };
}

// ---- entry point -----------------------------------------------------------------------------------

export function readRun(runDir: string): { meta: RunMeta; records: RunRecord[] } {
  const metaPath = join(runDir, 'run.json');
  if (!existsSync(metaPath)) throw new EvalError('RUN_INVALID', `不是评测运行目录（缺少 run.json）：${runDir}`);
  const meta = readJson<RunMeta>(metaPath);
  if (!isFormat(meta.format, META_FORMAT)) throw new EvalError('RUN_INVALID', `run.json 格式不支持：${String(meta.format)}`);
  const records: RunRecord[] = [];
  const dir = join(runDir, 'samples');
  if (existsSync(dir)) {
    for (const sid of readdirSync(dir).sort(byString)) {
      for (const f of readdirSync(join(dir, sid)).filter((x) => /^r\d+\.json$/.test(x)).sort((a, b) => Number(a.slice(1, -5)) - Number(b.slice(1, -5)))) {
        const rec = readJson<RunRecord>(join(dir, sid, f));
        if (!isFormat(rec.format, RUN_FORMAT)) throw new EvalError('RUN_INVALID', `${sid}/${f} 格式不支持`);
        records.push(rec);
      }
    }
  }
  return { meta, records };
}

export async function scoreRunDir(runDir: string, benchRoot?: string, opts: { trees?: RemoteOptions } = {}) {
  const { meta, records } = readRun(runDir);
  const bench = loadBench(benchRoot ?? meta.bench.root);
  const samples = new Map(bench.samples.map((s) => [s.sample_id, s]));
  const src = new Sources(bench);
  // Remote trees come from the local cache the run filled (fetched again only if the cache was removed).
  const used = [...new Set(records.map((r) => r.sample_id))].map((id) => samples.get(id)).filter((s): s is Sample => !!s);
  const unfetched = await prepareTrees(bench, used, opts.trees);
  // Sources changed since the run → their labels/spans no longer describe what the product saw.
  const hasher = new TreeHasher();
  const invalid = new Map<string, string>();
  try {
    for (const r of records) {
      const s = samples.get(r.sample_id);
      if (!s) { invalid.set(r.sample_id, '样本已不在 manifest 中'); continue; }
      if (invalid.has(s.sample_id)) continue;
      if (unfetched.has(s.sample_id)) { invalid.set(s.sample_id, `远程仓库无法取得：${unfetched.get(s.sample_id)!.join('；')}`); continue; }
      for (const [version, tree] of sampleTrees(s)) {
        const want = new Map([...s.repos.map((x) => [x.name, x.root_hash] as const), ...(s.scene_input?.versions ?? []).filter((v) => v.name === version).flatMap((v) => v.repos.map((x) => [x.name, x.root_hash] as const))]);
        for (const [repo, ref] of tree) {
          const actual = isRemoteOrigin(ref.origin) ? bench.remote.get(remoteKey(ref))?.rootHash : await hasher.hash(treeDir(bench, ref)!);
          if (want.get(repo) !== actual) invalid.set(s.sample_id, `${version}/${repo} 的源码与 manifest 的 root_hash 不一致`);
        }
      }
      if (r.status === 'invalid') invalid.set(s.sample_id, '运行时快照与 manifest 不一致');
    }
  } finally {
    hasher.dispose();
  }
  const valid = records.filter((r) => !invalid.has(r.sample_id));
  const runs = valid.map((r) => scoreRun(src, bench, samples.get(r.sample_id)!, r));
  const quality = qualitySection(runs);
  const adjudication: Adjudication[] = [];
  for (const r of runs) {
    const rec = valid.find((x) => x.sample_id === r.sample_id && x.repeat === r.repeat)!;
    const all = rec.audits.flatMap((a) => a.findings);
    for (const f of r.findings.filter((x) => x.outcome === 'queue' || x.outcome === 'pending_queue')) {
      const fr = all.find((x) => x.id === f.finding_id)!;
      adjudication.push({
        sample_id: r.sample_id, project: r.project, label_policy: r.label_policy, repeat: r.repeat, reason: f.reason ?? '', key: f.key,
        finding: { title: fr.title, category: fr.category, cwe: fr.cwe, severity: fr.severity, repo: fr.repo, path: normPath(fr.path), start_line: fr.start_line, end_line: fr.end_line, entries: fr.entries, status: fr.status },
      });
    }
  }
  return {
    format: SCORE_FORMAT,
    run: { name: meta.name, partition: meta.partition, repeats: meta.repeats, bench_version: meta.bench.version, labels_hash: meta.bench.labels_hash, bench_commit: meta.bench.commit?.revision ?? null, code: meta.code, pi_version: meta.pi_version, models: { default: meta.config.default_model, cheap: meta.config.cheap_model }, config_sha256: meta.config.sha256, knowledge: meta.knowledge.skills.map((k) => k.name) },
    bench: { version: bench.manifest.bench_version, labels_hash: bench.labelsHash, decisions_hash: bench.decisionsHash, labels_changed_since_run: bench.labelsHash !== meta.bench.labels_hash },
    cache: meta.cache ?? null,
    cached_runs: valid.filter((r) => r.cache?.hit).length,
    invalid: Object.fromEntries([...invalid.entries(), ...Object.entries(meta.invalid).map(([k, v]) => [k, v.join('；')] as const)].sort((a, b) => byString(a[0], b[0]))),
    skipped: meta.skipped,
    stopped_reason: meta.stopped_reason,
    availability: availabilitySection(valid),
    quality,
    cost: costSection(valid, quality.counts.tp),
    stability: stabilitySection(runs, valid),
    traceability: traceabilitySection(valid),
    coverage: coverageSection(src, bench, samples, valid),
    risk_hunt: riskSection(src, bench, samples, valid),
    reverify: reverifySection(src, bench, samples, valid),
    incremental: incrementalSection(runs, valid),
    identity: identitySection(src, bench, samples, valid),
    // Stage telemetry (absent from scores written before it).
    stages: stagesSection(valid),
    adjudication,
    runs,
  };
}

/**
 * Coverage: mean entry / sink coverage of the audited versions; the labeled-sink hit rate
 * (labeled dangerous places — sink or an alternative — that the tree-sitter sink list contains, by the scorer's
 * own function locator); numerator accuracy (concluded targets that were actually read). Denominator
 * precision / recall needs complete hand-labeled entry and sink lists, which the benchmark does not have.
 */
function coverageSection(src: Sources, bench: Bench, samples: Map<string, Sample>, recs: RunRecord[]) {
  let labeled = 0, hit = 0, concluded = 0, concludedRead = 0;
  const entry: number[] = [], sink: number[] = [];
  const misses: { sample_id: string; label_id: string }[] = [];
  for (const r of recs) {
    const s = samples.get(r.sample_id);
    const base = r.audits.find((a) => a.role === 'base' && a.coverage);
    if (!s || !base?.coverage) continue;
    const c = base.coverage;
    if (c.entry.total) entry.push(c.entry.reviewed / c.entry.total);
    if (c.sink.total) sink.push(c.sink.reviewed / c.sink.total);
    concluded += c.concluded;
    concludedRead += c.concluded_read;
    for (const l of sampleLabels(bench, s).vuln) {
      labeled++;
      const found = [l.sink, ...(l.alt_sinks ?? [])].some((a) => c.sinks.some((x) => x.repo === a.repo && normPath(x.path) === normPath(a.file)
        && src.spans(s, base.version, a).some((sp) => ('start' in sp ? sp.start : 0) <= x.line && x.line <= ('end' in sp ? sp.end : 0))));
      if (found) hit++; else misses.push({ sample_id: r.sample_id, label_id: l.label_id });
    }
  }
  const mean = (xs: number[]) => (xs.length ? round(xs.reduce((a, b) => a + b, 0) / xs.length) : null);
  return {
    runs: entry.length || sink.length ? Math.max(entry.length, sink.length) : 0,
    entry_coverage: mean(entry), sink_coverage: mean(sink),
    labeled_sink_hit_rate: ratio(hit, labeled), labeled_sinks: labeled, missed: misses.slice(0, 30),
    numerator_accuracy: ratio(concludedRead, concluded),
  };
}

/**
 * G3: share of formal findings (canonical, not dismissed) whose evidence is verified,
 * whose submission is in the trajectory and whose decision source is recorded. Target 100%; failures listed.
 */
function traceabilitySection(recs: RunRecord[]) {
  const failures: { sample_id: string; repeat: number; finding: string; missing: string[] }[] = [];
  let findings = 0, traceable = 0, unknown = 0;
  for (const r of recs) {
    for (const a of r.audits) {
      for (const f of a.findings) {
        if (f.status === 'dismissed') continue;
        if (!f.trace) { unknown++; continue; }
        findings++;
        const missing = (['evidence', 'trajectory', 'source'] as const).filter((k) => !f.trace![k]);
        if (missing.length) failures.push({ sample_id: r.sample_id, repeat: r.repeat, finding: `${f.title} (${f.path}:${f.start_line})`, missing: [...missing] });
        else traceable++;
      }
    }
  }
  return { findings, traceable, ratio: ratio(traceable, findings), not_recorded: unknown, failures: failures.slice(0, 50) };
}

export type ScoreResult = Awaited<ReturnType<typeof scoreRunDir>>;
export type { LocatedLabel };
