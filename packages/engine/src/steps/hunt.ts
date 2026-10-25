// hunt: one session per candidate batch. Structured results only via submit_findings
// (+ optional submit_state_update). Evidence locations are path/range validated and the sink location
// must have been read in this audit.
import { Type } from 'typebox';
import { COGNITIVE_FIELDS, newId, PENDING_KINDS_NEEDING_CLUE, placeholderPendingIssues, SubmitFindings, SubmitHypothesisVerification, type PendingCondition, SubmitStateUpdate, type CodeRef, type FindingDraft, type HypothesisDraft, type HypothesisVerdictDraft, type ModelRef, type StateOp } from '@xiezhi/contracts';
import { overlapRatio } from '@xiezhi/context';
import type { AuditTool } from '@xiezhi/agent';
import { applyOps, loadState, saveState, sliceSummary, type CognitiveState } from '../cognitive.js';
import { confidenceTier, enrichFinding, verifyCodeRef } from '../identity.js';
import { insertConnectorEvidence, type ConnectorRef } from '../connector-access.js';
import type { AuditRuntime } from '../runtime.js';
import { sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { markConcluded } from '../coverage.js';
import { checkEvidence } from '../evidence.js';
import { candidateResolver, type Candidate } from './triage.js';
import { diffTool, renderFileDiff } from './scope.js';
import { insertHypotheses, type HypothesisRow } from '../business.js';
import { applyVerdicts, relatedOf, verdictIssues, verificationLines, type PriorConclusions } from '../threat.js';
import { linkedThreatModels, relatedRiskIssues, resolveRelatedRisk, withRelatedRisk } from '../threat-model-audit.js';
import { P } from '@xiezhi/knowledge';
import { addFactRefs } from '../facts.js';

/** A submitted finding with its knowledge references checked against what the step read. */
export type HuntFinding = FindingDraft & { knowledge?: KnowledgeRef[]; connectors?: ConnectorRef[]; facts?: string[] };
export interface KnowledgeRef { name: string; file: string | null; layer: string; verified: boolean }

export interface HuntOutput {
  batch: string[];
  findings: HuntFinding[];
  reviewedTargets: { targetKind: 'entry' | 'sink'; targetId: string; verdict: string }[];
  ruledOut: { targetKind: 'entry' | 'sink'; targetId: string; reason: string }[];
  scopeReviewed: string[];
  stateOps: StateOp[];
  /** Multi-model hunts: the model of this session (`provider/model`); default the audit model. */
  model?: string;
  /** hypotheses neither proven nor refuted (`open`) and refuted ones, with the refutation attempts. */
  hypotheses?: HypothesisDraft[];
  /** verdicts on the threat-model hypotheses of a verification batch (`HYP-B*`). */
  verdicts?: HypothesisVerdictDraft[];
  /** listed index candidates the session gave no verdict, even after being asked once. */
  unanswered?: string[];
}

export function validateCodeRef(rt: AuditRuntime, ref: CodeRef, label: string, mustBeRead: boolean): string[] {
  const repo = rt.repoByName(ref.repo);
  if (!repo) return [P('feedback.hunt.unknown_repo', { label, repo: String(ref.repo) })];
  const view = rt.views.get(repo.name);
  const v = verifyCodeRef(view, ref);
  if (!v.verified) return [`${label}: ${v.reason} (${ref.path}:${ref.startLine}-${ref.endLine})`];
  if (mustBeRead) {
    const ranges = rt.readRanges(repo.name, view!.guard(ref.path));
    if (overlapRatio(ranges, { startLine: ref.startLine, endLine: ref.endLine }) === 0) {
      return [P('feedback.hunt.not_read', { label, path: ref.path, startLine: ref.startLine, endLine: ref.endLine })];
    }
  }
  return [];
}

/**
 * Whether the range was returned by the read tool in this audit. Evidence and chain refs are
 * accepted without it, but only read ranges are stored as verified, so an unread segment keeps the finding's
 * evidence incomplete instead of passing as checked.
 */
export function wasRead(rt: AuditRuntime, ref: CodeRef): boolean {
  const repo = rt.repoByName(ref.repo);
  const view = repo ? rt.views.get(repo.name) : undefined;
  if (!repo || !view) return false;
  try {
    return overlapRatio(rt.readRanges(repo.name, view.guard(ref.path)), { startLine: ref.startLine, endLine: ref.endLine }) > 0;
  } catch {
    return false;
  }
}

/**
 * business_rule / config items of a pending condition need a clue: a location read in this
 * audit or an existing skill that suggests the unusual rule or configuration. Without one the item is a
 * common-sense rule or defence in depth, which is not a reason to be pending.
 */
export function pendingClueIssues(rt: AuditRuntime, p: PendingCondition | undefined, where: string): string[] {
  if (!p) return [];
  const needing = p.missing.filter((m) => (PENDING_KINDS_NEEDING_CLUE as readonly string[]).includes(m.kind));
  const bad = needing.filter((m) => {
    if (m.clue?.ref) return validateCodeRef(rt, m.clue.ref, `${where}.pendingCondition.clue`, true).length > 0;
    if (m.clue?.skill) return !rt.knowledge.skills.some((s) => s.name === m.clue!.skill);
    return true;
  });
  if (!bad.length) return [];
  return [P('feedback.hunt.pending_clue', { where, items: bad.map((m) => `${m.kind}“${m.ref}”`).join('、') })];
}

/** Index targets by id: entry points and sinks of every repository, with their file and key. */
/**
 * Findings carrying `sameAs`: each repeats an earlier finding, so it is dropped; a verdict that pointed at
 * it (`finding: i`) points at the earlier one (`sameAs`), later indexes shift down.
 */
export function dropRepeatedFindings<A extends { findings?: object[]; verdicts?: object[] }>(raw: A): { args: A; repeats: { i: number; id: string }[] } {
  // prune runs before the schema passed: a field sent as text (`"findings": "[{…"`) is left for the schema to refuse.
  if (!Array.isArray(raw.findings)) return { args: raw, repeats: [] };
  const repeats = raw.findings.map((f, i) => {
    const id = (f as { sameAs?: unknown } | null)?.sameAs;
    return typeof id === 'string' ? { i, id } : null;
  }).filter((x): x is { i: number; id: string } => !!x);
  if (!repeats.length) return { args: raw, repeats };
  const verdicts = (Array.isArray(raw.verdicts) ? raw.verdicts : []).map((v) => {
    const n = (v as { finding?: unknown } | null)?.finding;
    if (typeof n !== 'number') return v;
    const r = repeats.find((x) => x.i === n);
    if (r) { const { finding: _, ...rest } = v as { finding?: number }; return { ...rest, sameAs: r.id }; }
    return { ...v, finding: n - repeats.filter((x) => x.i < n).length };
  });
  return { args: { ...raw, findings: raw.findings.filter((_, i) => !repeats.some((r) => r.i === i)), verdicts }, repeats };
}

/** An entry id without the repository prefix, path parameters as `{}` (`:id`, `{id}`, `<id>` → `{}`). */
function bareTargetId(id: string, repos: string[]): { repo: string | null; key: string } {
  const m = /^([^:\s]+):(.+)$/.exec(id);
  const repo = m && repos.includes(m[1]!) ? m[1]! : null;
  // A route followed by a remark (`POST /login 暴力破解/枚举`, `POST /posts/:id/delete (CSRF)`) is that route.
  const route = /^((?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY|WS)\s+\S+)/i.exec((repo ? m![2]! : id).trim());
  const rest = route ? route[1]! : repo ? m![2]! : id;
  return { repo, key: rest.replace(/\{[^}]*\}|<[^>]*>|(?<=\/):[A-Za-z_]\w*/g, '{}').replace(/\s+/g, ' ').trim() };
}

/**
 * The listed target id a model meant: the one id whose bare form equals the given id's, in the given
 * repository if it names one; null when none or several match (several repositories with the same route).
 */
export function resolveTargetId(known: Iterable<string>, id: string, repos: string[]): string | null {
  const all = [...known];
  // A sink written as its location (`rs-files:src/handlers.rs:32 Command sh -c` for `rs-files:src/handlers.rs#L32:24:cmdi`).
  const loc = /^(?:([^:\s]+):)?([^\s:#]+\.[A-Za-z0-9]+):(\d+)\b/.exec(id.trim());
  if (loc && (!loc[1] || repos.includes(loc[1]))) {
    const file = (k: string) => k.split('#')[0]!;
    const hits = all.filter((k) => k.includes(`#L${loc[3]}:`) && (loc[1] ? file(k) === `${loc[1]}:${loc[2]}` : file(k).endsWith(`:${loc[2]}`)));
    if (hits.length === 1) return hits[0]!;
  }
  const want = bareTargetId(id, repos);
  const hits = all.filter((k) => { const b = bareTargetId(k, repos); return b.key === want.key && (!want.repo || b.repo === want.repo); });
  return hits.length === 1 ? hits[0]! : null;
}

function indexTargets(rt: AuditRuntime): Map<string, { repo: string; path: string; key: string }> {
  const known = new Map<string, { repo: string; path: string; key: string }>();
  for (const [repo, idx] of rt.indexes) {
    for (const e of idx.entrypoints) known.set(e.entryId, { repo, path: e.path, key: e.entryKey });
    for (const k of idx.sinks) known.set(k.sinkId, { repo, path: k.path, key: k.sinkId });
  }
  return known;
}

/**
 * Targets concluded as `finding` that no finding of the same call covers (by sink id, entry id or key, or a location /
 * chain step in the target's file). For the hunt such a call is refused — the verdict would stand while the
 * vulnerability itself is lost; a domain expert's verdict is downgraded to `suspicious` instead.
 */
export function uncoveredFindingTargets(rt: AuditRuntime, a: { findings: FindingDraft[]; reviewedTargets: { targetId: string; verdict?: string }[] }): string[] {
  const known = indexTargets(rt);
  const norm = (s: string) => s.replace(/\{[^}]*\}/g, '{}').replace(/\/:[A-Za-z_]\w*/g, '/{}').trim();
  const out: string[] = [];
  for (const t of a.reviewedTargets) {
    const target = known.get(t.targetId);
    if (t.verdict !== 'finding' || !target) continue;
    const covered = a.findings.some((f) => f.sink?.sinkId === t.targetId
      || f.entries.some((e) => e === t.targetId || norm(e).endsWith(norm(target.key)))
      || [f.location, ...f.chain].some((r) => (r.repo ?? target.repo) === target.repo && r.path === target.path));
    if (!covered) out.push(t.targetId);
  }
  return out;
}

/** Prefix of the issue `validateFindings` raises for an uncovered `finding` verdict (filtered for domain experts). */
export const UNCOVERED_FINDING_PREFIX = 'reviewedTargets ';

export function validateFindings(rt: AuditRuntime, a: { findings: FindingDraft[]; reviewedTargets: { targetId: string; verdict?: string }[]; ruledOut: { targetId: string }[]; hypotheses?: HypothesisDraft[] }): string[] {
  const issues: string[] = [];
  // Hypotheses point at code the session actually read, like finding locations.
  (a.hypotheses ?? []).forEach((h, i) => issues.push(...validateCodeRef(rt, h.location, `hypotheses[${i}].location`, true)));
  const targets = new Set(rt.targets.map((r) => r.name));
  a.findings.forEach((f, i) => {
    issues.push(...validateCodeRef(rt, f.location, `findings[${i}].location`, true));
    // Related / context repositories are evidence only: a finding lands in a target repository.
    if (f.location.repo && !targets.has(f.location.repo) && rt.repoByName(f.location.repo)) {
      issues.push(P('feedback.hunt.related_repo', { i, repo: f.location.repo, targets: [...targets].join(' / ') }));
    }
    f.evidence.forEach((e, j) => issues.push(...validateCodeRef(rt, e, `findings[${i}].evidence[${j}]`, false)));
    f.chain.forEach((e, j) => issues.push(...validateCodeRef(rt, e, `findings[${i}].chain[${j}]`, false)));
    if (f.missingCheck) issues.push(...validateCodeRef(rt, f.missingCheck.location, `findings[${i}].missingCheck.location`, true));
    // Unified threshold: a confirmed finding states a workable attack path, its impact and its
    // preconditions; otherwise it can only be pending (saying what is missing) or not submitted.
    if (f.verdict === 'confirmed') {
      const weak = [
        ...((f.attackPath ?? '').trim().length < 20 ? [P('feedback.hunt.weak_attack_path')] : []),
        ...((f.impact ?? '').trim().length < 6 ? [P('feedback.hunt.weak_impact')] : []),
        ...(f.exploitConditions.length === 0 ? [P('feedback.hunt.weak_exploit_conditions')] : []),
      ];
      if (weak.length) issues.push(P('feedback.hunt.confirmed_weak', { i, fields: weak.join('、') }));
    }
    if (f.verdict === 'pending') {
      if (!f.pendingCondition) issues.push(P('feedback.hunt.pending_condition', { i }));
      issues.push(...placeholderPendingIssues(f.pendingCondition, `findings[${i}]`), ...pendingClueIssues(rt, f.pendingCondition, `findings[${i}]`));
    }
  });
  const known = indexTargets(rt);
  for (const t of [...a.reviewedTargets, ...a.ruledOut]) if (!known.has(t.targetId)) issues.push(P('feedback.hunt.unknown_target', { id: t.targetId }));
  // A target concluded as `finding` must be backed by a finding in the same call; otherwise the verdict
  // is recorded while the vulnerability itself is silently lost.
  for (const id of uncoveredFindingTargets(rt, a)) issues.push(`${UNCOVERED_FINDING_PREFIX}${P('feedback.hunt.uncovered_finding', { id })}`);
  return issues.slice(0, 30);
}

export interface HuntOptions {
  /** `coverage-gap` sessions are hunts over uncovered targets with extra context. */
  kind?: 'hunt' | 'coverage-gap';
  /** Lines placed before the candidate list (why these targets, prior context). */
  preface?: string[];
  /** Multi-model hunts: this session's model; its agent state stays separate (`statePrefix`). */
  model?: ModelRef;
  /** The cross-check slot key (`provider/model`, `#n` when the group repeats a model) recorded as the output's model. */
  modelKey?: string;
  /** The stage's model when not cross-reviewing (logic review, deep exploration); default the hunt model. */
  stageModel?: ModelRef;
  /** Only agent state items whose lineage starts with this prefix are shown (independent sessions per model). */
  statePrefix?: string;
  /** a per-entry logic review batch (hypothesis-first prompt). */
  logic?: boolean;
  /** a verification batch of threat-model hypotheses (`HYP-B*`); each needs exactly one verdict. */
  hypotheses?: HypothesisRow[];
  /** the bottom-up hunt's conclusions on the batch's places, reusable by `sameAs` (see priorConclusions). */
  prior?: PriorConclusions;
}

/** A cognitive-state view without the other models' agent items (独立会话). */
export function stateFor(state: CognitiveState, prefix: string | undefined): CognitiveState {
  if (!prefix) return state;
  return Object.fromEntries(Object.entries(state).map(([f, items]) => [f, items.filter((i) => i.source !== 'agent' || i.id.startsWith(prefix))])) as CognitiveState;
}

/**
 * the audit's cognitive state on demand — the session is shown only a summary (`sliceSummary`). Reads the
 * current state each call (other sessions keep adding to it), limited to this session's own items like the slice.
 */
export function stateQueryTool(rt: AuditRuntime, prefix: string | undefined): AuditTool {
  return {
    name: 'state_query', kind: 'read',
    description: P('tool.state_query'),
    parameters: Type.Object({
      field: Type.Optional(Type.Union(COGNITIVE_FIELDS.map((f) => Type.Literal(f)))),
      path: Type.Optional(Type.String({ maxLength: 500, description: 'Only items mentioning this file' })),
      text: Type.Optional(Type.String({ maxLength: 200, description: 'Only items containing this text' })),
      limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 50 })),
    }, { additionalProperties: false }),
    run(a: { field?: (typeof COGNITIVE_FIELDS)[number]; path?: string; text?: string; limit?: number }) {
      const state = stateFor(loadState(rt.store, rt.auditId).state, prefix);
      const fields = a.field ? [a.field] : [...COGNITIVE_FIELDS];
      const hits = fields.flatMap((f) => state[f].filter((i) => !i.retired)
        .filter((i) => (!a.path || i.text.includes(a.path) || !!i.evidence?.some((e) => e.path === a.path)) && (!a.text || i.text.includes(a.text)))
        .map((i) => `- [${f}·${i.id}] ${i.text}`));
      const limit = a.limit ?? 30;
      return { text: hits.length ? [...hits.slice(0, limit), ...(hits.length > limit ? [`…另有 ${hits.length - limit} 条`] : [])].join('\n') : '（没有匹配的条目）' };
    },
  };
}

/** Concurrent `task` sub-agents per hunt session; each also needs one of the audit's session slots. */
export const TASK_PARALLEL = 2;
/** How long a sub-agent waits for a session slot before the parent is told to investigate itself (tests shorten it). */
export const taskSlot = { waitMs: 20_000 };

/**
 * `task` sub-agent: the hunt session hands one focused question to a child session with the same
 * model, read-only tools and data boundary. The child cannot submit or spawn children; its summary goes back
 * to the parent, which submits. Usage counts against the parent step; at most TASK_PARALLEL run at once, the rest queue.
 */
/** `scope`: the repository the dispatching session works on, and whether its sub-agents stay in it. */
/** The `itemId=<key>` line of a checklist fill's scopeReviewed for an item, or null. */
export function checklistConclusion(scope: string, key: string): string | null {
  return scope.split('\n').map((l) => l.trim()).find((l) => l.includes(`itemId=${key}`) || l.includes(`itemId=\`${key}\``)) ?? null;
}

export function taskTool(rt: AuditRuntime, ctx: AttemptContext, model: ModelRef, scope: { repo?: string; ownRepoOnly?: boolean } = {}): AuditTool {
  let running = 0;
  // Calls beyond TASK_PARALLEL wait for a running one to finish: models dispatch several tasks in one turn without
  // knowing the limit, and a refusal cost them another full-context turn just to send the same tasks again.
  const waiters: (() => void)[] = [];
  const turn = (signal?: AbortSignal) => new Promise<void>((ok, fail) => {
    if (signal?.aborted) { fail(new Error('aborted')); return; }
    const go = () => { signal?.removeEventListener('abort', stop); ok(); };
    const stop = () => { const i = waiters.indexOf(go); if (i >= 0) waiters.splice(i, 1); fail(new Error('aborted')); };
    signal?.addEventListener('abort', stop, { once: true });
    waiters.push(go);
  });
  return {
    name: 'task', kind: 'read',
    parameters: Type.Object({
      goal: Type.String({ minLength: 10, maxLength: 2000, description: 'One focused investigation: what to find out and where to start' }),
      files: Type.Optional(Type.Array(Type.String({ maxLength: 500 }), { maxItems: 10, description: 'Files to start from' })),
    }, { additionalProperties: false }),
    description: P('tool.task'),
    async run(a: { goal: string; files?: string[] }, signal) {
      while (running >= TASK_PARALLEL) await turn(signal ?? ctx.signal);
      running++;
      try {
        const outcome = await rt.session({
          stepId: ctx.stepId, attempt: ctx.attempt, kind: 'hunt', phase: 'hunt', model, signal: signal ?? ctx.signal,
          prompt: [
            P('hunt.task.intro'),
            '', `## 问题\n${a.goal}`, ...(a.files?.length ? ['', `## 起点文件\n${a.files.join('\n')}`] : []),
          ].join('\n'),
          submitTools: [], requiredSubmits: [], maxTurns: Math.min(30, rt.strategy.limits.maxTurnsPerStep),
          task: { goal: a.goal, ...(a.files?.length ? { files: a.files } : {}), waitMs: taskSlot.waitMs },
          ...(scope.repo ? { repo: scope.repo } : {}), ...(scope.ownRepoOnly ? { ownRepoOnly: true } : {}),
        });
        if (outcome.status !== 'completed' && !outcome.finalText) throw new Error(P('feedback.task.no_summary', { status: outcome.status }));
        return { text: `${P('hunt.task.result_note')}\n${outcome.finalText.slice(0, 8000)}` };
      } finally {
        running--;
        waiters.shift()?.();
      }
    },
  };
}

/** A threat-model hypothesis as a progress-mark target: marked by its id, it has no index location. */
function hypothesisMark(h: HypothesisRow): Candidate {
  return { id: h.id, kind: 'hypothesis', repo: '', path: relatedOf(h).files[0] ?? '', line: 0, label: h.statement, score: h.priority ?? 0 };
}

/** Ids a submission gives a verdict to: reviewed, ruled out, or the sink / an entry of a finding (as settleCandidates). */
function answeredIds(s: { findings: FindingDraft[]; reviewedTargets: { targetId: string }[]; ruledOut: { targetId: string }[] }): string[] {
  return [...s.reviewedTargets.map((t) => t.targetId), ...s.ruledOut.map((t) => t.targetId), ...s.findings.flatMap((f) => [f.sink?.sinkId, ...f.entries].filter((x): x is string => !!x))];
}

/** how many unanswered ids the follow-up lists. */
const UNANSWERED_LISTED = 40;

/**
 * the follow-up a hunt session gets when its submission leaves listed index candidates
 * without a verdict. The session is asked once; what stays open is recorded and left to ⑨ coverage completion.
 */
export function unansweredPrompt(ids: string[]): string {
  return [
    P('nudge.hunt.unanswered', { n: ids.length }),
    ...ids.slice(0, UNANSWERED_LISTED).map((id) => `- \`${id}\``),
    ...(ids.length > UNANSWERED_LISTED ? [`- ……另有 ${ids.length - UNANSWERED_LISTED} 个`] : []),
    P('nudge.hunt.unanswered_ask'),
  ].join('\n');
}

/** Statuses the Agent reports per candidate; the final verdicts come from submit_findings. */
export const CANDIDATE_MARKS = ['investigating', 'finding', 'suspicious', 'no_issue', 'ruled_out'] as const;

/**
 * `mark_candidate`: the Agent reports its verdict on one candidate as soon as it has one, so
 * the progress of a batch is visible while the session runs. Progress only: submit_findings stays authoritative.
 */
function markTool(rt: AuditRuntime, ctx: AttemptContext, listed: Candidate[]): AuditTool {
  const resolve = candidateResolver(listed);
  return {
    name: 'mark_candidate', kind: 'meta',
    parameters: Type.Object({
      candidateId: Type.String({ minLength: 1, maxLength: 512, description: 'The candidate id exactly as listed' }),
      status: Type.Union(CANDIDATE_MARKS.map((m) => Type.Literal(m)), { description: 'investigating when you start on it; finding / suspicious / no_issue / ruled_out once you have a verdict' }),
      note: Type.Optional(Type.String({ maxLength: 300, description: 'One sentence: why' })),
    }, { additionalProperties: false }),
    description: P('tool.mark_candidate'),
    run(a: { candidateId: string; status: (typeof CANDIDATE_MARKS)[number]; note?: string }) {
      const id = resolve(a.candidateId);
      if (!id) throw new Error(P('feedback.hunt.mark_unknown', { id: a.candidateId }));
      rt.event('candidate.marked', { candidate: id, status: a.status, ...(a.note ? { note: a.note.slice(0, 300) } : {}) }, ctx.stepId);
      return { text: P('feedback.hunt.mark_recorded') };
    },
  };
}

/**
 * After the submission is accepted: one `candidate.settled` per listed candidate with the final verdict;
 * where the Agent's last progress mark said otherwise, the change is kept (`changedFrom`).
 */
export function settleCandidates(rt: AuditRuntime, stepId: string, listed: string[], out: HuntOutput): void {
  if (!listed.length) return;
  const final = new Map<string, { status: string; note?: string }>();
  for (const t of out.reviewedTargets) final.set(t.targetId, { status: ['finding', 'suspicious'].includes(t.verdict) ? t.verdict : 'no_issue' });
  for (const t of out.ruledOut) final.set(t.targetId, { status: 'ruled_out', note: t.reason.slice(0, 300) });
  for (const f of out.findings) for (const id of [f.sink?.sinkId, ...f.entries]) if (id && listed.includes(id)) final.set(id, { status: 'finding' });
  const VERDICT: Record<string, string> = { confirmed: 'finding', refuted: 'ruled_out', open: 'suspicious' };
  for (const v of out.verdicts ?? []) final.set(v.hypothesisId, { status: VERDICT[v.status] ?? 'unreviewed', note: v.reason.slice(0, 300) });
  const last = new Map<string, string>();
  for (const e of rt.store.listEvents(rt.auditId, 0, ['candidate.marked'])) if (e.stepId === stepId) last.set(String(e.payload.candidate), String(e.payload.status));
  for (const id of listed) {
    const f = final.get(id) ?? { status: 'unreviewed' };
    const before = last.get(id);
    rt.event('candidate.settled', { candidate: id, status: f.status, ...(f.note ? { note: f.note } : {}), ...(before && before !== 'investigating' && before !== f.status ? { changedFrom: before } : {}) }, stepId);
  }
}

export async function huntStep(rt: AuditRuntime, batch: Candidate[], lineage: string, ctx: AttemptContext, opts: HuntOptions = {}): Promise<StepResult> {
  const { state } = loadState(rt.store, rt.auditId);
  const hyps = opts.hypotheses ?? [];
  /** Hypotheses with a verdict in an accepted earlier submit_findings call of this session. */
  const verdicted = new Set<string>();
  /** candidate ids given a verdict by accepted calls. */
  const answered = new Set<string>();
  // Listed items that are not index targets (checklist, scanner, exploration, changed files) are shown as `repo:path:line`;
  // models still put them in reviewedTargets / ruledOut although the prompt says not to. Such entries are dropped, not
  // refused: the batch settles these items itself, and refusing cost whole attempts (seen with claude-haiku-5-5).
  const notTargets = new Set([
    ...batch.filter((c) => c.kind === 'change' || /^(checklist|external|explore):/.test(c.id))
      .flatMap((c) => [c.id, `${c.repo}:${c.path}:${c.line}`, `${c.repo}:${c.path}`, c.path]),
    // listed hypotheses written into reviewedTargets (their verdicts go in `verdicts`).
    ...hyps.map((h) => h.id),
  ]);
  const submitFindings: AuditTool = {
    name: 'submit_findings', kind: 'submit', parameters: linkedThreatModels(rt).length ? withRelatedRisk(hyps.length ? SubmitHypothesisVerification : SubmitFindings) : hyps.length ? SubmitHypothesisVerification : SubmitFindings,
    prune: (raw: { findings?: FindingDraft[]; verdicts?: HypothesisVerdictDraft[]; reviewedTargets?: { targetId: string }[]; ruledOut?: { targetId: string }[] }) => {
      // a finding carrying `sameAs` (the verdict field) says it repeats an earlier finding — seen with
      // claude-haiku-5-5, refused by the schema three times. The repeat is dropped and the verdicts that pointed at it
      // point at the earlier finding instead.
      const { args: a, repeats } = dropRepeatedFindings(raw);
      const known = indexTargets(rt);
      // an entry written without its repository prefix or with named path parameters
      // (`GET /files/{id}/owner` for `rs-files:GET /files/{}/owner`) is the listed one when exactly one matches.
      const fixed: string[] = [];
      const fix = <T extends { targetId: string }>(t: T): T => {
        if (known.has(t.targetId) || notTargets.has(t.targetId)) return t;
        const id = resolveTargetId(known.keys(), t.targetId, rt.repos.map((r) => r.name));
        if (!id) return t;
        fixed.push(`${t.targetId} → ${id}`);
        return { ...t, targetId: id };
      };
      // items that are not objects (or a list sent as text) are left for the schema to refuse.
      const items = <T,>(x: T[] | undefined): T[] | null => (x === undefined ? [] : Array.isArray(x) && x.every((t) => t && typeof t === 'object') ? x : null);
      const reviewedIn = items(a.reviewedTargets);
      const ruledIn = items(a.ruledOut);
      if (!reviewedIn || !ruledIn) return null;
      const reviewed = reviewedIn.map(fix);
      const ruled = ruledIn.map(fix);
      const drop = (t: { targetId: string }) => !known.has(t.targetId) && notTargets.has(t.targetId);
      const dropped = [...reviewed, ...ruled].filter(drop).map((t) => t.targetId);
      if (!dropped.length && !fixed.length && !repeats.length) return null;
      return {
        args: { ...a, reviewedTargets: reviewed.filter((t) => !drop(t)), ruledOut: ruled.filter((t) => !drop(t)) },
        note: [
          ...(dropped.length ? [P('feedback.hunt.not_targets_dropped', { ids: [...new Set(dropped)].join(', ').slice(0, 400) })] : []),
          ...(fixed.length ? [P('feedback.hunt.target_ids_resolved', { ids: fixed.join(', ').slice(0, 400) })] : []),
          ...(repeats.length ? [P('feedback.hunt.finding_same_as', { ids: repeats.map((r) => `findings[${r.i}] → ${r.id}`).join(', ').slice(0, 400) })] : []),
        ].join('\n'),
      };
    },
    description: hyps.length
      ? P('tool.submit_findings.hypotheses')
      : P('tool.submit_findings.hunt'),
    validate: (a) => [
      ...validateFindings(rt, a),
      ...relatedRiskIssues(rt, a.findings as { relatedRisk?: string }[]),
      ...(hyps.length ? verdictIssues(hyps, (a as { verdicts?: HypothesisVerdictDraft[] }).verdicts ?? [], a.findings.length, (ref, label, read) => validateCodeRef(rt, ref, label, read), verdicted, opts.prior) : []),
      ...checklistIssues((a as { scopeReviewed?: string }).scopeReviewed),
    ].slice(0, 30),
    run: (a: { findings: FindingDraft[]; reviewedTargets: { targetId: string }[]; ruledOut: { targetId: string }[]; verdicts?: HypothesisVerdictDraft[] }) => {
      for (const v of a.verdicts ?? []) verdicted.add(v.hypothesisId);
      for (const id of answeredIds(a)) answered.add(id);
      return { text: `accepted ${a.findings.length} finding(s)` };
    },
  };
  const submitState: AuditTool = {
    name: 'submit_state_update', kind: 'submit', parameters: SubmitStateUpdate,
    description: P('tool.submit_state_update.hunt'),
    run: () => ({ text: 'recorded' }),
  };
  // A checklist fill concludes item by item (one `itemId=` line each in scopeReviewed), not in one summary.
  const checklistKeys = batch.filter((c) => c.id.startsWith('checklist:')).map((c) => c.id.slice('checklist:'.length));
  const checklistIssues = (scope: string | undefined) => {
    const missing = checklistKeys.filter((k) => !checklistConclusion(scope ?? '', k));
    return missing.length ? [P('feedback.hunt.checklist_unanswered', { ids: missing.join(', ') })] : [];
  };
  const indexed = batch.filter((c) => c.kind !== 'change');
  // the index candidates this batch owes a verdict on (variant / exploration targets are not listed in reviewedTargets).
  const known = indexTargets(rt);
  const owed = hyps.length ? [] : indexed.filter((c) => !c.id.startsWith('explore:') && known.has(c.id)).map((c) => c.id);
  const missingOwed = () => owed.filter((id) => !answered.has(id));
  const changeFiles = batch.filter((c) => c.kind === 'change' && !/^(checklist|external|explore):/.test(c.id));
  const listing = [
    ...indexed.map((c) => `- id=\`${c.id}\`\n  位置：${c.repo}:${c.path}:${c.line}\n  ${c.label}${c.reason ? `\n  初筛：${c.llmScore}/5 ${c.reason}` : ''}`),
    ...changeFiles.map((c) => `- 变更文件：${c.repo}:${c.path}  ${c.label}`),
  ].join('\n');
  // Incremental: the diff of the batch's changed files is part of the input,
  // and a `diff` tool gives the rest; callers of changed code are traced with grep/read.
  // Each candidate's diff comes from its own repository's impact set.
  const impacts = rt.audit.scene === 'incremental' ? rt.impacts() : null;
  const impact = impacts?.size ? impacts : null;
  const changedIn = (repo: string, p: string) => {
    const c = impacts?.get(repo)?.changedFiles;
    return !!c && !impacts!.get(repo)!.fallbackReasons.includes('no_baseline') && (c.added.includes(p) || c.modified.includes(p) || c.renamed.some((r) => r.to === p));
  };
  const diffs = impact ? [...new Map(batch.map((c) => [`${c.repo}:${c.path}`, c])).values()].filter((c) => changedIn(c.repo, c.path)).map((c) => renderFileDiff(rt, c.path, undefined, c.repo)) : [];
  // Deep-explore directions: a target chosen by the decide round, not an indexed candidate.
  const exploreCands = batch.filter((c) => c.id.startsWith('explore:'));
  const exploreLines = exploreCands.length ? [
    '', P('hunt.explore_directions'),
    ...exploreCands.map((c) => `- ${c.repo}:${c.path}:${c.line}  ${c.label}`),
  ] : [];
  // checklist items the check left uncovered (not ledger units: reviewedTargets does not list them).
  // imported scanner results triaged as true positives, investigated here.
  const externalCands = batch.filter((c) => c.id.startsWith('external:'));
  const externalLines = externalCands.length ? ['', P('hunt.external_items'), ...externalCands.map((c) => `- ${c.repo}:${c.path}:${c.line}  ${c.label}`)] : [];
  const checklistCands = batch.filter((c) => c.id.startsWith('checklist:'));
  const checklistLines = checklistCands.length ? [
    '', P('hunt.checklist_items'),
    ...checklistCands.map((c) => `- itemId=\`${c.id.slice('checklist:'.length)}\`（从 ${c.repo}:${c.path} 开始）${c.label}`),
  ] : [];
  const incrementalLines = impact ? [
    '',
    P('hunt.incremental.intro'),
    ...(indexed.length === 0 ? [P('hunt.incremental.no_index')] : []),
    '', P('hunt.incremental.diff_heading'), diffs.length ? P('hunt.incremental.diff_attached') : P('hunt.incremental.no_diff'),
  ] : [];
  const prompt = hyps.length ? [
    ...(opts.preface ?? []),
    ...verificationLines(hyps, opts.prior),
    '',
    P('hunt.verify.submit'),
  ].join('\n') : [
    ...(opts.preface ?? []),
    // “以下 N 个候选” only when candidates are listed; batches of listed items alone say so.
    indexed.length + changeFiles.length ? P('hunt.batch.intro', { n: indexed.length + changeFiles.length }) : P('hunt.batch.intro_items', { n: batch.length }),
    ...(indexed.length ? [P('hunt.batch.mark')] : []),
    P('hunt.batch.submit'),
    '',
    listing,
    ...incrementalLines,
    ...exploreLines,
    ...checklistLines,
    ...externalLines,
  ].join('\n');
  const model = opts.model ?? opts.stageModel ?? rt.strategy.models.audit;
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: opts.kind ?? 'hunt', phase: 'hunt', model, signal: ctx.signal,
    prompt, submitTools: [submitFindings, submitState], requiredSubmits: ['submit_findings'], maxTurns: rt.strategy.limits.maxTurnsPerStep,
    extraTools: [...(impact ? [diffTool(rt, impact)] : []), taskTool(rt, ctx, model), stateQueryTool(rt, opts.statePrefix), ...(indexed.length || hyps.length ? [markTool(rt, ctx, [...indexed, ...hyps.map(hypothesisMark)])] : [])],
    // a summary of the cognitive state; the rest through state_query.
    cognitiveSlice: sliceSummary(stateFor(state, opts.statePrefix), [...batch.map((c) => c.path), ...hyps.flatMap((h) => relatedOf(h).files)]), askUser: true,
    // what the batch pushed, for the push-usage telemetry.
    pushed: [{ kind: 'candidate', ids: batch.map((c) => c.id) }, { kind: 'hypothesis', ids: hyps.map((h) => h.id) }],
    knowledgeNeeds: state.knowledgeNeeds.filter((k) => !k.retired).map((k) => ({ topic: k.text })),
    // The diffs are audited content — scanned and wrapped in the data boundary after the prompt.
    ...(diffs.length ? { untrustedPrompt: [{ source: 'diff', text: diffs.join('\n') }] } : {}),
    ...(owed.length ? {
      completionCheck: () => {
        const left = missingOwed();
        if (!left.length) return null;
        rt.event('judgement.made', { kind: 'candidates_unanswered', phase: 'asked', count: left.length, ids: left.slice(0, 50) }, ctx.stepId);
        return unansweredPrompt(left);
      },
    } : {}),
  });
  const err = sessionError(outcome);
  if (err) throw err;
  // A later call was rejected too often; the accepted calls stand, the rest stays unreviewed.
  if (outcome.contractShortfall) {
    rt.event('contract.violation', { tool: 'submit_findings', attempt: 0, issues: [`accepted submissions kept; the rejected call is dropped and the candidates it would have covered stay unreviewed: ${outcome.contractShortfall.slice(0, 400)}`] }, ctx.stepId);
  }
  const subs = (outcome.submissions.submit_findings ?? []) as HuntOutput[];
  const ops = ((outcome.submissions.submit_state_update ?? []) as { ops: StateOp[] }[]).flatMap((s) => s.ops);
  const out: HuntOutput = {
    // The model that produced the findings: the cross model, or the stage's fallback once the step switched.
    // Under cross-checking the slot key, so a model chosen twice counts as two runs.
    ...(rt.fallbacks.has(ctx.stepId) ? { model: `${rt.modelFor(ctx.stepId, model).provider}/${rt.modelFor(ctx.stepId, model).model}` }
      : opts.model ? { model: opts.modelKey ?? `${opts.model.provider}/${opts.model.model}` } : {}),
    batch: batch.map((c) => c.id),
    findings: subs.flatMap((s) => s.findings).map((f) => ({ ...f, knowledge: rt.knowledgeRefs(ctx.stepId, f.knowledgeRefs), connectors: rt.connectorRefs(ctx.stepId, f.connectorRefs), facts: rt.factRefs(ctx.stepId, f.factRefs) })),
    reviewedTargets: subs.flatMap((s) => s.reviewedTargets),
    ruledOut: subs.flatMap((s) => s.ruledOut),
    scopeReviewed: subs.map((s) => s.scopeReviewed as unknown as string),
    stateOps: ops,
    ...(!hyps.length && subs.some((x) => x.hypotheses?.length) ? { hypotheses: subs.flatMap((x) => x.hypotheses ?? []) } : {}),
    ...(hyps.length ? { verdicts: verdictsOf(subs) } : {}),
  };
  const unanswered = owed.filter((id) => !new Set(subs.flatMap(answeredIds)).has(id));
  if (unanswered.length) {
    out.unanswered = unanswered;
    rt.event('judgement.made', { kind: 'candidates_unanswered', phase: 'left', count: unanswered.length, ids: unanswered.slice(0, 50) }, ctx.stepId);
  }
  const outputRef = rt.store.artifacts.putJson(out);
  return { outputRef, apply: () => { applyHunt(rt, ctx.stepId, lineage, out, opts.prior); settleCandidates(rt, ctx.stepId, [...indexed.map((c) => c.id), ...hyps.map((h) => h.id)], out); } };
}

/**
 * Verdicts of all calls, with `finding` rebased onto the merged findings list (each call indexes its own findings).
 * A later verdict for the same hypothesis replaces an earlier one.
 */
export function verdictsOf(subs: (HuntOutput & { verdicts?: HypothesisVerdictDraft[] })[]): HypothesisVerdictDraft[] {
  const byId = new Map<string, HypothesisVerdictDraft>();
  let offset = 0;
  for (const s of subs) {
    for (const v of s.verdicts ?? []) byId.set(v.hypothesisId, v.finding !== undefined ? { ...v, finding: v.finding + offset } : v);
    offset += s.findings.length;
  }
  return [...byId.values()];
}

/** The pending condition that counts: only with verdict `pending`. */
function pendingOfDraft(d: FindingDraft): PendingCondition | null {
  return d.verdict === 'pending' ? d.pendingCondition ?? null : null;
}

/** With verdict `confirmed`, conditions the model listed anyway stay visible as unconfirmed exploit conditions. */
export function exploitConditionsOf(d: FindingDraft): FindingDraft['exploitConditions'] {
  if (d.verdict !== 'confirmed' || !d.pendingCondition) return d.exploitConditions;
  const extra = d.pendingCondition.holdsIf.map((c) => ({ condition: c.statement.slice(0, 1000), status: 'unconfirmed' as const, source: `模型列出的前提（结论已确认）：${d.pendingCondition!.missing.map((m) => m.ref).join('、')}`.slice(0, 500) }));
  return [...d.exploitConditions, ...extra].slice(0, 20);
}

export function applyHunt(rt: AuditRuntime, stepId: string, lineage: string, out: HuntOutput, prior?: PriorConclusions): void {
  const store = rt.store;
  const findingIds: string[] = [];
  out.findings.forEach((d, i) => {
    const repo = rt.repoByName(d.location.repo)!;
    const idx = rt.identityIndex(repo.name);
    const view = rt.views.get(repo.name)!;
    const e = enrichFinding(d, repo.id, idx);
    const findingId = newId('finding');
    findingIds.push(findingId);
    const loc = { repo: repo.name, path: view.guard(d.location.path), startLine: d.location.startLine, endLine: d.location.endLine };
    const detail = {
      evidence: d.evidence.map((x) => ({ ...x, repo: x.repo ?? repo.name })), chain: d.chain.map((x) => ({ ...x, repo: x.repo ?? repo.name })),
      reasoning: d.reasoning, counterCheck: d.counterCheck, exploitConditions: exploitConditionsOf(d), remediation: d.remediation,
      attackPath: d.attackPath, impact: d.impact,
      ...(d.missingCheck ? { missingCheck: { ...d.missingCheck, location: { ...d.missingCheck.location, repo: d.missingCheck.location.repo ?? repo.name } } } : {}),
      // what the engine could check about the chain, for the adversarial review.
      evidenceCheck: checkEvidence({ ...d, category: e.category }, idx, repo.name),
      ...(pendingOfDraft(d) ? { pendingCondition: pendingOfDraft(d) } : {}),
      ...(d.knowledge?.length ? { knowledgeRefs: d.knowledge } : {}),
      ...(d.connectors?.length ? { connectorRefs: d.connectors } : {}),
      ...(d.facts?.length ? { factRefs: d.facts } : {}),
      ...((d as { boundary?: string }).boundary ? { boundary: (d as { boundary?: string }).boundary } : {}),
    };
    store.insert('finding', {
      id: findingId, audit_id: rt.auditId, step_id: stepId, lineage_id: `${lineage}-F${i + 1}`, repository_id: repo.id,
      category: e.category, cwe: e.cwe, title: d.title, severity: d.severity, confidence: confidenceTier(d.confidence), confidence_score: d.confidence,
      module: e.module, sink_symbol: e.sinkSymbol, sink_api: e.sinkApi, entry_keys: e.entryKeys, root_cause: d.rootCause, location: loc,
      fp_sink: e.fpSink, fp_entry: e.fpEntry, detail_ref: store.artifacts.putJson(detail), source: 'ai', model: out.model ?? `${rt.strategy.models.audit.provider}/${rt.strategy.models.audit.model}`,
      state: 'submitted', confirmation: pendingOfDraft(d) ? 'pending' : 'maintain',
      // the requirement risk the finding relates to.
      related_risk: resolveRelatedRisk(rt, (d as { relatedRisk?: string }).relatedRisk)?.id ?? null,
    });
    const refs: [CodeRef, 'code_range' | 'call_chain_segment'][] = [[d.location, 'code_range'], ...d.evidence.map((x): [CodeRef, 'code_range'] => [x, 'code_range']), ...d.chain.map((x): [CodeRef, 'call_chain_segment'] => [x, 'call_chain_segment']),
      ...(d.missingCheck ? [[{ ...d.missingCheck.location, note: `应有的检查：${d.missingCheck.expected}`.slice(0, 1000) }, 'code_range'] as [CodeRef, 'code_range']] : [])];
    refs.forEach(([ref, kind], ord) => {
      const r = rt.repoByName(ref.repo) ?? repo;
      const v = verifyCodeRef(rt.views.get(r.name), ref);
      store.insert('evidence', {
        id: newId('evidence'), owner_kind: 'finding', owner_id: findingId, kind, snapshot_id: r.snapshotId, path: ref.path,
        start_line: ref.startLine, end_line: ref.endLine, content_hash: v.contentHash, verified: v.verified && wasRead(rt, ref) ? 1 : 0, step_id: stepId,
        note: ref.note ?? null, ord, origin_label: ord === 0 ? 'sink' : kind,
      });
    });
    // Knowledge the conclusion cites is recorded as evidence of kind `knowledge`; unverified knowledge stays
    // unverified and never counts towards evidence completeness.
    (d.knowledge ?? []).forEach((k, i) => store.insert('evidence', {
      id: newId('evidence'), owner_kind: 'finding', owner_id: findingId, kind: 'knowledge', snapshot_id: null, path: `${k.layer}:${k.name}${k.file ? `/${k.file}` : ''}`,
      verified: k.verified ? 1 : 0, step_id: stepId, note: k.verified ? null : '未核实的知识，只能作为推测', ord: refs.length + i, origin_label: 'knowledge',
    }));
    insertConnectorEvidence(store, 'finding', findingId, d.connectors ?? [], stepId, refs.length + (d.knowledge?.length ?? 0));
    // the facts it relies on; a later change of a fact marks this finding for reverification.
    if (d.facts?.length) addFactRefs(store, rt.auditId, findingId, d.facts);
    rt.event('finding.submitted', { finding_id: findingId, category: e.category, severity: d.severity, title: d.title, confidence: d.confidence }, stepId);
    // Findings conclude their anchors.
    if (e.sinkId) markConcluded(rt, 'sink', e.sinkId, stepId, 'finding', findingId);
    for (const ent of d.entries) {
      const hit = idx?.entrypoints.find((x) => x.entryId === ent || x.entryKey === ent);
      if (hit) markConcluded(rt, 'entry', hit.entryId, stepId, 'finding', findingId);
    }
  });
  if (out.hypotheses?.length) insertHypotheses(rt, stepId, out.hypotheses);
  if (out.verdicts?.length) applyVerdicts(rt, stepId, out.verdicts, findingIds, prior, out.model ?? `${rt.strategy.models.audit.provider}/${rt.strategy.models.audit.model}`);
  for (const t of out.reviewedTargets) markConcluded(rt, t.targetKind, t.targetId, stepId, t.verdict);
  for (const t of out.ruledOut) markConcluded(rt, t.targetKind, t.targetId, stepId, `ruled_out: ${t.reason.slice(0, 200)}`);
  if (out.stateOps.length) {
    const { version, state } = loadState(store, rt.auditId);
    const res = applyOps(state, out.stateOps, stepId, lineage, (ev) => validateCodeRef(rt, ev, 'evidence', false).length === 0);
    saveState(store, rt.auditId, version + 1, stepId, res.state);
    rt.event('state.updated', { version: version + 1, ops: out.stateOps.length, rejected: res.rejected.map((r) => r.reason) }, stepId);
  }
}
