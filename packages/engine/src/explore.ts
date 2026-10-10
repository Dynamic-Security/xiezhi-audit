// Deep exploration (`stages.deepExplore`; after VulnHunter's decide spiral). As ⑪
// it runs after reconcile and only works on what is uncertain — breadth is the coverage-gap round's job. Three
// pools in `work_item`: todo (user deep-dive requests, risk hypotheses left undetermined, findings with a model
// conflict, single-source findings, pending findings), leads (open hypotheses and questions of the cognitive
// state), done (with outcome). Each round a fresh
// `decide` session picks ONE direction and the step to derive; the engine runs it and writes back. The
// decide contract carries no facts and no findings (evidence gate): those only come from execution steps.
import { domainHuntOn, lastOpenLeads } from './domains.js';
import { EXPLORE_DIRECTION_ROUNDS } from './estimates.js';
import { newId, SubmitDecision, type SubmitDecision as Decision, stageModel } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import { fromJson } from '@xiezhi/store';
import { loadState, renderSlice } from './cognitive.js';
import type { AuditRuntime } from './runtime.js';
import { sessionError, type AttemptContext, type StepResult } from './step-runner.js';
import type { Candidate, TriageOutput } from './steps/triage.js';
import { P } from '@xiezhi/knowledge';

export interface WorkItem {
  id: string; audit_id: string; pool: 'todo' | 'leads' | 'done'; kind: string; lineage_id: string; parent_id: string | null; title: string; target: string;
  priority: number; round: number; created_by_step: string | null; closed_by_step: string | null; outcome: string | null;
}
export interface WorkTarget { repo?: string; path?: string; line?: number; symbol?: string; candidateId?: string; findingId?: string }

/** Rounds without new facts, hypotheses, coverage or findings before the loop stops early. */
export const STAGNATION_ROUNDS = 3;
const PRIORITY = { user: 50, entry: 40, finding: 35, sink: 30, hypothesis: 20, candidate: 10, question: 5 } as const;

export function workItems(rt: AuditRuntime, pool?: WorkItem['pool']): WorkItem[] {
  return pool
    ? rt.store.all<WorkItem>('SELECT * FROM work_item WHERE audit_id = ? AND pool = ? ORDER BY priority DESC, created_at, id', rt.auditId, pool)
    : rt.store.all<WorkItem>('SELECT * FROM work_item WHERE audit_id = ? ORDER BY priority DESC, created_at, id', rt.auditId);
}

function addItem(rt: AuditRuntime, it: { id?: string; pool: WorkItem['pool']; kind: keyof typeof PRIORITY | 'direction'; title: string; target: WorkTarget; round: number; lineage: string; parent?: string | null; stepId?: string | null }): string {
  const id = it.id ?? newId('workItem');
  rt.store.insert('work_item', {
    id, audit_id: rt.auditId, pool: it.pool, kind: it.kind, lineage_id: it.lineage, parent_id: it.parent ?? null, title: it.title.slice(0, 300), target: it.target,
    priority: it.kind === 'direction' ? 25 : PRIORITY[it.kind], round: it.round, created_by_step: it.stepId ?? null,
  });
  return id;
}

/**
 * Seed the pools once (resume-safe) with the uncertain items after reconcile: user deep-dive requests,
 * undetermined risk hypotheses, canonical findings with a cross-model conflict, single-source findings and pending
 * findings, plus the leads of the cognitive state.
 */
export function seedPools(rt: AuditRuntime, _triage?: TriageOutput): void {
  if (rt.store.get('SELECT id FROM work_item WHERE audit_id = ? LIMIT 1', rt.auditId)) return;
  rt.store.tx(() => {
    rt.store.listEvents(rt.auditId, 0, ['intervention.received']).filter((e) => e.payload.kind === 'deep_dive').forEach((e, i) =>
      addItem(rt, { pool: 'todo', kind: 'user', title: `用户要求深入：${String(e.payload.text ?? '').slice(0, 200)}`, target: {}, round: 0, lineage: `SEED-U${i + 1}` }));
    const hyps = rt.store.all<{ id: string; statement: string; location: string | null; attempts: string }>(
      `SELECT id, statement, location, attempts FROM hypothesis WHERE audit_id = ? AND origin = 'threat_model' AND status = 'open' ORDER BY COALESCE(priority, 0) DESC, created_at LIMIT 50`, rt.auditId);
    hyps.forEach((h, i) => {
      const l = fromJson<{ repo?: string; path?: string; startLine?: number }>(h.location, {});
      addItem(rt, { pool: 'todo', kind: 'hypothesis', title: `无法判定的风险假设：${h.statement}（${h.attempts.slice(0, 120)}）`, target: { ...(l.repo ? { repo: l.repo } : {}), ...(l.path ? { path: l.path, line: l.startLine ?? 1 } : {}) }, round: 0, lineage: `SEED-H${i + 1}` });
    });
    // directions the domain experts' last rounds left open.
    lastOpenLeads(rt).forEach(({ domain, lead }, i) => {
      const [path] = lead.files;
      addItem(rt, { pool: 'todo', kind: 'direction', title: `领域专家（${domain}）留下的方向：${lead.direction}`, target: path ? { path, line: 1 } : {}, round: 0, lineage: `SEED-D${i + 1}` });
    });
    const findings = rt.store.all<{ id: string; title: string; location: string; confirmation: string; detail_ref: string }>(
      `SELECT id, title, location, confirmation, detail_ref FROM finding WHERE audit_id = ? AND state = 'canonical' ORDER BY display_no`, rt.auditId);
    let n = 0;
    for (const f of findings) {
      const c = (rt.store.artifacts.getJson<{ consensus?: { singleSource?: boolean; conflicts?: unknown[] } }>(f.detail_ref).consensus) ?? {};
      const why = c.conflicts?.length ? '模型之间有冲突' : c.singleSource ? '只有一个模型发现' : f.confirmation === 'pending' ? '待确认' : null;
      if (!why) continue;
      const l = fromJson<{ repo?: string; path: string; startLine: number }>(f.location, { path: '', startLine: 1 });
      addItem(rt, { pool: 'todo', kind: 'finding', title: `${why}：${f.title}`, target: { findingId: f.id, ...(l.repo ? { repo: l.repo } : {}), path: l.path, line: l.startLine }, round: 0, lineage: `SEED-F${++n}` });
    }
    syncLeads(rt, 0, null);
  });
}

/** Rounds of the on-demand exploration of the experts' directions at most. */
export const AUTO_EXPLORE_ROUNDS = EXPLORE_DIRECTION_ROUNDS;

/**
 * How ⑪ runs: `full` when the strategy turns deep exploration on (the decide loop over everything
 * uncertain); `directions` when it is off by the scene default only (no layer chose `stages.deepExplore`) and the
 * domain experts' last rounds left directions open — up to AUTO_EXPLORE_ROUNDS of them, nothing else; else off.
 */
export function exploreMode(rt: AuditRuntime): 'full' | 'directions' | null {
  const planned = plannedExploreMode(rt);
  return planned === 'directions' ? (lastOpenLeads(rt).length ? 'directions' : null) : planned;
}

/**
 * How ⑪ may run, as far as the plan can tell: the same rule as `exploreMode`, except that the experts'
 * open directions are not known yet — the on-demand exploration is assumed to run (the estimate is an upper bound).
 */
export function plannedExploreMode(rt: AuditRuntime): 'full' | 'directions' | null {
  const s = rt.strategy;
  if (s.stages.deepExplore) return s.limits.maxRounds > 0 ? 'full' : null;
  if (!domainHuntOn(rt)) return null;
  const src = (JSON.parse(rt.audit.strategy_sources || '{}') as Record<string, string>)['stages.deepExplore'];
  if (src !== undefined && src !== 'system') return null;
  return 'directions';
}

/**
 * The directions of the on-demand exploration, seeded once (resume-safe): the experts' open directions,
 * taking one domain after another in turn so the first rounds spread over the domains; at most AUTO_EXPLORE_ROUNDS.
 */
export function seedDirections(rt: AuditRuntime): WorkItem[] {
  if (!rt.store.get('SELECT id FROM work_item WHERE audit_id = ? LIMIT 1', rt.auditId)) {
    const byDomain = new Map<string, { domain: string; lead: { direction: string; files: string[] } }[]>();
    for (const l of lastOpenLeads(rt)) (byDomain.get(l.domain) ?? byDomain.set(l.domain, []).get(l.domain)!).push(l);
    const lists = [...byDomain.values()];
    const picked: { domain: string; lead: { direction: string; files: string[] } }[] = [];
    for (let i = 0; picked.length < AUTO_EXPLORE_ROUNDS && lists.some((l) => l.length > i); i++) {
      for (const l of lists) if (l[i] && picked.length < AUTO_EXPLORE_ROUNDS) picked.push(l[i]!);
    }
    rt.store.tx(() => picked.forEach(({ domain, lead }, i) => {
      const [path] = lead.files;
      addItem(rt, { pool: 'todo', kind: 'direction', title: `领域专家（${domain}）留下的方向：${lead.direction}`, target: path ? { path, line: 1 } : {}, round: 0, lineage: `SEED-D${i + 1}` });
    }));
  }
  return rt.store.all<WorkItem>(`SELECT * FROM work_item WHERE audit_id = ? AND lineage_id LIKE 'SEED-D%' ORDER BY CAST(SUBSTR(lineage_id, 7) AS INTEGER)`, rt.auditId);
}

/** Open hypotheses and questions of the cognitive state become leads (once each). */
export function syncLeads(rt: AuditRuntime, round: number, stepId: string | null): number {
  const { state } = loadState(rt.store, rt.auditId);
  const known = new Set(rt.store.all<{ target: string }>(`SELECT target FROM work_item WHERE audit_id = ? AND kind IN ('hypothesis','question')`, rt.auditId).map((r) => fromJson<{ stateId?: string }>(r.target, {}).stateId));
  let added = 0;
  for (const [field, kind] of [['activeHypotheses', 'hypothesis'], ['pendingQuestions', 'question']] as const) {
    for (const i of state[field].filter((x) => !x.retired && !known.has(x.id))) {
      addItem(rt, { pool: 'leads', kind, title: i.text, target: { ...(i.evidence?.[0] ? { path: i.evidence[0].path, line: i.evidence[0].startLine, ...(i.evidence[0].repo ? { repo: i.evidence[0].repo } : {}) } : {}), stateId: i.id } as WorkTarget, round, lineage: i.id, stepId });
      added++;
    }
  }
  return added;
}

/**
 * Progress signature for stagnation detection: facts + hypotheses, covered targets, findings. Files read are
 * not counted — almost every round reads something new, so with them the 3-rounds-without-progress stop rarely fired.
 */
export function progress(rt: AuditRuntime): string {
  const { state } = loadState(rt.store, rt.auditId);
  const facts = state.confirmedFacts.length + state.activeHypotheses.length + state.ruledOutDirections.length;
  const covered = rt.store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM coverage_item WHERE audit_id = ? AND status = 'concluded'`, rt.auditId)!.n;
  const findings = rt.store.get<{ n: number }>('SELECT COUNT(*) AS n FROM finding WHERE audit_id = ?', rt.auditId)!.n;
  return `${facts}/${covered}/${findings}`;
}

export interface DecideOutput { round: number; decision: Decision; itemId: string; target: WorkTarget; title: string }

export async function decideStep(rt: AuditRuntime, round: number, ctx: AttemptContext): Promise<StepResult> {
  const todo = workItems(rt, 'todo');
  const leads = workItems(rt, 'leads');
  const done = workItems(rt, 'done');
  const findings = rt.store.all<{ id: string; title: string; confirmation: string }>(`SELECT id, title, confirmation FROM finding WHERE audit_id = ? AND state = 'canonical' ORDER BY display_no`, rt.auditId);
  const open = new Map([...todo, ...leads].map((i) => [i.id, i]));
  const repoNames = new Set(rt.repos.map((r) => r.name));
  /**
   * Real models often fill every optional field: an invented itemId next to a complete new direction, a
   * findingId on a hunt, a repository hash instead of its name. A given direction wins over an itemId that is
   * not listed; findingId only matters for challenge (a listed finding id put in itemId is moved there);
   * an unknown repository falls back to the audited one.
   */
  const normalizeDecision = (a: Decision): Decision => {
    const d: Decision = { ...a };
    if (d.itemId && !open.has(d.itemId)) {
      if (d.action === 'challenge' && !d.findingId && findings.some((f) => f.id === d.itemId)) { d.findingId = d.itemId; delete d.itemId; }
      else if (d.direction && !done.some((x) => x.id === d.itemId)) delete d.itemId;
    }
    if (d.action === 'challenge' && d.itemId && !open.has(d.itemId) && findings.some((f) => f.id === d.findingId)) delete d.itemId;
    if (d.action !== 'challenge') delete d.findingId;
    const repo = d.direction?.target.repo;
    if (d.direction && repo && !repoNames.has(repo)) {
      const alias = rt.repos.find((r) => r.id === repo || r.rootHash === repo || r.snapshotId === repo);
      const { repo: _drop, ...rest } = d.direction.target;
      d.direction = { ...d.direction, target: alias ? { ...rest, repo: alias.name } : rest };
    }
    return d;
  };
  const submit: AuditTool = {
    name: 'submit_decision', kind: 'submit', parameters: SubmitDecision,
    description: P('tool.submit_decision'),
    validate: (raw: Decision) => {
      if (raw.stop) return [];
      const a = normalizeDecision(raw);
      const issues: string[] = [];
      const valid = open.size ? P('feedback.decide.open_ids', { ids: [...open.keys()].slice(0, 8).join(', ') }) : P('feedback.decide.no_open');
      if (a.itemId && !open.has(a.itemId)) issues.push(done.some((d) => d.id === a.itemId) ? P('feedback.decide.already_done', { itemId: a.itemId, valid }) : P('feedback.decide.unknown_item', { itemId: a.itemId, valid }));
      if (!a.itemId && !a.direction && a.action !== 'challenge') issues.push(P('feedback.decide.need_target'));
      if (!a.itemId && a.direction && a.action !== 'challenge') {
        const same = done.find((x) => sameTarget(fromJson<WorkTarget>(x.target, {}), a.direction!.target));
        if (same) issues.push(P('feedback.decide.explored', { title: same.title, outcome: same.outcome ?? '' }));
      }
      if (a.action === 'challenge' && !findings.some((f) => f.id === a.findingId)) issues.push(findings.length ? P('feedback.decide.challenge_finding', { ids: findings.slice(0, 8).map((f) => f.id).join(', ') }) : P('feedback.decide.challenge_no_findings'));
      return issues;
    },
    run: () => ({ text: 'decision recorded' }),
  };
  const line = (i: WorkItem) => {
    const t = fromJson<WorkTarget>(i.target, {});
    return `- id=\`${i.id}\` [${i.kind}] ${i.title}${t.path ? `（${t.repo ? `${t.repo}:` : ''}${t.path}${t.line ? `:${t.line}` : ''}）` : ''}`;
  };
  const { state } = loadState(rt.store, rt.auditId);
  const prompt = [
    P('decide.intro', { round, maxRounds: rt.strategy.limits.maxRounds }),
    `${P('decide.fill', { repos: [...repoNames].join('、') })}${open.size ? '' : P('decide.fill_empty')}`,
    '', `## 待办（${todo.length}）`, ...todo.slice(0, 25).map(line), ...(todo.length > 25 ? [`- …另有 ${todo.length - 25} 项`] : []),
    '', `## 线索（${leads.length}）`, ...leads.slice(0, 15).map(line),
    '', `## 已完成（${done.length}）`, ...done.slice(-10).map((i) => `- [${i.kind}] ${i.title} → ${i.outcome ?? ''}`),
    '', `## 已提交的发现（${findings.length}）`, ...findings.slice(0, 20).map((f) => `- id=\`${f.id}\` ${f.title}${f.confirmation === 'pending' ? '（待确认）' : ''}`),
  ].join('\n');
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'decide', phase: 'hunt', model: stageModel(rt.strategy, 'explore')!, signal: ctx.signal,
    prompt, submitTools: [submit], requiredSubmits: ['submit_decision'], maxTurns: Math.min(12, rt.strategy.limits.maxTurnsPerStep),
    cognitiveSlice: renderSlice(state, []),
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const decision = normalizeDecision((outcome.submissions.submit_decision as Decision[]).at(-1)!);
  const picked = decision.itemId ? open.get(decision.itemId) : undefined;
  const target: WorkTarget = picked ? fromJson<WorkTarget>(picked.target, {}) : decision.direction ? { ...decision.direction.target } : {};
  if (decision.action === 'challenge' && decision.findingId) target.findingId = decision.findingId;
  // A new direction gets its item id now, so the recorded output names the item the round will close.
  const newItem = !decision.stop && !picked && decision.direction ? newId('workItem') : null;
  const out: DecideOutput = { round, decision, itemId: picked?.id ?? newItem ?? '', target, title: picked?.title ?? decision.direction?.title ?? '' };
  const outputRef = rt.store.artifacts.putJson(out);
  return {
    outputRef,
    apply: () => {
      if (newItem && decision.direction) {
        addItem(rt, { id: newItem, pool: 'todo', kind: 'direction', title: decision.direction.title, target, round, lineage: `R${round}-D`, stepId: ctx.stepId });
      }
      rt.event('judgement.made', { kind: 'decide', round, action: decision.action, stop: !!decision.stop, item: out.itemId, title: out.title.slice(0, 200), rationale: decision.rationale.slice(0, 300) }, ctx.stepId);
    },
  };
}

/** The hunt candidate a decision points at: the listed candidate itself, or an explore target. */
export function exploreCandidate(rt: AuditRuntime, d: DecideOutput, byId: Map<string, Candidate>): Candidate | null {
  if (d.target.candidateId && byId.has(d.target.candidateId)) return byId.get(d.target.candidateId)!;
  if (!d.target.path) return null;
  const repo = d.target.repo ?? rt.targetRepo.name;
  return { id: `explore:R${d.round}:${repo}:${d.target.path}#L${d.target.line ?? 1}`, kind: 'change', repo, path: d.target.path, line: d.target.line ?? 1, label: `[explore${d.decision.action === 'read' ? ' · 补读' : ''}] ${d.title}`, score: 1 };
}

/** The place of a finding a decision points at (an uncertain finding): investigated like a direction. */
export function findingCandidate(rt: AuditRuntime, d: DecideOutput): Candidate | null {
  if (!d.target.findingId) return null;
  const f = rt.store.get<{ location: string; title: string }>('SELECT location, title FROM finding WHERE id = ?', d.target.findingId);
  if (!f) return null;
  const l = fromJson<{ repo?: string; path: string; startLine: number }>(f.location, { path: '', startLine: 1 });
  if (!l.path) return null;
  const repo = l.repo ?? rt.targetRepo.name;
  return { id: `explore:R${d.round}:${repo}:${l.path}#L${l.startLine}`, kind: 'change', repo, path: l.path, line: l.startLine, label: `[explore · 不确定的发现] ${f.title}`, score: 1 };
}

/** Same file and symbol (or same line when neither names a symbol), in the same repository when both say. */
function sameTarget(a: WorkTarget, b: { repo?: string; path: string; line?: number; symbol?: string }): boolean {
  if (!a.path || a.path !== b.path) return false;
  if (a.repo && b.repo && a.repo !== b.repo) return false;
  if (a.symbol || b.symbol) return a.symbol === b.symbol;
  return (a.line ?? 1) === (b.line ?? 1);
}

export function closeItem(rt: AuditRuntime, itemId: string, stepId: string | null, outcome: string): void {
  if (itemId) rt.store.update('work_item', { id: itemId }, { pool: 'done', closed_by_step: stepId, outcome: outcome.slice(0, 500) });
}
