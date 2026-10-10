// 风险假设先行: a `threat-model` step lists, from the project profile / threat model and the
// entry index, the risks the repository may face (at most `limits.maxCandidates`), stored as `proposed`
// hypotheses. `HYP-B*` hunt batches then verify each one against the code: `confirmed` (with the finding that
// proves it), `refuted` or `open`, always with a reason and the code location the verdict rests on. Hypotheses
// left `proposed` (budget, failures) are a declared coverage gap. Gated by `strategy.stages.threatHypotheses`,
// or by a supplement audit (追加执行) started on a finished audit.
import { AccessPolicyDraft, newId, stageModel, SubmitThreatModel, VULN_CATEGORIES, type AuditStrategy, RiskDomainDraft, type ModelRef, type CodeRef, type EntryPoint, type HypothesisVerdictDraft, type ImpactSet, type ThreatHypothesisDraft } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import type { AuditRuntime, RepoInfo } from './runtime.js';
import { sessionError, type AttemptContext, type StepResult } from './step-runner.js';
import { renderThreatModel, type ProfileOutput } from './steps/profile.js';
import { logicEntries, type HypothesisRow } from './business.js';
import { domainHuntOn } from './domains.js';
import { validateCodeRef } from './steps/hunt.js';
import { P } from '@xiezhi/knowledge';

/** Bump when the threat-model prompt changes. */
// 3: access policy (submit_access_policy).
export const THREAT_PROMPT_VERSION = 3;
/** Hypotheses per verification batch. */
export const HYP_BATCH = 5;

export const threatHypothesesOn = (s: AuditStrategy): boolean => s.stages.threatHypotheses === true;

// ---- supplements (追加执行 on a finished audit) -------------------------------------------------------

export type SupplementKind = 'logic_review' | 'threat_hypotheses' | 'domains';
export interface SupplementScope {
  auditId: string;
  kind: SupplementKind;
  /** threat_hypotheses only: verify these `proposed` hypotheses of the source audit instead of listing new ones. */
  hypothesisIds?: string[];
  /** domains: the source audit's late domains (added after its expert phase) this supplement runs. */
  domainIds?: string[];
}

export function supplementScope(rt: AuditRuntime): SupplementScope | null {
  return fromJson<{ supplement?: SupplementScope }>(rt.audit.scope, {}).supplement ?? null;
}

/** Audit ids whose hypotheses are shown with `auditId`: itself and its supplements. */
export function hypothesisAuditIds(store: Store, auditId: string): string[] {
  const subs = store.all<{ id: string }>(
    `SELECT id FROM audit WHERE base_audit_id = ? AND json_extract(scope, '$.supplement.auditId') = ? ORDER BY created_at`, auditId, auditId);
  return [auditId, ...subs.map((s) => s.id)];
}

/**
 * What the analysis should focus on in an incremental setting: the audit's own impact set, or — for a
 * supplement of an incremental audit — the source audit's. Null = the whole repository.
 */
export function analysisFocus(rt: AuditRuntime): { changedFiles: string[]; affectedEntries: Set<string> } | null {
  const sup = supplementScope(rt);
  const auditId = sup ? sup.auditId : rt.auditId;
  const scene = sup ? rt.store.get<{ scene: string }>('SELECT scene FROM audit WHERE id = ?', sup.auditId)?.scene : rt.audit.scene;
  if (scene !== 'incremental') return null;
  const row = rt.store.get<{ output_ref: string }>(`SELECT output_ref FROM step WHERE audit_id = ? AND kind = 'scope' AND status = 'succeeded' ORDER BY seq DESC LIMIT 1`, auditId);
  if (!row) return null;
  const impact = rt.store.artifacts.getJson<ImpactSet>(row.output_ref);
  if (impact.mode === 'full_scan') return null;
  const c = impact.changedFiles;
  return { changedFiles: [...c.added, ...c.modified, ...c.renamed.map((r) => r.to)], affectedEntries: new Set(impact.affectedEntrypoints) };
}

// ---- threat-model step ----------------------------------------------------------------------------

/** The profile of `repo` this audit produced, else the latest one of the repository (any version). */
export function profileFor(rt: AuditRuntime, repo: RepoInfo): ProfileOutput | null {
  const rows = rt.store.all<{ output_ref: string; audit_id: string }>(
    `SELECT output_ref, audit_id FROM step WHERE kind = 'profile' AND status IN ('succeeded','skipped') AND output_ref IS NOT NULL ORDER BY (audit_id = ?) DESC, created_at DESC LIMIT 30`, rt.auditId);
  for (const r of rows) {
    const out = rt.store.artifacts.getJson<ProfileOutput>(r.output_ref);
    if (out.repositoryId === repo.id) return out;
  }
  return null;
}

function entryLine(e: EntryPoint, affected: boolean): string {
  return `- ${affected ? '[受变更影响] ' : ''}${e.entryKey} → ${e.handler}（${e.path}:${e.range.startLine}）${e.authSignals.length ? ` auth=[${e.authSignals.join(', ')}]` : ' auth=[]'}${e.middlewares.length ? ` mw=[${e.middlewares.join(', ')}]` : ''}`;
}

const MAX_ENTRY_LINES = 300;

/** The model of the threat model and the verification: the “风险假设” (logic) stage's model. */
export const hypothesisModel = (rt: AuditRuntime): ModelRef => stageModel(rt.strategy, 'logic')!;

/** `slot`: the cross-check slot key when the threat stage runs crossed — a model chosen twice runs twice. */
export function threatIdentity(rt: AuditRuntime, repo: RepoInfo, model: ModelRef = hypothesisModel(rt), slot?: string) {
  // A threat model that also plans the risk domains, or lists no hypotheses, is a different output.
  return {
    repo: repo.id, root: repo.rootHash, model: slot ?? `${model.provider}/${model.model}`, v: THREAT_PROMPT_VERSION, max: rt.strategy.limits.maxCandidates,
    ...(domainHuntOn(rt) ? { domains: true, hypotheses: threatHypothesesOn(rt.strategy) } : {}),
  };
}

/** Entries the threat model must go through one by one (the former logic review). */
const MAX_LOGIC_ENTRIES = 60;

/** What a threat-model session needs: its task text, submit tools, required submits, and how its submissions become the step's result. */
export interface ThreatSpec {
  lines: string[];
  tools: AuditTool[];
  required: string[];
  finish(submissions: Record<string, unknown[]>, stepId: string): StepResult;
}

/**
 * The threat model's task and contract (shared by the threat-model step and the system-understanding session).
 * `combined`: inside the system-understanding session — no profile yet (the same session writes it), and code is read
 * through sub-agents.
 */
export function threatSpec(rt: AuditRuntime, repo: RepoInfo, model: ModelRef, opts: { combined?: boolean } = {}): ThreatSpec {
  const max = rt.strategy.limits.maxCandidates;
  const profile = opts.combined ? null : profileFor(rt, repo);
  const idx = rt.indexes.get(repo.name);
  const focus = analysisFocus(rt);
  const entries = (idx?.entrypoints ?? []) as EntryPoint[];
  const ordered = focus ? [...entries.filter((e) => focus.affectedEntries.has(e.entryId)), ...entries.filter((e) => !focus.affectedEntries.has(e.entryId))] : entries;
  const view = rt.views.get(repo.name)!;
  const mustConsider = logicEntries(idx, MAX_LOGIC_ENTRIES, focus?.affectedEntries);
  // With the domain hunt the threat model also splits the system into risk domains; without 风险假设先行
  // it lists no hypotheses (the risk points go into the domains as leads for the experts).
  const domainsOn = domainHuntOn(rt);
  const hypothesesOn = threatHypothesesOn(rt.strategy);
  const submit: AuditTool = {
    name: 'submit_threat_model', kind: 'submit', parameters: SubmitThreatModel,
    description: domainsOn
      ? (hypothesesOn ? P('tool.submit_threat_model.domains_hypotheses', { max }) : P('tool.submit_threat_model.domains'))
      : P('tool.submit_threat_model.hypotheses', { max }),
    validate: (a: { hypotheses: ThreatHypothesisDraft[]; domains?: RiskDomainDraft[] }) => [
      ...(a.hypotheses.length > max ? [P('feedback.threat.max_hypotheses', { max })] : []),
      ...(a.domains ?? []).flatMap((d, i) => d.mechanisms.flatMap((m, j) => validateCodeRef(rt, { ...m.location, repo: m.location.repo || repo.name }, `domains[${i}].mechanisms[${j}].location`, true))),
    ].slice(0, 30),
    run: (a: { hypotheses: unknown[]; domains?: unknown[] }) => ({ text: `recorded ${a.hypotheses.length} hypotheses${a.domains ? `, ${a.domains.length} domains` : ''}` }),
  };
  // one domain per call — a flat object is short enough not to be cut off by the output limit, and models
  // that turn a nested array argument into a JSON string (seen with gemini) still send a valid object.
  const submitDomain: AuditTool = {
    name: 'submit_risk_domain', kind: 'submit', parameters: RiskDomainDraft,
    description: P('tool.submit_risk_domain'),
    validate: (d: RiskDomainDraft) => d.mechanisms.flatMap((m, j) => validateCodeRef(rt, { ...m.location, repo: m.location.repo || repo.name }, `mechanisms[${j}].location`, true)).slice(0, 30),
    run: (d: RiskDomainDraft) => ({ text: `recorded domain ${d.name}` }),
  };
  // the access policy, one group per call; the engine compares it with the index.
  const submitPolicy: AuditTool = {
    name: 'submit_access_policy', kind: 'submit', parameters: AccessPolicyDraft,
    description: P('tool.submit_access_policy'),
    validate: (g: AccessPolicyDraft) => (g.level === 'role' && !g.role ? [P('feedback.threat.policy_role')] : []),
    run: (g: AccessPolicyDraft) => ({ text: `recorded access group ${g.scope}` }),
  };
  const domainLines = domainsOn ? [
    '', P('threat.domains', { categories: VULN_CATEGORIES.join('、'), leadsOverlap: hypothesesOn ? P('threat.domains.leads_overlap') : '' }),
    '', P('threat.access_policy'),
  ] : [];
  const lines = [
    hypothesesOn
      ? P('threat.intro.hypotheses')
      : P('threat.intro.domains'),
    `仓库：${repo.name}；文件 ${view.manifest.stats.fileCount} 个；语言 ${JSON.stringify(view.manifest.stats.byLang)}。`,
    ...domainLines,
    '',
    hypothesesOn ? P('threat.req.heading_hypotheses') : P('threat.req.heading_leads'),
    P('threat.req.rules', { limit: hypothesesOn ? P('threat.req.limit_hypotheses', { max }) : P('threat.req.limit_leads') }),
    ...(hypothesesOn ? [
      P('threat.req.hypothesis_fields'),
    ] : [P('threat.req.lead_fields')]),
    opts.combined
      ? P('threat.req.read_by_task')
      : P('threat.req.read_self'),
    P('threat.req.untrusted'),
    ...(focus ? ['', P('threat.focus', { n: focus.changedFiles.length }), `变更文件：${focus.changedFiles.slice(0, 80).join('、') || '（无）'}${focus.changedFiles.length > 80 ? ' …' : ''}`] : []),
    ...(opts.combined ? [''] : [
      '',
      '## 项目画像与威胁模型',
      profile ? renderThreatModel(profile.profile, 6000) : P('threat.no_profile'),
      '',
    ]),
    ...(mustConsider.length ? [
      P('threat.must_consider', { n: mustConsider.length, listAs: hypothesesOn ? P('threat.must_consider.as_hypothesis') : P('threat.must_consider.as_lead') }),
      ...mustConsider.map((e) => entryLine(e, !!focus?.affectedEntries.has(e.entryId))),
      '',
    ] : []),
    `## 入口（结构索引，共 ${entries.length} 个${ordered.length > MAX_ENTRY_LINES ? `，列出前 ${MAX_ENTRY_LINES} 个` : ''}）`,
    ...(ordered.length ? ordered.slice(0, MAX_ENTRY_LINES).map((e) => entryLine(e, !!focus?.affectedEntries.has(e.entryId))) : [P('threat.no_entries')]),
    '',
    P('threat.submit'),
  ];
  return {
    lines,
    tools: domainsOn ? [submit, submitDomain, submitPolicy] : [submit],
    required: domainsOn ? ['submit_threat_model', 'submit_risk_domain'] : ['submit_threat_model'],
    finish: (submissions, stepId) => threatResult(rt, repo, model, submissions, stepId, { max, domainsOn, hypothesesOn }),
  };
}

export async function threatModelStep(rt: AuditRuntime, ctx: AttemptContext, repo: RepoInfo, model: ModelRef = hypothesisModel(rt)): Promise<StepResult> {
  const spec = threatSpec(rt, repo, model);
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'threat-model', phase: 'profile', model, signal: ctx.signal,
    prompt: spec.lines.join('\n'), submitTools: spec.tools, requiredSubmits: spec.required, maxTurns: Math.min(40, rt.strategy.limits.maxTurnsPerStep),
    // In a multi-repository audit each repository's understanding stays in it (the system model spans them).
    repo: repo.name, ownRepoOnly: rt.targets.length > 1,
  });
  const err = sessionError(outcome);
  if (err) throw err;
  return spec.finish(outcome.submissions, ctx.stepId);
}

/**
 * the threat-model step of a repository whose system-understanding session (the profile step of this
 * audit) already wrote the threat model — no session, the submissions are applied as this step's result.
 */
export function threatFromUnderstanding(rt: AuditRuntime, ctx: AttemptContext, repo: RepoInfo, model: ModelRef, submissions: Record<string, unknown[]>): StepResult {
  rt.event('judgement.made', { kind: 'threat_from_understanding', repo: repo.name }, ctx.stepId);
  return threatResult(rt, repo, model, submissions, ctx.stepId, { max: rt.strategy.limits.maxCandidates, domainsOn: domainHuntOn(rt), hypothesesOn: threatHypothesesOn(rt.strategy) });
}

/** The threat model's result from its submissions (a threat-model session, or the system-understanding session). */
export function threatResult(rt: AuditRuntime, repo: RepoInfo, model: ModelRef, submissions: Record<string, unknown[]>, stepId: string, o: { max: number; domainsOn: boolean; hypothesesOn: boolean }): StepResult {
  const { max, domainsOn, hypothesesOn } = o;
  const outcome = { submissions };
  const ctx = { stepId };
  const sub = (outcome.submissions.submit_threat_model as { hypotheses: ThreatHypothesisDraft[]; domains?: RiskDomainDraft[]; notes?: string }[]).at(-1)!;
  const hypotheses = hypothesesOn ? [...sub.hypotheses].sort((a, b) => b.priority - a.priority).slice(0, max) : [];
  // Domains from submit_risk_domain (a later call with the same name replaces an earlier one), plus any the model
  // still put into submit_threat_model.
  const byName = new Map<string, RiskDomainDraft>();
  for (const d of [...(sub.domains ?? []), ...((outcome.submissions.submit_risk_domain ?? []) as RiskDomainDraft[])]) byName.set(d.name, d);
  const domains = [...byName.values()];
  // the access policy (a later group with the same scope replaces an earlier one), at most 30 groups.
  const policy = new Map<string, AccessPolicyDraft>();
  for (const g of (outcome.submissions.submit_access_policy ?? []) as AccessPolicyDraft[]) policy.set(g.scope, g);
  const accessPolicy = [...policy.values()].slice(0, 30);
  const outputRef = rt.store.artifacts.putJson({ repositoryId: repo.id, hypotheses, ...(domainsOn ? { domains } : {}), ...(accessPolicy.length ? { accessPolicy } : {}), notes: sub.notes ?? null });
  return {
    outputRef,
    apply: () => {
      if (hypothesesOn) insertProposed(rt, ctx.stepId, repo, hypotheses, `${model.provider}/${model.model}`);
      if (domainsOn) rt.event('judgement.made', { kind: 'threat_domains', repo: repo.name, domains: domains.map((d) => d.name), model: `${model.provider}/${model.model}` }, ctx.stepId);
    },
  };
}

const norm = (t: string) => t.replace(/[\s，。、“”"'（）()：:；;,.]/g, '').toLowerCase();

/**
 * Store the proposed hypotheses of one threat-model step. With several models a hypothesis
 * another model already proposed for the same repository — same category and the same statement, or the same
 * first entry — is merged into it: the proposers are kept (`related.models`) and the higher priority wins.
 */
function insertProposed(rt: AuditRuntime, stepId: string, repo: RepoInfo, hs: ThreatHypothesisDraft[], model: string): void {
  // Idempotent per step: a retried apply does not list the same hypotheses twice.
  if (rt.store.get('SELECT 1 FROM hypothesis WHERE step_id = ? LIMIT 1', stepId)) return;
  const existing = rt.store.all<HypothesisRow>(`SELECT * FROM hypothesis WHERE audit_id = ? AND repository_id = ? AND origin = 'threat_model' AND step_id != ?`, rt.auditId, repo.id, stepId);
  let merged = 0;
  for (const h of hs) {
    const dup = existing.find((e) => e.category === h.category && (norm(e.statement) === norm(h.statement) || (!!h.entries[0] && relatedOf(e).entries[0] === h.entries[0])));
    if (dup) {
      const r = fromJson<{ entries?: string[]; files?: string[]; models?: string[] }>(dup.related, {});
      const related = { entries: [...new Set([...(r.entries ?? []), ...h.entries])], files: [...new Set([...(r.files ?? []), ...h.files])], models: [...new Set([...(r.models ?? []), model])] };
      rt.store.update('hypothesis', { id: dup.id }, { related, priority: Math.max(dup.priority ?? 0, h.priority) });
      dup.related = JSON.stringify(related);
      merged++;
      continue;
    }
    const id = newId('hypothesis');
    const related = { entries: h.entries, files: h.files, models: [model] };
    rt.store.insert('hypothesis', {
      id, audit_id: rt.auditId, step_id: stepId, project_id: rt.audit.project_id, repository_id: repo.id, category: h.category,
      statement: h.statement, location: null, entry_key: h.entries[0] ?? null, attempts: '', status: 'proposed', origin: 'threat_model',
      priority: h.priority, basis: h.basis, related,
    });
    existing.push({ id, category: h.category, statement: h.statement, related: JSON.stringify(related), priority: h.priority } as HypothesisRow);
  }
  rt.event('judgement.made', { kind: 'threat_model', repo: repo.name, hypotheses: hs.length, ...(merged ? { merged } : {}), model }, stepId);
}

// ---- editing the list while the audit runs ------------------------------------------

export interface AddHypothesisInput {
  statement: string; category: string; basis?: string; entries?: string[]; files?: string[]; priority?: number; repo?: string; actor: string;
}

export class HypothesisEditError extends Error {
  constructor(readonly code: 'NOT_FOUND' | 'INVALID', message: string) { super(message); }
}

/**
 * A reviewer adds a risk hypothesis to an audit's list (non-blocking): it is `proposed` and verified by the
 * audit's coverage-completion round if the audit is still before it, otherwise it waits for a supplement
 * (“验证所选”). Setting one aside is the existing dismiss decision.
 */
export function addHypothesis(store: Store, auditId: string, input: AddHypothesisInput): HypothesisRow {
  const a = store.get<{ id: string; project_id: string; scene: string; status: string }>('SELECT id, project_id, scene, status FROM audit WHERE id = ?', auditId);
  if (!a) throw new HypothesisEditError('NOT_FOUND', `audit ${auditId} not found`);
  if (!['full', 'incremental'].includes(a.scene)) throw new HypothesisEditError('INVALID', 'risk hypotheses belong to full and incremental audits');
  if (['cancelled', 'cancelling', 'failed'].includes(a.status)) throw new HypothesisEditError('INVALID', `audit is ${a.status}`);
  const repos = store.all<{ id: string; name: string; role_in_audit: string }>(
    'SELECT r.id, r.name, ar.role_in_audit FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id WHERE ar.audit_id = ? ORDER BY r.name', auditId);
  const targets = repos.filter((r) => r.role_in_audit === 'target');
  const repo = input.repo ? repos.find((r) => r.name === input.repo || r.id === input.repo) : targets[0] ?? repos[0];
  if (!repo) throw new HypothesisEditError('INVALID', `unknown repository ${input.repo ?? ''}`);
  const id = newId('hypothesis');
  store.insert('hypothesis', {
    id, audit_id: auditId, step_id: null, project_id: a.project_id, repository_id: repo.id, category: input.category,
    statement: input.statement, location: null, entry_key: input.entries?.[0] ?? null, attempts: '', status: 'proposed', origin: 'threat_model',
    priority: input.priority ?? 3, basis: input.basis?.trim() || '审计员补充', related: { entries: input.entries ?? [], files: input.files ?? [], models: [`user:${input.actor}`] },
  });
  store.appendEvent(auditId, 'judgement.made', { kind: 'hypothesis_added', hypothesis_id: id, statement: input.statement.slice(0, 300), actor: input.actor });
  return store.get<HypothesisRow>('SELECT * FROM hypothesis WHERE id = ?', id)!;
}

// ---- verification batches -------------------------------------------------------------------------

/** Threat-model hypotheses this audit verifies, in a stable order (priority, then listing order). */
export function verificationTargets(rt: AuditRuntime): HypothesisRow[] {
  const sup = supplementScope(rt);
  if (sup?.kind === 'threat_hypotheses' && sup.hypothesisIds?.length) {
    const ids = sup.hypothesisIds;
    return rt.store.all<HypothesisRow>(
      `SELECT * FROM hypothesis WHERE id IN (${ids.map(() => '?').join(',')}) AND origin = 'threat_model' ORDER BY COALESCE(priority, 0) DESC, created_at, id`, ...ids);
  }
  return rt.store.all<HypothesisRow>(`SELECT * FROM hypothesis WHERE audit_id = ? AND origin = 'threat_model' ORDER BY COALESCE(priority, 0) DESC, created_at, id`, rt.auditId);
}

/** Batches of hypothesis ids; stable across resumes (composition does not depend on verification state). */
export function hypothesisBatches(rows: HypothesisRow[]): string[][] {
  const out: string[][] = [];
  for (let i = 0; i < rows.length; i += HYP_BATCH) out.push(rows.slice(i, i + HYP_BATCH).map((h) => h.id));
  return out;
}

export function relatedOf(h: Pick<HypothesisRow, 'related'>): { entries: string[]; files: string[] } {
  const r = fromJson<{ entries?: string[]; files?: string[] }>(h.related, {});
  return { entries: r.entries ?? [], files: r.files ?? [] };
}

// ---- reuse of the bottom-up hunt (⑧) -------------------------------------------------------

/**
 * What the bottom-up hunt already concluded on the places a verification batch is about, from the same model:
 * findings (citable by their id with `sameAs`), candidates ruled out with the reason, candidates with no issue.
 */
export interface PriorConclusions {
  findings: Map<string, { id: string; location: CodeRef }>;
  lines: string[];
}

const PRIOR_LIMIT = 30;

/**
 * `crossModel`: with multi-model cross-checking, only that model's conclusions (sessions stay independent per model) —
 * a model, or its cross-check slot key (`provider/model#n` when the group repeats a model).
 */
export function priorConclusions(rt: AuditRuntime, hs: HypothesisRow[], crossModel?: { provider: string; model: string } | string): PriorConclusions {
  const files = new Set(hs.flatMap((h) => relatedOf(h).files));
  const entries = new Set(hs.flatMap((h) => relatedOf(h).entries));
  const modelId = crossModel ? (typeof crossModel === 'string' ? crossModel : `${crossModel.provider}/${crossModel.model}`) : null;
  const entryPath = new Map<string, string>();
  for (const idx of rt.indexes.values()) for (const e of idx.entrypoints as EntryPoint[]) { entryPath.set(e.entryId, e.path); entryPath.set(e.entryKey, e.path); }
  for (const e of entries) { const p = entryPath.get(e); if (p) files.add(p); }
  const relevant = (path: string) => files.size === 0 || files.has(path);
  // A supplement on the same snapshot also reuses the source audit's conclusions.
  const sup = supplementScope(rt);
  const audits = sup ? [rt.auditId, sup.auditId] : [rt.auditId];
  const inAudits = `(${audits.map(() => '?').join(',')})`;
  const rows = rt.store.all<{ id: string; lineage_id: string; title: string; category: string; location: string; root_cause: string | null; model: string | null }>(
    `SELECT f.id, f.lineage_id, f.title, f.category, f.location, f.root_cause, f.model FROM finding f JOIN step s ON s.id = f.step_id
     WHERE f.audit_id IN ${inAudits} AND s.kind = 'hunt' AND f.lineage_id NOT LIKE 'HYP-%' AND f.state != 'dropped' ORDER BY s.seq, f.id`, ...audits);
  const findings = new Map<string, { id: string; location: CodeRef }>();
  const lines: string[] = [];
  for (const f of rows) {
    if (modelId && f.model && f.model !== modelId) continue;
    const loc = fromJson<CodeRef>(f.location, { repo: '', path: '', startLine: 1, endLine: 1 });
    if (!relevant(loc.path) || findings.size >= PRIOR_LIMIT) continue;
    findings.set(f.lineage_id, { id: f.id, location: loc });
    lines.push(`- 发现 \`${f.lineage_id}\`：${f.title}（${f.category}）@ ${loc.repo}:${loc.path}:${loc.startLine}-${loc.endLine}${f.root_cause ? `；根因：${f.root_cause.slice(0, 200)}` : ''}`);
  }
  const outputs = rt.store.all<{ output_ref: string; lineage_id: string | null }>(
    `SELECT output_ref, lineage_id FROM step WHERE audit_id IN ${inAudits} AND kind = 'hunt' AND status = 'succeeded' AND output_ref IS NOT NULL AND (lineage_id IS NULL OR (lineage_id NOT LIKE 'HYP-%' AND lineage_id NOT LIKE 'LEAD-%')) ORDER BY seq`, ...audits);
  let n = 0;
  for (const o of outputs) {
    const out = rt.store.artifacts.getJson<{ model?: string; ruledOut: { targetId: string; reason: string }[]; reviewedTargets: { targetId: string; verdict: string }[] }>(o.output_ref);
    if (modelId && out.model && out.model !== modelId) continue;
    const pathOf = (id: string) => entryPath.get(id) ?? /^[^:]+:(.+?)#L\d+/.exec(id)?.[1] ?? '';
    for (const r of out.ruledOut) if (relevant(pathOf(r.targetId)) && n++ < PRIOR_LIMIT) lines.push(`- 已排除 \`${r.targetId}\`：${r.reason.slice(0, 200)}`);
    for (const r of out.reviewedTargets) if (r.verdict === 'no_issue' && relevant(pathOf(r.targetId)) && n++ < PRIOR_LIMIT) lines.push(`- 未发现问题 \`${r.targetId}\`（${o.lineage_id ?? ''}）`);
  }
  return { findings, lines };
}

/** The verification prompt section listing the batch's hypotheses (ids exactly as the verdicts must use them). */
export function verificationLines(hs: HypothesisRow[], prior?: PriorConclusions): string[] {
  return [
    ...(prior?.lines.length ? [
      P('hypothesis.verify.prior'),
      ...prior.lines, '',
    ] : []),
    P('hypothesis.verify', { n: hs.length }),
    '',
    ...hs.map((h) => {
      const r = relatedOf(h);
      return [
        `- hypothesisId=\`${h.id}\`（优先级 ${h.priority ?? '?'}，${h.category}）`,
        `  假设：${h.statement}`,
        ...(h.basis ? [`  依据：${h.basis}`] : []),
        ...(r.entries.length ? [`  相关入口：${r.entries.join('、')}`] : []),
        ...(r.files.length ? [`  起点文件：${r.files.join('、')}`] : []),
      ].join('\n');
    }),
  ];
}

/**
 * The `sameAs` a verdict really uses: models fill the optional field on every verdict
 * with placeholders ("", "/", ":none"); only a listed earlier finding id counts, trimmed. Anything else is dropped —
 * a confirmed verdict then needs its own finding, as without sameAs.
 */
export function effectiveSameAs(v: HypothesisVerdictDraft, prior?: PriorConclusions): string | undefined {
  const id = v.sameAs?.trim().replace(/^`|`$/g, '');
  return id && prior?.findings.has(id) ? id : undefined;
}

/**
 * Validation of the verdicts of a verification batch (called with the hunt submission's own issues). `requireAll`
 * false (a domain expert): verdicts may come over several calls, and one left without a verdict is retried
 * by HYP-R instead of refusing the call.
 */
export function verdictIssues(listed: HypothesisRow[], verdicts: HypothesisVerdictDraft[], findings: number, checkRef: (ref: CodeRef, label: string, mustBeRead: boolean) => string[], earlier: ReadonlySet<string> = new Set(), prior?: PriorConclusions, requireAll = true): string[] {
  const issues: string[] = [];
  // Every listed hypothesis needs a verdict by the end (this call plus earlier accepted calls): an evaluation run
  // ended with a whole batch left unverified because the submission carried no verdicts.
  const given = new Set([...earlier, ...verdicts.map((v) => v.hypothesisId)]);
  const missing = listed.filter((h) => !given.has(h.id)).map((h) => h.id);
  if (requireAll && missing.length) issues.push(P('feedback.hypothesis.missing', { ids: missing.join(', ') }));
  const ids = new Set(listed.map((h) => h.id));
  const seen = new Map<string, number>();
  verdicts.forEach((v, i) => {
    if (!ids.has(v.hypothesisId)) issues.push(P('feedback.hypothesis.unknown_id', { i, id: v.hypothesisId }));
    seen.set(v.hypothesisId, (seen.get(v.hypothesisId) ?? 0) + 1);
    if (earlier.has(v.hypothesisId) && !requireAll) issues.push(P('feedback.hypothesis.already_given', { i, id: v.hypothesisId }));
    const same = effectiveSameAs(v, prior);
    if (v.status === 'confirmed' && same === undefined) {
      if (v.finding === undefined || v.finding >= findings) issues.push(prior?.findings.size
        ? P('feedback.hypothesis.confirmed_ref', { i, ids: [...prior.findings.keys()].slice(0, 5).join(', '), maxIndex: Math.max(0, findings - 1) })
        : P('feedback.hypothesis.confirmed_finding', { i, maxIndex: Math.max(0, findings - 1) }));
    }
    // A verdict that reuses an earlier finding does not need to read the code again (no new evidence is claimed).
    issues.push(...checkRef(v.location, `verdicts[${i}].location`, !(v.status === 'confirmed' && same !== undefined)));
  });
  for (const [id, n] of seen) if (n > 1 && ids.has(id)) issues.push(P('feedback.hypothesis.duplicate', { id, n }));
  return issues;
}

/** Apply accepted verdicts: the hypothesis rows of the batch get their status, reason, location and finding. */
export interface HypothesisVote { model: string; status: 'confirmed' | 'refuted' | 'open'; reason: string; location: CodeRef; findingId: string | null; stepId: string }

/**
 * The status from the models' votes (one vote without cross-checking): votes never decide by
 * themselves — any model that proved it makes it confirmed (its finding then goes through reconcile, where a
 * single-source finding is downgraded); any undetermined vote, or models disagreeing, makes it open (both sides
 * kept); refuted only when every vote refuted it.
 */
export function combineVotes(votes: HypothesisVote[]): HypothesisVote['status'] {
  if (votes.some((v) => v.status === 'confirmed')) return 'confirmed';
  if (votes.length && votes.every((v) => v.status === 'refuted')) return 'refuted';
  return 'open';
}

export function applyVerdicts(rt: AuditRuntime, stepId: string, verdicts: HypothesisVerdictDraft[], findingIds: string[], prior: PriorConclusions | undefined, model: string): void {
  for (const v of verdicts) {
    const h = rt.store.get<HypothesisRow & { votes?: string }>('SELECT * FROM hypothesis WHERE id = ?', v.hypothesisId);
    if (!h || h.status === 'converted' || h.status === 'dismissed') continue;
    const votes = fromJson<HypothesisVote[]>(h.votes, []);
    if (votes.some((x) => x.model === model)) continue;
    const repo = rt.repoByName(v.location.repo) ?? rt.targetRepo;
    const view = rt.views.get(repo.name);
    const loc = { repo: repo.name, path: view ? view.guard(v.location.path) : v.location.path, startLine: v.location.startLine, endLine: v.location.endLine };
    const same = effectiveSameAs(v, prior);
    const findingId = v.status !== 'confirmed' ? null : same !== undefined ? prior?.findings.get(same)?.id ?? null : v.finding !== undefined ? findingIds[v.finding] ?? null : null;
    const all: HypothesisVote[] = [...votes, { model, status: v.status as HypothesisVote['status'], reason: v.reason, location: loc, findingId, stepId }];
    const status = combineVotes(all);
    const lead = all.find((x) => x.status === status) ?? all.at(-1)!;
    rt.store.update('hypothesis', { id: h.id }, {
      status, votes: all,
      attempts: all.length > 1 ? all.map((x) => `【${x.model}：${x.status}】${x.reason}`).join('\n') : v.reason,
      location: lead.location, finding_id: all.find((x) => x.findingId)?.findingId ?? null, verify_step_id: stepId, verified_at: Date.now(),
    });
    rt.event('judgement.made', { kind: 'hypothesis_verified', hypothesis_id: h.id, status: v.status, category: h.category, statement: h.statement.slice(0, 300), reason: v.reason.slice(0, 300), ...(same ? { same_as: same } : {}) }, stepId);
  }
}
