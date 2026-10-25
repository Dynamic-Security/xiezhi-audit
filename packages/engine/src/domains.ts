// 多领域专家漏洞狩猎: the threat model splits the system into risk domains; one expert per domain explores
// on its own — the domain's mechanisms and risk points, plus the entry points and sinks of its categories as leads, not
// a checklist — over up to three rounds within an equal share of the expert budget. The threat-model hypotheses of the
// domain's categories are part of the expert's work; what the experts leave uncovered goes to ⑨
// coverage completion. Without a usable plan the 6 fallback domains are used.
import { Type } from 'typebox';
import { SubmitDomainFindings, SubmitDomainVerification, SubmitStateUpdate, VULN_CATEGORIES, type CodeRef, type FindingDraft, type HypothesisVerdictDraft, type ModelRef, type RiskDomainDraft, type StateOp, type StructIndex } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import { loadState, sliceSummary } from './cognitive.js';
import type { HypothesisRow } from './business.js';
import { accessLines, type AccessCheck } from './access.js';
import { dependencyLines, type DependencyHit } from './dependencies.js';
import type { AuditRuntime } from './runtime.js';
import { sessionError, type AttemptContext, type StepResult } from './step-runner.js';
import { UNCOVERED_FINDING_PREFIX, applyHunt, stateFor, stateQueryTool, taskTool, uncoveredFindingTargets, validateCodeRef, validateFindings, verdictsOf, type HuntOutput } from './steps/hunt.js';
import { auditSystemModel, renderSystemModel, renderThreatModel } from './steps/profile.js';
import { changedFileList, diffTool } from './steps/scope.js';
import { hasPathParam, type Candidate } from './steps/triage.js';
import { backfillScope } from './steps/coverage-gap.js';
import { profileFor, relatedOf, supplementScope, verdictIssues, verificationLines, type PriorConclusions } from './threat.js';
import { linkedThreatModels, relatedRiskIssues, withRelatedRisk } from './threat-model-audit.js';
import { P } from '@xiezhi/knowledge';

/** Rounds per domain at most. */
export const DOMAIN_ROUNDS = 3;
/** A further round only while the domain has at least this share of its budget left. */
export const NEXT_ROUND_MIN_LEFT = 0.2;
/**
 * Share of the hunt stage quota the experts get; without stage quotas, the share of the total.
 * No generalist fallback shares the hunt quota; the tenth left absorbs rounds that run past their share
 * after the wrap-up reminder.
 */
export const EXPERT_SHARE_OF_HUNT = 0.9;
export const EXPERT_SHARE_OF_TOTAL = 0.6;
/** Leads (entry points / sinks of the domain's categories) shown to one expert. */
export const MAX_DOMAIN_LEADS = 60;
/** leads and earlier findings shown in the prompt; the rest through `domain_context`. */
export const PUSHED_LEADS = 10;
export const PUSHED_FINDINGS = 10;
/** Hypotheses one expert round must answer at most; the rest wait for the next round or HYP-R. */
export const HYPOTHESES_PER_ROUND = 15;
/** Domains per audit plan at most, the engine's “其他” included. */
export const MAX_DOMAINS = 9;

export interface PlannedDomain {
  /** D1, D2, … in plan order: part of step lineages (`DOM-D1-R1`). */
  id: string;
  name: string;
  focus: string;
  categories: string[];
  mechanisms: { name: string; location: CodeRef & { repo: string }; why: string }[];
  leads: { statement: string; entries: string[]; files: string[]; repo: string }[];
  /**
   * threat_model: chosen by the model; fallback: the fixed set; completion: the “其他” domain the engine added; user: added
   * by a person while the audit ran.
   */
  source: 'threat_model' | 'fallback' | 'completion' | 'user';
  /** a person removed it — experts that have not started skip it, results already in stay. */
  removed?: boolean;
  /** added after the expert phase had ended — it runs in a supplement (追加执行) once the audit is finished. */
  late?: boolean;
  /** focus a person added, from the domain's next round on. */
  userFocus?: string[];
  /** The threat-model domains over MAX_DOMAINS that the “其他” domain took over. */
  mergedFrom?: string[];
}

/** a person's change to an audit's domain plan, recorded as a `judgement.made` event. */
export type DomainEdit =
  | { op: 'add'; id: string; name: string; focus: string; categories: string[]; late: boolean; actor: string }
  | { op: 'remove'; domainId: string; actor: string }
  | { op: 'focus'; domainId: string; text: string; actor: string };

/** What planning needs: the store and the audit's repositories (id → name). */
export interface PlanSource { store: Pick<AuditRuntime['store'], 'all' | 'artifacts'>; auditId: string; repos: { id: string; name: string }[] }

/** The plan edits of an audit, in order. */
export function domainEdits(store: PlanSource['store'], auditId: string): DomainEdit[] {
  return store.all<{ payload: string }>(
    `SELECT payload FROM event WHERE audit_id = ? AND type = 'judgement.made' AND json_extract(payload, '$.kind') = 'domain_edit' ORDER BY seq`, auditId)
    .map((r) => JSON.parse(r.payload) as DomainEdit & { kind: string });
}

/** The fixed domains: the 27 categories merged into 6 areas. */
export const FALLBACK_DOMAINS: Pick<PlannedDomain, 'name' | 'focus' | 'categories'>[] = [
  { name: '服务端注入', focus: '外部输入进入解释器或查询：SQL / NoSQL / 命令 / 代码 / 表达式 / 模板 / LDAP / XML / 反序列化 / 日志。', categories: ['sqli', 'nosqli', 'cmdi', 'code_injection', 'expression_injection', 'ssti', 'ldapi', 'xxe', 'deserialization', 'log_injection'] },
  { name: '文件与外连', focus: '文件路径、上传与下载、服务端发起的请求与跳转。', categories: ['path_traversal', 'file_upload', 'ssrf', 'open_redirect'] },
  { name: '认证与会话', focus: '登录、令牌与会话的签发、校验、过期、吊销；跨站请求与跨域；WebSocket / SSE 握手鉴权。', categories: ['authn', 'csrf', 'cors'] },
  { name: '授权', focus: '谁能访问哪个对象、哪个功能：资源归属、角色、租户隔离。', categories: ['authz_object', 'authz_function'] },
  { name: '业务逻辑与并发', focus: '业务规则、状态流转、金额与数量、重复提交与竞态；资源耗尽与拒绝服务。', categories: ['business_logic', 'race_condition', 'dos'] },
  { name: '数据与输出', focus: '输出到客户端的内容、敏感信息泄露、加密与密钥。', categories: ['xss', 'info_leak', 'crypto_weak', 'hardcoded_secret', 'other'] },
];

/**
 * Whether this audit explores with the lead and its domain subtasks: every full and
 * incremental audit; backfills, supplements and risk hunts keep the generalist batches.
 */
export function domainHuntOn(rt: AuditRuntime): boolean {
  if (backfillScope(rt) || supplementScope(rt) || rt.testGeneralistHunt) return false;
  return rt.audit.scene === 'full' || rt.audit.scene === 'incremental';
}

/**
 * ⑨ coverage completion: on when the strategy asks for `gap_fill`, and in the domain hunt also when
 * no layer chose `onShortfall` (the scene default) — experts explore freely and leave ledger units without a conclusion,
 * which the generalist then completes. An explicit `declare` (any layer) is kept.
 */
export function gapFillOn(rt: AuditRuntime): boolean {
  if (rt.strategy.coverageTarget.onShortfall === 'gap_fill') return true;
  if (!domainHuntOn(rt)) return false;
  const sources = JSON.parse(rt.audit.strategy_sources || '{}') as Record<string, string>;
  const src = sources['coverageTarget.onShortfall'];
  return src === undefined || src === 'system';
}

/** Directions the last round of each domain left open: leads for the deep exploration. */
export function lastOpenLeads(rt: AuditRuntime): { domain: string; lead: OpenLead }[] {
  const rows = rt.store.all<{ lineage_id: string; output_ref: string }>(
    `SELECT lineage_id, output_ref FROM step WHERE audit_id = ? AND kind = 'hunt' AND lineage_id LIKE 'DOM-%' AND status = 'succeeded' AND output_ref IS NOT NULL ORDER BY seq`, rt.auditId);
  const last = new Map<string, string>();
  for (const r of rows) last.set(r.lineage_id.replace(/-R\d+$/, ''), r.output_ref);
  return [...last.values()].flatMap((ref) => {
    const o = rt.store.artifacts.getJson<DomainOutput>(ref);
    return o.openLeads.map((lead) => ({ domain: o.domain, lead }));
  });
}

/** The domains the threat-model steps of this audit submitted (all repositories, all models). */
function submittedDomains(src: PlanSource): { repo: string; domains: RiskDomainDraft[] }[] {
  const rows = src.store.all<{ output_ref: string }>(
    `SELECT output_ref FROM step WHERE audit_id = ? AND kind = 'threat-model' AND status = 'succeeded' AND output_ref IS NOT NULL ORDER BY seq`, src.auditId);
  const out: { repo: string; domains: RiskDomainDraft[] }[] = [];
  for (const r of rows) {
    const o = src.store.artifacts.getJson<{ repositoryId: string; domains?: RiskDomainDraft[] }>(r.output_ref);
    const repo = src.repos.find((x) => x.id === o.repositoryId);
    if (repo && o.domains?.length) out.push({ repo: repo.name, domains: o.domains });
  }
  return out;
}

/**
 * The domains of this audit: the threat models' (merged by name across repositories and models), else the
 * fallback set; an “其他” domain takes the categories no domain covers. Then a person's edits: removed
 * domains keep their id, added ones get the next ids — ids never shift, so step lineages and identities stay stable.
 * Deterministic for a given set of threat-model outputs and edits, so a resumed run builds the same steps.
 */
export function planDomains(rt: Pick<AuditRuntime, 'store' | 'auditId' | 'repos'>): PlannedDomain[] {
  return planDomainsOf({ store: rt.store, auditId: rt.auditId, repos: rt.repos });
}

export function planDomainsOf(src: PlanSource): PlannedDomain[] {
  const base = basePlan(src);
  const byId = new Map(base.map((d) => [d.id, d]));
  for (const e of domainEdits(src.store, src.auditId)) {
    if (e.op === 'add') {
      const d: PlannedDomain = { id: e.id, name: e.name, focus: e.focus, categories: [...e.categories], mechanisms: [], leads: [], source: 'user', ...(e.late ? { late: true } : {}) };
      base.push(d);
      byId.set(d.id, d);
    } else if (e.op === 'remove') {
      const d = byId.get(e.domainId);
      if (d) d.removed = true;
    } else {
      const d = byId.get(e.domainId);
      if (d) d.userFocus = [...(d.userFocus ?? []), e.text];
    }
  }
  return base;
}

function basePlan(src: PlanSource): PlannedDomain[] {
  const byName = new Map<string, Omit<PlannedDomain, 'id'>>();
  for (const { repo, domains } of submittedDomains(src)) {
    for (const d of domains) {
      const mechanisms = d.mechanisms.map((m) => ({ name: m.name, why: m.why, location: { ...m.location, repo: m.location.repo || repo } }));
      const leads = d.leads.map((l) => ({ ...l, repo }));
      const prev = byName.get(d.name);
      if (prev) {
        prev.categories = [...new Set([...prev.categories, ...d.categories])];
        prev.mechanisms.push(...mechanisms.filter((m) => !prev.mechanisms.some((x) => x.name === m.name)));
        prev.leads.push(...leads.filter((l) => !prev.leads.some((x) => x.statement === l.statement)));
      } else byName.set(d.name, { name: d.name, focus: d.focus, categories: [...new Set(d.categories)], mechanisms, leads, source: 'threat_model' });
    }
  }
  const chosen: Omit<PlannedDomain, 'id'>[] = byName.size
    ? [...byName.values()]
    : FALLBACK_DOMAINS.map((d) => ({ ...d, categories: [...d.categories], mechanisms: [], leads: [], source: 'fallback' as const }));
  return capDomains(chosen).map((d, i) => ({ ...d, mechanisms: d.mechanisms.slice(0, 6), leads: d.leads.slice(0, 24), id: `D${i + 1}` }));
}

/**
 * At most MAX_DOMAINS domains, every category owned. The “其他” domain takes the categories no kept domain
 * covers; when domains are over the limit, the last slot is “其他” and the domains past it are merged into it (their
 * categories, focus, mechanisms and risk points) — capping never leaves a category without an expert.
 */
function capDomains(chosen: Omit<PlannedDomain, 'id'>[]): Omit<PlannedDomain, 'id'>[] {
  const uncovered = (ds: Omit<PlannedDomain, 'id'>[]) => {
    const covered = new Set(ds.flatMap((d) => d.categories));
    return VULN_CATEGORIES.filter((c) => !covered.has(c));
  };
  // “其他” needs a slot when categories are left over at the limit, or when domains are over it.
  const full = chosen.length > MAX_DOMAINS || (chosen.length === MAX_DOMAINS && uncovered(chosen).length > 0);
  const kept = full ? chosen.slice(0, MAX_DOMAINS - 1) : chosen;
  const dropped = chosen.slice(kept.length);
  const missing = uncovered(kept);
  if (!missing.length && !dropped.length) return kept;
  const categories = [...new Set([...missing, ...dropped.flatMap((d) => d.categories)])];
  const focus = ['其他领域没有覆盖的漏洞类别。', ...(dropped.length ? [`领域数超过上限 ${MAX_DOMAINS}，以下领域并入本领域：${dropped.map((d) => `${d.name}（${d.focus}）`).join('；')}`] : [])].join('');
  const mechanisms = dropped.flatMap((d) => d.mechanisms).filter((m, i, all) => all.findIndex((x) => x.name === m.name) === i);
  const leads = dropped.flatMap((d) => d.leads).filter((l, i, all) => all.findIndex((x) => x.statement === l.statement) === i);
  return [...kept, { name: '其他', focus, categories, mechanisms, leads, source: 'completion', ...(dropped.length ? { mergedFrom: dropped.map((d) => d.name) } : {}) }];
}

const STATE_CHANGING = /^(POST|PUT|PATCH|DELETE|ANY)\b/i;

/** Sink category of a candidate (rule categories outside the closed set count as `other`). */
function sinkCategory(c: Candidate, indexes: ReadonlyMap<string, StructIndex>): string {
  const cat = indexes.get(c.repo)?.sinks.find((s) => s.sinkId === c.id)?.category ?? 'other';
  return (VULN_CATEGORIES as readonly string[]).includes(cat) ? cat : 'other';
}

/**
 * Leads per domain: a sink goes to the domains covering its category; an entry point to the domains covering
 * authorization or authentication, a state-changing or by-id one also to business logic. In candidate order, at most
 * MAX_DOMAIN_LEADS each. Leads are hints: the expert decides what to read.
 */
export function domainLeads(domains: PlannedDomain[], candidates: Candidate[], indexes: ReadonlyMap<string, StructIndex>): Map<string, Candidate[]> {
  const out = new Map(domains.map((d) => [d.id, [] as Candidate[]]));
  const covering = (cat: string) => domains.filter((d) => d.categories.includes(cat));
  for (const c of candidates) {
    let targets: PlannedDomain[] = [];
    if (c.kind === 'sink') targets = covering(sinkCategory(c, indexes));
    // incremental audits — a changed file or a variant hit may concern any domain; each looks at it
    // for its own categories.
    else if (c.kind === 'change') targets = domains;
    else if (c.kind === 'entry') {
      const entry = indexes.get(c.repo)?.entrypoints.find((e) => e.entryId === c.id);
      const key = entry?.entryKey ?? c.label;
      const sensitive = STATE_CHANGING.test(key) || (entry ? hasPathParam(entry) : false) || /mutation/i.test(key);
      targets = [...covering('authz_object'), ...covering('authz_function'), ...covering('authn'), ...(sensitive ? covering('business_logic') : [])];
    }
    // A multi-repository audit has each repository's domains; a candidate goes to the covering domains of its
    // own repository (and those not tied to one), not to another repository's experts.
    const own = targets.filter((d) => { const r = domainRepo(d); return !r || r === c.repo; });
    if (own.length) targets = own;
    for (const d of new Set(targets)) {
      const l = out.get(d.id)!;
      if (l.length < MAX_DOMAIN_LEADS) l.push(c);
    }
  }
  return out;
}

/** The token pool of all experts, from the audit's effective budget. */
export function expertPool(rt: AuditRuntime): number {
  const { effective } = rt.budget();
  const hunt = effective.stages?.hunt;
  return Math.floor(hunt !== undefined ? hunt * EXPERT_SHARE_OF_HUNT : effective.tokens * EXPERT_SHARE_OF_TOTAL);
}

/** Tokens a domain's steps (all rounds, sub-agents included) have used. */
export function domainUsed(rt: AuditRuntime, stepIds: string[]): number {
  if (!stepIds.length) return 0;
  return rt.store.get<{ n: number | null }>(
    `SELECT SUM(tokens_in + tokens_out + tokens_cached) AS n FROM step WHERE id IN (${stepIds.map(() => '?').join(',')})`, ...stepIds)?.n ?? 0;
}

export interface OpenLead { direction: string; files: string[] }

/** the built-in checklist session / cross-site / robustness domains start from, and the categories that use it. */
export const SESSION_CHECKLIST = 'session-transport-checklist';
const SESSION_CATEGORIES: readonly string[] = ['authn', 'csrf', 'cors', 'dos'];

/** index leads a gap report lists at most (the most promising first, as triage ordered them). */
export const GAP_LEADS_PER_ROUND = 15;

/**
 * what a domain's rounds so far left open, computed by the engine — the domain's mechanisms
 * none of its rounds read, and its index leads without a conclusion in the coverage ledger (any session's conclusion
 * counts; one without enough reading does not). Empty when nothing is left.
 */
export interface DomainGaps { mechanisms: PlannedDomain['mechanisms']; leads: Candidate[] }

/** Whether one of the steps read a line of the range (file.read events carry the step, sub-agents included). */
function readBySteps(rt: AuditRuntime, stepIds: readonly string[], ref: { repo: string; path: string; startLine: number; endLine: number }): boolean {
  const ids = new Set(stepIds);
  return rt.store.listEvents(rt.auditId, 0, ['file.read']).some((e) => e.stepId !== null && ids.has(e.stepId)
    && e.payload.path === ref.path && (e.payload.repo === undefined || e.payload.repo === ref.repo)
    && Number(e.payload.startLine) <= ref.endLine && Number(e.payload.endLine) >= ref.startLine);
}

export function domainGaps(rt: AuditRuntime, d: PlannedDomain, leads: Candidate[], stepIds: readonly string[]): DomainGaps {
  const mechanisms = d.mechanisms.filter((m) => !readBySteps(rt, stepIds, { repo: m.location.repo, path: m.location.path, startLine: m.location.startLine, endLine: m.location.endLine ?? m.location.startLine }));
  const open = new Set(rt.store.all<{ target_id: string }>(`SELECT target_id FROM coverage_item WHERE audit_id = ? AND status != 'concluded' AND status != 'excluded'`, rt.auditId).map((r) => r.target_id));
  return { mechanisms, leads: leads.filter((c) => open.has(c.id)).slice(0, GAP_LEADS_PER_ROUND) };
}

export const gapsEmpty = (g: DomainGaps | undefined) => !g || (!g.mechanisms.length && !g.leads.length);

/** the must-answer section of a round that follows up on the domain's gaps. */
export function gapLines(g: DomainGaps): string[] {
  if (gapsEmpty(g)) return [];
  return [
    '', P('domains.gaps.intro'),
    ...(g.mechanisms.length ? [P('domains.gaps.mechanisms'),
      ...g.mechanisms.map((m) => `- ${m.name}：${m.why}（${m.location.repo}:${m.location.path}:${m.location.startLine}）`)] : []),
    ...(g.leads.length ? [P('domains.gaps.leads'), ...g.leads.map(candidateLine)] : []),
  ];
}

/**
 * the follow-up once a gap round submitted while gaps are still open — the session is asked once
 * (`completionCheck`); what stays open goes to ⑨ coverage completion.
 */
export function gapsLeftPrompt(g: DomainGaps): string {
  return [
    P('nudge.domains.gaps_left'),
    ...g.mechanisms.map((m) => `- 机制未阅读：${m.name}（${m.location.repo}:${m.location.path}:${m.location.startLine}）`),
    ...g.leads.map((c) => `- 没有结论：\`${c.id}\``),
    P('nudge.domains.gaps_left_ask'),
  ].join('\n');
}
export type DomainOutput = HuntOutput & { domain: string; round: number; openLeads: OpenLead[] };

export interface DomainExpertOptions {
  /** The session's model (cross-checking: one expert per model and domain); default the hunt model. */
  model?: ModelRef;
  /** The cross-check slot key recorded as the output's model (`#n` when the group repeats a model). */
  modelKey?: string;
  /** the subtask the lead dispatched — what to find out and where to start; absent for floor rounds. */
  task?: { goal: string; files?: string[] };
  /** Only agent state items whose lineage starts with this prefix are shown (independent sessions per model). */
  statePrefix?: string;
  /** Tokens this round may use before it is told to wrap up (the domain's share left). */
  tokenCap: number;
  /** Earlier rounds of the domain: directions left open, findings already submitted, and the gaps they left. */
  previous?: { openLeads: OpenLead[]; findings: string[]; gaps?: DomainGaps };
  /** Names of the other domains (out-of-domain problems may still be submitted). */
  others: string[];
  /** Threat-model hypotheses this round must give a verdict on (⑧ merged into the expert). */
  hypotheses: HypothesisRow[];
  /** Conclusions of earlier expert rounds on the hypotheses' places, citable by `sameAs`. */
  prior?: PriorConclusions;
  /** access-policy differences this domain owns that have no conclusion yet (must-answer). */
  access?: AccessCheck[];
  /** OSV hits for the domain that owns dependency issues (first round only; leads). */
  dependencies?: DependencyHit[];
}

/** Same shape as a hunt batch listing (id, then location, then label). */
function candidateLine(c: Candidate): string {
  return `- id=\`${c.id}\`\n  位置：${c.repo}:${c.path}:${c.line}\n  ${c.label}${c.reason ? `\n  初筛：${c.llmScore}/5 ${c.reason}` : ''}`;
}

/** Prompt of one expert round. */
export function expertPrompt(rt: AuditRuntime, d: PlannedDomain, round: number, leads: Candidate[], o: Pick<DomainExpertOptions, 'previous' | 'others' | 'hypotheses' | 'prior' | 'access' | 'dependencies' | 'task'>): string {
  const impact = rt.audit.scene === 'incremental' && rt.impacts().size ? rt.impacts() : null;
  const changed = impact ? changedFileList(rt, impact) : [];
  return [
    P('domains.expert.intro', { name: d.name, round, maxRounds: DOMAIN_ROUNDS }),
    '',
    `## 你的领域：${d.name}`,
    `关注点：${d.focus}`,
    ...(d.userFocus?.length ? [P('domains.expert.user_focus'), ...d.userFocus.map((f) => `- ${f}`)] : []),
    `本领域的漏洞类别：${d.categories.join('、')}。`,
    P('domains.expert.others', { others: o.others.join('、') || '（无）' }),
    ...(o.task ? [
      '', P('domains.expert.task_heading'),
      `目标：${o.task.goal}`,
      ...(o.task.files?.length ? [`从这些文件开始：${o.task.files.join('、')}`] : []),
      P('domains.expert.task_rule'),
    ] : []),
    '',
    P('domains.expert.method'),
    // session / cross-site / robustness domains start from the checklist (when the skill is enabled).
    ...(d.categories.some((c) => SESSION_CATEGORIES.includes(c)) && rt.knowledge.skills.some((s) => s.name === SESSION_CHECKLIST)
      ? [P('domains.expert.session_checklist', { skill: SESSION_CHECKLIST })] : []),
    P('domains.expert.budget'),
    ...(o.hypotheses.length ? [P('domains.expert.hypotheses', { n: o.hypotheses.length })] : []),
    '',
    P('domains.expert.submit'),
    ...(o.hypotheses.length ? [P('domains.expert.submit_verdicts')] : []),
    P('domains.expert.open_leads', { next: round < DOMAIN_ROUNDS ? P('domains.expert.open_leads_next') : P('domains.expert.open_leads_last') }),
    ...(impact ? ['', P('domains.expert.incremental', { n: changed.length }), `变更文件：${changed.slice(0, 60).join('、') || '（无）'}${changed.length > 60 ? ' …' : ''}`] : []),
    ...(o.previous ? [
      '', P('domains.expert.previous_heading'),
      ...(o.previous.findings.length ? [
        P('domains.expert.previous_findings', { n: o.previous.findings.length, more: o.previous.findings.length > PUSHED_FINDINGS ? P('domains.expert.previous_findings_more', { shown: PUSHED_FINDINGS }) : '' }),
        ...o.previous.findings.slice(-PUSHED_FINDINGS).map((f) => `- ${f}`),
      ] : [P('domains.expert.no_previous_findings')]),
      ...(o.previous.openLeads.length ? [P('domains.expert.previous_leads'), ...o.previous.openLeads.map((l) => `- ${l.direction}${l.files.length ? `（从 ${l.files.join('、')} 开始）` : ''}`)] : []),
    ] : []),
    ...(o.previous?.gaps ? gapLines(o.previous.gaps) : []),
    ...accessLines(o.access ?? []),
    ...dependencyLines(o.dependencies ?? []),
    ...(d.mechanisms.length ? ['', P('domains.expert.mechanisms_heading'), ...d.mechanisms.map((m) => `- ${m.name}：${m.why}（${m.location.repo}:${m.location.path}:${m.location.startLine}）`)] : []),
    ...(d.leads.length ? ['', P('domains.expert.risk_points_heading'), ...d.leads.map((l) => `- ${l.statement}${l.entries.length ? `；入口：${l.entries.join('、')}` : ''}${l.files.length ? `；文件：${l.files.join('、')}` : ''}`)] : []),
    ...(o.hypotheses.length ? ['', ...verificationLines(o.hypotheses, o.prior)] : []),
    ...(leads.length ? [
      '', P('domains.expert.leads_heading', { n: leads.length, more: leads.length > PUSHED_LEADS ? P('domains.expert.leads_more', { shown: PUSHED_LEADS }) : '' }),
      ...leads.slice(0, PUSHED_LEADS).map(candidateLine),
    ] : ['', P('domains.expert.no_leads')]),
  ].join('\n');
}

/** the domain's leads and the findings of earlier rounds beyond what the prompt shows, paged. */
function domainContextTool(leads: Candidate[], findings: string[]): AuditTool {
  return {
    name: 'domain_context', kind: 'read',
    description: P('tool.domain_context'),
    parameters: Type.Object({
      kind: Type.Union([Type.Literal('leads'), Type.Literal('findings')]),
      offset: Type.Optional(Type.Integer({ minimum: 0 })), limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 30 })),
    }, { additionalProperties: false }),
    run(a: { kind: 'leads' | 'findings'; offset?: number; limit?: number }) {
      const offset = a.offset ?? 0, limit = a.limit ?? 20;
      const all = a.kind === 'leads' ? leads.map(candidateLine) : findings.map((f) => `- ${f}`);
      const page = all.slice(offset, offset + limit);
      return { text: page.length ? `${a.kind === 'leads' ? '线索' : '已提交的发现'} ${offset + 1}–${offset + page.length} / ${all.length}：\n${page.join('\n')}` : `没有更多（共 ${all.length} 条）。` };
    },
  };
}

/** `project_profile`: the full profile and threat model of a repository, on demand. */
export function profileTool(rt: AuditRuntime): AuditTool {
  return {
    name: 'project_profile', kind: 'read',
    parameters: Type.Object({ repo: Type.Optional(Type.String({ maxLength: 200, description: 'Repository name; default the first target' })) }, { additionalProperties: false }),
    description: P('tool.project_profile'),
    run(a: { repo?: string }) {
      const repo = a.repo ? rt.repoByName(a.repo) : rt.targets[0];
      if (!repo) throw new Error(`unknown repo ${a.repo}`);
      const out = profileFor(rt, repo);
      // The cross-repository system model goes with every repository's profile.
      const system = auditSystemModel(rt);
      const sysText = system ? `\n\n### 系统（跨仓库）\n${renderSystemModel(system, undefined, 20_000)}` : '';
      if (!out) return { text: `${P('data.project_profile_missing', { repo: repo.name })}${sysText}` };
      return { text: `${P('data.project_profile')}\n${renderThreatModel(out.profile, 40_000)}${sysText}` };
    },
  };
}

const PRUNABLE = ['findings', 'verdicts', 'reviewedTargets', 'ruledOut', 'hypotheses', 'openLeads'] as const;
const ITEM_ISSUE = new RegExp(`^(?:\\$\\.)?(${PRUNABLE.join('|')})(?:\\.|\\[)(\\d+)`);

/**
 * an expert call with issues keeps what is sound — the list items the issues point at are dropped
 * (a verdict citing a dropped finding goes with it; the others are renumbered), and the model is told which, to submit
 * them again fixed. Null (refuse as before) when an issue is not about one item, or nothing would be dropped.
 */
export function pruneExpertSubmission(args: Record<string, unknown>, issues: string[]): { args: Record<string, unknown>; note: string } | null {
  const bad = new Map<string, Map<number, string>>();
  for (const issue of issues) {
    const m = ITEM_ISSUE.exec(issue.trim());
    if (!m) return null;
    const byIndex = bad.get(m[1]!) ?? bad.set(m[1]!, new Map()).get(m[1]!)!;
    if (!byIndex.has(Number(m[2]))) byIndex.set(Number(m[2]), issue.trim().slice(0, 200));
  }
  if (!bad.size) return null;
  const out: Record<string, unknown> = { ...args };
  const list = (k: string) => (Array.isArray(args[k]) ? (args[k] as unknown[]) : null);
  const findings = list('findings');
  const droppedFindings = bad.get('findings') ?? new Map<number, string>();
  if (findings && droppedFindings.size) {
    const newIndex = new Map<number, number>();
    out.findings = findings.filter((_, i) => {
      if (droppedFindings.has(i)) return false;
      newIndex.set(i, newIndex.size);
      return true;
    });
    // Verdicts index the call's findings: renumber them; one citing a dropped finding is dropped too.
    const verdicts = list('verdicts');
    if (verdicts) {
      const vBad = bad.get('verdicts') ?? bad.set('verdicts', new Map()).get('verdicts')!;
      verdicts.forEach((v, i) => {
        const f = (v as { finding?: unknown }).finding;
        if (typeof f === 'number' && droppedFindings.has(f) && !vBad.has(i)) vBad.set(i, P('feedback.domains.dropped_verdict', { i, f }));
      });
      out.verdicts = verdicts.map((v) => {
        const f = (v as { finding?: unknown }).finding;
        return typeof f === 'number' && newIndex.has(f) ? { ...(v as object), finding: newIndex.get(f) } : v;
      });
    }
  }
  for (const k of PRUNABLE) {
    if (k === 'findings') continue;
    const idx = bad.get(k);
    const items = Array.isArray(out[k]) ? (out[k] as unknown[]) : null;
    if (idx?.size && items) out[k] = items.filter((_, i) => !idx.has(i));
  }
  const dropped = [...bad].flatMap(([k, m]) => [...m].map(([i, why]) => `${k}[${i}]：${why}`));
  return {
    args: out,
    note: P('feedback.domains.partial_accept', { items: dropped.slice(0, 20).join('\n- ') }),
  };
}

/**
 * The repository a domain works in when everything it was given (mechanisms, threat-model leads, pushed
 * leads) is in one: its tools and unqualified code references default to it. A domain spanning several repositories
 * (merged by name) or with nothing located keeps the audit's first target.
 */
export function domainRepo(d: Pick<PlannedDomain, 'mechanisms' | 'leads'>, leads: readonly { repo: string }[] = []): string | undefined {
  const repos = new Set([...d.mechanisms.map((m) => m.location.repo), ...d.leads.map((l) => l.repo), ...leads.map((c) => c.repo)].filter(Boolean));
  return repos.size === 1 ? [...repos][0] : undefined;
}

/**
 * The domain whose expert answers a hypothesis: the first runnable domain covering its category — of the
 * hypothesis's own repository first, then one not tied to a repository (a multi-repository audit has each
 * repository's domains).
 */
export function hypothesisOwner(domains: readonly PlannedDomain[], category: string, repo: string | undefined, leads?: ReadonlyMap<string, readonly { repo: string }[]>): string | undefined {
  const covering = domains.filter((d) => d.categories.includes(category));
  const repoOf = (d: PlannedDomain) => domainRepo(d, leads?.get(d.id));
  return (covering.find((d) => repo !== undefined && repoOf(d) === repo) ?? covering.find((d) => !repoOf(d)) ?? covering[0])?.id;
}

/** One round of one domain expert. */
export async function domainExpertStep(rt: AuditRuntime, d: PlannedDomain, round: number, leads: Candidate[], lineage: string, ctx: AttemptContext, o: DomainExpertOptions): Promise<StepResult> {
  const { state } = loadState(rt.store, rt.auditId);
  const hyps = o.hypotheses;
  /** Hypotheses with a verdict in an accepted earlier call of this session. */
  const verdicted = new Set<string>();
  /** index targets given a verdict by accepted calls of this round. */
  const answered = new Set<string>();
  const gaps = o.previous?.gaps;
  /** the round's must-answer gaps still open — mechanisms this round did not read, leads it gave no verdict. */
  const gapsLeft = (): DomainGaps => ({
    mechanisms: (gaps?.mechanisms ?? []).filter((m) => !readBySteps(rt, [ctx.stepId], { repo: m.location.repo, path: m.location.path, startLine: m.location.startLine, endLine: m.location.endLine ?? m.location.startLine })),
    leads: (gaps?.leads ?? []).filter((c) => !answered.has(c.id)),
  });
  /** access checks of this round still without a verdict. */
  const accessLeft = () => (o.access ?? []).filter((c) => !answered.has(c.entryId));
  const schema = hyps.length ? SubmitDomainVerification : SubmitDomainFindings;
  const submit: AuditTool = {
    name: 'submit_findings', kind: 'submit', parameters: linkedThreatModels(rt).length ? withRelatedRisk(schema) : schema,
    description: hyps.length
      ? P('tool.submit_findings.domain_verify')
      : P('tool.submit_findings.domain'),
    // an id the expert mistyped in reviewedTargets / ruledOut is dropped from its coverage claims instead of
    // refusing the whole submission (its findings would be lost with it). Likewise a `finding` verdict with no
    // finding of the same call behind it is downgraded to `suspicious` (below) instead of refusing the call.
    validate: (a) => [
      ...validateFindings(rt, a).filter((i) => !i.startsWith('unknown targetId ') && !i.startsWith(UNCOVERED_FINDING_PREFIX)),
      ...relatedRiskIssues(rt, a.findings as { relatedRisk?: string }[]),
      ...(hyps.length ? verdictIssues(hyps, (a as { verdicts?: HypothesisVerdictDraft[] }).verdicts ?? [], a.findings.length, (ref, label, read) => validateCodeRef(rt, ref, label, read), verdicted, o.prior, false) : []),
    ].slice(0, 30),
    // one faulty item no longer refuses the whole call.
    prune: (a, issues) => pruneExpertSubmission(a as Record<string, unknown>, issues),
    run: (a: { findings: FindingDraft[]; reviewedTargets: { targetId: string }[]; ruledOut: { targetId: string }[]; verdicts?: HypothesisVerdictDraft[] }) => {
      for (const v of a.verdicts ?? []) verdicted.add(v.hypothesisId);
      for (const t of [...a.reviewedTargets, ...a.ruledOut]) answered.add(t.targetId);
      for (const f of a.findings) for (const id of [f.sink?.sinkId, ...f.entries]) if (id) answered.add(id);
      return { text: `accepted ${a.findings.length} finding(s)${a.verdicts?.length ? `, ${a.verdicts.length} verdict(s)` : ''}` };
    },
  };
  const submitState: AuditTool = {
    name: 'submit_state_update', kind: 'submit', parameters: SubmitStateUpdate,
    description: P('tool.submit_state_update.domain'),
    run: () => ({ text: 'recorded' }),
  };
  const impact = rt.audit.scene === 'incremental' && rt.impacts().size ? rt.impacts() : null;
  const model = o.model ?? rt.strategy.models.audit;
  const repo = domainRepo(d, leads);
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'hunt', phase: 'hunt', model, signal: ctx.signal,
    prompt: expertPrompt(rt, d, round, leads, o), submitTools: [submit, submitState], requiredSubmits: ['submit_findings'], maxTurns: rt.strategy.limits.maxTurnsPerStep,
    ...(repo ? { repo } : {}),
    extraTools: [...(impact ? [diffTool(rt, impact)] : []), taskTool(rt, ctx, model), profileTool(rt), stateQueryTool(rt, o.statePrefix),
      ...(leads.length > PUSHED_LEADS || (o.previous?.findings.length ?? 0) > PUSHED_FINDINGS ? [domainContextTool(leads, o.previous?.findings ?? [])] : [])],
    // a summary of the cognitive state (state_query for the rest); no threat-model summary in the
    // system prompt (project_profile reads it); the knowledge index filtered to the domain's classes.
    cognitiveSlice: sliceSummary(stateFor(state, o.statePrefix), [...leads.map((c) => c.path), ...d.mechanisms.map((m) => m.location.path), ...d.leads.flatMap((l) => l.files), ...o.hypotheses.flatMap((h) => relatedOf(h).files)]),
    threatModel: false, vulnClasses: d.categories,
    askUser: true, tokenCap: o.tokenCap,
    // what the round pushed, for the push-usage telemetry.
    pushed: [
      { kind: 'lead', ids: leads.slice(0, PUSHED_LEADS).map((c) => c.id) },
      { kind: 'hypothesis', ids: hyps.map((h) => h.id) },
      { kind: 'gap', ids: (gaps?.leads ?? []).map((c) => c.id) },
      { kind: 'access', ids: (o.access ?? []).map((c) => c.entryId) },
    ],
    knowledgeNeeds: state.knowledgeNeeds.filter((k) => !k.retired).map((k) => ({ topic: k.text })),
    ...(!gapsEmpty(gaps) || o.access?.length ? {
      completionCheck: () => {
        const left = gapsLeft();
        const access = accessLeft();
        if (gapsEmpty(left) && !access.length) return null;
        rt.event('judgement.made', { kind: 'domain_gaps', phase: 'asked', domain: d.name, round, mechanisms: left.mechanisms.map((m) => m.name), leads: left.leads.length, access: access.length }, ctx.stepId);
        return gapsLeftPrompt({ mechanisms: left.mechanisms, leads: [...left.leads, ...access.filter((c) => !left.leads.some((l) => l.id === c.entryId)).map((c) => ({ id: c.entryId, kind: 'entry', repo: c.repo, path: '', line: 0, label: c.entryKey, score: 0 }) as Candidate)] });
      },
    } : {}),
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const known = new Set([...rt.indexes.values()].flatMap((idx) => [...idx.entrypoints.map((e) => e.entryId), ...idx.sinks.map((k) => k.sinkId)]));
  const subs = (outcome.submissions.submit_findings ?? []) as (HuntOutput & { findings: FindingDraft[]; openLeads?: OpenLead[]; scopeReviewed: string })[];
  // per call, a `finding` verdict no finding of that call covers becomes `suspicious` (the target stays concluded,
  // the claim of a vulnerability does not stand without a finding).
  const downgraded: string[] = [];
  for (const sub of subs) {
    const uncovered = new Set(uncoveredFindingTargets(rt, sub));
    if (!uncovered.size) continue;
    sub.reviewedTargets = sub.reviewedTargets.map((t) => (uncovered.has(t.targetId) && t.verdict === 'finding' ? { ...t, verdict: 'suspicious' } : t));
    downgraded.push(...uncovered);
  }
  const ops = ((outcome.submissions.submit_state_update ?? []) as { ops: StateOp[] }[]).flatMap((s) => s.ops);
  const out: DomainOutput = {
    // Under cross-checking the slot key, so a model chosen twice counts as two experts.
    ...(rt.fallbacks.has(ctx.stepId) ? { model: `${rt.modelFor(ctx.stepId, model).provider}/${rt.modelFor(ctx.stepId, model).model}` }
      : o.model ? { model: o.modelKey ?? `${o.model.provider}/${o.model.model}` } : {}),
    domain: d.name, round,
    batch: [],
    findings: subs.flatMap((s) => s.findings).map((f) => ({ ...f, knowledge: rt.knowledgeRefs(ctx.stepId, f.knowledgeRefs), connectors: rt.connectorRefs(ctx.stepId, f.connectorRefs), facts: rt.factRefs(ctx.stepId, f.factRefs) })),
    reviewedTargets: subs.flatMap((s) => s.reviewedTargets).filter((t) => known.has(t.targetId)),
    ruledOut: subs.flatMap((s) => s.ruledOut).filter((t) => known.has(t.targetId)),
    scopeReviewed: subs.map((s) => s.scopeReviewed),
    stateOps: ops,
    ...(!hyps.length && subs.some((x) => x.hypotheses?.length) ? { hypotheses: subs.flatMap((x) => x.hypotheses ?? []) } : {}),
    ...(hyps.length ? { verdicts: verdictsOf(subs) } : {}),
    // The last call's directions count: a later call replaces what an earlier one left open.
    openLeads: [...subs].reverse().find((s) => s.openLeads)?.openLeads ?? [],
  };
  const outputRef = rt.store.artifacts.putJson(out);
  return {
    outputRef,
    apply: () => {
      applyHunt(rt, ctx.stepId, lineage, out, o.prior);
      if (downgraded.length) rt.event('contract.violation', { tool: 'submit_findings', attempt: 0, issues: [`verdict "finding" without a finding of the same call, downgraded to suspicious: ${[...new Set(downgraded)].slice(0, 20).join(', ')}`] }, ctx.stepId);
      rt.event('judgement.made', { kind: 'domain_round', domain: d.name, round, findings: out.findings.length, concluded: out.reviewedTargets.length + out.ruledOut.length, openLeads: out.openLeads.length, ...(hyps.length ? { hypotheses: hyps.length, verdicts: out.verdicts?.length ?? 0 } : {}) }, ctx.stepId);
    },
  };
}
