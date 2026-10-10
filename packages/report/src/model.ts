// Report intermediate model: built from a read-only data snapshot of the store;
// every renderer consumes the same model. No LLM involvement; fixed ordering → identical bytes.
import { normalizePending, type PendingCondition } from '@xiezhi/contracts';
import type { PartialReason, Severity } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { reportVerification, type ReportVerification } from './verification.js';

export const REPORT_SCHEMA_VERSION = 1;

export interface CodeLoc { repo: string; path: string; startLine: number; endLine: number; note?: string }

export function pendingOfDetail(d: FindingDetail): PendingCondition | null {
  return normalizePending(d.pendingCondition) ?? normalizePending(d.missingContext);
}

export const MISSING_KIND_ZH: Record<string, string> = { repo: '仓库', gateway_policy: '网关策略', config: '配置', business_rule: '业务规则', external_service: '外部服务' };
export const PENDING_ACTION_ZH: Record<string, string> = { add_repo: '添加仓库', add_knowledge: '补充知识', query_connector: '通过连接器查询', ask_user: '询问用户' };

export interface KnowledgeUsageItem {
  name: string;
  layer: string;
  /** Highest level loaded: index / body / file. */
  maxLevel: string;
  /** Usage records (index injections, bodies, files). */
  reads: number;
  /** Distinct steps that loaded it. */
  steps: number;
  tokens: number;
  /** Reported findings that cite it (`knowledgeRefs`). */
  citedBy: number;
}

/**
 * Knowledge used by an audit, aggregated per skill (审计结果汇总): highest level, reads,
 * steps, tokens, and how many reported findings cite it. `citedShare` = skills whose body or file was
 * loaded and that are cited, over skills whose body or file was loaded.
 */
export function knowledgeUsage(store: Store, auditId: string): { items: KnowledgeUsageItem[]; knowledgeTokens: number; citedShare: number | null } {
  const rows = store.all<{ skill_name: string; layer: string; lvl: number; reads: number; steps: number; tokens: number }>(
    `SELECT skill_name, layer, MAX(CASE level WHEN 'file' THEN 3 WHEN 'body' THEN 2 ELSE 1 END) AS lvl, COUNT(*) AS reads,
       COUNT(DISTINCT step_id) AS steps, SUM(tokens) AS tokens
     FROM skill_usage WHERE audit_id = ? GROUP BY skill_name, layer ORDER BY skill_name`, auditId);
  const cites = store.all<{ path: string; n: number }>(
    `SELECT e.path, COUNT(DISTINCT e.owner_id) AS n FROM evidence e JOIN finding f ON f.id = e.owner_id
     WHERE e.owner_kind = 'finding' AND e.kind = 'knowledge' AND f.audit_id = ? AND f.state = 'canonical' GROUP BY e.path`, auditId);
  const citedBy = (layer: string, name: string) => cites.filter((c) => c.path === `${layer}:${name}` || c.path.startsWith(`${layer}:${name}/`)).reduce((n, c) => n + c.n, 0);
  const items = rows.map((k) => ({
    name: k.skill_name, layer: k.layer, maxLevel: ['', 'index', 'body', 'file'][k.lvl] ?? 'index', reads: k.reads, steps: k.steps, tokens: k.tokens ?? 0,
    citedBy: citedBy(k.layer, k.skill_name),
  }));
  const loaded = items.filter((i) => i.maxLevel !== 'index');
  return {
    items, knowledgeTokens: items.reduce((n, i) => n + i.tokens, 0),
    citedShare: loaded.length ? loaded.filter((i) => i.citedBy > 0).length / loaded.length : null,
  };
}

export interface FindingDetail {
  evidence: CodeLoc[];
  chain: CodeLoc[];
  reasoning: string;
  counterCheck: string;
  exploitConditions: { condition: string; status: string; source: string }[];
  remediation: { approach: string; suggestion?: string; verification?: string };
  /** attack path and impact; absent for findings submitted before it was recorded. */
  attackPath?: string;
  impact?: string;
  /** Structured pending condition; older details carry `missingContext` — read both via `pendingOfDetail`. */
  pendingCondition?: PendingCondition;
  missingContext?: { needs: string; holdsIf: string; notHoldsIf: string };
  challenge?: { codeDefense: string; threatModel: string; affirm: string; confirmation: string; confidenceDelta: number; reason: string };
  /** Connector results the conclusions cite: authoritative ones count as verified facts. */
  externalEvidence?: { source: string; authoritative: boolean; note: string | null }[];
}

export interface ReportFinding {
  displayNo: number;
  /** own-service defect / relies on an upstream guarantee / cross-service risk, and what the trust setting did. */
  boundary?: 'own' | 'upstream' | 'cross_service';
  boundaryNote?: string;
  /** its adversarial review failed (a tolerated share; the completion gate lists it). */
  unreviewed?: boolean;
  vulnId: string | null;
  vulnDisplayNo: number | null;
  title: string;
  category: string;
  cwe: string | null;
  severity: Severity;
  severityOriginal: Severity | null;
  confidence: string;
  confirmStatus: string;
  handlingStatus: string;
  handlingReason: string | null;
  lifecycle: string;
  sources: string[];
  repo: string;
  location: CodeLoc;
  sinkSymbol: string | null;
  sinkApi: string | null;
  entries: string[];
  rootCause: string;
  fingerprint: string | null;
  pendingKind: string | null;
  detail: FindingDetail;
  /** verification cases written for the user (with their result) and the latest patch suggestion. */
  verification?: ReportVerification;
  /** Project-level export only: the audit whose finding supplied the location and details. */
  origin?: { auditId: string | null; auditTitle: string | null; findingNo: number | null; rootHash: string | null };
}

export interface ReportRepo {
  id: string;
  name: string;
  role: string;
  roleInAudit: string;
  locator: string;
  rootHash: string;
  commit: string | null;
  ref: string | null;
  worktree: boolean;
}

export interface CoverageSummary {
  entry: { total: number; reviewed: number; readOnly: number };
  sink: { total: number; reviewed: number; readOnly: number };
  reading: { totalLines: number; readLines: number };
  /** `reason`: why the item has no conclusion, from the completion gate; absent for audits gated by older versions. */
  uncovered: { kind: string; targetId: string; path: string; line: number; status: string; reason?: string }[];
  /** items without a conclusion by reason (the completion gate's count; absent in older audits). */
  unconcluded?: { total: number; byReason: Record<string, number> };
  /** source files by reading, and unread security-named files no entry / sink anchors (report only). */
  files?: FileCoverage;
}

/** file-level coverage of the audit's source files. */
export interface FileCoverage {
  total: number; unread: number; read: number; concluded: number;
  /** Unread source files without any entry / sink whose path suggests security code (at most FILE_SIGNAL_LISTED). */
  signalUnread: { repo: string; path: string }[];
  signalUnreadTotal: number;
}
const FILE_SIGNAL_LISTED = 50;
/** Path words of security-relevant code (authentication, sessions, permissions, crypto, filters, file transfer, sharing). */
const SECURITY_PATH = /(auth|login|logout|session|token|jwt|oauth|sso|secur|permission|perm|acl|rbac|role|filter|interceptor|middleware|guard|crypto|cipher|passw|credential|admin|upload|download|share|websocket|socket|captcha|verify)/i;
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|fixtures?|mocks?|examples?)\/|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(go|py)$|Tests?\.(java|kt|cs)$/i;

/** Files of the audit's repositories: none read / some lines read / holding a concluded entry or sink. */
export function fileCoverage(store: Store, auditId: string, repos: { id: string; name: string; manifest_ref: string | null }[]): FileCoverage {
  const out: FileCoverage = { total: 0, unread: 0, read: 0, concluded: 0, signalUnread: [], signalUnreadTotal: 0 };
  for (const r of repos) {
    if (!r.manifest_ref) continue;
    const m = store.artifacts.getJson<{ files: { path: string; lang?: string; indexable?: boolean }[] }>(r.manifest_ref);
    const read = new Set(store.all<{ path: string }>('SELECT path FROM read_coverage WHERE audit_id = ? AND repository_id = ? AND lines_read > 0', auditId, r.id).map((x) => x.path));
    const items = store.all<{ path: string; status: string }>('SELECT path, status FROM coverage_item WHERE audit_id = ? AND repository_id = ?', auditId, r.id);
    const anchored = new Set(items.map((i) => i.path));
    const concluded = new Set(items.filter((i) => i.status === 'concluded').map((i) => i.path));
    for (const f of m.files ?? []) {
      if (!f.lang || f.indexable === false) continue;
      out.total++;
      if (concluded.has(f.path)) out.concluded++;
      else if (read.has(f.path)) out.read++;
      else {
        out.unread++;
        if (!anchored.has(f.path) && SECURITY_PATH.test(f.path) && !TEST_PATH.test(f.path)) {
          out.signalUnreadTotal++;
          if (out.signalUnread.length < FILE_SIGNAL_LISTED) out.signalUnread.push({ repo: r.name, path: f.path });
        }
      }
    }
  }
  return out;
}

/** the completion gate's list of items without a conclusion and why (engine `UnconcludedSummary`). */
export interface ReportUnconcluded { total: number; byReason: Record<string, number>; items: { targetId: string; reason: string }[] }
/** Status and gate results the report step passes before they are stored on the audit. */
export interface ReportOverride { status: string; partialReasons: PartialReason[]; unconcluded?: ReportUnconcluded; notices?: string[]; unreviewed?: string[]; obligations?: ReportObligations }
/** obligations by kind and source (the engine's ObligationSummary without its item list). */
export interface ReportObligations { total: number; settled: number; byKind: Record<string, { total: number; settled: number }>; bySource: Record<string, { total: number; settled: number }> }
/** obligation kinds and sources as the report says them. */
export const OBLIGATION_KIND_ZH: Record<string, string> = { entry: '入口', sink: '危险点', hypothesis: '风险假设', access: '访问策略差异', checklist: '清单条目', external: '外部扫描结果' };
export const OBLIGATION_SOURCE_ZH: Record<string, string> = { rule: '结构索引规则', model: '模型补充', threat_model: '威胁建模', requirement: '需求威胁模型', access_policy: '访问策略', checklist: '清单', external: '外部扫描', user: '人工' };

/** why an item has no conclusion, as the report says it. */
export const UNCONCLUDED_REASON_ZH: Record<string, string> = {
  concluded_without_reading: '有结论但阅读不足', assigned_no_verdict: '分配后未给结论', read_no_verdict: '读过未下结论',
  not_selected: '未入选（超出候选上限或初筛分过低）', not_assigned: '未分配给任何会话',
};

/** access levels and how an access check ended, as the report says them. */
export const ACCESS_LEVEL_ZH: Record<string, string> = { public: '公开', authenticated: '需要登录', role: '需要角色', owner: '只能访问本人的资源' };
export function accessVerdictZh(v: string | null): string {
  if (!v) return '未结论';
  if (v === 'finding') return '有问题（见发现）';
  if (v === 'suspicious') return '可疑';
  if (v === 'no_issue') return '已确认满足';
  return v.startsWith('ruled_out') ? '已排除' : v;
}

/** “（分配后未给结论 3、读过未下结论 2）” — the non-zero reasons, or empty. */
export function unconcludedText(byReason: Record<string, number>): string {
  const parts = Object.entries(byReason).filter(([, n]) => n > 0).map(([r, n]) => `${UNCONCLUDED_REASON_ZH[r] ?? r} ${n}`);
  return parts.length ? `（${parts.join('、')}）` : '';
}

export interface ReportModel {
  schemaVersion: number;
  audit: {
    id: string; title: string; scene: string; mode: string; status: string; partialReasons: PartialReason[];
    /** completion-gate notices that do not make the audit partial (absent in older audits). */
    notices?: string[];
    strategyHash: string | null; startedAt: number | null; endedAt: number | null;
    usage: { tokens: number; durationMs: number; costMicros: number | null };
    executionNote: string;
  };
  project: { id: string; name: string };
  repositories: ReportRepo[];
  findings: ReportFinding[];
  insufficient: ReportFinding[];
  /** cross-service risks kept as hints (trusted internal network): not published as vulnerabilities. */
  serviceHints?: ReportFinding[];
  coverage: CoverageSummary | null;
  /** the obligation ledger settled by the completion gate (absent in older audits). */
  obligations?: ReportObligations;
  knowledge: KnowledgeUsageItem[];
  injectionNotices: { path: string; signal: string }[];
  /** declared dependencies per repository and the OSV hits (when an OSV connector was enabled). */
  dependencies?: { repos: { repo: string; total: number; versioned: number }[]; osv: { available: boolean; queried: number; failed: number }; hits: { repo: string; ecosystem: string; name: string; version: string; path: string; advisories: { id: string; summary: string | null; aliases: string[] }[] }[] };
  /** entries whose auth signals did not obviously meet the threat model's access policy, and how they ended. */
  access?: { entryKey: string; level: string; role?: string; category: string; why: string; verdict: string | null }[];
  excludedControlFiles: { repo: string; path: string }[];
  /** Present only when the export narrowed the findings. */
  selection?: { vulns: number | null; includePending: boolean };
  /** Present only when the export asked for it: one row per step. */
  trajectory?: TrajectoryStep[];
  /** Present only for a project-level export: `audit` then describes the project, findings are vulnerabilities. */
  scope?: { kind: 'project'; vulns: number; audits: { id: string; title: string; endedAt: number | null }[] };
}

export interface TrajectoryStep { kind: string; lineage: string | null; status: string; durationMs: number; tokens: number; toolCalls: number; firstNote: string | null }

/** Export options that change the content: selected vulnerabilities, pending findings, trajectory summary. */
export interface ReportFilter { vulnIds?: string[]; includePending?: boolean; trajectory?: boolean }

export const STATIC_AUDIT_NOTE = '静态审计：未构建、未运行、未测试目标代码。';
export const COVERAGE_NOTE = '覆盖不等于检出率：100% 入口覆盖只说明每个入口都被阅读并给出了判断，不说明判断正确。';

const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

export function compareFindings(a: ReportFinding, b: ReportFinding): number {
  return (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0)
    || a.category.localeCompare(b.category)
    || (a.fingerprint ?? '').localeCompare(b.fingerprint ?? '')
    || a.displayNo - b.displayNo;
}

interface FindingRow {
  id: string; display_no: number | null; title: string; category: string; cwe: string | null; severity: Severity; confidence: string;
  repository_id: string; location: string; sink_symbol: string | null; sink_api: string | null; entry_keys: string; root_cause: string | null;
  fp_sink: string | null; detail_ref: string; state: string; confirmation: string; challenge_ref: string | null;
  boundary?: 'own' | 'upstream' | 'cross_service' | null; boundary_note?: string | null;
}

export function buildReportModel(store: Store, auditId: string, override?: ReportOverride, filter: ReportFilter = {}): ReportModel {
  const a = store.get<Record<string, any>>('SELECT * FROM audit WHERE id = ?', auditId);
  if (!a) throw new Error(`audit ${auditId} not found`);
  const project = store.get<{ id: string; name: string }>('SELECT id, name FROM project WHERE id = ?', a.project_id)!;
  const repoRows = store.all<Record<string, any>>(
    `SELECT r.id, r.name, r.role, ar.role_in_audit, s.root_hash, s.manifest_ref, s.resolved_commit, s.requested_ref, s.is_worktree, r.source_uri
     FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id LEFT JOIN snapshot s ON s.id = ar.snapshot_id
     WHERE ar.audit_id = ? ORDER BY r.name`, auditId);
  const repos: ReportRepo[] = repoRows.map((r) => ({
    id: r.id, name: r.name, role: r.role, roleInAudit: r.role_in_audit, locator: r.source_uri, rootHash: r.root_hash ?? '',
    commit: r.resolved_commit ?? null, ref: r.requested_ref ?? null, worktree: !!r.is_worktree,
  }));
  const repoName = new Map(repos.map((r) => [r.id, r.name]));

  const rows = store.all<FindingRow>(`SELECT * FROM finding WHERE audit_id = ? AND state IN ('canonical','insufficient') ORDER BY display_no, id`, auditId);
  // the completion gate's notices and unreviewed findings (passed by the report step, or stored with the gate).
  const gateStored = a.gate_ref ? store.artifacts.getJson<{ notices?: string[]; unreviewed?: string[]; obligations?: ReportObligations }>(a.gate_ref) : null;
  const ob = override?.obligations ?? gateStored?.obligations;
  const gateNotices = override?.notices ?? gateStored?.notices ?? [];
  const unreviewedIds = new Set(override?.unreviewed ?? gateStored?.unreviewed ?? []);
  const toFinding = (f: FindingRow): ReportFinding => {
    const occ = store.get<{ vulnerability_id: string }>('SELECT vulnerability_id FROM vuln_occurrence WHERE audit_id = ? AND finding_id = ?', auditId, f.id);
    const v = occ ? store.get<Record<string, any>>('SELECT * FROM vulnerability WHERE id = ?', occ.vulnerability_id) : undefined;
    const detail = store.artifacts.getJson<FindingDetail>(f.detail_ref);
    if (f.challenge_ref) detail.challenge = store.artifacts.getJson(f.challenge_ref);
    const ext = store.all<{ path: string; verified: number; note: string | null }>(`SELECT path, verified, note FROM evidence WHERE owner_kind = 'finding' AND owner_id = ? AND kind = 'connector' ORDER BY ord`, f.id);
    if (ext.length) detail.externalEvidence = ext.map((x) => ({ source: x.path.replace(/^connector:/, ''), authoritative: x.verified === 1, note: x.note }));
    const loc = fromJson<CodeLoc>(f.location, { repo: '', path: '', startLine: 1, endLine: 1 });
    return {
      displayNo: f.display_no ?? 0, ...(unreviewedIds.has(f.id) ? { unreviewed: true } : {}),
      ...(f.boundary ? { boundary: f.boundary } : {}), ...(f.boundary_note ? { boundaryNote: f.boundary_note } : {}), vulnId: v?.id ?? null, vulnDisplayNo: v?.display_no ?? null,
      title: f.title, category: f.category, cwe: f.cwe, severity: (v?.severity ?? f.severity) as Severity, severityOriginal: v?.severity_original ?? null,
      confidence: f.confidence, confirmStatus: v?.confirm_status ?? (f.state === 'insufficient' ? 'pending' : 'pending'),
      handlingStatus: v?.handling_status ?? 'open', handlingReason: v?.handling_reason ?? null, lifecycle: v?.lifecycle ?? 'new',
      sources: fromJson<string[]>(v?.sources, ['ai']), repo: repoName.get(f.repository_id) ?? loc.repo,
      location: { ...loc, repo: repoName.get(f.repository_id) ?? loc.repo }, sinkSymbol: f.sink_symbol, sinkApi: f.sink_api,
      entries: fromJson<string[]>(f.entry_keys, []), rootCause: f.root_cause ?? '', fingerprint: f.fp_sink,
      pendingKind: v?.pending_kind ?? (f.confirmation === 'pending' ? 'missing_context' : null), detail,
      ...withVerification(store, v?.id ?? null),
    };
  };
  const selected = filter.vulnIds ? new Set(filter.vulnIds) : null;
  const keep = (f: ReportFinding) => (!selected || (f.vulnId !== null && selected.has(f.vulnId))) && (filter.includePending !== false || f.confirmStatus !== 'pending');
  // a canonical cross-service risk that was not published (trusted internal network) is a hint, listed apart.
  const all = rows.filter((r) => r.state === 'canonical').map(toFinding);
  const isHint = (f: ReportFinding) => f.boundary === 'cross_service' && f.vulnId === null;
  const findings = all.filter((f) => !isHint(f)).filter(keep).sort(compareFindings);
  const serviceHints = selected ? [] : all.filter(isHint).sort(compareFindings);
  // Insufficient findings are pending by definition and belong to no selected vulnerability.
  const insufficient = selected || filter.includePending === false ? [] : rows.filter((r) => r.state === 'insufficient').map(toFinding).sort(compareFindings);

  const cov = store.all<{ kind: string; status: string; target_id: string; path: string; start_line: number }>(
    'SELECT kind, status, target_id, path, start_line FROM coverage_item WHERE audit_id = ? ORDER BY kind, path, start_line, target_id', auditId);
  let coverage: CoverageSummary | null = null;
  if (cov.length) {
    const sum = (k: string) => ({
      total: cov.filter((c) => c.kind === k && c.status !== 'excluded').length,
      reviewed: cov.filter((c) => c.kind === k && c.status === 'concluded').length,
      readOnly: cov.filter((c) => c.kind === k && c.status === 'read').length,
    });
    const reading = store.get<{ total: number | null; read: number | null }>('SELECT SUM(file_lines) AS total, SUM(lines_read) AS read FROM read_coverage WHERE audit_id = ?', auditId);
    const unc = override?.unconcluded ?? (a.gate_ref ? store.artifacts.getJson<{ unconcluded?: ReportUnconcluded }>(a.gate_ref).unconcluded : undefined);
    const reasonOf = new Map((unc?.items ?? []).map((i) => [i.targetId, i.reason]));
    coverage = {
      entry: sum('entry'), sink: sum('sink'),
      reading: { totalLines: reading?.total ?? 0, readLines: reading?.read ?? 0 },
      uncovered: cov.filter((c) => c.status === 'uncovered' || c.status === 'read' || c.status === 'failed')
        .map((c) => ({ kind: c.kind, targetId: c.target_id, path: c.path, line: c.start_line, status: c.status === 'read' ? 'read_only' : c.status === 'failed' ? 'gap' : 'untouched',
          ...(reasonOf.has(c.target_id) ? { reason: reasonOf.get(c.target_id)! } : {}) })),
      ...(unc ? { unconcluded: { total: unc.total, byReason: unc.byReason } } : {}),
      files: fileCoverage(store, auditId, repoRows as { id: string; name: string; manifest_ref: string | null }[]),
    };
  }
  const knowledge = knowledgeUsage(store, auditId).items;
  // the access-policy differences the engine handed to the experts, with each entry's conclusion.
  const accessEvent = store.listEvents(auditId, 0, ['judgement.made']).filter((e) => e.payload.kind === 'access_policy').at(-1);
  const verdictOf = new Map(cov.length ? store.all<{ target_id: string; status: string; verdict: string | null }>(`SELECT target_id, status, verdict FROM coverage_item WHERE audit_id = ? AND kind = 'entry'`, auditId)
    .map((c) => [c.target_id, c.status === 'concluded' ? c.verdict : null] as const) : []);
  const access = ((accessEvent?.payload.checks ?? []) as { entryId: string; entryKey: string; level: string; role?: string; category: string; why: string }[])
    .map((c) => ({ entryKey: c.entryKey, level: c.level, ...(c.role ? { role: c.role } : {}), category: c.category, why: c.why, verdict: verdictOf.get(c.entryId) ?? null }));
  const dependencies = store.listEvents(auditId, 0, ['judgement.made']).find((e) => e.payload.kind === 'dependencies')?.payload.record as ReportModel['dependencies'] | undefined;
  const injectionNotices = store.listEvents(auditId, 0, ['injection_suspected'])
    .map((e) => ({ path: String(e.payload.path ?? ''), signal: String(e.payload.signal ?? '') }))
    .filter((v, i, arr) => arr.findIndex((x) => x.path === v.path && x.signal === v.signal) === i)
    .sort((x, y) => x.path.localeCompare(y.path) || x.signal.localeCompare(y.signal));
  const excludedControlFiles: { repo: string; path: string }[] = [];
  for (const r of repoRows) {
    if (!r.manifest_ref) continue;
    const m = store.artifacts.getJson<{ excluded: { path: string; reason: string }[] }>(r.manifest_ref);
    for (const e of m.excluded) if (e.reason === 'agent_control') excludedControlFiles.push({ repo: r.name, path: e.path });
  }
  const consumed = fromJson<{ tokens?: number; durationMs?: number; costMicros?: number | null }>(a.budget_consumed, {});
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    audit: {
      id: a.id, title: a.title, scene: a.scene, mode: a.mode, status: override?.status ?? a.status,
      partialReasons: override?.partialReasons ?? fromJson<PartialReason[]>(a.partial_reasons, []), ...(gateNotices.length ? { notices: gateNotices } : {}), strategyHash: a.strategy_hash ?? null,
      startedAt: a.started_at ?? null, endedAt: a.ended_at ?? null,
      usage: { tokens: consumed.tokens ?? 0, durationMs: consumed.durationMs ?? 0, costMicros: consumed.costMicros ?? null },
      executionNote: STATIC_AUDIT_NOTE,
    },
    project,
    repositories: repos,
    findings,
    insufficient,
    ...(serviceHints.length ? { serviceHints } : {}),
    coverage,
    ...(ob ? { obligations: { total: ob.total, settled: ob.settled, byKind: ob.byKind, bySource: ob.bySource } } : {}),
    knowledge,
    injectionNotices,
    ...(access.length ? { access } : {}),
    ...(dependencies ? { dependencies } : {}),
    excludedControlFiles,
    ...(selected || filter.includePending === false ? { selection: { vulns: selected ? selected.size : null, includePending: filter.includePending !== false } } : {}),
    ...(filter.trajectory ? { trajectory: trajectorySummary(store, auditId) } : {}),
  };
}

function trajectorySummary(store: Store, auditId: string): TrajectoryStep[] {
  const steps = store.all<{ id: string; kind: string; lineage_id: string | null; status: string; started_at: number | null; ended_at: number | null; tokens_in: number; tokens_out: number }>(
    'SELECT id, kind, lineage_id, status, started_at, ended_at, tokens_in, tokens_out FROM step WHERE audit_id = ? ORDER BY seq', auditId);
  const calls = new Map(store.all<{ step_id: string; n: number }>(`SELECT step_id, COUNT(*) AS n FROM event WHERE audit_id = ? AND type = 'tool.called' GROUP BY step_id`, auditId).map((r) => [r.step_id, r.n]));
  const notes = new Map<string, string>();
  for (const e of store.listEvents(auditId, 0, ['agent.note'])) {
    const text = String(e.payload.text ?? '').trim();
    if (text && e.stepId && !notes.has(e.stepId)) notes.set(e.stepId, text.replace(/\s+/g, ' ').slice(0, 200));
  }
  return steps.map((s) => ({
    kind: s.kind, lineage: s.lineage_id, status: s.status, durationMs: s.started_at && s.ended_at ? s.ended_at - s.started_at : 0,
    tokens: (s.tokens_in ?? 0) + (s.tokens_out ?? 0), toolCalls: calls.get(s.id) ?? 0, firstNote: notes.get(s.id) ?? null,
  }));
}

/** the vulnerability's verification cases and patch suggestion, when it has any. */
export function withVerification(store: Store, vulnId: string | null): { verification?: ReportVerification } {
  const v = reportVerification(store, vulnId);
  return v ? { verification: v } : {};
}
