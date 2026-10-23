// zh-CN copy in one place. Formatting uses Intl.
import type { VulnCategory } from '@xiezhi/contracts';

export const SEVERITY: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const CONFIDENCE: Record<string, string> = { high: '高', medium: '中', low: '低' };
export const CONFIRM: Record<string, string> = { pending: '待确认', confirmed: '已确认', false_positive: '误报' };
export const HANDLING: Record<string, string> = { open: '待处理', fixing: '修复中', fixed: '已修复', risk_accepted: '接受风险' };
export const LIFECYCLE: Record<string, string> = { new: '新增', persisting: '仍存在', fixed_verified: '已修复（经验证）', regressed: '回归' };
export const SOURCE: Record<string, string> = { rule: '规则', ai: 'AI', human: '人工' };
export const PENDING_KIND: Record<string, string> = { insufficient_evidence: '证据不足', missing_context: '缺少上下文' };
export const AUDIT_STATUS: Record<string, string> = {
  planning: '生成计划中', awaiting_confirm: '待确认计划', queued: '排队中', running: '运行中', waiting_budget: '等待预算', paused: '已暂停',
  cancelling: '取消中', interrupted: '已中断', completed: '已完成', partial: '未完成', failed: '失败', cancelled: '已取消',
};
export const PHASE: Record<string, string> = {
  planning: '生成计划', awaiting_confirm: '待确认', queued: '排队', preparing: '准备代码', analyzing: '分析', verifying: '验证', reporting: '生成报告', done: '结束',
};
export const PHASE_ORDER = ['queued', 'preparing', 'analyzing', 'verifying', 'reporting', 'done'] as const;
export const STEP_KIND: Record<string, string> = {
  plan: '生成计划', snapshot: '固定代码版本', index: '结构索引', triage: '初筛', hunt: '深入审计', challenge: '对抗复核', reconcile: '归并对账',
  report: '报告与闸门', finalize: '收尾', review: '独立复核', scope: '影响范围', profile: '画像与威胁建模', decide: '深度探索决策', 'threat-model': '风险假设（威胁建模）',
  'verify-fix': '定向复验', 'coverage-gap': '覆盖补审', 'hunt-risk': '风险研判',
};
export const REVERIFY_VERDICT: Record<string, string> = { fixed: '已修复（经验证）', still_present: '仍存在', partially_fixed: '修复不完整', undetermined: '待确认' };
/** Budget stages, in pipeline order. */
export const BUDGET_STAGE: Record<string, string> = {
  prepare: '计划与画像', triage: '初筛', hunt: '深入审计', gap: '覆盖补齐', hypotheses: '风险假设', explore: '深度探索', merge: '归并', review: '对抗复核', verify: '复验',
};
export const ON_SHORTFALL: Record<string, string> = { declare: '只声明缺口', gap_fill: '补齐：再追查未覆盖的候选' };
export const SCENE: Record<string, string> = { full: '全量', incremental: '增量', risk_hunt: '风险排查', reverify: '复验' };
export const IMPACT_MODE: Record<string, string> = { precise: '精确影响分析', heuristic: '启发式影响分析', full_scan: '退化为全量' };
export const IMPACT_REASON: Record<string, string> = {
  ast_disabled: '未开启 AST 结构解析：以 diff 为中心审查，调用方由 Agent 用搜索追溯',
  no_baseline_index: '基线版本没有可用的结构索引',
  too_many_changes: '变更文件占比超过阈值',
  parse_gap_in_changed_files: '变更文件中解析失败的比例过高',
  unresolved_edges_dominant: '无法解析的调用多于可解析的调用',
};
export const STEP_STATUS: Record<string, string> = {
  pending: '等待', ready: '就绪', blocked_budget: '预算不足', running: '进行中', retry_wait: '等待重试', succeeded: '完成', failed: '失败',
  skipped: '已跳过', cancelled: '已取消', interrupted: '已中断',
};
export const PARTIAL_REASON: Record<string, string> = {
  BUDGET_EXHAUSTED: '预算耗尽', DURATION_EXHAUSTED: '时长耗尽', COST_CAP_REACHED: '达到成本上限', STEP_FAILED: '有步骤失败',
  OUTPUT_CONTRACT_FAILED: '模型输出不合规', MODEL_UNAVAILABLE: '模型不可用', ROUND_LIMIT_REACHED: '达到轮次上限', CONTEXT_REPO_MISSING: '缺少上下文仓库',
  INDEX_DEGRADED: '结构索引降级', PENDING_QUESTIONS: '有未回答的提问', USER_SKIPPED: '用户跳过部分内容', COVERAGE_GAP: '覆盖未达标',
};
export const EVENT_LABEL: Record<string, string> = {
  'audit.status_changed': '审计状态', 'step.status_changed': '步骤', 'step.attempt_started': '开始尝试', 'plan.generated': '计划已生成', 'plan.confirmed': '计划已确认',
  'session.started': '会话开始', 'session.paused': '会话暂停', 'session.resumed': '会话继续', 'session.turn': '回合', 'agent.note': 'Agent 说明', 'session.compacted': '上下文压缩', 'session.ended': '会话结束', 'tool.called': '调用工具', 'tool.result': '工具结果',
  'file.read': '读取代码', 'cross_repo.traced': '跨仓追溯', 'knowledge.loaded': '加载知识', 'knowledge.changed': '知识变更', 'connector.queried': '查询连接器', 'connector.write_requested': '连接器调用待批准', 'connector.write_decided': '连接器调用审批',
  'hypothesis.proposed': '提出假设', 'hypothesis.retired': '排除假设', 'state.updated': '更新认知', 'decide.chosen': '选择方向', 'question.asked': 'Agent 提问',
  'question.answered': '已回答', 'intervention.received': '用户介入', 'intervention.applied': '介入生效', 'judgement.made': '中间判断', 'finding.submitted': '提交发现',
  'finding.challenged': '质疑结论', 'finding.reconciled': '归并完成', 'vuln.created': '新漏洞', 'vuln.matched': '匹配已有漏洞', 'vuln.impact_changed': '影响面变化',
  'contract.violation': '输出不合规', 'security.blocked': '安全拦截', injection_suspected: '疑似注入', 'budget.reserved': '预留预算', 'budget.charged': '扣减预算',
  'budget.exhausted': '预算耗尽', 'budget.topped_up': '追加预算', 'coverage.updated': '覆盖更新', 'gate.evaluated': '完成闸门', error: '错误',
};
export const TRAJECTORY_FILTERS: { key: string; label: string }[] = [
  { key: 'note', label: 'Agent 说明' }, { key: 'read', label: '读取代码' }, { key: 'tool', label: '工具调用' }, { key: 'knowledge', label: '知识' }, { key: 'question', label: '提问' },
  { key: 'intervention', label: '介入' }, { key: 'judgement', label: '判断与发现' }, { key: 'vuln', label: '漏洞' }, { key: 'step', label: '步骤' },
  { key: 'budget', label: '预算' }, { key: 'security', label: '安全与错误' }, { key: 'plan', label: '计划' },
];
export const INTERVENTION: Record<string, string> = { supplement: '补充信息', refocus: '调整重点', skip: '跳过', deep_dive: '深入分析', concurrency: '调整并发' };
export const ANALYSIS_STATUS: Record<string, string> = { running: '进行中', succeeded: '已完成', partial: '部分完成', failed: '失败', interrupted: '已中断' };
export const REPO_ANALYSIS_STATUS: Record<string, string> = { succeeded: '已识别', reused: '复用上次结果', skipped: '未调用模型', failed: '失败' };
export const SOURCE_KIND: Record<string, string> = { local: '本地', git: 'Git', archive: '压缩包' };
export const ROLE: Record<string, string> = { gateway: '网关', auth: '鉴权', business: '业务', api_def: '接口定义', frontend: '前端', shared_lib: '共享库', unknown: '未识别' };

/** Vulnerability and sink categories (contracts `VULN_CATEGORIES`; a missing key is a compile error). */
export const VULN_CATEGORY: Record<VulnCategory, string> = {
  sqli: 'SQL 注入', nosqli: 'NoSQL 注入', cmdi: '命令注入', code_injection: '代码注入', expression_injection: '表达式注入', ssti: '模板注入',
  ssrf: 'SSRF', path_traversal: '路径遍历', file_upload: '文件上传', deserialization: '反序列化', xxe: 'XXE', xss: 'XSS',
  open_redirect: '开放重定向', csrf: 'CSRF', cors: 'CORS 配置', authn: '认证缺陷', authz_object: '越权（对象级）', authz_function: '越权（功能级）',
  business_logic: '业务逻辑', race_condition: '竞态条件', crypto_weak: '弱加密', hardcoded_secret: '硬编码密钥', info_leak: '信息泄露',
  ldapi: 'LDAP 注入', log_injection: '日志注入', dos: '拒绝服务', other: '其他',
};
/** Unknown keys (older data, free text) are shown as they are. */
/** Requirement threat-model risk categories: STRIDE plus business logic and abuse. */
export const THREAT_CATEGORY: Record<string, string> = {
  spoofing: '身份仿冒', tampering: '篡改', repudiation: '抵赖', information_disclosure: '信息泄露', denial_of_service: '拒绝服务',
  elevation_of_privilege: '权限提升', abuse: '滥用',
};
export const categoryLabel = (c: string | null | undefined): string => (c ? (VULN_CATEGORY as Record<string, string>)[c] ?? THREAT_CATEGORY[c] ?? c : '—');

/** Agent and conversation tools, by the name the model calls. */
export const TOOL_LABEL: Record<string, string> = {
  read: '读取代码', grep: '搜索代码', glob: '查找文件', list: '列目录', read_artifact: '读取结果', load_skill: '读取知识', connector_query: '查询连接器',
  entrypoints: '列出入口', dangerous_sinks: '列出危险点', callgraph: '调用图', symbol_lookup: '查符号', find_refs: '查调用点', definition: '跳到定义',
  references: '查找引用', cross_repo_trace: '跨仓追溯', git_log: '查看提交历史', task: '子任务', ask_user: '向你提问', mark_candidate: '标记候选进度',
  list_projects: '列出项目', list_repositories: '列出仓库', list_vulnerabilities: '列出漏洞', get_vulnerability: '查看漏洞', list_audits: '列出审计',
  report_investigation: '生成调查结果', propose_revision: '建议修订', propose_audit_plan: '生成审计计划', propose_reverify: '生成复验计划',
  propose_hunt: '生成排查计划', propose_merge: '建议合并', propose_split: '建议拆分', draft_connector: '连接器草稿',
  submit_plan: '提交计划', submit_triage: '提交初筛', submit_findings: '提交发现', submit_challenge: '提交质疑结论', submit_review: '提交复核结论',
  submit_reverify: '提交复验结论', submit_verdict_review: '提交结论复核', submit_risk_verdicts: '提交排查结论', submit_state_update: '更新认知状态',
  submit_decision: '提交探索决策', submit_profile: '提交画像', submit_system_model: '提交系统模型（跨仓库）', submit_threat_model: '提交风险假设清单', submit_merge_groups: '提交归并分组', submit_suspected_matches: '提交疑似匹配',
  submit_variant_patterns: '提交变体模式', submit_repo_role: '提交仓库角色', submit_hunt_basis: '提交排查依据', submit_architecture: '提交架构整理',
  submit_skill: '提交知识', submit_case: '提交案例', submit_conflicts: '提交冲突检查', submit_connector_pack: '提交连接器包', submit_push_args: '提交推送参数',
};
export const toolLabel = (tool: string): string => TOOL_LABEL[tool] ?? tool;

const s = (v: unknown): string => (v === undefined || v === null ? '' : String(v));
const lines = (a: Record<string, unknown>): string => (a.startLine ? `:${s(a.startLine)}${a.endLine ? `-${s(a.endLine)}` : ''}` : a.line ? `:${s(a.line)}` : '');

/** One readable line of tool arguments (trajectory rows and conversation tool calls). */
export function toolArgs(tool: string, args: unknown): string {
  if (!args || typeof args !== 'object') return '';
  const a = args as Record<string, unknown>;
  // Arguments too large for the event keep a JSON preview: its first string field, like the default below.
  if (a.truncated) return typeof a.preview === 'string' ? (/^\{"[^"]+":"((?:[^"\\]|\\.)*)"/.exec(a.preview)?.[1] ?? '').slice(0, 80) : '';
  const repo = a.repo ? `${s(a.repo)}:` : '';
  switch (tool) {
    case 'read': return `${repo}${s(a.path)}${lines(a)}`;
    case 'grep': return `“${s(a.pattern)}”${a.glob ? ` · ${s(a.glob)}` : ''}`;
    case 'glob': return s(a.pattern);
    case 'list': return `${repo}${s(a.dir) || '/'}`;
    case 'load_skill': return s(a.name);
    case 'ask_user': return s(a.question).slice(0, 80);
    case 'connector_query': return `${s(a.connector)} · ${s(a.operation)}`;
    case 'cross_repo_trace': return [a.method && a.pathTemplate ? `${s(a.method)} ${s(a.pathTemplate)}` : s(a.pathTemplate), a.path ? `${repo}${s(a.path)}${lines(a)}` : ''].filter(Boolean).join(' · ');
    case 'definition': case 'references': return `${s(a.symbol)}${a.symbol ? ' @ ' : ''}${repo}${s(a.path)}${lines(a)}`;
    case 'symbol_lookup': return s(a.name);
    case 'find_refs': return s(a.symbolId);
    case 'callgraph': return `${s(a.symbolId)} · ${a.direction === 'callers' ? '调用方' : '被调用方'}`;
    case 'dangerous_sinks': return a.category ? categoryLabel(s(a.category)) : s(a.pathPrefix);
    case 'entrypoints': return s(a.pathPrefix || a.framework);
    case 'git_log': return [s(a.path), a.grep ? `“${s(a.grep)}”` : ''].filter(Boolean).join(' · ');
    case 'task': return s(a.goal).slice(0, 80);
    default: {
      const first = Object.values(a).find((v) => typeof v === 'string' || typeof v === 'number');
      return first === undefined ? '' : String(first).slice(0, 80);
    }
  }
}

/** Conversation tool calls carry their arguments as JSON cut at 300 characters. */
export function toolArgsFromJson(tool: string, json: string): string {
  try { return toolArgs(tool, JSON.parse(json)); } catch { /* cut JSON: fall back to the path or the raw text */ }
  const path = /"path":"([^"]+)"/.exec(json)?.[1];
  return path ?? (json.length > 80 ? `${json.slice(0, 80)}…` : json);
}

/** Sources of exploit conditions are free text; the model often names the tool it used. */
export const sourceLabel = (src: string): string => TOOL_LABEL[src] ?? src;

/** Reasons recorded with audit status changes (engine, English). */
export const STATUS_REASON: Record<string, string> = {
  created: '已创建', 'plan ready': '计划已生成', 'plan ready; confirmed automatically': '计划已生成，自动确认', 'plan confirmed': '计划已确认',
  dequeued: '开始运行', 'budget insufficient': '预算不足', 'budget topped up': '已追加预算', 'cancel requested': '请求取消', 'cancelled by user': '用户取消',
  'completion gate': '完成闸门', 'engine error': '引擎错误', error: '出错', interrupted: '已中断', 'process interrupted': '进程中断',
  'service restart': '服务重启', 'paused by user': '用户暂停', 'resumed by user': '用户继续',
  'content filtered': '内容被过滤，等待处理', 'model service unavailable': '模型服务不可用，恢复后自动继续',
  'model service restored': '模型服务已恢复，自动继续', 'model provider quota used up': '模型服务余额或额度不足，等待处理',
};
export const SESSION_STATUS: Record<string, string> = {
  completed: '完成', contract_failed: '输出不合规', max_turns: '达到轮数上限', aborted: '已中止', budget_stopped: '因预算停止', error: '出错',
};

/** why a coverage item has no conclusion (engine `UNCONCLUDED_REASONS`). */
const UNCONCLUDED_REASON: Record<string, string> = {
  concluded_without_reading: '有结论但阅读不足', assigned_no_verdict: '分配后未给结论', read_no_verdict: '读过未下结论',
  not_selected: '未入选', not_assigned: '未分配',
};

/** Completion-gate checks are stored with English details; render them from the name and the numbers. */
/** obligation kinds in the gate's obligations check. */
const OBLIGATION_KIND: Record<string, string> = { entry: '入口', sink: '危险点', hypothesis: '风险假设', access: '访问策略差异', checklist: '清单条目', external: '外部扫描结果' };

export function gateCheckText(c: { name: string; ok: boolean; detail: string }): string {
  const n = (c.detail.match(/\d+/g) ?? []).map(Number);
  switch (c.name) {
    case 'finding_set': return c.ok ? '已生成归并后的发现' : '没有归并后的发现';
    case 'verdicts': return `${n[0] ?? 0}/${n[1] ?? 0} 个漏洞已有复验结论`;
    // "N failed step(s), M only noted" — tolerated failures are notices, not reasons.
    case 'steps': return n[0] ? `${n[0]} 个步骤失败${n.length > 1 ? `（其中 ${n[1]} 个只作提示）` : ''}` : '没有失败的步骤';
    // "S/T obligations settled (entry s/t, sink s/t, …)".
    case 'obligations': {
      const parts = [...c.detail.matchAll(/([a-z]+) (\d+)\/(\d+)/g)].map((m) => `${OBLIGATION_KIND[m[1]!] ?? m[1]} ${m[2]}/${m[3]}`);
      return `需要结论的项 ${n[0] ?? 0}/${n[1] ?? 0} 已结论${parts.length ? `（${parts.join('、')}）` : ''}`;
    }
    case 'reconciled': return n[0] ? `${n[0]} 条发现未归并` : '发现都已归并';
    case 'blocking_questions': return n[0] ? `${n[0]} 个影响结论的提问未回答` : '没有影响结论的未回答提问';
    case 'hypotheses': return n.length >= 2 ? `风险假设 ${n[0]}/${n[1]} 已验证` : c.detail;
    case 'coverage': return n.length >= 4 ? `覆盖：入口 ${n[0]}/${n[1]}，危险点 ${n[2]}/${n[3]}` : c.detail;
    case 'unconcluded': {
      // "N item(s) without a conclusion (reason n, …)".
      const why = [...c.detail.matchAll(/([a-z_]+) (\d+)/g)].map((m) => `${UNCONCLUDED_REASON[m[1]!] ?? m[1]} ${m[2]}`);
      return n[0] ? `${n[0]} 个入口 / 危险点没有结论${why.length ? `（${why.join('、')}）` : ''}` : '入口与危险点都有结论';
    }
    default: return c.detail;
  }
}

/** Share of prompt tokens served from the cache. pi's `input` counts only the uncached ones; cache reads come on top. */
export function cacheHitText(input: number, cacheRead: number): string {
  return input + cacheRead > 0 ? `${Math.round((cacheRead / (input + cacheRead)) * 100)}%` : '—';
}

const nf = new Intl.NumberFormat('zh-CN');
const cf = new Intl.NumberFormat('zh-CN', { notation: 'compact', maximumFractionDigits: 1 });
const dtf = new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
const tf = new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const rtf = new Intl.RelativeTimeFormat('zh-CN', { numeric: 'auto' });

export const fmt = {
  n: (v: number) => nf.format(v),
  compact: (v: number) => cf.format(v),
  date: (iso: string | null | undefined) => (iso ? dtf.format(new Date(iso)) : '—'),
  time: (iso: string | null | undefined) => (iso ? tf.format(new Date(iso)) : '—'),
  ago: (iso: string | null | undefined) => {
    if (!iso) return '—';
    const s = (new Date(iso).getTime() - Date.now()) / 1000;
    const abs = Math.abs(s);
    if (abs < 60) return rtf.format(Math.round(s), 'second');
    if (abs < 3600) return rtf.format(Math.round(s / 60), 'minute');
    if (abs < 86400) return rtf.format(Math.round(s / 3600), 'hour');
    return rtf.format(Math.round(s / 86400), 'day');
  },
  bytes: (n: number) => (n < 1024 ? `${n} B` : n < 1024 ** 2 ? `${(n / 1024).toFixed(1)} KB` : n < 1024 ** 3 ? `${(n / 1024 ** 2).toFixed(1)} MB` : `${(n / 1024 ** 3).toFixed(2)} GB`),
  duration: (ms: number) => {
    const s = Math.round(ms / 1000);
    if (s < 60) return `${s} 秒`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m} 分 ${s % 60} 秒`;
    return `${Math.floor(m / 60)} 小时 ${m % 60} 分`;
  },
  /** Unknown cost is shown as "未知", never 0. */
  cost: (micros: number | null | undefined, unknownCalls = 0) => {
    if (micros === null || micros === undefined) return '未知';
    const v = (micros / 1e6).toFixed(micros < 1e6 ? 4 : 2);
    return unknownCalls ? `≥ ${v}（${unknownCalls} 次调用成本未知）` : v;
  },
  loc: (l: { repo?: string; path: string; startLine: number; endLine: number }) =>
    `${l.repo ? `${l.repo}:` : ''}${l.path}:${l.startLine}${l.endLine !== l.startLine ? `-${l.endLine}` : ''}`,
  /** Entry keys normalise path parameters to `{}`; show them as a placeholder. */
  entry: (key: string) => key.replace(/\{\}/g, '{…}'),
};
