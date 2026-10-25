// zh-CN labels for report fields that are stored as internal keys: categories, confidence, sources,
// pending kinds, handling states and step kinds. Unknown keys are printed as they are.
export const CATEGORY_ZH: Record<string, string> = {
  sqli: 'SQL 注入', nosqli: 'NoSQL 注入', cmdi: '命令注入', code_injection: '代码注入', expression_injection: '表达式注入', ssti: '模板注入',
  ssrf: 'SSRF', path_traversal: '路径遍历', file_upload: '文件上传', deserialization: '反序列化', xxe: 'XXE', xss: 'XSS',
  open_redirect: '开放重定向', csrf: 'CSRF', cors: 'CORS 配置', authn: '认证缺陷', authz_object: '越权（对象级）', authz_function: '越权（功能级）',
  business_logic: '业务逻辑', race_condition: '竞态条件', crypto_weak: '弱加密', hardcoded_secret: '硬编码密钥', info_leak: '信息泄露',
  ldapi: 'LDAP 注入', log_injection: '日志注入', dos: '拒绝服务', other: '其他',
};
export const CONFIDENCE_ZH: Record<string, string> = { high: '高', medium: '中', low: '低' };
export const SOURCE_ZH: Record<string, string> = { rule: '规则', ai: 'AI', human: '人工' };
export const PENDING_KIND_ZH: Record<string, string> = { insufficient_evidence: '证据不足', missing_context: '缺少上下文' };
export const HANDLING_ZH: Record<string, string> = { open: '待处理', fixing: '修复中', fixed: '已修复', risk_accepted: '接受风险' };
export const STEP_ZH: Record<string, string> = {
  plan: '生成计划', snapshot: '固定代码版本', index: '结构索引', triage: '初筛', hunt: '领域审计', challenge: '质疑复核', reconcile: '归并对账',
  report: '报告与闸门', finalize: '收尾', review: '独立复核', scope: '影响范围', profile: '画像与威胁建模', decide: '深度探索决策',
  'verify-fix': '定向复验', 'coverage-gap': '覆盖补审', 'hunt-risk': '风险研判',
};
/**
 * A step's label. The hunt kind also runs coverage completion (GAP-*), deep exploration (R1…) and the retry of
 * hypothesis verification (HYP-*), so its label follows the lineage like contracts `STEP_ROLES`; others by kind.
 */
export function stepZh(kind: string, lineage?: string | null): string {
  if (kind === 'hunt' && lineage) {
    if (/^GAP/.test(lineage)) return '覆盖补审';
    if (/^R\d/.test(lineage)) return '深度探索';
    if (/^HYP/.test(lineage)) return '风险假设验证';
  }
  return STEP_ZH[kind] ?? kind;
}
export const STEP_STATUS_ZH: Record<string, string> = { succeeded: '完成', failed: '失败', skipped: '已跳过', cancelled: '已取消', interrupted: '已中断', running: '进行中', pending: '等待', ready: '就绪' };
/**
 * Why an audit is partial, or the process issues of a completed one (contracts `PARTIAL_REASONS`);
 * reports show the label with the code.
 */
export const PARTIAL_REASON_ZH: Record<string, string> = {
  BUDGET_EXHAUSTED: '预算耗尽', DURATION_EXHAUSTED: '时长耗尽', COST_CAP_REACHED: '达到成本上限', STEP_FAILED: '有步骤失败',
  OUTPUT_CONTRACT_FAILED: '模型输出不合规', MODEL_UNAVAILABLE: '模型不可用', ROUND_LIMIT_REACHED: '达到轮次上限', CONTEXT_REPO_MISSING: '缺少上下文仓库',
  INDEX_DEGRADED: '结构索引降级', PENDING_QUESTIONS: '有未回答的提问', USER_SKIPPED: '用户跳过部分内容', COVERAGE_GAP: '覆盖未达标',
};
export const partialReasonText = (r: string): string => (PARTIAL_REASON_ZH[r] ? `${PARTIAL_REASON_ZH[r]}（${r}）` : r);
export const zh = (map: Record<string, string>, v: string | null | undefined): string => (v ? map[v] ?? v : '');
