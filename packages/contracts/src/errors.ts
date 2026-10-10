// Closed error codes for user-facing errors. Messages are fixed text;
// raw exception text never reaches the user.
export const ERROR_CODES = {
  CONFIG_INVALID: '配置无效',
  STRATEGY_INVALID: '审计策略无效',
  PROJECT_NOT_FOUND: '项目不存在',
  PROJECT_EXISTS: '项目已存在',
  REPOSITORY_NOT_FOUND: '仓库不存在',
  REPOSITORY_EXISTS: '仓库已存在',
  AUDIT_NOT_FOUND: '审计不存在',
  AUDIT_NOT_RESUMABLE: '审计当前状态不可继续',
  AUDIT_TERMINAL: '审计已结束',
  INVALID_TRANSITION: '状态转移不合法',
  SNAPSHOT_FAILED: '无法固定代码版本',
  LOCK_HELD: '数据目录已被其他进程占用',
  MODEL_NOT_CONFIGURED: '未配置可用模型',
  CREDENTIAL_BINDING_MISMATCH: '凭证与服务地址不匹配',
  SECRET_ON_COMMAND_LINE: '凭证不能通过命令行参数传入',
  ARTIFACT_CORRUPT: '产物校验失败',
  EXPORT_FAILED: '导出失败',
  INTERNAL: '内部错误',
  // API codes. Append-only.
  COMMON_VALIDATION: '请求参数无效',
  COMMON_NOT_FOUND: '资源不存在',
  COMMON_REVISION_CONFLICT: '已被他处修改，请刷新后重做',
  COMMON_IDEMPOTENCY_KEY_REUSED: '幂等键已用于不同的请求',
  COMMON_PRECONDITION_REQUIRED: '缺少 If-Match 或 revision',
  AUTH_SESSION_REQUIRED: '需要登录会话',
  AUTH_ORIGIN_REJECTED: '请求来源不被允许',
  AUTH_HOST_REJECTED: '请求 Host 不被允许',
  AUTH_BOOTSTRAP_EXPIRED: '引导码无效或已过期',
  AUTH_CSRF_INVALID: 'CSRF 校验失败',
  AUDIT_INVALID_TRANSITION: '审计当前状态不允许该操作',
  AUDIT_PLAN_NOT_READY: '审计计划尚未生成',
  QUESTION_NOT_FOUND: '提问不存在',
  QUESTION_CLOSED: '提问已关闭',
  VULN_NOT_FOUND: '漏洞不存在',
  VULN_EVIDENCE_INCOMPLETE: '证据不完整：单条确认需要写明原因，批量确认不包含这类漏洞',
  VULN_REASON_REQUIRED: '该操作需要填写原因',
  SOURCE_NOT_IN_MANIFEST: '文件不在该审计的快照中',
  EXPORT_FORMAT_UNSUPPORTED: '不支持的导出格式',
  EXPORT_NOT_FOUND: '导出记录不存在',
  MODEL_UNREACHABLE: '模型服务无法连通',
  PROVIDER_NOT_FOUND: '模型服务不存在',
  REPO_REF_NOT_FOUND: '分支或提交不存在',
  SERVER_NOT_RUNNING: '服务未运行',
  // Incremental audits and vulnerability merges. Append-only.
  AUDIT_BASELINE_UNAVAILABLE: '没有可用的对比基线',
  VULN_MERGE_CROSS_PROJECT: '不能合并不同项目的漏洞',
  // Repository sources and uploads. Append-only.
  REPO_UNREACHABLE: '仓库无法访问',
  REPO_AUTH_FAILED: 'Git 认证失败',
  UPLOAD_NOT_FOUND: '上传文件不存在或已过期',
  UPLOAD_TOO_LARGE: '上传文件过大',
  ARCHIVE_REJECTED: '压缩包不符合安全限制',
  // Knowledge. Append-only.
  KNOWLEDGE_INVALID: 'skill 不符合格式要求',
  KNOWLEDGE_EXISTS: '同名 skill 已存在',
  KNOWLEDGE_PATH_INVALID: 'skill 名称或文件路径无效',
  // Conversations. Append-only.
  CONVERSATION_NOT_FOUND: '会话不存在',
  MESSAGE_NOT_FOUND: '消息不存在',
  MESSAGE_BUSY: '上一条回复仍在生成',
  CARD_NOT_FOUND: '卡片不存在',
  CARD_NOT_PENDING: '卡片已处理或已失效',
  // Hypotheses. Append-only.
  HYPOTHESIS_NOT_FOUND: '假设不存在',
  HYPOTHESIS_DECIDED: '该假设已处理',
  // Requirement threat models. Append-only.
  THREAT_MODEL_NOT_FOUND: '威胁模型不存在',
  THREAT_MODEL_BUSY: '威胁模型正在生成，暂不能修改',
  THREAT_SOURCE_NOT_FOUND: '输入来源不存在',
  THREAT_RISK_NOT_FOUND: '风险不存在',
  THREAT_REASON_REQUIRED: '除待研判外，设置风险状态需要填写理由',
} as const;
export type ErrorCode = keyof typeof ERROR_CODES;

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly hint: string | undefined;
  readonly detail: unknown;
  constructor(code: ErrorCode, hint?: string, detail?: unknown) {
    super(`${code}: ${ERROR_CODES[code]}${hint ? ` — ${hint}` : ''}`);
    this.code = code;
    this.hint = hint;
    this.detail = detail;
  }
}
