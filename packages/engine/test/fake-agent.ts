// A deterministic scripted "model" speaking the OpenAI chat.completions protocol. It reads the
// system prompt to decide which step it is in and drives tools like a real agent would.
import type { ScriptedReply } from '../../agent/test/fake-openai.js';

interface Msg { role: string; content?: unknown; tool_calls?: unknown[] }

function text(m: Msg): string {
  if (typeof m.content === 'string') return m.content;
  if (Array.isArray(m.content)) return m.content.map((c: { text?: string }) => c.text ?? '').join('\n');
  return '';
}

export interface FakeAgentOptions {
  /** The plan model never submits its plan (the plan step fails). */
  planBroken?: boolean;
  /** The merge model answers merge groups and suspected matches with invalid submissions. */
  mergeBroken?: boolean;
  /** The hunt also reports the SSRF in OrderController.fetch (a second, separate finding). */
  secondFinding?: boolean;
  /** Produce the OrderDao SQL injection finding when its sink is in the batch. */
  findSqli?: boolean;
  /** Cite a location without reading it first (should be rejected by the evidence gate). */
  citeUnread?: boolean;
  /** Ask a blocking question during hunt. */
  askBlocking?: boolean;
  /** Where the SQL-injection DAO lives (rename/move scenarios). */
  daoPath?: string;
  /** Suspected matching: link every finding to its first candidate (default) or to none. */
  suspect?: 'first' | 'none';
  /** Reverification verdict (default still_present). */
  reverify?: 'fixed' | 'still_present' | 'partially_fixed' | 'undetermined';
  /** shop fixture: report the order IDOR as pending on the gateway policy, after tracing callers across repositories. */
  pendingIdor?: boolean;
  /** Targeted reverification of a pending vulnerability. */
  pendingResolution?: 'holds' | 'refuted' | 'still_pending';
  /** Risk hunt: repository verdict given next to a hit (default affected). */
  riskVerdict?: 'affected' | 'pending' | 'not_affected';
  /** Skills the hunt reads with load_skill, and the refs its SQL-injection finding cites. */
  knowledge?: { read?: string[]; cite?: string[] };
  /** The challenge reads these skills and cites them with this confidence delta. */
  challengeKnowledge?: { read: string[]; cite: string[]; delta: number };
  /** The hunt queries this connector operation alongside its first reads. */
  connectorQuery?: { connector: string; operation: string; args: Record<string, unknown> };
  /** The SQL-injection finding cites every connector result (`call=` id) seen in the session. */
  citeConnector?: boolean;
  /** The challenge queries `connectorQuery` and cites only that result with this confidence delta. */
  challengeConnector?: { delta: number };
  /** The java-mini reverification queries `connectorQuery` and cites only that result. */
  reverifyConnector?: boolean;
  /** conversations: what the scripted assistant does for the next reply. */
  chat?: 'investigate' | 'plan' | 'text' | 'bad_card' | 'slow' | 'reverify_fixed' | 'hunt_all' | 'merge' | 'connector';
  /** The challenge maintains the finding but attaches a pendingCondition anyway (seen with a real model). */
  challengeMaintainWithCondition?: boolean;
  /** Second-opinion review of “已修复” / “受影响”. */
  verdictReview?: 'maintain' | 'doubt';
  /** multi-model: the model `m2` rules the SQL-injection sink out instead of reporting it. */
  multiDiverge?: boolean;
  /** The hunt hands one question to a `task` sub-agent. */
  useTask?: boolean;
  /**
   * The hunt leaves the first non-DAO candidate without a verdict; asked about it, it then answers
   * (`answer_on_nudge`) or still does not (`never`).
   */
  omitCandidate?: 'answer_on_nudge' | 'never';
  /**
   * A domain expert leaves its first non-DAO lead without a verdict in round 1 and answers it when it comes back
   * as a gap (`answer_in_gap_round`), or never does.
   */
  expertOmitLead?: 'answer_in_gap_round' | 'never';
  /**
   * The authorization domain lists the token filter as a mechanism (the threat model reads it first); the
   * expert reads it only when it comes back as a gap (`read_in_gap_round`), or never.
   */
  expertMechanism?: 'read_in_gap_round' | 'never';
  /** The threat model submits an access policy (admin routes need ADMIN, order routes are per owner, search is public). */
  accessPolicy?: boolean;
  /** independent review verdict. */
  review?: 'holds' | 'refuted' | 'insufficient';
  /** Extra files every hunt session reads on its first turn (e.g. a README carrying an injection). */
  extraReads?: string[];
  /** Every hunt session asks the language server for this definition and its references first. */
  useLsp?: { path: string; line: number; symbol: string };
  /** AI report: `good` keeps every conclusion; `fix_on_repair` first drops one and changes a severity, then fixes
   * them when told; `always_bad` keeps inventing a number. */
  aiReport?: 'good' | 'fix_on_repair' | 'always_bad';
  /** Audit turns that only call tools also carry a one-line explanation (narrative trajectory). */
  narrate?: boolean;
  /** Hunts report progress per candidate with mark_candidate (investigating, then the verdict). */
  markCandidates?: boolean;
  /** The progress mark of the SQL-injection sink says no_issue while the submission says finding. */
  markMismatch?: boolean;
  /** The first progress mark names a candidate that is not listed (refused as a tool error). */
  markUnknown?: boolean;
  /** deep explore: walk the todo pool (first try an unknown id), or keep choosing a fruitless new direction;
   *  `revisit`: round 1 re-investigates the SQL-injection DAO (the hunt reports the same finding again), then stops. */
  explore?: 'walk' | 'stall' | 'sloppy' | 'revisit';
  /** The exploration hunt reports the SQL injection at the controller entry instead of the DAO line. */
  revisitAtController?: boolean;
  /** The merge model groups the first new label with the first existing finding. */
  mergeIntoExisting?: boolean;
  /** Confidence of the SQL-injection finding in the first hunt and in the exploration hunt. */
  revisitConfidence?: { first: number; again: number };
  /** The hypothesis verification leaves every listed hypothesis undetermined (open). */
  verifyOpen?: boolean;
  /** The threat model plans no domains (the engine falls back to its fixed set). */
  noDomains?: boolean;
  /** The SQL domain expert leaves a direction open in round 1 (a second round follows). */
  expertOpenLead?: boolean;
  /** The experts also list a target id that is not in the index. */
  expertUnknownTarget?: boolean;
  /** The experts conclude one target outside the DAO as `finding` without submitting a finding for it. */
  expertFindingNoFinding?: boolean;
  /** The SQL expert adds one finding that breaks the schema and one citing lines past the end of the file. */
  expertBadFindings?: boolean;
  /** Every expert round leaves a direction open (the last round's go to the deep exploration). */
  expertOpenLeadAlways?: boolean;
  /** The experts read nothing and conclude nothing (the ledger stays open for ⑨). */
  expertIdle?: boolean;
  /**
   * The triage model gives 5 only to the last listed candidate in another file than the first listed (the
   * heuristic order would not start with it), 2 to the others.
   */
  triageScores?: boolean;
  /** Severity of the second (SSRF) finding; default high. */
  secondSeverity?: 'medium' | 'low';
  /** The experts leave the hypotheses listed to them without a verdict (HYP-R retries them). */
  expertNoVerdicts?: boolean;
  /** The hunt queries the enterprise facts and its SQL finding cites them (factRefs). */
  useFacts?: boolean;
  /** The adversarial review reads the finder's reasoning through finding_reasoning on its first turn. */
  reviewReadsReasoning?: boolean;
  /** The recheck disagrees with the first unit of each batch (→ reopened for ⑨). */
  recheckDisagree?: boolean;
  /** The checklist check finds every item covered or not applicable (no fill). */
  checklistAllCovered?: boolean;
  /** A checklist fill session lists its items in reviewedTargets (as `repo:path:line`). */
  fillListsItems?: boolean;
  /** The first lead session's dispatch reports a context above the lead's cap (→ handoff to a second session). */
  leadContextCap?: boolean;
  /** The lead's first reply is two dispatch calls side by side, both naming the first domain (haiku). */
  leadParallelDispatch?: boolean;
  /** Entry targets written without the repository prefix and with a named parameter (haiku). */
  bareTargetIds?: boolean;
}

/** `call=` ids of the connector results seen in the session (in order). */
function connectorCalls(messages: Msg[]): string[] {
  return [...new Set(messages.filter((m) => m.role === 'tool').flatMap((m) => [...text(m).matchAll(/call=(ccl_[0-9A-Z]{26})/g)].map((x) => x[1]!)))];
}

const SHOP_CTRL = 'src/main/java/com/shop/order/OrderController.java';
const PENDING = {
  missing: [{ kind: 'gateway_policy', ref: 'gateway', hint: '网关是否对 /api/order/** 做归属校验' }],
  holdsIf: [{ statement: '网关或 auth-service 只校验登录态', checkable: { tool: 'cross_repo_trace', target: 'gateway /api/order/**' } }],
  refutedIf: [{ statement: '网关对该路由做了订单归属校验' }],
  severityIfHolds: 'high', suggestedActions: ['add_repo', 'ask_user'],
};

const DEFAULT_DAO = 'src/main/java/com/demo/dao/OrderDao.java';

/** A long reply with GFM features (rendering checks). */
export const MARKDOWN_SAMPLE = [
  '## 对比',
  '',
  '| 场景 | 范围 | 适用时机 |',
  '| --- | --- | --- |',
  '| 全量审计 | 整个仓库 | 首次审计、大版本发布前 |',
  '| 增量审计 | 变更及其影响范围 | 日常提交、合并请求 |',
  '',
  '修复示例：',
  '',
  '```java',
  'public List<Order> search(String name) {',
  '    return jdbc.query("SELECT * FROM orders WHERE name = ?", mapper, name);',
  '}',
  '```',
  '',
  '参考：[OWASP SQL 注入防护](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)',
  '',
  ...Array.from({ length: 40 }, (_, i) => `${i + 1}. 第 ${i + 1} 条检查要点：确认参数来源、拼接方式与防护位置。`),
].join('\n');
const CTRL = 'src/main/java/com/demo/controller/OrderController.java';
const TOKEN_FILTER = 'src/main/java/com/demo/security/TokenFilter.java';
/** The scripted threat model's hypotheses (风险假设先行). */
const RISK_FIRST_HYPOTHESES = [
  { statement: '订单详情未校验订单属于当前用户', category: 'authz_object', basis: '资产：订单；角色：普通用户', entries: ['GET /api/order/{id}'], files: [CTRL], priority: 5 },
  { statement: '抓取接口可被用来访问内网地址', category: 'ssrf', basis: '信任边界：服务端外部请求', entries: ['POST /api/order/fetch'], files: [CTRL], priority: 4 },
  { statement: '导出接口文件名可穿越目录', category: 'path_traversal', basis: '资产：导出目录', entries: ['GET /api/order/export'], files: [CTRL], priority: 3 },
];

/** A one-line explanation of the calls a turn makes (what a real model says before acting). */
function narration(calls: { name: string; args: unknown }[]): string {
  const say = (c: { name: string; args: unknown }): string => {
    const a = (c.args ?? {}) as Record<string, unknown>;
    if (c.name === 'read') return `读取 ${String(a.path ?? '').split('/').at(-1)}`;
    if (c.name === 'grep') return `搜索“${String(a.pattern ?? '')}”`;
    if (c.name === 'ask_user') return '向你确认一个会影响结论的问题';
    if (c.name.startsWith('submit_')) return '整理已有证据并提交结论';
    return `调用 ${c.name}`;
  };
  return `接下来${calls.map(say).join('，')}。`;
}

/** The scripted agent; with `narrate`, audit turns that only call tools also say what they do. */
/** The scripted project profile (profile and system-understanding sessions). */
export const PROFILE_ARGS = {
  summary: 'Spring Boot 订单服务：订单查询、搜索、管理接口', techStack: ['Java', 'Spring MVC', 'JDBC'],
  modules: [{ path: 'src/main/java/com/demo/controller', purpose: 'HTTP 接口' }, { path: 'src/main/java/com/demo/dao', purpose: '数据访问' }],
  authModel: 'SecurityConfig 要求所有请求登录；未见按订单归属的校验',
  trustBoundaries: [{ name: '互联网 → 订单 API', description: '登录用户可调用 /api/order/**，参数完全由用户控制' }],
  assets: [{ name: '订单数据', sensitivity: 'high', description: '含用户订单内容' }],
  roles: [{ name: '登录用户', description: '只应访问自己的订单' }, { name: '管理员', description: '访问 /admin/**' }],
  externalDependencies: [{ name: '库存服务', description: 'InventoryClient 出站 HTTP 调用' }],
  assumptions: ['网关是否额外做鉴权未知'],
};

export function fakeAgent(opts: FakeAgentOptions = {}) {
  const inner = scriptedAgent(opts);
  if (!opts.narrate) return inner;
  return (body: { messages: Msg[]; model?: string }): ScriptedReply => {
    const r = inner(body);
    const sys = text(body.messages.find((m) => m.role === 'system') ?? { role: 'system' });
    if (r.text || !r.toolCalls?.length || sys.includes('代码安全审计助手')) return r;
    return { ...r, text: narration(r.toolCalls) };
  };
}

function scriptedAgent(opts: FakeAgentOptions) {
  const DAO = opts.daoPath ?? DEFAULT_DAO;
  return (body: { messages: Msg[]; model?: string }): ScriptedReply => {
    const sys = text(body.messages.find((m) => m.role === 'system') ?? { role: 'system' });
    const model = body.model ?? '';
    const user = body.messages.filter((m) => m.role === 'user').map(text).join('\n');
    const assistantTurns = body.messages.filter((m) => m.role === 'assistant').length;
    const lastTool = [...body.messages].reverse().find((m) => m.role === 'tool');
    const lastToolText = lastTool ? text(lastTool) : '';

    // risk-hypothesis-first: a fixed threat model for java-mini, and verification that refutes / leaves
    // open the listed hypotheses in turn (reasons cite the controller lines it read).
    if (opts.triageScores && user.includes('以下是结构索引识别出的候选')) {
      if (lastToolText.startsWith('accepted')) return { text: 'done' };
      const listed = [...user.matchAll(/^- (.+?) \| [^:\n]+:([^:\n]+):\d+ \| /gm)].map((m) => ({ id: m[1]!, path: m[2]! }));
      const top = [...listed].reverse().find((c) => c.path !== listed[0]?.path)?.id;
      return { toolCalls: [{ name: 'submit_triage', args: { scores: listed.map((c) => ({ candidateId: c.id, score: c.id === top ? 5 : 2, reason: '脚本初筛' })) } }] };
    }
    // External results — the log-injection one is a false positive (with the controller lines read), the rest hold.
    if (user.includes('这是外部扫描结果分诊环节')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { path: CTRL } }] };
      if (!body.messages.some((m) => m.role === 'tool' && text(m) === 'recorded')) {
        const ids = [...user.matchAll(/itemId=`([^`]+)`/g)].map((m) => m[1]!);
        return { toolCalls: [{ name: 'submit_external_triage', args: { items: ids.map((itemId) => (/crlf/.test(itemId)
          ? { itemId, verdict: 'false_positive', reason: '日志写入的是订单 id（Long），不是任意字符串（脚本分诊）', evidence: [{ path: CTRL, startLine: 24, endLine: 27 }] }
          : { itemId, verdict: 'true_positive', reason: '用户输入直接到达危险调用（脚本分诊）' })) } }] };
      }
      return { text: 'done' };
    }
    // The recheck reads the controller and agrees with every "no issue" conclusion (with `recheckDisagree`, not
    // with the first unit).
    if (user.includes('这是结论复查环节')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { path: CTRL } }] };
      if (!body.messages.some((m) => m.role === 'tool' && text(m) === 'recorded')) {
        const ids = [...user.matchAll(/targetId=`([^`]+)`/g)].map((m) => m[1]!);
        return { toolCalls: [{ name: 'submit_recheck', args: { items: ids.map((targetId, i) => (opts.recheckDisagree && i === 0
          ? { targetId, agree: false, reason: '没有找到归属校验，结论不成立（脚本复查）', evidence: [{ path: CTRL, startLine: 1, endLine: 5 }] }
          : { targetId, agree: true, reason: '读过的代码有防护，结论成立（脚本复查）' })) } }] };
      }
      return { text: 'done' };
    }
    // The checklist check reads the controller, then settles every item: WebSocket / GraphQL items do not apply,
    // the CSRF item of state-changing endpoints is uncovered (unless `checklistAllCovered`), the rest covered.
    if (user.includes('这是清单出口核对环节')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { path: CTRL } }] };
      if (!body.messages.some((m) => m.role === 'tool' && text(m) === 'recorded')) {
        const keys = [...user.matchAll(/itemId=`([^`]+)`/g)].map((m) => m[1]!);
        return { toolCalls: [{ name: 'submit_checklist', args: { items: keys.map((itemId) => (/:(ws-|csrf-graphql)/.test(itemId)
          ? { itemId, status: 'not_applicable', reason: '系统没有 WebSocket 与 GraphQL 入口（读过的控制器只有 REST 接口）' }
          : /:csrf-state-changing$/.test(itemId) && !opts.checklistAllCovered
            ? { itemId, status: 'uncovered', reason: '未找到 CSRF 防护配置，需要补审', startFiles: [CTRL] }
            : { itemId, status: 'covered', reason: '控制器入口已检查（脚本核对）', evidence: [{ path: CTRL, startLine: 1, endLine: 5 }] })) } }] };
      }
      return { text: 'done' };
    }
    // The lead dispatches one subtask per planned domain, then finishes.
    if (user.includes('你是本次审计的主控')) {
      // At the context cap the engine asks for a handoff; the next lead session continues from it.
      if (user.includes('上下文已接近上限') && !body.messages.some((m) => m.role === 'tool' && text(m) === 'recorded')) {
        return { toolCalls: [{ name: 'submit_lead_done', args: { done: false, summary: '第一个主控会话已派发全部领域', handoff: '交接：各领域首个子任务均已返回，下一步检查账本中剩余的必答项。' } }] };
      }
      if (opts.leadContextCap && !user.includes('上一个主控会话的交接') && assistantTurns === 0) {
        const ids = [...new Set([...user.split('## 怎么做')[0]!.matchAll(/^- (D\d+)「/gm)].map((m) => m[1]!))];
        return { promptTokens: 50_000, toolCalls: [{ name: 'dispatch', args: { tasks: ids.map((domainId) => ({ domainId, goal: `按领域视角检查 ${domainId} 的线索与必答项，给出结论` })) } }] };
      }
      if (opts.leadContextCap && user.includes('上一个主控会话的交接') && assistantTurns === 0) {
        return { toolCalls: [{ name: 'ledger', args: {} }] };
      }
      if (opts.leadParallelDispatch && assistantTurns === 0) {
        const ids = [...new Set([...user.split('## 怎么做')[0]!.matchAll(/^- (D\d+)「/gm)].map((m) => m[1]!))];
        const task = (domainId: string, goal: string) => ({ domainId, goal });
        return { toolCalls: [
          { name: 'dispatch', args: { tasks: ids.map((d) => task(d, `按领域视角检查 ${d} 的线索与必答项，给出结论`)) } },
          { name: 'dispatch', args: { tasks: [task(ids[0]!, `再核实 ${ids[0]} 的必答项`)] } },
        ] };
      }
      if (assistantTurns === 0) {
        const ids = [...new Set([...user.split('## 怎么做')[0]!.matchAll(/^- (D\d+)「/gm)].map((m) => m[1]!))];
        return { toolCalls: [{ name: 'dispatch', args: { tasks: ids.map((domainId) => ({ domainId, goal: `按领域视角检查 ${domainId} 的线索与必答项，给出结论` })) } }] };
      }
      // A domain whose subtask left directions open gets another one (up to three dispatch calls in all).
      const again = [...lastToolText.matchAll(/^- (D\d+) 子任务「[^」]*」：.*留下方向 ([1-9]\d*) 条/gm)].map((m) => m[1]!);
      if (again.length && assistantTurns < 3 && !lastToolText.startsWith('recorded')) {
        return { toolCalls: [{ name: 'dispatch', args: { tasks: [...new Set(again)].map((domainId) => ({ domainId, goal: `继续 ${domainId} 上一子任务留下的方向` })) } }] };
      }
      if (!body.messages.some((m) => m.role === 'tool' && text(m) === 'recorded')) {
        return { toolCalls: [{ name: 'submit_lead_done', args: { done: true, summary: '各领域子任务均已返回' } }] };
      }
      return { text: 'done' };
    }
    if (user.includes('## 风险假设验证') && !user.includes('多领域专家漏洞狩猎的第')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { repo: 'java-mini', path: CTRL } }] };
      if (assistantTurns === 1) {
        const ids = [...user.matchAll(/hypothesisId=`(hyp_[0-9A-Z]+)`/g)].map((m) => m[1]!);
        return { toolCalls: [{ name: 'submit_findings', args: { findings: [], reviewedTargets: [], ruledOut: [], scopeReviewed: CTRL, verdicts: ids.map((id, i) => (i % 2 === 0 && !opts.verifyOpen
          ? { hypothesisId: id, status: 'refuted', reason: '服务端按会话用户重新查询，未信任请求参数（脚本模型）', location: { repo: 'java-mini', path: CTRL, startLine: 24, endLine: 27 } }
          : { hypothesisId: id, status: 'open', reason: '取决于网关是否统一鉴权，代码中读不到（脚本模型）', location: { repo: 'java-mini', path: CTRL, startLine: 36, endLine: 39 } })) } }] };
      }
      return { text: 'done' };
    }
    // The threat model also plans the risk domains (and, without 风险假设先行, lists no hypotheses).
    const wantDomains = user.includes('## 风险领域划分') && !opts.noDomains;
    const MECH = { name: '令牌过滤器', why: '所有请求的认证都经过它', location: { path: TOKEN_FILTER, startLine: 1, endLine: 5 } };
    const DOMAINS = [
      { name: 'SQL 与数据访问', focus: '订单查询与 DAO 层的 SQL 拼接', categories: ['sqli', 'nosqli'], mechanisms: [], leads: [{ statement: '订单搜索把 name 拼进 SQL', entries: ['GET /api/order/search'], files: [DAO] }] },
      { name: '订单归属与授权', focus: '订单读写的归属校验与角色', categories: ['authz_object', 'authz_function', 'authn', 'business_logic'], mechanisms: opts.expertMechanism ? [MECH] : [], leads: [{ statement: '订单详情未校验订单属于当前用户', entries: ['GET /api/order/{id}'], files: [CTRL] }] },
    ];
    const mechRead = opts.expertMechanism ? [{ name: 'read', args: { path: TOKEN_FILTER } }] : [];
    const policy = opts.accessPolicy ? [
      { scope: '/api/admin', level: 'role', role: 'ADMIN', reason: '运维接口只给管理员' },
      { scope: '/api/order', level: 'owner', reason: '订单只能由下单用户读写' },
      { scope: '/api/order/search', level: 'public', reason: '公开的商品搜索（脚本假设）' },
    ].map((g) => ({ name: 'submit_access_policy', args: g })) : [];
    // The cross-repository system session of a multi-repository audit, after the repositories' own profiles.
    if (user.includes('系统理解（跨仓库）环节')) {
      if (!body.messages.some((m) => m.role === 'tool' && text(m).startsWith('system model recorded'))) {
        const repos = /目标仓库：([^。\n]+)。/.exec(user)?.[1]?.split('、') ?? [];
        return { toolCalls: [{ name: 'submit_system_model', args: {
          summary: '脚本：服务之间经网关转发，下游信任网关注入的用户头。',
          flows: repos.length > 1 ? [{ from: repos[0]!, to: repos[1]!, via: 'HTTP /internal', carries: 'X-User-Id 请求头', check: '未校验' }] : [],
          trustBoundaries: [{ name: '网关与内部服务', description: '网关校验令牌后注入用户头', repos }],
          risks: [{ title: '下游信任可伪造的用户头', statement: '内部服务直接使用 X-User-Id', repos }],
          assumptions: [],
        } }] };
      }
      return { text: 'done' };
    }
    // The system-understanding session writes the profile and the threat model together; it reads code only
    // through a `task` sub-agent (here: the mechanism's file).
    if (user.includes('这是系统理解环节')) {
      const riskFirst = user.includes('“风险假设先行”的威胁建模环节');
      const recorded = (t: string) => body.messages.some((m) => m.role === 'tool' && text(m).startsWith(t));
      if (opts.expertMechanism && !body.messages.some((m) => m.role === 'tool' && text(m).includes('子任务结论'))) {
        return { toolCalls: [{ name: 'task', args: { goal: `读令牌过滤器的实现 ${TOKEN_FILTER}，说明它如何校验令牌`, files: [TOKEN_FILTER] } }] };
      }
      // Look at the structure first (as the profile session did), then submit.
      if (assistantTurns === 0 && !opts.expertMechanism) return { toolCalls: [{ name: 'entrypoints', args: {} }] };
      if (!recorded('profile recorded')) {
        const threat = riskFirst
          ? [...(wantDomains ? DOMAINS.map((d) => ({ name: 'submit_risk_domain', args: d })) : []), { name: 'submit_threat_model', args: { hypotheses: RISK_FIRST_HYPOTHESES } }]
          : [{ name: 'submit_threat_model', args: { hypotheses: [] } }, ...(wantDomains ? DOMAINS.map((d) => ({ name: 'submit_risk_domain', args: d })) : []), ...(wantDomains ? policy : [])];
        return { toolCalls: [{ name: 'submit_profile', args: PROFILE_ARGS }, ...threat] };
      }
      if (opts.noDomains && !recorded('recorded domain')) return { toolCalls: [{ name: 'submit_risk_domain', args: DOMAINS[1] }] };
      return { text: 'done' };
    }
    // One submit_risk_domain call per domain; with `noDomains` the domain comes only after a reminder.
    if (user.includes('这是威胁建模环节')) {
      if (assistantTurns === 0) return { toolCalls: [...mechRead, { name: 'submit_threat_model', args: { hypotheses: [] } }, ...(wantDomains ? DOMAINS.map((d) => ({ name: 'submit_risk_domain', args: d })) : []), ...(wantDomains ? policy : [])] };
      if (opts.noDomains && !body.messages.some((m) => m.role === 'tool' && text(m).startsWith('recorded domain'))) return { toolCalls: [{ name: 'submit_risk_domain', args: DOMAINS[1] }] };
      return { text: 'done' };
    }
    if (user.includes('“风险假设先行”的威胁建模环节')) {
      if (assistantTurns === 0) {
        return { toolCalls: [...(wantDomains ? DOMAINS.map((d) => ({ name: 'submit_risk_domain', args: d })) : []), { name: 'submit_threat_model', args: { hypotheses: RISK_FIRST_HYPOTHESES } }] };
      }
      return { text: 'done' };
    }
    // AI report: write the report from the facts in the data.
    if (sys.includes('代码安全审计报告的撰写人')) {
      if (lastTool) return { text: '报告已提交。' };
      const facts = [...user.matchAll(/"id": "([FI]-\d+)",\s*"vuln": [^,]+,\s*"title": "((?:[^"\\]|\\.)*)",\s*"category": "[^"]*",\s*"severity": "([^"]+)"[\s\S]*?"confirmStatus": "([^"]+)"/g)]
        .map((m) => ({ id: m[1]!, title: m[2]!, severity: m[3]!, status: m[4]! }));
      const repair = user.includes('上一次写的报告与审计记录有以下不一致');
      const mode = opts.aiReport ?? 'good';
      let list = facts;
      if (mode === 'fix_on_repair' && !repair) list = facts.slice(0, -1).map((f, i) => (i === 0 ? { ...f, severity: f.severity === '低' ? '高' : '低' } : f));
      const md = [
        '# 代码安全审计报告', '', '> 静态审计：未构建、未运行、未测试目标代码。', '', '## 结论摘要', `共 ${facts.length} 条结论。`, '',
        ...list.flatMap((f) => [`### ${f.id} ${f.title}`, `严重度：${f.severity}｜确认状态：${f.status}`, '', '说明与修复建议。', '']),
        ...(mode === 'always_bad' ? ['### F-99 编造的漏洞', '严重度：高｜确认状态：已确认'] : []),
      ].join('\n');
      return { toolCalls: [{ name: 'submit_report', args: { markdown: md } }] };
    }

    // conversation replies: investigate the mentioned vulnerability in its snapshot and emit cards.
    if (sys.includes('代码安全审计助手')) {
      const vulnId = /"id": "(vul_[0-9A-Z]{26})"/.exec(sys)?.[1];
      const projectId = /"id": "(prj_[0-9A-Z]{26})"/.exec(sys)?.[1];
      // A long Markdown answer (table, code, link) to exercise rendering and follow-the-bottom scrolling.
      if (/表格|代码示例/.test(user.split('\n').at(-1) ?? '')) return { text: MARKDOWN_SAMPLE };
      // Without an explicit script: “帮我审计…” asks for a plan, anything else is a follow-up.
      const mode = opts.chat ?? (/帮我(全量)?审计/.test(user) ? 'plan' : 'investigate');
      if (mode === 'text' || (!vulnId && mode === 'investigate')) return { text: `收到：${user.split('\n').at(-1)!.slice(0, 40)}。这是一个直接回答。` };
      if (mode === 'slow') return assistantTurns === 0 ? { toolCalls: [{ name: 'read', args: { path: DAO } }] } : { text: '分段'.repeat(400) };
      // Find the vulnerabilities by filter, then propose a reverification of all of them.
      if (mode === 'reverify_fixed') {
        if (assistantTurns === 0) return { toolCalls: [{ name: 'list_vulnerabilities', args: { handlingStatus: ['fixed'] } }] };
        if (assistantTurns === 1) {
          const ids = [...lastToolText.matchAll(/"id": "(vul_[0-9A-Z]{26})"/g)].map((m) => m[1]!);
          return ids.length
            ? { toolCalls: [{ name: 'propose_reverify', args: { vulnIds: ids, rationale: '这些漏洞标为已修复，复验确认修复是否生效' } }] }
            : { text: '没有标为已修复的漏洞。' };
        }
        return { text: '已生成复验计划卡片。' };
      }
      if (mode === 'hunt_all') {
        if (assistantTurns === 0) return { toolCalls: [{ name: 'list_projects', args: {} }] };
        if (assistantTurns === 1) return { toolCalls: [{ name: 'propose_hunt', args: { basis: { kind: 'prompt', text: '订单详情按 id 读取，未校验订单归属' }, allProjects: true, rationale: '排查所有项目' } }] };
        return { text: '已生成风险排查卡片。' };
      }
      if (mode === 'merge') {
        if (assistantTurns === 0) return { toolCalls: [{ name: 'list_vulnerabilities', args: {} }] };
        if (assistantTurns === 1) {
          const ids = [...lastToolText.matchAll(/"id": "(vul_[0-9A-Z]{26})"/g)].map((m) => m[1]!);
          return { toolCalls: [{ name: 'propose_merge', args: { targetId: ids[0], sourceIds: ids.slice(1), reason: '同一危险点' } }] };
        }
        return { text: '已给出合并建议。' };
      }
      if (mode === 'connector') {
        if (assistantTurns === 0) {
          // A credential in the config is refused; the corrected draft names the secret instead.
          return { toolCalls: [{ name: 'draft_connector', args: { name: 'wiki', protocol: 'mcp_http', purpose: 'context', config: { url: 'https://wiki.example.com/mcp', headers: { Authorization: 'Bearer abcdefgh12345' } } } }] };
        }
        if (assistantTurns === 1) {
          return { toolCalls: [{ name: 'draft_connector', args: { name: 'wiki', protocol: 'mcp_http', purpose: 'context', config: { url: 'https://wiki.example.com/mcp', headers: { Authorization: 'Bearer ${secret:token}' } }, secrets: ['token'], notes: '需要只读 token' } }] };
        }
        return { text: '草稿已生成，请在设置中填写 token 并测试连接。' };
      }
      if (mode === 'plan') {
        if (assistantTurns > 0) return { text: '已生成审计计划卡片，请确认后生成计划。' };
        return { toolCalls: [{ name: 'propose_audit_plan', args: { request: { projectId, scene: 'full', title: '会话发起的全量审计' }, rationale: '用户要求审计该项目', recommended: ['开启质疑复核'] } }] };
      }
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { path: DAO } }] };
      if (mode === 'bad_card' && assistantTurns === 1) {
        // Cites a line it never read → rejected; then corrects.
        return { toolCalls: [{ name: 'report_investigation', args: { title: 'x', conclusion: 'y', evidence: [{ path: CTRL, startLine: 1, endLine: 2 }] } }] };
      }
      if (lastToolText.startsWith('investigation card') || lastToolText.startsWith('revision suggestion card')) {
        if (assistantTurns >= 3 || lastToolText.startsWith('revision')) return { text: '结论：name 参数直接拼接进 SQL，漏洞成立。我已给出建议修订，请确认。' };
      }
      if (assistantTurns <= 2 && !lastToolText.startsWith('investigation card')) {
        return { toolCalls: [{ name: 'report_investigation', args: { title: '订单搜索 SQL 注入复查', conclusion: 'OrderDao.search 把 name 拼接进 SQL', evidence: [{ path: DAO, startLine: 17, endLine: 21 }], vulnId: 'V-1' } }] };
      }
      return { toolCalls: [{ name: 'propose_revision', args: { vulnId: 'V-1', severity: 'critical', handlingStatus: 'fixing', reason: '可直接读取全部订单，建议上调严重度并开始修复', evidence: [{ path: DAO, startLine: 17, endLine: 21 }] } }] };
    }

    // variant search: abstract the fixed pattern into a search expression.
    if (user.includes('这是增量审计的“变体搜索”')) {
      if (assistantTurns > 0) return { text: 'patterns submitted' };
      return { toolCalls: [{ name: 'submit_variant_patterns', args: { patterns: [{ description: '字符串拼接进 Statement.executeQuery', grep: 'executeQuery\\("SELECT[^"]*\'" \\+' }] } }] };
    }

    if (sys.includes('仓库角色分析员')) {
      if (assistantTurns > 0) return { text: 'roles submitted' };
      const json = /<untrusted_data[^>]*>\n([\s\S]*?)\n<\/untrusted_data/.exec(user)?.[1] ?? '{}';
      const sig = JSON.parse(json) as { gatewayConfigs?: { path: string; routes: number }[]; frontendFrameworks?: string[]; entrypoints?: { http: number }; referencedBy?: string[]; contracts?: { proto: number } };
      const roles: { role: string; confidence: number; evidence: { signal: string; path?: string; count?: number }[] }[] = [];
      if (sig.gatewayConfigs?.length) roles.push({ role: 'gateway', confidence: 0.9, evidence: [{ signal: 'gatewayConfigs', path: sig.gatewayConfigs[0]!.path, count: sig.gatewayConfigs[0]!.routes }] });
      if (sig.frontendFrameworks?.length) roles.push({ role: 'frontend', confidence: 0.85, evidence: [{ signal: `frontendFrameworks: ${sig.frontendFrameworks.join(',')}` }] });
      if (sig.referencedBy?.length) roles.push({ role: 'shared_lib', confidence: 0.7, evidence: [{ signal: 'referencedBy', count: sig.referencedBy.length }] });
      if (!roles.length && (sig.entrypoints?.http ?? 0) > 0) roles.push({ role: 'business', confidence: 0.8, evidence: [{ signal: 'entrypoints.http', count: sig.entrypoints!.http }] });
      return { toolCalls: [{ name: 'submit_repo_role', args: { roles, rationale: roles.length ? '依据信号摘要判断' : '信号不足' } }] };
    }

    // Knowledge ingestion: organize into a skill or a case, then judge contradictions.
    if (sys.includes('安全知识库的整理员')) {
      if (assistantTurns > 0) return { text: 'submitted' };
      if (user.includes('已确认漏洞整理成漏洞案例库')) {
        return { toolCalls: [{ name: 'submit_case', args: {
          name: 'idor-order-case', description: '按订单 ID 查询未校验归属', vulnClass: 'authz_object', cwe: ['CWE-639'], languages: ['java'], frameworks: ['spring-mvc'],
          appliesWhen: 'Spring MVC，按资源 ID 读写的接口', pattern: '按路径参数 id 读取资源后直接返回。', codeTraits: '`orderDao.findById(id)` 之后没有比较 owner。',
          holdsIf: '链路上没有归属校验。', notHoldsIf: '查询条件包含当前用户，或网关统一校验归属。', fix: '在查询中加入当前用户条件。', whenToUse: '审计按 ID 读取订单、账单等资源的接口时。',
        } }] };
      }
      const cat = /类别建议：(\w+)/.exec(user)?.[1] ?? 'audit_method';
      return { toolCalls: [{ name: 'submit_skill', args: {
        name: cat === 'audit_method' ? 'order-owner-method' : 'order-gateway-facts', description: '订单接口越权判断方法，审计按 ID 读写订单的接口时读取',
        category: cat, appliesTo: { vulnClasses: ['authz_object'] }, body: `# 订单归属校验\n\n## 判断要点\n\n- 查询条件是否带当前用户\n\n## 成立条件 / 不成立条件\n\n- 网关只校验登录态时成立\n`,
      } }] };
    }
    // With several follow-up operations, look something up first, then choose the steps.
    if (sys.includes('推送指引把一条漏洞') && user.includes('从下列操作中')) {
      const json = /<untrusted_data[^>]*source="vulnerability"[^>]*>\n([\s\S]*?)\n<\/untrusted_data/.exec(user)?.[1] ?? '{}';
      const f = JSON.parse(json) as { display_no: string; handling_status: string };
      if (assistantTurns === 0) return { toolCalls: [{ name: 'connector_query', args: { operation: 'search', args: { q: 'states' }, reason: '查询可流转的状态' } }] };
      if (assistantTurns === 1) {
        return { toolCalls: [{ name: 'submit_push_args', args: { steps: [
          { operation: 'get_ticket', args: { comment: `复验：${f.display_no} ${f.handling_status}` } },
          ...(f.handling_status === 'fixed' ? [{ operation: 'env', args: { state: 'resolved' } }] : []),
        ] } }] };
      }
      return { text: 'submitted' };
    }
    if (sys.includes('推送指引把一条漏洞')) {
      if (assistantTurns > 0) return { text: 'submitted' };
      const json = /<untrusted_data[^>]*source="vulnerability"[^>]*>\n([\s\S]*?)\n<\/untrusted_data/.exec(user)?.[1] ?? '{}';
      const f = JSON.parse(json) as { display_no: string; title: string; severity: string; description: string };
      if (user.includes('本次是更新')) return { toolCalls: [{ name: 'submit_push_args', args: { args: { text: `AI 更新：${f.display_no} ${f.title}` } } }] };
      return { toolCalls: [{ name: 'submit_push_args', args: { args: { project: 'SEC', summary: `AI: ${f.display_no} ${f.title}`, description: f.description, labels: ['xiezhi-audit', f.severity] } } }] };
    }
    // A verification case (read the code first, then submit).
    if (sys.includes('验证用例作者')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read_snapshot', args: { path: 'src/main/java/com/demo/dao/OrderDao.java', startLine: 15, endLine: 30 } }] };
      if (assistantTurns === 1) return { toolCalls: [{ name: 'submit_verification_case', args: {
        preconditions: ['测试环境已部署 java-mini，订单表中有 name=alice 的记录', '一个可以调用 /api/order/search 的测试账号'],
        steps: [
          { kind: 'http', title: '正常查询（基线）', content: 'GET $BASE_URL/api/order/search?name=alice\nAuthorization: Bearer $TOKEN' },
          { kind: 'http', title: '注入布尔条件', content: "GET $BASE_URL/api/order/search?name=alice'%20OR%20'1'='1\nAuthorization: Bearer $TOKEN" },
        ],
        expected: { vulnerable: '第 2 步返回的订单多于第 1 步（条件被注入）', fixed: '第 2 步返回空列表或 400，与第 1 步不同' },
        notes: '只读取测试数据，不修改数据。',
      } }] };
      return { text: 'submitted' };
    }
    // A fix suggestion — first a diff whose context does not match the snapshot (refused), then a correct one.
    if (sys.includes('修复建议作者')) {
      const path = 'src/main/java/com/demo/dao/OrderDao.java';
      const good = [
        `--- a/${path}`, `+++ b/${path}`, '@@ -19,4 +19,5 @@',
        '         try (Connection conn = dataSource.getConnection()) {',
        '-            Statement stmt = conn.createStatement();',
        `-            ResultSet rs = stmt.executeQuery("SELECT body FROM orders WHERE name = '" + name + "'");`,
        '+            PreparedStatement stmt = conn.prepareStatement("SELECT body FROM orders WHERE name = ?");',
        '+            stmt.setString(1, name);',
        '+            ResultSet rs = stmt.executeQuery();',
        '             while (rs.next()) out.add(rs.getString(1));',
      ].join('\n');
      const bad = good.replace('Statement stmt = conn.createStatement();', 'Statement stmt = connection.createStatement();');
      const args = (diff: string) => ({ summary: '改用参数化查询（PreparedStatement）绑定 name。', patches: [{ path, diff }], verify: '重新执行验证用例第 2 步，应返回空列表。' });
      if (assistantTurns === 0) return { toolCalls: [{ name: 'submit_fix_suggestion', args: args(bad) }] };
      if (assistantTurns === 1) return { toolCalls: [{ name: 'submit_fix_suggestion', args: args(good) }] };
      return { text: 'submitted' };
    }
    // A project rule — first an untested submit (rejected), then a test, then the tested pattern.
    if (sys.includes('项目规则作者')) {
      const q = '(method_invocation name: (identifier) @m (#eq? @m "executeQuery") arguments: (argument_list (binary_expression))) @sink';
      if (assistantTurns === 0) return { toolCalls: [{ name: 'submit_project_rule', args: { matcher: 'tree_sitter', pattern: q, title: '拼接 SQL 的 executeQuery', rationale: '未试跑直接提交' } }] };
      if (assistantTurns === 1) return { toolCalls: [{ name: 'test_rule', args: { matcher: 'tree_sitter', pattern: q } }] };
      if (assistantTurns === 2) return { toolCalls: [{ name: 'submit_project_rule', args: { matcher: 'tree_sitter', pattern: q, title: '拼接 SQL 的 executeQuery', rationale: '危险调用 executeQuery 的参数是字符串拼接；参数化查询不会命中。' } }] };
      return { text: 'submitted' };
    }
    if (sys.includes('连接器包作者')) {
      if (assistantTurns > 0) return { text: 'submitted' };
      return { toolCalls: [{ name: 'submit_connector_pack', args: {
        name: 'tickets-api', description: '内部工单系统：查询与创建工单（由 OpenAPI 生成）', baseUrl: 'https://tickets.example.com',
        auth: { type: 'header', header: 'Authorization', value: 'Bearer ${secret:token}' }, secrets: ['token'],
        operations: [
          { name: 'list_tickets', kind: 'read', description: '按关键字查询工单', method: 'GET', path: '/api/tickets', query: { q: '{q}' }, params: { q: { type: 'string', maxLength: 200, required: true } }, extract: '$.items[*].{id,title}' },
          { name: 'create_ticket', kind: 'write', description: '创建工单', method: 'POST', path: '/api/tickets', body: { title: '{title}' }, params: { title: { type: 'string', maxLength: 200, required: true } } },
        ],
        notes: '需要一个只读 token。',
      } }] };
    }
    // A requirement threat model — read the first source, then submit two risks.
    if (sys.includes('需求安全分析员')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read_source', args: { source: 1 } }] };
      if (assistantTurns === 1) return { toolCalls: [{ name: 'submit_threat_model', args: {
        clarification: '## 功能\n- 买家可以对已支付订单申请退款。（S1）\n## 设计如此的行为\n- 管理员可以查看所有订单。（S1）\n## 待确认与冲突点\n- 无',
        risks: [
          { category: 'elevation_of_privilege', level: 'high', statement: '买家可以为他人的订单申请退款。', impact: '资金损失。', mitigation: '退款前校验订单所有者。', features: ['申请退款'], sources: [1] },
          { category: 'business_logic', level: 'medium', statement: '退款金额可以超过实付金额。', impact: '多退款。', mitigation: '服务端按实付金额校验。', features: ['申请退款'], sources: [1] },
        ],
      } }] };
      return { text: 'submitted' };
    }
    if (sys.includes('架构资料整理员')) {
      if (assistantTurns > 0) return { text: 'submitted' };
      return { toolCalls: [{ name: 'submit_architecture', args: {
        services: [
          { name: 'gateway', kind: 'gateway', repo: 'gateway' }, { name: 'order-svc', kind: 'service', repo: 'order-service' },
          { name: 'payment-provider', kind: 'external_service', description: '第三方支付' }, { name: 'ghost', kind: 'service', repo: 'no-such-repo' },
        ],
        edges: [
          { from: 'gateway', to: 'order-svc', kind: 'client_call', protocol: 'gateway_route', statement: '网关把 /api/order/** 路由到 order-svc，只校验登录态' },
          { from: 'order-svc', to: 'payment-provider', kind: 'client_call', protocol: 'http', statement: '下单时调用第三方支付' },
          { from: 'order-svc', to: 'nowhere', kind: 'client_call', protocol: 'http', statement: 'x' },
        ],
        summary: '网关统一鉴权但只校验登录态；订单服务调用第三方支付。',
      } }] };
    }
    if (sys.includes('安全知识库的审校员')) {
      if (assistantTurns > 0) return { text: 'submitted' };
      return { toolCalls: [{ name: 'submit_conflicts', args: { conflicts: [{ candidate: 'c1', points: ['新：网关只校验登录态；旧：网关对 /api/order/** 做归属校验'], suggestion: 'merge', merged: 'merged text' }] } }] };
    }

    if (sys.includes('风险排查依据整理员')) {
      if (assistantTurns > 0) return { text: 'basis submitted' };
      return { toolCalls: [{ name: 'submit_hunt_basis', args: {
        title: '订单详情越权（按 id 读取不校验归属）', summary: '按路径中的订单 id 直接读取订单，未与当前登录用户比对。', category: 'authz_object', severity: 'high',
        features: { dependencies: [], apis: [], codePatterns: [{ description: '按 id 读取订单的接口', grep: 'GetMapping\\("/\\{id\\}"\\)' }], locations: [] },
        affectedIf: ['按 id 读取订单且链路上没有归属校验'], notAffectedIf: ['查询条件或读取后比较了当前用户'], remediation: '在查询中加入当前用户条件，或读取后比较 owner。', references: [],
      } }] };
    }

    if (user.includes('这是风险排查（不是全面审计）')) {
      const repo = /只判断仓库 ([\w.-]+) 是否受/.exec(user)?.[1] ?? '';
      const cands = [...user.matchAll(/- id=`([^`]+)`\n\s+位置：([^:\n]+):([^:\n]+):(\d+)/g)].map((m) => ({ id: m[1]!, path: m[3]!, line: Number(m[4]) }));
      const ctrl = cands.find((c) => c.path.endsWith('OrderController.java'));
      if (assistantTurns === 0) return { toolCalls: cands.slice(0, 5).map((c) => ({ name: 'read', args: { repo, path: c.path } })) };
      if (lastToolText.startsWith('recorded')) return { text: 'done' };
      const hits = ctrl ? [{
        title: '订单详情缺少归属校验', category: 'authz_object', severity: 'high', confidence: 0.85,
        location: { repo, path: ctrl.path, startLine: ctrl.line, endLine: ctrl.line + 2 }, entries: [], rootCause: '按 id 直接读取订单', attackPath: '登录用户把路径中的订单 id 换成他人订单号，请求直接按 id 读取，未与当前用户比较', impact: '读取任意用户的订单详情',
        evidence: [{ repo, path: ctrl.path, startLine: ctrl.line, endLine: ctrl.line + 2, note: '未校验归属' }], chain: [],
        reasoning: '入口按 id 读取，链路上没有与当前用户比较。', counterCheck: '检查了控制器与服务层。', exploitConditions: [{ condition: '已登录', status: 'confirmed', source: '入口' }],
        remediation: { approach: '查询时加入当前用户条件' },
      }] : [];
      return { toolCalls: [{ name: 'submit_risk_verdicts', args: {
        hits, ruledOut: cands.filter((c) => c !== ctrl).map((c) => ({ candidateId: c.id, reason: '不是按 id 读取订单' })),
        repoVerdict: ctrl ? { verdict: opts.riskVerdict ?? 'affected', reason: '订单详情接口没有归属校验', evidence: [], ...(opts.riskVerdict === 'pending' ? { pendingCondition: PENDING } : {}) } : { verdict: 'not_affected', reason: '没有按 id 读取订单的接口', evidence: cands[0] ? [{ repo, path: cands[0].path, startLine: Math.max(1, cands[0].line), endLine: Math.max(1, cands[0].line) }] : [] },
      } }] };
    }

    if (sys.includes('审计负责人')) {
      if (opts.planBroken) return { text: 'no plan' };
      if (assistantTurns === 0) return { toolCalls: [{ name: 'entrypoints', args: {} }] };
      if (assistantTurns === 1) {
        return { toolCalls: [{ name: 'submit_plan', args: { summary: 'Spring 订单服务，审计 SQL 注入与越权', focusDirections: [{ direction: 'SQL 注入', reason: 'Statement 拼接' }], plannedKnowledge: [{ skill: 'spring-authz-method', reason: '鉴权' }], contextNeeded: ['网关是否做鉴权'], limitations: [] } }] };
      }
      return { text: 'plan submitted' };
    }

    if (sys.includes('复验员')) {
      // Verify at the vulnerability's own evidence location (shop fixture) or the java-mini DAO.
      const shopEv = user.includes(SHOP_CTRL) ? { repo: /该漏洞位于仓库 ([\w.-]+)/.exec(user)?.[1] ?? 'order-service', path: SHOP_CTRL, startLine: 15, endLine: 18 } : null;
      if (shopEv) {
        if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { repo: shopEv.repo, path: SHOP_CTRL } }, { name: 'cross_repo_trace', args: { repo: shopEv.repo, pathTemplate: '/api/order/{id}', direction: 'caller' } }] };
        if (assistantTurns === 1) {
          return { toolCalls: [{ name: 'submit_reverify', args: {
            verdict: 'still_present', reasoning: '服务内仍无归属校验；网关 TokenPresenceFilter 只检查 Authorization 头是否存在', evidence: [{ ...shopEv, note: '仍直接按 id 读取' }], fixedEntries: [],
            ...(user.includes('待确认”（定向复验）') ? { pendingResolution: opts.pendingResolution ?? 'holds', ...(opts.pendingResolution === 'still_pending' ? { pendingCondition: PENDING } : {}) } : {}),
          } }] };
        }
        return { text: 'done' };
      }
      const rcq = opts.reverifyConnector && opts.connectorQuery ? [{ name: 'connector_query', args: { ...opts.connectorQuery, reason: '核实网关是否过滤参数' } }] : [];
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { path: DAO } }, { name: 'diff', args: { path: DAO } }, ...rcq] };
      if (assistantTurns === 1) {
        const verdict = opts.reverify ?? 'still_present';
        return {
          toolCalls: [{
            name: 'submit_reverify', args: {
              verdict, reasoning: verdict === 'fixed' ? '改为 PreparedStatement 参数化，name 不再拼接进 SQL' : 'name 仍拼接进 SQL',
              evidence: verdict === 'undetermined' ? [] : [{ path: DAO, startLine: 17, endLine: 23, note: '当前实现' }],
              fixedEntries: verdict === 'partially_fixed' ? ['GET /api/order/search'] : [],
              ...(verdict === 'undetermined' ? { pendingCondition: { missing: [{ kind: 'config', ref: 'SQL 防火墙' }], holdsIf: [{ statement: '未启用 SQL 防火墙' }], refutedIf: [{ statement: '已启用且拦截拼接' }], severityIfHolds: 'high', suggestedActions: ['ask_user'] } } : {}),
              ...(user.includes('待确认”（定向复验）') && opts.pendingResolution ? { pendingResolution: opts.pendingResolution } : {}),
              ...(rcq.length ? { connectorRefs: connectorCalls(body.messages) } : {}),
            },
          }],
        };
      }
      return { text: 'reverified' };
    }

    if (sys.includes('归并员')) {
      if (assistantTurns > 0 && !opts.mergeBroken) return { text: 'done' };
      if (opts.mergeBroken) return { toolCalls: [{ name: user.includes('已追踪的漏洞') ? 'submit_suspected_matches' : 'submit_merge_groups', args: {} }] };
      if (user.includes('已追踪的漏洞')) {
        const findings = [...user.matchAll(/^(F\d+) \|/gm)].map((m) => m[1]!);
        const cands = new Map([...user.matchAll(/^(F\d+) \|[\s\S]*?候选：([^\n]+)/gm)].map((m) => [m[1]!, m[2]!.split(',').map((x) => x.trim())]));
        return { toolCalls: [{ name: 'submit_suspected_matches', args: { decisions: findings.map((f) => ({ finding: f, vulnerability: opts.suspect === 'none' ? null : cands.get(f)?.[0] ?? null, reason: '危险操作与根因一致：同一处 SQL 拼接被重构' })) } }] };
      }
      const labels = [...user.matchAll(/^(L\d+) \|/gm)].map((m) => m[1]!);
      const existing = [...user.matchAll(/^(E\d+) \|/gm)].map((m) => m[1]!);
      if (opts.mergeIntoExisting && existing.length && labels.length) {
        return { toolCalls: [{ name: 'submit_merge_groups', args: { groups: [{ labels: [labels[0]!, existing[0]!] }, ...labels.slice(1).map((l) => ({ labels: [l] }))], dropped: [] } }] };
      }
      return { toolCalls: [{ name: 'submit_merge_groups', args: { groups: labels.map((l) => ({ labels: [l] })), dropped: [] } }] };
    }

    if (sys.includes('威胁建模')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'entrypoints', args: {} }] };
      if (assistantTurns === 1) {
        return {
          toolCalls: [{
            name: 'submit_profile', args: PROFILE_ARGS,
          }],
        };
      }
      return { text: 'profile submitted' };
    }

    if (sys.includes('质疑者') && (user.includes('复核“已修复”结论') || user.includes('复核“受影响”结论'))) {
      const repo = /仓库 ([\w.-]+)/.exec(user)?.[1];
      const path = user.includes('复核“已修复”结论') ? DAO : (/- (src\/[^:\s]+):\d+/.exec(user)?.[1] ?? DAO);
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { ...(repo && !user.includes('复核“已修复”结论') ? { repo } : {}), path } }] };
      if (assistantTurns === 1) {
        const doubt = opts.verdictReview === 'doubt';
        return { toolCalls: [{ name: 'submit_verdict_review', args: {
          decision: doubt ? 'doubt' : 'maintain', reason: doubt ? '导出接口仍调用旧的拼接查询' : '修复覆盖了全部入口',
          evidence: doubt ? [{ ...(repo && !user.includes('复核“已修复”结论') ? { repo } : {}), path, startLine: 1, endLine: 2 }] : [],
          ...(doubt ? { pendingCondition: PENDING } : {}),
        } }] };
      }
      return { text: 'reviewed' };
    }
    if (sys.includes('质疑者')) {
      const ck = opts.challengeKnowledge;
      const cc = opts.challengeConnector && opts.connectorQuery ? opts.challengeConnector : null;
      if (assistantTurns === 0) {
        return { toolCalls: [{ name: 'read', args: { path: DAO } }, ...(opts.reviewReadsReasoning ? [{ name: 'finding_reasoning', args: {} }] : []), ...(ck?.read ?? []).map((n) => ({ name: 'load_skill', args: { name: n, reason: '核对网关鉴权' } })),
          ...(cc ? [{ name: 'connector_query', args: { ...opts.connectorQuery!, reason: '核实网关是否过滤参数' } }] : [])] };
      }
      if (assistantTurns === 1) {
        if (cc) return { toolCalls: [{ name: 'submit_challenge', args: { codeDefense: '网关统一过滤', threatModel: '连接器返回网关做了参数过滤', affirm: '字符串直接拼接进 SQL', confirmation: 'maintain', confidenceDelta: cc.delta, reason: '连接器称网关过滤了 name 参数', connectorRefs: connectorCalls(body.messages) } }] };
        if (ck) return { toolCalls: [{ name: 'submit_challenge', args: { codeDefense: '网关统一过滤', threatModel: '网关据称已做参数化', affirm: '字符串直接拼接进 SQL', confirmation: 'maintain', confidenceDelta: ck.delta, reason: '知识称网关过滤了 name 参数', knowledgeRefs: ck.cite } }] };
        // adversarial review: refuted with the code it read (the DAO, read on the first turn).
        if (opts.review === 'refuted') return { toolCalls: [{ name: 'submit_challenge', args: { codeDefense: 'name 在 DAO 前已被白名单校验', threatModel: '入口参数不可控', affirm: '字符串拼接进 SQL', confirmation: 'refuted', confidenceDelta: -0.5, reason: '读到了白名单校验（脚本模型）', evidence: [{ path: DAO, startLine: 17, endLine: 21 }] } }] };
        return { toolCalls: [{ name: 'submit_challenge', args: { codeDefense: '无参数化，无过滤', threatModel: '入口对登录用户开放', affirm: '字符串直接拼接进 SQL', confirmation: 'maintain', confidenceDelta: 0.05, reason: '未发现防护', ...(opts.challengeMaintainWithCondition ? { pendingCondition: { missing: [{ kind: 'business_rule', ref: 'unused' }], holdsIf: [{ statement: 'unused' }], refutedIf: [{ statement: 'unused' }], severityIfHolds: 'high', suggestedActions: ['ask_user'] } } : {}) } }] };
      }
      return { text: 'done' };
    }

    // hunt: cross-repository pending IDOR (shop fixture)
    if (opts.pendingIdor && user.includes(SHOP_CTRL) && user.includes('order-service:')) {
      if (assistantTurns === 0) {
        return { toolCalls: [{ name: 'read', args: { repo: 'order-service', path: SHOP_CTRL } }, { name: 'cross_repo_trace', args: { repo: 'order-service', pathTemplate: '/api/order/{id}', direction: 'caller' } }] };
      }
      if (lastToolText.startsWith('accepted')) return { text: 'done' };
      const idsHere = [...user.matchAll(/- id=`([^`]+)`/g)].map((m) => m[1]!);
      return {
        toolCalls: [{
          name: 'submit_findings', args: {
            findings: [{
              title: '订单详情缺少归属校验（依赖网关）', category: 'authz_object', cwe: 'CWE-639', severity: 'high', confidence: 0.7,
              location: { repo: 'order-service', path: SHOP_CTRL, startLine: 17, endLine: 17 }, entries: ['GET /api/order/{}'],
              rootCause: 'get 按 id 直接读取订单，不校验订单属于当前用户', attackPath: '登录用户在 /api/order/{id} 中换成他人订单号，服务按 id 直接读取，未校验归属', impact: '读取他人订单', evidence: [{ repo: 'order-service', path: SHOP_CTRL, startLine: 15, endLine: 18, note: '无归属校验' }],
              chain: [{ repo: 'order-service', path: SHOP_CTRL, startLine: 15, endLine: 18, note: '入口直接调用 orders.load(id)' }],
              reasoning: '服务本身不校验归属；是否成立取决于网关策略。', counterCheck: '服务内没有 Filter / 注解鉴权。',
              exploitConditions: [{ condition: '网关只校验登录态', status: 'unconfirmed', source: 'cross_repo_trace' }],
              remediation: { approach: '在服务内校验订单 owner 与当前用户一致' }, verdict: 'pending', pendingCondition: PENDING,
            }],
            reviewedTargets: idsHere.map((id) => ({ targetKind: id.includes('#L') ? 'sink' : 'entry', targetId: id, verdict: 'no_issue' })), ruledOut: [], scopeReviewed: SHOP_CTRL,
          },
        }],
      };
    }

    // decide rounds: pick one open item (or a new direction), never facts or findings.
    if (user.includes('这是深度探索的第')) {
      if (lastToolText.startsWith('decision recorded')) return { text: 'decided' };
      const todo = [...user.split('## 线索')[0]!.matchAll(/- id=`(wki_[0-9A-Z]{26})`/g)].map((m) => m[1]!);
      const leads = [...(user.split('## 线索')[1] ?? '').split('## 已完成')[0]!.matchAll(/- id=`(wki_[0-9A-Z]{26})`/g)].map((m) => m[1]!);
      if (opts.explore === 'sloppy') {
        // What a real model sent: an invented itemId next to a complete new direction, a
        // findingId on a hunt and a repository hash instead of its name.
        return { toolCalls: [{ name: 'submit_decision', args: { itemId: 'new:uncovered-entrypoints', direction: { title: '库存客户端的出站调用', target: { repo: 'f'.repeat(64), path: 'src/main/java/com/demo/client/InventoryClient.java', line: 1 } }, action: 'hunt', findingId: 'payment-authorization-state', rationale: '新方向' } }] };
      }
      if (opts.explore === 'revisit') {
        const round = Number(/深度探索的第 (\d+) 轮/.exec(user)?.[1] ?? 1);
        return { toolCalls: [{ name: 'submit_decision', args: round === 1 ? { direction: { title: '再查订单搜索的 SQL 拼接', target: { path: DAO, line: 21 } }, action: 'hunt', rationale: '复核拼接点' } : { action: 'hunt', rationale: '没有剩余方向', stop: true } }] };
      }
      if (opts.explore === 'stall') {
        // A first repeat of an explored direction (refused), then a fresh line each time.
        const round = Number(/深度探索的第 (\d+) 轮/.exec(user)?.[1] ?? 1);
        const line = assistantTurns === 0 && round > 1 ? round - 1 : round;
        return { toolCalls: [{ name: 'submit_decision', args: { direction: { title: '再看一次库存客户端', target: { path: 'src/main/java/com/demo/client/InventoryClient.java', line } }, action: 'read', rationale: '看看出站调用' } }] };
      }
      if (assistantTurns === 0) return { toolCalls: [{ name: 'submit_decision', args: { itemId: 'wki_00000000000000000000000000', action: 'hunt', rationale: '试探' } }] };
      const pick = todo[0] ?? leads[0];
      return { toolCalls: [{ name: 'submit_decision', args: pick ? { itemId: pick, action: 'hunt', rationale: '未覆盖的入口优先' } : { action: 'hunt', rationale: '没有剩余方向', stop: true } }] };
    }

    // An idle expert submits an empty result.
    if (opts.expertIdle && user.includes('多领域专家漏洞狩猎的第')) {
      if (lastToolText.startsWith('accepted')) return { text: 'done' };
      return { toolCalls: [{ name: 'submit_findings', args: { findings: [], reviewedTargets: [], ruledOut: [], scopeReviewed: 'none' } }] };
    }
    // task sub-agent: investigate, then answer in text (it has no submit tools).
    if (user.includes('你是审计员派出的子任务')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { path: user.includes(TOKEN_FILTER) ? TOKEN_FILTER : CTRL } }] };
      return { text: '子任务结论：search 入口的 name 参数未经任何校验直接传入 OrderDao.search（OrderController.java:31-34）。' };
    }
    // independent review: judge from the code only.
    if (user.includes('请独立复核下面这条疑似漏洞')) {
      if (assistantTurns === 0) return { toolCalls: [{ name: 'read', args: { path: DAO } }] };
      if (assistantTurns === 1) {
        const v = opts.review ?? 'holds';
        return { toolCalls: [{ name: 'submit_review', args: { verdict: v, confidence: v === 'holds' ? 0.85 : 0.6, reason: v === 'refuted' ? 'name 在 DAO 前已被白名单校验' : 'name 直接拼接进 SQL', evidence: [{ path: DAO, startLine: 17, endLine: 21 }] } }] };
      }
      return { text: 'reviewed' };
    }

    // hunt
    const ids = [...user.matchAll(/- id=`([^`]+)`\n\s+位置：([^:\n]+):([^:\n]+):(\d+)/g)].map((m) => ({ id: m[1]!, repo: m[2]!, path: m[3]! }));
    // Incremental change candidates: "- 变更文件：repo:path  label" (no id).
    const changed = [...user.matchAll(/- 变更文件：([^:\n]+):(\S+)/g)].map((m) => m[2]!);
    // Deep-explore targets ("- repo:path:line  [explore] …") are read like changed files.
    for (const m of user.matchAll(/- [\w.-]+:(\S+?):\d+ {2}\[(?:explore|checklist|external)/g)) changed.push(m[1]!);
    const files = [...new Set([...ids.map((i) => i.path), ...changed])];
    const hasSqli = ids.some((i) => i.path === DAO) || changed.includes(DAO);
    if (assistantTurns === 0) {
      if (opts.citeUnread && hasSqli) return { toolCalls: [{ name: 'glob', args: { pattern: '**/*.java' } }] };
      const repoOf = new Map(ids.map((i) => [i.path, i.repo]));
      const multi = new Set(ids.map((i) => i.repo)).size > 1 || sys.includes('本次审计包含');
      const reads = [...new Set([...files, ...(hasSqli ? [DAO, CTRL] : [])])].map((p) => ({ name: 'read', args: { ...(multi && repoOf.get(p) ? { repo: repoOf.get(p) } : {}), path: p } }));
      const calls = opts.askBlocking && hasSqli ? [...reads, { name: 'ask_user', args: { question: '网关是否对 /api/order/search 做鉴权？', blocking: true } }] : reads;
      const investigating = opts.markCandidates && user.includes('mark_candidate') ? [...(opts.markUnknown ? [{ name: 'mark_candidate', args: { candidateId: 'sink:not-listed', status: 'investigating' } }] : []), ...ids.slice(0, 2).map((i) => ({ name: 'mark_candidate', args: { candidateId: i.id, status: 'investigating' } }))] : [];
      const skills = hasSqli ? (opts.knowledge?.read ?? []).map((n) => ({ name: 'load_skill', args: { name: n, reason: '参考注入审计方法' } })) : [];
      const cq = hasSqli && opts.connectorQuery ? [{ name: 'connector_query', args: { ...opts.connectorQuery, reason: '确认网关是否做参数过滤' } }] : [];
      const task = hasSqli && opts.useTask ? [{ name: 'task', args: { goal: '追踪 OrderController.search 到 OrderDao 的 name 参数是否经过校验', files: [CTRL] } }] : [];
      const lsp = opts.useLsp ? [{ name: 'definition', args: opts.useLsp }, { name: 'references', args: opts.useLsp }] : [];
      const extra = (opts.extraReads ?? []).map((p) => ({ name: 'read', args: { path: p } }));
      // An expert with hypotheses to answer reads the controller its verdicts cite.
      const hypRead = user.includes('多领域专家漏洞狩猎的第') && user.includes('hypothesisId=`') && !files.includes(CTRL) && !hasSqli ? [{ name: 'read', args: { path: CTRL } }] : [];
      // A mechanism listed as a gap is read in the gap round (unless the expert never reads it).
      const gapMech = opts.expertMechanism === 'read_in_gap_round' && user.includes('本领域还没有阅读过的机制') ? [{ name: 'read', args: { path: TOKEN_FILTER } }] : [];
      // With facts in force the hunt looks them up (its SQL finding then cites them).
      const factsCall = opts.useFacts && hasSqli && JSON.stringify(body).includes('"facts_query"') ? [{ name: 'facts_query', args: {} }] : [];
      return { toolCalls: [...calls, ...hypRead, ...gapMech, ...investigating, ...skills, ...cq, ...task, ...lsp, ...extra, ...factsCall] };
    }
    // domain experts are hunted like a batch of their leads; a later round does not report the same finding again.
    const expertRound = user.includes('多领域专家漏洞狩猎的第') ? Number(/漏洞狩猎的第 (\d+) 轮/.exec(user)?.[1] ?? 1) : 0;
    const openLeads = (opts.expertOpenLeadAlways && expertRound > 0 && hasSqli) || (opts.expertOpenLead && expertRound === 1 && hasSqli) ? { openLeads: [{ direction: '再看订单导出的文件名拼接', files: [CTRL] }] } : {};
    const bogus = [
      ...(opts.expertUnknownTarget && expertRound > 0 ? [{ targetKind: 'entry', targetId: 'src/Nope.java#Missing', verdict: 'no_issue' }] : []),
      // A fill session listing its checklist items (shown as `repo:path:line`) in reviewedTargets, as real models do.
      ...(opts.fillListsItems && user.includes('## 清单补审条目') ? [...user.matchAll(/^- (java-mini:\S+:1) {2}\[checklist\]/gm)].map((m) => ({ targetKind: 'entry', targetId: m[1]!, verdict: 'no_issue' })) : []),
    ];
    const loose = opts.expertFindingNoFinding && expertRound > 0 ? ids.find((i) => i.path !== DAO)?.id : undefined;
    const omitted = (opts.omitCandidate && expertRound === 0) || (expertRound > 0 && (opts.expertOmitLead === 'never' || (opts.expertOmitLead === 'answer_in_gap_round' && expertRound === 1)))
      ? ids.find((i) => i.path !== DAO)?.id : undefined;
    // An expert gives a verdict on every hypothesis listed to it (refuted / open in turn, as the ⑧ batches do).
    const hypIds = expertRound > 0 && !opts.expertNoVerdicts ? [...user.matchAll(/hypothesisId=`(hyp_[0-9A-Z]+)`/g)].map((m) => m[1]!) : [];
    const verdicts = hypIds.length ? { verdicts: hypIds.map((id, i) => (i % 2 === 0
      ? { hypothesisId: id, status: 'refuted', reason: '服务端按会话用户重新查询，未信任请求参数（脚本专家）', location: { repo: 'java-mini', path: CTRL, startLine: 24, endLine: 27 } }
      : { hypothesisId: id, status: 'open', reason: '取决于网关是否统一鉴权，代码中读不到（脚本专家）', location: { repo: 'java-mini', path: CTRL, startLine: 36, endLine: 39 } })) } : {};
    const diverge = !!opts.multiDiverge && model === 'm2';
    const atCtrl = !!opts.revisitAtController && user.includes('[explore');
    const badFindings = opts.expertBadFindings && expertRound === 1 && hasSqli ? [
      { title: '缺少必填字段的发现', category: 'sqli' },
      { title: '引用越界行号的发现', category: 'sqli', cwe: 'CWE-89', severity: 'high', confidence: 0.8, location: { path: DAO, startLine: 21, endLine: 21 }, entries: [], rootCause: 'x',
        attackPath: '登录用户在搜索参数中注入 SQL 片段，参数原样拼接进查询语句', impact: '读取任意数据', evidence: [{ path: DAO, startLine: 1, endLine: 9999 }], chain: [],
        reasoning: 'x', counterCheck: 'x', exploitConditions: [{ condition: '需要登录', status: 'unconfirmed', source: 'x' }], remediation: { approach: 'x' }, verdict: 'confirmed' },
    ] : [];
    const findings = opts.findSqli !== false && hasSqli && !diverge && expertRound <= 1 ? [{
      title: '订单搜索存在 SQL 注入', category: 'sqli', cwe: 'CWE-89', severity: 'high',
      confidence: opts.revisitConfidence ? (user.includes('[explore') ? opts.revisitConfidence.again : opts.revisitConfidence.first) : 0.9,
      location: atCtrl ? { path: CTRL, startLine: 31, endLine: 34 } : { path: DAO, startLine: 21, endLine: 21 },
      entries: ['GET /api/order/search'], rootCause: 'name 参数直接拼接进 SQL 语句',
      attackPath: '登录用户在 GET /api/order/search 的 name 参数中注入 SQL 片段，参数原样拼接进 Statement.executeQuery', impact: '读取或篡改订单库中的任意数据',
      evidence: [{ path: DAO, startLine: 21, endLine: 21, note: 'executeQuery 拼接 name' }],
      chain: [{ path: CTRL, startLine: 31, endLine: 34, note: 'search 入口接收 name' }, { path: DAO, startLine: 17, endLine: 21, note: 'search 拼接 SQL' }],
      reasoning: '入口 search 的 name 参数未经处理传入 OrderDao.search，被拼接进 Statement.executeQuery。', counterCheck: '检查了 Filter 与参数校验，未发现过滤。',
      exploitConditions: [{ condition: '需要登录', status: 'unconfirmed', source: 'SecurityConfig anyRequest().authenticated()' }],
      remediation: { approach: '改用 PreparedStatement 参数化查询' }, verdict: 'confirmed',
      ...(opts.knowledge?.cite ? { knowledgeRefs: opts.knowledge.cite } : {}),
      ...(opts.citeConnector ? { connectorRefs: connectorCalls(body.messages) } : {}),
      ...(opts.useFacts ? { factRefs: [...new Set(body.messages.filter((m) => m.role === 'tool').flatMap((m) => [...text(m).matchAll(/id=(fct_[0-9A-Z]{26})/g)].map((x) => x[1]!)))].slice(0, 3) } : {}),
    }, ...(opts.secondFinding ? [{
      title: '订单抓取接口存在 SSRF', category: 'ssrf', cwe: 'CWE-918', severity: opts.secondSeverity ?? 'high', confidence: 0.85,
      location: { path: CTRL, startLine: 38, endLine: 38 }, entries: ['POST /api/order/fetch'], rootCause: 'url 参数原样交给 RestTemplate 发起请求',
      attackPath: '登录用户在 POST /api/order/fetch 的 url 参数中填写内网地址，服务端原样请求该地址并返回内容', impact: '访问内网服务与云元数据',
      evidence: [{ path: CTRL, startLine: 38, endLine: 38 }], chain: [{ path: CTRL, startLine: 36, endLine: 38, note: 'fetch 入口接收 url' }],
      reasoning: 'url 未经白名单校验直接请求。', counterCheck: '检查了参数校验与代理配置，未发现限制。',
      exploitConditions: [{ condition: '需要登录', status: 'unconfirmed', source: 'SecurityConfig' }], remediation: { approach: '按白名单校验目标地址' }, verdict: 'confirmed',
    }] : [])] : [];
    // The verdict of each candidate as a progress mark, right before the submission (optionally contradicting it).
    const verdictMarks = () => (opts.markCandidates && user.includes('mark_candidate') ? ids.map((i) => {
      const sqliSink = i.path === DAO && findings.length > 0;
      return { name: 'mark_candidate', args: { candidateId: i.id, status: sqliSink && !opts.markMismatch ? 'finding' : 'no_issue', note: sqliSink ? 'name 拼接进 SQL' : '未发现问题' } };
    }) : []);
    if (assistantTurns === 1 && opts.citeUnread && hasSqli && !lastToolText.includes('提交被拒绝')) {
      return { toolCalls: [{ name: 'submit_findings', args: { findings, reviewedTargets: [], ruledOut: [], scopeReviewed: 'none' } }] };
    }
    if (lastToolText.includes('提交被拒绝') || (assistantTurns === 1 && !lastToolText.startsWith('accepted'))) {
      if (lastToolText.includes('提交被拒绝')) {
        return { toolCalls: [{ name: 'read', args: { path: DAO } }, { name: 'read', args: { path: CTRL } }] };
      }
      return {
        toolCalls: [...verdictMarks(), {
          name: 'submit_findings',
          args: {
            findings: [...findings, ...badFindings],
            reviewedTargets: [...ids.filter((i) => !(diverge && i.path === DAO && i.id.includes('#L')) && i.id !== omitted).map((i) => ({ targetKind: i.id.includes('#L') ? 'sink' : 'entry', targetId: opts.bareTargetIds && !i.id.includes('#') ? i.id.replace(/^[\w.-]+:/, '').replace('{}', '{id}') : i.id, verdict: (i.path === DAO && findings.length) || i.id === loose ? 'finding' : 'no_issue' })), ...bogus],
            ruledOut: diverge ? ids.filter((i) => i.path === DAO && i.id.includes('#L')).map((i) => ({ targetKind: 'sink', targetId: i.id, reason: 'name 在进入 DAO 前经过白名单校验' })) : [], scopeReviewed: files.join(', ') || 'none', ...openLeads, ...verdicts,
          },
        }],
      };
    }
    // Asked once about the omitted candidate after the first accepted submission.
    if (omitted && lastToolText.startsWith('accepted') && user.includes('还没有结论') && opts.omitCandidate === 'answer_on_nudge'
      && body.messages.filter((m) => m.role === 'tool' && text(m).startsWith('accepted')).length === 1) {
      return { toolCalls: [{ name: 'submit_findings', args: { findings: [], reviewedTargets: [{ targetKind: omitted.includes('#L') ? 'sink' : 'entry', targetId: omitted, verdict: 'no_issue' }], ruledOut: [], scopeReviewed: files.join(', ') || 'none' } }] };
    }
    if (lastToolText.startsWith('accepted')) return { text: 'done' };
    return {
      toolCalls: [...verdictMarks(), {
        name: 'submit_findings',
        args: {
          findings: [...findings, ...badFindings],
          reviewedTargets: [...ids.filter((i) => !(diverge && i.path === DAO && i.id.includes('#L')) && i.id !== omitted).map((i) => ({ targetKind: i.id.includes('#L') ? 'sink' : 'entry', targetId: i.id, verdict: (i.path === DAO && findings.length) || i.id === loose ? 'finding' : 'no_issue' })), ...bogus],
          ruledOut: diverge ? ids.filter((i) => i.path === DAO && i.id.includes('#L')).map((i) => ({ targetKind: 'sink', targetId: i.id, reason: 'name 在进入 DAO 前经过白名单校验' })) : [], scopeReviewed: files.join(', ') || 'none', ...openLeads, ...verdicts,
        },
      }],
    };
  };
}
