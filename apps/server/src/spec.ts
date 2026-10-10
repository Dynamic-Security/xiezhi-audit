// Route documentation and schemas. One entry per API route: attached to the route by
// an onRoute hook, so responses are serialized through the contract schema (field whitelist) and
// openapi.json is generated from exactly what the service enforces. A test fails if any /api route
// lacks an entry.
import { Type, type TSchema } from 'typebox';
import * as C from '@xiezhi/contracts';
import * as B from './bodies.js';
import * as Q from './queries.js';

export interface RouteDoc {
  tag: string;
  summary: string;
  body?: TSchema;
  /** Query-string parameters (validated; listed in openapi.json). */
  query?: TSchema;
  /** Success responses by status code; omitted for streams/downloads. */
  response?: Record<number, TSchema>;
  /** Non-JSON content types (SSE, file download) for documentation. */
  produces?: string[];
  description?: string;
}

const A = Type.Array;
const ok = (s: TSchema, code = 200) => ({ [code]: s });
const none = { 204: Type.Null({ description: 'No content' }) };

function skillRoutes(prefix: string, layer: string): Record<string, RouteDoc> {
  return {
    [`GET ${prefix}/:name`]: { tag: 'knowledge', summary: `${layer} skill：入口文件全文、文件清单与内容哈希`, response: ok(C.SkillBodyDto) },
    [`PUT ${prefix}/:name`]: { tag: 'knowledge', summary: `新建（baseSha256 为 null）或修改${layer} skill 的入口文件；内容哈希不一致返回 412 并附磁盘版本，格式不合法返回 422`, body: B.PutSkillBody, response: ok(C.SkillBodyDto) },
    [`DELETE ${prefix}/:name`]: { tag: 'knowledge', summary: `删除${layer} skill（If-Match 或 baseSha256 为入口文件哈希）`, query: Q.DeleteSkillQuery, response: none },
    [`GET ${prefix}/:name/files/*`]: { tag: 'knowledge', summary: `${layer} skill 的子文件`, response: ok(C.SkillFileDto) },
    [`PUT ${prefix}/:name/files/*`]: { tag: 'knowledge', summary: `新建或修改${layer} skill 的子文件；单文件 skill 在添加第一个子文件时转为目录形态`, body: B.PutSkillFileBody, response: ok(C.SkillBodyDto) },
    [`DELETE ${prefix}/:name/files/*`]: { tag: 'knowledge', summary: `删除${layer} skill 的子文件`, query: Q.DeleteSkillQuery, response: ok(C.SkillBodyDto) },
  };
}

export const ROUTE_DOCS: Record<string, RouteDoc> = {
  // session & health
  'POST /api/session/bootstrap': { tag: 'session', summary: '用一次性引导码换取浏览器会话（设置 HttpOnly cookie）', body: B.PostSessionBootstrapBody, response: ok(C.SessionInfo) },
  'GET /api/session': { tag: 'session', summary: '当前会话与 CSRF token', response: ok(C.SessionInfo) },
  'POST /api/v1/session/bootstrap-codes': { tag: 'session', summary: '（仅 CLI Bearer）生成新的一次性登录链接', response: ok(C.BootstrapUrl) },
  'GET /api/v1/health': { tag: 'system', summary: '存活与就绪检查（公开，无敏感信息）', response: ok(C.HealthInfo) },
  'GET /api/v1/openapi.json': { tag: 'system', summary: '本接口的 OpenAPI 3 文档' },
  'GET /api/v1/diagnostics': { tag: 'system', summary: '诊断页数据（缓存 10 分钟）', response: ok(C.DiagnosticsDto) },
  'POST /api/v1/diagnostics/run': { tag: 'system', summary: '重新执行诊断', response: ok(C.DiagnosticsDto) },
  // settings
  'GET /api/v1/settings/model-providers': { tag: 'settings', summary: '模型服务列表（凭证只返回 configured/hint）', response: ok(A(C.ProviderDto)) },
  'POST /api/v1/settings/model-providers': { tag: 'settings', summary: '添加模型服务', body: B.ProviderCreate, response: ok(C.ProviderDto, 201) },
  'PATCH /api/v1/settings/model-providers/:id': { tag: 'settings', summary: '修改模型服务；baseUrl 的 origin 变化时清除密钥', body: B.ProviderPatch, response: ok(C.ProviderPatched) },
  'DELETE /api/v1/settings/model-providers/:id': { tag: 'settings', summary: '删除模型服务', response: none },
  'POST /api/v1/settings/model-providers/probe': { tag: 'settings', summary: '探测未保存表单的可用模型（可沿用已保存服务的密钥，需同一 origin；不跟随重定向）', body: B.ProviderProbeBody, response: ok(C.ProviderProbeResult) },
  'POST /api/v1/settings/model-providers/check': { tag: 'settings', summary: '测验未保存表单的连通性：列模型，再对勾选的模型（最多 10 个）各发一次极短请求', body: B.ProviderCheckBody, response: ok(C.ProviderCheckResult) },
  'POST /api/v1/settings/model-providers/:id/test': { tag: 'settings', summary: '连通性测试（不跟随重定向）', response: ok(C.ProviderTestResult) },
  'GET /api/v1/settings/models': { tag: 'settings', summary: '模型设置（默认模型、各阶段模型、备用模型、可接收机密事实的模型）', response: ok(C.ModelSettingsDto) },
  'PUT /api/v1/settings/models': { tag: 'settings', summary: '保存模型设置（revision 为配置哈希）', body: B.PutSettingsModelsBody, response: ok(C.ModelSettingsDto) },
  'GET /api/v1/settings/scene-defaults/:scene': { tag: 'settings', summary: '场景的任务创建默认值（覆盖层与合并结果）', response: ok(C.SceneDefaultsDto) },
  'PUT /api/v1/settings/scene-defaults/:scene': { tag: 'settings', summary: '修改场景默认值', body: B.PutSettingsSceneDefaultsSceneBody, response: ok(C.SceneDefaultsDto) },
  'GET /api/v1/settings/general': { tag: 'settings', summary: '通用设置', response: ok(C.GeneralSettingsDto) },
  'PATCH /api/v1/settings/general': { tag: 'settings', summary: '修改通用设置', body: B.PatchSettingsGeneralBody, response: ok(C.GeneralSettingsDto) },
  'GET /api/v1/settings/git-credentials': { tag: 'settings', summary: 'Git HTTPS 凭证（按域名；token 只返回 configured/hint）', response: ok(A(C.GitCredentialDto)) },
  'PUT /api/v1/settings/git-credentials/:host': { tag: 'settings', summary: '设置某域名的 Git 用户名与 token（token 留空表示不变）', body: B.PutSettingsGitCredentialsHostBody, response: ok(C.GitCredentialDto) },
  'DELETE /api/v1/settings/git-credentials/:host': { tag: 'settings', summary: '删除某域名的 Git 凭证', response: none },
  // knowledge
  // enterprise facts
  'GET /api/v1/projects/:pid/facts': { tag: 'knowledge', summary: '项目的企业事实（默认只列生效版本；status=all 含历史版本），可按主题、关键词筛选', query: Type.Object({ status: Type.Optional(Type.String()), topic: Type.Optional(Type.String()), q: Type.Optional(Type.String()) }), response: ok(A(C.FactDto)) },
  'POST /api/v1/projects/:pid/facts': { tag: 'knowledge', summary: '新增事实（同一键已有生效版本时写入新版本）；sourceKind=review 表示由复核裁定保存', body: C.PostFactBody, response: ok(C.FactDto) },
  'POST /api/v1/projects/:pid/facts/import': { tag: 'knowledge', summary: '从业务 / 架构知识、拓扑与架构导入、需求风险裁定、画像假设、已回答的提问导入事实（按来源去重，人改过的不覆盖）', response: ok(C.FactImportDto) },
  'POST /api/v1/audits/:aid/external-results': { tag: 'audits', summary: '导入外部扫描结果（SARIF 2.1.0，如 Semgrep、CodeQL）：每条结果成为审计须核对的外部义务（重复、误报或补审成发现），审计结束前可导入', body: B.PostExternalResultsBody, response: ok(Type.Object({ results: Type.Integer(), added: Type.Integer(), skipped: Type.Integer() })) },
  // project rules
  'GET /api/v1/projects/:pid/rules': { tag: 'vulnerabilities', summary: '项目规则（确认漏洞固化的检测模式），可按漏洞筛选；批准的规则从下一次审计起作为危险点规则运行', query: Type.Object({ vulnId: Type.Optional(Type.String()) }), response: ok(A(C.ProjectRuleDto)) },
  'POST /api/v1/vulnerabilities/:vid/rules': { tag: 'vulnerabilities', summary: '为漏洞生成项目规则：mode=ai 由对话模型起草（202，后台进行）；否则提交自己写的模式（立即校验能否命中原位置）', body: C.PostProjectRuleBody, response: ok(C.ProjectRuleDto) },
  'POST /api/v1/vulnerabilities/:vid/rules/test': { tag: 'vulnerabilities', summary: '在漏洞所在快照上试跑一个模式：是否命中原位置、命中多少处与样例', body: C.TestProjectRuleBody, response: ok(C.ProjectRuleValidationDto) },
  'GET /api/v1/rules/:rid': { tag: 'vulnerabilities', summary: '一条项目规则', response: ok(C.ProjectRuleDto) },
  'POST /api/v1/rules/:rid/decision': { tag: 'vulnerabilities', summary: '批准（再次校验）、驳回或停用项目规则', body: C.ProjectRuleDecisionBody, response: ok(C.ProjectRuleDto) },
  // verification cases and fix suggestions
  'GET /api/v1/vulnerabilities/:vid/verification-cases': { tag: 'vulnerabilities', summary: '漏洞的验证用例（由 AI 编写、用户在自己的环境执行；引擎不执行）', response: ok(A(C.VerificationCaseDto)) },
  'POST /api/v1/vulnerabilities/:vid/verification-cases': { tag: 'vulnerabilities', summary: '由对话模型编写验证用例（202，后台进行）', response: ok(C.VerificationCaseDto) },
  'GET /api/v1/verification-cases/:id': { tag: 'vulnerabilities', summary: '一个验证用例', response: ok(C.VerificationCaseDto) },
  'POST /api/v1/verification-cases/:id/result': { tag: 'vulnerabilities', summary: '回填验证结果：复现 → 按用户验证确认漏洞；未复现 → 生成误报建议（需说明）；无法判断 → 只记录', body: C.PostCaseResultBody, response: ok(C.VerificationCaseDto) },
  'GET /api/v1/vulnerabilities/:vid/fix-suggestions': { tag: 'vulnerabilities', summary: '漏洞的补丁建议（unified diff，已检查能应用到快照；不写入仓库）与关联复验的结论', response: ok(A(C.FixSuggestionDto)) },
  'POST /api/v1/vulnerabilities/:vid/fix-suggestions': { tag: 'vulnerabilities', summary: '为确认的漏洞由对话模型编写补丁建议（202，后台进行）', response: ok(C.FixSuggestionDto) },
  'GET /api/v1/fix-suggestions/:id': { tag: 'vulnerabilities', summary: '一条补丁建议', response: ok(C.FixSuggestionDto) },
  'POST /api/v1/fix-suggestions/:id/reverify': { tag: 'vulnerabilities', summary: '应用补丁后发起复验（创建复验审计并关联到建议，202）', response: ok(C.FixSuggestionDto) },
  'GET /api/v1/audits/:aid/egress': { tag: 'audits', summary: '外发记录：本次审计每个模型会话发往哪个模型服务（地址）、涉及的文件与企业事实、未发送的机密事实数、token；format=csv 下载', query: Type.Object({ format: Type.Optional(Type.String()) }), response: ok(A(C.EgressDto)) },
  'GET /api/v1/projects/:pid/egress': { tag: 'projects', summary: '项目的外发记录（含对话与独立会话，最新 2000 条）；format=csv 下载', query: Type.Object({ format: Type.Optional(Type.String()) }), response: ok(A(C.EgressDto)) },
  'GET /api/v1/projects/:pid/services/:repo/card': { tag: 'projects', summary: '服务责任卡：入站（经哪些网关路由、是否先鉴权；只能从内部到达的入口）、上游保证（企业事实）、出站调用', response: ok(C.ServiceCardDto) },
  'GET /api/v1/projects/:pid/gateway-exposure': { tag: 'projects', summary: '入口暴露图：项目各网关的路由、转发目标、去掉的路径段、路由与全局鉴权、设置或移除的请求头（由网关配置确定性提取）', response: ok(C.GatewayExposureDto) },
  'GET /api/v1/facts/:fid': { tag: 'knowledge', summary: '事实详情：各版本与依赖它的漏洞（stale 为依赖的版本已不再生效，需要复验）', response: ok(C.FactDetailDto) },
  'PUT /api/v1/facts/:fid': { tag: 'knowledge', summary: '修改生效的事实：写入新版本，依赖旧版本的发现标记为需要复验', body: C.PutFactBody, response: ok(C.FactDto) },
  'POST /api/v1/facts/:fid/retract': { tag: 'knowledge', summary: '作废事实（需要理由），依赖它的发现标记为需要复验', body: C.RetractFactBody, response: ok(C.FactDto) },
  // pipeline prompts
  'GET /api/v1/knowledge/prompts': { tag: 'knowledge', summary: '流程提示词：内置默认、全局层与（带 projectId 时）项目层的覆盖、生效版本；工具与字段说明只读', query: Q.KnowledgeQuery, response: ok(C.PromptListDto) },
  'PUT /api/v1/knowledge/prompts/:id': { tag: 'knowledge', summary: '覆盖一条提示词（带 projectId 为项目层，否则全局层）；缺少变量或锁定词、只读条目返回 422', body: C.PutPromptBody, response: ok(C.PromptDto) },
  'DELETE /api/v1/knowledge/prompts/:id': { tag: 'knowledge', summary: '恢复一条提示词的默认（删除该层的覆盖）', query: Q.KnowledgeQuery, response: ok(C.PromptDto) },
  'DELETE /api/v1/knowledge/prompts': { tag: 'knowledge', summary: '恢复该层全部提示词的默认', query: Q.KnowledgeQuery, response: ok(Type.Object({ restored: A(Type.String()) })) },
  'GET /api/v1/knowledge': { tag: 'knowledge', summary: '知识列表：不带 projectId 为全局层（标注全局下线与覆盖它的项目）；带 projectId 为项目视图（项目层 + 全局层，标注覆盖全局、停用原因、无效原因）', query: Q.KnowledgeQuery, response: ok(A(C.SkillDto)) },
  ...skillRoutes('/api/v1/knowledge/global', '全局'),
  ...skillRoutes('/api/v1/projects/:pid/knowledge', '项目'),
  'PUT /api/v1/projects/:pid/knowledge-overrides/:name': { tag: 'knowledge', summary: '本项目停用或恢复某条 skill（全局或项目层，按名称；写入项目 _settings.json）', body: B.PutKnowledgeOverrideBody, response: ok(C.KnowledgeOverrideDto) },
  'PUT /api/v1/projects/:pid/knowledge-category-overrides/:category': { tag: 'knowledge', summary: '本项目按类别停用或恢复知识', body: B.PutKnowledgeOverrideBody, response: ok(C.KnowledgeOverrideDto) },
  'GET /api/v1/knowledge/drafts': { tag: 'knowledge', summary: '待审核的知识草稿（全局层；带 projectId 为该项目层；all=1 含已处理的）', query: Q.KnowledgeDraftsQuery, response: ok(A(C.KnowledgeDraftDto)) },
  'POST /api/v1/knowledge/drafts': { tag: 'knowledge', summary: '生成知识草稿：粘贴 / 上传文本由 AI 整理，手写内容直接校验；或由已回答的提问生成项目业务知识（202，后台整理并检测重复与冲突）', body: B.PostKnowledgeDraftsBody, response: ok(C.KnowledgeDraftDto, 202) },
  'GET /api/v1/knowledge/drafts/:did': { tag: 'knowledge', summary: '草稿详情：内容、校验、疑似注入提示、同名与相似知识、结论矛盾', response: ok(C.KnowledgeDraftDto) },
  'PUT /api/v1/knowledge/drafts/:did': { tag: 'knowledge', summary: '审核前修改草稿（revision 乐观并发），重新校验', body: B.PutKnowledgeDraftBody, response: ok(C.KnowledgeDraftDto) },
  'POST /api/v1/knowledge/drafts/:did/approve': { tag: 'knowledge', summary: '审核启用：再次校验后原子写入知识层；同名需 replace；移到全局可删除项目原文件', body: B.PostKnowledgeDraftApproveBody, response: ok(C.DraftApprovedDto) },
  'POST /api/v1/knowledge/drafts/:did/reject': { tag: 'knowledge', summary: '驳回草稿（保留 30 天后清理）', response: ok(C.KnowledgeDraftDto) },
  'POST /api/v1/vulnerabilities/:vid/distill-case': { tag: 'knowledge', summary: '从漏洞沉淀案例草稿（AI 按案例模板整理，启用后更新案例库索引）', body: B.PostDistillCaseBody, response: ok(C.KnowledgeDraftDto, 202) },
  'POST /api/v1/projects/:pid/knowledge/:name/move-to-global': { tag: 'knowledge', summary: '移到全局：不带 confirm 返回私有信息提示；confirm:true（可带脱敏后的 text）生成全局草稿', body: B.PostMoveToGlobalBody, response: { 200: C.MoveToGlobalPreviewDto, 202: C.KnowledgeDraftDto } },
  // architecture imports
  'POST /api/v1/projects/:pid/architecture-imports': { tag: 'projects', summary: '导入架构资料（202）：AI 提取服务与连接补全拓扑（来源“架构资料导入”、可信程度“推断”），并生成项目系统架构 skill 草稿', body: B.PostProjectsPidArchitectureImportsBody, response: ok(C.ArchitectureImportDto, 202) },
  'GET /api/v1/projects/:pid/architecture-imports': { tag: 'projects', summary: '最近的架构资料导入', response: ok(A(C.ArchitectureImportDto)) },
  'GET /api/v1/projects/:pid/architecture-imports/:iid': { tag: 'projects', summary: '一次导入的状态与结果（新增节点 / 连接 / 服务名映射、跳过项、知识草稿）', response: ok(C.ArchitectureImportDto) },
  // connector packs
  'GET /api/v1/connector-packs': { tag: 'connectors', summary: '连接器包列表（有效性、操作与读写、脚本、密钥）', response: ok(A(C.ConnectorPackDto)) },
  'GET /api/v1/connector-packs/examples': { tag: 'connectors', summary: '内置示例连接器包', response: ok(A(C.ConnectorPackDto)) },
  'POST /api/v1/connector-packs/examples/:name/install': { tag: 'connectors', summary: '安装示例连接器包到数据目录（不覆盖已有）', response: ok(C.ConnectorPackDto, 201) },
  'GET /api/v1/connector-packs/:name': { tag: 'connectors', summary: '连接器包详情与全部文件（含脚本内容，供确认前审阅）', response: ok(Type.Object({ ...C.ConnectorPackDto.properties, files: A(C.ConnectorPackFileDto) }, { additionalProperties: false })) },
  'PUT /api/v1/connector-packs/:name/files/*': { tag: 'connectors', summary: '编辑连接器包文件（内容哈希并发；改动后使用它的连接器需重新测试，脚本改动需重新确认）', body: B.PutConnectorPackFileBody, response: ok(C.ConnectorPackDto) },
  'DELETE /api/v1/connector-packs/:name': { tag: 'connectors', summary: '删除连接器包（被连接器使用时拒绝）', response: none },
  'GET /api/v1/connector-pack-drafts': { tag: 'connectors', summary: '待审核的连接器包草稿（AI 从 OpenAPI 生成）', response: ok(A(C.ConnectorPackDraftDto)) },
  'POST /api/v1/connector-pack-drafts': { tag: 'connectors', summary: '由 AI 从 OpenAPI 文档生成连接器包草稿（202；只含声明式操作，不写脚本）', body: B.PostConnectorPackDraftsBody, response: ok(C.ConnectorPackDraftDto, 202) },
  'GET /api/v1/connector-pack-drafts/:id': { tag: 'connectors', summary: '草稿详情与文件', response: ok(Type.Object({ ...C.ConnectorPackDraftDto.properties, files: A(C.ConnectorPackFileDto) }, { additionalProperties: false })) },
  'POST /api/v1/connector-pack-drafts/:id/approve': { tag: 'connectors', summary: '审核通过：草稿成为连接器包（必须有效，不覆盖已有）', response: ok(C.ConnectorPackDto) },
  'POST /api/v1/connector-pack-drafts/:id/reject': { tag: 'connectors', summary: '驳回草稿', response: none },
  // connectors
  'GET /api/v1/connectors': { tag: 'connectors', summary: '连接器列表（不返回凭证，只显示引用的密钥是否已配置）', response: ok(A(C.ConnectorDto)) },
  'GET /api/v1/connector-imports': { tag: 'connectors', summary: '本机其他工具（Cursor、Claude Code、Claude Desktop、Gemini CLI、Windsurf）中已配置的 MCP 服务；凭证只显示掩码', response: ok(A(C.McpImportCandidateDto)) },
  'POST /api/v1/connector-imports': { tag: 'connectors', summary: '把一个已配置的 MCP 服务导入为连接器：凭证按选择复制到本机密钥、留空待填或去掉该参数；之后照常确认命令与测试', body: B.PostConnectorImportsBody, response: ok(C.ConnectorDto, 201) },
  'POST /api/v1/connectors': { tag: 'connectors', summary: '添加 MCP 连接器（stdio / streamable HTTP）；凭证写作 ${secret:name}', body: B.PostConnectorsBody, response: ok(C.ConnectorDto, 201) },
  'GET /api/v1/connectors/:id': { tag: 'connectors', summary: '连接器详情：状态、命令行、工具与只读标注、最近测试、熔断状态', response: ok(C.ConnectorDto) },
  'PATCH /api/v1/connectors/:id': { tag: 'connectors', summary: '修改配置（改动后需重新测试）、写入密钥（只写）、选择向 Agent 开放的只读工具、启用 / 停用', body: B.PatchConnectorsIdBody, response: ok(C.ConnectorDto) },
  'DELETE /api/v1/connectors/:id': { tag: 'connectors', summary: '删除连接器及其密钥', response: none },
  'POST /api/v1/connectors/:id/confirm-command': { tag: 'connectors', summary: '确认 stdio 连接器的完整命令行（提交界面显示的 commandHash；命令变化后需重新确认）', body: B.PostConnectorsIdConfirmCommandBody, response: ok(C.ConnectorDto) },
  'POST /api/v1/connectors/:id/test': { tag: 'connectors', summary: '连通性测试：initialize + tools/list，不调用任何工具', response: ok(C.ConnectorDto) },
  'POST /api/v1/connectors/:id/query': { tag: 'connectors', summary: '用户发起的只读查询（只允许只读标注的工具）；结果为未核实的外部数据，附疑似注入提示', body: B.PostConnectorsIdQueryBody, response: ok(C.ConnectorQueryResultDto) },
  'GET /api/v1/projects/:pid/connectors': { tag: 'connectors', summary: '项目绑定的上下文连接器（含全局绑定）；审计默认授权这些连接器', response: ok(A(C.ProjectConnectorDto)) },
  'PUT /api/v1/projects/:pid/connectors': { tag: 'connectors', summary: '设置本项目绑定的上下文连接器', body: B.PutProjectsPidConnectorsBody, response: ok(A(C.ProjectConnectorDto)) },
  'GET /api/v1/connector-writes': { tag: 'connectors', summary: '待批准的连接器调用（参数或会话带有被审代码中的疑似注入指令）：可按状态筛选 pending / executed / failed / rejected', response: ok(A(C.ConnectorWriteDto)) },
  'POST /api/v1/connector-writes/:id/approve': { tag: 'connectors', summary: '批准一次被暂停的调用：连接器须可用且启用，随即执行并记录结果', body: B.PostConnectorWritesIdDecisionBody, response: ok(C.ConnectorWriteDto) },
  'POST /api/v1/connector-writes/:id/reject': { tag: 'connectors', summary: '拒绝一次被暂停的调用（不执行）', body: B.PostConnectorWritesIdDecisionBody, response: ok(C.ConnectorWriteDto) },
  'GET /api/v1/connectors/:id/calls': { tag: 'connectors', summary: '最近 50 次调用记录（操作、状态、耗时、大小；不含内容）', response: ok(A(C.ConnectorCallDto)) },
  'GET /api/v1/projects/:pid/push-guides': { tag: 'connectors', summary: '本项目可用的推送指引（全局 + 项目知识中的“推送指引”类），附目标连接器是否可写', response: ok(A(C.PushGuideDto)) },
  'POST /api/v1/projects/:pid/pushes': { tag: 'connectors', summary: '按推送指引推送漏洞：有模板则确定性渲染，否则对话模型填参数；默认直接执行，指引要求确认或疑似注入时返回待确认预览', body: B.PostProjectsPidPushesBody, response: ok(C.PushDto) },
  'POST /api/v1/pushes/:id/confirm': { tag: 'connectors', summary: '确认执行预览（令牌一次性、绑定预览内容、5 分钟有效）', body: B.PostPushesIdConfirmBody, response: ok(C.PushDto) },
  'DELETE /api/v1/pushes/:id': { tag: 'connectors', summary: '放弃待确认的推送预览', response: none },
  'GET /api/v1/vulnerabilities/:vid/sync': { tag: 'connectors', summary: '漏洞在外部系统中的对应记录（工单号、链接）', response: ok(A(C.SyncRecordDto)) },
  'PUT /api/v1/vulnerabilities/:vid/sync': { tag: 'vulnerabilities', summary: '关联已有外部记录（手工建的工单，或推送结果里没有可识别 ID 时）：之后推送该漏洞会更新这条记录', body: B.PutVulnerabilitiesVidSyncBody, response: ok(A(C.SyncRecordDto)) },
  'PUT /api/v1/knowledge/global-overrides/:name': { tag: 'knowledge', summary: '全局下线或恢复某条全局 skill（对所有项目生效）', body: B.PutKnowledgeOverrideBody, response: ok(C.KnowledgeOverrideDto) },
  // risk hunts
  'POST /api/v1/hunt-bases': { tag: 'hunts', summary: '由 skill、Prompt 或 1Day/CVE 文本生成排查依据草稿（AI 整理，202；链接不会被访问）', body: B.PostHuntBasesBody, response: ok(Type.Object({ basisId: Type.String() }, { additionalProperties: false }), 202) },
  'GET /api/v1/hunt-bases/:bid': { tag: 'hunts', summary: '排查依据（草稿状态、整理结果）', response: ok(C.HuntBasisDto) },
  'PATCH /api/v1/hunt-bases/:bid': { tag: 'hunts', summary: '用户修订排查依据（If-Match 或 revision）', body: B.PatchHuntBasesBidBody, response: ok(C.HuntBasisDto) },
  'POST /api/v1/hunt-bases/:bid/save-as-skill': { tag: 'hunts', summary: '依据存为全局 skill（漏洞案例或审计方法）：生成知识草稿，审核后启用', body: B.PostHuntBasesBidSaveAsSkillBody, response: ok(Type.Object({ name: Type.String(), draftId: Type.String() }, { additionalProperties: false })) },
  'GET /api/v1/hunts': { tag: 'hunts', summary: '排查记录列表', response: ok(A(C.HuntDto)) },
  'POST /api/v1/hunts': { tag: 'hunts', summary: '创建排查计划（项目或全部项目）', body: B.PostHuntsBody, response: ok(C.HuntDto, 201) },
  'GET /api/v1/hunts/:hid': { tag: 'hunts', summary: '排查详情：依据、计划、汇总', response: ok(C.HuntDto) },
  'PATCH /api/v1/hunts/:hid': { tag: 'hunts', summary: '重命名排查', body: B.PatchHuntsHidBody, response: ok(C.HuntDto) },
  'DELETE /api/v1/hunts/:hid': { tag: 'hunts', summary: '删除排查记录与各仓库结论；各项目的排查审计与已转为漏洞的命中保留（进行中不可删）', response: none },
  'POST /api/v1/hunts/:hid/confirm': { tag: 'hunts', summary: '确认启动（幂等）：每个项目一条风险排查审计', response: ok(C.HuntDto) },
  'GET /api/v1/hunts/:hid/results': { tag: 'hunts', summary: '各仓库结论（不受影响带依据）与命中位置', query: Q.HuntResultsQuery, response: ok(C.HuntResultsDto) },
  'POST /api/v1/hunts/:hid/rerun': { tag: 'hunts', summary: '同依据、同范围重新排查（结束后与上一次对比）', response: ok(C.HuntDto, 201) },
  'GET /api/v1/hunts/:hid/compare': { tag: 'hunts', summary: '与另一次排查对比：新增受影响、已消除', query: Q.HuntCompareQuery, response: ok(C.HuntCompareDto) },
  'GET /api/v1/hunts/:hid/export': { tag: 'hunts', summary: '导出排查报告（多项目汇总 + 各项目明细）', query: Q.HuntExportQuery, produces: ['text/markdown', 'text/html', 'application/json'] },
  'POST /api/v1/hunt-hits/:hitId/promote': { tag: 'hunts', summary: '命中位置转为漏洞（按同一漏洞规则去重）', response: ok(Type.Object({ vulnId: Type.String(), displayNo: Type.Integer(), created: Type.Boolean() }, { additionalProperties: false })) },
  'PATCH /api/v1/hunt-targets/:tid': { tag: 'hunts', summary: '人工改判某仓库的排查结论（必须写理由）', body: B.PatchHuntTargetsTidBody, response: ok(Type.Object({ ok: Type.Boolean() }, { additionalProperties: false })) },
  // projects & repositories
  'GET /api/v1/projects': { tag: 'projects', summary: '项目列表（含未处理漏洞概况）', response: ok(A(C.ProjectDto)) },
  'POST /api/v1/projects': { tag: 'projects', summary: '新建项目', body: B.PostProjectsBody, response: ok(C.ProjectDto, 201) },
  'GET /api/v1/projects/:pid': { tag: 'projects', summary: '项目详情', response: ok(C.ProjectDto) },
  'PATCH /api/v1/projects/:pid': { tag: 'projects', summary: '重命名、归档、内部信任设置（internalTrust，null 为按拓扑推断）', body: B.PatchProjectsPidBody, response: ok(C.ProjectDto) },
  'DELETE /api/v1/projects/:pid': { tag: 'projects', summary: '删除项目（confirmName 必须等于项目名）', query: Q.DeleteProjectQuery, response: none },
  'POST /api/v1/directory-picks': { tag: 'projects', summary: '在服务所在机器上打开系统的目录选择窗口，返回选中的绝对路径（取消 / 不可用时说明原因；同时只能开一个）', response: ok(C.DirectoryPickDto) },
  'POST /api/v1/repo-probes': { tag: 'projects', summary: '添加前探测来源（本地目录 / Git 地址 / 已上传压缩包）：可达性、Git 信息、语言、是否可审计', body: B.PostRepoProbesBody, response: ok(C.RepoProbeDto) },
  'POST /api/v1/uploads': {
    tag: 'projects', summary: '上传压缩包（zip / tar / tar.gz，≤ 2 GB）到暂存区，24 小时后清理', query: Q.UploadQuery, response: ok(C.UploadDto, 201),
    description: '请求体为文件原始字节，Content-Type: application/octet-stream。',
  },
  'POST /api/v1/projects/:pid/analyze': { tag: 'projects', summary: '手动触发 AI 仓库分析（语言、模块、是否可审计、角色；轻量模型，按内容缓存）', response: ok(Type.Object({ analysisId: Type.String() }, { additionalProperties: false }), 202) },
  'GET /api/v1/projects/:pid/analysis': { tag: 'projects', summary: '最近一次仓库分析的状态与每个仓库的结果（角色、证据、信号摘要）', response: ok(C.ProjectAnalysisDto) },
  'GET /api/v1/projects/:pid/topology': { tag: 'projects', summary: '系统拓扑：节点、连接（类型、协议、来源、可信程度、证据）；ETag 为拓扑修订号', response: ok(C.TopologyDto) },
  'PATCH /api/v1/projects/:pid/topology': { tag: 'projects', summary: '用户增删连接与项目外服务（If-Match 或 revision）；删除 AI 连接会被记住，重新分析不恢复', body: B.PatchProjectsPidTopologyBody, response: ok(C.TopologyDto) },
  'GET /api/v1/projects/:pid/repos': { tag: 'projects', summary: '仓库列表', response: ok(A(C.RepoDto)) },
  'POST /api/v1/projects/:pid/repos': { tag: 'projects', summary: '批量添加仓库（逐条结果；全部失败时 422）', body: B.PostProjectsPidReposBody, response: { 201: C.AddReposResult, 422: C.AddReposResult } },
  'GET /api/v1/repos/:rid': { tag: 'projects', summary: '仓库详情', response: ok(C.RepoDto) },
  'PATCH /api/v1/repos/:rid': { tag: 'projects', summary: '修改默认审计版本、角色（role=auto 取消人工修正，回到最近一次 AI 结论）、可审计 / 仅当做上下文（auditable=true|false；auto 回到自动判定）', body: B.PatchReposRidBody, response: ok(C.RepoDto) },
  'DELETE /api/v1/repos/:rid': { tag: 'projects', summary: '移除仓库（不影响已完成审计）', response: none },
  'GET /api/v1/repos/:rid/refs': { tag: 'projects', summary: '分支、标签、最近提交', query: Q.RefsQuery, response: ok(A(C.RefDto)) },
  // audits
  'POST /api/v1/audit-plans': { tag: 'audits', summary: '生成审计计划草稿（后台，202；支持 Idempotency-Key）', body: B.PostAuditPlansBody, response: ok(C.PlanCreated, 202) },
  'GET /api/v1/audit-plans/:id': { tag: 'audits', summary: '查看计划与冻结前策略（ETag）', response: ok(C.PlanDto) },
  'PATCH /api/v1/audit-plans/:id': { tag: 'audits', summary: '编辑策略覆盖项（If-Match）', body: B.PatchAuditPlansIdBody, response: ok(C.PlanDto) },
  'POST /api/v1/audit-plans/:id/confirm': { tag: 'audits', summary: '确认启动：冻结策略并入队（幂等）', response: ok(C.AuditDetailDto) },
  'GET /api/v1/audits': { tag: 'audits', summary: '审计列表', query: Q.AuditsQuery, response: ok(C.PageOf(C.AuditSummaryDto)) },
  'GET /api/v1/audits/:aid': { tag: 'audits', summary: '审计详情：状态、阶段、预算、步骤、闸门', response: ok(C.AuditDetailDto) },
  'POST /api/v1/audits/:aid/cancel': { tag: 'audits', summary: '取消', response: ok(C.AuditDetailDto) },
  'POST /api/v1/audits/:aid/pause': { tag: 'audits', summary: '暂停（steer 收尾，宽限期后中止）', response: ok(C.AuditDetailDto) },
  'POST /api/v1/audits/:aid/resume': { tag: 'audits', summary: '继续（已暂停、已中断）；restartFiltered 时被内容过滤拦截的步骤从头开始；switchModel 时这些步骤改用所选模型重试', body: B.PostAuditsAidResumeBody, response: ok(C.AuditDetailDto) },
  'POST /api/v1/audits/:aid/budget-grants': { tag: 'audits', summary: '追加预算（幂等）；liftStageQuotas 取消本次审计的阶段额度，之后只受总预算限制', body: B.PostAuditsAidBudgetGrantsBody, response: ok(C.AuditDetailDto) },
  'POST /api/v1/audits/:aid/budget-grants/decline': { tag: 'audits', summary: '拒绝追加，以已有结果收尾', response: ok(C.AuditDetailDto) },
  'POST /api/v1/audits/:aid/rerun': { tag: 'audits', summary: '以原配置新建审计：保留场景、版本、策略与增量基线或复验目标（202）', response: ok(C.PlanCreated, 202) },
  'GET /api/v1/audits/:aid/compare': { tag: 'audits', summary: '两次审计对比：新增、消失、变化的漏洞', query: Q.CompareQuery, response: ok(C.AuditCompareDto) },
  'GET /api/v1/audits/:aid/questions': { tag: 'interaction', summary: 'Agent 提问列表', response: ok(A(C.QuestionDto)) },
  'POST /api/v1/questions/:qid/answer': { tag: 'interaction', summary: '回答提问（运行中注入会话，否则写入认知状态）', body: B.PostQuestionsQidAnswerBody, response: ok(C.AnswerResult) },
  'POST /api/v1/questions/:qid/dismiss': { tag: 'interaction', summary: '忽略提问', response: ok(C.QuestionDto) },
  'POST /api/v1/audits/:aid/interventions': { tag: 'interaction', summary: '用户介入：补充、调整重点、跳过、深入分析', body: B.PostAuditsAidInterventionsBody, response: ok(C.InterventionResult) },
  'GET /api/v1/audits/:aid/steps': { tag: 'audits', summary: '步骤列表', response: ok(A(C.StepDto)) },
  'POST /api/v1/audits/:aid/concurrency': { tag: 'audits', summary: '调整本次审计的并发会话数（1 至全局模型请求上限）：写入审计策略，对运行中的审计立即生效（不打断进行中的会话），记入轨迹', body: B.PostAuditConcurrencyBody, response: ok(Type.Object({ from: Type.Integer(), to: Type.Integer(), live: Type.Boolean() }, { additionalProperties: false })) },
  'GET /api/v1/audits/:aid/execution': { tag: 'audits', summary: '执行概览：按阶段的步骤、候选与逐项进度、Agent 会话（含子 Agent）与等待原因、并发占用', response: ok(C.ExecutionDto) },
  'GET /api/v1/audits/:aid/trajectory': { tag: 'audits', summary: '行为轨迹', query: Q.TrajectoryQuery, response: ok(C.TrajectoryPage) },
  'GET /api/v1/audits/:aid/usage': { tag: 'audits', summary: '用量与成本', query: Q.UsageQuery, response: ok(A(C.UsageRow)) },
  'GET /api/v1/audits/:aid/events': {
    tag: 'streams', summary: '审计事件 SSE（Last-Event-ID / after 续传；Accept: application/json 时为轮询）', query: Q.EventsQuery,
    response: ok(C.EventPoll), produces: ['text/event-stream', 'application/json'],
  },
  // Conversations
  'GET /api/v1/conversations': { tag: 'conversations', summary: '会话列表（最近 / 已归档；可按内容搜索、按引用对象筛选）', query: Q.ConversationsQuery, response: ok(A(C.ConversationDto)) },
  'POST /api/v1/conversations': { tag: 'conversations', summary: '新建会话（可带初始 @ 引用，如从漏洞详情“AI 追问”）', body: B.PostConversationsBody, response: ok(C.ConversationDto, 201) },
  'POST /api/v1/audits/:aid/conversation': { tag: 'conversations', summary: '审计绑定的会话：发起它的会话，没有就新建一条引用该审计的会话', response: ok(C.ConversationDto) },
  'GET /api/v1/conversations/:cid': { tag: 'conversations', summary: '会话详情', response: ok(C.ConversationDto) },
  'PATCH /api/v1/conversations/:cid': { tag: 'conversations', summary: '重命名 / 归档 / 置顶 / 切换模型（null 恢复为设置中的对话模型）', body: B.PatchConversationBody, response: ok(C.ConversationDto) },
  'DELETE /api/v1/conversations/:cid': { tag: 'conversations', summary: '删除会话（其消息与卡片一并删除；待处理的 AI 建议记为驳回）', response: none },
  'GET /api/v1/conversations/:cid/messages': { tag: 'conversations', summary: '历史消息（按 seq 游标分页，新消息在后）', query: Q.MessagesQuery, response: ok(C.MessagePageDto) },
  'POST /api/v1/conversations/:cid/messages': { tag: 'conversations', summary: '发送消息（幂等 key = clientMessageId），立即返回用户消息与助手消息 ID；随后读取回复流', body: B.PostMessagesBody, response: ok(C.PostMessageResultDto, 202) },
  'GET /api/v1/messages/:mid': { tag: 'conversations', summary: '单条消息（含工具调用与卡片）', response: ok(C.MessageDto) },
  'GET /api/v1/messages/:mid/stream': {
    tag: 'streams', summary: '助手回复 SSE：message_start / delta / tool_call / card / done / error，按 seq 续传；已结束的回复一次补发后发送 end', query: Q.MessageStreamQuery,
    produces: ['text/event-stream', 'application/json'],
  },
  'POST /api/v1/messages/:mid/stop': { tag: 'conversations', summary: '停止生成（保留已生成的部分）', response: none },
  'POST /api/v1/messages/:mid/edit': { tag: 'conversations', summary: '编辑最后一条用户消息并重新回复（回复中已应用过卡片时拒绝）', body: B.EditMessageBody, response: ok(Type.Object({ userMessageId: Type.String(), assistantMessageId: Type.String() }, { additionalProperties: false }), 202) },
  'POST /api/v1/messages/:mid/regenerate': { tag: 'conversations', summary: '重新生成：对同一条用户消息再回复一次', response: ok(Type.Object({ assistantMessageId: Type.String() }, { additionalProperties: false }), 202) },
  'POST /api/v1/cards/:cardId/apply': { tag: 'conversations', summary: '应用卡片：建议修订 / 合并 / 拆分（If-Match 为目标漏洞 revision）、生成审计 / 复验计划、创建排查依据、创建连接器草稿', body: B.PostCardApplyBody, response: ok(C.CardDto) },
  'POST /api/v1/cards/:cardId/dismiss': { tag: 'conversations', summary: '驳回卡片（建议修订记为 rejected）', response: ok(C.CardDto) },
  'GET /api/v1/mention-candidates': { tag: 'conversations', summary: '@ 引用候选（项目、仓库、审计、漏洞、知识）', query: Q.MentionCandidatesQuery, response: ok(A(C.MentionCandidateDto)) },
  'GET /api/v1/events': { tag: 'streams', summary: '全局通知 SSE（状态变化、提问）', produces: ['text/event-stream'] },
  'GET /api/v1/audits/:aid/findings': { tag: 'results', summary: '本次发现', query: Q.FindingsQuery, response: ok(A(C.FindingDto)) },
  'GET /api/v1/audits/:aid/coverage': { tag: 'results', summary: '按仓库的覆盖汇总', response: ok(C.CoverageDto) },
  'GET /api/v1/audits/:aid/hypotheses': { tag: 'results', summary: '风险假设：审查中提出的未排除 / 已反驳假设与威胁建模的风险假设及其验证结论（含追加执行）', query: Q.HypothesesQuery, response: ok(C.HypothesisList) },
  'POST /api/v1/audits/:aid/hypotheses': { tag: 'results', summary: '补充风险假设：加入本次审计的清单，状态为未验证；审计尚未到覆盖补齐环节时由本次验证，否则可追加执行验证', body: B.PostAuditsAidHypothesesBody, response: ok(C.HypothesisDto, 201) },
  'POST /api/v1/hypotheses/:hid/decision': { tag: 'results', summary: '处理假设：未排除的可转为漏洞（待确认）或排除；尚未验证的只能排除', body: B.PostHypothesesHidDecisionBody, response: ok(C.HypothesisDecisionResult) },
  // Requirement threat models
  'GET /api/v1/projects/:pid/threat-models': { tag: 'threat-models', summary: '项目的需求威胁模型列表（新的在前）：状态、来源数、各风险状态计数、来源是否在生成后变化', response: ok(Type.Object({ items: A(C.ThreatModelSummaryDto) })) },
  'POST /api/v1/projects/:pid/threat-models': { tag: 'threat-models', summary: '新建需求威胁模型（草稿）', body: B.PostThreatModelBody, response: ok(C.ThreatModelDto, 201) },
  'GET /api/v1/threat-models/:tid': { tag: 'threat-models', summary: '威胁模型详情：来源、功能澄清、风险（含研判历史）', response: ok(C.ThreatModelDto) },
  'PATCH /api/v1/threat-models/:tid': { tag: 'threat-models', summary: '改标题；确认 / 取消确认功能澄清（需要已生成澄清）', body: B.PatchThreatModelBody, response: ok(C.ThreatModelDto) },
  'DELETE /api/v1/threat-models/:tid': { tag: 'threat-models', summary: '删除威胁模型及其来源与风险（生成中不可删；已冻结进审计的产物保留）', response: none },
  'POST /api/v1/threat-models/:tid/sources': { tag: 'threat-models', summary: '追加一条输入来源：上传文档（浏览器读取后以文本提交，Markdown / 纯文本）、文字描述或在线文档（连接器 + 文档链接或 ID）；单条 ≤ 256 KB，数量不限', body: B.PostThreatSourceBody, response: ok(C.ThreatSourceDto, 201) },
  'PATCH /api/v1/threat-model-sources/:sid': { tag: 'threat-models', summary: '修改来源：标题、备注、文字来源的文字、在线来源的连接器或文档；injectionAck 表示人已查看注入信号', body: B.PatchThreatSourceBody, response: ok(C.ThreatSourceDto) },
  'DELETE /api/v1/threat-model-sources/:sid': { tag: 'threat-models', summary: '删除来源（S 编号不复用）', response: none },
  'GET /api/v1/threat-model-sources/:sid/content': { tag: 'threat-models', summary: '来源正文（上传、文字或在线文档取回的副本，已脱敏）', response: ok(Type.Object({ text: Type.String() })) },
  'PUT /api/v1/threat-models/:tid/source-order': { tag: 'threat-models', summary: '来源显示顺序：ids 必须列出全部来源各一次', body: B.PutThreatSourceOrderBody, response: ok(Type.Object({ items: A(C.ThreatSourceDto) })) },
  'POST /api/v1/threat-models/:tid/generate': { tag: 'threat-models', summary: '生成或重新生成（202，后台运行）：读取来源、在线文档经连接器只读取回，提交澄清与风险；已研判的风险保留状态；生成中返回 409；有未查看的注入信号时返回 400', body: B.PostThreatGenerateBody, response: ok(C.ThreatModelDto, 202) },
  'PATCH /api/v1/threat-risks/:rid': { tag: 'threat-models', summary: '研判一条风险：待研判 / 需规避 / 已规避 / 接受风险 / 误报·不适用；除待研判外必须有理由', body: B.PatchThreatRiskBody, response: ok(C.ThreatRiskDto) },
  'PATCH /api/v1/threat-models/:tid/risks': { tag: 'threat-models', summary: '批量研判同一威胁模型的风险（全部成功或全部不改）', body: B.PatchThreatRisksBody, response: ok(Type.Object({ results: A(Type.Object({ id: Type.String(), changed: Type.Boolean() })), threatModel: C.ThreatModelDto })) },
  'GET /api/v1/threat-models/:tid/export': { tag: 'threat-models', summary: '导出 Markdown 报告（按当前研判状态渲染）', produces: ['text/markdown'] },
  'GET /api/v1/projects/:pid/threat-sync-guides': { tag: 'threat-models', summary: '威胁模型的同步指引（推送指引中 push.target 为 threat_model 的），附目标连接器是否可写', response: ok(A(C.PushGuideDto)) },
  'POST /api/v1/threat-models/:tid/sync': { tag: 'threat-models', summary: '同步到在线文档：按同步指引生成操作参数（有模板则确定性渲染，否则对话模型填写），返回待确认预览；报告未变化时跳过，已同步过时更新同一份文档', body: B.PostThreatSyncBody, response: ok(C.ThreatSyncDto) },
  'POST /api/v1/threat-syncs/:id/confirm': { tag: 'threat-models', summary: '确认执行同步预览（令牌一次性、绑定预览内容、5 分钟有效）', body: B.PostThreatSyncConfirmBody, response: ok(C.ThreatSyncDto) },
  'DELETE /api/v1/threat-syncs/:id': { tag: 'threat-models', summary: '放弃待确认的同步预览', response: none },
  'GET /api/v1/audits/:aid/domain-plan': { tag: 'results', summary: '领域规划：多领域专家狩猎的风险领域、审计员的修改与每个领域已运行的专家轮次', response: ok(C.DomainPlanDto) },
  'POST /api/v1/audits/:aid/domain-plan/edits': { tag: 'results', summary: '修改领域规划（不阻塞审计）：新增领域（专家阶段结束后新增的在审计结束后追加执行）、删除未开始的领域、给领域补充关注点（从下一轮起生效）', body: B.PostAuditsAidDomainPlanEditsBody, response: ok(C.DomainPlanDto) },
  'POST /api/v1/audits/:aid/supplements': { tag: 'results', summary: '追加执行：对已结束的全量 / 增量审计追加按入口的逻辑审查或风险假设先行（可只验证尚未验证的假设），同一快照，直接开始（202，幂等）', body: B.PostAuditsAidSupplementsBody, response: ok(C.PlanCreated, 202) },
  'GET /api/v1/audits/:aid/knowledge-usage': { tag: 'results', summary: '本次审计用到的知识：每条 skill 的最高加载级别、次数、步骤、tokens、被结论引用次数；知识 token 与引用率（G9）', response: ok(C.KnowledgeUsageDto) },
  'GET /api/v1/audits/:aid/coverage/items': { tag: 'results', summary: '覆盖明细', query: Q.CoverageItemsQuery, response: ok(A(C.CoverageItemDto)) },
  'GET /api/v1/audits/:aid/coverage/uncovered': { tag: 'results', summary: '未覆盖项清单（未读到、已读未结论、解析缺口）', query: Q.UncoveredQuery, response: ok(A(C.CoverageItemDto)) },
  'POST /api/v1/audits/:aid/coverage/backfills': { tag: 'results', summary: '一键补审：以原快照为选中的（或全部）未覆盖项创建范围受限的补审审计并直接开始（202，幂等）', body: B.PostAuditsAidCoverageBackfillsBody, response: ok(C.PlanCreated, 202) },
  'GET /api/v1/audits/:aid/repos/:rid/tree': { tag: 'results', summary: '按审计快照 manifest 列目录', query: Q.TreeQuery, response: ok(A(C.TreeEntryDto)) },
  'GET /api/v1/audits/:aid/repos/:rid/source': { tag: 'results', summary: '按审计快照读取文件片段（只接受 manifest 内路径）', query: Q.SourceQuery, response: ok(C.SourceDto) },
  'POST /api/v1/exports': { tag: 'exports', summary: '导出 md/html/json/sarif（202，幂等）；`mode: ai` 由报告模型按报告 skill 在后台写 md/html，生成后校验（状态 running → succeeded / failed）', body: B.PostExportsBody, response: ok(C.ExportDto, 202) },
  'GET /api/v1/exports/:eid': { tag: 'exports', summary: '导出状态', response: ok(C.ExportDto) },
  'GET /api/v1/exports/:eid/download': { tag: 'exports', summary: '下载导出文件（附件）', produces: ['text/markdown', 'text/html', 'application/json', 'application/sarif+json'] },
  'GET /api/v1/audits/:aid/exports': { tag: 'exports', summary: '该审计的历史导出', response: ok(A(C.ExportDto)) },
  'GET /api/v1/audits/:aid/ai-report': { tag: 'exports', summary: 'AI 报告的默认模型（报告阶段或跟随深入审计）、备用模型与 token 预估', query: Q.AiReportDefaultsQuery, response: ok(C.AiReportDefaultsDto) },
  'GET /api/v1/exports/:eid/preview': { tag: 'exports', summary: 'AI 报告的 Markdown 正文（预览用，已脱敏）', response: ok(C.ExportPreviewDto) },
  'GET /api/v1/inbox': { tag: 'home', summary: '待我处理', response: ok(C.InboxDto) },
  'GET /api/v1/dashboard': { tag: 'home', summary: '首页：待办、进行中、项目风险概况', response: ok(C.DashboardDto) },
  // vulnerabilities
  'GET /api/v1/projects/:pid/vulnerabilities': {
    tag: 'vulnerabilities', summary: '项目漏洞清单', query: Q.VulnsQuery,
    response: ok(C.PageOf(C.VulnSummaryDto)),
  },
  'GET /api/v1/vulnerabilities/:vid': { tag: 'vulnerabilities', summary: '漏洞详情四层（ETag）', response: ok(C.VulnDetailDto) },
  'PATCH /api/v1/vulnerabilities/:vid': { tag: 'vulnerabilities', summary: '人工复核（If-Match 或 body.revision）', body: B.PatchVulnerabilitiesVidBody, response: ok(C.VulnDetailDto) },
  'POST /api/v1/vulnerabilities/:vid/match-decision': { tag: 'vulnerabilities', summary: '“疑似同一”确认或拆开（If-Match 或 body.revision）', body: B.PostVulnerabilitiesVidMatchDecisionBody, response: ok(C.MatchDecisionResult) },
  'POST /api/v1/vulnerabilities/merge': { tag: 'vulnerabilities', summary: '合并：sourceIds 并入 targetId（If-Match 或 body.revision 为目标漏洞）', body: B.PostVulnerabilitiesMergeBody, response: ok(C.VulnDetailDto) },
  'POST /api/v1/vulnerabilities/:vid/split': { tag: 'vulnerabilities', summary: '拆分：把选中的入口和指纹移到新漏洞（If-Match 或 body.revision）', body: B.PostVulnerabilitiesVidSplitBody, response: ok(C.SplitResult) },
  'POST /api/v1/vulnerabilities/:vid/identity-undo': { tag: 'vulnerabilities', summary: '撤销合并或拆分（仅限仍是最近一次身份变更时）', body: B.PostVulnerabilitiesVidIdentityUndoBody, response: ok(C.VulnDetailDto) },
  'POST /api/v1/reverifications': { tag: 'vulnerabilities', summary: '复验（单条与批量同一入口；创建 reverify 审计并直接开始，202，支持 Idempotency-Key）', body: B.PostReverificationsBody, response: ok(C.PlanCreated, 202) },
  'POST /api/v1/vulnerabilities/batch-updates': { tag: 'vulnerabilities', summary: '批量复核：设置处理状态、批量确认或标误报（整批共用一个原因；逐条 revision 校验，单条规则逐条适用，不符合的条目带错误码跳过）', body: B.PostVulnerabilitiesBatchUpdatesBody, response: ok(C.BatchUpdateResult) },
  'GET /api/v1/projects/:pid/review-stats': { tag: 'vulnerabilities', summary: '人工复核耗时（G1）：单条判定与批量判定的次数、中位数与平均值（毫秒），以及人工确认 / 误报次数', response: ok(C.ReviewStatsDto) },
  'GET /api/v1/projects/:pid/export': { tag: 'exports', summary: '项目级导出：项目内全部活跃漏洞（或选中的漏洞），每条取最近一次审计的发现作为位置与详情（同步下载）', query: Q.ProjectExportQuery, produces: ['text/markdown', 'text/html', 'application/json', 'application/sarif+json'] },
  'GET /api/v1/vulnerabilities/:vid/revisions': { tag: 'vulnerabilities', summary: '修订历史', response: ok(A(C.RevisionDto)) },
  'GET /api/v1/vulnerabilities/:vid/trajectory-links': { tag: 'vulnerabilities', summary: '反查产生该漏洞的轨迹片段', response: ok(A(C.TrajectoryLink)) },
};

const ERROR_RESPONSES: Record<string, TSchema> = { '4xx': C.ApiErrorBody, '5xx': C.ApiErrorBody };

/** Fastify route schema for a documented route. */
export function routeSchema(d: RouteDoc): Record<string, unknown> {
  return {
    tags: [d.tag], summary: d.summary,
    ...(d.description ? { description: d.description } : {}),
    ...(d.body ? { body: d.body } : {}),
    ...(d.query ? { querystring: d.query } : {}),
    ...(d.produces ? { produces: d.produces } : {}),
    response: { ...(d.response ?? {}), ...ERROR_RESPONSES },
  };
}

/** Contract schemas published as reusable components (name → schema). */
const COMPONENTS: Record<string, TSchema> = {
  ApiError: C.ApiErrorBody, SessionInfo: C.SessionInfo, HealthInfo: C.HealthInfo, SeverityCounts: C.SeverityCounts, ProjectDto: C.ProjectDto,
  RepoDto: C.RepoDto, RepoProbeDto: C.RepoProbeDto, DirectoryPickDto: C.DirectoryPickDto, RefDto: C.RefDto, UploadDto: C.UploadDto, GitCredentialDto: C.GitCredentialDto, AnalysisDto: C.AnalysisDto, TopologyDto: C.TopologyDto, HuntBasisDto: C.HuntBasisDto, HuntDto: C.HuntDto, HuntResultsDto: C.HuntResultsDto, HuntBasis: C.HuntBasis, TopologyNodeDto: C.TopologyNodeDto, TopologyEdgeDto: C.TopologyEdgeDto, RepoAnalysisDto: C.RepoAnalysisDto, RepoSignals: C.RepoSignals, BudgetDto: C.BudgetDto, AuditSummaryDto: C.AuditSummaryDto, StepDto: C.StepDto,
  GateDto: C.GateDto, AuditDetailDto: C.AuditDetailDto, AuditStrategy: C.AuditStrategy, ModelRef: C.ModelRef, PlanDto: C.PlanDto, QuestionDto: C.QuestionDto,
  EventDto: C.EventDtoSchema, UsageRow: C.UsageRow, CodeLocDto: C.CodeLocDto, FindingDto: C.FindingDto, VulnSummaryDto: C.VulnSummaryDto,
  VulnDetailDto: C.VulnDetailDto, RevisionDto: C.RevisionDto, CoverageDto: C.CoverageDto, CoverageItemDto: C.CoverageItemDto, SourceDto: C.SourceDto,
  TreeEntryDto: C.TreeEntryDto, ExportDto: C.ExportDto, ProviderDto: C.ProviderDto, ModelSettingsDto: C.ModelSettingsDto, SceneDefaultsDto: C.SceneDefaultsDto,
  GeneralSettingsDto: C.GeneralSettingsDto, DoctorCheckDto: C.DoctorCheckDto, DiagnosticsDto: C.DiagnosticsDto, InboxDto: C.InboxDto,
  DashboardDto: C.DashboardDto, SkillDto: C.SkillDto, IncrementalSummaryDto: C.IncrementalSummaryDto, SuspectedMatchDto: C.SuspectedMatchDto, ProposalDto: C.ProposalDto, ReverifyItemDto: C.ReverifyItemDto,
};

/**
 * Replace every inlined occurrence of a component schema with a `$ref` and publish the components.
 * Pure post-processing of the generated document: what the service validates/serializes is unchanged.
 */
export function compactOpenApi<T extends Record<string, unknown>>(doc: T): T {
  const key = (v: unknown) => C.canonicalJson(v);
  // @fastify/swagger rewrites TypeBox records (`patternProperties: {"^.*$": X}`) to `additionalProperties: X`
  // and `const: x` to `enum: [x]`; normalize both sides the same way before matching.
  const norm = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(norm);
    if (!v || typeof v !== 'object') return v;
    const o = { ...(v as Record<string, unknown>) };
    const pp = o.patternProperties as Record<string, unknown> | undefined;
    if (pp && Object.keys(pp).length === 1 && '^.*$' in pp) {
      delete o.patternProperties;
      o.additionalProperties = pp['^.*$'];
    }
    if ('const' in o) {
      o.enum = [o.const];
      delete o.const;
    }
    return Object.fromEntries(Object.entries(o).map(([k, x]) => [k, norm(x)]));
  };
  const plain = (s: TSchema) => norm(JSON.parse(JSON.stringify(s)));
  const byKey = new Map(Object.entries(COMPONENTS).map(([name, s]) => [key(plain(s)), name]));
  const walk = (v: unknown, self?: string): unknown => {
    if (Array.isArray(v)) return v.map((x) => walk(x));
    if (!v || typeof v !== 'object') return v;
    const name = byKey.get(key(v));
    if (name && name !== self) return { $ref: `#/components/schemas/${name}` };
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, walk(x)]));
  };
  const schemas = Object.fromEntries(Object.entries(COMPONENTS).map(([name, s]) => [name, walk(plain(s), name)]));
  const out = walk(doc) as Record<string, unknown>;
  const components = (out.components ?? {}) as Record<string, unknown>;
  return { ...out, components: { ...components, schemas } } as unknown as T;
}
