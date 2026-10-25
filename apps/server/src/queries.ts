// Query-string schemas. Attached to routes as `querystring`: Fastify validates them
// (no coercion: values stay strings; a repeated key arrives as an array) and openapi.json lists them as
// parameters. Undeclared parameters are rejected, so the document cannot silently fall behind.
import { Type, type TSchema } from 'typebox';
import {
  AUDIT_STATUSES, CONFIRM_STATUSES, COVERAGE_KINDS, COVERAGE_STATUSES, FINDING_STATES, HANDLING_STATUSES, LIFECYCLES, SCENES, SEVERITIES,
  TRAJECTORY_GROUP_NAMES,
} from '@xiezhi/contracts';

const Q = (props: Record<string, TSchema>) => Type.Object(props, { additionalProperties: false });
const Opt = Type.Optional;
const Str = (description: string, max = 500) => Type.String({ maxLength: max, description });
const Digits = (description: string) => Type.String({ pattern: '^[0-9]{1,9}$', description });
const Enum = (values: readonly string[], description: string) => Type.Enum([...values], { type: 'string', description });
/** Repeatable parameter (`?k=a&k=b`): one value or several. */
const Many = (item: TSchema, description: string) => Type.Union([item, Type.Array(item, { maxItems: 50 })], { description });

const limit = Digits('每页条数（1–200）');
const cursor = Str('上一页返回的 nextCursor', 200);

export const DeleteProjectQuery = Q({ confirmName: Str('必须等于项目名（破坏性确认）') });
export const RefsQuery = Q({ kind: Opt(Enum(['branch', 'tag', 'commit'], '版本类型')), q: Opt(Str('名称或提交信息关键字', 200)) });
export const AuditsQuery = Q({
  projectId: Opt(Str('项目 ID', 100)), status: Opt(Many(Enum(AUDIT_STATUSES, '审计状态'), '审计状态，可重复')), scene: Opt(Enum(SCENES, '场景')),
  limit: Opt(limit), cursor: Opt(cursor),
});
export const TrajectoryQuery = Q({
  after: Opt(Digits('只返回 seq 大于它的事件')), type: Opt(Many(Enum(TRAJECTORY_GROUP_NAMES, '事件分组'), '事件分组，可重复；不传时隐藏预算记账等高频事件')),
  step: Opt(Str('步骤 ID', 100)), q: Opt(Str('在事件内容中搜索', 200)), limit: Opt(Digits('条数上限（最多 2000，默认 500）')), all: Opt(Enum(['1'], '为 1 时包含高频记账事件')),
});
export const UsageQuery = Q({ groupBy: Opt(Enum(['step', 'model', 'stage'], '汇总维度（默认 step）')) });
export const EventsQuery = Q({ after: Opt(Digits('从 seq 大于它的事件开始回放；与 Last-Event-ID 取较大值')) });
export const FindingsQuery = Q({
  severity: Opt(Many(Enum(SEVERITIES, '严重度'), '严重度，可重复')),
  state: Opt(Many(Enum(FINDING_STATES, '发现状态'), '发现状态，可重复；默认 canonical 与 insufficient')),
});
export const CoverageItemsQuery = Q({
  kind: Opt(Enum(COVERAGE_KINDS, '入口或危险点')), repo: Opt(Str('仓库名或 ID', 200)), status: Opt(Many(Enum(COVERAGE_STATUSES, '覆盖状态'), '覆盖状态，可重复')),
});
export const UncoveredQuery = Q({ kind: Opt(Enum(COVERAGE_KINDS, '入口或危险点')), repo: Opt(Str('仓库名或 ID', 200)) });
export const CompareQuery = Q({ with: Str('与之对比的（较早的）审计 ID', 100) });
export const TreeQuery = Q({ path: Opt(Str('快照内目录（相对仓库根）', 4096)) });
export const SourceQuery = Q({ path: Str('快照内文件（相对仓库根，仅 manifest 内路径）', 4096), from: Opt(Digits('起始行（默认 1）')), to: Opt(Digits('结束行（默认 from+400，单次最多 2000 行）')) });
export const KnowledgeQuery = Q({ projectId: Opt(Str('同时列出该项目层知识', 100)) });
export const VulnsQuery = Q({
  severity: Opt(Many(Enum(SEVERITIES, '严重度'), '严重度，可重复')),
  confirmation: Opt(Many(Enum(CONFIRM_STATUSES, '确认状态'), '确认状态，可重复')),
  handling: Opt(Many(Enum(HANDLING_STATUSES, '处理状态'), '处理状态，可重复')),
  lifecycle: Opt(Many(Enum(LIFECYCLES, '生命周期'), '生命周期，可重复')),
  category: Opt(Many(Str('漏洞类别', 100), '漏洞类别，可重复')), repo: Opt(Many(Str('仓库名', 200), '仓库，可重复')), source: Opt(Many(Str('来源', 100), '来源，可重复')),
  q: Opt(Str('编号、标题、类别关键字', 200)),
  sort: Opt(Type.String({ pattern: '^-?(severity|confidence|displayNo|updatedAt|category)(,-?(severity|confidence|displayNo|updatedAt|category))*$', description: '排序键，逗号分隔，- 前缀为降序（默认 -severity,displayNo）；confidence 按 低 < 中 < 高' })),
  limit: Opt(limit), cursor: Opt(cursor),
});

export const UploadQuery = Q({ name: Type.String({ minLength: 1, maxLength: 255, description: '原始文件名（仅用于展示与推断仓库名）' }) });
export const HuntResultsQuery = Q({ projectId: Opt(Str('只看某个项目', 60)) });
export const HuntCompareQuery = Q({ with: Str('对比的另一次排查 id', 60) });
/** Project-level export: all active vulnerabilities of the project, or the selected ones. */
/** what the token estimate of an AI report covers. */
export const AiReportDefaultsQuery = Q({
  includePending: Opt(Enum(['0', '1'], '0 表示不含待确认项（默认 1）')),
  snippets: Opt(Enum(['0', '1'], '是否把代码片段交给报告模型（默认按设置）')),
});
export const ProjectExportQuery = Q({
  format: Opt(Enum(['md', 'html', 'json', 'sarif'], '导出格式，默认 md')),
  vulnIds: Opt(Type.Union([Str('漏洞 ID', 64), Type.Array(Str('漏洞 ID', 64), { maxItems: 200 })], { description: '只导出这些漏洞，可重复（最多 200）' })),
  includePending: Opt(Enum(['0', '1'], '0 表示不含待确认项（默认 1）')),
  snippets: Opt(Enum(['0', '1'], 'SARIF 是否含代码片段（默认按设置）')),
  localRoots: Opt(Enum(['0', '1'], 'SARIF 是否写本机绝对根（默认按设置）')),
});
export const HuntExportQuery = Q({ format: Opt(Enum(['md', 'html', 'json'], '导出格式，默认 md')) });
/** DELETE of a skill or sub-file: the content hash the user saw (or If-Match). */
export const DeleteSkillQuery = Q({ baseSha256: Opt(Type.String({ pattern: '^[0-9a-f]{64}$', description: '删除前看到的内容哈希（也可用 If-Match）' })) });
/** DELETE of a model provider: `clearReferences=1` also clears the model settings that name it. */
export const ProviderDeleteQuery = Q({ clearReferences: Opt(Enum(['1'], '同时清除引用该服务的模型配置（默认模型、备用模型、各阶段模型等）')) });
export const KnowledgeDraftsQuery = Q({ projectId: Opt(Str('项目层草稿', 100)), all: Opt(Enum(['1'], '含已启用与已驳回的草稿')) });

// Conversations.
export const ConversationsQuery = Q({
  status: Opt(Enum(['active', 'archived'], '最近（active）或已归档')),
  q: Opt(Str('按标题或消息内容搜索', 200)),
  mention: Opt(Type.String({ pattern: '^(project|repo|audit|vuln|skill):[A-Za-z0-9_]{1,80}$', description: '只列出引用了该对象的会话，形如 vuln:<id>' })),
  limit: Opt(Type.String({ pattern: '^[0-9]{1,3}$', description: '最多返回条数（默认 200）' })),
});
export const MessagesQuery = Q({ before: Opt(Digits('返回 seq 小于它的消息（上一页的 nextCursor）')), limit: Opt(limit) });
export const MessageStreamQuery = Q({ after: Opt(Digits('从 seq 大于它的事件开始（断线续传）')) });
export const MentionCandidatesQuery = Q({
  q: Opt(Str('名称关键字；漏洞可用 V-n', 200)), types: Opt(Str('逗号分隔：project,repo,audit,vuln,skill', 100)),
});
export const HypothesesQuery = Q({
  status: Opt(Many(Enum(['proposed', 'confirmed', 'open', 'refuted', 'converted', 'dismissed'], '假设状态'), '假设状态，可重复；不传时返回全部')),
  origin: Opt(Enum(['hunt', 'threat_model'], '来源：hunt = 审查中提出；threat_model = 风险假设先行的威胁建模')),
});
