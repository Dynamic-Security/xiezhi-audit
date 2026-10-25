// What each budget stage and each status-bar segment does (the ⓘ next to it). The step → model / quota / segment
// mapping follows contracts `STEP_ROLES`; keep both in step when a role moves.

export interface StageInfo { does: string; model?: string; quota?: string }

/** Budget stages (contracts `BUDGET_STAGES`): what the quota pays for and where those steps show in the status bar. */
export const BUDGET_INFO: Record<string, { does: string; shows: string }> = {
  prepare: { does: '生成审计计划、仓库画像；增量审计还有影响范围分析。', shows: '生成计划、画像与威胁建模（画像部分）、影响范围' },
  hypotheses: { does: '威胁建模列出风险假设；领域专家没给结论的假设再单独验证一次。', shows: '画像与威胁建模（威胁建模部分）、领域审计里的 HYP 步骤' },
  triage: { does: '给入口与危险点打风险分并排序，超出候选上限的部分声明为覆盖缺口。', shows: '初筛' },
  hunt: { does: '按风险领域派专家并行审计（每位最多 3 轮），提交发现，并给本领域的风险假设下结论。风险排查的定位与研判也计入这里。', shows: '领域审计、定位、研判' },
  gap: { does: '补审专家没覆盖到的候选、按知识库清单核对、复查可疑的“无问题”结论、分诊外部扫描结果。', shows: '领域审计里的 GAP 步骤、外部结果、清单核对、结论复查' },
  merge: { does: '把根因相同的发现合成一条，并与已跟踪的漏洞对号。', shows: '汇总（归并步骤）' },
  explore: { does: '归并之后，每轮从不确定的地方（未判定的假设、模型间冲突、待确认或只有一个模型认定的发现、专家遗留的线索）选一个方向，派一次专门调查；连续 3 轮没有进展就停止。', shows: '深度探索' },
  review: { does: '站在反方为每个正式发现找反证，给出维持、降低置信度或已驳倒。', shows: '对抗复核' },
  verify: { does: '漏洞复验：判断已报漏洞是否已修复、部分修复或仍存在。', shows: '定向复验' },
};

/** Status-bar segments (contracts `EXECUTION_SEGMENTS`; `profile` also stands for the merged 画像与威胁建模). */
export const SEGMENT_INFO: Record<string, StageInfo> = {
  snapshot: { does: '固定本次审计的代码版本，之后的步骤都读这一版。不调用模型。' },
  index: { does: '解析代码，建立符号、调用关系、入口与危险点的结构索引。不调用模型。' },
  plan: { does: '理解项目，生成审计计划：范围、重点与预算。', model: '计划与画像', quota: '计划与画像' },
  profile: { does: '仓库画像（技术栈、入口、信任边界、敏感数据），再做威胁建模、列出风险假设。两个模型相同时在同一个会话里完成。', model: '画像用计划与画像，威胁建模用风险假设', quota: '画像计入计划与画像，威胁建模计入风险假设' },
  scope: { does: '增量审计：从变更文件出发追调用链，找出受影响的入口与危险点。', model: '影响范围', quota: '计划与画像' },
  threat: { does: '威胁建模：结合画像与入口列出风险假设（越权、业务逻辑等）。', model: '风险假设', quota: '风险假设' },
  triage: { does: '给入口与危险点打风险分并排序，决定先审哪些；超出候选上限的部分声明为覆盖缺口。', model: '初筛', quota: '初筛' },
  hunt: { does: '按风险领域派专家并行审计，每位最多 3 轮：读代码、追踪数据路径、提交发现，并给本领域的风险假设下结论。补齐追查（GAP）和假设补验（HYP）也显示在这里。', model: '领域审计（HYP 用风险假设）', quota: '领域审计（GAP 计入覆盖补齐，HYP 计入风险假设）' },
  external: { does: '分诊外部扫描工具的结果，判断是否成立。', model: '领域审计或对抗复核', quota: '覆盖补齐' },
  checklist: { does: '按知识库清单逐类核对是否都审到，没覆盖的条目再补审。', model: '领域审计', quota: '覆盖补齐' },
  recheck: { does: '与索引事实矛盾的“无问题”结论，加上一定比例的抽样，交给独立会话复查；不同意就重开，再补审。', model: '对抗复核', quota: '覆盖补齐' },
  explore: { does: '每轮从不确定的地方选一个方向，派一次专门调查；连续 3 轮没有进展或达到轮数上限就停止。', model: '深度探索', quota: '深度探索' },
  challenge: { does: '站在反方为每个正式发现找反证（防护、不可达、前置条件不满足），给出维持、降低置信度或已驳倒。', model: '对抗复核', quota: '对抗复核' },
  verify: { does: '判断已报漏洞是否已修复、部分修复或仍存在。', model: '复验与风险研判', quota: '复验' },
  locate: { does: '风险排查：找出可能受这个风险影响的代码位置。', model: '复验与风险研判', quota: '领域审计' },
  judge: { does: '风险排查：逐个位置判断是否受影响。', model: '复验与风险研判', quota: '领域审计' },
  finalize: { does: '归并重复发现（用归并模型、计入归并额度），然后发布结果、生成报告并做闸门检查（不调用模型）。' },
};
