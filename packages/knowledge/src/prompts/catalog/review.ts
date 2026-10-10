// Adversarial review, verdict reviews and conclusion recheck (engine/steps/challenge.ts, verdict-review.ts, recheck.ts).
import type { PromptDef } from '../registry.js';

export const REVIEW: PromptDef[] = [
  {
    id: 'challenge.cluster_heading', group: 'step_task', title: '对抗复核：同一聚类的其他提交（标题）',
    description: '反向证据之前列出同一聚类中其他批次 / 模型的提交；{{n}} 为条数。',
    text: '## 同一聚类中的其他提交（{{n}} 条，来自不同批次 / 模型 / 两条线）',
  },
  {
    id: 'challenge.counter_heading', group: 'step_task', title: '对抗复核：反向证据（标题）',
    description: '本次审计其他会话排除附近位置、模型冲突、被反驳的假设，作为线索列出。',
    text: '## 本次审计中的反向证据（需要你用代码核实，不能直接采信）',
  },
  {
    id: 'challenge.pending_heading', group: 'step_task', title: '对抗复核：待确认条件（标题）',
    description: '发现带待确认条件时列在复核提示中。',
    text: '## 待确认条件（发现者提出，请判断能否用代码或知识解决）',
  },
  {
    id: 'challenge.evidence_check_heading', group: 'step_task', title: '对抗复核：证据清单（标题）',
    description: '引擎对调用边与应有检查的核对结果。',
    text: '## 证据清单（引擎核对结果，请逐项用代码核实）',
  },
  {
    id: 'challenge.gap_rule', group: 'step_task', title: '对抗复核：证据缺口的处理',
    description: '证据清单有缺口时追加的说明。',
    text: '缺口中的项如果你也无法用代码补上，confirmation 用 pending，并在 pendingCondition 中写明缺什么。',
  },
  {
    id: 'challenge.intro', group: 'step_task', title: '对抗复核：任务',
    description: '对抗复核会话任务的开头（不附发现者推理）。',
    text: '你是对抗复核员：独立核实下面这条已汇总的发现，并尽力反驳它。提示中只有结论、证据位置与证据行代码片段（片段附在提示末尾的数据边界中），没有发现者的推理；请自己从代码出发判断，需要时可以用 finding_reasoning 读取发现者的推理（它可能是错的）。先用只读工具核实，再调用 submit_challenge：',
  },
  {
    id: 'challenge.light', group: 'step_task', title: '对抗复核：简化复核',
    description: '简化复核（中低危、无争议的发现）的说明；{{turns}} 为轮次上限。',
    text: '这是简化复核（中低危或待确认的发现）：轮次上限 {{turns}}。只核对下面列出的证据位置、证据清单与反向证据，确认调用链与缺少的检查是否属实；不需要全面重新追查。核对不了的项按下面的规则用 pending 说明。',
  },
  {
    id: 'challenge.rules', group: 'step_task', title: '对抗复核：判定规则',
    description: '复核的四层判断（代码防护、威胁模型、支持论据、结论）与知识、连接器引用规则。',
    text: [
      '① codeDefense：路径上是否已有校验、过滤、鉴权、框架默认防护；',
      '② threatModel：前提是否独立成立、信任边界是否在路径外（如网关）、时序条件、上游状态；攻击路径是否真的可行、影响是否被夸大；',
      '③ affirm：支持该发现成立的论据；',
      '④ confirmation：证据足以支持则 maintain；读到了具体的反驳证据（防护代码、不可达的路径）则 refuted，并在 evidence 中给出这些代码位置；只有成立与否取决于一个具体的、代码中看不到的外部事实（按工作规则中“待确认”的界定：缺失的仓库或网关、未提供配置的具体取值、有线索的特殊业务规则）时才 pending，并填写 pendingCondition（缺什么、成立/不成立条件、成立时的严重度、建议操作）。部署与暴露情况、数据库权限等纵深防御、常识性安全预期都不是 pending 的理由；confidenceDelta：置信度调整（-1..1）。',
      '你不能删除发现；refuted 会把它转为“待确认”并保留正反两方论据，最终由人裁决。下方的反向证据来自本次审计的其他会话，只是线索，必须用代码核实。',
      '依据知识库内容作出判断时，在 knowledgeRefs 中列出本次读取过的 skill 名；标为 [推测] 的未核实知识只能作为推测，不能单独作为排除或确认的依据。',
      '依据连接器查询结果作出判断时，在 connectorRefs 中列出结果里的 call id；只有标为“已核实”的权威数据源结果可以作为排除或确认的依据。',
    ].join('\n'),
  },
  {
    id: 'tool.finding_reasoning', group: 'tool', title: '工具：finding_reasoning（对抗复核）', readonly: '工具与字段说明是引擎与模型之间的契约，只读展示',
    description: '对抗复核会话按需读取发现者推理的工具说明。',
    text: "Read the finder's reasoning and counter-check for this finding. Form your own view from the code first; the reasoning may be wrong.",
  },
  {
    id: 'tool.submit_challenge', group: 'tool', title: '工具：submit_challenge', readonly: '工具与字段说明是引擎与模型之间的契约，只读展示',
    description: '对抗复核的提交工具说明。',
    text: 'Submit the challenge verdict: code-defense layer, threat-model layer, affirm view, and the adjustment.',
  },
  {
    id: 'feedback.challenge.refuted_evidence', group: 'tool', title: '校验反馈：反驳须附证据', readonly: '校验反馈：提交不合规时返回给模型的说明，只读展示',
    description: 'submit_challenge 校验：refuted 没有 evidence。',
    text: 'confirmation 为 refuted 时必须在 evidence 中给出你读到的反驳证据（防护代码、不可达的位置）',
  },
  {
    id: 'feedback.challenge.pending_condition', group: 'tool', title: '校验反馈：待确认须附条件', readonly: '校验反馈：提交不合规时返回给模型的说明，只读展示',
    description: 'submit_challenge 校验：pending 没有 pendingCondition。',
    text: 'confirmation 为 pending 时必须给出 pendingCondition（缺少的具体事实、成立 / 不成立条件）；没有具体缺失时请用 maintain',
  },
];
