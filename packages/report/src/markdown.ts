// Deterministic Markdown rendering.
import { formatTokens } from '@xiezhi/contracts';
import { CATEGORY_ZH, CONFIDENCE_ZH, HANDLING_ZH, PENDING_KIND_ZH, SOURCE_ZH, STEP_STATUS_ZH, partialReasonText, stepZh, zh } from './labels.js';
import { verificationMarkdown } from './verification.js';
import { ACCESS_LEVEL_ZH, accessVerdictZh, COVERAGE_NOTE, MISSING_KIND_ZH, OBLIGATION_KIND_ZH, OBLIGATION_SOURCE_ZH, UNCONCLUDED_REASON_ZH, unconcludedText, PENDING_ACTION_ZH, pendingOfDetail, STATIC_AUDIT_NOTE, type ReportFinding, type ReportModel } from './model.js';

const SEV_ZH: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };
const STATUS_ZH: Record<string, string> = {
  completed: '完成', partial: '未完成（部分结果）', failed: '失败', cancelled: '已取消', running: '运行中', interrupted: '已中断',
};
const CONFIRM_ZH: Record<string, string> = { pending: '待确认', confirmed: '已确认', false_positive: '误报' };
const LIFECYCLE_ZH: Record<string, string> = { new: '新增', persisting: '仍存在', fixed_verified: '已修复（经验证）', regressed: '回归' };
const COND_ZH: Record<string, string> = { confirmed: '已确认', unconfirmed: '未确认', unsatisfied: '不满足' };

const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
const loc = (l: { repo: string; path: string; startLine: number; endLine: number }) =>
  `\`${l.repo}:${l.path}:${l.startLine}${l.endLine !== l.startLine ? `-${l.endLine}` : ''}\``;
const pct = (n: number, d: number) => (d === 0 ? '—' : `${((n / d) * 100).toFixed(1)}% (${n}/${d})`);

function findingSection(f: ReportFinding, prefix: string): string {
  const d = f.detail;
  const lines: string[] = [];
  const vuln = f.vulnDisplayNo !== null && !f.origin ? ` · V-${f.vulnDisplayNo}` : '';
  lines.push(`### ${prefix}-${f.displayNo}${vuln} [${SEV_ZH[f.severity] ?? f.severity}] ${f.title}${f.unreviewed ? '（未复核）' : ''}`);
  lines.push('');
  if (f.origin) lines.push(`- 最近一次发现：${f.origin.auditTitle ? `审计「${f.origin.auditTitle}」${f.origin.findingNo !== null ? ` F-${f.origin.findingNo}` : ''}` : '无（按漏洞记录）'}`);
  lines.push(`- 类别：${zh(CATEGORY_ZH, f.category)}${f.cwe ? `（${f.cwe}）` : ''}；置信度：${zh(CONFIDENCE_ZH, f.confidence)}；判定来源：${f.sources.map((s) => zh(SOURCE_ZH, s)).join('、')}`);
  lines.push(`- 确认状态：${CONFIRM_ZH[f.confirmStatus] ?? f.confirmStatus}${f.pendingKind ? `（${zh(PENDING_KIND_ZH, f.pendingKind)}）` : ''}；跨审计状态：${LIFECYCLE_ZH[f.lifecycle] ?? f.lifecycle}；处理状态：${zh(HANDLING_ZH, f.handlingStatus)}`);
  if (f.severityOriginal) lines.push(`- 严重度已人工调整，原值：${SEV_ZH[f.severityOriginal] ?? f.severityOriginal}`);
  lines.push(`- 危险点：${loc(f.location)}${f.sinkApi ? ` · \`${f.sinkApi}\`` : ''}`);
  if (f.entries.length) lines.push(`- 入口：${f.entries.map((e) => `\`${e}\``).join('、')}`);
  lines.push(`- 根因：${f.rootCause}`);
  if (f.boundary) lines.push(`- 责任归属：${({ own: '本服务缺陷', upstream: '依赖上游假设', cross_service: '服务间风险' } as Record<string, string>)[f.boundary] ?? f.boundary}${f.boundaryNote ? `（${f.boundaryNote}）` : ''}`);
  lines.push('');
  lines.push('#### ① 证据');
  for (const e of d.evidence) lines.push(`- ${loc(e)}${e.note ? ` — ${e.note}` : ''}`);
  lines.push('');
  lines.push('#### ② 推理与链路');
  if (d.chain.length) d.chain.forEach((c, i) => lines.push(`${i + 1}. ${loc(c)}${c.note ? ` — ${c.note}` : ''}`));
  lines.push('');
  lines.push(d.reasoning);
  lines.push('');
  lines.push(`**反证检查：** ${d.counterCheck}`);
  if (d.challenge) {
    lines.push('');
    lines.push(`**对抗复核：** ${d.challenge.confirmation === 'pending' ? '转为待确认' : d.challenge.confirmation === 'refuted' ? '反驳（转为待确认，由人裁决）' : '维持'}（置信度调整 ${d.challenge.confidenceDelta >= 0 ? '+' : ''}${d.challenge.confidenceDelta}）。${d.challenge.reason}`);
  }
  if (d.externalEvidence?.length) {
    lines.push('');
    lines.push(`**外部依据：** ${d.externalEvidence.map((x) => `连接器 ${x.source}（${x.authoritative ? '权威数据源' : '未核实'}${x.note ? `；${x.note}` : ''}）`).join('；')}`);
  }
  lines.push('');
  lines.push('#### ③ 利用条件');
  if (d.attackPath) lines.push(`**攻击路径：** ${d.attackPath}`, '');
  if (d.impact) lines.push(`**影响：** ${d.impact}`, '');
  if (d.exploitConditions.length) {
    lines.push('| 条件 | 状态 | 来源 |', '| --- | --- | --- |');
    for (const c of d.exploitConditions) lines.push(`| ${esc(c.condition)} | ${COND_ZH[c.status] ?? c.status} | ${esc(c.source)} |`);
  } else lines.push('（未列出）');
  const pc = pendingOfDetail(d);
  if (pc) {
    lines.push('');
    lines.push(`**待确认，缺少：** ${pc.missing.map((m) => `${MISSING_KIND_ZH[m.kind] ?? m.kind} ${m.ref}${m.hint ? `（${m.hint}）` : ''}`).join('；')}`);
    for (const c of pc.holdsIf) lines.push(`- 成立条件：${c.statement}`);
    for (const c of pc.refutedIf) lines.push(`- 不成立条件：${c.statement}`);
    lines.push(`- 若成立，严重度：${pc.severityIfHolds}；建议：${pc.suggestedActions.map((a) => PENDING_ACTION_ZH[a] ?? a).join('、')}`);
  }
  lines.push('');
  lines.push('#### ④ 修复建议（由 AI 生成，需人工确认）');
  lines.push(d.remediation.approach);
  if (d.remediation.suggestion) lines.push('', d.remediation.suggestion);
  if (d.remediation.verification) lines.push('', `验证方式：${d.remediation.verification}`);
  lines.push('');
  lines.push(...verificationMarkdown(f.verification));
  return lines.join('\n');
}

/** Project-level report: the vulnerabilities of a project across audits, no run-level sections. */
function renderProjectMarkdown(m: ReportModel): string {
  const out: string[] = [];
  const sc = m.scope!;
  out.push(`# 项目漏洞报告：${m.project.name}`, '', `> ${STATIC_AUDIT_NOTE}`, '');
  out.push(`- 项目：${m.project.name}`);
  out.push(`- 范围：项目内全部活跃漏洞（合并后的漏洞按保留的一条计），每条取最近一次审计中的发现作为位置与详情`);
  out.push(`- 来源审计：${sc.audits.length} 次`);
  out.push('');
  out.push('## 仓库与最近审计版本', '');
  out.push('| 仓库 | 角色 | 版本 | 快照 |', '| --- | --- | --- | --- |');
  for (const r of m.repositories) {
    const ver = r.worktree ? `工作区${r.commit ? `（基于 ${r.commit.slice(0, 12)}）` : ''}` : `${r.ref ?? ''} ${r.commit ? r.commit.slice(0, 12) : ''}`.trim();
    out.push(`| ${esc(r.name)} | ${r.roleInAudit} | ${esc(ver)} | \`${r.rootHash.slice(0, 16)}\` |`);
  }
  out.push('');
  out.push('## 结论摘要', '');
  if (m.selection) out.push(`> 本报告只包含${m.selection.vulns !== null ? `选中的 ${m.selection.vulns} 个漏洞` : '部分漏洞'}${m.selection.includePending ? '' : '，不含待确认项'}。`, '');
  const bySev = (sev: string) => m.findings.filter((f) => f.severity === sev).length;
  const byConfirm = (c: string) => m.findings.filter((f) => f.confirmStatus === c).length;
  out.push(`漏洞 ${m.findings.length} 条（严重 ${bySev('critical')}、高 ${bySev('high')}、中 ${bySev('medium')}、低 ${bySev('low')}、信息 ${bySev('info')}）；已确认 ${byConfirm('confirmed')}、待确认 ${byConfirm('pending')}、误报 ${byConfirm('false_positive')}。`);
  out.push('');
  if (m.findings.length) {
    out.push('| 编号 | 严重度 | 标题 | 确认状态 | 处理状态 | 跨审计状态 | 位置 |', '| --- | --- | --- | --- | --- | --- | --- |');
    for (const f of m.findings) out.push(`| V-${f.displayNo} | ${SEV_ZH[f.severity]} | ${esc(f.title)} | ${CONFIRM_ZH[f.confirmStatus] ?? f.confirmStatus} | ${zh(HANDLING_ZH, f.handlingStatus)} | ${LIFECYCLE_ZH[f.lifecycle] ?? f.lifecycle} | ${loc(f.location)} |`);
    out.push('');
    out.push('## 漏洞详情', '');
    for (const f of m.findings) out.push(findingSection(f, 'V'));
  }
  if (sc.audits.length) {
    out.push('## 来源审计', '');
    for (const a of sc.audits) out.push(`- ${a.title}（\`${a.id}\`）`);
    out.push('');
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n') + '\n';
}

export function renderMarkdown(m: ReportModel): string {
  if (m.scope?.kind === 'project') return renderProjectMarkdown(m);
  const out: string[] = [];
  out.push(`# 代码安全审计报告：${m.audit.title}`);
  out.push('');
  out.push(`> ${STATIC_AUDIT_NOTE}`);
  out.push('');
  out.push(`- 项目：${m.project.name}`);
  out.push(`- 审计：${m.audit.id}（场景 ${m.audit.scene}，模式 ${m.audit.mode}）`);
  out.push(`- 状态：**${STATUS_ZH[m.audit.status] ?? m.audit.status}**`);
  if (m.audit.partialReasons.length) out.push(`- ${m.audit.status === 'completed' ? '过程问题' : '未完成原因'}（按优先级）：${m.audit.partialReasons.map(partialReasonText).join(' > ')}`);
  for (const n of m.audit.notices ?? []) out.push(`- 提示：${n}`);
  if (m.audit.strategyHash) out.push(`- 冻结策略：\`${m.audit.strategyHash.slice(0, 16)}\``);
  out.push(`- 用量：${formatTokens(m.audit.usage.tokens)} tokens${m.audit.usage.costMicros !== null ? `，成本 ${(m.audit.usage.costMicros / 1e6).toFixed(4)}` : '，成本未知'}`);
  out.push('');
  out.push('## 审计范围与版本');
  out.push('');
  out.push('| 仓库 | 角色 | 版本 | 快照 |', '| --- | --- | --- | --- |');
  for (const r of m.repositories) {
    const ver = r.worktree ? `工作区${r.commit ? `（基于 ${r.commit.slice(0, 12)}）` : ''}` : `${r.ref ?? ''} ${r.commit ? r.commit.slice(0, 12) : ''}`.trim();
    out.push(`| ${esc(r.name)} | ${r.roleInAudit} | ${esc(ver)} | \`${r.rootHash.slice(0, 16)}\` |`);
  }
  out.push('');
  if (m.audit.status !== 'completed') {
    out.push(`> 本次审计未完整结束，结论不能视为“完整审计”或“代码安全”。`);
    out.push('');
  }
  out.push('## 结论摘要');
  out.push('');
  if (m.selection) out.push(`> 本报告只包含${m.selection.vulns !== null ? `选中的 ${m.selection.vulns} 个漏洞对应的发现` : '部分发现'}${m.selection.includePending ? '' : '，不含待确认项与证据不足项'}。`, '');
  const bySev = (sev: string) => m.findings.filter((f) => f.severity === sev).length;
  out.push(`正式发现 ${m.findings.length} 条（严重 ${bySev('critical')}、高 ${bySev('high')}、中 ${bySev('medium')}、低 ${bySev('low')}、信息 ${bySev('info')}）；证据不足 ${m.insufficient.length} 条（单独列出，不计入正式结论）。`);
  out.push('');
  if (m.findings.length) {
    out.push('| 编号 | 严重度 | 标题 | 确认状态 | 位置 |', '| --- | --- | --- | --- | --- |');
    for (const f of m.findings) out.push(`| F-${f.displayNo} | ${SEV_ZH[f.severity]} | ${esc(f.title)} | ${CONFIRM_ZH[f.confirmStatus] ?? f.confirmStatus} | ${loc(f.location)} |`);
    out.push('');
  }
  if (m.obligations?.total) {
    // what the audit had to settle, by kind and by source.
    const ob = m.obligations;
    out.push('## 义务结算', '', `需要给出结论的项共 ${ob.total} 个，已结论 ${ob.settled} 个。`, '', '| 种类 | 已结论 / 总数 |', '| --- | --- |');
    for (const [k, v] of Object.entries(ob.byKind)) out.push(`| ${OBLIGATION_KIND_ZH[k] ?? k} | ${v.settled} / ${v.total} |`);
    out.push('', '| 来源 | 已结论 / 总数 |', '| --- | --- |');
    for (const [k, v] of Object.entries(ob.bySource)) out.push(`| ${OBLIGATION_SOURCE_ZH[k] ?? k} | ${v.settled} / ${v.total} |`);
    out.push('');
  }
  if (m.coverage) {
    out.push('## 覆盖对照');
    out.push('');
    out.push(`- 入口覆盖：${pct(m.coverage.entry.reviewed, m.coverage.entry.total)}；已读未结论 ${m.coverage.entry.readOnly}`);
    out.push(`- 危险点覆盖：${pct(m.coverage.sink.reviewed, m.coverage.sink.total)}；已读未结论 ${m.coverage.sink.readOnly}`);
    out.push(`- 阅读覆盖：${pct(m.coverage.reading.readLines, m.coverage.reading.totalLines)}`);
    if (m.coverage.unconcluded) out.push(`- 未结论：${m.coverage.unconcluded.total}${unconcludedText(m.coverage.unconcluded.byReason)}`);
    const fc = m.coverage.files;
    if (fc?.total) out.push(`- 源码文件：${fc.total} 个，有结论 ${fc.concluded}、读过 ${fc.read}、未读 ${fc.unread}${fc.signalUnreadTotal ? `；其中没有入口 / 危险点、名称涉及安全且未读的 ${fc.signalUnreadTotal} 个（见下）` : ''}`);
    out.push(`- ${COVERAGE_NOTE}`);
    if (m.coverage.uncovered.length) {
      out.push('', '<details><summary>未覆盖项</summary>', '');
      for (const u of m.coverage.uncovered) out.push(`- [${u.kind}] \`${u.targetId}\`（${u.status}${u.reason ? `；${UNCONCLUDED_REASON_ZH[u.reason] ?? u.reason}` : ''}）`);
      out.push('', '</details>');
    }
    if (fc?.signalUnread.length) {
      out.push('', `<details><summary>没有入口 / 危险点、名称涉及安全且未读的文件（${fc.signalUnreadTotal}）</summary>`, '');
      for (const f of fc.signalUnread) out.push(`- \`${f.repo}:${f.path}\``);
      if (fc.signalUnreadTotal > fc.signalUnread.length) out.push(`- ……另有 ${fc.signalUnreadTotal - fc.signalUnread.length} 个`);
      out.push('', '</details>');
    }
    out.push('');
  }
  if (m.dependencies && m.dependencies.repos.some((r) => r.total > 0)) {
    const d = m.dependencies;
    out.push('## 依赖与已知漏洞', '');
    out.push(`- 解析到的依赖：${d.repos.map((r) => `${r.repo} ${r.total} 个（有版本 ${r.versioned}）`).join('；')}`);
    out.push(d.osv.available ? `- OSV 查询：${d.osv.queried} 个${d.osv.failed ? `（失败 ${d.osv.failed} 个）` : ''}，命中 ${d.hits.length} 个组件；是否可达由领域专家判断，可达的作为发现报告` : '- 未启用 OSV 连接器：没有查询已知漏洞（启用后只发送生态、包名与版本）');
    if (d.hits.length) {
      out.push('', '| 组件 | 版本 | 位置 | 公告 |', '| --- | --- | --- | --- |');
      for (const h of d.hits) out.push(`| ${esc(h.name)} | ${esc(h.version)} | ${esc(`${h.repo}:${h.path}`)} | ${esc(h.advisories.slice(0, 5).map((a) => a.id).join('、'))} |`);
    }
    out.push('');
  }
  if (m.access?.length) {
    out.push('## 访问策略对照', '', '威胁建模给出的访问级别与结构索引中的鉴权信号对照后，看不出满足要求的入口，以及领域专家的结论：', '');
    out.push('| 入口 | 应为 | 引擎看到 | 结论 |', '| --- | --- | --- | --- |');
    for (const a of m.access) out.push(`| ${esc(a.entryKey)} | ${ACCESS_LEVEL_ZH[a.level] ?? a.level}${a.role ? `（${esc(a.role)}）` : ''} | ${esc(a.why)} | ${accessVerdictZh(a.verdict)} |`);
    out.push('');
  }
  if (m.findings.length) {
    out.push('## 发现详情', '');
    for (const f of m.findings) out.push(findingSection(f, 'F'));
  }
  if (m.insufficient.length) {
    out.push('## 证据不足（不计入正式结论）', '');
    for (const f of m.insufficient) out.push(findingSection(f, 'I'));
  }
  if (m.serviceHints?.length) {
    out.push('## 服务间风险提示（内部信任为“内网可信”，未发布为漏洞）', '');
    for (const f of m.serviceHints) out.push(findingSection(f, 'H'));
  }
  if (m.injectionNotices.length || m.excludedControlFiles.length) {
    out.push('## 安全提示', '');
    for (const c of m.excludedControlFiles) out.push(`- 已排除 Agent 控制文件 \`${c.repo}:${c.path}\`（不对 Agent 可见）。`);
    for (const n of m.injectionNotices) out.push(`- 检测到疑似指令内容 \`${n.path}\`（${n.signal}），已作为数据处理，未执行。`);
    out.push('');
  }
  if (m.knowledge.length) {
    out.push('## 使用的知识', '');
    out.push('| skill | 层 | 最高加载级别 | 次数 | 步骤 | tokens | 被结论引用 |', '| --- | --- | --- | --- | --- | --- | --- |');
    for (const k of m.knowledge) out.push(`| ${k.name} | ${k.layer} | ${k.maxLevel} | ${k.reads} | ${k.steps} | ${formatTokens(k.tokens)} | ${k.citedBy} |`);
    out.push('');
  }
  if (m.trajectory?.length) {
    out.push('## 行为轨迹摘要', '');
    out.push('| 步骤 | 状态 | 耗时 | tokens | 工具调用 | Agent 说明（首条） |', '| --- | --- | --- | --- | --- | --- |');
    for (const s of m.trajectory) out.push(`| ${stepZh(s.kind, s.lineage)}${s.lineage ? ` ${s.lineage}` : ''} | ${zh(STEP_STATUS_ZH, s.status)} | ${(s.durationMs / 1000).toFixed(1)} 秒 | ${formatTokens(s.tokens)} | ${s.toolCalls} | ${esc(s.firstNote ?? '')} |`);
    out.push('');
  }
  return out.join('\n').replace(/\n{3,}/g, '\n\n') + '\n';
}
