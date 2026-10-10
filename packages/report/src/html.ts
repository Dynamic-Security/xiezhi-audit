// Deterministic single-file HTML rendering: inline styles, no scripts,
// no external resources; every audited-content string is HTML-escaped. Same model as Markdown.
import { CATEGORY_ZH, CONFIDENCE_ZH, PENDING_KIND_ZH, SOURCE_ZH, STEP_STATUS_ZH, STEP_ZH, partialReasonText, zh } from './labels.js';
import { verificationHtml } from './verification.js';
import { ACCESS_LEVEL_ZH, accessVerdictZh, COVERAGE_NOTE, MISSING_KIND_ZH, OBLIGATION_KIND_ZH, OBLIGATION_SOURCE_ZH, UNCONCLUDED_REASON_ZH, unconcludedText, PENDING_ACTION_ZH, pendingOfDetail, STATIC_AUDIT_NOTE, type CodeLoc, type ReportFinding, type ReportModel } from './model.js';

const SEV_ZH: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };
const STATUS_ZH: Record<string, string> = {
  completed: '完成', partial: '未完成（部分结果）', failed: '失败', cancelled: '已取消', running: '运行中', interrupted: '已中断',
};
const CONFIRM_ZH: Record<string, string> = { pending: '待确认', confirmed: '已确认', false_positive: '误报' };
const LIFECYCLE_ZH: Record<string, string> = { new: '新增', persisting: '仍存在', fixed_verified: '已修复（经验证）', regressed: '回归' };
const HANDLING_ZH: Record<string, string> = { open: '待处理', fixing: '修复中', fixed: '已修复', risk_accepted: '接受风险' };
const COND_ZH: Record<string, string> = { confirmed: '已确认', unconfirmed: '未确认', unsatisfied: '不满足' };

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
const e = escapeHtml;
const loc = (l: CodeLoc) => `<code>${e(`${l.repo}:${l.path}:${l.startLine}${l.endLine !== l.startLine ? `-${l.endLine}` : ''}`)}</code>`;
const pct = (n: number, d: number) => (d === 0 ? '—' : `${((n / d) * 100).toFixed(1)}% (${n}/${d})`);
const para = (s: string) => s.split(/\r?\n\r?\n/).map((p) => `<p>${e(p).replace(/\r?\n/g, '<br>')}</p>`).join('');

const CSS = `
:root{--fg:#1d2330;--muted:#5b6475;--line:#d9dde5;--bg:#ffffff;--panel:#f6f7f9;--crit:#8f1d1d;--high:#b42318;--med:#b54708;--low:#175cd3;--info:#475467}
@media (prefers-color-scheme:dark){:root{--fg:#e6e9ef;--muted:#a3abba;--line:#343a46;--bg:#15181e;--panel:#1d2129;--crit:#ff8a8a;--high:#f97066;--med:#fdb022;--low:#84adff;--info:#98a2b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 20px 64px}h1{font-size:24px;margin:0 0 12px}h2{font-size:18px;margin:32px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:24px 0 8px}h4{font-size:14px;margin:16px 0 6px;color:var(--muted)}code{font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--panel);padding:1px 4px;border-radius:4px;word-break:break-all}
.note{border-left:4px solid var(--med);background:var(--panel);padding:10px 14px;margin:12px 0;border-radius:4px}.warn{border-left-color:var(--high)}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}th{background:var(--panel)}
.sev{display:inline-block;padding:0 8px;border-radius:10px;font-size:12px;font-weight:600;border:1px solid currentColor}
.sev-critical{color:var(--crit)}.sev-high{color:var(--high)}.sev-medium{color:var(--med)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.finding{border:1px solid var(--line);border-radius:8px;padding:4px 16px 12px;margin:16px 0}.meta{color:var(--muted);font-size:13px}ul{padding-left:20px}
details summary{cursor:pointer}@media print{.finding{break-inside:avoid}}
`;

function sevBadge(sev: string): string {
  return `<span class="sev sev-${e(sev)}">${e(SEV_ZH[sev] ?? sev)}</span>`;
}

function findingHtml(f: ReportFinding, prefix: string): string {
  const d = f.detail;
  const vuln = f.vulnDisplayNo !== null && !f.origin ? ` · V-${f.vulnDisplayNo}` : '';
  const out: string[] = [];
  out.push(`<section class="finding" id="${e(`${prefix}-${f.displayNo}`)}">`);
  out.push(`<h3>${e(`${prefix}-${f.displayNo}${vuln}`)} ${sevBadge(f.severity)} ${e(f.title)}${f.unreviewed ? ' （未复核）' : ''}</h3>`);
  out.push('<ul class="meta">');
  if (f.origin) out.push(`<li>最近一次发现：${f.origin.auditTitle ? e(`审计「${f.origin.auditTitle}」${f.origin.findingNo !== null ? ` F-${f.origin.findingNo}` : ''}`) : '无（按漏洞记录）'}</li>`);
  out.push(`<li>类别：${e(zh(CATEGORY_ZH, f.category))}${f.cwe ? `（${e(f.cwe)}）` : ''}；置信度：${e(zh(CONFIDENCE_ZH, f.confidence))}；判定来源：${e(f.sources.map((s) => zh(SOURCE_ZH, s)).join('、'))}</li>`);
  out.push(`<li>确认状态：${e(CONFIRM_ZH[f.confirmStatus] ?? f.confirmStatus)}${f.pendingKind ? `（${e(zh(PENDING_KIND_ZH, f.pendingKind))}）` : ''}；跨审计状态：${e(LIFECYCLE_ZH[f.lifecycle] ?? f.lifecycle)}；处理状态：${e(HANDLING_ZH[f.handlingStatus] ?? f.handlingStatus)}</li>`);
  if (f.severityOriginal) out.push(`<li>严重度已人工调整，原值：${e(SEV_ZH[f.severityOriginal] ?? f.severityOriginal)}</li>`);
  out.push(`<li>危险点：${loc(f.location)}${f.sinkApi ? ` · <code>${e(f.sinkApi)}</code>` : ''}</li>`);
  if (f.entries.length) out.push(`<li>入口：${f.entries.map((x) => `<code>${e(x)}</code>`).join('、')}</li>`);
  out.push(`<li>根因：${e(f.rootCause)}</li>`);
  if (f.boundary) out.push(`<li>责任归属：${e(({ own: '本服务缺陷', upstream: '依赖上游假设', cross_service: '服务间风险' } as Record<string, string>)[f.boundary] ?? f.boundary)}${f.boundaryNote ? `（${e(f.boundaryNote)}）` : ''}</li>`);
  out.push('</ul>');
  out.push('<h4>① 证据</h4><ul>');
  for (const ev of d.evidence) out.push(`<li>${loc(ev)}${ev.note ? ` — ${e(ev.note)}` : ''}</li>`);
  out.push('</ul><h4>② 推理与链路</h4>');
  if (d.chain.length) out.push(`<ol>${d.chain.map((c) => `<li>${loc(c)}${c.note ? ` — ${e(c.note)}` : ''}</li>`).join('')}</ol>`);
  out.push(para(d.reasoning));
  out.push(`<p><strong>反证检查：</strong>${e(d.counterCheck)}</p>`);
  if (d.challenge) {
    out.push(`<p><strong>对抗复核：</strong>${d.challenge.confirmation === 'pending' ? '转为待确认' : d.challenge.confirmation === 'refuted' ? '反驳（转为待确认，由人裁决）' : '维持'}（置信度调整 ${d.challenge.confidenceDelta >= 0 ? '+' : ''}${d.challenge.confidenceDelta}）。${e(d.challenge.reason)}</p>`);
  }
  if (d.externalEvidence?.length) {
    out.push(`<p><strong>外部依据：</strong>${d.externalEvidence.map((x) => `连接器 ${e(x.source)}（${x.authoritative ? '权威数据源' : '未核实'}${x.note ? `；${e(x.note)}` : ''}）`).join('；')}</p>`);
  }
  out.push('<h4>③ 利用条件</h4>');
  if (d.attackPath) out.push(`<p><strong>攻击路径：</strong>${e(d.attackPath)}</p>`);
  if (d.impact) out.push(`<p><strong>影响：</strong>${e(d.impact)}</p>`);
  if (d.exploitConditions.length) {
    out.push('<table><thead><tr><th>条件</th><th>状态</th><th>来源</th></tr></thead><tbody>');
    for (const c of d.exploitConditions) out.push(`<tr><td>${e(c.condition)}</td><td>${e(COND_ZH[c.status] ?? c.status)}</td><td>${e(c.source)}</td></tr>`);
    out.push('</tbody></table>');
  } else out.push('<p class="meta">（未列出）</p>');
  const pc = pendingOfDetail(d);
  if (pc) {
    out.push(`<div class="note"><strong>待确认，缺少：</strong>${e(pc.missing.map((m) => `${MISSING_KIND_ZH[m.kind] ?? m.kind} ${m.ref}${m.hint ? `（${m.hint}）` : ''}`).join('；'))}`
      + pc.holdsIf.map((c) => `<br>成立条件：${e(c.statement)}`).join('') + pc.refutedIf.map((c) => `<br>不成立条件：${e(c.statement)}`).join('')
      + `<br>若成立，严重度：${e(pc.severityIfHolds)}；建议：${e(pc.suggestedActions.map((a) => PENDING_ACTION_ZH[a] ?? a).join('、'))}</div>`);
  }
  out.push('<h4>④ 修复建议（由 AI 生成，需人工确认）</h4>');
  out.push(para(d.remediation.approach));
  if (d.remediation.suggestion) out.push(`<pre><code>${e(d.remediation.suggestion)}</code></pre>`);
  if (d.remediation.verification) out.push(`<p>验证方式：${e(d.remediation.verification)}</p>`);
  out.push(...verificationHtml(f.verification, e));
  out.push('</section>');
  return out.join('\n');
}

function head(o: string[], title: string): void {
  o.push('<!DOCTYPE html>');
  o.push('<html lang="zh-CN"><head><meta charset="utf-8">');
  o.push('<meta name="viewport" content="width=device-width, initial-scale=1">');
  o.push(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`);
  o.push(`<title>${e(title)}</title>`);
  o.push(`<style>${CSS}</style></head><body><main>`);
}

/** A complete page around body HTML the caller has already escaped (the AI report). */
export function htmlPage(title: string, body: string): string {
  const o: string[] = [];
  head(o, title);
  o.push(body, '</main></body></html>');
  return `${o.join('\n')}\n`;
}

function versionRows(o: string[], m: ReportModel): void {
  o.push('<table><thead><tr><th>仓库</th><th>角色</th><th>版本</th><th>快照</th></tr></thead><tbody>');
  for (const r of m.repositories) {
    const ver = r.worktree ? `工作区${r.commit ? `（基于 ${r.commit.slice(0, 12)}）` : ''}` : `${r.ref ?? ''} ${r.commit ? r.commit.slice(0, 12) : ''}`.trim();
    o.push(`<tr><td>${e(r.name)}</td><td>${e(r.roleInAudit)}</td><td>${e(ver)}</td><td><code>${e(r.rootHash.slice(0, 16))}</code></td></tr>`);
  }
  o.push('</tbody></table>');
}

/** Project-level report: the vulnerabilities of a project across audits, no run-level sections. */
function renderProjectHtml(m: ReportModel): string {
  const o: string[] = [];
  const sc = m.scope!;
  head(o, `项目漏洞报告 · ${m.project.name}`);
  o.push(`<h1>项目漏洞报告：${e(m.project.name)}</h1>`);
  o.push(`<div class="note">${e(STATIC_AUDIT_NOTE)}</div>`);
  o.push('<ul class="meta">');
  o.push(`<li>项目：${e(m.project.name)}</li>`);
  o.push('<li>范围：项目内全部活跃漏洞（合并后的漏洞按保留的一条计），每条取最近一次审计中的发现作为位置与详情</li>');
  o.push(`<li>来源审计：${sc.audits.length} 次</li>`);
  o.push('</ul>');
  o.push('<h2>仓库与最近审计版本</h2>');
  versionRows(o, m);
  o.push('<h2>结论摘要</h2>');
  if (m.selection) o.push(`<p><em>本报告只包含${m.selection.vulns !== null ? `选中的 ${m.selection.vulns} 个漏洞` : '部分漏洞'}${m.selection.includePending ? '' : '，不含待确认项'}。</em></p>`);
  const bySev = (sev: string) => m.findings.filter((f) => f.severity === sev).length;
  const byConfirm = (c: string) => m.findings.filter((f) => f.confirmStatus === c).length;
  o.push(`<p>漏洞 ${m.findings.length} 条（严重 ${bySev('critical')}、高 ${bySev('high')}、中 ${bySev('medium')}、低 ${bySev('low')}、信息 ${bySev('info')}）；已确认 ${byConfirm('confirmed')}、待确认 ${byConfirm('pending')}、误报 ${byConfirm('false_positive')}。</p>`);
  if (m.findings.length) {
    o.push('<table><thead><tr><th>编号</th><th>严重度</th><th>标题</th><th>确认状态</th><th>处理状态</th><th>跨审计状态</th><th>位置</th></tr></thead><tbody>');
    for (const f of m.findings) {
      o.push(`<tr><td><a href="#V-${f.displayNo}">V-${f.displayNo}</a></td><td>${sevBadge(f.severity)}</td><td>${e(f.title)}</td><td>${e(CONFIRM_ZH[f.confirmStatus] ?? f.confirmStatus)}</td><td>${e(HANDLING_ZH[f.handlingStatus] ?? f.handlingStatus)}</td><td>${e(LIFECYCLE_ZH[f.lifecycle] ?? f.lifecycle)}</td><td>${loc(f.location)}</td></tr>`);
    }
    o.push('</tbody></table>');
    o.push('<h2>漏洞详情</h2>');
    for (const f of m.findings) o.push(findingHtml(f, 'V'));
  }
  if (sc.audits.length) {
    o.push('<h2>来源审计</h2><ul>');
    for (const a of sc.audits) o.push(`<li>${e(a.title)}（<code>${e(a.id)}</code>）</li>`);
    o.push('</ul>');
  }
  o.push('</main></body></html>');
  return o.join('\n') + '\n';
}

export function renderHtml(m: ReportModel): string {
  if (m.scope?.kind === 'project') return renderProjectHtml(m);
  const o: string[] = [];
  head(o, `审计报告 · ${m.audit.title}`);
  o.push(`<h1>代码安全审计报告：${e(m.audit.title)}</h1>`);
  o.push(`<div class="note">${e(STATIC_AUDIT_NOTE)}</div>`);
  o.push('<ul class="meta">');
  o.push(`<li>项目：${e(m.project.name)}</li>`);
  o.push(`<li>审计：<code>${e(m.audit.id)}</code>（场景 ${e(m.audit.scene)}，模式 ${e(m.audit.mode)}）</li>`);
  o.push(`<li>状态：<strong>${e(STATUS_ZH[m.audit.status] ?? m.audit.status)}</strong></li>`);
  if (m.audit.partialReasons.length) o.push(`<li>未完成原因（按优先级）：${e(m.audit.partialReasons.map(partialReasonText).join(' > '))}</li>`);
  for (const n of m.audit.notices ?? []) o.push(`<li>提示：${e(n)}</li>`);
  if (m.audit.strategyHash) o.push(`<li>冻结策略：<code>${e(m.audit.strategyHash.slice(0, 16))}</code></li>`);
  o.push(`<li>用量：${m.audit.usage.tokens} tokens${m.audit.usage.costMicros !== null ? `，成本 ${(m.audit.usage.costMicros / 1e6).toFixed(4)}` : '，成本未知'}</li>`);
  o.push('</ul>');
  if (m.audit.status !== 'completed') o.push('<div class="note warn">本次审计未完整结束，结论不能视为“完整审计”或“代码安全”。</div>');

  o.push('<h2>审计范围与版本</h2>');
  versionRows(o, m);

  o.push('<h2>结论摘要</h2>');
  if (m.selection) o.push(`<p><em>本报告只包含${m.selection.vulns !== null ? `选中的 ${m.selection.vulns} 个漏洞对应的发现` : '部分发现'}${m.selection.includePending ? '' : '，不含待确认项与证据不足项'}。</em></p>`);
  const bySev = (sev: string) => m.findings.filter((f) => f.severity === sev).length;
  o.push(`<p>正式发现 ${m.findings.length} 条（严重 ${bySev('critical')}、高 ${bySev('high')}、中 ${bySev('medium')}、低 ${bySev('low')}、信息 ${bySev('info')}）；证据不足 ${m.insufficient.length} 条（单独列出，不计入正式结论）。</p>`);
  if (m.findings.length) {
    o.push('<table><thead><tr><th>编号</th><th>严重度</th><th>标题</th><th>确认状态</th><th>位置</th></tr></thead><tbody>');
    for (const f of m.findings) {
      o.push(`<tr><td><a href="#F-${f.displayNo}">F-${f.displayNo}</a></td><td>${sevBadge(f.severity)}</td><td>${e(f.title)}</td><td>${e(CONFIRM_ZH[f.confirmStatus] ?? f.confirmStatus)}</td><td>${loc(f.location)}</td></tr>`);
    }
    o.push('</tbody></table>');
  }
  if (m.dependencies && m.dependencies.repos.some((r) => r.total > 0)) {
    const d = m.dependencies;
    o.push('<h2>依赖与已知漏洞</h2><ul>');
    o.push(`<li>解析到的依赖：${e(d.repos.map((r) => `${r.repo} ${r.total} 个（有版本 ${r.versioned}）`).join('；'))}</li>`);
    o.push(`<li>${d.osv.available ? `OSV 查询：${d.osv.queried} 个，命中 ${d.hits.length} 个组件；是否可达由领域专家判断` : '未启用 OSV 连接器：没有查询已知漏洞'}</li></ul>`);
    if (d.hits.length) {
      o.push('<table><thead><tr><th>组件</th><th>版本</th><th>位置</th><th>公告</th></tr></thead><tbody>');
      for (const h of d.hits) o.push(`<tr><td>${e(h.name)}</td><td>${e(h.version)}</td><td>${e(`${h.repo}:${h.path}`)}</td><td>${e(h.advisories.slice(0, 5).map((a) => a.id).join('、'))}</td></tr>`);
      o.push('</tbody></table>');
    }
  }
  if (m.access?.length) {
    o.push('<h2>访问策略对照</h2><table><thead><tr><th>入口</th><th>应为</th><th>引擎看到</th><th>结论</th></tr></thead><tbody>');
    for (const a of m.access) o.push(`<tr><td>${e(a.entryKey)}</td><td>${e(ACCESS_LEVEL_ZH[a.level] ?? a.level)}${a.role ? `（${e(a.role)}）` : ''}</td><td>${e(a.why)}</td><td>${e(accessVerdictZh(a.verdict))}</td></tr>`);
    o.push('</tbody></table>');
  }
  if (m.obligations?.total) {
    const ob = m.obligations;
    o.push(`<h2>义务结算</h2><p>需要给出结论的项共 ${ob.total} 个，已结论 ${ob.settled} 个。</p><ul>`);
    for (const [k, v] of Object.entries(ob.byKind)) o.push(`<li>${e(OBLIGATION_KIND_ZH[k] ?? k)}：${v.settled} / ${v.total}</li>`);
    o.push('</ul><ul>');
    for (const [k, v] of Object.entries(ob.bySource)) o.push(`<li>${e(OBLIGATION_SOURCE_ZH[k] ?? k)}：${v.settled} / ${v.total}</li>`);
    o.push('</ul>');
  }
  if (m.coverage) {
    o.push('<h2>覆盖对照</h2><ul>');
    o.push(`<li>入口覆盖：${pct(m.coverage.entry.reviewed, m.coverage.entry.total)}；已读未结论 ${m.coverage.entry.readOnly}</li>`);
    o.push(`<li>危险点覆盖：${pct(m.coverage.sink.reviewed, m.coverage.sink.total)}；已读未结论 ${m.coverage.sink.readOnly}</li>`);
    o.push(`<li>阅读覆盖：${pct(m.coverage.reading.readLines, m.coverage.reading.totalLines)}</li>`);
    if (m.coverage.unconcluded) o.push(`<li>未结论：${m.coverage.unconcluded.total}${e(unconcludedText(m.coverage.unconcluded.byReason))}</li>`);
    const fc = m.coverage.files;
    if (fc?.total) o.push(`<li>源码文件：${fc.total} 个，有结论 ${fc.concluded}、读过 ${fc.read}、未读 ${fc.unread}${fc.signalUnreadTotal ? `；其中没有入口 / 危险点、名称涉及安全且未读的 ${fc.signalUnreadTotal} 个` : ''}</li>`);
    o.push(`<li>${e(COVERAGE_NOTE)}</li></ul>`);
    if (m.coverage.uncovered.length) {
      o.push(`<details><summary>未覆盖项（${m.coverage.uncovered.length}）</summary><ul>`);
      for (const u of m.coverage.uncovered) o.push(`<li>[${e(u.kind)}] <code>${e(u.targetId)}</code>（${e(u.status)}${u.reason ? `；${e(UNCONCLUDED_REASON_ZH[u.reason] ?? u.reason)}` : ''}）</li>`);
      o.push('</ul></details>');
    }
    if (fc?.signalUnread.length) {
      o.push(`<details><summary>没有入口 / 危险点、名称涉及安全且未读的文件（${fc.signalUnreadTotal}）</summary><ul>`);
      for (const f of fc.signalUnread) o.push(`<li><code>${e(`${f.repo}:${f.path}`)}</code></li>`);
      o.push('</ul></details>');
    }
  }
  if (m.findings.length) {
    o.push('<h2>发现详情</h2>');
    for (const f of m.findings) o.push(findingHtml(f, 'F'));
  }
  if (m.insufficient.length) {
    o.push('<h2>证据不足（不计入正式结论）</h2>');
    for (const f of m.insufficient) o.push(findingHtml(f, 'I'));
  }
  if (m.serviceHints?.length) {
    o.push('<h2>服务间风险提示（内部信任为“内网可信”，未发布为漏洞）</h2>');
    for (const f of m.serviceHints) o.push(findingHtml(f, 'H'));
  }
  if (m.injectionNotices.length || m.excludedControlFiles.length) {
    o.push('<h2>安全提示</h2><ul>');
    for (const c of m.excludedControlFiles) o.push(`<li>已排除 Agent 控制文件 <code>${e(`${c.repo}:${c.path}`)}</code>（不对 Agent 可见）。</li>`);
    for (const n of m.injectionNotices) o.push(`<li>检测到疑似指令内容 <code>${e(n.path)}</code>（${e(n.signal)}），已作为数据处理，未执行。</li>`);
    o.push('</ul>');
  }
  if (m.knowledge.length) {
    o.push('<h2>使用的知识</h2><table><thead><tr><th>skill</th><th>层</th><th>最高加载级别</th><th>次数</th><th>步骤</th><th>tokens</th><th>被结论引用</th></tr></thead><tbody>');
    for (const k of m.knowledge) o.push(`<tr><td>${e(k.name)}</td><td>${e(k.layer)}</td><td>${e(k.maxLevel)}</td><td>${k.reads}</td><td>${k.steps}</td><td>${k.tokens}</td><td>${k.citedBy}</td></tr>`);
    o.push('</tbody></table>');
  }
  if (m.trajectory?.length) {
    o.push('<h2>行为轨迹摘要</h2><table><thead><tr><th>步骤</th><th>状态</th><th>耗时</th><th>tokens</th><th>工具调用</th><th>Agent 说明（首条）</th></tr></thead><tbody>');
    for (const s of m.trajectory) o.push(`<tr><td>${e(zh(STEP_ZH, s.kind))}${s.lineage ? ` ${e(s.lineage)}` : ''}</td><td>${e(zh(STEP_STATUS_ZH, s.status))}</td><td>${(s.durationMs / 1000).toFixed(1)} 秒</td><td>${s.tokens}</td><td>${s.toolCalls}</td><td>${e(s.firstNote ?? '')}</td></tr>`);
    o.push('</tbody></table>');
  }
  o.push('</main></body></html>');
  return o.join('\n') + '\n';
}
