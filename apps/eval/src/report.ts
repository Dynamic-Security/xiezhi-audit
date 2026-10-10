// Deterministic Markdown rendering of scores and experiments: same JSON → same bytes.
// No model is involved; numbers are formatted with fixed precision.
import type { ExperimentResult } from './experiment.js';
import type { CostTotals, ScoreResult } from './score.js';

const pct = (x: number | null | undefined) => (x === null || x === undefined ? '不适用' : `${(x * 100).toFixed(1)}%`);
const num = (x: number | null | undefined, d = 3) => (x === null || x === undefined ? '不适用' : x.toFixed(d));
const cell = (s: unknown) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

/**
 * Precision with its adjudication caveat: withheld below the coverage threshold (shown as
 * "未知" plus the bounds), partial with bounds when some unlabelled output is still undecided.
 */
export function precisionText(m: { precision?: number | null; precision_low?: number | null; precision_high?: number | null; adjudication_coverage?: number | null }): string {
  const bounds = m.precision_low != null && m.precision_high != null && m.precision_low !== m.precision_high ? `[${pct(m.precision_low)}, ${pct(m.precision_high)}]` : '';
  const cov = m.adjudication_coverage != null ? `裁定覆盖 ${pct(m.adjudication_coverage)}` : '';
  if (m.precision == null && bounds) return `未知（${cov}，区间 ${bounds}）`;
  if (bounds) return `${pct(m.precision)}（部分结论：${cov}，区间 ${bounds}）`;
  return pct(m.precision);
}

function table(head: string[], rows: unknown[][]): string {
  if (!rows.length) return '（无）\n';
  return [`| ${head.join(' | ')} |`, `| ${head.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.map(cell).join(' | ')} |`)].join('\n') + '\n';
}

export function costText(c: CostTotals): string {
  const known = Object.entries(c.known).map(([cur, v]) => `${v.toFixed(4)} ${cur}`).join(' + ');
  if (!known && c.unknown_calls) return `unknown（${c.unknown_calls} 次调用无单价）`;
  return `${known || '0'}${c.unknown_calls ? `（另有 ${c.unknown_calls} 次调用无单价，费用 unknown）` : ''}`;
}

export function renderReport(s: ScoreResult): string {
  const q = s.quality;
  const a = s.availability;
  const out: string[] = [];
  out.push(`# 评测报告：${s.run.name ?? '未命名运行'}`, '');
  out.push('## 运行身份', '');
  out.push(table(['项', '值'], [
    ['基准版本（运行时 / 评分时）', `${s.run.bench_version} / ${s.bench.version}${s.bench.labels_changed_since_run ? '（标注已变更）' : ''}`],
    ['分区', s.run.partition], ['重复次数', s.run.repeats],
    ['被测代码', `${s.run.code.revision ?? '未知'}${s.run.code.dirty ? '（有未提交改动，不可作为发布验收）' : ''}`],
    ['基准仓库版本', s.run.bench_commit ?? '未知'],
    ['pi 版本', s.run.pi_version], ['默认模型 / 轻量模型', `${s.run.models.default ?? '-'} / ${s.run.models.cheap ?? '-'}`],
    ['配置哈希', s.run.config_sha256.slice(0, 16)], ['知识集合', s.run.knowledge.join(', ') || '（仅内置）'],
    ['结果缓存', s.cache?.enabled ? `复用 ${s.cached_runs ?? s.cache.hits} 次运行（被复用的运行保留原始 tokens 与耗时，费用按当前价格重算）` : `未启用${s.cache?.reason ? `（${s.cache.reason}）` : ''}`],
  ]));
  if (Object.keys(s.invalid).length) out.push('**作废样本**（root_hash 不一致或已移除）：', '', table(['样本', '原因'], Object.entries(s.invalid)));
  if (s.stopped_reason) out.push(`**提前停止**：${s.stopped_reason}；未运行 ${s.skipped.length} 次。`, '');

  out.push('## 可用性', '');
  out.push(table(['运行', '完成', '未完成', '失败', '取消', '异常', '完成率'], [[a.runs, a.completed, a.partial, a.failed, a.cancelled, a.error, pct(a.completion_rate)]]));
  if (Object.keys(a.partial_reasons).length) out.push('未完成原因：', '', table(['原因', '次数'], Object.entries(a.partial_reasons)));
  if (Object.keys(a.error_classes).length) out.push('错误类型：', '', table(['错误', '尝试次数', '影响样本'], Object.entries(a.error_classes).map(([k, v]) => [k, v.attempts, v.samples.join(', ')])));
  if (Object.keys(a.run_errors).length) out.push('运行异常：', '', table(['代码', '次数'], Object.entries(a.run_errors)));
  out.push(`重试后恢复：${a.retry_recovery.recovered}/${a.retry_recovery.steps_with_errors}（${pct(a.retry_recovery.rate)}）`, '');

  out.push('## 质量', '');
  out.push('只统计成功完成的运行；“待确认”不进 Precision，单列。混合口径把未完成运行的标注全部计为漏检。', '');
  out.push(table(['Precision', 'Recall', 'F1', 'Recall_mixed', 'F1_mixed', 'Recall_loose'], [[precisionText(q), pct(q.recall), num(q.f1), pct(q.recall_mixed), num(q.f1_mixed), pct(q.recall_loose ?? null)]]));
  out.push('Recall_loose：严格口径未命中的标注，若有类别等价、未被其他标注使用的发现落在其危险点或备选危险点所在文件、并且与它共享至少一个入口，也算命中；只用于判断漏报是否只是代表位置不同，不进 Precision，逐条见下方“宽松命中”，需要人工核对。', '');
  const c = q.counts;
  out.push(table(['命中', '重复', '误报', '裁定为真 / 误报', '待裁定', '待确认（命中 / 误报）', '标注（命中 / 总数 / 含未完成）'], [[c.tp, c.duplicate, c.fp, `${c.adj_tp ?? 0} / ${c.adj_fp ?? 0}`, c.queue, `${c.pending}（${c.pending_hit} / ${c.pending_fp}）`, `${c.labels_hit} / ${c.labels_total} / ${c.labels_total_all}`]]));
  const sh = Object.entries(q.by_sample_hits ?? {});
  const spr = (x: { median: number | null; min: number | null; max: number | null }) => `${num(x.median)}（${x.min ?? '-'}–${x.max ?? '-'}）`;
  if (sh.length) out.push('各样本命中（完成的运行；中位数与最小–最大）：', '', table(['样本', '运行', '标注', '严格', '宽松', '各次（严格 / 宽松）'], sh.map(([k, v]) => [k, v.runs, v.labels, spr(v.strict), spr(v.loose), v.strict.values.map((x, i) => `${x}/${v.loose.values[i]}`).join(' · ')])));
  if (q.loose_hits?.length) out.push('宽松命中：', '', table(['样本', '次', '标注', '发现'], q.loose_hits.map((h) => [h.sample_id, h.repeat, h.label_id, h.finding_id])));
  const adj = q.adjudication;
  if (adj?.runs) out.push(`只标注已知漏洞的样本（${adj.runs} 次运行）：Recall 只按已知漏洞计算；其余发现已裁定 ${adj.decided} 条、未裁定 ${adj.undecided} 条（裁定覆盖 ${pct(adj.coverage)}）。Precision 只含已裁定的发现：覆盖不到 100% 时是部分结论，并给出区间（下限：未裁定的全是误报；上限：全是真问题）；覆盖（不含待确认）低于 80% 时不给 Precision 数值，只给区间。`, '');
  out.push(table(['类别正确率', '定位正确率', '入口命中率', '严重度在期望范围', '结论类型正确率（G10）', '待确认正确率'], [[pct(q.category_accuracy), pct(q.localization_accuracy), pct(q.entry_hit_rate), pct(q.severity_in_range), pct(q.verdict_accuracy), pct(q.pending_accuracy)]]));
  const hy = q.hypotheses;
  if (hy?.runs) out.push('', `未排除的假设（不计入 Precision / Recall）：${hy.runs} 次运行共 ${hy.open} 条（另有已被反驳 ${hy.refuted} 条）；漏检的标注中有 ${hy.labels_missed_but_hypothesised} 条落在未排除的假设上（计入后 Recall ${pct(hy.recall_with_hypotheses)}）。`);
  if (hy?.threat?.total) out.push('', `威胁建模风险假设（不计入 Precision / Recall）：共 ${hy.threat.total} 条，已证实 ${hy.threat.confirmed}、已排除 ${hy.threat.refuted}、无法判定 ${hy.threat.open}、未验证 ${hy.threat.proposed}。`);
  const cv = s.coverage;
  if (cv.runs) out.push('', `覆盖：入口覆盖 ${pct(cv.entry_coverage)} · 危险点覆盖 ${pct(cv.sink_coverage)} · 标注危险点命中率 ${pct(cv.labeled_sink_hit_rate)}（${cv.labeled_sinks} 个标注${cv.missed.length ? `；未命中：${cv.missed.slice(0, 5).map((m) => `${m.sample_id}/${m.label_id}`).join('、')}` : ''}）· 分子准确性 ${pct(cv.numerator_accuracy)}；分母 Precision / Recall 未评（需要人工标注完整的入口与危险点清单）`);
  const g3 = s.traceability;
  out.push('', `可追溯（G3，目标 100%）：${pct(g3.ratio)}（${g3.traceable}/${g3.findings}${g3.not_recorded ? `；${g3.not_recorded} 条运行未记录` : ''}）${g3.failures.length ? `；未满足：${g3.failures.slice(0, 5).map((f) => `${f.sample_id}#${f.repeat} ${f.finding} 缺 ${f.missing.join('、')}`).join('；')}` : ''}`);
  out.push('修复版本与负例上的误报（按防护位置）：', '');
  out.push(table(['防护', '运行', '有误报的运行', '误报数', '误报率'], Object.entries(q.false_positives_on_clean).map(([g, v]) => [g, v.runs, v.runs_with_fp, v.fp, pct(v.fp_rate)])));
  const recallRows = (o: Record<string, { labels: number; hit: number; recall: number | null; recall_mixed: number | null; hit_loose?: number; recall_loose?: number | null }>) => Object.entries(o).map(([k, v]) => [k, v.labels, v.hit, pct(v.recall), pct(v.recall_mixed), v.hit_loose ?? v.hit, pct(v.recall_loose ?? v.recall)]);
  out.push('按类别：', '', table(['类别', '标注', '命中', 'Recall', 'Recall_mixed', '宽松命中', 'Recall_loose'], recallRows(q.by_category)));
  out.push('按深度：', '', table(['深度', '标注', '命中', 'Recall', 'Recall_mixed', '宽松命中', 'Recall_loose'], recallRows(q.by_depth)));
  if (q.by_boundary && Object.keys(q.by_boundary).some((k) => k !== 'own')) {
    out.push('按服务边界（own 本服务缺陷 / upstream 依赖上游假设 / cross_service 服务间风险）：', '', table(['类别', '标注', '命中', 'Recall', 'Recall_mixed', '宽松命中', 'Recall_loose'], recallRows(q.by_boundary)));
    out.push(`边界类别正确率（命中中发现的类别与标注一致；没有类别的发现按 own 计）：${pct(q.boundary_accuracy ?? null)}`, '');
  }
  const pRows = (o: Record<string, { precision: number | null; precision_low?: number | null; precision_high?: number | null; adjudication_coverage?: number | null; recall: number | null; f1: number | null; recall_mixed: number | null }>) => Object.entries(o).map(([k, v]) => [k, precisionText(v), pct(v.recall), num(v.f1), pct(v.recall_mixed)]);
  out.push('按语言：', '', table(['语言', 'Precision', 'Recall', 'F1', 'Recall_mixed'], pRows(q.by_language)));
  out.push('按来源数据集：', '', table(['来源', 'Precision', 'Recall', 'F1', 'Recall_mixed'], pRows(q.by_dataset)));
  if (q.by_label_policy) out.push('按标注口径：', '', table(['口径', 'Precision', 'Recall', 'F1', 'Recall_mixed'], pRows(q.by_label_policy)));

  out.push('## 成本', '');
  const t = s.cost.total;
  out.push(table(['输入 tokens', '输出 tokens', '缓存 tokens', '墙钟（秒）', '模型（秒）', '费用'], [[t.tokens_in, t.tokens_out, t.tokens_cached, (t.wall_ms / 1000).toFixed(1), (t.model_ms / 1000).toFixed(1), costText(t)]]));
  out.push('按场景：', '', table(['场景', 'tokens', '墙钟（秒）', '费用'], Object.entries(s.cost.by_scene).map(([k, v]) => [k, v.tokens_in + v.tokens_out + v.tokens_cached, (v.wall_ms / 1000).toFixed(1), costText(v)])));
  out.push('按步骤：', '', table(['步骤', 'tokens', '调用', '费用'], Object.entries(s.cost.by_step).map(([k, v]) => [k, v.tokens_in + v.tokens_out + v.tokens_cached, v.calls, costText(v)])));
  out.push(`每个真阳性的成本：${s.cost.cost_per_tp ? `${s.cost.cost_per_tp.usd.toFixed(4)} USD${s.cost.cost_per_tp.partial ? '（部分调用无单价，偏低）' : ''}` : '不适用'}`, '');

  const st = s.stages;
  if (st && Object.keys(st.by_stage).length) {
    out.push('## 阶段遥测', '');
    out.push(`带会话遥测的审计：${st.audits_with_telemetry}。步骤耗时为各步骤时长之和（同阶段步骤并行，不等于墙钟）；峰值上下文为单次模型请求的输入 + 缓存 tokens。`, '');
    const k = (n: number | null) => (n === null ? '-' : `${(n / 1000).toFixed(1)}k`);
    // Older records without stage telemetry have no step times or finding counts: shown as “-”, not 0.
    const timed = st.audits_with_telemetry > 0;
    out.push(table(['阶段', '步骤（失败）', '步骤耗时（分）', '最长（分）', '发现', '会话（子代理）', '峰值上下文 中位 / 最大', '压缩'], Object.entries(st.by_stage).map(([name, v]) => [
      name, `${v.steps}（${v.failed}）`, timed ? (v.step_ms / 60000).toFixed(1) : '-', timed ? (v.longest_ms / 60000).toFixed(1) : '-', timed ? v.findings : '-', `${v.sessions}（${v.task_sessions}）`, `${k(v.peak_context_median)} / ${k(v.peak_context_max)}`, v.compactions,
    ])));
    const sections = [...new Set(Object.values(st.by_stage).flatMap((v) => Object.keys(v.prompt_chars)))].sort();
    if (sections.length) out.push('开场内容（主会话平均字符数）：', '', table(['阶段', ...sections], Object.entries(st.by_stage).filter(([, v]) => Object.keys(v.prompt_chars).length).map(([name, v]) => [name, ...sections.map((x) => v.prompt_chars[x] ?? 0)])));
    if (st.push.length) out.push('推送使用率（推送进提示的条目中，在工具调用里被引用的比例）：', '', table(['类型', '推送', '被引用', '比例'], st.push.map((p) => [p.kind, p.pushed, p.referenced, pct(p.rate)])));
    out.push(`义务完成率（覆盖账本中有结论的单元）：${st.obligations.concluded}/${st.obligations.tracked}（${pct(st.obligations.rate)}）`, '');
  }

  out.push('## 稳定性', '');
  out.push(`平均 Jaccard：${num(s.stability.mean_jaccard)}`, '');
  const v = s.stability.variation;
  out.push(table(['指标', '各次', '标准差', '极差'], [
    ['Precision', v.precision.values.map((x) => pct(x)).join(' / '), num(v.precision.std), num(v.precision.range)],
    ['Recall', v.recall.values.map((x) => pct(x)).join(' / '), num(v.recall.std), num(v.recall.range)],
    ['F1', v.f1.values.map((x) => num(x)).join(' / '), num(v.f1.std), num(v.f1.range)],
    ['费用 USD', v.cost_usd.values.map((x) => num(x, 4)).join(' / '), num(v.cost_usd.std, 4), num(v.cost_usd.range, 4)],
  ]));
  out.push('不稳定发现：', '', table(['样本', '键', '出现次数', '是否命中'], s.stability.unstable_findings.map((u) => [u.sample_id, u.key, `${u.present_in}/${u.runs}`, u.hit ? '是' : '否'])));

  out.push('## 风险排查', '');
  const r = s.risk_hunt;
  out.push(table(['目标', '结论正确率', '受影响位置 Recall', '“不受影响”理由类型正确率', '理由证据核实率'], [[r.targets, pct(r.accuracy), pct(r.location_recall), pct(r.not_affected_reason.type_accuracy), pct(r.not_affected_reason.evidence_ok_rate)]]));
  out.push(confusion(r.confusion, ['affected', 'not_affected', 'pending', 'missing']));

  out.push('## 复验', '');
  const rv = s.reverify;
  out.push(table(['步骤', '正确率', '明确率', '错误放行率'], [[rv.steps, pct(rv.accuracy), pct(rv.definite_rate), pct(rv.false_release_rate)]]));
  out.push(confusion(rv.confusion, ['fixed', 'still_present', 'partially_fixed', 'regressed', 'undetermined', 'no_verdict', 'not_run', 'base_missed']));

  const inc = s.incremental;
  if (inc?.runs) {
    out.push('## 增量审计（G5）', '');
    out.push('同一次运行先对基线版本做全量审计，再对变更做增量审计；比值 = 增量 / 全量。', '');
    out.push(table(['运行（完成 / 成对）', 'Precision', 'Recall', 'tokens 比', '费用比', '墙钟比'], [[`${inc.runs}（${inc.completed} / ${inc.pairs}）`, pct(inc.precision), pct(inc.recall), num(inc.token_ratio), inc.usd_ratio === null ? '不适用' : num(inc.usd_ratio), num(inc.wall_ratio)]]));
    out.push(table(['样本', '成对运行', 'tokens 比', '墙钟比'], Object.entries(inc.per_sample).map(([k, v]) => [k, v.runs, num(v.token_ratio), num(v.wall_ratio)])));
  }
  out.push('## 漏洞身份匹配', '');
  const id = s.identity;
  const idRow = (k: string, m: typeof id) => [k, m.pairs, m.undetected, pct(m.exact_precision), pct(m.exact_coverage), pct(m.suspected_precision), pct(m.suspected_recall), pct(m.false_merge_rate), pct(m.false_split_rate)];
  out.push(table(['重构类型', '成对', '未检出', '确定匹配 P', '确定匹配覆盖', '疑似 P', '疑似 R', '错误合并率', '错误拆分率'], [idRow('全部', id), ...Object.entries(id.by_refactor).map(([k, m]) => idRow(k, m as typeof id))]));

  out.push('## 待裁定', '');
  const known = s.adjudication.filter((x) => x.label_policy === 'known_only').length;
  out.push(`${s.adjudication.length} 条未被标注的发现进入待裁定队列（adjudication.yaml），不计为误报。完整标注的样本：人工判定后回写标注并递增 manifest 版本${known ? `；只标注已知漏洞的样本（${known} 条）：判定写入 bench/adjudication/<项目>.yaml，不改标注` : ''}。`, '');
  return out.join('\n');
}

function confusion(m: Record<string, Record<string, number>>, cols: string[]): string {
  const rows = Object.keys(m).sort().map((exp) => [exp, ...cols.map((c) => m[exp]![c] ?? 0)]);
  return rows.length ? `期望 \\ 实际：\n\n${table(['期望', ...cols], rows)}` : '（无样本）\n';
}

export function renderExperiment(e: ExperimentResult): string {
  const out: string[] = [];
  const id = e.identity;
  out.push(`# 对比实验：${id.experiment}`, '');
  out.push(table(['项', '值'], [
    ['配置哈希', id.config_sha256.slice(0, 16)], ['被测代码', `${id.code.revision ?? '未知'}${id.code.dirty ? '（有未提交改动）' : ''}`],
    ['基准版本 / 分区', `${id.bench_version} / ${id.partition}`], ['pi', id.pi_version], ['模型', `${id.models.default ?? '-'} / ${id.models.cheap ?? '-'}`],
    ['重复次数', id.repeats], ['bootstrap', `${id.bootstrap.resamples} 次，种子 ${id.bootstrap.seed}`],
    ['费用上限 / 已用', `${e.cost_limit ?? '未设'} / ${e.spent_usd.toFixed(4)} USD`],
  ]));
  out.push('## 各组指标', '');
  out.push(table(['组', '变量', 'Precision', 'Recall', 'F1', 'Recall_mixed', 'F1_mixed', '完成率', '费用 USD', '无单价调用'], e.arms.map((a) => [
    a.name, a.variable ?? '（基线）', precisionText(a.metrics), pct(a.metrics.recall), num(a.metrics.f1), pct(a.metrics.recall_mixed), num(a.metrics.f1_mixed), pct(a.completion_rate), num(a.cost_usd, 4), a.unknown_price_calls,
  ])));
  for (const c of e.comparisons) {
    out.push(`## ${c.variant} 对比基线（${c.variable}）`, '');
    out.push(`样本 ${c.samples} 个，标注 ${c.labels} 条。`, '');
    const mrow = (name: string, m: Omit<typeof c.primary, 'metric'>) => [name, num(m.baseline), num(m.variant), num(m.diff), m.ci95 ? `[${num(m.ci95[0])}, ${num(m.ci95[1])}]` : '不适用', `${m.conclusion}（方向：${m.direction}）`];
    out.push(table(['指标', '基线', '变体', '差值', '95% CI', '结论'], [mrow(`${c.primary.metric}（主）`, c.primary), ...Object.entries(c.guards).map(([k, g]) => mrow(`${k}（守护）`, g))]));
    out.push(`McNemar：基线独有检出 ${c.mcnemar.b}，变体独有检出 ${c.mcnemar.c}，${c.mcnemar.method === 'none' ? '无不一致对' : `p = ${num(c.mcnemar.p, 4)}（${c.mcnemar.method === 'exact' ? '精确二项' : 'χ² 连续性校正'}）`}`, '');
    out.push(`逐样本：胜 ${c.paired.wins.length}，负 ${c.paired.losses.length}，平 ${c.paired.ties.length}。`, '');
    out.push('负样本：', '', table(['样本', '差值（命中 − 误报 − 重复）'], c.paired.losses.map((l) => [l.sample_id, num(l.delta)])));
    out.push('检出变化：', '', table(['样本', '标注', '变化'], c.mcnemar.flips.map((f) => [f.sample_id, f.label_id, f.change === 'lost' ? '变为漏检' : '新增检出'])));
    out.push('按类别 Recall：', '', table(['类别', '标注', '基线', '变体', '差值', '结论'], Object.entries(c.by_category).map(([k, v]) => [k, v.labels, pct(v.baseline), pct(v.variant), num(v.diff), `${v.conclusion}（方向：${v.direction}）`])));
    out.push(table(['费用差 USD', '新增真阳性', '每新增真阳性边际成本', '稳定性（基线 / 变体）', '完成率（基线 / 变体）'], [[
      `${num(c.cost.diff_usd, 4)}${c.cost.unknown_prices ? '（含无单价调用）' : ''}`, num(c.cost.tp_diff, 2), num(c.cost.marginal_usd_per_new_tp, 4),
      `${num(c.stability.baseline_jaccard)} / ${num(c.stability.variant_jaccard)}`, `${pct(c.availability.baseline_completion)} / ${pct(c.availability.variant_completion)}`,
    ]]));
    out.push(`**建议**：${c.recommendation}`, '');
  }
  return out.join('\n');
}
