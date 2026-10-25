// Audit results: findings of this audit, completion gate, usage, exports; coverage
// comparison (entries / sinks, uncovered list) and backfill of uncovered targets.
import { useEffect, useState } from 'react';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { AuditDetailDto, ExportDto, KnowledgeUsageDto, ModelRef } from '@xiezhi/contracts';
import { api, newIdempotencyKey } from '../../shared/api/client';
import { useAiReportDefaults, useCoverage, useCoverageItems, useExport, useExportPreview, useExports, useFindings, useKnowledge, useProviders, useUsage } from '../../shared/api/queries';
import { Markdown } from '../../shared/markdown/Markdown';
import { CONFIDENCE, LIFECYCLE, PARTIAL_REASON, REVERIFY_VERDICT, STEP_KIND, categoryLabel, fmt, gateCheckText, reasonsLabel } from '../../shared/format/messages';
import {
  AuditStatusBadge, Badge, Button, ConfirmBadge, Dialog, EmptyState, Field, Icon, LifecycleBadge, Loading, Progress, Segmented, SeverityBadge, cx, ui, useToast,
} from '../../shared/ui';
import A from './audits.module.css';
import { CoverageItemsTable } from './CoverageItems';
import { AnalysesPanel, HypothesesSection, NoCoverageCompare, ThreatHypothesesCoverage } from './Hypotheses';

const TERMINALISH = ['completed', 'partial', 'failed', 'cancelled', 'waiting_budget', 'paused', 'interrupted'];

const PHASE: Record<string, string> = { generating: '报告模型正在撰写', verifying: '正在核对编号、严重度与确认状态', repairing: '发现不一致，正在让模型修正' };
const THINK: Record<string, string> = { off: '关', low: '低', medium: '中', high: '高' };
const refKey = (m: ModelRef | null | undefined) => (m ? `${m.provider}/${m.model}` : '');

/** One line for an export in the history: format, how it was made, the model. */
function exportLabel(x: ExportDto): string {
  return [x.format.toUpperCase(), x.mode === 'ai' ? `AI 生成 · ${x.model ?? ''}` : '按模板填充', x.reportSkill ? `报告 skill ${x.reportSkill}` : ''].filter(Boolean).join(' · ');
}

/** The report model of an AI report: what it is, where it comes from, its fallback; changeable for this export. */
function ReportModelBox({ aid, snippets, includePending, picked, value, onChange }: {
  aid: string; snippets: boolean; includePending: boolean; picked: boolean; value: ModelRef | null; onChange: (m: ModelRef | null) => void;
}) {
  const d = useAiReportDefaults(aid, { snippets, includePending }, true);
  const providers = useProviders();
  const [changing, setChanging] = useState(false);
  if (!d.data) return <Loading rows={2} />;
  const all = (providers.data ?? []).flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`));
  const cur = value ?? d.data.model;
  return (
    <div className={A.reportModel} aria-label="报告模型">
      <div className={ui.spread}>
        <div>
          <b className={ui.mono}>{refKey(cur)}</b>
          <span className={ui.faint}> · 思考强度 {THINK[cur.thinking ?? ''] ?? '默认'}</span>
          <div className={ui.faint} style={{ fontSize: 12 }}>
            {value ? '仅本次导出更换' : d.data.source === 'report_stage' ? '来自本次审计的“报告”阶段（默认取自 设置 › 模型）' : '报告阶段未单独设置，跟随领域审计的模型'}
            {' · '}{!d.data.fallback ? '未设置备用模型' : refKey(d.data.fallback) === refKey(cur) ? '备用模型与当前模型相同，不切换' : `备用 ${refKey(d.data.fallback)}`}
          </div>
        </div>
        <Button size="sm" variant="ghost" onClick={() => { if (changing) onChange(null); setChanging(!changing); }}>{changing ? '恢复默认' : '更换（仅本次）'}</Button>
      </div>
      {changing && (
        <div className={ui.row} style={{ marginTop: 8 }}>
          <select aria-label="报告模型" className={ui.select} value={refKey(cur)} onChange={(e) => { const x = e.target.value; const i = x.indexOf('/'); onChange({ provider: x.slice(0, i), model: x.slice(i + 1), ...(cur.thinking ? { thinking: cur.thinking } : {}) }); }}>
            {all.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <select aria-label="报告思考强度" className={ui.select} style={{ width: 110 }} value={cur.thinking ?? ''} onChange={(e) => { const { thinking: _, ...rest } = cur; const t = e.target.value as NonNullable<ModelRef['thinking']> | ''; onChange(t ? { ...rest, thinking: t } : rest); }}>
            <option value="">思考：默认</option>
            {Object.entries(THINK).map(([k, l]) => <option key={k} value={k}>思考：{l}</option>)}
          </select>
        </div>
      )}
      <div className={ui.faint} style={{ fontSize: 12, marginTop: 6 }}>
        预计约 {fmt.tokens(d.data.estimate.tokens)} tokens（{d.data.estimate.conclusions} 条结论{picked ? '，按全部发现估算' : ''}；校验不一致时最多再写一次）
      </div>
    </div>
  );
}

/** A finished AI report: the check, a preview, regenerate and download. */
function AiResult({ x, onRegenerate }: { x: ExportDto; onRegenerate: () => void }) {
  const [preview, setPreview] = useState(false);
  const p = useExportPreview(preview ? x.id : null);
  const v = x.verification;
  return (
    <div className={ui.stack} style={{ gap: 8 }}>
      {v && (v.ok
        ? <div className={ui.banner} style={{ background: 'var(--ok-soft, var(--bg-hover))', color: 'var(--ok)' }}><Icon name="checkCircle" />校验通过：结论的编号、严重度与确认状态与审计记录一致{v.rounds > 1 ? `（第一次有 ${v.firstIssues.length} 处不一致，已修正）` : ''}</div>
        : <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)', alignItems: 'flex-start' }}><Icon name="alert" /><div>校验未通过（已让模型修正一次）：报告顶部列出了不一致之处，末尾附程序生成的事实清单。<ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>{v.issues.slice(0, 5).map((i) => <li key={i}>{i}</li>)}</ul>{v.issues.length > 5 && `…共 ${v.issues.length} 处`}</div></div>)}
      <div className={ui.faint} style={{ fontSize: 12 }}>{x.model}{v?.fallbackFrom ? `（${v.fallbackFrom} 不可用，已改用备用模型）` : ''} · {fmt.tokens(x.tokens)} tokens</div>
      <div className={cx(ui.row, ui.wrap)}>
        <a className={cx(ui.btn, ui.primary)} href={`/api/v1/exports/${x.id}/download`} download={x.fileName}><Icon name="download" />下载 {x.format === 'md' ? 'Markdown' : 'HTML'}</a>
        <Button icon="eye" onClick={() => setPreview(!preview)}>{preview ? '收起预览' : '预览'}</Button>
        <Button icon="refresh" onClick={onRegenerate}>重新生成</Button>
      </div>
      {preview && <div className={A.reportPreview}>{p.data ? <Markdown text={p.data.markdown} /> : <Loading rows={4} />}</div>}
    </div>
  );
}

export function ExportDialog({ audit, open, onClose }: { audit: AuditDetailDto; open: boolean; onClose: () => void }) {
  const [format, setFormat] = useState<'md' | 'html' | 'json' | 'sarif'>('html');
  /** `ai` = the report model writes the report (Markdown / HTML only). */
  const [mode, setMode] = useState<'template' | 'ai'>('template');
  const [model, setModel] = useState<ModelRef | null>(null);
  const [snippets, setSnippets] = useState(true);
  const [localRoots, setLocalRoots] = useState(true);
  const [reportSkill, setReportSkill] = useState('');
  const [includePending, setIncludePending] = useState(true);
  const [trajectory, setTrajectory] = useState(false);
  /** null = every finding of the audit; a set = only these vulnerabilities. */
  const [picked, setPicked] = useState<Set<string> | null>(null);
  const found = useFindings(audit.id);
  const vulns = [...new Map((found.data ?? []).filter((f) => f.state === 'canonical' && f.vulnId).map((f) => [f.vulnId!, f])).values()];
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<ExportDto | null>(null);
  const job = useExport(done?.mode === 'ai' ? done.id : null);
  const cur = done?.mode === 'ai' ? job.data ?? done : done;
  const exports = useExports(audit.id);
  const skills = useKnowledge(audit.projectId);
  const reportSkills = (skills.data ?? []).filter((s) => s.valid && !s.disabled && s.category === 'report' && !(s.layer === 'global' && s.overriddenBy.includes(audit.projectId)));
  const qc = useQueryClient();
  const toast = useToast();
  const ai = mode === 'ai' && (format === 'md' || format === 'html');
  const running = cur?.status === 'running';
  useEffect(() => { if (cur && cur.mode === 'ai' && cur.status !== 'running') void qc.invalidateQueries({ queryKey: ['audit', audit.id, 'exports'] }); }, [cur?.status]);
  const reset = () => setDone(null);
  const run = async () => {
    setBusy(true);
    try {
      const r = await api.post<ExportDto>('/exports', {
        scope: 'audit', ids: [audit.id], format, snippets, ...(format === 'sarif' ? { localRoots } : {}), ...(reportSkill ? { reportSkill } : {}),
        ...(picked ? { vulnIds: [...picked] } : {}), ...(includePending ? {} : { includePending: false }), ...(trajectory && format !== 'sarif' && !ai ? { trajectory: true } : {}),
        ...(ai ? { mode: 'ai', ...(model ? { model } : {}) } : {}),
      }, { idempotencyKey: newIdempotencyKey() });
      setDone(r);
      if (r.status === 'failed') toast.error(new Error('渲染失败'), '导出失败');
    } catch (e) { toast.error(e, '导出失败'); }
    setBusy(false);
    await qc.invalidateQueries({ queryKey: ['audit', audit.id, 'exports'] });
  };
  const can = TERMINALISH.includes(audit.status);
  const close = () => { setDone(null); onClose(); };
  return (
    <Dialog open={open} onClose={close} title="导出报告" footer={<>
      <Button onClick={close}>关闭</Button>
      <Button variant="primary" icon={ai ? 'sparkle' : 'download'} loading={busy || running} disabled={!can || running || (picked !== null && picked.size === 0)} onClick={() => void run()}>{ai ? 'AI 生成' : '生成'}</Button>
    </>}>
      {!can && <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)' }}>审计停止后才能导出。</div>}
      <Segmented value={format} onChange={(f) => { setFormat(f); reset(); }} items={[{ key: 'html', label: 'HTML' }, { key: 'md', label: 'Markdown' }, { key: 'json', label: 'JSON' }, { key: 'sarif', label: 'SARIF' }]} />
      <p className={ui.muted} style={{ fontSize: 13 }}>
        {format === 'sarif' ? 'SARIF 2.1.0：可导入 VS Code / JetBrains 定位代码。' : format === 'json' ? '结构化主格式，带 schemaVersion。' : '单文件报告，内联样式、不含脚本；被审代码中的密钥默认掩码。'}
      </p>
      {(format === 'md' || format === 'html') && (
        <Field group label="生成方式">
          <Segmented value={mode} onChange={(m) => { setMode(m); reset(); }} items={[{ key: 'template', label: '按模板填充' }, { key: 'ai', label: 'AI 生成' }]} />
          <div className={ui.faint} style={{ fontSize: 12, marginTop: 6 }}>
            {ai ? '报告模型按所选报告 skill 写整份报告；程序核对每条结论的编号、严重度与确认状态，不一致时让模型修正一次。' : '程序按固定结构填充，不调用模型，结果可重复。'}
          </div>
        </Field>
      )}
      {ai && <ReportModelBox aid={audit.id} snippets={snippets} includePending={includePending} picked={picked !== null} value={model} onChange={(m) => { setModel(m); reset(); }} />}
      <Field group label="范围">
        <Segmented value={picked ? 'picked' : 'all'} onChange={(v) => { setPicked(v === 'all' ? null : new Set(vulns.map((f) => f.vulnId!))); reset(); }}
          items={[{ key: 'all', label: '本次审计的全部发现' }, { key: 'picked', label: '只导出选中的漏洞' }]} />
        {picked && (
          <div className={ui.stack} style={{ gap: 4, marginTop: 8, maxHeight: 180, overflowY: 'auto' }}>
            {vulns.length === 0 && <span className={ui.faint}>本次审计没有关联到漏洞的发现</span>}
            {vulns.map((f) => (
              <label key={f.vulnId} className={ui.checkbox}>
                <input type="checkbox" checked={picked.has(f.vulnId!)} onChange={(e) => { const n = new Set(picked); if (e.target.checked) n.add(f.vulnId!); else n.delete(f.vulnId!); setPicked(n); reset(); }} />
                <SeverityBadge severity={f.severity} /> V-{f.vulnDisplayNo} {f.title}
              </label>
            ))}
          </div>
        )}
      </Field>
      <label className={ui.checkbox}><input type="checkbox" checked={includePending} onChange={(e) => { setIncludePending(e.target.checked); reset(); }} />包含待确认项与证据不足项</label>
      {format !== 'sarif' && !ai && <label className={ui.checkbox}><input type="checkbox" checked={trajectory} onChange={(e) => { setTrajectory(e.target.checked); reset(); }} />附带行为轨迹摘要（每个步骤的状态、耗时、tokens、调用数与 Agent 的首条说明）</label>}
      <label className={ui.checkbox}><input type="checkbox" checked={snippets} onChange={(e) => { setSnippets(e.target.checked); reset(); }} />{ai ? '把代码片段交给报告模型（关闭时模型只看到位置与结论）' : '包含代码片段'}</label>
      {(format === 'md' || ai) && reportSkills.length > 0 && (
        <Field label="报告 skill" hint={ai ? '模型按这个 skill 的结构、读者与语气写报告；不选时用设置中的默认值' : '报告 skill 的模板只调整章节顺序与标题，不改变任何结论；不选时使用设置中的默认值'}>
          <select aria-label="报告 skill" className={ui.input} value={reportSkill} onChange={(e) => { setReportSkill(e.target.value); reset(); }}>
            <option value="">默认</option>
            {reportSkills.map((s) => <option key={`${s.layer}:${s.name}`} value={s.name}>{s.name}{s.layer === 'project' ? '（项目）' : ''}</option>)}
          </select>
        </Field>
      )}
      {format === 'sarif' && <label className={ui.checkbox}><input type="checkbox" checked={localRoots} onChange={(e) => setLocalRoots(e.target.checked)} />写入本机绝对路径（便于本机 IDE 直接定位；分享给同事时取消）</label>}
      {format === 'sarif' && <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)' }}><Icon name="alert" />SARIF 保留被审代码原文，文件可能包含代码中的明文密钥。</div>}
      {cur?.status === 'running' && (
        <div className={ui.banner} role="status" style={{ background: 'var(--accent-soft)', color: 'var(--accent-text)' }}>
          <span className={ui.spinner} />{PHASE[cur.progress ?? 'generating']}…{cur.tokens ? ` 已用 ${fmt.tokens(cur.tokens)} tokens` : ''}
        </div>
      )}
      {cur?.status === 'failed' && cur.mode === 'ai' && <div className={ui.banner} style={{ background: 'var(--danger-soft)', color: 'var(--danger)' }}><Icon name="alert" />AI 生成失败：{cur.error ?? '未知原因'}</div>}
      {cur?.status === 'succeeded' && cur.mode === 'ai' && <AiResult x={cur} onRegenerate={() => void run()} />}
      {cur?.status === 'succeeded' && cur.mode !== 'ai' && (
        <a className={cx(ui.btn, ui.primary)} href={`/api/v1/exports/${cur.id}/download`} download={cur.fileName}><Icon name="download" />下载 {cur.fileName}（{fmt.n(cur.bytes)} 字节）</a>
      )}
      {exports.data && exports.data.length > 0 && (
        <div>
          <div className={ui.faint} style={{ fontSize: 12, marginBottom: 6 }}>历史导出</div>
          {exports.data.slice(0, 5).map((x) => (
            <div key={x.id} className={ui.spread} style={{ fontSize: 13, padding: '4px 0' }}>
              <span>{exportLabel(x)} · {fmt.date(x.createdAt)}{x.mode === 'ai' && x.verification && !x.verification.ok ? ' · 校验未通过' : ''}</span>
              {x.status === 'succeeded' ? <a href={`/api/v1/exports/${x.id}/download`} download={x.fileName}>下载</a> : x.status === 'running' ? <span className={ui.faint}>生成中</span> : <span className={ui.faint}>失败</span>}
            </div>
          ))}
        </div>
      )}
    </Dialog>
  );
}

export function ResultsView({ audit, onVuln }: { audit: AuditDetailDto; onVuln: (vid: string) => void }) {
  const f = useFindings(audit.id);
  const usage = useUsage(audit.id, 'step');
  const [showIns, setShowIns] = useState(false);
  const gate = audit.gate;
  const main = (f.data ?? []).filter((x) => x.state === 'canonical');
  const insufficient = (f.data ?? []).filter((x) => x.state === 'insufficient');
  // Findings the hunt submitted, not merged (yet): on a large repository the merge comes an hour or more after the first
  // one, and “暂无发现” meanwhile contradicted the trajectory and the domain plan. A paused or cancelled
  // audit keeps them unmerged.
  const pending = (f.data ?? []).filter((x) => x.state === 'submitted');
  const unknownCalls = (usage.data ?? []).reduce((n, r) => n + r.unknownCostCalls, 0);
  return (
    <div className={ui.stack} style={{ gap: 20 }}>
      {gate && (
        <div className={cx(ui.card, ui.cardPad)}>
          <div className={ui.spread}>
            <div className={ui.row}><Icon name="checkCircle" /><b>完成闸门</b>
              <Badge tone={gate.status === 'completed' ? 'ok' : gate.status === 'partial' ? 'warn' : 'danger'}>{gate.status === 'completed' ? '完整' : gate.status === 'partial' ? '部分完成' : '失败'}</Badge></div>
            {gate.coverage && <span className={ui.faint} style={{ fontSize: 12 }}>入口 {gate.coverage.entry.reviewed}/{gate.coverage.entry.total} · 危险点 {gate.coverage.sink.reviewed}/{gate.coverage.sink.total}</span>}
          </div>
          {gate.partialReasons.length > 0 && <div className={cx(ui.row, ui.wrap)} style={{ marginTop: 10 }}><span className={ui.faint} style={{ fontSize: 12 }}>{reasonsLabel(gate.status)}：</span>{gate.partialReasons.map((r) => <Badge key={r} tone="warn">{PARTIAL_REASON[r] ?? r}</Badge>)}</div>}
          {gate.notices?.length ? <ul className={ui.faint} style={{ fontSize: 12, marginTop: 8, paddingLeft: 18 }}>{gate.notices.map((n) => <li key={n}>提示：{n}</li>)}</ul> : null}
          <div className={A.checks}>{gate.checks.map((c) => <div key={c.name} className={ui.row}><span style={{ color: c.ok ? 'var(--ok)' : 'var(--warn)' }}><Icon name={c.ok ? 'check' : 'alert'} size={14} /></span><span className={ui.muted} style={{ fontSize: 13 }}>{gateCheckText(c)}</span></div>)}</div>
          {gate.status !== 'completed' && <p className={ui.faint} style={{ fontSize: 12, marginTop: 8 }}>未完整结束的审计，结论不能视为“完整审计”或“代码安全”。</p>}
          {gate.status === 'completed' && gate.partialReasons.length > 0 && <p className={ui.faint} style={{ fontSize: 12, marginTop: 8 }}>主线已跑通，过程问题不影响完成。在“执行轨迹”的状态栏点击带 ! 的环节可定位失败或跳过的步骤；需要时在“覆盖”页补审未覆盖项、追加执行，或重新审计。</p>}
        </div>
      )}
      {audit.reverify && (
        <div>
          <div className={ui.spread} style={{ marginBottom: 10 }}><b>复验结论（{audit.reverify.filter((x) => x.verdict).length}/{audit.reverify.length}）</b></div>
          <div className={ui.card} style={{ overflow: 'auto' }}>
            <table className={ui.table} aria-label="复验结论">
              <thead><tr><th>漏洞</th><th>严重度</th><th>标题</th><th>结论</th><th>跨审计状态</th><th>依据</th></tr></thead>
              <tbody>{audit.reverify.map((x) => (
                <tr key={x.vulnId} className={ui.rowLink} onClick={() => onVuln(x.vulnId)}>
                  <td className={ui.mono}>V-{x.displayNo}</td>
                  <td><SeverityBadge severity={x.severity} /></td>
                  <td>{x.title}<div className={ui.faint}>{categoryLabel(x.category)}</div></td>
                  <td>{x.verdict ? <Badge tone={x.verdict === 'fixed' ? 'ok' : x.verdict === 'undetermined' ? 'neutral' : 'danger'}>{REVERIFY_VERDICT[x.verdict]}</Badge> : <span className={ui.faint}>进行中</span>}</td>
                  <td>{x.lifecycleAfter ? <>{LIFECYCLE[x.lifecycleBefore ?? ''] ?? '—'} → <b>{LIFECYCLE[x.lifecycleAfter]}</b></> : '—'}</td>
                  <td className={ui.muted} style={{ maxWidth: 360 }}>{x.reasoning ?? ''}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </div>
      )}
      {!audit.reverify && <div>
        <div className={ui.spread} style={{ marginBottom: 10 }}><b>本次发现（{main.length}）</b></div>
        {f.isLoading ? <Loading /> : main.length === 0 ? (
          <div className={ui.card}><EmptyState icon="shield" title={TERMINALISH.includes(audit.status) ? '没有正式发现' : pending.length ? '还没有归并后的正式发现' : '暂无发现'}>{TERMINALISH.includes(audit.status) ? '“没有发现”不等于“没有漏洞”，请结合覆盖对照判断。' : pending.length ? `追查已提交 ${pending.length} 条，列在下方；归并时去重、复核后成为正式发现。` : '分析进行中，发现会实时出现在这里。'}</EmptyState></div>
        ) : (
          <div className={ui.card} style={{ overflow: 'auto' }}>
            <table className={ui.table}>
              <thead><tr><th>编号</th><th>严重度</th><th>标题</th><th>置信度</th><th>确认</th><th>跨审计</th><th>位置</th></tr></thead>
              <tbody>{main.map((x) => (
                <tr key={x.id} className={ui.rowLink} onClick={() => x.vulnId && onVuln(x.vulnId)}>
                  <td className={ui.mono}>F-{x.displayNo}{x.vulnDisplayNo ? <div className={ui.faint}>V-{x.vulnDisplayNo}</div> : null}</td>
                  <td><SeverityBadge severity={x.severity} /></td>
                  <td style={{ maxWidth: 320 }}><div className={ui.ellipsis}>{x.title}</div><div className={ui.faint} style={{ fontSize: 12 }}>{categoryLabel(x.category)}{x.cwe ? ` · ${x.cwe}` : ''}</div></td>
                  <td>{CONFIDENCE[x.confidence]}</td>
                  <td>{x.confirmStatus ? <ConfirmBadge status={x.confirmStatus} /> : '—'}</td>
                  <td>{x.lifecycle ? <LifecycleBadge status={x.lifecycle} /> : '—'}</td>
                  <td className={ui.mono} style={{ fontSize: 12, whiteSpace: 'nowrap' }} title={fmt.loc(x.location)}>{x.location.path.split('/').pop()}:{x.location.startLine}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
        {pending.length > 0 && (
          <div style={{ marginTop: 12 }} data-testid="pending-findings">
            <div className={ui.faint} style={{ fontSize: 12, marginBottom: 4 }}>追查中提交、未归并（{pending.length}）：归并会合并重复项，复核可能改判；以正式发现为准</div>
            {pending.map((x) => <div key={x.id} className={ui.row} style={{ padding: '6px 4px', fontSize: 13 }}><SeverityBadge severity={x.severity} /><span className={ui.grow}>{x.title}</span><span className={cx(ui.mono, ui.faint)}>{fmt.loc(x.location)}</span></div>)}
          </div>
        )}
        {insufficient.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <button className={A.more} onClick={() => setShowIns(!showIns)}><Icon name={showIns ? 'chevronDown' : 'chevronRight'} />证据不足（{insufficient.length}，不计入正式结论）</button>
            {showIns && insufficient.map((x) => <div key={x.id} className={ui.row} style={{ padding: '6px 4px', fontSize: 13 }}><SeverityBadge severity={x.severity} /><span className={ui.grow}>{x.title}</span><span className={cx(ui.mono, ui.faint)}>{fmt.loc(x.location)}</span></div>)}
          </div>
        )}
      </div>}
      <div>
        <b>用量</b>
        <div className={ui.card} style={{ marginTop: 10, overflow: 'auto' }}>
          <table className={ui.table}>
            <thead><tr><th>环节</th><th>次数</th><th>输入</th><th title="命中提示缓存的输入：不在“输入”里，计入预算">缓存输入</th><th>输出</th><th>合计</th><th>成本</th></tr></thead>
            {/* The rows summed to 530万 under a header of 4703万 — cached input (90%) was not shown. */}
            <tbody>{(usage.data ?? []).map((r) => <tr key={r.key}><td>{STEP_KIND[r.key] ?? r.key}</td><td>{r.calls}</td><td>{fmt.tokens(r.tokensIn)}</td><td>{fmt.tokens(r.tokensCached)}</td><td>{fmt.tokens(r.tokensOut)}</td><td>{fmt.tokens(r.tokensIn + r.tokensCached + r.tokensOut)}</td><td>{fmt.cost(r.unknownCostCalls ? null : r.costMicros)}</td></tr>)}</tbody>
          </table>
        </div>
        {unknownCalls > 0 && <p className={ui.faint} style={{ fontSize: 12, marginTop: 6 }}>有 {unknownCalls} 个步骤的模型未配置价格，成本记为“未知”（可在 设置 › 通用 › 价格表 中配置）。</p>}
      </div>
      <HypothesesSection aid={audit.id} onVuln={onVuln} />
      <KnowledgeUsage aid={audit.id} />
    </div>
  );
}

const LEVEL: Record<string, string> = { index: '只在索引中', body: '读取正文', file: '读取子文件' };

/** Knowledge used by this audit (加载透明). */
function KnowledgeUsage({ aid }: { aid: string }) {
  const q = useQuery({ queryKey: ['audit', aid, 'knowledge-usage'], queryFn: () => api.get<KnowledgeUsageDto>(`/audits/${aid}/knowledge-usage`) });
  const loaded = (q.data?.items ?? []).filter((k) => k.maxLevel !== 'index');
  if (!q.data || !q.data.items.length) return null;
  return (
    <div>
      <b>本次用到的知识</b>
      <p className={ui.faint} style={{ fontSize: 12, margin: '4px 0 0' }}>
        索引中出现 {q.data.items.length} 条，读取正文或子文件 {loaded.length} 条；知识占 {fmt.tokens(q.data.knowledgeTokens)} tokens{q.data.totalTokens ? `（本次共 ${fmt.tokens(q.data.totalTokens)}）` : ''}
        {q.data.citedShare !== null ? `；被结论引用的比例 ${Math.round(q.data.citedShare * 100)}%` : ''}。
      </p>
      {loaded.length > 0 && (
        <div className={ui.card} style={{ marginTop: 10, overflow: 'auto' }}>
          <table className={ui.table}>
            <thead><tr><th>skill</th><th>层</th><th>加载</th><th>次数</th><th>步骤</th><th>tokens</th><th>被结论引用</th></tr></thead>
            <tbody>{loaded.map((k) => <tr key={`${k.layer}:${k.name}`}><td className={ui.mono}>{k.name}</td><td>{k.layer === 'project' ? '项目' : '全局'}</td><td>{LEVEL[k.maxLevel] ?? k.maxLevel}</td><td>{k.reads}</td><td>{k.steps}</td><td>{fmt.tokens(k.tokens)}</td><td>{k.citedBy}</td></tr>)}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/** Compact coverage line for the audit page (“覆盖：order-svc 38/42 入口…”). */
export function CoverageStrip({ aid, live, onOpen }: { aid: string; live: boolean; onOpen: () => void }) {
  const c = useCoverage(aid, live);
  const hyp = (c.data?.repos ?? []).some((r) => r.hypothesis.total > 0);
  if ((!c.data?.enabled && !hyp) || !c.data || c.data.repos.length === 0) return null;
  return (
    <button className={A.covStrip} onClick={onOpen} title="打开覆盖对照">
      <Icon name="target" size={14} />
      <span>覆盖：</span>
      {c.data.repos.map((r) => (
        <span key={r.repoId} className={A.covStripRepo}>
          <b>{r.repo}</b>{c.data!.enabled ? ` 入口 ${r.entry.reviewed}/${r.entry.total} · 危险点 ${r.sink.reviewed}/${r.sink.total}` : ''}{r.hypothesis.total ? ` · 风险假设 ${r.hypothesis.reviewed}/${r.hypothesis.total}` : ''}{c.data!.enabled && r.sourceLines ? ` · 已读 ${Math.round((r.reading.readLines / r.sourceLines) * 100)}%` : ''}
        </span>
      ))}
    </button>
  );
}

export function CoverageView({ aid, finished, onVuln }: { aid: string; finished: boolean; onVuln?: (vid: string) => void }) {
  const c = useCoverage(aid);
  const [kind, setKind] = useState<'entry' | 'sink'>('entry');
  const items = useCoverageItems(aid, kind);
  const [onlyGaps, setOnlyGaps] = useState(true);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [key] = useState(newIdempotencyKey);
  const navigate = useNavigate();
  const toast = useToast();
  const backfill = async () => {
    setBusy(true);
    try {
      const r = await api.post<{ auditId: string }>(`/audits/${aid}/coverage/backfills`, picked.size ? { itemIds: [...picked] } : { all: true }, { idempotencyKey: `${key}-${[...picked].sort().join(',')}` });
      toast.ok('已开始补审');
      void navigate({ to: '/audits/$aid', params: { aid: r.auditId } });
    } catch (e) { toast.error(e, '无法补审'); }
    setBusy(false);
  };
  if (c.isLoading) return <Loading />;
  if (!c.data) return null;
  // risk hypotheses are a coverage dimension of their own; they show even without the entry / sink comparison.
  const extras = (
    <>
      <AnalysesPanel aid={aid} coverage={c.data} finished={finished} />
      <ThreatHypothesesCoverage aid={aid} finished={finished} supplementable={c.data.supplementable} enabled={c.data.analyses.threatHypotheses} {...(onVuln ? { onVuln } : {})} />
    </>
  );
  if (!c.data.enabled) return <div className={ui.stack} style={{ gap: 20 }}><NoCoverageCompare />{extras}</div>;
  const isGap = (s: string) => s !== 'concluded' && s !== 'excluded';
  const list = (items.data ?? []).filter((i) => !onlyGaps || isGap(i.status));
  const gaps = c.data.repos.reduce((n, r) => n + (r.entry.total - r.entry.reviewed) + (r.sink.total - r.sink.reviewed), 0);
  return (
    <div className={ui.stack} style={{ gap: 20 }}>
      <div className={A.covGrid}>
        {c.data.repos.map((r) => (
          <div key={r.repoId} className={cx(ui.card, ui.cardPad)}>
            <div className={ui.row} style={{ marginBottom: 12 }}><Icon name="git" /><b>{r.repo}</b></div>
            {(['entry', 'sink'] as const).map((k) => {
              const x = r[k];
              const pct = x.total ? x.reviewed / x.total : 1;
              return (
                <div key={k} style={{ marginBottom: 12 }}>
                  <div className={ui.spread} style={{ fontSize: 13, marginBottom: 4 }}><span>{k === 'entry' ? '入口覆盖' : '危险点覆盖'}</span><span><b>{x.total ? `${Math.round(pct * 100)}%` : '—'}</b> <span className={ui.faint}>{x.reviewed}/{x.total}{x.readOnly ? ` · 已读未结论 ${x.readOnly}` : ''}{(x as { fromModel?: number }).fromModel ? ` · 模型补充 ${(x as { fromModel?: number }).fromModel}` : ''}</span></span></div>
                  <Progress value={x.reviewed} max={Math.max(1, x.total)} {...(pct < 0.8 ? { tone: 'warn' as const } : {})} />
                </div>
              );
            })}
            {r.hypothesis.total > 0 && (
              <div style={{ marginBottom: 12 }}>
                <div className={ui.spread} style={{ fontSize: 13, marginBottom: 4 }}><span>风险假设覆盖</span><span><b>{Math.round((r.hypothesis.reviewed / r.hypothesis.total) * 100)}%</b> <span className={ui.faint}>{r.hypothesis.reviewed}/{r.hypothesis.total}</span></span></div>
                <Progress value={r.hypothesis.reviewed} max={r.hypothesis.total} {...(r.hypothesis.reviewed < r.hypothesis.total ? { tone: 'warn' as const } : {})} />
                <div className={ui.faint} style={{ fontSize: 12, marginTop: 4 }}>证实 {r.hypothesis.confirmed} · 排除 {r.hypothesis.refuted} · 无法判定 {r.hypothesis.open}{r.hypothesis.proposed ? ` · 未验证 ${r.hypothesis.proposed}` : ''}</div>
              </div>
            )}
            <div className={ui.spread} style={{ fontSize: 13 }}><span>阅读覆盖</span><span className={ui.faint}>已读 {fmt.n(r.reading.readLines)} 行 / 源码 {fmt.n(r.sourceLines)} 行{r.sourceLines ? `（${Math.round((r.reading.readLines / r.sourceLines) * 100)}%）` : ''}</span></div>
            {r.indexStatus && r.indexStatus !== 'complete' && <div className={ui.faint} style={{ fontSize: 12, marginTop: 6, color: 'var(--warn)' }}>结构索引{r.indexStatus === 'partial' ? '不完整' : '失败'}：{r.gaps.length} 个缺口，覆盖分母可能偏小</div>}
            {r.byModule.length > 1 && (
              <details style={{ marginTop: 10 }}>
                <summary className={ui.faint} style={{ fontSize: 12, cursor: 'pointer' }}>按模块阅读覆盖（{r.byModule.length}）</summary>
                <table className={ui.table} style={{ marginTop: 6, fontSize: 12 }}>
                  <thead><tr><th>模块</th><th style={{ textAlign: 'right' }}>已读 / 行数</th></tr></thead>
                  <tbody>{r.byModule.slice(0, 20).map((m) => (
                    <tr key={m.module}><td className={ui.mono}>{m.module}</td><td style={{ textAlign: 'right' }}>{fmt.n(m.readLines)}/{fmt.n(m.totalLines)}{m.totalLines ? `（${Math.round((m.readLines / m.totalLines) * 100)}%）` : ''}</td></tr>
                  ))}</tbody>
                </table>
              </details>
            )}
            {r.gaps.length > 0 && (
              <details style={{ marginTop: 6 }}>
                <summary className={ui.faint} style={{ fontSize: 12, cursor: 'pointer' }}>索引缺口（{r.gaps.length}）</summary>
                <ul style={{ margin: '6px 0 0', paddingLeft: 18, fontSize: 12 }}>{r.gaps.slice(0, 20).map((g) => <li key={`${g.path}-${g.reason}`}><span className={ui.mono}>{g.path}</span> · {g.reason}</li>)}</ul>
              </details>
            )}
          </div>
        ))}
      </div>
      <p className={ui.faint} style={{ fontSize: 12 }}>覆盖不等于检出率：100% 入口覆盖只说明每个入口都被阅读并给出了判断，不说明判断正确；风险假设覆盖同理。</p>
      {extras}
      {c.data.backfills.length > 0 && (
        <div className={cx(ui.card, ui.cardPad)} aria-label="补审记录">
          <b>补审</b>
          {c.data.backfills.map((b) => (
            <div key={b.auditId} className={ui.spread} style={{ marginTop: 8 }}>
              <Link to="/audits/$aid" params={{ aid: b.auditId }}>{b.title}</Link>
              <span className={ui.row}><AuditStatusBadge status={b.status} /><span className={ui.faint} style={{ fontSize: 12 }}>已结论 {b.concluded}/{b.targets}</span></span>
            </div>
          ))}
        </div>
      )}
      <div>
        <div className={ui.spread} style={{ marginBottom: 10 }}>
          <Segmented value={kind} onChange={setKind} items={[{ key: 'entry', label: '入口' }, { key: 'sink', label: '危险点' }]} />
          <div className={ui.row}>
            <label className={ui.checkbox}><input type="checkbox" checked={onlyGaps} onChange={(e) => setOnlyGaps(e.target.checked)} />只看未覆盖</label>
            <Button size="sm" variant="primary" icon="play" loading={busy} disabled={!finished || gaps === 0}
              title={!finished ? '审计结束后才能补审' : gaps === 0 ? '没有未覆盖项' : undefined} onClick={() => void backfill()}>
              {picked.size ? `补审所选（${picked.size}）` : `一键补审全部（${gaps}）`}
            </Button>
          </div>
        </div>
        {items.isLoading ? <Loading /> : list.length === 0 ? <EmptyState icon="checkCircle" title="全部已覆盖" /> : (
          <CoverageItemsTable aid={aid} kind={kind} items={items.data ?? []} finished={finished} multiRepo={c.data.repos.length > 1} onlyGaps={onlyGaps}
            picked={picked} onPick={(id) => setPicked((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; })} />
        )}
      </div>
    </div>
  );
}
