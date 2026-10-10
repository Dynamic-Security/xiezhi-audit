// On the vulnerability panel: project rules — a confirmed vulnerability solidified
// into a pattern the next audits hit directly; verification cases the user runs; patch suggestions
// with a linked reverification. Nothing here is executed by the engine.
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { FixSuggestionDto, ProjectRuleDto, ProjectRuleValidationDto, VerificationCaseDto, VulnDetailDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { fmt } from '../../shared/format/messages';
import { Badge, Button, Dialog, Field, Segmented, cx, ui, useToast } from '../../shared/ui';
import V from './vulns.module.css';

const RULE_STATUS: Record<string, { label: string; tone: 'ok' | 'warn' | 'danger' | 'neutral' | 'info' | 'accent' }> = {
  drafting: { label: 'AI 起草中', tone: 'info' }, proposed: { label: '待批准', tone: 'warn' }, approved: { label: '已生效', tone: 'ok' },
  rejected: { label: '已驳回', tone: 'neutral' }, retired: { label: '已停用', tone: 'neutral' }, failed: { label: '未通过', tone: 'danger' },
};

function ValidationView({ v }: { v: ProjectRuleValidationDto }) {
  return (
    <div className={ui.stack} style={{ gap: 4 }}>
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
        {v.error ? <Badge tone="danger">无法运行</Badge> : <Badge tone={v.originHit ? 'ok' : 'danger'}>{v.originHit ? '命中原位置' : '未命中原位置'}</Badge>}
        {!v.error && <span className={ui.faint}>在快照 {v.files} 个文件中命中 {v.hits}{v.truncated ? '+' : ''} 处</span>}
      </div>
      {v.error && <span className={ui.faint}>{v.error}</span>}
      {v.sample.length > 0 && (
        <ul className={ui.faint} style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>
          {v.sample.slice(0, 8).map((h) => <li key={`${h.path}:${h.startLine}`}><span className={ui.mono}>{h.path}:{h.startLine}</span> {h.text}</li>)}
        </ul>
      )}
    </div>
  );
}

function RuleEditor({ v, onClose }: { v: VulnDetailDto; onClose: () => void }) {
  const [matcher, setMatcher] = useState<'tree_sitter' | 'regex'>('tree_sitter');
  const [pattern, setPattern] = useState('');
  const [title, setTitle] = useState('');
  const [result, setResult] = useState<ProjectRuleValidationDto | null>(null);
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const test = async () => {
    setBusy(true);
    try { setResult(await api.post<ProjectRuleValidationDto>(`/vulnerabilities/${v.id}/rules/test`, { matcher, pattern })); } catch (e) { toast.error(e); }
    setBusy(false);
  };
  const save = async () => {
    try {
      await api.post(`/vulnerabilities/${v.id}/rules`, { matcher, pattern, ...(title ? { title } : {}) });
      toast.ok('已保存为待批准的规则');
      await qc.invalidateQueries({ queryKey: ['rules'] });
      onClose();
    } catch (e) { toast.error(e); }
  };
  return (
    <Dialog open onClose={onClose} title={`为 V-${v.displayNo} 编写项目规则`} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button loading={busy} disabled={!pattern.trim()} onClick={() => void test()}>试跑</Button>
      <Button variant="primary" disabled={!result || !!result.error || !result.originHit} onClick={() => void save()}>保存</Button>
    </>}>
      <div className={ui.stack}>
        <Field label="匹配方式"><Segmented value={matcher} onChange={(x) => { setMatcher(x as 'tree_sitter' | 'regex'); setResult(null); }} items={[{ key: 'tree_sitter', label: 'tree-sitter 查询' }, { key: 'regex', label: '单行正则' }]} /></Field>
        <Field label="模式" hint={matcher === 'tree_sitter' ? '把危险调用节点捕获为 @sink；规则必须命中原漏洞位置' : '逐行匹配；规则必须命中原漏洞位置'}>
          <textarea aria-label="规则模式" className={cx(ui.textarea, ui.mono)} rows={5} value={pattern} onChange={(e) => { setPattern(e.target.value); setResult(null); }} />
        </Field>
        <Field label="标题"><input aria-label="规则标题" className={ui.input} value={title} placeholder={`V-${v.displayNo} ${v.title}`} onChange={(e) => setTitle(e.target.value)} /></Field>
        {result && <ValidationView v={result} />}
      </div>
    </Dialog>
  );
}

/** Project rules of this vulnerability: AI draft or own pattern, the engine's check on the snapshot, approve / reject / retire. */
export function ProjectRulesSection({ v }: { v: VulnDetailDto }) {
  const rules = useQuery({
    queryKey: ['rules', v.projectId, v.id], queryFn: () => api.get<ProjectRuleDto[]>(`/projects/${v.projectId}/rules?vulnId=${v.id}`),
    refetchInterval: (q) => ((q.state.data ?? []).some((r) => r.status === 'drafting') ? 2000 : false),
  });
  const [edit, setEdit] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const draft = async () => {
    try { await api.post(`/vulnerabilities/${v.id}/rules`, { mode: 'ai' }); toast.ok('AI 正在起草规则'); } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['rules'] });
  };
  const decide = async (r: ProjectRuleDto, decision: 'approve' | 'reject' | 'retire') => {
    try {
      await api.post(`/rules/${r.id}/decision`, { decision });
      toast.ok(decision === 'approve' ? '已批准：从下一次审计起生效' : decision === 'reject' ? '已驳回' : '已停用');
    } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['rules'] });
  };
  const confirmed = v.confirmStatus === 'confirmed';
  const list = rules.data ?? [];
  return (
    <section className={V.layer}>
      <h3 className={V.layerTitle}>项目规则</h3>
      <p className={ui.faint} style={{ marginTop: 0 }}>把这个漏洞固化为检测模式：引擎在快照上校验它能命中原位置，批准后下一次审计直接命中这里与同类写法。</p>
      <div className={ui.row} style={{ gap: 8 }}>
        <Button size="sm" icon="sparkle" disabled={!confirmed || list.some((r) => r.status === 'drafting')} title={confirmed ? undefined : '确认后才能固化'} onClick={() => void draft()}>AI 起草规则</Button>
        <Button size="sm" icon="edit" disabled={!confirmed} onClick={() => setEdit(true)}>自己编写</Button>
      </div>
      {list.map((r) => (
        <div key={r.id} className={cx(ui.card, ui.cardPad, ui.stack)} style={{ marginTop: 8, gap: 6 }}>
          <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
            <Badge tone={RULE_STATUS[r.status]?.tone ?? 'neutral'}>{RULE_STATUS[r.status]?.label ?? r.status}</Badge>
            <b className={ui.grow}>{r.title}</b>
            <span className={ui.faint} style={{ fontSize: 12 }}>{r.source === 'ai' ? `AI${r.model ? ` · ${r.model}` : ''}` : '人工'} · {fmt.date(r.createdAt)}</span>
          </div>
          {r.pattern && <pre className={ui.code} style={{ padding: 8, whiteSpace: 'pre-wrap', margin: 0 }}>{r.matcher === 'regex' ? `regex: ${r.pattern}` : r.pattern}</pre>}
          {r.rationale && <div className={ui.muted}>{r.rationale}</div>}
          {r.validation && <ValidationView v={r.validation} />}
          {r.error && r.status === 'failed' && <div className={ui.faint}>{r.error}</div>}
          <div className={ui.row} style={{ gap: 8 }}>
            {r.status === 'proposed' && <Button size="sm" variant="primary" onClick={() => void decide(r, 'approve')}>批准</Button>}
            {(r.status === 'proposed' || r.status === 'failed') && <Button size="sm" variant="ghost" onClick={() => void decide(r, 'reject')}>驳回</Button>}
            {r.status === 'approved' && <Button size="sm" variant="ghost" onClick={() => void decide(r, 'retire')}>停用</Button>}
          </div>
        </div>
      ))}
      {edit && <RuleEditor v={v} onClose={() => setEdit(false)} />}
    </section>
  );
}

const OUTCOME: Record<string, { label: string; tone: 'ok' | 'warn' | 'danger' | 'neutral' }> = {
  reproduced: { label: '已复现', tone: 'danger' }, not_reproduced: { label: '未复现', tone: 'ok' }, inconclusive: { label: '无法判断', tone: 'neutral' },
};
const STEP_KIND: Record<string, string> = { http: 'HTTP 请求', test: '测试代码', manual: '手工操作' };

function ResultEditor({ c, onClose }: { c: VerificationCaseDto; onClose: () => void }) {
  const [outcome, setOutcome] = useState<'reproduced' | 'not_reproduced' | 'inconclusive'>('reproduced');
  const [note, setNote] = useState('');
  const qc = useQueryClient();
  const toast = useToast();
  const save = async () => {
    try {
      await api.post(`/verification-cases/${c.id}/result`, { outcome, ...(note.trim() ? { note } : {}) });
      toast.ok(outcome === 'reproduced' ? '已记录：漏洞按用户验证确认' : outcome === 'not_reproduced' ? '已记录：生成了“误报”建议待处理' : '已记录');
      await qc.invalidateQueries({ queryKey: ['cases'] });
      await qc.invalidateQueries({ queryKey: ['vuln'] });
      await qc.invalidateQueries({ queryKey: ['vulns'] });
      onClose();
    } catch (e) { toast.error(e); }
  };
  return (
    <Dialog open onClose={onClose} title="回填验证结果" footer={<><Button onClick={onClose}>取消</Button><Button variant="primary" disabled={outcome !== 'reproduced' && !note.trim()} onClick={() => void save()}>保存</Button></>}>
      <div className={ui.stack}>
        <Field label="结果"><Segmented value={outcome} onChange={(x) => setOutcome(x as typeof outcome)} items={[{ key: 'reproduced', label: '复现' }, { key: 'not_reproduced', label: '未复现' }, { key: 'inconclusive', label: '无法判断' }]} /></Field>
        <Field label="观察到的情况" hint={outcome === 'reproduced' ? '可选；复现会把漏洞确认为“用户验证”' : '必填；未复现会生成“误报”建议，由你在面板中决定'}>
          <textarea aria-label="验证结果说明" className={ui.textarea} rows={4} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
    </Dialog>
  );
}

/** Verification cases: written by the model, run by the user in their own environment, result recorded here. */
export function VerificationSection({ v }: { v: VulnDetailDto }) {
  const cases = useQuery({
    queryKey: ['cases', v.id], queryFn: () => api.get<VerificationCaseDto[]>(`/vulnerabilities/${v.id}/verification-cases`),
    refetchInterval: (q) => ((q.state.data ?? []).some((c) => c.status === 'drafting') ? 2000 : false),
  });
  const [result, setResult] = useState<VerificationCaseDto | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const list = cases.data ?? [];
  const generate = async () => {
    try { await api.post(`/vulnerabilities/${v.id}/verification-cases`, {}); toast.ok('AI 正在编写验证用例'); } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['cases'] });
  };
  return (
    <section className={V.layer}>
      <h3 className={V.layerTitle}>验证用例</h3>
      <p className={ui.faint} style={{ marginTop: 0 }}>由 AI 编写、在你自己的测试环境中执行；引擎不执行任何请求或代码。回填结果后，复现的漏洞按“用户验证”确认。</p>
      <Button size="sm" icon="sparkle" disabled={v.confirmStatus === 'false_positive' || list.some((c) => c.status === 'drafting')} onClick={() => void generate()}>生成验证用例</Button>
      {list.map((c) => (
        <div key={c.id} className={cx(ui.card, ui.cardPad, ui.stack)} style={{ marginTop: 8, gap: 6 }}>
          <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
            {/* A case with a recorded outcome was executed: no “待执行” next to “已复现”. */}
            {!(c.status === 'ready' && c.outcome) && <Badge tone={c.status === 'ready' ? 'info' : c.status === 'failed' ? 'danger' : 'neutral'}>{c.status === 'drafting' ? '编写中' : c.status === 'failed' ? '生成失败' : '待执行'}</Badge>}
            {c.outcome && <Badge tone={OUTCOME[c.outcome]?.tone ?? 'neutral'}>{OUTCOME[c.outcome]?.label ?? c.outcome}</Badge>}
            <span className={ui.grow} />
            <span className={ui.faint} style={{ fontSize: 12 }}>{c.model ?? ''} · {fmt.date(c.createdAt)}</span>
          </div>
          {c.error && <div className={ui.faint}>{c.error}</div>}
          {c.preconditions.length > 0 && <div><b>前置条件</b><ul style={{ margin: '4px 0', paddingLeft: 18 }}>{c.preconditions.map((p, i) => <li key={i}>{p}</li>)}</ul></div>}
          {c.steps.map((s, i) => (
            <div key={i}>
              <div><b>{i + 1}. {s.title}</b> <Badge>{STEP_KIND[s.kind] ?? s.kind}{s.lang ? ` · ${s.lang}` : ''}</Badge></div>
              <pre className={ui.code} style={{ padding: 8, whiteSpace: 'pre-wrap', margin: '4px 0 0' }}>{s.content}</pre>
            </div>
          ))}
          {c.expected && <div className={ui.muted}><div>存在漏洞时：{c.expected.vulnerable}</div><div>修复后：{c.expected.fixed}</div></div>}
          {c.notes && <div className={ui.faint}>{c.notes}</div>}
          {c.outcomeNote && <div className={ui.faint}>结果说明：{c.outcomeNote}</div>}
          {c.status === 'ready' && <div><Button size="sm" onClick={() => setResult(c)}>{c.outcome ? '更新结果' : '回填结果'}</Button></div>}
        </div>
      ))}
      {result && <ResultEditor c={result} onClose={() => setResult(null)} />}
    </section>
  );
}

const VERDICT: Record<string, { label: string; tone: 'ok' | 'warn' | 'danger' | 'neutral' | 'info' }> = {
  running: { label: '复验中', tone: 'info' }, fixed: { label: '复验：已修复', tone: 'ok' }, still_present: { label: '复验：仍存在', tone: 'danger' }, unknown: { label: '复验无结论', tone: 'neutral' },
};

/** Fix suggestions: a patch checked against the snapshot (never written to the repository), then a linked reverification. */
export function FixSection({ v }: { v: VulnDetailDto }) {
  const fixes = useQuery({
    queryKey: ['fixes', v.id], queryFn: () => api.get<FixSuggestionDto[]>(`/vulnerabilities/${v.id}/fix-suggestions`),
    refetchInterval: (q) => ((q.state.data ?? []).some((f) => f.status === 'drafting' || f.reverify?.verdict === 'running') ? 3000 : false),
  });
  const qc = useQueryClient();
  const toast = useToast();
  const list = fixes.data ?? [];
  const generate = async () => {
    try { await api.post(`/vulnerabilities/${v.id}/fix-suggestions`, {}); toast.ok('AI 正在编写补丁建议'); } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['fixes'] });
  };
  const reverify = async (f: FixSuggestionDto) => {
    try { await api.post(`/fix-suggestions/${f.id}/reverify`, {}); toast.ok('已发起复验'); } catch (e) { toast.error(e); }
    await qc.invalidateQueries({ queryKey: ['fixes'] });
  };
  const confirmed = v.confirmStatus === 'confirmed';
  return (
    <section className={V.layer}>
      <h3 className={V.layerTitle}>补丁建议</h3>
      <p className={ui.faint} style={{ marginTop: 0 }}>AI 按快照中的代码写出最小补丁（unified diff），引擎检查能否应用到快照；不写入仓库，由你审阅后应用，再发起复验。</p>
      <Button size="sm" icon="sparkle" disabled={!confirmed || list.some((f) => f.status === 'drafting')} title={confirmed ? undefined : '确认后才能生成补丁建议'} onClick={() => void generate()}>生成补丁建议</Button>
      {list.map((f) => (
        <div key={f.id} className={cx(ui.card, ui.cardPad, ui.stack)} style={{ marginTop: 8, gap: 6 }}>
          <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
            <Badge tone={f.status === 'ready' ? 'info' : f.status === 'failed' ? 'danger' : 'neutral'}>{f.status === 'drafting' ? '编写中' : f.status === 'failed' ? '生成失败' : '可应用到快照'}</Badge>
            {f.reverify && <Badge tone={VERDICT[f.reverify.verdict]?.tone ?? 'neutral'}>{VERDICT[f.reverify.verdict]?.label ?? f.reverify.verdict}</Badge>}
            <span className={ui.grow} />
            <span className={ui.faint} style={{ fontSize: 12 }}>{f.model ?? ''} · {fmt.date(f.createdAt)}</span>
          </div>
          {f.error && <div className={ui.faint}>{f.error}</div>}
          {f.summary && <div>{f.summary}</div>}
          {f.patches.map((p) => <pre key={p.path} aria-label={`补丁 ${p.path}`} className={ui.code} style={{ padding: 8, whiteSpace: 'pre', overflowX: 'auto', margin: 0 }}>{p.diff}</pre>)}
          {f.verify && <div className={ui.muted}>复验方式：{f.verify}</div>}
          {f.notes && <div className={ui.faint}>{f.notes}</div>}
          {f.status === 'ready' && f.reverify?.verdict !== 'running' && <div><Button size="sm" onClick={() => void reverify(f)}>已应用，发起复验</Button></div>}
        </div>
      ))}
    </section>
  );
}
