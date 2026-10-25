// Risk hunting: list of hunts, the new-hunt flow (basis from a skill / prompt / 1Day-CVE
// intel → AI-organized basis the user reviews → scope → plan → confirm), and the results page
// (per project / repository verdicts with reasons, hits with evidence, promote, override, rerun, export).
import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearch } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { HuntBasis, HuntBasisDto, HuntDto, HuntResultsDto, HuntTargetDto, SkillDto } from '@xiezhi/contracts';
import { api, ApiError } from '../../shared/api/client';
import { useProjects } from '../../shared/api/queries';
import { fmt, SEVERITY } from '../../shared/format/messages';
import { Badge, Button, Dialog, EmptyState, ErrorState, Field, Icon, Loading, Segmented, Spinner, cx, ui, useToast } from '../../shared/ui';
import { PageLayout, Section, TopBar } from '../layout/AppShell';

export const VERDICT: Record<string, string> = { affected: '受影响', not_affected: '不受影响', pending: '待确认' };
const VERDICT_TONE: Record<string, 'danger' | 'ok' | 'warn'> = { affected: 'danger', not_affected: 'ok', pending: 'warn' };
const STATUS: Record<string, string> = { planned: '待确认计划', running: '排查中', completed: '已完成', partial: '部分完成', failed: '失败', cancelled: '已取消' };
const DELTA: Record<string, string> = { new_affected: '新增受影响', cleared: '已消除', changed: '结论变化', unchanged: '无变化', new: '新纳入' };
const KIND: Record<string, string> = { skill: '知识', prompt: 'Prompt', intel: '1Day / CVE 情报', report: '外部报告', ticket: '工单' };
const errText = (e: unknown) => (e instanceof ApiError ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : String(e));

/** Audits of a hunt waiting their turn or a person (a queued hunt read “排查中” for twenty minutes). */
const WAITING: Record<string, string> = { queued: '排队中', waiting_budget: '等待预算', paused: '已暂停', planning: '生成计划中', awaiting_confirm: '待确认计划' };

function VerdictBadge({ v, audit }: { v: string | null; audit?: string | null }) {
  if (v) return <Badge tone={VERDICT_TONE[v]}>{VERDICT[v]}</Badge>;
  if (audit && WAITING[audit]) return <Badge tone="warn" title={audit === 'queued' ? '一次只运行一个审计或排查，前面的完成后自动开始' : undefined}>{WAITING[audit]}</Badge>;
  return <Badge><Spinner /> 排查中</Badge>;
}

// ---- list ---------------------------------------------------------------------------------------------------

export function HuntsPage() {
  const hunts = useQuery({ queryKey: ['hunts'], queryFn: () => api.get<HuntDto[]>('/hunts'), refetchInterval: (q) => (q.state.data?.some((h) => h.status === 'running') ? 2000 : false), refetchIntervalInBackground: true });
  const navigate = useNavigate();
  return (
    <>
      <TopBar crumbs={[{ label: '风险排查' }]} actions={<Button variant="primary" icon="plus" onClick={() => void navigate({ to: '/hunts/new' })}>新建排查</Button>} />
      <PageLayout>
        <p className={ui.muted}>针对一个特定的已知风险（新披露的 1Day、某种漏洞模式），快速评估一个或多个项目是否受影响。不是全面审计，通常以分钟计。</p>
        {hunts.isLoading ? <Loading /> : hunts.error ? <ErrorState error={hunts.error} /> : hunts.data!.length === 0 ? (
          <div className={ui.card}><EmptyState icon="target" title="还没有排查记录" action={<Button variant="primary" icon="plus" onClick={() => void navigate({ to: '/hunts/new' })}>新建排查</Button>}>从知识库选一个 skill、直接描述风险，或粘贴漏洞公告。</EmptyState></div>
        ) : (
          <div className={ui.card} style={{ overflow: 'auto' }}>
            <table className={ui.table}>
              <thead><tr><th>排查</th><th>依据来源</th><th>状态</th><th>结果</th><th>时间</th></tr></thead>
              <tbody>
                {hunts.data!.map((h) => (
                  <tr key={h.id}>
                    <td><Link to="/hunts/$hid" params={{ hid: h.id }}><b>{h.title}</b></Link>{h.rerunOfId && <Badge>重新排查</Badge>}</td>
                    <td>{KIND[h.basisKind] ?? h.basisKind}</td>
                    <td><Badge tone={h.status === 'completed' ? 'ok' : h.status === 'running' ? 'info' : h.status === 'failed' ? 'danger' : 'neutral'}>{STATUS[h.status] ?? h.status}</Badge></td>
                    <td className={ui.faint} style={{ fontSize: 13 }}>{h.summary.projects} 个项目 · 受影响 {h.summary.affected} · 不受影响 {h.summary.notAffected} · 待确认 {h.summary.pending}</td>
                    <td className={ui.faint} style={{ fontSize: 12 }}>{fmt.date(h.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </PageLayout>
    </>
  );
}

// ---- basis editor -------------------------------------------------------------------------------------------

const lines = (s: string) => s.split('\n').map((x) => x.trim()).filter(Boolean);

interface Pair { a: string; b: string }

/** Two inputs per row (e.g. regex + description), so neither side has to avoid a separator character. */
function PairRows({ label, rows, onChange, a, b }: {
  label: string; rows: Pair[]; onChange: (rows: Pair[]) => void;
  a: { label: string; placeholder: string; mono?: boolean }; b: { label: string; placeholder: string; mono?: boolean };
}) {
  const set = (i: number, patch: Partial<Pair>) => onChange(rows.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <Field group label={label}>
      <div className={ui.stack} style={{ gap: 6 }}>
        {rows.map((r, i) => (
          <div key={i} className={ui.row}>
            <input aria-label={`${a.label} ${i + 1}`} className={cx(ui.input, a.mono && ui.mono)} style={{ flex: a.mono ? 3 : 4, fontSize: 12, minWidth: 0 }} value={r.a} placeholder={a.placeholder} onChange={(e) => set(i, { a: e.target.value })} />
            <input aria-label={`${b.label} ${i + 1}`} className={cx(ui.input, b.mono && ui.mono)} style={{ flex: b.mono ? 3 : 4, fontSize: 12, minWidth: 0 }} value={r.b} placeholder={b.placeholder} onChange={(e) => set(i, { b: e.target.value })} />
            <Button size="sm" variant="ghost" icon="x" aria-label={`删除${label}第 ${i + 1} 行`} onClick={() => onChange(rows.filter((_, j) => j !== i))} />
          </div>
        ))}
        <div><Button size="sm" variant="ghost" icon="plus" onClick={() => onChange([...rows, { a: '', b: '' }])}>添加一行</Button></div>
      </div>
    </Field>
  );
}

function BasisEditor({ basis, onSave, busy, error }: { basis: HuntBasis; onSave: (b: HuntBasis) => void; busy: boolean; error: string | null }) {
  const [title, setTitle] = useState(basis.title);
  const [summary, setSummary] = useState(basis.summary);
  const [deps, setDeps] = useState(basis.features.dependencies.map((d) => `${d.ecosystem} ${d.name} ${d.affectedVersions}`).join('\n'));
  const [apis, setApis] = useState<Pair[]>(basis.features.apis.map((x) => ({ a: x.pattern, b: x.description })));
  const [patterns, setPatterns] = useState<Pair[]>(basis.features.codePatterns.map((x) => ({ a: x.description, b: x.grep ?? '' })));
  const [aff, setAff] = useState(basis.affectedIf.join('\n'));
  const [notAff, setNotAff] = useState(basis.notAffectedIf.join('\n'));
  const [rem, setRem] = useState(basis.remediation);
  const build = (): HuntBasis => ({
    ...basis, title: title.trim(), summary: summary.trim(), remediation: rem.trim(), affectedIf: lines(aff), notAffectedIf: lines(notAff),
    features: {
      ...basis.features,
      dependencies: lines(deps).map((l) => {
        const [eco, name, ...range] = l.split(/\s+/);
        return { ecosystem: (['maven', 'go', 'npm', 'pypi', 'composer', 'nuget', 'rubygems', 'cargo', 'any'].includes(eco!) ? eco : 'any') as 'maven', name: name ?? eco!, affectedVersions: range.join(' ') || '*' };
      }),
      apis: apis.filter((r) => r.a.trim()).map((r) => ({ ...basis.features.apis.find((x) => x.pattern === r.a.trim()), pattern: r.a.trim(), description: r.b.trim() || r.a.trim() })),
      codePatterns: patterns.filter((r) => r.a.trim() || r.b.trim()).map((r) => ({ description: r.a.trim() || r.b.trim(), ...(r.b.trim() ? { grep: r.b.trim() } : {}) })),
    },
  });
  const ta = (v: string, set: (x: string) => void, label: string, rows = 3, ph?: string) => <textarea aria-label={label} className={cx(ui.input, ui.mono)} rows={rows} value={v} placeholder={ph} onChange={(e) => set(e.target.value)} style={{ fontSize: 12 }} />;
  return (
    <div className={ui.stack}>
      <Field label="标题"><input className={ui.input} value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
      <Field label="风险说明">{ta(summary, setSummary, '风险说明', 3)}</Field>
      <Field label="受影响组件（每行：生态 名称 版本范围）" hint="生态为 maven / go / npm / pypi / composer / nuget / rubygems / cargo / any；maven 名称写 groupId:artifactId，composer 写 vendor/package；范围如 <2.13.4.2 或 *">{ta(deps, setDeps, '受影响组件', 3, 'maven com.fasterxml.jackson.core:jackson-databind <2.13.4.2')}</Field>
      <PairRows label="危险 API" rows={apis} onChange={setApis} a={{ label: '危险 API 正则', placeholder: 'ripgrep 正则，如 Statement\\.execute(Query)?\\(', mono: true }} b={{ label: '危险 API 说明', placeholder: '说明' }} />
      <PairRows label="代码模式" rows={patterns} onChange={setPatterns} a={{ label: '代码模式说明', placeholder: '需要人判断的写法' }} b={{ label: '代码模式正则', placeholder: '可选：粗筛正则', mono: true }} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
        <Field label="判定为受影响（每行一条）">{ta(aff, setAff, '判定为受影响', 3)}</Field>
        <Field label="判定为不受影响（每行一条）">{ta(notAff, setNotAff, '判定为不受影响', 3)}</Field>
      </div>
      <Field label="修复方式">{ta(rem, setRem, '修复方式', 2)}</Field>
      <div className={cx(ui.row, ui.wrap)}>
        <Button onClick={() => onSave(build())} loading={busy}>保存修改</Button>
        {error && <span className={ui.error} role="alert">{error}</span>}
      </div>
    </div>
  );
}

// ---- new hunt -------------------------------------------------------------------------------------------------

export function NewHuntPage() {
  const search = useSearch({ from: '/hunts/new' });
  const [source, setSource] = useState<'skill' | 'prompt' | 'intel'>(search.skill ? 'skill' : 'prompt');
  const [skill, setSkill] = useState(search.skill ?? '');
  const [text, setText] = useState('');
  const [basisId, setBasisId] = useState<string | null>(search.basis ?? null);
  const [all, setAll] = useState(!search.projects?.length);
  const [picked, setPicked] = useState<string[]>(search.projects ?? []);
  const [huntId, setHuntId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<{ at: 'draft' | 'save' | 'plan'; text: string } | null>(null);
  const [saveSkill, setSaveSkill] = useState(false);
  const skills = useQuery({ queryKey: ['knowledge', 'global'], queryFn: () => api.get<SkillDto[]>('/knowledge') });
  const projects = useProjects();
  const basis = useQuery({
    queryKey: ['hunt-basis', basisId], enabled: !!basisId, queryFn: () => api.get<HuntBasisDto>(`/hunt-bases/${basisId}`),
    refetchInterval: (q) => (q.state.data?.status === 'drafting' ? 1000 : false), refetchIntervalInBackground: true,
  });
  const qc = useQueryClient();
  const huntQ = useQuery({
    queryKey: ['hunt-plan', huntId], enabled: !!huntId, queryFn: () => api.get<HuntDto>(`/hunts/${huntId}`),
    refetchInterval: (q) => (q.state.data?.plan?.estimate.precheck.status === 'running' ? 1000 : false), refetchIntervalInBackground: true,
  });
  const hunt = huntId ? huntQ.data ?? null : null;
  const toast = useToast();
  const navigate = useNavigate();
  const run = async (at: 'draft' | 'save' | 'plan', fn: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    try { await fn(); } catch (e) { setErr({ at, text: errText(e) }); }
    setBusy(false);
  };
  const errAt = (at: 'draft' | 'save' | 'plan') => (err?.at === at ? err.text : null);
  const errLine = (at: 'draft' | 'save' | 'plan') => errAt(at) && <div className={ui.error} role="alert" style={{ marginTop: 8 }}>{errAt(at)}</div>;
  const draft = () => run('draft', async () => {
    const r = await api.post<{ basisId: string }>('/hunt-bases', source === 'skill' ? { kind: 'skill', skill } : { kind: source, text });
    setBasisId(r.basisId);
    setHuntId(null);
  });
  const b = basis.data;
  return (
    <>
      <TopBar crumbs={[{ label: '风险排查', to: '/hunts' }, { label: '新建排查' }]} />
      <PageLayout narrow>
        <Section title="① 排查依据">
          <div className={ui.card} style={{ padding: 16 }}>
            <Segmented value={source} onChange={(s) => { setSource(s); setBasisId(null); }} items={[{ key: 'skill', label: '选择知识' }, { key: 'prompt', label: '直接写 Prompt' }, { key: 'intel', label: '1Day / CVE 情报' }]} />
            <div style={{ marginTop: 12 }}>
              {source === 'skill' ? (
                <Field label="知识（漏洞案例或审计方法）">
                  <select aria-label="选择知识" className={ui.select} value={skill} onChange={(e) => setSkill(e.target.value)}>
                    <option value="">选择…</option>
                    {(skills.data ?? []).filter((s) => s.valid && !s.disabled && ['vuln_case', 'audit_method'].includes(s.category ?? '')).map((s) => <option key={s.name} value={s.name}>{s.name} — {(s.description ?? '').slice(0, 60)}</option>)}
                  </select>
                </Field>
              ) : (
                <Field label={source === 'intel' ? '漏洞公告 / 通告文本或 CVE 编号' : '要排查的风险'} hint={source === 'intel' ? '粘贴公告正文效果最好；链接不会被访问，只给编号时 AI 按已有知识整理，需要你核对版本范围' : '描述风险、成立条件和不成立条件；可以写明大致位置（如某个接口）'}>
                  <textarea aria-label="排查依据输入" className={ui.input} rows={6} value={text} onChange={(e) => setText(e.target.value)}
                    placeholder={source === 'intel' ? '例如：CVE-2022-42889 Apache Commons Text 1.5–1.9 StringSubstitutor 插值导致远程代码执行…' : '例如：排查“用请求参数里的 userId 查询数据、却没有和登录用户比对”的越权'} />
                </Field>
              )}
              <Button variant="primary" icon="sparkle" loading={busy && !basisId} disabled={source === 'skill' ? !skill : !text.trim()} onClick={() => void draft()}>AI 整理排查依据</Button>
              {errLine('draft')}
            </div>
          </div>
          {basisId && (
            <div className={ui.card} style={{ padding: 16, marginTop: 12 }}>
              {!b || b.status === 'drafting' ? <div className={ui.faint}><Spinner /> AI 正在整理排查依据…</div>
                : b.status === 'failed' ? <div className={ui.error}>整理失败：{b.error}</div>
                  : (
                    <>
                      <div className={cx(ui.row, ui.wrap)} style={{ marginBottom: 8 }}><Badge tone="ok">已整理</Badge><span className={ui.faint} style={{ fontSize: 12 }}>请核对特征与判定条件，可以直接修改后保存</span>
                        <Button size="sm" variant="ghost" onClick={() => setSaveSkill(true)}>存为 skill</Button></div>
                      <BasisEditor key={b.revision} basis={b.basis!} busy={busy} error={errAt('save')} onSave={(nb) => void run('save', async () => {
                        await api.patch(`/hunt-bases/${b.id}`, { revision: b.revision, basis: nb });
                        await qc.invalidateQueries({ queryKey: ['hunt-basis', basisId] });
                        toast.ok('已保存');
                      })} />
                    </>
                  )}
            </div>
          )}
        </Section>
        {b?.status === 'ready' && (
          <Section title="② 排查范围">
            <div className={ui.card} style={{ padding: 16 }}>
              <label className={ui.row}><input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} /> 全部项目（1Day 应急常用）</label>
              {!all && (
                <div className={cx(ui.row, ui.wrap)} style={{ marginTop: 8 }}>
                  {(projects.data ?? []).filter((p) => p.status === 'active').map((p) => (
                    <label key={p.id} className={ui.chip} style={{ cursor: 'pointer' }}>
                      <input type="checkbox" checked={picked.includes(p.id)} onChange={(e) => setPicked(e.target.checked ? [...picked, p.id] : picked.filter((x) => x !== p.id))} />{p.name}
                    </label>
                  ))}
                </div>
              )}
              <p className={ui.faint} style={{ fontSize: 12 }}>各仓库默认使用它的默认审计版本。</p>
              <Button variant="primary" loading={busy && !!basisId && !hunt} disabled={!all && !picked.length} onClick={() => void run('plan', async () => {
                const h = await api.post<HuntDto>('/hunts', { basisId: b.id, ...(all ? { allProjects: true } : { projectIds: picked }) });
                setHuntId(h.id);
                qc.setQueryData(['hunt-plan', h.id], h);
              })}>生成排查计划</Button>
              {errLine('plan')}
            </div>
          </Section>
        )}
        {hunt?.plan && (
          <Section title="③ 排查计划">
            <HuntPlan hunt={hunt} onConfirmed={() => void navigate({ to: '/hunts/$hid', params: { hid: hunt.id } })} />
          </Section>
        )}
        {saveSkill && b && <SaveSkillDialog basisId={b.id} title={b.title} onClose={() => setSaveSkill(false)} />}
      </PageLayout>
    </>
  );
}

/**
 * The plan of a hunt that is not confirmed yet, with the confirm button. Shown in the
 * new-hunt flow and on the results page, so a hunt left at `planned` (page closed before confirming,
 * or a rerun whose confirm failed) can still be started.
 */
function HuntPlan({ hunt, onConfirmed }: { hunt: HuntDto; onConfirmed: () => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const qc = useQueryClient();
  const plan = hunt.plan!;
  const confirm = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.post(`/hunts/${hunt.id}/confirm`);
      await Promise.all([qc.invalidateQueries({ queryKey: ['hunts'] }), qc.invalidateQueries({ queryKey: ['hunt', hunt.id] })]);
      onConfirmed();
    } catch (e) { setErr(errText(e)); }
    setBusy(false);
  };
  return (
    <div className={ui.card} style={{ padding: 16 }}>
      <div className={ui.stack}>
        {plan.projects.map((p) => (
          <div key={p.id}><b>{p.name}</b>：{p.repos.filter((r) => r.auditable).map((r) => r.name).join('、') || <span className={ui.faint}>没有可审计仓库（记为不受影响）</span>}</div>
        ))}
      </div>
      <p className={ui.muted} style={{ fontSize: 13 }}>
        排查特征：{[...hunt.basis.features.dependencies.map((d) => `${d.name} ${d.affectedVersions}`), ...hunt.basis.features.apis.map((a) => a.pattern), ...hunt.basis.features.codePatterns.map((p) => p.description)].join('；') || '（由 Agent 按描述查找）'}
      </p>
      <PlanEstimate estimate={plan.estimate} />
      <Button variant="primary" icon="play" loading={busy} onClick={() => void confirm()}>确认启动</Button>
      {err && <div className={ui.error} role="alert" style={{ marginTop: 8 }}>{err}</div>}
    </div>
  );
}

type PlanEstimateDto = NonNullable<HuntDto['plan']>['estimate'];

/** Estimate from the deterministic precheck: only repositories with candidates cost tokens. */
function PlanEstimate({ estimate: e }: { estimate: PlanEstimateDto }) {
  const minutes = (sec: number) => Math.max(1, Math.round(sec / 60));
  const pc = e.precheck;
  const range = `约 ${fmt.tokens(e.tokens.p50)}–${fmt.tokens(e.tokens.p90)} tokens，${minutes(e.durationSec.p50)}–${minutes(e.durationSec.p90)} 分钟`;
  if (pc.status === 'running') {
    return <p className={ui.muted} style={{ fontSize: 13 }}><Spinner /> 正在预检：按排查特征定位 {e.repositories} 个仓库（不调用模型），已完成 {pc.repos.length} 个…</p>;
  }
  if (pc.status !== 'done') {
    return <p className={ui.muted} style={{ fontSize: 13 }}>预计涉及 {e.repositories} 个仓库，{range}（未能预检，按全部仓库需要 AI 研判估算上限）。</p>;
  }
  const withCandidates = pc.repos.filter((r) => r.candidates > 0 || r.error);
  return (
    <div className={ui.muted} style={{ fontSize: 13, marginBottom: 12 }}>
      <p style={{ margin: '0 0 4px' }}>预计涉及 {e.repositories} 个仓库：<b>{pc.judged}</b> 个有候选、需要 AI 研判，{pc.cleared} 个没有候选、按规则判为不受影响（不消耗 token）；{range}。</p>
      {withCandidates.length > 0 && (
        <p className={ui.faint} style={{ margin: 0, fontSize: 12 }}>
          需要研判：{withCandidates.map((r) => `${r.project}/${r.name}（${r.error ? `预检失败：${r.error}` : `${r.candidates} 个候选`}）`).join('、')}
        </p>
      )}
    </div>
  );
}

function SaveSkillDialog({ basisId, title, onClose }: { basisId: string; title: string; onClose: () => void }) {
  const [name, setName] = useState(`hunt-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'basis'}`);
  const [category, setCategory] = useState<'vuln_case' | 'audit_method'>('vuln_case');
  const [err, setErr] = useState<string | null>(null);
  const toast = useToast();
  return (
    <Dialog open onClose={onClose} title="排查依据存为 skill" footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" onClick={() => void api.post<{ name: string; draftId: string }>(`/hunt-bases/${basisId}/save-as-skill`, { name, category }).then((r) => { toast.ok(`已生成知识草稿 ${r.name}，在知识库中审核后启用`); onClose(); }, (e) => setErr(errText(e)))}>保存</Button>
    </>}>
      <p className={ui.muted}>存入全局知识库，下次排查可以直接选择，全量审计中也会被按需加载。</p>
      <Field label="名称" hint="小写字母、数字与横线"><input className={cx(ui.input, ui.mono)} value={name} onChange={(e) => setName(e.target.value)} /></Field>
      <Field label="类别"><Segmented value={category} onChange={setCategory} items={[{ key: 'vuln_case', label: '漏洞案例' }, { key: 'audit_method', label: '审计方法' }]} /></Field>
      {err && <div className={ui.error}>{err}</div>}
    </Dialog>
  );
}

// ---- results --------------------------------------------------------------------------------------------------

function OverrideDialog({ t, onClose, onDone }: { t: HuntTargetDto; onClose: () => void; onDone: () => void }) {
  const [verdict, setVerdict] = useState<'affected' | 'not_affected' | 'pending'>((t.verdict ?? 'pending') as 'affected' | 'not_affected' | 'pending');
  const [reason, setReason] = useState('');
  const [err, setErr] = useState<string | null>(null);
  return (
    <Dialog open onClose={onClose} title={`改判 · ${t.projectName}${t.repoName ? ` / ${t.repoName}` : ''}`} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" disabled={!reason.trim()} onClick={() => void api.patch(`/hunt-targets/${t.id}`, { verdict, reason }).then(() => { onDone(); onClose(); }, (e) => setErr(errText(e)))}>保存</Button>
    </>}>
      <Segmented value={verdict} onChange={setVerdict} items={[{ key: 'affected', label: '受影响' }, { key: 'not_affected', label: '不受影响' }, { key: 'pending', label: '待确认' }]} />
      <Field label="理由（必填）"><textarea aria-label="改判理由" className={ui.input} rows={3} value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
      {err && <div className={ui.error}>{err}</div>}
    </Dialog>
  );
}

export function HuntPage() {
  const { hid } = useParams({ from: '/hunts/$hid' });
  const r = useQuery({
    queryKey: ['hunt', hid], queryFn: () => api.get<HuntResultsDto>(`/hunts/${hid}/results`),
    refetchInterval: (q) => ((q.state.data?.hunt.status ?? 'running') === 'running' ? 2000 : false), refetchIntervalInBackground: true,
  });
  // A hunt still at `planned` has no targets yet: show its plan with the confirm button.
  const planned = r.data?.hunt.status === 'planned';
  const planQ = useQuery({
    queryKey: ['hunt-plan', hid], enabled: planned, queryFn: () => api.get<HuntDto>(`/hunts/${hid}`),
    refetchInterval: (q) => (q.state.data?.plan?.estimate.precheck.status === 'running' ? 1000 : false), refetchIntervalInBackground: true,
  });
  const [override, setOverride] = useState<HuntTargetDto | null>(null);
  const [showBasis, setShowBasis] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const byProject = useMemo(() => {
    const m = new Map<string, HuntTargetDto[]>();
    for (const t of r.data?.targets ?? []) m.set(t.projectName, [...(m.get(t.projectName) ?? []), t]);
    return [...m];
  }, [r.data]);
  useEffect(() => { if (r.data && !['planned', 'running'].includes(r.data.hunt.status)) void qc.invalidateQueries({ queryKey: ['hunts'] }); }, [r.data, qc]);
  if (r.isLoading) return <><TopBar crumbs={[{ label: '风险排查', to: '/hunts' }]} /><PageLayout><Loading /></PageLayout></>;
  if (r.error) return <><TopBar crumbs={[{ label: '风险排查', to: '/hunts' }]} /><PageLayout><ErrorState error={r.error} /></PageLayout></>;
  const { hunt, hits } = r.data!;
  const s = hunt.summary;
  const running = hunt.status === 'running';
  const targets = r.data!.targets;
  const queued = running && targets.length > 0 && targets.every((t) => t.auditStatus === 'queued');
  const refresh = () => void qc.invalidateQueries({ queryKey: ['hunt', hid] });
  return (
    <>
      <TopBar crumbs={[{ label: '风险排查', to: '/hunts' }, { label: hunt.title }]} actions={<>
        {['md', 'html', 'json'].map((f) => <a key={f} className={ui.chip} href={`/api/v1/hunts/${hunt.id}/export?format=${f}`} download><Icon name="download" size={12} />{f.toUpperCase()}</a>)}
        <Button icon="refresh" disabled={running || planned} onClick={() => void api.post<HuntDto>(`/hunts/${hunt.id}/rerun`).then(async (h) => { await api.post(`/hunts/${h.id}/confirm`); void navigate({ to: '/hunts/$hid', params: { hid: h.id } }); }, (e) => toast.error(e))}>重新排查</Button>
      </>} />
      <PageLayout>
        <h1 style={{ margin: '0 0 6px' }}>{hunt.title}</h1>
        <div className={cx(ui.row, ui.wrap)}>
          <Badge tone={hunt.status === 'completed' ? 'ok' : queued ? 'warn' : running ? 'info' : 'warn'}>{running && !queued && <Spinner />}{queued ? '排队中' : STATUS[hunt.status]}</Badge>
          {queued && <span className={ui.faint} style={{ fontSize: 12 }}>一次只运行一个审计或排查，前面的完成后自动开始</span>}
          <span className={ui.muted}>{s.projects} 个项目 · {s.repositories} 个仓库：</span>
          <Badge tone="danger">受影响 {s.affected}</Badge><Badge tone="ok">不受影响 {s.notAffected}</Badge><Badge tone="warn">待确认 {s.pending}</Badge>
          {s.unfinished > 0 && <Badge>未完成 {s.unfinished}</Badge>}
          <span className={ui.faint} style={{ fontSize: 12 }}>依据：{KIND[hunt.basisKind]}{hunt.rerunOfId && <> · 与<Link to="/hunts/$hid" params={{ hid: hunt.rerunOfId }}>上一次排查</Link>对比</>}</span>
          <Button size="sm" variant="ghost" onClick={() => setShowBasis(!showBasis)}>{showBasis ? '收起依据' : '查看依据'}</Button>
        </div>
        {planned && (
          <Section title="排查计划">
            <p className={ui.muted} style={{ marginTop: 0, fontSize: 13 }}>这次排查已生成计划但还没有启动。核对范围与预估后确认启动；不需要时可以在侧栏删除。</p>
            {planQ.error ? <ErrorState error={planQ.error} /> : planQ.data?.plan ? <HuntPlan hunt={planQ.data} onConfirmed={refresh} /> : <Loading />}
          </Section>
        )}
        {showBasis && (
          <div className={ui.card} style={{ padding: 12, marginTop: 12, fontSize: 13 }}>
            <p style={{ marginTop: 0 }}>{hunt.basis.summary}</p>
            <div><b>受影响：</b>{hunt.basis.affectedIf.join('；')}</div>
            <div><b>不受影响：</b>{hunt.basis.notAffectedIf.join('；')}</div>
            <div><b>修复：</b>{hunt.basis.remediation}</div>
          </div>
        )}
        {!planned && <><Section title="各项目结论">
          {byProject.map(([project, ts]) => (
            <div key={project} className={ui.card} style={{ marginBottom: 12, overflow: 'auto' }}>
              <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)' }}><b>{project}</b> <VerdictBadge v={s.projectVerdicts[ts[0]!.projectId] === 'unfinished' ? null : s.projectVerdicts[ts[0]!.projectId] ?? null} audit={ts.every((t) => t.auditStatus === ts[0]!.auditStatus) ? ts[0]!.auditStatus : null} /></div>
              <table className={ui.table}>
                <thead><tr><th>仓库</th><th>结论</th><th>理由与依据</th>{hunt.rerunOfId && <th>变化</th>}<th /></tr></thead>
                <tbody>
                  {ts.map((t) => (
                    <tr key={t.id}>
                      <td>{t.repoName ?? '—'}{t.auditId && <div><Link to="/audits/$aid" params={{ aid: t.auditId }} className={ui.faint} style={{ fontSize: 12 }}>轨迹</Link></div>}</td>
                      <td><VerdictBadge v={t.verdict} audit={t.auditStatus} />{t.verdictSource === 'human' && <div className={ui.faint} style={{ fontSize: 11 }}>人工改判</div>}{t.verdictSource === 'rule' && <div className={ui.faint} style={{ fontSize: 11 }}>按规则</div>}</td>
                      <td style={{ fontSize: 13 }}>
                        {t.reason}
                        {t.evidence.slice(0, 4).map((e, i) => <div key={i} className={cx(ui.faint, ui.mono)} style={{ fontSize: 12 }}>· {e.path ? `${e.path}${e.startLine ? `:${e.startLine}` : ''} ` : ''}{e.note ?? ''}</div>)}
                        {t.pendingCondition && <div className={ui.faint} style={{ fontSize: 12 }}>缺：{t.pendingCondition.missing.map((m) => m.ref).join('、')}</div>}
                      </td>
                      {hunt.rerunOfId && <td>{t.delta ? <Badge tone={t.delta === 'new_affected' ? 'danger' : t.delta === 'cleared' ? 'ok' : 'neutral'}>{DELTA[t.delta]}</Badge> : ''}</td>}
                      <td>{t.verdict && <Button size="sm" variant="ghost" onClick={() => setOverride(t)}>改判</Button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </Section>
        <Section title={`受影响位置（${hits.length}）`}>
          {hits.length === 0 ? <p className={ui.faint}>{running ? '排查中…' : '没有受影响的位置。'}</p> : (
            <div className={ui.stack}>
              {hits.map((h) => (
                <div key={h.id} className={ui.card} style={{ padding: 12 }}>
                  <div className={cx(ui.row, ui.wrap)}>
                    <Badge tone="danger">{SEVERITY[h.severity] ?? h.severity}</Badge><b>{h.title}</b>
                    <span className={cx(ui.faint, ui.mono)} style={{ fontSize: 12 }}>{h.projectName} / {h.repoName} · {h.location.path}:{h.location.startLine}</span>
                    <span className={ui.grow} />
                    {h.promotedVulnId
                      ? <Link to="/projects/$pid" params={{ pid: h.projectId }} search={{ tab: 'vulns', panel: `vuln:${h.promotedVulnId}` }} className={ui.chip}>已转为 V-{h.promotedDisplayNo}</Link>
                      : <Button size="sm" variant="primary" onClick={() => void api.post<{ displayNo: number; created: boolean }>(`/hunt-hits/${h.id}/promote`).then((x) => { toast.ok(x.created ? `已转为漏洞 V-${x.displayNo}` : `与已有漏洞 V-${x.displayNo} 为同一漏洞`); refresh(); }, (e) => toast.error(e))}>转为漏洞</Button>}
                  </div>
                  <p className={ui.muted} style={{ fontSize: 13, marginBottom: 4 }}>{h.reasoning}</p>
                  {h.exploitConditions.map((c, i) => <div key={i} className={ui.faint} style={{ fontSize: 12 }}>· 利用条件：{c.condition}（{c.status}）</div>)}
                  {h.evidence.slice(0, 5).map((e, i) => <div key={i} className={cx(ui.faint, ui.mono)} style={{ fontSize: 12 }}>· {e.repo ? `${e.repo}:` : ''}{e.path}:{e.startLine}-{e.endLine} {e.note ?? ''}{!e.verified && '（未核实）'}</div>)}
                </div>
              ))}
            </div>
          )}
        </Section></>}
        {override && <OverrideDialog t={override} onClose={() => setOverride(null)} onDone={() => { toast.ok('已改判'); refresh(); }} />}
      </PageLayout>
    </>
  );
}
