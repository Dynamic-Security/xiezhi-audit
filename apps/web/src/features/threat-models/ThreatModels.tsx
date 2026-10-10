// 威胁建模 project tab: threat models of a project; sources added one by one (upload,
// online document, text — any number), generation, the clarification, and risk triage with reasons.
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { ThreatModelDto, ThreatModelSummaryDto, ThreatRiskDto, ThreatRiskStatus, ThreatSourceDto } from '@xiezhi/contracts';
import { API, api } from '../../shared/api/client';
import { useConnectors } from '../../shared/api/queries';
import { fmt } from '../../shared/format/messages';
import { Markdown } from '../../shared/markdown/Markdown';
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, ErrorState, Field, Icon, Loading, Segmented, cx, ui, useToast, type Tone } from '../../shared/ui';
import { Section } from '../layout/AppShell';
import { ThreatSyncButton } from './ThreatSync';

export const RISK_STATUS: Record<ThreatRiskStatus, string> = { pending: '待研判', to_mitigate: '需规避', mitigated: '已规避', accepted: '接受风险', false_positive: '误报 / 不适用' };
const RISK_TONE: Record<ThreatRiskStatus, Tone> = { pending: 'neutral', to_mitigate: 'warn', mitigated: 'ok', accepted: 'info', false_positive: 'neutral' };
const RISK_HINT: Record<ThreatRiskStatus, string> = {
  pending: 'AI 提出，尚未研判；审计中只作背景',
  to_mitigate: '真实风险，需要设计或代码规避；审计会验证是否已规避',
  mitigated: '已有规避措施；审计做回归检查',
  accepted: '业务上接受；审计中相关发现自动标为接受风险并折叠',
  false_positive: '不成立或就是功能本身；审计中相关发现自动标为误报并折叠',
};
const CATEGORY: Record<string, string> = {
  spoofing: '身份仿冒', tampering: '篡改', repudiation: '抵赖', information_disclosure: '信息泄露', denial_of_service: '拒绝服务',
  elevation_of_privilege: '权限提升', business_logic: '业务逻辑', abuse: '滥用',
};
const LEVEL: Record<string, string> = { high: '高', medium: '中', low: '低' };
/** A verified risk as a hypothesis: confirmed = present in the code, refuted = mitigated. */
const VERIFY_LABEL: Record<string, string> = { confirmed: '未规避（代码中存在）', refuted: '已规避', open: '无法判定', proposed: '未验证', dismissed: '人工排除', converted: '已转为漏洞' };
const LEVEL_TONE: Record<string, Tone> = { high: 'danger', medium: 'warn', low: 'neutral' };
const MODEL_STATUS: Record<string, [string, Tone]> = {
  draft: ['草稿', 'neutral'], generating: ['生成中', 'info'], ready: ['已生成', 'ok'], partial: ['结果不完整', 'warn'], failed: ['生成失败', 'danger'],
};
const KIND: Record<string, string> = { upload: '上传文档', online: '在线文档', text: '文字描述' };

const listKey = (pid: string) => ['threat-models', pid] as const;
const detailKey = (tid: string) => ['threat-model', tid] as const;

function ModelStatus({ status }: { status: string }) {
  const [label, tone] = MODEL_STATUS[status] ?? [status, 'neutral' as Tone];
  return <Badge tone={tone} dot pulse={status === 'generating'}>{label}</Badge>;
}

function riskSummary(c: ThreatModelSummaryDto['riskCounts']): string {
  const parts = (Object.keys(RISK_STATUS) as ThreatRiskStatus[]).filter((k) => c[k] > 0).map((k) => `${RISK_STATUS[k]} ${c[k]}`);
  return parts.length ? parts.join(' · ') : '无风险';
}

export function ThreatModelsTab({ pid, selected, onSelect }: { pid: string; selected: string | undefined; onSelect: (tid: string | undefined) => void }) {
  return selected ? <ThreatModelDetail pid={pid} tid={selected} onBack={() => onSelect(undefined)} /> : <ThreatModelList pid={pid} onSelect={onSelect} />;
}

function ThreatModelList({ pid, onSelect }: { pid: string; onSelect: (tid: string) => void }) {
  const q = useQuery({
    queryKey: listKey(pid), queryFn: () => api.get<{ items: ThreatModelSummaryDto[] }>(`/projects/${pid}/threat-models`),
    refetchInterval: (x) => (x.state.data?.items.some((t) => t.status === 'generating') ? 2000 : false),
  });
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState('');
  const toast = useToast();
  const create = async () => {
    try {
      const d = await api.post<ThreatModelDto>(`/projects/${pid}/threat-models`, { title: title.trim() });
      setCreating(false);
      setTitle('');
      onSelect(d.id);
    } catch (e) { toast.error(e); }
  };
  return (
    <>
      <div className={ui.spread} style={{ marginBottom: 12 }}>
        <p className={ui.muted} style={{ margin: 0 }}>根据需求、PRD、TRD 列出系统可能面临的风险，由人研判；审计（尤其是增量审计）可以引用研判结果。</p>
        <Button variant="primary" size="sm" icon="plus" onClick={() => setCreating(true)}>新建威胁模型</Button>
      </div>
      {q.error ? <ErrorState error={q.error} /> : !q.data ? <Loading /> : !q.data.items.length ? (
        <EmptyState icon="shield" title="还没有威胁模型" action={<Button variant="primary" icon="plus" onClick={() => setCreating(true)}>新建威胁模型</Button>}>
          添加需求文档、在线文档或文字描述，AI 生成功能澄清与风险清单。
        </EmptyState>
      ) : (
        <table className={ui.table}>
          <thead><tr><th>威胁模型</th><th>状态</th><th>来源</th><th>风险</th><th>生成时间</th></tr></thead>
          <tbody>
            {q.data.items.map((t) => (
              <tr key={t.id}>
                <td><button className={ui.ghost} style={{ padding: 0, fontWeight: 600 }} onClick={() => onSelect(t.id)}>{t.title}</button>{t.sourcesChanged && <Badge tone="warn">来源已变化</Badge>}</td>
                <td><ModelStatus status={t.status} /></td>
                <td>{t.sourceCount}</td>
                <td className={ui.faint} style={{ fontSize: 13 }}>{riskSummary(t.riskCounts)}</td>
                <td className={ui.faint} style={{ fontSize: 12 }}>{fmt.date(t.generatedAt)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Dialog open={creating} onClose={() => setCreating(false)} title="新建威胁模型" footer={<>
        <Button onClick={() => setCreating(false)}>取消</Button>
        <Button variant="primary" disabled={!title.trim()} onClick={() => void create()}>创建</Button>
      </>}>
        <Field label="标题" hint="例如需求名称或迭代名称"><input className={ui.input} value={title} maxLength={200} onChange={(e) => setTitle(e.target.value)} autoFocus /></Field>
      </Dialog>
    </>
  );
}

function ThreatModelDetail({ pid, tid, onBack }: { pid: string; tid: string; onBack: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({
    queryKey: detailKey(tid), queryFn: () => api.get<ThreatModelDto>(`/threat-models/${tid}`),
    refetchInterval: (x) => (x.state.data?.status === 'generating' ? 1500 : false), refetchIntervalInBackground: true,
  });
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);
  const refresh = async () => { await qc.invalidateQueries({ queryKey: detailKey(tid) }); await qc.invalidateQueries({ queryKey: listKey(pid) }); };
  const act = async (fn: () => Promise<unknown>, ok?: string) => {
    setBusy(true);
    try { await fn(); if (ok) toast.ok(ok); await refresh(); } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  if (q.error) return <ErrorState error={q.error} />;
  if (!q.data) return <Loading />;
  const d = q.data;
  const generating = d.status === 'generating';
  const blocked = d.sources.filter((s) => s.injection.length > 0 && !s.injectionAck && s.kind !== 'online');
  return (
    <div className={ui.stack} style={{ gap: 20 }}>
      <div className={ui.spread}>
        <div className={ui.row} style={{ gap: 10 }}>
          <Button variant="ghost" size="sm" icon="sidebar" onClick={onBack}>全部威胁模型</Button>
          <h2 style={{ margin: 0, fontSize: 18 }}>{d.title}</h2>
          <ModelStatus status={d.status} />
        </div>
        <div className={ui.row} style={{ gap: 8 }}>
          <Button variant="primary" size="sm" icon={generating ? undefined : 'sparkle'} loading={generating || busy}
            disabled={generating || !d.sources.length || blocked.length > 0}
            title={!d.sources.length ? '先添加来源' : blocked.length ? `先查看 ${blocked.map((s) => `S${s.no}`).join('、')} 的可疑内容` : undefined}
            onClick={() => void act(() => api.post(`/threat-models/${tid}/generate`, {}), '已开始生成')}>
            {generating ? '生成中…' : d.generatedAt ? '重新生成' : '生成'}
          </Button>
          <a className={cx(ui.btn, ui.sm)} href={`${API}/threat-models/${tid}/export`} download aria-disabled={!d.generatedAt}><Icon name="download" />导出 Markdown</a>
          <ThreatSyncButton pid={pid} tid={tid} disabled={!d.generatedAt || generating} />
          {d.generatedAt && !generating && <Link className={cx(ui.btn, ui.sm)} to="/audits/new" search={{ projectId: pid, scene: 'incremental', tm: [tid] }}><Icon name="play" />发起关联审计</Link>}
          <Button size="sm" variant="ghost" icon="trash" aria-label="删除威胁模型" disabled={generating} onClick={() => setDeleting(true)} />
        </div>
      </div>
      <div className={ui.faint} style={{ fontSize: 12 }}>
        {d.generatedAt ? `生成于 ${fmt.date(d.generatedAt)}` : '尚未生成'}{d.model ? ` · ${d.model}` : ''}{d.tokensIn + d.tokensOut > 0 ? ` · ${fmt.compact(d.tokensIn + d.tokensOut)} tokens · ${fmt.cost(d.costMicros)}` : ''}
      </div>
      {d.syncs.length > 0 && (
        <div className={ui.faint} style={{ fontSize: 12 }}>
          已同步：{d.syncs.map((x) => <span key={x.connectorId}>{x.connectorName} {x.externalUrl ? <a href={x.externalUrl} target="_blank" rel="noreferrer">{x.externalId}</a> : x.externalId}（{fmt.date(x.updatedAt)}）</span>)}
        </div>
      )}
      {d.error && <div className={ui.banner} role="status"><Icon name="alert" />{d.status === 'failed' ? '生成失败：' : '说明：'}{d.error}</div>}
      {d.sourcesChanged && !generating && <div className={ui.banner} role="status"><Icon name="refresh" />来源在上次生成后有变化，可以重新生成；已研判的风险会保留状态与理由。</div>}

      <Sources pid={pid} d={d} disabled={generating} onChanged={refresh} />

      <Section title="功能澄清" actions={d.clarification ? (
        d.clarifiedAt
          ? <Button size="sm" variant="ghost" onClick={() => void act(() => api.patch(`/threat-models/${tid}`, { clarified: false }))}>取消确认</Button>
          : <Button size="sm" icon="check" onClick={() => void act(() => api.patch(`/threat-models/${tid}`, { clarified: true }), '已确认澄清')}>确认澄清</Button>
      ) : undefined}>
        {d.clarification ? (
          <div className={cx(ui.card, ui.cardPad)}>
            <div className={ui.faint} style={{ fontSize: 12, marginBottom: 8 }}>{d.clarifiedAt ? `已确认（${fmt.date(d.clarifiedAt)}）：审计中作为已核实的业务背景使用` : '未确认：审计中按未核实信息使用'}</div>
            <Markdown text={d.clarification} />
          </div>
        ) : <p className={ui.faint}>生成后在这里列出功能、角色与权限、数据与资产、信任边界、设计如此的行为、待确认与冲突点。</p>}
      </Section>

      <Risks tid={tid} risks={d.risks} disabled={generating} onChanged={refresh} />

      <ConfirmDialog open={deleting} onClose={() => setDeleting(false)} title="删除威胁模型" level="destructive" confirmText="删除" typeToConfirm={d.title}
        onConfirm={() => void act(async () => { await api.del(`/threat-models/${tid}`); setDeleting(false); onBack(); }, '已删除')}>
        将删除该威胁模型的全部来源、功能澄清与风险研判。已经引用它的审计保留当时的副本。
      </ConfirmDialog>
    </div>
  );
}

// ---- sources -----------------------------------------------------------------------------------------------

type SourceDraft = { kind: 'text' | 'online'; id?: string; title: string; note: string; text: string; connectorId: string; docRef: string };

function Sources({ pid, d, disabled, onChanged }: { pid: string; d: ThreatModelDto; disabled: boolean; onChanged: () => Promise<void> }) {
  const toast = useToast();
  const [draft, setDraft] = useState<SourceDraft | null>(null);
  const [viewing, setViewing] = useState<ThreatSourceDto | null>(null);
  const [removing, setRemoving] = useState<ThreatSourceDto | null>(null);
  const [busy, setBusy] = useState(false);
  const run = async (fn: () => Promise<unknown>, ok?: string) => {
    setBusy(true);
    try { await fn(); if (ok) toast.ok(ok); await onChanged(); } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  const upload = async (files: FileList | null) => {
    if (!files?.length) return;
    await run(async () => {
      for (const f of [...files]) {
        if (f.size > 256 * 1024) throw new Error(`${f.name} 超过 256 KB`);
        await api.post(`/threat-models/${d.id}/sources`, { kind: 'upload', title: f.name, content: await f.text() });
      }
    }, files.length > 1 ? `已添加 ${files.length} 份文档` : '已添加文档');
  };
  const move = (i: number, delta: number) => {
    const ids = d.sources.map((s) => s.id);
    const j = i + delta;
    if (j < 0 || j >= ids.length) return;
    [ids[i], ids[j]] = [ids[j]!, ids[i]!];
    void run(() => api.put(`/threat-models/${d.id}/source-order`, { ids }));
  };
  const save = async () => {
    if (!draft) return;
    const body = draft.kind === 'text'
      ? { ...(draft.title.trim() ? { title: draft.title.trim() } : {}), text: draft.text, note: draft.note.trim() || (draft.id ? null : undefined) }
      : { title: draft.title.trim(), connectorId: draft.connectorId, docRef: draft.docRef.trim(), note: draft.note.trim() || (draft.id ? null : undefined) };
    await run(async () => {
      if (draft.id) await api.patch(`/threat-model-sources/${draft.id}`, body);
      else await api.post(`/threat-models/${d.id}/sources`, { kind: draft.kind, ...body });
      setDraft(null);
    }, draft.id ? '已保存' : '已添加');
  };
  const empty = (kind: 'text' | 'online'): SourceDraft => ({ kind, title: '', note: '', text: '', connectorId: '', docRef: '' });
  return (
    <Section title={`输入来源（${d.sources.length}）`} actions={
      <div className={ui.row} style={{ gap: 6 }}>
        <label className={cx(ui.btn, ui.sm)} aria-disabled={disabled}>
          <Icon name="upload" />上传文档
          <input type="file" accept=".md,.markdown,.txt,text/markdown,text/plain" multiple hidden disabled={disabled} onChange={(e) => { void upload(e.target.files); e.target.value = ''; }} />
        </label>
        <Button size="sm" icon="link" disabled={disabled} onClick={() => setDraft(empty('online'))}>添加在线文档</Button>
        <Button size="sm" icon="edit" disabled={disabled} onClick={() => setDraft(empty('text'))}>添加文字描述</Button>
      </div>
    }>
      {!d.sources.length ? <p className={ui.faint}>逐条添加需求、PRD、TRD：可以上传 Markdown / 纯文本文档、引用在线文档（通过连接器读取）或直接写文字补充，数量不限。</p> : (
        <table className={ui.table}>
          <thead><tr><th style={{ width: 48 }}>编号</th><th>来源</th><th>状态</th><th style={{ width: 200 }} /></tr></thead>
          <tbody>
            {d.sources.map((s, i) => (
              <tr key={s.id}>
                <td className={ui.mono}>S{s.no}</td>
                <td>
                  <div className={ui.row} style={{ gap: 6 }}><Badge>{KIND[s.kind]}</Badge><b>{s.title}</b></div>
                  {s.kind === 'online' && <div className={cx(ui.faint, ui.mono)} style={{ fontSize: 12 }}>{s.docRef}</div>}
                  {s.note && <div className={ui.muted} style={{ fontSize: 12 }}>备注：{s.note}</div>}
                  {s.injection.length > 0 && (
                    <div style={{ fontSize: 12, marginTop: 4 }}>
                      <Badge tone="warn">疑似注入内容</Badge> <span className={ui.faint}>第 {s.injection.map((x) => x.line).join('、')} 行：{s.injection[0]!.excerpt}</span>
                      {!s.injectionAck && s.kind !== 'online' && <Button size="sm" variant="ghost" disabled={disabled || busy} onClick={() => void run(() => api.patch(`/threat-model-sources/${s.id}`, { injectionAck: true }), '已允许使用')}>已查看，允许使用</Button>}
                    </div>
                  )}
                </td>
                <td style={{ fontSize: 12 }}>
                  {s.kind !== 'online' ? fmt.bytes(s.bytes)
                    : s.fetchStatus === 'ok' ? <span title={s.fetchedAt ?? ''}>已取回 {fmt.bytes(s.bytes)}</span>
                      : s.fetchStatus === 'failed' ? <Badge tone="danger" title={s.fetchError ?? ''}>读取失败</Badge>
                        : <span className={ui.faint}>生成时读取</span>}
                  {s.fetchStatus === 'failed' && s.fetchError && <div className={ui.faint}>{s.fetchError}</div>}
                </td>
                <td>
                  <div className={ui.row} style={{ gap: 2, justifyContent: 'flex-end' }}>
                    <Button size="sm" variant="ghost" icon="eye" aria-label={`查看 S${s.no}`} disabled={!s.contentHash} onClick={() => setViewing(s)} />
                    <Button size="sm" variant="ghost" aria-label={`上移 S${s.no}`} disabled={disabled || busy || i === 0} onClick={() => move(i, -1)}>↑</Button>
                    <Button size="sm" variant="ghost" aria-label={`下移 S${s.no}`} disabled={disabled || busy || i === d.sources.length - 1} onClick={() => move(i, 1)}>↓</Button>
                    {s.kind !== 'upload' && <Button size="sm" variant="ghost" icon="edit" aria-label={`编辑 S${s.no}`} disabled={disabled} onClick={async () => {
                      const text = s.kind === 'text' ? (await api.get<{ text: string }>(`/threat-model-sources/${s.id}/content`).catch(() => ({ text: '' }))).text : '';
                      setDraft({ kind: s.kind as 'text' | 'online', id: s.id, title: s.title, note: s.note ?? '', text, connectorId: s.connectorId ?? '', docRef: s.docRef ?? '' });
                    }} />}
                    <Button size="sm" variant="ghost" icon="trash" aria-label={`删除 S${s.no}`} disabled={disabled} onClick={() => setRemoving(s)} />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {draft && <SourceDialog pid={pid} draft={draft} busy={busy} onChange={setDraft} onClose={() => setDraft(null)} onSave={() => void save()} />}
      {viewing && <SourceView source={viewing} onClose={() => setViewing(null)} />}
      <ConfirmDialog open={!!removing} onClose={() => setRemoving(null)} title={`删除来源 S${removing?.no ?? ''}`} confirmText="删除"
        onConfirm={() => void run(async () => { await api.del(`/threat-model-sources/${removing!.id}`); setRemoving(null); }, '已删除')}>
        删除后编号不会复用；重新生成时不再使用这条来源。
      </ConfirmDialog>
    </Section>
  );
}

function SourceDialog({ draft, busy, onChange, onClose, onSave }: { pid: string; draft: SourceDraft; busy: boolean; onChange: (d: SourceDraft) => void; onClose: () => void; onSave: () => void }) {
  const connectors = useConnectors();
  const usable = connectors.data ?? [];
  const valid = draft.kind === 'text' ? !!draft.text.trim() : !!draft.title.trim() && !!draft.connectorId && !!draft.docRef.trim();
  const set = (patch: Partial<SourceDraft>) => onChange({ ...draft, ...patch });
  return (
    <Dialog open onClose={onClose} wide={draft.kind === 'text'} title={`${draft.id ? '编辑' : '添加'}${draft.kind === 'text' ? '文字描述' : '在线文档'}`} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!valid} onClick={onSave}>{draft.id ? '保存' : '添加'}</Button>
    </>}>
      {draft.kind === 'online' && (
        <>
          <Field label="连接器" hint={usable.length ? '读取在线文档的连接器。生成时按知识库中的读取指引调用它的读取操作。' : '还没有可用的连接器：在 设置 › 连接器包 用 lark-cli 添加（名称建议用 Feishu），或在 MCP 连接器中添加。'}>
            <select className={ui.input} value={draft.connectorId} onChange={(e) => set({ connectorId: e.target.value })}>
              <option value="">选择连接器…</option>
              {usable.map((c) => <option key={c.id} value={c.id}>{c.name}{c.status !== 'ready' ? `（${c.status === 'failed' ? '测试失败' : '未就绪'}）` : ''}</option>)}
            </select>
          </Field>
          <Field label="文档链接或 ID"><input className={ui.input} value={draft.docRef} maxLength={2000} placeholder="https://xxx.feishu.cn/docx/…" onChange={(e) => set({ docRef: e.target.value })} /></Field>
        </>
      )}
      <Field label={draft.kind === 'text' ? '标题（可选）' : '标题'}><input className={ui.input} value={draft.title} maxLength={200} onChange={(e) => set({ title: e.target.value })} /></Field>
      {draft.kind === 'text' && (
        <textarea aria-label="文字描述" className={ui.textarea} style={{ minHeight: '28vh' }} value={draft.text} onChange={(e) => set({ text: e.target.value })}
          placeholder="补充需求说明、业务规则或后来的修改…" />
      )}
      <Field label="备注（可选）" hint="例如“以这份为准”“这是后来的修改”；生成时按备注判断来源之间的优先级。"><input className={ui.input} value={draft.note} maxLength={1000} onChange={(e) => set({ note: e.target.value })} /></Field>
    </Dialog>
  );
}

function SourceView({ source, onClose }: { source: ThreatSourceDto; onClose: () => void }) {
  const q = useQuery({ queryKey: ['threat-source', source.id, source.contentHash], queryFn: () => api.get<{ text: string }>(`/threat-model-sources/${source.id}/content`) });
  return (
    <Dialog open onClose={onClose} wide="xl" title={`S${source.no} · ${source.title}`}>
      {q.error ? <ErrorState error={q.error} /> : q.data === undefined ? <Loading /> : <pre className={cx(ui.pre, ui.mono)} style={{ maxHeight: '60vh', overflow: 'auto', whiteSpace: 'pre-wrap', fontSize: 12.5 }}>{q.data.text}</pre>}
    </Dialog>
  );
}

// ---- risks -------------------------------------------------------------------------------------------------

function Risks({ tid, risks, disabled, onChanged }: { tid: string; risks: ThreatRiskDto[]; disabled: boolean; onChanged: () => Promise<void> }) {
  const [filter, setFilter] = useState<'all' | ThreatRiskStatus>('all');
  const [picked, setPicked] = useState<string[]>([]);
  const [deciding, setDeciding] = useState<{ ids: string[]; risk?: ThreatRiskDto } | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const shown = risks.filter((r) => filter === 'all' || r.status === filter);
  const count = (s: ThreatRiskStatus) => risks.filter((r) => r.status === s).length;
  return (
    <Section title={`风险清单（${risks.length}）`} actions={picked.length ? <Button size="sm" variant="primary" disabled={disabled} onClick={() => setDeciding({ ids: picked })}>批量研判（{picked.length}）</Button> : undefined}>
      {!risks.length ? <p className={ui.faint}>生成后在这里列出风险，逐条研判：待研判、需规避、已规避、接受风险、误报 / 不适用。</p> : (
        <>
          <div style={{ marginBottom: 10 }}>
            <Segmented value={filter} onChange={(v) => { setFilter(v); setPicked([]); }} items={[
              { key: 'all', label: `全部 ${risks.length}` },
              ...(Object.keys(RISK_STATUS) as ThreatRiskStatus[]).map((k) => ({ key: k, label: `${RISK_STATUS[k]} ${count(k)}` })),
            ]} />
          </div>
          <table className={ui.table}>
            <thead><tr>
              <th style={{ width: 28 }}><input type="checkbox" aria-label="全选" checked={shown.length > 0 && shown.every((r) => picked.includes(r.id))} onChange={(e) => setPicked(e.target.checked ? shown.map((r) => r.id) : [])} /></th>
              <th style={{ width: 56 }}>编号</th><th style={{ width: 52 }}>等级</th><th>风险</th><th style={{ width: 120 }}>状态</th><th style={{ width: 72 }} />
            </tr></thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.id}>
                  <td><input type="checkbox" aria-label={`选择 ${r.code}`} checked={picked.includes(r.id)} onChange={(e) => setPicked(e.target.checked ? [...picked, r.id] : picked.filter((x) => x !== r.id))} /></td>
                  <td className={ui.mono}>{r.code}</td>
                  <td>{r.level ? <Badge tone={LEVEL_TONE[r.level]}>{LEVEL[r.level]}</Badge> : '—'}</td>
                  <td>
                    <div className={ui.row} style={{ gap: 6, alignItems: 'baseline' }}>
                      <span className={ui.faint} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{CATEGORY[r.category] ?? r.category}</span>
                      <button className={ui.ghost} style={{ padding: 0, textAlign: 'left' }} aria-expanded={open === r.id} onClick={() => setOpen(open === r.id ? null : r.id)}>{r.statement}</button>
                      {r.stale && <Badge tone="neutral" title="最近一次生成没有再提出这条风险；研判结果保留">本次未提出</Badge>}
                    </div>
                    <div className={ui.faint} style={{ fontSize: 12 }}>来源 {r.sources.map((n) => `S${n}`).join('、')}{r.features.length ? ` · ${r.features.join('、')}` : ''}</div>
                    {open === r.id && (
                      <div className={ui.stack} style={{ gap: 4, fontSize: 13, marginTop: 6 }}>
                        {r.impact && <div><b>影响：</b>{r.impact}</div>}
                        {r.mitigation && <div><b>规避建议：</b>{r.mitigation}</div>}
                        {r.verifications.length > 0 && (
                          <div style={{ fontSize: 12 }}>
                            <b>审计验证（建议，不自动改状态）：</b>
                            {r.verifications.slice(0, 3).map((v) => <div key={v.auditId}><Link to="/audits/$aid" params={{ aid: v.auditId }}>{v.auditTitle}</Link>：{VERIFY_LABEL[v.status] ?? v.status}{v.reason ? ` — ${v.reason.slice(0, 200)}` : ''}</div>)}
                          </div>
                        )}
                        {r.vulnerabilities.length > 0 && <div style={{ fontSize: 12 }}><b>相关漏洞：</b>{r.vulnerabilities.map((v) => `V-${v.displayNo} ${v.title}`).join('；')}</div>}
                        {r.history.length > 0 && (
                          <div className={ui.faint} style={{ fontSize: 12 }}>
                            {r.history.slice().reverse().map((h, k) => <div key={k}>{fmt.date(h.at)} · {h.actor}：{RISK_STATUS[h.from as ThreatRiskStatus]} → {RISK_STATUS[h.to as ThreatRiskStatus]}{h.reason ? `（${h.reason}）` : ''}</div>)}
                          </div>
                        )}
                      </div>
                    )}
                  </td>
                  <td>
                    <Badge tone={RISK_TONE[r.status as ThreatRiskStatus]} title={RISK_HINT[r.status as ThreatRiskStatus]}>{RISK_STATUS[r.status as ThreatRiskStatus]}</Badge>
                    {r.reason && <div className={ui.faint} style={{ fontSize: 12 }}>{r.reason}</div>}
                    {r.verifications[0] && <div style={{ fontSize: 11 }} className={ui.faint}>最近审计：{VERIFY_LABEL[r.verifications[0].status] ?? r.verifications[0].status}</div>}
                  </td>
                  <td><Button size="sm" disabled={disabled} onClick={() => setDeciding({ ids: [r.id], risk: r })}>研判</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {deciding && <DecideDialog tid={tid} target={deciding} onClose={() => setDeciding(null)} onDone={async () => { setDeciding(null); setPicked([]); await onChanged(); }} />}
    </Section>
  );
}

function DecideDialog({ tid, target, onClose, onDone }: { tid: string; target: { ids: string[]; risk?: ThreatRiskDto }; onClose: () => void; onDone: () => Promise<void> }) {
  const toast = useToast();
  const [status, setStatus] = useState<ThreatRiskStatus>(target.risk?.status && target.risk.status !== 'pending' ? target.risk.status as ThreatRiskStatus : 'to_mitigate');
  const [reason, setReason] = useState(target.risk?.reason ?? '');
  const [busy, setBusy] = useState(false);
  const needsReason = status !== 'pending';
  const submit = async () => {
    setBusy(true);
    try {
      const body = { status, reason: reason.trim() || null };
      if (target.ids.length === 1) await api.patch(`/threat-risks/${target.ids[0]}`, body);
      else await api.patch(`/threat-models/${tid}/risks`, { ids: target.ids, ...body });
      toast.ok('已保存研判');
      await onDone();
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <Dialog open onClose={onClose} title={target.risk ? `研判 ${target.risk.code}` : `批量研判 ${target.ids.length} 条风险`} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={needsReason && !reason.trim()} onClick={() => void submit()}>保存</Button>
    </>}>
      {target.risk && <p style={{ margin: 0 }}>{target.risk.statement}</p>}
      <div className={ui.stack} style={{ gap: 6 }} role="radiogroup" aria-label="风险状态">
        {(Object.keys(RISK_STATUS) as ThreatRiskStatus[]).map((k) => (
          <label key={k} className={ui.checkbox} style={{ alignItems: 'flex-start' }}>
            <input type="radio" name="risk-status" checked={status === k} onChange={() => setStatus(k)} />
            <span><b>{RISK_STATUS[k]}</b><span className={ui.faint} style={{ fontSize: 12, display: 'block' }}>{RISK_HINT[k]}</span></span>
          </label>
        ))}
      </div>
      <Field label={needsReason ? '理由（必填）' : '理由（可选）'}>
        <textarea aria-label="研判理由" className={ui.textarea} value={reason} maxLength={2000} onChange={(e) => setReason(e.target.value)} placeholder="例如：网关已校验订单所有者；或：这是需求要求的功能" />
      </Field>
    </Dialog>
  );
}
