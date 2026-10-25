// Knowledge drafts (入库与质量控制): import / paste for AI organizing, the
// review dialog (schema errors, suspected injection, same name, similar knowledge, contradictions with a
// merge proposal), approve / reject, and moving a project skill to global.
import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { KnowledgeDraftDto, MoveToGlobalPreviewDto } from '@xiezhi/contracts';
import { ApiError, api } from '../../shared/api/client';
import { fmt } from '../../shared/format/messages';
import { Badge, Button, Dialog, EmptyState, Field, Loading, Spinner, cx, ui, useToast } from '../../shared/ui';
import { SkillPreview } from './Markdown';
import { CATEGORY } from './skills';

const STATUS: Record<string, { l: string; t: 'info' | 'warn' | 'danger' | 'ok' | 'neutral' }> = {
  organizing: { l: 'AI 整理中', t: 'info' }, ready: { l: '待审核', t: 'warn' }, failed: { l: '失败', t: 'danger' }, approved: { l: '已启用', t: 'ok' }, rejected: { l: '已驳回', t: 'neutral' },
};
const SUGGESTION: Record<string, string> = { merge: '建议合并', replace: '建议以新替旧', keep_both: '建议保留两者并互相注明' };

export function useDrafts(pid?: string) {
  return useQuery({
    queryKey: ['knowledge', pid ?? 'global', 'drafts'], queryFn: () => api.get<KnowledgeDraftDto[]>(`/knowledge/drafts${pid ? `?projectId=${pid}` : ''}`),
    refetchInterval: (q) => (q.state.data?.some((d) => d.status === 'organizing') ? 1500 : false),
  });
}

export function DraftList({ pid, onOpen }: { pid?: string; onOpen: (id: string) => void }) {
  const q = useDrafts(pid);
  if (!q.data?.length) return null;
  return (
    <section style={{ marginTop: 20 }} aria-label="待审核的知识草稿">
      <h2 style={{ fontSize: 15, marginBottom: 10 }}>待审核 <Badge tone="warn">{q.data.length}</Badge></h2>
      <div className={ui.card} style={{ overflow: 'auto' }}>
        <table className={ui.table}>
          <tbody>{q.data.map((d) => (
            <tr key={d.id} className={ui.rowLink} onClick={() => onOpen(d.id)}>
              <td>
                <div className={ui.row} style={{ gap: 8 }}>
                  <b>{d.kind === 'case' ? `${d.library}/${d.name ?? '…'}.md` : d.name ?? '（整理中）'}</b>
                  <Badge tone={STATUS[d.status]!.t}>{STATUS[d.status]!.l}</Badge>
                  {d.checks.errors.length > 0 && <Badge tone="danger">格式问题</Badge>}
                  {d.checks.injection.length > 0 && <Badge tone="danger">疑似注入</Badge>}
                  {d.checks.conflicts.length > 0 && <Badge tone="warn">结论矛盾</Badge>}
                  {d.checks.sameName && <Badge tone="warn">同名</Badge>}
                </div>
                <div className={ui.faint} style={{ fontSize: 12 }}>来源：{d.source.label}</div>
              </td>
              <td className={ui.faint} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{fmt.ago(d.createdAt)}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </section>
  );
}

/** Review one draft: checks, editable text with preview, approve / reject. */
export function DraftDialog({ id, onClose, onApproved }: { id: string | null; onClose: () => void; onApproved?: (name: string) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const q = useQuery({
    queryKey: ['knowledge-draft', id], enabled: !!id, queryFn: () => api.get<KnowledgeDraftDto>(`/knowledge/drafts/${id}`),
    refetchInterval: (x) => (x.state.data?.status === 'organizing' ? 1000 : false),
  });
  const d = q.data;
  const [text, setText] = useState('');
  const [dirty, setDirty] = useState(false);
  const [replace, setReplace] = useState(false);
  const [deleteOriginal, setDeleteOriginal] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { if (d && !dirty) setText(d.text); }, [d, dirty]);
  useEffect(() => { if (!id) { setDirty(false); setErr(null); setReplace(false); } }, [id]);
  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: ['knowledge'] }), qc.invalidateQueries({ queryKey: ['knowledge-draft', id] }), qc.invalidateQueries({ queryKey: ['skill'] })]);
  const act = async (what: string, fn: () => Promise<unknown>, done?: string) => {
    setBusy(what);
    setErr(null);
    try {
      await fn();
      if (done) toast.ok(done);
      await refresh();
    } catch (e) {
      setErr(e instanceof ApiError ? [e.message, e.hint, ...((e.details?.errors as string[] | undefined) ?? [])].filter(Boolean).join('：') : String(e));
      throw e;
    } finally {
      setBusy(null);
    }
  };
  const saveEdits = () => act('save', async () => { await api.put(`/knowledge/drafts/${id}`, { text, revision: d!.revision }); setDirty(false); }, '已保存修改');
  const approve = async () => {
    if (dirty) await saveEdits();
    const approved = { name: '' };
    await act('approve', async () => { approved.name = (await api.post<{ name: string }>(`/knowledge/drafts/${id}/approve`, { ...(replace ? { replace: true } : {}), ...(d?.moveFrom ? { afterMove: deleteOriginal ? 'delete' : 'keep' } : {}) })).name; }, '已启用');
    onClose();
    if (approved.name) onApproved?.(approved.name);
  };
  const reject = async () => { await act('reject', () => api.post(`/knowledge/drafts/${id}/reject`), '已驳回（保留 30 天）'); onClose(); };
  const c = d?.checks;
  const decided = d && (d.status === 'approved' || d.status === 'rejected');
  return (
    <Dialog open={!!id} onClose={onClose} wide="xl" title={d ? `知识草稿 · ${d.kind === 'case' ? `${d.library}/${d.name ?? '…'}.md` : d.name ?? '整理中'}` : '知识草稿'} footer={d && !decided && d.status !== 'organizing' ? <>
      {err && <div role="alert" className={ui.error} style={{ marginRight: 'auto', maxWidth: '60%' }}>{err}</div>}
      <Button variant="danger" loading={busy === 'reject'} onClick={() => void reject().catch(() => undefined)}>驳回</Button>
      {dirty && <Button loading={busy === 'save'} onClick={() => void saveEdits().catch(() => undefined)}>保存修改</Button>}
      <Button variant="primary" loading={busy === 'approve'} disabled={!!c?.sameName && !replace} onClick={() => void approve().catch(() => undefined)}>审核通过并启用</Button>
    </> : undefined}>
      {!d ? <Loading rows={6} /> : (
        <>
          <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
            <Badge tone={STATUS[d.status]!.t}>{STATUS[d.status]!.l}</Badge>
            <Badge>{d.layer === 'global' ? '全局知识库' : '项目知识库'}</Badge>
            {d.kind === 'case' && <Badge tone="info">案例 · {d.library}</Badge>}
            <span className={ui.faint} style={{ fontSize: 12 }}>来源：{d.source.label}{d.model ? ` · 整理模型 ${d.model}` : ''}{d.tokens ? ` · ${fmt.tokens(d.tokens)} tokens` : ''}</span>
          </div>
          {d.status === 'organizing' && <div className={ui.row} style={{ gap: 8 }}><Spinner /><span className={ui.muted}>AI 正在整理并检查重复与冲突…</span></div>}
          {d.error && <div className={ui.banner} role="alert">整理失败：{d.error}</div>}
          {c && d.status !== 'organizing' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {c.errors.length > 0 && <div className={ui.banner} role="alert">格式问题（修正后才能启用）：{c.errors.join('；')}</div>}
              {c.injection.length > 0 && (
                <div className={ui.banner} role="alert">
                  检测到疑似面向 AI 的指令内容（已作为数据处理，未执行）。启用前请确认正文中没有这类内容：
                  <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>{c.injection.map((i, k) => <li key={k} className={ui.mono} style={{ fontSize: 12 }}>第 {i.line} 行 · {i.signal}：{i.excerpt}</li>)}</ul>
                </div>
              )}
              {c.sameName && (
                <label className={ui.checkbox}>
                  <input type="checkbox" checked={replace} onChange={(e) => setReplace(e.target.checked)} />
                  已存在同名{c.sameName.file ? `案例 ${c.sameName.name}/${c.sameName.file}` : ` skill ${c.sameName.name}`}：启用时替换它（或在下方修改名称）
                </label>
              )}
              {c.overridesGlobal && <div className={ui.faint} style={{ fontSize: 12 }}>启用后将在本项目覆盖同名全局 skill。</div>}
              {c.similar.length > 0 && (
                <div className={ui.faint} style={{ fontSize: 12 }}>相似的已有知识：{c.similar.map((s) => `${s.layer === 'global' ? '全局' : '项目'} ${s.name}${s.file ? `/${s.file}` : ''}（相似度 ${s.score}）`).join('、')}</div>
              )}
              {c.conflicts.map((x, k) => (
                <div key={k} className={ui.card} style={{ padding: 10 }}>
                  <div className={ui.row} style={{ gap: 8 }}><b>与 {x.layer === 'global' ? '全局' : '项目'} {x.name}{x.file ? `/${x.file}` : ''} 结论矛盾</b><Badge tone="warn">{SUGGESTION[x.suggestion] ?? x.suggestion}</Badge></div>
                  <ul style={{ margin: '6px 0 0', paddingLeft: 18, fontSize: 13 }}>{x.points.map((p, j) => <li key={j}>{p}</li>)}</ul>
                  {x.merged && !decided && <Button size="sm" style={{ marginTop: 6 }} onClick={() => { setText(x.merged!); setDirty(true); }}>采用合并稿（启用前可继续修改）</Button>}
                </div>
              ))}
              {d.moveFrom && !decided && (
                <label className={ui.checkbox}><input type="checkbox" checked={deleteOriginal} onChange={(e) => setDeleteOriginal(e.target.checked)} />启用后删除项目中的原 skill（不勾选则保留为项目覆盖版本）</label>
              )}
            </div>
          )}
          {d.status !== 'organizing' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, minHeight: '45vh' }}>
              <textarea aria-label="草稿内容" className={cx(ui.textarea, ui.mono)} style={{ minHeight: '45vh', fontSize: 12.5 }} value={text} readOnly={!!decided}
                onChange={(e) => { setText(e.target.value); setDirty(true); }} spellCheck={false} />
              <div className={ui.card} style={{ padding: 14, overflow: 'auto', maxHeight: '55vh' }} aria-label="草稿预览"><SkillPreview text={text} /></div>
            </div>
          )}
          {d.inputPreview && d.source.kind !== 'manual' && (
            <details><summary className={ui.faint} style={{ fontSize: 12, cursor: 'pointer' }}>查看原始输入</summary><pre className={cx(ui.pre, ui.mono)} style={{ fontSize: 12, maxHeight: 240, overflow: 'auto' }}>{d.inputPreview}</pre></details>
          )}
        </>
      )}
    </Dialog>
  );
}

/** Paste or upload text for AI organizing (or a complete skill file to check as is). */
export function ImportDialog({ open, onClose, pid, onCreated, preset }: {
  open: boolean; onClose: () => void; pid?: string | undefined; onCreated: (id: string) => void;
  preset?: { category?: string; text?: string; label?: string };
}) {
  const toast = useToast();
  const [text, setText] = useState('');
  const [label, setLabel] = useState('');
  const [organize, setOrganize] = useState(true);
  const [kind, setKind] = useState<'skill' | 'case'>('skill');
  const [category, setCategory] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) return;
    setText(preset?.text ?? '');
    setLabel(preset?.label ?? '');
    setCategory(preset?.category ?? '');
    setOrganize(true);
    setKind('skill');
  }, [open, preset]);
  const readFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > 1024 * 1024) { toast.error(new Error('文件过大（上限 1 MB 文本）')); return; }
    setText(await f.text());
    setLabel(f.name);
  };
  const submit = async () => {
    setBusy(true);
    try {
      const d = await api.post<KnowledgeDraftDto>('/knowledge/drafts', {
        layer: pid ? 'project' : 'global', ...(pid ? { projectId: pid } : {}), kind, text, organize, ...(category ? { category } : {}),
        source: { kind: label ? 'upload' : organize ? 'text' : 'manual', ...(label ? { label } : {}) },
      });
      onClose();
      onCreated(d.id);
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <Dialog open={open} onClose={onClose} wide title={pid ? '导入到项目知识库' : '导入到全局知识库'} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!text.trim()} onClick={() => void submit()}>{organize ? '交给 AI 整理' : '检查并生成草稿'}</Button>
    </>}>
      <p className={ui.muted} style={{ margin: 0 }}>粘贴文档、规则或经验，AI 会整理成 skill（写好描述、按模板组织），并检查格式、重复与冲突；外部内容一律作为数据处理。生成的是草稿，审核通过后才会启用。</p>
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 12, alignItems: 'flex-end' }}>
        <Field label="类型"><select className={ui.input} value={kind} onChange={(e) => setKind(e.target.value as 'skill' | 'case')}><option value="skill">一条 skill</option><option value="case">漏洞案例（进入案例库）</option></select></Field>
        {kind === 'skill' && <Field label="类别建议"><select className={ui.input} value={category} onChange={(e) => setCategory(e.target.value)}><option value="">由 AI 判断</option>{Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>}
        <Field label="上传文本文件"><input type="file" accept=".md,.txt,.markdown,text/*" onChange={(e) => void readFile(e.target.files?.[0])} /></Field>
      </div>
      <textarea aria-label="导入内容" className={cx(ui.textarea, ui.mono)} style={{ minHeight: '36vh', fontSize: 12.5 }} value={text} onChange={(e) => setText(e.target.value)} placeholder="粘贴要整理的内容…" />
      <label className={ui.checkbox}><input type="checkbox" checked={organize} onChange={(e) => setOrganize(e.target.checked)} />由 AI 整理（取消勾选：内容已是完整的 skill 文件，只做校验与查重）</label>
    </Dialog>
  );
}

/** Move a project skill to global: clean up the flagged private details, then a global draft. */
export function MoveToGlobalDialog({ pid, name, onClose, onCreated }: { pid: string; name: string | null; onClose: () => void; onCreated: (id: string) => void }) {
  const toast = useToast();
  const q = useQuery({ queryKey: ['move-to-global', pid, name], enabled: !!name, queryFn: () => api.post<MoveToGlobalPreviewDto>(`/projects/${pid}/knowledge/${name}/move-to-global`, {}) });
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (q.data) setText(q.data.text); }, [q.data]);
  const submit = async () => {
    setBusy(true);
    try {
      const d = await api.post<KnowledgeDraftDto>(`/projects/${pid}/knowledge/${name}/move-to-global`, { confirm: true, text });
      onClose();
      onCreated(d.id);
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  const remaining = (q.data?.hints ?? []).filter((h) => text.toLowerCase().includes(h.text.toLowerCase()));
  return (
    <Dialog open={!!name} onClose={onClose} wide title={`移到全局 · ${name ?? ''}`} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!q.data} onClick={() => void submit()}>生成全局草稿</Button>
    </>}>
      {q.isLoading ? <Loading /> : !q.data ? <EmptyState title="无法读取" /> : (
        <>
          <p className={ui.muted} style={{ margin: 0 }}>全局 skill 对所有项目可见。请去掉项目私有信息（内部域名、IP、业务名、人名、工单号）；下面列出了自动识别到的可疑内容。{q.data.globalExists ? '全局已有同名 skill，启用时需要选择替换。' : ''}</p>
          {q.data.hints.length > 0 && (
            <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
              {q.data.hints.map((h, k) => <Badge key={k} tone={remaining.includes(h) ? 'warn' : 'ok'} title={`第 ${h.line} 行`}>{remaining.includes(h) ? '' : '✓ '}{h.text}</Badge>)}
            </div>
          )}
          <textarea aria-label="移到全局的内容" className={cx(ui.textarea, ui.mono)} style={{ minHeight: '40vh', fontSize: 12.5 }} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />
        </>
      )}
    </Dialog>
  );
}
