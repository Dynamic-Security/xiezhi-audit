// Import architecture material: paste or upload an architecture document or a
// service list; AI proposes services and connections (imported, inferred) and the material becomes a
// project architecture knowledge draft to review.
import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { ArchitectureImportDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { Button, Dialog, Field, Spinner, cx, ui, useToast } from '../../shared/ui';
import { DraftDialog } from '../knowledge/drafts';

export function ArchitectureImportDialog({ pid, open, onClose }: { pid: string; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [text, setText] = useState('');
  const [label, setLabel] = useState('');
  const [id, setId] = useState<string | null>(null);
  const [draft, setDraft] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) { setText(''); setLabel(''); setId(null); } }, [open]);
  const q = useQuery({
    queryKey: ['architecture-import', pid, id], enabled: !!id, queryFn: () => api.get<ArchitectureImportDto>(`/projects/${pid}/architecture-imports/${id}`),
    refetchInterval: (x) => (x.state.data?.status === 'running' ? 1000 : false),
  });
  useEffect(() => { if (q.data?.status === 'done') void qc.invalidateQueries({ queryKey: ['project', pid, 'topology'] }); }, [q.data?.status, qc, pid]);
  const readFile = async (f: File | undefined) => {
    if (!f) return;
    if (f.size > 1024 * 1024) { toast.error(new Error('文件过大（上限 1 MB 文本）')); return; }
    setText(await f.text());
    setLabel(f.name);
  };
  const start = async () => {
    setBusy(true);
    try { setId((await api.post<ArchitectureImportDto>(`/projects/${pid}/architecture-imports`, { text, ...(label.trim() ? { label: label.trim() } : {}) })).id); } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  const r = q.data;
  return (
    <>
      <Dialog open={open} onClose={onClose} wide title="导入架构资料" footer={<>
        <Button onClick={onClose}>关闭</Button>
        {!id && <Button variant="primary" loading={busy} disabled={!text.trim()} onClick={() => void start()}>交给 AI 提取</Button>}
        {r?.draftId && <Button variant="primary" onClick={() => setDraft(r.draftId)}>审核系统架构知识草稿</Button>}
      </>}>
        {!id ? (
          <>
            <p className={ui.muted} style={{ margin: 0 }}>粘贴架构文档、服务清单或部署说明。AI 提取服务与调用关系补全拓扑（标为“架构资料导入 · 推断”，可以删除），并把资料整理成项目知识库中的系统架构 skill 草稿，审核后启用。资料作为数据处理，其中的指令不会被执行。</p>
            <div className={cx(ui.row, ui.wrap)} style={{ gap: 12 }}>
              <Field label="名称"><input className={ui.input} value={label} onChange={(e) => setLabel(e.target.value)} placeholder="例如 订单域架构说明 v3" /></Field>
              <Field label="上传文本文件"><input type="file" accept=".md,.txt,.markdown,.yaml,.yml,text/*" onChange={(e) => void readFile(e.target.files?.[0])} /></Field>
            </div>
            <textarea aria-label="架构资料" className={cx(ui.textarea, ui.mono)} style={{ minHeight: '36vh', fontSize: 12.5 }} value={text} onChange={(e) => setText(e.target.value)} />
          </>
        ) : !r || r.status === 'running' ? (
          <div className={ui.row} style={{ gap: 8 }}><Spinner /><span className={ui.muted}>AI 正在提取服务与连接…</span></div>
        ) : r.status === 'failed' ? (
          <div className={ui.banner} role="alert">导入失败：{r.error}</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }} aria-label="导入结果">
            <div>新增 {r.result!.nodesAdded} 个节点、{r.result!.edgesAdded} 条连接、{r.result!.aliases} 个服务名映射（用于跨仓匹配）。</div>
            {r.result!.summary && <div className={ui.faint} style={{ fontSize: 13 }}>{r.result!.summary}</div>}
            {r.result!.skipped.length > 0 && <details><summary className={ui.faint} style={{ fontSize: 12, cursor: 'pointer' }}>跳过 {r.result!.skipped.length} 项</summary><ul style={{ fontSize: 12, margin: 0 }}>{r.result!.skipped.map((x, i) => <li key={i}>{x}</li>)}</ul></details>}
          </div>
        )}
      </Dialog>
      <DraftDialog id={draft} onClose={() => setDraft(null)} />
    </>
  );
}
