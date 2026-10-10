// “通过连接器查询” (待确认闭环): the user runs one read-only connector operation
// to find what a pending vulnerability is missing. The result is unverified external data; it can be saved
// as a project knowledge draft (source connector:…, verified: false) and reviewed before use.
import { useEffect, useMemo, useState } from 'react';
import type { ConnectorQueryResultDto, KnowledgeDraftDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { useConnectors, useProjectConnectors } from '../../shared/api/queries';
import { Button, Dialog, EmptyState, Field, cx, ui, useToast } from '../../shared/ui';

export function ConnectorQueryDialog({ open, onClose, projectId, context, onDraft }: {
  open: boolean; onClose: () => void; projectId: string; context: string; onDraft: (draftId: string) => void;
}) {
  const toast = useToast();
  const all = useConnectors();
  const bound = useProjectConnectors(projectId);
  const usable = useMemo(() => {
    const boundIds = new Set((bound.data ?? []).map((b) => b.connectorId));
    return (all.data ?? []).filter((c) => c.enabled && c.status === 'ready' && c.tools.some((t) => t.readOnlyHint === true))
      .sort((a, b) => Number(boundIds.has(b.id)) - Number(boundIds.has(a.id)) || a.name.localeCompare(b.name));
  }, [all.data, bound.data]);
  const [cid, setCid] = useState('');
  const [tool, setTool] = useState('');
  const [args, setArgs] = useState('{}');
  const [res, setRes] = useState<ConnectorQueryResultDto | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const c = usable.find((x) => x.id === cid) ?? usable[0];
  const tools = (c?.tools ?? []).filter((t) => t.readOnlyHint === true);
  const t = tools.find((x) => x.name === tool) ?? tools[0];
  useEffect(() => { if (!open) { setRes(null); setErr(null); } }, [open]);
  const run = async () => {
    setErr(null);
    let parsed: Record<string, unknown>;
    try { parsed = JSON.parse(args || '{}') as Record<string, unknown>; } catch { setErr('参数必须是 JSON 对象'); return; }
    setBusy('run');
    try { setRes(await api.post<ConnectorQueryResultDto>(`/connectors/${c!.id}/query`, { tool: t!.name, args: parsed })); } catch (e) { setErr(e instanceof Error ? ((e as { hint?: string }).hint ?? e.message) : String(e)); } finally { setBusy(null); }
  };
  const saveDraft = async () => {
    setBusy('draft');
    try {
      const d = await api.post<KnowledgeDraftDto>('/knowledge/drafts', {
        layer: 'project', projectId, kind: 'skill', organize: true, category: 'architecture',
        text: `待确认问题：${context}\n\n通过连接器 ${c!.name} 的操作 ${t!.name} 查询（参数 ${args}），外部系统返回：\n\n${res!.text}`,
        source: { kind: 'connector', ref: `${c!.id}:${t!.name}`, label: `连接器 ${c!.name} · ${t!.name}` },
      });
      onClose();
      onDraft(d.id);
    } catch (e) { toast.error(e); } finally { setBusy(null); }
  };
  return (
    <Dialog open={open} onClose={onClose} wide title="通过连接器查询" footer={<>
      {err && <div role="alert" className={ui.error} style={{ marginRight: 'auto' }}>{err}</div>}
      <Button onClick={onClose}>关闭</Button>
      {res && <Button loading={busy === 'draft'} onClick={() => void saveDraft()}>存为知识草稿</Button>}
      <Button variant="primary" loading={busy === 'run'} disabled={!c || !t} onClick={() => void run()}>查询</Button>
    </>}>
      {!usable.length ? <EmptyState icon="link" title="没有可用的连接器">在 设置 › 连接器 中添加、测试连接器，并确认工具带有只读标注。</EmptyState> : (
        <>
          <p className={ui.muted} style={{ margin: 0 }}>要确认的内容：{context}</p>
          <div className={cx(ui.row, ui.wrap)} style={{ gap: 12 }}>
            <Field label="连接器"><select className={ui.input} value={c?.id ?? ''} onChange={(e) => { setCid(e.target.value); setTool(''); setRes(null); }}>{usable.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></Field>
            <Field label="操作（只读）"><select className={ui.input} value={t?.name ?? ''} onChange={(e) => { setTool(e.target.value); setRes(null); }}>{tools.map((x) => <option key={x.name} value={x.name}>{x.name}</option>)}</select></Field>
          </div>
          {t?.description && <div className={ui.faint} style={{ fontSize: 12 }}>{t.description}</div>}
          <Field label="参数（JSON）"><textarea aria-label="查询参数" className={cx(ui.textarea, ui.mono)} value={args} onChange={(e) => setArgs(e.target.value)} /></Field>
          {res && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div className={ui.banner} role="note">{res.authoritative ? '以下内容来自权威数据源，可作为判断依据。' : '以下内容来自外部系统，未经核实：只能作为推测或待确认的前提。'}{res.injection.length > 0 ? ` 检测到疑似面向 AI 的指令（${res.injection.map((i) => i.signal).join('、')}），已作为数据处理${c?.authoritative ? '，本次结果不按权威数据处理' : ''}。` : ''}</div>
              <pre aria-label="查询结果" className={cx(ui.card, ui.mono, ui.pre)} style={{ padding: 10, fontSize: 12, maxHeight: 320, overflow: 'auto', margin: 0 }}>{res.text || '（空）'}</pre>
            </div>
          )}
        </>
      )}
    </Dialog>
  );
}
