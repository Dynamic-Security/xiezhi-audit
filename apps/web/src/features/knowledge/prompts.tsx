// Pipeline prompts in the knowledge base: every text the pipeline sends to a model, by group. Shown
// as the first knowledge tab, 审计流程. The
// prompt groups can be overridden in the global layer (knowledge page) or a project layer (project knowledge tab);
// saving checks the variables and the locked tokens; one entry or the whole layer goes back to the defaults in one click.
// Tool and field descriptions and submission feedback are shown read-only. Audits keep the prompts they started with.
import { useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { PromptDto, PromptListDto } from '@xiezhi/contracts';
import { ApiError, api } from '../../shared/api/client';
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Loading, Tabs, cx, ui, useToast } from '../../shared/ui';
import { fmt } from '../../shared/format/messages';

type Group = 'role_rules' | 'step_task' | 'standalone' | 'conversation' | 'nudge' | 'data_note' | 'tool';
export const PROMPT_GROUP: Record<Group, string> = {
  role_rules: '角色与规则', step_task: '审计步骤任务', standalone: '独立会话', conversation: '对话', nudge: '运行中提醒', data_note: '数据标注说明', tool: '工具说明',
};

const qs = (pid?: string) => (pid ? `?projectId=${encodeURIComponent(pid)}` : '');
export function usePrompts(pid?: string) {
  return useQuery({ queryKey: ['prompts', pid ?? ''], queryFn: () => api.get<PromptListDto>(`/knowledge/prompts${qs(pid)}`) });
}

/** The override of the layer this view edits (project tab: the project layer; knowledge page: the global layer). */
const mine = (p: PromptDto, pid?: string) => (pid ? p.project : p.global);

function Flags({ p, pid }: { p: PromptDto; pid?: string | undefined }) {
  const own = mine(p, pid);
  return (
    <span className={cx(ui.row, ui.wrap)} style={{ gap: 4 }}>
      {!p.editable && <Badge title={p.readonlyReason ?? ''}>只读</Badge>}
      {p.effectiveLayer === 'project' && <Badge tone="accent">项目覆盖</Badge>}
      {p.effectiveLayer === 'global' && <Badge tone="info">{pid ? '全局覆盖' : '已覆盖'}</Badge>}
      {own && !own.valid && <Badge tone="danger" title={own.issues.join('\n')}>覆盖无效（未生效）</Badge>}
      {own?.defaultChanged && <Badge tone="warn" title="覆盖是基于旧版本的默认写的，默认已更新，建议对比后再确认">默认已更新</Badge>}
    </span>
  );
}

export function PromptLibrary({ pid }: { pid?: string }) {
  const q = usePrompts(pid);
  const qc = useQueryClient();
  const toast = useToast();
  const [tab, setTab] = useState<Group>('role_rules');
  const [open, setOpen] = useState<string | null>(null);
  const [resetAll, setResetAll] = useState(false);
  const [busy, setBusy] = useState(false);
  const items = q.data?.items ?? [];
  const ownCount = items.filter((p) => mine(p, pid)).length;
  const groups = (Object.keys(PROMPT_GROUP) as Group[]).map((g) => ({ key: g, label: PROMPT_GROUP[g], count: items.filter((p) => p.group === g).length }));
  const list = items.filter((p) => p.group === tab);
  const current = items.find((p) => p.id === open) ?? null;
  const restoreAll = async () => {
    setBusy(true);
    try {
      const r = await api.del<{ restored: string[] }>(`/knowledge/prompts${qs(pid)}`);
      toast.ok(`已恢复 ${r.restored.length} 条提示词的默认`);
      await qc.invalidateQueries({ queryKey: ['prompts'] });
      setResetAll(false);
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <section aria-label="流程提示词">
      <div className={ui.spread} style={{ gap: 12, alignItems: 'flex-start' }}>
        <p className={ui.faint} style={{ fontSize: 12, margin: 0 }}>
          审计流程中发给模型的全部提示词，按用途分组。{pid ? '这里的修改只作用于本项目（覆盖全局层）。' : '这里的修改作用于所有项目（项目可以再覆盖）。'}
          修改保存前会检查变量与锁定词；已开始的审计使用开始时的版本。工具与字段说明只读展示。
        </p>
        {ownCount > 0 && <Button size="sm" icon="refresh" onClick={() => setResetAll(true)}>全部恢复默认（{ownCount}）</Button>}
      </div>
      {q.isLoading ? <Loading /> : !items.length ? <EmptyState icon="book" title="没有提示词" /> : (
        <>
          <div style={{ marginTop: 8 }}><Tabs value={tab} onChange={setTab} items={groups} /></div>
          <div className={ui.card} style={{ overflow: 'auto', marginTop: 12 }} role="tabpanel" aria-label={PROMPT_GROUP[tab]}>
            <table className={ui.table}>
              <tbody>{list.map((p) => (
                <tr key={p.id} className={cx(ui.rowLink, open === p.id && ui.rowSel)} onClick={() => setOpen(p.id)}>
                  <td>
                    <div className={ui.row} style={{ gap: 8 }}><b>{p.title}</b><Flags p={p} pid={pid} /></div>
                    <div className={ui.faint} style={{ fontSize: 12 }}>{p.description}</div>
                  </td>
                  <td className={ui.mono} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{p.id}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </>
      )}
      {current && <PromptDialog key={current.id} p={current} pid={pid} onClose={() => setOpen(null)} />}
      <ConfirmDialog open={resetAll} onClose={() => setResetAll(false)} onConfirm={() => void restoreAll()} loading={busy} level="destructive" confirmText="全部恢复默认"
        title={pid ? '恢复本项目全部提示词的默认？' : '恢复全局层全部提示词的默认？'}>
        将删除{pid ? '本项目' : '全局层'}的 {ownCount} 条覆盖，{pid ? '之后本项目使用全局层或内置默认。' : '之后使用内置默认（项目层的覆盖不受影响）。'}已开始的审计不受影响。
      </ConfirmDialog>
    </section>
  );
}

/** Line diff (LCS) of the default against the text being edited. */
export function lineDiff(a: string, b: string): { op: ' ' | '-' | '+'; line: string }[] {
  const x = a.split('\n');
  const y = b.split('\n');
  const n = x.length;
  const m = y.length;
  const L = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) L[i]![j] = x[i] === y[j] ? L[i + 1]![j + 1]! + 1 : Math.max(L[i + 1]![j]!, L[i]![j + 1]!);
  const out: { op: ' ' | '-' | '+'; line: string }[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (x[i] === y[j]) { out.push({ op: ' ', line: x[i]! }); i++; j++; } else if (L[i + 1]![j]! >= L[i]![j + 1]!) out.push({ op: '-', line: x[i++]! }); else out.push({ op: '+', line: y[j++]! });
  }
  while (i < n) out.push({ op: '-', line: x[i++]! });
  while (j < m) out.push({ op: '+', line: y[j++]! });
  return out;
}

function PromptDialog({ p, pid, onClose }: { p: PromptDto; pid?: string | undefined; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const own = mine(p, pid);
  // Edit from this layer's override, else from what is in effect below it (the global override or the default).
  const start = own?.text ?? (pid && p.global?.valid ? p.global.text : p.defaultText);
  const [text, setText] = useState(start);
  const [issues, setIssues] = useState<string[]>([]);
  const [diff, setDiff] = useState(false);
  const [busy, setBusy] = useState(false);
  const d = useMemo(() => (diff ? lineDiff(p.defaultText, text) : []), [diff, p.defaultText, text]);
  const done = async (msg: string) => { toast.ok(msg); await qc.invalidateQueries({ queryKey: ['prompts'] }); onClose(); };
  const save = async () => {
    setBusy(true);
    try {
      await api.put<PromptDto>(`/knowledge/prompts/${p.id}`, { text, ...(pid ? { projectId: pid } : {}) });
      await done('已保存，新开始的审计会使用它');
    } catch (e) {
      const errs = e instanceof ApiError ? (e.details?.errors as string[] | undefined) : undefined;
      if (errs?.length) setIssues(errs); else toast.error(e);
    } finally { setBusy(false); }
  };
  const restore = async () => {
    setBusy(true);
    try {
      await api.del<PromptDto>(`/knowledge/prompts/${p.id}${qs(pid)}`);
      await done('已恢复默认');
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <Dialog open onClose={onClose} wide title={<span>{p.title} <span className={ui.mono} style={{ fontSize: 12, fontWeight: 400 }}>{p.id}</span></span>} footer={p.editable ? <>
      {own && <Button variant="danger" icon="refresh" loading={busy} onClick={() => void restore()} style={{ marginRight: 'auto' }}>恢复默认</Button>}
      <Button onClick={() => setDiff(!diff)} aria-pressed={diff}>{diff ? '隐藏对比' : '与默认对比'}</Button>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={text === start} onClick={() => void save()}>保存{pid ? '到本项目' : '到全局'}</Button>
    </> : <Button onClick={onClose}>关闭</Button>}>
      <p className={ui.muted} style={{ marginTop: 0 }}>{p.description}</p>
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 6, marginBottom: 8 }}>
        <Flags p={p} pid={pid} />
        <span className={ui.faint} style={{ fontSize: 12 }}>生效版本：{p.effectiveLayer === 'default' ? '内置默认' : p.effectiveLayer === 'global' ? '全局层' : '项目层'}{own?.updatedAt ? ` · 本层修改于 ${fmt.ago(own.updatedAt)}` : ''}</span>
      </div>
      {!p.editable && <div className={ui.banner} role="note">{p.readonlyReason}</div>}
      {p.variables.length > 0 && <p className={ui.faint} style={{ fontSize: 12 }}>变量（引擎填入，必须保留）：{p.variables.map((v) => <code key={v} style={{ marginRight: 6 }}>{`{{${v}}}`}</code>)}</p>}
      {p.editable && p.locked.length > 0 && <details style={{ fontSize: 12, marginBottom: 8 }}><summary className={ui.faint}>锁定词（{p.locked.length} 个，工具、字段与标记名，必须原样保留）</summary><div className={ui.mono} style={{ marginTop: 4 }}>{p.locked.join('  ')}</div></details>}
      {issues.length > 0 && <div className={ui.banner} role="alert"><b>没有保存：</b><ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>{issues.map((i) => <li key={i}>{i}</li>)}</ul></div>}
      {own && !own.valid && <div className={ui.banner} role="alert">本层现有的覆盖不合格，没有生效：{own.issues.join('；')}</div>}
      {p.editable
        ? <textarea aria-label="提示词内容" className={cx(ui.textarea, ui.mono)} style={{ minHeight: '40vh', fontSize: 12.5 }} value={text} onChange={(e) => { setText(e.target.value); setIssues([]); }} spellCheck={false} />
        : <pre className={cx(ui.card, ui.mono, ui.pre)} style={{ padding: 12, margin: 0, fontSize: 12.5, whiteSpace: 'pre-wrap' }}>{p.effectiveText}</pre>}
      {diff && (
        <pre className={cx(ui.card, ui.mono, ui.pre)} aria-label="与默认对比" style={{ padding: 12, marginTop: 10, fontSize: 12, whiteSpace: 'pre-wrap', maxHeight: '30vh', overflow: 'auto' }}>
          {d.map((l, i) => <div key={i} style={{ background: l.op === '+' ? 'var(--ok-bg, rgba(46,160,67,.15))' : l.op === '-' ? 'var(--danger-bg, rgba(248,81,73,.15))' : undefined }}>{l.op} {l.line}</div>)}
        </pre>
      )}
    </Dialog>
  );
}
