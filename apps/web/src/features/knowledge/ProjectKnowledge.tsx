// Project knowledge tab: the project layer plus every global skill with what hides it here;
// disable by name or category, copy a global skill into the project to customise it.
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { KnowledgeOverrideDto, SkillDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { useConnectors, useKnowledge, useProjectConnectors } from '../../shared/api/queries';
import { Button, Dialog, Loading, cx, ui, useToast } from '../../shared/ui';
import { CATEGORY, SkillEditor, SkillGroups, SkillView } from './skills';
import { DraftDialog, DraftList, ImportDialog, MoveToGlobalDialog } from './drafts';
import { PromptLibrary, usePrompts } from './prompts';

export function ProjectKnowledge({ pid }: { pid: string }) {
  const k = useKnowledge(pid);
  const prompts = usePrompts(pid);
  const qc = useQueryClient();
  const toast = useToast();
  const [open, setOpen] = useState<SkillDto | null>(null);
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [draft, setDraft] = useState<string | null>(null);
  const [moving, setMoving] = useState<string | null>(null);
  const [approved, setApproved] = useState<string | null>(null);
  // Category overrides live in the project's _settings.json; the list tells which categories are off.
  const disabledCats = useQuery({
    queryKey: ['knowledge', pid, 'categories'],
    queryFn: () => new Set((k.data ?? []).filter((s) => s.disabledBy.includes('project_category')).map((s) => s.category)),
    enabled: !!k.data,
  });
  const toggleCategory = async (c: string, disabled: boolean) => {
    try {
      await api.put<KnowledgeOverrideDto>(`/projects/${pid}/knowledge-category-overrides/${c}`, { disabled });
      await qc.invalidateQueries({ queryKey: ['knowledge'] });
    } catch (e) { toast.error(e); }
  };
  if (k.isLoading) return <Loading />;
  const current = open ? (k.data ?? []).find((s) => s.layer === open.layer && s.name === open.name) ?? open : null;
  return (
    <>
      <div className={ui.spread} style={{ marginBottom: 12, gap: 12, alignItems: 'flex-start' }}>
        <p className={ui.muted} style={{ margin: 0 }}>本项目可见的知识：项目层 + 全局层，同名时以项目层为准。停用只影响本项目；业务知识与系统架构写明来源，未核实的只能作为推测使用。</p>
        <div className={ui.row} style={{ gap: 6 }}>
          <Button size="sm" icon="upload" onClick={() => setImporting(true)}>导入 / 粘贴</Button>
          <Button size="sm" variant="primary" icon="plus" onClick={() => setCreating(true)}>新建项目 skill</Button>
        </div>
      </div>
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }} aria-label="按类别停用">
        {Object.entries(CATEGORY).map(([c, label]) => {
          const off = disabledCats.data?.has(c) ?? false;
          return <button key={c} className={cx(ui.chip, !off && ui.chipOn)} aria-pressed={!off} title={off ? '本项目已停用该类别，点击恢复' : '点击在本项目停用该类别'} onClick={() => void toggleCategory(c, !off)}>{label}{off ? '（已停用）' : ''}</button>;
        })}
      </div>
      <ProjectConnectors pid={pid} />
      <DraftList pid={pid} onOpen={setDraft} />
      <SkillGroups items={k.data ?? []} projectView selected={open ? `${open.layer}:${open.name}` : undefined} onSelect={setOpen} reveal={approved ?? undefined} flow={{ count: prompts.data?.items.length, content: <PromptLibrary pid={pid} /> }} />
      <Dialog open={!!current} onClose={() => setOpen(null)} wide title={current ? `${current.layer === 'project' ? '项目' : '全局'} skill · ${current.name}` : ''}>
        {current && <div style={{ margin: '-16px -24px' }}><SkillView key={`${current.layer}:${current.name}`} item={current} pid={pid} onDeleted={() => setOpen(null)} onMoveToGlobal={(n) => { setOpen(null); setMoving(n); }} /></div>}
      </Dialog>
      <ImportDialog open={importing} onClose={() => setImporting(false)} pid={pid} onCreated={setDraft} />
      <DraftDialog id={draft} onClose={() => setDraft(null)} onApproved={(name) => setApproved(`project:${name}`)} />
      <MoveToGlobalDialog pid={pid} name={moving} onClose={() => setMoving(null)} onCreated={setDraft} />
      <SkillEditor open={creating} onClose={() => setCreating(false)} layer="project" pid={pid} name={null} />
    </>
  );
}

/** Context connectors bound to the project: the default authorization of its audits. */
function ProjectConnectors({ pid }: { pid: string }) {
  const all = useConnectors();
  const bound = useProjectConnectors(pid);
  const qc = useQueryClient();
  const toast = useToast();
  const context = all.data ?? [];
  if (!context.length) return null;
  const mine = new Set((bound.data ?? []).filter((b) => b.scope === 'project').map((b) => b.connectorId));
  const global = new Set((bound.data ?? []).filter((b) => b.scope === 'global').map((b) => b.connectorId));
  const toggle = async (id: string) => {
    const next = mine.has(id) ? [...mine].filter((x) => x !== id) : [...mine, id];
    try {
      await api.put(`/projects/${pid}/connectors`, { connectorIds: next });
      await qc.invalidateQueries({ queryKey: ['connectors', 'project', pid] });
    } catch (e) { toast.error(e); }
  };
  return (
    <section style={{ marginTop: 16 }} aria-label="项目绑定的连接器">
      <h2 style={{ fontSize: 15, marginBottom: 6 }}>可使用的连接器</h2>
      <p className={ui.faint} style={{ fontSize: 12, margin: '0 0 8px' }}>本项目的审计默认允许 Agent 使用这些连接器中已开放的工具，读和写都可以（发起审计时可以取消）；查询结果作为未核实的外部数据使用。</p>
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
        {context.map((c) => {
          const on = mine.has(c.id) || global.has(c.id);
          return <button key={c.id} className={cx(ui.chip, on && ui.chipOn)} aria-pressed={on} disabled={global.has(c.id)} title={global.has(c.id) ? '全局绑定' : c.status !== 'ready' ? '连接器未就绪' : undefined} onClick={() => void toggle(c.id)}>{c.name}{c.status !== 'ready' ? '（未就绪）' : ''}</button>;
        })}
      </div>
    </section>
  );
}
