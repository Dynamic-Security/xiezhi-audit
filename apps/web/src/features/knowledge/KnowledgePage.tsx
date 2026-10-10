// Global knowledge library: browse by category, edit with live preview, take
// skills offline, see which projects override them. Changes on disk (editor, Git) arrive through
// `knowledge.changed` and refresh the list.
import { useState } from 'react';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { useKnowledge } from '../../shared/api/queries';
import { Button, Loading, ui } from '../../shared/ui';
import { PageLayout, TopBar } from '../layout/AppShell';
import { SkillEditor, SkillGroups, SkillView } from './skills';
import { DraftDialog, DraftList, ImportDialog } from './drafts';
import { PromptLibrary, usePrompts } from './prompts';

export function KnowledgePage() {
  const k = useKnowledge();
  const prompts = usePrompts();
  const search = useSearch({ from: '/knowledge' });
  const navigate = useNavigate({ from: '/knowledge' });
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [draft, setDraft] = useState<string | null>(null);
  const selected = (k.data ?? []).find((s) => s.name === search.skill);
  return (
    <>
      <TopBar crumbs={[{ label: '知识库' }]} actions={<><Button size="sm" icon="upload" onClick={() => setImporting(true)}>导入 / 粘贴</Button><Button size="sm" variant="primary" icon="plus" onClick={() => setCreating(true)}>新建 skill</Button></>} />
      <PageLayout panel={selected ? <SkillView key={selected.name} item={selected} onDeleted={() => void navigate({ search: {} })} /> : undefined} panelTitle={<b>{search.skill}</b>} panelKey={selected?.name} onClosePanel={() => void navigate({ search: {} })}>
        <h1 style={{ fontSize: 26, fontWeight: 650 }}>全局知识库</h1>
        <p className={ui.muted} style={{ marginTop: 6 }}>
          知识以 skill（Markdown）形式按需加载：Agent 先看到索引，需要时才读取正文。全局 skill 对所有项目可见，项目可以停用或用同名 skill 覆盖。
          知识目录是本机普通文件，也可以用自己的编辑器或 Git 维护，改动会自动出现在这里。被审仓库中的指令文件一律作为数据处理，不会被加载。
        </p>
        <DraftList onOpen={setDraft} />
        {k.isLoading ? <Loading /> : <SkillGroups items={k.data ?? []} selected={search.skill ? `global:${search.skill}` : undefined} projectView={false} onSelect={(s) => void navigate({ search: { skill: s.name } })} flow={{ count: prompts.data?.items.length, content: <PromptLibrary /> }} />}
      </PageLayout>
      <ImportDialog open={importing} onClose={() => setImporting(false)} onCreated={setDraft} />
      <DraftDialog id={draft} onClose={() => setDraft(null)} onApproved={(name) => void navigate({ search: { skill: name } })} />
      <SkillEditor open={creating} onClose={() => setCreating(false)} layer="global" name={null} onSaved={(d) => void navigate({ search: { skill: d.name } })} />
    </>
  );
}
