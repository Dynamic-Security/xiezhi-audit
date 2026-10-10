// ⌘K search and actions: projects, audits, vulnerabilities, conversations and skills
// by name, plus the common “new …” actions. Keyboard only is enough: type, ↑↓, Enter, Esc.
import { useEffect, useMemo, useState, type KeyboardEvent } from 'react';
import { useNavigate } from '@tanstack/react-router';
import type { VulnDetailDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { useConversationSearch, useMentionCandidates, useProjects } from '../../shared/api/queries';
import { Icon, cx, ui, useToast, type IconName } from '../../shared/ui';
import { useAi } from '../assistant/ai';
import L from './layout.module.css';

interface Item { key: string; group: string; label: string; detail?: string | null; icon: IconName; run: () => void | Promise<void> }

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState('');
  const [active, setActive] = useState(0);
  const navigate = useNavigate();
  const ai = useAi();
  const toast = useToast();
  const projects = useProjects();
  const term = q.trim();
  const objects = useMentionCandidates(term, open && term.length > 0, 'audit,vuln,skill');
  const convs = useConversationSearch(term, open);
  useEffect(() => { if (open) { setQ(''); setActive(0); } }, [open]);

  const items = useMemo<Item[]>(() => {
    const go = (fn: () => void) => () => { onClose(); fn(); };
    const actions: Item[] = [
      { key: 'a:audit', group: '操作', label: '新建审计', icon: 'plus', run: go(() => void navigate({ to: '/audits/new', search: {} })) },
      { key: 'a:hunt', group: '操作', label: '新建风险排查', icon: 'target', run: go(() => void navigate({ to: '/hunts/new', search: {} })) },
      { key: 'a:chat', group: '操作', label: '新建会话（AI 面板）', icon: 'sparkle', run: go(() => ai.show(null)) },
      { key: 'a:knowledge', group: '操作', label: '知识库', icon: 'book', run: go(() => void navigate({ to: '/knowledge', search: {} })) },
      { key: 'a:settings', group: '操作', label: '设置', icon: 'settings', run: go(() => void navigate({ to: '/settings/$section', params: { section: 'models' } })) },
    ];
    const match = (s: string) => !term || s.toLowerCase().includes(term.toLowerCase());
    const out: Item[] = actions.filter((a) => match(a.label));
    for (const p of projects.data ?? []) if (p.status === 'active' && match(p.name)) out.push({ key: `p:${p.id}`, group: '项目', label: p.name, detail: `${p.repoCount} 个仓库`, icon: 'folder', run: go(() => void navigate({ to: '/projects/$pid', params: { pid: p.id } })) });
    for (const o of objects.data ?? []) {
      if (o.kind === 'audit') out.push({ key: `o:${o.id}`, group: '审计', label: o.label, detail: o.detail, icon: 'activity', run: go(() => void navigate({ to: '/audits/$aid', params: { aid: o.id } })) });
      if (o.kind === 'vuln') {
        out.push({
          key: `o:${o.id}`, group: '漏洞', label: o.label, detail: o.detail, icon: 'bug',
          run: async () => {
            onClose();
            try {
              const v = await api.get<VulnDetailDto>(`/vulnerabilities/${o.id}`);
              void navigate({ to: '/projects/$pid', params: { pid: v.projectId }, search: { tab: 'vulns', panel: `vuln:${o.id}` } });
            } catch (e) { toast.error(e); }
          },
        });
      }
      if (o.kind === 'skill') out.push({ key: `o:${o.id}`, group: '知识', label: o.label, detail: o.detail, icon: 'book', run: go(() => void navigate({ to: '/knowledge', search: { skill: o.id } })) });
    }
    if (term) for (const c of convs.data ?? []) out.push({ key: `c:${c.id}`, group: '会话', label: c.title, icon: 'message', run: go(() => void navigate({ to: '/conversations/$cid', params: { cid: c.id } })) });
    return out.slice(0, 40);
  }, [term, projects.data, objects.data, convs.data, navigate, ai, onClose, toast]);

  useEffect(() => { setActive(0); }, [term]);
  if (!open) return null;
  const onKey = (e: KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => Math.min(items.length - 1, a + 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => Math.max(0, a - 1)); }
    else if (e.key === 'Enter') { e.preventDefault(); void items[active]?.run(); }
    else if (e.key === 'Escape') { e.preventDefault(); onClose(); }
  };
  let lastGroup = '';
  return (
    <div className={L.paletteScrim} onMouseDown={onClose}>
      <div className={L.palette} role="dialog" aria-label="搜索与命令" onMouseDown={(e) => e.stopPropagation()}>
        <div className={L.paletteInput}>
          <Icon name="search" />
          <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} placeholder="搜索项目、审计、漏洞、会话、知识，或输入操作…" aria-label="搜索" />
          <kbd>Esc</kbd>
        </div>
        <div className={L.paletteList} role="listbox">
          {items.length === 0 && <div className={cx(ui.faint, L.paletteEmpty)}>没有匹配的结果</div>}
          {items.map((it, i) => {
            const head = it.group !== lastGroup ? it.group : null;
            lastGroup = it.group;
            return (
              <div key={it.key}>
                {head && <div className={L.paletteGroup}>{head}</div>}
                <button role="option" aria-selected={i === active} className={cx(L.paletteItem, i === active && L.paletteItemOn)} onMouseEnter={() => setActive(i)} onClick={() => void it.run()}>
                  <Icon name={it.icon} size={15} /><span className={ui.ellipsis} style={{ flex: 1 }}>{it.label}</span>{it.detail && <span className={L.paletteDetail}>{it.detail}</span>}
                </button>
              </div>
            );
          })}
        </div>
        <div className={L.paletteFoot}>⌘K 搜索 · ⌘J AI 面板 · ↑↓ 选择 · Enter 打开</div>
      </div>
    </div>
  );
}
