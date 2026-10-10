// Sidebar items with a per-item menu (user acceptance feedback): "⋯" on hover or right-click opens
// pin / rename / archive / delete for conversations and projects, rerun / rename / delete for risk hunts;
// rename happens in place.
import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Link, useNavigate } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { ConversationDto, HuntDto, ProjectDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { qk } from '../../shared/api/queries';
import { Badge, ConfirmDialog, Icon, cx, ui, useToast, type IconName } from '../../shared/ui';
import { nameProblem } from '../projects/NewProjectDialog';
import L from './layout.module.css';

export type MenuAction = { label: string; icon: IconName; onSelect: () => void; danger?: boolean } | 'sep';

function ItemMenu({ at, actions, onClose }: { at: { x: number; y: number }; actions: MenuAction[]; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState(at);
  // Keep the menu inside the viewport.
  useLayoutEffect(() => {
    const r = ref.current?.getBoundingClientRect();
    if (!r) return;
    setPos({ x: Math.max(8, Math.min(at.x, window.innerWidth - r.width - 8)), y: Math.max(8, Math.min(at.y, window.innerHeight - r.height - 8)) });
  }, [at]);
  useEffect(() => {
    ref.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    const onDown = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) onClose(); };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.preventDefault(); onClose(); return; }
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      e.preventDefault();
      const items = [...(ref.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [])];
      const i = items.indexOf(document.activeElement as HTMLElement);
      items[(i + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length]?.focus();
    };
    const close = () => onClose();
    // A scroll still settling when the menu opens (trackpad momentum, a list scrolled to the item) closed it at once:
    // only a scroll after the menu is up closes it.
    const opened = performance.now();
    const onScroll = () => { if (performance.now() - opened > 200) onClose(); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', onScroll, true);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', onScroll, true);
    };
  }, [onClose]);
  return createPortal(
    <div ref={ref} className={cx(ui.menu, L.itemMenu)} role="menu" style={{ left: pos.x, top: pos.y }}>
      {actions.map((a, i) => a === 'sep'
        ? <div key={`sep${i}`} className={L.menuSep} role="separator" />
        : (
          <button key={a.label} role="menuitem" className={cx(ui.menuItem, a.danger && ui.menuDanger)} onClick={() => { onClose(); a.onSelect(); }}>
            <Icon name={a.icon} size={14} />{a.label}
          </button>
        ))}
    </div>,
    document.body,
  );
}

function RenameInput({ initial, label, problem, onDone }: { initial: string; label: string; problem?: (s: string) => string | null; onDone: (name: string | null) => void }) {
  const [v, setV] = useState(initial);
  const done = useRef(false);
  const err = problem?.(v) ?? null;
  const finish = (save: boolean) => {
    if (done.current) return;
    done.current = true;
    const name = v.trim();
    onDone(save && name && name !== initial && !err ? name : null);
  };
  return (
    <div className={L.renameRow}>
      <input className={cx(ui.input, L.renameInput)} value={v} aria-label={label} aria-invalid={!!err} title={err ?? undefined} autoFocus
        onFocus={(e) => e.currentTarget.select()} onChange={(e) => setV(e.target.value)} onBlur={() => finish(true)}
        onKeyDown={(e) => {
          if (e.nativeEvent.isComposing) return;
          if (e.key === 'Enter') { e.preventDefault(); finish(true); }
          if (e.key === 'Escape') { e.preventDefault(); finish(false); }
        }} />
      {err && <div className={L.renameErr}>{err}</div>}
    </div>
  );
}

function SideItem({ to, params, search, icon, label, active, meta, actions, menuLabel }: {
  to: string; params: Record<string, string>; search?: Record<string, unknown>; icon: IconName; label: string; active: boolean;
  meta?: ReactNode; actions: MenuAction[]; menuLabel: string;
}) {
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const close = () => { setMenu(null); };
  return (
    <div className={cx(L.item, menu && L.itemOpen)} onContextMenu={(e) => { e.preventDefault(); setMenu({ x: e.clientX, y: e.clientY }); }}>
      <Link to={to as never} params={params as never} search={search as never} className={cx(L.navItem, active && L.navActive)} title={label}>
        <Icon name={icon} />
        <span className={L.navLabel}>{label}</span>
        {meta && <span className={L.itemMeta}>{meta}</span>}
      </Link>
      <button ref={btn} className={L.itemMore} aria-label={menuLabel} aria-haspopup="menu" aria-expanded={!!menu}
        onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); setMenu(menu ? null : { x: r.left, y: r.bottom + 4 }); }}>
        <Icon name="more" size={15} />
      </button>
      {menu && <ItemMenu at={menu} actions={actions} onClose={() => { close(); btn.current?.focus({ preventScroll: true }); }} />}
    </div>
  );
}

export function SideConversations({ items, path }: { items: ConversationDto[]; path: string }) {
  const [renaming, setRenaming] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<ConversationDto | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const refresh = (cid: string) => { void qc.invalidateQueries({ queryKey: ['conversations'] }); void qc.invalidateQueries({ queryKey: qk.conversation(cid) }); };
  const patch = async (c: ConversationDto, body: Record<string, unknown>, ok?: string) => {
    try { await api.patch(`/conversations/${c.id}`, body); if (ok) toast.ok(ok); } catch (e) { toast.error(e); }
    refresh(c.id);
  };
  return (
    <>
      {items.map((c) => renaming === c.id ? (
        <RenameInput key={c.id} initial={c.title} label="会话标题" onDone={(t) => { setRenaming(null); if (t) void patch(c, { title: t }); }} />
      ) : (
        <SideItem key={c.id} to="/conversations/$cid" params={{ cid: c.id }} icon={c.pinned ? 'pin' : 'message'} label={c.title} menuLabel={`会话操作：${c.title}`}
          active={path === `/conversations/${c.id}`}
          meta={c.streaming ? <Badge tone="accent" pulse dot>回复中</Badge> : c.pendingCards ? <Badge tone="warn">{c.pendingCards}</Badge> : undefined}
          actions={[
            { label: c.pinned ? '取消置顶' : '置顶', icon: 'pin', onSelect: () => void patch(c, { pinned: !c.pinned }) },
            { label: '重命名', icon: 'edit', onSelect: () => setRenaming(c.id) },
            { label: '归档', icon: 'archive', onSelect: () => void patch(c, { status: 'archived' }, '已归档，可在“全部会话”的已归档中找到') },
            'sep',
            { label: '删除', icon: 'trash', danger: true, onSelect: () => setDeleting(c) },
          ]} />
      ))}
      <ConfirmDialog open={!!deleting} onClose={() => setDeleting(null)} level="destructive" title="删除会话" confirmText="删除"
        onConfirm={async () => {
          const c = deleting!;
          setDeleting(null);
          try {
            await api.del(`/conversations/${c.id}`);
            toast.ok('会话已删除');
            if (path === `/conversations/${c.id}`) void navigate({ to: '/conversations' });
          } catch (e) { toast.error(e); }
          void qc.invalidateQueries({ queryKey: ['conversations'] });
        }}>
        删除「{deleting?.title}」后消息与卡片都会移除；尚未处理的 AI 建议会记为驳回。已应用的修订保留在漏洞的修订历史中。
      </ConfirmDialog>
    </>
  );
}

export function SideProjects({ items, activeId }: { items: ProjectDto[]; activeId: string | undefined }) {
  const [renaming, setRenaming] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<ProjectDto | null>(null);
  const [showArchived, setShowArchived] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const refresh = (pid: string) => { void qc.invalidateQueries({ queryKey: qk.projects }); void qc.invalidateQueries({ queryKey: qk.project(pid) }); void qc.invalidateQueries({ queryKey: ['dashboard'] }); };
  const patch = async (p: ProjectDto, body: Record<string, unknown>, ok?: string) => {
    try { await api.patch(`/projects/${p.id}`, body); if (ok) toast.ok(ok); } catch (e) { toast.error(e); }
    refresh(p.id);
  };
  const active = items.filter((p) => p.status === 'active');
  const archived = items.filter((p) => p.status !== 'active');
  const item = (p: ProjectDto) => {
    if (renaming === p.id) {
      return <RenameInput key={p.id} initial={p.name} label="项目名称" problem={nameProblem} onDone={(n) => { setRenaming(null); if (n) void patch(p, { name: n }); }} />;
    }
    const open = Object.values(p.openVulns).reduce((a, b) => a + b, 0);
    const isArchived = p.status !== 'active';
    return (
      <SideItem key={p.id} to="/projects/$pid" params={{ pid: p.id }} icon={isArchived ? 'archive' : 'folder'} label={p.name} menuLabel={`项目操作：${p.name}`}
        active={activeId === p.id} meta={open ? <span className={L.navMeta} title="未处理漏洞">{open}</span> : undefined}
        actions={[
          ...(isArchived ? [] : [{ label: '发起审计', icon: 'play' as const, onSelect: () => void navigate({ to: '/audits/new', search: { projectId: p.id } }) }]),
          { label: '重命名', icon: 'edit', onSelect: () => setRenaming(p.id) },
          isArchived
            ? { label: '取消归档', icon: 'archive', onSelect: () => void patch(p, { status: 'active' }, '已取消归档') }
            : { label: '归档', icon: 'archive', onSelect: () => void patch(p, { status: 'archived' }, '已归档，可在侧栏“已归档”中找到') },
          'sep',
          { label: '删除项目…', icon: 'trash', danger: true, onSelect: () => setDeleting(p) },
        ]} />
    );
  };
  return (
    <>
      {active.length === 0 && <div className={L.navItem} style={{ cursor: 'default', color: 'var(--text-3)' }}>还没有项目</div>}
      {active.map(item)}
      {archived.length > 0 && (
        <button className={cx(L.navItem, L.archivedToggle)} aria-expanded={showArchived} onClick={() => setShowArchived(!showArchived)}>
          <Icon name={showArchived ? 'chevronDown' : 'chevronRight'} size={14} />
          <span className={L.navLabel}>已归档（{archived.length}）</span>
        </button>
      )}
      {showArchived && archived.map(item)}
      <ConfirmDialog open={!!deleting} onClose={() => setDeleting(null)} title="删除项目" level="destructive" confirmText="永久删除" typeToConfirm={deleting?.name}
        onConfirm={async () => {
          const p = deleting!;
          setDeleting(null);
          try {
            await api.del(`/projects/${p.id}?confirmName=${encodeURIComponent(p.name)}`);
            toast.ok('项目已删除');
            if (activeId === p.id) void navigate({ to: '/' });
          } catch (e) { toast.error(e); }
          refresh(p.id);
        }}>
        将删除「{deleting?.name}」下的所有仓库记录、审计、漏洞与报告，且无法恢复。
      </ConfirmDialog>
    </>
  );
}

export function SideHunts({ items, path }: { items: HuntDto[]; path: string }) {
  const [renaming, setRenaming] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<HuntDto | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  const refresh = (hid: string) => { void qc.invalidateQueries({ queryKey: ['hunts'] }); void qc.invalidateQueries({ queryKey: ['hunt', hid] }); };
  const rerun = async (h: HuntDto) => {
    try {
      const n = await api.post<HuntDto>(`/hunts/${h.id}/rerun`);
      await api.post(`/hunts/${n.id}/confirm`);
      toast.ok('已开始重新排查，结束后与上一次对比');
      void navigate({ to: '/hunts/$hid', params: { hid: n.id } });
    } catch (e) { toast.error(e); }
    refresh(h.id);
  };
  return (
    <>
      {items.map((h) => {
        if (renaming === h.id) {
          return <RenameInput key={h.id} initial={h.title} label="排查标题" onDone={(t) => {
            setRenaming(null);
            if (t) void api.patch(`/hunts/${h.id}`, { title: t }).catch((e: unknown) => toast.error(e)).finally(() => refresh(h.id));
          }} />;
        }
        const running = h.status === 'running';
        return (
          <SideItem key={h.id} to="/hunts/$hid" params={{ hid: h.id }} icon="target" label={h.title} menuLabel={`排查操作：${h.title}`}
            active={path === `/hunts/${h.id}`}
            meta={running ? <Badge tone="accent" pulse dot>排查中</Badge> : h.summary.affected ? <span className={L.navMeta} title="受影响">{h.summary.affected}</span> : undefined}
            actions={[
              ...(running ? [] : [{ label: '重新排查', icon: 'refresh' as const, onSelect: () => void rerun(h) }]),
              { label: '重命名', icon: 'edit', onSelect: () => setRenaming(h.id) },
              ...(running ? [] : ['sep' as const, { label: '删除', icon: 'trash' as const, danger: true, onSelect: () => setDeleting(h) }]),
            ]} />
        );
      })}
      <ConfirmDialog open={!!deleting} onClose={() => setDeleting(null)} level="destructive" title="删除排查记录" confirmText="删除"
        onConfirm={async () => {
          const h = deleting!;
          setDeleting(null);
          try {
            await api.del(`/hunts/${h.id}`);
            toast.ok('排查记录已删除');
            if (path === `/hunts/${h.id}`) void navigate({ to: '/hunts' });
          } catch (e) { toast.error(e); }
          refresh(h.id);
        }}>
        删除「{deleting?.title}」的排查记录与各仓库结论。它在各项目中运行的排查审计，以及已转为漏洞的命中会保留。
      </ConfirmDialog>
    </>
  );
}
