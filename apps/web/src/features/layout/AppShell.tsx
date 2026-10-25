// Three-column workbench: sidebar · main · context panel. Sidebar collapses to an icon
// rail and becomes a drawer on narrow screens; the context panel becomes an overlay drawer.
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, Outlet, useNavigate, useRouterState } from '@tanstack/react-router';
import { useConversations, useDashboard, useHunts, useProjects } from '../../shared/api/queries';
import { useGlobalEvents } from '../../shared/stream/streams';
import { Badge, BrandMark, Button, Icon, cx, ui, useDismiss, useToast, type IconName } from '../../shared/ui';
import { AUDIT_STATUS } from '../../shared/format/messages';
import { NewProjectDialog } from '../projects/NewProjectDialog';
import { inboxCount } from '../home/inbox';
import { AiProvider, useAi } from '../assistant/ai';
import { CommandPalette } from './CommandPalette';
import { SideConversations, SideHunts, SideProjects } from './SideItems';
import { notify, setTitleBadge } from '../../shared/notify';
import { AiPanelBody } from '../assistant/AiPanel';
import L from './layout.module.css';

const ShellCtx = createContext<{ openMobile: () => void }>({ openMobile: () => undefined });

function readPref(key: string, def: string): string {
  try { return localStorage.getItem(key) ?? def; } catch { return def; }
}
function writePref(key: string, v: string): void {
  try { localStorage.setItem(key, v); } catch { /* private mode */ }
}

function NavLink({ to, icon, label, active, meta, sub, onClick, params, search }: {
  to: string; icon?: IconName; label: string; active: boolean; meta?: ReactNode; sub?: boolean; onClick?: () => void;
  params?: Record<string, string>; search?: Record<string, unknown>;
}) {
  return (
    <Link to={to as never} params={params as never} search={search as never} className={cx(L.navItem, active && L.navActive, sub && L.navSub)} onClick={onClick} title={label}>
      {icon && <Icon name={icon} />}
      <span className={L.navLabel}>{label}</span>
      {meta}
    </Link>
  );
}

export function AppShell() {
  return <AiProvider><Shell /></AiProvider>;
}

function Shell() {
  const [collapsed, setCollapsed] = useState(() => readPref('ca.sidebar', 'open') === 'collapsed');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [theme, setTheme] = useState(() => readPref('ca.theme', 'system'));
  const [newProject, setNewProject] = useState(false);
  const path = useRouterState({ select: (s) => s.location.pathname });
  const projects = useProjects();
  const conversations = useConversations('active');
  const dash = useDashboard();
  const toast = useToast();
  const navigate = useNavigate();

  useEffect(() => {
    if (theme === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', theme);
    writePref('ca.theme', theme);
  }, [theme]);
  useEffect(() => { setMobileOpen(false); }, [path]);

  useGlobalEvents(useCallback((e) => {
    if (e.type.startsWith('conversation.')) return;
    const open = () => void navigate({ to: '/audits/$aid', params: { aid: e.auditId }, search: { panel: 'chat' } });
    if (e.type === 'question.asked') {
      toast.info(`Agent 提问：${String(e.payload.text ?? '').slice(0, 80)}`);
      notify('Agent 提问', String(e.payload.text ?? ''), open, `q-${e.auditId}`);
    }
    if (e.type === 'audit.status_changed') {
      const to = String(e.payload.to);
      // Audits that start by themselves (form default, reverification, backfill, hunts): no “awaiting confirmation” toast.
      const auto = String(e.payload.reason ?? '').includes('confirmed automatically');
      if (['completed', 'partial', 'failed', 'waiting_budget', 'awaiting_confirm'].includes(to) && !(to === 'awaiting_confirm' && auto)) {
        toast.info(`审计状态：${AUDIT_STATUS[to] ?? to}`);
        // system notifications while the page is in the background.
        if (to !== 'awaiting_confirm') notify(`审计${AUDIT_STATUS[to] ?? to}`, to === 'waiting_budget' ? '预算不足，已暂停，等你追加' : '点击查看结果', () => void navigate({ to: '/audits/$aid', params: { aid: e.auditId } }), `a-${e.auditId}`);
      }
    }
  }, [toast, navigate]));
  const todoCount = inboxCount(dash.data?.inbox);
  useEffect(() => { setTitleBadge(todoCount); }, [todoCount]);

  const ai = useAi();
  const hunts = useHunts();
  const pidInPath = /^\/projects\/([^/]+)/.exec(path)?.[1];
  const [palette, setPalette] = useState(false);
  const [newMenu, setNewMenu] = useState(false);
  const newRef = useDismiss(newMenu, () => setNewMenu(false));
  // ⌘K / Ctrl+K opens search.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); setPalette((v) => !v); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  const newAudit = () => void navigate({ to: '/audits/new', search: pidInPath ? { projectId: pidInPath } : {} });
  const toggle = () => { const next = !collapsed; setCollapsed(next); writePref('ca.sidebar', next ? 'collapsed' : 'open'); };
  const todo = inboxCount(dash.data?.inbox);
  const running = dash.data?.running ?? [];

  return (
    <ShellCtx.Provider value={{ openMobile: () => setMobileOpen(true) }}>
      <a href="#main" className="sr-only">跳到主内容</a>
      <div className={L.shell}>
        <div className={cx(L.scrim, mobileOpen && L.show)} onClick={() => setMobileOpen(false)} />
        <aside className={cx(L.sidebar, collapsed && L.collapsed, mobileOpen && L.mobileOpen)} aria-label="导航">
          <div className={L.sideTop}>
            <Link to="/" className={L.brand} style={{ textDecoration: 'none' }}>
              <BrandMark size={28} />
              {!collapsed && <span>獬豸审计</span>}
            </Link>
            {!collapsed && <Button variant="ghost" size="sm" icon="sidebar" aria-label="收起侧栏" onClick={toggle} />}
          </div>
          {collapsed ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, padding: '4px 0' }}>
              <Button variant="ghost" icon="sidebar" aria-label="展开侧栏" onClick={toggle} />
              <Button variant="ghost" icon="plus" aria-label="新建审计" onClick={newAudit} />
              <Button variant="ghost" icon="search" aria-label="搜索" onClick={() => setPalette(true)} />
              <Button variant="ghost" icon="sparkle" aria-label="AI 面板" onClick={() => ai.setOpen(!ai.open)} />
              <Button variant="ghost" icon="home" aria-label="工作台" onClick={() => void navigate({ to: '/' })} />
              <Button variant="ghost" icon="target" aria-label="风险排查" onClick={() => void navigate({ to: '/hunts' })} />
              <Button variant="ghost" icon="book" aria-label="知识库" onClick={() => void navigate({ to: '/knowledge' })} />
              <Button variant="ghost" icon="settings" aria-label="设置" onClick={() => void navigate({ to: '/settings/$section', params: { section: 'models' } })} />
            </div>
          ) : (
            <>
              <div className={L.sideActions}>
                <div className={L.newWrap} ref={newRef}>
                  <button className={L.newBtn} aria-haspopup="menu" aria-expanded={newMenu} onClick={() => setNewMenu(!newMenu)}>
                    <Icon name="plus" /> 新建 <Icon name="chevronDown" size={14} style={{ marginLeft: 'auto', color: 'var(--text-3)' }} />
                  </button>
                  {newMenu && (
                    <div className={cx(ui.menu, L.newMenu)} role="menu">
                      <button role="menuitem" className={ui.menuItem} onClick={() => { setNewMenu(false); newAudit(); }}><Icon name="play" size={14} />审计</button>
                      <button role="menuitem" className={ui.menuItem} onClick={() => { setNewMenu(false); void navigate({ to: '/hunts/new', search: {} }); }}><Icon name="target" size={14} />风险排查</button>
                      <button role="menuitem" className={ui.menuItem} onClick={() => { setNewMenu(false); ai.show(null); }}><Icon name="sparkle" size={14} />会话</button>
                      <button role="menuitem" className={ui.menuItem} onClick={() => { setNewMenu(false); setNewProject(true); }}><Icon name="folder" size={14} />项目</button>
                    </div>
                  )}
                </div>
                <button className={L.searchBtn} onClick={() => setPalette(true)} aria-label="搜索">
                  <Icon name="search" size={15} /><span>搜索</span><kbd>⌘K</kbd>
                </button>
              </div>
              <nav className={L.nav}>
                <NavLink to="/" icon="home" label="工作台" active={path === '/'} meta={todo ? <Badge tone="warn">{todo}</Badge> : undefined} />
                {running.length > 0 && (
                  <div className={L.group}>
                    <div className={L.groupHead}>进行中</div>
                    {running.slice(0, 6).map((a) => (
                      <NavLink key={a.id} to="/audits/$aid" params={{ aid: a.id }} label={a.title} active={path === `/audits/${a.id}`}
                        icon="activity" meta={<span className={L.navMeta}>{AUDIT_STATUS[a.status]}</span>} />
                    ))}
                  </div>
                )}
                <div className={L.group}>
                  <div className={L.groupHead}>
                    <span>会话</span>
                    <Link to="/conversations" className={L.navMeta} style={{ textDecoration: 'none' }}>全部</Link>
                  </div>
                  {conversations.data?.length === 0 && <div className={L.navItem} style={{ cursor: 'default', color: 'var(--text-3)' }}>还没有会话</div>}
                  <SideConversations items={conversations.data?.slice(0, 6) ?? []} path={path} />
                </div>
                <div className={L.group}>
                  <div className={L.groupHead}>
                    <span>项目</span>
                    <Button variant="ghost" size="sm" icon="plus" aria-label="新建项目" onClick={() => setNewProject(true)} />
                  </div>
                  <SideProjects items={projects.data ?? []} activeId={pidInPath} />
                </div>
                <div className={L.group}>
                  <div className={L.groupHead}>
                    <span>风险排查</span>
                    <Link to="/hunts" className={L.navMeta} style={{ textDecoration: 'none' }}>全部</Link>
                  </div>
                  {hunts.data?.length === 0 && <div className={L.navItem} style={{ cursor: 'default', color: 'var(--text-3)' }}>还没有排查</div>}
                  <SideHunts items={hunts.data?.slice(0, 5) ?? []} path={path} />
                </div>
              </nav>
              <div className={L.sideFoot}>
                <NavLink to="/knowledge" icon="book" label="知识库" active={path.startsWith('/knowledge')} />
                <NavLink to="/settings/$section" params={{ section: 'models' }} icon="settings" label="设置" active={path.startsWith('/settings')} />
                <button className={L.navItem} onClick={() => setTheme(theme === 'dark' ? 'light' : theme === 'light' ? 'system' : 'dark')}>
                  <Icon name={theme === 'dark' ? 'moon' : 'sun'} />
                  <span className={L.navLabel}>主题：{theme === 'dark' ? '深色' : theme === 'light' ? '浅色' : '跟随系统'}</span>
                </button>
              </div>
            </>
          )}
        </aside>
        <main id="main" className={L.main} tabIndex={-1}>
          <Outlet />
        </main>
      </div>
      <NewProjectDialog open={newProject} onClose={() => setNewProject(false)} />
      <CommandPalette open={palette} onClose={() => setPalette(false)} />
    </ShellCtx.Provider>
  );
}

export function TopBar({ crumbs, actions, ai = true }: { crumbs: { label: string; to?: string; params?: Record<string, string>; search?: Record<string, unknown> }[]; actions?: ReactNode; ai?: boolean }) {
  const { openMobile } = useContext(ShellCtx);
  const assistant = useAi();
  return (
    <div className={L.topbar}>
      <Button className={L.menuBtn} variant="ghost" size="sm" icon="sidebar" aria-label="打开导航" onClick={openMobile} />
      <nav className={L.crumbs} aria-label="位置">
        {crumbs.map((c, i) => (
          <span key={i} style={{ display: 'contents' }}>
            {i > 0 && <Icon name="chevronRight" size={14} />}
            {c.to && i < crumbs.length - 1
              ? <Link to={c.to as never} params={c.params as never} search={c.search as never}>{c.label}</Link>
              : <span className={i === crumbs.length - 1 ? L.crumbCur : undefined}>{c.label}</span>}
          </span>
        ))}
      </nav>
      {actions && <div style={{ display: 'flex', gap: 8, alignItems: 'center', flex: 'none' }}>{actions}</div>}
      {ai && (
        <Button size="sm" variant={assistant.open ? 'default' : 'ghost'} icon="sparkle" aria-pressed={assistant.open} title="AI 面板（⌘J）"
          onClick={() => assistant.setOpen(!assistant.open)}>AI</Button>
      )}
    </div>
  );
}

/**
 * Main area + resizable right-hand panel (320–760px, remembered) with two tabs: the page's detail
 * (`panel`) and the global AI panel. `panelKey` changes when the page opens another object: the detail tab
 * comes to the front. `noAi` pages (the full conversation page) never show the AI tab.
 */
export function PageLayout({ children, panel, onClosePanel, panelTitle, panelKey, narrow, flush, noAi }: {
  children: ReactNode; panel?: ReactNode; onClosePanel?: () => void; panelTitle?: ReactNode; panelKey?: string | undefined; narrow?: boolean; flush?: boolean; noAi?: boolean;
}) {
  const ai = useAi();
  const [w, setW] = useState(() => Number(readPref('ca.panelW', '480')) || 480);
  const drag = useRef<{ x: number; w: number } | null>(null);
  const { setTab } = ai;
  // A newly opened object brings the detail tab to the front (`panel` itself is a new node every render).
  useEffect(() => { if (panelKey !== undefined) setTab('detail'); }, [panelKey, setTab]);
  useEffect(() => {
    const move = (e: MouseEvent) => { if (drag.current) setW(Math.max(320, Math.min(760, drag.current.w + drag.current.x - e.clientX))); };
    const up = () => { if (drag.current) { drag.current = null; writePref('ca.panelW', String(w)); document.body.style.userSelect = ''; } };
    // A resize whose mouseup never reaches the page (released outside the window) left the whole page
    // unselectable (`user-select: none` on body); losing focus ends the drag too.
    window.addEventListener('mousemove', move);
    window.addEventListener('mouseup', up);
    window.addEventListener('blur', up);
    return () => { window.removeEventListener('mousemove', move); window.removeEventListener('mouseup', up); window.removeEventListener('blur', up); };
  }, [w]);
  const showAi = ai.open && !noAi;
  const side: 'detail' | 'ai' | null = panel && showAi ? ai.tab : panel ? 'detail' : showAi ? 'ai' : null;
  return (
    <div className={L.content}>
      <div className={L.page}>
        {flush ? children : <div className={cx(L.pageInner, narrow && L.pageNarrow)}>{children}</div>}
      </div>
      {side && (
        <aside className={L.panel} style={{ ['--panel-w' as string]: `${w}px` }} aria-label="详情面板">
          <div className={L.panelResize} onMouseDown={(e) => { drag.current = { x: e.clientX, w }; document.body.style.userSelect = 'none'; }} />
          <div className={L.panelHead}>
            <div className={L.panelTabs} role="tablist">
              {panel && (
                <button role="tab" aria-selected={side === 'detail'} className={cx(L.panelTab, side === 'detail' && L.panelTabOn)} onClick={() => setTab('detail')}>
                  {panelTitle ?? '详情'}
                </button>
              )}
              {showAi && (
                <button role="tab" aria-selected={side === 'ai'} className={cx(L.panelTab, side === 'ai' && L.panelTabOn)} onClick={() => setTab('ai')}>
                  <Icon name="sparkle" size={14} /> AI
                </button>
              )}
            </div>
            {side === 'detail' && onClosePanel && <Button variant="ghost" size="sm" icon="x" aria-label="关闭面板" onClick={onClosePanel} />}
            {side === 'ai' && <Button variant="ghost" size="sm" icon="x" aria-label="关闭 AI 面板" onClick={() => ai.setOpen(false)} />}
          </div>
          {/* Both stay mounted: the detail declares the object the AI talks about, the thread keeps its state. */}
          {panel && <div className={L.panelBody} role="tabpanel" aria-label="详情" hidden={side !== 'detail'}>{panel}</div>}
          {showAi && <div className={L.panelBody} role="tabpanel" aria-label="AI" hidden={side !== 'ai'}><AiPanelBody /></div>}
        </aside>
      )}
    </div>
  );
}

export function Section({ title, actions, children }: { title: ReactNode; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className={L.section}>
      <div className={L.sectionHead}><h2 className={L.sectionTitle}>{title}</h2>{actions}</div>
      {children}
    </section>
  );
}

export { L as layoutStyles };
