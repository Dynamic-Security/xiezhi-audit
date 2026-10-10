// Routes. Filters, tabs and the context-panel selection live in validated search params
// so refresh/share returns to the same place.
import { createRootRoute, createRoute, createRouter } from '@tanstack/react-router';
import { AppShell } from './features/layout/AppShell';
import { HomePage } from './features/home/HomePage';
import { ProjectPage } from './features/projects/ProjectPage';
import { NewAuditPage } from './features/audits/NewAuditPage';
import { AuditPage } from './features/audits/AuditPage';
import { KnowledgePage } from './features/knowledge/KnowledgePage';
import { SettingsPage } from './features/settings/SettingsPage';
import { HuntPage, HuntsPage, NewHuntPage } from './features/hunts/HuntPages';
import { NotFound } from './features/home/NotFound';
import { ConversationPage, ConversationsPage, NewConversationPage } from './features/conversations/ConversationPage';

const str = (v: unknown): string | undefined => (typeof v === 'string' && v.length <= 500 ? v : typeof v === 'number' ? String(v) : undefined);
const list = (v: unknown): string[] | undefined => {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string').slice(0, 20);
  const s = str(v);
  return s ? s.split(',').filter(Boolean).slice(0, 20) : undefined;
};
const oneOf = <T extends string>(v: unknown, allowed: readonly T[]): T | undefined => (allowed.includes(v as T) ? (v as T) : undefined);
const clean = <T extends Record<string, unknown>>(o: T): T => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && !(Array.isArray(v) && v.length === 0))) as T;

export const PROJECT_TABS = ['overview', 'repos', 'topology', 'audits', 'vulns', 'threats', 'facts', 'knowledge'] as const;
export type ProjectSearch = {
  tab?: (typeof PROJECT_TABS)[number]; addRepo?: number; panel?: string; severity?: string[]; confirmation?: string[]; handling?: string[];
  lifecycle?: string[]; q?: string; sort?: string;
  /** the threat model open in the 威胁建模 tab. */
  tm?: string;
};
export const AUDIT_TABS = ['execution', 'trajectory', 'results', 'coverage', 'plan', 'egress'] as const;
export type AuditSearch = { tab?: (typeof AUDIT_TABS)[number]; panel?: string; type?: string[]; q?: string; step?: string; kind?: string };

const rootRoute = createRootRoute({ component: AppShell, notFoundComponent: NotFound });
const homeRoute = createRoute({ getParentRoute: () => rootRoute, path: '/', component: HomePage });
const projectRoute = createRoute({
  getParentRoute: () => rootRoute, path: '/projects/$pid', component: ProjectPage,
  validateSearch: (s: Record<string, unknown>): ProjectSearch => clean({
    tab: oneOf(s.tab, PROJECT_TABS), addRepo: s.addRepo ? 1 : undefined, panel: str(s.panel), severity: list(s.severity), confirmation: list(s.confirmation),
    handling: list(s.handling), lifecycle: list(s.lifecycle), q: str(s.q), sort: str(s.sort), tm: str(s.tm),
  }),
});
const newAuditRoute = createRoute({
  getParentRoute: () => rootRoute, path: '/audits/new', component: NewAuditPage,
  validateSearch: (s: Record<string, unknown>): { projectId?: string; repo?: string; scene?: string; tm?: string[] } => clean({ projectId: str(s.projectId), repo: str(s.repo), scene: s.scene === 'incremental' ? 'incremental' : undefined, tm: list(s.tm) }),
});
const auditRoute = createRoute({
  getParentRoute: () => rootRoute, path: '/audits/$aid', component: AuditPage,
  validateSearch: (s: Record<string, unknown>): AuditSearch => clean({ tab: oneOf(s.tab, AUDIT_TABS), panel: str(s.panel), type: list(s.type), q: str(s.q), step: str(s.step), kind: str(s.kind) }),
});
const knowledgeRoute = createRoute({ getParentRoute: () => rootRoute, path: '/knowledge', component: KnowledgePage, validateSearch: (s: Record<string, unknown>): { skill?: string } => clean({ skill: str(s.skill) }) });
const settingsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/settings/$section', component: SettingsPage });
const huntsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/hunts', component: HuntsPage });
const newHuntRoute = createRoute({
  getParentRoute: () => rootRoute, path: '/hunts/new', component: NewHuntPage,
  // `basis` / `projects`: continue a basis created from a conversation card.
  validateSearch: (s: Record<string, unknown>): { skill?: string; basis?: string; projects?: string[] } => clean({ skill: str(s.skill), basis: str(s.basis), projects: list(s.projects) }),
});
const huntRoute = createRoute({ getParentRoute: () => rootRoute, path: '/hunts/$hid', component: HuntPage });

const conversationsRoute = createRoute({ getParentRoute: () => rootRoute, path: '/conversations', component: ConversationsPage });
const newConversationRoute = createRoute({ getParentRoute: () => rootRoute, path: '/conversations/new', component: NewConversationPage });
const conversationRoute = createRoute({
  getParentRoute: () => rootRoute, path: '/conversations/$cid', component: ConversationPage,
  validateSearch: (s: Record<string, unknown>): { panel?: string } => clean({ panel: str(s.panel) }),
});

const routeTree = rootRoute.addChildren([homeRoute, projectRoute, newAuditRoute, auditRoute, knowledgeRoute, settingsRoute, huntsRoute, newHuntRoute, huntRoute, conversationsRoute, newConversationRoute, conversationRoute]);
export const router = createRouter({ routeTree, defaultPreload: false, scrollRestoration: true });
export { projectRoute, auditRoute, newAuditRoute, knowledgeRoute, settingsRoute };

declare module '@tanstack/react-router' {
  interface Register { router: typeof router }
}
