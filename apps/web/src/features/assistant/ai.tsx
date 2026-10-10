// Global AI panel state. The panel is app state, not URL state: it stays open
// across navigation (many links replace the search string). Pages declare the object they show with
// `useAiScope`; the most specific one (e.g. the vulnerability panel inside a project page) is the current scope.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { MentionDto } from '@xiezhi/contracts';

export interface AiScope { kind: MentionDto['kind']; id: string; label: string }

/** Objects whose own conversation is continued; elsewhere the panel uses one general conversation. */
const CONTINUED = new Set<AiScope['kind']>(['vuln', 'audit']);
const RANK: Record<AiScope['kind'], number> = { project: 1, skill: 2, repo: 3, audit: 4, vuln: 5 };
export const scopeKey = (s: AiScope | null): string => (s && CONTINUED.has(s.kind) ? `${s.kind}:${s.id}` : 'general');

interface AiState {
  open: boolean;
  tab: 'detail' | 'ai';
  setOpen: (v: boolean) => void;
  setTab: (t: 'detail' | 'ai') => void;
  scope: AiScope | null;
  /** Conversation per scope key: an id, null for a new draft, undefined when not decided yet. */
  assigned: (key: string) => string | null | undefined;
  assign: (key: string, cid: string | null) => void;
  /** Open the AI tab (e.g. “追问” on the object in view). */
  ask: () => void;
  /** Open a conversation (null: a new one) in the AI tab for the current scope. */
  show: (cid: string | null) => void;
  pushScope: (token: symbol, s: AiScope) => void;
  popScope: (token: symbol) => void;
}

const Ctx = createContext<AiState | null>(null);

function read<T>(key: string, def: T): T {
  try { const v = localStorage.getItem(key); return v ? JSON.parse(v) as T : def; } catch { return def; }
}
function write(key: string, v: unknown): void {
  try { localStorage.setItem(key, JSON.stringify(v)); } catch { /* private mode */ }
}

export function AiProvider({ children }: { children: ReactNode }) {
  const [open, setOpenState] = useState<boolean>(() => read('ca.ai.open', false));
  const [tab, setTab] = useState<'detail' | 'ai'>('ai');
  const [stack, setStack] = useState<{ token: symbol; scope: AiScope }[]>([]);
  const [map, setMap] = useState<Record<string, string | null>>(() => read('ca.ai.map', {}));
  // Child effects run before their parents', so declaration order is not nesting order: the most specific
  // kind wins (a vulnerability panel inside a project page), the latest declaration among equals.
  const scope = stack.reduce<AiScope | null>((best, x) => (!best || (RANK[x.scope.kind] ?? 0) >= (RANK[best.kind] ?? 0) ? x.scope : best), null);
  const scopeRef = useRef(scope);
  scopeRef.current = scope;

  const setOpen = useCallback((v: boolean) => { setOpenState(v); write('ca.ai.open', v); if (v) setTab('ai'); }, []);
  const assign = useCallback((key: string, cid: string | null) => {
    setMap((m) => {
      const next = { ...m, [key]: cid };
      const keys = Object.keys(next);
      // Keep the map small: the 50 most recent keys (insertion order).
      const trimmed = keys.length > 50 ? Object.fromEntries(keys.slice(-50).map((k) => [k, next[k]!])) : next;
      write('ca.ai.map', trimmed);
      return trimmed;
    });
  }, []);
  const pushScope = useCallback((token: symbol, s: AiScope) => setStack((st) => [...st.filter((x) => x.token !== token), { token, scope: s }]), []);
  const popScope = useCallback((token: symbol) => setStack((st) => (st.some((x) => x.token === token) ? st.filter((x) => x.token !== token) : st)), []);
  const state = useMemo<AiState>(() => ({
    open, tab, setOpen, setTab, scope,
    assigned: (key) => (key in map ? map[key] : undefined),
    assign,
    ask: () => setOpen(true),
    show: (cid) => { assign(scopeKey(scopeRef.current), cid); setOpen(true); },
    pushScope, popScope,
  }), [open, tab, setOpen, scope, map, assign, pushScope, popScope]);

  // ⌘J / Ctrl+J toggles the panel (keyboard access).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'j') { e.preventDefault(); setOpen(!open); }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, setOpen]);

  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}

export function useAi(): AiState {
  const s = useContext(Ctx);
  if (!s) throw new Error('useAi outside AiProvider');
  return s;
}

/** Declare the object a page (or a panel inside it) shows; the innermost declaration wins. */
export function useAiScope(s: AiScope | null) {
  const { pushScope, popScope } = useAi();
  const token = useRef(Symbol('scope'));
  const key = s ? `${s.kind}:${s.id}:${s.label}` : '';
  useEffect(() => {
    const t = token.current;
    if (s) pushScope(t, s); else popScope(t);
    return () => popScope(t);
  }, [key, pushScope, popScope]); // `s` is captured through `key`
}
