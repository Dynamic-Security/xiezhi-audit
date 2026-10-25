// Shared UI components: Button, Badge/StatusBadge, Dialog/ConfirmDialog (focus trap,
// focus return, no native confirm), Toast (errors carry requestId), EmptyState, Tabs, CodeView.
import {
  createContext, useCallback, useContext, useEffect, useId, useLayoutEffect, useMemo, useRef, useState,
  type ButtonHTMLAttributes, type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { ApiError } from '../api/client';
import { useGeneral } from '../api/queries';
import { formatCost, tokenCost } from '../format/cost';
import { fromMillions, toMillions } from '../format/tokens';
import { AUDIT_STATUS, CONFIRM, HANDLING, LIFECYCLE, SEVERITY } from '../format/messages';
import { Icon, type IconName } from './icons';
import s from './ui.module.css';

export { Icon, type IconName } from './icons';
export { BrandMark } from './brand';
export { s as ui };

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(' ');

type Variant = 'default' | 'primary' | 'danger' | 'dangerSolid' | 'ghost';
export function Button({ variant = 'default', size, icon, loading, children, className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant; size?: 'sm'; icon?: IconName; loading?: boolean;
}) {
  const iconOnly = !children && icon;
  return (
    <button type="button" {...rest} disabled={rest.disabled || loading}
      className={cx(s.btn, variant !== 'default' && s[variant], size === 'sm' && s.sm, iconOnly && (size === 'sm' ? s.iconSm : s.icon), className)}>
      {loading ? <span className={s.spinner} /> : icon ? <Icon name={icon} size={size === 'sm' ? 14 : 16} /> : null}
      {children}
    </button>
  );
}

export type Tone = 'ok' | 'warn' | 'danger' | 'accent' | 'info' | 'neutral';
export function Badge({ tone = 'neutral', dot, pulse, children, title }: { tone?: Tone; dot?: boolean; pulse?: boolean; children: ReactNode; title?: string }) {
  return (
    <span className={cx(s.badge, tone !== 'neutral' && s[`tone-${tone}`])} title={title}>
      {dot && <span className={cx(s.dot, pulse && s.pulse)} />}
      {children}
    </span>
  );
}

export function SeverityBadge({ severity, original }: { severity: string; original?: string | null }) {
  return (
    <span className={cx(s.badge, s[`sev-${severity}`])} title={original ? `原严重度：${SEVERITY[original]}` : undefined}>
      <Icon name={severity === 'critical' || severity === 'high' ? 'alert' : 'shield'} size={12} />
      {SEVERITY[severity] ?? severity}{original ? '*' : ''}
    </span>
  );
}

const STATUS_TONE: Record<string, Tone> = {
  planning: 'accent', awaiting_confirm: 'warn', queued: 'info', running: 'accent', waiting_budget: 'warn', paused: 'warn', cancelling: 'warn',
  interrupted: 'warn', completed: 'ok', partial: 'warn', failed: 'danger', cancelled: 'neutral',
};
export function AuditStatusBadge({ status }: { status: string }) {
  const live = status === 'running' || status === 'planning' || status === 'cancelling';
  return <Badge tone={STATUS_TONE[status] ?? 'neutral'} dot pulse={live}>{AUDIT_STATUS[status] ?? status}</Badge>;
}
export function ConfirmBadge({ status }: { status: string }) {
  return <Badge tone={status === 'confirmed' ? 'danger' : status === 'false_positive' ? 'neutral' : 'warn'}>{status === 'confirmed' ? <Icon name="check" size={12} /> : null}{CONFIRM[status] ?? status}</Badge>;
}
export function HandlingBadge({ status }: { status: string }) {
  return <Badge tone={status === 'fixed' ? 'ok' : status === 'fixing' ? 'accent' : status === 'risk_accepted' ? 'info' : 'neutral'}>{HANDLING[status] ?? status}</Badge>;
}
export function LifecycleBadge({ status }: { status: string }) {
  return <Badge tone={status === 'regressed' ? 'danger' : status === 'new' ? 'accent' : status === 'fixed_verified' ? 'ok' : 'info'}>{LIFECYCLE[status] ?? status}</Badge>;
}

export function Spinner() {
  return <span className={s.spinner} role="status" aria-label="加载中" />;
}

export function EmptyState({ icon = 'inbox', title, children, action }: { icon?: IconName; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className={s.empty}>
      <div className={s.emptyIcon}><Icon name={icon} size={22} /></div>
      <div className={s.emptyTitle}>{title}</div>
      {children && <div className={s.muted} style={{ maxWidth: 440 }}>{children}</div>}
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const e = error instanceof ApiError ? error : null;
  const gone = e?.status === 404;
  return (
    <EmptyState icon={gone ? 'search' : 'alert'} title={gone ? '已失效或已删除' : '加载失败'} action={onRetry && !gone ? <Button size="sm" onClick={onRetry} icon="refresh">重试</Button> : undefined}>
      {e ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : String((error as Error)?.message ?? error)}
      {e?.requestId && <div className={s.faint} style={{ fontSize: 12, marginTop: 4 }}>请求 ID：{e.requestId}</div>}
    </EmptyState>
  );
}

export function Skeleton({ h = 16, w = '100%' }: { h?: number; w?: number | string }) {
  return <div className={s.skeleton} style={{ height: h, width: w }} />;
}

export function Loading({ rows = 3 }: { rows?: number }) {
  return <div className={s.stack} style={{ padding: 16 }}>{Array.from({ length: rows }, (_, i) => <Skeleton key={i} h={18} w={`${90 - i * 12}%`} />)}</div>;
}

export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { key: T; label: string; count?: number | undefined }[] }) {
  return (
    <div className={s.tabs} role="tablist">
      {items.map((it) => (
        <button key={it.key} role="tab" aria-selected={value === it.key} className={cx(s.tab, value === it.key && s.tabActive)} onClick={() => onChange(it.key)}>
          {it.label}{it.count !== undefined && <span className={s.tabCount}>{it.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Segmented<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { key: T; label: string }[] }) {
  return (
    <div className={s.seg} role="radiogroup">
      {items.map((it) => (
        <button key={it.key} role="radio" aria-checked={value === it.key} className={cx(s.segBtn, value === it.key && s.segActive)} onClick={() => onChange(it.key)}>{it.label}</button>
      ))}
    </div>
  );
}

export function Field({ label, hint, error, children, group }: { label: ReactNode; hint?: ReactNode; error?: string | null; children: ReactNode; group?: boolean }) {
  const id = useId();
  const foot = error ? <span className={s.error}>{error}</span> : hint ? <span className={s.hint}>{hint}</span> : null;
  // Only single inputs are wrapped in <label>; composite content (buttons, pickers) is a labelled group,
  // otherwise every nested button would inherit the field label as its accessible name.
  if (group) {
    return (
      <div className={s.field} role="group" aria-labelledby={id}>
        <span id={id} className={s.label}>{label}</span>
        {children}
        {foot}
      </div>
    );
  }
  return (
    <label className={s.field}>
      <span className={s.label}>{label}</span>
      {children}
      {foot}
    </label>
  );
}

export function Progress({ value, max, tone }: { value: number; max: number; tone?: 'warn' | 'danger' }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return <div className={s.progress} role="progressbar" aria-valuenow={value} aria-valuemax={max}><div className={cx(s.progressBar, tone === 'warn' && s.progressWarn, tone === 'danger' && s.progressDanger)} style={{ width: `${pct}%` }} /></div>;
}

// ---- Dialog with focus trap and focus return ----
export function Dialog({ open, onClose, title, children, footer, wide, labelledBy }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; wide?: boolean | 'xl'; labelledBy?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const id = useId();
  // Callers pass inline `onClose` functions, a new one each render: as an effect dependency it re-ran the effect on
  // every keystroke, moving focus back to the first input (typing in the second field of a dialog went
  // into the first). The latest one is read through a ref; focus is set once per opening.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    const focusables = () => [...(el?.querySelectorAll<HTMLElement>('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])') ?? [])].filter((x) => !x.hasAttribute('disabled'));
    setTimeout(() => (el?.querySelector<HTMLElement>('[autofocus], input, textarea, select') ?? focusables()[0])?.focus(), 0);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onCloseRef.current(); }
      if (e.key === 'Tab') {
        const f = focusables();
        if (!f.length) return;
        if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1]!.focus(); }
        else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0]!.focus(); }
      }
    };
    document.addEventListener('keydown', onKey, true);
    return () => { document.removeEventListener('keydown', onKey, true); prev?.focus?.(); };
  }, [open]);
  if (!open) return null;
  return (
    <div className={s.overlay} onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div ref={ref} className={cx(s.dialog, wide === 'xl' ? s.dialogXl : wide && s.dialogWide)} role="dialog" aria-modal="true" aria-labelledby={labelledBy ?? id}>
        <div className={s.dialogHead}>
          <div id={id} className={s.dialogTitle}>{title}</div>
          <Button variant="ghost" size="sm" icon="x" aria-label="关闭" onClick={onClose} />
        </div>
        <div className={s.dialogBody}>{children}</div>
        {footer && <div className={s.dialogFoot}>{footer}</div>}
      </div>
    </div>
  );
}

/** Three levels: normal, destructive (type the name), external write. */
export function ConfirmDialog({ open, onClose, onConfirm, title, children, confirmText = '确认', level = 'normal', typeToConfirm, loading }: {
  open: boolean; onClose: () => void; onConfirm: () => void; title: string; children?: ReactNode; confirmText?: string;
  level?: 'normal' | 'destructive'; typeToConfirm?: string; loading?: boolean;
}) {
  const [typed, setTyped] = useState('');
  useEffect(() => { if (!open) setTyped(''); }, [open]);
  const blocked = !!typeToConfirm && typed !== typeToConfirm;
  return (
    <Dialog open={open} onClose={onClose} title={title} footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant={level === 'destructive' ? 'dangerSolid' : 'primary'} disabled={blocked} loading={loading} onClick={onConfirm}>{confirmText}</Button>
    </>}>
      {children && <div className={s.muted}>{children}</div>}
      {typeToConfirm && (
        <Field label={<>请输入 <code>{typeToConfirm}</code> 以确认</>}>
          <input className={s.input} value={typed} onChange={(e) => setTyped(e.target.value)} autoFocus />
        </Field>
      )}
    </Dialog>
  );
}

// ---- Toasts ----
interface ToastItem { id: number; kind: 'ok' | 'error' | 'info'; text: string; meta?: string }
const ToastCtx = createContext<{ push: (t: Omit<ToastItem, 'id'>) => void } | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const push = useCallback((t: Omit<ToastItem, 'id'>) => {
    const id = Date.now() + Math.random();
    setItems((xs) => [...xs.slice(-3), { ...t, id }]);
    setTimeout(() => setItems((xs) => xs.filter((x) => x.id !== id)), t.kind === 'error' ? 8000 : 3500);
  }, []);
  const value = useMemo(() => ({ push }), [push]);
  return (
    <ToastCtx.Provider value={value}>
      {children}
      <div className={s.toasts} aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={cx(s.toast, t.kind === 'error' && s.toastErr)}>
            <span style={{ color: t.kind === 'error' ? 'var(--danger)' : t.kind === 'ok' ? 'var(--ok)' : 'var(--accent)', marginTop: 2 }}>
              <Icon name={t.kind === 'error' ? 'alert' : t.kind === 'ok' ? 'checkCircle' : 'bulb'} />
            </span>
            <div className={s.grow}>
              <div>{t.text}</div>
              {t.meta && <div className={s.toastMeta}>{t.meta}{t.kind === 'error' && <button className={s.menuItem} style={{ display: 'inline', padding: '0 4px', width: 'auto' }} onClick={() => navigator.clipboard?.writeText(t.meta ?? '')}>复制</button>}</div>}
            </div>
            <Button size="sm" variant="ghost" icon="x" aria-label="关闭" onClick={() => setItems((xs) => xs.filter((x) => x.id !== t.id))} />
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastCtx);
  if (!ctx) throw new Error('ToastProvider missing');
  return useMemo(() => ({
    ok: (text: string) => ctx.push({ kind: 'ok', text }),
    info: (text: string) => ctx.push({ kind: 'info', text }),
    error: (e: unknown, prefix = '操作失败') => {
      if (e instanceof ApiError) {
        const conflict = e.code === 'COMMON_REVISION_CONFLICT';
        ctx.push({ kind: 'error', text: conflict ? '已被他处修改，已刷新为最新内容，请重新操作' : `${prefix}：${e.message}${e.hint ? `（${e.hint}）` : ''}`, ...(e.requestId ? { meta: `请求 ID ${e.requestId}` } : {}) });
      } else ctx.push({ kind: 'error', text: `${prefix}：${String((e as Error)?.message ?? e)}` });
    },
  }), [ctx]);
}

// ---- CodeView: snapshot source with highlighted range ----
export function CodeView({ lines, from, highlight, title, actions, maxHeight = 420 }: {
  lines: string[]; from: number; highlight?: [number, number] | undefined; title?: ReactNode; actions?: ReactNode; maxHeight?: number;
}) {
  const hiRef = useRef<HTMLDivElement>(null);
  const boxRef = useRef<HTMLDivElement>(null);
  // Scroll only inside the code box (scrollIntoView would also scroll the surrounding panel).
  useEffect(() => {
    const box = boxRef.current;
    const hi = hiRef.current;
    if (box && hi) box.scrollTop = Math.max(0, hi.offsetTop - box.clientHeight / 2);
  }, [highlight?.[0], lines.length]);
  return (
    <div ref={boxRef} className={s.code} style={{ maxHeight, position: 'relative' }}>
      {title && <div className={s.codeHead}><span className={s.ellipsis}>{title}</span>{actions}</div>}
      <div style={{ padding: '6px 0' }}>
        {lines.map((text, i) => {
          const no = from + i;
          const hi = !!highlight && no >= highlight[0] && no <= highlight[1];
          return (
            <div key={no} ref={hi && no === highlight![0] ? hiRef : undefined} className={cx(s.codeLine, hi && s.codeHi)}>
              <span className={s.codeNo}>{no}</span><span className={s.codeText}>{text || ' '}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/**
 * An ⓘ next to a setting: shows what it means on hover, focus or click (in a portal above dialogs, so scroll areas
 * neither clip nor cover it).
 */
export function InfoTip({ label, children }: { label: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [pinned, setPinned] = useState(false);
  const btn = useRef<HTMLButtonElement>(null);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  useLayoutEffect(() => {
    if (!open || !btn.current) { setPos(null); return; }
    const r = btn.current.getBoundingClientRect();
    const w = Math.min(300, window.innerWidth - 32);
    setPos({ top: r.bottom + 6, left: Math.max(16, Math.min(r.left - w / 2 + r.width / 2, window.innerWidth - w - 16)) });
  }, [open]);
  useEffect(() => {
    if (!pinned) return;
    const onDown = (e: MouseEvent) => { if (!btn.current?.contains(e.target as Node)) { setPinned(false); setOpen(false); } };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [pinned]);
  return (
    <>
      <button ref={btn} type="button" className={s.infoBtn} aria-label={label} aria-expanded={open}
        onMouseEnter={() => setOpen(true)} onMouseLeave={() => { if (!pinned) setOpen(false); }} onFocus={() => setOpen(true)} onBlur={() => { if (!pinned) setOpen(false); }}
        onClick={(e) => { e.preventDefault(); e.stopPropagation(); setPinned(!pinned); setOpen(!pinned); }}>
        <Icon name="info" size={13} />
      </button>
      {open && pos && createPortal(<div role="tooltip" className={s.infoPop} style={{ top: pos.top, left: pos.left }}>{children}</div>, document.body)}
    </>
  );
}

/** Close on outside click / Escape for small popovers. */
export function useDismiss(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) onClose(); };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey); };
  }, [open, onClose]);
  return ref;
}

/** Grow a textarea with its content up to `max` px, then scroll inside it. */
export function useAutoGrow(value: string, max = 200) {
  const ref = useRef<HTMLTextAreaElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, max)}px`;
    el.style.overflowY = el.scrollHeight > max ? 'auto' : 'hidden';
  }, [value, max]);
  return ref;
}

/**
 * Keep a scroll container at the bottom while its content grows (streamed replies, new cards), unless the
 * user has scrolled up to read; `toBottom()` jumps back and re-pins (e.g. after sending a message).
 */
export function useStickToBottom<S extends HTMLElement, C extends HTMLElement>() {
  const scrollRef = useRef<S>(null);
  const contentRef = useRef<C>(null);
  const pinnedRef = useRef(true);
  const [pinned, setPinned] = useState(true);
  const toBottom = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    pinnedRef.current = true;
    setPinned(true);
    el.scrollTop = el.scrollHeight;
  }, []);
  useEffect(() => {
    const el = scrollRef.current;
    const content = contentRef.current;
    if (!el || !content) return;
    const onScroll = () => {
      const at = el.scrollHeight - el.scrollTop - el.clientHeight < 48;
      if (at !== pinnedRef.current) { pinnedRef.current = at; setPinned(at); }
    };
    // While the mouse is held in the thread or text in it is selected, live content (an audit's progress,
    // its questions) must not move the text under the cursor: following the bottom then made selecting a question fail.
    let holding = false;
    const down = () => { holding = true; };
    const up = () => { holding = false; };
    const selecting = () => { const sel = document.getSelection(); return !!sel && !sel.isCollapsed && !!sel.anchorNode && content.contains(sel.anchorNode); };
    const grow = new ResizeObserver(() => { if (pinnedRef.current && !holding && !selecting()) el.scrollTop = el.scrollHeight; });
    el.addEventListener('scroll', onScroll, { passive: true });
    el.addEventListener('pointerdown', down);
    window.addEventListener('pointerup', up);
    grow.observe(content);
    el.scrollTop = el.scrollHeight;
    return () => { el.removeEventListener('scroll', onScroll); el.removeEventListener('pointerdown', down); window.removeEventListener('pointerup', up); grow.disconnect(); };
  }, []);
  return { scrollRef, contentRef, pinned, toBottom };
}

/**
 * Approximate cost next to a token amount. Budgets stay in tokens; this only helps judge them.
 * Without a price for the model the cost shows as unknown, marked "价格缺失".
 */
/** A token amount typed in millions (M); `value` and `onChange` are in tokens ('' when empty or not a number). */
export function TokenInput({ value, onChange, placeholder }: { value: number | ''; onChange: (tokens: number | '') => void; placeholder?: number }) {
  const [text, setText] = useState(() => toMillions(value));
  // Follow values set from outside (loaded defaults, suggested top-ups) without rewriting what the user is typing.
  useEffect(() => { if (fromMillions(text) !== value) setText(toMillions(value)); }, [value]);
  return (
    <span className={s.unitInput}>
      <input className={s.input} type="number" min={0} step="any" inputMode="decimal" value={text}
        placeholder={placeholder ? toMillions(placeholder) : undefined}
        onChange={(e) => { setText(e.target.value); onChange(fromMillions(e.target.value)); }} />
      <span className={s.unit} title="百万 tokens" aria-hidden>M</span>
    </span>
  );
}

export function TokenCostHint({ tokens, model }: { tokens: number; model: { provider: string; model: string } | null | undefined }) {
  const general = useGeneral();
  if (!tokens || tokens <= 0) return null;
  const c = tokenCost(tokens, model, general.data?.pricing);
  if (c.known) {
    return <span className={s.faint} style={{ fontSize: 12 }} title={`按 ${c.key} 的单价、80% 输入 / 20% 输出估算；缓存读取更便宜，实际通常更低`}>{formatCost(c)}（按 {c.key} 单价估算）</span>;
  }
  return (
    <span className={s.faint} style={{ fontSize: 12, display: 'inline-flex', gap: 6, alignItems: 'center' }}>
      费用：未知 <Badge tone="warn" title={c.key ? `价格表中没有 ${c.key} 的单价，可在 设置 › 通用 › 价格表 中补充` : '没有选定模型'}>价格缺失</Badge>
    </span>
  );
}
