// System notifications and the tab title badge: the audit ended, the Agent asked, the budget ran
// out. Asked for once, on a user action that starts work (the browser requires a gesture); “设置 › 通用” turns
// them off. Nothing is shown while the page itself is in front: the in-page toast is enough then.
const PREF = 'ca.notify';

export function notifyEnabled(): boolean {
  try { return localStorage.getItem(PREF) !== 'off'; } catch { return true; }
}
export function setNotifyEnabled(on: boolean): void {
  try { localStorage.setItem(PREF, on ? 'on' : 'off'); } catch { /* private mode */ }
  if (on) askNotifyPermission();
}
export function notifyPermission(): NotificationPermission | 'unsupported' {
  return typeof Notification === 'undefined' ? 'unsupported' : Notification.permission;
}

/** Ask the browser once (only while the preference is on and nothing was decided yet). */
export function askNotifyPermission(): void {
  if (typeof Notification === 'undefined' || !notifyEnabled() || Notification.permission !== 'default') return;
  void Notification.requestPermission().catch(() => undefined);
}

export function notify(title: string, body: string, onClick?: () => void, tag?: string): void {
  if (typeof Notification === 'undefined' || !notifyEnabled() || Notification.permission !== 'granted') return;
  if (document.visibilityState === 'visible' && document.hasFocus()) return;
  try {
    const n = new Notification(title, { body: body.slice(0, 200), ...(tag ? { tag } : {}) });
    n.onclick = () => { window.focus(); onClick?.(); n.close(); };
  } catch { /* some browsers only allow notifications from a service worker */ }
}

/** “(3) 獬豸审计” while there is something to do. */
export function setTitleBadge(count: number): void {
  const base = '獬豸审计';
  document.title = count > 0 ? `(${count}) ${base}` : base;
}
