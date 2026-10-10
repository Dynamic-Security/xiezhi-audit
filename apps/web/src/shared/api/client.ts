// HTTP client: session bootstrap, CSRF header on writes, JSON only, closed error codes.
import type { ApiErrorBody, SessionInfo } from '@xiezhi/contracts';

export const API = '/api/v1';

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly hint?: string, readonly requestId?: string, readonly details?: Record<string, unknown>) {
    super(message);
    this.name = 'ApiError';
  }
}

let csrf: string | null = null;

/**
 * the CSRF token is handed out once, at bootstrap, and kept in localStorage — scoped to this origin
 * (scheme, host and port), so other local services never see it — for reloads and new tabs.
 */
const CSRF_KEY = 'xiezhi.csrf';
function storedCsrf(): string | null {
  try { return window.localStorage.getItem(CSRF_KEY); } catch { return null; }
}
function storeCsrf(token: string | null): void {
  try { if (token) window.localStorage.setItem(CSRF_KEY, token); else window.localStorage.removeItem(CSRF_KEY); } catch { /* storage blocked: this tab keeps it in memory */ }
}

export function setCsrf(token: string | null): void {
  csrf = token;
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  ifMatch?: number;
  idempotencyKey?: string;
  signal?: AbortSignal;
  raw?: boolean;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { accept: 'application/json' };
  if (method !== 'GET') {
    if (csrf) headers['x-csrf-token'] = csrf;
    if (method !== 'DELETE') headers['content-type'] = 'application/json';
  }
  if (opts.ifMatch !== undefined) headers['if-match'] = `W/"r${opts.ifMatch}"`;
  if (opts.idempotencyKey) headers['idempotency-key'] = opts.idempotencyKey;
  const res = await fetch(path.startsWith('/api') ? path : `${API}${path}`, {
    method, headers, credentials: 'same-origin', ...(opts.signal ? { signal: opts.signal } : {}),
    ...(method !== 'GET' && method !== 'DELETE' ? { body: JSON.stringify(opts.body ?? {}) } : {}),
  });
  if (!res.ok) {
    let body: ApiErrorBody | null = null;
    try { body = (await res.json()) as ApiErrorBody; } catch { /* not JSON */ }
    const e = body?.error;
    throw new ApiError(res.status, e?.code ?? 'INTERNAL', e?.message ?? `请求失败（HTTP ${res.status}）`, e?.hint, e?.requestId, e?.details);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T>(p: string, signal?: AbortSignal) => request<T>(p, signal ? { signal } : {}),
  post: <T>(p: string, body?: unknown, extra: Omit<RequestOptions, 'method' | 'body'> = {}) => request<T>(p, { method: 'POST', body: body ?? {}, ...extra }),
  put: <T>(p: string, body: unknown, extra: Omit<RequestOptions, 'method' | 'body'> = {}) => request<T>(p, { method: 'PUT', body, ...extra }),
  patch: <T>(p: string, body: unknown, extra: Omit<RequestOptions, 'method' | 'body'> = {}) => request<T>(p, { method: 'PATCH', body, ...extra }),
  del: <T>(p: string) => request<T>(p, { method: 'DELETE' }),
};

/**
 * Upload a file as raw bytes to POST /uploads. XHR rather than fetch for upload
 * progress; same CSRF header and error shape as `request`.
 */
export function uploadFile<T>(file: File, onProgress?: (loaded: number, total: number) => void, signal?: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${API}/uploads?name=${encodeURIComponent(file.name)}`);
    xhr.withCredentials = true;
    xhr.setRequestHeader('content-type', 'application/octet-stream');
    xhr.setRequestHeader('accept', 'application/json');
    if (csrf) xhr.setRequestHeader('x-csrf-token', csrf);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress?.(e.loaded, e.total); };
    xhr.onerror = () => reject(new ApiError(0, 'INTERNAL', '上传失败：网络错误'));
    xhr.onabort = () => reject(new ApiError(0, 'INTERNAL', '上传已取消'));
    xhr.onload = () => {
      let body: unknown = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) { resolve(body as T); return; }
      const e = (body as ApiErrorBody | null)?.error;
      reject(new ApiError(xhr.status, e?.code ?? 'INTERNAL', e?.message ?? `上传失败（HTTP ${xhr.status}）`, e?.hint, e?.requestId, e?.details));
    };
    signal?.addEventListener('abort', () => xhr.abort());
    xhr.send(file);
  });
}

/** Exchange `#boot=<code>` for a session, clearing the fragment immediately. */
export async function initSession(): Promise<SessionInfo> {
  const m = /[#&]boot=([A-Za-z0-9_-]+)/.exec(window.location.hash);
  if (m) {
    const code = m[1]!;
    window.history.replaceState(null, '', window.location.pathname + window.location.search);
    try {
      const s = await request<SessionInfo>('/api/session/bootstrap', { method: 'POST', body: { code } });
      setCsrf(s.csrfToken);
      storeCsrf(s.csrfToken);
      return s;
    } catch {
      // Fall through: maybe an existing session cookie is still valid.
    }
  }
  const s = await request<SessionInfo>('/api/session');
  setCsrf(s.csrfToken ?? (s.authenticated ? storedCsrf() : null));
  return s;
}

export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}
