// Local API protection: Host/Origin checks, one-time bootstrap codes, in-memory browser
// sessions with CSRF tokens, CLI bearer token and the service discovery file.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, closeSync, fsyncSync, mkdirSync, openSync, renameSync, rmSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { AppError, type ServiceDiscovery } from '@xiezhi/contracts';

export const SESSION_COOKIE = 'ca_session';
/**
 * the cookie name carries the port. Browsers send loopback cookies to every port, so
 * the name cannot keep another local service from receiving it; it keeps instances on different ports apart. The
 * CSRF token is what a leaked cookie lacks: it is only handed out once, at bootstrap.
 */
export function sessionCookieName(port: number): string {
  return `${SESSION_COOKIE}_${port}`;
}
const BOOTSTRAP_TTL_MS = 5 * 60_000;
const SESSION_IDLE_MS = 12 * 3600_000;

function token(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  if (x.length !== y.length) {
    timingSafeEqual(x, x); // keep timing independent of the mismatch position
    return false;
  }
  return timingSafeEqual(x, y);
}

interface Session { id: string; csrf: string; lastSeen: number }

export class AuthState {
  readonly cliToken = token();
  private bootstrap: { code: string; expiresAt: number } | null = null;
  private sessions = new Map<string, Session>();

  constructor(readonly port: number) {}

  get allowedHosts(): string[] {
    return [`127.0.0.1:${this.port}`, `localhost:${this.port}`];
  }

  get allowedOrigins(): string[] {
    return this.allowedHosts.map((h) => `http://${h}`);
  }

  /** New one-time bootstrap code; replaces any earlier unused one. */
  issueBootstrap(): string {
    const code = token();
    this.bootstrap = { code, expiresAt: Date.now() + BOOTSTRAP_TTL_MS };
    return code;
  }

  bootstrapUrl(code: string): string {
    return `http://127.0.0.1:${this.port}/#boot=${code}`;
  }

  /** Exchange a bootstrap code for a session (single use, constant-time compare). */
  redeem(code: string): Session {
    const b = this.bootstrap;
    if (!b || Date.now() > b.expiresAt || !safeEqual(code, b.code)) throw new AppError('AUTH_BOOTSTRAP_EXPIRED');
    this.bootstrap = null;
    const s: Session = { id: token(), csrf: token(), lastSeen: Date.now() };
    this.sessions.set(s.id, s);
    return s;
  }

  session(id: string | undefined): Session | null {
    if (!id) return null;
    const s = this.sessions.get(id);
    if (!s) return null;
    if (Date.now() - s.lastSeen > SESSION_IDLE_MS) {
      this.sessions.delete(id);
      return null;
    }
    s.lastSeen = Date.now();
    return s;
  }

  checkBearer(header: string | undefined): boolean {
    if (!header?.startsWith('Bearer ')) return false;
    return safeEqual(header.slice(7), this.cliToken);
  }
}

/**
 * Whether a path that matched no route belongs to the API. The router percent-decodes paths before
 * matching and accepts absolute-form targets, so the scheme and host are dropped and every decoding is
 * checked, case-insensitively and with duplicate slashes collapsed; a path that still decodes further
 * after a few rounds, or cannot be decoded, counts as API (deny by default).
 */
export function isApiPath(rawPath: string): boolean {
  let p = rawPath.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]*/i, '');
  for (let round = 0; round < 4; round++) {
    if (/^\/api(?:[^a-z0-9]|$)/.test(p.replace(/\\/g, '/').replace(/\/{2,}/g, '/').toLowerCase())) return true;
    let next: string;
    try { next = decodeURIComponent(p); } catch { return true; }
    if (next === p) return false;
    p = next;
  }
  return true;
}

/** Absolute-form target (`http://host/...`) or an encoded first segment (`/%61pi/...`): no client of ours sends either. */
export function isNonCanonicalTarget(rawPath: string): boolean {
  return !rawPath.startsWith('/') || rawPath.slice(1).split('/')[0]!.includes('%');
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function sessionCookie(id: string, port: number): string {
  // loopback is plain http: no Secure / __Host-; Host/Origin checks compensate.
  return `${sessionCookieName(port)}=${id}; HttpOnly; SameSite=Strict; Path=/`;
}

export const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; connect-src 'self'; base-uri 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

/** `<data-dir>/run/api.json`, 0600 in a 0700 dir; rewritten on every start, removed on exit. */
export function writeDiscovery(dataDir: string, info: ServiceDiscovery): string {
  const dir = join(dataDir, 'run');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const path = join(dir, 'api.json');
  const tmp = `${path}.${process.pid}.tmp`;
  const fd = openSync(tmp, 'w', 0o600);
  try {
    writeSync(fd, JSON.stringify(info));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
  return path;
}

export function removeDiscovery(dataDir: string): void {
  rmSync(join(dataDir, 'run', 'api.json'), { force: true });
}
