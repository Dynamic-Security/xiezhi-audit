// Unified outbound HTTP for connectors: resolve DNS first, check every address,
// connect to the checked address only (no DNS rebinding), https only unless the configured host is on a
// private network, no redirects, size and time limits. Link-local (cloud metadata) is always refused;
// loopback / private addresses are allowed only for the host the user configured.
import { lookup as dnsLookup } from 'node:dns/promises';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP } from 'node:net';

export class OutboundError extends Error {
  constructor(readonly code: 'blocked_address' | 'scheme' | 'dns' | 'timeout' | 'too_large' | 'redirect' | 'network' | 'aborted', message: string) {
    super(message);
    this.name = 'OutboundError';
  }
}

export type AddressClass = 'public' | 'loopback' | 'private' | 'link_local' | 'unspecified' | 'multicast' | 'broadcast' | 'reserved';

function v4(parts: number[]): AddressClass {
  const [a, b] = parts as [number, number];
  if (a === 0) return 'unspecified';
  if (a === 127) return 'loopback';
  if (a === 169 && b === 254) return 'link_local';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127)) return 'private';
  if (a >= 224 && a <= 239) return 'multicast';
  if (parts.every((p) => p === 255)) return 'broadcast';
  if (a >= 240) return 'reserved';
  return 'public';
}

/** Classify an IP literal; IPv4-mapped IPv6 is judged by its IPv4 address. */
export function classifyAddress(ip: string): AddressClass {
  if (isIP(ip) === 4) return v4(ip.split('.').map(Number));
  const lower = ip.toLowerCase();
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped) return v4(mapped[1]!.split('.').map(Number));
  if (lower === '::1') return 'loopback';
  if (lower === '::') return 'unspecified';
  if (/^fe[89ab]/.test(lower)) return 'link_local';
  if (/^f[cd]/.test(lower)) return 'private';
  if (/^ff/.test(lower)) return 'multicast';
  return 'public';
}

export interface OutboundPolicy {
  /** Hosts the user configured for this connector; they may resolve to loopback / private addresses. */
  configuredHosts: string[];
}

/**
 * Resolve and check a host. Link-local, unspecified, multicast, broadcast and reserved addresses are always
 * refused; loopback / private only for a configured host. Returns the address to connect to.
 */
export async function resolveChecked(host: string, policy: OutboundPolicy): Promise<{ address: string; family: 4 | 6; internal: boolean }> {
  const bare = host.replace(/^\[|\]$/g, '');
  let addrs: { address: string; family: number }[];
  if (isIP(bare)) addrs = [{ address: bare, family: isIP(bare) }];
  else {
    try { addrs = await dnsLookup(bare, { all: true, verbatim: true }); } catch (e) { throw new OutboundError('dns', `cannot resolve ${bare}: ${(e as Error).message}`); }
  }
  if (!addrs.length) throw new OutboundError('dns', `no address for ${bare}`);
  const configured = policy.configuredHosts.some((h) => h.toLowerCase() === bare.toLowerCase());
  for (const a of addrs) {
    const c = classifyAddress(a.address);
    if (c === 'public') continue;
    if ((c === 'loopback' || c === 'private') && configured) continue;
    throw new OutboundError('blocked_address', `${bare} resolves to a ${c.replace('_', '-')} address (${a.address}); refused`);
  }
  const first = addrs[0]!;
  const internal = addrs.every((a) => classifyAddress(a.address) !== 'public');
  return { address: first.address, family: first.family === 6 ? 6 : 4, internal };
}

export interface OutboundRequest {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers?: Record<string, string>;
  body?: string;
  policy: OutboundPolicy;
  connectTimeoutMs?: number;
  timeoutMs?: number;
  maxBytes?: number;
  signal?: AbortSignal;
}

export interface OutboundResponse {
  status: number;
  headers: Record<string, string>;
  /** Raw chunks as they arrive (SSE); the total is still capped by `maxBytes`. */
  chunks: AsyncIterable<Buffer>;
  text(): Promise<string>;
}

/** One request to a checked, pinned address. Redirects are not followed. */
export async function outbound(req: OutboundRequest): Promise<OutboundResponse> {
  let url: URL;
  try { url = new URL(req.url); } catch { throw new OutboundError('scheme', 'invalid URL'); }
  if (url.username || url.password) throw new OutboundError('scheme', 'credentials in URLs are not allowed');
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new OutboundError('scheme', `scheme ${url.protocol} is not allowed`);
  const target = await resolveChecked(url.hostname, req.policy);
  // http only towards internal addresses.
  if (url.protocol === 'http:' && !target.internal) throw new OutboundError('scheme', 'http is only allowed for hosts on a private network; use https');
  const maxBytes = req.maxBytes ?? 4 * 1024 * 1024;
  const make = url.protocol === 'https:' ? httpsRequest : httpRequest;
  return new Promise<OutboundResponse>((resolve, reject) => {
    const r = make({
      protocol: url.protocol, hostname: url.hostname, port: url.port || undefined, path: `${url.pathname}${url.search}`, method: req.method,
      headers: { ...(req.body !== undefined ? { 'content-length': String(Buffer.byteLength(req.body)) } : {}), ...req.headers },
      servername: isIP(url.hostname.replace(/^\[|\]$/g, '')) ? undefined : url.hostname,
      // Pin the connection to the address that was checked.
      lookup: (_h: string, _o: unknown, cb: (err: Error | null, address: string | { address: string; family: number }[], family?: number) => void) => {
        if ((_o as { all?: boolean } | undefined)?.all) cb(null, [{ address: target.address, family: target.family }]);
        else cb(null, target.address, target.family);
      },
      timeout: req.connectTimeoutMs ?? 5000,
    } as never, (res: IncomingMessage) => {
      if ((res.statusCode ?? 0) >= 300 && (res.statusCode ?? 0) < 400) {
        res.resume();
        reject(new OutboundError('redirect', `redirect to ${res.headers.location ?? '(none)'} is not followed`));
        return;
      }
      let total = 0;
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) if (typeof v === 'string') headers[k.toLowerCase()] = v; else if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(', ');
      async function* chunks(): AsyncIterable<Buffer> {
        for await (const c of res) {
          const b = c as Buffer;
          total += b.length;
          if (total > maxBytes) { res.destroy(); throw new OutboundError('too_large', `response exceeds ${maxBytes} bytes`); }
          yield b;
        }
      }
      const it = chunks();
      resolve({
        status: res.statusCode ?? 0, headers, chunks: it,
        async text() {
          const parts: Buffer[] = [];
          for await (const c of it) parts.push(c);
          return Buffer.concat(parts).toString('utf8');
        },
      });
    });
    const overall = setTimeout(() => r.destroy(new OutboundError('timeout', `request exceeded ${req.timeoutMs ?? 30_000} ms`)), req.timeoutMs ?? 30_000);
    r.on('close', () => clearTimeout(overall));
    r.on('timeout', () => r.destroy(new OutboundError('timeout', 'connect timeout')));
    r.on('error', (e) => reject(e instanceof OutboundError ? e : new OutboundError('network', e.message)));
    if (req.signal) {
      if (req.signal.aborted) r.destroy(new OutboundError('aborted', 'aborted'));
      req.signal.addEventListener('abort', () => r.destroy(new OutboundError('aborted', 'aborted')), { once: true });
    }
    if (req.body !== undefined) r.write(req.body);
    r.end();
  });
}
