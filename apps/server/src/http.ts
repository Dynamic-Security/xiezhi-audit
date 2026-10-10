// Request helpers: schema validation, optimistic concurrency (If-Match), idempotency keys, cursor
// pagination.
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppError, canonicalJson, check, sha256Hex, type Page } from '@xiezhi/contracts';
import type { TSchema, Static } from 'typebox';
import { findIdempotencyRecord, saveIdempotencyRecord, type Store } from '@xiezhi/store';

export function parseBody<S extends TSchema>(schema: S, body: unknown): Static<S> {
  const r = check(schema, body ?? {});
  if (!r.ok) throw new AppError('COMMON_VALIDATION', r.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; '), { issues: r.issues.slice(0, 10) });
  return r.value;
}

/** Expected revision from `If-Match: W/"r<n>"` or body.revision. */
export function expectedRevision(req: FastifyRequest, body?: { revision?: unknown }): number {
  const h = req.headers['if-match'];
  if (typeof h === 'string') {
    const m = /^(?:W\/)?"r(\d+)"$/.exec(h.trim());
    if (!m) throw new AppError('COMMON_VALIDATION', 'bad If-Match');
    return Number(m[1]);
  }
  if (body && typeof body.revision === 'number') return body.revision;
  throw new AppError('COMMON_PRECONDITION_REQUIRED');
}

export function etag(reply: FastifyReply, revision: number | string): void {
  reply.header('ETag', `W/"r${revision}"`);
}

const IDEMPOTENCY_TTL_MS = 24 * 3600_000;

/**
 * Idempotent POST: same key + route + body → stored response; same key, different
 * body → 422. Only successful responses are stored.
 */
export async function idempotent<T>(store: Store, req: FastifyRequest, reply: FastifyReply, route: string, fn: () => Promise<{ status: number; body: T }>): Promise<T> {
  const key = req.headers['idempotency-key'];
  if (typeof key !== 'string' || !key) {
    const r = await fn();
    reply.code(r.status);
    return r.body;
  }
  if (key.length > 128) throw new AppError('COMMON_VALIDATION', 'Idempotency-Key too long');
  const hash = sha256Hex(canonicalJson(req.body ?? {}));
  const prev = findIdempotencyRecord(store, key, route);
  if (prev) {
    if (prev.body_hash !== hash) throw new AppError('COMMON_IDEMPOTENCY_KEY_REUSED');
    reply.code(prev.status);
    reply.header('Idempotent-Replayed', 'true');
    return JSON.parse(prev.response) as T;
  }
  const r = await fn();
  saveIdempotencyRecord(store, key, route, { bodyHash: hash, status: r.status, response: r.body, ttlMs: IDEMPOTENCY_TTL_MS });
  reply.code(r.status);
  return r.body;
}

export function limitOf(q: { limit?: string }, def = 50): number {
  const n = Number(q.limit ?? def);
  if (!Number.isInteger(n) || n < 1) throw new AppError('COMMON_VALIDATION', 'limit');
  return Math.min(n, 200);
}

/** Opaque cursor = base64url(offset). Lists here are small enough for offset paging. */
export function paginate<T>(items: T[], q: { limit?: string; cursor?: string }): Page<T> {
  const limit = limitOf(q);
  let offset = 0;
  if (q.cursor) {
    offset = Number(Buffer.from(q.cursor, 'base64url').toString('utf8'));
    if (!Number.isInteger(offset) || offset < 0) throw new AppError('COMMON_VALIDATION', 'cursor');
  }
  const page = items.slice(offset, offset + limit);
  const next = offset + limit < items.length ? Buffer.from(String(offset + limit)).toString('base64url') : null;
  return { items: page, nextCursor: next, totalEstimate: items.length };
}

/** Multi-value query parameter (`?a=x&a=y`) as an array. */
export function multi(v: unknown): string[] {
  if (v === undefined) return [];
  return (Array.isArray(v) ? v : [v]).map(String).filter(Boolean);
}
