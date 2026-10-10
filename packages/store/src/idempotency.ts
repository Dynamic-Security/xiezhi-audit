// Idempotency records of write requests: a response is kept per (key, route) until it
// expires, so a retried request gets the same answer.
import type { Store } from './store.js';

export interface IdempotencyRecord { body_hash: string; status: number; response: string }

/** The stored response for a key on a route; expired records are removed first. */
export function findIdempotencyRecord(store: Store, key: string, route: string): IdempotencyRecord | undefined {
  store.db.run('DELETE FROM idempotency_record WHERE expires_at < ?', Date.now());
  return store.get<IdempotencyRecord>('SELECT body_hash, status, response FROM idempotency_record WHERE key = ? AND route = ?', key, route);
}

export function saveIdempotencyRecord(store: Store, key: string, route: string, record: { bodyHash: string; status: number; response: unknown; ttlMs: number }): void {
  store.db.run('INSERT OR REPLACE INTO idempotency_record(key, route, body_hash, status, response, expires_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)',
    key, route, record.bodyHash, record.status, JSON.stringify(record.response ?? null), Date.now() + record.ttlMs, Date.now(), Date.now());
}
