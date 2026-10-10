import type { Store } from '@xiezhi/store';
import type { Engine, DoctorCheck } from '@xiezhi/engine';
import type { AuthState } from './security.js';
import type { Scheduler } from './scheduler.js';
import type { ErrorRing } from './errors.js';
import type { Uploads } from './uploads.js';

export const SERVER_VERSION = '0.2.0';

export interface AppContext {
  store: Store;
  engine: Engine;
  scheduler: Scheduler;
  auth: AuthState;
  errors: ErrorRing;
  startedAt: number;
  log: (level: 'info' | 'warn' | 'error', msg: string, extra?: Record<string, unknown>) => void;
  doctorCache: { at: number; checks: DoctorCheck[] } | null;
  providerTests: Map<string, { ok: boolean; at: string; detail: string }>;
  /** Replay limit / heartbeat for SSE. */
  stream: { heartbeatMs: number; replayLimit: number };
  /** Open SSE streams, closed on shutdown so the server can stop promptly. */
  openStreams: Set<() => void>;
  /** Archive upload staging (tmp/uploads, 24 h TTL). */
  uploads: Uploads;
  /** Notifications that are not audit events (e.g. `knowledge.changed`), relayed on `GET /events`. */
  notices: Set<(type: string, payload: Record<string, unknown>) => void>;
  notify: (type: string, payload: Record<string, unknown>) => void;
}
