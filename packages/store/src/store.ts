// Store facade: data-dir + writer lock + SQLite + artifacts + config.
import { homedir } from 'node:os';
import {
  AppError, type AppConfig, type AuditEvent, upgradeConfig, EVENT_PAYLOAD_INLINE_LIMIT, type EventType, collectSecrets, redactDeep, type RedactOptions,
} from '@xiezhi/contracts';
import { ArtifactStore } from './artifacts.js';
import { Db, fromJson, toJson, type Param, type Row } from './db.js';
import { initDataDir, readConfig, writeConfig, type DataDirPaths } from './datadir.js';
import { WriterLock } from './lock.js';

export interface OpenOptions {
  dataDir: string;
  /** Who holds the writer lock (e.g. `cli`, `serve`). Omit `lock` only for read-only tooling like doctor. */
  role: string;
  lock?: boolean;
}

export type EventListener = (e: AuditEvent) => void;

/** The writer lock, or null while a running process holds it. */
function tryAcquire(path: string, role: string): WriterLock | null {
  try {
    return WriterLock.acquire(path, role);
  } catch (e) {
    if (e instanceof AppError && e.code === 'LOCK_HELD') return null;
    throw e;
  }
}

export class Store {
  readonly paths: DataDirPaths;
  readonly db: Db;
  readonly artifacts: ArtifactStore;
  private lock: WriterLock | null;
  private cfg: AppConfig;
  readonly configWarnings: string[];
  private listeners = new Set<EventListener>();
  private pendingEvents: AuditEvent[] = [];

  private constructor(paths: DataDirPaths, db: Db, lock: WriterLock | null, cfg: AppConfig, warnings: string[]) {
    this.paths = paths;
    this.db = db;
    this.lock = lock;
    this.cfg = cfg;
    this.configWarnings = warnings;
    this.artifacts = new ArtifactStore(paths.artifacts, db);
  }

  static open(opts: OpenOptions): Store {
    const paths = initDataDir(opts.dataDir);
    const lock = opts.lock === false ? null : WriterLock.acquire(paths.lock, opts.role);
    try {
      const { config, warnings } = readConfig(paths.config);
      const db = new Db(paths.db);
      try {
        // only the writer-lock holder migrates. Without the lock (read-only commands next to a running
        // service, possibly of another build sharing the data-dir) the schema must already be current —
        // unless no writer is running (a new data-dir, or the first command after an upgrade): then this
        // command takes the lock just long enough to migrate.
        if (lock) db.migrate();
        else {
          const { pending } = db.schemaStatus();
          if (pending.length) {
            const migrating = tryAcquire(paths.lock, `${opts.role}:migrate`);
            if (!migrating) {
              throw new AppError('CONFIG_INVALID', `数据库结构需要升级（待执行迁移 ${pending.map((m) => m.version).join('、')}），另一个进程（如正在运行的服务）持有写锁，只读命令不做升级。请待其结束或停止该服务后，用本版本启动服务（xiezhi serve）或运行 xiezhi project list 完成升级，再重试`, { pending: pending.map((m) => m.version) });
            }
            try { db.migrate(); } finally { migrating.release(); }
          }
        }
      } catch (e) {
        db.close();
        throw e;
      }
      return new Store(paths, db, lock, config, warnings);
    } catch (e) {
      lock?.release();
      throw e;
    }
  }

  close(): void {
    this.db.close();
    this.lock?.release();
    this.lock = null;
  }

  get config(): AppConfig {
    return this.cfg;
  }

  saveConfig(raw: AppConfig): void {
    const cfg = upgradeConfig(raw); // callers passing the deprecated light / chat model keys
    writeConfig(this.paths.config, cfg);
    this.cfg = cfg;
  }

  redactOptions(snapshotRoot?: string): RedactOptions {
    return { secrets: collectSecrets(this.cfg), homeDir: homedir(), dataDir: this.paths.root, snapshotRoot };
  }

  // ---- generic row helpers -------------------------------------------------

  insert(table: string, row: Record<string, unknown>): void {
    const now = Date.now();
    const full: Record<string, unknown> = { created_at: now, updated_at: now, ...row };
    const cols = Object.keys(full);
    this.db.run(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`, ...cols.map((c) => encode(full[c])));
  }

  update(table: string, where: Record<string, unknown>, patch: Record<string, unknown>): number {
    const set: Record<string, unknown> = { ...patch, updated_at: Date.now() };
    const sc = Object.keys(set);
    const wc = Object.keys(where);
    return this.db.run(
      `UPDATE ${table} SET ${sc.map((c) => `${c} = ?`).join(', ')} WHERE ${wc.map((c) => `${c} = ?`).join(' AND ')}`,
      ...sc.map((c) => encode(set[c])), ...wc.map((c) => encode(where[c])),
    ).changes;
  }

  get<T = Row>(sql: string, ...params: Param[]): T | undefined {
    return this.db.get<T>(sql, ...params);
  }

  all<T = Row>(sql: string, ...params: Param[]): T[] {
    return this.db.all<T>(sql, ...params);
  }

  tx<T>(fn: () => T): T {
    this.txDepth++;
    let result: T;
    try {
      result = this.db.tx(fn);
    } catch (e) {
      this.txDepth--;
      if (this.txDepth === 0) this.pendingEvents = [];
      throw e;
    }
    this.txDepth--;
    if (this.txDepth === 0) {
      const flush = this.pendingEvents;
      this.pendingEvents = [];
      for (const ev of flush) this.emit(ev);
    }
    return result;
  }
  private txDepth = 0;

  // ---- events ----------------------------------------------------

  /**
   * Append an event. seq = audit.last_event_seq + 1 inside the same transaction, strictly
   * monotonic without gaps. Payloads are redacted; >8KB payloads move to an artifact.
   * Listeners are notified only after the transaction commits ("commit first, push later").
   */
  appendEvent(auditId: string, type: EventType, payload: Record<string, unknown>, stepId: string | null = null): AuditEvent {
    return this.tx(() => {
      const clean = redactDeep(payload, this.redactOptions());
      let text = JSON.stringify(clean);
      let payloadRef: string | null = null;
      if (Buffer.byteLength(text) > EVENT_PAYLOAD_INLINE_LIMIT) {
        payloadRef = this.artifacts.put(text, 'application/json');
        text = JSON.stringify({ truncated: true, preview: text.slice(0, 2000) });
      }
      const row = this.db.get<{ last_event_seq: number }>(
        'UPDATE audit SET last_event_seq = last_event_seq + 1 WHERE id = ? RETURNING last_event_seq', auditId,
      );
      if (!row) throw new Error(`appendEvent: audit ${auditId} not found`);
      const ev: AuditEvent = { auditId, seq: row.last_event_seq, type, stepId, ts: Date.now(), payload: JSON.parse(text), payloadRef };
      this.db.run('INSERT INTO event(audit_id, seq, type, step_id, ts, payload, payload_ref) VALUES (?,?,?,?,?,?,?)',
        auditId, ev.seq, type, stepId, ev.ts, text, payloadRef);
      this.pendingEvents.push(ev);
      return ev;
    });
  }

  listEvents(auditId: string, afterSeq = 0, types?: EventType[]): AuditEvent[] {
    const rows = this.db.all<{ audit_id: string; seq: number; type: EventType; step_id: string | null; ts: number; payload: string; payload_ref: string | null }>(
      'SELECT * FROM event WHERE audit_id = ? AND seq > ? ORDER BY seq', auditId, afterSeq,
    );
    return rows
      .filter((r) => !types || types.includes(r.type))
      .map((r) => ({ auditId: r.audit_id, seq: r.seq, type: r.type, stepId: r.step_id, ts: r.ts, payload: fromJson(r.payload, {}), payloadRef: r.payload_ref }));
  }

  onEvent(listener: EventListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(ev: AuditEvent): void {
    for (const l of this.listeners) {
      try { l(ev); } catch { /* listener errors never affect the writer */ }
    }
  }
}

function encode(v: unknown): Param {
  if (v === undefined || v === null) return null;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'object' && !(v instanceof Uint8Array)) return toJson(v);
  return v as Param;
}
