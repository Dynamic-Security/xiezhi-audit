// SQLite access. node:sqlite is synchronous, so every transaction body is synchronous
// and the process-wide single writer is naturally serialized.
import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { AppError } from '@xiezhi/contracts';
import { MIGRATIONS, migrationChecksum, type Migration } from './migrations.js';

export type Row = Record<string, unknown>;
export type Param = SQLInputValue;

export class Db {
  readonly raw: DatabaseSync;
  private depth = 0;

  constructor(path: string) {
    this.raw = new DatabaseSync(path);
    this.raw.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;');
  }

  get<T = Row>(sql: string, ...params: Param[]): T | undefined {
    return this.raw.prepare(sql).get(...params) as T | undefined;
  }

  all<T = Row>(sql: string, ...params: Param[]): T[] {
    return this.raw.prepare(sql).all(...params) as T[];
  }

  run(sql: string, ...params: Param[]): { changes: number } {
    const r = this.raw.prepare(sql).run(...params);
    return { changes: Number(r.changes) };
  }

  /** Run `fn` inside a transaction (nested calls use savepoints). `fn` must be synchronous. */
  tx<T>(fn: () => T): T {
    const name = `sp${this.depth}`;
    this.raw.exec(this.depth === 0 ? 'BEGIN IMMEDIATE' : `SAVEPOINT ${name}`);
    this.depth++;
    try {
      const result = fn();
      if (result instanceof Promise) throw new Error('Db.tx body must be synchronous');
      this.depth--;
      this.raw.exec(this.depth === 0 ? 'COMMIT' : `RELEASE ${name}`);
      return result;
    } catch (err) {
      this.depth--;
      this.raw.exec(this.depth === 0 ? 'ROLLBACK' : `ROLLBACK TO ${name}; RELEASE ${name}`);
      throw err;
    }
  }

  /**
   * Compare the database's applied migrations with this build's. Read-only: nothing is created.
   * Throws when the database was migrated by a newer build (versions this build does not know) or a shipped
   * migration's checksum differs; returns the migrations this build still has to apply.
   */
  schemaStatus(): { pending: Migration[] } {
    const hasTable = this.get("SELECT 1 AS x FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'");
    const rows = hasTable ? this.all<{ version: number; name: string; checksum: string }>('SELECT version, name, checksum FROM schema_migrations ORDER BY version') : [];
    const known = new Set(MIGRATIONS.map((m) => m.version));
    const newer = rows.filter((r) => !known.has(r.version));
    if (newer.length) {
      throw new AppError('CONFIG_INVALID', `数据库已被更新版本的程序升级（迁移 ${newer.map((r) => `${r.version} ${r.name}`).join('、')} 本版本不认识；本版本只到迁移 ${MIGRATIONS.length}）。请改用更新的版本，或为本版本指定另一个数据目录（--data-dir / XIEZHI_AUDIT_DATA_DIR）`, { newer: newer.map((r) => r.version), known: MIGRATIONS.length });
    }
    const applied = new Map(rows.map((r) => [r.version, r.checksum]));
    for (const m of MIGRATIONS) {
      const prev = applied.get(m.version);
      if (prev !== undefined && prev !== migrationChecksum(m) && !m.accepts?.includes(prev)) throw new Error(`migration ${m.version} (${m.name}) checksum mismatch; the database was created by a different build`);
    }
    return { pending: MIGRATIONS.filter((m) => !applied.has(m.version)) };
  }

  migrate(): number[] {
    const { pending } = this.schemaStatus();
    this.raw.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)`);
    const ran: number[] = [];
    for (const m of pending) {
      const sum = migrationChecksum(m);
      // PRAGMA foreign_keys is a no-op inside a transaction, so it is switched around it (SQLite 12-step rebuild).
      const fkBefore = m.foreignKeysOff ? this.all('PRAGMA foreign_key_check').length : 0;
      if (m.foreignKeysOff) this.raw.exec('PRAGMA foreign_keys=OFF');
      try {
        this.tx(() => {
          this.raw.exec(m.sql);
          if (m.foreignKeysOff) {
            const fkAfter = this.all('PRAGMA foreign_key_check').length;
            if (fkAfter > fkBefore) throw new Error(`migration ${m.version} (${m.name}) left ${fkAfter - fkBefore} foreign key violation(s)`);
          }
          this.run('INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?,?,?,?)', m.version, m.name, sum, Date.now());
        });
      } finally {
        if (m.foreignKeysOff) this.raw.exec('PRAGMA foreign_keys=ON');
      }
      ran.push(m.version);
    }
    return ran;
  }

  close(): void {
    this.raw.close();
  }
}

export function toJson(value: unknown): string {
  return JSON.stringify(value ?? null);
}

export function fromJson<T>(text: unknown, fallback: T): T {
  if (typeof text !== 'string') return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}
