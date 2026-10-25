import { mkdtempSync, statSync, readdirSync, writeFileSync, chmodSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Db, MIGRATIONS, Store, WriterLock, migrationChecksum, readConfig } from '@xiezhi/store';
import { newId, sha256Hex } from '@xiezhi/contracts';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-store-'));

function seedAudit(s: Store): string {
  const pid = newId('project');
  s.insert('project', { id: pid, name: 'p' });
  const aid = newId('audit');
  s.insert('audit', {
    id: aid, project_id: pid, scene: 'full', mode: 'single', title: 't', status: 'planning',
    strategy_draft: {}, strategy_sources: {}, budget_initial: { tokens: 1 }, budget_effective: { tokens: 1 }, budget_consumed: { tokens: 0 }, origin: 'cli',
  });
  return aid;
}

describe('store', () => {
  it('initializes a private data-dir and migrates idempotently', () => {
    const dir = join(tmp(), 'dd');
    const s = Store.open({ dataDir: dir, role: 'test' });
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(statSync(join(dir, 'config.json')).mode & 0o777).toBe(0o600);
    s.close();
    const s2 = Store.open({ dataDir: dir, role: 'test' });
    expect(s2.all('SELECT version FROM schema_migrations')).toHaveLength(MIGRATIONS.length);
    s2.close();
  });

  it('migration 25 switches every existing connector tool on for the Agent', () => {
    const s = Store.open({ dataDir: join(tmp(), 'dd'), role: 'test' });
    const tools = [{ name: 'search', readOnlyHint: true, exposed: false }, { name: 'create', readOnlyHint: false, exposed: false }];
    s.insert('connector', { id: newId('connector'), name: 'jira', protocol: 'http', purpose: 'context', config: {}, tools });
    s.insert('connector', { id: newId('connector'), name: 'empty', protocol: 'http', purpose: 'context', config: {}, tools: [] });
    s.db.run(MIGRATIONS.find((m) => m.version === 25)!.sql.trim());
    const rows = s.all<{ name: string; tools: string }>('SELECT name, tools FROM connector ORDER BY name');
    expect(JSON.parse(rows[1]!.tools)).toEqual(tools.map((t) => ({ ...t, exposed: true })));
    expect(JSON.parse(rows[0]!.tools)).toEqual([]);
    s.close();
  });

  it('enforces a single writer and reclaims stale locks', () => {
    const dir = tmp();
    const s = Store.open({ dataDir: dir, role: 'a' });
    const s2 = Store.open({ dataDir: dir, role: 'b' }); // same pid: allowed to reclaim own lock
    s2.close();
    s.close();
    writeFileSync(join(dir, 'writer.lock'), JSON.stringify({ pid: 999999, startedAt: 0, role: 'dead' }));
    const lock = WriterLock.acquire(join(dir, 'writer.lock'), 'x');
    lock.release();
    writeFileSync(join(dir, 'writer.lock'), JSON.stringify({ pid: 1, startedAt: 0, role: 'init' }));
    expect(() => WriterLock.acquire(join(dir, 'writer.lock'), 'x')).toThrow(/LOCK_HELD/);
  });

  it('writes artifacts atomically and idempotently', () => {
    const s = Store.open({ dataDir: tmp(), role: 't' });
    const a = s.artifacts.put('hello');
    const b = s.artifacts.put('hello');
    expect(a).toBe(b);
    expect(a).toBe(sha256Hex('hello'));
    expect(s.artifacts.get(a, true).toString()).toBe('hello');
    expect(readdirSync(join(s.paths.artifacts, '.tmp'))).toHaveLength(0);
    expect(s.get('SELECT size FROM artifact WHERE sha256 = ?', a)).toEqual({ size: 5 });
    s.close();
  });

  it('allocates gapless event seq, redacts payloads, offloads large ones and notifies after commit', () => {
    const s = Store.open({ dataDir: tmp(), role: 't' });
    s.saveConfig({ ...s.config, modelProviders: [{ id: 'gw', api: 'openai-completions', baseUrl: 'http://x', apiKey: 'secret-key-abcdef', models: [] }] });
    const aid = seedAudit(s);
    const seen: number[] = [];
    s.onEvent((e) => seen.push(e.seq));
    s.tx(() => {
      s.appendEvent(aid, 'tool.called', { args: 'uses secret-key-abcdef' });
      expect(seen).toEqual([]);
      s.appendEvent(aid, 'tool.result', { big: 'x'.repeat(20_000) });
    });
    expect(seen).toEqual([1, 2]);
    expect(() => s.tx(() => { s.appendEvent(aid, 'error', {}); throw new Error('boom'); })).toThrow('boom');
    expect(seen).toEqual([1, 2]);
    const evs = s.listEvents(aid);
    expect(evs.map((e) => e.seq)).toEqual([1, 2]);
    expect(JSON.stringify(evs[0]!.payload)).not.toContain('secret-key-abcdef');
    expect(evs[1]!.payloadRef).toMatch(/^[0-9a-f]{64}$/);
    s.appendEvent(aid, 'error', {});
    expect(s.listEvents(aid, 2).map((e) => e.seq)).toEqual([3]);
    s.close();
  });

  it('enforces immutable frozen strategy and evidence-complete confirmation in the DB', () => {
    const s = Store.open({ dataDir: tmp(), role: 't' });
    const aid = seedAudit(s);
    s.update('audit', { id: aid }, { strategy_frozen: { a: 1 } });
    expect(() => s.update('audit', { id: aid }, { strategy_frozen: { a: 2 } })).toThrow(/immutable/);
    const pid = s.get<{ project_id: string }>('SELECT project_id FROM audit WHERE id=?', aid)!.project_id;
    const base = { project_id: pid, repository_id: 'r', category: 'sqli', title: 't', severity: 'high', confidence: 'high', lifecycle: 'new', detail_ref: 'x' };
    expect(() => s.insert('vulnerability', { id: 'v1', display_no: 1, confirm_status: 'confirmed', evidence_complete: 0, ...base })).toThrow(/evidence_complete/);
    s.insert('vulnerability', { id: 'v2', display_no: 2, confirm_status: 'pending', evidence_complete: 0, ...base });
    expect(() => s.update('vulnerability', { id: 'v2' }, { confirm_status: 'confirmed' })).toThrow(/evidence_complete/);
    // A human override lets a confirmation through without complete evidence.
    s.update('vulnerability', { id: 'v2' }, { confirm_status: 'confirmed', confirm_override: 1 });
    expect(s.get('SELECT confirm_status, evidence_complete, confirm_override FROM vulnerability WHERE id = ?', 'v2')).toEqual({ confirm_status: 'confirmed', evidence_complete: 0, confirm_override: 1 });
    expect(() => s.update('vulnerability', { id: 'v2' }, { lifecycle: 'bogus' })).toThrow(/CHECK/);
    s.close();
  });

  it('tightens overly broad config permissions', () => {
    const dir = tmp();
    Store.open({ dataDir: dir, role: 't' }).close();
    chmodSync(join(dir, 'config.json'), 0o644);
    const r = readConfig(join(dir, 'config.json'));
    expect(r.warnings.length).toBe(1);
    expect(statSync(join(dir, 'config.json')).mode & 0o777).toBe(0o600);
  });
});

// Several builds share one data-dir. Only the lock holder migrates; nobody opens a newer schema.
describe('schema version guard', () => {
  const applied = (path: string) => {
    const db = new Db(path);
    const hasTable = db.get("SELECT 1 AS x FROM sqlite_master WHERE name = 'schema_migrations'");
    const vs = hasTable ? db.all<{ version: number }>('SELECT version FROM schema_migrations ORDER BY version').map((r) => r.version) : [];
    db.close();
    return vs;
  };
  const openErr = (dir: string, lock: boolean): unknown => {
    try { Store.open({ dataDir: dir, role: 'test', lock }).close(); } catch (e) { return e; }
    return null;
  };

  // With no writer running, a read-only open takes the lock just long enough to migrate.
  it('opening without the writer lock migrates only when no writer is running, else refuses pending migrations', () => {
    const dir = join(tmp(), 'dd');
    const dbPath = join(dir, 'db.sqlite');
    const lockPath = join(dir, 'writer.lock');
    // Fresh data-dir, nobody holds the lock: the read-only open migrates and releases the lock again.
    expect(openErr(dir, false)).toBeNull();
    expect(applied(dbPath)).toHaveLength(MIGRATIONS.length);
    WriterLock.acquire(lockPath, 'test').release();
    // An older build's database while another process (a running service) holds the lock: refused, nothing migrated.
    const last = MIGRATIONS[MIGRATIONS.length - 1]!;
    const db = new Db(dbPath);
    db.run('DELETE FROM schema_migrations WHERE version = ?', last.version);
    db.close();
    writeFileSync(lockPath, JSON.stringify({ pid: process.ppid, startedAt: Date.now(), role: 'serve' }));
    const err = openErr(dir, false);
    expect(err).toMatchObject({ code: 'CONFIG_INVALID', detail: { pending: [last.version] } });
    expect((err as Error).message).toMatch(/持有写锁，只读命令不做升级.*xiezhi serve/);
    expect(applied(dbPath)).not.toContain(last.version);
    unlinkSync(lockPath);
    const db2 = new Db(dbPath);
    db2.run('INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?,?,?,?)', last.version, last.name, migrationChecksum(last), 0);
    db2.close();
    // Schema current: a read-only open works next to the writer (no lock taken).
    const w = Store.open({ dataDir: dir, role: 'test' });
    const ro = Store.open({ dataDir: dir, role: 'cli', lock: false });
    expect(ro.all('SELECT version FROM schema_migrations')).toHaveLength(MIGRATIONS.length);
    ro.close();
    w.close();
  });

  it('refuses a database migrated by a newer build, with or without the writer lock', () => {
    const dir = join(tmp(), 'dd');
    Store.open({ dataDir: dir, role: 'test' }).close();
    const future = MIGRATIONS.length + 1;
    const db = new Db(join(dir, 'db.sqlite'));
    db.run('INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?,?,?,?)', future, 'from_a_newer_build', 'x', 0);
    db.close();
    // Writer, read-only, writer again (the first refusal released the lock: CONFIG_INVALID, not LOCK_HELD).
    for (const lock of [true, false, true]) {
      const err = openErr(dir, lock);
      expect(err).toMatchObject({ code: 'CONFIG_INVALID', detail: { newer: [future], known: MIGRATIONS.length } });
      expect((err as Error).message).toContain(`迁移 ${future} from_a_newer_build 本版本不认识`);
    }
  });
});
