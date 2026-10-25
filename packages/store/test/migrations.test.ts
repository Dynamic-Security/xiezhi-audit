// Shipped migrations keep their checksums; databases created by older builds (migration 1 with older
// closed-set CHECK lists, stamped with the old checksum or re-stamped by hand) open and get the current lists.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { Db, MIGRATIONS, migrationChecksum } from '@xiezhi/store';
import {
  AUDIT_ORIGINS, AUDIT_STATUSES, CARD_KINDS, CARD_STATES, CONFIDENCES, CONFIRM_STATUSES, CONVERSATION_STATUSES,
  COVERAGE_KINDS, COVERAGE_STATUSES, DECISION_SOURCES, ERROR_CLASSES, EVIDENCE_KINDS, FINDING_STATES, FINISH_REASONS,
  HANDLING_STATUSES, LIFECYCLES, MATCH_LEVELS, MESSAGE_EVENT_TYPES, MESSAGE_ROLES, MESSAGE_STATUSES, MODES,
  PENDING_KINDS, PRESENCES, QUESTION_STATUSES, REPO_ROLES, REVISION_DIMENSIONS, REVISION_STATES, ROLE_IN_AUDIT,
  SCENES, SEVERITIES, SKILL_LAYERS, SKILL_LOAD_LEVELS, SKILL_TRIGGERS, SOURCE_KINDS, STEP_KINDS, STEP_STATUSES,
  THREAT_FETCH_STATUSES, THREAT_MODEL_STATUSES, THREAT_RISK_LEVELS, THREAT_RISK_STATUSES, OBLIGATION_STATUSES, THREAT_SOURCE_KINDS,
  sha256Hex,
} from '@xiezhi/contracts';

// Every shipped migration's checksum. A failure here means a shipped migration's SQL changed (for instance a contracts
// closed set was edited and leaked into it): existing databases would refuse to open. Add a migration instead.
const PINNED: Record<number, string> = {
  1: '9703400070e5fa8ceed192f37be00fe109a9a4e458b09114968390f3612f87b7', // m1_core
  2: '81291e60028dc7ccc67047bd143ba5125d19e546ad2d5071629214e7926e3e07', // m2_api
  3: 'ffeeea5473bcbfba7aa4448f40420c497d67b97d85c6ef1b30bc48d217d0a581', // m3_incremental
  4: '7257ccafb3e5af2a72fa514f0021bcda71ff2acfc33ce53d16dd3c3a38e8741b', // m4_sources
  5: 'e0cb9575930fbfa77d2510bb8af9e9128913e999fcfc7d0e611d57302fc9a457', // m4_analysis
  6: 'c484d84f4d3fcf6fc951cb7231d99897861798e359d20404d25afa4debce9112', // m4_topology
  7: '2dbd1371e579b3cf1e5832df985d93bbe856d6edac5b881ad8d6a397463358c5', // m5_risk_hunt
  8: '58827b2cfc7bae8ef47ef449316eec6aeaeed7839bf3c21a9398562d74d2e3bb', // m5_hunt_delta_changed
  9: 'e733dcbf1ae351920256928ef8f225cf688807406f642653d42a49a2a26835df', // m5_hunt_precheck
  10: '184946ef26bcf25660fd541e18f1ec2ba3182d423120cbd1e85f7441944241fc', // m6_connectors
  11: 'd0e48bd71dcb2e0bef6db4292b42c9eb05488106637f88524f38218cd6c4796b', // m6_architecture_import
  12: 'c473eb91e4c704ae235243d23a0204fba9856267c55ee198f8773e9500dae497', // m6_authoritative_connectors
  13: '984fe030cdb6937767d3ac429b159748ae2c1eb332e0d959d1280f4e11e23e65', // m7_conversations
  14: '3530de8f673aff130a4be66b338005f913240095aaf023752269207286e55c84', // m7_work_items
  15: '3b2036a7b054f08dfa68b09a353cb13027664e9d11de97bfe05a022dcd019ea4', // m8_audit_conversation
  16: 'f8c9d4db83e8b3f2dfc0df006847ff10e6220e98402986c0801e6b3281e9d1cb', // m8_conversation_pin
  17: 'b4d4eedc14c01fa5fff214e064941965f414266a064ab249bee50710aeaefe89', // m9_review_duration
  18: '4278c3767ea31bdadea6ae167cade0d32595cc4075c63920e9e585d1615b2a36', // m9_hypotheses
  19: '03bef6fe37c98c05db6e5b40d0fe114f2e966a9947f4a3a1ded114d24f943108', // m10_ai_report
  20: '8ddc6d86c674c420b0e15e2def14b082ec3a65b055666e2e89984a26aa3efd8a', // m11_auditable_override
  21: 'a6174101acecdc5d062a994e8873c7d40d4e1dae34248850253f84510889ad72', // m10_threat_hypotheses
  22: 'e5a5f7c1eb361a866e2b215b7ad9be85d4a0110f20e00aadf64805b9975c6c33', // m12_hypothesis_votes
  23: '3d58008e3c3051e6b771facd15258a18b2a662351b2b5c2b8311110c473c0a48', // m12_explore_uncertain
  24: 'e78bd1168614cc64db785ab880600f4fc153b05fbbee32247e5f2468b0020bd3', // m10_connector_writes
  25: 'cec514bd5939200698dbefb9dac1fa9c239a13d3c8cad7708a9388143a7bae54', // m10_connector_tools_open
  26: 'b4954ec84a4a9cba9824afb809c4c4bac7d72694ddfcfa94ca6e0935f451159f', // m13_closed_set_checks
  27: 'fb1df6481cee1f7b087a8c77591d4eefa98777bf6856c5273029d91351a92036', // m12_quota_estimates_write_replay
  28: '8fe2dfdb21ecc4f91d76805bb5eec6ee21b3b75d96a4e125c64d5c9dae168d41', // m10_coverage_detail
  29: 'ac5d592f473fd2db12520fe0bc31e89d6ac6ad280b0fe0c602a1b5d01559af44', // m12_confirm_override
  30: '8e2d5ab65024843a3cd5ec69d98006b763508b1942d1a83c41557d705be9b9d8', // m15_threat_models
  31: '9b3bd715761cf1e30789619320c9e3a04dd1ee815d084dc8244d9e9accb38191', // m15_threat_model_sync
  32: 'a2b1c29aacf11de9442975f2d2fb3683e36db891c20a8f53b7ae1b6ac6c60f76', // m15_audit_threat_models
  33: '7c48307d67da6569056e0fe993104be1817c183fa8a3d8a544f833feb89161b3', // m18_obligations
  34: 'dbc32b8129115df6d3763cdff4d805529b283f7cdc791e5b3783d4058264f4ef', // m18_facts
  35: 'f6dd24e8c388848db0f942e74e77162cb02bddf9f5c86a61e0538e9eea6056be', // m18_internal_trust
  36: '7b7434adecfde50ea2f94e8d971e55b7761d5f0cc51e9e13f6c28a0fc6363ba4', // m18_egress
  37: 'f8d4697f54ad8a5a16dac4746c0c7c95c16887faecb38cb8645114ac388ce488', // m18_project_rules
  38: '06aa125303ebbaff4525a449ec719f948db4507f5ba12e0fd2bf83b8afebb5e2', // m18_verification_cases
  39: '5e0759ed898cebb18c3056e0887d97f26bf25eba649102f7ea8161d68898f258', // m18_fix_suggestions
  40: 'bb4bfe3d0d2a17851a25cf628db91ec6fc6de830905679f0dbef68b13555c1c1', // m18_question_options
  41: '639c764eb367d7564117e55a169da08f02fbf5cc039b48e0dbd0721e51a05472', // m18_model_switches
  42: '596132716a4780cec95716dd1f2246c34370e15d6df93952f375d55865a44d18', // m18_message_attachments
};

// Columns whose CHECK list comes from a contracts closed set, after all migrations.
const CLOSED_SET_COLUMNS: [table: string, column: string, values: readonly string[]][] = [
  ['repository', 'source_kind', SOURCE_KINDS], ['repository', 'role', REPO_ROLES],
  ['audit', 'scene', SCENES], ['audit', 'mode', MODES], ['audit', 'status', AUDIT_STATUSES],
  ['audit', 'origin', AUDIT_ORIGINS], ['audit', 'error_class', ERROR_CLASSES],
  ['audit_repository', 'role_in_audit', ROLE_IN_AUDIT],
  ['step', 'kind', STEP_KINDS], ['step', 'status', STEP_STATUSES], ['step', 'error_class', ERROR_CLASSES],
  ['step_attempt', 'error_class', ERROR_CLASSES],
  ['question', 'status', QUESTION_STATUSES],
  ['finding', 'severity', SEVERITIES], ['finding', 'confidence', CONFIDENCES], ['finding', 'state', FINDING_STATES],
  ['vulnerability', 'severity', SEVERITIES], ['vulnerability', 'severity_original', SEVERITIES],
  ['vulnerability', 'confidence', CONFIDENCES], ['vulnerability', 'confirm_status', CONFIRM_STATUSES],
  ['vulnerability', 'handling_status', HANDLING_STATUSES], ['vulnerability', 'lifecycle', LIFECYCLES],
  ['vulnerability', 'pending_kind', PENDING_KINDS],
  ['vuln_occurrence', 'match_level', MATCH_LEVELS], ['vuln_occurrence', 'presence', PRESENCES],
  ['evidence', 'kind', EVIDENCE_KINDS],
  ['revision', 'dimension', REVISION_DIMENSIONS], ['revision', 'source', DECISION_SOURCES], ['revision', 'state', REVISION_STATES],
  ['coverage_item', 'kind', COVERAGE_KINDS], ['coverage_item', 'status', COVERAGE_STATUSES],
  ['skill_usage', 'layer', SKILL_LAYERS], ['skill_usage', 'level', SKILL_LOAD_LEVELS], ['skill_usage', 'trigger', SKILL_TRIGGERS],
  ['conversation', 'status', CONVERSATION_STATUSES],
  ['message', 'role', MESSAGE_ROLES], ['message', 'status', MESSAGE_STATUSES], ['message', 'finish_reason', FINISH_REASONS],
  ['message_event', 'type', MESSAGE_EVENT_TYPES],
  ['conversation_card', 'kind', CARD_KINDS], ['conversation_card', 'state', CARD_STATES],
  ['threat_model', 'status', THREAT_MODEL_STATUSES],
  ['threat_model_source', 'kind', THREAT_SOURCE_KINDS], ['threat_model_source', 'fetch_status', THREAT_FETCH_STATUSES],
  ['threat_risk', 'level', THREAT_RISK_LEVELS], ['threat_risk', 'status', THREAT_RISK_STATUSES],
  ['obligation', 'status', OBLIGATION_STATUSES],
];

const tmpDb = () => join(mkdtempSync(join(tmpdir(), 'xz-migr-')), 'db.sqlite');
const M1 = MIGRATIONS.find((m) => m.version === 1)!;
// Migration 1 as built by two older versions, and by the one before them.
const M1_PRE_M12_13 = M1.sql.replaceAll(",'CONTENT_FILTERED'", '');
const M1_PRE_M10_11 = M1_PRE_M12_13.replace(",'threat-model'", '');

/** A database as an older build left it: migrations up to `upTo` with migration 1's `v1Sql`, stamped `stamp`. */
function legacyDb(path: string, v1Sql: string, stamp: string, upTo: number): Db {
  const db = new Db(path);
  db.raw.exec('CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, checksum TEXT NOT NULL, applied_at INTEGER NOT NULL)');
  for (const m of MIGRATIONS.filter((x) => x.version <= upTo)) {
    db.raw.exec(m.version === 1 ? v1Sql : m.sql);
    db.run('INSERT INTO schema_migrations VALUES (?,?,?,?)', m.version, m.name, m.version === 1 ? stamp : migrationChecksum(m), 0);
  }
  return db;
}

const NOW = 1;
function seed(db: Db, n: string, kind = 'hunt', errorClass: string | null = 'PROVIDER_TRANSIENT'): void {
  db.run('INSERT OR IGNORE INTO project (id, name, created_at, updated_at) VALUES (?,?,?,?)', 'p1', 'p', NOW, NOW);
  db.run(`INSERT INTO audit (id, project_id, scene, mode, title, status, strategy_draft, strategy_sources, strategy_frozen,
    budget_initial, budget_effective, budget_consumed, origin, error_class, created_at, updated_at)
    VALUES (?, 'p1', 'full', 'single', 't', 'failed', '{}', '{}', '{"x":1}', '{}', '{}', '{}', 'cli', ?, ?, ?)`, `a${n}`, errorClass, NOW, NOW);
  db.run(`INSERT INTO step (id, audit_id, seq, kind, status, idempotency_key, error_class, created_at, updated_at)
    VALUES (?, ?, 1, ?, 'failed', 'k', ?, ?, ?)`, `s${n}`, `a${n}`, kind, errorClass, NOW, NOW);
  db.run(`INSERT INTO step_attempt (step_id, attempt, outcome, error_class, started_at, created_at, updated_at)
    VALUES (?, 1, 'failed', ?, ?, ?, ?)`, `s${n}`, errorClass, NOW, NOW, NOW);
}

const tableSql = (db: Db, name: string) => db.get<{ sql: string }>('SELECT sql FROM sqlite_master WHERE name = ?', name)?.sql;
const schemaOf = (db: Db) => db.all<{ type: string; name: string; sql: string }>(
  "SELECT type, name, sql FROM sqlite_master WHERE tbl_name IN ('audit','step','step_attempt') ORDER BY type, name");

function freshDb(): Db {
  const db = new Db(tmpDb());
  db.migrate();
  return db;
}

/** After migration 26: the new closed-set values are accepted, data and constraints are intact. */
function expectCurrent(db: Db): void {
  expect(schemaOf(db)).toEqual(schemaOf(freshDb()));
  expect(db.get<{ foreign_keys: number }>('PRAGMA foreign_keys')?.foreign_keys).toBe(1);
  expect(db.all('PRAGMA foreign_key_check')).toEqual([]);
  seed(db, 'new', 'threat-model', 'CONTENT_FILTERED');
  expect(db.get('SELECT error_class FROM step_attempt WHERE step_id = ?', 'snew')).toEqual({ error_class: 'CONTENT_FILTERED' });
  // The trigger and the cascades are back.
  expect(() => db.run("UPDATE audit SET strategy_frozen = '{}' WHERE id = 'anew'")).toThrow(/strategy_frozen is immutable/);
  db.run("DELETE FROM audit WHERE id = 'anew'");
  expect(db.get("SELECT count(*) AS n FROM step_attempt WHERE step_id = 'snew'")).toEqual({ n: 0 });
}

describe('migrations', () => {
  it('pins every shipped migration checksum', () => {
    expect(Object.fromEntries(MIGRATIONS.map((m) => [m.version, migrationChecksum(m)]))).toEqual(PINNED);
    expect(MIGRATIONS.map((m) => m.version)).toEqual(MIGRATIONS.map((_, i) => i + 1));
  });

  it('the historical migration 1 texts are the accepted checksums', () => {
    expect(M1.accepts).toEqual([sha256Hex(M1_PRE_M10_11), sha256Hex(M1_PRE_M12_13)]);
  });

  it('the final CHECK lists match the contracts closed sets', () => {
    const db = freshDb();
    for (const [table, col, values] of CLOSED_SET_COLUMNS) {
      const sql = tableSql(db, table)!;
      const m = new RegExp(`CHECK\\(${col}(?: IS NULL OR ${col})? IN \\(([^)]*)\\)\\)`).exec(sql);
      expect(m, `${table}.${col}`).not.toBeNull();
      expect(m![1]!.split(',').map((v) => v.replace(/'/g, '')), `${table}.${col}`).toEqual([...values]);
    }
  });

  it('a fresh database runs every migration once', () => {
    const path = tmpDb();
    const db = new Db(path);
    expect(db.migrate()).toEqual(MIGRATIONS.map((m) => m.version));
    db.close();
    const again = new Db(path);
    expect(again.migrate()).toEqual([]);
    expectCurrent(again);
  });

  it('(a) a database from an older version (old checksum, old CHECK) opens and accepts CONTENT_FILTERED', () => {
    const db = legacyDb(tmpDb(), M1_PRE_M12_13, sha256Hex(M1_PRE_M12_13), 25);
    seed(db, '1');
    db.run(`INSERT INTO repository (id, project_id, name, source_kind, source_uri, created_at, updated_at)
      VALUES ('r1', 'p1', 'r', 'local', '/x', ?, ?)`, NOW, NOW);
    db.run(`INSERT INTO hypothesis (id, audit_id, step_id, project_id, repository_id, category, statement, status, created_at, updated_at)
      VALUES ('h1', 'a1', 's1', 'p1', 'r1', 'sqli', 'st', 'open', ?, ?)`, NOW, NOW);
    db.run(`INSERT INTO event (audit_id, seq, type, ts, payload) VALUES ('a1', 1, 'x', ?, '{}')`, NOW);
    expect(() => seed(db, '2', 'hunt', 'CONTENT_FILTERED')).toThrow(/CHECK constraint failed/);

    expect(db.migrate()).toEqual([26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42]);
    expect(db.get("SELECT checksum FROM schema_migrations WHERE version = 1")).toEqual({ checksum: sha256Hex(M1_PRE_M12_13) });
    expect(db.get("SELECT error_class, strategy_frozen FROM audit WHERE id = 'a1'")).toEqual({ error_class: 'PROVIDER_TRANSIENT', strategy_frozen: '{"x":1}' });
    expect(db.get("SELECT count(*) AS n FROM step_attempt WHERE step_id = 's1'")).toEqual({ n: 1 });
    expect(db.get("SELECT count(*) AS n FROM event WHERE audit_id = 'a1'")).toEqual({ n: 1 });
    expect(db.get("SELECT step_id FROM hypothesis WHERE id = 'h1'")).toEqual({ step_id: 's1' });
    // Foreign keys are enforced again: the hypothesis still points at its step.
    expect(() => db.run("DELETE FROM step WHERE id = 's1'")).toThrow(/FOREIGN KEY constraint failed/);
    expectCurrent(db);
  });

  it('(a) a database from an older version with only migrations 1–2 applied opens and accepts threat-model steps', () => {
    const db = legacyDb(tmpDb(), M1_PRE_M10_11, sha256Hex(M1_PRE_M10_11), 2);
    seed(db, '1');
    expect(() => seed(db, '2', 'threat-model', null)).toThrow(/CHECK constraint failed/);
    expect(db.migrate()).toEqual(MIGRATIONS.filter((m) => m.version > 2).map((m) => m.version));
    expect(db.get("SELECT count(*) AS n FROM step_attempt WHERE step_id = 's1'")).toEqual({ n: 1 });
    expectCurrent(db);
  });

  it('(b) a database re-stamped with the current checksum but still on the old CHECK gets the new lists', () => {
    const db = legacyDb(tmpDb(), M1_PRE_M12_13, migrationChecksum(M1), 25);
    seed(db, '1');
    expect(() => seed(db, '2', 'hunt', 'CONTENT_FILTERED')).toThrow(/CHECK constraint failed/);
    expect(db.migrate()).toEqual([26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42]);
    expect(db.get("SELECT error_class FROM step WHERE id = 's1'")).toEqual({ error_class: 'PROVIDER_TRANSIENT' });
    expectCurrent(db);
  });

  it('still refuses a migration 1 checksum it does not know', () => {
    const db = legacyDb(tmpDb(), M1.sql, sha256Hex('something else'), 25);
    expect(() => db.migrate()).toThrow(/migration 1 \(m1_core\) checksum mismatch/);
  });
});
