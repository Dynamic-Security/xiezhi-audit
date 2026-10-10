// data-dir layout and config.json handling.
import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import { AppConfig, AppError, check, defaultAppConfig, upgradeConfig } from '@xiezhi/contracts';

export interface DataDirPaths {
  root: string;
  config: string;
  db: string;
  lock: string;
  snapshots: string;
  indexes: string;
  artifacts: string;
  knowledgeGlobal: string;
  projects: string;
  logs: string;
  tmp: string;
  agent: string;
  /** Per-URL bare caches of remote Git sources. */
  gitCache: string;
  /** Connector packs: `<data-dir>/connectors/<pack>/`, plain files (shareable with Git). */
  connectorPacks: string;
  /** Saved transcripts of audit sessions that may continue after a pause or restart. */
  sessions: string;
}

export function resolveDataDir(explicit?: string): string {
  return resolve(explicit ?? process.env.XIEZHI_AUDIT_DATA_DIR ?? join(homedir(), '.xiezhi-code-audit'));
}

export function dataDirPaths(root: string): DataDirPaths {
  return {
    root,
    config: join(root, 'config.json'),
    db: join(root, 'db.sqlite'),
    lock: join(root, 'writer.lock'),
    snapshots: join(root, 'snapshots'),
    indexes: join(root, 'indexes'),
    artifacts: join(root, 'artifacts'),
    knowledgeGlobal: join(root, 'knowledge', 'global'),
    projects: join(root, 'projects'),
    logs: join(root, 'logs'),
    tmp: join(root, 'tmp'),
    agent: join(root, 'tmp', 'pi-agent'),
    gitCache: join(root, 'cache', 'git'),
    connectorPacks: join(root, 'connectors'),
    sessions: join(root, 'sessions'),
  };
}

export function initDataDir(root: string): DataDirPaths {
  const p = dataDirPaths(root);
  const created = !existsSync(root);
  mkdirSync(root, { recursive: true, mode: 0o700 });
  if (created) chmodSync(root, 0o700);
  for (const dir of [p.snapshots, p.indexes, p.artifacts, join(p.artifacts, '.tmp'), p.knowledgeGlobal, p.projects, p.logs, p.tmp, p.agent, p.gitCache, p.connectorPacks, p.sessions]) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  if (!existsSync(p.config)) writeConfig(p.config, defaultAppConfig());
  return p;
}

/** Atomic 0600 write: temp file → fsync → rename. */
export function writeConfig(path: string, cfg: AppConfig): void {
  const r = check(AppConfig, cfg);
  if (!r.ok) throw new AppError('CONFIG_INVALID', r.issues.map((i) => `${i.path} ${i.message}`).join('; '));
  const tmp = `${path}.${process.pid}.tmp`;
  const fd = openSync(tmp, 'w', 0o600);
  try {
    writeSync(fd, JSON.stringify(cfg, null, 2) + '\n');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

export interface LoadedConfig { config: AppConfig; warnings: string[] }

export function readConfig(path: string): LoadedConfig {
  const warnings: string[] = [];
  const st = statSync(path);
  if ((st.mode & 0o077) !== 0) {
    try {
      chmodSync(path, 0o600);
      warnings.push('config.json permissions were too broad and have been tightened to 0600');
    } catch {
      throw new AppError('CONFIG_INVALID', 'config.json permissions are too broad and could not be tightened');
    }
  }
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new AppError('CONFIG_INVALID', 'config.json is not owned by the current user');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new AppError('CONFIG_INVALID', 'config.json is not valid JSON');
  }
  // the light / chat model keys become stage models (before defaults fill an empty `stageModels`).
  const merged = { ...defaultAppConfig(), ...upgradeConfig((parsed ?? {}) as Record<string, unknown>) };
  const r = check(AppConfig, merged);
  if (!r.ok) throw new AppError('CONFIG_INVALID', r.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; '));
  return { config: r.value, warnings };
}
