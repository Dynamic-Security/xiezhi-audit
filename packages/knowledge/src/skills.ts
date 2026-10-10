// Skill discovery, validation, effective set and prefilter.
import { createHash } from 'node:crypto';
import { copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { canonicalJson, KNOWLEDGE_FRAMEWORKS, KNOWLEDGE_LANGUAGES, REPO_ROLES, SCENES, sha256Hex, SKILL_CATEGORIES, VULN_CATEGORIES, type Scene, type SkillCategory } from '@xiezhi/contracts';

export const MAX_SKILL_FILE_BYTES = 256 * 1024;
export const MAX_SKILL_DIR_BYTES = 2 * 1024 * 1024;
export const MAX_SKILL_DIR_FILES = 200;
export const NAME_RE = /^[a-z0-9][a-z0-9-]{1,63}$/;
const CATEGORY_ALIASES: Record<string, SkillCategory> = {
  漏洞案例: 'vuln_case', 审计方法: 'audit_method', 输出报告: 'report', 业务知识: 'business', 系统架构: 'architecture', 推送指引: 'push_guide', 安全规范: 'security_spec', 报告规范: 'report',
};
/** `threat_model`: the requirement threat-model generation session, never an audit step. */
export const PHASES = ['plan', 'profile', 'hunt', 'challenge', 'reconcile', 'verify', 'report', 'conversation', 'threat_model'] as const;
export type Phase = (typeof PHASES)[number];

export interface AppliesTo { scenes?: string[]; languages?: string[]; frameworks?: string[]; vuln_classes?: string[]; repo_roles?: string[] }

/**
 * one item of a checklist written in a skill's frontmatter (`checklist:`). The id is stable (the
 * obligation key is `<skill>:<id>`); `vuln_class` decides the check batch; `applies_to` narrows it to languages and
 * frameworks.
 */
export interface ChecklistItem { id: string; title: string; check: string; vulnClass: string; appliesTo: Pick<AppliesTo, 'languages' | 'frameworks'> }
const CHECKLIST_ID_RE = /^[a-z0-9][a-z0-9.-]{0,47}$/;
const MAX_CHECKLIST_ITEMS = 60;

/** Parse and check a frontmatter `checklist` (errors name the item). */
export function parseChecklist(raw: unknown, errors: string[]): ChecklistItem[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) { errors.push('checklist must be a list'); return []; }
  if (raw.length > MAX_CHECKLIST_ITEMS) errors.push(`checklist has more than ${MAX_CHECKLIST_ITEMS} items`);
  const out: ChecklistItem[] = [];
  const seen = new Set<string>();
  raw.forEach((x, i) => {
    const it = (x ?? {}) as Record<string, unknown>;
    const id = String(it.id ?? '');
    const at = `checklist[${i}]${id ? ` (${id})` : ''}`;
    if (!CHECKLIST_ID_RE.test(id)) errors.push(`${at}: id must match ${CHECKLIST_ID_RE.source}`);
    else if (seen.has(id)) errors.push(`${at}: id is listed twice`);
    seen.add(id);
    const title = String(it.title ?? '');
    const check = String(it.check ?? '');
    if (title.length < 2 || title.length > 120) errors.push(`${at}: title must be 2–120 characters`);
    if (check.length < 10 || check.length > 1000) errors.push(`${at}: check must be 10–1000 characters`);
    const vc = String(it.vuln_class ?? '');
    if (!(VULN_CATEGORIES as readonly string[]).includes(vc)) errors.push(`${at}: vuln_class ${vc || '(missing)'} not in ${VULN_CATEGORIES.join(' / ')}`);
    const a = (it.applies_to ?? {}) as Record<string, unknown>;
    if (typeof a !== 'object' || Array.isArray(a)) errors.push(`${at}: applies_to must be an object`);
    for (const k of Object.keys(a)) if (!['languages', 'frameworks'].includes(k)) errors.push(`${at}: applies_to.${k} is not a checklist dimension (languages / frameworks)`);
    const list = (k: 'languages' | 'frameworks') => (Array.isArray(a[k]) ? (a[k] as unknown[]).map(String) : undefined);
    out.push({ id, title, check, vulnClass: vc, appliesTo: { ...(list('languages') ? { languages: list('languages') } : {}), ...(list('frameworks') ? { frameworks: list('frameworks') } : {}) } });
  });
  return out;
}

export interface Skill {
  name: string;
  description: string;
  category: SkillCategory;
  layer: 'global' | 'project';
  load: { mode: 'on_demand' } | { mode: 'always' } | { mode: 'phase'; phases: Phase[] };
  appliesTo: AppliesTo;
  cwe: string[];
  tags: string[];
  source?: string;
  verified?: boolean;
  /** Entry file (single-file skill or SKILL.md) absolute path. */
  entry: string;
  /** Directory for directory-form skills. */
  dir: string | null;
  /** Relative path → sha256 for every file of the skill. */
  files: Record<string, string>;
  sha256: string;
  body: string;
  /** Non-fatal findings (e.g. `scope` differs from the layer). */
  warnings?: string[];
  /** push_guide only. */
  push?: PushSpec;
  /** checklist items (frontmatter `checklist`). */
  checklist?: ChecklistItem[];
}

export interface InvalidSkill { layer: 'global' | 'project'; path: string; errors: string[] }

export interface LayerScan { skills: Skill[]; invalid: InvalidSkill[]; settings: LayerSettings }
export interface LayerSettings { disabled: string[]; disabled_categories: string[] }

export function builtinSkillsDir(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'skills');
}

/** Installed built-in entries and the content hash written (`_builtin.json` in the global layer; ignored by scans). */
export const BUILTIN_RECORD = '_builtin.json';
/** Content hashes of earlier versions of each built-in entry (`skills/_history.json`, generated from git). */
export const BUILTIN_HISTORY = '_history.json';

/** sha256 of a skill entry: the file, or for a directory every file's relative path and content (sorted). */
export function skillEntryHash(path: string): string {
  const h = createHash('sha256');
  if (!statSync(path).isDirectory()) return h.update(readFileSync(path)).digest('hex');
  const files: string[] = [];
  const walk = (d: string) => { for (const n of readdirSync(d).sort()) { const f = join(d, n); if (statSync(f).isDirectory()) walk(f); else files.push(f); } };
  walk(path);
  for (const f of files) h.update(`${relative(path, f).split(sep).join('/')}\0${createHash('sha256').update(readFileSync(f)).digest('hex')}\n`);
  return h.digest('hex');
}

export interface BuiltinSync {
  /** Entries copied because the global layer did not have them. */
  installed: string[];
  /** Entries replaced by the new built-in version: the user's copy was an unmodified earlier built-in version. */
  updated: string[];
  /** Entries left alone because the user changed them; the new built-in version is not applied. */
  kept: string[];
}

function readJson<T>(path: string, fallback: T): T {
  try { return existsSync(path) ? (JSON.parse(readFileSync(path, 'utf8')) as T) : fallback; } catch { return fallback; }
}

/**
 * Bring the built-in skills of the global layer up to date. A missing entry is copied;
 * an entry whose content is still what was installed (`_builtin.json`) or an earlier built-in version
 * (`skills/_history.json`, for layers installed before the record existed) is replaced by the new version; an entry
 * the user edited is kept and reported. Deleting a built-in entry brings it back on the next start, as before.
 */
export function syncBuiltinSkills(globalDir: string, from = builtinSkillsDir()): BuiltinSync {
  const out: BuiltinSync = { installed: [], updated: [], kept: [] };
  if (!existsSync(from)) return out;
  mkdirSync(globalDir, { recursive: true });
  const recordPath = join(globalDir, BUILTIN_RECORD);
  const record = readJson<Record<string, string>>(recordPath, {});
  const history = readJson<Record<string, string[]>>(join(from, BUILTIN_HISTORY), {});
  const copy = (src: string, dst: string) => {
    if (statSync(src).isDirectory()) cpSync(src, dst, { recursive: true });
    else copyFileSync(src, dst);
  };
  for (const name of readdirSync(from).sort()) {
    if (name.startsWith('.') || name.startsWith('_')) continue;
    const src = join(from, name);
    const dst = join(globalDir, name);
    const current = skillEntryHash(src);
    if (!existsSync(dst)) {
      copy(src, dst);
      record[name] = current;
      out.installed.push(name);
      continue;
    }
    const have = skillEntryHash(dst);
    if (have === current) { record[name] = current; continue; }
    const pristine = record[name] === have || (history[name] ?? []).includes(have);
    if (!pristine) { out.kept.push(name); continue; }
    rmSync(dst, { recursive: true, force: true });
    copy(src, dst);
    record[name] = current;
    out.updated.push(name);
  }
  writeFileSync(recordPath, JSON.stringify(record, null, 1));
  return out;
}

/** Install / update the built-in skills (see `syncBuiltinSkills`); returns the entries written (installed or updated). */
export function installBuiltinSkills(globalDir: string, from = builtinSkillsDir()): string[] {
  const r = syncBuiltinSkills(globalDir, from);
  return [...r.installed, ...r.updated];
}

export function splitFrontmatter(text: string): { meta: Record<string, unknown> | null; body: string; error?: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) return { meta: null, body: text, error: 'missing frontmatter' };
  try {
    const meta = parseYaml(m[1]!) as Record<string, unknown>;
    return { meta: meta ?? {}, body: text.slice(m[0].length) };
  } catch (e) {
    return { meta: null, body: text, error: `invalid frontmatter: ${(e as Error).message}` };
  }
}

function parseLoad(v: unknown): Skill['load'] | string {
  if (v === undefined || v === 'on_demand') return { mode: 'on_demand' };
  if (v === 'always') return { mode: 'always' };
  if (typeof v === 'string' && v.startsWith('phase:')) {
    const phases = v.slice(6).split(',').map((p) => p.trim());
    const bad = phases.filter((p) => !(PHASES as readonly string[]).includes(p));
    if (bad.length) return `unknown phase ${bad.join(',')}`;
    return { mode: 'phase', phases: phases as Phase[] };
  }
  return `invalid load ${String(v)}`;
}

function listDirFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const name of readdirSync(d).sort()) {
      if (name.startsWith('.') || name.startsWith('_')) continue;
      const p = join(d, name);
      if (statSync(p).isDirectory()) walk(p);
      else out.push(p);
    }
  };
  walk(dir);
  return out;
}

/**
 * `push:` block of a push-guidance skill: the target connector write operation, whether a
 * preview must be confirmed (default: executes directly), how to read the external id / URL from the
 * result, and an optional operation used when the vulnerability was pushed before.
 */
/** `updateOperations`: several follow-up operations; on a re-push the model picks which to run, in order. */
/** `target`: what the guide pushes — a vulnerability (default) or a requirement threat model. */
export const PUSH_TARGETS = ['vulnerability', 'threat_model'] as const;
export type PushTarget = (typeof PUSH_TARGETS)[number];
export interface PushSpec { connector: string; operation: string; confirm: boolean; target: PushTarget; externalId?: string; externalUrl?: string; updateOperation?: string; updateOperations?: string[]; updateKey?: string }

export interface SkillMeta {
  push?: PushSpec;
  checklist?: ChecklistItem[];
  name: string;
  description: string;
  category: SkillCategory;
  load: Skill['load'];
  appliesTo: AppliesTo;
  cwe: string[];
  tags: string[];
  source?: string;
  verified?: boolean;
  scope?: string;
}

/**
 * Validate an entry file's text. Used both when scanning and before an edit is written,
 * so the UI can refuse an invalid save instead of leaving an invalid skill on disk.
 */
export function validateSkillText(text: string, layer: 'global' | 'project', expectedName: string, form: 'file' | 'dir'): { meta: SkillMeta | null; body: string; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (Buffer.byteLength(text) > MAX_SKILL_FILE_BYTES) errors.push(`${form === 'dir' ? 'SKILL.md' : `${expectedName}.md`} exceeds 256 KB`);
  const { meta, body, error } = splitFrontmatter(text);
  if (error) errors.push(error);
  const m = meta ?? {};
  const name = String(m.name ?? '');
  if (!NAME_RE.test(name)) errors.push('name must match ^[a-z0-9][a-z0-9-]{1,63}$');
  if (name && name !== expectedName) errors.push(`name "${name}" must equal ${form === 'dir' ? 'directory' : 'file'} name "${expectedName}"`);
  const description = String(m.description ?? '');
  if (description.length < 20 || description.length > 400) errors.push('description must be 20–400 characters');
  if (/[\r\n<>]|\]\(/.test(description)) errors.push('description must not contain newlines, links or angle brackets');
  const rawCat = String(m.category ?? '');
  const category = (CATEGORY_ALIASES[rawCat] ?? rawCat) as SkillCategory;
  if (!(SKILL_CATEGORIES as readonly string[]).includes(category)) errors.push(`invalid category ${rawCat}`);
  const load = parseLoad(m.load);
  if (typeof load === 'string') errors.push(load);
  if (category === 'business' || category === 'architecture') {
    if (!m.source) errors.push('source is required for business/architecture skills');
    if (typeof m.verified !== 'boolean') errors.push('verified is required for business/architecture skills');
  }
  // applies_to: closed sets are errors; unknown language / framework ids only warn, but say
  // what they do — the prefilter matches ids exactly, so an unknown id excludes the skill from those audits.
  const at = m.applies_to;
  if (at !== undefined && (typeof at !== 'object' || at === null || Array.isArray(at))) errors.push('applies_to must be an object');
  else if (at) {
    const a = at as Record<string, unknown>;
    for (const k of Object.keys(a)) if (!['scenes', 'languages', 'frameworks', 'vuln_classes', 'repo_roles'].includes(k)) errors.push(`applies_to.${k} is not a known dimension`);
    const list = (k: string) => (Array.isArray(a[k]) ? (a[k] as unknown[]).map(String) : a[k] === undefined ? [] : null);
    const closed: [string, readonly string[]][] = [['scenes', SCENES], ['vuln_classes', VULN_CATEGORIES], ['repo_roles', REPO_ROLES]];
    for (const [k, set] of closed) {
      const v = list(k);
      if (v === null) errors.push(`applies_to.${k} must be an array`);
      else { const bad = v.filter((x) => !set.includes(x)); if (bad.length) errors.push(`applies_to.${k}: ${bad.join(', ')} not in ${set.join(' / ')}`); }
    }
    for (const [k, known] of [['languages', KNOWLEDGE_LANGUAGES], ['frameworks', KNOWLEDGE_FRAMEWORKS]] as const) {
      const v = list(k);
      if (v === null) errors.push(`applies_to.${k} must be an array`);
      else {
        const bad = v.filter((x) => !(known as readonly string[]).includes(x.toLowerCase()));
        if (bad.length) warnings.push(`applies_to.${k}: ${bad.join(', ')} is not a known id (${known.join(', ')}); audits never match it, so the skill is left out wherever ${k} are detected`);
      }
    }
  }
  const cwe = Array.isArray(m.cwe) ? m.cwe.map(String) : [];
  if (cwe.some((c) => !/^CWE-\d+$/.test(c))) errors.push('cwe entries must look like CWE-<n>');
  let push: PushSpec | undefined;
  if (category === 'push_guide') {
    const p = (m.push ?? {}) as Record<string, unknown>;
    if (typeof p.connector !== 'string' || !p.connector) errors.push('push.connector is required for push_guide skills');
    if (typeof p.operation !== 'string' || !/^[A-Za-z_][\w.-]{0,127}$/.test(p.operation ?? '')) errors.push('push.operation is required for push_guide skills');
    if (p.confirm !== undefined && typeof p.confirm !== 'boolean') errors.push('push.confirm must be true or false');
    if (p.target !== undefined && !(PUSH_TARGETS as readonly unknown[]).includes(p.target)) errors.push(`push.target must be one of ${PUSH_TARGETS.join(', ')}`);
    if (p.update_operation !== undefined && (typeof p.update_operation !== 'string' || !/^[A-Za-z_][\w.-]{0,127}$/.test(p.update_operation))) errors.push('push.update_operation must be an operation name');
    const ups = p.update_operations;
    if (ups !== undefined && (!Array.isArray(ups) || !ups.length || ups.length > 10 || ups.some((x) => typeof x !== 'string' || !/^[A-Za-z_][\w.-]{0,127}$/.test(x)))) errors.push('push.update_operations must be a list of 1–10 operation names');
    push = {
      connector: String(p.connector ?? ''), operation: String(p.operation ?? ''), confirm: p.confirm === true, target: (p.target as PushTarget | undefined) ?? 'vulnerability',
      ...(typeof p.external_id === 'string' ? { externalId: p.external_id } : {}), ...(typeof p.external_url === 'string' ? { externalUrl: p.external_url } : {}),
      ...(typeof p.update_operation === 'string' ? { updateOperation: p.update_operation } : {}),
      ...(Array.isArray(ups) && ups.length ? { updateOperations: ups.map(String) } : {}),
      ...(typeof p.update_key === 'string' ? { updateKey: p.update_key } : {}),
    };
  }
  const checklist = parseChecklist(m.checklist, errors);
  const tags = Array.isArray(m.tags) ? m.tags.map(String) : [];
  if (tags.length > 10 || tags.some((t) => t.length > 32)) errors.push('at most 10 tags of ≤ 32 characters');
  // The directory decides the layer; a mismatch is only a warning (files are copied between layers).
  if (m.scope !== undefined && m.scope !== layer) warnings.push(`scope "${String(m.scope)}" differs from the ${layer} layer; the layer wins`);
  if (errors.length) return { meta: null, body, errors, warnings };
  return {
    meta: {
      name, description, category, load: load as Skill['load'], appliesTo: (m.applies_to ?? {}) as AppliesTo, cwe, tags, ...(push ? { push } : {}),
      ...(checklist.length ? { checklist } : {}),
      ...(m.source ? { source: String(m.source) } : {}),
      ...(typeof m.verified === 'boolean' ? { verified: m.verified } : {}),
      ...(m.scope !== undefined ? { scope: String(m.scope) } : {}),
    },
    body, errors, warnings,
  };
}

function parseSkill(layer: 'global' | 'project', entry: string, dir: string | null, expectedName: string): Skill | InvalidSkill {
  const errors: string[] = [];
  const files: Record<string, string> = {};
  let total = 0;
  const fileList = dir ? listDirFiles(dir) : [entry];
  if (fileList.length > MAX_SKILL_DIR_FILES) errors.push(`too many files (${fileList.length} > ${MAX_SKILL_DIR_FILES})`);
  for (const f of fileList) {
    const size = statSync(f).size;
    total += size;
    if (size > MAX_SKILL_FILE_BYTES && f !== entry) errors.push(`${relative(dir ?? dirname(entry), f)} exceeds 256 KB`);
    files[(dir ? relative(dir, f) : relative(dirname(entry), f)).split(sep).join('/')] = sha256Hex(readFileSync(f));
  }
  if (total > MAX_SKILL_DIR_BYTES) errors.push('skill exceeds 2 MB');
  const v = validateSkillText(readFileSync(entry, 'utf8'), layer, expectedName, dir ? 'dir' : 'file');
  errors.push(...v.errors);
  if (errors.length || !v.meta) return { layer, path: entry, errors };
  const { scope: _scope, ...meta } = v.meta;
  return {
    ...meta, layer, entry, dir, files,
    sha256: sha256Hex(canonicalJson(Object.entries(files).sort(([a], [b]) => a.localeCompare(b)))),
    body: v.body,
    ...(v.warnings.length ? { warnings: v.warnings } : {}),
  };
}

export function scanLayer(dir: string, layer: 'global' | 'project'): LayerScan {
  const result: LayerScan = { skills: [], invalid: [], settings: { disabled: [], disabled_categories: [] } };
  if (!existsSync(dir)) return result;
  const settingsFile = join(dir, '_settings.json');
  if (existsSync(settingsFile)) {
    try {
      const s = JSON.parse(readFileSync(settingsFile, 'utf8')) as Partial<LayerSettings>;
      result.settings = { disabled: s.disabled ?? [], disabled_categories: s.disabled_categories ?? [] };
    } catch {
      result.invalid.push({ layer, path: settingsFile, errors: ['invalid _settings.json'] });
    }
  }
  const entries = readdirSync(dir).filter((n) => !n.startsWith('.') && !n.startsWith('_')).sort();
  const names = new Map<string, string[]>();
  for (const n of entries) {
    const key = n.endsWith('.md') ? n.slice(0, -3) : n;
    names.set(key, [...(names.get(key) ?? []), n]);
  }
  for (const [name, variants] of names) {
    if (variants.length > 1) {
      result.invalid.push({ layer, path: join(dir, name), errors: ['both <name>.md and <name>/SKILL.md exist'] });
      continue;
    }
    const p = join(dir, variants[0]!);
    if (statSync(p).isDirectory()) {
      const entry = join(p, 'SKILL.md');
      if (!existsSync(entry)) { result.invalid.push({ layer, path: p, errors: ['missing SKILL.md'] }); continue; }
      const s = parseSkill(layer, entry, p, name);
      if ('errors' in s) result.invalid.push(s);
      else result.skills.push(s);
    } else if (p.endsWith('.md')) {
      const s = parseSkill(layer, p, null, name);
      if ('errors' in s) result.invalid.push(s);
      else result.skills.push(s);
    }
  }
  return result;
}

/** effective(project): the global and project layers combined. */
export function effectiveSkills(global: LayerScan, project: LayerScan | null): Skill[] {
  const G = global.skills.filter((s) => !global.settings.disabled.includes(s.name));
  const P = project?.skills ?? [];
  const pNames = new Set(P.map((s) => s.name));
  const merged = [...P, ...G.filter((g) => !pNames.has(g.name))];
  const ps = project?.settings ?? { disabled: [], disabled_categories: [] };
  return merged.filter((s) => !ps.disabled.includes(s.name) && !ps.disabled_categories.includes(s.category));
}

export interface TaskFacts {
  scene: Scene;
  phase: Phase;
  languages: string[];
  frameworks: string[];
  vulnClasses: string[];
  repoRoles: string[];
  include: string[];
  exclude: string[];
}

function dimOk(declared: string[] | undefined, task: string[]): { ok: boolean; hit: boolean } {
  if (!declared || declared.length === 0 || task.length === 0) return { ok: true, hit: false };
  const t = new Set(task.map((x) => x.toLowerCase()));
  const hit = declared.some((d) => t.has(String(d).toLowerCase()));
  return { ok: hit, hit };
}

export interface Selected { skill: Skill; mode: 'index' | 'body'; trigger: 'on_demand' | 'always' | 'phase' | 'user_pinned'; score: number }

const CATEGORY_RANK: Record<SkillCategory, number> = { security_spec: 4, audit_method: 4, vuln_case: 3, architecture: 2, business: 1, report: 0, push_guide: 0 };

/** Deterministic prefilter and ordering. */
export function prefilter(skills: Skill[], t: TaskFacts): Selected[] {
  const out: Selected[] = [];
  for (const s of skills) {
    if (t.exclude.includes(s.name)) continue;
    // Push guidance is for the push flow, never for audit or conversation sessions.
    if (s.category === 'push_guide') continue;
    if (t.include.includes(s.name)) { out.push({ skill: s, mode: 'body', trigger: 'user_pinned', score: 100 }); continue; }
    if (s.load.mode === 'phase' && !s.load.phases.includes(t.phase)) continue;
    const dims = [
      dimOk(s.appliesTo.scenes, [t.scene]), dimOk(s.appliesTo.languages, t.languages), dimOk(s.appliesTo.frameworks, t.frameworks),
      dimOk(s.appliesTo.vuln_classes, t.vulnClasses), dimOk(s.appliesTo.repo_roles, t.repoRoles),
    ];
    if (dims.some((d) => !d.ok)) continue;
    const hits = dims.filter((d) => d.hit).length;
    const mode = s.load.mode === 'on_demand' ? 'index' : 'body';
    const trigger = s.load.mode === 'on_demand' ? 'on_demand' : s.load.mode === 'always' ? 'always' : 'phase';
    out.push({ skill: s, mode, trigger, score: (s.layer === 'project' ? 1000 : 0) + hits * 10 + CATEGORY_RANK[s.category] });
  }
  return out.sort((a, b) => b.score - a.score || a.skill.name.localeCompare(b.skill.name));
}

export function estimateTokens(text: string): number {
  // Conservative: CJK ≈ 1 token/char, ASCII ≈ 1 token/4 chars.
  let cjk = 0;
  for (const ch of text) if (ch.charCodeAt(0) > 0x2e80) cjk++;
  return Math.ceil(cjk + (text.length - cjk) / 4);
}
