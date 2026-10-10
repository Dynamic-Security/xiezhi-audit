// Knowledge management on disk: read and edit skills of either layer with content-
// hash concurrency, atomic writes, per-layer `_settings.json` overrides, the annotated listing shown in
// the UI, and regeneration of generated case-library indexes. Files are the only source of truth
//: nothing here is cached in the database.
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { basename, dirname, join } from 'node:path';
import { sha256Hex, VULN_CATEGORIES, type SkillCategory } from '@xiezhi/contracts';
import { parse as parseYaml } from 'yaml';
import {
  MAX_SKILL_DIR_BYTES, MAX_SKILL_DIR_FILES, MAX_SKILL_FILE_BYTES, NAME_RE, scanLayer, splitFrontmatter, validateSkillText,
  type LayerScan, type LayerSettings, type Skill,
} from './skills.js';

export type Layer = 'global' | 'project';

/** Why a write was refused; the API maps these to closed error codes. */
export class KnowledgeError extends Error {
  constructor(
    readonly kind: 'not_found' | 'invalid' | 'conflict' | 'exists' | 'bad_path',
    message: string,
    readonly detail: { errors?: string[]; current?: { sha256: string | null; text: string | null } } = {},
  ) {
    super(message);
  }
}

// ---- files ----------------------------------------------------------------------------------------------

export function fileSha(path: string): string | null {
  try { return sha256Hex(readFileSync(path)); } catch { return null; }
}

/** Temporary file + rename in the same directory; the temp name is hidden from discovery. */
export function atomicWrite(path: string, data: string | Buffer): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(4).toString('hex')}.tmp`);
  writeFileSync(tmp, data);
  try {
    renameSync(tmp, path);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw e;
  }
}

const SUBFILE_EXT = /\.(md|txt|java|kt|go|js|ts|py|php|cs|xml|ya?ml|json|sql|properties|gradle|proto)$/i;

/** Relative path of a skill sub-file: no traversal, no hidden segments, a text extension. */
export function normalizeSubPath(rel: string): string {
  const segs = rel.replace(/\\/g, '/').split('/').filter(Boolean);
  if (!segs.length || segs.some((s) => s === '.' || s === '..' || s.startsWith('.') || s.startsWith('_'))) throw new KnowledgeError('bad_path', `invalid file path "${rel}"`);
  const out = segs.join('/');
  if (out === 'SKILL.md') throw new KnowledgeError('bad_path', 'SKILL.md is the entry file; edit it through the skill itself');
  if (!SUBFILE_EXT.test(out)) throw new KnowledgeError('bad_path', `unsupported file type "${out}"`);
  return out;
}

function assertName(name: string): void {
  if (!NAME_RE.test(name)) throw new KnowledgeError('bad_path', 'name must match ^[a-z0-9][a-z0-9-]{1,63}$');
}

// ---- reading --------------------------------------------------------------------------------------------

export interface SkillFileInfo { path: string; size: number; sha256: string }

export interface SkillDetail {
  name: string;
  layer: Layer;
  form: 'file' | 'dir';
  valid: boolean;
  errors: string[];
  warnings: string[];
  category: SkillCategory | null;
  description: string | null;
  load: string | null;
  verified: boolean | null;
  source: string | null;
  /** Aggregate hash of all files; null when invalid. */
  sha256: string | null;
  entryFile: string;
  entryText: string;
  entrySha256: string;
  files: SkillFileInfo[];
  updatedAt: number;
}

function locate(dir: string, name: string): { form: 'file' | 'dir'; entry: string; root: string } | null {
  const file = join(dir, `${name}.md`);
  const folder = join(dir, name);
  const hasDir = existsSync(join(folder, 'SKILL.md'));
  if (existsSync(file) && !hasDir) return { form: 'file', entry: file, root: dir };
  if (hasDir && !existsSync(file)) return { form: 'dir', entry: join(folder, 'SKILL.md'), root: folder };
  if (hasDir) return { form: 'dir', entry: join(folder, 'SKILL.md'), root: folder };
  return null;
}

function walkFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (d: string, prefix: string) => {
    for (const n of readdirSync(d).sort()) {
      if (n.startsWith('.') || n.startsWith('_')) continue;
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p, `${prefix}${n}/`);
      else out.push(`${prefix}${n}`);
    }
  };
  walk(root, '');
  return out;
}

export function loadLabel(load: Skill['load']): string {
  return load.mode === 'phase' ? `phase:${load.phases.join(',')}` : load.mode;
}

export function readSkill(dir: string, layer: Layer, name: string): SkillDetail | null {
  assertName(name);
  const loc = locate(dir, name);
  if (!loc) return null;
  const scan = scanLayer(dir, layer);
  const skill = scan.skills.find((s) => s.name === name);
  const invalid = scan.invalid.find((i) => i.path === loc.entry || i.path === join(dir, name) || i.path === join(dir, `${name}.md`));
  const rels = loc.form === 'dir' ? walkFiles(loc.root) : [`${name}.md`];
  const files = rels.map((rel) => {
    const p = loc.form === 'dir' ? join(loc.root, ...rel.split('/')) : loc.entry;
    return { path: rel, size: statSync(p).size, sha256: fileSha(p)! };
  });
  const updatedAt = Math.max(...rels.map((rel) => statSync(loc.form === 'dir' ? join(loc.root, ...rel.split('/')) : loc.entry).mtimeMs));
  const entryText = readFileSync(loc.entry, 'utf8');
  return {
    name, layer, form: loc.form, valid: !!skill,
    errors: skill ? [] : invalid?.errors ?? ['invalid skill'],
    warnings: skill?.warnings ?? [],
    category: skill?.category ?? null, description: skill?.description ?? null, load: skill ? loadLabel(skill.load) : null,
    verified: skill?.verified ?? null, source: skill?.source ?? null,
    sha256: skill?.sha256 ?? null,
    entryFile: loc.form === 'dir' ? 'SKILL.md' : `${name}.md`, entryText, entrySha256: sha256Hex(entryText),
    files, updatedAt,
  };
}

export function readSkillFile(dir: string, name: string, rel: string): { text: string; sha256: string } {
  assertName(name);
  const loc = locate(dir, name);
  if (!loc || loc.form !== 'dir') throw new KnowledgeError('not_found', `skill ${name} has no sub-files`);
  const p = join(loc.root, ...normalizeSubPath(rel).split('/'));
  if (!existsSync(p)) throw new KnowledgeError('not_found', `file ${rel}`);
  const text = readFileSync(p, 'utf8');
  return { text, sha256: sha256Hex(text) };
}

// ---- writing --------------------------------------------------------------------------------------------

function checkBase(path: string, base: string | null): void {
  const current = fileSha(path);
  if (current !== base) throw new KnowledgeError('conflict', 'changed on disk', { current: { sha256: current, text: current ? readFileSync(path, 'utf8') : null } });
}

/**
 * Create (base = null) or replace the entry file of a skill. The new text must be a valid skill; an
 * existing skill keeps its form (single file or directory).
 */
export function writeSkillEntry(dir: string, layer: Layer, name: string, text: string, base: string | null, opts: { form?: 'file' | 'dir' } = {}): SkillDetail {
  assertName(name);
  const loc = locate(dir, name);
  if (!loc && base !== null) throw new KnowledgeError('not_found', `skill ${name}`);
  if (loc && base === null) throw new KnowledgeError('exists', `skill ${name} already exists`);
  const form = loc?.form ?? opts.form ?? 'file';
  const v = validateSkillText(text, layer, name, form);
  if (v.errors.length) throw new KnowledgeError('invalid', 'invalid skill', { errors: v.errors });
  const entry = loc?.entry ?? (form === 'dir' ? join(dir, name, 'SKILL.md') : join(dir, `${name}.md`));
  if (loc) checkBase(entry, base);
  atomicWrite(entry, text);
  return readSkill(dir, layer, name)!;
}

/** Create or replace a sub-file; a single-file skill becomes a directory skill on its first sub-file. */
export function writeSkillFile(dir: string, layer: Layer, name: string, rel: string, text: string, base: string | null): SkillDetail {
  assertName(name);
  const path = normalizeSubPath(rel);
  let loc = locate(dir, name);
  if (!loc) throw new KnowledgeError('not_found', `skill ${name}`);
  if (Buffer.byteLength(text) > MAX_SKILL_FILE_BYTES) throw new KnowledgeError('invalid', 'file too large', { errors: [`${path} exceeds 256 KB`] });
  if (loc.form === 'file') {
    if (base !== null) throw new KnowledgeError('conflict', 'file does not exist', { current: { sha256: null, text: null } });
    const folder = join(dir, name);
    mkdirSync(folder, { recursive: true });
    renameSync(loc.entry, join(folder, 'SKILL.md'));
    loc = { form: 'dir', entry: join(folder, 'SKILL.md'), root: folder };
  }
  const target = join(loc.root, ...path.split('/'));
  checkBase(target, base);
  const others = walkFiles(loc.root).filter((f) => f !== path);
  const size = others.reduce((n, f) => n + statSync(join(loc.root, ...f.split('/'))).size, 0) + Buffer.byteLength(text);
  if (others.length + 1 > MAX_SKILL_DIR_FILES || size > MAX_SKILL_DIR_BYTES) throw new KnowledgeError('invalid', 'skill too large', { errors: ['a skill directory holds at most 200 files and 2 MB'] });
  atomicWrite(target, text);
  return readSkill(dir, layer, name)!;
}

export function deleteSkillFile(dir: string, layer: Layer, name: string, rel: string, base: string): SkillDetail {
  assertName(name);
  const path = normalizeSubPath(rel);
  const loc = locate(dir, name);
  if (!loc || loc.form !== 'dir') throw new KnowledgeError('not_found', `skill ${name}`);
  const target = join(loc.root, ...path.split('/'));
  if (!existsSync(target)) throw new KnowledgeError('not_found', `file ${rel}`);
  checkBase(target, base);
  unlinkSync(target);
  return readSkill(dir, layer, name)!;
}

/** Delete a whole skill; `base` is the entry file hash the user saw. */
export function deleteSkill(dir: string, name: string, base: string): void {
  assertName(name);
  const loc = locate(dir, name);
  if (!loc) throw new KnowledgeError('not_found', `skill ${name}`);
  checkBase(loc.entry, base);
  if (loc.form === 'dir') rmSync(loc.root, { recursive: true, force: true });
  else unlinkSync(loc.entry);
}

// ---- overrides --------------------------------------------------------------------------

export function readSettings(dir: string): LayerSettings {
  try {
    const s = JSON.parse(readFileSync(join(dir, '_settings.json'), 'utf8')) as Partial<LayerSettings>;
    return { disabled: s.disabled ?? [], disabled_categories: s.disabled_categories ?? [] };
  } catch {
    return { disabled: [], disabled_categories: [] };
  }
}

/** Disable or restore a skill name (or a whole category) in one layer's `_settings.json`. */
export function setOverride(dir: string, target: { name: string } | { category: SkillCategory }, disabled: boolean): LayerSettings {
  const s = readSettings(dir);
  const key = 'name' in target ? 'disabled' : 'disabled_categories';
  const value = 'name' in target ? target.name : target.category;
  const set = new Set(s[key]);
  if (disabled) set.add(value); else set.delete(value);
  const next = { ...s, [key]: [...set].sort() };
  atomicWrite(join(dir, '_settings.json'), `${JSON.stringify(next, null, 2)}\n`);
  return next;
}

// ---- annotated listing ----------------------------------------------------------------------------------

export interface KnowledgeItem {
  name: string;
  layer: Layer;
  valid: boolean;
  errors: string[];
  warnings: string[];
  category: SkillCategory | null;
  description: string | null;
  load: string | null;
  verified: boolean | null;
  /** Relative to the layer directory. */
  path: string;
  updatedAt: number;
  /** Not effective for this view: offline globally, disabled by name or by category in the project. */
  disabled: boolean;
  disabledBy: ('global' | 'project_name' | 'project_category')[];
  /** Project skill with the same name as a global one. */
  overridesGlobal: boolean;
  /** Projects whose layer has a skill of the same name (global items only). */
  overriddenBy: string[];
}

function mtimeOf(s: Skill): number {
  const root = s.dir ?? dirname(s.entry);
  return Math.max(...Object.keys(s.files).map((rel) => statSync(join(root, ...rel.split('/'))).mtimeMs));
}

function items(scan: LayerScan, layer: Layer, dir: string): KnowledgeItem[] {
  const valid = scan.skills.map((s): KnowledgeItem => ({
    name: s.name, layer, valid: true, errors: [], warnings: s.warnings ?? [], category: s.category, description: s.description,
    load: loadLabel(s.load), verified: s.verified ?? null,
    path: (s.dir ? `${s.name}/SKILL.md` : `${s.name}.md`), updatedAt: mtimeOf(s),
    disabled: false, disabledBy: [], overridesGlobal: false, overriddenBy: [],
  }));
  const invalid = scan.invalid.filter((i) => !i.path.endsWith('_settings.json')).map((i): KnowledgeItem => {
    const rel = i.path.slice(dir.length + 1);
    const name = rel.split('/')[0]!.replace(/\.md$/, '');
    let updatedAt = 0;
    try { updatedAt = statSync(i.path).mtimeMs; } catch { /* conflicting pair: no single file */ }
    return {
      name, layer, valid: false, errors: i.errors, warnings: [], category: null, description: null, load: null, verified: null,
      path: rel, updatedAt, disabled: false, disabledBy: [], overridesGlobal: false, overriddenBy: [],
    };
  });
  return [...valid, ...invalid];
}

/**
 * Listing for the knowledge pages (`GET /knowledge`). The global view marks offline skills
 * and the projects overriding them; a project view lists the project layer and every global skill with
 * what hides it in this project.
 */
export function listKnowledge(globalDir: string, projectDirs: Map<string, string>, view: { projectId?: string }): KnowledgeItem[] {
  const g = scanLayer(globalDir, 'global');
  const gItems = items(g, 'global', globalDir);
  for (const it of gItems) {
    if (g.settings.disabled.includes(it.name)) { it.disabled = true; it.disabledBy.push('global'); }
  }
  if (!view.projectId) {
    for (const [pid, dir] of projectDirs) {
      const names = new Set(scanLayer(dir, 'project').skills.map((s) => s.name));
      for (const it of gItems) if (names.has(it.name)) it.overriddenBy.push(pid);
    }
    return gItems.sort(byName);
  }
  const dir = projectDirs.get(view.projectId);
  const p = dir ? scanLayer(dir, 'project') : { skills: [], invalid: [], settings: { disabled: [], disabled_categories: [] } };
  const pItems = dir ? items(p, 'project', dir) : [];
  const pNames = new Set(p.skills.map((s) => s.name));
  const gNames = new Set(g.skills.map((s) => s.name));
  const hide = (it: KnowledgeItem) => {
    if (p.settings.disabled.includes(it.name)) { it.disabled = true; it.disabledBy.push('project_name'); }
    if (it.category && p.settings.disabled_categories.includes(it.category)) { it.disabled = true; it.disabledBy.push('project_category'); }
  };
  for (const it of pItems) { it.overridesGlobal = it.valid && gNames.has(it.name); hide(it); }
  for (const it of gItems) {
    if (pNames.has(it.name)) it.overriddenBy.push(view.projectId);
    hide(it);
  }
  return [...pItems, ...gItems].sort(byName);
}

function byName(a: KnowledgeItem, b: KnowledgeItem): number {
  return a.name.localeCompare(b.name) || (a.layer === b.layer ? 0 : a.layer === 'project' ? -1 : 1);
}

// ---- case-library index -------------------------------------------------------------------

export const INDEX_BEGIN = '<!-- BEGIN GENERATED INDEX: 以下内容由程序生成，请勿手改 -->';
export const INDEX_END = '<!-- END GENERATED INDEX -->';
const INDEX_WARN_LINES = 200;

const CLASS_LABELS: Record<string, string> = {
  sqli: 'SQL 注入', nosqli: 'NoSQL 注入', cmdi: '命令注入', code_injection: '代码注入', expression_injection: '表达式注入', ssti: '模板注入',
  ssrf: 'SSRF', path_traversal: '路径穿越', file_upload: '文件上传', deserialization: '反序列化', xxe: 'XXE', xss: 'XSS',
  open_redirect: '开放重定向', csrf: 'CSRF', cors: 'CORS 配置', authn: '认证', authz_object: '越权（IDOR）', authz_function: '越权（功能级）',
  business_logic: '业务逻辑', race_condition: '竞态条件', crypto_weak: '弱加密', hardcoded_secret: '硬编码密钥', info_leak: '信息泄露',
  ldapi: 'LDAP 注入', log_injection: '日志注入', dos: '拒绝服务', other: '其他',
};
/** Aliases accepted in case files (the case template uses `idor`). */
const CLASS_ALIASES: Record<string, string> = { idor: 'authz_object', sql_injection: 'sqli', command_injection: 'cmdi', rce: 'code_injection' };

export interface CaseIndexResult { skill: string; written: boolean; lines: number; invalid: string[]; warning?: string }

/** Generated index body for the case files of one directory skill. */
export function caseIndexBody(root: string): { body: string; lines: number; invalid: string[] } {
  const sections = new Map<string, string[]>();
  const invalid: string[] = [];
  for (const rel of walkFiles(root).filter((f) => f.endsWith('.md') && f !== 'SKILL.md')) {
    const { meta, error } = splitFrontmatter(readFileSync(join(root, ...rel.split('/')), 'utf8'));
    const m = meta ?? {};
    const raw = String(m.vuln_class ?? '');
    const cls = CLASS_ALIASES[raw] ?? raw;
    const reason = error ?? (!m.description ? 'missing description' : !(VULN_CATEGORIES as readonly string[]).includes(cls) ? `unknown vuln_class "${raw}"` : null);
    if (reason) {
      invalid.push(rel);
      sections.set('invalid', [...(sections.get('invalid') ?? []), `- \`${rel}\` — （无效：${reason}）`]);
      continue;
    }
    const applies = m.applies_when ? `。适用：${String(m.applies_when).replace(/\s+/g, ' ')}` : '';
    sections.set(cls, [...(sections.get(cls) ?? []), `- \`${rel}\` — ${String(m.description).replace(/\s+/g, ' ')}${applies}`]);
  }
  const out: string[] = [];
  for (const cls of [...VULN_CATEGORIES, 'invalid']) {
    const lines = sections.get(cls);
    if (!lines) continue;
    out.push(`## ${cls === 'invalid' ? '无效案例' : CLASS_LABELS[cls] ?? cls}`, ...lines.sort(), '');
  }
  return { body: out.join('\n'), lines: out.length, invalid };
}

/**
 * Rewrite the generated part of every directory-form vuln_case skill that carries the markers. Only the
 * text between the markers changes; identical bytes are not written (no watcher loop); a concurrent edit
 * of SKILL.md wins and the regeneration is skipped until the next change.
 */
export function regenerateCaseIndexes(dir: string, layer: Layer): CaseIndexResult[] {
  const results: CaseIndexResult[] = [];
  for (const s of scanLayer(dir, layer).skills) {
    if (s.category !== 'vuln_case' || !s.dir) continue;
    const before = readFileSync(s.entry, 'utf8');
    const b = before.indexOf(INDEX_BEGIN);
    const e = before.indexOf(INDEX_END);
    if (b < 0 || e < b) continue;
    const idx = caseIndexBody(s.dir);
    const next = `${before.slice(0, b + INDEX_BEGIN.length)}\n${idx.body}${idx.body ? '\n' : ''}${before.slice(e)}`;
    const r: CaseIndexResult = { skill: s.name, written: false, lines: idx.lines, invalid: idx.invalid };
    if (idx.lines > INDEX_WARN_LINES) r.warning = `index has ${idx.lines} lines; consider splitting the library by category (e.g. ${s.name}-authz)`;
    if (next !== before && fileSha(s.entry) === sha256Hex(before)) {
      atomicWrite(s.entry, next);
      r.written = true;
    }
    results.push(r);
  }
  return results;
}

/** Parsed frontmatter of a case file, for drafts and previews. */
export function caseMeta(text: string): Record<string, unknown> | null {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return null;
  try { return (parseYaml(m[1]!) ?? {}) as Record<string, unknown>; } catch { return null; }
}
