// Knowledge drafts: every AI-produced or imported piece of knowledge lands in
// `<layer>/.drafts/<id>/draft.json` first — invisible to discovery and never loaded by an audit — and is
// written into the layer only when the user approves it. This module owns storage, the deterministic
// checks (schema, same name, character 3-gram similarity) and approval; AI organizing, injection
// detection and the contradiction judgement live in the engine.
import { existsSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { VULN_CATEGORIES } from '@xiezhi/contracts';
import { scanLayer, splitFrontmatter, validateSkillText, type Skill } from './skills.js';
import {
  INDEX_BEGIN, INDEX_END, KnowledgeError, atomicWrite, fileSha, readSkill, regenerateCaseIndexes, writeSkillEntry, writeSkillFile, type Layer,
} from './manage.js';

export const DRAFT_KINDS = ['skill', 'case'] as const;
export const DRAFT_STATUSES = ['organizing', 'ready', 'failed', 'approved', 'rejected'] as const;
export const DRAFT_SOURCES = ['manual', 'text', 'upload', 'question', 'connector', 'hunt_basis', 'vulnerability', 'move_to_global', 'conversation'] as const;
export type DraftStatus = (typeof DRAFT_STATUSES)[number];
export type DraftSourceKind = (typeof DRAFT_SOURCES)[number];

/** Rejected and approved drafts are kept this long, then removed. */
export const DRAFT_RETENTION_MS = 30 * 24 * 3600_000;
export const SIMILARITY_THRESHOLD = 0.5;
export const SIMILAR_MAX = 5;
/** Default case library of a project: shown next to the global `vuln-cases`. */
export const PROJECT_CASE_LIBRARY = 'vuln-cases-project';
export const GLOBAL_CASE_LIBRARY = 'vuln-cases';

export interface DraftSource { kind: DraftSourceKind; ref: string | null; label: string }
export interface SimilarItem { layer: Layer; name: string; file: string | null; score: number }
export interface ConflictItem { layer: Layer; name: string; file: string | null; points: string[]; suggestion: 'merge' | 'replace' | 'keep_both'; merged: string | null }
export interface InjectionHint { signal: string; line: number; excerpt: string }

export interface DraftChecks {
  errors: string[];
  warnings: string[];
  injection: InjectionHint[];
  /** A skill (or case file) of the same name already exists in the target layer. */
  sameName: { layer: Layer; name: string; file: string | null } | null;
  /** Same name in the global layer while the draft targets a project: approving overrides it. */
  overridesGlobal: boolean;
  similar: SimilarItem[];
  conflicts: ConflictItem[];
}

export interface Draft {
  id: string;
  layer: Layer;
  projectId: string | null;
  status: DraftStatus;
  revision: number;
  /** `skill`: a whole skill entry file; `case`: one case file of a case library. */
  kind: 'skill' | 'case';
  name: string | null;
  library: string | null;
  text: string;
  /** Raw input kept for re-organizing (capped). */
  input: string;
  source: DraftSource;
  checks: DraftChecks;
  model: string | null;
  tokens: number;
  error: string | null;
  /** Move to global: the project skill this draft came from. */
  moveFrom: { projectId: string; name: string } | null;
  /** Category suggested to the organizing model (e.g. a question answer → business / architecture). */
  categoryHint?: string | null;
  createdAt: number;
  updatedAt: number;
  decidedAt: number | null;
}

export const EMPTY_CHECKS: DraftChecks = { errors: [], warnings: [], injection: [], sameName: null, overridesGlobal: false, similar: [], conflicts: [] };

// ---- storage ----------------------------------------------------------------------------------------------

const draftFile = (layerDir: string, id: string) => join(layerDir, '.drafts', id, 'draft.json');

export function saveDraft(layerDir: string, d: Draft): Draft {
  if (!/^kdr_[0-9A-Z]{26}$/.test(d.id)) throw new KnowledgeError('bad_path', 'invalid draft id');
  atomicWrite(draftFile(layerDir, d.id), `${JSON.stringify(d, null, 1)}\n`);
  return d;
}

export function readDraft(layerDir: string, id: string): Draft | null {
  if (!/^kdr_[0-9A-Z]{26}$/.test(id)) return null;
  try { return JSON.parse(readFileSync(draftFile(layerDir, id), 'utf8')) as Draft; } catch { return null; }
}

export function listDrafts(layerDir: string): Draft[] {
  const dir = join(layerDir, '.drafts');
  if (!existsSync(dir)) return [];
  return readdirSync(dir).map((id) => readDraft(layerDir, id)).filter((d): d is Draft => !!d).sort((a, b) => b.createdAt - a.createdAt);
}

/** Remove decided drafts older than the retention (startup and hourly). */
export function sweepDrafts(layerDir: string, now = Date.now()): number {
  let n = 0;
  for (const d of listDrafts(layerDir)) {
    if ((d.status === 'rejected' || d.status === 'approved') && d.decidedAt && now - d.decidedAt > DRAFT_RETENTION_MS) {
      rmSync(join(layerDir, '.drafts', d.id), { recursive: true, force: true });
      n++;
    }
  }
  return n;
}

/** A service restart interrupts organizing: those drafts fail with a clear reason. */
export function failInterruptedDrafts(layerDir: string): number {
  let n = 0;
  for (const d of listDrafts(layerDir)) {
    if (d.status !== 'organizing') continue;
    saveDraft(layerDir, { ...d, status: 'failed', error: 'interrupted: the service stopped while organizing', updatedAt: Date.now() });
    n++;
  }
  return n;
}

// ---- deterministic checks -----------------------------------------------------------------------

function grams(text: string): Set<string> {
  const t = text.toLowerCase().replace(/[\s\p{P}\p{S}]+/gu, '');
  const out = new Set<string>();
  for (let i = 0; i + 3 <= t.length; i++) out.add(t.slice(i, i + 3));
  return out;
}

export function jaccard(a: string, b: string): number {
  const x = grams(a);
  const y = grams(b);
  if (!x.size || !y.size) return 0;
  let inter = 0;
  for (const g of x) if (y.has(g)) inter++;
  return inter / (x.size + y.size - inter);
}

/** Description + headings: the part that says what a skill is about (“description 与正文标题”). */
function signature(description: string, body: string): string {
  const headings = body.split('\n').filter((l) => /^#{1,6}\s/.test(l)).map((l) => l.replace(/^#+\s*/, '')).join(' ');
  return `${description} ${headings}`;
}

function caseFiles(lib: Skill): { file: string; description: string; body: string }[] {
  if (!lib.dir) return [];
  return Object.keys(lib.files).filter((f) => f.endsWith('.md') && f !== 'SKILL.md').map((file) => {
    const { meta, body } = splitFrontmatter(readFileSync(join(lib.dir!, ...file.split('/')), 'utf8'));
    return { file, description: String(meta?.description ?? ''), body };
  });
}

export function validateCaseText(text: string): string[] {
  const { meta, error } = splitFrontmatter(text);
  const errors: string[] = [];
  if (error) errors.push(error);
  const m = meta ?? {};
  if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(String(m.name ?? ''))) errors.push('name must match ^[a-z0-9][a-z0-9-]{1,63}$');
  const d = String(m.description ?? '');
  if (d.length < 4 || d.length > 400 || /[\r\n<>]/.test(d)) errors.push('description must be 4–400 characters without newlines or angle brackets');
  const cls = String(m.vuln_class ?? '');
  if (!(VULN_CATEGORIES as readonly string[]).includes(cls) && cls !== 'idor') errors.push(`vuln_class must be one of the vulnerability categories (got "${cls}")`);
  if (Buffer.byteLength(text) > 256 * 1024) errors.push('case file exceeds 256 KB');
  return errors;
}

/**
 * Schema, same name and similarity against both layers. For a project draft the global layer is also
 * compared (a project skill with a global name overrides it).
 */
export function staticChecks(dirs: { global: string; project: string | null }, d: Pick<Draft, 'layer' | 'kind' | 'name' | 'library' | 'text'>): Omit<DraftChecks, 'injection' | 'conflicts'> {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!d.name) errors.push('name is required');
  let description = '';
  let body = d.text;
  if (d.kind === 'skill') {
    if (d.name) {
      const v = validateSkillText(d.text, d.layer, d.name, 'file');
      errors.push(...v.errors);
      warnings.push(...v.warnings);
      description = v.meta?.description ?? '';
      body = v.body;
    }
  } else {
    errors.push(...validateCaseText(d.text));
    const { meta, body: b } = splitFrontmatter(d.text);
    description = String(meta?.description ?? '');
    body = b;
    if (meta?.name && d.name && meta.name !== d.name) errors.push(`name "${String(meta.name)}" must equal the case file name "${d.name}"`);
  }
  const layers: [Layer, string][] = [['global', dirs.global], ...(dirs.project ? [['project', dirs.project] as [Layer, string]] : [])];
  const scans = layers.map(([layer, dir]) => ({ layer, scan: scanLayer(dir, layer) }));
  let sameName: DraftChecks['sameName'] = null;
  let overridesGlobal = false;
  const similar: SimilarItem[] = [];
  const sig = signature(description, body);
  for (const { layer, scan } of scans) {
    for (const s of scan.skills) {
      if (d.kind === 'skill') {
        if (d.name === s.name && layer === d.layer) sameName = { layer, name: s.name, file: null };
        if (d.name === s.name && layer === 'global' && d.layer === 'project') overridesGlobal = true;
        const score = jaccard(sig, signature(s.description, s.body));
        if (score >= SIMILARITY_THRESHOLD && !(d.name === s.name && layer === d.layer)) similar.push({ layer, name: s.name, file: null, score: Math.round(score * 100) / 100 });
      } else if (s.category === 'vuln_case' && s.dir) {
        for (const c of caseFiles(s)) {
          if (layer === d.layer && s.name === d.library && c.file === `${d.name}.md`) sameName = { layer, name: s.name, file: c.file };
          const score = jaccard(sig, signature(c.description, c.body));
          if (score >= SIMILARITY_THRESHOLD && !(layer === d.layer && s.name === d.library && c.file === `${d.name}.md`)) similar.push({ layer, name: s.name, file: c.file, score: Math.round(score * 100) / 100 });
        }
      }
    }
  }
  similar.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  return { errors, warnings, sameName, overridesGlobal, similar: similar.slice(0, SIMILAR_MAX) };
}

// ---- approval ---------------------------------------------------------------------------------------------

function libraryText(name: string, layer: Layer): string {
  return `---\nname: ${name}\ndescription: ${layer === 'project' ? '本项目的历史漏洞与误报先例。' : '历史漏洞与同类案例库。'}遇到同类可疑模式、需要参考先例判断成立与不成立条件时加载，再按索引读取具体案例。\ncategory: vuln_case\nscope: ${layer}\n---\n# ${layer === 'project' ? '项目漏洞案例库' : '漏洞案例库'}\n\n每个案例是本目录下的一个子文件；从漏洞详情“沉淀为案例”生成草稿，审核启用后索引自动更新。\n\n${INDEX_BEGIN}\n${INDEX_END}\n`;
}

export interface ApproveOptions {
  /** Replace an existing skill / case file of the same name. */
  replace?: boolean;
}

/**
 * Enable a draft (“审核后启用”): validate again, write atomically into the layer, rebuild the
 * case index for case drafts. Same name without `replace` is refused.
 */
export function approveDraft(dirs: { global: string; project: string | null }, d: Draft, opts: ApproveOptions = {}): { name: string; file: string | null } {
  if (d.status !== 'ready') throw new KnowledgeError('invalid', `draft is ${d.status}`, { errors: [`draft is ${d.status}`] });
  const layerDir = d.layer === 'global' ? dirs.global : dirs.project!;
  const checks = staticChecks(dirs, d);
  if (checks.errors.length) throw new KnowledgeError('invalid', 'invalid draft', { errors: checks.errors });
  if (checks.sameName && !opts.replace) throw new KnowledgeError('exists', `${checks.sameName.file ? `${checks.sameName.name}/${checks.sameName.file}` : checks.sameName.name} already exists`);
  if (d.kind === 'skill') {
    const existing = readSkill(layerDir, d.layer, d.name!);
    writeSkillEntry(layerDir, d.layer, d.name!, d.text, existing ? existing.entrySha256 : null);
    return { name: d.name!, file: null };
  }
  const library = d.library ?? (d.layer === 'project' ? PROJECT_CASE_LIBRARY : GLOBAL_CASE_LIBRARY);
  if (!readSkill(layerDir, d.layer, library)) writeSkillEntry(layerDir, d.layer, library, libraryText(library, d.layer), null, { form: 'dir' });
  const file = `${d.name}.md`;
  const current = fileSha(join(layerDir, library, file));
  writeSkillFile(layerDir, d.layer, library, file, d.text, current);
  regenerateCaseIndexes(layerDir, d.layer);
  return { name: library, file };
}

// ---- move to global: private information --------------------------------------------------------

export interface PrivateHint { kind: 'ip' | 'domain' | 'url' | 'email' | 'ticket' | 'term'; text: string; line: number }

const PUBLIC_DOMAINS = /(^|\.)(example\.(com|org|net)|github\.com|gitlab\.com|owasp\.org|cwe\.mitre\.org|mitre\.org|nvd\.nist\.gov|spring\.io|golang\.org|go\.dev|apache\.org|oracle\.com|java\.com|mozilla\.org|w3\.org|ietf\.org|python\.org|pypi\.org|djangoproject\.com|php\.net|laravel\.com|symfony\.com|nodejs\.org|npmjs\.com|kotlinlang\.org|ktor\.io|microsoft\.com|nuget\.org)$/i;

/**
 * Deterministic scan for project-private details before a project skill is proposed for the global layer:
 * IPs, non-public domains and URLs, e-mails, ticket keys, and the project's own names (project, repositories).
 */
export function privateInfoHints(text: string, terms: string[] = []): PrivateHint[] {
  const out: PrivateHint[] = [];
  const seen = new Set<string>();
  const lines = text.split('\n');
  const add = (kind: PrivateHint['kind'], t: string, line: number) => {
    const key = `${kind}:${t.toLowerCase()}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, text: t, line });
  };
  lines.forEach((l, i) => {
    const n = i + 1;
    for (const m of l.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) if (!/^(0\.0\.0\.0|127\.0\.0\.1)$/.test(m[0])) add('ip', m[0], n);
    for (const m of l.matchAll(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g)) add('email', m[0], n);
    for (const m of l.matchAll(/https?:\/\/[^\s)'"<>`]+/g)) {
      try { if (!PUBLIC_DOMAINS.test(new URL(m[0]).hostname)) add('url', m[0], n); } catch { /* not a URL */ }
    }
    for (const m of l.matchAll(/\b(?:[a-z0-9-]+\.)+(?:internal|corp|local|lan|intra|intranet|private|cn|com|net|io)\b/gi)) {
      if (!PUBLIC_DOMAINS.test(m[0]) && !/\.(java|go|md|ts|js|py|php|cs|kt|xml|yml|yaml|json)$/i.test(m[0]) && /\./.test(m[0]) && !/^\d/.test(m[0])) add('domain', m[0], n);
    }
    for (const m of l.matchAll(/\b[A-Z][A-Z0-9]{1,9}-\d{1,7}\b/g)) if (!/^(CWE|CVE|GHSA|RFC|ISO|UTF)-/.test(m[0])) add('ticket', m[0], n);
    for (const t of terms) if (t.length >= 3 && l.toLowerCase().includes(t.toLowerCase())) add('term', t, n);
  });
  return out;
}

// ---- composing text from an organized submission ------------------------------------------------------------

function yamlLine(v: unknown): string {
  return JSON.stringify(v);
}

/**
 * Deterministic frontmatter + body for a skill. `source` / `verified` come from the pipeline (required for
 * business / architecture); the model never decides them.
 */
export function composeSkillText(s: {
  name: string; description: string; category: string; layer: Layer; load?: string | undefined;
  appliesTo?: { scenes?: string[] | undefined; languages?: string[] | undefined; frameworks?: string[] | undefined; vulnClasses?: string[] | undefined; repoRoles?: string[] | undefined } | undefined;
  cwe?: string[] | undefined; tags?: string[] | undefined; source?: string | undefined; verified?: boolean | undefined; body: string;
}): string {
  const fact = s.category === 'business' || s.category === 'architecture';
  const lines = ['---', `name: ${s.name}`, `description: ${yamlLine(s.description.replace(/[\r\n<>]+/g, ' ').trim())}`, `category: ${s.category}`, `scope: ${s.layer}`];
  if (s.load && s.load !== 'on_demand') lines.push(`load: ${yamlLine(s.load)}`);
  const at = s.appliesTo ?? {};
  const dims: [string, string[] | undefined][] = [['scenes', at.scenes], ['languages', at.languages], ['frameworks', at.frameworks], ['vuln_classes', at.vulnClasses], ['repo_roles', at.repoRoles]];
  if (dims.some(([, v]) => v?.length)) {
    lines.push('applies_to:');
    for (const [k, v] of dims) if (v?.length) lines.push(`  ${k}: ${yamlLine(v)}`);
  }
  if (s.cwe?.length) lines.push(`cwe: ${yamlLine(s.cwe)}`);
  if (s.tags?.length) lines.push(`tags: ${yamlLine(s.tags)}`);
  if (fact || s.source) lines.push(`source: ${yamlLine(s.source ?? 'user:')}`);
  if (fact) lines.push(`verified: ${s.verified === true}`);
  lines.push('---');
  return `${lines.join('\n')}\n${s.body.trim()}\n`;
}

/** Case file in the case template's layout. */
export function composeCaseText(c: {
  name: string; description: string; vulnClass: string; cwe?: string[] | undefined; languages?: string[] | undefined; frameworks?: string[] | undefined;
  appliesWhen: string; source?: string | undefined; pattern: string; codeTraits: string; holdsIf: string; notHoldsIf: string; fix: string; whenToUse: string;
}): string {
  const lines = ['---', `name: ${c.name}`, `description: ${yamlLine(c.description.replace(/[\r\n<>]+/g, ' ').trim())}`, `vuln_class: ${c.vulnClass}`];
  if (c.cwe?.length) lines.push(`cwe: ${yamlLine(c.cwe)}`);
  if (c.languages?.length) lines.push(`languages: ${yamlLine(c.languages)}`);
  if (c.frameworks?.length) lines.push(`frameworks: ${yamlLine(c.frameworks)}`);
  lines.push(`applies_when: ${yamlLine(c.appliesWhen.replace(/\s+/g, ' ').trim())}`);
  if (c.source) lines.push(`source: ${yamlLine(c.source)}`);
  lines.push('---');
  const sec = (h: string, t: string) => `## ${h}\n\n${t.trim()}\n`;
  return `${lines.join('\n')}\n${[sec('漏洞模式', c.pattern), sec('代码特征', c.codeTraits), sec('成立条件', c.holdsIf), sec('不成立条件', c.notHoldsIf), sec('修复方式', c.fix), sec('何时参考', c.whenToUse)].join('\n')}`;
}
