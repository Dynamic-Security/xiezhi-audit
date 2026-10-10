// Pipeline prompts in the knowledge base (36): every text the engine and the agent send to a model is
// a catalog entry with a built-in default (read-only, shipped with the release) in one of 7 groups. The prompt groups
// may be overridden in the global layer and, on top of it, in a project layer (`<layer>/_prompts/<id>.md`); an override
// keeps the template variables and the locked tokens of the default (tool, field and tag names the engine and the
// model rely on). Tool and field descriptions and submission feedback are listed for audit only. An audit freezes the
// overrides in effect when it starts; steps render through the frozen set (`withPrompts`).
import { AsyncLocalStorage } from 'node:async_hooks';
import { existsSync, readdirSync, readFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import * as Contracts from '@xiezhi/contracts';
import { canonicalJson, sha256Hex } from '@xiezhi/contracts';
import { atomicWrite, KnowledgeError } from '../manage.js';
import { splitFrontmatter } from '../skills.js';
import { CATALOG } from './catalog/index.js';

/** The 7 groups: the first six are prompts (editable), `tool` is listed for audit only. */
export const PROMPT_GROUPS = ['role_rules', 'step_task', 'standalone', 'conversation', 'nudge', 'data_note', 'tool'] as const;
export type PromptGroup = (typeof PROMPT_GROUPS)[number];
export const PROMPT_GROUP_LABEL: Record<PromptGroup, string> = {
  role_rules: '角色与规则', step_task: '审计步骤任务', standalone: '独立会话', conversation: '对话', nudge: '运行中提醒', data_note: '数据标注说明', tool: '工具说明',
};

export interface PromptDef {
  /** Stable id, dotted (`role.hunt`, `hunt.batch.intro`). */
  id: string;
  group: PromptGroup;
  /** Short Chinese label. */
  title: string;
  /** Where the engine uses it and what the variables are. */
  description: string;
  /** The default template; `{{name}}` are variables the engine fills. */
  text: string;
  /** Why the entry cannot be overridden (tool descriptions, security boundaries); absent = editable unless group `tool`. */
  readonly?: string;
  /** Tokens an override must keep besides the automatic ones. */
  locked?: string[];
}

export type PromptLayer = 'global' | 'project';
export interface PromptOverride { id: string; text: string; layer: PromptLayer; editedFrom: string; updatedAt: string | null }

const VAR = /\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}/g;
export const PROMPT_ID_RE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;
const MAX_OVERRIDE_CHARS = 20_000;

const BY_ID = new Map<string, PromptDef>();
for (const d of CATALOG) {
  if (BY_ID.has(d.id)) throw new Error(`prompt catalog: ${d.id} is defined twice`);
  if (!PROMPT_ID_RE.test(d.id)) throw new Error(`prompt catalog: bad id ${d.id}`);
  BY_ID.set(d.id, d);
}

export function promptCatalog(): PromptDef[] { return CATALOG; }
export function promptDef(id: string): PromptDef | undefined { return BY_ID.get(id); }
export function promptEditable(d: PromptDef): boolean { return d.group !== 'tool' && !d.readonly; }
export function defaultSha(d: PromptDef): string { return sha256Hex(d.text); }

/** The variables of a template, in order of first use. */
export function templateVars(text: string): string[] {
  return [...new Set([...text.matchAll(VAR)].map((m) => m[1]!))];
}

/**
 * Tokens an override must keep: the default's variables, back-quoted spans, lowercase ASCII words (tool, field and enum
 * names — snake_case, camelCase, `pending`), `<tag>`-like markers, and the entry's own extras.
 */
export function lockedTokens(d: PromptDef): string[] {
  const t = d.text.replace(VAR, ' ');
  const found = [
    ...[...t.matchAll(/`([^`\n]{1,80})`/g)].map((m) => `\`${m[1]}\``),
    // Lowercase ASCII words in the (Chinese) prompts are tool, field and enum names: submit_findings, knowledgeRefs, pending.
    ...[...t.matchAll(/\b[a-z][a-z0-9]*(?:[_A-Z][A-Za-z0-9]*)*\b/g)].map((m) => m[0]).filter((w) => w.length >= 3),
    ...[...t.matchAll(/<\/?[a-z_]+[^>\n]{0,40}>/g)].map((m) => m[0]),
    ...(d.locked ?? []),
  ];
  return [...new Set(found)];
}

/** Problems of an override text against its default (empty = acceptable). */
export function validatePromptText(d: PromptDef, text: string): string[] {
  const issues: string[] = [];
  if (!promptEditable(d)) issues.push(`${d.id} 不能修改：${d.readonly ?? '工具说明只读'}`);
  if (!text.trim()) issues.push('内容不能为空');
  if (text.length > MAX_OVERRIDE_CHARS) issues.push(`内容超过 ${MAX_OVERRIDE_CHARS} 字`);
  const want = templateVars(d.text);
  const have = templateVars(text);
  const missing = want.filter((v) => !have.includes(v));
  const unknown = have.filter((v) => !want.includes(v));
  if (missing.length) issues.push(`缺少必需变量：${missing.map((v) => `{{${v}}}`).join('、')}`);
  if (unknown.length) issues.push(`未知变量：${unknown.map((v) => `{{${v}}}`).join('、')}（可用：${want.map((v) => `{{${v}}}`).join('、') || '无'}）`);
  const gone = lockedTokens(d).filter((tok) => !text.includes(tok));
  if (gone.length) issues.push(`缺少锁定词（引擎或模型依赖的工具、字段与标记名，必须原样保留）：${gone.join('、')}`);
  return issues;
}

/** Fill a template; a variable without a value is an engine bug. */
export function renderTemplate(id: string, text: string, vars: Record<string, string | number> = {}): string {
  return text.replace(VAR, (_, name: string) => {
    const v = vars[name];
    if (v === undefined) throw new Error(`prompt ${id}: variable {{${name}}} has no value`);
    return String(v);
  });
}

// ---- override files -----------------------------------------------------------------------------------------------

export const PROMPTS_DIR = '_prompts';
const fileOf = (layerDir: string, id: string) => join(layerDir, PROMPTS_DIR, `${id}.md`);

export interface OverrideFile { id: string; text: string; editedFrom: string; updatedAt: string | null; issues: string[] }

/** The override files of a layer, each checked against the current default (an invalid one is not applied). */
export function readPromptOverrides(layerDir: string): OverrideFile[] {
  const dir = join(layerDir, PROMPTS_DIR);
  if (!existsSync(dir)) return [];
  const out: OverrideFile[] = [];
  for (const f of readdirSync(dir).filter((n) => n.endsWith('.md') && !n.startsWith('.')).sort()) {
    const id = f.slice(0, -3);
    const raw = readFileSync(join(dir, f), 'utf8');
    const { meta, body } = splitFrontmatter(raw);
    const m = meta ?? {};
    const text = body.replace(/^\n/, '').replace(/\n$/, '');
    const d = promptDef(id);
    const issues = d ? validatePromptText(d, text) : [`没有 id 为 ${id} 的提示词`];
    out.push({ id, text, editedFrom: String(m.edited_from ?? ''), updatedAt: m.updated_at ? String(m.updated_at) : null, issues });
  }
  return out;
}

export function savePromptOverride(layerDir: string, id: string, text: string): OverrideFile {
  const d = promptDef(id);
  if (!d) throw new KnowledgeError('not_found', `prompt ${id}`);
  const issues = validatePromptText(d, text);
  if (issues.length) throw new KnowledgeError('invalid', `prompt ${id} is invalid`, { errors: issues });
  const updatedAt = new Date().toISOString();
  atomicWrite(fileOf(layerDir, id), `---\nid: ${id}\nedited_from: ${defaultSha(d)}\nupdated_at: ${updatedAt}\n---\n${text}\n`);
  return { id, text, editedFrom: defaultSha(d), updatedAt, issues: [] };
}

/** Restore the default of one entry in a layer (delete its override); false when there was none. */
export function deletePromptOverride(layerDir: string, id: string): boolean {
  const f = fileOf(layerDir, id);
  if (!existsSync(f)) return false;
  unlinkSync(f);
  return true;
}

/** Restore every default of a layer; returns the ids restored. */
export function deleteAllPromptOverrides(layerDir: string): string[] {
  return readPromptOverrides(layerDir).map((o) => o.id).filter((id) => deletePromptOverride(layerDir, id));
}

// ---- the effective set --------------------------------------------------------------------------------------------

export interface FrozenPrompts { hash: string; overrides: Record<string, { text: string; layer: PromptLayer }> }
export const DEFAULT_PROMPTS_HASH = 'default';

/** The valid overrides in effect: the project layer over the global one. */
export function resolvePromptOverrides(globalDir: string, projectDir: string | null): FrozenPrompts {
  const overrides: FrozenPrompts['overrides'] = {};
  for (const o of readPromptOverrides(globalDir)) if (!o.issues.length) overrides[o.id] = { text: o.text, layer: 'global' };
  if (projectDir) for (const o of readPromptOverrides(projectDir)) if (!o.issues.length) overrides[o.id] = { text: o.text, layer: 'project' };
  return { overrides, hash: promptsHash(overrides) };
}

export function promptsHash(overrides: FrozenPrompts['overrides']): string {
  const ids = Object.keys(overrides).sort();
  return ids.length ? sha256Hex(canonicalJson(ids.map((id) => [id, overrides[id]!.text]))).slice(0, 16) : DEFAULT_PROMPTS_HASH;
}

export class PromptSet {
  static readonly DEFAULT = new PromptSet({ hash: DEFAULT_PROMPTS_HASH, overrides: {} });
  constructor(readonly frozen: FrozenPrompts) {}
  get hash(): string { return this.frozen.hash; }
  text(id: string): string {
    const d = promptDef(id);
    if (!d) throw new Error(`unknown prompt ${id}`);
    const o = this.frozen.overrides[id];
    // A frozen override that no longer fits the default (the default changed in a later release) falls back to it.
    return o && promptEditable(d) && !validatePromptText(d, o.text).length ? o.text : d.text;
  }
  render(id: string, vars?: Record<string, string | number>): string { return renderTemplate(id, this.text(id), vars); }
}

const scope = new AsyncLocalStorage<PromptSet>();

/** Run `fn` with the prompt set of an audit or a conversation. */
export function withPrompts<T>(set: PromptSet, fn: () => T): T { return scope.run(set, fn); }
export function currentPrompts(): PromptSet { return scope.getStore() ?? PromptSet.DEFAULT; }

/** Render a catalog entry with the set in scope (defaults outside any scope). */
export function P(id: string, vars?: Record<string, string | number>): string { return currentPrompts().render(id, vars); }

// ---- listing (knowledge page) -------------------------------------------------------------------------------------

/**
 * Field descriptions of the submission schemas (`Submit*` in contracts) as read-only `tool` entries: they live with the
 * schemas, which the contracts package defines for engine and model alike; listed here so they can be audited too.
 */
export function fieldDescriptions(): PromptDef[] {
  const out: PromptDef[] = [];
  const walk = (schema: unknown, name: string, path: string) => {
    if (!schema || typeof schema !== 'object') return;
    const s = schema as { description?: unknown; properties?: Record<string, unknown>; items?: unknown; anyOf?: unknown[] };
    if (path && typeof s.description === 'string') {
      out.push({ id: `field.${name}.${path}`.replace(/[^a-zA-Z0-9_.]/g, '_').toLowerCase(), group: 'tool', title: `字段：${name}.${path}`, description: `提交工具参数 ${name} 中字段 ${path} 的说明（contracts）。`, text: s.description, readonly: '字段说明随提交结构定义（contracts），只读展示' });
    }
    for (const [k, v] of Object.entries(s.properties ?? {})) walk(v, name, path ? `${path}.${k}` : k);
    if (s.items) walk(s.items, name, `${path}[]`);
    for (const v of s.anyOf ?? []) walk(v, name, path);
  };
  for (const [name, v] of Object.entries(Contracts).sort(([a], [b]) => a.localeCompare(b))) if (/^Submit[A-Z]/.test(name)) walk(v, name, '');
  const seen = new Set<string>();
  return out.filter((d) => (seen.has(d.id) ? false : (seen.add(d.id), true)));
}

export interface PromptLayerView { text: string; updatedAt: string | null; valid: boolean; issues: string[]; defaultChanged: boolean }
export interface PromptView {
  def: PromptDef; editable: boolean; variables: string[]; locked: string[];
  global: PromptLayerView | null; project: PromptLayerView | null; effectiveLayer: 'default' | PromptLayer; effectiveText: string;
}

/** Every catalog entry (and the schema field descriptions) with the overrides of the global layer and a project layer. */
export function listPrompts(globalDir: string, projectDir: string | null): { items: PromptView[]; hash: string; overrides: number; invalid: number } {
  const layer = (dir: string | null) => new Map((dir ? readPromptOverrides(dir) : []).map((o) => [o.id, o]));
  const g = layer(globalDir);
  const pr = layer(projectDir);
  const view = (d: PromptDef, o: OverrideFile | undefined): PromptLayerView | null => (o ? { text: o.text, updatedAt: o.updatedAt, valid: !o.issues.length, issues: o.issues, defaultChanged: !!o.editedFrom && o.editedFrom !== defaultSha(d) } : null);
  const items = [...CATALOG, ...fieldDescriptions()].map((d): PromptView => {
    const gv = view(d, g.get(d.id));
    const pv = view(d, pr.get(d.id));
    const effectiveLayer = pv?.valid ? 'project' : gv?.valid ? 'global' : 'default';
    return {
      def: d, editable: promptEditable(d), variables: templateVars(d.text), locked: lockedTokens(d), global: gv, project: pv, effectiveLayer,
      effectiveText: effectiveLayer === 'project' ? pv!.text : effectiveLayer === 'global' ? gv!.text : d.text,
    };
  });
  // Override files for ids the catalog no longer has (a renamed or removed entry) are reported, never applied.
  const stray = [...g.values(), ...pr.values()].filter((o) => !BY_ID.has(o.id)).length;
  const r = resolvePromptOverrides(globalDir, projectDir);
  return { items, hash: r.hash, overrides: Object.keys(r.overrides).length, invalid: items.filter((i) => (i.global && !i.global.valid) || (i.project && !i.project.valid)).length + stray };
}
