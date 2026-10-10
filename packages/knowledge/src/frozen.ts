// Audit-frozen knowledge: skill contents are copied to the artifact store at audit
// start; load_skill only ever reads frozen content, so audits are reproducible.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ArtifactStore } from '@xiezhi/store';
import type { FrozenPrompts } from './prompts/registry.js';
import { estimateTokens, prefilter, type Selected, type Skill, type TaskFacts } from './skills.js';

export interface FrozenSkill {
  name: string;
  description: string;
  category: Skill['category'];
  layer: Skill['layer'];
  load: Skill['load'];
  appliesTo: Skill['appliesTo'];
  cwe: string[];
  tags: string[];
  verified?: boolean;
  sha256: string;
  /** Relative file path → artifact sha256 (entry file is `SKILL.md` or `<name>.md`). */
  files: Record<string, string>;
  entryFile: string;
  /** checklist items (absent in audits frozen before checklists existed). */
  checklist?: Skill['checklist'];
}

/** `prompts`: the prompt overrides in effect when the audit started; absent in older audits (= defaults). */
/** an approved project rule as frozen with an audit (run as an extra sink rule over its snapshots). */
export interface FrozenProjectRule { id: string; lang: string; matcher: 'tree_sitter' | 'regex'; pattern: string; category: string; title: string }

export interface FrozenKnowledge { skills: FrozenSkill[]; prompts?: FrozenPrompts; projectRules?: FrozenProjectRule[] }

export function freezeSkills(skills: Skill[], artifacts: ArtifactStore): FrozenKnowledge {
  const out: FrozenSkill[] = [];
  for (const s of [...skills].sort((a, b) => a.name.localeCompare(b.name))) {
    const files: Record<string, string> = {};
    const base = s.dir ?? join(s.entry, '..');
    for (const rel of Object.keys(s.files)) files[rel] = artifacts.put(readFileSync(join(base, ...rel.split('/'))), 'text/markdown');
    out.push({
      name: s.name, description: s.description, category: s.category, layer: s.layer, load: s.load, appliesTo: s.appliesTo,
      cwe: s.cwe, tags: s.tags, ...(s.verified !== undefined ? { verified: s.verified } : {}), sha256: s.sha256, files,
      entryFile: s.dir ? 'SKILL.md' : `${s.name}.md`,
      ...(s.checklist?.length ? { checklist: s.checklist } : {}),
    });
  }
  return { skills: out };
}

export const INDEX_MAX_ITEMS = 60;
export const INDEX_MAX_TOKENS = 4000;
export const BODY_BUDGET_TOKENS = 6000;
export const READ_PAGE_TOKENS = 8000;

export interface KnowledgeNeed { topic: string; reason?: string }

export interface SessionKnowledge {
  /** Level-1 index block for the system prompt. */
  indexText: string;
  /** Bodies injected directly (always / phase / include), within the 6k budget. */
  bodies: { name: string; text: string; trigger: Selected['trigger'] }[];
  /** Names visible to load_skill in this session. */
  readable: Set<string>;
  /** Usage records to persist (index + injected bodies). */
  usage: { name: string; layer: string; sha256: string; level: 'index' | 'body'; trigger: string; reason: string; tokens: number }[];
}

function toSkillLike(f: FrozenSkill): Skill {
  return {
    name: f.name, description: f.description, category: f.category, layer: f.layer, load: f.load, appliesTo: f.appliesTo,
    cwe: f.cwe, tags: f.tags, entry: '', dir: null, files: f.files, sha256: f.sha256, body: '',
  };
}

function matchesNeed(f: FrozenSkill, need: KnowledgeNeed): boolean {
  const t = need.topic.toLowerCase();
  return f.name === t || (f.appliesTo.vuln_classes ?? []).some((v) => t.includes(v)) || f.cwe.some((c) => t.includes(c.toLowerCase()))
    || t.split(/\s+/).filter((w) => w.length > 3).some((w) => f.description.toLowerCase().includes(w));
}

/** Build the per-session knowledge view: prefiltered index + budgeted bodies. */
export function sessionKnowledge(frozen: FrozenKnowledge, facts: TaskFacts, artifacts: ArtifactStore, needs: KnowledgeNeed[] = []): SessionKnowledge {
  const byName = new Map(frozen.skills.map((s) => [s.name, s]));
  const selected = prefilter(frozen.skills.map(toSkillLike), facts);
  const bodies: SessionKnowledge['bodies'] = [];
  const usage: SessionKnowledge['usage'] = [];
  const indexLines: string[] = [];
  let bodyTokens = 0;
  let indexTokens = 0;
  let omitted = 0;
  const readable = new Set<string>();
  for (const sel of selected) {
    const f = byName.get(sel.skill.name)!;
    readable.add(f.name);
    if (sel.mode === 'body') {
      const text = artifacts.getText(f.files[f.entryFile]!);
      const tokens = estimateTokens(text);
      if (bodyTokens + tokens <= BODY_BUDGET_TOKENS) {
        bodyTokens += tokens;
        bodies.push({ name: f.name, text, trigger: sel.trigger });
        usage.push({ name: f.name, layer: f.layer, sha256: f.sha256, level: 'body', trigger: sel.trigger, reason: sel.trigger === 'user_pinned' ? 'include' : sel.trigger, tokens });
        continue;
      }
      usage.push({ name: f.name, layer: f.layer, sha256: f.sha256, level: 'index', trigger: sel.trigger, reason: 'budget_degraded', tokens: 0 });
    }
    const need = needs.find((n) => matchesNeed(f, n));
    const mark = sel.mode === 'body' ? ' [建议阅读]' : need ? ` [建议阅读：${need.topic.slice(0, 60)}]` : '';
    const verified = f.verified === false ? ' [推测]' : '';
    const line = `- ${f.name} (${f.category})${verified}${mark} — ${f.description}`;
    const lt = estimateTokens(line);
    if (indexLines.length >= INDEX_MAX_ITEMS || indexTokens + lt > INDEX_MAX_TOKENS) { omitted++; continue; }
    indexTokens += lt;
    indexLines.push(line);
    if (need) usage.push({ name: f.name, layer: f.layer, sha256: f.sha256, level: 'index', trigger: 'knowledge_need', reason: 'knowledge_need_hinted', tokens: lt });
  }
  if (omitted) indexLines.push(`- （另有 ${omitted} 条未列出）`);
  return {
    indexText: indexLines.length ? indexLines.join('\n') : '（无可用知识）',
    bodies, readable, usage,
  };
}

export interface LoadSkillResult { name: string; file: string; page: number; pages: number; text: string; sha256: string; layer: string; tokens: number }

/** load_skill(name, file?, page?) over frozen content only. */
export function loadFrozenSkill(frozen: FrozenKnowledge, readable: Set<string>, artifacts: ArtifactStore, args: { name: string; file?: string; page?: number }): LoadSkillResult {
  const f = frozen.skills.find((s) => s.name === args.name);
  if (!f || !readable.has(args.name)) throw new Error(`skill "${args.name}" is not available in this session`);
  // An empty string is how some models "omit" an optional argument.
  const file = args.file?.trim() || f.entryFile;
  if (file.includes('..') || file.startsWith('/')) throw new Error('file must be a relative path inside the skill');
  const ref = f.files[file];
  if (!ref) throw new Error(`file "${file}" not found in skill "${args.name}"; files: ${Object.keys(f.files).join(', ')}`);
  const text = artifacts.getText(ref);
  const pageChars = READ_PAGE_TOKENS * 3;
  const pages = Math.max(1, Math.ceil(text.length / pageChars));
  const page = Math.min(pages, Math.max(1, Math.floor(args.page ?? 1)));
  const slice = text.slice((page - 1) * pageChars, page * pageChars);
  return { name: f.name, file, page, pages, text: slice, sha256: f.sha256, layer: f.layer, tokens: estimateTokens(slice) };
}
