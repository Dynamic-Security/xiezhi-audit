// The prompt catalog — integrity, override checks (variables, locked tokens, read-only entries),
// global / project layers with one-click restore, frozen sets and the render scope.
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PROMPTS_HASH, P, PROMPT_GROUPS, PROMPTS_DIR, PromptSet, deleteAllPromptOverrides, deletePromptOverride, listPrompts, lockedTokens, promptCatalog,
  promptDef, readPromptOverrides, resolvePromptOverrides, savePromptOverride, templateVars, validatePromptText, withPrompts,
} from '@xiezhi/knowledge';

const ROOT = resolve(__dirname, '../../..');
const tmp = () => mkdtempSync(join(tmpdir(), 'ca-prompts-'));

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) { if (n !== 'node_modules' && n !== 'dist' && n !== 'test') out.push(...sources(p)); } else if (n.endsWith('.ts')) out.push(p);
  }
  return out;
}

describe('prompt catalog', () => {
  it('ids are unique and well-formed, groups are known, tool entries are read-only, every template renders', () => {
    const all = promptCatalog();
    expect(all.length).toBeGreaterThan(20);
    expect(new Set(all.map((d) => d.id)).size).toBe(all.length);
    for (const d of all) {
      expect(PROMPT_GROUPS).toContain(d.group);
      expect(d.title.length).toBeGreaterThan(1);
      const vars = Object.fromEntries(templateVars(d.text).map((v) => [v, `<${v}>`]));
      expect(() => new PromptSet({ hash: DEFAULT_PROMPTS_HASH, overrides: {} }).render(d.id, vars)).not.toThrow();
    }
    expect(all.filter((d) => d.group === 'tool').every((d) => !!d.readonly)).toBe(true);
    // The data boundary declaration is a security boundary: never overridable.
    expect(promptDef('boundary.declaration')!.readonly).toBeTruthy();
  });

  it('every P(id) in the engine and the agent names a catalog entry, and every entry is used', () => {
    const files = [...sources(join(ROOT, 'packages/engine/src')), ...sources(join(ROOT, 'packages/agent/src'))];
    const text = files.map((f) => readFileSync(f, 'utf8')).join('\n');
    const used = new Set([...text.matchAll(/\bP\('([a-z0-9_.]+)'/g)].map((m) => m[1]!));
    const ids = new Set(promptCatalog().map((d) => d.id));
    expect([...used].filter((id) => !ids.has(id))).toEqual([]);
    // Entries referenced through a computed id (role.<step>, scene.<scene>) are covered by the agent's prompt tests.
    const computed = (id: string) => id.startsWith('role.') || id.startsWith('scene.');
    // Ids chosen in code (`P(cond ? 'a' : 'b')`) count as used when they appear as a quoted literal.
    const quoted = (id: string) => text.includes(`'${id}'`);
    expect([...ids].filter((id) => !used.has(id) && !quoted(id) && !computed(id))).toEqual([]);
  });

  it('an override keeps the variables and the locked tokens; read-only entries cannot be overridden', () => {
    const d = promptDef('challenge.light')!;
    expect(templateVars(d.text)).toEqual(['turns']);
    expect(lockedTokens(d)).toContain('pending');
    expect(validatePromptText(d, d.text)).toEqual([]);
    expect(validatePromptText(d, d.text.replace('{{turns}}', '十二')).join()).toMatch(/缺少必需变量：\{\{turns\}\}/);
    expect(validatePromptText(d, `${d.text}{{other}}`).join()).toMatch(/未知变量：\{\{other\}\}/);
    expect(validatePromptText(d, d.text.replace(/pending/g, '待定')).join()).toMatch(/缺少锁定词.*pending/);
    expect(validatePromptText(d, '  ').join()).toMatch(/不能为空/);
    const b = promptDef('boundary.declaration')!;
    expect(validatePromptText(b, b.text).join()).toMatch(/不能修改/);
  });

  it('layers: the project overrides the global one, which overrides the default; restore one or all; invalid files are not applied', () => {
    const g = tmp();
    const p = tmp();
    const d = promptDef('challenge.intro')!;
    expect(resolvePromptOverrides(g, p)).toEqual({ hash: DEFAULT_PROMPTS_HASH, overrides: {} });
    savePromptOverride(g, d.id, `${d.text}\n全局补充。`);
    expect(() => savePromptOverride(g, d.id, '随便写')).toThrow(/invalid/);
    let r = resolvePromptOverrides(g, p);
    expect(r.overrides[d.id]).toEqual({ text: `${d.text}\n全局补充。`, layer: 'global' });
    expect(r.hash).not.toBe(DEFAULT_PROMPTS_HASH);
    savePromptOverride(p, d.id, `${d.text}\n项目补充。`);
    r = resolvePromptOverrides(g, p);
    expect(r.overrides[d.id]!.layer).toBe('project');
    expect(listPrompts(g, p).items.find((i) => i.def.id === d.id)).toMatchObject({ effectiveLayer: 'project', effectiveText: `${d.text}\n项目补充。` });
    // A hand-edited file that drops a locked token is listed as invalid and not applied.
    writeFileSync(join(p, PROMPTS_DIR, `${d.id}.md`), '---\nid: challenge.intro\n---\n不调用工具\n');
    expect(readPromptOverrides(p)[0]!.issues.length).toBeGreaterThan(0);
    expect(resolvePromptOverrides(g, p).overrides[d.id]!.layer).toBe('global');
    expect(listPrompts(g, p).invalid).toBe(1);
    expect(deletePromptOverride(p, d.id)).toBe(true);
    expect(deletePromptOverride(p, d.id)).toBe(false);
    savePromptOverride(g, 'challenge.gap_rule', promptDef('challenge.gap_rule')!.text + '（全局）');
    expect(deleteAllPromptOverrides(g).sort()).toEqual(['challenge.gap_rule', 'challenge.intro']);
    expect(resolvePromptOverrides(g, p).hash).toBe(DEFAULT_PROMPTS_HASH);
    // An override file for an id the catalog does not have is reported, never applied.
    mkdirSync(join(g, PROMPTS_DIR), { recursive: true });
    writeFileSync(join(g, PROMPTS_DIR, 'gone.entry.md'), '---\nid: gone.entry\n---\nx\n');
    expect(listPrompts(g, null).invalid).toBe(1);
    expect(resolvePromptOverrides(g, null).overrides).toEqual({});
  });

  it('renders through the set in scope; defaults outside any scope', () => {
    const d = promptDef('challenge.light')!;
    const set = new PromptSet({ hash: 'x', overrides: { [d.id]: { text: `简化：{{turns}} 轮；${d.text}`, layer: 'global' } } });
    expect(P(d.id, { turns: 3 })).toBe(d.text.replace('{{turns}}', '3'));
    expect(withPrompts(set, () => P(d.id, { turns: 3 }))).toBe(`简化：3 轮；${d.text.replace('{{turns}}', '3')}`);
    // A frozen override that no longer fits the default falls back to the default.
    const stale = new PromptSet({ hash: 'y', overrides: { [d.id]: { text: '没有变量了', layer: 'global' } } });
    expect(stale.render(d.id, { turns: 3 })).toBe(d.text.replace('{{turns}}', '3'));
    expect(() => P(d.id)).toThrow(/turns/);
  });
});
