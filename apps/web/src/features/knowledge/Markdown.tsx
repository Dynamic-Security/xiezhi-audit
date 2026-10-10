// Skill preview (“编辑时实时预览”): frontmatter as a key list, the body through the shared Markdown
// renderer (no raw HTML, links confirmed before opening).
import { Markdown } from '../../shared/markdown/Markdown';
import { ui } from '../../shared/ui';

/** Split `---` frontmatter from the body; the preview shows the frontmatter as a key list. */
export function splitFrontmatter(text: string): { meta: [string, string][]; body: string } {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) return { meta: [], body: text };
  const meta: [string, string][] = [];
  let lastKey: string | null = null;
  for (const line of m[1]!.split('\n')) {
    const kv = /^([\w-]+):\s*(.*)$/.exec(line);
    if (kv) { meta.push([kv[1]!, kv[2]!]); lastKey = kv[1]!; } else if (lastKey && line.trim()) meta[meta.length - 1]![1] += ` ${line.trim()}`;
  }
  return { meta, body: text.slice(m[0].length) };
}

export function SkillPreview({ text }: { text: string }) {
  const { meta, body } = splitFrontmatter(text);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {meta.length > 0 && (
        <div className={ui.kv} style={{ fontSize: 12.5, display: 'grid', gridTemplateColumns: 'max-content 1fr', gap: '4px 12px', padding: '8px 10px', background: 'var(--bg-subtle)', borderRadius: 8 }}>
          {meta.map(([key, v]) => [<span key={`k${key}`} className={ui.faint}>{key}</span>, <span key={`v${key}`} style={{ overflowWrap: 'anywhere' }}>{v}</span>])}
        </div>
      )}
      <Markdown text={body} />
    </div>
  );
}
