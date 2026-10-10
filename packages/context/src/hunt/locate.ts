// hunt-risk locate phase: deterministic and fast — declared dependency
// versions against the affected range, dangerous APIs and code patterns via ripgrep, rough locations
// from the basis. The judge phase (LLM) then decides each candidate.
import { parse as parseYaml } from 'yaml';
import { AUDIT_LANGUAGE_INFO, AUDIT_LANGUAGES, type HuntBasis, type RiskCandidate } from '@xiezhi/contracts';
import { toolGrep, type ToolContext } from '../tools/tools.js';
import { declaredDependencies, type Declared } from './deps.js';

export { declaredDependencies, type Declared };

// ---- versions -----------------------------------------------------------------------------------------------

function parts(v: string): number[] {
  return v.replace(/^v/i, '').split(/[.+-]/).map((p) => (/^\d+$/.test(p) ? Number(p) : NaN)).filter((n) => !Number.isNaN(n));
}

export function compareVersions(a: string, b: string): number {
  const x = parts(a);
  const y = parts(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  // Same numbers: a pre-release (1.0.0-rc1) sorts before the release.
  const pa = /-(alpha|beta|rc|m|snapshot)/i.test(a);
  const pb = /-(alpha|beta|rc|m|snapshot)/i.test(b);
  return pa === pb ? 0 : pa ? -1 : 1;
}

/**
 * Range expressions: `*`; comparators `<`, `<=`, `>`, `>=`, `=` joined by spaces or commas (AND);
 * alternatives with `||`. Returns null when the version is unknown or not a version.
 */
export function versionInRange(version: string | null | undefined, range: string): boolean | null {
  const r = range.trim();
  if (!r || r === '*' || /^all$/i.test(r)) return true;
  if (!version || !/\d/.test(version)) return null;
  return r.split('||').some((alt) => {
    const comps = alt.trim().split(/[\s,]+/).filter(Boolean);
    return comps.length > 0 && comps.every((c) => {
      const m = /^(<=|>=|<|>|=|==)?\s*v?([\w.+-]+)$/.exec(c);
      if (!m) return false;
      const cmp = compareVersions(version, m[2]!);
      switch (m[1] ?? '=') {
        case '<': return cmp < 0;
        case '<=': return cmp <= 0;
        case '>': return cmp > 0;
        case '>=': return cmp >= 0;
        default: return cmp === 0;
      }
    });
  });
}

// ---- declared dependencies ----------------------------------------------------------------------------------

const pep503 = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');

function nameMatches(d: Declared, want: { ecosystem: string; name: string }): boolean {
  if (want.ecosystem !== 'any' && want.ecosystem !== d.ecosystem) return false;
  const w = want.name.trim().toLowerCase();
  const n = d.name.toLowerCase();
  if (n === w) return true;
  if (d.ecosystem === 'maven') {
    // Spring Boot / Cloud starters pull in the core artifact: `…-starter-gateway` brings `…-gateway` (version from the BOM).
    const unstarter = n.replace(/-starter(?=-|$)/, '');
    if (unstarter !== n && (unstarter === w || (!w.includes(':') && unstarter.endsWith(`:${w}`)))) return true;
    if (!w.includes(':')) return n.endsWith(`:${w}`);
  }
  if (d.ecosystem === 'go') return n === w || n.startsWith(`${w}/`);
  // PEP 503: names compare case-insensitively with runs of `-`, `_`, `.` treated as one `-`; extras are ignored.
  if (d.ecosystem === 'pypi') return pep503(n) === pep503(w.replace(/\[.*\]$/, ''));
  return false;
}

// ---- locate ---------------------------------------------------------------------------------------------------

export interface LocateResult {
  candidates: RiskCandidate[];
  /** What was checked, for “not affected” evidence (e.g. “no declared dependency on X”). */
  checks: string[];
  truncated: boolean;
}

const LANG_GLOBS: Record<string, string[]> = {
  java: ['*.java', '*.kt', '*.xml'], go: ['*.go'], javascript: ['*.js', '*.jsx', '*.ts', '*.tsx', '*.vue', '*.mjs'],
  // The other audit languages use their registry glob.
  ...Object.fromEntries(AUDIT_LANGUAGES.filter((l) => !['java', 'go', 'javascript'].includes(l)).map((l) => [l, [AUDIT_LANGUAGE_INFO[l].glob]])),
};

export async function locateRiskCandidates(ctx: ToolContext, repos: string[], basis: HuntBasis, opts: { maxCandidates?: number } = {}): Promise<LocateResult> {
  const max = opts.maxCandidates ?? 100;
  const out: RiskCandidate[] = [];
  const checks: string[] = [];
  const seen = new Set<string>();
  const add = (c: Omit<RiskCandidate, 'id'>) => {
    const id = `${c.kind}:${c.repo}:${c.path}:${c.line}`;
    if (seen.has(id)) return;
    seen.add(id);
    out.push({ id, ...c });
  };
  // 1. Rough locations first (the basis may name an interface or file).
  for (const loc of basis.features.locations) {
    for (const repo of repos) {
      if (loc.repo && loc.repo !== repo) continue;
      const v = ctx.views.get(repo)!;
      if (loc.path && v.hasFile(loc.path)) add({ repo, kind: 'location', path: loc.path, line: 0, label: `指定位置 ${loc.path}` });
      if (loc.route) {
        const literal = loc.route.split('/').filter((s) => s && !/[{}:*<>]/.test(s)).slice(-2).join('/');
        if (literal.length >= 3) {
          const r = await toolGrep({ ...ctx, defaultRepo: repo }, { repo, pattern: literal, maxResults: 20 });
          for (const m of r.matches.filter((x) => !x.context)) add({ repo, kind: 'location', path: m.path, line: m.line, label: `接口 ${loc.route}`, detail: m.text.trim().slice(0, 200) });
        }
      }
    }
  }
  // 2. Declared dependencies against the affected range.
  if (basis.features.dependencies.length) {
    for (const repo of repos) {
      const declared = declaredDependencies(ctx.views.get(repo)!);
      for (const want of basis.features.dependencies) {
        const hits = declared.filter((d) => nameMatches(d, want));
        if (!hits.length) { checks.push(`${repo}：构建文件中未声明 ${want.name}`); continue; }
        for (const d of hits) {
          const inRange = versionInRange(d.version, want.affectedVersions);
          if (inRange === false) { checks.push(`${repo}：${d.path} 声明 ${d.name} ${d.version}${d.via ? `（版本来自 ${d.via}）` : ''}，不在受影响范围 ${want.affectedVersions}`); continue; }
          const via = d.name.toLowerCase() === want.name.toLowerCase() || d.name.toLowerCase().endsWith(`:${want.name.toLowerCase()}`) ? '' : `（通过 ${d.name} 间接引入 ${want.name}）`;
          const source = d.via ? `（版本来自 ${d.via}）` : '';
          const unknown = d.managedBy?.length
            ? `版本由仓库外的 ${d.managedBy.join('、')} 管理，快照中无法确定（受影响范围 ${want.affectedVersions}），需按该 BOM / 父 POM 版本确认实际版本`
            : `版本未知（受影响范围 ${want.affectedVersions}），需确认实际版本（父 POM / BOM / 锁文件）`;
          add({ repo, kind: 'dependency', path: d.path, line: d.line, label: `依赖 ${d.name} ${d.version ?? '（版本未知）'}${via}`, detail: inRange === null ? unknown : `版本在受影响范围 ${want.affectedVersions} 内${source}` });
        }
      }
    }
  }
  // 3. Dangerous APIs and grep-able code patterns.
  const searches = [
    ...basis.features.apis.map((a) => ({ pattern: a.pattern, lang: a.language ?? 'any', label: `危险 API：${a.description}`, kind: 'api' as const })),
    ...basis.features.codePatterns.filter((p) => p.grep).map((p) => ({ pattern: p.grep!, lang: 'any', label: `代码模式：${p.description}`, kind: 'pattern' as const })),
  ].filter((s, i, all) => all.findIndex((o) => o.pattern === s.pattern && o.lang === s.lang) === i);
  for (const s of searches) {
    for (const repo of repos) {
      const globs = s.lang === 'any' ? [undefined] : LANG_GLOBS[s.lang] ?? [undefined];
      // Ruby calls may leave out the parentheses (`send_file File.join(dir, params[:f])`): a pattern written as
      // `send_file\s*\(` found nothing there, and the repository was cleared without a look.
      const pattern = (s.lang === 'any' || s.lang === 'ruby') && hasRuby(ctx, repo) ? parenOptional(s.pattern) : s.pattern;
      let found = 0;
      for (const glob of globs) {
        let r;
        try {
          r = await toolGrep({ ...ctx, defaultRepo: repo }, { repo, pattern, regex: true, caseSensitive: true, maxResults: 30, ...(glob ? { glob } : {}) });
        } catch (e) {
          checks.push(`${repo}：搜索 ${s.pattern} 失败（${(e as Error).message.slice(0, 120)}）`);
          continue;
        }
        for (const m of r.matches.filter((x) => !x.context)) {
          found++;
          add({ repo, kind: s.kind, path: m.path, line: m.line, label: s.label, detail: m.text.trim().slice(0, 200) });
        }
      }
      if (!found) checks.push(`${repo}：未搜索到 ${s.pattern}`);
    }
  }
  const order: Record<string, number> = { location: 0, dependency: 1, api: 2, pattern: 3 };
  out.sort((a, b) => (order[a.kind] ?? 9) - (order[b.kind] ?? 9) || a.repo.localeCompare(b.repo) || a.path.localeCompare(b.path) || a.line - b.line);
  return { candidates: out.slice(0, max), checks, truncated: out.length > max };
}

/** `name\s*\(` → `name` followed by `(` or by a space and an argument (Ruby leaves the parentheses out). */
export function parenOptional(pattern: string): string {
  return pattern.replace(/([A-Za-z0-9_\]])((?:\\s\*)?)\\\(/g, (_m, before: string) => `${before}(?:\\s*\\(|\\s+[^\\s=,)])`);
}

function hasRuby(ctx: ToolContext, repo: string): boolean {
  return !!ctx.views.get(repo)?.listFiles().some((f) => /\.(rb|ru|rake)$/.test(f.path));
}

/** Parse a YAML/JSON basis the user pasted (edit form round-trips JSON). */
export function parseBasisText(text: string): unknown {
  try { return JSON.parse(text); } catch { return parseYaml(text, { maxAliasCount: 50, logLevel: 'silent' }); }
}
