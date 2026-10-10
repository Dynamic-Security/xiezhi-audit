// PyPI declared dependencies. Read as text, never evaluated:
// - manifests: requirements*.txt (PEP 508 lines), pyproject.toml ([project] dependencies and optional groups,
//   [tool.poetry.*dependencies]), setup.cfg ([options] install_requires), Pipfile ([packages], [dev-packages]);
// - locks: poetry.lock / uv.lock / pdm.lock ([[package]] name + version), Pipfile.lock (JSON).
// A version is reported only when pinned exactly (`==1.2.3`, `===1.2.3`, Poetry bare `1.2.3`); ranges stay unknown.
// Names are PEP 503-normalized so a lock file supersedes the manifest entries of its directory.
import type { Declared, EcosystemReader } from './deps.js';

export const pep503 = (name: string): string => name.toLowerCase().replace(/[-_.]+/g, '-');

const lineAt = (text: string, index: number) => text.slice(0, index).split('\n').length;

/** Exact version of a PEP 440 specifier set (`==1.2`, `===1.2`); null for ranges, wildcards and markers. */
function exactVersion(spec: string): string | null {
  const s = spec.trim().replace(/^\(|\)$/g, '');
  const m = /^={2,3}\s*([A-Za-z0-9][A-Za-z0-9.+!_-]*)$/.exec(s);
  return m && !m[1]!.includes('*') ? m[1]! : null;
}

/** One PEP 508 requirement (`name[extra] >=1, <2 ; marker`, `name @ url`). */
export function parseRequirement(req: string): { name: string; version: string | null } | null {
  const noMarker = req.split(';')[0]!.trim();
  const m = /^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$/.exec(noMarker);
  if (!m) return null;
  const rest = m[3]!.trim();
  if (rest.startsWith('@')) return { name: pep503(m[1]!), version: null };
  return { name: pep503(m[1]!), version: rest && !rest.includes(',') ? exactVersion(rest) : null };
}

function requirementsTxt(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line || line.startsWith('-') || /^[a-z+]+:\/\//i.test(line) || line.startsWith('.') || line.startsWith('/')) return;
    const r = parseRequirement(line);
    if (r) out.push({ ecosystem: 'pypi', ...r, path, line: i + 1 });
  });
  return out;
}

/** TOML-ish sections: header → [start index, body]. Enough for the dependency tables (no evaluation). */
function sections(text: string): { name: string; start: number; body: string }[] {
  const out: { name: string; start: number; body: string }[] = [];
  const re = /^\s*\[{1,2}([^\]\n]+)\]{1,2}\s*$/gm;
  let m: RegExpExecArray | null;
  let prev: { name: string; start: number } | null = null;
  while ((m = re.exec(text))) {
    if (prev) out.push({ ...prev, body: text.slice(prev.start, m.index) });
    prev = { name: m[1]!.trim(), start: m.index + m[0].length };
  }
  if (prev) out.push({ ...prev, body: text.slice(prev.start) });
  return out;
}

/** String items of a TOML array value starting after `key =` (may span lines). */
function tomlArray(body: string, key: string): { value: string; offset: number }[] {
  const m = new RegExp(`^\\s*${key}\\s*=\\s*\\[`, 'm').exec(body);
  if (!m) return [];
  const out: { value: string; offset: number }[] = [];
  let i = m.index + m[0].length;
  let depth = 1;
  while (i < body.length && depth > 0) {
    const ch = body[i]!;
    if (ch === '"' || ch === "'") {
      const end = body.indexOf(ch, i + 1);
      if (end < 0) break;
      out.push({ value: body.slice(i + 1, end), offset: i });
      i = end + 1;
      continue;
    }
    if (ch === '#') { const nl = body.indexOf('\n', i); i = nl < 0 ? body.length : nl; continue; }
    if (ch === '[') depth++;
    else if (ch === ']') depth--;
    i++;
  }
  return out;
}

/** `name = "spec"` / `name = { version = "spec", … }` tables (Poetry, Pipfile). */
function specTable(path: string, text: string, sec: { start: number; body: string }, poetry: boolean): Declared[] {
  const out: Declared[] = [];
  for (const m of sec.body.matchAll(/^\s*["']?([A-Za-z0-9][A-Za-z0-9._-]*)["']?\s*=\s*(.+)$/gm)) {
    const name = m[1]!;
    if (name === 'python') continue;
    const value = m[2]!.trim();
    const spec = /^["']([^"']*)["']/.exec(value)?.[1] ?? /\bversion\s*=\s*["']([^"']*)["']/.exec(value)?.[1] ?? null;
    let version: string | null = null;
    if (spec !== null) version = poetry && /^\d[\w.+!-]*$/.test(spec.trim()) ? spec.trim() : exactVersion(spec);
    out.push({ ecosystem: 'pypi', name: pep503(name), version, path, line: lineAt(text, sec.start + m.index!) });
  }
  return out;
}

function pyproject(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  for (const sec of sections(text)) {
    const arrays = sec.name === 'project' ? tomlArray(sec.body, 'dependencies')
      : sec.name === 'project.optional-dependencies' ? [...sec.body.matchAll(/^\s*([\w-]+)\s*=\s*\[/gm)].flatMap((g) => tomlArray(sec.body.slice(g.index), g[1]!).map((x) => ({ ...x, offset: x.offset + g.index! })))
        : [];
    for (const a of arrays) {
      const r = parseRequirement(a.value);
      if (r) out.push({ ecosystem: 'pypi', ...r, path, line: lineAt(text, sec.start + a.offset) });
    }
    if (/^tool\.poetry\.(dependencies|dev-dependencies|group\.[\w-]+\.dependencies)$/.test(sec.name)) out.push(...specTable(path, text, sec, true));
  }
  return out;
}

function setupCfg(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  const m = /^install_requires\s*=[^\S\n]*(.*)\n((?:[ \t]+.*\n?)*)/m.exec(text);
  if (!m) return out;
  const startLine = lineAt(text, m.index);
  const items = [m[1]!, ...m[2]!.split('\n')];
  items.forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) return;
    const r = parseRequirement(line);
    if (r) out.push({ ecosystem: 'pypi', ...r, path, line: startLine + i });
  });
  return out;
}

function pipfile(path: string, text: string): Declared[] {
  return sections(text).filter((s) => s.name === 'packages' || s.name === 'dev-packages').flatMap((s) => specTable(path, text, s, false));
}

/** poetry.lock / uv.lock / pdm.lock: `[[package]]` blocks with name and version (the uv project itself is skipped). */
function packageLock(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  for (const sec of sections(text)) {
    if (sec.name !== 'package') continue;
    const name = /^\s*name\s*=\s*["']([^"']+)["']/m.exec(sec.body);
    const version = /^\s*version\s*=\s*["']([^"']+)["']/m.exec(sec.body)?.[1] ?? null;
    if (!name || /^\s*source\s*=\s*\{\s*(editable|virtual)\s*=/m.test(sec.body)) continue;
    out.push({ ecosystem: 'pypi', name: pep503(name[1]!), version, path, line: lineAt(text, sec.start + name.index), via: path.split('/').pop()! });
  }
  return out;
}

function pipfileLock(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  const j = JSON.parse(text) as Record<string, Record<string, { version?: string }> | undefined>;
  for (const group of ['default', 'develop']) {
    for (const [name, v] of Object.entries(j[group] ?? {})) {
      const idx = text.indexOf(`"${name}"`);
      out.push({ ecosystem: 'pypi', name: pep503(name), version: v?.version ? exactVersion(v.version) : null, path, line: idx >= 0 ? lineAt(text, idx) : 0, via: 'Pipfile.lock' });
    }
  }
  return out;
}

export const PYPI_READER: EcosystemReader = {
  ecosystem: 'pypi',
  kind(base) {
    if (/requirements[\w.-]*\.txt$/i.test(base) || base === 'pyproject.toml' || base === 'setup.cfg' || base === 'Pipfile') return 'manifest';
    if (base === 'poetry.lock' || base === 'uv.lock' || base === 'pdm.lock' || base === 'Pipfile.lock') return 'lock';
    return null;
  },
  read(path, text) {
    const base = path.split('/').pop()!;
    if (base === 'pyproject.toml') return pyproject(path, text);
    if (base === 'setup.cfg') return setupCfg(path, text);
    if (base === 'Pipfile') return pipfile(path, text);
    if (base === 'Pipfile.lock') return pipfileLock(path, text);
    if (base.endsWith('.lock')) return packageLock(path, text);
    return requirementsTxt(path, text);
  },
};
