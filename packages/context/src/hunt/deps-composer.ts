// Composer declared dependencies: composer.json `require` / `require-dev`; lock: composer.lock
// `packages` / `packages-dev`. Read as JSON text, never evaluated (no Composer, no plugins, no scripts).
import type { Declared, EcosystemReader } from './deps.js';

/** Platform requirements are not packages: php, ext-*, lib-*, composer APIs. */
const PLATFORM_RE = /^(php(-64bit|-ipv6|-zts|-debug)?|hhvm|ext-.+|lib-.+|composer(-plugin-api|-runtime-api)?)$/i;
/** An exact version constraint (`1.2.3`, `v2.0`, `1.0.0-beta2`); ranges, wildcards and branches are unknown. */
const EXACT_RE = /^v?(\d+(?:\.\d+){0,3}(?:[-.]?(?:alpha|beta|rc|patch|p|pl)\.?\d*)?)$/i;

function lineOf(text: string, name: string): number {
  const idx = text.indexOf(`"${name}"`);
  return idx < 0 ? 0 : text.slice(0, idx).split('\n').length;
}

function parse(text: string): Record<string, unknown> | null {
  try {
    const j = JSON.parse(text) as unknown;
    return j && typeof j === 'object' && !Array.isArray(j) ? (j as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function manifestDeps(path: string, text: string): Declared[] {
  const j = parse(text);
  if (!j) return [];
  const out: Declared[] = [];
  for (const section of ['require', 'require-dev']) {
    const deps = j[section];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, constraint] of Object.entries(deps as Record<string, unknown>)) {
      if (PLATFORM_RE.test(name) || !name.includes('/')) continue;
      const exact = typeof constraint === 'string' ? EXACT_RE.exec(constraint.trim()) : null;
      out.push({ ecosystem: 'composer', name: name.toLowerCase(), version: exact ? exact[1]! : null, path, line: lineOf(text, name) });
    }
  }
  return out;
}

function lockDeps(path: string, text: string): Declared[] {
  const j = parse(text);
  if (!j) return [];
  const out: Declared[] = [];
  for (const section of ['packages', 'packages-dev']) {
    const pkgs = j[section];
    if (!Array.isArray(pkgs)) continue;
    for (const p of pkgs as { name?: unknown; version?: unknown }[]) {
      if (typeof p?.name !== 'string' || typeof p.version !== 'string') continue;
      const v = p.version.replace(/^v(?=\d)/, '');
      out.push({ ecosystem: 'composer', name: p.name.toLowerCase(), version: /^\d/.test(v) ? v : null, path, line: lineOf(text, p.name) });
    }
  }
  return out;
}

export const COMPOSER_READER: EcosystemReader = {
  ecosystem: 'composer',
  kind: (base) => (base === 'composer.json' ? 'manifest' : base === 'composer.lock' ? 'lock' : null),
  read: (path, text) => (path.endsWith('composer.lock') ? lockDeps(path, text) : manifestDeps(path, text)),
};
