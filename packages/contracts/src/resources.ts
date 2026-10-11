// Where the bundled resources live: rules/, skills/, connector-packs/, web/, grammars/, vendor/.
// A source checkout keeps them at the repository root, the npm package at its own root; both are found by walking up
// from this module, so the layout of the compiled code (per-package dist or one bundle) does not matter.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

let found: string | null = null;

/** `XIEZHI_AUDIT_HOME`, else the nearest directory above this module that holds `rules/` and `skills/`. */
export function resourceRoot(): string {
  const env = process.env.XIEZHI_AUDIT_HOME;
  if (env) return resolve(env);
  if (found) return found;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(dir, 'rules')) && existsSync(join(dir, 'skills'))) return (found = dir);
    const up = dirname(dir);
    if (up === dir) throw new Error('xiezhi resources (rules/, skills/) not found; set XIEZHI_AUDIT_HOME to the install directory');
    dir = up;
  }
}

export function resourcePath(...parts: string[]): string {
  return join(resourceRoot(), ...parts);
}

/** The version of this install: `package.json` at the resource root (the repository's or the npm package's). */
export function appVersion(): string {
  try {
    return (JSON.parse(readFileSync(resourcePath('package.json'), 'utf8')) as { version?: string }).version ?? 'unknown';
  } catch {
    return 'unknown';
  }
}
