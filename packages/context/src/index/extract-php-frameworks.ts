// Composer dependencies that select PHP framework rules whose route files may import nothing
// from the framework (Slim `return function ($app) { … }`, CodeIgniter 4 `app/Config/Routes.php`). Only files under a
// composer.json that declares one of the markers get `langContext`, so other repositories' inputs are unchanged.
import type { SnapshotView } from '../snapshot/view.js';

export interface PhpFrameworkContext { deps: string[] }

const MARKERS = ['slim/slim', 'codeigniter4/framework', 'codeigniter4/codeigniter4', 'yiisoft/yii2'] as const;
const cache = new WeakMap<SnapshotView, Map<string, PhpFrameworkContext>>();

export function phpFrameworkContexts(view: SnapshotView): Map<string, PhpFrameworkContext> {
  const hit = cache.get(view);
  if (hit) return hit;
  const out = new Map<string, PhpFrameworkContext>();
  cache.set(view, out);
  const files = view.listFiles().filter((f) => !f.path.includes('vendor/'));
  const pkgs: { dir: string; deps: string[] }[] = [];
  for (const f of files) {
    if (!(f.path === 'composer.json' || f.path.endsWith('/composer.json')) || f.size > 512 * 1024) continue;
    try {
      const j = JSON.parse(view.text(f.path)) as Record<string, Record<string, unknown> | undefined>;
      const deps = [...Object.keys(j.require ?? {}), ...Object.keys(j['require-dev'] ?? {})].filter((d) => (MARKERS as readonly string[]).includes(d));
      if (deps.length) pkgs.push({ dir: f.path.includes('/') ? f.path.slice(0, f.path.lastIndexOf('/')) : '', deps });
    } catch { /* not JSON */ }
  }
  if (!pkgs.length) return out;
  pkgs.sort((a, b) => b.dir.length - a.dir.length);
  for (const f of files) {
    if (f.lang !== 'php') continue;
    const pkg = pkgs.find((p) => p.dir === '' || f.path.startsWith(p.dir + '/'));
    if (pkg) out.set(f.path, { deps: pkg.deps });
  }
  return out;
}
