// NuGet declared dependencies: *.csproj / *.fsproj / *.vbproj / Directory.Build.props and
// packages.config (manifests); packages.lock.json (lock). Read as text, never evaluated (no MSBuild).
//
// Central package management: `Directory.Packages.props` (`<PackageVersion Include Version>`) is classified as a
// lock-like file, so — like any lock file of this reader interface — its versions supersede the version-less
// `<PackageReference Include="X" />` of the projects in its directory tree (the reported declaration is the
// central one). `packages.lock.json` does the same and also lists transitive packages.
import type { Declared, EcosystemReader } from './deps.js';

function lineAt(text: string, index: number): number {
  return text.slice(0, index).split('\n').length;
}

/** Blank XML comments (keeps offsets and newlines). */
function stripComments(text: string): string {
  return text.replace(/<!--[\s\S]*?-->/g, (m) => m.replace(/[^\n]/g, ' '));
}

const attr = (attrs: string, name: string): string | undefined => new RegExp(`\\b${name}\\s*=\\s*"([^"]*)"`, 'i').exec(attrs)?.[1];

/** `1.2.3`, `[1.2.3]`, `[1.2.3, )`, `$(Prop)` (unknown) → a concrete version or null. */
function versionOf(spec: string | undefined, props: Map<string, string>): string | null {
  if (!spec) return null;
  let s = spec.trim();
  const prop = /^\$\(([\w.-]+)\)$/.exec(s);
  if (prop) s = props.get(prop[1]!) ?? '';
  const m = /(\d+(?:\.\d+){0,3}(?:-[\w.]+)?)/.exec(s);
  return m ? m[1]! : null;
}

function msbuildDeps(path: string, raw: string, element: 'PackageReference' | 'PackageVersion'): Declared[] {
  const text = stripComments(raw);
  const props = new Map<string, string>();
  for (const m of text.matchAll(/<PropertyGroup\b[^>]*>([\s\S]*?)<\/PropertyGroup>/g)) {
    for (const p of m[1]!.matchAll(/<([\w.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props.set(p[1]!, p[2]!);
  }
  const out: Declared[] = [];
  const re = new RegExp(`<${element}\\b([^>]*?)(/>|>([\\s\\S]*?)</${element}>)`, 'g');
  for (const m of text.matchAll(re)) {
    const attrs = m[1]!;
    const name = attr(attrs, 'Include') ?? attr(attrs, 'Update');
    if (!name) continue;
    const nested = m[3] ? /<(?:Version|VersionOverride)>\s*([^<]*?)\s*<\/(?:Version|VersionOverride)>/.exec(m[3])?.[1] : undefined;
    const version = versionOf(attr(attrs, 'VersionOverride') ?? attr(attrs, 'Version') ?? nested, props);
    out.push({ ecosystem: 'nuget', name, version, path, line: lineAt(text, m.index ?? 0), ...(element === 'PackageVersion' ? { via: 'Directory.Packages.props' } : {}) });
  }
  return out;
}

function packagesConfigDeps(path: string, raw: string): Declared[] {
  const text = stripComments(raw);
  const out: Declared[] = [];
  for (const m of text.matchAll(/<package\b([^>]*?)\/?>/g)) {
    const name = attr(m[1]!, 'id');
    if (name) out.push({ ecosystem: 'nuget', name, version: versionOf(attr(m[1]!, 'version'), new Map()), path, line: lineAt(text, m.index ?? 0) });
  }
  return out;
}

function lockDeps(path: string, text: string): Declared[] {
  let j: { dependencies?: Record<string, Record<string, { resolved?: string }>> };
  try { j = JSON.parse(text) as typeof j; } catch { return []; }
  const out: Declared[] = [];
  const seen = new Set<string>();
  for (const deps of Object.values(j.dependencies ?? {})) {
    for (const [name, info] of Object.entries(deps ?? {})) {
      const version = info?.resolved ?? null;
      const key = `${name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const idx = text.indexOf(`"${name}"`);
      out.push({ ecosystem: 'nuget', name, version, path, line: idx >= 0 ? lineAt(text, idx) : 0, via: 'packages.lock.json' });
    }
  }
  return out;
}

export const NUGET_READER: EcosystemReader = {
  ecosystem: 'nuget',
  kind(base) {
    const b = base.toLowerCase();
    if (/\.(csproj|fsproj|vbproj)$/.test(b) || b === 'directory.build.props' || b === 'packages.config') return 'manifest';
    if (b === 'packages.lock.json' || b === 'directory.packages.props') return 'lock';
    return null;
  },
  read(path, text) {
    const base = (path.split('/').pop() ?? path).toLowerCase();
    if (base === 'packages.config') return packagesConfigDeps(path, text);
    if (base === 'packages.lock.json') return lockDeps(path, text);
    if (base === 'directory.packages.props') return msbuildDeps(path, text, 'PackageVersion');
    return msbuildDeps(path, text, 'PackageReference');
  },
};
