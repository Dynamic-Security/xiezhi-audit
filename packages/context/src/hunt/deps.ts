// Declared dependencies for the hunt-risk locate phase. Static and snapshot-only: build files
// are read as text, never evaluated, and nothing outside the snapshot is fetched. Versions come from the
// declaration itself, properties, a parent POM or BOM in the same repository, a Gradle version catalog,
// or a lock file; when the version is managed by a BOM outside the repository the dependency is reported
// with an unknown version and the BOM named, so the judge can decide.
import { parse as parseYaml } from 'yaml';
import type { DependencyEcosystem } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';
import { COMPOSER_READER } from './deps-composer.js';
import { NUGET_READER } from './deps-nuget.js';
import { PYPI_READER } from './deps-pypi.js';
import { CARGO_READER } from './deps-cargo.js';
import { RUBYGEMS_READER } from './deps-rubygems.js';

export interface Declared {
  ecosystem: DependencyEcosystem;
  name: string;
  version: string | null;
  path: string;
  line: number;
  /** Where the version came from when not written on the declaration (parent POM, BOM, catalog, lock file). */
  via?: string;
  /** BOMs / parents outside the repository that may manage the version (only when the version is unknown). */
  managedBy?: string[];
}

/**
 * Ecosystems of the other audit languages: each reader classifies files by base name as a manifest or a lock file and reads
 * declarations from the text. A lock file supersedes the manifests of its directory and below (as npm).
 */
export interface EcosystemReader {
  ecosystem: DependencyEcosystem;
  kind(base: string): 'manifest' | 'lock' | null;
  read(path: string, text: string): Declared[];
}
const READERS: EcosystemReader[] = [PYPI_READER, COMPOSER_READER, NUGET_READER, RUBYGEMS_READER, CARGO_READER];

const MAX_BUILD_FILE = 2 * 1024 * 1024;
const MAX_LOCK_FILE = 16 * 1024 * 1024;

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split('\n').length;
}

function dirOf(path: string): string {
  const i = path.lastIndexOf('/');
  return i < 0 ? '' : path.slice(0, i);
}

function joinPath(dir: string, rel: string): string {
  const out: string[] = dir ? dir.split('/') : [];
  for (const seg of rel.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') out.pop();
    else out.push(seg);
  }
  return out.join('/');
}

/**
 * BOMs whose version is also the version of every artifact in their group (the release is versioned as a
 * whole). Release-train BOMs such as spring-cloud-dependencies are not aligned and are only named.
 */
const ALIGNED_BOMS: { group: string; artifacts: string[] }[] = [
  { group: 'org.springframework.boot', artifacts: ['spring-boot-starter-parent', 'spring-boot-dependencies', 'spring-boot-parent'] },
  { group: 'org.springframework', artifacts: ['spring-framework-bom'] },
  { group: 'org.apache.logging.log4j', artifacts: ['log4j-bom'] },
  { group: 'io.netty', artifacts: ['netty-bom'] },
];

interface Coord { g: string; a: string; v: string | null }

function alignedVersion(boms: Coord[], group: string): { version: string; via: string } | null {
  for (const b of boms) {
    if (!b.v || b.g !== group) continue;
    if (ALIGNED_BOMS.some((x) => x.group === b.g && x.artifacts.includes(b.a))) return { version: b.v, via: `${b.g}:${b.a}:${b.v}` };
  }
  return null;
}

// ---- Maven ------------------------------------------------------------------------------------------------

interface PomDep { g: string; a: string; v: string | undefined; scope: string | undefined; type: string | undefined; index: number }
interface Pom {
  path: string;
  text: string;
  g: string | undefined;
  a: string | undefined;
  v: string | undefined;
  parent: { g: string; a: string; v: string | undefined; relativePath: string } | null;
  props: Map<string, string>;
  deps: PomDep[];
  managed: PomDep[];
}

/** Blank out a block (keeps offsets so line numbers stay right). */
function blank(text: string, re: RegExp): string {
  return text.replace(re, (c) => c.replace(/[^\n]/g, ' '));
}

function tag(block: string, name: string): string | undefined {
  return new RegExp(`<${name}>\\s*([^<]*?)\\s*</${name}>`).exec(block)?.[1];
}

function pomDeps(block: string, offset: number): PomDep[] {
  const out: PomDep[] = [];
  for (const m of block.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = tag(m[1]!, 'groupId');
    const a = tag(m[1]!, 'artifactId');
    if (g && a) out.push({ g, a, v: tag(m[1]!, 'version'), scope: tag(m[1]!, 'scope'), type: tag(m[1]!, 'type'), index: offset + (m.index ?? 0) });
  }
  return out;
}

function parsePom(path: string, text: string): Pom {
  const clean = blank(text, /<!--[\s\S]*?-->/g);
  const parentBlock = /<parent>([\s\S]*?)<\/parent>/.exec(clean)?.[1];
  const parent = parentBlock && tag(parentBlock, 'groupId') && tag(parentBlock, 'artifactId')
    ? { g: tag(parentBlock, 'groupId')!, a: tag(parentBlock, 'artifactId')!, v: tag(parentBlock, 'version'), relativePath: tag(parentBlock, 'relativePath') ?? '../pom.xml' }
    : null;
  const props = new Map<string, string>();
  const propBlock = /<properties>([\s\S]*?)<\/properties>/.exec(clean)?.[1] ?? '';
  for (const m of propBlock.matchAll(/<([\w.-]+)>\s*([^<]*?)\s*<\/\1>/g)) props.set(m[1]!, m[2]!);
  const mgmt = /<dependencyManagement>[\s\S]*?<\/dependencyManagement>/.exec(clean);
  const managed = mgmt ? pomDeps(mgmt[0], mgmt.index) : [];
  const rest = blank(clean, /<dependencyManagement>[\s\S]*?<\/dependencyManagement>/g);
  const deps = pomDeps(rest, 0);
  // Project coordinates: the first top-level ones once nested blocks are removed.
  const top = blank(rest, /<(parent|dependencies|build|profiles|reporting|properties|repositories|pluginRepositories|distributionManagement|modules|developers|licenses|scm)>[\s\S]*?<\/\1>/g);
  return { path, text: clean, g: tag(top, 'groupId') ?? parent?.g, a: tag(top, 'artifactId'), v: tag(top, 'version') ?? parent?.v, parent, props, deps, managed };
}

interface Managed { version: string | null; via: string }

class MavenModel {
  private readonly byPath = new Map<string, Pom>();
  private readonly byCoord = new Map<string, Pom>();

  constructor(poms: Pom[]) {
    for (const p of poms) {
      this.byPath.set(p.path, p);
      if (p.g && p.a) this.byCoord.set(`${p.g}:${p.a}`, p);
    }
  }

  parentOf(p: Pom): Pom | null {
    if (!p.parent) return null;
    const rel = joinPath(dirOf(p.path), p.parent.relativePath);
    const candidate = this.byPath.get(rel.endsWith('.xml') ? rel : joinPath(rel, 'pom.xml'));
    const hit = candidate && candidate.g === p.parent.g && candidate.a === p.parent.a ? candidate : this.byCoord.get(`${p.parent.g}:${p.parent.a}`);
    return hit && hit !== p ? hit : null;
  }

  /** Ancestors, nearest first, stopping at cycles. */
  chain(p: Pom): Pom[] {
    const out: Pom[] = [];
    const seen = new Set<Pom>([p]);
    for (let cur = this.parentOf(p); cur && !seen.has(cur); cur = this.parentOf(cur)) {
      out.push(cur);
      seen.add(cur);
    }
    return out;
  }

  resolve(p: Pom, raw: string | undefined): string | null {
    if (!raw) return null;
    const ancestors = this.chain(p);
    const lookup = (k: string): string | undefined => {
      if (k === 'project.version' || k === 'pom.version' || k === 'version') return p.v;
      if (k === 'project.groupId' || k === 'pom.groupId') return p.g;
      if (k === 'project.parent.version' || k === 'parent.version') return p.parent?.v;
      for (const x of [p, ...ancestors]) if (x.props.has(k)) return x.props.get(k);
      return undefined;
    };
    let v = raw;
    for (let i = 0; i < 5 && v.includes('${'); i++) v = v.replace(/\$\{([\w.-]+)\}/g, (s, k: string) => lookup(k) ?? s);
    return v.includes('${') || !/\d/.test(v) ? null : v;
  }

  /** dependencyManagement in effect for `p`: inherited, own (child wins), then imported BOMs for missing keys. */
  managed(p: Pom, seen = new Set<Pom>()): { map: Map<string, Managed>; external: Coord[] } {
    const map = new Map<string, Managed>();
    const external: Coord[] = [];
    if (seen.has(p)) return { map, external };
    seen.add(p);
    const parent = this.parentOf(p);
    if (parent) {
      const up = this.managed(parent, seen);
      for (const [k, v] of up.map) map.set(k, v);
      external.push(...up.external);
    } else if (p.parent) {
      external.push({ g: p.parent.g, a: p.parent.a, v: this.resolve(p, p.parent.v ?? undefined) });
    }
    const imports: PomDep[] = [];
    for (const d of p.managed) {
      if (d.scope === 'import' && d.type === 'pom') { imports.push(d); continue; }
      map.set(`${d.g}:${d.a}`, { version: this.resolve(p, d.v), via: p.path });
    }
    for (const d of imports) {
      const version = this.resolve(p, d.v);
      const bom = this.byCoord.get(`${d.g}:${d.a}`);
      if (!bom) { external.push({ g: d.g, a: d.a, v: version }); continue; }
      const sub = this.managed(bom, seen);
      for (const [k, v] of sub.map) if (!map.has(k)) map.set(k, v);
      external.push(...sub.external);
    }
    return { map, external };
  }
}

function mavenDeclared(files: { path: string; text: string }[]): Declared[] {
  const poms = files.map((f) => parsePom(f.path, f.text));
  const model = new MavenModel(poms);
  const out: Declared[] = [];
  for (const p of poms) {
    const { map, external } = model.managed(p);
    for (const d of p.deps) {
      const name = `${d.g}:${d.a}`;
      const line = lineOf(p.text, d.index);
      if (d.v) {
        const v = model.resolve(p, d.v);
        out.push({ ecosystem: 'maven', name, version: v, path: p.path, line, ...(v && d.v.includes('${') ? { via: `属性 ${d.v}` } : {}) });
        continue;
      }
      const m = map.get(name);
      if (m?.version) { out.push({ ecosystem: 'maven', name, version: m.version, path: p.path, line, via: m.via === p.path ? 'dependencyManagement' : `${m.via} 的 dependencyManagement` }); continue; }
      const aligned = alignedVersion(external, d.g);
      if (aligned) { out.push({ ecosystem: 'maven', name, version: aligned.version, path: p.path, line, via: `BOM ${aligned.via}` }); continue; }
      out.push({ ecosystem: 'maven', name, version: null, path: p.path, line, ...(external.length ? { managedBy: external.map((e) => `${e.g}:${e.a}${e.v ? `:${e.v}` : ''}`) } : {}) });
    }
  }
  return out;
}

// ---- Gradle -----------------------------------------------------------------------------------------------

const GRADLE_CONFIGS = 'implementation|api|compile|compileOnly|runtimeOnly|runtime|testImplementation|testCompile|testRuntimeOnly|annotationProcessor|kapt|classpath|developmentOnly|providedCompile|providedRuntime';

/** Variables a build may use in dependency strings: gradle.properties, `ext`, `extra`, Kotlin `val`. */
function gradleVars(files: { path: string; text: string }[]): Map<string, string> {
  const vars = new Map<string, string>();
  for (const f of files) {
    if (f.path.endsWith('gradle.properties')) {
      for (const m of f.text.matchAll(/^\s*([\w.-]+)\s*[=:]\s*(\S+)\s*$/gm)) vars.set(m[1]!, m[2]!);
      continue;
    }
    for (const m of f.text.matchAll(/(?:^|[\s{;])(?:ext\.|val\s+|def\s+|var\s+)?([A-Za-z_][\w]*)\s*=\s*['"]([\w.+-]+)['"]/gm)) if (!vars.has(m[1]!)) vars.set(m[1]!, m[2]!);
    for (const m of f.text.matchAll(/(?:extra\[|set\(\s*)['"]([\w.-]+)['"]\s*(?:\]\s*=|,)\s*['"]([\w.+-]+)['"]/g)) vars.set(m[1]!, m[2]!);
  }
  return vars;
}

function substitute(raw: string, vars: Map<string, string>): string | null {
  const v = raw.replace(/\$\{?([A-Za-z_][\w.]*)\}?/g, (s, k: string) => vars.get(k) ?? vars.get(k.replace(/^(project|rootProject)\./, '')) ?? s);
  const clean = v.split(/[:@]/)[0]!;
  return clean.includes('$') || !/\d/.test(clean) ? null : clean;
}

/** Minimal line-based reader for Gradle version catalogs (`[versions]` / `[libraries]`, inline tables). */
function catalogDeclared(path: string, text: string): Declared[] {
  const versions = new Map<string, string>();
  const libs: { key: string; body: string; index: number }[] = [];
  let section = '';
  let offset = 0;
  for (const raw of text.split('\n')) {
    const lineStart = offset;
    offset += raw.length + 1;
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    const sec = /^\[([\w.-]+)\]$/.exec(line);
    if (sec) { section = sec[1]!; continue; }
    const kv = /^["']?([\w.-]+)["']?\s*=\s*(.+)$/.exec(line);
    if (!kv) continue;
    if (section === 'versions') {
      const plain = /^["']([^"']+)["']$/.exec(kv[2]!)?.[1] ?? /(?:strictly|require|prefer)\s*=\s*["']([^"']+)["']/.exec(kv[2]!)?.[1];
      if (plain) versions.set(kv[1]!, plain.replace(/!!.*$/, ''));
    } else if (section === 'libraries') {
      libs.push({ key: kv[1]!, body: kv[2]!, index: lineStart });
    }
  }
  const out: Declared[] = [];
  for (const l of libs) {
    const str = /^["']([^"']+)["']$/.exec(l.body)?.[1];
    let g: string | undefined; let a: string | undefined; let v: string | null; let via: string | undefined;
    if (str) {
      [g, a] = str.split(':');
      v = str.split(':')[2] ?? null;
    } else {
      const f = (k: string) => new RegExp(`(?:^|[{,\\s])${k.replace('.', '\\.')}\\s*=\\s*["']([^"']+)["']`).exec(l.body)?.[1];
      const module = f('module');
      [g, a] = module ? module.split(':') : [f('group'), f('name')];
      const ref = f('version.ref') ?? /version\s*=\s*\{\s*ref\s*=\s*["']([^"']+)["']/.exec(l.body)?.[1];
      if (ref) { v = versions.get(ref) ?? null; via = `版本目录 ${path}（${ref}）`; }
      else v = f('version') ?? /version\s*=\s*\{[^}]*?(?:strictly|require|prefer)\s*=\s*["']([^"']+)["']/.exec(l.body)?.[1] ?? null;
    }
    if (!g || !a) continue;
    out.push({ ecosystem: 'maven', name: `${g}:${a}`, version: v && /\d/.test(v) ? v.replace(/!!.*$/, '') : null, path, line: lineOf(text, l.index), ...(via ? { via } : {}) });
  }
  return out;
}

function gradleDeclared(files: { path: string; text: string }[]): Declared[] {
  const vars = gradleVars(files);
  const out: Declared[] = [];
  const boms: Coord[] = [];
  const builds = files.filter((f) => /\.gradle(\.kts)?$/.test(f.path));
  // Platforms / imported BOMs / the Spring Boot plugin manage versions of version-less declarations.
  for (const f of builds) {
    for (const m of f.text.matchAll(/(?:platform|enforcedPlatform|mavenBom)\s*\(?\s*['"]([\w.-]+):([\w.-]+):([^'"\s]+)['"]/g)) boms.push({ g: m[1]!, a: m[2]!, v: substitute(m[3]!, vars) });
    const boot = /id\s*\(?\s*['"]org\.springframework\.boot['"]\s*\)?\s*version\s*\(?\s*['"]([^'"]+)['"]/.exec(f.text);
    if (boot) boms.push({ g: 'org.springframework.boot', a: 'spring-boot-dependencies', v: substitute(boot[1]!, vars) });
  }
  for (const f of builds) {
    for (const m of f.text.matchAll(/['"]([\w.-]+):([\w.-]+):([^'"\s]+)['"]/g)) {
      const raw = m[3]!;
      const version = substitute(raw, vars);
      out.push({ ecosystem: 'maven', name: `${m[1]}:${m[2]}`, version, path: f.path, line: lineOf(f.text, m.index ?? 0), ...(version && raw.includes('$') ? { via: `变量 ${raw}` } : {}) });
    }
    for (const m of f.text.matchAll(/group\s*[:=]\s*['"]([\w.-]+)['"]\s*,\s*name\s*[:=]\s*['"]([\w.-]+)['"](?:\s*,\s*version\s*[:=]\s*['"]([^'"]+)['"])?/g)) {
      const version = m[3] ? substitute(m[3], vars) : null;
      out.push({ ecosystem: 'maven', name: `${m[1]}:${m[2]}`, version, path: f.path, line: lineOf(f.text, m.index ?? 0) });
    }
    // Version-less declarations: the version comes from a platform / BOM.
    for (const m of f.text.matchAll(new RegExp(`\\b(?:${GRADLE_CONFIGS})\\s*\\(?\\s*['"]([\\w.-]+):([\\w.-]+)['"]`, 'g'))) {
      const aligned = alignedVersion(boms, m[1]!);
      const line = lineOf(f.text, m.index ?? 0);
      if (aligned) out.push({ ecosystem: 'maven', name: `${m[1]}:${m[2]}`, version: aligned.version, path: f.path, line, via: `BOM ${aligned.via}` });
      else out.push({ ecosystem: 'maven', name: `${m[1]}:${m[2]}`, version: null, path: f.path, line, ...(boms.length ? { managedBy: boms.map((b) => `${b.g}:${b.a}${b.v ? `:${b.v}` : ''}`) } : {}) });
    }
  }
  return out;
}

// ---- Go ---------------------------------------------------------------------------------------------------

function goDeps(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  for (const m of text.matchAll(/^\s*(?:require\s+)?([\w.-]+\.[\w.-]+\/[\w./-]+)\s+(v[\w.+-]+)/gm)) out.push({ ecosystem: 'go', name: m[1]!, version: m[2]!, path, line: lineOf(text, m.index ?? 0) });
  return out;
}

// ---- npm --------------------------------------------------------------------------------------------------

function packageJsonDeps(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  let j: Record<string, unknown>;
  try { j = JSON.parse(text) as Record<string, unknown>; } catch { return out; }
  for (const sec of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    for (const [name, spec] of Object.entries((j[sec] ?? {}) as Record<string, string>)) {
      const idx = text.indexOf(`"${name}"`);
      const v = /(\d+(?:\.\d+){0,3}(?:-[\w.]+)?)/.exec(String(spec))?.[1] ?? null;
      out.push({ ecosystem: 'npm', name, version: v, path, line: idx >= 0 ? lineOf(text, idx) : 0 });
    }
  }
  return out;
}

function packageLockDeps(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  let j: Record<string, unknown>;
  try { j = JSON.parse(text) as Record<string, unknown>; } catch { return out; }
  for (const [k, v] of Object.entries((j.packages ?? {}) as Record<string, { version?: string }>)) {
    const name = k.replace(/^.*node_modules\//, '');
    if (name && v?.version) out.push({ ecosystem: 'npm', name, version: v.version, path, line: 0 });
  }
  // lockfileVersion 1: nested `dependencies`.
  const walk = (deps: unknown) => {
    for (const [name, v] of Object.entries((deps ?? {}) as Record<string, { version?: string; dependencies?: unknown }>)) {
      if (v?.version && /\d/.test(v.version)) out.push({ ecosystem: 'npm', name, version: v.version, path, line: 0 });
      walk(v?.dependencies);
    }
  };
  if (!j.packages) walk(j.dependencies);
  return out;
}

/** Package name of a yarn.lock descriptor: `lodash@^4.17.0`, `"@babel/core@npm:^7.0.0"`. */
function descriptorName(spec: string): string | null {
  const s = spec.trim().replace(/^["']|["']$/g, '');
  const at = s.indexOf('@', 1);
  return at > 0 ? s.slice(0, at) : null;
}

function yarnLockDeps(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  let names: string[] = [];
  let index = 0;
  let offset = 0;
  for (const line of text.split('\n')) {
    const start = offset;
    offset += line.length + 1;
    if (!line.trim() || line.startsWith('#')) continue;
    if (!/^\s/.test(line) && line.trimEnd().endsWith(':')) {
      if (line.startsWith('__metadata')) { names = []; continue; }
      names = [...new Set(line.trimEnd().slice(0, -1).split(',').map(descriptorName).filter((n): n is string => !!n))];
      index = start;
      continue;
    }
    const v = /^\s+version:?\s+["']?([^"'\s]+)["']?\s*$/.exec(line);
    if (v && names.length) {
      for (const name of names) out.push({ ecosystem: 'npm', name, version: v[1]!, path, line: lineOf(text, index) });
      names = [];
    }
  }
  return out;
}

/** pnpm-lock.yaml package keys: `/name/1.0.0` (v5), `/name@1.0.0(peer)` (v6), `name@1.0.0` (v9). */
function pnpmKey(key: string): { name: string; version: string } | null {
  const k = key.replace(/^\//, '').replace(/\(.*$/, '');
  // v5 first: its peer suffix (`_bufferutil@4.0.0`) also contains `@`.
  const v5 = /^((?:@[^/]+\/)?[^/@]+)\/(\d[^/]*)$/.exec(k);
  if (v5) return { name: v5[1]!, version: v5[2]!.replace(/_.*$/, '') };
  const at = k.indexOf('@', 1);
  return at > 0 ? { name: k.slice(0, at), version: k.slice(at + 1) } : null;
}

function pnpmLockDeps(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  let j: Record<string, unknown>;
  try { j = parseYaml(text, { maxAliasCount: 50, logLevel: 'silent' }) as Record<string, unknown>; } catch { return out; }
  if (!j || typeof j !== 'object') return out;
  const seen = new Set<string>();
  for (const key of Object.keys((j.packages ?? {}) as Record<string, unknown>)) {
    const p = pnpmKey(key);
    if (!p || !/\d/.test(p.version) || seen.has(`${p.name}@${p.version}`)) continue;
    seen.add(`${p.name}@${p.version}`);
    const idx = text.indexOf(key);
    out.push({ ecosystem: 'npm', name: p.name, version: p.version, path, line: idx >= 0 ? lineOf(text, idx) : 0 });
  }
  return out;
}

const LOCK_READERS: Record<string, (path: string, text: string) => Declared[]> = {
  'package-lock.json': packageLockDeps,
  'npm-shrinkwrap.json': packageLockDeps,
  'yarn.lock': yarnLockDeps,
  'pnpm-lock.yaml': pnpmLockDeps,
};

/** A lock file resolves the ranges of manifest files in its directory and below (workspaces). */
function lockedDeclared(manifests: Declared[], locks: Declared[]): Declared[] {
  const locked = new Map<string, string[]>();
  for (const l of locks) locked.set(l.name, [...(locked.get(l.name) ?? []), dirOf(l.path)]);
  const covered = (d: Declared) => (locked.get(d.name) ?? []).some((dir) => !dir || d.path.startsWith(`${dir}/`));
  return [...manifests.filter((d) => !covered(d)), ...locks];
}

// ---- entry ------------------------------------------------------------------------------------------------

export function declaredDependencies(view: SnapshotView): Declared[] {
  const poms: { path: string; text: string }[] = [];
  const gradle: { path: string; text: string }[] = [];
  const out: Declared[] = [];
  const manifests: Declared[] = [];
  const locks: Declared[] = [];
  const extra = new Map(READERS.map((r) => [r, { manifests: [] as Declared[], locks: [] as Declared[] }]));
  for (const f of view.listFiles()) {
    if (f.path.includes('node_modules/')) continue;
    const base = f.path.split('/').pop()!;
    const reader = READERS.find((r) => r.kind(base));
    if (reader) {
      const k = reader.kind(base)!;
      if (f.size > (k === 'lock' ? MAX_LOCK_FILE : MAX_BUILD_FILE)) continue;
      try {
        const got = reader.read(f.path, view.text(f.path));
        extra.get(reader)![k === 'lock' ? 'locks' : 'manifests'].push(...got);
      } catch { /* unreadable: skipped like any other build file */ }
      continue;
    }
    const lock = LOCK_READERS[base];
    const kind = base === 'pom.xml' ? 'pom'
      : /\.gradle(\.kts)?$/.test(base) || base === 'gradle.properties' ? 'gradle'
        : base.endsWith('.versions.toml') ? 'catalog'
          : base === 'go.mod' ? 'go' : base === 'package.json' ? 'npm' : lock ? 'lock' : null;
    if (!kind || f.size > (kind === 'lock' ? MAX_LOCK_FILE : MAX_BUILD_FILE)) continue;
    let text: string;
    try { text = view.text(f.path); } catch { continue; }
    if (kind === 'pom') poms.push({ path: f.path, text });
    else if (kind === 'gradle') gradle.push({ path: f.path, text });
    else if (kind === 'catalog') out.push(...catalogDeclared(f.path, text));
    else if (kind === 'go') out.push(...goDeps(f.path, text));
    else if (kind === 'npm') manifests.push(...packageJsonDeps(f.path, text));
    else locks.push(...lock!(f.path, text));
  }
  return [
    ...mavenDeclared(poms), ...gradleDeclared(gradle), ...out, ...lockedDeclared(manifests, locks),
    ...[...extra.values()].flatMap((e) => lockedDeclared(e.manifests, e.locks)),
  ];
}
