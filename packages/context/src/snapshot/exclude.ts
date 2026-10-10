// Built-in exclusion lists. Settings may add rules, never remove these.
import picomatch from 'picomatch';
import type { ExcludeReason } from '@xiezhi/contracts';

const VCS_DIRS = new Set(['.git', '.hg', '.svn']);
const AGENT_CONTROL_DIRS = new Set(['.pi', '.claude', '.cursor', '.codex']);
const AGENT_CONTROL_FILES = new Set(['AGENTS.md', 'CLAUDE.md', 'GEMINI.md', '.cursorrules', '.windsurfrules', 'SKILL.md', '.mcp.json']);
const AGENT_CONTROL_PATHS = new Set(['.github/copilot-instructions.md']);
/** Build output and tool caches at any depth: these names are never source packages. */
const BUILD_DIRS = new Set([
  'node_modules', '.gradle', '.idea',
  // Python virtualenvs / caches (`bin/` is kept: often scripts).
  '__pycache__', '.venv', 'venv', '.tox', 'site-packages', '.mypy_cache', '.pytest_cache',
]);
/**
 * Names that are build output next to a build descriptor but are also ordinary package names
 * (Go `pkg/build`, Java `com/x/build`, `internal/target`). They are excluded at the repository root or in a directory
 * that has a build descriptor (a module root), and kept anywhere else.
 */
const MODULE_OUTPUT_DIRS = new Set(['target', 'build', 'vendor', 'dist', 'out', 'obj']);
const BUILD_DESCRIPTORS = new Set([
  'pom.xml', 'build.gradle', 'build.gradle.kts', 'settings.gradle', 'settings.gradle.kts', 'build.xml', 'build.sbt',
  'package.json', 'tsconfig.json', 'go.mod', 'Cargo.toml', 'composer.json', 'pyproject.toml', 'setup.py', 'setup.cfg',
  'CMakeLists.txt', 'Makefile',
]);
const BUILD_DESCRIPTOR_EXT = /\.(csproj|fsproj|vbproj|sln)$/i;

function isModuleRoot(parentFiles: Iterable<string>): boolean {
  for (const f of parentFiles) if (BUILD_DESCRIPTORS.has(f) || BUILD_DESCRIPTOR_EXT.test(f)) return true;
  return false;
}
const SENSITIVE = picomatch(['.env', '.env.*', '*.pem', '*.key', 'id_rsa*', '*.p12', '*.jks', '.npmrc', '.netrc'], { dot: true, nocase: true });
/**
 * Secret files recognised by name (`credentials`, `credentials.json`, `.aws/credentials`, `kubeconfig`,
 * `prod.kubeconfig`, `kubeconfig.yaml`). A source file whose name merely starts with / contains the
 * word (`CredentialsController.java`, `credentials_service.py`, `KubeconfigHandler.go`) is code, not a secret.
 */
const SENSITIVE_BY_NAME = picomatch(['credentials*', '*kubeconfig*'], { dot: true, nocase: true });
/** Programming-language ids (`detectLang`) whose files are source code; config and data formats are not listed. */
const SOURCE_LANGS = new Set([
  'java', 'go', 'kotlin', 'scala', 'groovy', 'typescript', 'javascript', 'vue', 'python', 'ruby', 'php', 'rust', 'solidity', 'c', 'cpp', 'csharp', 'proto',
]);

/** Whether a file name marks a secret file the snapshot never contains. */
export function isSensitiveName(name: string): boolean {
  if (SENSITIVE(name)) return true;
  if (!SENSITIVE_BY_NAME(name)) return false;
  const lang = detectLang(name);
  return !(lang && SOURCE_LANGS.has(lang));
}

export interface ExcludeOptions {
  /** Include vendor/ (Go vendoring, PHP Composer; strategy switch). */
  includeVendor?: boolean;
  extraGlobs?: string[];
}

export function makeExcluder(opts: ExcludeOptions = {}) {
  const extra = opts.extraGlobs?.length ? picomatch(opts.extraGlobs, { dot: true }) : null;
  return {
    /**
     * Directory-level decision (path is POSIX relative, name is the basename). `parentFiles` are the names of the
     * files next to the directory; without them a module-output name is excluded at any depth (the old rule).
     */
    dir(path: string, name: string, parentFiles?: Iterable<string>): ExcludeReason | null {
      if (VCS_DIRS.has(name)) return 'vcs';
      if (AGENT_CONTROL_DIRS.has(name)) return 'agent_control';
      if (BUILD_DIRS.has(name)) return 'build_output';
      if (MODULE_OUTPUT_DIRS.has(name) && !(name === 'vendor' && opts.includeVendor)
        && (!path.includes('/') || !parentFiles || isModuleRoot(parentFiles))) return 'build_output';
      if (extra?.(path) || extra?.(`${path}/`)) return 'scope';
      return null;
    },
    file(path: string, name: string): ExcludeReason | null {
      if (AGENT_CONTROL_FILES.has(name) || AGENT_CONTROL_PATHS.has(path)) return 'agent_control';
      if (isSensitiveName(name)) return 'sensitive';
      if (extra?.(path)) return 'scope';
      return null;
    },
  };
}

export const MAX_FILE_BYTES = 5 * 1024 * 1024;

export function isBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 8192);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

const LANGS: Record<string, string> = {
  java: 'java', go: 'go', kt: 'kotlin', scala: 'scala', groovy: 'groovy', ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript',
  js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript', vue: 'vue', py: 'python', pyi: 'python', rb: 'ruby', php: 'php', phtml: 'php',
  rs: 'rust', sol: 'solidity', c: 'c', h: 'c', cc: 'cpp', cpp: 'cpp', cs: 'csharp', proto: 'proto', xml: 'xml',
  yaml: 'yaml', yml: 'yaml', json: 'json', properties: 'properties', sql: 'sql', html: 'html', md: 'markdown',
  gradle: 'gradle', toml: 'toml', sh: 'shell', mod: 'gomod',
};

export function detectLang(path: string): string | undefined {
  const base = path.split('/').pop() ?? '';
  if (base === 'go.mod') return 'gomod';
  if (base === 'pom.xml') return 'maven';
  const ext = base.includes('.') ? base.split('.').pop()!.toLowerCase() : '';
  return LANGS[ext];
}
