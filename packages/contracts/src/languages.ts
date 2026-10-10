// Audit languages: the single list of languages that get a full audit, with the language-level
// facts other packages share (file ids, ecosystems, framework ids, test-file patterns, backend markers).
// Parsers, rules and language servers live in @xiezhi/context (index/languages.ts); this table is pure data.

/** Languages with a full audit. Ids equal the snapshot file language ids (`detectLang`). */
// Ruby and Rust appended (order is the display order).
export const AUDIT_LANGUAGES = ['java', 'go', 'python', 'javascript', 'typescript', 'php', 'kotlin', 'csharp', 'ruby', 'rust'] as const;
export type AuditLanguage = (typeof AUDIT_LANGUAGES)[number];

/** Dependency ecosystems of risk hunting and of the declared-dependency reader. */
export const DEPENDENCY_ECOSYSTEMS = ['maven', 'go', 'npm', 'pypi', 'composer', 'nuget', 'rubygems', 'cargo'] as const;
export type DependencyEcosystem = (typeof DEPENDENCY_ECOSYSTEMS)[number];

export interface AuditLanguageInfo {
  id: AuditLanguage;
  /** Display name. */
  label: string;
  /** Glob for ripgrep (`--glob`) selecting this language's source files. */
  glob: string;
  ecosystems: readonly DependencyEcosystem[];
  /** Framework ids the index reports as `EntryPoint.framework` (also the knowledge `applies_to.frameworks` ids). */
  frameworks: readonly string[];
  /** Test sources (lower triage priority). */
  testPath: RegExp;
  /**
   * JS / TS and Rust: a repository counts as auditable only when a manifest (package.json / Cargo.toml) declares one
   * of these server-side dependencies; otherwise it is a frontend, CLI or library — a context
   * repository.
   */
  backendDependencies?: readonly string[];
}

/**
 * servers that are not web frameworks — sockets, queue consumers, timed jobs — count as backends too. CLI
 * libraries (commander, yargs) do not: frontend build tooling depends on them as well.
 */
const SERVICE_DEPENDENCIES = [
  'socket.io', 'ws', 'uWebSockets.js', 'express-ws', '@fastify/websocket', '@nestjs/websockets', '@nestjs/microservices', '@nestjs/schedule', '@nestjs/bull', '@nestjs/bullmq',
  'kafkajs', 'amqplib', 'amqp-connection-manager', 'bull', 'bullmq', 'ioredis', 'redis', 'node-cron', 'cron', 'node-schedule',
  // gRPC servers (a Node service that only speaks gRPC is a backend).
  '@grpc/grpc-js', 'grpc',
];

/** Rust crates that make a repository a server (not `hyper` alone: HTTP clients depend on it too). */
export const RUST_SERVER_DEPENDENCIES = ['axum', 'actix-web', 'rocket', 'warp', 'poem', 'tonic', 'salvo', 'tide', 'gotham', 'ntex', 'loco-rs'] as const;

/**
 * Dependency names of a Cargo.toml (`[dependencies]`, `[workspace.dependencies]`, `[target.….dependencies]` and
 * `[dependencies.<name>]` tables; dev- and build-dependencies excluded). Line-based, no TOML parser.
 */
export function cargoDependencyNames(text: string): string[] {
  const out = new Set<string>();
  let inDeps = false;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/#.*$/, '').trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      const h = header[1]!.trim();
      const table = /^(?:workspace\.|target\.[^.]+(?:\.[^.]+)*?\.)?dependencies\.([\w-]+)$/.exec(h);
      if (table) { out.add(table[1]!); inDeps = false; continue; }
      inDeps = /^(?:workspace\.|target\..+\.)?dependencies$/.test(h);
      continue;
    }
    if (!inDeps) continue;
    const kv = /^([\w-]+)\s*=/.exec(line);
    if (kv) out.add(kv[1]!);
  }
  return [...out];
}

/** Whether a Rust crate's declared dependencies include a server framework. */
export function isRustBackend(dependencies: Iterable<string>): boolean {
  const markers = new Set<string>(RUST_SERVER_DEPENDENCIES);
  for (const d of dependencies) if (markers.has(d)) return true;
  return false;
}

export const AUDIT_LANGUAGE_INFO: Record<AuditLanguage, AuditLanguageInfo> = {
  java: {
    id: 'java', label: 'Java', glob: '*.java', ecosystems: ['maven'], frameworks: ['spring', 'mybatis', 'jdbc', 'jaxrs', 'grpc', 'servlet', 'struts2', 'jsp', 'webflux', 'vertx'],
    testPath: /(^|\/)src\/test\/|Tests?\.java$/,
  },
  go: {
    id: 'go', label: 'Go', glob: '*.go', ecosystems: ['go'], frameworks: ['gin', 'echo', 'nethttp', 'chi', 'flamego', 'fiber', 'hertz', 'grpc', 'beego', 'go-zero', 'kratos', 'grpc-gateway'],
    testPath: /_test\.go$/,
  },
  python: {
    id: 'python', label: 'Python', glob: '*.py', ecosystems: ['pypi'], frameworks: ['django', 'flask', 'fastapi', 'tornado', 'aiohttp', 'sanic', 'falcon'],
    testPath: /(^|\/)(tests?\/|test_[^/]*\.py$|[^/]*_test\.py$|conftest\.py$)/,
  },
  javascript: {
    id: 'javascript', label: 'JavaScript', glob: '*.{js,jsx,mjs,cjs}', ecosystems: ['npm'], frameworks: ['express', 'koa', 'nestjs', 'fastify', 'hapi', 'restify', 'egg', 'midway', 'nextjs', 'nuxt'],
    testPath: /(^|\/)(__tests__|tests?)\/|\.(test|spec)\.[cm]?jsx?$/,
    // standalone GraphQL servers count as backends too.
    backendDependencies: ['express', 'koa', '@koa/router', 'koa-router', '@nestjs/core', 'fastify', '@hapi/hapi', 'hapi', 'restify', 'egg', '@midwayjs/core',
      '@apollo/server', 'apollo-server', 'apollo-server-express', 'graphql-yoga', 'mercurius', '@nestjs/graphql', 'type-graphql', 'graphql-http', 'express-graphql',
      ...SERVICE_DEPENDENCIES],
  },
  typescript: {
    id: 'typescript', label: 'TypeScript', glob: '*.{ts,tsx,mts,cts}', ecosystems: ['npm'], frameworks: ['express', 'koa', 'nestjs', 'fastify', 'hapi', 'restify', 'egg', 'midway', 'nextjs', 'nuxt'],
    testPath: /(^|\/)(__tests__|tests?)\/|\.(test|spec)\.[cm]?tsx?$/,
    // standalone GraphQL servers count as backends too.
    backendDependencies: ['express', 'koa', '@koa/router', 'koa-router', '@nestjs/core', 'fastify', '@hapi/hapi', 'hapi', 'restify', 'egg', '@midwayjs/core',
      '@apollo/server', 'apollo-server', 'apollo-server-express', 'graphql-yoga', 'mercurius', '@nestjs/graphql', 'type-graphql', 'graphql-http', 'express-graphql',
      ...SERVICE_DEPENDENCIES],
  },
  php: {
    id: 'php', label: 'PHP', glob: '*.{php,phtml}', ecosystems: ['composer'], frameworks: ['laravel', 'symfony', 'thinkphp', 'php', 'wordpress', 'yii', 'codeigniter', 'slim'],
    testPath: /(^|\/)tests?\/|Test\.php$/,
  },
  kotlin: {
    id: 'kotlin', label: 'Kotlin', glob: '*.kt', ecosystems: ['maven'], frameworks: ['spring', 'ktor'],
    testPath: /(^|\/)src\/test\/|Tests?\.kt$/,
  },
  csharp: {
    id: 'csharp', label: 'C#', glob: '*.cs', ecosystems: ['nuget'], frameworks: ['aspnetcore', 'grpc', 'signalr'],
    testPath: /(^|\/)[^/]*\.Tests?\/|Tests?\.cs$/,
  },
  // Ruby counts by share like Python; Rust only with a declared server framework.
  ruby: {
    id: 'ruby', label: 'Ruby', glob: '*.rb', ecosystems: ['rubygems'], frameworks: ['rails', 'sinatra', 'grape'],
    testPath: /(^|\/)(spec|test)\/|_(spec|test)\.rb$/,
  },
  rust: {
    id: 'rust', label: 'Rust', glob: '*.rs', ecosystems: ['cargo'], frameworks: ['axum', 'actix-web', 'rocket'],
    testPath: /(^|\/)(tests|benches)\/|_test\.rs$|(^|\/)tests\.rs$/,
    backendDependencies: RUST_SERVER_DEPENDENCIES,
  },
};

export function isAuditLanguage(lang: string): lang is AuditLanguage {
  return (AUDIT_LANGUAGES as readonly string[]).includes(lang);
}

/** A language below this share of the repository's main audit language is incidental (scripts, tooling). */
export const MINOR_LANGUAGE_SHARE = 0.1;

/**
 * Audit languages of a repository, from per-language file counts:
 * - JS / TS count only when `jsBackend` says a manifest declares a server-side framework (unknown → not counted);
 *   Rust likewise with `rustBackend` (a Cargo.toml declares a server framework);
 *   they are one group (a TS backend with a few JS files is still one language family).
 * - Any other language with fewer files than MINOR_LANGUAGE_SHARE of the largest audit language is left out, so a
 *   Java service with a few Python scripts is audited as Java (the scripts stay readable as context).
 */
export function auditLanguagesOf(byLang: Record<string, number>, jsBackend = false, rustBackend = false): AuditLanguage[] {
  const group = (l: AuditLanguage) => (l === 'typescript' ? 'javascript' : l);
  const backend = (l: AuditLanguage) => !AUDIT_LANGUAGE_INFO[l].backendDependencies || (l === 'rust' ? rustBackend : jsBackend);
  const counts = new Map<string, number>();
  for (const l of AUDIT_LANGUAGES) {
    const n = byLang[l] ?? 0;
    if (n > 0 && backend(l)) counts.set(group(l), (counts.get(group(l)) ?? 0) + n);
  }
  const max = Math.max(0, ...counts.values());
  // Java / Go keep their original rule (any file counts), so existing repositories are indexed as before.
  return AUDIT_LANGUAGES.filter((l) => (byLang[l] ?? 0) > 0 && (counts.get(group(l)) ?? 0) >= (l === 'java' || l === 'go' ? 1 : Math.max(1, max * MINOR_LANGUAGE_SHARE)));
}

/** Every audit language with at least one file, without the share or JS-backend rules (a manual “auditable” setting). */
export function presentAuditLanguages(byLang: Record<string, number>): AuditLanguage[] {
  return AUDIT_LANGUAGES.filter((l) => (byLang[l] ?? 0) > 0);
}

/**
 * full-stack frameworks whose dependency alone does not make a backend — only server code does
 * (Next.js API routes / route handlers / Server Actions, Nuxt / Nitro server routes). A page-only app stays a frontend.
 */
export const FULLSTACK_DEPENDENCIES = ['next', 'nuxt', 'nitropack'] as const;

/** Next.js / Nuxt server-route files by path (`pages/api/…`, `app/…/route.*`, `server/api|routes/…`), optionally under `src/`. */
export function isFullstackServerPath(path: string): boolean {
  return /(^|\/)(src\/)?pages\/api\/[^]*\.[cm]?[jt]sx?$/.test(path)
    || /(^|\/)(src\/)?app\/(?:[^/]+\/)*route\.[cm]?[jt]s$/.test(path)
    || /(^|\/)server\/(api|routes)\/[^]*\.[cm]?[jt]s$/.test(path);
}

/** A `'use server'` directive at the top of a file (Next.js Server Actions module). */
export const USE_SERVER_DIRECTIVE_RE = /^(?:\s|\/\/[^\n]*\n|\/\*[^]*?\*\/)*(['"])use server\1/;

/** Whether any declared npm dependency marks a JS / TS backend. */
export function isJsBackend(dependencies: Iterable<string>): boolean {
  const markers = new Set(AUDIT_LANGUAGE_INFO.javascript.backendDependencies);
  for (const d of dependencies) if (markers.has(d)) return true;
  return false;
}

/** Display list, e.g. “Java、Go、Python…” (Chinese enumeration comma). */
export function auditLanguageLabels(): string {
  return [...new Set(AUDIT_LANGUAGES.map((l) => (l === 'typescript' ? null : AUDIT_LANGUAGE_INFO[l].label)).filter(Boolean))]
    .map((l) => (l === 'JavaScript' ? 'JavaScript/TypeScript' : l)).join('、');
}

/** Test source path in any audit language. */
export function isTestPath(path: string): boolean {
  return AUDIT_LANGUAGES.some((l) => AUDIT_LANGUAGE_INFO[l].testPath.test(path));
}
