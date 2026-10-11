#!/usr/bin/env node
/* global console, process */
// Assembles the npm package `xiezhi-audit` in release/xiezhi-audit from a built checkout (run `pnpm build` first;
// `pnpm release:pack` does both and packs the result):
//   dist/main.js, dist/worker.js   the workspace packages bundled by esbuild; third-party packages stay dependencies
//   bin/xiezhi.js                  the command
//   rules/ skills/ connector-packs/ web/   resources, found at run time by resourceRoot()
//   grammars/*.wasm + versions.json        tree-sitter grammars without the grammar packages, whose install
//                                          scripts would try to compile native bindings on the user's machine
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, join } from 'node:path';
import { build } from 'esbuild';

const ROOT = join(import.meta.dirname, '..');
const OUT = join(ROOT, 'release', 'xiezhi-audit');
const NAME = 'xiezhi-audit';
const readJson = (p) => JSON.parse(readFileSync(p, 'utf8'));
const fail = (msg) => { console.error(`build-release: ${msg}`); process.exit(1); };

const root = readJson(join(ROOT, 'package.json'));
// The packages the CLI runs (the browser app is shipped as built files in web/).
const workspace = ['apps/cli', 'apps/server', 'apps/eval', ...readdirSync(join(ROOT, 'packages')).map((d) => `packages/${d}`)]
  .filter((d) => existsSync(join(ROOT, d, 'package.json')));
const isGrammar = (name) => /(^|\/)tree-sitter-/.test(name);

// Third-party runtime dependencies of the bundled code; the same package must be pinned to one version everywhere.
const deps = {};
for (const dir of workspace) {
  const pkg = readJson(join(ROOT, dir, 'package.json'));
  for (const [name, version] of Object.entries(pkg.dependencies ?? {})) {
    if (name.startsWith('@xiezhi/') || isGrammar(name)) continue;
    if (deps[name] && deps[name] !== version) fail(`${name} is pinned to ${deps[name]} and ${version} in different packages`);
    deps[name] = version;
  }
}

for (const p of ['apps/cli/dist/main.js', 'packages/context/dist/index/worker.js', 'apps/web/dist/index.html']) {
  if (!existsSync(join(ROOT, p))) fail(`${p} is missing; run pnpm build first`);
}
rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

// worker.js sits next to main.js: the index pool loads it with new URL('./worker.js', import.meta.url).
await build({
  absWorkingDir: ROOT,
  entryPoints: { main: 'apps/cli/dist/main.js', worker: 'packages/context/dist/index/worker.js' },
  outdir: join(OUT, 'dist'),
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  external: Object.keys(deps).flatMap((d) => [d, `${d}/*`]),
  logLevel: 'warning',
});

// The grammars, from the context package's resolution of them.
const { GRAMMARS } = await import(join(ROOT, 'packages/context/dist/index/grammar.js'));
const requireCtx = createRequire(join(ROOT, 'packages/context/package.json'));
const versions = {};
mkdirSync(join(OUT, 'grammars'));
for (const g of Object.values(GRAMMARS)) {
  const wasm = requireCtx.resolve(g.wasm);
  cpSync(wasm, join(OUT, 'grammars', basename(wasm)));
  versions[basename(wasm)] = readJson(requireCtx.resolve(`${g.pkg}/package.json`)).version;
}
writeFileSync(join(OUT, 'grammars', 'versions.json'), JSON.stringify(versions, null, 2) + '\n');

for (const d of ['rules', 'skills', 'connector-packs']) cpSync(join(ROOT, d), join(OUT, d), { recursive: true });
cpSync(join(ROOT, 'apps/web/dist'), join(OUT, 'web'), { recursive: true });
for (const f of ['LICENSE', 'README.md']) cpSync(join(ROOT, f), join(OUT, f));

mkdirSync(join(OUT, 'bin'));
writeFileSync(join(OUT, 'bin', 'xiezhi.js'), `#!/usr/bin/env node
// node:sqlite still prints an ExperimentalWarning on Node 22 / 24; it says nothing a CLI user can act on.
const emitWarning = process.emitWarning;
process.emitWarning = function (warning, ...rest) {
  const type = typeof rest[0] === 'string' ? rest[0] : rest[0]?.type;
  if (type === 'ExperimentalWarning' && /SQLite/.test(String(warning?.message ?? warning))) return;
  return emitWarning.call(process, warning, ...rest);
};
const { runCli } = await import('../dist/main.js');
await runCli(process.argv.slice(2));
`, { mode: 0o755 });

writeFileSync(join(OUT, 'package.json'), JSON.stringify({
  name: NAME,
  version: root.version,
  description: '獬豸 Xiezhi：本机运行的 AI 代码安全审计 Agent（静态审计，支持 Java / Go / Python / JS / TS / PHP / Kotlin / C# / Ruby / Rust）',
  keywords: ['security', 'audit', 'sast', 'code-review', 'llm', 'agent'],
  license: 'MIT',
  repository: { type: 'git', url: 'git+https://github.com/Dynamic-Security/xiezhi-audit.git' },
  type: 'module',
  bin: { xiezhi: 'bin/xiezhi.js' },
  engines: root.engines,
  files: ['bin', 'dist', 'grammars', 'rules', 'skills', 'connector-packs', 'web'],
  dependencies: Object.fromEntries(Object.entries(deps).sort(([a], [b]) => a.localeCompare(b))),
}, null, 2) + '\n');

console.log(`build-release: ${NAME}@${root.version} → ${OUT}`);
