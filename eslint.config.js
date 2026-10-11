// Package dependency red lines and exec governance.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

const ALL = ['contracts', 'store', 'context', 'knowledge', 'connectors', 'agent', 'engine', 'report', 'cli', 'server', 'web', 'eval'];
const ALLOWED = {
  contracts: [],
  store: ['contracts'],
  context: ['contracts', 'store'],
  knowledge: ['contracts', 'store'],
  // Same level as context / knowledge; stdio processes are launched through an injected launcher.
  connectors: ['contracts', 'store'],
  agent: ['contracts', 'store', 'context', 'knowledge', 'connectors'],
  engine: ['contracts', 'store', 'context', 'knowledge', 'connectors', 'agent', 'report'],
  report: ['contracts', 'store'],
  cli: ['contracts', 'store', 'context', 'knowledge', 'connectors', 'agent', 'engine', 'report', 'server', 'eval'],
  server: ['contracts', 'store', 'context', 'knowledge', 'connectors', 'agent', 'engine', 'report'],
  // Evaluation harness: same level as the CLI, drives the engine in-process.
  eval: ['contracts', 'store', 'context', 'knowledge', 'connectors', 'agent', 'engine', 'report'],
  // The browser app talks to the server over HTTP only; it may share contract *types*.
  web: ['contracts'],
};
const CHILD_PROCESS = ['child_process', 'node:child_process'];

function restrictions(pkg, allowChildProcess) {
  const forbidden = ALL.filter((p) => p !== pkg && !ALLOWED[pkg].includes(p));
  const paths = forbidden.map((p) => ({ name: `@xiezhi/${p}`, message: `${pkg} may not depend on ${p}.` }));
  if (!allowChildProcess) {
    for (const name of CHILD_PROCESS) paths.push({ name, message: 'Only packages/context/src/exec may spawn processes.' });
  }
  return ['error', {
    paths,
    patterns: [{ group: ['@xiezhi/*/*'], message: 'Deep imports into another package are forbidden.' },
      { group: ['../../*/src/*', '../../../packages/*'], message: 'Cross-package relative imports are forbidden.' }],
  }];
}

const FILES = { cli: ['apps/cli/src/**/*.ts'], server: ['apps/server/src/**/*.ts'], eval: ['apps/eval/src/**/*.ts'], web: ['apps/web/src/**/*.ts', 'apps/web/src/**/*.tsx'] };
const pkgConfigs = Object.keys(ALLOWED).map((pkg) => ({
  files: FILES[pkg] ?? [`packages/${pkg}/src/**/*.ts`],
  rules: { 'no-restricted-imports': restrictions(pkg, false) },
}));

export default tseslint.config(
  { ignores: ['**/dist/**', '**/node_modules/**', 'release/**', 'apps/web/vite.config.ts'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  ...pkgConfigs,
  { files: ['packages/context/src/exec/**/*.ts'], rules: { 'no-restricted-imports': restrictions('context', true) } },
  // The applications (server, cli, eval) shape responses; SQL and direct writes live in engine / store.
  {
    files: ['apps/server/src/**/*.ts', 'apps/cli/src/**/*.ts', 'apps/eval/src/**/*.ts'],
    rules: {
      'no-restricted-syntax': ['error',
        { selector: 'Literal[value=/^\\s*(SELECT\\s|INSERT\\s+(OR\\s+[A-Z]+\\s+)?INTO\\s|UPDATE\\s+[a-z_]+\\s+SET\\s|DELETE\\s+FROM\\s)/i]', message: 'No SQL in the applications: add a query to packages/engine/src/queries/.' },
        { selector: 'TemplateElement[value.raw=/^\\s*(SELECT\\s|INSERT\\s+(OR\\s+[A-Z]+\\s+)?INTO\\s|UPDATE\\s+[a-z_]+\\s+SET\\s|DELETE\\s+FROM\\s)/i]', message: 'No SQL in the applications: add a query to packages/engine/src/queries/.' },
        { selector: "CallExpression[callee.property.name=/^(insert|update|tx)$/][callee.object.name='store']", message: 'No direct writes in the applications: call an engine function.' },
        { selector: "MemberExpression[property.name='db'][object.name='store']", message: 'No raw database access in the applications.' },
      ],
    },
  },
  // Web may import contracts for types only (the contracts runtime depends on Node built-ins).
  {
    files: ['apps/web/src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': 'off',
      '@typescript-eslint/no-restricted-imports': ['error', {
        paths: [
          { name: '@xiezhi/contracts', allowTypeImports: true, message: 'web may import contracts types only (use `import type`).' },
          ...ALL.filter((p) => p !== 'contracts' && p !== 'web').map((p) => ({ name: `@xiezhi/${p}`, message: `web may not depend on ${p}; use the HTTP API.` })),
        ],
      }],
    },
  },
);
