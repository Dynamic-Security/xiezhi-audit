#!/usr/bin/env node
/* global console, fetch, process, setTimeout */
// Smoke test of an installed xiezhi-audit package (the release workflow runs it after `npm install -g` of the
// packed tarball; locally: `node scripts/smoke-package.mjs <version> [path/to/xiezhi]`). Uses a throwaway data dir
// and no model: checks the version, that no warning leaks to stderr, that doctor finds rg / git / sqlite and loads
// every grammar and the rules, that a read-only command works on a new data dir, and that serve answers.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [version, bin = 'xiezhi'] = process.argv.slice(2);
if (!version) { console.error('usage: smoke-package.mjs <expected version> [xiezhi binary]'); process.exit(2); }
const dataDir = mkdtempSync(join(tmpdir(), 'xiezhi-smoke-'));
const env = { ...process.env, XIEZHI_AUDIT_DATA_DIR: dataDir };
let failed = 0;
const check = (ok, what, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${ok || !detail ? '' : `\n     ${detail}`}`);
  if (!ok) failed++;
};
const run = (args) => {
  try {
    return { code: 0, stdout: execFileSync(bin, args, { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }), stderr: '' };
  } catch (e) {
    return { code: e.status ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? String(e) };
  }
};

try {
  const v = run(['--version']);
  check(v.stdout.trim() === version, `version ${version}`, `got ${JSON.stringify(v.stdout.trim())}`);
  check(!v.stderr.trim(), 'nothing on stderr (node:sqlite warning hidden)', v.stderr.trim());

  // doctor exits non-zero without a model; its JSON is what is checked.
  const checks = JSON.parse(run(['doctor', '--json']).stdout);
  const level = (name) => checks.find((c) => c.name === name);
  for (const name of ['node', 'sqlite', 'rg', 'git', 'tree-sitter']) {
    const c = level(name);
    check(c?.level === 'ok', `doctor ${name}`, c ? `${c.level}: ${c.detail}` : 'missing');
  }
  const ts = level('tree-sitter')?.detail ?? '';
  for (const g of ['java', 'go', 'javascript', 'typescript', 'tsx', 'python', 'php', 'kotlin', 'csharp', 'ruby', 'rust']) {
    check(new RegExp(`\\b${g} \\d`).test(ts), `grammar ${g}`, ts);
  }
  check(/\d+ 条规则/.test(ts) && !/\b0 条规则/.test(ts), 'rules loaded', ts);

  const k = run(['knowledge', 'list']);
  check(k.code === 0 && k.stdout.includes('authz-judgement-method'), 'knowledge list on a new data dir', k.stderr || k.stdout.slice(0, 300));

  const port = 40000 + Math.floor(Math.random() * 20000);
  const serve = spawn(bin, ['serve', '--port', String(port)], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  try {
    let out = '';
    serve.stdout.on('data', (d) => { out += d; });
    serve.stderr.on('data', (d) => { out += d; });
    for (let i = 0; i < 120 && !out.includes(`127.0.0.1:${port}`); i++) await new Promise((r) => setTimeout(r, 250));
    const health = await fetch(`http://127.0.0.1:${port}/api/v1/health`).then((r) => r.json()).catch((e) => ({ error: String(e) }));
    check(health.status === 'ok' && health.version === version, 'serve /api/v1/health', JSON.stringify(health).slice(0, 300) + (health.status ? '' : `\n     ${out.slice(0, 500)}`));
    const page = await fetch(`http://127.0.0.1:${port}/`).then(async (r) => ({ status: r.status, text: await r.text() })).catch((e) => ({ status: 0, text: String(e) }));
    check(page.status === 200 && page.text.includes('<title>'), 'serve web UI', `${page.status} ${page.text.slice(0, 200)}`);
  } finally {
    serve.kill();
  }
} finally {
  rmSync(dataDir, { recursive: true, force: true });
}
console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
process.exit(failed ? 1 : 0);
