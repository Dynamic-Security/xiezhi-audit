// Language registry — audit-language detection, rule loading, repository signals, LSP adapters.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { auditLanguagesOf, isJsBackend, isTestPath, KNOWLEDGE_FRAMEWORKS, KNOWLEDGE_LANGUAGES } from '@xiezhi/contracts';
import {
  auditLanguagesOfView, computeRepoSignals, configurationFor, createSnapshot, Executor, GRAMMARS, initializationOptions, LANGUAGE_PLUGINS, loadLanguage,
  loadRules, prepareWorkspace, PYRIGHT_NO_INTERPRETER, serverCommand, SnapshotView, LSP_BINARIES,
} from '@xiezhi/context';

async function viewOf(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'ca-m11reg-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const ex = new Executor({ scratchDir: join(root, 'exec') });
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: ex });
  return { view: new SnapshotView('repo', s.root, s.manifest), root };
}

describe('audit languages', () => {
  it('Java / Go keep the original rule; the other languages need a 10 % share; JS / TS need a backend marker', () => {
    expect(auditLanguagesOf({ java: 100, go: 1 })).toEqual(['java', 'go']);
    expect(auditLanguagesOf({ java: 100, python: 5 })).toEqual(['java']);
    expect(auditLanguagesOf({ java: 100, python: 10 })).toEqual(['java', 'python']);
    expect(auditLanguagesOf({ python: 3 })).toEqual(['python']);
    expect(auditLanguagesOf({ typescript: 40, javascript: 2 })).toEqual([]);
    expect(auditLanguagesOf({ typescript: 40, javascript: 2 }, true)).toEqual(['javascript', 'typescript']);
    expect(auditLanguagesOf({ php: 50, javascript: 200 }, false)).toEqual(['php']);
    expect(isJsBackend(['react', 'express'])).toBe(true);
    expect(isJsBackend(['react', 'vue', 'axios'])).toBe(false);
  });

  it('snapshot view: frontend package.json stays context, express makes it auditable', async () => {
    const fe = await viewOf({ 'package.json': JSON.stringify({ dependencies: { react: '18' } }), 'src/App.tsx': 'export const A = 1;\n' });
    expect(auditLanguagesOfView(fe.view)).toEqual([]);
    const be = await viewOf({ 'package.json': JSON.stringify({ dependencies: { express: '4' } }), 'src/app.ts': 'export const A = 1;\n' });
    expect(auditLanguagesOfView(be.view)).toEqual(['typescript']);
  });

  it('knowledge vocabulary and test paths cover the new languages', () => {
    expect(KNOWLEDGE_LANGUAGES).toEqual(expect.arrayContaining(['python', 'php', 'kotlin', 'csharp', 'javascript', 'typescript']));
    expect(KNOWLEDGE_FRAMEWORKS).toEqual(expect.arrayContaining(['spring', 'gin', 'django', 'flask', 'fastapi', 'express', 'nestjs', 'laravel', 'ktor', 'aspnetcore']));
    for (const p of ['tests/test_views.py', 'app/foo_test.py', 'src/a.spec.ts', 'tests/Feature/OrderTest.php', 'src/test/kotlin/a/ATest.kt', 'Shop.Tests/OrderTests.cs']) expect(isTestPath(p), p).toBe(true);
    for (const p of ['app/views.py', 'src/app.ts', 'app/Http/Controllers/OrderController.php', 'Controllers/OrdersController.cs']) expect(isTestPath(p), p).toBe(false);
  });
});

describe('registry', () => {
  it('every plugin grammar loads', async () => {
    for (const g of Object.keys(GRAMMARS) as (keyof typeof GRAMMARS)[]) await expect(loadLanguage(g)).resolves.toBeTruthy();
    expect(LANGUAGE_PLUGINS.typescript.grammar('a/b.tsx')).toBe('tsx');
    expect(LANGUAGE_PLUGINS.typescript.grammar('a/b.ts')).toBe('typescript');
    expect(LANGUAGE_PLUGINS.javascript.grammar('a/b.js')).toBe('javascript');
    expect(LANGUAGE_PLUGINS.typescript.ruleLang).toBe('javascript');
  });

  it('rules: unknown languages and unknown post functions are errors; the newer language prefixes are accepted', () => {
    const dir = mkdtempSync(join(tmpdir(), 'ca-m11rules-'));
    const put = (p: string, yaml: string) => { mkdirSync(dirname(join(dir, p)), { recursive: true }); writeFileSync(join(dir, `${p}.yaml`), yaml); writeFileSync(join(dir, `${p}.scm`), '(call) @call'); };
    put('python/flask/route', 'id: python.flask.route\nversion: 1\nkind: entrypoint\nlang: python\nframework: flask\npost: python_flask_route\n');
    put('swift/vapor/route', 'id: swift.vapor.route\nversion: 1\nkind: entrypoint\nlang: swift\nframework: vapor\n');
    put('python/x/bad', 'id: python.x.bad\nversion: 1\nkind: sink\nlang: python\nframework: x\npost: exec_anything\n');
    const rs = loadRules(dir);
    expect(rs.rules.map((r) => r.id)).toEqual(['python.flask.route']);
    expect(rs.errors.join('\n')).toMatch(/unsupported lang swift/);
    expect(rs.errors.join('\n')).toMatch(/unknown post function exec_anything/);
    expect(loadRules().errors).toEqual([]);
  });
});

describe('repository signals', () => {
  it('reads Python, PHP and .NET build files for modules, coordinates and security dependencies', async () => {
    const { view } = await viewOf({
      'requirements.txt': '# deps\nDjango>=4.2\nPyJWT==2.8.0 ; python_version > "3.8"\n-r other.txt\n',
      'svc/pyproject.toml': '[project]\nname = "order-svc"\ndependencies = ["fastapi>=0.110", "authlib"]\n\n[tool.poetry.dependencies]\npython = "^3.11"\nhttpx = "*"\n',
      'php/composer.json': JSON.stringify({ name: 'acme/shop', require: { php: '>=8.1', 'laravel/framework': '^10', 'laravel/sanctum': '^3' } }),
      'dotnet/Shop.Api.csproj': '<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.0" /><PackageReference Include="Dapper" Version="2.1.0" /></ItemGroup></Project>',
    });
    const s = computeRepoSignals(view, null, 'skipped');
    expect(s.modules.map((m) => `${m.lang}:${m.path}`).sort()).toEqual(['csharp:dotnet', 'php:php', 'python:', 'python:svc']);
    expect(s.provides).toEqual(expect.arrayContaining(['order-svc', 'acme/shop', 'Shop.Api']));
    expect(s.dependencies).toEqual(expect.arrayContaining(['Django', 'PyJWT', 'fastapi', 'authlib', 'httpx', 'laravel/framework', 'Dapper']));
    expect(s.dependencies).not.toContain('python');
    expect(s.securityDependencies).toEqual(expect.arrayContaining(['PyJWT', 'authlib', 'laravel/sanctum', 'Microsoft.AspNetCore.Authentication.JwtBearer']));
  });
});

describe('language servers', () => {
  it('pyright never gets an interpreter; typescript-language-server has type acquisition off', async () => {
    expect(LSP_BINARIES).toEqual(expect.arrayContaining(['pyright-langserver', 'typescript-language-server']));
    expect(serverCommand('python', '/tmp/x').args).toEqual(['--stdio']);
    expect(configurationFor('python', 'python')).toEqual({ pythonPath: PYRIGHT_NO_INTERPRETER });
    expect(configurationFor('go', 'gopls')).toBeNull();
    expect(initializationOptions('typescript')).toMatchObject({ disableAutomaticTypingAcquisition: true });
    const { view, root } = await viewOf({ 'app/views.py': 'def f():\n    pass\n', 'pyrightconfig.json': '{"pythonPath": "/usr/bin/python3"}', 'sitecustomize.txt': 'x' });
    const ws = join(root, 'ws');
    prepareWorkspace(view, ws, 'python');
    const { readFileSync, existsSync } = await import('node:fs');
    expect(JSON.parse(readFileSync(join(ws, 'pyrightconfig.json'), 'utf8')).pythonPath).toBe(PYRIGHT_NO_INTERPRETER);
    expect(existsSync(join(ws, 'app/views.py'))).toBe(true);
    expect(existsSync(join(ws, 'sitecustomize.txt'))).toBe(false);
  });
});
