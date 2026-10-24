// Auditable vs context repositories from a language census.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildIndex, createSnapshot, Executor, loadRules, SnapshotView } from '@xiezhi/context';
import { Store } from '@xiezhi/store';
import { addRepository, auditableFrom, createProject, scanLocalJsBackend, scanLocalRustBackend } from '../src/index.js';
import { autoAuditable, indexLanguagesFor, recordAutoAuditable } from '../src/auditable.js';

describe('auditable repositories', () => {
  it('audit languages make a repository auditable; JS / TS depend on the backend marker', () => {
    expect(auditableFrom({ python: 12, yaml: 3 }, null)).toEqual({ auditable: true, note: null });
    expect(auditableFrom({ php: 1 }, null).auditable).toBe(true);
    expect(auditableFrom({ typescript: 30 }, true).auditable).toBe(true);
    expect(auditableFrom({ typescript: 30 }, false)).toMatchObject({ auditable: false, note: expect.stringContaining('前端') });
    expect(auditableFrom({ typescript: 30 }, null)).toMatchObject({ auditable: false, note: expect.stringContaining('首次分析') });
    expect(auditableFrom({ yaml: 3, proto: 2 }, null)).toMatchObject({ auditable: false, note: expect.stringContaining('Python') });
  });

  it('finds a server-side framework in nested package.json files, not in node_modules', () => {
    const root = mkdtempSync(join(tmpdir(), 'ca-m11aud-'));
    mkdirSync(join(root, 'node_modules/x'), { recursive: true });
    writeFileSync(join(root, 'node_modules/x/package.json'), JSON.stringify({ dependencies: { express: '4' } }));
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { react: '18' } }));
    expect(scanLocalJsBackend(root)).toBe(false);
    mkdirSync(join(root, 'server'));
    writeFileSync(join(root, 'server/package.json'), JSON.stringify({ dependencies: { '@nestjs/core': '10' } }));
    expect(scanLocalJsBackend(root)).toBe(true);
  });

  it('a local Rust crate is auditable only with a server framework; Ruby by share', () => {
    const root = mkdtempSync(join(tmpdir(), 'ca-m1130aud-'));
    writeFileSync(join(root, 'Cargo.toml'), '[package]\nname = "tool"\n[dependencies]\nclap = "4"\n');
    expect(scanLocalRustBackend(root)).toBe(false);
    expect(auditableFrom({ rust: 12 }, false, false)).toMatchObject({ auditable: false, note: expect.stringContaining('命令行工具或库') });
    expect(auditableFrom({ rust: 12 }, null, null)).toMatchObject({ auditable: false, note: expect.stringContaining('Cargo.toml') });
    mkdirSync(join(root, 'server'));
    writeFileSync(join(root, 'server/Cargo.toml'), '[package]\nname = "server"\n[dependencies]\naxum = "0.7"\n');
    expect(scanLocalRustBackend(root)).toBe(true);
    expect(auditableFrom({ rust: 12 }, false, true).auditable).toBe(true);
    expect(auditableFrom({ ruby: 20 }, null, null).auditable).toBe(true);
  });

  it('a local Next.js / Nuxt app is a backend only with server code', () => {
    const root = mkdtempSync(join(tmpdir(), 'ca-m1120aud-'));
    writeFileSync(join(root, 'package.json'), JSON.stringify({ dependencies: { next: '15', react: '19' } }));
    mkdirSync(join(root, 'app'));
    writeFileSync(join(root, 'app/page.tsx'), 'export default function Page() { return null; }\n');
    expect(scanLocalJsBackend(root)).toBe(false);
    writeFileSync(join(root, 'app/actions.ts'), "'use server';\nexport async function save() {}\n");
    expect(scanLocalJsBackend(root)).toBe(true);
    const nuxt = mkdtempSync(join(tmpdir(), 'ca-m1120aud-'));
    writeFileSync(join(nuxt, 'package.json'), JSON.stringify({ dependencies: { nuxt: '3' } }));
    expect(scanLocalJsBackend(nuxt)).toBe(false);
    mkdirSync(join(nuxt, 'server/api'), { recursive: true });
    writeFileSync(join(nuxt, 'server/api/todos.get.ts'), 'export default defineEventHandler(() => []);\n');
    expect(scanLocalJsBackend(nuxt)).toBe(true);
  });
});

describe('manual auditable setting', () => {
  it('a user-set auditable JS repository indexes its sources; analyses do not override the setting', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ca-m11-08-'));
    const src = join(dir, 'svc');
    mkdirSync(join(src, 'src'), { recursive: true });
    writeFileSync(join(src, 'package.json'), JSON.stringify({ dependencies: { pg: '8' } }));
    writeFileSync(join(src, 'src/app.ts'), "import { Router } from 'my-router';\nconst router = Router();\nrouter.get('/orders/:id', (req: any, res: any) => res.send(req.params.id));\nexport function q(db: any, id: string) { return db.query(`SELECT * FROM o WHERE id = ${id}`); }\n");
    const store = Store.open({ dataDir: join(dir, 'data'), role: 'test' });
    const p = createProject(store, 'p');
    const repo = addRepository(store, p.id, { path: src });
    expect(repo).toMatchObject({ is_auditable: 0, auditable_source: 'auto', auditable_auto: 0 });
    expect(repo.auditable_reason).toMatch(/服务端框架/);

    const ex = new Executor({ scratchDir: join(dir, 'exec') });
    const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(dir, 'snapshots'), tmpDir: join(dir, 'tmp'), executor: ex });
    const view = new SnapshotView('svc', s.root, s.manifest);
    expect(indexLanguagesFor(store, repo.id, view)).toBeUndefined();
    const auto = await buildIndex(view, loadRules(), { indexesDir: join(dir, 'idx') });
    expect(auto.index.sinks).toHaveLength(0);

    store.update('repository', { id: repo.id }, { auditable_source: 'user', is_auditable: 1 });
    const langs = indexLanguagesFor(store, repo.id, view);
    expect(langs).toEqual(['typescript']);
    const forced = await buildIndex(view, loadRules(), { indexesDir: join(dir, 'idx'), languages: langs! });
    expect(forced.index.sinks.map((x) => x.category)).toContain('sqli');

    recordAutoAuditable(store, repo.id, autoAuditable(view));
    expect(store.get('SELECT is_auditable, auditable_source, auditable_auto FROM repository WHERE id = ?', repo.id)).toEqual({ is_auditable: 1, auditable_source: 'user', auditable_auto: 0 });
    store.update('repository', { id: repo.id }, { auditable_source: 'auto' });
    recordAutoAuditable(store, repo.id, autoAuditable(view));
    expect(store.get('SELECT is_auditable FROM repository WHERE id = ?', repo.id)).toEqual({ is_auditable: 0 });
    store.close();
  });
});
