// Background jobs a restart cut off do not stay “in progress” for ever.
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { defaultAppConfig } from '@xiezhi/contracts';
import { Store } from '@xiezhi/store';
import { Engine, createArchitectureImport, createBasis, createDraft, createPackDraft, createProject, getArchitectureImport, getBasis, findDraft, getPackDraft } from '@xiezhi/engine';

describe('background jobs after a restart', () => {
  it('settles drafts, imports and basis drafts left in progress', async () => {
    const dataDir = join(mkdtempSync(join(tmpdir(), 'ca-jobs-')), 'data');
    let store = Store.open({ dataDir, role: 'test' });
    store.saveConfig(defaultAppConfig());
    const p = createProject(store, 'demo');
    // Rows as a process that died while working on them left them.
    const basis = createBasis(store, { kind: 'prompt', text: '排查越权' });
    const imp = createArchitectureImport(store, p.id, { text: 'gateway → order', label: '架构说明' });
    const pack = createPackDraft(store, { openapi: 'openapi: 3.0.0' });
    const draft = createDraft(store, { layer: 'global', kind: 'skill', text: '---\nname: x\n---\n正文', organize: true });
    expect(getBasis(store, basis).status).toBe('drafting');
    store.close();

    store = Store.open({ dataDir, role: 'test' });
    const engine = await Engine.open({ store });
    expect(getBasis(store, basis)).toMatchObject({ status: 'failed', error: expect.stringContaining('服务重启') });
    expect(getArchitectureImport(store, imp)).toMatchObject({ status: 'failed' });
    expect(getPackDraft(store, pack.id)).toMatchObject({ status: 'failed', error: expect.stringContaining('服务重启') });
    expect(findDraft(store, draft.id).draft.status).toBe('failed');
    await engine.stopAnalyses();
    store.close();
  });
});
