// Full audits list the declared dependencies; only with an OSV connector (operation
// `osv_query`) does the engine ask about each versioned one, sending ecosystem, name and version; hits become leads
// of one domain expert and a report section. The result is recorded once and reused.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ConnectorAccess } from '@xiezhi/agent';
import { createSnapshot, Executor, SnapshotView } from '@xiezhi/context';
import { dependencyCheck, parseAdvisories, type DependencyRecord } from '@xiezhi/engine';
import { dependencyLines } from '../src/dependencies.js';

async function viewOf(files: Record<string, string>) {
  const root = mkdtempSync(join(tmpdir(), 'ca-m17-08-'));
  const src = join(root, 'repo');
  for (const [p, c] of Object.entries(files)) { mkdirSync(dirname(join(src, p)), { recursive: true }); writeFileSync(join(src, p), c); }
  const s = await createSnapshot({ source: { kind: 'local', path: src }, snapshotsDir: join(root, 'snapshots'), tmpDir: join(root, 'tmp'), executor: new Executor({ scratchDir: join(root, 'exec') }) });
  return new SnapshotView('repo', s.root, s.manifest);
}

const POM = `<project><modelVersion>4.0.0</modelVersion><groupId>x</groupId><artifactId>x</artifactId><version>1</version>
<dependencies>
  <dependency><groupId>org.apache.shiro</groupId><artifactId>shiro-core</artifactId><version>1.4.2</version></dependency>
  <dependency><groupId>com.alibaba</groupId><artifactId>fastjson</artifactId><version>1.2.83</version></dependency>
  <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId></dependency>
</dependencies></project>`;

function stubRt(view: SnapshotView) {
  const events: { type: string; payload: Record<string, unknown> }[] = [];
  const rt = {
    auditId: 'aud_x', targets: [{ name: 'repo' }], views: new Map([['repo', view]]), connectorPool: null, strategy: { connectors: [] }, auditArtifacts: new Set<string>(),
    store: { listEvents: (_a: string, _s: number, types: string[]) => events.filter((e) => types.includes(e.type)).map((e) => ({ payload: e.payload })) },
    event: (type: string, payload: Record<string, unknown>) => { events.push({ type, payload }); },
  };
  return { rt: rt as unknown as Parameters<typeof dependencyCheck>[0], events };
}

function fakeAccess(calls: Record<string, unknown>[]): ConnectorAccess {
  return {
    operations: [{ connectorId: 'c1', connector: 'osv', tool: 'osv_query', description: '', params: '', authoritative: false }],
    call: async (_op, args) => {
      calls.push(args);
      const text = args.name === 'org.apache.shiro:shiro-core'
        ? JSON.stringify([{ id: 'GHSA-xxxx-0001', summary: 'Apache Shiro authentication bypass', aliases: ['CVE-2020-1957'], 'database_specific.severity': 'HIGH' }]) // the pack's projection keys
        : '[]';
      return { text, isError: false, totalBytes: text.length, artifactId: null, callId: 'ccl_1', authoritative: false, signals: [] };
    },
  };
}

describe('dependencies', () => {
  it('without an OSV connector: lists the dependencies, sends nothing', async () => {
    const { rt } = stubRt(await viewOf({ 'pom.xml': POM }));
    const r = await dependencyCheck(rt, undefined, null);
    expect(r.repos).toEqual([{ repo: 'repo', total: 3, versioned: 2, byEcosystem: { maven: 3 } }]);
    expect(r.osv).toEqual({ available: false, queried: 0, failed: 0 });
    expect(r.hits).toEqual([]);
  });

  it('with an OSV connector: asks about each versioned dependency (ecosystem, name, version only) and keeps the hits; recorded once', async () => {
    const { rt, events } = stubRt(await viewOf({ 'pom.xml': POM }));
    const calls: Record<string, unknown>[] = [];
    const r: DependencyRecord = await dependencyCheck(rt, undefined, fakeAccess(calls));
    expect(calls).toEqual([
      { name: 'org.apache.shiro:shiro-core', ecosystem: 'Maven', version: '1.4.2' },
      { name: 'com.alibaba:fastjson', ecosystem: 'Maven', version: '1.2.83' },
    ]);
    expect(r.osv).toEqual({ available: true, queried: 2, failed: 0 });
    expect(r.hits).toHaveLength(1);
    expect(r.hits[0]).toMatchObject({ name: 'org.apache.shiro:shiro-core', version: '1.4.2', path: 'pom.xml', advisories: [{ id: 'GHSA-xxxx-0001', aliases: ['CVE-2020-1957'], severity: 'HIGH' }] });
    // A second run (resume) reuses the record and calls nothing.
    await dependencyCheck(rt, undefined, fakeAccess(calls));
    expect(calls).toHaveLength(2);
    expect(events.filter((e) => e.payload.kind === 'dependencies')).toHaveLength(1);
    const lines = dependencyLines(r.hits).join('\n');
    expect(lines).toContain('## 已知漏洞依赖（OSV 查询结果，1 个组件；需判断是否可达）');
    expect(lines).toContain('org.apache.shiro:shiro-core@1.4.2（maven，repo:pom.xml:3）：GHSA-xxxx-0001/CVE-2020-1957');
  });

  it('parses the extracted advisories; anything else is no hit', () => {
    expect(parseAdvisories('[{"id":"OSV-1","summary":"s"}]')).toEqual([{ id: 'OSV-1', summary: 's', aliases: [], severity: null }]);
    expect(parseAdvisories('no vulnerabilities')).toEqual([]);
    expect(parseAdvisories('[not json')).toEqual([]);
  });
});
