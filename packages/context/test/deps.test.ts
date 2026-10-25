// Declared dependency versions for risk hunts: parent POMs, BOMs, Gradle catalogs
// and variables, npm lock files. Everything is read from the snapshot; nothing is fetched or built.
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createSnapshot, declaredDependencies, Executor, locateRiskCandidates, parenOptional, SnapshotView, type ToolContext } from '@xiezhi/context';
import { ArtifactStore } from '@xiezhi/store';
import type { HuntBasis } from '@xiezhi/contracts';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-deps-'));
const ex = new Executor({ scratchDir: tmp() });

async function view(files: Record<string, string>): Promise<SnapshotView> {
  const dir = tmp();
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), text);
  }
  const dd = tmp();
  const s = await createSnapshot({ source: { kind: 'local', path: dir }, snapshotsDir: join(dd, 'snapshots'), tmpDir: join(dd, 'tmp'), executor: ex });
  return new SnapshotView('r', s.root, s.manifest);
}

const dep = (g: string, a: string, v?: string, extra = '') => `<dependency><groupId>${g}</groupId><artifactId>${a}</artifactId>${v ? `<version>${v}</version>` : ''}${extra}</dependency>`;

describe('maven', () => {
  it('resolves versions from the parent POM, a BOM in the repository and aligned external BOMs', async () => {
    const v = await view({
      'pom.xml': `<project>
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>2.6.3</version></parent>
  <groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version>
  <properties><log4j.version>2.14.1</log4j.version><jackson.version>2.13.1</jackson.version></properties>
  <dependencyManagement><dependencies>
    ${dep('org.apache.logging.log4j', 'log4j-core', '${log4j.version}')}
    ${dep('org.springframework.cloud', 'spring-cloud-dependencies', '2021.0.0', '<type>pom</type><scope>import</scope>')}
    ${dep('com.acme', 'acme-bom', '${project.version}', '<type>pom</type><scope>import</scope>')}
  </dependencies></dependencyManagement>
</project>`,
      'bom/pom.xml': `<project><groupId>com.acme</groupId><artifactId>acme-bom</artifactId><version>1.0</version>
  <dependencyManagement><dependencies>${dep('com.acme', 'lib', '3.2.1')}</dependencies></dependencyManagement></project>`,
      'app/pom.xml': `<project>
  <parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
  <artifactId>app</artifactId>
  <dependencies>
    ${dep('org.apache.logging.log4j', 'log4j-core')}
    ${dep('com.fasterxml.jackson.core', 'jackson-databind', '${jackson.version}')}
    ${dep('org.springframework.boot', 'spring-boot-starter-web')}
    ${dep('org.springframework.cloud', 'spring-cloud-starter-gateway')}
    ${dep('com.acme', 'lib')}
  </dependencies>
</project>`,
    });
    const deps = declaredDependencies(v).filter((d) => d.path === 'app/pom.xml');
    const by = (n: string) => deps.find((d) => d.name.endsWith(`:${n}`))!;
    expect(by('log4j-core')).toMatchObject({ version: '2.14.1', via: 'pom.xml 的 dependencyManagement' });
    expect(by('jackson-databind')).toMatchObject({ version: '2.13.1', via: '属性 ${jackson.version}' });
    expect(by('spring-boot-starter-web')).toMatchObject({ version: '2.6.3', via: 'BOM org.springframework.boot:spring-boot-starter-parent:2.6.3' });
    expect(by('lib')).toMatchObject({ version: '3.2.1', via: 'bom/pom.xml 的 dependencyManagement' });
    // A release-train BOM is not aligned with its artifacts: unknown, but the BOM is named for the judge.
    expect(by('spring-cloud-starter-gateway')).toMatchObject({ version: null });
    expect(by('spring-cloud-starter-gateway').managedBy).toEqual(expect.arrayContaining(['org.springframework.cloud:spring-cloud-dependencies:2021.0.0', 'org.springframework.boot:spring-boot-starter-parent:2.6.3']));
    expect(by('log4j-core').line).toBe(5);
  });

  it('survives parent cycles and unresolved properties', async () => {
    const v = await view({
      'a/pom.xml': `<project><parent><groupId>x</groupId><artifactId>b</artifactId><relativePath>../b/pom.xml</relativePath></parent><groupId>x</groupId><artifactId>a</artifactId>
  <dependencies>${dep('g', 'd', '${missing}')}</dependencies></project>`,
      'b/pom.xml': `<project><parent><groupId>x</groupId><artifactId>a</artifactId><relativePath>../a/pom.xml</relativePath></parent><groupId>x</groupId><artifactId>b</artifactId></project>`,
    });
    expect(declaredDependencies(v)).toEqual([expect.objectContaining({ name: 'g:d', version: null })]);
  });
});

describe('gradle', () => {
  it('reads version catalogs, variables and the Spring Boot plugin', async () => {
    const v = await view({
      'gradle/libs.versions.toml': `[versions]
jackson = "2.13.1"
netty = { strictly = "4.1.70.Final" }

[libraries]
jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
netty-codec = { group = "io.netty", name = "netty-codec-http", version = { ref = "netty" } }
guava = "com.google.guava:guava:30.0-jre"
managed = { module = "org.springframework.boot:spring-boot-starter" }
`,
      'gradle.properties': 'snakeVersion=1.29\n',
      'build.gradle': `plugins { id 'org.springframework.boot' version '2.5.0' }
ext { log4jVersion = '2.14.0' }
dependencies {
  implementation "org.yaml:snakeyaml:$snakeVersion"
  implementation "org.apache.logging.log4j:log4j-core:\${log4jVersion}"
  implementation 'org.springframework.boot:spring-boot-starter-web'
  implementation 'org.springframework.cloud:spring-cloud-starter-gateway'
  implementation group: 'commons-io', name: 'commons-io', version: '2.6'
}`,
    });
    const deps = declaredDependencies(v);
    const by = (n: string) => deps.find((d) => d.name.endsWith(`:${n}`))!;
    expect(by('jackson-databind')).toMatchObject({ version: '2.13.1', path: 'gradle/libs.versions.toml', line: 6, via: expect.stringContaining('版本目录') });
    expect(by('netty-codec-http')).toMatchObject({ version: '4.1.70.Final' });
    expect(by('guava')).toMatchObject({ version: '30.0-jre' });
    expect(by('spring-boot-starter')).toMatchObject({ version: null });
    expect(by('snakeyaml')).toMatchObject({ version: '1.29', via: '变量 $snakeVersion' });
    expect(by('log4j-core')).toMatchObject({ version: '2.14.0' });
    expect(by('spring-boot-starter-web')).toMatchObject({ version: '2.5.0', via: 'BOM org.springframework.boot:spring-boot-dependencies:2.5.0' });
    expect(by('spring-cloud-starter-gateway')).toMatchObject({ version: null, managedBy: ['org.springframework.boot:spring-boot-dependencies:2.5.0'] });
    expect(by('commons-io')).toMatchObject({ version: '2.6' });
  });
});

describe('npm lock files', () => {
  const pkg = JSON.stringify({ dependencies: { lodash: '^4.17.0', left: '^1.0.0' } }, null, 2);

  it('reads yarn v1 / berry and pnpm v6 / v9 and lets the lock file supersede package.json ranges', async () => {
    const v = await view({
      'package.json': pkg,
      'yarn.lock': `# yarn lockfile v1\n\nlodash@^4.17.0, lodash@^4.17.15:\n  version "4.17.21"\n  resolved "https://x"\n\n"@babel/core@^7.0.0":\n  version "7.12.3"\n`,
      'berry/package.json': JSON.stringify({ dependencies: { minimist: '^1.2.0' } }),
      'berry/yarn.lock': `__metadata:\n  version: 6\n\n"minimist@npm:^1.2.0":\n  version: 1.2.5\n  resolution: "minimist@npm:1.2.5"\n`,
      'p6/pnpm-lock.yaml': `lockfileVersion: '6.0'\npackages:\n  /axios@0.21.1:\n    resolution: {integrity: sha512-x}\n  /@types/node@18.0.0(typescript@5.0.0):\n    dev: true\n`,
      'p9/pnpm-lock.yaml': `lockfileVersion: '9.0'\npackages:\n  follow-redirects@1.14.7:\n    resolution: {integrity: sha512-y}\n`,
      'p5/pnpm-lock.yaml': `lockfileVersion: 5.4\npackages:\n  /ws/7.4.5_bufferutil@4.0.0:\n    dev: false\n`,
    });
    const deps = declaredDependencies(v);
    const of = (n: string) => deps.filter((d) => d.name === n).map((d) => [d.path, d.version]);
    expect(of('lodash')).toEqual([['yarn.lock', '4.17.21']]);
    expect(of('left')).toEqual([['package.json', '1.0.0']]);
    expect(of('@babel/core')).toEqual([['yarn.lock', '7.12.3']]);
    expect(of('minimist')).toEqual([['berry/yarn.lock', '1.2.5']]);
    expect(of('axios')).toEqual([['p6/pnpm-lock.yaml', '0.21.1']]);
    expect(of('@types/node')).toEqual([['p6/pnpm-lock.yaml', '18.0.0']]);
    expect(of('follow-redirects')).toEqual([['p9/pnpm-lock.yaml', '1.14.7']]);
    expect(of('ws')).toEqual([['p5/pnpm-lock.yaml', '7.4.5']]);
    expect(deps.find((d) => d.name === 'lodash')!.line).toBe(3);
  });

  it('clears a repository whose lock file pins a fixed version', async () => {
    const v = await view({ 'package.json': pkg, 'yarn.lock': 'lodash@^4.17.0:\n  version "4.17.21"\n' });
    const dd = tmp();
    mkdirSync(join(dd, '.tmp'), { recursive: true });
    const ctx: ToolContext = { views: new Map([['r', v]]), defaultRepo: 'r', executor: ex, artifacts: new ArtifactStore(dd), auditArtifacts: new Set() };
    const basis = { features: { dependencies: [{ ecosystem: 'npm', name: 'lodash', affectedVersions: '<4.17.21' }], apis: [], codePatterns: [], locations: [] } } as unknown as HuntBasis;
    const r = await locateRiskCandidates(ctx, ['r'], basis);
    expect(r.candidates).toEqual([]);
    expect(r.checks).toEqual(['r：yarn.lock 声明 lodash 4.17.21，不在受影响范围 <4.17.21']);
  });
});

describe('risk-hunt API patterns in Ruby', () => {
  it('a call pattern written with parentheses also finds the Ruby call without them; other repositories are unchanged', async () => {
    expect(parenOptional('send_file\\s*\\(')).toBe('send_file(?:\\s*\\(|\\s+[^\\s=,)])');
    expect(parenOptional('\\bFile\\.read\\(')).toBe('\\bFile\\.read(?:\\s*\\(|\\s+[^\\s=,)])');
    const v = await view({
      'app.rb': 'get "/avatar" do\n  send_file File.join("/srv/avatars", params["file"])\nend\n',
      'lib/x.rb': 'def send_file_name = "x"\n',
    });
    const dd = tmp();
    mkdirSync(join(dd, '.tmp'), { recursive: true });
    const ctx: ToolContext = { views: new Map([['r', v]]), defaultRepo: 'r', executor: ex, artifacts: new ArtifactStore(dd), auditArtifacts: new Set() };
    const basis = { features: { dependencies: [], apis: [{ pattern: 'send_file\\s*\\(', description: 'send_file' }], codePatterns: [], locations: [] } } as unknown as HuntBasis;
    // Before: no candidate, and the repository was cleared as not affected without a model looking at it.
    const r = await locateRiskCandidates(ctx, ['r'], basis);
    expect(r.candidates.map((c) => `${c.path}:${c.line}`)).toEqual(['app.rb:2']);
  });
});
