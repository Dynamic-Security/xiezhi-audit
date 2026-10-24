// Private HTTPS remotes end to end: a local TLS smart-HTTP git server that
// requires Basic auth, reached through the real ls-remote / fetch / probe code with the one-shot askpass.
// The CA option used here is test-only; production git trusts only the system store.
import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Executor, fetchToCache, listRemoteTree, lsRemote, parseGitUrl, RemoteGitError, resolveRemoteRef } from '@xiezhi/context';

const tmp = () => mkdtempSync(join(tmpdir(), 'ca-https-'));
const git = (cwd: string, ...args: string[]) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();

function hasOpenssl(): boolean {
  try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); return true; } catch { return false; }
}

const USER = 'ca-tester';
const PASS = `pw-${Math.random().toString(36).slice(2)}`;

describe.skipIf(!hasOpenssl())('private HTTPS remote with Basic auth', () => {
  const dir = tmp();
  const seen: { path: string; auth: 'none' | 'ok' | 'bad' }[] = [];
  let server: Server;
  let url = '';
  let commit = '';
  /** Drop the protocol v2 header: v0 servers refuse unadvertised commits by default. */
  let forceV0 = false;

  beforeAll(async () => {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '1',
      '-subj', '/CN=localhost', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
    const work = join(dir, 'work');
    execFileSync('git', ['init', '-q', '-b', 'main', work]);
    writeFileSync(join(work, 'main.go'), 'package main\n\nfunc main() {}\n');
    git(work, 'add', '.');
    git(work, '-c', 'user.email=t@t', '-c', 'user.name=t', 'commit', '-qm', 'init');
    commit = git(work, 'rev-parse', 'HEAD');
    execFileSync('git', ['clone', '-q', '--bare', work, join(dir, 'root', 'secret.git')]);
    const expected = `Basic ${Buffer.from(`${USER}:${PASS}`).toString('base64')}`;
    server = createServer({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')) }, (req, res) => {
      const u = new URL(req.url ?? '/', 'https://localhost');
      const auth = req.headers.authorization;
      seen.push({ path: u.pathname, auth: !auth ? 'none' : auth === expected ? 'ok' : 'bad' });
      if (auth !== expected) { res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="test"' }); res.end(); return; }
      const cgi = spawn('git', ['http-backend'], {
        env: {
          PATH: process.env.PATH ?? '', GIT_PROJECT_ROOT: join(dir, 'root'), GIT_HTTP_EXPORT_ALL: '1', PATH_INFO: u.pathname, REQUEST_METHOD: req.method ?? 'GET',
          QUERY_STRING: u.search.slice(1), CONTENT_TYPE: String(req.headers['content-type'] ?? ''), HTTP_CONTENT_ENCODING: String(req.headers['content-encoding'] ?? ''),
          GIT_PROTOCOL: forceV0 ? '' : String(req.headers['git-protocol'] ?? ''), REMOTE_USER: USER, REMOTE_ADDR: '127.0.0.1',
        },
      });
      req.pipe(cgi.stdin);
      let head = Buffer.alloc(0);
      let started = false;
      cgi.stdout.on('data', (d: Buffer) => {
        if (started) { res.write(d); return; }
        head = Buffer.concat([head, d]);
        const i = head.indexOf('\r\n\r\n');
        if (i < 0) return;
        started = true;
        let status = 200;
        const headers: Record<string, string> = {};
        for (const line of head.subarray(0, i).toString().split('\r\n')) {
          const k = line.slice(0, line.indexOf(':'));
          const v = line.slice(line.indexOf(':') + 1).trim();
          if (k.toLowerCase() === 'status') status = parseInt(v, 10); else headers[k] = v;
        }
        res.writeHead(status, headers);
        res.write(head.subarray(i + 4));
      });
      cgi.stdout.on('end', () => res.end());
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
    url = `https://127.0.0.1:${(server.address() as AddressInfo).port}/secret.git`;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));

  const exec = () => new Executor({ scratchDir: tmp() });
  const ca = () => join(dir, 'cert.pem');

  it('reports an authentication error without a credential and with a wrong one', async () => {
    const remote = parseGitUrl(url);
    expect(remote).toMatchObject({ kind: 'https', host: `127.0.0.1:${new URL(url).port}` });
    for (const credential of [undefined, { username: USER, token: 'wrong' }]) {
      const err = await lsRemote(exec(), remote, { credential, testCaInfo: ca() }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(RemoteGitError);
      expect((err as RemoteGitError).code).toBe('auth');
    }
    expect(seen.some((s) => s.auth === 'bad')).toBe(true);
  });

  it('does not trust an unknown certificate', async () => {
    const err = await lsRemote(exec(), parseGitUrl(url), { credential: { username: USER, token: PASS } }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RemoteGitError);
    expect((err as RemoteGitError).code).not.toBe('auth');
  });

  it('lists, probes and fetches with the configured credential; the secret never outlives the call', async () => {
    const ex = exec();
    const remote = parseGitUrl(url);
    const auth = { credential: { username: USER, token: PASS }, testCaInfo: ca() };
    const listing = await lsRemote(ex, remote, auth);
    expect(listing.defaultBranch).toBe('main');
    const resolved = resolveRemoteRef(listing, null);
    expect(resolved.commit).toBe(commit);
    expect(await listRemoteTree(ex, remote, commit, auth)).toEqual(['main.go']);
    const cache = await fetchToCache(ex, tmp(), remote, resolved, auth);
    expect(git(cache, 'cat-file', '-t', commit)).toBe('commit');
    expect(git(cache, 'show', `${commit}:main.go`)).toContain('func main');
    // The cache config never records the remote URL or the credential.
    expect(readFileSync(join(cache, 'config'), 'utf8')).not.toContain(PASS);
    // One-shot askpass directories are removed after each call.
    expect(readdirSync(ex.scratchDir).filter((f) => f.startsWith('askpass-'))).toEqual([]);
    expect(seen.filter((s) => s.auth === 'ok').length).toBeGreaterThan(0);
    expect(existsSync(join(ex.scratchDir, 'probe'))).toBe(true);
  });

  it('falls back to the ref name when the server refuses to fetch an unadvertised commit', async () => {
    forceV0 = true;
    try {
      const ex = exec();
      const remote = parseGitUrl(url);
      const auth = { credential: { username: USER, token: PASS }, testCaInfo: ca() };
      const resolved = resolveRemoteRef(await lsRemote(ex, remote, auth), 'main');
      const before = seen.filter((x) => x.path.endsWith('/git-upload-pack') && x.auth === 'ok').length;
      const cache = await fetchToCache(ex, tmp(), remote, resolved, auth);
      expect(git(cache, 'rev-parse', `refs/snap/${commit}`)).toBe(commit);
      // The commit fetch was refused, then retried by ref name.
      expect(seen.filter((x) => x.path.endsWith('/git-upload-pack') && x.auth === 'ok').length - before).toBeGreaterThanOrEqual(2);
    } finally {
      forceV0 = false;
    }
  });
});
