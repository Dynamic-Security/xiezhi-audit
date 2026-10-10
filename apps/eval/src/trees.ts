// Sample source trees: a directory under `sources/`, or an https Git URL pinned by
// a full commit. Remote trees are fetched with the product's hardened Git (context/snapshot) into a local
// cache and materialised as the product's own snapshot, so `root_hash` is computed exactly as the product
// computes it. They are audit data only: never built, run or tested.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { canonicalJson, sha256Hex } from '@xiezhi/contracts';
import { createSnapshot, Executor, parseGitUrl } from '@xiezhi/context';
import type { Sample } from './schema.js';

export interface TreeRef { origin: string; commit?: string | undefined }
export interface RemoteTree { dir: string; rootHash: string }

export interface RemoteOptions {
  /** Cache root; default `XIEZHI_AUDIT_BENCH_CACHE`, else `<bench>/.cache` (ignored by the bench repository). */
  cacheDir?: string;
  /** Never fetch: trees that are not cached yet are reported as missing. */
  offline?: boolean;
  /** Tests only: accept file:// remotes. */
  allowFileProtocol?: boolean;
  log?: (line: string) => void;
}

export const isRemoteOrigin = (origin: string): boolean => /^[a-z][a-z0-9+.-]*:\/\//i.test(origin);
export const remoteKey = (ref: TreeRef): string => `${ref.origin}@${ref.commit ?? ''}`;

export function cacheDirOf(benchRoot: string, opts: RemoteOptions = {}): string {
  return resolve(opts.cacheDir ?? process.env.XIEZHI_AUDIT_BENCH_CACHE ?? join(benchRoot, '.cache'));
}

/** Every repository tree of a sample: the base version and each later version. */
export function sampleRefs(s: Sample): (TreeRef & { name: string; version: string; root_hash: string })[] {
  return [
    ...s.repos.map((r) => ({ name: r.name, version: 'base', origin: r.origin, commit: r.commit, root_hash: r.root_hash })),
    ...(s.scene_input?.versions ?? []).flatMap((v) => v.repos.map((r) => ({ name: r.name, version: v.name, origin: r.origin, commit: r.commit, root_hash: r.root_hash }))),
  ];
}

/** Why a remote reference is unusable, or null. Only https is accepted outside tests. */
export function remoteRefProblem(ref: TreeRef, allowFile = false): string | null {
  if (!ref.commit || !/^[0-9a-f]{40}$/.test(ref.commit)) return `远程仓库 ${ref.origin} 需要 40 位完整 commit`;
  try {
    const u = parseGitUrl(ref.origin, { allowFile });
    if (u.kind !== 'https' && !(allowFile && u.kind === 'file')) return `远程仓库只支持 https：${ref.origin}`;
    if (u.url !== ref.origin.replace(/\/+$/, '')) return `远程地址需写成规范形式 ${u.url}`;
  } catch (e) {
    return `远程地址无效（${ref.origin}）：${(e as Error).message}`;
  }
  return null;
}

/**
 * Fetch and materialise one remote tree (idempotent). The cache keeps the bare Git objects (`git/`), the
 * snapshots (`snapshots/<root_hash>/`) and an index from `url@commit` to the root hash.
 */
export async function materializeRemote(ref: TreeRef, cacheDir: string, opts: RemoteOptions = {}): Promise<RemoteTree> {
  const problem = remoteRefProblem(ref, !!opts.allowFileProtocol);
  if (problem) throw new Error(problem);
  const indexFile = join(cacheDir, 'index', `${sha256Hex(remoteKey(ref)).slice(0, 32)}.json`);
  const snapshotsDir = join(cacheDir, 'snapshots');
  if (existsSync(indexFile)) {
    const hit = JSON.parse(readFileSync(indexFile, 'utf8')) as { origin: string; commit: string; root_hash: string };
    const dir = join(snapshotsDir, hit.root_hash);
    if (hit.origin === ref.origin && hit.commit === ref.commit && existsSync(dir)) return { dir, rootHash: hit.root_hash };
  }
  if (opts.offline) throw new Error(`尚未拉取 ${ref.origin}@${ref.commit!.slice(0, 12)}（离线模式）`);
  opts.log?.(`拉取 ${ref.origin}@${ref.commit!.slice(0, 12)}…`);
  mkdirSync(join(cacheDir, 'tmp'), { recursive: true, mode: 0o700 });
  const executor = new Executor({ scratchDir: join(cacheDir, 'exec') });
  const snap = await createSnapshot({
    source: {
      kind: 'remote', remote: parseGitUrl(ref.origin, { allowFile: !!opts.allowFileProtocol }), ref: ref.commit, cacheRoot: join(cacheDir, 'git'),
      ...(opts.allowFileProtocol ? { auth: { allowFileProtocol: true } } : {}),
    },
    snapshotsDir, tmpDir: join(cacheDir, 'tmp'), executor,
  });
  if (snap.manifest.source.commit !== ref.commit) throw new Error(`拉取到的提交 ${snap.manifest.source.commit ?? '未知'} 与 manifest 的 ${ref.commit} 不一致`);
  mkdirSync(join(cacheDir, 'index'), { recursive: true });
  writeFileSync(indexFile, canonicalJson({ origin: ref.origin, commit: ref.commit, root_hash: snap.manifest.rootHash }) + '\n');
  return { dir: snap.root, rootHash: snap.manifest.rootHash };
}
