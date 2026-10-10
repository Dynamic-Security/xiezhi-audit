// Benchmark loading and validation: schema, cross references, partition rules,
// anti-leak layout checks, source headers, answer hints in comments, label anchors and root hashes.
import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, normalize, resolve } from 'node:path';
import { canonicalJson, sha256Hex } from '@xiezhi/contracts';
import { createSnapshot, Executor } from '@xiezhi/context';
import { functionSpans, langOf } from './locate.js';
import {
  AdjudicationFile, LabelFile, Manifest, type AdjudicationDecision, type CodeAnchor, type IdentityLabel, type Label, type NegativeLabel, type ReverifyLabel, type RiskHuntLabel, type Sample, type VulnLabel,
} from './schema.js';
import { cacheDirOf, isRemoteOrigin, materializeRemote, remoteKey, remoteRefProblem, sampleRefs, type RemoteOptions, type RemoteTree, type TreeRef } from './trees.js';
import { byString, EvalError, readYamlFile, removeTree, validated, walkFiles } from './util.js';

export const HEADER = 'Benchmark fixture. Never built.';
/** Datasets whose vulnerability labels must name at least one entry (hand-built and real-project labels). */
export const ENTRY_REQUIRED = new Set(['self-built', 'real-oss']);
/** Files that must carry the header comment on their first line. */
const HEADER_EXT = /(\.(java|go|xml|ya?ml|properties|sql|proto|gradle|kts|mod|md|ts|js|html|py|php|kt|cs|csproj|tsx|jsx|mjs|cjs|toml|txt|rb|rake|ru|erb|rs)|(^|\/)(Gemfile|Rakefile))$/i;
/** Answer hints that must never appear in source comments (暗示答案的注释不得进入快照). */
const HINT_WORDS = [
  'vulnerab', 'exploit', 'injection', 'insecure', 'idor', 'ssrf', 'xss', 'traversal', 'cwe-', 'cve-', 'decoy', 'true positive', 'false positive',
  'expected', 'label', 'fixed version', 'patched', 'backdoor', 'unsafe here', 'bug here', 'fix:', 'todo: fix', 'security issue',
  '漏洞', '注入', '越权', '修复', '误报', '诱饵', '标注', '期望', '危险点',
];

export type LocatedLabel = Label & { project: string; file: string };

export interface Bench {
  root: string;
  manifest: Manifest;
  /** sha256 over the canonical manifest and all label files: the exact answer key used. */
  manifestHash: string;
  labelsHash: string;
  labels: Map<string, LocatedLabel>;
  samples: Sample[];
  /** Adjudication decisions for `known_only` samples, by project; `decisionsHash` over all files. */
  decisions: Map<string, AdjudicationDecision[]>;
  decisionsHash: string;
  /** Remote trees materialised by `prepareTrees`, by `url@commit`. */
  remote: Map<string, RemoteTree>;
}

export interface Issue { level: 'error' | 'warn'; where: string; message: string }

export function loadBench(root: string): Bench {
  const abs = resolve(root);
  const mf = join(abs, 'manifest.yaml');
  if (!existsSync(mf)) throw new EvalError('BENCH_INVALID', `找不到 ${mf}`);
  const manifest = validated(Manifest, readYamlFile(mf), 'manifest.yaml');
  const labels = new Map<string, LocatedLabel>();
  const labelDir = join(abs, 'labels');
  const files = walkFiles(labelDir).filter((f) => /\.ya?ml$/.test(f));
  const labelTexts: string[] = [];
  for (const f of files) {
    const lf = validated(LabelFile, readYamlFile(join(labelDir, f)), `labels/${f}`);
    labelTexts.push(canonicalJson(lf));
    for (const l of lf.labels) {
      if (labels.has(l.label_id)) throw new EvalError('BENCH_INVALID', `标注 ID 重复：${l.label_id}（labels/${f}）`);
      labels.set(l.label_id, { ...(l as Label), project: lf.project, file: `labels/${f}` } as LocatedLabel);
    }
  }
  const decisions = new Map<string, AdjudicationDecision[]>();
  const decisionTexts: string[] = [];
  const adjDir = join(abs, 'adjudication');
  // Only top-level files are decisions; subdirectories (drafts, notes) are never read as effective decisions.
  for (const f of walkFiles(adjDir).filter((x) => /\.ya?ml$/.test(x) && !x.includes('/'))) {
    const af = validated(AdjudicationFile, readYamlFile(join(adjDir, f)), `adjudication/${f}`);
    decisionTexts.push(canonicalJson(af));
    decisions.set(af.project, [...(decisions.get(af.project) ?? []), ...af.decisions]);
  }
  return {
    root: abs, manifest, labels, samples: manifest.samples,
    manifestHash: sha256Hex(canonicalJson(manifest)), labelsHash: sha256Hex(labelTexts.join('\n')),
    decisions, decisionsHash: sha256Hex(decisionTexts.join('\n')), remote: new Map(),
  };
}

/** Absolute directory of a tree; null for a remote tree that `prepareTrees` has not materialised. */
export function treeDir(bench: Bench, ref: TreeRef): string | null {
  if (!isRemoteOrigin(ref.origin)) return join(bench.root, ref.origin);
  return bench.remote.get(remoteKey(ref))?.dir ?? null;
}

/**
 * Materialise the remote trees of these samples (fetching into the cache when needed). Returns the samples
 * whose trees could not be prepared, with the reasons; local trees need nothing.
 */
export async function prepareTrees(bench: Bench, samples: Sample[], opts: RemoteOptions = {}): Promise<Map<string, string[]>> {
  const failed = new Map<string, string[]>();
  const errors = new Map<string, string>();
  const cacheDir = cacheDirOf(bench.root, opts);
  for (const s of samples) {
    for (const r of sampleRefs(s)) {
      if (!isRemoteOrigin(r.origin)) continue;
      const key = remoteKey(r);
      if (!bench.remote.has(key) && !errors.has(key)) {
        try {
          bench.remote.set(key, await materializeRemote(r, cacheDir, opts));
        } catch (e) {
          errors.set(key, (e as Error).message.slice(0, 300));
        }
      }
      const err = errors.get(key);
      if (err) failed.set(s.sample_id, [...(failed.get(s.sample_id) ?? []), `${r.version}/${r.name}: ${err}`]);
    }
  }
  return failed;
}

function isSafeOrigin(origin: string): boolean {
  const n = normalize(origin).split('\\').join('/');
  return !isAbsolute(origin) && n.startsWith('sources/') && !n.split('/').includes('..');
}

/** Label ids of a sample by kind. */
export function sampleLabels(bench: Bench, s: Sample) {
  const all = s.labels.map((id) => bench.labels.get(id)).filter((l): l is LocatedLabel => !!l);
  return {
    vuln: all.filter((l): l is VulnLabel & LocatedLabel => l.kind === 'vuln'),
    negative: all.filter((l): l is NegativeLabel & LocatedLabel => l.kind === 'negative'),
    risk: all.filter((l): l is RiskHuntLabel & LocatedLabel => l.kind === 'risk_hunt'),
    reverify: all.filter((l): l is ReverifyLabel & LocatedLabel => l.kind === 'reverify'),
    identity: all.filter((l): l is IdentityLabel & LocatedLabel => l.kind === 'identity'),
  };
}

/** Repository trees of a sample: the base version and every later version, by version name. */
export function sampleTrees(s: Sample): Map<string, Map<string, TreeRef>> {
  const ref = (r: { origin: string; commit?: string | undefined }): TreeRef => ({ origin: r.origin, ...(r.commit ? { commit: r.commit } : {}) });
  const trees = new Map<string, Map<string, TreeRef>>([['base', new Map(s.repos.map((r) => [r.name, ref(r)]))]]);
  for (const v of s.scene_input?.versions ?? []) {
    const m = new Map(trees.get('base')!);
    for (const r of v.repos) m.set(r.name, ref(r));
    trees.set(v.name, m);
  }
  return trees;
}

/** The version a vulnerability label is anchored in (identity `b` labels live in their version). */
export function labelVersion(bench: Bench, s: Sample, labelId: string): string {
  for (const l of sampleLabels(bench, s).identity) if (l.b === labelId) return l.version;
  // Incremental (G5): the labelled vulnerability is in the changed version, not in the baseline.
  if (s.kind === 'incremental') return s.scene_input?.versions?.[0]?.name ?? 'base';
  return 'base';
}

function anchorIssues(bench: Bench, s: Sample, tree: Map<string, TreeRef>, a: CodeAnchor, where: string): Issue[] {
  const ref = tree.get(a.repo);
  if (!ref) return [{ level: 'error', where, message: `仓库 ${a.repo} 不在样本 ${s.sample_id} 中` }];
  const dir = treeDir(bench, ref);
  if (!dir) return [{ level: 'warn', where, message: `远程仓库 ${a.repo} 尚未拉取，锚点未校验` }];
  const origin = isRemoteOrigin(ref.origin) ? `${a.repo}@${ref.commit?.slice(0, 12)}` : ref.origin;
  const file = join(dir, a.file);
  if (!existsSync(file)) return [{ level: 'error', where, message: `文件不存在：${origin}/${a.file}` }];
  if (!a.function) {
    return a.line_range ? [] : [{ level: 'error', where, message: '没有 function 时必须给出 line_range' }];
  }
  if (!langOf(a.file)) return a.line_range ? [] : [{ level: 'error', where, message: `${a.file} 无法按函数定位，需给出 line_range` }];
  const spans = functionSpans(readFileSync(file, 'utf8'), a.file, a.function);
  if (!spans.length) return [{ level: 'error', where, message: `在 ${origin}/${a.file} 中找不到函数 ${a.function}` }];
  if (a.line_range && !spans.some((sp) => sp.start <= a.line_range![1]! && a.line_range![0]! <= sp.end)) {
    return [{ level: 'warn', where, message: `line_range ${a.line_range.join('-')} 不在函数 ${a.function} 内（参考值，匹配以函数为准）` }];
  }
  return [];
}

function commentLines(text: string, file: string): string[] {
  const out: string[] = [];
  if (/\.(xml|html|md|csproj)$/i.test(file)) for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) out.push(m[1]!);
  if (/(\.(ya?ml|properties|py|php|toml|txt|rb|rake|ru)|(^|\/)(Gemfile|Rakefile))$/i.test(file)) for (const m of text.matchAll(/(?:^|\s)#(?!\{)(.*)$/gm)) out.push(m[1]!);
  if (/\.erb$/i.test(file)) for (const m of text.matchAll(/<%#([\s\S]*?)%>/g)) out.push(m[1]!);
  if (/\.py$/i.test(file)) for (const m of text.matchAll(/("{3}|'{3})([\s\S]*?)\1/g)) out.push(m[2]!);
  if (/\.(java|go|gradle|kts|mod|proto|ts|js|sql|php|kt|cs|tsx|jsx|mjs|cjs|rs)$/i.test(file)) {
    for (const m of text.matchAll(/\/\/(.*)$/gm)) out.push(m[1]!);
    for (const m of text.matchAll(/\/\*([\s\S]*?)\*\//g)) out.push(m[1]!);
  }
  if (/\.sql$/i.test(file)) for (const m of text.matchAll(/--(.*)$/gm)) out.push(m[1]!);
  return out;
}

/** Everything `validate` checks except root hashes (which need snapshots). `allowFileProtocol`: tests only. */
export function staticChecks(bench: Bench, opts: { allowFileProtocol?: boolean } = {}): Issue[] {
  const issues: Issue[] = [];
  const err = (where: string, message: string) => issues.push({ level: 'error', where, message });
  const warn = (where: string, message: string) => issues.push({ level: 'warn', where, message });
  const m = bench.manifest;

  const active = new Set(m.sources.filter((x) => x.status === 'active').map((x) => x.dataset));
  const ids = new Set<string>();
  const partitionOf = new Map<string, string>();
  const basisFiles = new Set<string>();
  for (const s of m.samples) {
    const where = `sample ${s.sample_id}`;
    if (ids.has(s.sample_id)) err(where, 'sample_id 重复');
    ids.add(s.sample_id);
    if (!active.has(s.source.dataset)) err(where, `来源 ${s.source.dataset} 不是 active 状态的 sources 条目`);
    // The partition unit is the project.
    const p = partitionOf.get(s.project);
    if (p && p !== s.partition) err(where, `项目 ${s.project} 的样本分在不同分区（${p} / ${s.partition}）`);
    partitionOf.set(s.project, s.partition);
    const trees = sampleTrees(s);
    for (const [, tree] of trees) {
      for (const [name, ref] of tree) {
        if (isRemoteOrigin(ref.origin)) {
          const p = remoteRefProblem(ref, !!opts.allowFileProtocol);
          if (p) err(where, `仓库 ${name}：${p}`);
          continue;
        }
        if (ref.commit) warn(where, `仓库 ${name} 是本地目录，commit 只作记录`);
        if (!isSafeOrigin(ref.origin)) { err(where, `仓库 ${name} 的 origin 必须位于 sources/ 下或是 https Git 地址：${ref.origin}`); continue; }
        const abs = join(bench.root, ref.origin);
        if (!existsSync(abs) || !statSync(abs).isDirectory()) err(where, `仓库 ${name} 的源码目录不存在：${ref.origin}`);
      }
    }
    if (s.label_policy === 'known_only' && !['vuln', 'fixed', 'incremental'].includes(s.kind)) err(where, 'label_policy: known_only 只适用于 vuln / fixed / incremental 样本（真实项目无法断言“没有问题”）');
    if (s.scene === 'incremental' && s.kind !== 'incremental') err(where, 'scene=incremental 只用于 incremental 样本');
    if (!s.repos.some((r) => r.role === 'auditable')) err(where, '至少需要一个 auditable 仓库');
    if (s.scene_input?.basis_ref) {
      if (!isSafeOrigin(s.scene_input.basis_ref) || !existsSync(join(bench.root, s.scene_input.basis_ref))) err(where, `basis_ref 不存在或不在 sources/ 下：${s.scene_input.basis_ref}`);
      basisFiles.add(normalize(s.scene_input.basis_ref).split('\\').join('/'));
    }

    // Labels: existence, project, kinds per sample kind.
    for (const id of s.labels) {
      const l = bench.labels.get(id);
      if (!l) { err(where, `标注不存在：${id}`); continue; }
      if (l.project !== s.project) err(where, `标注 ${id} 属于项目 ${l.project}，不是 ${s.project}`);
    }
    const L = sampleLabels(bench, s);
    const expectKinds: Record<string, () => string | null> = {
      vuln: () => (L.vuln.length ? null : 'vuln 样本至少需要一条 vuln 标注'),
      fixed: () => (L.vuln.length ? 'fixed 样本不能有 vuln 标注' : L.negative.length ? null : 'fixed 样本需要一条 negative 标注（修复位置作为诱饵点）'),
      negative: () => (L.vuln.length ? 'negative 样本不能有 vuln 标注' : L.negative.length ? null : 'negative 样本至少需要一条 negative 标注'),
      risk_hunt: () => (L.risk.length === 1 && s.scene === 'risk_hunt' && s.scene_input?.basis_ref ? null : 'risk_hunt 样本需要 scene=risk_hunt、basis_ref 和恰好一条 risk_hunt 标注'),
      reverify: () => (L.reverify.length === 1 && s.scene === 'reverify' && s.scene_input?.versions?.length ? null : 'reverify 样本需要 scene=reverify、versions 和恰好一条 reverify 标注'),
      identity: () => (L.identity.length && s.scene_input?.versions?.length ? null : 'identity 样本需要 versions 和至少一条 identity 标注'),
      incremental: () => (s.scene === 'incremental' && s.scene_input?.versions?.length === 1 && L.vuln.length && !L.identity.length && !L.reverify.length
        ? null : 'incremental 样本需要 scene=incremental、恰好一个 versions（变更后的版本）和至少一条 vuln 标注（标注锚定在变更后的版本）'),
    };
    const k = expectKinds[s.kind]!();
    if (k) err(where, k);
    if (['vuln', 'fixed', 'negative'].includes(s.kind) && s.scene !== 'full') err(where, `${s.kind} 样本的 scene 应为 full`);
    for (const r of L.reverify) {
      if (!s.labels.includes(r.target_label)) err(where, `reverify 标注的 target_label ${r.target_label} 不在样本标注中`);
      if (s.scene_input?.target_label && s.scene_input.target_label !== r.target_label) err(where, 'scene_input.target_label 与 reverify 标注不一致');
      if (r.expected.length !== (s.scene_input?.versions?.length ?? 0)) err(where, 'reverify 标注的 expected 个数必须等于 versions 个数');
    }
    for (const r of L.identity) {
      if (!s.labels.includes(r.a) || !s.labels.includes(r.b)) err(where, `identity 标注 ${r.label_id} 的 a/b 必须在样本标注中`);
      if (!trees.has(r.version)) err(where, `identity 标注 ${r.label_id} 的 version ${r.version} 不在 scene_input.versions 中`);
    }

    // Anchors resolve in the right tree (independent locator).
    for (const l of L.vuln) {
      const tree = trees.get(labelVersion(bench, s, l.label_id)) ?? trees.get('base')!;
      issues.push(...anchorIssues(bench, s, tree, l.sink, `${where} / ${l.label_id}.sink`));
      (l.alt_sinks ?? []).forEach((a, i) => issues.push(...anchorIssues(bench, s, tree, a, `${where} / ${l.label_id}.alt_sinks[${i}]`)));
      if (!l.entries.every((e) => tree.has(e.repo))) err(`${where} / ${l.label_id}`, '入口的仓库不在样本中');
      if (!l.entries.length && ENTRY_REQUIRED.has(s.source.dataset)) err(`${where} / ${l.label_id}`, `来源 ${s.source.dataset} 的漏洞标注至少需要一个入口（只有导入的公开数据集可以不标入口）`);
      if (l.expected.verdict === 'pending' && !l.expected.missing?.length) err(`${where} / ${l.label_id}`, 'pending 标注需要 expected.missing');
    }
    for (const l of L.negative) l.decoys.forEach((d, i) => issues.push(...anchorIssues(bench, s, trees.get('base')!, d, `${where} / ${l.label_id}.decoys[${i}]`)));
    for (const l of L.risk) {
      for (const t of l.targets) {
        if (!trees.get('base')!.has(t.repo)) err(`${where} / ${l.label_id}`, `目标仓库 ${t.repo} 不在样本中`);
        if (t.expected === 'not_affected' && (!t.reason_type || !t.reason_evidence?.length)) err(`${where} / ${l.label_id}`, `${t.repo}：not_affected 需要 reason_type 与 reason_evidence`);
        if (t.expected === 'affected' && !t.locations?.length) err(`${where} / ${l.label_id}`, `${t.repo}：affected 需要 locations`);
        for (const a of [...(t.locations ?? []), ...(t.reason_evidence ?? [])]) issues.push(...anchorIssues(bench, s, trees.get('base')!, a, `${where} / ${l.label_id}.${t.repo}`));
      }
    }
  }

  // Adjudication decisions: known projects, known_only samples of that project, unique keys per scope.
  const knownOnly = new Map(m.samples.filter((s) => s.label_policy === 'known_only').map((s) => [s.sample_id, s.project]));
  // Completely labelled projects may record true positives found on their fixed / negative samples.
  const cleanComplete = new Map(m.samples.filter((s) => s.label_policy !== 'known_only' && (s.kind === 'fixed' || s.kind === 'negative')).map((s) => [s.sample_id, s.project]));
  const projects = new Set(m.samples.map((s) => s.project));
  for (const [project, ds] of bench.decisions) {
    const where = `adjudication ${project}`;
    if (!projects.has(project)) err(where, `项目 ${project} 不在 manifest 中`);
    const seen = new Map<string, string>();
    for (const d of ds) {
      if (!/^[a-z_]+\|[^|]+:.+:.+$/.test(d.key)) err(where, `key 格式应为“类别|仓库:路径:函数”（评分器输出的稳定键）：${d.key}`);
      const onComplete = (d.samples ?? []).some((sid) => cleanComplete.get(sid) === project);
      if (onComplete && (d.verdict !== 'true_positive' || !(d.samples ?? []).every((sid) => cleanComplete.get(sid) === project))) {
        err(where, `${d.key}：完整标注项目的裁定只能是 fixed / negative 样本上的 true_positive，且 samples 只列这类样本`);
      }
      for (const sid of d.samples ?? []) {
        if (knownOnly.get(sid) !== project && cleanComplete.get(sid) !== project) err(where, `${d.key}：样本 ${sid} 不是项目 ${project} 的 known_only 样本，也不是其 fixed / negative 样本`);
      }
      if (!d.samples && ![...knownOnly.values()].includes(project)) err(where, `${d.key}：完整标注项目的裁定必须用 samples 限定到 fixed / negative 样本`);
      for (const scope of d.samples ?? ['*']) {
        const k = `${d.key}\u0000${scope}`;
        const prev = seen.get(k);
        if (prev && prev !== d.verdict) err(where, `${d.key}：同一范围内有相互矛盾的裁定`);
        seen.set(k, d.verdict);
      }
    }
    if (![...knownOnly.values()].includes(project) && !ds.every((d) => (d.samples ?? []).some((sid) => cleanComplete.get(sid) === project))) warn(where, `项目 ${project} 没有 known_only 样本，裁定不会被使用`);
  }

  // Every label is used; labels never live in a source tree.
  const used = new Set(m.samples.flatMap((s) => s.labels));
  for (const id of bench.labels.keys()) if (!used.has(id)) warn(`label ${id}`, '标注未被任何样本引用');

  // Anti-leak layout: sources hold code only — no labels, manifests or expected-result files.
  const sourceFiles = walkFiles(join(bench.root, 'sources'));
  for (const f of sourceFiles) {
    const rel = `sources/${f}`;
    const base = f.split('/').pop()!.toLowerCase();
    if (/^(manifest|labels?|expected|answers?)[._-]/.test(base) || base === 'manifest.yaml') { err(rel, '标注 / manifest / 期望结果文件不能放在 sources/ 下'); continue; }
    const text = readFileSync(join(bench.root, rel), 'utf8');
    if (/^\s*(label_id|bench_version)\s*:/m.test(text)) err(rel, '源码目录中出现标注或 manifest 内容');
    if (basisFiles.has(rel)) continue; // the basis text is model input by design
    const firstLine = text.split('\n').find((l) => l.trim().length > 0) ?? '';
    if (HEADER_EXT.test(f)) {
      if (!firstLine.includes(HEADER)) err(rel, `首行缺少“${HEADER}”头注释`);
    } else warn(rel, '该类型文件无法写头注释');
    const lowered = commentLines(text, f).map((c) => c.toLowerCase());
    for (const w of HINT_WORDS) {
      const hit = lowered.find((c) => c.includes(w));
      if (hit) err(rel, `注释中出现暗示答案的词“${w}”：${hit.trim().slice(0, 80)}`);
    }
  }

  // Partition ratio (~7:3 by project).
  const byProject = [...partitionOf.entries()];
  const hold = byProject.filter(([, p]) => p === 'holdout').length;
  if (byProject.length >= 3) {
    const share = hold / byProject.length;
    if (share < 0.2 || share > 0.4) warn('manifest', `留出集项目占比 ${(share * 100).toFixed(0)}%，偏离约 30% 的目标`);
  }
  return issues.sort((a, b) => byString(a.where, b.where) || byString(a.message, b.message));
}

/** Content hash of a source tree exactly as the product's snapshot computes it. */
export class TreeHasher {
  private readonly cache = new Map<string, string>();
  private readonly dir: string;
  private readonly executor: Executor;

  constructor() {
    this.dir = mkdtempSync(join(tmpdir(), 'ca-eval-hash-'));
    this.executor = new Executor({ scratchDir: join(this.dir, 'exec') });
  }

  async hash(absDir: string): Promise<string> {
    const hit = this.cache.get(absDir);
    if (hit) return hit;
    const snap = await createSnapshot({ source: { kind: 'local', path: absDir }, snapshotsDir: join(this.dir, 'snap'), tmpDir: join(this.dir, 'tmp'), executor: this.executor });
    this.cache.set(absDir, snap.manifest.rootHash);
    return snap.manifest.rootHash;
  }

  dispose(): void {
    removeTree(this.dir);
  }
}

/**
 * root_hash check per sample (不一致时样本作废). Returns the invalid samples and why. Remote trees must
 * have been prepared (`prepareTrees`); their hash is the one the product's snapshot computed when fetching.
 */
export async function checkRootHashes(bench: Bench, samples: Sample[], hasher = new TreeHasher()): Promise<Map<string, string[]>> {
  const bad = new Map<string, string[]>();
  try {
    for (const s of samples) {
      for (const t of sampleRefs(s)) {
        const add = (why: string) => bad.set(s.sample_id, [...(bad.get(s.sample_id) ?? []), `${t.version}/${t.name}: ${why}`]);
        if (isRemoteOrigin(t.origin)) {
          const hit = bench.remote.get(remoteKey(t));
          if (!hit) add('远程仓库尚未拉取');
          else if (hit.rootHash !== t.root_hash) add(`root_hash 不一致（manifest ${t.root_hash.slice(0, 12)}…，实际 ${hit.rootHash.slice(0, 12)}…）`);
          continue;
        }
        const abs = join(bench.root, t.origin);
        if (!existsSync(abs)) { add('源码目录不存在'); continue; }
        const actual = await hasher.hash(abs);
        if (actual !== t.root_hash) add(`root_hash 不一致（manifest ${t.root_hash.slice(0, 12)}…，实际 ${actual.slice(0, 12)}…）`);
      }
    }
  } finally {
    hasher.dispose();
  }
  return bad;
}
