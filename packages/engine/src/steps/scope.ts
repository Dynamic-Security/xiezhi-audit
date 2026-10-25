// scope: deterministic impact analysis between the baseline and head snapshots
// of an incremental audit. Runs during planning so the plan can show the baseline, the change size and
// the analysis mode; the pipeline then hunts over the impact slice instead of the whole repository.
import { Type } from 'typebox';
import type { DiffHunk, ImpactSet, StructIndex } from '@xiezhi/contracts';
import { buildIndex, computeImpact, lineHunks, type RuleSet } from '@xiezhi/context';
import type { AuditTool } from '@xiezhi/agent';
import type { AuditRuntime, RepoInfo } from '../runtime.js';
import { StepError, type AttemptContext, type StepResult } from '../step-runner.js';
import { buildCandidates, makeBatches, rankCandidates, scopePredicate, type Candidate, type TriageOutput } from './triage.js';
import { P } from '@xiezhi/knowledge';

/** One scope step per target repository (each target of a multi-repository incremental audit has its own baseline). */
export function scopeIdentity(rt: AuditRuntime, rules: RuleSet, head: RepoInfo = rt.targetRepo) {
  const base = rt.baseRepo(head.id);
  return {
    repo: head.id, base: base?.rootHash ?? null, head: head.rootHash, ast: rt.strategy.tools.ast, impact: rt.strategy.impact, rules: rules.version,
  };
}

export async function scopeStep(rt: AuditRuntime, rules: RuleSet, ctx: AttemptContext, head: RepoInfo = rt.targetRepo): Promise<StepResult> {
  const base = rt.baseRepo(head.id);
  const headView = rt.views.get(head.name);
  const baseView = rt.baseViews.get(head.name);
  if (headView && !base && rt.audit.mode === 'multi') return { outputRef: rt.store.artifacts.putJson(noBaselineImpact(headView.manifest.files.map((f) => f.path))) };
  if (!base || !baseView || !headView) throw new StepError('SNAPSHOT_UNAVAILABLE', 'incremental audit has no baseline snapshot');
  let baseIndex: StructIndex | undefined;
  let headIndex: StructIndex | undefined;
  if (rt.strategy.tools.ast) {
    try {
      baseIndex = (await buildIndex(baseView, rules, { indexesDir: rt.store.paths.indexes, signal: ctx.signal, ...rt.indexLanguages(head.name, baseView) })).index;
    } catch {
      baseIndex = undefined; // reported as no_baseline_index → full scan
    }
    headIndex = rt.indexes.get(head.name);
  }
  const impact = computeImpact({
    base: { manifest: baseView.manifest, src: baseView, ...(baseIndex ? { index: baseIndex } : {}) },
    head: { manifest: headView.manifest, src: headView, ...(headIndex ? { index: headIndex } : {}) },
    params: rt.strategy.impact, ast: rt.strategy.tools.ast,
  });
  return { outputRef: rt.store.artifacts.putJson(impact) };
}

/** A target without a baseline: every file is new and the repository is audited in full. */
export function noBaselineImpact(files: string[]): ImpactSet {
  return {
    mode: 'full_scan', fallbackReasons: ['no_baseline'], changedFiles: { added: [...files].sort(), modified: [], deleted: [], renamed: [] }, hunks: [],
    changedSymbols: [], renames: [], affectedSymbols: [], affectedEntrypoints: [], affectedSinks: [],
    stats: { indexableFiles: 0, changedIndexableFiles: 0, unresolvedCallers: 0, resolvedCallers: 0 },
  };
}

/** Human-readable mode and fallback reasons for the plan and report (N5: say how precise this is). */
export const IMPACT_MODE_TEXT: Record<ImpactSet['mode'], string> = {
  precise: '精确：只审计受变更影响的入口与危险点（调用链全部可解析）',
  heuristic: '启发式：影响范围含不确定的调用关系，Agent 需要复核',
  full_scan: '退化为全量：影响分析不可靠，按全量候选审计',
};
export const IMPACT_REASON_TEXT: Record<string, string> = {
  ast_disabled: '未开启 AST 结构解析，只以 diff 为中心审查，调用方由 Agent 用 grep 追溯',
  no_baseline_index: '基线版本没有可用的结构索引',
  too_many_changes: '变更文件占比超过阈值',
  parse_gap_in_changed_files: '变更文件中解析失败的比例过高',
  unresolved_edges_dominant: '无法解析的调用多于可解析的调用',
  no_baseline: '没有基线（没有已完成的审计，也没有指定基线版本），按全量审计',
};

/** `impacts` by target; a multi-repository audit names each repository. */
export function impactLimitations(impacts: Map<string, ImpactSet>): string[] {
  const out: string[] = [];
  const multi = impacts.size > 1;
  for (const [repo, impact] of impacts) {
    const at = multi ? `（${repo}）` : '';
    if (multi && impact.mode !== 'full_scan' && !changedFileCount(impact)) {
      out.push(`增量影响分析${at}：相对基线没有变更，不产生候选，只作为跨仓调用链的依据。`);
      continue;
    }
    out.push(`增量影响分析${at}：${IMPACT_MODE_TEXT[impact.mode]}。`);
    for (const r of impact.fallbackReasons) out.push(`影响分析回退原因${at}：${IMPACT_REASON_TEXT[r] ?? r}。`);
  }
  out.push('增量审计只覆盖影响范围：范围外的已知漏洞本次记为“未覆盖”，状态不变（没有覆盖到不等于已修复）。');
  return out;
}

/**
 * Changed files over all targets for prompts (`changedPaths` of each): `repo:path` when the audit has several targets;
 * a target without a baseline is one line instead of all its files.
 */
export function changedFileList(rt: AuditRuntime, impacts: Map<string, ImpactSet>): string[] {
  const multi = impacts.size > 1;
  return [...impacts].flatMap(([repo, impact]) => {
    if (impact.fallbackReasons.includes('no_baseline')) return [`${repo}（没有基线，全部 ${impact.changedFiles.added.length} 个文件按全量审计）`];
    return changedPaths(rt, impact, repo).map((p) => (multi ? `${repo}:${p}` : p));
  });
}

const changedFileCount = (impact: ImpactSet) => {
  const c = impact.changedFiles;
  return c.added.length + c.modified.length + c.deleted.length + c.renamed.length;
};

/** Changed files of one target (default the first) that the incremental audit looks at (in scope, not deleted). */
export function changedPaths(rt: AuditRuntime, impact: ImpactSet, repo = rt.targetRepo.name): string[] {
  const inScope = scopePredicate(rt.strategy.scope.include, rt.strategy.scope.exclude);
  const view = rt.views.get(repo)!;
  return [...impact.changedFiles.added, ...impact.changedFiles.modified, ...impact.changedFiles.renamed.map((r) => r.to)]
    .filter((p) => inScope(p) && view.hasFile(p)).sort();
}

/**
 * Candidates of an incremental audit (`scope → hunt`): the affected entrypoints and sinks,
 * plus one "change" candidate per changed file not already represented (config, mapper XML, code the
 * index cannot attribute). A full-scan fallback uses the full candidate set. Same shape as triage.
 * `impacts` has one impact set per target; each target is selected by its own.
 */
export function incrementalSelection(rt: AuditRuntime, impacts: Map<string, ImpactSet>): TriageOutput {
  const max = rt.strategy.limits.maxCandidates;
  // Change candidate ids name the repository when the audit has several targets.
  const multi = rt.targets.length > 1;
  const all = buildCandidates(rt);
  const indexed: Candidate[] = [];
  const changes: Candidate[] = [];
  for (const t of rt.targets) {
    const impact = impacts.get(t.name);
    if (!impact) continue;
    const own = all.filter((c) => c.repo === t.name);
    if (impact.mode === 'full_scan') {
      indexed.push(...own);
      continue;
    }
    const affected = new Set([...impact.affectedEntrypoints, ...impact.affectedSinks]);
    const hit = own.filter((c) => affected.has(c.id));
    indexed.push(...hit);
    const covered = new Set(hit.map((c) => c.path));
    const at = multi ? `${t.name}:` : '';
    const hunkCount = (p: string) => impact.hunks.filter((h) => h.path === p).length;
    changes.push(...changedPaths(rt, impact, t.name).filter((p) => !covered.has(p)).map((p) => ({
      id: `change:${at}${p}`, kind: 'change' as const, repo: t.name, path: p, line: impact.hunks.find((h) => h.path === p)?.headStart || 1,
      label: `[change] ${impact.changedFiles.added.includes(p) ? '新增文件' : impact.changedFiles.renamed.some((r) => r.to === p) ? '移动的文件' : `修改（${hunkCount(p)} 处）`}`,
      score: 1,
    })));
  }
  const candidates = [...rankCandidates(indexed), ...changes];
  const selected = candidates.slice(0, max);
  return {
    candidates, selected: selected.map((c) => c.id), overflow: candidates.slice(max).map((c) => c.id), batches: makeBatches(selected),
  };
}

const CONTEXT = 3;
const MAX_DIFF_LINES = 400;

/** Unified-style diff of one file of a target (default the first) with head-side line numbers (what the Agent must cite). */
export function renderFileDiff(rt: AuditRuntime, path: string, maxLines = MAX_DIFF_LINES, repo = rt.targetRepo.name): string {
  const head = rt.views.get(repo)!;
  const base = rt.baseViews.get(repo);
  const b = base?.hasFile(path) ? base.lines(path) : [];
  const h = head.hasFile(path) ? head.lines(path) : [];
  const hunks: DiffHunk[] = lineHunks(path, b, h);
  if (!base?.hasFile(path)) return P('scope.diff.new_file', { path: rt.targets.length > 1 ? `${repo}:${path}` : path, lines: h.length });
  const out: string[] = [`### ${rt.targets.length > 1 ? `${repo}:${path}` : path}`];
  for (const x of hunks) {
    const hs = Math.max(1, (x.headCount ? x.headStart : x.headStart + 1) - CONTEXT);
    out.push(`@@ 基线 ${x.baseStart},${x.baseCount} → 当前 ${x.headStart},${x.headCount} @@`);
    const pre = (x.headCount ? x.headStart : x.headStart + 1) - hs;
    for (let i = 0; i < pre; i++) out.push(`  ${String(hs + i).padStart(5)}  ${h[hs + i - 1] ?? ''}`);
    for (let i = 0; i < x.baseCount; i++) out.push(`- ${' '.repeat(5)}  ${b[(x.baseStart - 1) + i] ?? ''}`);
    for (let i = 0; i < x.headCount; i++) out.push(`+ ${String(x.headStart + i).padStart(5)}  ${h[x.headStart - 1 + i] ?? ''}`);
    const after = (x.headCount ? x.headStart + x.headCount : x.headStart + 1);
    for (let i = 0; i < CONTEXT && after + i <= h.length; i++) out.push(`  ${String(after + i).padStart(5)}  ${h[after + i - 1] ?? ''}`);
    if (out.length > maxLines) { out.push(P('scope.diff.truncated')); break; }
  }
  return out.join('\n');
}

/** Changed-file list of one impact set (`diff` tool without a path). */
function changeList(impact: ImpactSet): string[] {
  const c = impact.changedFiles;
  if (impact.fallbackReasons.includes('no_baseline')) return [`（没有基线：全部 ${c.added.length} 个文件按新增处理，按全量审计）`];
  return [...c.added.map((p) => `A ${p}`), ...c.modified.map((p) => `M ${p}`), ...c.deleted.map((p) => `D ${p}`), ...c.renamed.map((r) => `R ${r.from} → ${r.to}`)];
}

/**
 * Incremental sessions' `diff` tool: changed-file list, or one file's diff. With several targets
 * The list is per repository and `repo` picks the repository of `path` (default: the one that changed it).
 */
export function diffTool(rt: AuditRuntime, impacts: Map<string, ImpactSet>): AuditTool {
  const multi = impacts.size > 1;
  return {
    name: 'diff', kind: 'read', untrusted: 'diff',
    description: P('tool.diff'),
    parameters: Type.Object({ path: Type.Optional(Type.String({ maxLength: 1000 })), ...(multi ? { repo: Type.Optional(Type.String({ maxLength: 200 })) } : {}) }, { additionalProperties: false }),
    run: (a: { path?: string; repo?: string }) => {
      if (a.repo && !impacts.has(a.repo)) return { text: `error: ${a.repo} 不是本次增量审计的目标仓库（${[...impacts.keys()].join('、')}）` };
      if (!a.path) {
        const pick = a.repo ? [[a.repo, impacts.get(a.repo)!] as const] : [...impacts];
        const lines = multi ? pick.flatMap(([repo, impact]) => [`## ${repo}`, ...(changeList(impact).length ? changeList(impact) : ['（没有变更）'])]) : changeList(pick[0]![1]);
        return { text: lines.length ? lines.join('\n') : '（没有变更）' };
      }
      const path = a.path;
      const touched = (impact: ImpactSet) => [...impact.changedFiles.added, ...impact.changedFiles.modified, ...impact.changedFiles.deleted, ...impact.changedFiles.renamed.map((r) => r.to)].includes(path);
      const repo = a.repo ?? [...impacts].find(([, impact]) => touched(impact))?.[0] ?? rt.targetRepo.name;
      const impact = impacts.get(repo);
      const view = rt.views.get(repo)!;
      let rel: string;
      try {
        rel = view.guard(path);
      } catch (e) {
        const base = rt.baseViews.get(repo);
        if (base?.hasFile(path) && impact?.changedFiles.deleted.includes(path)) return { text: `${path} 在当前版本中已删除（基线 ${base.lines(path).length} 行）` };
        return { text: `error: ${(e as Error).message}` };
      }
      return { text: renderFileDiff(rt, rel, 2000, repo) };
    },
  };
}
