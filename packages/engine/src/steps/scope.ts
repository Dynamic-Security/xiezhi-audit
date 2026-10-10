// scope: deterministic impact analysis between the baseline and head snapshots
// of an incremental audit. Runs during planning so the plan can show the baseline, the change size and
// the analysis mode; the pipeline then hunts over the impact slice instead of the whole repository.
import { Type } from 'typebox';
import { stageModel, SubmitVariantPatterns, type DiffHunk, type ImpactSet, type StructIndex } from '@xiezhi/contracts';
import { buildIndex, computeImpact, lineHunks, toolGrep, type RuleSet } from '@xiezhi/context';
import type { AuditTool } from '@xiezhi/agent';
import type { AuditRuntime } from '../runtime.js';
import { sessionError, StepError, type AttemptContext, type StepResult } from '../step-runner.js';
import { buildCandidates, makeBatches, rankCandidates, scopePredicate, type Candidate, type TriageOutput } from './triage.js';
import { P } from '@xiezhi/knowledge';

export function scopeIdentity(rt: AuditRuntime, rules: RuleSet) {
  const base = rt.baseRepo();
  const m = stageModel(rt.strategy, 'scope')!;
  return {
    repo: rt.targetRepo.id, base: base?.rootHash ?? null, head: rt.targetRepo.rootHash, ast: rt.strategy.tools.ast, impact: rt.strategy.impact, rules: rules.version,
    // Variant search is model output: a different model is a different result.
    ...(rt.strategy.impact.variantSearch ? { variantModel: `${m.provider}/${m.model}` } : {}),
  };
}

export async function scopeStep(rt: AuditRuntime, rules: RuleSet, ctx: AttemptContext): Promise<StepResult> {
  const head = rt.targetRepo;
  const base = rt.baseRepo();
  const headView = rt.views.get(head.name);
  const baseView = rt.baseViews.get(head.name);
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
  if (rt.strategy.impact.variantSearch && impact.mode !== 'full_scan' && changedPaths(rt, impact).length) {
    impact.variants = await variantSearch(rt, impact, ctx);
  }
  return { outputRef: rt.store.artifacts.putJson(impact) };
}

/** Variant hits kept per pattern and in total (the hunt cost stays bounded). */
export const VARIANT_HITS_PER_PATTERN = 10;
export const VARIANT_HITS_TOTAL = 30;

/**
 * Diff-seeded variant search (Big Sleep): the agent abstracts the patterns the change fixed or
 * introduced into ripgrep expressions; the engine greps the head snapshot deterministically and keeps hits
 * in files the change did not touch. They become hunt candidates.
 */
async function variantSearch(rt: AuditRuntime, impact: ImpactSet, ctx: AttemptContext): Promise<NonNullable<ImpactSet['variants']>> {
  const changed = changedPaths(rt, impact);
  const submit: AuditTool = {
    name: 'submit_variant_patterns', kind: 'submit', parameters: SubmitVariantPatterns,
    description: P('tool.submit_variant_patterns'),
    validate: (a: SubmitVariantPatterns) => a.patterns.flatMap((p, i) => {
      try { new RegExp(p.grep); return []; } catch { return [P('feedback.variant.bad_regex', { i })]; }
    }),
    run: (a: SubmitVariantPatterns) => ({ text: `recorded ${a.patterns.length} pattern(s)` }),
  };
  const prompt = [
    P('scope.variant'),
    '', '## 本次变更（基线 → 当前）', ...changed.slice(0, 6).map((p) => renderFileDiff(rt, p, 200)),
  ].join('\n');
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'scope', phase: 'hunt', model: stageModel(rt.strategy, 'scope')!, signal: ctx.signal,
    prompt, submitTools: [submit], requiredSubmits: ['submit_variant_patterns'], maxTurns: Math.min(20, rt.strategy.limits.maxTurnsPerStep), withIndex: false,
  });
  const err = sessionError(outcome);
  if (err) throw err;
  const patterns = ((outcome.submissions.submit_variant_patterns ?? []) as SubmitVariantPatterns[]).at(-1)?.patterns ?? [];
  const changedSet = new Set(changed);
  const seen = new Set<string>();
  const out: NonNullable<ImpactSet['variants']> = [];
  let total = 0;
  for (const p of patterns) {
    let hits: { path: string; line: number; text: string }[] = [];
    try {
      const r = await toolGrep(rt.toolContext(ctx.signal, ctx.stepId), { repo: rt.targetRepo.name, pattern: p.grep, regex: true, caseSensitive: true, maxResults: 200, ...(p.glob ? { glob: p.glob } : {}) });
      hits = r.matches.filter((m) => !m.context && !changedSet.has(m.path)).map((m) => ({ path: m.path, line: m.line, text: m.text.slice(0, 200) }));
    } catch { /* an unusable pattern yields no hits */ }
    const kept = hits.filter((h) => { const k = `${h.path}:${h.line}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, Math.max(0, Math.min(VARIANT_HITS_PER_PATTERN, VARIANT_HITS_TOTAL - total)));
    total += kept.length;
    out.push({ description: p.description, grep: p.grep, hits: kept });
  }
  rt.event('judgement.made', { kind: 'variant_search', patterns: out.length, hits: total }, ctx.stepId);
  return out;
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
};

export function impactLimitations(impact: ImpactSet): string[] {
  const out = [`增量影响分析：${IMPACT_MODE_TEXT[impact.mode]}。`];
  for (const r of impact.fallbackReasons) out.push(`影响分析回退原因：${IMPACT_REASON_TEXT[r] ?? r}。`);
  out.push('增量审计只覆盖影响范围：范围外的已知漏洞本次记为“未覆盖”，状态不变（没有覆盖到不等于已修复）。');
  return out;
}

/** Changed files that the incremental audit looks at (in scope, not deleted). */
export function changedPaths(rt: AuditRuntime, impact: ImpactSet): string[] {
  const inScope = scopePredicate(rt.strategy.scope.include, rt.strategy.scope.exclude);
  const view = rt.views.get(rt.targetRepo.name)!;
  return [...impact.changedFiles.added, ...impact.changedFiles.modified, ...impact.changedFiles.renamed.map((r) => r.to)]
    .filter((p) => inScope(p) && view.hasFile(p)).sort();
}

/**
 * Candidates of an incremental audit (`scope → hunt`): the affected entrypoints and sinks,
 * plus one "change" candidate per changed file not already represented (config, mapper XML, code the
 * index cannot attribute). A full-scan fallback uses the full candidate set. Same shape as triage.
 */
export function incrementalSelection(rt: AuditRuntime, impact: ImpactSet): TriageOutput {
  const max = rt.strategy.limits.maxCandidates;
  let candidates: Candidate[];
  if (impact.mode === 'full_scan') {
    candidates = rankCandidates(buildCandidates(rt));
  } else {
    const affected = new Set([...impact.affectedEntrypoints, ...impact.affectedSinks]);
    const indexed = rankCandidates(buildCandidates(rt).filter((c) => affected.has(c.id)));
    const covered = new Set(indexed.map((c) => c.path));
    const hunkCount = (p: string) => impact.hunks.filter((h) => h.path === p).length;
    const changes: Candidate[] = changedPaths(rt, impact).filter((p) => !covered.has(p)).map((p) => ({
      id: `change:${p}`, kind: 'change', repo: rt.targetRepo.name, path: p, line: impact.hunks.find((h) => h.path === p)?.headStart || 1,
      label: `[change] ${impact.changedFiles.added.includes(p) ? '新增文件' : impact.changedFiles.renamed.some((r) => r.to === p) ? '移动的文件' : `修改（${hunkCount(p)} 处）`}`,
      score: 1,
    }));
    // Variant hits: unchanged places with the pattern the change fixed or introduced.
    const variants: Candidate[] = (impact.variants ?? []).flatMap((v) => v.hits.map((h) => ({
      id: `variant:${h.path}#L${h.line}`, kind: 'change' as const, repo: rt.targetRepo.name, path: h.path, line: h.line,
      label: `[variant] 与本次变更相似：${v.description}`, score: 1,
    })));
    candidates = [...indexed, ...changes, ...variants];
  }
  const selected = candidates.slice(0, max);
  return {
    candidates, selected: selected.map((c) => c.id), overflow: candidates.slice(max).map((c) => c.id), batches: makeBatches(selected),
  };
}

const CONTEXT = 3;
const MAX_DIFF_LINES = 400;

/** Unified-style diff of one file with head-side line numbers (what the Agent must cite). */
export function renderFileDiff(rt: AuditRuntime, path: string, maxLines = MAX_DIFF_LINES): string {
  const head = rt.views.get(rt.targetRepo.name)!;
  const base = rt.baseViews.get(rt.targetRepo.name);
  const b = base?.hasFile(path) ? base.lines(path) : [];
  const h = head.hasFile(path) ? head.lines(path) : [];
  const hunks: DiffHunk[] = lineHunks(path, b, h);
  if (!base?.hasFile(path)) return P('scope.diff.new_file', { path, lines: h.length });
  const out: string[] = [`### ${path}`];
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

/** Incremental sessions' `diff` tool: changed-file list, or one file's diff. */
export function diffTool(rt: AuditRuntime, impact: ImpactSet): AuditTool {
  return {
    name: 'diff', kind: 'read', untrusted: 'diff',
    description: P('tool.diff'),
    parameters: Type.Object({ path: Type.Optional(Type.String({ maxLength: 1000 })) }, { additionalProperties: false }),
    run: (a: { path?: string }) => {
      if (!a.path) {
        const c = impact.changedFiles;
        const lines = [
          ...c.added.map((p) => `A ${p}`), ...c.modified.map((p) => `M ${p}`), ...c.deleted.map((p) => `D ${p}`), ...c.renamed.map((r) => `R ${r.from} → ${r.to}`),
        ];
        return { text: lines.length ? lines.join('\n') : '（没有变更）' };
      }
      const view = rt.views.get(rt.targetRepo.name)!;
      let rel: string;
      try {
        rel = view.guard(a.path);
      } catch (e) {
        const base = rt.baseViews.get(rt.targetRepo.name);
        if (base?.hasFile(a.path) && impact.changedFiles.deleted.includes(a.path)) return { text: `${a.path} 在当前版本中已删除（基线 ${base.lines(a.path).length} 行）` };
        return { text: `error: ${(e as Error).message}` };
      }
      return { text: renderFileDiff(rt, rel, 2000) };
    },
  };
}
