// plan: one short LLM session produces the plan narrative; scale, estimate and limits
// are computed deterministically and attached by the engine.
import { domainHuntOn, gapFillOn } from '../domains.js';
import { checklistOn } from '../checklist.js';
import { plannedExploreMode } from '../explore.js';
import { supplementScope } from '../threat.js';
import { backfillScope } from './coverage-gap.js';
import { calibrated, calibrationRatio } from '../calibration.js';
import { SubmitPlan, type SubmitPlan as PlanSubmission, stageModel } from '@xiezhi/contracts';
import type { HuntBasis, ModelRef, StepKind } from '@xiezhi/contracts';
import type { AuditTool } from '@xiezhi/agent';
import { estimatePipeline, estimateStep, stageShortfalls, type PlanEstimate } from '../estimates.js';
import { lspLanguageOfLang, lspServer, LSP_SERVER_NAMES } from '../lsp.js';
import { auditLanguagesOfView, type LspLanguage } from '@xiezhi/context';
import { auditLanguageLabels } from '@xiezhi/contracts';
import type { AuditRuntime } from '../runtime.js';
import { sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { buildCandidates } from './triage.js';
import { changedPaths, IMPACT_MODE_TEXT, impactLimitations, incrementalSelection } from './scope.js';
import { P } from '@xiezhi/knowledge';

const BUDGET_STAGE_LABEL: Record<string, string> = {
  prepare: '计划与画像', triage: '初筛', hunt: '深入审计', gap: '覆盖补齐', hypotheses: '风险假设', explore: '深度探索', merge: '归并', review: '对抗复核', verify: '复验',
};
const tokensLabel = (n: number) => (n >= 1e6 ? `${(n / 1e6).toFixed(1)}M` : `${Math.round(n / 1e3)}k`);

/** Incremental audits: what is compared and how precise the impact analysis is. */
export interface IncrementalSummary {
  base: { auditId: string | null; ref: string | null; commit: string | null; rootHash: string; worktree: boolean };
  mode: 'precise' | 'heuristic' | 'full_scan';
  fallbackReasons: string[];
  changedFiles: { added: number; modified: number; deleted: number; renamed: number };
  changedSymbols: number;
  affectedEntrypoints: number;
  affectedSinks: number;
}

export interface AuditPlan {
  submitted: PlanSubmission;
  scale: { files: number; byLang: Record<string, number>; entrypoints: number; sinks: number; candidates: number; sinksByCategory: Record<string, number> };
  estimate: PlanEstimate;
  strategySources: Record<string, string>;
  limitations: string[];
  knowledge: string[];
  incremental?: IncrementalSummary;
}

export function incrementalSummary(rt: AuditRuntime): IncrementalSummary | undefined {
  const impact = rt.impact();
  const base = rt.baseRepo();
  if (!impact || !base) return undefined;
  const snap = rt.store.get<{ requested_ref: string | null; resolved_commit: string | null; is_worktree: number }>('SELECT requested_ref, resolved_commit, is_worktree FROM snapshot WHERE id = ?', base.snapshotId);
  const c = impact.changedFiles;
  return {
    base: { auditId: rt.audit.base_audit_id ?? null, ref: snap?.requested_ref ?? null, commit: snap?.resolved_commit ?? null, rootHash: base.rootHash, worktree: !!snap?.is_worktree },
    mode: impact.mode as IncrementalSummary['mode'], fallbackReasons: impact.fallbackReasons,
    changedFiles: { added: c.added.length, modified: c.modified.length, deleted: c.deleted.length, renamed: c.renamed.length },
    changedSymbols: impact.changedSymbols.length, affectedEntrypoints: impact.affectedEntrypoints.length, affectedSinks: impact.affectedSinks.length,
  };
}

/** Scale over every target repository (multi-repository audits sum their targets). */
export function scaleSummary(rt: AuditRuntime): AuditPlan['scale'] {
  const sinksByCategory: Record<string, number> = {};
  const byLang: Record<string, number> = {};
  let files = 0;
  let entrypoints = 0;
  let sinks = 0;
  for (const t of rt.targets) {
    const v = rt.views.get(t.name)!;
    const idx = rt.indexes.get(t.name);
    files += v.manifest.stats.fileCount;
    for (const [l, n] of Object.entries(v.manifest.stats.byLang)) byLang[l] = (byLang[l] ?? 0) + n;
    for (const s of idx?.sinks ?? []) sinksByCategory[s.category] = (sinksByCategory[s.category] ?? 0) + 1;
    entrypoints += idx?.entrypoints.length ?? 0;
    sinks += idx?.sinks.length ?? 0;
  }
  return {
    files, byLang, entrypoints, sinks, sinksByCategory,
    candidates: rt.audit.scene === 'incremental' && rt.impact() ? incrementalSelection(rt, rt.impact()!).candidates.length : buildCandidates(rt).length,
  };
}

export function engineLimitations(rt: AuditRuntime): string[] {
  const out = ['静态审计：未构建、未运行、未测试目标代码。'];
  if (rt.strategy.tools.lsp) {
    const langs = new Set(rt.targets.flatMap((t) => Object.keys(rt.views.get(t.name)?.manifest.stats.byLang ?? {})).map(lspLanguageOfLang).filter((l): l is LspLanguage => !!l));
    for (const l of langs) {
      const { reason } = lspServer(rt.store.config, l);
      if (reason) out.push(`LSP（${LSP_SERVER_NAMES[l]}）不可用：${reason}；definition / references 退化为 tree-sitter 结构索引，用到时记 INDEX_DEGRADED。`);
    }
  }
  if (!rt.strategy.tools.ast) out.push('结构索引关闭：没有入口/危险点清单，覆盖对照不可用，只能用 grep/read 近似。');
  // Variant search is seeded by a diff; a full audit has none.
  if (rt.strategy.impact.variantSearch && rt.audit.scene !== 'incremental') out.push('变体搜索以本次变更（diff）为种子，只在增量审计中执行；本次全量审计没有基线，未执行。');
  for (const [repo, idx] of rt.indexes) if (idx.gaps.length) out.push(`${repo}：结构索引有 ${idx.gaps.length} 个缺口（解析失败或规则错误），覆盖分母不完整。`);
  if (rt.targets.every((t) => { const v = rt.views.get(t.name); return !v || auditLanguagesOfView(v).length === 0; })) {
    out.push(`仓库中没有可完整审计的源码：完整审计支持 ${auditLanguageLabels()}（JavaScript/TypeScript 需声明服务端框架依赖）。`);
  }
  // Services the code calls but the project does not contain (topology external services, 已知限制).
  const ext = rt.store.all<{ name: string }>(`SELECT DISTINCT n.name FROM topology_node n JOIN topology_edge e ON e.to_node = n.id AND e.removed = 0
    WHERE n.project_id = ? AND n.kind = 'external_service' ORDER BY n.name`, rt.audit.project_id).map((r) => r.name);
  if (ext.length) out.push(`缺失的仓库：代码调用了项目外的服务 ${ext.slice(0, 10).join('、')}${ext.length > 10 ? ' 等' : ''}，依赖它们的结论可能只能标为“待确认”。`);
  const related = rt.repos.filter((r) => r.role !== 'target').map((r) => r.name);
  if (related.length) out.push(`关联 / 上下文仓库 ${related.join('、')} 只作为证据来源，不产生其自身的发现。`);
  const impact = rt.audit.scene === 'incremental' ? rt.impact() : null;
  if (impact) out.push(...impactLimitations(impact));
  return out;
}

/**
 * Reverification plan: deterministic, no model call — the targets are known, so there is
 * nothing to plan; the audit is confirmed right after (reverify is an action).
 */
export function reverifyPlan(rt: AuditRuntime, targets: string[]): StepResult {
  const store = rt.store;
  const vulns = targets.map((id) => store.get<{ display_no: number; title: string; severity: string; category: string; lifecycle: string }>('SELECT display_no, title, severity, category, lifecycle FROM vulnerability WHERE id = ?', id)!);
  const s = rt.strategy;
  const v = rt.views.get(rt.targetRepo.name)!;
  const tokens = calibrated(store, estimateStep('verify-fix') * targets.length, 'verify-fix', stageModel(s, 'verify'));
  const pricing = store.config.pricing[`${s.models.audit.provider}/${s.models.audit.model}`];
  const cost = (t: number) => (pricing ? (t * 0.8 * pricing.input + t * 0.2 * pricing.output) / 1e6 : 0);
  const plan: AuditPlan = {
    submitted: {
      summary: `沿原链路定向复验 ${targets.length} 条漏洞在当前版本中是否仍然成立。`,
      focusDirections: vulns.map((x) => ({ direction: `V-${x.display_no} ${x.title}`, reason: `当前跨审计状态：${x.lifecycle}` })),
      plannedKnowledge: [], contextNeeded: [], limitations: [],
    },
    scale: { files: v.manifest.stats.fileCount, byLang: v.manifest.stats.byLang, entrypoints: 0, sinks: 0, candidates: targets.length, sinksByCategory: {} },
    estimate: {
      tokens: { p50: Math.ceil(tokens * 0.7), p90: Math.ceil(tokens * 1.3) }, durationSec: { p50: 60 * targets.length, p90: 180 * targets.length },
      cost: pricing ? { p50: cost(tokens * 0.7), p90: cost(tokens * 1.3), currency: pricing.currency } : null, byStep: { 'verify-fix': tokens },
    },
    strategySources: JSON.parse(rt.audit.strategy_sources) as Record<string, string>,
    limitations: [...engineLimitations(rt), '复验只沿每个漏洞的原链路定向验证，不寻找新的问题；“回归”只在漏洞曾“已修复（经验证）”时成立。'],
    knowledge: rt.knowledge.skills.map((k) => k.name),
  };
  const ref = store.artifacts.putJson(plan);
  return { outputRef: ref, apply: () => store.update('audit', { id: rt.auditId }, { plan_ref: ref }) };
}

/**
 * Risk hunt plan per project: deterministic from the confirmed basis — the hunt itself was
 * confirmed by the user at /hunts/{hid}/confirm, so the project audit starts at once.
 */
export function riskHuntPlan(rt: AuditRuntime, basis: HuntBasis): StepResult {
  const store = rt.store;
  const s = rt.strategy;
  const f = basis.features;
  const tokens = Math.min(s.budget.tokens, 60_000 * Math.max(1, rt.targets.length));
  const pricing = store.config.pricing[`${s.models.audit.provider}/${s.models.audit.model}`];
  const cost = (t: number) => (pricing ? (t * 0.8 * pricing.input + t * 0.2 * pricing.output) / 1e6 : 0);
  const scale = scaleSummary(rt);
  const plan: AuditPlan = {
    submitted: {
      summary: `风险排查：${basis.title}。先按排查特征定位候选点（依赖版本、危险 API、代码模式、指定位置），再逐个研判是否受影响。`,
      focusDirections: [
        ...f.dependencies.map((d) => ({ direction: `依赖 ${d.name} ${d.affectedVersions}`, reason: '受影响组件与版本范围' })),
        ...f.apis.map((a) => ({ direction: `危险 API ${a.pattern}`, reason: a.description })),
        ...f.codePatterns.map((p) => ({ direction: `代码模式：${p.description}`, reason: p.grep ? `grep ${p.grep}` : '由 Agent 按描述查找' })),
      ].slice(0, 20),
      plannedKnowledge: [], contextNeeded: [], limitations: [],
    },
    scale: { ...scale, candidates: 0 },
    estimate: {
      tokens: { p50: Math.ceil(tokens * 0.5), p90: tokens }, durationSec: { p50: 60 * rt.targets.length, p90: Math.min(s.budget.durationSec, 240 * rt.targets.length) },
      cost: pricing ? { p50: cost(tokens * 0.5), p90: cost(tokens), currency: pricing.currency } : null, byStep: { 'hunt-risk': tokens },
    },
    strategySources: JSON.parse(rt.audit.strategy_sources) as Record<string, string>,
    limitations: [...engineLimitations(rt), '风险排查只围绕这一个风险找位置、做判断，不是全面审计；判定条件：受影响——' + basis.affectedIf.join('；') + '；不受影响——' + basis.notAffectedIf.join('；')],
    knowledge: rt.knowledge.skills.map((k) => k.name),
  };
  const ref = store.artifacts.putJson(plan);
  return { outputRef: ref, apply: () => store.update('audit', { id: rt.auditId }, { plan_ref: ref }) };
}

/**
 * `deterministic`: no model session — the fallback when the plan model failed. The model's summary and focus
 * directions are only shown on the plan card, so the audit goes on with an engine-written plan instead of failing.
 */
export async function planStep(rt: AuditRuntime, ctx: AttemptContext, opts: { deterministic?: boolean } = {}): Promise<StepResult> {
  const scale = scaleSummary(rt);
  const submit: AuditTool = {
    name: 'submit_plan', kind: 'submit', parameters: SubmitPlan,
    description: P('tool.submit_plan'),
    run: () => ({ text: 'plan recorded' }),
  };
  const s = rt.strategy;
  const inc = incrementalSummary(rt);
  const impact = inc ? rt.impact()! : null;
  const prompt = [
    P('plan.intro'),
    ...(inc && impact ? [
      P('plan.incremental', {
        base: inc.base.ref ?? inc.base.commit?.slice(0, 12) ?? '上次审计的版本', added: inc.changedFiles.added, modified: inc.changedFiles.modified,
        deleted: inc.changedFiles.deleted, renamed: inc.changedFiles.renamed, mode: String(IMPACT_MODE_TEXT[inc.mode]), entrypoints: inc.affectedEntrypoints, sinks: inc.affectedSinks,
      }),
      `变更文件：${changedPaths(rt, impact).slice(0, 60).join('、') || '（无）'}`,
    ] : []),
    rt.repos.length > 1
      ? `仓库：${rt.repos.map((r) => `${r.name}（${r.role === 'target' ? '审计目标' : r.role === 'related' ? '关联' : '上下文'}）`).join('、')}；目标仓库合计文件 ${scale.files} 个；语言分布 ${JSON.stringify(scale.byLang)}。`
      : `仓库：${rt.targetRepo.name}；文件 ${scale.files} 个；语言分布 ${JSON.stringify(scale.byLang)}。`,
    `结构索引：入口 ${scale.entrypoints} 个，危险点 ${scale.sinks} 个（${JSON.stringify(scale.sinksByCategory)}），候选 ${scale.candidates} 个（上限 ${s.limits.maxCandidates}）。`,
    `关注点：${s.focus.categories.join('、') || '（未指定）'} ${s.focus.text ?? ''}`,
    P('plan.submit'),
  ].join('\n');
  let submitted: PlanSubmission;
  if (opts.deterministic) {
    submitted = {
      summary: `审计 ${rt.targets.map((r) => r.name).join('、')}：结构索引给出入口 ${scale.entrypoints} 个、危险点 ${scale.sinks} 个、候选 ${scale.candidates} 个。`,
      focusDirections: s.focus.categories.map((c) => ({ direction: c, reason: '任务指定的关注类别' })),
      plannedKnowledge: [], contextNeeded: [], limitations: ['规划模型没有成功，这份计划由引擎根据结构索引生成。'],
    };
  } else {
    const outcome = await rt.session({
      stepId: ctx.stepId, attempt: ctx.attempt, kind: 'plan', phase: 'plan', model: stageModel(s, 'profile')!, signal: ctx.signal, prompt,
      submitTools: [submit], requiredSubmits: ['submit_plan'], maxTurns: Math.min(20, s.limits.maxTurnsPerStep),
    });
    const err = sessionError(outcome);
    if (err) throw err;
    submitted = (outcome.submissions.submit_plan as PlanSubmission[]).at(-1)!;
  }
  const pricing = rt.store.config.pricing[`${s.models.audit.provider}/${s.models.audit.model}`];
  // Calibrated from this data directory's history.
  const ratio = (kind: StepKind, model: ModelRef | null) => calibrationRatio(rt.store, kind, model);
  const estimate = estimatePipeline(s, scale.candidates, Math.ceil(Math.min(scale.candidates, s.limits.maxCandidates) / 4), pricing, ratio, {
    domainHunt: domainHuntOn(rt), gapFill: gapFillOn(rt) && s.tools.coverageCompare, incremental: rt.audit.scene === 'incremental',
    // the checklist check, the conclusion recheck and the external triage are estimated too.
    checklist: checklistOn(rt), recheck: ['full', 'incremental'].includes(rt.audit.scene) && !backfillScope(rt) && !supplementScope(rt),
    external: rt.store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM obligation WHERE audit_id = ? AND kind = 'external'`, rt.auditId)?.n ?? 0,
    // ⑪ also runs on demand after the experts when the strategy leaves it at the scene default.
    explore: plannedExploreMode(rt),
  });
  // say before the start which stage quota the estimate does not fit.
  const short = stageShortfalls(s, estimate, ratio, rt.targets.length).map((x) =>
    `${BUDGET_STAGE_LABEL[x.stage]}估算约 ${tokensLabel(x.need)}，超过阶段额度 ${tokensLabel(x.limit)}：运行中可能暂停等待追加。可在发起前调高该阶段的份额。`);
  // the whole budget too (an incremental plan estimated 3.1–5.7M against 3M and said nothing).
  if (estimate.tokens.p50 > s.budget.tokens) {
    short.unshift(`整体估算约 ${tokensLabel(estimate.tokens.p50)}–${tokensLabel(estimate.tokens.p90)}，超过 token 预算 ${tokensLabel(s.budget.tokens)}：运行中可能暂停等待追加。可在“调整”中提高预算。`);
  }
  const plan: AuditPlan = {
    submitted, scale, estimate,
    strategySources: JSON.parse(rt.audit.strategy_sources) as Record<string, string>,
    limitations: [...engineLimitations(rt), ...short, ...submitted.limitations],
    knowledge: rt.knowledge.skills.map((k) => k.name),
    ...(inc ? { incremental: inc } : {}),
  };
  const ref = rt.store.artifacts.putJson(plan);
  return { outputRef: ref, apply: () => rt.store.update('audit', { id: rt.auditId }, { plan_ref: ref }) };
}
