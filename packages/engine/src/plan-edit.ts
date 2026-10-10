// Edit an audit plan before it is confirmed: the task-level
// override is merged into the draft strategy, checked, and the budget recomputed.
import { AppError, auditBudget, AuditStrategy, check, checkStrategy, mergeStrategy, upgradeStrategy, type Scene } from '@xiezhi/contracts';
import { fromJson, type Store } from '@xiezhi/store';
import { getAudit, type AuditRow } from './state.js';

export type DraftAuditRow = AuditRow & { draft_rev: number };

/**
 * Apply `strategyOverride` (and a new title) to the draft of a planning or awaiting_confirm audit. `expectedRevision`
 * must be the draft revision the caller saw (COMMON_REVISION_CONFLICT otherwise). Fields the override sets are marked
 * as task-level in the strategy sources.
 */
export function updatePlanDraft(
  store: Store, knownModels: ReadonlySet<string>, auditId: string, expectedRevision: number | undefined,
  patch: { strategyOverride: Record<string, unknown>; title?: string },
): DraftAuditRow {
  return store.tx(() => {
    const a = getAudit(store, auditId) as DraftAuditRow;
    if (a.status !== 'awaiting_confirm' && a.status !== 'planning') throw new AppError('AUDIT_INVALID_TRANSITION', `audit is ${a.status}`);
    if (a.draft_rev !== expectedRevision) throw new AppError('COMMON_REVISION_CONFLICT', `current revision ${a.draft_rev}`, { revision: a.draft_rev });
    const draft = upgradeStrategy(JSON.parse(a.strategy_draft));
    const merged = mergeStrategy(draft, undefined, patch.strategyOverride);
    const r = check(AuditStrategy, merged.strategy);
    if (!r.ok) throw new AppError('STRATEGY_INVALID', r.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; '));
    const issues = checkStrategy(merged.strategy, a.scene as Scene, knownModels);
    if (issues.length) throw new AppError('STRATEGY_INVALID', issues.map((i) => `${i.path}: ${i.message}`).join('; '));
    const sources = { ...fromJson<Record<string, string>>(a.strategy_sources, {}) };
    for (const [k, v] of Object.entries(merged.sources)) if (v === 'task') sources[k] = 'task';
    const s = merged.strategy;
    const targets = store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM audit_repository WHERE audit_id = ? AND role_in_audit = 'target'`, a.id)?.n ?? 1;
    const budget = auditBudget(s, { targets });
    store.update('audit', { id: a.id }, {
      strategy_draft: s, strategy_sources: sources, draft_rev: a.draft_rev + 1, budget_initial: budget, budget_effective: budget,
      scope: { include: s.scope.include, exclude: s.scope.exclude, focus: s.focus }, ...(patch.title ? { title: patch.title } : {}),
    });
    return getAudit(store, a.id) as DraftAuditRow;
  });
}
