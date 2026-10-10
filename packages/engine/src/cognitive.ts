// Externalized cognitive state: versioned rows, deterministic application of
// submit_state_update ops, evidence gate for confirmed facts, deterministic slicing.
import { COGNITIVE_FIELDS, type CognitiveField, type StateOp } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { P } from '@xiezhi/knowledge';

export interface StateItem { id: string; text: string; evidence?: { repo?: string; path: string; startLine: number; endLine: number }[]; source: string; stepId: string; retired?: boolean }
export type CognitiveState = Record<CognitiveField, StateItem[]>;

const COLUMN: Record<CognitiveField, string> = {
  confirmedFacts: 'confirmed_facts', activeHypotheses: 'active_hypotheses', pendingQuestions: 'pending_questions',
  ruledOutDirections: 'ruled_out_directions', exploredNodes: 'explored_nodes', knowledgeNeeds: 'knowledge_needs',
};

export function emptyState(): CognitiveState {
  return Object.fromEntries(COGNITIVE_FIELDS.map((f) => [f, []])) as unknown as CognitiveState;
}

export function loadState(store: Store, auditId: string): { version: number; state: CognitiveState } {
  const row = store.get<Record<string, string | number>>('SELECT * FROM cognitive_state WHERE audit_id = ? ORDER BY version DESC LIMIT 1', auditId);
  if (!row) return { version: 0, state: emptyState() };
  const state = emptyState();
  for (const f of COGNITIVE_FIELDS) state[f] = JSON.parse(String(row[COLUMN[f]])) as StateItem[];
  return { version: Number(row.version), state };
}

/**
 * Apply ops. `verifyEvidence` implements the evidence gate: confirmedFacts additions without
 * verifiable evidence are rejected (returned in `rejected`).
 */
export function applyOps(state: CognitiveState, ops: StateOp[], stepId: string, lineage: string, verifyEvidence: (e: NonNullable<StateOp['evidenceRefs']>[number]) => boolean) {
  const next = structuredClone(state);
  const rejected: { op: StateOp; reason: string }[] = [];
  let n = 0;
  for (const op of ops) {
    const list: StateItem[] = next[op.field as CognitiveField];
    if (op.op === 'add') {
      if (!op.text) { rejected.push({ op, reason: 'text required' }); continue; }
      if (op.field === 'confirmedFacts') {
        const ev = op.evidenceRefs ?? [];
        if (ev.length === 0 || !ev.every(verifyEvidence)) { rejected.push({ op, reason: 'confirmed facts need verifiable evidenceRefs' }); continue; }
      }
      list.push({ id: `${lineage}-${op.field.slice(0, 3).toUpperCase()}${++n}`, text: op.text, ...(op.evidenceRefs ? { evidence: op.evidenceRefs } : {}), source: 'agent', stepId });
    } else {
      const item = list.find((i) => i.id === op.id);
      if (!item) { rejected.push({ op, reason: `unknown id ${op.id}` }); continue; }
      if (op.op === 'retire') item.retired = true;
      else if (op.text) item.text = op.text;
    }
  }
  return { state: next, rejected };
}

export function saveState(store: Store, auditId: string, version: number, stepId: string, state: CognitiveState): void {
  const row: Record<string, unknown> = { audit_id: auditId, version, step_id: stepId };
  for (const f of COGNITIVE_FIELDS) row[COLUMN[f]] = state[f];
  store.insert('cognitive_state', row);
}

const SLICE_LABELS: Record<CognitiveField, string> = {
  confirmedFacts: '已确认事实', activeHypotheses: '活跃假设', pendingQuestions: '待回答问题',
  ruledOutDirections: '已排除方向', exploredNodes: '已探索节点', knowledgeNeeds: '知识需求',
};

/**
 * what a session is shown up front — how many active items each field has and at most `maxItems`
 * of them (those mentioning the given paths first); the rest is read with `state_query`.
 */
export function sliceSummary(state: CognitiveState, focusPaths: string[], maxItems = 10): string {
  const counts = COGNITIVE_FIELDS.map((f) => [f, state[f].filter((i) => !i.retired)] as const).filter(([, items]) => items.length);
  if (!counts.length) return '（空）';
  const focused = (i: StateItem) => focusPaths.some((p) => i.text.includes(p) || i.evidence?.some((e) => e.path === p));
  const ranked = counts.flatMap(([f, items]) => items.map((i) => ({ f, i }))).sort((a, b) => Number(focused(b.i)) - Number(focused(a.i)));
  const shown = ranked.slice(0, maxItems);
  const total = ranked.length;
  return [
    `共 ${total} 条：${counts.map(([f, items]) => `${SLICE_LABELS[f]} ${items.length}`).join('，')}。`,
    ...shown.map(({ f, i }) => `- [${SLICE_LABELS[f]}·${i.id}] ${i.text}`),
    ...(total > shown.length ? [P('state.slice_rest', { n: total - shown.length })] : []),
  ].join('\n');
}

/** Deterministic slice: active items, those mentioning the given paths first, capped at ~4k tokens. */
export function renderSlice(state: CognitiveState, focusPaths: string[], maxChars = 12_000): string {
  const lines: string[] = [];
  const labels: Record<CognitiveField, string> = {
    confirmedFacts: '已确认事实', activeHypotheses: '活跃假设', pendingQuestions: '待回答问题',
    ruledOutDirections: '已排除方向', exploredNodes: '已探索节点', knowledgeNeeds: '知识需求',
  };
  for (const f of COGNITIVE_FIELDS) {
    const items = state[f].filter((i) => !i.retired);
    if (!items.length) continue;
    const score = (i: StateItem) => (focusPaths.some((p) => i.text.includes(p) || i.evidence?.some((e) => e.path === p)) ? 0 : 1);
    const sorted = [...items].sort((a, b) => score(a) - score(b) || a.id.localeCompare(b.id));
    lines.push(`## ${labels[f]}`);
    for (const i of sorted) lines.push(`- [${i.id}] ${i.text}`);
  }
  let out = lines.join('\n');
  if (out.length > maxChars) out = out.slice(0, maxChars) + '\n…（已截断）';
  return out || '（空）';
}
