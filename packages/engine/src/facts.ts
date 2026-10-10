// Enterprise facts: what the enterprise is like — gateway policies, deployment, business rules,
// trust between services — kept apart from knowledge (how to audit). A fact has a topic, a statement, a scope (repos,
// services, paths), where it came from, how far it can be trusted, how sensitive it is, and versions under a stable key:
// changing it writes a new version and marks the findings that relied on the old one as stale (they should be
// reverified). Facts come from people (the project page, answered plan questions, review rulings) or are imported from
// what the project already knows: business / architecture knowledge, the topology (also architecture imports), the
// requirement-risk decisions, the profile's assumptions.
import { join } from 'node:path';
import { AppError, isDeferAnswer, newId, type FactSensitivity, type FactSource, type FactTopic, type FactTrust } from '@xiezhi/contracts';
import { effectiveSkills, scanLayer } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';
import { getProject } from './services.js';

export interface FactScope { repos?: string[]; services?: string[]; paths?: string[] }
export interface FactRow {
  id: string; project_id: string; fact_key: string; version: number; topic: FactTopic; statement: string; scope: string;
  source_kind: FactSource; source_ref: string | null; trust: FactTrust; sensitivity: FactSensitivity;
  status: 'active' | 'superseded' | 'retracted'; created_by: string; reason: string | null; created_at: number; updated_at: number;
}
export interface FactInput {
  topic: FactTopic; statement: string; scope?: FactScope; sourceKind: FactSource; sourceRef?: string | null;
  trust: FactTrust; sensitivity?: FactSensitivity; key?: string; reason?: string | null;
}

const MAX_STATEMENT = 4000;

export function getFact(store: Store, id: string): FactRow {
  const f = store.get<FactRow>('SELECT * FROM fact WHERE id = ?', id);
  if (!f) throw new AppError('COMMON_NOT_FOUND', `fact ${id}`);
  return f;
}

export function activeFacts(store: Store, projectId: string): FactRow[] {
  return store.all<FactRow>(`SELECT * FROM fact WHERE project_id = ? AND status = 'active' ORDER BY topic, fact_key`, projectId);
}

function clean(input: FactInput): FactInput {
  const statement = input.statement.trim();
  if (!statement) throw new AppError('COMMON_VALIDATION', 'statement is empty');
  if (statement.length > MAX_STATEMENT) throw new AppError('COMMON_VALIDATION', `statement too long (max ${MAX_STATEMENT})`);
  return { ...input, statement };
}

/** Mark the references to a fact version stale: the findings relying on it should be reverified. */
function staleRefs(store: Store, factId: string): number {
  return store.db.run(`UPDATE fact_ref SET stale = 1, updated_at = ? WHERE fact_id = ? AND stale = 0`, Date.now(), factId).changes;
}

/**
 * Add a fact; with the key of an active fact this writes its next version (the previous one is superseded and the
 * findings relying on it go stale).
 */
export function addFact(store: Store, projectId: string, raw: FactInput, actor: string): FactRow {
  getProject(store, projectId);
  const input = clean(raw);
  const key = input.key ?? `${input.sourceKind}:${input.sourceRef ?? newId('fact')}`;
  return store.tx(() => {
    const prev = store.get<FactRow>(`SELECT * FROM fact WHERE project_id = ? AND fact_key = ? ORDER BY version DESC LIMIT 1`, projectId, key);
    if (prev?.status === 'active') {
      store.update('fact', { id: prev.id }, { status: 'superseded' });
      staleRefs(store, prev.id);
    }
    const id = newId('fact');
    store.insert('fact', {
      id, project_id: projectId, fact_key: key, version: (prev?.version ?? 0) + 1, topic: input.topic, statement: input.statement,
      scope: input.scope ?? {}, source_kind: input.sourceKind, source_ref: input.sourceRef ?? null, trust: input.trust,
      sensitivity: input.sensitivity ?? 'internal', status: 'active', created_by: actor, reason: input.reason ?? null,
    });
    return getFact(store, id);
  });
}

/** Change an active fact: a new version under the same key. */
export function reviseFact(store: Store, factId: string, patch: Partial<Omit<FactInput, 'key' | 'sourceKind'>> & { sourceKind?: FactSource }, actor: string): FactRow {
  const f = getFact(store, factId);
  if (f.status !== 'active') throw new AppError('COMMON_VALIDATION', `fact ${factId} is ${f.status}; only the active version can be changed`);
  return addFact(store, f.project_id, {
    topic: patch.topic ?? f.topic, statement: patch.statement ?? f.statement, scope: patch.scope ?? fromJson<FactScope>(f.scope, {}),
    sourceKind: patch.sourceKind ?? f.source_kind, sourceRef: patch.sourceRef !== undefined ? patch.sourceRef : f.source_ref, trust: patch.trust ?? f.trust,
    sensitivity: patch.sensitivity ?? f.sensitivity, key: f.fact_key, reason: patch.reason ?? null,
  }, actor);
}

/** Retract an active fact: no longer in force; the findings relying on it go stale. */
export function retractFact(store: Store, factId: string, reason: string, actor: string): FactRow {
  const f = getFact(store, factId);
  if (f.status !== 'active') throw new AppError('COMMON_VALIDATION', `fact ${factId} is ${f.status}`);
  if (!reason.trim()) throw new AppError('COMMON_VALIDATION', 'a reason is required to retract a fact');
  store.tx(() => {
    store.update('fact', { id: factId }, { status: 'retracted', reason: reason.trim().slice(0, 1000), created_by: actor });
    staleRefs(store, factId);
  });
  return getFact(store, factId);
}

/** Record the facts a finding relies on (ids the step's facts_query returned). */
export function addFactRefs(store: Store, auditId: string, findingId: string, factIds: string[]): void {
  for (const factId of [...new Set(factIds)]) {
    store.db.run(`INSERT OR IGNORE INTO fact_ref(id, fact_id, audit_id, finding_id, stale, created_at, updated_at) VALUES (?, ?, ?, ?, 0, ?, ?)`,
      newId('factRef'), factId, auditId, findingId, Date.now(), Date.now());
  }
}

// ---- import ----------------------------------------------------------------------------------------------------------

interface Candidate { key: string; topic: FactTopic; statement: string; sourceKind: FactSource; sourceRef: string | null; trust: FactTrust; scope?: FactScope }

function knowledgeCandidates(store: Store, projectId: string): Candidate[] {
  const skills = effectiveSkills(scanLayer(store.paths.knowledgeGlobal, 'global'), scanLayer(join(store.paths.projects, projectId, 'knowledge'), 'project'));
  return skills.filter((s) => s.category === 'business' || s.category === 'architecture').map((s) => ({
    key: `knowledge:${s.name}`, topic: s.category === 'business' ? 'business_rule' : 'architecture',
    statement: `${s.description}（知识「${s.name}」${s.source ? `，来源：${s.source}` : ''}）`, sourceKind: 'knowledge', sourceRef: s.name,
    trust: s.verified === true ? 'verified' : 'unverified',
  }));
}

function topologyCandidates(store: Store, projectId: string): Candidate[] {
  const nodes = store.all<{ id: string; kind: string; name: string; origin: string; repository_id: string | null }>('SELECT id, kind, name, origin, repository_id FROM topology_node WHERE project_id = ?', projectId);
  const edges = store.all<{ from_node: string; to_node: string; kind: string; protocol: string; origin: string; confidence: string }>(
    'SELECT from_node, to_node, kind, protocol, origin, confidence FROM topology_edge WHERE project_id = ? AND removed = 0', projectId);
  const name = new Map(nodes.map((n) => [n.id, n.name]));
  const out: Candidate[] = [];
  for (const n of nodes) {
    const outs = edges.filter((e) => e.from_node === n.id);
    const ins = edges.filter((e) => e.to_node === n.id);
    if (n.kind !== 'gateway' && !outs.length && !ins.length) continue;
    const kinds = new Set([n.origin, ...outs.map((e) => e.origin), ...ins.map((e) => e.origin)]);
    const all = [...outs, ...ins];
    const statement = [
      `${n.name}${n.kind === 'gateway' ? '是网关' : n.kind === 'external_service' ? '是外部服务' : ''}`,
      outs.length ? `调用 ${outs.map((e) => `${name.get(e.to_node)}（${e.protocol}）`).join('、')}` : '',
      ins.length ? `被 ${ins.map((e) => `${name.get(e.from_node)}（${e.protocol}）`).join('、')} 调用` : '',
    ].filter(Boolean).join('；');
    // Imported architecture and the user's own edits are confirmed; what the analysis inferred is not.
    const trust: FactTrust = !kinds.has('ai') && all.every((e) => e.confidence === 'confirmed') ? 'verified' : 'unverified';
    out.push({
      key: `topology:${n.name}`, topic: n.kind === 'gateway' ? 'gateway' : 'architecture', statement: `系统拓扑：${statement}。`,
      sourceKind: kinds.has('imported') ? 'architecture_import' : 'topology', sourceRef: n.name, trust, scope: { services: [n.name] },
    });
  }
  return out;
}

function requirementRiskCandidates(store: Store, projectId: string): Candidate[] {
  const LABEL: Record<string, string> = { mitigated: '已规避', accepted: '接受风险', false_positive: '不构成风险', to_mitigate: '待规避' };
  return store.all<{ title: string; no: number; statement: string; status: string; reason: string | null; tm: string }>(
    `SELECT t.title, r.no, r.statement, r.status, r.reason, t.id AS tm FROM threat_risk r JOIN threat_model t ON t.id = r.threat_model_id
     WHERE t.project_id = ? AND r.status != 'pending' AND r.reason IS NOT NULL ORDER BY t.id, r.no`, projectId)
    .map((r) => ({
      key: `requirement_risk:${r.tm}:${r.no}`, topic: 'business_rule' as const, sourceKind: 'requirement_risk' as const, sourceRef: `${r.tm}#${r.no}`, trust: 'verified' as const,
      statement: `需求威胁模型「${r.title}」风险 ${r.no}：${r.statement.slice(0, 600)}——人工裁定为${LABEL[r.status] ?? r.status}，理由：${r.reason!.slice(0, 600)}`,
    }));
}

function profileCandidates(store: Store, projectId: string): Candidate[] {
  const row = store.get<{ output_ref: string }>(
    `SELECT s.output_ref FROM step s JOIN audit a ON a.id = s.audit_id WHERE a.project_id = ? AND s.kind = 'profile' AND COALESCE(s.lineage_id, '') != 'SYSTEM' AND s.status IN ('succeeded','skipped') AND s.output_ref IS NOT NULL ORDER BY s.created_at DESC LIMIT 1`, projectId);
  if (!row) return [];
  const p = store.artifacts.getJson<{ profile?: { assumptions?: string[] } }>(row.output_ref);
  return (p.profile?.assumptions ?? []).map((a, i) => ({
    key: `profile:assumption:${i + 1}`, topic: 'architecture' as const, statement: `画像中的假设：${a}`, sourceKind: 'profile' as const, sourceRef: `assumption ${i + 1}`, trust: 'unverified' as const,
  }));
}

function answerCandidates(store: Store, projectId: string): Candidate[] {
  // Answers the user gave to the audits' questions (their confirmed statements); plan-context questions became facts
  // when answered already (`as_fact`), so they are not repeated here.
  return store.all<{ id: string; text: string; answer: string }>(
    `SELECT q.id, q.text, q.answer FROM question q JOIN audit a ON a.id = q.audit_id WHERE a.project_id = ? AND q.status = 'answered' AND q.answer IS NOT NULL AND q.as_fact = 0 ORDER BY q.answered_at`, projectId)
    .filter((q) => !isDeferAnswer(q.answer))
    .map((q) => ({ key: `question:${q.id}`, topic: 'other' as const, statement: `问：${q.text.slice(0, 600)}\n答：${q.answer.slice(0, 1500)}`, sourceKind: 'question' as const, sourceRef: q.id, trust: 'verified' as const }));
}

export interface ImportResult { added: number; updated: number; unchanged: number; kept: number }

/**
 * Import the facts the project already holds elsewhere. Idempotent by source key: an unchanged statement is kept, a
 * changed one (from an import, not edited by a person) becomes a new version; a fact a person edited or retracted is
 * left as it is.
 */
export function importFacts(store: Store, projectId: string): ImportResult {
  getProject(store, projectId);
  const r: ImportResult = { added: 0, updated: 0, unchanged: 0, kept: 0 };
  const candidates = [...knowledgeCandidates(store, projectId), ...topologyCandidates(store, projectId), ...requirementRiskCandidates(store, projectId), ...profileCandidates(store, projectId), ...answerCandidates(store, projectId)];
  for (const c of candidates) {
    const prev = store.get<FactRow>(`SELECT * FROM fact WHERE project_id = ? AND fact_key = ? ORDER BY version DESC LIMIT 1`, projectId, c.key);
    if (prev && (prev.status === 'retracted' || prev.created_by !== 'import')) { r.kept++; continue; }
    if (prev && prev.statement === c.statement && prev.trust === c.trust) { r.unchanged++; continue; }
    addFact(store, projectId, { ...c, ...(c.scope ? { scope: c.scope } : {}) }, 'import');
    if (prev) r.updated++; else r.added++;
  }
  return r;
}

// ---- plan questions ----------------------------------------------------------------------------------------------

/** The plan's "context needed" items as questions whose answers become facts (non-blocking; once per text). */
export function planContextQuestions(store: Store, auditId: string, stepId: string | null, items: string[]): number {
  let n = 0;
  for (const text of items.map((t) => t.trim()).filter(Boolean).slice(0, 20)) {
    if (store.get('SELECT 1 FROM question WHERE audit_id = ? AND text = ? AND as_fact = 1', auditId, text)) continue;
    store.insert('question', { id: newId('question'), audit_id: auditId, step_id: stepId, text, blocking: 0, status: 'open', as_fact: 1 });
    n++;
  }
  return n;
}

/** An answered plan-context question becomes a fact of the audit's project (confirmed by the person who answered). */
export function factFromAnswer(store: Store, questionId: string, actor: string): FactRow | null {
  const q = store.get<{ id: string; audit_id: string; text: string; answer: string | null; as_fact: number }>('SELECT id, audit_id, text, answer, as_fact FROM question WHERE id = ?', questionId);
  if (!q?.as_fact || !q.answer || isDeferAnswer(q.answer)) return null;
  const projectId = store.get<{ project_id: string }>('SELECT project_id FROM audit WHERE id = ?', q.audit_id)!.project_id;
  return addFact(store, projectId, {
    topic: 'other', statement: `问：${q.text.slice(0, 600)}\n答：${q.answer.slice(0, 2000)}`, sourceKind: 'question', sourceRef: q.id, trust: 'verified', key: `question:${q.id}`,
  }, actor);
}
