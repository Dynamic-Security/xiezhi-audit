// Knowledge ingestion pipeline: source → AI organizing (chat model, no
// repository access) → schema check + injection hints → similarity and contradiction check → draft for
// review → approval writes the layer. Sources: pasted / uploaded text, hand-written skills, answered
// questions, vulnerabilities (case distillation), risk hunt bases, and project skills moved to global.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  AppError, KnowledgeCaseSubmit, KnowledgeConflictSubmit, KnowledgeSkillSubmit, newId, type ModelRef, type SkillCategory,
} from '@xiezhi/contracts';
import { boundaryDeclaration, detectInjection, newNonce, startSession, wrapUntrusted, type AuditTool, type ModelHub } from '@xiezhi/agent';
import {
  EMPTY_CHECKS, GLOBAL_CASE_LIBRARY, KnowledgeError, PROJECT_CASE_LIBRARY, approveDraft, composeCaseText, composeSkillText, deleteSkill, listDrafts,
  privateInfoHints, readDraft, readSkill, saveDraft, splitFrontmatter, staticChecks, type ConflictItem, type Draft, type DraftSource, type Layer, type PrivateHint,
} from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';
import { chatModelOf, getProject, listProjects, listRepositories } from './services.js';
import { P } from '@xiezhi/knowledge';
import { withLivePrompts } from './prompts.js';

const MAX_INPUT = 200_000;

export function knowledgeDir(store: Store, layer: Layer, projectId: string | null): string {
  if (layer === 'global') return store.paths.knowledgeGlobal;
  if (!projectId) throw new AppError('COMMON_VALIDATION', 'projectId is required for the project layer');
  getProject(store, projectId);
  return join(store.paths.projects, projectId, 'knowledge');
}

function dirsFor(store: Store, d: Pick<Draft, 'layer' | 'projectId'>) {
  return { global: store.paths.knowledgeGlobal, project: d.projectId ? join(store.paths.projects, d.projectId, 'knowledge') : null };
}

/** Find a draft in the global layer or any project layer (ids are unique). */
export function findDraft(store: Store, id: string): { draft: Draft; dir: string } {
  for (const dir of [store.paths.knowledgeGlobal, ...listProjects(store).map((p) => join(store.paths.projects, p.id, 'knowledge'))]) {
    const d = readDraft(dir, id);
    if (d) return { draft: d, dir };
  }
  throw new AppError('COMMON_NOT_FOUND', `draft ${id}`);
}

export function listAllDrafts(store: Store, opts: { projectId?: string; includeDecided?: boolean } = {}): Draft[] {
  const dirs = opts.projectId ? [knowledgeDir(store, 'project', opts.projectId)] : [store.paths.knowledgeGlobal];
  return dirs.flatMap((d) => listDrafts(d)).filter((d) => opts.includeDecided || d.status === 'organizing' || d.status === 'ready' || d.status === 'failed');
}

export interface CreateDraftInput {
  layer: Layer;
  projectId?: string | null;
  kind: 'skill' | 'case';
  /** Raw input: text to organize, or a complete skill / case file when `organize` is false. */
  text: string;
  organize: boolean;
  source: DraftSource;
  name?: string | null;
  library?: string | null;
  /** Category hint for organizing (e.g. a question answer → business / architecture). */
  category?: SkillCategory | null;
  moveFrom?: { projectId: string; name: string } | null;
}

function nameFromText(text: string): string | null {
  const { meta } = splitFrontmatter(text);
  const n = meta?.name;
  return typeof n === 'string' && /^[a-z0-9][a-z0-9-]{1,63}$/.test(n) ? n : null;
}

/**
 * Create the draft record. Whether or not it needs organizing, the draft is then processed in the
 * background (`processDraft`): a draft that was written by hand still gets the contradiction check.
 */
export function createDraft(store: Store, input: CreateDraftInput): Draft {
  if (!input.text.trim()) throw new AppError('COMMON_VALIDATION', 'text is empty');
  if (input.text.length > MAX_INPUT) throw new AppError('COMMON_VALIDATION', `text exceeds ${MAX_INPUT} characters`);
  const projectId = input.layer === 'project' ? input.projectId ?? null : null;
  const dir = knowledgeDir(store, input.layer, projectId);
  const now = Date.now();
  const d: Draft = {
    id: newId('knowledgeDraft'), layer: input.layer, projectId, status: 'organizing', revision: 1, kind: input.kind,
    name: input.name ?? (input.organize ? null : nameFromText(input.text)),
    library: input.kind === 'case' ? input.library ?? (input.layer === 'project' ? PROJECT_CASE_LIBRARY : GLOBAL_CASE_LIBRARY) : null,
    text: input.organize ? '' : input.text, input: input.text, source: input.source, checks: EMPTY_CHECKS,
    model: null, tokens: 0, error: null, moveFrom: input.moveFrom ?? null, createdAt: now, updatedAt: now, decidedAt: null,
  };
  return saveDraft(dir, { ...d, categoryHint: input.category ?? null });
}

function chatModel(store: Store): ModelRef {
  return chatModelOf(store.config);
}

function sourceField(d: Draft): string {
  switch (d.source.kind) {
    case 'question': return `question:${d.source.ref}`;
    case 'vulnerability': return `vuln:${d.source.ref}`;
    case 'hunt_basis': return `hunt-basis:${d.source.ref}`;
    case 'connector': return `connector:${d.source.ref}`;
    case 'conversation': return `conversation:${d.source.ref}`;
    case 'upload': return `doc:${d.source.label}`;
    case 'move_to_global': return `project:${d.source.ref}`;
    default: return 'user:';
  }
}

/**
 * Organize (if needed), run the checks and — when similar knowledge exists — ask the model which
 * statements contradict. Errors leave the draft `failed` with the reason; the text so far is kept.
 */
async function processDraftInner(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const { draft, dir } = findDraft(store, id);
  const d: Draft = { ...draft };
  const save = () => saveDraft(dir, { ...d, updatedAt: Date.now() });
  const usage = { total: 0 };
  let model: ModelRef | null;
  try { model = chatModel(store); } catch { model = null; }
  try {
    if (!d.text) {
      if (!model) throw new AppError('MODEL_NOT_CONFIGURED', 'AI organizing needs a chat or default model');
      const nonce = newNonce();
      const hint = d.categoryHint;
      const tool: AuditTool = d.kind === 'case'
        ? { name: 'submit_case', kind: 'submit', parameters: KnowledgeCaseSubmit, description: P('tool.submit_case'), run: () => ({ text: 'case recorded' }) }
        : { name: 'submit_skill', kind: 'submit', parameters: KnowledgeSkillSubmit, description: P('tool.submit_skill'), run: () => ({ text: 'skill recorded' }) };
      const outcome = await startSession({
        hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
        systemPrompt: [P('role.knowledge_organizer'), boundaryDeclaration(nonce)].join('\n\n'),
        prompt: [
          d.kind === 'case' ? P('knowledge.case_guide') : P('knowledge.skill_guide'), '',
          `目标：${d.layer === 'global' ? '全局知识库' : '项目知识库'}${hint ? `；类别建议：${hint}` : ''}${d.name ? `；名称：${d.name}` : ''}`,
          `来源：${d.source.label}`,
          wrapUntrusted(nonce, 'user_upload', `knowledge:${d.source.kind}`, d.input),
        ].join('\n'),
        tools: [tool], requiredSubmits: [tool.name], maxTurns: 4, signal,
        onUsage: (u) => { usage.total += u.total; return 'continue'; },
      }).outcome;
      const sub = (outcome.submissions[tool.name] as unknown[] | undefined)?.at(-1);
      if (!sub) throw new Error(`the model did not submit (${outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
      const source = sourceField(d);
      if (d.kind === 'case') {
        const c = sub as KnowledgeCaseSubmit;
        d.name = d.name ?? c.name;
        d.text = composeCaseText({ ...c, name: d.name, source });
      } else {
        const s = sub as KnowledgeSkillSubmit;
        d.name = d.name ?? s.name;
        d.text = composeSkillText({ ...s, name: d.name, layer: d.layer, source, verified: false });
      }
      d.model = `${model.provider}/${model.model}`;
      d.tokens = usage.total;
      save();
    }
    // Deterministic checks and injection hints on the input and the result.
    const st = staticChecks(dirsFor(store, d), d);
    const injection = [...detectInjection(d.text), ...detectInjection(d.input)].slice(0, 10);
    d.checks = { ...st, injection, conflicts: [] };
    save();
    // Contradictions: model only over the few similar candidates.
    if (st.similar.length) {
      if (!model) d.checks.warnings = [...d.checks.warnings, '未配置模型，未做结论矛盾检查'];
      else d.checks.conflicts = await judgeConflicts(deps, d, model, signal, usage);
    }
    d.tokens = usage.total;
    d.status = 'ready';
    d.error = null;
    save();
  } catch (e) {
    d.status = 'failed';
    d.error = (e instanceof AppError ? e.message : (e as Error).message).slice(0, 500);
    d.tokens = usage.total;
    save();
  }
}

function readCase(path: string): string {
  try { return readFileSync(path, 'utf8'); } catch { return ''; }
}

async function judgeConflicts(deps: { store: Store; hub: ModelHub }, d: Draft, model: ModelRef, signal: AbortSignal, usage: { total: number }): Promise<ConflictItem[]> {
  const { store } = deps;
  const dirs = dirsFor(store, d);
  const candidates = d.checks.similar.slice(0, 3).map((s, i) => {
    const dir = s.layer === 'global' ? dirs.global : dirs.project!;
    const skill = readSkill(dir, s.layer, s.name);
    const text = s.file ? readCase(join(dir, s.name, ...s.file.split('/'))) : skill?.entryText ?? '';
    return { id: `c${i + 1}`, item: s, text };
  });
  const nonce = newNonce();
  const tool: AuditTool = { name: 'submit_conflicts', kind: 'submit', parameters: KnowledgeConflictSubmit, description: P('tool.submit_conflicts'), run: () => ({ text: 'recorded' }) };
  const outcome = await startSession({
    hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
    systemPrompt: [P('role.knowledge_reviewer'), boundaryDeclaration(nonce)].join('\n\n'),
    prompt: [
      P('knowledge.conflict_task'),
      wrapUntrusted(nonce, 'user_upload', 'draft', d.text),
      ...candidates.map((c) => wrapUntrusted(nonce, 'user_upload', `${c.id}:${c.item.layer}:${c.item.name}${c.item.file ? `/${c.item.file}` : ''}`, c.text)),
    ].join('\n\n'),
    tools: [tool], requiredSubmits: [tool.name], maxTurns: 3, signal,
    onUsage: (u) => { usage.total += u.total; return 'continue'; },
  }).outcome;
  const sub = (outcome.submissions.submit_conflicts as KnowledgeConflictSubmit[] | undefined)?.at(-1);
  if (!sub) return [];
  return sub.conflicts.flatMap((c) => {
    const cand = candidates.find((x) => x.id === c.candidate);
    if (!cand || !c.points.length) return [];
    return [{ layer: cand.item.layer, name: cand.item.name, file: cand.item.file, points: c.points, suggestion: c.suggestion as ConflictItem['suggestion'], merged: c.merged ?? null }];
  });
}

/** User edit of a ready (or failed) draft before approval; re-runs the deterministic checks. */
export function updateDraft(store: Store, id: string, revision: number, patch: { text: string; name?: string | null }): Draft {
  const { draft, dir } = findDraft(store, id);
  if (draft.revision !== revision) throw new AppError('COMMON_REVISION_CONFLICT', `draft revision is ${draft.revision}`, { revision: draft.revision });
  if (draft.status === 'organizing' || draft.status === 'approved' || draft.status === 'rejected') throw new AppError('COMMON_VALIDATION', `draft is ${draft.status}`);
  const d: Draft = { ...draft, text: patch.text, name: patch.name ?? nameFromText(patch.text) ?? draft.name, revision: draft.revision + 1, status: 'ready', error: null, updatedAt: Date.now() };
  const st = staticChecks(dirsFor(store, d), d);
  d.checks = { ...st, injection: detectInjection(d.text).slice(0, 10), conflicts: draft.checks.conflicts };
  return saveDraft(dir, d);
}

/**
 * Approve (“审核后启用”). Side effects: the question is marked saved; a move to global deletes
 * the project original when asked.
 */
export function approveKnowledgeDraft(store: Store, id: string, opts: { replace?: boolean; afterMove?: 'delete' | 'keep' } = {}): { draft: Draft; name: string; file: string | null } {
  const { draft, dir } = findDraft(store, id);
  let r: { name: string; file: string | null };
  try {
    r = approveDraft(dirsFor(store, draft), draft, { ...(opts.replace ? { replace: true } : {}) });
  } catch (e) {
    if (e instanceof KnowledgeError) {
      if (e.kind === 'exists') throw new AppError('KNOWLEDGE_EXISTS', e.message);
      throw new AppError('KNOWLEDGE_INVALID', (e.detail.errors ?? [e.message]).join('; ').slice(0, 400), { errors: e.detail.errors ?? [e.message] });
    }
    throw e;
  }
  if (draft.source.kind === 'question' && draft.source.ref) store.update('question', { id: draft.source.ref }, { save_as_skill: 'saved' });
  if (draft.source.kind === 'hunt_basis' && draft.source.ref) store.update('hunt_basis', { id: draft.source.ref }, { skill_name: r.name });
  if (draft.moveFrom && opts.afterMove === 'delete') {
    const pdir = knowledgeDir(store, 'project', draft.moveFrom.projectId);
    const orig = readSkill(pdir, 'project', draft.moveFrom.name);
    if (orig) deleteSkill(pdir, draft.moveFrom.name, orig.entrySha256);
  }
  const done = saveDraft(dir, { ...draft, status: 'approved', decidedAt: Date.now(), updatedAt: Date.now() });
  return { draft: done, ...r };
}

export function rejectKnowledgeDraft(store: Store, id: string): Draft {
  const { draft, dir } = findDraft(store, id);
  if (draft.status === 'approved') throw new AppError('COMMON_VALIDATION', 'draft already approved');
  if (draft.source.kind === 'question' && draft.source.ref) store.update('question', { id: draft.source.ref }, { save_as_skill: 'declined' });
  return saveDraft(dir, { ...draft, status: 'rejected', decidedAt: Date.now(), updatedAt: Date.now() });
}

// ---- sources ------------------------------------------------------------------------------------------------

/** An answered question as input for a project business / architecture draft. */
export function questionDraftInput(store: Store, questionId: string): { projectId: string; text: string; label: string } {
  const q = store.get<{ id: string; audit_id: string; text: string; answer: string | null; status: string }>('SELECT id, audit_id, text, answer, status FROM question WHERE id = ?', questionId);
  if (!q) throw new AppError('QUESTION_NOT_FOUND');
  if (q.status !== 'answered' || !q.answer) throw new AppError('COMMON_VALIDATION', 'only answered questions can be saved as knowledge');
  const a = store.get<{ project_id: string; title: string }>('SELECT project_id, title FROM audit WHERE id = ?', q.audit_id)!;
  return {
    projectId: a.project_id, label: `审计「${a.title}」中的提问与用户回答`,
    text: `Agent 在审计中的提问：\n${q.text}\n\n用户的回答：\n${q.answer}\n\n说明：回答来自用户，未经核实；整理为业务知识或系统架构（verified: false）。`,
  };
}

/** A vulnerability's four layers as input for a case draft (“沉淀为案例”). */
export function vulnerabilityCaseInput(store: Store, vulnId: string): { projectId: string; text: string; label: string } {
  const v = store.get<Record<string, any>>('SELECT * FROM vulnerability WHERE id = ?', vulnId);
  if (!v) throw new AppError('VULN_NOT_FOUND');
  const detail = store.artifacts.getJson<{ chain?: { repo?: string; path: string; startLine: number; symbol?: string }[]; reasoning?: string; counterCheck?: string; exploitConditions?: { condition: string }[]; remediation?: { approach: string; suggestion?: string } }>(v.detail_ref);
  const entries = store.all<{ entry_key: string }>('SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ?', vulnId).map((e) => e.entry_key);
  const pending = fromJson<{ holdsIf?: { statement: string }[]; refutedIf?: { statement: string }[] } | null>(v.missing_context, null);
  const lines = [
    `标题：${v.title}`, `类别：${v.category}${v.cwe ? `（${v.cwe}）` : ''}；严重度：${v.severity}；确认状态：${v.confirm_status}`,
    `根因：${v.root_cause ?? ''}`, `危险点：${v.sink_symbol ?? ''} ${v.sink_api ?? ''}`, `受影响入口：${entries.join('、') || '—'}`,
    `调用链：${(detail.chain ?? []).map((c) => `${c.symbol ?? ''}@${c.path}:${c.startLine}`).join(' → ') || '—'}`,
    `推理：${detail.reasoning ?? ''}`, `反向核查：${detail.counterCheck ?? ''}`,
    `利用条件：${(detail.exploitConditions ?? []).map((e) => e.condition).join('；') || '—'}`,
    ...(pending?.holdsIf?.length ? [`成立条件：${pending.holdsIf.map((x) => x.statement).join('；')}`] : []),
    ...(pending?.refutedIf?.length ? [`不成立条件：${pending.refutedIf.map((x) => x.statement).join('；')}`] : []),
    `修复：${detail.remediation?.approach ?? ''} ${detail.remediation?.suggestion ?? ''}`,
  ];
  return { projectId: v.project_id, label: `漏洞 V-${v.display_no}「${v.title}」`, text: lines.join('\n') };
}

/** Move to global, step 1: the text plus private-information hints for the user to clean up. */
export function moveToGlobalPreview(store: Store, projectId: string, name: string): { text: string; hints: PrivateHint[]; globalExists: boolean } {
  const p = getProject(store, projectId);
  const s = readSkill(knowledgeDir(store, 'project', projectId), 'project', name);
  if (!s) throw new AppError('COMMON_NOT_FOUND', `skill ${name}`);
  if (s.form === 'dir') throw new AppError('COMMON_VALIDATION', 'directory skills are moved by hand (copy the directory into the global layer)');
  const terms = [p.name, ...listRepositories(store, projectId).map((r) => r.name)];
  const text = s.entryText.replace(/^scope:\s*project\s*$/m, 'scope: global');
  return { text, hints: privateInfoHints(text, terms), globalExists: !!readSkill(store.paths.knowledgeGlobal, 'global', name) };
}

/** with the prompt overrides of the draft's layer (its project, or the global layer). */
export async function processDraft(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  return withLivePrompts(deps.store, findDraft(deps.store, id).draft.projectId, () => processDraftInner(deps, id, signal), 'knowledge_draft', id);
}
