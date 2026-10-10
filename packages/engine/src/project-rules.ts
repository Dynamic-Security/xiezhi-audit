// Project rules: a confirmed vulnerability solidified into a pattern the next audits hit directly.
// A model (or the user) proposes a tree-sitter query or a line regex; the engine runs it over the snapshot the
// vulnerability was found in and keeps it only when it compiles and hits the original place (and is not too broad).
// After the user approves it, audits freeze the approved rules with their knowledge and run them as extra sinks
// (rule id `project:<id>`), so the place and its variants enter triage, the coverage ledger and the hunt.
import { Type } from 'typebox';
import { AppError, newId, type ModelRef, type StructIndex } from '@xiezhi/contracts';
import { boundaryDeclaration, newNonce, startSession, wrapUntrusted, type AuditTool, type ModelHub } from '@xiezhi/agent';
import { hitsOrigin, matchProjectRule, projectRuleSinks, type ProjectRuleSpec, type RuleMatchResult, type SnapshotView } from '@xiezhi/context';
import { P } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';
import { withLivePrompts } from './prompts.js';
import { chatModelOf } from './services.js';
import { readSnapshotTool, vulnBrief, vulnContext, type CodeLoc } from './vuln-context.js';

export const RULE_MATCHERS = ['tree_sitter', 'regex'] as const;
export type RuleMatcher = (typeof RULE_MATCHERS)[number];
/** More hits than this and the rule is too broad to approve (a sink per call of a common API is noise). */
export const MAX_RULE_HITS = 100;

export interface RuleValidation {
  originHit: boolean; hits: number; files: number; truncated: boolean; error: string | null;
  sample: { path: string; startLine: number; text: string }[];
}

export interface ProjectRuleRow {
  id: string; project_id: string; vulnerability_id: string | null; repository_id: string | null; lang: string; matcher: RuleMatcher; pattern: string;
  category: string; cwe: string | null; title: string; rationale: string | null; status: 'drafting' | 'proposed' | 'approved' | 'rejected' | 'retired' | 'failed';
  source: 'ai' | 'user'; origin: string | null; validation: string | null; model: string | null; tokens: number; error: string | null;
  decided_by: string | null; decided_at: number | null; created_at: number; updated_at: number;
}

export function getProjectRule(store: Store, id: string): ProjectRuleRow {
  const r = store.get<ProjectRuleRow>('SELECT * FROM project_rule WHERE id = ?', id);
  if (!r) throw new AppError('COMMON_NOT_FOUND', `project rule ${id}`);
  return r;
}

/** Why a validation result cannot be approved, or null. */
export function ruleProblem(v: RuleValidation): string | null {
  if (v.error) return v.error;
  if (!v.originHit) return 'the pattern does not hit the original place';
  if (v.truncated || v.hits > MAX_RULE_HITS) return `the pattern hits ${v.truncated ? 'too many' : v.hits} places (more than ${MAX_RULE_HITS}); make it narrower`;
  return null;
}

function toValidation(r: RuleMatchResult, origin: CodeLoc): RuleValidation {
  return {
    originHit: !r.error && hitsOrigin(r.hits, origin), hits: r.hits.length, files: r.files, truncated: r.truncated, error: r.error,
    sample: r.hits.slice(0, 20).map((h) => ({ path: h.path, startLine: h.startLine, text: h.text })),
  };
}

/** Run a pattern over the vulnerability's snapshot. */
export async function testRule(view: SnapshotView, origin: CodeLoc, spec: { lang: string; matcher: RuleMatcher; pattern: string }): Promise<RuleValidation> {
  return toValidation(await matchProjectRule(view, spec), origin);
}

/** A rule the user writes for a vulnerability: validated now, saved as proposed (approval is a separate step). */
export async function addProjectRule(store: Store, vulnId: string, input: { matcher: RuleMatcher; pattern: string; title?: string; rationale?: string; lang?: string }, actor: string): Promise<ProjectRuleRow> {
  const c = vulnContext(store, vulnId);
  const lang = input.lang ?? c.lang;
  if (!lang) throw new AppError('COMMON_VALIDATION', `the language of ${c.origin.path} is not supported by rules`);
  const v = await testRule(c.view, c.origin, { lang, matcher: input.matcher, pattern: input.pattern });
  const problem = ruleProblem(v);
  if (problem) throw new AppError('COMMON_VALIDATION', problem);
  const id = newId('projectRule');
  store.insert('project_rule', {
    id, project_id: c.vuln.project_id, vulnerability_id: vulnId, repository_id: c.vuln.repository_id, lang, matcher: input.matcher, pattern: input.pattern,
    category: c.vuln.category, cwe: c.vuln.cwe, title: (input.title ?? `V-${c.vuln.display_no} ${c.vuln.title}`).slice(0, 200), rationale: input.rationale ?? null,
    status: 'proposed', source: 'user', origin: c.origin, validation: v, decided_by: actor,
  });
  return getProjectRule(store, id);
}

/** Start an AI draft for a vulnerability (the row exists at once; `processRuleDraft` fills it). */
export function createRuleDraft(store: Store, vulnId: string): ProjectRuleRow {
  const c = vulnContext(store, vulnId);
  if (!c.lang) throw new AppError('COMMON_VALIDATION', `the language of ${c.origin.path} is not supported by rules`);
  if (store.get(`SELECT 1 FROM project_rule WHERE vulnerability_id = ? AND status = 'drafting'`, vulnId)) throw new AppError('INVALID_TRANSITION', 'a rule is already being drafted for this vulnerability');
  const id = newId('projectRule');
  store.insert('project_rule', {
    id, project_id: c.vuln.project_id, vulnerability_id: vulnId, repository_id: c.vuln.repository_id, lang: c.lang, matcher: 'tree_sitter', pattern: '',
    category: c.vuln.category, cwe: c.vuln.cwe, title: `V-${c.vuln.display_no} ${c.vuln.title}`.slice(0, 200), status: 'drafting', source: 'ai', origin: c.origin,
  });
  return getProjectRule(store, id);
}

const SubmitRule = Type.Object({
  matcher: Type.Union(RULE_MATCHERS.map((m) => Type.Literal(m))),
  pattern: Type.String({ minLength: 1, maxLength: 4000 }),
  title: Type.String({ minLength: 4, maxLength: 200 }),
  rationale: Type.String({ minLength: 4, maxLength: 1500 }),
}, { additionalProperties: false });
type SubmitRule = { matcher: RuleMatcher; pattern: string; title: string; rationale: string };

async function processRuleDraftInner(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const row = getProjectRule(store, id);
  const usage = { total: 0 };
  let model: ModelRef | null = null;
  try {
    try { model = chatModelOf(store.config); } catch { throw new AppError('MODEL_NOT_CONFIGURED', 'rule drafting needs a chat or default model'); }
    const c = vulnContext(store, row.vulnerability_id!);
    const nonce = newNonce();
    // Tested patterns: the submit tool (synchronous validation) accepts only a pattern last tested and found valid.
    const tested = new Map<string, RuleValidation>();
    const key = (m: string, p: string) => `${m}\u0000${p}`;
    const test: AuditTool = {
      name: 'test_rule', kind: 'read', description: P('tool.test_rule'),
      parameters: Type.Object({ matcher: Type.Union(RULE_MATCHERS.map((m) => Type.Literal(m))), pattern: Type.String({ minLength: 1, maxLength: 4000 }) }, { additionalProperties: false }),
      run: async (a: { matcher: RuleMatcher; pattern: string }) => {
        const v = await testRule(c.view, c.origin, { lang: row.lang, matcher: a.matcher, pattern: a.pattern });
        tested.set(key(a.matcher, a.pattern), v);
        const lines = [
          v.error ? `error: ${v.error}` : `originHit=${v.originHit} hits=${v.hits}${v.truncated ? '+' : ''} files=${v.files}`,
          ruleProblem(v) ? `not acceptable: ${ruleProblem(v)}` : 'acceptable',
          ...v.sample.map((h) => `- ${h.path}:${h.startLine}  ${h.text}`),
        ];
        return { text: wrapUntrusted(nonce, 'tool_output', 'test_rule', lines.join('\n')) };
      },
    };
    const submit: AuditTool = {
      name: 'submit_project_rule', kind: 'submit', parameters: SubmitRule, description: P('tool.submit_project_rule'),
      validate: (a: SubmitRule) => {
        const v = tested.get(key(a.matcher, a.pattern));
        if (!v) return ['call test_rule with exactly this matcher and pattern first'];
        const problem = ruleProblem(v);
        return problem ? [problem] : [];
      },
      run: () => ({ text: 'recorded' }),
    };
    const outcome = await startSession({
      hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
      systemPrompt: [P('role.rule_author'), boundaryDeclaration(nonce)].join('\n\n'),
      prompt: [P('rules.guide', { lang: row.lang }), '', vulnBrief(c, nonce)].join('\n'),
      tools: [readSnapshotTool(c.view, nonce), test, submit], requiredSubmits: ['submit_project_rule'], maxTurns: 12, signal,
      onUsage: (u) => { usage.total += u.total; return 'continue'; },
    }).outcome;
    const sub = (outcome.submissions.submit_project_rule as SubmitRule[] | undefined)?.at(-1);
    if (!sub) throw new Error(`the model did not submit (${outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
    // Validated again on save (the submit check used the session's test of the same pattern).
    const v = await testRule(c.view, c.origin, { lang: row.lang, matcher: sub.matcher, pattern: sub.pattern });
    const problem = ruleProblem(v);
    store.update('project_rule', { id }, {
      matcher: sub.matcher, pattern: sub.pattern, title: sub.title, rationale: sub.rationale, validation: v,
      status: problem ? 'failed' : 'proposed', error: problem, model: `${model.provider}/${model.model}`, tokens: usage.total,
    });
  } catch (e) {
    store.update('project_rule', { id }, { status: 'failed', error: (e as Error).message.slice(0, 500), tokens: usage.total, ...(model ? { model: `${model.provider}/${model.model}` } : {}) });
  }
}

export async function processRuleDraft(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const row = getProjectRule(deps.store, id);
  return withLivePrompts(deps.store, row.project_id, () => processRuleDraftInner(deps, id, signal), 'rule_draft', id);
}

/** Approve (proposed → approved), reject, or retire an approved rule. Approval checks the rule again on its snapshot. */
export async function decideProjectRule(store: Store, id: string, decision: 'approve' | 'reject' | 'retire', actor: string): Promise<ProjectRuleRow> {
  const r = getProjectRule(store, id);
  const want: Record<typeof decision, ProjectRuleRow['status'][]> = { approve: ['proposed'], reject: ['proposed', 'failed'], retire: ['approved'] };
  if (!want[decision].includes(r.status)) throw new AppError('INVALID_TRANSITION', `rule is ${r.status}`);
  if (decision === 'approve' && r.vulnerability_id) {
    const c = vulnContext(store, r.vulnerability_id);
    const problem = ruleProblem(await testRule(c.view, c.origin, { lang: r.lang, matcher: r.matcher, pattern: r.pattern }));
    if (problem) throw new AppError('COMMON_VALIDATION', problem);
  }
  store.update('project_rule', { id }, { status: decision === 'approve' ? 'approved' : decision === 'reject' ? 'rejected' : 'retired', decided_by: actor, decided_at: Date.now() });
  return getProjectRule(store, id);
}

/** Approved rules of a project, as frozen with an audit's knowledge. */
export function approvedRuleSpecs(store: Store, projectId: string): ProjectRuleSpec[] {
  return store.all<ProjectRuleRow>(`SELECT * FROM project_rule WHERE project_id = ? AND status = 'approved' ORDER BY created_at, id`, projectId)
    .map((r) => ({ id: r.id, lang: r.lang, matcher: r.matcher, pattern: r.pattern, category: r.category, title: r.title }));
}

/** The smallest method / function of the index enclosing a line. */
function enclosingSymbol(index: StructIndex, path: string, line: number): string | null {
  let best: { id: string; size: number } | null = null;
  for (const s of index.symbols) {
    if (s.path !== path || (s.kind !== 'method' && s.kind !== 'func') || line < s.range.startLine || line > s.range.endLine) continue;
    const size = s.range.endLine - s.range.startLine;
    if (!best || size < best.size) best = { id: s.symbolId, size };
  }
  return best?.id ?? null;
}

/**
 * The index with the hits of the frozen project rules added as sinks. A place an index rule already flags with the same
 * category is not added twice. Rules that no longer compile or match too broadly are skipped (reported by the caller).
 */
export async function withProjectRules(view: SnapshotView, index: StructIndex, rules: ProjectRuleSpec[]): Promise<{ index: StructIndex; added: number; skipped: string[] }> {
  if (!rules.length) return { index, added: 0, skipped: [] };
  const existing = new Set(index.sinks.map((s) => `${s.path}:${s.range.startLine}:${s.category}`));
  const sinks = [...index.sinks];
  const skipped: string[] = [];
  let added = 0;
  for (const rule of rules) {
    const r = await matchProjectRule(view, rule);
    if (r.error || r.truncated) { skipped.push(`${rule.id}: ${r.error ?? 'too many hits'}`); continue; }
    for (const s of projectRuleSinks(view.repo, rule, r.hits, (p, l) => enclosingSymbol(index, p, l))) {
      const k = `${s.path}:${s.range.startLine}:${s.category}`;
      if (existing.has(k)) continue;
      existing.add(k);
      sinks.push(s);
      added++;
    }
  }
  return { index: added ? { ...index, sinks } : index, added, skipped };
}

export const ruleValidationOf = (r: ProjectRuleRow): RuleValidation | null => fromJson<RuleValidation | null>(r.validation, null);
export const ruleOriginOf = (r: ProjectRuleRow): CodeLoc | null => fromJson<CodeLoc | null>(r.origin, null);
