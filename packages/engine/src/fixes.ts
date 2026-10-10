// Fix suggestions: for a confirmed vulnerability, a model writes a minimal patch (unified diff per file) against
// the snapshot the vulnerability was found in. The engine checks each diff applies to the snapshot text (context and
// removed lines match) and never writes to the repository. A reverification started from the suggestion is linked to it,
// and its result (fixed / still present) shows on the suggestion.
import { Type } from 'typebox';
import { AppError, newId, type ModelRef } from '@xiezhi/contracts';
import { boundaryDeclaration, newNonce, startSession, type AuditTool, type ModelHub } from '@xiezhi/agent';
import type { SnapshotView } from '@xiezhi/context';
import { P } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';
import { withLivePrompts } from './prompts.js';
import { chatModelOf } from './services.js';
import { readSnapshotTool, vulnBrief, vulnContext } from './vuln-context.js';

export interface FixPatch { path: string; diff: string }
export interface FixSuggestionRow {
  id: string; project_id: string; vulnerability_id: string; status: 'drafting' | 'ready' | 'failed'; summary: string | null; patches: string | null;
  verify: string | null; notes: string | null; model: string | null; tokens: number; error: string | null; reverify_audit_id: string | null; created_at: number; updated_at: number;
}

export function getFixSuggestion(store: Store, id: string): FixSuggestionRow {
  const r = store.get<FixSuggestionRow>('SELECT * FROM fix_suggestion WHERE id = ?', id);
  if (!r) throw new AppError('COMMON_NOT_FOUND', `fix suggestion ${id}`);
  return r;
}

interface Hunk { oldStart: number; lines: string[] }

/** Parse a unified diff of one file: its target path and hunks (lines keep their ' ', '-', '+' prefix). */
export function parseUnifiedDiff(diff: string): { path: string | null; hunks: Hunk[]; error: string | null } {
  const lines = diff.replace(/\r\n/g, '\n').replace(/\n+$/, '').split('\n'); // a trailing newline is not a blank context line
  let path: string | null = null;
  const hunks: Hunk[] = [];
  let cur: Hunk | null = null;
  for (const l of lines) {
    if (l.startsWith('--- ')) { cur = null; continue; }
    if (l.startsWith('+++ ')) { path = l.slice(4).trim().replace(/^b\//, '').split('\t')[0]!; cur = null; continue; }
    const h = /^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@/.exec(l);
    if (h) { cur = { oldStart: Number(h[1]), lines: [] }; hunks.push(cur); continue; }
    if (!cur) continue;
    if (l.startsWith('\\')) continue; // "\ No newline at end of file"
    if (l === '') { cur.lines.push(' '); continue; }
    if (![' ', '-', '+'].includes(l[0]!)) return { path, hunks, error: `unexpected line in a hunk: ${l.slice(0, 80)}` };
    cur.lines.push(l);
  }
  if (!hunks.length) return { path, hunks, error: 'no hunks (@@ … @@)' };
  return { path, hunks, error: null };
}

/**
 * Apply hunks to a file's lines; each hunk's old side (context and removed lines, trailing whitespace ignored) must
 * match the file at its stated line or within 50 lines of it. Returns the new lines or why it does not apply.
 */
export function applyHunks(file: string[], hunks: Hunk[]): { lines: string[] | null; error: string | null } {
  const out = [...file];
  let shift = 0;
  const norm = (s: string) => s.replace(/\s+$/, '');
  for (const [i, h] of hunks.entries()) {
    const old = h.lines.filter((l) => l[0] !== '+').map((l) => norm(l.slice(1)));
    const neu = h.lines.filter((l) => l[0] !== '-').map((l) => l.slice(1));
    const want = h.oldStart - 1 + shift;
    let at = -1;
    for (let d = 0; d <= 50 && at < 0; d++) {
      for (const pos of d === 0 ? [want] : [want - d, want + d]) {
        if (pos < 0 || pos + old.length > out.length) continue;
        if (old.every((x, k) => norm(out[pos + k]!) === x)) { at = pos; break; }
      }
    }
    if (at < 0) return { lines: null, error: `hunk ${i + 1} (@@ -${h.oldStart}) does not match the snapshot` };
    out.splice(at, old.length, ...neu);
    shift += neu.length - old.length + (at - want);
  }
  return { lines: out, error: null };
}

/** Check every patch against the snapshot: its path exists and its hunks apply. */
export function checkPatches(view: SnapshotView, patches: FixPatch[]): string[] {
  const issues: string[] = [];
  for (const [i, p] of patches.entries()) {
    let path: string;
    try { path = view.guard(p.path); } catch (e) { issues.push(`patches[${i}]: ${(e as Error).message}`); continue; }
    if (!view.hasFile(path)) { issues.push(`patches[${i}]: ${path} is not in the snapshot`); continue; }
    const d = parseUnifiedDiff(p.diff);
    if (d.error) { issues.push(`patches[${i}]: ${d.error}`); continue; }
    if (d.path && d.path !== path && d.path !== '/dev/null') issues.push(`patches[${i}]: the diff is for ${d.path}, not ${path}`);
    const r = applyHunks(view.lines(path), d.hunks);
    if (r.error) issues.push(`patches[${i}]: ${r.error}`);
  }
  return issues;
}

export function createFixDraft(store: Store, vulnId: string): FixSuggestionRow {
  const c = vulnContext(store, vulnId);
  if (c.vuln.confirm_status !== 'confirmed') throw new AppError('COMMON_VALIDATION', 'only a confirmed vulnerability gets a fix suggestion');
  if (store.get(`SELECT 1 FROM fix_suggestion WHERE vulnerability_id = ? AND status = 'drafting'`, vulnId)) throw new AppError('INVALID_TRANSITION', 'a fix suggestion is already being written for this vulnerability');
  const id = newId('fixSuggestion');
  store.insert('fix_suggestion', { id, project_id: c.vuln.project_id, vulnerability_id: vulnId, status: 'drafting' });
  return getFixSuggestion(store, id);
}

const SubmitFix = Type.Object({
  summary: Type.String({ minLength: 4, maxLength: 1500 }),
  patches: Type.Array(Type.Object({ path: Type.String({ maxLength: 500 }), diff: Type.String({ minLength: 10, maxLength: 20_000 }) }, { additionalProperties: false }), { minItems: 1, maxItems: 8 }),
  verify: Type.String({ minLength: 4, maxLength: 1500 }),
  notes: Type.Optional(Type.String({ maxLength: 1500 })),
}, { additionalProperties: false });
type SubmitFix = { summary: string; patches: FixPatch[]; verify: string; notes?: string };

async function processFixDraftInner(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const row = getFixSuggestion(store, id);
  const usage = { total: 0 };
  let model: ModelRef | null = null;
  try {
    try { model = chatModelOf(store.config); } catch { throw new AppError('MODEL_NOT_CONFIGURED', 'fix suggestions need a chat or default model'); }
    const c = vulnContext(store, row.vulnerability_id);
    const nonce = newNonce();
    const submit: AuditTool = {
      name: 'submit_fix_suggestion', kind: 'submit', parameters: SubmitFix, description: P('tool.submit_fix_suggestion'),
      validate: (a: SubmitFix) => checkPatches(c.view, a.patches).slice(0, 20),
      run: () => ({ text: 'recorded' }),
    };
    const outcome = await startSession({
      hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
      systemPrompt: [P('role.fix_author'), boundaryDeclaration(nonce)].join('\n\n'),
      prompt: [P('fix.guide'), '', vulnBrief(c, nonce, 40)].join('\n'),
      tools: [readSnapshotTool(c.view, nonce), submit], requiredSubmits: ['submit_fix_suggestion'], maxTurns: 12, signal,
      onUsage: (u) => { usage.total += u.total; return 'continue'; },
    }).outcome;
    const sub = (outcome.submissions.submit_fix_suggestion as SubmitFix[] | undefined)?.at(-1);
    if (!sub) throw new Error(`the model did not submit (${outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
    store.update('fix_suggestion', { id }, {
      status: 'ready', summary: sub.summary, patches: sub.patches.map((p) => ({ path: c.view.guard(p.path), diff: p.diff })), verify: sub.verify, notes: sub.notes ?? null,
      model: `${model.provider}/${model.model}`, tokens: usage.total,
    });
  } catch (e) {
    store.update('fix_suggestion', { id }, { status: 'failed', error: (e as Error).message.slice(0, 500), tokens: usage.total, ...(model ? { model: `${model.provider}/${model.model}` } : {}) });
  }
}

export async function processFixDraft(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const row = getFixSuggestion(deps.store, id);
  return withLivePrompts(deps.store, row.project_id, () => processFixDraftInner(deps, id, signal), 'fix_suggestion', id);
}

/** Link a reverification audit (started for the suggestion's vulnerability) to the suggestion. */
export function linkFixReverify(store: Store, id: string, auditId: string): FixSuggestionRow {
  const r = getFixSuggestion(store, id);
  if (r.status !== 'ready') throw new AppError('INVALID_TRANSITION', `fix suggestion is ${r.status}`);
  store.update('fix_suggestion', { id }, { reverify_audit_id: auditId });
  return getFixSuggestion(store, id);
}

/**
 * The linked reverification's verdict on the vulnerability: running, fixed (not found any more), still present, or
 * unknown (the audit ended without a verdict on it).
 */
export function fixReverifyState(store: Store, r: FixSuggestionRow): { auditId: string; status: string; verdict: 'running' | 'fixed' | 'still_present' | 'unknown' } | null {
  if (!r.reverify_audit_id) return null;
  const a = store.get<{ status: string }>('SELECT status FROM audit WHERE id = ?', r.reverify_audit_id);
  if (!a) return null;
  if (!['completed', 'partial', 'failed', 'cancelled'].includes(a.status)) return { auditId: r.reverify_audit_id, status: a.status, verdict: 'running' };
  const o = store.get<{ presence: string }>('SELECT presence FROM vuln_occurrence WHERE audit_id = ? AND vulnerability_id = ? ORDER BY created_at DESC LIMIT 1', r.reverify_audit_id, r.vulnerability_id);
  const verdict = !o ? 'unknown' : o.presence === 'found' ? 'still_present' : o.presence === 'not_found_verified' ? 'fixed' : 'unknown';
  return { auditId: r.reverify_audit_id, status: a.status, verdict };
}

export const fixPatchesOf = (r: FixSuggestionRow): FixPatch[] => fromJson<FixPatch[]>(r.patches, []);
