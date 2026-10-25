// What a content filter refused: the step's model, the provider's reply, and the last messages sent before it
// — read from the step's newest saved transcript, for the pause banner to check a refusal quickly.
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AppError } from '@xiezhi/contracts';
import { findTranscript } from '@xiezhi/agent';
import type { Store } from '@xiezhi/store';
import { sessionsDir } from '../resume.js';

/** Messages before the refused reply that are shown, and the characters kept of each. */
const REQUEST_MESSAGES = 3;
const MESSAGE_CHARS = 6000;

export interface FilteredMessage { role: string; text: string; chars: number }
export interface FilteredDetail {
  stepId: string; lineage: string | null; model: string | null; attempt: number;
  /** The engine's error summary (provider message and the transport's note). */
  error: string | null;
  /** The reply the provider gave in place of an answer, and the model it named. */
  reply: { text: string; model: string | null; stopReason: string | null; errorMessage: string | null } | null;
  /** The newest messages sent before the refusal, oldest first (each cut to MESSAGE_CHARS; `chars` is the full length). */
  request: FilteredMessage[];
}

interface Entry { type?: string; message?: { role?: string; content?: unknown; provider?: string; model?: string; stopReason?: string; errorMessage?: string } }

function textOf(content: unknown): string {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return content == null ? '' : JSON.stringify(content);
  return content.map((p: { type?: string; text?: string; thinking?: string }) => (p.type === 'text' ? p.text ?? '' : p.type === 'thinking' ? '' : JSON.stringify(p))).filter(Boolean).join('\n');
}

/** The newest transcript of the step: the highest attempt, then the highest main session. */
function newestTranscript(store: Store, auditId: string, stepId: string): string | null {
  let dirs: string[];
  try { dirs = readdirSync(join(sessionsDir(store, auditId), stepId)); } catch { return null; }
  const order = dirs.map((d) => /^a(\d+)-s(\d+)$/.exec(d)).filter((m): m is RegExpExecArray => !!m)
    .sort((a, b) => Number(b[1]) - Number(a[1]) || Number(b[2]) - Number(a[2]));
  for (const m of order) {
    const f = findTranscript(join(sessionsDir(store, auditId), stepId, m[0]));
    if (f) return f;
  }
  return null;
}

export function filteredStepDetail(store: Store, auditId: string, stepId: string): FilteredDetail {
  const s = store.get<{ id: string; lineage_id: string | null; provider: string | null; model: string | null; attempt: number; error_summary: string | null }>(
    'SELECT id, lineage_id, provider, model, attempt, error_summary FROM step WHERE id = ? AND audit_id = ?', stepId, auditId);
  if (!s) throw new AppError('COMMON_NOT_FOUND', `step ${stepId}`);
  const detail: FilteredDetail = { stepId: s.id, lineage: s.lineage_id, model: s.provider && s.model ? `${s.provider}/${s.model}` : null, attempt: s.attempt, error: s.error_summary, reply: null, request: [] };
  const file = newestTranscript(store, auditId, stepId);
  if (!file) return detail;
  const messages: NonNullable<Entry['message']>[] = [];
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line) continue;
    try {
      const e = JSON.parse(line) as Entry;
      if (e.type === 'message' && e.message) messages.push(e.message);
    } catch { /* a line cut off by a crash */ }
  }
  // The refused reply: the last assistant message that ended in an error; what was sent is everything before it.
  let at = messages.length;
  for (let i = messages.length - 1; i >= 0; i--) {
    if (messages[i]!.role === 'assistant' && messages[i]!.stopReason === 'error') { at = i; break; }
  }
  const r = messages[at];
  if (r) detail.reply = { text: textOf(r.content), model: r.provider && r.model ? `${r.provider}/${r.model}` : null, stopReason: r.stopReason ?? null, errorMessage: r.errorMessage ?? null };
  detail.request = messages.slice(0, at).filter((m) => textOf(m.content)).slice(-REQUEST_MESSAGES).map((m) => {
    const text = textOf(m.content);
    return { role: m.role ?? 'unknown', text: text.slice(0, MESSAGE_CHARS), chars: text.length };
  });
  return detail;
}

/**
 * Every model (`provider/model`) a content filter refused in this audit, a fallback model refused after the
 * switch included: newer attempts record their model; for older attempts the switch away from a refused
 * model and the steps still waiting on a refusal tell (a redacted provider id is left out).
 */
export function filteredModels(store: Store, auditId: string): string[] {
  const out = new Set<string>();
  for (const r of store.all<{ model: string }>(
    `SELECT DISTINCT a.model FROM step_attempt a JOIN step s ON s.id = a.step_id
     WHERE s.audit_id = ? AND a.error_class = 'CONTENT_FILTERED' AND a.model IS NOT NULL`, auditId,
  )) out.add(r.model);
  for (const e of store.listEvents(auditId, 0, ['model.fallback'])) {
    const p = e.payload;
    if (p.reason === 'CONTENT_FILTERED' && !p.later && typeof p.from === 'string' && !p.from.includes('[REDACTED]')) out.add(p.from);
  }
  for (const s of store.all<{ provider: string | null; model: string | null }>(
    `SELECT provider, model FROM step WHERE audit_id = ? AND status = 'interrupted' AND error_class = 'CONTENT_FILTERED'`, auditId,
  )) if (s.provider && s.model) out.add(`${s.provider}/${s.model}`);
  return [...out];
}
