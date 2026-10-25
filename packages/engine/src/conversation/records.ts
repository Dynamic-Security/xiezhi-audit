// Conversation records: conversations, @-mentions, messages, cards and their persisted reply
// events. Split out of conversation.ts.
import { AppError, newId, type CardKind, type CardState, type FinishReason, type Mention, type MentionKind, type ModelRef } from '@xiezhi/contracts';
import { scanLayer } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';

// ---- rows ---------------------------------------------------------------------------------------

export interface ConversationRow { id: string; title: string; model: string | null; status: 'active' | 'archived'; mentions: string; last_message_at: number | null; pinned_at: number | null; created_at: number; updated_at: number }
export interface MessageRow {
  id: string; conversation_id: string; seq: number; role: 'user' | 'assistant'; content: string; refs: string; attachments: string; cards: string; status: 'streaming' | 'complete' | 'interrupted';
  finish_reason: FinishReason | null; model: string | null; tokens: number; usage: string | null; error: string | null; client_message_id: string | null; reply_to: string | null;
  last_event_seq: number; created_at: number; updated_at: number;
}
export interface CardRow {
  id: string; conversation_id: string; message_id: string; kind: CardKind; state: CardState; tool: string | null; data: string; result: string | null;
  target_kind: string | null; target_id: string | null; target_revision: number | null; revision_ids: string; decided_by: string | null; decided_at: number | null; created_at: number;
}
export interface MessageEvent { seq: number; type: 'message_start' | 'delta' | 'tool_call' | 'card' | 'done' | 'error'; data: Record<string, unknown> }

export const REPLY_MAX_TURNS = 30;
/** A reply without any subscriber for this long stops. */
export const NO_SUBSCRIBER_STOP_MS = 10 * 60_000;

// ---- conversations ------------------------------------------------------------------------------

export function getConversation(store: Store, id: string): ConversationRow {
  const c = store.get<ConversationRow>('SELECT * FROM conversation WHERE id = ?', id);
  if (!c) throw new AppError('CONVERSATION_NOT_FOUND', id);
  return c;
}

export function createConversation(store: Store, input: { title?: string; model?: ModelRef | null; mentions?: Mention[] }): ConversationRow {
  const id = newId('conversation');
  const mentions = dedupeMentions(input.mentions ?? []);
  const title = input.title?.trim() || defaultTitle(store, mentions);
  store.insert('conversation', { id, title, model: input.model ?? null, status: 'active', mentions, last_message_at: null });
  return getConversation(store, id);
}

/**
 * Conversations, newest activity first. `q` matches the title or any message text; `mention` keeps the
 * conversations that reference an object, in the conversation or in one of its messages (AI panel).
 */
export function listConversations(store: Store, status?: 'active' | 'archived', limit = 200, filter: { q?: string; mention?: Mention } = {}): ConversationRow[] {
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (status) { where.push('c.status = ?'); args.push(status); }
  const q = filter.q?.trim();
  if (q) {
    where.push(`(instr(lower(c.title), lower(?)) > 0 OR EXISTS (SELECT 1 FROM message m WHERE m.conversation_id = c.id AND instr(lower(m.content), lower(?)) > 0))`);
    args.push(q, q);
  }
  if (filter.mention) {
    const needle = `"id":"${filter.mention.id}"`;
    where.push(`(instr(c.mentions, ?) > 0 OR EXISTS (SELECT 1 FROM message m WHERE m.conversation_id = c.id AND m.role = 'user' AND instr(m.refs, ?) > 0))`);
    args.push(needle, needle);
  }
  return store.all<ConversationRow>(
    `SELECT c.* FROM conversation c${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY c.pinned_at IS NULL, c.pinned_at DESC, COALESCE(c.last_message_at, c.created_at) DESC LIMIT ?`, ...args, limit);
}

/**
 * The conversation an audit lives in: the one it was started from, else one created now that
 * references the audit (a deleted conversation is replaced).
 */
export function auditConversation(store: Store, auditId: string): ConversationRow {
  const a = store.get<{ conversation_id: string | null }>('SELECT conversation_id FROM audit WHERE id = ?', auditId);
  if (!a) throw new AppError('AUDIT_NOT_FOUND', auditId);
  if (a.conversation_id) {
    const c = store.get<ConversationRow>('SELECT * FROM conversation WHERE id = ?', a.conversation_id);
    if (c) return c;
  }
  return store.tx(() => {
    const c = createConversation(store, { mentions: [{ kind: 'audit', id: auditId }] });
    store.update('audit', { id: auditId }, { conversation_id: c.id });
    return c;
  });
}

/** Title from the first message: whitespace folded, cut at the first sentence end, at most 30 characters. */
export function titleFromText(text: string): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  const end = flat.search(/[。？！?!；;]/);
  const first = end > 0 && end < 30 ? flat.slice(0, end + 1) : flat;
  return first.length > 30 ? `${first.slice(0, 30)}…` : first || '新会话';
}

export function updateConversation(store: Store, id: string, patch: { title?: string; status?: 'active' | 'archived'; model?: ModelRef | null; pinned?: boolean }): ConversationRow {
  getConversation(store, id);
  const changes: Record<string, unknown> = {};
  if (patch.title !== undefined) changes.title = patch.title.trim() || '未命名会话';
  if (patch.status !== undefined) changes.status = patch.status;
  if (patch.model !== undefined) changes.model = patch.model;
  if (patch.pinned !== undefined) changes.pinned_at = patch.pinned ? Date.now() : null;
  if (Object.keys(changes).length) store.update('conversation', { id }, changes);
  return getConversation(store, id);
}

/** Deleting a conversation removes its messages and cards; revisions it proposed keep their (soft) reference. */
export function deleteConversation(store: Store, id: string): void {
  getConversation(store, id);
  store.tx(() => {
    store.db.run(`UPDATE conversation_card SET state = 'expired' WHERE conversation_id = ? AND state = 'pending'`, id);
    // Pending AI proposals made in this conversation lose their card: reject them (they stay in history).
    store.db.run(`UPDATE revision SET state = 'rejected' WHERE conversation_id = ? AND state = 'proposed'`, id);
    store.db.run('DELETE FROM conversation WHERE id = ?', id);
  });
}

export function conversationMentions(store: Store, c: ConversationRow): Mention[] {
  const fromMessages = store.all<{ refs: string }>(`SELECT refs FROM message WHERE conversation_id = ? AND role = 'user' ORDER BY seq`, c.id).flatMap((m) => fromJson<Mention[]>(m.refs, []));
  return dedupeMentions([...fromJson<Mention[]>(c.mentions, []), ...fromMessages]);
}

export function dedupeMentions(ms: Mention[]): Mention[] {
  const seen = new Set<string>();
  return ms.filter((m) => { const k = `${m.kind}:${m.id}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 20);
}

function defaultTitle(store: Store, mentions: Mention[]): string {
  const first = mentions[0];
  if (!first) return '新会话';
  const r = resolveMention(store, first);
  return r.valid ? `关于 ${r.label}` : '新会话';
}

// ---- mentions -----------------------------------------------------------------------------------

export interface ResolvedMention { kind: MentionKind; id: string; label: string; valid: boolean }

/** Soft references: a deleted object shows as “已失效”. */
export function resolveMention(store: Store, m: Mention): ResolvedMention {
  const bad: ResolvedMention = { ...m, label: '已失效', valid: false };
  switch (m.kind) {
    case 'project': { const p = store.get<{ name: string }>('SELECT name FROM project WHERE id = ?', m.id); return p ? { ...m, label: p.name, valid: true } : bad; }
    case 'repo': { const r = store.get<{ name: string; project: string }>('SELECT r.name, p.name AS project FROM repository r JOIN project p ON p.id = r.project_id WHERE r.id = ?', m.id); return r ? { ...m, label: `${r.project}/${r.name}`, valid: true } : bad; }
    case 'audit': { const a = store.get<{ title: string; project: string }>('SELECT a.title, p.name AS project FROM audit a JOIN project p ON p.id = a.project_id WHERE a.id = ?', m.id); return a ? { ...m, label: `${a.project} · ${a.title}`, valid: true } : bad; }
    case 'vuln': { const v = store.get<{ display_no: number; title: string; project: string }>('SELECT v.display_no, v.title, p.name AS project FROM vulnerability v JOIN project p ON p.id = v.project_id WHERE v.id = ?', m.id); return v ? { ...m, label: `${v.project} V-${v.display_no} ${v.title}`, valid: true } : bad; }
    case 'skill': return { ...m, label: m.id, valid: true };
    default: return bad;
  }
}

export function mentionCandidates(store: Store, q: string, types: MentionKind[], limit = 20): { kind: MentionKind; id: string; label: string; detail: string | null }[] {
  const like = `%${q.replace(/[%_]/g, (x) => `\\${x}`)}%`;
  const out: { kind: MentionKind; id: string; label: string; detail: string | null }[] = [];
  const want = new Set(types.length ? types : ['project', 'repo', 'audit', 'vuln', 'skill']);
  if (want.has('project')) for (const p of store.all<{ id: string; name: string }>(`SELECT id, name FROM project WHERE name LIKE ? ESCAPE '\\' ORDER BY updated_at DESC LIMIT ?`, like, limit)) out.push({ kind: 'project', id: p.id, label: p.name, detail: null });
  if (want.has('repo')) for (const r of store.all<{ id: string; name: string; project: string }>(`SELECT r.id, r.name, p.name AS project FROM repository r JOIN project p ON p.id = r.project_id WHERE r.name LIKE ? ESCAPE '\\' OR p.name LIKE ? ESCAPE '\\' ORDER BY r.updated_at DESC LIMIT ?`, like, like, limit)) out.push({ kind: 'repo', id: r.id, label: `${r.project}/${r.name}`, detail: null });
  if (want.has('audit')) for (const a of store.all<{ id: string; title: string; project: string; status: string }>(`SELECT a.id, a.title, p.name AS project, a.status FROM audit a JOIN project p ON p.id = a.project_id WHERE a.title LIKE ? ESCAPE '\\' OR p.name LIKE ? ESCAPE '\\' ORDER BY a.created_at DESC LIMIT ?`, like, like, limit)) out.push({ kind: 'audit', id: a.id, label: `${a.project} · ${a.title}`, detail: a.status });
  if (want.has('vuln')) {
    const no = /^v-?(\d+)$/i.exec(q.trim())?.[1];
    const rows = no
      ? store.all<{ id: string; display_no: number; title: string; project: string; severity: string }>(`SELECT v.id, v.display_no, v.title, p.name AS project, v.severity FROM vulnerability v JOIN project p ON p.id = v.project_id WHERE v.display_no = ? AND v.status = 'active' LIMIT ?`, Number(no), limit)
      : store.all<{ id: string; display_no: number; title: string; project: string; severity: string }>(`SELECT v.id, v.display_no, v.title, p.name AS project, v.severity FROM vulnerability v JOIN project p ON p.id = v.project_id WHERE v.status = 'active' AND (v.title LIKE ? ESCAPE '\\' OR p.name LIKE ? ESCAPE '\\') ORDER BY v.updated_at DESC LIMIT ?`, like, like, limit);
    for (const v of rows) out.push({ kind: 'vuln', id: v.id, label: `${v.project} V-${v.display_no} ${v.title}`, detail: v.severity });
  }
  if (want.has('skill')) {
    const global = scanLayer(store.paths.knowledgeGlobal, 'global');
    for (const s of global.skills.filter((x) => x.name.includes(q.toLowerCase()) || x.description.includes(q)).slice(0, limit)) out.push({ kind: 'skill', id: s.name, label: s.name, detail: s.description.slice(0, 120) });
  }
  return out.slice(0, limit * 2);
}

// ---- messages -----------------------------------------------------------------------------------

export function getMessage(store: Store, id: string): MessageRow {
  const m = store.get<MessageRow>('SELECT * FROM message WHERE id = ?', id);
  if (!m) throw new AppError('MESSAGE_NOT_FOUND', id);
  return m;
}

/** History, newest last; `before` is a seq cursor (cursor pagination). */
export function listMessages(store: Store, conversationId: string, before?: number, limit = 50): { items: MessageRow[]; nextCursor: number | null } {
  getConversation(store, conversationId);
  const rows = before
    ? store.all<MessageRow>('SELECT * FROM message WHERE conversation_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?', conversationId, before, limit + 1)
    : store.all<MessageRow>('SELECT * FROM message WHERE conversation_id = ? ORDER BY seq DESC LIMIT ?', conversationId, limit + 1);
  const more = rows.length > limit;
  const items = rows.slice(0, limit).reverse();
  return { items, nextCursor: more ? items[0]!.seq : null };
}

export function messageEvents(store: Store, messageId: string, after = 0): MessageEvent[] {
  return store.all<{ seq: number; type: MessageEvent['type']; payload: string }>('SELECT seq, type, payload FROM message_event WHERE message_id = ? AND seq > ? ORDER BY seq', messageId, after)
    .map((e) => ({ seq: e.seq, type: e.type, data: JSON.parse(e.payload) as Record<string, unknown> }));
}

export function messageCards(store: Store, messageId: string): CardRow[] {
  return store.all<CardRow>('SELECT * FROM conversation_card WHERE message_id = ? ORDER BY created_at, id', messageId);
}

export function getCard(store: Store, id: string): CardRow {
  const c = store.get<CardRow>('SELECT * FROM conversation_card WHERE id = ?', id);
  if (!c) throw new AppError('CARD_NOT_FOUND', id);
  return c;
}

/** Tool calls of a message, folded from its persisted events (started + finished per call id). */
type ToolCallView = { callId: string; name: string; argsSummary: string; phase: 'started' | 'finished'; ok: boolean | null; resultPreview: string | null; textOffset: number | null };
export function messageToolCalls(store: Store, messageId: string): ToolCallView[] {
  const byId = new Map<string, ToolCallView>();
  for (const e of messageEvents(store, messageId)) {
    if (e.type !== 'tool_call') continue;
    const d = e.data as { callId: string; name: string; argsSummary?: string; phase: 'started' | 'finished'; ok?: boolean; resultPreview?: string; textOffset?: number };
    const prev = byId.get(d.callId);
    byId.set(d.callId, {
      callId: d.callId, name: d.name, argsSummary: d.argsSummary ?? prev?.argsSummary ?? '', phase: d.phase, ok: d.ok ?? prev?.ok ?? null,
      resultPreview: d.resultPreview ?? prev?.resultPreview ?? null, textOffset: d.textOffset ?? prev?.textOffset ?? null,
    });
  }
  return [...byId.values()];
}

/** Where each card appeared in the reply text (card id → text length at that moment). */
export function messageCardOffsets(store: Store, messageId: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const e of messageEvents(store, messageId)) {
    const d = e.data as { cardId?: string; textOffset?: number };
    if (e.type === 'card' && d.cardId && typeof d.textOffset === 'number') out.set(d.cardId, d.textOffset);
  }
  return out;
}
