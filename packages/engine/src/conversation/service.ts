// AI conversations. A conversation stands on its own and
// @-mentions projects, repositories, audits, vulnerabilities and skills. Each assistant reply is one fresh
// pi session over the frozen snapshots of the mentioned objects, with the history in the prompt. The agent
// never changes data: its propose_* tools produce cards the user applies. Replies stream to subscribers;
// non-delta events are persisted per message so a reconnect resumes by `seq`.
// The live reply service. Records are in records.ts, the reply context in context.ts.
import { AppError, CONVERSATION_TOOLS, type AttachmentInput, isAuditLanguage, newId, ProposeHunt, type CardKind, type FinishReason, type Mention, type ModelRef, type SnapshotManifest, type StructIndex } from '@xiezhi/contracts';
import { buildIndex, SnapshotView, type Executor, type IndexMap, type RuleSet } from '@xiezhi/context';
import { effectiveSkills, freezeSkills, P, scanLayer, sessionKnowledge, type FrozenKnowledge } from '@xiezhi/knowledge';
import { buildAuditTools, buildConversationPrompt, newNonce, modelCallContext, startSession, unverifiedKnowledgeNote, wrapUntrusted, type ModelHub, type SessionEvent, type SessionOutcome, type UsageDelta } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import type { ConnectorPool } from '@xiezhi/connectors';
import { join } from 'node:path';
import { indexLanguagesFor } from '../auditable.js';
import { buildConnectorAccess, connectorPrompt } from '../connector-access.js';
import { chatModelOf } from '../services.js';
import { projectConnectors } from '../connectors.js';
import { attachmentImages, attachmentText, messageAttachments, storeAttachments, type StoredAttachment } from './attachments.js';
import { codeScope, historyText, mentionContext, mentionedProjects } from './context.js';
import { cardTools, dataTools, type ReplyToolContext } from './tools.js';
export { credentialValues } from './tools.js';
import { conversationMentions, dedupeMentions, getCard, getConversation, getMessage, messageCards, messageEvents, NO_SUBSCRIBER_STOP_MS, REPLY_MAX_TURNS, resolveMention, titleFromText, type CardRow, type ConversationRow, type MessageEvent, type MessageRow } from './records.js';
import { withLivePrompts } from '../prompts.js';

/** flush accumulated text every 500 ms or 64 deltas. */
const FLUSH_MS = 500;
const FLUSH_DELTAS = 64;
/** history in the prompt up to this share of the context window. */
const HISTORY_SHARE = 0.3;

// ---- the live reply -----------------------------------------------------------------------------

type Listener = (e: MessageEvent) => void;

interface LiveReply {
  messageId: string;
  conversationId: string;
  text: string;
  seq: number;
  listeners: Set<Listener>;
  abort: AbortController;
  stopReason: FinishReason | null;
  idleTimer: NodeJS.Timeout | null;
  pendingDeltas: number;
  lastFlush: number;
  done: Promise<void>;
}

export interface CardActions {
  /** Create a planning audit from the same request the form sends; returns its id. */
  startAudit(req: import('@xiezhi/contracts').AuditPlanRequest, conversationId: string): string;
  startReverify(input: { vulnIds: string[]; note?: string }, conversationId: string): string;
  startHunt(input: { basis: ProposeHunt['basis']; projectIds?: string[]; allProjects?: boolean; title?: string }, conversationId: string): { basisId: string };
}

export interface ConversationDeps {
  store: Store;
  executor: Executor;
  rules: RuleSet;
  hub: () => ModelHub;
  pool: () => ConnectorPool | null;
  /** Relays conversation notices on the global stream (sidebar marks). */
  notify?: (type: string, payload: Record<string, unknown>) => void;
}

export class ConversationService {
  private readonly live = new Map<string, LiveReply>();

  constructor(private readonly deps: ConversationDeps) {}

  /** The server relays conversation notices on the global stream (sidebar status marks). */
  onNotice(fn: (type: string, payload: Record<string, unknown>) => void): void { this.deps.notify = fn; }

  private get store(): Store { return this.deps.store; }

  /** Startup: replies that were streaming when the process stopped are interrupted. */
  recover(): number {
    const rows = this.store.all<{ id: string }>(`SELECT id FROM message WHERE status = 'streaming'`);
    for (const r of rows) {
      this.store.tx(() => {
        const m = getMessage(this.store, r.id);
        const seq = m.last_event_seq + 1;
        this.store.insert('message_event', { message_id: r.id, seq, type: 'error', payload: { code: 'INTERRUPTED', message: '服务重启，回复中断，可重新生成', partial: true } });
        this.store.update('message', { id: r.id }, { status: 'interrupted', finish_reason: 'interrupted', last_event_seq: seq, error: '服务重启，回复中断' });
      });
    }
    return rows.length;
  }

  isStreaming(messageId: string): boolean { return this.live.has(messageId); }
  streamingIn(conversationId: string): boolean { return [...this.live.values()].some((l) => l.conversationId === conversationId); }

  /** Send a user message (idempotent by clientMessageId) and start the assistant reply. */
  postMessage(conversationId: string, input: { clientMessageId: string; content: string; mentions?: Mention[]; attachments?: AttachmentInput[] }): { userMessageId: string; assistantMessageId: string } {
    return this.post(conversationId, input, (c) => input.attachments?.length ? storeAttachments(this.store, input.attachments, this.acceptsImages(c)) : []);
  }

  private post(conversationId: string, input: { clientMessageId: string; content: string; mentions?: Mention[] }, files: (c: ConversationRow) => StoredAttachment[]): { userMessageId: string; assistantMessageId: string } {
    const c = getConversation(this.store, conversationId);
    const existing = this.store.get<{ id: string }>('SELECT id FROM message WHERE conversation_id = ? AND client_message_id = ?', conversationId, input.clientMessageId);
    if (existing) {
      const reply = this.store.get<{ id: string }>('SELECT id FROM message WHERE reply_to = ? ORDER BY seq DESC LIMIT 1', existing.id);
      if (reply) return { userMessageId: existing.id, assistantMessageId: reply.id };
    }
    if (this.streamingIn(conversationId)) throw new AppError('MESSAGE_BUSY', 'stop the current reply first');
    const attachments = files(c);
    if (!input.content.trim() && !attachments.length) throw new AppError('COMMON_VALIDATION', '消息需要文字或文件');
    if (c.status === 'archived') this.store.update('conversation', { id: conversationId }, { status: 'active' });
    const ids = this.store.tx(() => {
      const next = (this.store.get<{ m: number | null }>('SELECT MAX(seq) AS m FROM message WHERE conversation_id = ?', conversationId)?.m ?? 0) + 1;
      const userId = newId('message');
      this.store.insert('message', {
        id: userId, conversation_id: conversationId, seq: next, role: 'user', content: input.content, refs: dedupeMentions(input.mentions ?? []), attachments, cards: [], status: 'complete',
        finish_reason: null, client_message_id: input.clientMessageId,
      });
      const assistantId = this.createAssistant(conversationId, next + 1, userId);
      this.store.update('conversation', { id: conversationId }, { last_message_at: Date.now() });
      return { userMessageId: userId, assistantMessageId: assistantId };
    });
    this.startReply(ids.assistantMessageId);
    return ids;
  }

  /**
   * Edit the last user message and answer it again. Its replies are removed; proposals still pending in
   * them are rejected (as when a conversation is deleted). Refused once a card of the reply was applied: that
   * action already happened, so the user sends a new message instead.
   */
  editLast(userMessageId: string, input: { clientMessageId: string; content: string }): { userMessageId: string; assistantMessageId: string } {
    const m = getMessage(this.store, userMessageId);
    if (m.role !== 'user') throw new AppError('COMMON_VALIDATION', 'only a user message can be edited');
    if (this.streamingIn(m.conversation_id)) throw new AppError('MESSAGE_BUSY', 'stop the current reply first');
    const later = this.store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM message WHERE conversation_id = ? AND role = 'user' AND seq > ?`, m.conversation_id, m.seq)!.n;
    if (later) throw new AppError('COMMON_VALIDATION', 'only the last user message can be edited');
    const replies = this.store.all<{ id: string }>('SELECT id FROM message WHERE reply_to = ?', m.id).map((r) => r.id);
    const cards = replies.flatMap((id) => messageCards(this.store, id));
    if (cards.some((c) => c.state === 'applied')) throw new AppError('COMMON_VALIDATION', 'a card of this reply was already applied; send a new message instead');
    this.store.tx(() => {
      for (const c of cards) for (const rid of fromJson<string[]>(c.revision_ids, [])) this.store.db.run(`UPDATE revision SET state = 'rejected' WHERE id = ? AND state = 'proposed'`, rid);
      this.store.db.run('DELETE FROM message WHERE reply_to = ?', m.id);
      this.store.db.run('DELETE FROM message WHERE id = ?', m.id);
    });
    // The message keeps its files: only the text is edited.
    const attachments = messageAttachments(m.attachments);
    return this.post(m.conversation_id, { clientMessageId: input.clientMessageId, content: input.content, mentions: fromJson<Mention[]>(m.refs, []) }, () => attachments);
  }

  /** Answer the same user message again (e.g. after an interrupted reply). */
  regenerate(assistantMessageId: string): { assistantMessageId: string } {
    const m = getMessage(this.store, assistantMessageId);
    if (m.role !== 'assistant' || !m.reply_to) throw new AppError('COMMON_VALIDATION', 'only an assistant reply can be regenerated');
    if (this.streamingIn(m.conversation_id)) throw new AppError('MESSAGE_BUSY', 'stop the current reply first');
    const id = this.store.tx(() => {
      const next = (this.store.get<{ m: number | null }>('SELECT MAX(seq) AS m FROM message WHERE conversation_id = ?', m.conversation_id)?.m ?? 0) + 1;
      const aid = this.createAssistant(m.conversation_id, next, m.reply_to!);
      this.store.update('conversation', { id: m.conversation_id }, { last_message_at: Date.now() });
      return aid;
    });
    this.startReply(id);
    return { assistantMessageId: id };
  }

  private createAssistant(conversationId: string, seq: number, replyTo: string): string {
    const c = getConversation(this.store, conversationId);
    const model = this.modelOf(c);
    const id = newId('message');
    this.store.insert('message', {
      id, conversation_id: conversationId, seq, role: 'assistant', content: '', refs: [], cards: [], status: 'streaming', finish_reason: null,
      model: `${model.provider}/${model.model}`, reply_to: replyTo, last_event_seq: 0,
    });
    return id;
  }

  modelOf(c: ConversationRow): ModelRef {
    const own = fromJson<ModelRef | null>(c.model, null);
    if (own) return own;
    const cfg = this.store.config;
    try { return chatModelOf(cfg); } catch { throw new AppError('MODEL_NOT_CONFIGURED', 'conversations need a chat or default model'); }
  }

  /** Whether the conversation's model takes images (`images: false` on its entry makes it text only). */
  acceptsImages(c: ConversationRow): boolean {
    try { return this.deps.hub().resolve(this.modelOf(c)).input.includes('image'); } catch { return false; }
  }

  /** User stop (the only way to halt a reply actively). */
  stop(messageId: string): void {
    const l = this.live.get(messageId);
    if (!l) { getMessage(this.store, messageId); return; }
    l.stopReason = 'user_stopped';
    l.abort.abort();
  }

  /** Wait until a live reply ends (tests, shutdown). */
  async settle(messageId?: string): Promise<void> {
    const all = messageId ? [this.live.get(messageId)].filter(Boolean) as LiveReply[] : [...this.live.values()];
    await Promise.all(all.map((l) => l.done));
  }

  async stopAll(): Promise<void> {
    for (const l of this.live.values()) { l.stopReason = 'interrupted'; l.abort.abort(); }
    await this.settle();
  }

  /**
   * Subscribe to a reply after `after`: persisted events are replayed, the text so far is
   * sent as one `delta` with `replace: true`, then live events follow. Returns null when the reply ended
   * (the caller replays persisted events and the final text and closes).
   */
  subscribe(messageId: string, after: number, listener: Listener): (() => void) | null {
    const l = this.live.get(messageId);
    if (!l) return null;
    for (const e of messageEvents(this.store, messageId, after)) listener(e);
    if (l.text && l.seq > after) listener({ seq: l.seq, type: 'delta', data: { text: l.text, replace: true } });
    l.listeners.add(listener);
    if (l.idleTimer) { clearTimeout(l.idleTimer); l.idleTimer = null; }
    return () => {
      l.listeners.delete(listener);
      if (l.listeners.size === 0) this.armIdle(l);
    };
  }

  private armIdle(l: LiveReply): void {
    if (l.idleTimer) clearTimeout(l.idleTimer);
    l.idleTimer = setTimeout(() => { l.stopReason = 'no_subscriber'; l.abort.abort(); }, NO_SUBSCRIBER_STOP_MS);
    l.idleTimer.unref?.();
  }

  private emit(l: LiveReply, type: MessageEvent['type'], data: Record<string, unknown>, persist = type !== 'delta'): MessageEvent {
    l.seq++;
    const e: MessageEvent = { seq: l.seq, type, data };
    if (persist) {
      this.store.insert('message_event', { message_id: l.messageId, seq: e.seq, type, payload: data });
      this.store.update('message', { id: l.messageId }, { last_event_seq: l.seq });
    }
    for (const fn of l.listeners) { try { fn(e); } catch { /* a broken subscriber never stops the reply */ } }
    return e;
  }

  private flush(l: LiveReply, force = false): void {
    if (!force && l.pendingDeltas < FLUSH_DELTAS && Date.now() - l.lastFlush < FLUSH_MS) return;
    this.store.update('message', { id: l.messageId }, { content: l.text, last_event_seq: l.seq });
    l.pendingDeltas = 0;
    l.lastFlush = Date.now();
  }

  private startReply(messageId: string): void {
    const m = getMessage(this.store, messageId);
    const l: LiveReply = {
      messageId, conversationId: m.conversation_id, text: '', seq: m.last_event_seq, listeners: new Set(), abort: new AbortController(), stopReason: null,
      idleTimer: null, pendingDeltas: 0, lastFlush: Date.now(), done: Promise.resolve(),
    };
    this.live.set(messageId, l);
    this.armIdle(l);
    this.deps.notify?.('conversation.updated', { conversation_id: l.conversationId, message_id: messageId, streaming: true });
    l.done = this.runReply(l).catch((e) => this.finishWithError(l, (e as Error).message)).finally(() => {
      if (l.idleTimer) clearTimeout(l.idleTimer);
      this.live.delete(messageId);
      this.deps.notify?.('conversation.updated', { conversation_id: l.conversationId, message_id: messageId, streaming: false });
    });
  }

  private finishWithError(l: LiveReply, message: string): void {
    const safe = message.replace(/(sk|key|token)[-_A-Za-z0-9]{8,}/gi, '[redacted]').slice(0, 500);
    this.flush(l, true);
    this.emit(l, 'error', { code: 'REPLY_FAILED', message: safe, partial: true });
    this.store.update('message', { id: l.messageId }, { status: 'interrupted', finish_reason: 'error', error: safe, content: l.text });
  }

  /** a reply uses the prompt overrides of the global layer and the first mentioned project. */
  private async runReply(l: LiveReply): Promise<void> {
    const projectId = mentionedProjects(this.store, conversationMentions(this.store, getConversation(this.store, l.conversationId)))[0] ?? null;
    const run = () => withLivePrompts(this.store, projectId, () => this.runReplyInner(l), 'conversation', l.conversationId);
    return run();
  }

  private async runReplyInner(l: LiveReply): Promise<void> {
    const store = this.store;
    const msg = getMessage(store, l.messageId);
    const conv = getConversation(store, l.conversationId);
    const userMsg = getMessage(store, msg.reply_to!);
    const mentions = conversationMentions(store, conv);
    const model = this.modelOf(conv);
    const hub = this.deps.hub();
    const nonce = newNonce();

    // Code scope: frozen snapshots of the mentioned objects.
    const scope = codeScope(store, mentions);
    const views = new Map<string, SnapshotView>();
    for (const r of scope) views.set(r.name, new SnapshotView(r.name, join(store.paths.snapshots, r.rootHash), store.artifacts.getJson<SnapshotManifest>(r.manifestRef)));
    const repoIds = new Map(scope.map((r) => [r.name, r.repositoryId]));
    const indexes = new Map<string, StructIndex>();
    for (const [name, view] of views) {
      const languages = indexLanguagesFor(store, repoIds.get(name), view);
      try { indexes.set(name, (await buildIndex(view, this.deps.rules, { indexesDir: store.paths.indexes, signal: l.abort.signal, ...(languages ? { languages } : {}) })).index); } catch { /* grep/read still work */ }
    }
    const reads = new Map<string, [number, number][]>();
    const artifactsSeen = new Set<string>();

    // Knowledge: global + the first mentioned project's layer; conversation-phase skills get their body.
    const projects = mentionedProjects(store, mentions);
    const global = scanLayer(store.paths.knowledgeGlobal, 'global');
    const project = projects[0] ? scanLayer(join(store.paths.projects, projects[0], 'knowledge'), 'project') : null;
    const frozen: FrozenKnowledge = freezeSkills(effectiveSkills(global, project), store.artifacts);
    const langs = [...new Set([...views.values()].flatMap((v) => Object.keys(v.manifest.stats.byLang)).filter(isAuditLanguage))];
    const sk = sessionKnowledge(frozen, {
      scene: 'full', phase: 'conversation', languages: langs, frameworks: [...new Set([...indexes.values()].flatMap((i) => i.entrypoints.map((e) => e.framework)))],
      vulnClasses: [], repoRoles: [], include: mentions.filter((m) => m.kind === 'skill').map((m) => m.id), exclude: [],
    }, store.artifacts);
    const skillRead = new Set<string>(sk.bodies.map((b) => b.name));
    for (const u of sk.usage) this.recordSkill(l.conversationId, l.messageId, u);

    // Connectors bound to the mentioned projects (read-only).
    const pool = this.deps.pool();
    const connectorRefs = [...new Set(projects.flatMap((p) => projectConnectors(store, p).map((c) => c.connectorId)))];
    const access = pool && connectorRefs.length ? buildConnectorAccess({
      store, pool, refs: connectorRefs, conversationId: l.conversationId, stepId: l.messageId, artifacts: artifactsSeen,
    }) : null;

    const codeTools = new Set(['read', 'grep', 'glob', 'list', 'entrypoints', 'dangerous_sinks', 'callgraph', 'symbol_lookup', 'find_refs']);
    const base = buildAuditTools({
      ctx: {
        views, defaultRepo: scope[0]?.name ?? '', executor: this.deps.executor, artifacts: store.artifacts, auditArtifacts: artifactsSeen, signal: l.abort.signal,
        onRead: (e) => { const k = `${e.repo}\u0000${e.path}`; (reads.get(k) ?? reads.set(k, []).get(k)!).push([e.startLine, e.endLine]); },
      },
      nonce,
      ...(indexes.size ? { indexes: indexes as IndexMap } : {}),
      knowledge: { frozen, readable: sk.readable, artifacts: store.artifacts, tokenCap: this.knowledgeCap(hub, model) },
      ...(access ? { connectors: access } : {}),
      hooks: {
        onSkillRead: (r) => { skillRead.add(r.name); skillRead.add(`${r.name}/${r.file}`); this.recordSkill(l.conversationId, l.messageId, { name: r.name, layer: r.layer, sha256: r.sha256, level: 'body', trigger: 'on_demand', reason: `model_request: ${r.reason}`, tokens: r.tokens }); },
      },
    }).filter((t) => views.size > 0 || !codeTools.has(t.name));

    const card = (tool: keyof typeof CONVERSATION_TOOLS, data: Record<string, unknown>, target?: { kind: string; id: string; revision?: number }, revisionIds: string[] = []): string => {
      const id = newId('card');
      const kind = CONVERSATION_TOOLS[tool];
      store.tx(() => {
        store.insert('conversation_card', {
          id, conversation_id: l.conversationId, message_id: l.messageId, kind, state: kind === 'investigation' ? 'info' : 'pending', tool, data, result: null,
          target_kind: target?.kind ?? null, target_id: target?.id ?? null, target_revision: target?.revision ?? null, revision_ids: revisionIds,
        });
        const m = getMessage(store, l.messageId);
        store.update('message', { id: l.messageId }, { cards: [...fromJson<string[]>(m.cards, []), id] });
      });
      this.emit(l, 'card', { cardId: id, kind, tool, data, state: kind === 'investigation' ? 'info' : 'pending', textOffset: l.text.length });
      return id;
    };

    const toolCtx: ReplyToolContext = { store, nonce, conversationId: l.conversationId, messageId: l.messageId, userMessage: userMsg.content, projects, scope, views, reads, skillRead, card };
    const replyTools = [...dataTools(toolCtx), ...cardTools(toolCtx)];

    const codeScopeText = scope.length
      ? `${P('conversation.code_scope')}\n${scope.map((r) => `- ${r.name}（审计 ${r.auditId}）`).join('\n')}`
      : P('conversation.no_code_scope');
    const ctxText = mentionContext(store, mentions, nonce);
    const systemPrompt = buildConversationPrompt({
      nonce, codeScope: codeScopeText, context: ctxText,
      mandatoryKnowledge: sk.bodies.map((b) => {
        const unverified = frozen.skills.find((f) => f.name === b.name)?.verified === false;
        return { name: b.name, text: unverified ? `${unverifiedKnowledgeNote()}\n${wrapUntrusted(nonce, 'knowledge', `skill:${b.name}`, b.text.replace(/^---[\s\S]*?---\n/, ''))}` : b.text };
      }),
      skillIndex: sk.indexText,
      ...(access ? { connectors: connectorPrompt(access.operations, nonce) } : {}),
    });
    const budgetChars = Math.floor(this.contextWindow(hub, model) * HISTORY_SHARE * 2);
    const history = historyText(store, l.conversationId, userMsg.seq, budgetChars);
    const files = messageAttachments(userMsg.attachments);
    const fileText = attachmentText(store, files, nonce);
    const refs = fromJson<Mention[]>(userMsg.refs, []);
    const current = [
      userMsg.content,
      refs.length ? `（本条消息引用：${refs.map((m) => resolveMention(store, m).label).join('、')}）` : '',
      files.length ? `（本条消息附件：${files.map((a) => a.name).join('、')}）` : '',
      fileText,
    ].filter(Boolean).join('\n\n');
    const prompt = history ? P('conversation.with_history', { history, current }) : current;

    this.emit(l, 'message_start', { messageId: l.messageId, model: `${model.provider}/${model.model}`, mentions: mentions.map((m) => resolveMention(store, m)) });
    const usage: UsageDelta = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0, cost: 0 };
    const toolNames = new Map<string, string>();
    const onEvent = (e: SessionEvent) => {
      if (e.type === 'text.delta') {
        l.text += e.text;
        l.pendingDeltas++;
        this.emit(l, 'delta', { text: e.text });
        this.flush(l);
      } else if (e.type === 'tool.called') {
        toolNames.set(e.callId, e.tool);
        this.emit(l, 'tool_call', { callId: e.callId, name: e.tool, argsSummary: summarize(e.args), phase: 'started', textOffset: l.text.length });
      } else if (e.type === 'tool.result') {
        this.emit(l, 'tool_call', { callId: e.callId, name: e.tool, phase: 'finished', ok: e.ok, resultPreview: e.preview.slice(0, 1500) });
      } else if (e.type === 'session.turn') {
        for (const k of Object.keys(usage) as (keyof UsageDelta)[]) usage[k] += e.usage[k];
      }
    };
    // A person is waiting for this reply: its model requests go before queued audit work.
    const handle = modelCallContext.run({ priority: 'interactive' }, () => startSession({
      hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent, systemPrompt, prompt, images: attachmentImages(store, files), tools: [...base, ...replyTools], requiredSubmits: [],
      maxTurns: REPLY_MAX_TURNS, signal: l.abort.signal, onEvent,
    }));
    this.finishReply(l, await handle.outcome, usage, conv, userMsg);
  }

  /** Settle a finished reply: final text, `done` or `error`, usage; the first reply names a new conversation. */
  private finishReply(l: LiveReply, out: SessionOutcome, usage: UsageDelta, conv: ConversationRow, userMsg: MessageRow): void {
    const store = this.store;
    this.flush(l, true);
    const text = l.text || out.finalText;
    if (!l.text && out.finalText) { l.text = out.finalText; this.emit(l, 'delta', { text: out.finalText }); }
    const tokens = out.usage.total || usage.total;
    const finish: FinishReason = l.stopReason ?? (out.status === 'max_turns' ? 'max_turns' : out.status === 'completed' ? 'stop' : 'error');
    if (finish === 'error' || finish === 'interrupted') {
      const message = finish === 'interrupted' ? '服务停止，回复中断，可重新生成' : `回复中断，可重新生成（${out.errorClass ?? out.status}${out.errorMessage ? `：${out.errorMessage.slice(0, 200)}` : ''}）`;
      this.emit(l, 'error', { code: finish === 'interrupted' ? 'INTERRUPTED' : (out.errorClass ?? 'REPLY_FAILED'), message, partial: true });
      store.update('message', { id: l.messageId }, { status: 'interrupted', finish_reason: finish, content: text, tokens, usage: out.usage, error: message });
      return;
    }
    this.emit(l, 'done', { finishReason: finish, usage: { input: out.usage.input, output: out.usage.output, cacheRead: out.usage.cacheRead, total: tokens } });
    store.update('message', { id: l.messageId }, { status: 'complete', finish_reason: finish, content: text, tokens, usage: out.usage });
    if (conv.title === '新会话' && userMsg.seq === 1) store.update('conversation', { id: conv.id }, { title: titleFromText(userMsg.content || messageAttachments(userMsg.attachments).map((a) => a.name).join('、')) });
  }

  private recordSkill(conversationId: string, messageId: string, u: { name: string; layer: string; sha256: string; level: string; trigger: string; reason: string; tokens: number }): void {
    this.store.insert('skill_usage', {
      id: newId('skillUsage'), audit_id: null, conversation_id: conversationId, step_id: messageId, skill_name: u.name, layer: u.layer, skill_hash: u.sha256, level: u.level,
      trigger: ['on_demand', 'always', 'phase', 'user_pinned', 'knowledge_need'].includes(u.trigger) ? u.trigger : 'on_demand', reason: u.reason, tokens: u.tokens,
    });
  }

  private contextWindow(hub: ModelHub, model: ModelRef): number {
    try { return (hub.resolve(model) as { contextWindow?: number }).contextWindow ?? 128_000; } catch { return 128_000; }
  }

  private knowledgeCap(hub: ModelHub, model: ModelRef): number {
    return Math.floor(this.contextWindow(hub, model)) >> 2;
  }

  // ---- cards --------------------------------------------------------------------------------------

  /** Dismiss a pending card: the revisions it proposed are rejected. */
  dismissCard(cardId: string): CardRow {
    const c = getCard(this.store, cardId);
    if (c.state !== 'pending') throw new AppError('CARD_NOT_PENDING', c.state);
    this.store.tx(() => {
      for (const id of fromJson<string[]>(c.revision_ids, [])) this.store.db.run(`UPDATE revision SET state = 'rejected' WHERE id = ? AND state = 'proposed'`, id);
    });
    return this.decideCard(c.id, 'dismissed', null);
  }

  /** Mark a card decided (the caller has carried out the action). */
  decideCard(cardId: string, state: 'applied' | 'dismissed', result: Record<string, unknown> | null, actor = 'user'): CardRow {
    this.store.update('conversation_card', { id: cardId }, { state, result, decided_by: actor, decided_at: Date.now() });
    const c = getCard(this.store, cardId);
    this.deps.notify?.('conversation.card', { conversation_id: c.conversation_id, card_id: c.id, state });
    return c;
  }

  /** Add a card to an existing (finished) message, e.g. the audit status after a plan card was applied. */
  appendCard(messageId: string, kind: CardKind, data: Record<string, unknown>, target?: { kind: string; id: string }): string {
    const m = getMessage(this.store, messageId);
    const id = newId('card');
    this.store.tx(() => {
      this.store.insert('conversation_card', {
        id, conversation_id: m.conversation_id, message_id: messageId, kind, state: 'info', tool: null, data, result: null,
        target_kind: target?.kind ?? null, target_id: target?.id ?? null, target_revision: null, revision_ids: [],
      });
      const seq = getMessage(this.store, messageId).last_event_seq + 1;
      this.store.insert('message_event', { message_id: messageId, seq, type: 'card', payload: { cardId: id, kind, data, state: 'info', textOffset: m.content.length } });
      this.store.update('message', { id: messageId }, { cards: [...fromJson<string[]>(m.cards, []), id], last_event_seq: seq });
    });
    return id;
  }
}



function summarize(args: unknown): string {
  const s = JSON.stringify(args ?? {});
  return s.length <= 300 ? s : `${s.slice(0, 300)}…`;
}
