// AI conversations. Sending and streaming are two
// steps: POST stores the user message and a `streaming` assistant message, then the client reads
// `GET /messages/{mid}/stream` (resumable by seq). Cards are applied only by the user.
import type { FastifyInstance } from 'fastify';
import {
  AppError, type AuditPlanRequest, type CardDto, type ConversationDto, type Mention, type MentionKind, type MessageDto, type ModelRef, type ProposeHunt, type ProposeProject,
} from '@xiezhi/contracts';
import {
  auditConversation, createConnector, createConversation, createProject, createThreatModelWithSources, listRepositories, type AddThreatSourceInput, deleteConversation, getCard, getConversation, getMessage, listConversations, listMessages, mentionCandidates, mergeVulnerabilities,
  messageCards, messageCardOffsets, messageEvents, messageToolCalls, resolveMention, revisionCardProgress, applyRevisionSuggestion, splitVulnerability, updateConversation, conversationMentions, mentionedProjects,
  type CardRow, type ConversationRow, type MessageEvent, type MessageRow, messageAttachments, queries as Q,
} from '@xiezhi/engine';
import { fromJson, type Store } from '@xiezhi/store';
import type { AppContext } from '../context.js';
import { expectedRevision, parseBody } from '../http.js';
import * as B from '../bodies.js';
import { openStream } from './events.js';
import { addFromSource } from './projects.js';

const iso = (ms: number | null) => (ms == null ? null : new Date(ms).toISOString());

export function cardDto(store: Store, c: CardRow): CardDto {
  const progress = c.state === 'pending' && c.tool === 'propose_revision' ? revisionCardProgress(store, c) : null;
  return {
    id: c.id, conversationId: c.conversation_id, messageId: c.message_id, kind: c.kind, state: c.state,
    data: fromJson<Record<string, unknown>>(c.data, {}), result: c.result ? fromJson<Record<string, unknown>>(c.result, {}) : null,
    targetRevision: c.target_revision, decidedAt: iso(c.decided_at), createdAt: iso(c.created_at)!,
    ...(progress ? { progress: { done: progress.done, open: progress.open, conflict: progress.conflict } } : {}),
  };
}

export function registerConversationRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;
  const svc = () => ctx.engine.conversations;

  const conversationDto = (c: ConversationRow): ConversationDto => {
    const mentions = conversationMentions(store, c);
    return {
      id: c.id, title: c.title, model: c.model ? (() => { const m = fromJson<ModelRef | null>(c.model, null); return m ? `${m.provider}/${m.model}` : null; })() : null,
      status: c.status, mentions: mentions.map((m) => resolveMention(store, m)), projectId: mentionedProjects(store, mentions)[0] ?? null,
      lastMessageAt: iso(c.last_message_at), streaming: svc().streamingIn(c.id),
      pendingCards: Q.pendingCardCount(store, c.id),
      createdAt: iso(c.created_at)!, updatedAt: iso(c.updated_at)!, pinned: c.pinned_at != null,
    };
  };
  const messageDto = (m: MessageRow): MessageDto => ({
    id: m.id, conversationId: m.conversation_id, seq: m.seq, role: m.role, content: m.content,
    mentions: fromJson<Mention[]>(m.refs, []).map((x) => resolveMention(store, x)), attachments: messageAttachments(m.attachments), status: m.status, finishReason: m.finish_reason, model: m.model, tokens: m.tokens,
    toolCalls: m.role === 'assistant' ? messageToolCalls(store, m.id) : [],
    cards: m.role === 'assistant' ? (() => { const at = messageCardOffsets(store, m.id); return messageCards(store, m.id).map((c) => ({ ...cardDto(store, c), textOffset: at.get(c.id) ?? null })); })() : [],
    error: m.error, clientMessageId: m.client_message_id, createdAt: iso(m.created_at)!,
  });

  app.get<{ Querystring: { status?: 'active' | 'archived'; q?: string; mention?: string; limit?: string } }>('/api/v1/conversations', async (req) => {
    const [kind, id] = req.query.mention?.split(':') ?? [];
    const limit = Math.min(200, Math.max(1, Number(req.query.limit ?? 200) || 200));
    return listConversations(store, req.query.status, limit, { ...(req.query.q ? { q: req.query.q } : {}), ...(kind && id ? { mention: { kind: kind as Mention['kind'], id } } : {}) }).map(conversationDto);
  });
  app.post('/api/v1/conversations', async (req, reply) => {
    const b = parseBody(B.PostConversationsBody, req.body);
    const c = createConversation(store, { ...(b.title ? { title: b.title } : {}), ...(b.model ? { model: b.model } : {}), ...(b.mentions ? { mentions: b.mentions as Mention[] } : {}) });
    reply.code(201);
    return conversationDto(c);
  });
  app.get<{ Params: { cid: string } }>('/api/v1/conversations/:cid', async (req) => conversationDto(getConversation(store, req.params.cid)));
  app.post<{ Params: { aid: string } }>('/api/v1/audits/:aid/conversation', async (req) => conversationDto(auditConversation(store, req.params.aid)));
  app.patch<{ Params: { cid: string } }>('/api/v1/conversations/:cid', async (req) => {
    const b = parseBody(B.PatchConversationBody, req.body);
    if (b.model) ctx.engine.hub.resolve(b.model as ModelRef);
    return conversationDto(updateConversation(store, req.params.cid, { ...(b.title !== undefined ? { title: b.title } : {}), ...(b.status ? { status: b.status as 'active' | 'archived' } : {}), ...(b.model !== undefined ? { model: b.model as ModelRef | null } : {}), ...(b.pinned !== undefined ? { pinned: b.pinned } : {}) }));
  });
  app.delete<{ Params: { cid: string } }>('/api/v1/conversations/:cid', async (req, reply) => {
    if (svc().streamingIn(req.params.cid)) throw new AppError('MESSAGE_BUSY', 'stop the current reply first');
    deleteConversation(store, req.params.cid);
    return reply.code(204).send();
  });

  app.get<{ Params: { cid: string }; Querystring: { before?: string; limit?: string } }>('/api/v1/conversations/:cid/messages', async (req) => {
    const r = listMessages(store, req.params.cid, req.query.before ? Number(req.query.before) : undefined, Math.min(200, Math.max(1, Number(req.query.limit ?? 50) || 50)));
    return { items: r.items.map(messageDto), nextCursor: r.nextCursor == null ? null : String(r.nextCursor) };
  });
  // Files travel base64 in the body: up to 5 images of 5 MB and 1 MB of text.
  app.post<{ Params: { cid: string } }>('/api/v1/conversations/:cid/messages', { bodyLimit: 40 * 1024 * 1024 }, async (req, reply) => {
    const b = parseBody(B.PostMessagesBody, req.body);
    const r = svc().postMessage(req.params.cid, { clientMessageId: b.clientMessageId, content: b.content, ...(b.mentions ? { mentions: b.mentions as Mention[] } : {}), ...(b.attachments ? { attachments: b.attachments } : {}) });
    reply.code(202);
    return r;
  });
  app.get<{ Params: { mid: string } }>('/api/v1/messages/:mid', async (req) => messageDto(getMessage(store, req.params.mid)));
  /** A file of a message, only by the message that has it; served as an attachment except images, never sniffed. */
  app.get<{ Params: { mid: string; id: string } }>('/api/v1/messages/:mid/attachments/:id', async (req, reply) => {
    const a = messageAttachments(getMessage(store, req.params.mid).attachments).find((x) => x.id === req.params.id);
    if (!a) throw new AppError('COMMON_NOT_FOUND', 'attachment not found');
    reply.header('Content-Type', a.kind === 'image' ? a.mimeType : 'text/plain; charset=utf-8').header('X-Content-Type-Options', 'nosniff')
      .header('Cache-Control', 'private, max-age=31536000, immutable')
      .header('Content-Disposition', `${a.kind === 'image' ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(a.name.split('/').pop() ?? a.name)}`);
    return reply.send(store.artifacts.get(a.id));
  });
  app.post<{ Params: { mid: string } }>('/api/v1/messages/:mid/stop', async (req, reply) => {
    svc().stop(req.params.mid);
    return reply.code(204).send();
  });
  app.post<{ Params: { mid: string } }>('/api/v1/messages/:mid/edit', async (req, reply) => {
    const b = parseBody(B.EditMessageBody, req.body);
    const r = svc().editLast(req.params.mid, { clientMessageId: b.clientMessageId, content: b.content });
    reply.code(202);
    return r;
  });
  app.post<{ Params: { mid: string } }>('/api/v1/messages/:mid/regenerate', async (req, reply) => {
    reply.code(202);
    return svc().regenerate(req.params.mid);
  });

  /** Reply stream: replay persisted events after `after`, the text so far, then live; `end` when finished. */
  app.get<{ Params: { mid: string }; Querystring: { after?: string } }>('/api/v1/messages/:mid/stream', async (req, reply) => {
    const mid = req.params.mid;
    getMessage(store, mid);
    const lastEventId = Number(req.headers['last-event-id'] ?? 0) || 0;
    const after = Math.max(lastEventId, Number(req.query.after ?? 0) || 0);
    const finalFrames = (): MessageEvent[] => {
      const m = getMessage(store, mid);
      const events = messageEvents(store, mid, after);
      // The final text as one replacing delta, just before the closing event.
      const closing = events.filter((e) => e.type === 'done' || e.type === 'error');
      const rest = events.filter((e) => e.type !== 'done' && e.type !== 'error');
      const text: MessageEvent[] = m.content ? [{ seq: m.last_event_seq, type: 'delta', data: { text: m.content, replace: true } }] : [];
      return [...rest, ...text, ...closing];
    };
    if ((req.headers.accept ?? '').includes('application/json')) {
      const m = getMessage(store, mid);
      return { status: m.status, events: finalFrames().map((e) => ({ seq: e.seq, type: e.type, data: e.data })), content: m.content, lastSeq: m.last_event_seq };
    }
    const s = openStream(ctx, req, reply);
    const frame = (e: MessageEvent) => `id: ${e.seq}\nevent: ${e.type}\ndata: ${JSON.stringify({ seq: e.seq, ...e.data })}\n\n`;
    const end = () => { s.write(`event: end\ndata: ${JSON.stringify({ status: getMessage(store, mid).status })}\n\n`); s.close(); };
    const unsub = svc().subscribe(mid, after, (e) => {
      s.write(frame(e));
      if (e.type === 'done' || e.type === 'error') setImmediate(end);
    });
    if (!unsub) {
      for (const e of finalFrames()) s.write(frame(e));
      end();
      return;
    }
    s.onClose(unsub);
    const hb = setInterval(() => s.write(': ping\n\n'), ctx.stream.heartbeatMs);
    s.onClose(() => clearInterval(hb));
  });

  app.get<{ Querystring: { q?: string; types?: string } }>('/api/v1/mention-candidates', async (req) => {
    const types = (req.query.types ?? '').split(',').map((t) => t.trim()).filter((t): t is MentionKind => ['project', 'repo', 'audit', 'vuln', 'skill'].includes(t));
    return mentionCandidates(store, req.query.q ?? '', types);
  });

  // ---- cards ----------------------------------------------------------------------
  app.post<{ Params: { cardId: string } }>('/api/v1/cards/:cardId/apply', async (req) => {
    const b = parseBody(B.PostCardApplyBody, req.body ?? {});
    const c = getCard(store, req.params.cardId);
    if (c.state !== 'pending') throw new AppError('CARD_NOT_PENDING', c.state);
    const d = fromJson<Record<string, unknown>>(c.data, {});
    const cid = c.conversation_id;
    let result: Record<string, unknown>;
    switch (c.tool) {
      case 'propose_revision': {
        // Stale only when a dimension the card changes moved since the suggestion; If-Match is not compared.
        const r = applyRevisionSuggestion(store, {
          vulnId: String(d.vulnId), from: (d.from ?? {}) as Parameters<typeof applyRevisionSuggestion>[1]['from'], to: (d.to ?? {}) as Parameters<typeof applyRevisionSuggestion>[1]['to'],
          reason: `采纳会话建议：${String(d.reason ?? '')}`.slice(0, 2000),
        });
        result = { vulnId: d.vulnId, revision: r.rev };
        break;
      }
      case 'propose_merge':
        mergeVulnerabilities(store, { sourceIds: d.sourceIds as string[], targetId: String(d.targetId), reason: `采纳会话建议：${String(d.reason ?? '')}`, actor: 'user', targetRevision: expectedRevision(req, b) });
        result = { vulnId: d.targetId };
        break;
      case 'propose_split': {
        const r = splitVulnerability(store, { vulnId: String(d.vulnId), entryKeys: (d.entryKeys as string[]) ?? [], fingerprints: (d.fingerprints as string[]) ?? [], reason: `采纳会话建议：${String(d.reason ?? '')}`, actor: 'user', revision: expectedRevision(req, b) });
        result = { vulnId: r.id, displayNo: r.displayNo };
        break;
      }
      case 'propose_audit_plan': {
        const q = d.request as AuditPlanRequest;
        const id = ctx.engine.createAudit({
          projectId: q.projectId, origin: 'conversation', conversationId: cid, ...(q.repository ? { repository: q.repository } : {}), ...(q.ref ? { ref: q.ref } : {}),
          ...(q.mode ? { mode: q.mode } : {}), ...(q.related ? { related: q.related } : {}), ...(q.repositories ? { repositories: q.repositories } : {}), ...(q.refs ? { refs: q.refs } : {}),
          ...(q.scene ? { scene: q.scene } : {}), ...(q.baseRef ? { baseRef: q.baseRef } : {}), ...(q.baseRefs ? { baseRefs: q.baseRefs } : {}), ...(q.baseAuditId ? { baseAuditId: q.baseAuditId } : {}),
          ...(q.title ? { title: q.title } : {}), ...(q.strategyOverride ? { strategyOverride: q.strategyOverride } : {}),
          autoStart: true, // the card is the one confirmation
        });
        ctx.scheduler.plan(id);
        svc().appendCard(c.message_id, 'audit_status', { title: String(d.title ?? '审计'), auditId: id, scene: q.scene ?? 'full' }, { kind: 'audit', id });
        result = { auditId: id };
        break;
      }
      case 'propose_reverify': {
        const id = ctx.engine.createReverify({ vulnIds: d.vulnIds as string[], origin: 'conversation', conversationId: cid, ...(d.note ? { note: String(d.note) } : {}) });
        ctx.scheduler.plan(id);
        svc().appendCard(c.message_id, 'audit_status', { title: String(d.title ?? '复验'), auditId: id, scene: 'reverify' }, { kind: 'audit', id });
        result = { auditId: id };
        break;
      }
      case 'propose_hunt': {
        const basis = d.basis as ProposeHunt['basis'];
        const basisId = ctx.engine.jobs.startBasis(basis.kind === 'skill' ? { kind: 'skill', skill: basis.skill } : { kind: basis.kind, text: basis.text });
        result = { basisId, projectIds: d.projectIds ?? [], allProjects: !!d.allProjects };
        break;
      }
      case 'draft_connector': {
        const row = createConnector(store, { name: String(d.name), protocol: d.protocol as 'mcp_stdio', purpose: d.purpose as 'context', config: d.config as never });
        result = { connectorId: row.id, secrets: d.secrets ?? [] };
        break;
      }
      // Project, threat model, vulnerability drafts, project analysis.
      case 'propose_project': {
        // Like the project form: the project is created, then each repository is added on its own (one bad path does not undo the rest).
        const p = createProject(store, String(d.name));
        const repos: { ok: boolean; source: string; name?: string; error?: string }[] = [];
        for (const r of (d.repos ?? []) as ProposeProject['repos']) {
          try {
            repos.push({ ok: true, source: r.path ?? r.git ?? '', name: (await addFromSource(ctx, p.id, r)).name });
          } catch (e) {
            if (!(e instanceof AppError)) throw e;
            repos.push({ ok: false, source: r.path ?? r.git ?? '', error: e.hint ?? e.code });
          }
        }
        result = { projectId: p.id, repos };
        if (!repos.some((r) => r.ok)) break;
        if (d.analyze) result.analysisId = ctx.engine.jobs.startAnalysis(p.id);
        const audit = d.audit as ProposeProject['audit'] | null;
        if (audit) {
          try {
            const id = ctx.engine.createAudit({
              projectId: p.id, origin: 'conversation', conversationId: cid, mode: listRepositories(store, p.id).filter((r) => r.is_auditable).length > 1 ? 'multi' : 'single',
              ...(audit.title ? { title: audit.title } : {}), ...(audit.strategyOverride ? { strategyOverride: audit.strategyOverride } : {}), autoStart: true,
            });
            ctx.scheduler.plan(id);
            svc().appendCard(c.message_id, 'audit_status', { title: audit.title ?? `${p.name} · 全量审计`, auditId: id, scene: 'full' }, { kind: 'audit', id });
            result.auditId = id;
          } catch (e) {
            // E.g. no repository with audit-language sources: the project stays, the card says why no audit started.
            if (!(e instanceof AppError)) throw e;
            result.auditError = e.hint ?? e.code;
          }
        }
        break;
      }
      case 'propose_threat_model': {
        const tm = createThreatModelWithSources(store, String(d.projectId), { title: String(d.title), sources: d.sources as AddThreatSourceInput[] });
        result = { threatModelId: tm.id, projectId: d.projectId, generating: false };
        if (d.generate !== false) {
          try {
            ctx.engine.jobs.startThreatModel(tm.id);
            result.generating = true;
          } catch (e) {
            // A source with suspected injected instructions needs a review on the threat model page first.
            if (!(e instanceof AppError)) throw e;
            result.generateError = e.hint ?? e.code;
          }
        }
        break;
      }
      case 'propose_vuln_drafts': {
        const vid = String(d.vulnId);
        const jobs = ctx.engine.jobs;
        const drafts: Record<string, string> = {};
        for (const k of d.kinds as string[]) drafts[k] = (k === 'fix' ? jobs.startFixDraft(vid) : k === 'case' ? jobs.startCaseDraft(vid) : jobs.startRuleDraft(vid)).id;
        result = { vulnId: vid, drafts };
        break;
      }
      case 'propose_analysis':
        result = { projectId: d.projectId, analysisId: ctx.engine.jobs.startAnalysis(String(d.projectId)) };
        break;
      default:
        throw new AppError('CARD_NOT_PENDING', `${c.kind} cards have no action`);
    }
    return cardDto(store, svc().decideCard(c.id, 'applied', result));
  });
  app.post<{ Params: { cardId: string } }>('/api/v1/cards/:cardId/dismiss', async (req) => {
    return cardDto(store, svc().dismissCard(req.params.cardId));
  });
}
