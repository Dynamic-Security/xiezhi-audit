// Server-sent events: subscribe first, then replay `seq > after` from the event table,
// dedupe by seq, then live. Heartbeat comment every 15s; `resync` when too far behind; `end` once the
// audit is terminal. A connection is only a subscriber: closing it never affects the audit.
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { AuditEvent, EventType } from '@xiezhi/contracts';
import { getAudit } from '@xiezhi/engine';
import type { AppContext } from '../context.js';
import { eventDto } from '../dto.js';
import { SECURITY_HEADERS } from '../security.js';

const TERMINAL = ['completed', 'partial', 'failed', 'cancelled'];
/** Types relayed on the global notification stream (`GET /events`). */
const GLOBAL_TYPES: EventType[] = ['audit.status_changed', 'question.asked', 'question.answered', 'budget.exhausted', 'plan.generated', 'vuln.created', 'gate.evaluated'];

export function openStream(ctx: AppContext, req: FastifyRequest, reply: FastifyReply): { write: (s: string) => boolean; close: () => void; onClose: (fn: () => void) => void } {
  reply.hijack();
  const raw = reply.raw;
  raw.writeHead(200, {
    ...SECURITY_HEADERS, 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no',
  });
  raw.write('retry: 3000\n\n');
  let closed = false;
  const closers: (() => void)[] = [];
  const close = () => {
    if (closed) return;
    closed = true;
    for (const c of closers) c();
    raw.end();
  };
  req.raw.on('close', close);
  ctx.openStreams.add(close);
  closers.push(() => ctx.openStreams.delete(close));
  return { write: (s) => (!closed ? raw.write(s) : false), close, onClose: (fn) => closers.push(fn) };
}

const frame = (e: AuditEvent) => `id: ${e.seq}\nevent: ${e.type}\ndata: ${JSON.stringify(eventDto(e))}\n\n`;

export function registerEventRoutes(app: FastifyInstance, ctx: AppContext): void {
  const { store } = ctx;

  app.get<{ Params: { aid: string }; Querystring: { after?: string } }>('/api/v1/audits/:aid/events', async (req, reply) => {
    const auditId = req.params.aid;
    getAudit(store, auditId);
    const lastEventId = Number(req.headers['last-event-id'] ?? 0) || 0;
    const after = Math.max(lastEventId, Number(req.query.after ?? 0) || 0);
    // Polling fallback: JSON when the client asks for it.
    if ((req.headers.accept ?? '').includes('application/json')) {
      const events = store.listEvents(auditId, after);
      if (events.length > ctx.stream.replayLimit) return { resync: true, events: [], lastSeq: events.at(-1)!.seq, status: getAudit(store, auditId).status };
      return { resync: false, events: events.map(eventDto), lastSeq: events.at(-1)?.seq ?? after, status: getAudit(store, auditId).status };
    }
    const s = openStream(ctx, req, reply);
    let lastSent = after;
    let replaying = true;
    const buffered: AuditEvent[] = [];
    const endIfTerminal = () => {
      const a = getAudit(store, auditId);
      if (TERMINAL.includes(a.status)) {
        s.write(`event: end\ndata: ${JSON.stringify({ status: a.status, partialReasons: JSON.parse(a.partial_reasons) })}\n\n`);
        s.close();
        return true;
      }
      return false;
    };
    const send = (e: AuditEvent) => {
      if (e.seq <= lastSent) return;
      lastSent = e.seq;
      s.write(frame(e));
      // Defer: events committed in the same transaction as the terminal transition are emitted right
      // after it, and replay must finish first — only then send `end`.
      if (!replaying && e.type === 'audit.status_changed' && TERMINAL.includes(String(e.payload.to))) setImmediate(endIfTerminal);
    };
    const off = store.onEvent((e) => {
      if (e.auditId !== auditId) return;
      if (replaying) buffered.push(e); else send(e);
    });
    s.onClose(off);
    const hb = setInterval(() => s.write(': ping\n\n'), ctx.stream.heartbeatMs);
    s.onClose(() => clearInterval(hb));
    const backlog = store.listEvents(auditId, after);
    if (backlog.length > ctx.stream.replayLimit) {
      s.write(`event: resync\ndata: ${JSON.stringify({ lastSeq: backlog.at(-1)!.seq })}\n\n`);
      lastSent = backlog.at(-1)!.seq;
    } else {
      for (const e of backlog) send(e);
    }
    replaying = false;
    for (const e of buffered.splice(0)) send(e);
    endIfTerminal();
  });

  /** Global notifications (status changes, questions) across all audits. */
  app.get('/api/v1/events', async (req, reply) => {
    const s = openStream(ctx, req, reply);
    const off = store.onEvent((e) => {
      if (!GLOBAL_TYPES.includes(e.type)) return;
      s.write(`event: ${e.type}\ndata: ${JSON.stringify({ auditId: e.auditId, ...eventDto(e) })}\n\n`);
    });
    s.onClose(off);
    // Not audit events: knowledge changes on disk.
    const notice = (type: string, payload: Record<string, unknown>) => { s.write(`event: ${type}\ndata: ${JSON.stringify({ type, auditId: null, payload })}\n\n`); };
    ctx.notices.add(notice);
    s.onClose(() => ctx.notices.delete(notice));
    const hb = setInterval(() => s.write(': ping\n\n'), ctx.stream.heartbeatMs);
    s.onClose(() => clearInterval(hb));
  });

}
