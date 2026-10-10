// Event streams: one detail stream per tab, seq de-duplication, fallback
// to JSON polling after 3 failures in 30s, retry SSE every 60s, close when hidden > 5 min. Events are
// written into the query cache (stream/cache.ts): status/budget patch the audit, trajectory events are
// appended; results, coverage and questions are invalidated (batched, 500 ms).
import { useEffect, useRef, useState } from 'react';
import { useQueryClient, type QueryClient } from '@tanstack/react-query';
import type { AuditDetailDto, EventDto, StepDto } from '@xiezhi/contracts';
import { api } from '../api/client';
import { qk } from '../api/queries';
import { HANDLING, advanceCursor, appendTrajectory, cursorFor, needsRefetch, patchAudit, patchSteps, type SeqCursor, type TrajectoryFilter, type TrajectoryPage } from './cache';

type Refetch = 'audit' | 'results' | 'coverage' | 'questions';

/** Write one event into the cache; `refetch` batches the invalidations that remain. */
export function applyEvent(qc: QueryClient, aid: string, e: EventDto, refetch: (k: Refetch) => void): void {
  const handling = HANDLING[e.type];
  if (handling === 'patch_audit') {
    let stale = needsRefetch(e);
    qc.setQueryData<AuditDetailDto>(qk.audit(aid), (a) => {
      if (!a) return a;
      const next = patchAudit(a, e);
      if (!next) { stale = true; return a; }
      return next;
    });
    qc.setQueryData<StepDto[]>(qk.steps(aid), (steps) => {
      if (!steps) return steps;
      const next = patchSteps(steps, e);
      if (!next) { stale = true; return steps; }
      return next;
    });
    if (stale) refetch('audit');
  }
  for (const q of qc.getQueryCache().findAll({ queryKey: ['audit', aid, 'trajectory'] })) {
    const filter = q.queryKey[3] as TrajectoryFilter | undefined;
    if (!filter || typeof filter !== 'object') continue;
    qc.setQueryData<TrajectoryPage>(q.queryKey, (page) => (page ? appendTrajectory(page, filter, e) : page));
  }
  if (handling === 'invalidate_results') refetch('results');
  else if (handling === 'invalidate_coverage') refetch('coverage');
  else if (handling === 'invalidate_questions') refetch('questions');
}

function batcher(qc: QueryClient, aid: string) {
  const pending = new Set<Refetch>();
  let t: ReturnType<typeof setTimeout> | null = null;
  const flush = () => {
    t = null;
    const kinds = [...pending];
    pending.clear();
    if (kinds.includes('audit')) {
      void qc.invalidateQueries({ queryKey: qk.audit(aid), exact: true });
      void qc.invalidateQueries({ queryKey: qk.plan(aid) });
      void qc.invalidateQueries({ queryKey: qk.steps(aid) });
    }
    if (kinds.includes('questions')) void qc.invalidateQueries({ queryKey: qk.questions(aid) });
    if (kinds.includes('results')) { void qc.invalidateQueries({ queryKey: qk.findings(aid) }); void qc.invalidateQueries({ queryKey: ['vulns'] }); }
    if (kinds.includes('coverage')) void qc.invalidateQueries({ queryKey: qk.coverage(aid) });
  };
  return (k: Refetch) => {
    pending.add(k);
    if (!t) t = setTimeout(flush, 500);
  };
}

/** A server-sent event named `error` (the engine's event type) as opposed to EventSource's own connection error. */
export function isEngineEvent(ev: Event): boolean {
  return typeof (ev as MessageEvent).data === 'string';
}

export type StreamState = 'connecting' | 'live' | 'polling' | 'ended' | 'idle';

/** Subscribe to one audit's events while `enabled`. Returns the connection state and live tail. */
export function useAuditStream(aid: string, enabled: boolean): { state: StreamState; last: EventDto | null } {
  const qc = useQueryClient();
  const [state, setState] = useState<StreamState>('idle');
  // Tagged with its audit: the page is reused across audits, and B's page must not show A's last event.
  const [last, setLast] = useState<{ aid: string; event: EventDto } | null>(null);
  const cursorRef = useRef<SeqCursor | null>(null);

  useEffect(() => {
    // a new audit starts from seq 0 (cursorFor); the old subscription's callbacks keep the old cursor.
    const cursor = cursorFor(cursorRef.current, aid);
    cursorRef.current = cursor;
    if (!enabled) { setState('idle'); return; }
    let es: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let hiddenTimer: ReturnType<typeof setTimeout> | null = null;
    let failures: number[] = [];
    let stopped = false;
    const refetch = batcher(qc, aid);
    const onEvent = (e: EventDto) => {
      if (stopped || !advanceCursor(cursor, e.seq)) return;
      setLast({ aid, event: e });
      applyEvent(qc, aid, e, refetch);
    };
    const end = () => {
      stopped = true;
      setState('ended');
      es?.close();
      if (pollTimer) clearInterval(pollTimer);
      void qc.invalidateQueries({ queryKey: ['audit', aid] });
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
    };
    const startPolling = () => {
      setState('polling');
      pollTimer = setInterval(async () => {
        try {
          const r = await api.get<{ resync: boolean; events: EventDto[]; lastSeq: number; status: string }>(`/audits/${aid}/events?after=${cursor.seq}`);
          if (stopped) return;
          if (r.resync) { cursor.seq = r.lastSeq; void qc.invalidateQueries({ queryKey: ['audit', aid] }); }
          r.events.forEach(onEvent);
          if (['completed', 'partial', 'failed', 'cancelled'].includes(r.status)) end();
        } catch { /* keep polling */ }
      }, 5000);
      retryTimer = setTimeout(() => { if (pollTimer) clearInterval(pollTimer); pollTimer = null; if (!stopped) connect(); }, 60_000);
    };
    const connect = () => {
      if (stopped) return;
      setState('connecting');
      es = new EventSource(`/api/v1/audits/${aid}/events?after=${cursor.seq}`, { withCredentials: true });
      es.onopen = () => setState('live');
      es.onmessage = () => undefined;
      const handler = (ev: MessageEvent) => { try { onEvent(JSON.parse(ev.data) as EventDto); } catch { /* ignore */ } };
      // EventSource only dispatches named events to named listeners.
      for (const t of Object.keys(HANDLING)) {
        es.addEventListener(t, handler as EventListener);
      }
      es.addEventListener('resync', ((ev: MessageEvent) => {
        try { cursor.seq = (JSON.parse(ev.data) as { lastSeq: number }).lastSeq; } catch { /* ignore */ }
        void qc.invalidateQueries({ queryKey: ['audit', aid] });
      }) as EventListener);
      es.addEventListener('end', () => end());
      es.onerror = (ev) => {
        // The engine has an event type named `error` (a step error), sent as `event: error`: EventSource dispatches it
        // like a connection error. It carries data and is handled by its listener above; only a real failure counts
        // (an audit with a step error otherwise stayed at “连接中…” and fell back to polling).
        if (isEngineEvent(ev)) return;
        if (stopped) return;
        const now = Date.now();
        failures = [...failures.filter((f) => now - f < 30_000), now];
        if (failures.length >= 3) { es?.close(); startPolling(); } else setState('connecting');
      };
    };
    const onVisibility = () => {
      if (document.hidden) {
        hiddenTimer = setTimeout(() => { es?.close(); es = null; }, 5 * 60_000);
      } else {
        if (hiddenTimer) clearTimeout(hiddenTimer);
        if (!es && !pollTimer && !stopped) connect();
      }
    };
    document.addEventListener('visibilitychange', onVisibility);
    connect();
    return () => {
      stopped = true;
      es?.close();
      if (pollTimer) clearInterval(pollTimer);
      if (retryTimer) clearTimeout(retryTimer);
      if (hiddenTimer) clearTimeout(hiddenTimer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [aid, enabled, qc]);
  return { state, last: last && last.aid === aid ? last.event : null };
}

/**
 * Global notification stream: one tab (elected via Web Locks) holds the EventSource and relays over
 * BroadcastChannel so tabs never exhaust the 6-connection limit. When the leader tab
 * closes, the lock passes to the next waiting tab, which opens the stream.
 */
export function useGlobalEvents(onNotify: (e: { type: string; auditId: string; payload: Record<string, unknown> }) => void) {
  const qc = useQueryClient();
  const cb = useRef(onNotify);
  cb.current = onNotify;
  useEffect(() => {
    const bc = typeof BroadcastChannel !== 'undefined' ? new BroadcastChannel('xiezhi-events') : null;
    const handle = (e: { type: string; auditId: string; payload: Record<string, unknown> }) => {
      void qc.invalidateQueries({ queryKey: ['dashboard'] });
      void qc.invalidateQueries({ queryKey: ['audits'] });
      if (e.type === 'vuln.created') void qc.invalidateQueries({ queryKey: ['projects'] });
      if (e.type.startsWith('conversation.')) {
        void qc.invalidateQueries({ queryKey: ['conversations'] });
        const cid = String(e.payload.conversation_id ?? '');
        if (cid) { void qc.invalidateQueries({ queryKey: ['conversation', cid], exact: true }); if (e.type === 'conversation.card') void qc.invalidateQueries({ queryKey: ['conversation', cid, 'messages'] }); }
        return;
      }
      // a vulnerability changed somewhere (any tab, any page): its detail, the lists, the conversation
      // cards about it and the pending badges follow.
      if (e.type === 'vuln.changed') {
        void qc.invalidateQueries({ queryKey: ['vuln'] });
        void qc.invalidateQueries({ queryKey: ['vulns'] });
        void qc.invalidateQueries({ queryKey: ['conversations'] });
        void qc.invalidateQueries({ queryKey: ['conversation'] });
        void qc.invalidateQueries({ queryKey: ['projects'] });
        return;
      }
      if (e.type === 'knowledge.changed') {
        void qc.invalidateQueries({ queryKey: ['knowledge'] });
        void qc.invalidateQueries({ queryKey: ['skill'] });
        return;
      }
      cb.current(e);
    };
    if (bc) bc.onmessage = (m) => handle(m.data as never);
    let es: EventSource | null = null;
    let release: (() => void) | null = null;
    let disposed = false;
    const lead = () => {
      es = new EventSource('/api/v1/events', { withCredentials: true });
      const relay = (ev: MessageEvent) => {
        try {
          const d = JSON.parse(ev.data) as { auditId: string; type: string; payload: Record<string, unknown> };
          handle(d);
          bc?.postMessage(d);
        } catch { /* ignore */ }
      };
      for (const t of ['audit.status_changed', 'question.asked', 'question.answered', 'budget.exhausted', 'plan.generated', 'vuln.created', 'gate.evaluated', 'knowledge.changed', 'conversation.updated', 'conversation.card', 'vuln.changed']) es.addEventListener(t, relay as EventListener);
    };
    const locks = (navigator as Navigator & { locks?: { request: (n: string, o: { signal: AbortSignal }, cb: () => Promise<void>) => Promise<void> } }).locks;
    const waiting = new AbortController();
    if (locks) {
      // A tab that unmounts while still queued withdraws its request instead of leading later.
      locks.request('xiezhi-global-events', { signal: waiting.signal }, () => {
        if (disposed) return Promise.resolve();
        return new Promise<void>((resolve) => { release = resolve; lead(); });
      }).catch(() => undefined);
    } else lead();
    return () => {
      disposed = true;
      waiting.abort();
      es?.close();
      release?.();
      bc?.close();
    };
  }, [qc]);
}
