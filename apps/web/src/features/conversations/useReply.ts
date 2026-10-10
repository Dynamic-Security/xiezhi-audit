// Assistant reply stream: EventSource on /messages/{mid}/stream, seq de-duplication,
// resume with `after`, a replacing delta carries the full text after a reconnect; JSON polling after
// 3 failures within 30 s. The server's `error` event shares its name with EventSource's own connection
// error: only the one with data is a reply error.
import { useEffect, useRef, useState } from 'react';
import type { CardDto, ToolCallDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';

export interface LiveCard { cardId: string; kind: CardDto['kind']; state: CardDto['state']; data: Record<string, unknown>; textOffset: number | null }
export interface LiveReply {
  text: string;
  toolCalls: ToolCallDto[];
  cards: LiveCard[];
  status: 'connecting' | 'streaming' | 'polling' | 'done' | 'error';
  error: string | null;
}

const EMPTY: LiveReply = { text: '', toolCalls: [], cards: [], status: 'connecting', error: null };

export function useReplyStream(mid: string | null, onEnd: () => void): LiveReply {
  const [state, setState] = useState<LiveReply>(EMPTY);
  const end = useRef(onEnd);
  end.current = onEnd;

  useEffect(() => {
    if (!mid) return;
    let lastSeq = 0;
    let es: EventSource | null = null;
    let poll: ReturnType<typeof setInterval> | null = null;
    let failures: number[] = [];
    let closed = false;
    setState(EMPTY);

    const apply = (type: string, d: Record<string, unknown>) => {
      const seq = Number(d.seq ?? 0);
      const replace = d.replace === true;
      if (!replace && seq && seq <= lastSeq) return;
      if (seq > lastSeq) lastSeq = seq;
      setState((s) => {
        switch (type) {
          case 'message_start': return { ...s, status: 'streaming' };
          case 'delta': return { ...s, status: s.status === 'connecting' ? 'streaming' : s.status, text: replace ? String(d.text ?? '') : s.text + String(d.text ?? '') };
          case 'tool_call': {
            const id = String(d.callId);
            const prev = s.toolCalls.find((t) => t.callId === id);
            const next: ToolCallDto = {
              callId: id, name: String(d.name ?? prev?.name ?? ''), argsSummary: String(d.argsSummary ?? prev?.argsSummary ?? ''),
              phase: d.phase === 'finished' ? 'finished' : 'started', ok: typeof d.ok === 'boolean' ? d.ok : prev?.ok ?? null,
              resultPreview: typeof d.resultPreview === 'string' ? d.resultPreview : prev?.resultPreview ?? null,
              textOffset: typeof d.textOffset === 'number' ? d.textOffset : prev?.textOffset ?? null,
            };
            return { ...s, toolCalls: prev ? s.toolCalls.map((t) => (t.callId === id ? next : t)) : [...s.toolCalls, next] };
          }
          case 'card': return s.cards.some((c) => c.cardId === d.cardId) ? s : { ...s, cards: [...s.cards, { cardId: String(d.cardId), kind: d.kind as LiveCard['kind'], state: d.state as LiveCard['state'], data: (d.data ?? {}) as Record<string, unknown>, textOffset: typeof d.textOffset === 'number' ? d.textOffset : null }] };
          case 'done': return { ...s, status: 'done' };
          case 'error': return { ...s, status: 'error', error: String(d.message ?? '回复中断') };
          default: return s;
        }
      });
    };

    const finish = () => {
      if (closed) return;
      closed = true;
      es?.close();
      if (poll) clearInterval(poll);
      end.current();
    };

    const startPolling = () => {
      es?.close();
      setState((s) => ({ ...s, status: s.status === 'done' ? s.status : 'polling' }));
      const tick = async () => {
        try {
          const r = await api.get<{ status: string; events: { seq: number; type: string; data: Record<string, unknown> }[] }>(`/messages/${mid}/stream?after=${lastSeq}`);
          for (const e of r.events) apply(e.type, { ...e.data, seq: e.seq });
          if (r.status !== 'streaming') finish();
        } catch { /* keep polling */ }
      };
      void tick();
      poll = setInterval(() => void tick(), 5000);
    };

    const connect = () => {
      es = new EventSource(`/api/v1/messages/${mid}/stream?after=${lastSeq}`, { withCredentials: true });
      const on = (type: string) => es!.addEventListener(type, (ev) => {
        const me = ev as MessageEvent;
        if (type === 'error' && typeof me.data !== 'string') {
          // Connection error: EventSource retries by itself (with Last-Event-ID); count failures.
          const now = Date.now();
          failures = [...failures.filter((t) => now - t < 30_000), now];
          if (failures.length >= 3) startPolling();
          return;
        }
        try { apply(type, JSON.parse(me.data as string) as Record<string, unknown>); } catch { /* ignore malformed */ }
      });
      for (const t of ['message_start', 'delta', 'tool_call', 'card', 'done', 'error']) on(t);
      es.addEventListener('end', () => finish());
    };
    connect();
    return () => { closed = true; es?.close(); if (poll) clearInterval(poll); };
  }, [mid]);

  return state;
}
