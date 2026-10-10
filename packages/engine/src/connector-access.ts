// Connector access for agent sessions: the `connector_query` operations a session may call, the
// operation list shown to the model, and cited connector results as evidence. Shared by audit steps, conversations and
// push. Moved out of runtime.ts.
import { canonicalJson, newId, sha256Hex } from '@xiezhi/contracts';
import { detectInjection, wrapUntrusted, type ConnectorAccess, type ConnectorOperation } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import type { ConnectorPool, ConnectorSpec } from '@xiezhi/connectors';
import { connectorSpec, connectorStatus, logConnectorCall, requestConnectorWrite, type ConnectorRow, type ConnectorTool } from './connectors.js';
import { P } from '@xiezhi/knowledge';

/** A connector result a conclusion cites: recorded as evidence of kind `connector`. */
export interface ConnectorRef { callId: string; connector: string; operation: string; authoritative: boolean; responseRef: string | null; responseHash: string | null; at: number }

/**
 * Cited connector results as evidence of kind `connector`: verified only when the call counted as
 * authoritative; the stored response and its hash are the proof. Never counts towards code-evidence completeness.
 */
export function insertConnectorEvidence(store: Store, ownerKind: 'finding' | 'revision', ownerId: string, refs: ConnectorRef[], stepId: string, ordStart: number): string[] {
  return refs.map((c, i) => {
    const id = newId('evidence');
    store.insert('evidence', {
      id, owner_kind: ownerKind, owner_id: ownerId, kind: 'connector', snapshot_id: null, path: `connector:${c.connector}/${c.operation}`,
      content_hash: c.responseHash, artifact_ref: c.responseRef, verified: c.authoritative ? 1 : 0, step_id: stepId, ord: ordStart + i, origin_label: 'connector',
      note: c.authoritative ? `权威数据源 · 调用 ${c.callId} · ${new Date(c.at).toISOString()}` : `外部数据，未核实 · 调用 ${c.callId}`,
    });
    return id;
  });
}

/** Connector results inline up to this size; larger ones are stored as an artifact. */
export const CONNECTOR_INLINE_BYTES = 32 * 1024;

/** The operation list shown to the model: descriptions come from the external server, so they are data. */
export function connectorPrompt(ops: ConnectorOperation[], nonce: string): string {
  const list = ops.map((o) => `- ${o.connector}${o.authoritative ? ' [权威]' : ''} · ${o.tool}（参数：${o.params || '无'}）：${o.description}`).join('\n');
  const anyWrite = ops.some((o) => o.write);
  const anyAuth = ops.some((o) => o.authoritative);
  // With only “results are unverified” the model never queried — say when to query and what the
  // result is for (it narrows a pending condition and tells the user where to verify; it never confirms alone).
  return [
    '# 可用连接器操作',
    anyWrite ? P('connectors.intro_write') : P('connectors.intro_read'),
    ...(anyWrite ? [P('connectors.write_rule')] : []),
    P('connectors.usage'),
    ...(anyAuth ? [P('connectors.authoritative_rule')] : []),
    P('data.connector_operations'),
    wrapUntrusted(nonce, 'connector', 'connector-operations', list),
  ].join('\n');
}

/**
 * `connector_query` access for one session: enabled, tested context connectors among
 * `refs` with the tools they offer (read and write). Shared by audit steps and conversations: each
 * call is logged with its owner, judged authoritative per call, and reported through `onQueried`.
 */
export function buildConnectorAccess(o: {
  store: Store; pool: ConnectorPool; refs: string[]; auditId?: string | null; conversationId?: string | null; stepId: string;
  artifacts: Set<string>; onQueried?: (payload: Record<string, unknown>) => void;
  /** a call was held for the user's approval (audit trajectory). */
  onWriteRequested?: (payload: Record<string, unknown>) => void;
  /** the session has read suspected injected instructions in the audited code — its calls wait for approval. */
  codeInjectionSeen?: () => boolean;
  /** Who holds a call for approval when it is held (default: the audit or the conversation). */
  source?: 'audit' | 'conversation' | 'push';
}): ConnectorAccess | null {
  const { store, pool } = o;
  const specs = new Map<string, ConnectorSpec>();
  const operations: ConnectorOperation[] = [];
  for (const ref of o.refs) {
    const row = store.get<ConnectorRow>('SELECT * FROM connector WHERE id = ? OR name = ?', ref, ref);
    if (!row || !row.enabled || connectorStatus(row, store.paths.connectorPacks) !== 'ready') continue;
    specs.set(row.id, connectorSpec(row, store.paths.connectorPacks));
    for (const t of fromJson<ConnectorTool[]>(row.tools, [])) {
      const op = { connectorId: row.id, connector: row.name, tool: t.name, description: (t.description ?? '').slice(0, 300), params: t.params ?? '', authoritative: !!row.authoritative };
      // every tool the user left on is offered — MCP tools and pack operations, read or write; they run
      // directly unless instructions from the audited code are involved (then the call waits for approval).
      if (t.exposed === false) continue;
      operations.push(t.readOnlyHint === true ? op : { ...op, write: true });
    }
  }
  if (!operations.length) return null;
  const owner = { auditId: o.auditId ?? null, conversationId: o.conversationId ?? null, stepId: o.stepId };
  const emit = (p: Record<string, unknown>) => { try { o.onQueried?.(p); } catch { /* observers never break calls */ } };
  return {
    operations,
    call: async (op, args, reason, signal) => {
      // hold the call for the user when it carries instructions from the audited code.
      const argSignals = detectInjection(JSON.stringify(args));
      if (argSignals.length || o.codeInjectionSeen?.()) {
        const w = requestConnectorWrite(store, {
          connectorId: op.connectorId, tool: op.tool, args, reason, source: o.source ?? (o.auditId ? 'audit' : 'conversation'),
          auditId: o.auditId ?? null, stepId: o.auditId ? o.stepId : null, conversationId: o.conversationId ?? null, messageId: o.conversationId ? o.stepId : null,
        });
        const why = argSignals.length ? 'args' : 'session';
        try { o.onWriteRequested?.({ request_id: w.id, connector: op.connector, operation: op.tool, reason: reason.slice(0, 300), signals: fromJson<string[]>(w.signals, []), held_because: why }); } catch { /* observers never break calls */ }
        return {
          text: P(why === 'args' ? 'feedback.connector.held_args' : 'feedback.connector.held_session', { operation: `${op.connector}.${op.tool}`, requestId: w.id }),
          isError: false, totalBytes: 0, artifactId: null, callId: w.id, authoritative: false, signals: [], pending: true,
        };
      }
      if (op.write) {
        const replay = writeReplay(store, o, op, args);
        if (replay) return replay;
      }
      const started = Date.now();
      try {
        const r = await pool.call(specs.get(op.connectorId)!, op.tool, args, signal);
        const bytes = Buffer.byteLength(r.text);
        let text = r.text;
        let artifactId: string | null = null;
        // Inline at most 32 KB; the rest is kept as an artifact the model can page.
        if (bytes > CONNECTOR_INLINE_BYTES) {
          artifactId = store.artifacts.put(r.text, 'text/plain');
          o.artifacts.add(artifactId);
          text = Buffer.from(r.text).subarray(0, CONNECTOR_INLINE_BYTES).toString('utf8');
        }
        // Authoritative only when the connector is marked so, the call succeeded and nothing in the content
        // looks like instructions to the model; the full response is kept as the evidence.
        const signals = [...new Set(detectInjection(r.text).map((x) => x.signal))];
        const authoritative = op.authoritative && !r.isError && signals.length === 0;
        let responseRef: string | null = null;
        // A write keeps its full request and response, so a later identical call can be answered from it.
        if (authoritative || op.write) {
          responseRef = artifactId ?? store.artifacts.put(r.text, 'text/plain');
          o.artifacts.add(responseRef);
        }
        const requestRef = op.write ? store.artifacts.putJson(args) : null;
        const callId = store.tx(() => {
          const id = logConnectorCall(store, op.connectorId, {
            operation: op.tool, kind: op.write ? 'write' : 'read', confirmedBy: op.write ? 'auto' : null, status: r.isError ? 'error' : 'ok', durationMs: Date.now() - started, request: args, bytes, ...owner,
            authoritative, responseHash: authoritative ? sha256Hex(r.text) : null, responseRef, requestRef,
          });
          emit({ connector: op.connector, operation: op.tool, status: r.isError ? 'error' : 'ok', bytes, duration_ms: Date.now() - started, reason: reason.slice(0, 300), call_id: id, authoritative, ...(op.authoritative && !authoritative ? { downgraded: r.isError ? ['error'] : signals } : {}) });
          return id;
        });
        return { text, isError: r.isError, totalBytes: bytes, artifactId, callId, authoritative, signals };
      } catch (e) {
        const err = e as { code?: string; message: string };
        const status = err.code === 'unavailable' ? 'unavailable' : err.code === 'timeout' ? 'timeout' : err.code === 'blocked' ? 'blocked' : 'error';
        store.tx(() => {
          logConnectorCall(store, op.connectorId, { operation: op.tool, kind: op.write ? 'write' : 'read', status, durationMs: Date.now() - started, request: args, error: err.message, ...owner });
          emit({ connector: op.connector, operation: op.tool, status, duration_ms: Date.now() - started, error: err.message.slice(0, 300) });
        });
        throw new Error(status === 'unavailable'
          ? P('feedback.connector.unavailable', { connector: op.connector })
          : `connector ${op.connector} failed (${status}): ${err.message.slice(0, 300)}`, { cause: e });
      }
    },
  };
}

/** Connector write calls one audit step or one reply may run; `engine.connectorWritesPerStep` overrides it. */
export const CONNECTOR_WRITES_PER_STEP = 20;

type Owner = { store: Store; auditId?: string | null; conversationId?: string | null; stepId: string; artifacts: Set<string>; onQueried?: (payload: Record<string, unknown>) => void };

/**
 * A write call that need not run: the same call — connector, operation and arguments — that
 * already succeeded in this audit (any step: a retry, a fallback model, a continued session or a split batch) or in
 * this reply is answered with the stored result instead of running again (a second ticket); past the per-step limit
 * the call is refused. null: run it.
 */
function writeReplay(store: Store, o: Owner, op: ConnectorOperation, args: Record<string, unknown>) {
  const hash = sha256Hex(canonicalJson(args));
  const scope = o.auditId ? ['audit_id = ?', o.auditId] as const : ['step_id = ?', o.stepId] as const;
  const prior = store.get<{ id: string; response_ref: string | null; response_bytes: number; authoritative: number }>(
    `SELECT id, response_ref, response_bytes, authoritative FROM connector_call WHERE ${scope[0]} AND connector_id = ? AND operation = ? AND kind = 'write'
     AND status = 'ok' AND request_hash = ? AND replayed_from IS NULL ORDER BY created_at, rowid LIMIT 1`, scope[1], op.connectorId, op.tool.slice(0, 200), hash);
  const owner = { auditId: o.auditId ?? null, conversationId: o.conversationId ?? null, stepId: o.stepId };
  const emit = (p: Record<string, unknown>) => { try { o.onQueried?.(p); } catch { /* observers never break calls */ } };
  if (prior) {
    const full = prior.response_ref ? store.artifacts.getText(prior.response_ref) : null;
    const callId = logConnectorCall(store, op.connectorId, {
      operation: op.tool, kind: 'write', confirmedBy: 'auto', status: 'ok', durationMs: 0, request: args, bytes: prior.response_bytes, ...owner,
      responseRef: prior.response_ref, replayedFrom: prior.id,
    });
    emit({ connector: op.connector, operation: op.tool, status: 'ok', bytes: prior.response_bytes, duration_ms: 0, call_id: callId, replayed_from: prior.id });
    const note = P('feedback.connector.write_replayed', { callId: prior.id });
    const text = full === null ? `${note}\n${P('feedback.connector.replay_missing')}` : `${note}\n${Buffer.from(full).subarray(0, CONNECTOR_INLINE_BYTES).toString('utf8')}`;
    if (prior.response_ref) o.artifacts.add(prior.response_ref);
    return { text, isError: false, totalBytes: prior.response_bytes, artifactId: full !== null && Buffer.byteLength(full) > CONNECTOR_INLINE_BYTES ? prior.response_ref : null, callId, authoritative: false, signals: [] };
  }
  const cap = store.config.engine.connectorWritesPerStep ?? CONNECTOR_WRITES_PER_STEP;
  const made = store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM connector_call WHERE step_id = ? AND kind = 'write' AND replayed_from IS NULL AND status <> 'refused'`, o.stepId)!.n;
  if (made < cap) return null;
  const callId = logConnectorCall(store, op.connectorId, { operation: op.tool, kind: 'write', status: 'refused', durationMs: 0, request: args, error: `write limit ${cap} per step reached`, ...owner });
  emit({ connector: op.connector, operation: op.tool, status: 'refused', duration_ms: 0, call_id: callId, error: `write limit ${cap} per step reached` });
  return {
    text: P('feedback.connector.write_limit', { made, cap }),
    isError: true, totalBytes: 0, artifactId: null, callId, authoritative: false, signals: [],
  };
}
