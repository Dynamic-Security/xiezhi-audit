// Outbound records: every model session stores what it sent to which provider (files read, facts
// carried by tool results, tools, tokens) and how many confidential facts it was not allowed to see. Facts marked
// confidential only reach the models listed in `confidentialModels` (global setting).
import { newId, type ModelRef } from '@xiezhi/contracts';
import type { EgressRecord, EgressScope } from '@xiezhi/agent';
import type { Store } from '@xiezhi/store';

/** May this model receive confidential facts? */
export function confidentialAllowed(store: Store, model: ModelRef): boolean {
  return (store.config.confidentialModels ?? []).includes(`${model.provider}/${model.model}`);
}

/** The provider's endpoint host (what leaves the machine, without the key). */
function endpointOf(store: Store, provider: string): string | null {
  const p = store.config.modelProviders.find((x) => x.id === provider);
  if (!p?.baseUrl) return null;
  try { return new URL(p.baseUrl).host; } catch { return null; }
}

/** A sink that stores the record of a session (with extra counts the caller knows, e.g. withheld facts). */
export function egressSink(store: Store, extra: () => { withheldFacts?: number } = () => ({})): EgressScope['sink'] {
  // A standalone session about an audit (the AI report, ref = audit id) lists with the audit.
  return (r: EgressRecord, s: EgressScope) => {
    const x = extra();
    store.insert('egress_record', {
      id: newId('egress'), kind: s.kind, audit_id: s.auditId ?? (s.ref?.startsWith('aud_') ? s.ref : null), step_id: s.stepId ?? null, conversation_id: s.conversationId ?? (s.kind === 'conversation' ? s.ref ?? null : null),
      project_id: s.projectId ?? null, ref: s.ref ?? null, provider: r.provider, model: r.model, endpoint: endpointOf(store, r.provider),
      status: r.status, turns: r.turns, tokens_in: r.tokens.input, tokens_out: r.tokens.output, tokens_cached: r.tokens.cached,
      files: r.files.slice(0, 500), facts: r.facts, withheld_facts: x.withheldFacts ?? 0, tools: r.tools, started_at: r.startedAt, ended_at: r.endedAt,
    });
  };
}

/** Files a candidate id names (`repo:path#L…`), for the record of what a prompt carried. */
export function filesOfIds(ids: string[]): { repo: string; path: string }[] {
  const out = new Map<string, { repo: string; path: string }>();
  for (const id of ids) {
    const m = /^([^:]+):([^#]+)#/.exec(id);
    if (m) out.set(`${m[1]}:${m[2]}`, { repo: m[1]!, path: m[2]! });
  }
  return [...out.values()];
}
