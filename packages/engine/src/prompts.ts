// Prompt sets outside audit steps: conversations, AI reports, requirement threat models, pushes,
// knowledge and pack drafting, repository analysis and risk-hunt bases use the overrides in effect when they run — the
// global layer and, when the work belongs to a project, that project's layer.
import { join } from 'node:path';
import { withEgressScope } from '@xiezhi/agent';
import { PromptSet, resolvePromptOverrides, withPrompts } from '@xiezhi/knowledge';
import { egressSink } from './egress.js';
import type { Store } from '@xiezhi/store';

export function livePrompts(store: Store, projectId: string | null): PromptSet {
  return new PromptSet(resolvePromptOverrides(store.paths.knowledgeGlobal, projectId ? join(store.paths.projects, projectId, 'knowledge') : null));
}

/** Also the outbound-record scope: `kind` names the work (ai_report, threat_model, push …), `ref` its id. */
export function withLivePrompts<T>(store: Store, projectId: string | null, fn: () => T, kind = 'standalone', ref?: string): T {
  return withEgressScope({ kind, projectId, ...(ref ? { ref } : {}), sink: egressSink(store) }, () => withPrompts(livePrompts(store, projectId), fn));
}
