// Outbound record: what each model session sent to which provider — the files its tools read, the
// enterprise facts tool results carried, the tools it used, the tokens. The caller puts a scope around the session (an
// audit step, a conversation reply, a standalone session) with a sink that stores the record; without a scope nothing is
// recorded.
import { AsyncLocalStorage } from 'node:async_hooks';

export interface EgressScope {
  kind: string;
  auditId?: string; stepId?: string; conversationId?: string; projectId?: string | null; ref?: string;
  /** Files the engine put into the prompt itself (diffs, evidence snippets, candidate locations). */
  promptFiles?: { repo?: string; path: string }[];
  sink: (r: EgressRecord, scope: EgressScope) => void;
}

export interface EgressRecord {
  provider: string; model: string; status: string; turns: number;
  tokens: { input: number; output: number; cached: number };
  files: { repo?: string; path: string }[];
  /** Enterprise fact ids that tool results carried into the session. */
  facts: string[];
  tools: Record<string, number>;
  startedAt: number; endedAt: number;
}

const scope = new AsyncLocalStorage<EgressScope>();
export function withEgressScope<T>(s: EgressScope, fn: () => T): T { return scope.run(s, fn); }
export function currentEgressScope(): EgressScope | undefined { return scope.getStore(); }

/** Collects one session's outbound record. */
export class EgressCollector {
  private readonly files = new Map<string, { repo?: string; path: string }>();
  private readonly facts = new Set<string>();
  private readonly tools: Record<string, number> = {};
  readonly startedAt = Date.now();
  constructor(readonly scope: EgressScope | undefined) {}

  call(name: string, args: unknown): void {
    this.tools[name] = (this.tools[name] ?? 0) + 1;
    const a = (args ?? {}) as { path?: unknown; repo?: unknown; paths?: unknown };
    const repo = typeof a.repo === 'string' ? a.repo : undefined;
    for (const p of [a.path, ...(Array.isArray(a.paths) ? a.paths : [])]) {
      if (typeof p === 'string' && p) this.files.set(`${repo ?? ''}:${p}`, { ...(repo ? { repo } : {}), path: p });
    }
  }

  result(text: string): void {
    for (const m of text.matchAll(/\bfct_[0-9A-Z]{26}\b/g)) this.facts.add(m[0]);
  }

  finish(r: { provider: string; model: string; status: string; turns: number; tokens: EgressRecord['tokens'] }): void {
    if (!this.scope) return;
    for (const f of this.scope.promptFiles ?? []) this.files.set(`${f.repo ?? ''}:${f.path}`, f);
    try {
      this.scope.sink({ ...r, files: [...this.files.values()], facts: [...this.facts], tools: { ...this.tools }, startedAt: this.startedAt, endedAt: Date.now() }, this.scope);
    } catch { /* recording never fails a session */ }
  }
}
