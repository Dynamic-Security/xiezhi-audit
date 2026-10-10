// Agent record/replay. Replay serves recorded responses keyed by a normalized request
// hash and FAILS on mismatch (never falls back to a real model). Only for deterministic behaviour
// tests — never for quality evaluation.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { canonicalJson, redactDeep, sha256Hex } from '@xiezhi/contracts';

export interface Exchange {
  requestHash: string;
  /** Normalized request (for diffs on mismatch). */
  request: unknown;
  response: unknown;
}

export interface FixtureHeader {
  piVersion: string;
  models: string[];
  recordedAt: string;
  note?: string;
  /** fixed prompt templates and submit contracts the fixture was recorded against. */
  promptHash?: string;
  toolSchemaHash?: string;
}

export interface Fixture { header: FixtureHeader; exchanges: Exchange[] }

const NORMALIZERS: [RegExp, string][] = [
  [/nonce="[0-9a-f]+"/g, 'nonce="<nonce>"'],
  [/\b[a-z]{3}_[0-9A-HJKMNP-TV-Z]{26}\b/g, '<id>'],
  [/\b\d{13}\b/g, '<ts>'],
  [/(\/private)?\/(var\/folders|tmp)\/[^\s"'`)]+/g, '<tmp>'],
  [/\/Users\/[^/\s"']+\/[^\s"'`)]*/g, '<home>'],
];

function normalizeText(s: string): string {
  let out = s;
  for (const [re, rep] of NORMALIZERS) out = out.replace(re, rep);
  return out;
}

function contentOf(message: Record<string, unknown>): unknown {
  const c = message.content;
  if (typeof c === 'string') return normalizeText(c);
  if (Array.isArray(c)) {
    return c.map((b: Record<string, unknown>) => {
      if (b.type === 'text') return { t: 'text', v: normalizeText(String(b.text ?? '')) };
      if (b.type === 'toolCall') return { t: 'call', n: b.name, a: JSON.parse(normalizeText(JSON.stringify(b.arguments ?? {}))) };
      if (b.type === 'thinking') return null;
      return { t: b.type };
    }).filter((x) => x !== null);
  }
  return null;
}

/** Normalize a pi TranscriptContext into a stable, comparable structure. */
export function normalizeRequest(context: { messages?: unknown[] }): unknown {
  const messages = (context.messages ?? []) as Record<string, unknown>[];
  return messages.map((m) => {
    const role = String(m.role);
    if (role === 'toolResult') return { r: 'tool', n: m.toolName, e: !!m.isError, c: contentOf(m) };
    if (role === 'system') {
      // System transcript entries may carry the prompt and tool declarations.
      const tools = (m.tools as { name: string }[] | undefined)?.map((t) => t.name).sort();
      return { r: 'system', c: contentOf(m), ...(tools ? { tools } : {}), ...(typeof m.systemPrompt === 'string' ? { p: normalizeText(m.systemPrompt) } : {}) };
    }
    return { r: role, c: contentOf(m) };
  });
}

export function requestHash(context: { messages?: unknown[] }): string {
  return sha256Hex(canonicalJson(normalizeRequest(context)));
}

export class ReplayMismatchError extends Error {
  constructor(readonly hash: string, readonly request: unknown) {
    super(`REPLAY_MISMATCH: no recorded response for request ${hash.slice(0, 12)}`);
    this.name = 'ReplayMismatchError';
  }
}

export class Replayer {
  private readonly queues = new Map<string, unknown[]>();
  readonly mismatches: { hash: string; request: unknown }[] = [];
  readonly served: string[] = [];

  constructor(readonly fixture: Fixture) {
    for (const ex of fixture.exchanges) {
      const q = this.queues.get(ex.requestHash) ?? [];
      q.push(ex.response);
      this.queues.set(ex.requestHash, q);
    }
  }

  static load(path: string): Replayer {
    return new Replayer(JSON.parse(readFileSync(path, 'utf8')) as Fixture);
  }

  next(context: { messages?: unknown[] }): unknown {
    const hash = requestHash(context);
    const q = this.queues.get(hash);
    if (!q || q.length === 0) {
      const request = normalizeRequest(context);
      this.mismatches.push({ hash, request });
      throw new ReplayMismatchError(hash, request);
    }
    this.served.push(hash);
    return q.length > 1 ? q.shift() : q[0];
  }
}

export class Recorder {
  readonly exchanges: Exchange[] = [];
  constructor(private readonly secrets: readonly string[] = []) {}

  record(context: { messages?: unknown[] }, response: unknown): void {
    const request = normalizeRequest(context);
    this.exchanges.push({
      requestHash: sha256Hex(canonicalJson(request)),
      request: redactDeep(request, { secrets: this.secrets }),
      response: redactDeep(response, { secrets: this.secrets }),
    });
  }

  save(path: string, header: FixtureHeader): void {
    let existing: Exchange[] = [];
    if (existsSync(path)) existing = (JSON.parse(readFileSync(path, 'utf8')) as Fixture).exchanges;
    writeFileSync(path, JSON.stringify({ header, exchanges: [...existing, ...this.exchanges] }, null, 1));
  }
}
