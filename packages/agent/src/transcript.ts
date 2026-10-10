// Saved session transcripts: an audit session is written to a pi session file (`.jsonl`, one entry
// per line, appended as the session goes), so a session stopped between turns — paused by the user, out of stage
// quota, or cut off by a restart — can be opened again and continue where it stopped, like `pi --session <id>`.
import { SessionManager } from '@earendil-works/pi-coding-agent';
import { existsSync, mkdirSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/** Custom entry carrying what the engine needs to continue a session (the data-boundary nonce). Name kept across the rename. */
export const TRANSCRIPT_META = 'code_audit';

export interface TranscriptMeta { nonce?: string }

/** Where an audit session's transcript lives and where it continues from. */
export interface TranscriptSpec {
  /** Directory for this session's transcript (created on demand). */
  dir: string;
  /** A transcript of an earlier attempt to continue (it is copied; the original stays as it was). */
  resumeFrom?: string;
  meta?: TranscriptMeta;
}

export interface ResumeInfo { messages: number; repaired: number }

/**
 * Result given to a tool call cut off by a pause or an interruption. The call may have run: a write, a submission
 * or a question must be checked before it is repeated, or it would happen twice.
 */
export const REPAIRED_RESULT = '这次工具调用在会话暂停或中断时没有返回结果。它可能已经执行，也可能没有。读取类调用可以重新调用；写入外部系统、提交结论或向用户提问的调用不要直接重复：先查询确认它是否已经生效，再决定。';

/** The transcript file in a session directory, or null when the session never got as far as a model reply. */
export function findTranscript(dir: string): string | null {
  if (!existsSync(dir)) return null;
  const f = readdirSync(dir).filter((x) => x.endsWith('.jsonl')).sort().at(-1);
  return f ? join(dir, f) : null;
}

/** The engine's metadata saved in a transcript (null when unreadable). */
export function readTranscriptMeta(file: string): TranscriptMeta | null {
  try {
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      if (!line.includes(TRANSCRIPT_META)) continue;
      const e = JSON.parse(line) as { type?: string; customType?: string; data?: TranscriptMeta };
      if (e.type === 'custom' && e.customType === TRANSCRIPT_META) return e.data ?? {};
    }
    return {};
  } catch {
    return null;
  }
}

type Entry = { id: string; parentId: string | null; type: string; message?: Msg };
type Msg = { role?: string; stopReason?: string; content?: { type: string; id?: string; name?: string; arguments?: unknown }[]; toolCallId?: string; isError?: boolean; usage?: Usage };
type Usage = { input?: number; output?: number; cacheRead?: number; cacheWrite?: number; totalTokens?: number };

/**
 * Make an opened transcript continuable: a last reply that ended in an error or an abort is dropped (the leaf moves to
 * its parent), and tool calls of the last reply without a result get one saying the call was cut off. Returns how many
 * results were added.
 */
function repair(sm: SessionManager): number {
  let leaf = sm.getLeafEntry() as Entry | undefined;
  while (leaf?.type === 'message' && leaf.message?.role === 'assistant' && ['aborted', 'error'].includes(leaf.message.stopReason ?? '')) {
    if (leaf.parentId) sm.branch(leaf.parentId);
    else sm.resetLeaf();
    leaf = sm.getLeafEntry() as Entry | undefined;
  }
  const branch = sm.getBranch() as Entry[];
  const lastAssistant = [...branch].reverse().find((e) => e.type === 'message' && e.message?.role === 'assistant');
  if (!lastAssistant) return 0;
  const after = branch.slice(branch.indexOf(lastAssistant) + 1);
  const answered = new Set(after.filter((e) => e.message?.role === 'toolResult').map((e) => e.message!.toolCallId));
  const open = (lastAssistant.message!.content ?? []).filter((c) => c.type === 'toolCall' && c.id && !answered.has(c.id));
  for (const c of open) {
    sm.appendMessage({
      role: 'toolResult', toolCallId: c.id!, toolName: c.name ?? '', isError: true, timestamp: Date.now(),
      content: [{ type: 'text', text: REPAIRED_RESULT }],
    } as never);
  }
  return open.length;
}

/**
 * The session manager for an audit session: a copy of `resumeFrom` made continuable, or a new transcript in `dir`.
 * A transcript that cannot be read starts the session afresh (`resumed: null`).
 */
export function openTranscript(cwd: string, t: TranscriptSpec): { sm: SessionManager; resumed: ResumeInfo | null } {
  mkdirSync(t.dir, { recursive: true, mode: 0o700 });
  if (t.resumeFrom) {
    try {
      const sm = SessionManager.forkFrom(t.resumeFrom, cwd, t.dir);
      const repaired = repair(sm);
      const messages = sm.buildSessionContext().messages.length;
      if (messages > 0) return { sm, resumed: { messages, repaired } };
    } catch { /* unreadable: start afresh */ }
  }
  const sm = SessionManager.create(cwd, t.dir);
  sm.appendCustomEntry(TRANSCRIPT_META, t.meta ?? {});
  return { sm, resumed: null };
}

/** What a continued session already did: accepted submissions, assistant turns and usage. */
/** `accept`: what an accepted call's arguments were (null: drop it); by default the arguments as saved. */
export function restoredState(sm: SessionManager, submitNames: Set<string>, accept: (name: string, args: unknown) => unknown = (_n, a) => a): { submissions: Record<string, unknown[]>; turns: number; usage: Required<Usage> } {
  const branch = (sm.getBranch() as Entry[]).filter((e) => e.type === 'message');
  const results = new Map(branch.filter((e) => e.message?.role === 'toolResult').map((e) => [e.message!.toolCallId, e.message!]));
  const submissions: Record<string, unknown[]> = {};
  const usage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0 };
  let turns = 0;
  for (const e of branch) {
    const m = e.message!;
    if (m.role !== 'assistant') continue;
    turns++;
    for (const k of Object.keys(usage) as (keyof typeof usage)[]) usage[k] += m.usage?.[k] ?? 0;
    for (const c of m.content ?? []) {
      if (c.type !== 'toolCall' || !c.name || !submitNames.has(c.name)) continue;
      const r = results.get(c.id);
      if (!r || r.isError) continue;
      const args = accept(c.name, c.arguments);
      if (args !== null) (submissions[c.name] ??= []).push(args);
    }
  }
  return { submissions, turns, usage };
}
