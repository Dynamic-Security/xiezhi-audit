// One pi session = one step attempt. The engine never talks to pi directly; it uses
// runSession() with audit tools, submit contracts and callbacks for trajectory and budget.
import {
  createAgentSession, DefaultResourceLoader, SessionManager, SettingsManager, defineTool, type ToolDefinition,
} from '@earendil-works/pi-coding-agent';
import { existsSync } from 'node:fs';
import type { TSchema } from 'typebox';
import { check, type ErrorClass, type ModelRef } from '@xiezhi/contracts';
import type { ModelHub } from './models.js';
import { openTranscript, restoredState, type ResumeInfo, type TranscriptSpec } from './transcript.js';
import { P } from '@xiezhi/knowledge';
import { EgressCollector, currentEgressScope } from './egress.js';
import { decodedJsonFields, repairLeakedParameters, withEmptyRequiredLists } from './repair.js';
import { MIN_OUTPUT_TOKENS, outputRoom } from './limits.js';

export interface ToolRunResult { text: string; details?: unknown; summary?: Record<string, unknown> }

export interface AuditTool {
  name: string;
  description: string;
  parameters: TSchema;
  /** submit tools feed the output contract; read tools are plain evidence gathering. */
  kind: 'read' | 'submit' | 'meta';
  run(args: any, signal: AbortSignal | undefined): Promise<ToolRunResult> | ToolRunResult;
  /** submit only: semantic validation beyond the schema; return issues to reject. */
  validate?(args: any): string[];
  /**
   * The tool returns audited content (e.g. a diff); the runtime scans its output for injected
   * instructions and wraps it in the data boundary under this source label.
   */
  untrusted?: string;
  /**
   * submit only: given a call's issues (schema or semantic), drop the items they point at and return the rest
   * with a note for the model, or null to refuse the call as before. The pruned call is checked again; it is accepted
   * only when no issue is left.
   */
  prune?(args: any, issues: string[]): { args: any; note: string } | null;
  /**
   * submit only: fill defaults the model may leave out before the call is checked; the result is what is
   * validated, run and recorded as the submission.
   */
  normalize?(args: any): any;
}

export type SessionEvent =
  | { type: 'session.started'; model: string }
  | { type: 'session.turn'; turn: number; usage: UsageDelta; /** The assistant's text of the turn. */ text?: string }
  | { type: 'session.ended'; status: SessionStatus; turns: number; telemetry: SessionTelemetry }
  | { type: 'tool.called'; tool: string; args: unknown; callId: string }
  | { type: 'tool.result'; tool: string; callId: string; ok: boolean; preview: string; summary?: Record<string, unknown>; durationMs: number }
  | { type: 'contract.violation'; tool: string; issues: string[]; attempt: number }
  | { type: 'security.blocked'; tool: string; reason: string }
  /** Streamed assistant text (conversations render it as it arrives). */
  | { type: 'text.delta'; text: string }
  /** the session continues a saved transcript instead of starting from the task prompt. */
  | { type: 'session.resumed'; messages: number; repaired: number }
  /** pi compacted the conversation (the context window was nearly full). */
  | { type: 'session.compacted'; reason: string };

export interface UsageDelta { input: number; output: number; cacheRead: number; cacheWrite: number; total: number; cost: number }

export type BudgetVerdict = 'continue' | 'wrap_up' | 'abort';

export type SessionStatus = 'completed' | 'contract_failed' | 'max_turns' | 'aborted' | 'budget_stopped' | 'error';

export interface SessionSpec {
  hub: ModelHub;
  model: ModelRef;
  cwd: string;
  agentDir: string;
  systemPrompt: string;
  prompt: string;
  tools: AuditTool[];
  /** Submit tools that must be called successfully at least once before the session may end. */
  requiredSubmits: string[];
  maxTurns: number;
  signal?: AbortSignal;
  onEvent?: (e: SessionEvent) => void;
  /** Called after every assistant message; the verdict implements budget wrap-up/abort. */
  onUsage?: (u: UsageDelta) => BudgetVerdict;
  /**
   * Awaited before every model request: `pause` (the user paused the audit) ends the session
   * as aborted, `budget` (its stage quota is used up) as BUDGET_EXHAUSTED — both between turns, so the transcript is
   * complete and a later attempt continues it.
   */
  beforeRequest?: () => Promise<'continue' | 'pause' | 'budget'>;
  /** Save the conversation to a transcript (and continue an earlier one) instead of keeping it in memory. */
  transcript?: TranscriptSpec;
  /** First message of a continued session; the task prompt is already in its history. */
  resumePrompt?: string;
  /**
   * asked when every required submit is in and the session is about to end. A message continues the session
   * once with it (e.g. listed candidates still without a verdict); null lets it end.
   */
  completionCheck?: () => string | null;
  /**
   * ids of items pushed into the prompt (leads, candidates, hypotheses, skill names, connector operations); the
   * outcome lists those that appear in any tool call's arguments (read, query or submission).
   */
  trackIds?: string[];
  /** the steer sent on the first `wrap_up` verdict instead of the budget wording (e.g. a context-cap handoff). */
  wrapUpMessage?: string;
}

/** what the session's context looked like, for the stage telemetry. */
export interface SessionTelemetry {
  /** Largest context of one model request: input + cache read + cache write tokens. */
  peakContext: number;
  /** Times pi compacted the conversation. */
  compactions: number;
  /** The `trackIds` that appeared in a tool call's arguments. */
  referenced: string[];
}

/** What a continued session is told first. */
export const resumePrompt = (): string => P('nudge.session.resume');

export interface SessionOutcome {
  status: SessionStatus;
  errorClass: ErrorClass | null;
  errorMessage?: string;
  turns: number;
  usage: UsageDelta;
  submissions: Record<string, unknown[]>;
  finalText: string;
  /**
   * The session already had accepted submissions for every required tool when a later submission was rejected
   * too often: it ends as completed so the accepted results are kept; the rejected part is
   * described here and whatever it would have covered stays unreviewed.
   */
  contractShortfall?: string;
  telemetry: SessionTelemetry;
}

export const MAX_CONTRACT_CORRECTIONS = 2;
const MAX_SETTLE_NUDGES = 2;
/** how often a session with its required results is sent back for what its completion check still misses. */
export const MAX_COMPLETION_NUDGES = 1;

/** Turns left when the turn-limit wrap-up is sent: 15% of the limit, at least 2; none for limits under 5. */
export function wrapUpTurns(maxTurns: number): number {
  return maxTurns < 5 ? 0 : Math.max(2, Math.ceil(maxTurns * 0.15));
}

/**
 * Replies in a row cut at the output limit with next to no output before the session ends as CONTEXT_OVERFLOW: the
 * backstop of the request check for a context the estimate misses (a provider that clamps on its own).
 */
export const MAX_EMPTY_TRUNCATED_REPLIES = 3;
const EMPTY_REPLY_TOKENS = 16;

/** Why a request with `room` output tokens left is not sent, or null when it has enough. */
export function contextTooLarge(model: { contextWindow: number; maxTokens: number }, room: number): string | null {
  const floor = Math.min(MIN_OUTPUT_TOKENS, model.maxTokens);
  if (room >= floor) return null;
  return `context too large: the conversation leaves ${Math.max(0, room)} output tokens of the model's ${model.contextWindow}-token context window (at least ${floor} needed); `
    + 'set the model\'s real context window in its provider settings or use a model with a larger one';
}

export interface SessionHandle { steer(text: string): Promise<void>; outcome: Promise<SessionOutcome> }

function zeroUsage(): UsageDelta {
  return { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0, cost: 0 };
}

/**
 * A provider's content filter refused the request. Gateways often report it as a broken stream, so the text the
 * model sent before the error is checked too (Gemini: "This request was blocked by Gemini's filters").
 */
const CONTENT_FILTER = /blocked by .{0,40}filters?|content.?filter|content (was )?(blocked|filtered)|safety (filter|policy|settings|block)|responsible ?ai|generative-ai\/use-policy|finish.?reason.{0,6}(safety|content_filter)/i;

export function isContentFiltered(...texts: (string | undefined)[]): boolean {
  return texts.some((t) => !!t && CONTENT_FILTER.test(t));
}

const PROVIDER_QUOTA = /\b402\b|payment required|insufficient.{0,20}(balance|credit|funds|quota)|credit balance (is )?too low|exceeded your current quota|billing.{0,20}(limit|details|hard)|out of credits|余额不足|欠费|额度不足/;

export function classifyProviderError(message: string, replyText?: string): ErrorClass {
  const m = message.toLowerCase();
  if (m.includes('replay_mismatch')) return 'INTERNAL';
  if (isContentFiltered(message, replyText)) return 'CONTENT_FILTERED';
  // No balance or quota left (402, billing). Checked before 429: OpenAI answers "exceeded your current
  // quota … billing" with 429. A per-minute quota ("quota exceeded for metric … per minute") stays a rate limit.
  if (PROVIDER_QUOTA.test(m)) return 'PROVIDER_QUOTA';
  if (/\b429\b|rate.?limit|too many requests/.test(m)) return 'RATE_LIMITED';
  if (/\b(401|403)\b|unauthori[sz]ed|invalid api key|no api key|authentication/.test(m)) return 'AUTH_INVALID';
  // Gateways also reject a model they do not serve with 400 ("model … is not supported", "invalid model"); a retry
  // cannot help, so these switch to the fallback model at once.
  if (/model.{0,60}(not found|does not exist|unknown|not supported|unsupported|not available)|(invalid|unknown|unsupported) model|\b404\b/.test(m)) return 'MODEL_NOT_FOUND';
  if (/context.{0,20}(length|window|overflow)|too many tokens|maximum context/.test(m)) return 'CONTEXT_OVERFLOW';
  return 'PROVIDER_TRANSIENT';
}

/**
 * What a tool call's arguments become before pi checks the schema: arguments that leaked the model's parameter markup
 * into a string field are split back into fields, required lists left out are empty, fields sent as JSON text are
 * decoded; then a prunable submit drops the items that still break the schema, so one bad item no longer
 * refuses the whole call. Also used for submissions restored from a saved transcript, which keeps the raw arguments.
 */
export function prepareToolArguments(t: AuditTool, raw: unknown, note: (issue: string) => void = () => undefined): { args: unknown; pruneNote?: string } {
  if (!raw || typeof raw !== 'object') return { args: raw };
  let schema = check(t.parameters, raw);
  if (schema.ok) return { args: raw };
  let args: unknown = raw;
  let repaired = repairLeakedParameters(raw);
  // a leaked tag the schema does not know (`<codeDefense2>无</codeDefense2>`) would refuse the repaired call.
  const props = (t.parameters as { properties?: Record<string, unknown> }).properties;
  if (repaired !== raw && props && !Array.isArray(repaired)) {
    const r = repaired as Record<string, unknown>;
    repaired = Object.fromEntries(Object.entries(r).filter(([k]) => k in props || k in (raw as Record<string, unknown>)));
  }
  if (repaired !== raw) {
    const again = check(t.parameters, repaired);
    if (again.ok || again.issues.length < schema.issues.length) {
      args = repaired;
      schema = again;
      note('split parameter markup that leaked into a string field back into fields');
    }
  }
  // Required list fields left out (`ruledOut`, `reviewedTargets` when there is nothing to list) are empty lists.
  const filled = withEmptyRequiredLists(t.parameters, args);
  if (!schema.ok && filled !== args) {
    const again = check(t.parameters, filled);
    if (again.ok || again.issues.length < schema.issues.length) { args = filled; schema = again; }
  }
  for (const [k, decoded] of schema.ok ? [] : decodedJsonFields(args)) {
    const next = { ...(args as Record<string, unknown>), [k]: decoded };
    const again = check(t.parameters, next);
    // Kept once the field itself has the right type: what remains is about its content, which tells the model
    // more than “must be array” (the decoded items may well have more issues than the one type error).
    if (!again.ok && again.issues.some((i) => i.path === `$.${k}`)) continue;
    args = next;
    schema = again;
    note(`decoded field ${k} sent as JSON text`);
    if (schema.ok) break;
  }
  if (schema.ok || t.kind !== 'submit' || !t.prune) return { args };
  const p = safePrune(t, args, schema.issues.map((i) => `${i.path} ${i.message}`));
  if (!p || !check(t.parameters, p.args).ok) return { args };
  return { args: p.args, pruneNote: p.note };
}

/**
 * A tool's prune, run on arguments the schema has not passed yet: one that throws on an unexpected shape
 * (a list sent as text) prunes nothing, so the model is told the schema issues instead of the exception.
 */
function safePrune(t: AuditTool, args: unknown, issues: string[]): { args: unknown; note: string } | null {
  try { return t.prune?.(args, issues) ?? null; } catch { return null; }
}

export function startSession(spec: SessionSpec): SessionHandle {
  // the outbound record of this session (stored by the caller's scope, if any).
  const egress = new EgressCollector(currentEgressScope());
  let session: Awaited<ReturnType<typeof createAgentSession>>['session'] | null = null;
  const pendingSteers: string[] = [];
  const outcome = (async (): Promise<SessionOutcome> => {
    const submissions: Record<string, unknown[]> = {};
    const violations: Record<string, number> = {};
    /** Submit tools already counted as rejected in the current reply. */
    const struckThisReply = new Set<string>();
    const usage = zeroUsage();
    let turns = 0;
    let status: SessionStatus | null = null;
    let errorClass: ErrorClass | null = null;
    let errorMessage: string | undefined;
    let nudges = 0;
    let completionNudges = 0;
    let wrapUpSent = false;
    let emptyTruncated = 0;
    const model = spec.hub.resolve(spec.model);
    let contractShortfall: string | undefined;
    const telemetry: SessionTelemetry = { peakContext: 0, compactions: 0, referenced: [] };
    const tracked = new Set(spec.trackIds ?? []);
    const referenced = new Set<string>();
    const noteReferences = (args: unknown) => {
      if (!tracked.size) return;
      let text: string;
      try { text = JSON.stringify(args) ?? ''; } catch { return; }
      for (const id of tracked) if (text.includes(id)) { referenced.add(id); tracked.delete(id); }
    };
    const emit = (e: SessionEvent) => { try { spec.onEvent?.(e); } catch { /* observers never break sessions */ } };

    const stop = async (s: SessionStatus, cls: ErrorClass | null, msg?: string) => {
      if (status) return;
      status = s;
      errorClass = cls;
      if (msg) errorMessage = msg;
      await session?.abort().catch(() => undefined);
    };

    /** notes of calls pruned before pi's schema check, consumed by the call's execute (per tool, in order). */
    const prunedNotes: Record<string, string[]> = {};
    const toolDefs: ToolDefinition[] = spec.tools.map((t) => defineTool({
      name: t.name, label: t.name, description: t.description, parameters: t.parameters,
      // pi checks the schema before execute; see prepareToolArguments.
      prepareArguments: (raw: unknown) => {
        const r = prepareToolArguments(t, raw, (issue) => emit({ type: 'contract.violation', tool: t.name, issues: [issue], attempt: 0 }));
        if (r.pruneNote) (prunedNotes[t.name] ??= []).push(r.pruneNote);
        return r.args as never;
      },
      async execute(callId, params, signal) {
        const started = Date.now();
        emit({ type: 'tool.called', tool: t.name, args: params, callId });
        egress.call(t.name, params);
        noteReferences(params);
        try {
          let args = t.kind === 'submit' && t.normalize ? t.normalize(params) : params;
          let pruned: string | null = prunedNotes[t.name]?.shift() ?? null;
          if (pruned) emit({ type: 'contract.violation', tool: t.name, issues: [`accepted after dropping the faulty items: ${pruned}`.slice(0, 2000)], attempt: 0 });
          if (t.kind === 'submit') {
            const issuesOf = (a: unknown) => {
              const schema = check(t.parameters, a);
              return schema.ok ? (t.validate?.(a) ?? []) : schema.issues.map((i) => `${i.path} ${i.message}`);
            };
            let issues = issuesOf(args);
            // drop only the faulty items when the tool can, keeping the rest of the call.
            if (issues.length && t.prune) {
              const p = safePrune(t, args, issues);
              const left = p ? issuesOf(p.args) : issues;
              if (p && !left.length) {
                args = p.args;
                pruned = pruned ? `${pruned}\n${p.note}` : p.note;
                issues = [];
                emit({ type: 'contract.violation', tool: t.name, issues: [`accepted after dropping the faulty items: ${p.note}`.slice(0, 2000)], attempt: 0 });
              } else if (p && left.length < issues.length) {
                // still refused, but only what the repair could not settle is listed — the model kept
                // rewriting ids the repair would have resolved while the real problem sat further down the list.
                issues = [...left, p.note];
              }
            }
            if (issues.length) throw new Error(`${P('feedback.session.rejected', { tool: t.name })}\n- ${issues.slice(0, 20).join('\n- ')}`);
            (submissions[t.name] ??= []).push(args);
            // The limit counts consecutive rejections: an accepted call starts the count again.
            violations[t.name] = 0;
          }
          const r = await t.run(args, signal);
          const text = pruned ? `${r.text}\n${pruned}` : r.text;
          emit({ type: 'tool.result', tool: t.name, callId, ok: true, preview: text.slice(0, 2000), ...(r.summary ? { summary: r.summary } : {}), durationMs: Date.now() - started });
          return { content: [{ type: 'text', text }], details: r.details };
        } catch (e) {
          const msg = (e as Error).message;
          emit({ type: 'tool.result', tool: t.name, callId, ok: false, preview: msg.slice(0, 2000), durationMs: Date.now() - started });
          throw e;
        }
      },
    }));

    const allowed = new Set(spec.tools.map((t) => t.name));
    const submitNames = new Set(spec.tools.filter((t) => t.kind === 'submit').map((t) => t.name));
    const loader = new DefaultResourceLoader({
      cwd: spec.cwd, agentDir: spec.agentDir, noSkills: true, noPromptTemplates: true, noThemes: true, noContextFiles: true,
      systemPrompt: spec.systemPrompt,
      // Keep only our inline factories; drop anything discovered on disk (cwd `.pi/`, agentDir).
      extensionsOverride: (base) => ({ ...base, extensions: base.extensions.filter((x) => !x.path || !existsSync(x.path)) }),
      extensionFactories: [(pi) => {
        pi.on('tool_call', (e) => {
          if (!allowed.has(e.toolName)) {
            emit({ type: 'security.blocked', tool: e.toolName, reason: 'tool not in whitelist' });
            return { block: true, reason: P('feedback.session.tool_not_allowed') };
          }
          return undefined;
        });
        // pi awaits `context` handlers before each LLM call; a thrown error would be swallowed, so a stop is signalled
        // by aborting the session (not awaited: the abort waits for the loop, which waits for this handler).
        pi.on('context', async (e) => {
          if (status) return undefined;
          // pi-ai clamps max_tokens to what the window leaves, down to 1: a request that cannot carry a tool call
          // only repeats until the turn limit, each one billing the whole context (compaction, if any, has run already).
          const tooLarge = contextTooLarge(model, outputRoom(model, e.messages));
          if (tooLarge) {
            void stop('error', 'CONTEXT_OVERFLOW', tooLarge);
            return undefined;
          }
          if (!spec.beforeRequest) return undefined;
          const r = await spec.beforeRequest();
          if (r === 'pause') void stop('aborted', 'CANCELLED', 'paused by the user');
          else if (r === 'budget') void stop('budget_stopped', 'BUDGET_EXHAUSTED', 'stage quota used up');
          return undefined;
        });
        pi.on('turn_end', () => {
          turns++;
          if (turns >= spec.maxTurns) {
            // The contract is met: the session ends as completed instead of failing the step.
            if (spec.requiredSubmits.every((n) => submissions[n]?.length)) void stop('completed', null);
            else void stop('max_turns', 'STEP_TIMEOUT', `exceeded ${spec.maxTurns} turns`);
          } else if (turns === spec.maxTurns - wrapUpTurns(spec.maxTurns)) {
            // Turn limit ahead and a required result still missing: wind down like the budget wrap-up does,
            // instead of being cut off while still exploring.
            const missing = spec.requiredSubmits.filter((n) => !submissions[n]?.length);
            if (missing.length) void session?.steer(P('nudge.session.turn_limit', { left: spec.maxTurns - turns, tools: missing.join('、') })).catch(() => undefined);
          }
          return undefined;
        });
        pi.on('agent_before_settle', () => {
          if (status) return undefined;
          // A provider error ended the turn: asking again only repeats it and hides the error class.
          if ((lastAssistant as { stopReason?: string } | null)?.stopReason === 'error') return undefined;
          const missing = spec.requiredSubmits.filter((n) => !submissions[n]?.length);
          if (missing.length === 0) {
            if (!spec.completionCheck || completionNudges >= MAX_COMPLETION_NUDGES) return undefined;
            const text = spec.completionCheck();
            if (!text) return undefined;
            completionNudges++;
            return { continue: true, entries: [{ type: 'custom_message', customType: 'output_contract', display: false, content: text }] };
          }
          if (nudges >= MAX_SETTLE_NUDGES) return undefined;
          nudges++;
          return {
            continue: true,
            entries: [{
              type: 'custom_message', customType: 'output_contract', display: false,
              content: P('nudge.session.required_submit', { tools: missing.join('、') }),
            }],
          };
        });
      }],
    });
    await loader.reload();

    let resumed: ResumeInfo | null = null;
    let sessionManager: SessionManager;
    if (spec.transcript) ({ sm: sessionManager, resumed } = openTranscript(spec.cwd, spec.transcript));
    else sessionManager = SessionManager.inMemory(spec.cwd);
    const settingsManager = SettingsManager.inMemory({
      compaction: { enabled: true },
      retry: { enabled: true, maxRetries: 2 },
    } as never);
    const created = await createAgentSession({
      cwd: spec.cwd, agentDir: spec.agentDir, model, thinkingLevel: (spec.model.thinking ?? 'off') as never,
      modelRuntime: spec.hub.runtime, resourceLoader: loader, tools: [...allowed], customTools: toolDefs,
      sessionManager, settingsManager,
    });
    session = created.session;
    if (resumed) {
      // what the saved part of the conversation already did counts — accepted submissions above all.
      // The transcript keeps the arguments as the model sent them; an accepted call may have been repaired or pruned
      // first, so a restored submission goes through the same preparation and must pass the schema (a raw
      // profile without `trustBoundaries` came back after a budget pause and crashed every later session).
      const byName = new Map(spec.tools.map((t) => [t.name, t]));
      const r = restoredState(sessionManager, submitNames, (name, raw) => {
        const t = byName.get(name);
        if (!t) return null;
        const a = prepareToolArguments(t, raw).args;
        return check(t.parameters, a).ok ? a : null;
      });
      Object.assign(submissions, r.submissions);
      turns = r.turns;
      Object.assign(usage, { input: r.usage.input, output: r.usage.output, cacheRead: r.usage.cacheRead, cacheWrite: r.usage.cacheWrite, total: r.usage.totalTokens || r.usage.input + r.usage.output });
      emit({ type: 'session.resumed', messages: resumed.messages, repaired: resumed.repaired });
    }
    for (const s of pendingSteers.splice(0)) await session.steer(s).catch(() => undefined);
    emit({ type: 'session.started', model: `${spec.model.provider}/${spec.model.model}` });

    let lastAssistant: { stopReason?: string; errorMessage?: string; text: string } | null = null;
    const unsubscribe = session.subscribe((ev) => {
      if (ev.type === 'message_update') {
        const ame = (ev as { assistantMessageEvent?: { type: string; delta?: string } }).assistantMessageEvent;
        if (ame?.type === 'text_delta' && ame.delta) emit({ type: 'text.delta', text: ame.delta });
        return;
      }
      if (ev.type === 'tool_execution_end') {
        // Every rejected submit (pi schema validation or our semantic validation) is one contract
        // violation; more than MAX_CONTRACT_CORRECTIONS corrections in a row fails closed. An accepted
        // submit starts the count again: a session may submit in parts, and one part that needs
        // corrections must not throw away the parts already accepted.
        const te = ev as { toolName: string; isError: boolean; result?: { content?: { type: string; text?: string }[] } };
        egress.result((te.result?.content ?? []).map((c) => c.text ?? '').join('\n'));
        if (!submitNames.has(te.toolName)) return;
        if (!te.isError) {
          violations[te.toolName] = 0;
          return;
        }
        // Parallel calls of one tool in the same reply fail together (e.g. a reply cut at the output limit drops all of
        // them): they are one correction, or a single reply would use up every retry before any feedback is read.
        if (!struckThisReply.has(te.toolName)) {
          struckThisReply.add(te.toolName);
          violations[te.toolName] = (violations[te.toolName] ?? 0) + 1;
        }
        const issues = (te.result?.content ?? []).map((c) => c.text ?? '').join('\n').split('\n').filter(Boolean).slice(0, 20);
        emit({ type: 'contract.violation', tool: te.toolName, issues, attempt: violations[te.toolName]! });
        if (violations[te.toolName]! > MAX_CONTRACT_CORRECTIONS) {
          const msg = `${te.toolName} rejected ${violations[te.toolName]} times: ${issues.slice(0, 3).join('; ')}`;
          // Results already accepted are not thrown away with the failed call.
          if (spec.requiredSubmits.every((n) => submissions[n]?.length)) {
            contractShortfall = msg;
            void stop('completed', null);
          } else {
            void stop('contract_failed', 'OUTPUT_CONTRACT', msg);
          }
        }
        return;
      }
      if (ev.type === 'compaction_start') {
        telemetry.compactions++;
        emit({ type: 'session.compacted', reason: String((ev as { reason?: unknown }).reason ?? 'unknown') });
        return;
      }
      if (ev.type !== 'message_end') return;
      const msg = ev.message as { role?: string; usage?: { input: number; output: number; cacheRead: number; cacheWrite: number; totalTokens: number; cost?: { total: number } }; stopReason?: string; errorMessage?: string; content?: { type: string; text?: string }[] };
      if (msg.role !== 'assistant') return;
      struckThisReply.clear();
      const u = msg.usage;
      const delta: UsageDelta = u
        ? { input: u.input, output: u.output, cacheRead: u.cacheRead, cacheWrite: u.cacheWrite, total: u.totalTokens || u.input + u.output, cost: u.cost?.total ?? 0 }
        : zeroUsage();
      for (const k of Object.keys(usage) as (keyof UsageDelta)[]) usage[k] += delta[k];
      telemetry.peakContext = Math.max(telemetry.peakContext, delta.input + delta.cacheRead + delta.cacheWrite);
      lastAssistant = {
        ...(msg.stopReason ? { stopReason: msg.stopReason } : {}),
        ...(msg.errorMessage ? { errorMessage: msg.errorMessage } : {}),
        text: (msg.content ?? []).filter((c) => c.type === 'text').map((c) => c.text ?? '').join('\n'),
      };
      emit({ type: 'session.turn', turn: turns + 1, usage: delta, ...(lastAssistant.text ? { text: lastAssistant.text } : {}) });
      // A reply cut at the output limit drops its tool calls; pi only says “re-issue”, and models re-send the same
      // oversized call (seen with claude-haiku-5-5 at the default 8192 output tokens).
      if (msg.stopReason === 'length') void session?.steer(P('nudge.session.output_truncated')).catch(() => undefined);
      emptyTruncated = msg.stopReason === 'length' && delta.output <= EMPTY_REPLY_TOKENS ? emptyTruncated + 1 : 0;
      if (emptyTruncated >= MAX_EMPTY_TRUNCATED_REPLIES) {
        void stop('error', 'CONTEXT_OVERFLOW', `context too large: ${emptyTruncated} replies in a row were cut at the output limit with ${delta.output} output tokens (context ${delta.input + delta.cacheRead + delta.cacheWrite} tokens)`);
      }
      const verdict = spec.onUsage?.(delta) ?? 'continue';
      if (verdict === 'abort') void stop('budget_stopped', 'BUDGET_EXHAUSTED');
      else if (verdict === 'wrap_up' && !wrapUpSent) {
        wrapUpSent = true;
        void session?.steer(spec.wrapUpMessage ?? P('nudge.session.budget_wrap_up')).catch(() => undefined);
      }
    });

    const onAbort = () => void stop('aborted', 'CANCELLED');
    if (spec.signal?.aborted) onAbort();
    spec.signal?.addEventListener('abort', onAbort, { once: true });
    try {
      if (!status) await session.prompt(resumed ? (spec.resumePrompt ?? resumePrompt()) : spec.prompt);
    } catch (e) {
      if (!status) { status = 'error'; errorMessage = (e as Error).message; errorClass = classifyProviderError(errorMessage, (lastAssistant as { text?: string } | null)?.text); }
    } finally {
      spec.signal?.removeEventListener('abort', onAbort);
      unsubscribe();
    }
    const last = lastAssistant as { stopReason?: string; errorMessage?: string; text: string } | null;
    if (!status) {
      if (last?.stopReason === 'error') {
        status = 'error';
        errorMessage = last.errorMessage ?? 'provider error';
        errorClass = classifyProviderError(errorMessage, last.text);
        // The filter's own words tell the user why.
        if (errorClass === 'CONTENT_FILTERED' && last.text) errorMessage = `${last.text.slice(0, 400)}（${errorMessage}）`;
      } else if (spec.requiredSubmits.some((n) => !submissions[n]?.length)) {
        status = 'contract_failed';
        errorClass = 'OUTPUT_CONTRACT';
        errorMessage = `required submit missing: ${spec.requiredSubmits.filter((n) => !submissions[n]?.length).join(', ')}`;
      } else {
        status = 'completed';
      }
    }
    session.dispose();
    const final = status as SessionStatus;
    telemetry.referenced = [...referenced];
    emit({ type: 'session.ended', status: final, turns, telemetry });
    egress.finish({ provider: spec.model.provider, model: spec.model.model, status: final, turns, tokens: { input: usage.input, output: usage.output, cached: usage.cacheRead } });
    return { status: final, errorClass, ...(errorMessage ? { errorMessage } : {}), turns, usage, submissions, finalText: last?.text ?? '', ...(contractShortfall ? { contractShortfall } : {}), telemetry };
  })();

  return {
    outcome,
    async steer(text: string) {
      if (session) await session.steer(text).catch(() => undefined);
      else pendingSteers.push(text);
    },
  };
}

export function runSession(spec: SessionSpec): Promise<SessionOutcome> {
  return startSession(spec).outcome;
}
