// AI report: at export time the report-stage model writes the whole report from the audit's
// structured results, following the chosen report skill; the program checks it against the recorded conclusions,
// sends the differences back for one repair round, and — if they persist — delivers it with the differences on top
// and a program-generated fact list at the end. Runs in the background; the export row shows the phase.
import { Type } from 'typebox';
import { AppError, newId, redact, stageFallback, stageModel, upgradeStrategy, type ErrorClass, type ModelRef } from '@xiezhi/contracts';
import { boundaryDeclaration, newNonce, startSession, wrapUntrusted, type AuditTool, type ModelHub } from '@xiezhi/agent';
import { aiReportHtml, aiReportInput, aiReportRules, annotateAiReport, buildReportModel, reportFacts, verifyAiReport, type ReportFilter } from '@xiezhi/report';
import type { Store } from '@xiezhi/store';
import { getAudit } from './state.js';
import { P } from '@xiezhi/knowledge';
import { withLivePrompts } from './prompts.js';

export interface AiReportRequest {
  auditId: string;
  format: 'md' | 'html';
  model: ModelRef;
  fallback: ModelRef | null;
  /** The report skill's text (its body and `template.md`); null = the built-in writing rules only. */
  instructions: string | null;
  filter: ReportFilter;
  snippets: boolean;
  /** Wall-clock limit of one writing session (default 10 minutes); running out counts as a model failure. */
  timeoutMs?: number;
}
export interface AiReportVerification { ok: boolean; rounds: number; issues: string[]; firstIssues: string[]; fallbackFrom: string | null }

const MODEL_ERRORS: ErrorClass[] = ['MODEL_NOT_FOUND', 'AUTH_INVALID', 'RATE_LIMITED', 'PROVIDER_TRANSIENT', 'STEP_TIMEOUT'];
export const AI_REPORT_TIMEOUT_MS = 10 * 60_000;
const key = (m: ModelRef) => `${m.provider}/${m.model}`;
const SubmitReport = Type.Object({ markdown: Type.String({ minLength: 1, maxLength: 400_000 }) }, { additionalProperties: false });

/**
 * The model an AI report of this audit uses by default: the frozen strategy's report stage, else the hunt
 * model; `fallback` is the stage's own or the global one — not yet compared with the model, which the export may change
 * (see `aiReportFallback`).
 */
export function aiReportModel(store: Store, auditId: string): { model: ModelRef; source: 'report_stage' | 'hunt'; fallback: ModelRef | null } {
  const a = getAudit(store, auditId);
  const s = upgradeStrategy(JSON.parse(a.strategy_frozen ?? a.strategy_draft));
  const model = stageModel(s, 'report')!;
  return { model, source: s.models.report ? 'report_stage' : 'hunt', fallback: s.modelFallbacks?.report ?? store.config.fallbackModel ?? null };
}

/** The fallback of an AI report written by `model`: never the model itself. */
export function aiReportFallback(store: Store, auditId: string, model: ModelRef): ModelRef | null {
  const a = getAudit(store, auditId);
  return stageFallback(upgradeStrategy(JSON.parse(a.strategy_frozen ?? a.strategy_draft)), 'report', store.config.fallbackModel ?? null, model);
}

/** Rough token use: the data and rules in, about 400 tokens per conclusion out; a repair round can double it. */
export function estimateAiReport(store: Store, auditId: string, filter: ReportFilter, snippets: boolean): { tokens: number; conclusions: number } {
  const m = buildReportModel(store, auditId, undefined, filter);
  const input = aiReportInput(store, m, { snippets });
  const n = m.findings.length + m.insufficient.length;
  return { tokens: Math.round(input.length / 2) + 2000 + 600 + 400 * n, conclusions: n };
}

export function createAiReportJob(store: Store, req: AiReportRequest, options: Record<string, unknown>): string {
  const id = newId('export');
  store.insert('export_job', { id, audit_id: req.auditId, format: req.format, options, status: 'running', mode: 'ai', model: key(req.model), progress: 'generating' });
  return id;
}

async function runAiReportInner(deps: { store: Store; hub: ModelHub }, id: string, req: AiReportRequest, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  let tokens = 0;
  const progress = (p: string) => store.update('export_job', { id }, { progress: p, tokens });
  try {
    const a = getAudit(store, req.auditId);
    const report = buildReportModel(store, req.auditId, undefined, req.filter);
    const facts = reportFacts(report);
    const nonce = newNonce();
    const data = aiReportInput(store, report, { snippets: req.snippets });
    const systemPrompt = [
      P('role.ai_report'),
      boundaryDeclaration(nonce),
    ].join('\n\n');
    const base = [
      aiReportRules(facts),
      '',
      req.instructions
        ? `${P('ai_report.skill_heading')}\n${wrapUntrusted(nonce, 'knowledge', 'report-skill', req.instructions)}`
        : P('ai_report.default_structure'),
      '',
      `审计数据（JSON）：\n${wrapUntrusted(nonce, 'tool_output', 'audit-results', data)}`,
    ].join('\n');

    let model = req.model;
    let fallbackFrom: string | null = null;
    const write = async (prompt: string): Promise<string> => {
      for (;;) {
        // A model that neither answers nor fails would keep the export running forever (real-model acceptance).
        const timeout = AbortSignal.timeout(req.timeoutMs ?? AI_REPORT_TIMEOUT_MS);
        const outcome = await startSession({
          hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent, systemPrompt, prompt,
          tools: [{ name: 'submit_report', kind: 'submit', parameters: SubmitReport, description: P('tool.submit_report'), run: () => ({ text: 'recorded' }) } satisfies AuditTool],
          requiredSubmits: ['submit_report'], maxTurns: 3, signal: AbortSignal.any([signal, timeout]),
          onUsage: (u) => { tokens += u.total; return 'continue'; },
        }).outcome;
        const sub = (outcome.submissions.submit_report as { markdown: string }[] | undefined)?.at(-1);
        if (sub) return sub.markdown;
        if (signal.aborted) throw new Error('已中断');
        const timedOut = timeout.aborted;
        if (timedOut) outcome.errorClass = 'STEP_TIMEOUT';
        // The report stage's fallback, once.
        if (!fallbackFrom && req.fallback && outcome.errorClass && MODEL_ERRORS.includes(outcome.errorClass)) {
          fallbackFrom = key(model);
          model = req.fallback;
          store.update('export_job', { id }, { model: key(model) });
          continue;
        }
        if (timedOut) {
          const sec = Math.round((req.timeoutMs ?? AI_REPORT_TIMEOUT_MS) / 1000);
          throw new Error(`报告模型 ${key(model)} 在 ${sec >= 60 ? `${Math.round(sec / 60)} 分钟` : `${sec} 秒`}内没有写完报告`);
        }
        throw new AppError('COMMON_VALIDATION', `the model did not submit a report (${outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
      }
    };

    let markdown = await write(base);
    progress('verifying');
    const firstIssues = verifyAiReport(markdown, facts);
    let issues = firstIssues;
    let rounds = 1;
    if (issues.length) {
      progress('repairing');
      rounds = 2;
      markdown = await write([
        base, '',
        P('ai_report.repair'), ...issues.map((i) => `- ${i}`), '',
        `上一次的报告：\n${wrapUntrusted(nonce, 'tool_output', 'previous-report', markdown)}`,
      ].join('\n'));
      progress('verifying');
      issues = verifyAiReport(markdown, facts);
    }
    const final = redact(annotateAiReport(markdown, issues, facts), store.redactOptions());
    const text = req.format === 'md' ? final : redact(aiReportHtml(`审计报告 · ${a.title}`, final), store.redactOptions());
    const verification: AiReportVerification = { ok: issues.length === 0, rounds, issues, firstIssues, fallbackFrom };
    store.update('export_job', { id }, {
      status: 'succeeded', progress: null, tokens, model: key(model), verification, bytes: Buffer.byteLength(text),
      artifact_ref: store.artifacts.put(text, req.format === 'md' ? 'text/markdown' : 'text/html'), markdown_ref: store.artifacts.put(final, 'text/markdown'),
    });
  } catch (e) {
    const msg = signal.aborted ? '已中断' : (e as Error).message.slice(0, 500);
    store.update('export_job', { id }, { status: 'failed', progress: null, tokens, error: msg });
  }
}

/** with the prompt overrides of the audit's project. */
export async function runAiReport(deps: { store: Store; hub: ModelHub }, id: string, req: AiReportRequest, signal: AbortSignal): Promise<void> {
  const projectId = deps.store.get<{ project_id: string }>('SELECT project_id FROM audit WHERE id = ?', req.auditId)?.project_id ?? null;
  return withLivePrompts(deps.store, projectId, () => runAiReportInner(deps, id, req, signal), 'ai_report', req.auditId);
}
