// Generation of a requirement threat model: one background Agent session that reads the
// sources on demand (source directory + read_source), fetches online documents through the source's connector
// (read operations only), follows the phase:threat_model knowledge, and submits the clarification and the risks.
// It never sees code. Regeneration keeps what people decided on the risks.
import {
  AppError, configStageModel, newId, SubmitRequirementThreatModel, THREAT_SOURCE_MAX_BYTES,
  type ModelRef, type RequirementThreatRiskDraft,
} from '@xiezhi/contracts';
import { boundaryDeclaration, detectInjection, newNonce, startSession, wrapUntrusted, type AuditTool, type ConnectorAccess, type ConnectorOperation, type ModelHub } from '@xiezhi/agent';
import type { ConnectorPool } from '@xiezhi/connectors';
import { effectiveSkills, freezeSkills, loadFrozenSkill, scanLayer, sessionKnowledge } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';
import { join } from 'node:path';
import { Type } from 'typebox';
import { buildConnectorAccess } from './connector-access.js';
import { costMicros } from './estimates.js';
import { modelDefaults } from './services.js';
import { renderThreatModelReport } from './threat-model-report.js';
import { getThreatModelRow, listSourceRows, type ThreatRiskRow, type ThreatSourceRow } from './threat-models.js';
import { P } from '@xiezhi/knowledge';
import { withLivePrompts } from './prompts.js';

export const THREAT_MODEL_TOKEN_LIMIT = 400_000;
const PAGE_CHARS = 24_000;
/** Tools of an online source's connector that look like writes are not offered, whatever their hints say. */
const WRITE_NAME = /(create|update|delete|remove|import|insert|patch|batch|move|copy|transfer|send|post|write|upload|set_|add_|share|permission)/i;

export interface GenerateOptions { model?: ModelRef; tokenLimit?: number }

/** The model of a generation: the request's, else the 风险假设 (logic) stage of the settings, else the default model. */
export function threatModelModel(store: Store, requested?: ModelRef): ModelRef {
  if (requested) return requested;
  return configStageModel(store.config, 'logic') ?? modelDefaults(store.config).defaultModel;
}

/**
 * Checks before a generation starts, then marks the threat model `generating` (refused while one runs). Sources with
 * injection signals must have been acknowledged by a person.
 */
export function beginGeneration(store: Store, id: string, opts: GenerateOptions): { model: ModelRef; tokenLimit: number } {
  const model = threatModelModel(store, opts.model);
  const tokenLimit = opts.tokenLimit ?? THREAT_MODEL_TOKEN_LIMIT;
  if (!Number.isInteger(tokenLimit) || tokenLimit < 10_000 || tokenLimit > 5_000_000) throw new AppError('COMMON_VALIDATION', 'tokenLimit must be between 10000 and 5000000');
  store.tx(() => {
    const tm = getThreatModelRow(store, id);
    if (tm.status === 'generating') throw new AppError('THREAT_MODEL_BUSY', id);
    const sources = listSourceRows(store, id);
    if (!sources.length) throw new AppError('COMMON_VALIDATION', 'add at least one source before generating');
    const unacked = sources.filter((s) => s.injection_ack === 0 && fromJson<unknown[]>(s.injection, []).length > 0 && s.kind !== 'online');
    if (unacked.length) throw new AppError('COMMON_VALIDATION', `sources with suspected injected instructions need a review first: ${unacked.map((s) => `S${s.seq}`).join(', ')}`);
    store.update('threat_model', { id }, { status: 'generating', error: null, model: `${model.provider}/${model.model}` });
  });
  return { model, tokenLimit };
}

interface SourceState { row: ThreatSourceRow; parts: string[]; access: ConnectorAccess | null; ops: ConnectorOperation[] }

function sourceLine(s: SourceState): string {
  const r = s.row;
  const kind = r.kind === 'upload' ? '上传文档' : r.kind === 'text' ? '文字描述' : '在线文档';
  const where = r.kind !== 'online' ? P('threat_model.source_local', { bytes: r.bytes })
    : s.ops.length ? P('threat_model.source_online', { connector: s.ops[0]!.connector, doc: String(r.doc_ref) })
      : r.content_ref ? P('threat_model.source_copy', { date: new Date(r.fetched_at ?? 0).toISOString().slice(0, 10) })
        : P('threat_model.source_unavailable');
  return `- S${r.seq}［${kind}］${r.title.replace(/[\n<>]/g, ' ')}${r.note ? `（备注：${r.note.replace(/[\n<>]/g, ' ')}）` : ''}：${where}`;
}

const normalize = (t: string) => t.toLowerCase().replace(/[\s\p{P}\p{S}]/gu, '');

/**
 * Write a submission (one transaction): the clarification, the risks, and the deterministic report.
 * - A risk with `no` updates that risk; without `no`, an existing risk of the same category and the same statement
 *   (spacing and punctuation ignored) is that risk; otherwise it is new.
 * - People's decisions (status, reason, history) are never changed by generation.
 * - Existing risks not proposed again: pending ones are removed (nobody looked at them), triaged ones stay and are
 *   marked stale.
 */
export function applyThreatModelSubmission(store: Store, id: string, sub: SubmitRequirementThreatModel): { added: number; updated: number; removed: number; stale: number } {
  return store.tx(() => {
    const tm = getThreatModelRow(store, id);
    const existing = store.all<ThreatRiskRow>('SELECT * FROM threat_risk WHERE threat_model_id = ?', id);
    const byNo = new Map(existing.map((r) => [r.no, r]));
    const byText = new Map(existing.map((r) => [`${r.category}\u0000${normalize(r.statement)}`, r]));
    let next = tm.next_risk_no;
    const seen = new Set<number>();
    let added = 0;
    let updated = 0;
    for (const d of sub.risks) {
      const match = (d.no !== undefined ? byNo.get(d.no) : undefined) ?? byText.get(`${d.category}\u0000${normalize(d.statement)}`);
      const content = riskContent(d);
      if (match && !seen.has(match.no)) {
        seen.add(match.no);
        store.update('threat_risk', { id: match.id }, { ...content, stale: 0 });
        updated++;
      } else {
        store.insert('threat_risk', { id: newId('threatRisk'), threat_model_id: id, no: next, ...content });
        seen.add(next);
        next++;
        added++;
      }
    }
    let removed = 0;
    let stale = 0;
    for (const r of existing) {
      if (seen.has(r.no)) continue;
      if (r.status === 'pending') { store.db.run('DELETE FROM threat_risk WHERE id = ?', r.id); removed++; } else { store.update('threat_risk', { id: r.id }, { stale: 1 }); stale++; }
    }
    // A person confirmed the earlier wording; a different clarification is unconfirmed again (audits treat
    // an unconfirmed clarification as unverified).
    const changed = !tm.clarification_ref || store.artifacts.getText(tm.clarification_ref) !== sub.clarification;
    store.update('threat_model', { id }, { clarification_ref: store.artifacts.put(sub.clarification, 'text/markdown'), next_risk_no: next, ...(changed ? { clarified_at: null } : {}) });
    store.update('threat_model', { id }, { report_ref: store.artifacts.put(renderThreatModelReport(store, id), 'text/markdown') });
    return { added, updated, removed, stale };
  });
}

function riskContent(d: RequirementThreatRiskDraft): Record<string, unknown> {
  return {
    category: d.category, level: d.level, statement: d.statement.trim(), impact: d.impact.trim(), mitigation: d.mitigation.trim(),
    features: [...new Set(d.features.map((f) => f.trim()).filter(Boolean))], sources: [...new Set(d.sources)].sort((a, b) => a - b),
  };
}

export interface GenerationDeps { store: Store; hub: ModelHub; pool: ConnectorPool | null }

/** Run a generation started by `beginGeneration`; settles the threat model as ready, partial or failed. */
async function runThreatModelGenerationInner(deps: GenerationDeps, id: string, run: { model: ModelRef; tokenLimit: number }, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const usage = { input: 0, output: 0, cacheRead: 0, total: 0 };
  const sources = new Map<number, SourceState>();
  const issues = new Map<number, string>();
  /** Pages of each source read in this session, and how many it has. */
  const read = new Map<number, { pages: number; seen: Set<number> }>();
  let budgetHit = false;
  try {
    const tm = getThreatModelRow(store, id);
    const nonce = newNonce();
    const artifactsSeen = new Set<string>();
    for (const row of listSourceRows(store, id)) {
      let access: ConnectorAccess | null = null;
      let ops: ConnectorOperation[] = [];
      if (row.kind === 'online' && row.connector_id && deps.pool) {
        access = buildConnectorAccess({ store, pool: deps.pool, refs: [row.connector_id], stepId: `threat-model:${id}`, artifacts: artifactsSeen, source: 'conversation' });
        ops = (access?.operations ?? []).filter((op) => !op.write || !WRITE_NAME.test(op.tool)).map((op) => ({ ...op, write: false }));
      }
      sources.set(row.seq, { row, parts: [], access, ops });
    }

    // Knowledge: global + the project's layer; phase:threat_model bodies are injected.
    const frozen = freezeSkills(effectiveSkills(scanLayer(store.paths.knowledgeGlobal, 'global'), scanLayer(join(store.paths.projects, tm.project_id, 'knowledge'), 'project')), store.artifacts);
    const sk = sessionKnowledge(frozen, { scene: 'full', phase: 'threat_model', languages: [], frameworks: [], vulnClasses: [], repoRoles: [], include: [], exclude: [] }, store.artifacts);

    const pageOf = (text: string, page: number) => {
      const pages = Math.max(1, Math.ceil(text.length / PAGE_CHARS));
      const p = Math.min(pages, Math.max(1, page));
      return { p, pages, slice: text.slice((p - 1) * PAGE_CHARS, p * PAGE_CHARS) };
    };
    const tools: AuditTool[] = [
      {
        name: 'read_source', kind: 'read',
        description: P('tool.read_source'),
        parameters: Type.Object({ source: Type.Integer({ minimum: 1 }), page: Type.Optional(Type.Integer({ minimum: 1 })) }, { additionalProperties: false }),
        run(args: { source: number; page?: number }) {
          const s = sources.get(args.source);
          if (!s) throw new Error(`no source S${args.source}; sources: ${[...sources.keys()].map((n) => `S${n}`).join(', ')}`);
          let text: string | null = null;
          if (s.row.kind !== 'online') text = s.row.content_ref ? store.artifacts.getText(s.row.content_ref) : null;
          else if (s.parts.length) text = s.parts.join('\n\n');
          else if (!s.ops.length && s.row.content_ref) text = store.artifacts.getText(s.row.content_ref);
          if (text === null) throw new Error(s.ops.length ? P('feedback.threat_model.fetch_first', { source: args.source }) : `S${args.source} has no content available`);
          const { p, pages, slice } = pageOf(text, args.page ?? 1);
          const r = read.get(args.source) ?? { pages, seen: new Set<number>() };
          r.pages = pages;
          r.seen.add(p);
          read.set(args.source, r);
          return { text: `source S${args.source} page ${p}/${pages}\n${wrapUntrusted(nonce, 'user_upload', `S${args.source}:${s.row.title}`, slice)}`, summary: { source: args.source, page: p, pages } };
        },
      },
    ];
    if (sk.readable.size) {
      let used = 0;
      tools.push({
        name: 'load_skill', kind: 'read', description: P('tool.load_skill.threat_model'),
        parameters: Type.Object({ name: Type.String(), reason: Type.String({ minLength: 3, maxLength: 500 }), file: Type.Optional(Type.String()), page: Type.Optional(Type.Integer({ minimum: 1 })) }),
        run(args) {
          const r = loadFrozenSkill(frozen, sk.readable, store.artifacts, args);
          if (used + r.tokens > 30_000) throw new Error('knowledge read budget for this session is exhausted');
          used += r.tokens;
          return { text: `skill ${r.name} (${r.file}, page ${r.page}/${r.pages})\n${r.text}`, summary: { skill: r.name } };
        },
      });
    }
    const onlineOps = [...sources.values()].flatMap((s) => s.ops.map((op) => ({ s, op })));
    if (onlineOps.length) {
      tools.push({
        name: 'connector_read', kind: 'read',
        description: P('tool.connector_read'),
        parameters: Type.Object({
          source: Type.Integer({ minimum: 1 }), connector: Type.String(), operation: Type.String(),
          args: Type.Record(Type.String(), Type.Unknown()), reason: Type.String({ minLength: 3, maxLength: 500 }), body: Type.Optional(Type.Boolean()),
        }),
        async run(args: { source: number; connector: string; operation: string; args: Record<string, unknown>; reason: string; body?: boolean }, sig) {
          const s = sources.get(args.source);
          if (!s || s.row.kind !== 'online') throw new Error(`S${args.source} is not an online source`);
          const op = s.ops.find((x) => (x.connector === args.connector || x.connectorId === args.connector) && x.tool === args.operation);
          if (!op) throw new Error(`operation not available for S${args.source}; available: ${s.ops.map((x) => `${x.connector}.${x.tool}`).join(', ')}`);
          if (JSON.stringify(args.args ?? {}).length > 16 * 1024) throw new Error('arguments exceed 16 KB');
          const r = await s.access!.call(op, args.args ?? {}, args.reason, sig);
          const full = r.artifactId ? store.artifacts.getText(r.artifactId) : r.text;
          if (args.body && !r.isError && !r.pending) s.parts.push(full);
          if (r.isError) issues.set(args.source, `连接器报错：${r.text.slice(0, 300)}`);
          const shown = full.length > PAGE_CHARS ? `${full.slice(0, PAGE_CHARS)}\n[truncated: ${full.length} characters${args.body ? '; read the rest with read_source' : ''}]` : full;
          return {
            text: `connector ${op.connector}.${op.tool}${r.isError ? ' (the external system reported an error)' : ''}${args.body && !r.isError ? ` — kept as the text of S${args.source}` : ''}\n${wrapUntrusted(nonce, 'connector', `S${args.source}:${op.connector}/${op.tool}`, shown)}`,
            summary: { source: args.source, operation: op.tool, body: !!args.body },
          };
        },
      });
    }
    const validNos = new Set(store.all<{ no: number }>('SELECT no FROM threat_risk WHERE threat_model_id = ?', id).map((r) => r.no));
    tools.push({
      name: 'submit_threat_model', kind: 'submit', parameters: SubmitRequirementThreatModel,
      description: P('tool.submit_threat_model.requirement'),
      validate(args: SubmitRequirementThreatModel) {
        const out: string[] = [];
        const nos = new Set<number>();
        for (const [i, r] of args.risks.entries()) {
          for (const n of r.sources) if (!sources.has(n)) out.push(P('feedback.threat_model.unknown_source', { i, n }));
          // A number that is not an existing risk is a new risk (models number new risks R15, R16 … after the existing
          // ones); applyThreatModelSubmission gives it the next number. Refusing it failed whole regenerations.
          if (r.no !== undefined && validNos.has(r.no)) {
            if (nos.has(r.no)) out.push(P('feedback.threat_model.duplicate_risk', { i, no: r.no }));
            nos.add(r.no);
          }
        }
        for (const x of args.sourceIssues ?? []) if (!sources.has(x.source)) out.push(P('feedback.threat_model.unknown_issue_source', { source: x.source }));
        return out.slice(0, 20);
      },
      run: () => ({ text: 'recorded' }),
    });

    const previous = store.all<ThreatRiskRow>('SELECT * FROM threat_risk WHERE threat_model_id = ? ORDER BY no', id);
    const opsList = onlineOps.map(({ s, op }) => `- S${s.row.seq}：${op.connector}.${op.tool}${op.description ? ` — ${op.description}` : ''}${op.params ? `（参数：${op.params.slice(0, 300)}）` : ''}`).join('\n');
    const systemPrompt = [
      P('role.threat_model'),
      boundaryDeclaration(nonce),
      sk.bodies.length ? `# 必读知识\n${sk.bodies.map((b) => `## ${b.name}\n${b.text}`).join('\n\n')}` : '',
      sk.indexText ? `${P('threat_model.knowledge_index_heading')}\n${sk.indexText}` : '',
    ].filter(Boolean).join('\n\n');
    const prompt = [
      P('threat_model.task', { title: tm.title.replace(/[\n<>]/g, ' ') }),
      `# 来源目录（${sources.size} 条）\n${[...sources.values()].map(sourceLine).join('\n')}`,
      opsList ? `${P('threat_model.ops_heading')}\n${wrapUntrusted(nonce, 'connector', 'connector-operations', opsList)}` : '',
      previous.length ? `${P('threat_model.previous_heading')}\n${wrapUntrusted(nonce, 'user_upload', 'existing-risks', previous.map((r) => `R${r.no} [${r.category}/${r.level ?? '-'}] ${r.statement}（状态：${r.status}${r.reason ? `，理由：${r.reason}` : ''}）`).join('\n'))}` : '',
    ].filter(Boolean).join('\n\n');

    const maxTurns = Math.min(120, 16 + sources.size * 3);
    const outcome = await startSession({
      hub: deps.hub, model: run.model, cwd: store.paths.tmp, agentDir: store.paths.agent, systemPrompt, prompt, tools,
      requiredSubmits: ['submit_threat_model'], maxTurns, signal,
      onUsage: (u) => {
        usage.input += u.input; usage.output += u.output; usage.cacheRead += u.cacheRead; usage.total += u.total;
        if (usage.total >= run.tokenLimit) { budgetHit = true; return 'abort'; }
        return usage.total >= run.tokenLimit * 0.85 ? 'wrap_up' : 'continue';
      },
    }).outcome;

    const sub = (outcome.submissions.submit_threat_model as SubmitRequirementThreatModel[] | undefined)?.at(-1);
    // A local source read to its last page is not incomplete: what the model reported is about its content (seen with
    // claude-haiku-5-5: conflicts between requirements reported as source problems marked the result partial).
    const readInFull = (n: number) => sources.get(n)?.row.kind !== 'online' && (read.get(n)?.seen.size ?? 0) >= (read.get(n)?.pages ?? Infinity);
    for (const x of sub?.sourceIssues ?? []) if (!readInFull(x.source)) issues.set(x.source, x.problem);
    const failedSources = saveOnlineCopies(store, sources, issues);
    const cost = costMicros(store.config.pricing[`${run.model.provider}/${run.model.model}`], usage);
    if (!sub) {
      const why = budgetHit ? `达到 token 上限（${run.tokenLimit}）前没有提交结果` : signal.aborted ? '生成被中断' : `模型没有提交结果（${outcome.status}${outcome.errorMessage ? `：${outcome.errorMessage.slice(0, 200)}` : ''}）`;
      store.update('threat_model', { id }, { status: 'failed', error: why, tokens_in: usage.input, tokens_out: usage.output, cost_micros: cost });
      return;
    }
    applyThreatModelSubmission(store, id, sub);
    const partial = budgetHit || outcome.status !== 'completed' || failedSources.length > 0 || issues.size > 0;
    const note = [
      budgetHit ? `达到 token 上限（${run.tokenLimit}），结果可能不完整` : '',
      [...issues].map(([n, p]) => `S${n}：${p}`).join('；'),
    ].filter(Boolean).join('；');
    store.update('threat_model', { id }, {
      status: partial ? 'partial' : 'ready', error: note || null, generated_at: Date.now(), tokens_in: usage.input, tokens_out: usage.output, cost_micros: cost,
    });
  } catch (e) {
    saveOnlineCopies(store, sources, issues);
    store.update('threat_model', { id }, { status: 'failed', error: (e as Error).message.slice(0, 500), tokens_in: usage.input, tokens_out: usage.output });
  }
}

/** Keep the fetched text of each online source (or why it could not be read); returns the S-numbers that failed. */
function saveOnlineCopies(store: Store, sources: Map<number, SourceState>, issues: Map<number, string>): number[] {
  const failed: number[] = [];
  for (const s of sources.values()) {
    if (s.row.kind !== 'online') continue;
    if (s.parts.length) {
      let text = s.parts.join('\n\n');
      if (Buffer.byteLength(text) > THREAT_SOURCE_MAX_BYTES) {
        text = Buffer.from(text).subarray(0, THREAT_SOURCE_MAX_BYTES).toString('utf8');
        issues.set(s.row.seq, issues.get(s.row.seq) ?? `正文超过 ${THREAT_SOURCE_MAX_BYTES} 字节，副本已截断`);
      }
      const ref = store.artifacts.put(text, 'text/markdown');
      store.update('threat_model_source', { id: s.row.id }, {
        content_ref: ref, content_hash: ref, bytes: Buffer.byteLength(text), fetch_status: 'ok', fetch_error: null, fetched_at: Date.now(), injection: detectInjection(text),
      });
    } else if (!s.ops.length && s.row.content_ref) {
      // Connector unavailable: the earlier copy was offered; keep it and say so.
      issues.set(s.row.seq, issues.get(s.row.seq) ?? '连接器不可用，使用了上次取回的副本');
    } else {
      failed.push(s.row.seq);
      const why = issues.get(s.row.seq) ?? (s.ops.length ? '生成会话没有取回该文档' : '连接器不可用（未启用、未通过测试，或没有可用的读取操作）');
      issues.set(s.row.seq, why);
      store.update('threat_model_source', { id: s.row.id }, { fetch_status: 'failed', fetch_error: why.slice(0, 500) });
    }
  }
  return failed;
}

/** with the prompt overrides of the threat model's project. */
export async function runThreatModelGeneration(deps: GenerationDeps, id: string, run: { model: ModelRef; tokenLimit: number }, signal: AbortSignal): Promise<void> {
  const projectId = deps.store.get<{ project_id: string }>('SELECT project_id FROM threat_model WHERE id = ?', id)?.project_id ?? null;
  return withLivePrompts(deps.store, projectId, () => runThreatModelGenerationInner(deps, id, run, signal), 'threat_model', id);
}
