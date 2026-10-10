// Pushing vulnerabilities to external systems.
// A push-guidance skill names a connector write operation. Its arguments come from a placeholder
// template when the skill has one (deterministic), otherwise the chat model fills them following the
// guidance. Pushes are started by the user; by default they execute at once, but a preview must be
// confirmed when the skill says so or when the payload carries suspected injected instructions.
// `sync_record` keeps pushes idempotent: unchanged content is skipped, pushed vulnerabilities use the
// skill's update operation (or are skipped).
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AppError, canonicalJson, newId, sha256Hex, type ModelRef } from '@xiezhi/contracts';
import { Type } from 'typebox';
import { parse as parseYaml } from 'yaml';
import { boundaryDeclaration, detectInjection, newNonce, startSession, wrapUntrusted, type AuditTool, type ModelHub } from '@xiezhi/agent';
import { checkArgs, extract, loadPack, type ConnectorPool, type McpToolInfo } from '@xiezhi/connectors';
import { effectiveSkills, scanLayer, type PushTarget, type Skill } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';
import { connectorSpec, connectorStatus, isMcp, logConnectorCall, type ConnectorRow, type ConnectorTool } from './connectors.js';
import { buildConnectorAccess, connectorPrompt } from './connector-access.js';
import { chatModelOf, getProject } from './services.js';
import { P } from '@xiezhi/knowledge';
import { withLivePrompts } from './prompts.js';

export const PUSH_TOKEN_TTL_MS = 5 * 60_000;
const SEVERITY_LABEL: Record<string, string> = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };

export interface PushItem {
  vulnId: string; displayNo: number; title: string;
  action: 'create' | 'update' | 'skip';
  operation: string | null;
  args: Record<string, unknown>;
  hash: string;
  skipReason: string | null;
  /** Why this item needs a confirmed preview (suspected injection …). */
  reasons: string[];
  existing: { externalId: string; externalUrl: string | null } | null;
  result?: { ok: boolean; externalId: string | null; externalUrl: string | null; error: string | null };
  /** operations run in order (one for create / a single update; several when the guide lists update_operations). */
  steps: { operation: string; args: Record<string, unknown>; ok: boolean | null; error: string | null }[];
}

export interface PushPlan {
  id: string; projectId: string; skill: string; connectorId: string; connectorName: string;
  status: 'awaiting_confirm' | 'done' | 'expired';
  confirmRequired: boolean; confirmReasons: string[];
  payloadHash: string; token: string | null; expiresAt: number; createdAt: number; tokens: number;
  items: PushItem[];
}

/** Guides of the project for one kind of target; vulnerability pushes see only vulnerability guides. */
export function pushGuides(store: Store, projectId: string, target: PushTarget = 'vulnerability'): Skill[] {
  getProject(store, projectId);
  return effectiveSkills(scanLayer(store.paths.knowledgeGlobal, 'global'), scanLayer(join(store.paths.projects, projectId, 'knowledge'), 'project'))
    .filter((s) => s.category === 'push_guide' && s.push && s.push.target === target);
}

/** Guides with whether their connector can take the write now (for the push dialog). */
export function pushGuideList(store: Store, projectId: string, target: PushTarget = 'vulnerability'): { name: string; description: string; layer: string; connector: string; operation: string; updateOperation: string | null; confirm: boolean; template: boolean; connectorId: string | null; available: boolean; reason: string | null }[] {
  return pushGuides(store, projectId, target).map((s) => {
    const p = s.push!;
    let connectorId: string | null = null;
    let reason: string | null = null;
    try {
      connectorId = writableConnector(store, p.connector, p.operation).row.id;
      for (const op of updateOps(p)) writableConnector(store, p.connector, op);
    } catch (e) {
      reason = e instanceof AppError ? e.hint ?? e.message : (e as Error).message;
      connectorId ??= store.get<{ id: string }>('SELECT id FROM connector WHERE name = ? OR id = ?', p.connector, p.connector)?.id ?? null;
    }
    return {
      name: s.name, description: s.description, layer: s.layer, connector: p.connector, operation: p.operation, updateOperation: updateOps(p).join(' / ') || null,
      confirm: !!p.confirm, template: templateOf(s, 'template.yaml') !== null, connectorId, available: !reason, reason,
    };
  });
}

/** Follow-up operations of a guide: the list or the single legacy one. */
function updateOps(p: NonNullable<Skill['push']>): string[] {
  return p.updateOperations?.length ? p.updateOperations : p.updateOperation ? [p.updateOperation] : [];
}

function guide(store: Store, projectId: string, name: string, target: PushTarget = 'vulnerability'): Skill {
  const s = pushGuides(store, projectId, target).find((x) => x.name === name);
  if (!s) throw new AppError('COMMON_NOT_FOUND', `push guide ${name}`);
  return s;
}

function writableConnector(store: Store, name: string, operation: string): { row: ConnectorRow; tool: ConnectorTool | null } {
  const row = store.get<ConnectorRow>('SELECT * FROM connector WHERE name = ? OR id = ?', name, name);
  if (!row) throw new AppError('COMMON_VALIDATION', `connector ${name} does not exist`);
  if (!row.enabled || connectorStatus(row, store.paths.connectorPacks) !== 'ready') throw new AppError('COMMON_VALIDATION', `connector ${row.name} is not ready`);
  const tool = fromJson<ConnectorTool[]>(row.tools, []).find((t) => t.name === operation) ?? null;
  if (!tool) throw new AppError('COMMON_VALIDATION', `operation ${operation} is not offered by ${row.name}; run the connectivity test`);
  // Connector packs declare read / write per operation; for MCP the guide decides which tools push uses.
  if (tool.readOnlyHint === true && !isMcp(row)) throw new AppError('COMMON_VALIDATION', `operation ${operation} is read-only, not a write operation`);
  return { row, tool };
}

// ---- vulnerability fields ----------------------------------------------------------------------------------

/** Deterministic fields a template can use (`{{name}}`); also the model's input. */
export function vulnFields(store: Store, vulnId: string): Record<string, string | string[]> {
  const v = store.get<Record<string, any>>('SELECT v.*, p.name AS project_name, r.name AS repo_name FROM vulnerability v JOIN project p ON p.id = v.project_id LEFT JOIN repository r ON r.id = v.repository_id WHERE v.id = ?', vulnId);
  if (!v) throw new AppError('VULN_NOT_FOUND');
  const d = store.artifacts.getJson<{ evidence?: { repo?: string; path: string; startLine: number }[]; chain?: { repo?: string; path: string; startLine: number; note?: string }[]; reasoning?: string; exploitConditions?: { condition: string; status: string }[]; remediation?: { approach?: string; suggestion?: string } }>(v.detail_ref);
  const entries = store.all<{ entry_key: string }>('SELECT entry_key FROM vuln_entry WHERE vulnerability_id = ? ORDER BY entry_key', vulnId).map((e) => e.entry_key);
  const fp = store.get<{ fp: string }>(`SELECT fp FROM vuln_fingerprint WHERE vulnerability_id = ? AND active = 1 ORDER BY created_at LIMIT 1`, vulnId)?.fp ?? '';
  const loc = (x: { repo?: string; path: string; startLine: number }) => `${x.repo ?? v.repo_name}:${x.path}:${x.startLine}`;
  const cut = (t: string | undefined, n: number) => (t ?? '').replace(/\s+/g, ' ').trim().slice(0, n);
  const location = d.evidence?.[0] ? loc(d.evidence[0]) : '';
  const description = [
    `【证据】${(d.evidence ?? []).slice(0, 5).map(loc).join('；') || location}`,
    `【推理与链路】${cut(d.reasoning, 1200)}${d.chain?.length ? `（链路：${d.chain.slice(0, 8).map(loc).join(' → ')}）` : ''}`,
    `【利用条件】${(d.exploitConditions ?? []).map((e) => `${e.condition}（${e.status}）`).join('；') || '—'}`,
    `【修复建议】${cut(d.remediation?.approach, 800)}${d.remediation?.suggestion ? ` ${cut(d.remediation.suggestion, 800)}` : ''}（由 AI 生成，需人工确认）`,
  ].join('\n');
  return {
    display_no: `V-${v.display_no}`, title: v.title, severity: v.severity, severity_label: SEVERITY_LABEL[v.severity] ?? v.severity, category: v.category, cwe: v.cwe ?? '', project: v.project_name, repo: v.repo_name ?? '',
    location, entries: entries.join(', '), entries_list: entries, root_cause: v.root_cause ?? '', remediation: cut(d.remediation?.approach, 1000),
    confirm_status: v.confirm_status, fingerprint: fp, description,
    // what a follow-up push reacts to (fixed → resolved, false positive / accepted risk → closed, regressed → reopened).
    handling_status: v.handling_status ?? '', handling_reason: v.handling_reason ?? '', lifecycle: v.lifecycle ?? '',
  };
}

/** `{{name}}` template: a string that is exactly one placeholder takes the (possibly array) value. */
export function fillPushTemplate(t: unknown, f: Record<string, string | string[]>): unknown {
  if (typeof t === 'string') {
    const whole = /^\{\{\s*([a-z_]+)\s*\}\}$/.exec(t);
    if (whole) return f[whole[1]!] ?? '';
    return t.replace(/\{\{\s*([a-z_]+)\s*\}\}/g, (_, k: string) => { const v = f[k]; return Array.isArray(v) ? v.join(', ') : v ?? ''; });
  }
  if (Array.isArray(t)) return t.map((x) => fillPushTemplate(x, f));
  if (t && typeof t === 'object') return Object.fromEntries(Object.entries(t).map(([k, v]) => [k, fillPushTemplate(v, f)]));
  return t;
}

function templateOf(s: Skill, file: string): unknown | null {
  if (!s.dir) return null;
  const p = join(s.dir, file);
  if (!existsSync(p)) return null;
  try { return parseYaml(readFileSync(p, 'utf8'), { maxAliasCount: 0 }) as unknown; } catch (e) { throw new AppError('COMMON_VALIDATION', `${s.name}/${file}: ${(e as Error).message}`, { cause: e }); }
}

// ---- planning ----------------------------------------------------------------------------------------------

async function operationSchema(store: Store, pool: ConnectorPool, row: ConnectorRow, operation: string): Promise<McpToolInfo | null> {
  try { return (await pool.tools(connectorSpec(row, store.paths.connectorPacks))).find((t) => t.name === operation) ?? null; } catch { return null; }
}

/** Pack operations are checked with the pack's parameter rules; MCP tools only need an object. */
function checkPackArgs(store: Store, row: ConnectorRow, operation: string, args: Record<string, unknown>): string[] {
  const spec = connectorSpec(row, store.paths.connectorPacks);
  if (!spec.pack) return [];
  try {
    const op = loadPack(spec.pack.dir, spec.pack.name).operations.find((o) => o.name === operation);
    if (!op) return [`unknown operation ${operation}`];
    checkArgs(op, args);
    return [];
  } catch (e) {
    return (e as { errors?: string[] }).errors ?? [(e as Error).message];
  }
}

/**
 * The chat model fills the operation arguments following the guide. It may first look things up
 * through the same connector (any of its tools except the guide's own write operations — those are what the push runs);
 * on a re-push with several follow-up operations it chooses which to run, in order.
 */
async function aiSteps(
  deps: { store: Store; hub: ModelHub; pool: ConnectorPool }, s: Skill, row: ConnectorRow, ops: string[], fields: Record<string, string | string[]>, mode: 'create' | 'update',
  existing: string | null, fixed: Record<string, unknown>, usage: { total: number }, subject: PushSubject = VULN_SUBJECT(),
): Promise<{ operation: string; args: Record<string, unknown> }[]> {
  const { store } = deps;
  let model: ModelRef;
  try { model = chatModelOf(store.config); } catch { throw new AppError('MODEL_NOT_CONFIGURED', 'push guide without a template needs a chat or default model'); }
  const nonce = newNonce();
  const schemas = await Promise.all(ops.map(async (op) => ({ op, schema: await operationSchema(store, deps.pool, row, op) })));
  const several = ops.length > 1;
  const stepSchema = Type.Object({ operation: Type.String(), args: Type.Record(Type.String(), Type.Unknown()) }, { additionalProperties: false });
  const submit: AuditTool = {
    name: 'submit_push_args', kind: 'submit',
    parameters: several
      ? Type.Object({ steps: Type.Array(stepSchema, { minItems: 1, maxItems: ops.length }) }, { additionalProperties: false })
      : Type.Object({ args: Type.Record(Type.String(), Type.Unknown()) }, { additionalProperties: false }),
    description: several ? P('tool.submit_push_args.steps') : P('tool.submit_push_args'),
    run: () => ({ text: 'recorded' }),
    validate: (a: { args?: Record<string, unknown>; steps?: { operation: string; args: Record<string, unknown> }[] }) => {
      const steps = a.steps ?? [{ operation: ops[0]!, args: a.args ?? {} }];
      return steps.flatMap((st) => (ops.includes(st.operation) ? checkPackArgs(store, row, st.operation, withFixed(st.args, fixed)) : [P('feedback.push.unknown_operation', { operation: st.operation, operations: ops.join(', ') })]));
    },
  };
  // Look-ups through the connector; never the guide's own write operations.
  const writes = new Set([s.push!.operation, ...updateOps(s.push!)]);
  const access = buildConnectorAccess({ store, pool: deps.pool, refs: [row.id], stepId: `push:${s.name}`, artifacts: new Set(), source: 'push' });
  const lookups = access ? { ...access, operations: access.operations.filter((o) => !writes.has(o.tool)) } : null;
  const tools: AuditTool[] = [submit];
  if (lookups?.operations.length) {
    tools.push({
      name: 'connector_query', kind: 'read',
      description: P('tool.connector_query.push', { connector: row.name }),
      parameters: Type.Object({ operation: Type.String(), args: Type.Record(Type.String(), Type.Unknown()), reason: Type.String({ minLength: 3, maxLength: 300 }) }, { additionalProperties: false }),
      async run(a: { operation: string; args: Record<string, unknown>; reason: string }, signal?: AbortSignal) {
        const op = lookups.operations.find((o) => o.tool === a.operation);
        if (!op) throw new Error(`operation not available; available: ${lookups.operations.map((o) => o.tool).join(', ')}`);
        const r = await lookups.call(op, a.args ?? {}, a.reason, signal);
        return { text: r.pending ? r.text : `${row.name}.${op.tool}${r.isError ? ' (error)' : ''}\n${wrapUntrusted(nonce, 'connector', `connector:${row.name}/${op.tool}`, r.text)}`, summary: { connector: row.name, operation: op.tool } };
      },
    });
  }
  const outcome = await startSession({
    hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
    systemPrompt: [`# 角色\n${subject.role}`, boundaryDeclaration(nonce)].join('\n\n'),
    prompt: [
      P('push.guide_heading'), s.body.trim(), '',
      mode === 'update'
        ? `${P('push.update', { noun: subject.noun, connector: row.name, externalId: String(existing) })}${several ? P('push.update_choose', { noun: subject.noun, operations: ops.join('、') }) : `操作：${ops[0]}。`}`
        : `## 目标操作：${row.name}.${ops[0]}`,
      ...schemas.map((x) => `参数说明 ${x.op}：${JSON.stringify(x.schema?.inputSchema ?? {}).slice(0, 4000)}`),
      ...(Object.keys(fixed).length ? [P('push.fixed_params', { params: fixedPaths(fixed).join('、') })] : []),
      ...(lookups?.operations.length ? [connectorPrompt(lookups.operations, nonce)] : []),
      subject.note,
      wrapUntrusted(nonce, 'tool_output', subject.label, JSON.stringify(fields, null, 1)),
    ].join('\n'),
    tools, requiredSubmits: ['submit_push_args'], maxTurns: 12, signal: new AbortController().signal,
    onUsage: (u) => { usage.total += u.total; return 'continue'; },
  }).outcome;
  const sub = (outcome.submissions.submit_push_args as { args?: Record<string, unknown>; steps?: { operation: string; args: Record<string, unknown> }[] }[] | undefined)?.at(-1);
  if (!sub) throw new AppError('INTERNAL', `the model did not submit arguments (${outcome.status})`);
  return sub.steps ?? [{ operation: ops[0]!, args: sub.args ?? {} }];
}

/** What the model turns into operation arguments: a vulnerability, or a threat-model report. */
interface PushSubject { role: string; noun: string; label: string; note: string }
const VULN_SUBJECT = (): PushSubject => ({
  role: P('role.push_vulnerability'),
  noun: '漏洞', label: 'vulnerability', note: P('push.vulnerability_note'),
});
const THREAT_SUBJECT = (): PushSubject => ({
  role: P('role.push_threat_model'),
  noun: '威胁模型', label: 'threat-model', note: P('push.threat_model_note'),
});

/**
 * The external record's key on an update (`update_key`). A dotted key (`path.document_id`) sets a nested
 * argument, for MCP servers whose tools take `{path, params, data}` objects (the Feishu / Lark MCP).
 */
export function fixedKey(key: string | undefined, id: string | undefined): Record<string, unknown> {
  if (!key || !id) return {};
  return key.split('.').reduceRight<unknown>((v, k) => ({ [k]: v }), id) as Record<string, unknown>;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** The model's or template's arguments with the fixed key merged in (the fixed value wins, nested objects merge). */
export function withFixed(args: Record<string, unknown>, fixed: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = { ...args };
  for (const [k, v] of Object.entries(fixed)) out[k] = isObj(v) && isObj(out[k]) ? withFixed(out[k] as Record<string, unknown>, v) : v;
  return out;
}

function fixedPaths(fixed: Record<string, unknown>, prefix = ''): string[] {
  return Object.entries(fixed).flatMap(([k, v]) => (isObj(v) ? fixedPaths(v, `${prefix}${k}.`) : [`${prefix}${k}`]));
}

function strings(v: unknown): string[] {
  if (typeof v === 'string') return [v];
  if (Array.isArray(v)) return v.flatMap(strings);
  if (v && typeof v === 'object') return Object.values(v).flatMap(strings);
  return [];
}

async function planPushInner(deps: { store: Store; hub: ModelHub; pool: ConnectorPool }, input: { projectId: string; skill: string; vulnIds: string[] }): Promise<PushPlan> {
  const { store } = deps;
  if (!input.vulnIds.length || input.vulnIds.length > 50) throw new AppError('COMMON_VALIDATION', 'push 1–50 vulnerabilities at a time');
  const s = guide(store, input.projectId, input.skill);
  const push = s.push!;
  const { row } = writableConnector(store, push.connector, push.operation);
  const follow = updateOps(push);
  for (const op of follow) writableConnector(store, push.connector, op);
  const usage = { total: 0 };
  const items: PushItem[] = [];
  for (const vid of [...new Set(input.vulnIds)]) {
    const v = store.get<{ id: string; project_id: string; display_no: number; title: string }>('SELECT id, project_id, display_no, title FROM vulnerability WHERE id = ?', vid);
    if (!v || v.project_id !== input.projectId) throw new AppError('VULN_NOT_FOUND', vid);
    const fields = vulnFields(store, vid);
    const rec = store.get<{ external_id: string; external_url: string | null; last_pushed_hash: string | null }>(`SELECT external_id, external_url, last_pushed_hash FROM sync_record WHERE connector_id = ? AND local_kind = 'vulnerability' AND local_id = ?`, row.id, vid);
    const existing = rec ? { externalId: rec.external_id, externalUrl: rec.external_url } : null;
    const base = { vulnId: vid, displayNo: v.display_no, title: v.title, existing, reasons: [] as string[], steps: [] as PushItem['steps'] };
    if (existing && !follow.length) {
      items.push({ ...base, action: 'skip', operation: null, args: {}, hash: '', skipReason: `已推送（${existing.externalId}），推送指引没有更新操作` });
      continue;
    }
    // Idempotency is on the vulnerability content (with the guide): unchanged → nothing is sent again.
    const hash = sha256Hex(canonicalJson({ skill: s.name, fields }));
    if (rec?.last_pushed_hash === hash) {
      items.push({ ...base, action: 'skip', operation: null, args: {}, hash, skipReason: '漏洞内容与上次推送相同' });
      continue;
    }
    const action: 'create' | 'update' = existing ? 'update' : 'create';
    // The key of the external record on updates comes from sync_record, never from the template or model.
    const fixed = fixedKey(action === 'update' && existing ? push.updateKey : undefined, existing?.externalId);
    const t = templateOf(s, action === 'update' ? 'template-update.yaml' : 'template.yaml');
    let chosen: { operation: string; args: Record<string, unknown> }[];
    if (t) {
      chosen = [{ operation: action === 'update' ? follow[0]! : push.operation, args: fillPushTemplate(t, { ...fields, external_id: existing?.externalId ?? '' }) as Record<string, unknown> }];
    } else {
      chosen = await aiSteps(deps, s, row, action === 'update' ? follow : [push.operation], fields, action, existing?.externalId ?? null, fixed, usage);
    }
    const steps = chosen.map((c) => ({ operation: c.operation, args: withFixed(c.args, fixed), ok: null, error: null }));
    for (const st of steps) {
      const argErrors = checkPackArgs(store, row, st.operation, st.args);
      if (argErrors.length) throw new AppError('COMMON_VALIDATION', `V-${v.display_no}: ${argErrors.join('; ')}`);
    }
    // Content from the audited code or the model may carry instructions: then a person looks first.
    const signals = detectInjection(steps.flatMap((st) => strings(st.args)).join('\n'));
    const reasons = signals.length ? [`疑似注入内容（${[...new Set(signals.map((x) => x.signal))].join('、')}）`] : [];
    items.push({ ...base, action, operation: steps.map((st) => st.operation).join(' → '), args: steps[0]!.args, steps, hash, skipReason: null, reasons });
  }
  const confirmReasons = [...(push.confirm ? ['推送指引要求确认'] : []), ...new Set(items.flatMap((i) => i.reasons))];
  // The confirmation binds exactly what the preview shows.
  const payloadHash = sha256Hex(canonicalJson(items.map((i) => [i.vulnId, i.action, i.steps.map((st) => [st.operation, st.args]), i.hash])));
  return {
    id: newId('push'), projectId: input.projectId, skill: s.name, connectorId: row.id, connectorName: row.name,
    status: confirmReasons.length ? 'awaiting_confirm' : 'done', confirmRequired: confirmReasons.length > 0, confirmReasons, payloadHash,
    token: confirmReasons.length ? randomBytes(24).toString('hex') : null, expiresAt: Date.now() + PUSH_TOKEN_TTL_MS, createdAt: Date.now(), tokens: usage.total, items,
  };
}

// ---- execution ---------------------------------------------------------------------------------------------

const inflight = new Set<string>();

/** Execute the non-skipped items; one in-flight push per vulnerability and connector. */
export async function executePush(deps: { store: Store; pool: ConnectorPool }, plan: PushPlan, confirmedBy: 'auto' | 'user'): Promise<PushPlan> {
  const { store } = deps;
  const s = guide(store, plan.projectId, plan.skill);
  const push = s.push!;
  const row = writableConnector(store, push.connector, push.operation).row;
  if (row.id !== plan.connectorId) throw new AppError('COMMON_VALIDATION', 'the push guide now points to another connector; start again');
  const spec = connectorSpec(row, store.paths.connectorPacks);
  const baseUrl = spec.pack?.baseUrl ?? spec.url ?? '';
  for (const it of plan.items) {
    if (it.action === 'skip' || !it.operation) continue;
    const key = `${row.id}:${it.vulnId}`;
    if (inflight.has(key)) { it.result = { ok: false, externalId: null, externalUrl: null, error: 'another push of this vulnerability is running' }; continue; }
    inflight.add(key);
    const started = Date.now();
    let current = it.steps[0]!;
    try {
      // Steps run in order; a failed step stops the rest.
      let obj: unknown = null;
      let firstText = '';
      let bytes = 0;
      for (const st of it.steps) {
        current = st;
        const stepStarted = Date.now();
        const r = await deps.pool.call(spec, st.operation, st.args);
        if (r.isError) throw new Error(r.text.slice(0, 500));
        st.ok = true;
        bytes += Buffer.byteLength(r.text);
        if (st === it.steps[0]) { firstText = r.text; obj = r.structured ?? null; if (!obj) { try { obj = JSON.parse(r.text); } catch { obj = null; } } }
        if (st !== it.steps[0]) logConnectorCall(store, row.id, { operation: st.operation, kind: 'write', status: 'ok', durationMs: Date.now() - stepStarted, request: st.args, bytes: Buffer.byteLength(r.text), confirmedBy });
      }
      const got = it.action === 'create' && push.externalId ? externalIdOf(obj, firstText, push.externalId) : null;
      const externalId = got ?? it.existing?.externalId ?? null;
      const externalUrl = externalId && push.externalUrl ? push.externalUrl.replace(/\{external_id\}/g, encodeURIComponent(externalId)).replace(/\{base_url\}/g, baseUrl.replace(/\/+$/, '')) : it.existing?.externalUrl ?? null;
      store.tx(() => {
        logConnectorCall(store, row.id, { operation: it.steps[0]!.operation, kind: 'write', status: 'ok', durationMs: Date.now() - started, request: it.steps[0]!.args, bytes, confirmedBy });
        if (externalId) {
          const cur = store.get<{ id: string }>(`SELECT id FROM sync_record WHERE connector_id = ? AND local_kind = 'vulnerability' AND local_id = ?`, row.id, it.vulnId);
          if (cur) store.update('sync_record', { id: cur.id }, { external_id: externalId, external_url: externalUrl, last_pushed_hash: it.hash });
          else store.insert('sync_record', { id: newId('syncRecord'), connector_id: row.id, local_kind: 'vulnerability', local_id: it.vulnId, external_id: externalId, external_url: externalUrl, last_pushed_hash: it.hash });
        }
      });
      // Without an ID the push cannot update the record later: say so, with what the system returned.
      it.result = { ok: true, externalId, externalUrl, error: externalId ? null : `外部系统没有返回可识别的 ID（检查推送指引的 external_id；返回内容开头：${firstText.replace(/\s+/g, ' ').slice(0, 200)}）。可在漏洞详情的“外部记录”中手动关联。` };
    } catch (e) {
      const msg = (e as Error).message.slice(0, 500);
      current.ok = false;
      current.error = msg;
      logConnectorCall(store, row.id, { operation: current.operation, kind: 'write', status: 'error', durationMs: Date.now() - started, request: current.args, error: msg, confirmedBy });
      it.result = { ok: false, externalId: null, externalUrl: null, error: `${current.operation}：${msg}` };
    } finally {
      inflight.delete(key);
    }
  }
  return { ...plan, status: 'done', token: null };
}

/**
 * The external ID in an operation's result: the guide's `$.path` first; `$..key` (or a `$.key` that did not
 * match) searches the whole result for that key; a non-JSON reply is searched as text (`key: 123`, `"key":"abc"`).
 */
export function externalIdOf(obj: unknown, text: string, expr: string): string | null {
  const scalar = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim() : typeof v === 'number' ? String(v) : null);
  const deep = /^\$\.\.([\w-]+)$/.exec(expr.trim());
  if (!deep) { const v = scalar(extract(obj, expr)); if (v) return v; }
  const key = deep?.[1] ?? /^\$\.(?:[\w-]+\.)*([\w-]+)$/.exec(expr.trim())?.[1];
  if (!key) return null;
  const find = (v: unknown, depth: number): string | null => {
    if (!v || typeof v !== 'object' || depth > 8) return null;
    if (!Array.isArray(v) && key in (v as Record<string, unknown>)) { const s = scalar((v as Record<string, unknown>)[key]); if (s) return s; }
    for (const x of Array.isArray(v) ? v : Object.values(v)) { const s = find(x, depth + 1); if (s) return s; }
    return null;
  };
  const fromObj = find(obj, 0);
  if (fromObj) return fromObj;
  const m = new RegExp(`["']?${key.replace(/[-]/g, '\\-')}["']?\\s*[:：=]\\s*["']?([\\w-]+)`).exec(text);
  return m?.[1] ?? null;
}

/**
 * Link a vulnerability to a record that already exists in the external system: created by hand, or created by a
 * push whose result carried no recognizable ID. The next push of the vulnerability updates that record.
 */
export function linkExternalRecord(store: Store, vulnId: string, input: { connectorId: string; externalId: string; externalUrl?: string | null }): void {
  if (!store.get('SELECT 1 FROM vulnerability WHERE id = ?', vulnId)) throw new AppError('VULN_NOT_FOUND', vulnId);
  if (!store.get('SELECT 1 FROM connector WHERE id = ?', input.connectorId)) throw new AppError('COMMON_NOT_FOUND', `connector ${input.connectorId}`);
  const externalId = input.externalId.trim();
  if (!externalId || externalId.length > 200) throw new AppError('COMMON_VALIDATION', 'external id is required (≤ 200 characters)');
  const url = input.externalUrl?.trim() || null;
  if (url && !/^https?:\/\//i.test(url)) throw new AppError('COMMON_VALIDATION', 'external url must be http(s)');
  const cur = store.get<{ id: string }>(`SELECT id FROM sync_record WHERE connector_id = ? AND local_kind = 'vulnerability' AND local_id = ?`, input.connectorId, vulnId);
  // No pushed hash: the next push sends the current content as an update.
  if (cur) store.update('sync_record', { id: cur.id }, { external_id: externalId, external_url: url, last_pushed_hash: null });
  else store.insert('sync_record', { id: newId('syncRecord'), connector_id: input.connectorId, local_kind: 'vulnerability', local_id: vulnId, external_id: externalId, external_url: url, last_pushed_hash: null });
}

export function syncRecords(store: Store, vulnId: string): { connectorId: string; connectorName: string; externalId: string; externalUrl: string | null; updatedAt: number }[] {
  return store.all<{ connector_id: string; name: string; external_id: string; external_url: string | null; updated_at: number }>(
    `SELECT s.connector_id, c.name, s.external_id, s.external_url, s.updated_at FROM sync_record s JOIN connector c ON c.id = s.connector_id
     WHERE s.local_kind = 'vulnerability' AND s.local_id = ? ORDER BY s.updated_at DESC`, vulnId)
    .map((r) => ({ connectorId: r.connector_id, connectorName: r.name, externalId: r.external_id, externalUrl: r.external_url, updatedAt: r.updated_at }));
}

// ---- start / confirm ---------------------------------------------------------------------------------------

// Plans awaiting confirmation live in memory only (single local server): a restart simply expires them.
const pending = new Map<string, PushPlan>();

function sweep(now = Date.now()): void {
  for (const [id, p] of pending) if (p.expiresAt <= now) pending.delete(id);
}

/** Plan a push; execute it at once unless a preview must be confirmed (or `preview` was asked for). */
async function startPushInner(deps: { store: Store; hub: ModelHub; pool: ConnectorPool }, input: { projectId: string; skill: string; vulnIds: string[]; preview?: boolean }): Promise<PushPlan> {
  sweep();
  const plan = await planPush(deps, input);
  const actionable = plan.items.some((i) => i.action !== 'skip');
  if (!actionable) return { ...plan, status: 'done', token: null, confirmRequired: false };
  if (plan.confirmRequired || input.preview) {
    const p: PushPlan = { ...plan, status: 'awaiting_confirm', token: plan.token ?? randomBytes(24).toString('hex') };
    pending.set(p.id, p);
    return p;
  }
  return executePush(deps, plan, 'auto');
}

/** Execute a previewed plan: the token is single-use, bound to the plan's payload hash, valid 5 minutes. */
export async function confirmPush(deps: { store: Store; pool: ConnectorPool }, id: string, token: string, payloadHash: string): Promise<PushPlan> {
  sweep();
  const p = pending.get(id);
  if (!p) throw new AppError('COMMON_NOT_FOUND', 'push preview not found or expired; preview again');
  if (!p.token || token !== p.token || payloadHash !== p.payloadHash) throw new AppError('COMMON_VALIDATION', 'confirmation does not match this preview');
  pending.delete(id);
  return executePush(deps, p, 'user');
}

export function cancelPush(id: string): void {
  pending.delete(id);
}

// ---- threat-model sync to online documents -----------------------------------------

export interface ThreatSyncPlan {
  id: string; threatModelId: string; projectId: string; skill: string; connectorId: string; connectorName: string;
  status: 'awaiting_confirm' | 'done'; action: 'create' | 'update' | 'skip'; skipReason: string | null; reasons: string[];
  existing: { externalId: string; externalUrl: string | null } | null;
  steps: { operation: string; args: Record<string, unknown>; ok: boolean | null; error: string | null }[];
  hash: string; payloadHash: string; token: string | null; expiresAt: number; createdAt: number; tokens: number;
  result: { ok: boolean; externalId: string | null; externalUrl: string | null; error: string | null } | null;
}

/** Deterministic fields of a threat model for a template or the model: the report as rendered now. */
export function threatModelFields(store: Store, threatModelId: string, report: string): Record<string, string | string[]> {
  const tm = store.get<{ title: string; project_id: string; generated_at: number | null }>('SELECT title, project_id, generated_at FROM threat_model WHERE id = ?', threatModelId);
  if (!tm) throw new AppError('THREAT_MODEL_NOT_FOUND', threatModelId);
  const project = getProject(store, tm.project_id).name;
  return {
    title: tm.title, project, document_title: `${project} 威胁建模 · ${tm.title}`, report,
    generated_at: tm.generated_at ? new Date(tm.generated_at).toISOString() : '', threat_model_id: threatModelId,
  };
}

const threatPending = new Map<string, ThreatSyncPlan>();

/** A document link or ID: `…/docx/<id>` (Feishu / Lark) or another URL's last path segment, or the ID itself. */
export function documentRef(ref: string): { externalId: string; externalUrl: string | null } {
  const r = ref.trim();
  if (/^https?:\/\//i.test(r)) {
    let u: URL;
    try { u = new URL(r); } catch { throw new AppError('COMMON_VALIDATION', 'invalid document link'); }
    const seg = /\/(?:docx|docs|doc)\/([A-Za-z0-9_-]+)/.exec(u.pathname)?.[1] ?? u.pathname.split('/').filter(Boolean).at(-1);
    if (!seg || /\/wiki\//.test(u.pathname)) throw new AppError('COMMON_VALIDATION', 'use the link of the document itself (…/docx/…); a wiki page link is not supported here');
    return { externalId: seg, externalUrl: `${u.origin}${u.pathname}` };
  }
  if (!/^[A-Za-z0-9_-]{4,200}$/.test(r)) throw new AppError('COMMON_VALIDATION', 'invalid document ID');
  return { externalId: r, externalUrl: null };
}

/**
 * Plan a sync of a threat model with a `target: threat_model` guide (only one guide → it is used). Unchanged report →
 * skip; synced before → the guide's update operations on the same document. A sync always shows a preview first: it
 * writes a whole document to an external system.
 */
async function planThreatModelSyncInner(
  deps: { store: Store; hub: ModelHub; pool: ConnectorPool }, input: { threatModelId: string; skill?: string; report: string; document?: string },
): Promise<ThreatSyncPlan> {
  const { store } = deps;
  const tm = store.get<{ project_id: string; status: string }>('SELECT project_id, status FROM threat_model WHERE id = ?', input.threatModelId);
  if (!tm) throw new AppError('THREAT_MODEL_NOT_FOUND', input.threatModelId);
  if (tm.status === 'generating') throw new AppError('THREAT_MODEL_BUSY', input.threatModelId);
  const guides = pushGuides(store, tm.project_id, 'threat_model');
  const name = input.skill ?? (guides.length === 1 ? guides[0]!.name : null);
  if (!name) throw new AppError('COMMON_VALIDATION', guides.length ? `choose a sync guide: ${guides.map((g) => g.name).join(', ')}` : 'no sync guide for threat models (category push_guide, push.target: threat_model)');
  const s = guide(store, tm.project_id, name, 'threat_model');
  const push = s.push!;
  const { row } = writableConnector(store, push.connector, push.operation);
  const follow = updateOps(push);
  for (const op of follow) writableConnector(store, push.connector, op);
  const fields = threatModelFields(store, input.threatModelId, input.report);
  const rec = store.get<{ external_id: string; external_url: string | null; last_pushed_hash: string | null }>(
    `SELECT external_id, external_url, last_pushed_hash FROM sync_record WHERE connector_id = ? AND local_kind = 'threat_model' AND local_id = ?`, row.id, input.threatModelId);
  // sync into a document that already exists (a person created it and gave the app access) — an update.
  const target = input.document?.trim() ? documentRef(input.document) : null;
  const existing = target && target.externalId !== rec?.external_id ? target : rec ? { externalId: rec.external_id, externalUrl: rec.external_url } : null;
  if (target && !follow.length) throw new AppError('COMMON_VALIDATION', 'the sync guide has no update operations; it cannot write into an existing document');
  const hash = sha256Hex(canonicalJson({ skill: s.name, fields }));
  const base = {
    id: newId('push'), threatModelId: input.threatModelId, projectId: tm.project_id, skill: s.name, connectorId: row.id, connectorName: row.name,
    existing, hash, createdAt: Date.now(), expiresAt: Date.now() + PUSH_TOKEN_TTL_MS, result: null,
  };
  const skip = (why: string): ThreatSyncPlan => ({ ...base, status: 'done', action: 'skip', skipReason: why, reasons: [], steps: [], payloadHash: '', token: null, tokens: 0 });
  if (existing && !follow.length) return skip(`已同步（${existing.externalId}），同步指引没有更新操作`);
  if (rec?.last_pushed_hash === hash && existing?.externalId === rec.external_id) return skip('报告与上次同步时相同');
  const action: 'create' | 'update' = existing ? 'update' : 'create';
  const fixed = fixedKey(action === 'update' && existing ? push.updateKey : undefined, existing?.externalId);
  const usage = { total: 0 };
  const t = templateOf(s, action === 'update' ? 'template-update.yaml' : 'template.yaml');
  const chosen = t
    ? [{ operation: action === 'update' ? follow[0]! : push.operation, args: fillPushTemplate(t, { ...fields, external_id: existing?.externalId ?? '' }) as Record<string, unknown> }]
    : await aiSteps(deps, s, row, action === 'update' ? follow : [push.operation], fields, action, existing?.externalId ?? null, fixed, usage, THREAT_SUBJECT());
  const steps = chosen.map((c) => ({ operation: c.operation, args: withFixed(c.args, fixed), ok: null, error: null }));
  for (const st of steps) {
    const argErrors = checkPackArgs(store, row, st.operation, st.args);
    if (argErrors.length) throw new AppError('COMMON_VALIDATION', argErrors.join('; '));
  }
  const signals = detectInjection(steps.flatMap((st) => strings(st.args)).join('\n'));
  const reasons = ['同步会写入外部文档，需要先确认', ...(push.confirm ? ['同步指引要求确认'] : []), ...(signals.length ? [`疑似注入内容（${[...new Set(signals.map((x) => x.signal))].join('、')}）`] : [])];
  const plan: ThreatSyncPlan = {
    ...base, status: 'awaiting_confirm', action, skipReason: null, reasons, steps, tokens: usage.total,
    payloadHash: sha256Hex(canonicalJson([input.threatModelId, action, steps.map((st) => [st.operation, st.args]), hash])), token: randomBytes(24).toString('hex'),
  };
  threatPending.set(plan.id, plan);
  return plan;
}

/** Run a previewed threat-model sync: single-use token bound to the payload, one in-flight sync per document. */
export async function confirmThreatModelSync(deps: { store: Store; pool: ConnectorPool }, id: string, token: string, payloadHash: string): Promise<ThreatSyncPlan> {
  const { store } = deps;
  for (const [k, p] of threatPending) if (p.expiresAt <= Date.now()) threatPending.delete(k);
  const plan = threatPending.get(id);
  if (!plan) throw new AppError('COMMON_NOT_FOUND', 'sync preview not found or expired; preview again');
  if (!plan.token || token !== plan.token || payloadHash !== plan.payloadHash) throw new AppError('COMMON_VALIDATION', 'confirmation does not match this preview');
  threatPending.delete(id);
  const s = guide(store, plan.projectId, plan.skill, 'threat_model');
  const push = s.push!;
  const row = writableConnector(store, push.connector, push.operation).row;
  if (row.id !== plan.connectorId) throw new AppError('COMMON_VALIDATION', 'the sync guide now points to another connector; preview again');
  const spec = connectorSpec(row, store.paths.connectorPacks);
  const key = `${row.id}:${plan.threatModelId}`;
  if (inflight.has(key)) return { ...plan, status: 'done', token: null, result: { ok: false, externalId: null, externalUrl: null, error: 'another sync of this threat model is running' } };
  inflight.add(key);
  const started = Date.now();
  let current = plan.steps[0]!;
  try {
    let obj: unknown = null;
    let firstText = '';
    for (const st of plan.steps) {
      current = st;
      const t0 = Date.now();
      const r = await deps.pool.call(spec, st.operation, st.args);
      logConnectorCall(store, row.id, { operation: st.operation, kind: 'write', status: r.isError ? 'error' : 'ok', durationMs: Date.now() - t0, request: st.args, bytes: Buffer.byteLength(r.text), confirmedBy: 'user', ...(r.isError ? { error: r.text.slice(0, 500) } : {}) });
      if (r.isError) throw new Error(r.text.slice(0, 500));
      st.ok = true;
      if (st === plan.steps[0]) { firstText = r.text; obj = r.structured ?? null; if (!obj) { try { obj = JSON.parse(r.text); } catch { obj = null; } } }
    }
    const got = plan.action === 'create' && push.externalId ? externalIdOf(obj, firstText, push.externalId) : null;
    const urlInReply = plan.action === 'create' ? /https?:\/\/[^\s"'<>]+/.exec(firstText)?.[0] ?? null : null;
    const externalId = got ?? plan.existing?.externalId ?? null;
    const externalUrl = externalId && push.externalUrl
      ? push.externalUrl.replace(/\{external_id\}/g, encodeURIComponent(externalId)).replace(/\{base_url\}/g, (spec.pack?.baseUrl ?? spec.url ?? '').replace(/\/+$/, ''))
      : plan.existing?.externalUrl ?? urlInReply;
    if (externalId) {
      store.tx(() => {
        const cur = store.get<{ id: string }>(`SELECT id FROM sync_record WHERE connector_id = ? AND local_kind = 'threat_model' AND local_id = ?`, row.id, plan.threatModelId);
        if (cur) store.update('sync_record', { id: cur.id }, { external_id: externalId, external_url: externalUrl, last_pushed_hash: plan.hash });
        else store.insert('sync_record', { id: newId('syncRecord'), connector_id: row.id, local_kind: 'threat_model', local_id: plan.threatModelId, external_id: externalId, external_url: externalUrl, last_pushed_hash: plan.hash });
      });
    }
    return {
      ...plan, status: 'done', token: null,
      result: { ok: true, externalId, externalUrl, error: externalId ? null : `外部系统没有返回可识别的文档 ID（检查同步指引的 external_id；返回内容开头：${firstText.replace(/\s+/g, ' ').slice(0, 200)}）；再次同步会新建文档。` },
    };
  } catch (e) {
    const msg = (e as Error).message.slice(0, 500);
    current.ok = false;
    current.error = msg;
    return { ...plan, status: 'done', token: null, result: { ok: false, externalId: null, externalUrl: null, error: `${current.operation}：${msg}（${Date.now() - started} ms）` } };
  } finally {
    inflight.delete(key);
  }
}

export function cancelThreatModelSync(id: string): void {
  threatPending.delete(id);
}

/** Where a threat model has been synced (document ID and link per connector). */
export function threatModelSyncRecords(store: Store, threatModelId: string): { connectorId: string; connectorName: string; externalId: string; externalUrl: string | null; updatedAt: number }[] {
  return store.all<{ connector_id: string; name: string; external_id: string; external_url: string | null; updated_at: number }>(
    `SELECT s.connector_id, c.name, s.external_id, s.external_url, s.updated_at FROM sync_record s JOIN connector c ON c.id = s.connector_id
     WHERE s.local_kind = 'threat_model' AND s.local_id = ? ORDER BY s.updated_at DESC`, threatModelId)
    .map((r) => ({ connectorId: r.connector_id, connectorName: r.name, externalId: r.external_id, externalUrl: r.external_url, updatedAt: r.updated_at }));
}

/** with the prompt overrides of the project. */
export async function planPush(deps: { store: Store; hub: ModelHub; pool: ConnectorPool }, input: { projectId: string; skill: string; vulnIds: string[] }): Promise<PushPlan> {
  return withLivePrompts(deps.store, input.projectId, () => planPushInner(deps, input), 'push');
}

/** with the prompt overrides of the project. */
export async function startPush(deps: { store: Store; hub: ModelHub; pool: ConnectorPool }, input: { projectId: string; skill: string; vulnIds: string[]; preview?: boolean }): Promise<PushPlan> {
  return withLivePrompts(deps.store, input.projectId, () => startPushInner(deps, input), 'push');
}

/** with the prompt overrides of the threat model's project. */
export async function planThreatModelSync(
  deps: { store: Store; hub: ModelHub; pool: ConnectorPool }, input: { threatModelId: string; skill?: string; report: string; document?: string },
): Promise<ThreatSyncPlan> {
  const projectId = deps.store.get<{ project_id: string }>('SELECT project_id FROM threat_model WHERE id = ?', input.threatModelId)?.project_id ?? null;
  return withLivePrompts(deps.store, projectId, () => planThreatModelSyncInner(deps, input), 'threat_model_sync', input.threatModelId);
}
