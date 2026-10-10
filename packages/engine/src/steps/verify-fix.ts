// verify-fix: targeted re-verification of one tracked
// vulnerability along its original chain on the current snapshot. The model gives a verdict with
// current-version evidence; the lifecycle, occurrence and proposals are written by rule.
import { join } from 'node:path';
import { Type } from 'typebox';
import {
  newId, normalizePending, sha256Hex, SubmitReverify, type Lifecycle, type Presence, type SnapshotManifest, type SubmitReverify as Verdict, stageModel } from '@xiezhi/contracts';
import { lineHunks, SnapshotView } from '@xiezhi/context';
import type { AuditTool } from '@xiezhi/agent';
import { fromJson } from '@xiezhi/store';
import { verifyCodeRef } from '../identity.js';
import { insertConnectorEvidence, type ConnectorRef } from '../connector-access.js';
import type { AuditRuntime, RepoInfo } from '../runtime.js';
import { sessionError, type AttemptContext, type StepResult } from '../step-runner.js';
import { addRevision } from '../vulns.js';
import { validateCodeRef } from './hunt.js';
import { reviewVerdict } from './verdict-review.js';
import { P } from '@xiezhi/knowledge';

export interface VerifyFixOutput extends Verdict {
  /** Cited connector results and whether the user supplied information for this reverification. */
  connectors?: ConnectorRef[]; userNote?: boolean;
  vulnId: string;
  /** Snapshot (root hash) the verdict is about. */
  rootHash: string;
}

interface VulnRow {
  id: string; display_no: number; title: string; category: string; cwe: string | null; severity: string; repository_id: string;
  sink_symbol: string | null; sink_api: string | null; root_cause: string | null; lifecycle: Lifecycle; handling_status: string;
  last_seen_audit_id: string | null; detail_ref: string; project_id: string; confirm_status: string; missing_context: string | null;
}

/** The repository the vulnerability lives in (reverification may cover several). */
export function vulnRepo(rt: AuditRuntime, vulnId: string): RepoInfo {
  const v = rt.store.get<{ repository_id: string }>('SELECT repository_id FROM vulnerability WHERE id = ?', vulnId);
  return rt.repos.find((r) => r.id === v?.repository_id) ?? rt.targetRepo;
}

/**
 * Reuse key of a verdict (by vulnerability and code version). A pending vulnerability also
 * keys on its condition and the evidence repositories' versions: after the user supplies information
 * (answers, added repositories) the earlier verdict must not be reused.
 */
export function verifyIdentity(rt: AuditRuntime, vulnId: string) {
  const m = stageModel(rt.strategy, 'verify')!;
  // A verdict reached without the “已修复” review is not reused when the review is on.
  const base = { vuln: vulnId, root: vulnRepo(rt, vulnId).rootHash, model: `${m.provider}/${m.model}`, ...(rt.strategy.stages.adversarialReview ? { review: true } : {}) };
  const v = rt.store.get<{ confirm_status: string; missing_context: string | null }>('SELECT confirm_status, missing_context FROM vulnerability WHERE id = ?', vulnId);
  if (v?.confirm_status !== 'pending') return base;
  // Which authorized connectors are authoritative decides whether their results may resolve the condition
  //: declaring one authoritative must not reuse a verdict kept pending on unverified data.
  const authoritative = (rt.strategy.connectors ?? []).filter((ref) => rt.store.get<{ a: number }>('SELECT authoritative AS a FROM connector WHERE id = ? OR name = ?', ref, ref)?.a === 1).sort();
  return {
    ...base, pending: sha256Hex(v.missing_context ?? ''), note: sha256Hex(reverifyNote(rt) ?? ''), evidenceRoots: rt.repos.filter((r) => r.role !== 'target').map((r) => r.rootHash).sort(),
    ...(authoritative.length ? { authoritative } : {}),
  };
}

/** What the user supplied when starting the (targeted) reverification. */
export function reverifyNote(rt: AuditRuntime): string | null {
  return fromJson<{ reverifyNote?: string }>(rt.audit.scope, {}).reverifyNote ?? null;
}

/** The snapshot the vulnerability's evidence was captured in (for "then vs now" diffs). */
function evidenceSnapshot(rt: AuditRuntime, vulnId: string): SnapshotView | null {
  const ev = rt.store.get<{ snapshot_id: string | null }>(`SELECT snapshot_id FROM evidence WHERE owner_kind = 'vulnerability' AND owner_id = ? AND snapshot_id IS NOT NULL ORDER BY ord LIMIT 1`, vulnId);
  const snap = ev?.snapshot_id ? rt.store.get<{ root_hash: string; manifest_ref: string }>('SELECT root_hash, manifest_ref FROM snapshot WHERE id = ?', ev.snapshot_id) : undefined;
  if (!snap) return null;
  return new SnapshotView(vulnRepo(rt, vulnId).name, join(rt.store.paths.snapshots, snap.root_hash), rt.store.artifacts.getJson<SnapshotManifest>(snap.manifest_ref));
}

function fileDiff(then: SnapshotView, now: SnapshotView, path: string, maxLines = 200): string {
  if (!then.hasFile(path)) return `### ${path}：当时不存在`;
  if (!now.hasFile(path)) return P('verify.diff_file_gone', { path });
  const a = then.lines(path);
  const b = now.lines(path);
  const hunks = lineHunks(path, a, b);
  if (!hunks.length) return `### ${path}：未变化`;
  const out = [`### ${path}（当时 → 当前，行号为当前版本）`];
  for (const h of hunks) {
    out.push(`@@ 当时 ${h.baseStart},${h.baseCount} → 当前 ${h.headStart},${h.headCount} @@`);
    for (let i = 0; i < h.baseCount; i++) out.push(`- ${' '.repeat(5)}  ${a[h.baseStart - 1 + i] ?? ''}`);
    for (let i = 0; i < h.headCount; i++) out.push(`+ ${String(h.headStart + i).padStart(5)}  ${b[h.headStart - 1 + i] ?? ''}`);
    if (out.length > maxLines) { out.push(P('verify.diff_truncated')); break; }
  }
  return out.join('\n');
}

export async function verifyFixStep(rt: AuditRuntime, vulnId: string, ctx: AttemptContext): Promise<StepResult> {
  const store = rt.store;
  const v = store.get<VulnRow>('SELECT * FROM vulnerability WHERE id = ?', vulnId)!;
  const detail = store.artifacts.getJson<{ chain?: { repo?: string; path: string; startLine: number; endLine: number; note?: string }[]; reasoning?: string }>(v.detail_ref);
  const entries = store.all<{ entry_key: string; state: string }>('SELECT entry_key, state FROM vuln_entry WHERE vulnerability_id = ? ORDER BY entry_key', vulnId);
  const evidence = store.all<{ path: string | null; start_line: number | null; end_line: number | null; note: string | null; kind: string }>(
    `SELECT path, start_line, end_line, note, kind FROM evidence WHERE owner_kind = 'vulnerability' AND owner_id = ? ORDER BY ord`, vulnId);
  const repo = vulnRepo(rt, vulnId);
  const now = rt.views.get(repo.name)!;
  const then = evidenceSnapshot(rt, vulnId);
  // Pending confirmation: check only along the condition's chains.
  const pending = v.confirm_status === 'pending' ? normalizePending(v.missing_context === null ? null : JSON.parse(v.missing_context)) : null;
  const paths = [...new Set([...evidence.map((e) => e.path), ...(detail.chain ?? []).map((c) => c.path)].filter((p): p is string => !!p))];
  const diffs = then ? paths.map((p) => fileDiff(then, now, p)) : [P('verify.no_snapshot')];
  const submit: AuditTool = {
    name: 'submit_reverify', kind: 'submit', parameters: SubmitReverify,
    description: P('tool.submit_reverify'),
    validate: (a: Verdict) => {
      const issues: string[] = [];
      a.evidence.forEach((e, i) => issues.push(...validateCodeRef(rt, e, `evidence[${i}]`, true)));
      if ((a.verdict === 'fixed' || a.verdict === 'partially_fixed' || a.verdict === 'still_present') && a.evidence.length === 0) {
        issues.push(P('feedback.reverify.evidence', { verdict: a.verdict }));
      }
      if (a.verdict === 'partially_fixed' && a.fixedEntries.length === 0) issues.push(P('feedback.reverify.fixed_entries'));
      const known = new Set(entries.map((e) => e.entry_key));
      for (const e of a.fixedEntries) if (!known.has(e)) issues.push(P('feedback.reverify.unknown_entry', { entry: e, known: [...known].join(', ') }));
      if (a.verdict === 'undetermined' && !a.pendingCondition) issues.push(P('feedback.reverify.undetermined_condition'));
      if (pending && !a.pendingResolution) issues.push(P('feedback.reverify.pending_resolution'));
      if (a.pendingResolution === 'still_pending' && !a.pendingCondition) issues.push(P('feedback.reverify.still_pending_condition'));
      return issues.slice(0, 20);
    },
    run: (a: Verdict) => ({ text: `recorded: ${a.verdict}` }),
  };
  const diffTool: AuditTool = {
    name: 'diff', kind: 'read', parameters: Type.Object({ path: Type.String({ maxLength: 1000 }) }, { additionalProperties: false }),
    description: P('tool.diff.reverify'),
    run: (a: { path: string }) => ({ text: then ? fileDiff(then, now, a.path, 2000) : P('feedback.reverify.no_snapshot') }),
  };
  const prompt = [
    ...(rt.repos.length > 1 ? [P('verify.multi_repo', { repo: repo.name })] : []),
    P('verify.task', { no: v.display_no, title: v.title }),
    `类别：${v.category}${v.cwe ? `（${v.cwe}）` : ''}；危险点：${v.sink_symbol ?? '未知'}；敏感 API：${v.sink_api ?? '未知'}`,
    `受影响入口：${entries.map((e) => `${e.entry_key}${e.state !== 'active' ? `（${e.state}）` : ''}`).join('、') || '未知'}`,
    `根因：${v.root_cause ?? ''}`,
    '', P('verify.evidence_heading'),
    ...evidence.map((e) => `- ${e.kind}：${e.path ?? '?'}:${e.start_line ?? '?'}-${e.end_line ?? '?'}${e.note ? `  ${e.note}` : ''}`),
    ...(detail.chain ?? []).map((c) => `- 链路：${c.path}:${c.startLine}-${c.endLine}${c.note ? `  ${c.note}` : ''}`),
    // the reasoning of the time is read on demand (finding_reasoning), not pushed.
    ...(detail.reasoning ? ['', P('verify.reasoning_note')] : []),
    '', P('verify.diff_heading'), ...diffs,
    '', P('verify.verdict_rules'),
    ...(pending ? [
      '', P('verify.pending_heading'),
      `缺少：${pending.missing.map((m) => `${m.kind} ${m.ref}${m.hint ? `（${m.hint}）` : ''}`).join('；')}`,
      `成立条件：${pending.holdsIf.map((c) => c.statement).join('；')}`,
      `不成立条件：${pending.refutedIf.map((c) => c.statement).join('；')}`,
      `若成立的严重度：${pending.severityIfHolds}`,
      // Without this the model never used the bound connectors for conditions outside the code.
      P('verify.pending_rules'),
      ...(reverifyNote(rt) ? ['', P('verify.user_note_heading'), reverifyNote(rt)!] : []),
    ] : []),
    P('verify.closing'),
  ].join('\n');
  const outcome = await rt.session({
    stepId: ctx.stepId, attempt: ctx.attempt, kind: 'verify-fix', phase: 'verify', model: stageModel(rt.strategy, 'verify')!, signal: ctx.signal,
    prompt, submitTools: [submit], requiredSubmits: ['submit_reverify'], maxTurns: rt.strategy.limits.maxTurnsPerStep,
    extraTools: [diffTool, ...(detail.reasoning ? [{
      name: 'finding_reasoning', kind: 'read' as const, parameters: Type.Object({}, { additionalProperties: false }),
      description: P('tool.finding_reasoning.reverify'),
      run: () => ({ text: detail.reasoning!.slice(0, 6000) }),
    }] : [])],
  });
  const err = sessionError(outcome);
  if (err) throw err;
  let verdict = (outcome.submissions.submit_reverify as Verdict[]).at(-1)!;
  // Optional review of “已修复” (stages.adversarialReview): a doubt makes the verdict “待确认”.
  if (rt.strategy.stages.adversarialReview && verdict.verdict === 'fixed') {
    const review = await reviewVerdict(rt, ctx, 'fixed', [
      `漏洞 V-${v.display_no}「${v.title}」（${v.category}${v.cwe ? `，${v.cwe}` : ''}），仓库 ${repo.name}；受影响入口：${entries.map((e) => e.entry_key).join('、') || '未知'}`,
      `根因：${v.root_cause ?? ''}`,
      P('verify.review_fixed_heading'),
      `当前版本证据：${verdict.evidence.map((e) => `${e.repo ?? repo.name}:${e.path}:${e.startLine}-${e.endLine}${e.note ? ` ${e.note}` : ''}`).join('；')}`,
      '', P('verify.diff_heading'), ...diffs,
    ], verdict.reasoning);
    if (review.decision === 'doubt') {
      verdict = { ...verdict, verdict: 'undetermined', reasoning: `${verdict.reasoning}\n\n复核存疑：${review.reason}`, ...(review.pendingCondition ? { pendingCondition: review.pendingCondition } : {}) };
    }
  }
  const out: VerifyFixOutput = { ...verdict, vulnId, rootHash: repo.rootHash, connectors: rt.connectorRefs(ctx.stepId, verdict.connectorRefs), userNote: !!reverifyNote(rt) };
  const outputRef = store.artifacts.putJson(out);
  return { outputRef, apply: () => applyReverify(rt, out, ctx.stepId, outputRef) };
}

/** Mapping of a verdict to presence, lifecycle and proposals. */
export function applyReverify(rt: AuditRuntime, out: VerifyFixOutput, stepId: string, outputRef: string): void {
  const store = rt.store;
  const v = store.get<VulnRow>('SELECT * FROM vulnerability WHERE id = ?', out.vulnId)!;
  const before = v.lifecycle;
  let presence: Presence;
  let after: Lifecycle;
  switch (out.verdict) {
    case 'fixed': presence = 'not_found_verified'; after = 'fixed_verified'; break;
    case 'still_present': presence = 'found'; after = before === 'fixed_verified' ? 'regressed' : 'persisting'; break;
    case 'partially_fixed': presence = 'found'; after = 'persisting'; break;
    default: presence = 'not_covered'; after = before; break;
  }
  // Current-version evidence, attached to the lifecycle revision (owner: revision).
  const codeEvidenceIds = out.evidence.map((e, ord) => {
    const r = rt.repoByName(e.repo) ?? vulnRepo(rt, out.vulnId);
    const check = verifyCodeRef(rt.views.get(r.name), e);
    const id = newId('evidence');
    store.insert('evidence', {
      id, owner_kind: 'revision', owner_id: `pending-${stepId}`, kind: 'code_range', snapshot_id: r.snapshotId, path: e.path,
      start_line: e.startLine, end_line: e.endLine, content_hash: check.contentHash, verified: check.verified ? 1 : 0, step_id: stepId,
      note: e.note ?? null, ord, origin_label: 'reverify', artifact_ref: outputRef,
    });
    return id;
  });
  const evidenceIds = [...codeEvidenceIds, ...insertConnectorEvidence(store, 'revision', `pending-${stepId}`, out.connectors ?? [], stepId, codeEvidenceIds.length)];
  // A pending condition decided only on non-authoritative connector data stays pending:
  // the connector content is kept in the condition for the user to verify.
  const cited = out.connectors ?? [];
  if (out.pendingResolution && out.pendingResolution !== 'still_pending' && cited.length && cited.every((c) => !c.authoritative) && !out.userNote) {
    rt.event('contract.violation', { tool: 'connector_refs', attempt: 0, issues: [`pendingResolution ${out.pendingResolution} rests on unverified connector data only; kept as still_pending`] }, stepId);
    out.pendingResolution = 'still_pending';
  }
  store.insert('vuln_occurrence', {
    id: newId('occurrence'), vulnerability_id: v.id, audit_id: rt.auditId, finding_id: null, match_level: null,
    match_basis: { reverify: out.verdict, step: stepId }, presence, reverify_verdict: out.verdict, lifecycle_before: before, lifecycle_after: after,
  });
  const reason = `复验：${{ fixed: '已修复（经验证）', still_present: '仍存在', partially_fixed: '修复不完整', undetermined: '待确认' }[out.verdict]}`;
  if (after !== before) {
    store.update('vulnerability', { id: v.id }, { lifecycle: after, ...(out.verdict === 'fixed' ? { last_verified_audit_id: rt.auditId } : { last_seen_audit_id: rt.auditId }) });
  } else if (presence === 'found') {
    store.update('vulnerability', { id: v.id }, { last_seen_audit_id: rt.auditId });
  }
  addRevision(store, v.id, { dimension: 'lifecycle', source: 'rule', actor: 'engine', from: before, to: after, reason, evidenceIds, auditId: rt.auditId });
  const rev = store.get<{ id: string }>('SELECT id FROM revision WHERE vulnerability_id = ? ORDER BY seq DESC LIMIT 1', v.id)!;
  store.db.run(`UPDATE evidence SET owner_id = ? WHERE owner_kind = 'revision' AND owner_id = ?`, rev.id, `pending-${stepId}`);
  if (out.verdict === 'partially_fixed') {
    for (const e of out.fixedEntries) store.db.run(`UPDATE vuln_entry SET state = 'fixed', last_seen_audit_id = ? WHERE vulnerability_id = ? AND entry_key = ?`, rt.auditId, v.id, e);
    addRevision(store, v.id, { dimension: 'entries', source: 'rule', actor: 'engine', from: null, to: { fixed: out.fixedEntries }, reason: '复验：这些入口已不可达', evidenceIds, auditId: rt.auditId });
  }
  if (out.verdict === 'undetermined' && out.pendingCondition) {
    store.update('vulnerability', { id: v.id }, { missing_context: out.pendingCondition });
  }
  // Pending confirmation resolved by the targeted reverification: AI only proposes.
  if (v.confirm_status === 'pending' && out.pendingResolution) {
    if (out.pendingResolution === 'still_pending') {
      if (out.pendingCondition) store.update('vulnerability', { id: v.id }, { missing_context: out.pendingCondition });
    } else {
      const to = out.pendingResolution === 'holds' ? 'confirmed' : 'false_positive';
      // The condition held and the current code was cited and verified: the evidence is complete now,
      // so a person can accept the proposal (confirmed needs complete evidence).
      // Code evidence only: connector evidence never makes the code evidence complete.
      const verifiedNow = codeEvidenceIds.length > 0 && store.get<{ n: number }>(`SELECT COUNT(*) AS n FROM evidence WHERE id IN (${codeEvidenceIds.map(() => '?').join(',')}) AND verified = 1`, ...codeEvidenceIds)!.n > 0;
      if (out.pendingResolution === 'holds' && verifiedNow) store.update('vulnerability', { id: v.id }, { evidence_complete: 1 });
      const cond = normalizePending(v.missing_context === null ? null : JSON.parse(v.missing_context));
      addRevision(store, v.id, {
        dimension: 'confirm', source: 'ai', actor: 'verify-fix', from: 'pending', to,
        reason: `定向复验：${out.pendingResolution === 'holds' ? `成立条件满足${cond ? `（若成立严重度 ${cond.severityIfHolds}）` : ''}` : '不成立条件满足'}。${out.reasoning.slice(0, 300)}`,
        evidenceIds, auditId: rt.auditId, state: 'proposed',
      });
      if (out.pendingResolution === 'holds' && cond && cond.severityIfHolds !== v.severity) {
        addRevision(store, v.id, { dimension: 'severity', source: 'ai', actor: 'verify-fix', from: v.severity, to: cond.severityIfHolds, reason: '定向复验：条件成立时的严重度', evidenceIds, auditId: rt.auditId, state: 'proposed' });
      }
    }
    rt.event('judgement.made', { kind: 'pending_resolution', vulnerability_id: v.id, display_no: v.display_no, resolution: out.pendingResolution }, stepId);
  }
  // Handling status is human-owned: rules only propose.
  const propose = (to: string, why: string) => addRevision(store, v.id, { dimension: 'handling', source: 'rule', actor: 'engine', from: v.handling_status, to, reason: why, evidenceIds, auditId: rt.auditId, state: 'proposed' });
  if (out.verdict === 'fixed' && v.handling_status !== 'fixed') propose('fixed', '复验确认已修复');
  if (out.verdict === 'still_present' && v.handling_status === 'fixed') propose('fixing', '复验发现问题仍存在，修复未生效');
  rt.event('judgement.made', { kind: 'reverify', vulnerability_id: v.id, display_no: v.display_no, verdict: out.verdict, lifecycle: { from: before, to: after } }, stepId);
}

export function reverifyTargets(rt: AuditRuntime): string[] {
  return fromJson<{ reverify?: string[] }>(rt.audit.scope, {}).reverify ?? [];
}
