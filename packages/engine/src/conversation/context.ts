// What a conversation reply is given: the frozen snapshots in code scope, the mentioned objects as data
// blocks, and the history. Split out of conversation.ts.
import { type Mention } from '@xiezhi/contracts';
import { wrapUntrusted } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';
import { pendingOf } from '../vulns.js';
import { attachmentNote, messageAttachments } from './attachments.js';
import { messageCards, resolveMention, type CardRow, type MessageRow } from './records.js';
import { P } from '@xiezhi/knowledge';

// ---- code scope -----------------------------------------------------------------------

interface ScopeRepo { name: string; repositoryId: string; projectId: string; rootHash: string; manifestRef: string; auditId: string }

function auditSnapshots(store: Store, auditId: string): ScopeRepo[] {
  return store.all<ScopeRepo>(
    `SELECT r.name, r.id AS repositoryId, r.project_id AS projectId, s.root_hash AS rootHash, s.manifest_ref AS manifestRef, ar.audit_id AS auditId
     FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id JOIN snapshot s ON s.id = ar.snapshot_id WHERE ar.audit_id = ? ORDER BY r.name`, auditId);
}

function latestRepoSnapshot(store: Store, repositoryId: string): ScopeRepo | undefined {
  return store.get<ScopeRepo>(
    `SELECT r.name, r.id AS repositoryId, r.project_id AS projectId, s.root_hash AS rootHash, s.manifest_ref AS manifestRef, ar.audit_id AS auditId
     FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id JOIN snapshot s ON s.id = ar.snapshot_id JOIN audit a ON a.id = ar.audit_id
     WHERE ar.repository_id = ? ORDER BY a.created_at DESC LIMIT 1`, repositoryId);
}

function vulnAudit(store: Store, vulnId: string): string | null {
  const occ = store.get<{ audit_id: string }>('SELECT o.audit_id FROM vuln_occurrence o JOIN audit a ON a.id = o.audit_id WHERE o.vulnerability_id = ? ORDER BY a.created_at DESC LIMIT 1', vulnId);
  if (occ) return occ.audit_id;
  const v = store.get<{ last_seen_audit_id: string | null; first_seen_audit_id: string | null }>('SELECT last_seen_audit_id, first_seen_audit_id FROM vulnerability WHERE id = ?', vulnId);
  return v?.last_seen_audit_id ?? v?.first_seen_audit_id ?? null;
}

/** Projects the conversation is about: of mentioned projects, repos, audits and vulnerabilities. */
export function mentionedProjects(store: Store, mentions: Mention[]): string[] {
  const ids: string[] = [];
  for (const m of mentions) {
    const pid = m.kind === 'project' ? store.get<{ id: string }>('SELECT id FROM project WHERE id = ?', m.id)?.id
      : m.kind === 'repo' ? store.get<{ project_id: string }>('SELECT project_id FROM repository WHERE id = ?', m.id)?.project_id
        : m.kind === 'audit' ? store.get<{ project_id: string }>('SELECT project_id FROM audit WHERE id = ?', m.id)?.project_id
          : m.kind === 'vuln' ? store.get<{ project_id: string }>('SELECT project_id FROM vulnerability WHERE id = ?', m.id)?.project_id : undefined;
    if (pid && !ids.includes(pid)) ids.push(pid);
  }
  return ids;
}

export function codeScope(store: Store, mentions: Mention[]): ScopeRepo[] {
  const picked = new Map<string, ScopeRepo>();
  const add = (r: ScopeRepo | undefined) => { if (r && !picked.has(r.repositoryId)) picked.set(r.repositoryId, r); };
  for (const m of mentions) {
    if (m.kind === 'vuln') { const a = vulnAudit(store, m.id); if (a) auditSnapshots(store, a).forEach(add); }
    if (m.kind === 'audit') auditSnapshots(store, m.id).forEach(add);
    if (m.kind === 'repo') add(latestRepoSnapshot(store, m.id));
    if (m.kind === 'project') for (const r of store.all<{ id: string }>('SELECT id FROM repository WHERE project_id = ? ORDER BY name', m.id)) add(latestRepoSnapshot(store, r.id));
  }
  // Unique names across projects (tools address repositories by name).
  const out = [...picked.values()];
  const count = new Map<string, number>();
  for (const r of out) count.set(r.name, (count.get(r.name) ?? 0) + 1);
  return out.map((r) => (count.get(r.name)! > 1 ? { ...r, name: `${r.name}@${store.get<{ name: string }>('SELECT name FROM project WHERE id = ?', r.projectId)?.name ?? r.projectId}` } : r));
}

// ---- mention context (data blocks) --------------------------------------------------------------

export function mentionContext(store: Store, mentions: Mention[], nonce: string): string {
  const blocks: string[] = [];
  for (const m of mentions) {
    const r = resolveMention(store, m);
    if (!r.valid) { blocks.push(`- ${m.kind} ${m.id}：已失效（对象已删除）`); continue; }
    let body: string;
    if (m.kind === 'vuln') {
      const v = store.get<Record<string, unknown>>('SELECT v.*, p.name AS project, r.name AS repo FROM vulnerability v JOIN project p ON p.id = v.project_id LEFT JOIN repository r ON r.id = v.repository_id WHERE v.id = ?', m.id)!;
      const detail = v.detail_ref ? store.artifacts.getJson<Record<string, unknown>>(String(v.detail_ref)) : {};
      const ev = store.all<{ kind: string; path: string; start_line: number | null; end_line: number | null; verified: number; note: string | null }>(
        `SELECT kind, path, start_line, end_line, verified, note FROM evidence WHERE owner_kind = 'vulnerability' AND owner_id = ? ORDER BY ord LIMIT 20`, m.id);
      body = JSON.stringify({
        id: m.id, displayNo: `V-${String(v.display_no)}`, project: v.project, repository: v.repo, title: v.title, category: v.category, cwe: v.cwe, severity: v.severity,
        confirmStatus: v.confirm_status, handlingStatus: v.handling_status, lifecycle: v.lifecycle, rev: v.rev, rootCause: v.root_cause,
        pendingCondition: pendingOf(detail as never), evidence: ev.map((e) => `${e.kind} ${e.path}${e.start_line ? `:${e.start_line}-${e.end_line}` : ''}${e.verified ? '' : '（未核实）'}${e.note ? ` ${e.note}` : ''}`),
        reasoning: typeof detail.reasoning === 'string' ? detail.reasoning.slice(0, 3000) : undefined, auditId: vulnAudit(store, m.id),
      }, null, 1);
    } else if (m.kind === 'audit') {
      const a = store.get<Record<string, unknown>>('SELECT a.id, a.title, a.scene, a.mode, a.status, a.created_at, p.name AS project, p.id AS project_id FROM audit a JOIN project p ON p.id = a.project_id WHERE a.id = ?', m.id)!;
      const f = store.all<{ display_no: number | null; title: string; severity: string; confirmation: string }>(`SELECT display_no, title, severity, confirmation FROM finding WHERE audit_id = ? AND state = 'canonical' ORDER BY display_no LIMIT 50`, m.id);
      // Progress: the conversation of a running audit answers “进展如何 / 为什么这么判断” from here and the snapshot.
      const extra = store.get<{ budget_consumed: string; budget_effective: string; partial_reasons: string }>('SELECT budget_consumed, budget_effective, partial_reasons FROM audit WHERE id = ?', m.id)!;
      const steps = store.all<{ kind: string; status: string; n: number }>('SELECT kind, status, COUNT(*) AS n FROM step WHERE audit_id = ? GROUP BY kind, status ORDER BY MIN(seq)', m.id);
      const questions = store.all<{ text: string; status: string; answer: string | null }>('SELECT text, status, answer FROM question WHERE audit_id = ? ORDER BY created_at LIMIT 20', m.id);
      body = JSON.stringify({
        ...a, repositories: auditSnapshots(store, m.id).map((r) => r.name),
        findings: f.map((x) => `F-${x.display_no} [${x.severity}] ${x.title}${x.confirmation === 'pending' ? '（待确认）' : ''}`),
        budget: { consumed: fromJson(extra.budget_consumed, {}), limit: fromJson(extra.budget_effective, {}) }, partialReasons: fromJson(extra.partial_reasons, []),
        steps: steps.map((s) => `${s.kind}:${s.status}×${s.n}`), questions: questions.map((q) => ({ text: q.text.slice(0, 300), status: q.status, ...(q.answer ? { answer: q.answer.slice(0, 300) } : {}) })),
      }, null, 1);
    } else if (m.kind === 'project') {
      const p = store.get<{ id: string; name: string }>('SELECT id, name FROM project WHERE id = ?', m.id)!;
      const repos = store.all<{ id: string; name: string; role: string; is_auditable: number; default_ref: string | null }>('SELECT id, name, role, is_auditable, default_ref FROM repository WHERE project_id = ? ORDER BY name', m.id);
      const counts = store.all<{ confirm_status: string; n: number }>(`SELECT confirm_status, COUNT(*) AS n FROM vulnerability WHERE project_id = ? AND status = 'active' GROUP BY confirm_status`, m.id);
      const audits = store.all<{ id: string; title: string; scene: string; status: string }>('SELECT id, title, scene, status FROM audit WHERE project_id = ? ORDER BY created_at DESC LIMIT 5', m.id);
      body = JSON.stringify({ ...p, repositories: repos, vulnerabilities: Object.fromEntries(counts.map((c) => [c.confirm_status, c.n])), recentAudits: audits }, null, 1);
    } else if (m.kind === 'repo') {
      const r = store.get<Record<string, unknown>>('SELECT r.id, r.name, r.role, r.languages, r.is_auditable, r.default_ref, p.name AS project, p.id AS project_id FROM repository r JOIN project p ON p.id = r.project_id WHERE r.id = ?', m.id)!;
      body = JSON.stringify(r, null, 1);
    } else {
      body = P('conversation.mention_skill', { name: m.id });
    }
    blocks.push(`## ${m.kind} ${r.label}\n${wrapUntrusted(nonce, 'tool_output', `mention:${m.kind}/${m.id}`, body)}`);
  }
  return blocks.join('\n\n');
}

// ---- history --------------------------------------------------------------------------

function cardSummary(c: CardRow): string {
  const d = fromJson<Record<string, unknown>>(c.data, {});
  const state = ({ pending: '待处理', applied: '已应用', dismissed: '已驳回', expired: '已失效', info: '' } as Record<string, string>)[c.state] ?? '';
  return `[卡片·${c.kind}${state ? `·${state}` : ''}] ${String(d.title ?? d.summary ?? c.tool ?? '').slice(0, 200)}`;
}

export function historyText(store: Store, conversationId: string, beforeSeq: number, budgetChars: number): string {
  const rows = store.all<MessageRow>('SELECT * FROM message WHERE conversation_id = ? AND seq < ? ORDER BY seq DESC LIMIT 200', conversationId, beforeSeq);
  const out: string[] = [];
  let used = 0;
  let omitted = 0;
  for (const m of rows) {
    const cards = m.role === 'assistant' ? messageCards(store, m.id).map(cardSummary) : [];
    const text = `${m.role === 'user' ? '用户' : '助手'}：${m.content}${attachmentNote(messageAttachments(m.attachments))}${m.status === 'interrupted' ? '（回复中断）' : ''}${cards.length ? `\n${cards.join('\n')}` : ''}`;
    if (used + text.length > budgetChars) { omitted++; continue; }
    used += text.length;
    out.push(text);
  }
  if (omitted) out.push(`（更早的 ${omitted} 条消息已省略）`);
  return out.reverse().join('\n\n');
}
