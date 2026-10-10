// What the phase-4 sessions about one vulnerability see: the vulnerability, its latest
// finding (location, evidence, chain, attack path) and the snapshot that finding was made on — read-only, as data.
import { join } from 'node:path';
import { Type } from 'typebox';
import { AppError, type SnapshotManifest } from '@xiezhi/contracts';
import { pluginFor, SnapshotView } from '@xiezhi/context';
import { wrapUntrusted, type AuditTool } from '@xiezhi/agent';
import { P } from '@xiezhi/knowledge';
import { fromJson, type Store } from '@xiezhi/store';

export interface CodeLoc { repo: string; path: string; startLine: number; endLine: number }

export interface VulnContext {
  vuln: { id: string; project_id: string; display_no: number; title: string; category: string; cwe: string | null; severity: string; confirm_status: string; sink_api: string | null; root_cause: string | null; repository_id: string };
  findingId: string;
  auditId: string;
  origin: CodeLoc;
  /** The audit language of the origin file (`java`, `go`, …), or null. */
  lang: string | null;
  view: SnapshotView;
  detail: Record<string, unknown>;
}

/** The vulnerability with its latest finding and that audit's snapshot of the repository. */
export function vulnContext(store: Store, vulnId: string): VulnContext {
  const vuln = store.get<VulnContext['vuln']>(
    `SELECT id, project_id, display_no, title, category, cwe, severity, confirm_status, sink_api, root_cause, repository_id FROM vulnerability WHERE id = ? AND status = 'active'`, vulnId);
  if (!vuln) throw new AppError('COMMON_NOT_FOUND', `vulnerability ${vulnId}`);
  const f = store.get<{ id: string; audit_id: string; repository_id: string; location: string; detail_ref: string }>(
    `SELECT f.id, f.audit_id, f.repository_id, f.location, f.detail_ref FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id
     WHERE o.vulnerability_id = ? ORDER BY o.created_at DESC, o.rowid DESC LIMIT 1`, vulnId);
  if (!f) throw new AppError('COMMON_VALIDATION', 'the vulnerability has no finding to start from');
  const snap = store.get<{ root_hash: string; manifest_ref: string; name: string }>(
    `SELECT s.root_hash, s.manifest_ref, r.name FROM audit_repository ar JOIN snapshot s ON s.id = ar.snapshot_id JOIN repository r ON r.id = ar.repository_id
     WHERE ar.audit_id = ? AND ar.repository_id = ?`, f.audit_id, f.repository_id);
  if (!snap) throw new AppError('COMMON_VALIDATION', 'the snapshot of the finding is not available');
  const view = new SnapshotView(snap.name, join(store.paths.snapshots, snap.root_hash), store.artifacts.getJson<SnapshotManifest>(snap.manifest_ref));
  const loc = fromJson<{ path: string; startLine: number; endLine: number }>(f.location, { path: '', startLine: 1, endLine: 1 });
  const lang = view.file(loc.path)?.lang;
  return {
    vuln, findingId: f.id, auditId: f.audit_id, origin: { repo: snap.name, path: loc.path, startLine: loc.startLine, endLine: loc.endLine },
    lang: lang ? pluginFor(lang)?.id ?? null : null, view, detail: store.artifacts.getJson<Record<string, unknown>>(f.detail_ref),
  };
}

/** Numbered lines of a file in the snapshot (clamped), as data. */
export function snippet(view: SnapshotView, path: string, start: number, end: number): string {
  const lines = view.lines(path);
  const s = Math.max(1, start);
  const e = Math.min(lines.length, end);
  return lines.slice(s - 1, e).map((l, i) => `${String(s + i).padStart(5)}  ${l}`).join('\n');
}

export function remediationText(r: string | { approach?: string; suggestion?: string; verification?: string } | undefined): string {
  if (!r) return '';
  if (typeof r === 'string') return r;
  return [r.approach, r.suggestion, r.verification ? `复验：${r.verification}` : ''].filter(Boolean).join('；');
}

/** The vulnerability, its evidence and the code around the origin, for a session prompt (the code inside the data boundary). */
export function vulnBrief(c: VulnContext, nonce: string, around = 30): string {
  const d = c.detail as { evidence?: { path?: string; startLine?: number; endLine?: number; note?: string }[]; chain?: { path?: string; startLine?: number; note?: string }[]; attackPath?: string; impact?: string; exploitConditions?: unknown; remediation?: string | { approach?: string; suggestion?: string; verification?: string } };
  const head = [
    `## 漏洞 V-${c.vuln.display_no}：${c.vuln.title}`,
    `- 类别：${c.vuln.category}${c.vuln.cwe ? `（${c.vuln.cwe}）` : ''}；严重度：${c.vuln.severity}；确认状态：${c.vuln.confirm_status}`,
    `- 位置：${c.origin.repo}:${c.origin.path}:${c.origin.startLine}-${c.origin.endLine}${c.vuln.sink_api ? `；危险点：${c.vuln.sink_api}` : ''}`,
    ...(c.vuln.root_cause ? [`- 根因：${c.vuln.root_cause}`] : []),
    ...(d.attackPath ? [`- 攻击路径：${d.attackPath}`] : []),
    ...(d.impact ? [`- 影响：${d.impact}`] : []),
    // Findings store remediation as { approach, suggestion?, verification? } (SubmitFindings); older details as text.
    ...(remediationText(d.remediation) ? [`- 发现时的修复建议：${remediationText(d.remediation)}`] : []),
  ].join('\n');
  const ev = [...(d.chain ?? []), ...(d.evidence ?? [])].filter((x) => x.path).slice(0, 12)
    .map((x) => `- ${x.path}:${x.startLine ?? '?'}${x.note ? `  ${x.note}` : ''}`).join('\n');
  const code = snippet(c.view, c.origin.path, c.origin.startLine - around, c.origin.endLine + around);
  return [wrapUntrusted(nonce, 'tool_output', `vuln:V-${c.vuln.display_no}`, head + (ev ? `\n\n证据与调用链：\n${ev}` : '')), '', `原位置代码（${c.origin.path}）：`, wrapUntrusted(nonce, 'repo_file', c.origin.path, code)].join('\n');
}

/** Read lines of a snapshot file (at most 200 per call), as data. */
export function readSnapshotTool(view: SnapshotView, nonce: string): AuditTool {
  return {
    name: 'read_snapshot', kind: 'read', description: P('tool.read_snapshot'),
    parameters: Type.Object({ path: Type.String({ maxLength: 500 }), startLine: Type.Optional(Type.Integer({ minimum: 1 })), endLine: Type.Optional(Type.Integer({ minimum: 1 })) }, { additionalProperties: false }),
    run: (a: { path: string; startLine?: number; endLine?: number }) => {
      let path: string;
      try { path = view.guard(a.path); } catch (e) { return { text: `error: ${(e as Error).message}` }; }
      const s = a.startLine ?? 1;
      const e = Math.min(a.endLine ?? s + 199, s + 199);
      return { text: wrapUntrusted(nonce, 'repo_file', path, snippet(view, path, s, e) || '（空）') };
    },
  };
}
