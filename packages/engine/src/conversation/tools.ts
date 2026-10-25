// Tools of a conversation reply besides the code tools: read-only product data, and the cards the agent
// proposes for the user to apply. Split out of service.ts `runReply`.
import {
  CONVERSATION_TOOLS, ProposeAnalysis, ProposeAuditPlan, ProposeHunt, ProposeMerge, ProposeProject, ProposeReverify, ProposeRevision, ProposeSplit, ProposeThreatModel, ProposeVulnDrafts,
  ReportInvestigation, DraftConnector, type CodeRef,
} from '@xiezhi/contracts';
import { Type } from 'typebox';
import type { SnapshotView } from '@xiezhi/context';
import { wrapUntrusted, type AuditTool } from '@xiezhi/agent';
import type { Store } from '@xiezhi/store';
import { insertConnectorEvidence, type ConnectorRef } from '../connector-access.js';
import { verifyCodeRef } from '../identity.js';
import { PROJECT_NAME, strategyOverrideIssues } from '../services.js';
import { addRevision } from '../vulns.js';
import { mentionContext } from './context.js';
import { P } from '@xiezhi/knowledge';

/** What the reply's tools work with. */
export interface ReplyToolContext {
  store: Store;
  nonce: string;
  conversationId: string;
  messageId: string;
  /** The user message this reply answers (a threat model source of kind `user_message`). */
  userMessage: string;
  /** Projects the conversation is about (vulnerability numbers V-n are looked up in them). */
  projects: string[];
  /** Repositories in code scope, the first is the default. */
  scope: { name: string }[];
  views: Map<string, SnapshotView>;
  /** Ranges read in this reply, by `repo\u0000path`. */
  reads: Map<string, [number, number][]>;
  /** Skills (and skill files) read in this reply. */
  skillRead: Set<string>;
  /** Show a card in the reply; returns its id. */
  card: (tool: keyof typeof CONVERSATION_TOOLS, data: Record<string, unknown>, target?: { kind: string; id: string; revision?: number }, revisionIds?: string[]) => string;
}

function helpers(rc: ReplyToolContext) {
  const { store, scope, views, reads, projects } = rc;
  const wasRead = (ref: CodeRef): boolean => {
    const repo = ref.repo ?? scope[0]?.name ?? '';
    return (reads.get(`${repo}\u0000${ref.path}`) ?? []).some(([s, e]) => ref.startLine <= e && ref.endLine >= s);
  };
  const checkRefs = (refs: CodeRef[], label: string): string[] => refs.flatMap((ref, i) => {
    const repo = ref.repo ?? scope[0]?.name;
    const v = verifyCodeRef(repo ? views.get(repo) : undefined, ref);
    if (!v.verified) return [`${label}[${i}]: ${v.reason ?? 'invalid location'}`];
    return wasRead(ref) ? [] : [P('feedback.conversation.ref_not_read', { ref: `${label}[${i}]: ${ref.path}:${ref.startLine}-${ref.endLine}` })];
  });
  const callRefs = (ids: string[] | undefined): ConnectorRef[] => (ids ?? []).flatMap((id) => {
    const c = store.get<{ id: string; name: string; operation: string; authoritative: number; response_ref: string | null; response_hash: string | null; created_at: number }>(
      `SELECT cc.id, c.name, cc.operation, cc.authoritative, cc.response_ref, cc.response_hash, cc.created_at FROM connector_call cc JOIN connector c ON c.id = cc.connector_id
       WHERE cc.id = ? AND cc.conversation_id = ? AND cc.step_id = ? AND cc.status = 'ok'`, id, rc.conversationId, rc.messageId);
    return c ? [{ callId: c.id, connector: c.name, operation: c.operation, authoritative: !!c.authoritative, responseRef: c.response_ref, responseHash: c.response_hash, at: c.created_at }] : [];
  });
  // A vulnerability is named by id or by its number `V-n` within the conversation's projects (the model sees
  // V-n in the context; numbers also keep recorded replies replayable).
  const vulnRow = (ref: string) => {
    type V = { id: string; rev: number; project_id: string; confirm_status: string; handling_status: string; severity: string; display_no: number; title: string; status: string };
    const cols = 'SELECT id, rev, project_id, confirm_status, handling_status, severity, display_no, title, status FROM vulnerability';
    const no = /^V-?(\d+)$/i.exec(ref.trim())?.[1];
    if (!no) return store.get<V>(`${cols} WHERE id = ?`, ref);
    const hits = projects.flatMap((p) => store.all<V>(`${cols} WHERE project_id = ? AND display_no = ?`, p, Number(no)));
    return hits.length === 1 ? hits[0] : undefined;
  };
  return { checkRefs, callRefs, vulnRow };
}

/**
 * Read-only product data: lets the agent find what the user refers to without an @-mention.
 */
export function dataTools(rc: ReplyToolContext): AuditTool[] {
  const { store, nonce } = rc;
  const { vulnRow } = helpers(rc);
  // Read-only product data: lets the agent find what the user refers to without an @-mention
  // (“复验订单系统所有标为已修复的漏洞”). Values come from the store but titles and details derive from the
  // audited code and model output, so results are data blocks.
  const data = (source: string, body: unknown) => ({ text: wrapUntrusted(nonce, 'tool_output', source, JSON.stringify(body, null, 1)) });
  const strList = (max: number) => Type.Optional(Type.Array(Type.String({ maxLength: 40 }), { maxItems: max }));
  return [
    {
      name: 'list_projects', kind: 'read', parameters: Type.Object({}, { additionalProperties: false }),
      description: P('tool.list_projects'),
      run: () => data('projects', store.all<{ id: string; name: string; status: string }>('SELECT id, name, status FROM project ORDER BY name LIMIT 200').map((p) => ({
        ...p, repositories: store.get<{ n: number }>('SELECT COUNT(*) AS n FROM repository WHERE project_id = ?', p.id)!.n,
        vulnerabilities: Object.fromEntries(store.all<{ confirm_status: string; n: number }>(`SELECT confirm_status, COUNT(*) AS n FROM vulnerability WHERE project_id = ? AND status = 'active' GROUP BY confirm_status`, p.id).map((r) => [r.confirm_status, r.n])),
      }))),
    },
    {
      name: 'list_repositories', kind: 'read', parameters: Type.Object({ projectId: Type.String({ maxLength: 120 }) }, { additionalProperties: false }),
      description: P('tool.list_repositories'),
      run: (a: { projectId: string }) => data(`repositories:${a.projectId}`, store.all('SELECT id, name, role, is_auditable AS auditable, default_ref AS defaultRef, source_kind AS source FROM repository WHERE project_id = ? ORDER BY name', a.projectId)),
    },
    {
      name: 'list_vulnerabilities', kind: 'read',
      parameters: Type.Object({
        projectId: Type.Optional(Type.String({ maxLength: 120 })), confirmStatus: strList(4), handlingStatus: strList(6), lifecycle: strList(6), severity: strList(5),
        q: Type.Optional(Type.String({ maxLength: 100 })), limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
      }, { additionalProperties: false }),
      description: P('tool.list_vulnerabilities'),
      run: (a: { projectId?: string; confirmStatus?: string[]; handlingStatus?: string[]; lifecycle?: string[]; severity?: string[]; q?: string; limit?: number }) => {
        const where = [`v.status = 'active'`];
        const params: (string | number)[] = [];
        if (a.projectId) { where.push('v.project_id = ?'); params.push(a.projectId); }
        for (const [col, vals] of [['v.confirm_status', a.confirmStatus], ['v.handling_status', a.handlingStatus], ['v.lifecycle', a.lifecycle], ['v.severity', a.severity]] as const) {
          if (vals?.length) { where.push(`${col} IN (${vals.map(() => '?').join(',')})`); params.push(...vals); }
        }
        if (a.q) { where.push('v.title LIKE ?'); params.push(`%${a.q}%`); }
        const rows = store.all<Record<string, unknown>>(
          `SELECT v.id, v.display_no AS displayNo, p.name AS project, r.name AS repository, v.title, v.category, v.severity, v.confirm_status AS confirmStatus,
             v.handling_status AS handlingStatus, v.lifecycle FROM vulnerability v JOIN project p ON p.id = v.project_id LEFT JOIN repository r ON r.id = v.repository_id
           WHERE ${where.join(' AND ')} ORDER BY p.name, v.display_no LIMIT ?`, ...params, Math.min(100, a.limit ?? 50));
        return data('vulnerabilities', rows);
      },
    },
    {
      name: 'get_vulnerability', kind: 'read', parameters: Type.Object({ vulnId: Type.String({ maxLength: 120 }) }, { additionalProperties: false }),
      description: P('tool.get_vulnerability'),
      run: (a: { vulnId: string }) => ({ text: mentionContext(store, [{ kind: 'vuln', id: vulnRow(a.vulnId)?.id ?? a.vulnId }], nonce) }),
    },
    {
      name: 'list_audits', kind: 'read',
      parameters: Type.Object({ projectId: Type.String({ maxLength: 120 }), limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 50 })) }, { additionalProperties: false }),
      description: P('tool.list_audits'),
      run: (a: { projectId: string; limit?: number }) => data(`audits:${a.projectId}`, store.all<{ id: string; title: string; scene: string; status: string; created_at: number }>(
        'SELECT id, title, scene, status, created_at FROM audit WHERE project_id = ? ORDER BY created_at DESC LIMIT ?', a.projectId, a.limit ?? 10).map((x) => ({ ...x, created_at: new Date(x.created_at).toISOString() }))),
    },
    {
      name: 'list_connectors', kind: 'read', parameters: Type.Object({}, { additionalProperties: false }),
      description: P('tool.list_connectors'),
      run: () => data('connectors', store.all<{ id: string; name: string; protocol: string; purpose: string; enabled: number }>('SELECT id, name, protocol, purpose, enabled FROM connector ORDER BY name LIMIT 100')
        .map((c) => ({ ...c, enabled: !!c.enabled }))),
    },
    {
      name: 'list_threat_models', kind: 'read', parameters: Type.Object({ projectId: Type.String({ maxLength: 120 }) }, { additionalProperties: false }),
      description: P('tool.list_threat_models'),
      run: (a: { projectId: string }) => data(`threat_models:${a.projectId}`, store.all<{ id: string; title: string; status: string; sources: number; risks: number }>(
        `SELECT t.id, t.title, t.status, (SELECT COUNT(*) FROM threat_model_source s WHERE s.threat_model_id = t.id) AS sources,
           (SELECT COUNT(*) FROM threat_risk r WHERE r.threat_model_id = t.id) AS risks FROM threat_model t WHERE t.project_id = ? ORDER BY t.created_at DESC LIMIT 20`, a.projectId)),
    },
  ];
}

/** Tools that show a card the user applies or dismisses; nothing changes before that. */
export function cardTools(rc: ReplyToolContext): AuditTool[] {
  const { store, card, skillRead } = rc;
  const { checkRefs, callRefs, vulnRow } = helpers(rc);
  return [
    {
      name: 'report_investigation', kind: 'submit', parameters: ReportInvestigation,
      description: P('tool.report_investigation'),
      validate: (a: ReportInvestigation) => [...checkRefs(a.evidence, 'evidence'), ...(a.vulnId && !vulnRow(a.vulnId) ? [`unknown vulnId ${a.vulnId}`] : [])],
      run: (a: ReportInvestigation) => {
        const knowledge = (a.knowledgeRefs ?? []).filter((r) => skillRead.has(r));
        const connectors = callRefs(a.connectorRefs);
        const vid = a.vulnId ? vulnRow(a.vulnId)?.id ?? null : null;
        const id = card('report_investigation', { title: a.title, conclusion: a.conclusion, evidence: a.evidence, vulnId: vid, knowledgeRefs: knowledge, connectors }, vid ? { kind: 'vuln', id: vid } : undefined);
        return { text: P('feedback.conversation.investigation_shown', { id }) };
      },
    },
    {
      name: 'propose_revision', kind: 'submit', parameters: ProposeRevision,
      description: P('tool.propose_revision'),
      validate: (a: ProposeRevision) => {
        const v = vulnRow(a.vulnId);
        if (!v) return [`unknown vulnId ${a.vulnId}`];
        const issues = checkRefs(a.evidence, 'evidence');
        if (a.confirmStatus === undefined && a.handlingStatus === undefined && a.severity === undefined) issues.push(P('feedback.conversation.revision_empty'));
        if ((a.confirmStatus ?? v.confirm_status) === v.confirm_status && (a.handlingStatus ?? v.handling_status) === v.handling_status && (a.severity ?? v.severity) === v.severity) issues.push(P('feedback.conversation.revision_no_change'));
        const connectors = callRefs(a.connectorRefs);
        // unverified external data alone cannot overturn a conclusion.
        if (a.confirmStatus && a.confirmStatus !== v.confirm_status && connectors.length && connectors.every((c) => !c.authoritative) && a.evidence.length === 0) {
          issues.push(P('feedback.conversation.revision_unverified'));
        }
        return issues;
      },
      run: (a: ProposeRevision) => {
        const v = vulnRow(a.vulnId)!;
        const connectors = callRefs(a.connectorRefs);
        const revisionIds = store.tx(() => {
          const ids: string[] = [];
          const ev = connectors.length ? insertConnectorEvidence(store, 'revision', `conv-${rc.messageId}`, connectors, rc.messageId, 0) : [];
          const dims: [string, unknown, unknown][] = [
            ['confirm', v.confirm_status, a.confirmStatus], ['handling', v.handling_status, a.handlingStatus], ['severity', v.severity, a.severity],
          ];
          for (const [dimension, from, to] of dims) {
            if (to === undefined || to === from) continue;
            ids.push(addRevision(store, v.id, { dimension, source: 'ai', actor: 'conversation', from, to, reason: a.reason, evidenceIds: ev, conversationId: rc.conversationId, state: 'proposed' }));
          }
          if (ev.length && ids[0]) store.db.run(`UPDATE evidence SET owner_id = ? WHERE owner_kind = 'revision' AND owner_id = ?`, ids[0], `conv-${rc.messageId}`);
          return ids;
        });
        const id = card('propose_revision', {
          title: `V-${v.display_no} ${v.title}`, vulnId: v.id, displayNo: v.display_no, from: { confirmStatus: v.confirm_status, handlingStatus: v.handling_status, severity: v.severity },
          to: { ...(a.confirmStatus ? { confirmStatus: a.confirmStatus } : {}), ...(a.handlingStatus ? { handlingStatus: a.handlingStatus } : {}), ...(a.severity ? { severity: a.severity } : {}) },
          reason: a.reason, evidence: a.evidence, connectors,
        }, { kind: 'vuln', id: v.id, revision: v.rev }, revisionIds);
        return { text: P('feedback.conversation.revision_shown', { id }) };
      },
    },
    {
      name: 'propose_audit_plan', kind: 'submit', parameters: ProposeAuditPlan,
      description: P('tool.propose_audit_plan'),
      validate: (a: ProposeAuditPlan) => (store.get('SELECT id FROM project WHERE id = ?', a.request.projectId)
        ? strategyOverrideIssues(store, a.request.scene ?? 'full', a.request.strategyOverride as Record<string, unknown> | undefined)
        : [`unknown projectId ${a.request.projectId}`]),
      run: (a: ProposeAuditPlan) => {
        const p = store.get<{ name: string }>('SELECT name FROM project WHERE id = ?', a.request.projectId)!;
        const id = card('propose_audit_plan', { title: a.request.title ?? `${p.name} · ${a.request.scene === 'incremental' ? '增量' : '全量'}审计`, action: 'audit', project: p.name, request: a.request, rationale: a.rationale, recommended: a.recommended ?? [] }, { kind: 'project', id: a.request.projectId });
        return { text: P('feedback.conversation.audit_plan_shown', { id }) };
      },
    },
    {
      name: 'propose_reverify', kind: 'submit', parameters: ProposeReverify,
      description: P('tool.propose_reverify'),
      validate: (a: ProposeReverify) => a.vulnIds.filter((id) => !vulnRow(id)).map((id) => `unknown vulnId ${id}`),
      run: (a: ProposeReverify) => {
        const vs = a.vulnIds.map((id) => vulnRow(id)!);
        const id = card('propose_reverify', { title: `复验 ${vs.map((v) => `V-${v.display_no}`).join('、')}`, action: 'reverify', vulnIds: vs.map((v) => v.id), vulns: vs.map((v) => ({ id: v.id, displayNo: v.display_no, title: v.title })), note: a.note ?? null, rationale: a.rationale });
        return { text: P('feedback.conversation.reverify_shown', { id }) };
      },
    },
    {
      name: 'propose_hunt', kind: 'submit', parameters: ProposeHunt,
      description: P('tool.propose_hunt'),
      validate: (a: ProposeHunt) => [
        ...(a.projectIds ?? []).filter((id) => !store.get('SELECT id FROM project WHERE id = ?', id)).map((id) => `unknown projectId ${id}`),
        ...(!a.allProjects && !a.projectIds?.length ? [P('feedback.conversation.hunt_scope')] : []),
      ],
      run: (a: ProposeHunt) => {
        const id = card('propose_hunt', { title: a.title ?? '风险排查', action: 'hunt', basis: a.basis, projectIds: a.projectIds ?? [], allProjects: a.allProjects ?? false, rationale: a.rationale });
        return { text: P('feedback.conversation.hunt_shown', { id }) };
      },
    },
    {
      name: 'propose_merge', kind: 'submit', parameters: ProposeMerge,
      description: P('tool.propose_merge'),
      validate: (a: ProposeMerge) => {
        const t = vulnRow(a.targetId);
        if (!t) return [`unknown targetId ${a.targetId}`];
        return a.sourceIds.flatMap((id) => { const s = vulnRow(id); return !s ? [`unknown vulnId ${id}`] : s.project_id !== t.project_id ? [`${id} is in another project`] : s.id === t.id ? [P('feedback.conversation.merge_self')] : []; });
      },
      run: (a: ProposeMerge) => {
        const t = vulnRow(a.targetId)!;
        const src = a.sourceIds.map((id) => vulnRow(id)!);
        const id = card('propose_merge', { title: `合并 ${src.map((v) => `V-${v.display_no}`).join('、')} → V-${t.display_no}`, action: 'merge', targetId: t.id, sourceIds: src.map((v) => v.id), reason: a.reason }, { kind: 'vuln', id: t.id, revision: t.rev });
        return { text: P('feedback.conversation.merge_shown', { id }) };
      },
    },
    {
      name: 'propose_split', kind: 'submit', parameters: ProposeSplit,
      description: P('tool.propose_split'),
      validate: (a: ProposeSplit) => [...(vulnRow(a.vulnId) ? [] : [`unknown vulnId ${a.vulnId}`]), ...(!a.entryKeys?.length && !a.fingerprints?.length ? [P('feedback.conversation.split_empty')] : [])],
      run: (a: ProposeSplit) => {
        const v = vulnRow(a.vulnId)!;
        const id = card('propose_split', { title: `拆分 V-${v.display_no}`, action: 'split', vulnId: v.id, entryKeys: a.entryKeys ?? [], fingerprints: a.fingerprints ?? [], reason: a.reason }, { kind: 'vuln', id: v.id, revision: v.rev });
        return { text: P('feedback.conversation.split_shown', { id }) };
      },
    },
    {
      name: 'draft_connector', kind: 'submit', parameters: DraftConnector,
      description: P('tool.draft_connector'),
      validate: (a: DraftConnector) => {
        const issues = credentialValues(a.config).length ? [P('feedback.conversation.connector_credential', { paths: credentialValues(a.config).join(', ') })] : [];
        if (store.get('SELECT id FROM connector WHERE name = ?', a.name)) issues.push(`a connector named ${a.name} already exists`);
        return issues;
      },
      run: (a: DraftConnector) => {
        const id = card('draft_connector', { title: `连接器草稿 ${a.name}`, action: 'connector', name: a.name, protocol: a.protocol, purpose: a.purpose, config: a.config, secrets: a.secrets ?? [], notes: a.notes ?? null });
        return { text: P('feedback.conversation.connector_draft_shown', { id }) };
      },
    },
    // The rest of the product's AI tasks, still as cards.
    {
      name: 'propose_project', kind: 'submit', parameters: ProposeProject,
      description: P('tool.propose_project'),
      validate: (a: ProposeProject) => {
        const name = a.name.trim();
        const issues = PROJECT_NAME.test(name) ? [] : [P('feedback.conversation.project_name')];
        if (store.get('SELECT id FROM project WHERE name = ?', name)) issues.push(P('feedback.conversation.project_exists', { name }));
        a.repos.forEach((r, i) => { if (!r.path === !r.git) issues.push(`repos[${i}]: give exactly one of path or git`); });
        if (a.audit && !a.repos.length) issues.push(P('feedback.conversation.project_audit_no_repo'));
        if (a.audit?.strategyOverride) issues.push(...strategyOverrideIssues(store, 'full', a.audit.strategyOverride));
        return issues;
      },
      run: (a: ProposeProject) => {
        const id = card('propose_project', {
          title: `新建项目 ${a.name.trim()}`, action: 'project', name: a.name.trim(), repos: a.repos, analyze: a.analyze ?? false, audit: a.audit ?? null, rationale: a.rationale,
        });
        return { text: P('feedback.conversation.project_shown', { id }) };
      },
    },
    {
      name: 'propose_threat_model', kind: 'submit', parameters: ProposeThreatModel,
      description: P('tool.propose_threat_model'),
      validate: (a: ProposeThreatModel) => {
        if (!store.get('SELECT id FROM project WHERE id = ?', a.projectId)) return [`unknown projectId ${a.projectId}`];
        return a.sources.flatMap((s, i) => s.kind === 'online' && !store.get('SELECT id FROM connector WHERE id = ?', s.connectorId) ? [`sources[${i}]: unknown connectorId ${s.connectorId}`]
          : s.kind === 'user_message' && !rc.userMessage.trim() ? [`sources[${i}]: the user message is empty`]
            : s.kind === 'text' && !s.text.trim() ? [`sources[${i}]: empty text`] : []);
      },
      run: (a: ProposeThreatModel) => {
        const p = store.get<{ name: string }>('SELECT name FROM project WHERE id = ?', a.projectId)!;
        // The user's message is copied into the card: applying it later uses exactly what the user wrote.
        const sources = a.sources.map((s) => (s.kind === 'user_message' ? { kind: 'text' as const, title: s.title, text: rc.userMessage } : s));
        const id = card('propose_threat_model', {
          title: a.title, action: 'threat_model', projectId: a.projectId, project: p.name, sources, generate: a.generate ?? true, rationale: a.rationale,
        }, { kind: 'project', id: a.projectId });
        return { text: P('feedback.conversation.threat_model_shown', { id }) };
      },
    },
    {
      name: 'propose_vuln_drafts', kind: 'submit', parameters: ProposeVulnDrafts,
      description: P('tool.propose_vuln_drafts'),
      validate: (a: ProposeVulnDrafts) => (vulnRow(a.vulnId) ? [] : [`unknown vulnId ${a.vulnId}`]),
      run: (a: ProposeVulnDrafts) => {
        const v = vulnRow(a.vulnId)!;
        const id = card('propose_vuln_drafts', { title: `V-${v.display_no} ${v.title}`, action: 'vuln_drafts', vulnId: v.id, displayNo: v.display_no, kinds: a.kinds, rationale: a.rationale }, { kind: 'vuln', id: v.id });
        return { text: P('feedback.conversation.vuln_drafts_shown', { id }) };
      },
    },
    {
      name: 'propose_analysis', kind: 'submit', parameters: ProposeAnalysis,
      description: P('tool.propose_analysis'),
      validate: (a: ProposeAnalysis) => (!store.get('SELECT id FROM project WHERE id = ?', a.projectId) ? [`unknown projectId ${a.projectId}`]
        : store.get('SELECT id FROM repository WHERE project_id = ?', a.projectId) ? [] : [P('feedback.conversation.analysis_no_repo')]),
      run: (a: ProposeAnalysis) => {
        const p = store.get<{ name: string }>('SELECT name FROM project WHERE id = ?', a.projectId)!;
        const id = card('propose_analysis', { title: `${p.name} · 项目分析`, action: 'analysis', projectId: a.projectId, project: p.name, rationale: a.rationale }, { kind: 'project', id: a.projectId });
        return { text: P('feedback.conversation.analysis_shown', { id }) };
      },
    },
  ];
}

/** Paths of credential-like values that do not reference a secret (credentials only in the settings form). */
export function credentialValues(v: unknown, path = ''): string[] {
  if (typeof v === 'string') {
    const key = path.split('.').at(-1) ?? '';
    return /password|passwd|secret|token|api[_-]?key|authorization|cookie/i.test(key) && v.length >= 4 && !v.includes('${secret:') ? [path] : [];
  }
  if (Array.isArray(v)) return v.flatMap((x, i) => credentialValues(x, `${path}[${i}]`));
  if (v && typeof v === 'object') return Object.entries(v).flatMap(([k, x]) => credentialValues(x, path ? `${path}.${k}` : k));
  return [];
}
