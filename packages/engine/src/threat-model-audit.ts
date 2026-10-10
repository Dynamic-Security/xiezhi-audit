// Audits that reference requirement threat models. When the audit's knowledge is
// frozen, the referenced threat models are frozen with it (clarification, risks and the people's decisions at that
// moment) and enter the sessions as business knowledge: a summary injected in the profile / hunt / challenge /
// reconcile phases and the full text on demand. Risks to mitigate (or mitigated) become threat-model hypotheses the
// verification batches check; findings may name the risk they relate to, and a new vulnerability related to a risk a
// person accepted or ruled out gets that decision by rule.
import { createHash } from 'node:crypto';
import { AppError, newId, type Scene, type ThreatRiskStatus } from '@xiezhi/contracts';
import type { FrozenKnowledge, FrozenSkill } from '@xiezhi/knowledge';
import { fromJson, type ArtifactStore, type Store } from '@xiezhi/store';
import { Type, type TSchema } from 'typebox';
import type { AuditRuntime } from './runtime.js';
import { addRevision } from './vulns.js';
import { P } from '@xiezhi/knowledge';

export interface ThreatSnapshotRisk {
  id: string; no: number; code: string; category: string; level: string | null; statement: string; impact: string | null; mitigation: string | null;
  features: string[]; status: ThreatRiskStatus; reason: string | null;
}
export interface ThreatSnapshot { id: string; key: string; title: string; clarified: boolean; clarification: string | null; risks: ThreatSnapshotRisk[] }
/** The frozen knowledge of an audit, with the threat models it references. */
export type AuditKnowledge = FrozenKnowledge & { threatModels?: ThreatSnapshot[] };

const STATUS_LABEL: Record<ThreatRiskStatus, string> = { pending: '待研判', to_mitigate: '需规避', mitigated: '已规避', accepted: '接受风险', false_positive: '误报 / 不适用' };
const VERIFY: ThreatRiskStatus[] = ['to_mitigate', 'mitigated'];
const SUMMARY_SKILL = 'req-threat-summary';
/** The on-demand skill of one referenced threat model: TM1 → req-threat-tm1. */
const fullSkill = (key: string) => `req-threat-${key.toLowerCase()}`;
const flat = (t: string | null | undefined, n: number) => (t ?? '').replace(/\s+/g, ' ').replace(/[<>]/g, '').trim().slice(0, n);

/** The threat models a new audit may reference: of the same project, generated, full / incremental audits only. */
export function checkAuditThreatModels(store: Store, projectId: string, scene: Scene, ids: string[] | undefined): void {
  if (!ids?.length) return;
  if (scene !== 'full' && scene !== 'incremental') throw new AppError('STRATEGY_INVALID', 'threatModels: only full and incremental audits reference threat models');
  if (new Set(ids).size !== ids.length) throw new AppError('STRATEGY_INVALID', 'threatModels: listed twice');
  for (const id of ids) {
    const tm = store.get<{ project_id: string; generated_at: number | null; status: string }>('SELECT project_id, generated_at, status FROM threat_model WHERE id = ?', id);
    if (!tm) throw new AppError('STRATEGY_INVALID', `threatModels: unknown threat model ${id}`);
    if (tm.project_id !== projectId) throw new AppError('STRATEGY_INVALID', `threatModels: ${id} belongs to another project`);
    if (!tm.generated_at || tm.status === 'generating') throw new AppError('STRATEGY_INVALID', `threatModels: ${id} has not been generated`);
  }
}

/** The referenced threat models as they are now (TM1, TM2 … in the listed order). */
export function threatSnapshots(store: Store, ids: string[]): ThreatSnapshot[] {
  return ids.flatMap((id, i) => {
    const tm = store.get<{ id: string; title: string; clarification_ref: string | null; clarified_at: number | null }>('SELECT id, title, clarification_ref, clarified_at FROM threat_model WHERE id = ?', id);
    if (!tm) return [];
    const key = `TM${i + 1}`;
    const risks = store.all<{ id: string; no: number; category: string; level: string | null; statement: string; impact: string | null; mitigation: string | null; features: string; status: ThreatRiskStatus; reason: string | null }>(
      'SELECT id, no, category, level, statement, impact, mitigation, features, status, reason FROM threat_risk WHERE threat_model_id = ? ORDER BY no', id)
      .map((r) => ({ ...r, code: `${key}-R${r.no}`, features: fromJson<string[]>(r.features, []) }));
    return [{ id: tm.id, key, title: tm.title, clarified: !!tm.clarified_at, clarification: tm.clarification_ref ? store.artifacts.getText(tm.clarification_ref) : null, risks }];
  });
}

function skill(artifacts: ArtifactStore, name: string, description: string, load: FrozenSkill['load'], verified: boolean, text: string): FrozenSkill {
  const ref = artifacts.put(text, 'text/markdown');
  return {
    name, description, category: 'business', layer: 'project', load, appliesTo: {}, cwe: [], tags: ['threat-model'], verified,
    sha256: createHash('sha256').update(text).digest('hex'), files: { 'SKILL.md': ref }, entryFile: 'SKILL.md',
  };
}

/**
 * Knowledge from the referenced threat models: one summary (rules and the risk table, ≤ ~1.5k tokens) injected in the
 * phases that judge findings, and one skill per threat model with its clarification and risk details, read on demand.
 */
export function threatModelSkills(snaps: ThreatSnapshot[], artifacts: ArtifactStore): FrozenSkill[] {
  if (!snaps.length) return [];
  const lines: string[] = [];
  let budget = 3_000;
  for (const s of snaps) {
    lines.push(`### ${s.key}「${flat(s.title, 60)}」（功能澄清${s.clarified ? '已由人确认' : '未经人确认，只作推测'}；全文：load_skill ${fullSkill(s.key)}）`);
    for (const r of s.risks) {
      const line = `- ${r.code} [${STATUS_LABEL[r.status]}] ${flat(r.statement, 120)}${r.reason ? `（研判理由：${flat(r.reason, 80)}）` : ''}`;
      if ((budget -= line.length) < 0) { lines.push('- ……（其余风险见全文）'); break; }
      lines.push(line);
    }
  }
  const summary = [
    P('req_threat.summary_note'),
    '',
    P('req_threat.summary_rules'),
    '',
    '## 需求风险',
    ...lines,
  ].join('\n');
  return [
    skill(artifacts, SUMMARY_SKILL, P('req_threat.summary_description'), { mode: 'phase', phases: ['profile', 'hunt', 'challenge', 'reconcile'] }, snaps.every((s) => s.clarified), summary),
    ...snaps.map((s) => skill(artifacts, fullSkill(s.key), P('req_threat.full_description', { key: s.key, title: flat(s.title, 60) }),
      { mode: 'on_demand' }, s.clarified, [
        `# ${s.key} ${flat(s.title, 100)}`, '', '## 功能澄清', s.clarification ?? '（无）', '', '## 需求风险',
        ...s.risks.map((r) => [`### ${r.code} [${STATUS_LABEL[r.status]}]${r.level ? ` 等级 ${r.level}` : ''} 类别 ${r.category}`, `- 风险：${r.statement}`, ...(r.impact ? [`- 影响：${r.impact}`] : []), ...(r.mitigation ? [`- 规避建议：${r.mitigation}`] : []), ...(r.features.length ? [`- 关联功能：${r.features.join('、')}`] : []), ...(r.reason ? [`- 研判理由：${r.reason}`] : [])].join('\n')),
      ].join('\n'))),
  ];
}

/** Freeze the referenced threat models into the audit's knowledge (called where the knowledge is frozen). */
export function withThreatModels(store: Store, frozen: FrozenKnowledge, ids: string[] | undefined): AuditKnowledge {
  if (!ids?.length) return frozen;
  const snaps = threatSnapshots(store, ids);
  const own = new Set([SUMMARY_SKILL, ...snaps.map((s) => fullSkill(s.key))]);
  return { skills: [...frozen.skills.filter((s) => !own.has(s.name)), ...threatModelSkills(snaps, store.artifacts)], threatModels: snaps };
}

export function linkedThreatModels(rt: AuditRuntime): ThreatSnapshot[] {
  return (rt.knowledge as AuditKnowledge).threatModels ?? [];
}

/** Risks this audit verifies: to mitigate, or mitigated (regression). */
export function requirementRisksOn(rt: AuditRuntime): boolean {
  return linkedThreatModels(rt).some((s) => s.risks.some((r) => VERIFY.includes(r.status)));
}

const PRIORITY: Record<string, number> = { high: 5, medium: 3, low: 1 };

/**
 * The risks to verify as threat-model hypotheses of the first target repository (idempotent: one per risk and
 * audit). The verification verdict reads: confirmed = the risk is present in the code, refuted = mitigated.
 */
export function seedRequirementHypotheses(rt: AuditRuntime): number {
  const repo = rt.targets[0];
  if (!repo) return 0;
  const have = new Set(rt.store.all<{ threat_risk_id: string }>('SELECT threat_risk_id FROM hypothesis WHERE audit_id = ? AND threat_risk_id IS NOT NULL', rt.auditId).map((h) => h.threat_risk_id));
  let n = 0;
  rt.store.tx(() => {
    for (const s of linkedThreatModels(rt)) for (const r of s.risks) {
      if (!VERIFY.includes(r.status) || have.has(r.id)) continue;
      const mitigated = r.status === 'mitigated';
      rt.store.insert('hypothesis', {
        id: newId('hypothesis'), audit_id: rt.auditId, step_id: null, project_id: rt.audit.project_id, repository_id: repo.id, category: r.category,
        statement: `需求风险 ${r.code}：${flat(r.statement, 600)}${mitigated ? P('req_threat.mitigated_hint') : ''}`,
        location: null, entry_key: null, attempts: '', status: 'proposed', origin: 'threat_model', priority: PRIORITY[r.level ?? ''] ?? 3,
        basis: flat(`需求威胁模型 ${s.key}「${s.title}」，人工研判：${STATUS_LABEL[r.status]}${r.reason ? `（${r.reason}）` : ''}。${r.mitigation ? `规避建议：${r.mitigation}` : ''}${r.features.length ? ` 关联功能：${r.features.join('、')}` : ''}`, 1000),
        related: { entries: [], files: [], models: [`requirement:${s.key}`] }, threat_risk_id: r.id,
      });
      n++;
    }
  });
  if (n) rt.event('judgement.made', { kind: 'requirement_risks', hypotheses: n, threat_models: linkedThreatModels(rt).map((s) => s.key) });
  return n;
}

/** A risk code a finding names (TM1-R3; R3 when only one threat model is referenced). */
export function resolveRelatedRisk(rt: AuditRuntime, code: string | undefined): ThreatSnapshotRisk | null {
  if (!code?.trim()) return null;
  const c = code.trim().toUpperCase();
  const snaps = linkedThreatModels(rt);
  const full = /^TM\d+-R\d+$/.test(c) ? c : /^R\d+$/.test(c) && snaps.length === 1 ? `${snaps[0]!.key}-${c}` : null;
  return full ? snaps.flatMap((s) => s.risks).find((r) => r.code === full) ?? null : null;
}

/** The submit schema with `relatedRisk` on each finding — only for audits that reference threat models. */
export function withRelatedRisk(schema: TSchema): TSchema {
  const s = schema as unknown as { properties: Record<string, TSchema & { items?: TSchema & { properties: Record<string, TSchema> } }> };
  const findings = s.properties.findings!;
  const item = findings.items!;
  return Type.Object({
    ...s.properties,
    findings: Type.Array(Type.Object({
      ...item.properties,
      relatedRisk: Type.Optional(Type.String({ maxLength: 32, description: P('tool.field.related_risk') })),
    }, { additionalProperties: false }), { maxItems: (findings as { maxItems?: number }).maxItems ?? 50 }),
  }, { additionalProperties: false });
}

export function relatedRiskIssues(rt: AuditRuntime, findings: { relatedRisk?: string }[]): string[] {
  return findings.flatMap((f, i) => (f.relatedRisk?.trim() && !resolveRelatedRisk(rt, f.relatedRisk) ? [P('feedback.related_risk.unknown', { i, risk: f.relatedRisk })] : []));
}

/**
 * After publishing: a vulnerability first found in this audit whose finding relates to a risk a
 * person accepted, ruled out or marked mitigated gets that decision by rule (mitigated → false positive) (`source = rule`, actor `threat_risk:<id>`, the person's
 * reason quoted). Vulnerabilities a person already decided on are left alone. Every related vulnerability keeps the
 * risk (`vulnerability.threat_risk`) so the list can fold the handled ones.
 */
export function applyRiskDecisions(rt: AuditRuntime): number {
  const { store } = rt;
  if (!linkedThreatModels(rt).length) return 0;
  const byId = new Map(linkedThreatModels(rt).flatMap((s) => s.risks.map((r) => [r.id, { r, s }] as const)));
  // The related risk of a vulnerability: its own finding's, or one merged into it.
  const rows = store.all<{ vulnerability_id: string; related_risk: string; created_audit: string | null }>(
    `SELECT o.vulnerability_id, COALESCE(f.related_risk, (SELECT s.related_risk FROM finding_merge m JOIN finding s ON s.id = m.source_finding_id
       WHERE m.target_finding_id = f.id AND s.related_risk IS NOT NULL LIMIT 1)) AS related_risk,
       (SELECT o2.audit_id FROM vuln_occurrence o2 WHERE o2.vulnerability_id = o.vulnerability_id ORDER BY o2.created_at LIMIT 1) AS created_audit
     FROM vuln_occurrence o JOIN finding f ON f.id = o.finding_id WHERE o.audit_id = ?`, rt.auditId).filter((x) => x.related_risk);
  let n = 0;
  store.tx(() => {
    for (const row of rows) {
      const hit = byId.get(row.related_risk);
      if (!hit) continue;
      const { r, s } = hit;
      const v = store.get<{ confirm_status: string; handling_status: string; sources: string }>('SELECT confirm_status, handling_status, sources FROM vulnerability WHERE id = ?', row.vulnerability_id);
      if (!v) continue;
      store.update('vulnerability', { id: row.vulnerability_id }, { threat_risk: { riskId: r.id, code: r.code, threatModelId: s.id, title: s.title, status: r.status } });
      const human = fromJson<string[]>(v.sources, []).includes('human');
      if (row.created_audit !== rt.auditId || human) continue;
      const reason = `需求风险 ${r.code}（${s.title}）的人工研判：${STATUS_LABEL[r.status]}${r.reason ? `，理由：${r.reason}` : ''}${r.status === 'mitigated' ? '。按“已规避”自动标为误报；审计仍提交了相关发现，请复核规避措施是否覆盖这里' : ''}`.slice(0, 2000);
      const actor = `threat_risk:${r.id}`;
      if ((r.status === 'false_positive' || r.status === 'mitigated') && v.confirm_status !== 'false_positive') {
        addRevision(store, row.vulnerability_id, { dimension: 'confirm', source: 'rule', actor, from: v.confirm_status, to: 'false_positive', reason, auditId: rt.auditId });
        store.update('vulnerability', { id: row.vulnerability_id }, { confirm_status: 'false_positive', pending_kind: null });
        n++;
      } else if (r.status === 'accepted' && v.handling_status !== 'risk_accepted') {
        addRevision(store, row.vulnerability_id, { dimension: 'handling', source: 'rule', actor, from: v.handling_status, to: 'risk_accepted', reason, auditId: rt.auditId });
        store.update('vulnerability', { id: row.vulnerability_id }, { handling_status: 'risk_accepted', handling_reason: reason });
        n++;
      }
    }
  });
  if (n) rt.event('judgement.made', { kind: 'requirement_risk_decisions', vulnerabilities: n });
  return n;
}

