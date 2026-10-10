// the domain plan of an audit, visible and adjustable while the audit runs, without blocking it
// (like the hypothesis list). A person adds a domain, removes one, or adds focus to one; the edit is an audit
// event that planDomains applies. Added during the expert phase: the stage picks it up in its next round. Added after
// the phase ended: it is `late` and runs in a supplement (追加执行) once the audit is finished.
import { VULN_CATEGORIES, type DomainPlanDto, type DomainPlanEditBody } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { planDomainsOf, type DomainEdit, type PlanSource, type PlannedDomain } from './domains.js';

export class DomainPlanError extends Error {
  constructor(readonly code: 'NOT_FOUND' | 'INVALID' | 'NOT_PLANNED', message: string) { super(message); }
}

/** Recorded once by the expert stage when it ends; a domain added later is `late`. */
export const EXPERTS_DONE = 'domain_experts_done';

function auditRepos(store: Store, auditId: string): { id: string; name: string }[] {
  return store.all<{ id: string; name: string }>(
    'SELECT r.id, r.name FROM audit_repository ar JOIN repository r ON r.id = ar.repository_id WHERE ar.audit_id = ? ORDER BY r.name', auditId);
}

export function planSource(store: Store, auditId: string): PlanSource {
  return { store, auditId, repos: auditRepos(store, auditId) };
}

function judged(store: Store, auditId: string, kind: string): boolean {
  return !!store.get(`SELECT 1 FROM event WHERE audit_id = ? AND type = 'judgement.made' AND json_extract(payload, '$.kind') = ? LIMIT 1`, auditId, kind);
}

/** Whether the audit recorded a domain plan (the threat model has run and the experts are about to start). */
export function domainPlanned(store: Store, auditId: string): boolean {
  return judged(store, auditId, 'domain_plan');
}

export function expertsDone(store: Store, auditId: string): boolean {
  return judged(store, auditId, EXPERTS_DONE);
}

/** Late domains already run by a supplement: domain id → supplement audit id. */
function supplementedDomains(store: Store, auditId: string): Map<string, string> {
  const out = new Map<string, string>();
  const rows = store.all<{ id: string; scope: string }>(
    `SELECT id, scope FROM audit WHERE base_audit_id = ? AND json_extract(scope, '$.supplement.kind') = 'domains' AND status NOT IN ('cancelled','failed') ORDER BY created_at`, auditId);
  for (const r of rows) for (const d of (JSON.parse(r.scope) as { supplement: { domainIds?: string[] } }).supplement.domainIds ?? []) out.set(d, r.id);
  return out;
}

/** Late domains of a finished audit that no supplement has run yet. */
export function pendingLateDomains(store: Store, auditId: string): PlannedDomain[] {
  const done = supplementedDomains(store, auditId);
  return planDomainsOf(planSource(store, auditId)).filter((d) => d.late && !d.removed && !done.has(d.id));
}

/** The plan with the expert rounds run so far (per domain, every model). */
export function domainPlanView(store: Store, auditId: string): DomainPlanDto {
  const a = store.get<{ status: string; scene: string }>('SELECT status, scene FROM audit WHERE id = ?', auditId);
  if (!a) throw new DomainPlanError('NOT_FOUND', `audit ${auditId} not found`);
  if (!domainPlanned(store, auditId)) return { planned: false, phase: 'not_planned', editable: false, supplementable: false, domains: [] };
  const done = expertsDone(store, auditId);
  const finished = ['completed', 'partial'].includes(a.status);
  const sup = supplementedDomains(store, auditId);
  const steps = store.all<{ id: string; lineage_id: string; status: string; findings: number; provider: string | null; model: string | null }>(
    `SELECT s.id, s.lineage_id, s.status, s.provider, s.model, (SELECT COUNT(*) FROM finding f WHERE f.step_id = s.id) AS findings
     FROM step s WHERE s.audit_id = ? AND s.kind = 'hunt' AND s.lineage_id LIKE 'DOM-%' ORDER BY s.seq`, auditId);
  const domains = planDomainsOf(planSource(store, auditId)).map((d) => ({
    id: d.id, name: d.name, focus: d.focus, userFocus: d.userFocus ?? [], categories: d.categories, source: d.source,
    removed: !!d.removed, late: !!d.late, supplementAuditId: sup.get(d.id) ?? null,
    rounds: steps.filter((s) => new RegExp(`^DOM(-M\\d+)?-${d.id}-R\\d+$`).test(s.lineage_id)).map((s) => ({
      round: Number(/-R(\d+)$/.exec(s.lineage_id)![1]), status: s.status, findings: s.findings,
      ...(/^DOM-M\d+-/.test(s.lineage_id) && s.model ? { model: s.provider ? `${s.provider}/${s.model}` : s.model } : {}),
      slot: /^DOM-M(\d+)-/.exec(s.lineage_id)?.[1] ?? '',
    })).sort((x, y) => x.slot.localeCompare(y.slot) || x.round - y.round).map(({ slot: _, ...r }) => r),
  }));
  return {
    planned: true, phase: done ? 'done' : 'experts',
    editable: !['cancelled', 'cancelling', 'failed'].includes(a.status),
    supplementable: finished && domains.some((d) => d.late && !d.removed && !d.supplementAuditId),
    domains,
  };
}

const TEXT_MAX = 800;

/**
 * Apply one edit. Checked and recorded in one transaction with the stage's “experts done” mark, so a domain
 * is either picked up by the running stage or marked late — never lost in between.
 */
export function editDomainPlan(store: Store, auditId: string, input: DomainPlanEditBody, actor = 'user'): DomainPlanDto {
  store.tx(() => {
    const a = store.get<{ status: string; scene: string }>('SELECT status, scene FROM audit WHERE id = ?', auditId);
    if (!a) throw new DomainPlanError('NOT_FOUND', `audit ${auditId} not found`);
    if (!['full', 'incremental'].includes(a.scene)) throw new DomainPlanError('INVALID', 'domain plans belong to full and incremental audits');
    if (['cancelled', 'cancelling', 'failed'].includes(a.status)) throw new DomainPlanError('INVALID', `audit is ${a.status}`);
    if (!domainPlanned(store, auditId)) throw new DomainPlanError('NOT_PLANNED', '领域规划还没有生成（威胁建模完成后才有）');
    const plan = planDomainsOf(planSource(store, auditId));
    const live = plan.filter((d) => !d.removed);
    const done = expertsDone(store, auditId) || ['completed', 'partial'].includes(a.status);
    const find = (id: string | undefined) => {
      const d = live.find((x) => x.id === id);
      if (!d) throw new DomainPlanError('INVALID', `unknown or removed domain ${id ?? ''}`);
      return d;
    };
    let edit: DomainEdit;
    if (input.op === 'add') {
      const name = input.name?.trim() ?? '';
      const categories = [...new Set(input.categories ?? [])];
      if (!name || name.length > 60) throw new DomainPlanError('INVALID', 'name: 1–60 characters');
      if (live.some((d) => d.name === name)) throw new DomainPlanError('INVALID', `a domain named ${name} exists`);
      if (!categories.length || categories.some((c) => !(VULN_CATEGORIES as readonly string[]).includes(c))) throw new DomainPlanError('INVALID', 'categories: at least one known vulnerability category');
      const focus = input.focus?.trim() ?? '';
      if (!focus || focus.length > TEXT_MAX) throw new DomainPlanError('INVALID', `focus: 1–${TEXT_MAX} characters`);
      const next = Math.max(0, ...plan.map((d) => Number(d.id.slice(1)))) + 1;
      edit = { op: 'add', id: `D${next}`, name, focus, categories, late: done, actor };
    } else if (input.op === 'remove') {
      const d = find(input.domainId);
      // After the expert phase only a late domain not yet run can still be taken out.
      if (done && !d.late) throw new DomainPlanError('INVALID', '专家阶段已结束，删除不再影响本次审计');
      edit = { op: 'remove', domainId: d.id, actor };
    } else {
      const d = find(input.domainId);
      const text = input.text?.trim() ?? '';
      if (!text || text.length > TEXT_MAX) throw new DomainPlanError('INVALID', `text: 1–${TEXT_MAX} characters`);
      if (done && !d.late) throw new DomainPlanError('INVALID', '专家阶段已结束，补充的关注点不再生效');
      edit = { op: 'focus', domainId: d.id, text, actor };
    }
    store.appendEvent(auditId, 'judgement.made', { kind: 'domain_edit', ...edit });
  });
  return domainPlanView(store, auditId);
}

