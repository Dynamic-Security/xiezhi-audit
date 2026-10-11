// Export pipeline: model → renderer → redactor (last step, cannot be disabled).
import { canonicalJson, collectSecrets, redact, appVersion } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { buildReportModel, type ReportModel } from './model.js';
import { renderMarkdown } from './markdown.js';
import { renderSarif } from './sarif.js';
import { renderHtml } from './html.js';
import { buildProjectReportModel } from './project.js';

export { buildReportModel, knowledgeUsage, compareFindings, REPORT_SCHEMA_VERSION, STATIC_AUDIT_NOTE, COVERAGE_NOTE, type ReportModel, type ReportFinding, type ReportFilter, type FindingDetail, type CodeLoc, type KnowledgeUsageItem } from './model.js';
export { renderMarkdown } from './markdown.js';
export { renderSarif, type SarifOptions } from './sarif.js';
export { renderHtml, escapeHtml } from './html.js';

export type ExportFormat = 'md' | 'html' | 'json' | 'sarif';

export const TOOL_VERSION = appVersion();

export function renderJson(m: ReportModel): string {
  return JSON.stringify(JSON.parse(canonicalJson(m)), null, 2) + '\n';
}

import { applyReportTemplate } from './template.js';

export interface ExportOptions {
  snippets?: boolean; localRoots?: boolean; override?: import('./model.js').ReportOverride;
  /** Markdown template of the chosen report skill; other formats ignore it. */
  template?: string | null;
  /** Selected vulnerabilities, pending findings, trajectory summary. */
  filter?: import('./model.js').ReportFilter;
}

export function exportAudit(store: Store, auditId: string, format: ExportFormat, opts: ExportOptions = {}): string {
  return renderModel(store, buildReportModel(store, auditId, opts.override, opts.filter), format, opts);
}

/** Project-level export: every active vulnerability of the project across audits, same renderers and redaction. */
export function exportProject(store: Store, projectId: string, format: ExportFormat, opts: Omit<ExportOptions, 'override'> = {}): string {
  const f = opts.filter ?? {};
  const filter = { ...(f.vulnIds ? { vulnIds: f.vulnIds } : {}), ...(f.includePending === false ? { includePending: false } : {}) };
  return renderModel(store, buildProjectReportModel(store, projectId, filter), format, opts);
}

function renderModel(store: Store, model: ReportModel, format: ExportFormat, opts: ExportOptions): string {
  const secrets = collectSecrets(store.config);
  const snippets = opts.snippets ?? store.config.export.snippets;
  if (format === 'sarif') {
    // SARIF keeps audited-code content verbatim for IDE navigation; only configured credentials are removed.
    const text = renderSarif(model, { snapshotsDir: store.paths.snapshots, snippets, localRoots: opts.localRoots ?? store.config.export.localRoots, toolVersion: TOOL_VERSION });
    return redact(text, { secrets });
  }
  const md = format === 'md' ? renderMarkdown(model) : '';
  const text = format === 'md' ? (opts.template ? applyReportTemplate(md, opts.template) : md) : format === 'html' ? renderHtml(model) : renderJson(model);
  return redact(text, { ...store.redactOptions() });
}
export { buildProjectReportModel } from './project.js';
export { renderHuntReport, type HuntReportModel } from './hunt.js';
export { applyReportTemplate, TEMPLATE_SECTIONS } from './template.js';
export {
  reportFacts, aiReportInput, aiReportRules, verifyAiReport, annotateAiReport, markdownToHtml, aiReportHtml, SEVERITY_ZH, CONFIRM_STATUS_ZH, type ReportFact,
} from './ai.js';
export { htmlPage } from './html.js';
