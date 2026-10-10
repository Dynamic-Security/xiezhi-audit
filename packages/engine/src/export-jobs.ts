// Export jobs: a deterministic export renders at once and is recorded as a
// finished job; AI reports (ai-report.ts) run in the background. The rows are read here for the API.
import { newId } from '@xiezhi/contracts';
import { exportAudit, type ExportFormat, type ExportOptions } from '@xiezhi/report';
import type { Store } from '@xiezhi/store';

export interface ExportRow {
  id: string; audit_id: string; format: string; status: string; bytes: number; created_at: number; options: string; mode: string; model: string | null;
  tokens: number; progress: string | null; verification: string | null; error: string | null; artifact_ref: string | null; markdown_ref: string | null;
}

export const EXPORT_MIME: Record<ExportFormat, string> = { md: 'text/markdown; charset=utf-8', html: 'text/html; charset=utf-8', json: 'application/json; charset=utf-8', sarif: 'application/sarif+json' };

export function getExportJob(store: Store, id: string): ExportRow | undefined {
  return store.get<ExportRow>('SELECT * FROM export_job WHERE id = ?', id);
}

export function listExportJobs(store: Store, auditId: string): ExportRow[] {
  return store.all<ExportRow>('SELECT * FROM export_job WHERE audit_id = ? ORDER BY created_at DESC', auditId);
}

/**
 * Render a deterministic export now and record it: `succeeded` with the artifact, or `failed` (“render failed”) when
 * rendering threw — `onError` gets the cause for the log. `options` is what the job row shows.
 */
export function renderExport(store: Store, auditId: string, format: ExportFormat, options: Record<string, unknown>, render: ExportOptions, onError?: (e: Error) => void): ExportRow {
  const id = newId('export');
  try {
    const text = exportAudit(store, auditId, format, render);
    const ref = store.artifacts.put(text, EXPORT_MIME[format].split(';')[0]!);
    store.insert('export_job', { id, audit_id: auditId, format, options, status: 'succeeded', artifact_ref: ref, bytes: Buffer.byteLength(text) });
  } catch (e) {
    onError?.(e as Error);
    store.insert('export_job', { id, audit_id: auditId, format, options, status: 'failed', error: 'render failed' });
  }
  return getExportJob(store, id)!;
}
