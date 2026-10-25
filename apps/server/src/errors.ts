// Unified error mapping: business code throws AppError with a closed
// code; the API returns fixed messages + requestId. Raw exception text only reaches the (redacted)
// log and the in-memory ring buffer used by diagnostics.
import {
  AppError, ERROR_CODES, ERROR_HTTP_STATUS, redact, type ApiErrorBody, type ErrorCode, type RedactOptions,
} from '@xiezhi/contracts';

export interface RecentError { ts: string; requestId: string; code: string; message: string }

export class ErrorRing {
  private items: RecentError[] = [];
  push(e: RecentError): void {
    this.items.push(e);
    if (this.items.length > 50) this.items.shift();
  }
  list(): RecentError[] {
    return [...this.items].reverse();
  }
}

/** Only these detail keys may reach clients (whitelist). */
const DETAIL_KEYS = new Set(['revision', 'status', 'field', 'issues', 'holder', 'expected', 'errors', 'current', 'references']);

export function toApiError(e: unknown, requestId: string, redactOpts: RedactOptions): { status: number; body: ApiErrorBody; logMessage: string } {
  if (e instanceof AppError) {
    const code = e.code;
    const details: Record<string, unknown> = {};
    if (e.detail && typeof e.detail === 'object') {
      for (const [k, v] of Object.entries(e.detail as Record<string, unknown>)) if (DETAIL_KEYS.has(k)) details[k] = v;
    }
    const hint = e.hint ? redact(e.hint, redactOpts).slice(0, 500) : undefined;
    return {
      status: ERROR_HTTP_STATUS[code] ?? 400,
      body: { error: { code, message: ERROR_CODES[code], ...(hint ? { hint } : {}), ...(Object.keys(details).length ? { details } : {}), requestId } },
      logMessage: redact(e.message, redactOpts),
    };
  }
  const fastifyErr = e as { statusCode?: number; code?: string; message?: string; validation?: unknown };
  if (fastifyErr?.statusCode && fastifyErr.statusCode < 500) {
    const code: ErrorCode = fastifyErr.statusCode === 404 ? 'COMMON_NOT_FOUND' : 'COMMON_VALIDATION';
    // Schema validation messages name only schema paths and rules (never values): say what is wrong.
    const hint = fastifyErr.validation && fastifyErr.message ? redact(fastifyErr.message, redactOpts).slice(0, 500) : undefined;
    return {
      status: fastifyErr.statusCode === 404 ? 404 : 400,
      body: { error: { code, message: ERROR_CODES[code], ...(hint ? { hint } : {}), requestId } },
      logMessage: redact(String(fastifyErr.message ?? ''), redactOpts),
    };
  }
  return {
    status: 500,
    body: { error: { code: 'INTERNAL', message: ERROR_CODES.INTERNAL, requestId } },
    logMessage: redact(String((e as Error)?.stack ?? e), redactOpts),
  };
}
