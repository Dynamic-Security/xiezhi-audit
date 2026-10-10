// Shared redactor. Pure function used by logs, events, artifacts, exports and errors.
export interface RedactOptions {
  /** Known secret values (config.json credentials); also matched in base64 form. */
  secrets?: readonly string[];
  homeDir?: string;
  dataDir?: string;
  snapshotRoot?: string;
}

const R = '[REDACTED]';

const PATTERNS: [RegExp, string | ((m: string, ...g: string[]) => string)][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, R],
  [/\b(authorization\s*[:=]\s*)(bearer|basic)\s+[^\s"',;]+/gi, (_m, p, k) => `${p}${k} ${R}`],
  [/\b(x-api-key|cookie|set-cookie)(\s*[:=]\s*)[^\r\n"']+/gi, (_m, h, s) => `${h}${s}${R}`],
  [/\b(sk-ant-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{16,}|gh[po]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[abp]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/g, R],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, R],
  [/(\b[a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^@\s/]+)@/gi, (_m, s) => `${s}${R}@`],
  [/([?&](?:token|key|secret|password|signature|access_token|sig)=)[^&\s#"']+/gi, (_m, p) => `${p}${R}`],
];

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function redact(text: string, opts: RedactOptions = {}): string {
  let out = text;
  for (const secret of opts.secrets ?? []) {
    if (!secret || secret.length < 4) continue;
    for (const form of [secret, Buffer.from(secret).toString('base64')]) {
      out = out.replace(new RegExp(escapeRe(form), 'g'), R);
    }
  }
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep as never);
  const paths: [string | undefined, string][] = [
    [opts.snapshotRoot, '<snapshot>'], [opts.dataDir, '<data-dir>'], [opts.homeDir, '~'],
  ];
  for (const [p, label] of paths) if (p && p.length > 1) out = out.split(p).join(label);
  return out;
}

/** Redact every string inside a JSON-compatible value. */
export function redactDeep<T>(value: T, opts: RedactOptions = {}): T {
  if (typeof value === 'string') return redact(value, opts) as T;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, opts)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v, opts);
    return out as T;
  }
  return value;
}
