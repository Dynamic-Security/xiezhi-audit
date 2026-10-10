// deterministic hard-coded secret detection over the snapshot's text files. Hits become
// `hardcoded_secret` sinks of the structure index (leads for the experts, items of the coverage ledger); the value is
// redacted in the sink's description. Files the snapshot excludes as sensitive (`.env`, `*.pem`, …) are never here.
import type { Sink } from '@xiezhi/contracts';
import type { SnapshotView } from '../snapshot/view.js';

export interface SecretHit { line: number; column: number; kind: string; label: string; shown: string }

/** Publicly known default keys: whoever knows them can forge what they protect. Exact values only. */
const KNOWN_DEFAULT_KEYS: { value: string; label: string }[] = [
  { value: 'kPH+bIxk5D2deZiIxcaaaA==', label: 'Apache Shiro 公开的默认 rememberMe 密钥' },
  { value: 'your-256-bit-secret', label: 'jwt.io 示例中的 JWT 签名密钥' },
];

/** Token formats with a recognisable prefix (high precision, any file type). */
const TOKEN_PATTERNS: { kind: string; label: string; re: RegExp }[] = [
  { kind: 'private_key', label: '私钥', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/ },
  { kind: 'aws_access_key', label: 'AWS 访问密钥 ID', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { kind: 'github_token', label: 'GitHub 令牌', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { kind: 'slack_token', label: 'Slack 令牌', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { kind: 'google_api_key', label: 'Google API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
];

/** Names that say a value is a secret, in config keys, variables, constants and setters. */
const NAME = '(?:secret|passw(?:or)?d|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|cipher[_-]?key|signing[_-]?key|encrypt(?:ion)?[_-]?key|client[_-]?secret)';
/** `name: value` / `name = "value"` (config or code). */
const ASSIGN_RE = new RegExp(`(?:^|[^A-Za-z0-9])([A-Za-z0-9_.-]*${NAME}[A-Za-z0-9_.-]*)["']?\\s*[:=]\\s*(["']?)([^\\s"'\`,;)]{8,})\\2`, 'i');
/** `setCipherKey("value")`, `withSecret(Base64.decode("value"))`. */
const SETTER_RE = new RegExp(`\\b(?:set|with)${NAME}\\s*\\(\\s*(?:[\\w.]+\\(\\s*)?(["'])([^"']{8,})\\1`, 'i');

/**
 * Forms the two above miss: a typed declaration — `const API_KEY: &str = "…"` (Rust),
 * `const apiKey: string = "…"` (TypeScript), `val apiKey: String = "…"` (Kotlin) — and a Ruby setter with the name as
 * a symbol, `set :session_secret, "…"` (Sinatra) / `config.x(:secret, "…")`.
 */
const TYPED_RE = new RegExp(`(?:^|[^A-Za-z0-9])([A-Za-z0-9_]*${NAME}[A-Za-z0-9_]*)\\s*:\\s*[&\\w<>\\[\\]' ]{1,40}?\\s*=\\s*(["'])([^"']{8,})\\2`, 'i');
const SYMBOL_SET_RE = new RegExp(`\\b(?:set|config\\.\\w+)\\s*\\(?\\s*:([A-Za-z0-9_]*${NAME}[A-Za-z0-9_]*)\\s*,\\s*(["'])([^"']{8,})\\2`, 'i');

const CONFIG_FILE = /\.(ya?ml|properties|ini|toml|conf|cfg|json|xml|env\.\w+|config)$/i;
const SKIP_PATH = /(^|\/)(tests?|__tests__|spec|specs|fixtures?|mocks?|examples?|samples?|docs?|node_modules|vendor)\//i;
const SKIP_FILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.sum|composer\.lock|Cargo\.lock|poetry\.lock)$|\.(min\.js|map|svg|lock)$/i;
/** Test files and translation catalogs (values there are fixtures and messages). */
const SKIP_KIND = /\.(test|spec)\.[cm]?[jt]sx?$|_test\.go$|Tests?\.(java|kt|cs)$|_test\.py$|(^|\/)test_[^/]+\.py$|(^|\/)(i18n|locales?|translations?|extractedTranslations|lang)\//i;
const PLACEHOLDER = /^\$\{|^\$[A-Z_]|^<|^%|^\{\{|^\(|changeme|change[_-]?it|example|your[_-]|xxx|\*{3}|placeholder|dummy|sample|todo|^null$|^none$|^true$|^false$|^password$|^secret$/i;

export const MAX_SECRET_FILE_BYTES = 1024 * 1024;
const MAX_HITS_PER_FILE = 20;
const MAX_HITS_PER_REPO = 200;

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

/** A value that looks like a real secret: not a placeholder, mixed characters, not low entropy. */
function secretLike(v: string): boolean {
  // Printable ASCII only (i18n messages are not keys); MyBatis / template parameters are references, not values.
  if (!/^[\x21-\x7e]+$/.test(v) || /^#\{/.test(v) || PLACEHOLDER.test(v)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(v)).length;
  return classes >= 2 && entropy(v) >= 3;
}

/** The first characters and the length only. */
export function redact(v: string): string {
  return `${v.slice(0, 4)}…（${v.length} 个字符）`;
}

/** Secret hits of one file's text (path decides config vs code rules). */
export function scanSecretText(path: string, text: string): SecretHit[] {
  const config = CONFIG_FILE.test(path);
  const out: SecretHit[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length && out.length < MAX_HITS_PER_FILE; i++) {
    const line = lines[i]!;
    if (line.length > 2000) continue;
    const known = KNOWN_DEFAULT_KEYS.find((k) => line.includes(k.value));
    if (known) { out.push({ line: i + 1, column: line.indexOf(known.value) + 1, kind: 'known_default_key', label: known.label, shown: '公开的默认值' }); continue; }
    const token = TOKEN_PATTERNS.map((p) => ({ p, m: p.re.exec(line) })).find((x) => x.m);
    if (token) { out.push({ line: i + 1, column: token.m!.index + 1, kind: token.p.kind, label: token.p.label, shown: redact(token.m![0]) }); continue; }
    const setter = SETTER_RE.exec(line);
    if (setter && secretLike(setter[2]!)) { out.push({ line: i + 1, column: setter.index + 1, kind: 'assignment', label: '写死的密钥 / 口令', shown: redact(setter[2]!) }); continue; }
    const typed = TYPED_RE.exec(line) ?? SYMBOL_SET_RE.exec(line);
    if (typed && secretLike(typed[3]!)) { out.push({ line: i + 1, column: (typed.index ?? 0) + 1, kind: 'assignment', label: `写死的密钥 / 口令（${typed[1]!.slice(0, 60)}）`, shown: redact(typed[3]!) }); continue; }
    const a = ASSIGN_RE.exec(line);
    // In code a value must be a string literal (`password = req.get("p")` is not a secret); config values may be bare.
    if (a && (config || a[2]) && secretLike(a[3]!)) out.push({ line: i + 1, column: (a.index ?? 0) + 1, kind: 'assignment', label: `写死的密钥 / 口令（${a[1]!.slice(0, 60)}）`, shown: redact(a[3]!) });
  }
  return out;
}

/** `hardcoded_secret` sinks of a snapshot. */
export function secretSinks(view: SnapshotView): Sink[] {
  const out: Sink[] = [];
  for (const f of view.listFiles()) {
    if (out.length >= MAX_HITS_PER_REPO) break;
    if (f.size > MAX_SECRET_FILE_BYTES || SKIP_PATH.test(f.path) || SKIP_FILE.test(f.path) || SKIP_KIND.test(f.path)) continue;
    for (const h of scanSecretText(f.path, view.text(f.path))) {
      out.push({
        sinkId: `${view.repo}:${f.path}#L${h.line}:${h.column}:hardcoded_secret`, category: 'hardcoded_secret', symbolId: null, path: f.path,
        range: { startLine: h.line, endLine: h.line }, api: `硬编码密钥：${h.label}，${h.shown}`, ruleId: `secret.${h.kind}`,
      });
      if (out.length >= MAX_HITS_PER_REPO) break;
    }
  }
  return out;
}
