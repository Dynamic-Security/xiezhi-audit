// Internal vulnerability categories (closed set) and CWE mapping.
export const VULN_CATEGORIES = [
  'sqli', 'nosqli', 'cmdi', 'code_injection', 'expression_injection', 'ssti', 'ssrf', 'path_traversal',
  'file_upload', 'deserialization', 'xxe', 'xss', 'open_redirect', 'csrf', 'cors', 'authn',
  'authz_object', 'authz_function', 'business_logic', 'race_condition', 'crypto_weak',
  'hardcoded_secret', 'info_leak', 'ldapi', 'log_injection',
  // denial of service / robustness (resource exhaustion, unbounded loops or recursion, ReDoS, null
  // dereference that crashes a request handler). Appended before 'other'; no DB CHECK lists this set.
  'dos', 'other',
] as const;
export type VulnCategory = (typeof VULN_CATEGORIES)[number];

const CWE_TO_CATEGORY: Record<string, VulnCategory> = {
  'CWE-89': 'sqli', 'CWE-564': 'sqli', 'CWE-943': 'nosqli',
  'CWE-77': 'cmdi', 'CWE-78': 'cmdi', 'CWE-94': 'code_injection', 'CWE-95': 'code_injection',
  'CWE-917': 'expression_injection', 'CWE-1336': 'ssti', 'CWE-918': 'ssrf',
  'CWE-22': 'path_traversal', 'CWE-23': 'path_traversal', 'CWE-73': 'path_traversal',
  'CWE-434': 'file_upload', 'CWE-502': 'deserialization', 'CWE-611': 'xxe', 'CWE-79': 'xss',
  'CWE-601': 'open_redirect', 'CWE-352': 'csrf', 'CWE-942': 'cors', 'CWE-346': 'cors',
  'CWE-287': 'authn', 'CWE-306': 'authn', 'CWE-384': 'authn',
  'CWE-639': 'authz_object', 'CWE-862': 'authz_object', 'CWE-863': 'authz_object',
  'CWE-285': 'authz_function', 'CWE-269': 'authz_function',
  'CWE-840': 'business_logic', 'CWE-841': 'business_logic', 'CWE-362': 'race_condition', 'CWE-367': 'race_condition',
  'CWE-327': 'crypto_weak', 'CWE-328': 'crypto_weak', 'CWE-330': 'crypto_weak', 'CWE-338': 'crypto_weak',
  'CWE-798': 'hardcoded_secret', 'CWE-259': 'hardcoded_secret', 'CWE-200': 'info_leak', 'CWE-209': 'info_leak',
  'CWE-532': 'info_leak', 'CWE-90': 'ldapi', 'CWE-117': 'log_injection',
  'CWE-400': 'dos', 'CWE-770': 'dos', 'CWE-789': 'dos', 'CWE-834': 'dos', 'CWE-835': 'dos', 'CWE-674': 'dos',
  'CWE-1333': 'dos', 'CWE-407': 'dos', 'CWE-476': 'dos', 'CWE-369': 'dos',
};

const CATEGORY_DEFAULT_CWE: Record<VulnCategory, string | null> = {
  sqli: 'CWE-89', nosqli: 'CWE-943', cmdi: 'CWE-78', code_injection: 'CWE-94', expression_injection: 'CWE-917',
  ssti: 'CWE-1336', ssrf: 'CWE-918', path_traversal: 'CWE-22', file_upload: 'CWE-434', deserialization: 'CWE-502',
  xxe: 'CWE-611', xss: 'CWE-79', open_redirect: 'CWE-601', csrf: 'CWE-352', cors: 'CWE-942', authn: 'CWE-287',
  authz_object: 'CWE-639', authz_function: 'CWE-285', business_logic: 'CWE-840', race_condition: 'CWE-362',
  crypto_weak: 'CWE-327', hardcoded_secret: 'CWE-798', info_leak: 'CWE-200', ldapi: 'CWE-90',
  log_injection: 'CWE-117', dos: 'CWE-400', other: null,
};

export function normalizeCwe(cwe: string | null | undefined): string | null {
  if (!cwe) return null;
  const m = /^(?:CWE-)?(\d{1,5})$/i.exec(cwe.trim());
  return m ? `CWE-${m[1]}` : null;
}

/** Resolve the internal category: an explicit valid category wins, else map from CWE, else 'other'. */
export function resolveCategory(category: string | null | undefined, cwe?: string | null): VulnCategory {
  if (category && (VULN_CATEGORIES as readonly string[]).includes(category)) return category as VulnCategory;
  const n = normalizeCwe(cwe);
  return (n && CWE_TO_CATEGORY[n]) || 'other';
}

export function defaultCweFor(category: VulnCategory): string | null {
  return CATEGORY_DEFAULT_CWE[category];
}

/**
 * Category families for "suspected same" candidates: the model may label
 * one root cause differently across audits (a forged owner is `authn` in one run, `authz_object` in the
 * next). Exact fingerprints keep the precise category; only the candidate filter uses the family.
 */
const CATEGORY_FAMILIES: readonly (readonly VulnCategory[])[] = [
  ['authn', 'authz_object', 'authz_function', 'business_logic'],
  ['cmdi', 'code_injection', 'expression_injection', 'ssti'],
  ['sqli', 'nosqli', 'ldapi'],
];

export function sameCategoryFamily(a: string, b: string): boolean {
  return a === b || CATEGORY_FAMILIES.some((f) => f.includes(a as VulnCategory) && f.includes(b as VulnCategory));
}
