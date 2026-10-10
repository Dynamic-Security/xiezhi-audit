// Category equivalence table for scoring. Deliberately independent of the product's
// category families and CWE mapping (contracts/categories.ts): the scorer must not reuse the logic
// under test. A finding and a label are category-equivalent when their equivalence classes intersect.

/** Product category → equivalence class. */
const CLASS_OF_CATEGORY: Record<string, string> = {
  sqli: 'sql', nosqli: 'nosql', ldapi: 'ldap',
  cmdi: 'os_command',
  code_injection: 'code_exec', expression_injection: 'code_exec', ssti: 'code_exec',
  ssrf: 'ssrf',
  path_traversal: 'file_path', file_upload: 'file_upload',
  deserialization: 'deserialization', xxe: 'xxe', xss: 'xss', open_redirect: 'redirect',
  csrf: 'csrf', cors: 'cors',
  authn: 'authn', authz_object: 'access_control', authz_function: 'access_control',
  business_logic: 'business_logic', race_condition: 'concurrency',
  crypto_weak: 'crypto', hardcoded_secret: 'secret', info_leak: 'info_leak', log_injection: 'log_injection',
  dos: 'robustness',
  other: 'other',
};

/** CWE → equivalence class (own table; broader than the product's mapping on purpose). */
const CLASS_OF_CWE: Record<string, string> = {
  'CWE-89': 'sql', 'CWE-564': 'sql', 'CWE-943': 'nosql', 'CWE-90': 'ldap',
  'CWE-77': 'os_command', 'CWE-78': 'os_command', 'CWE-88': 'os_command',
  'CWE-94': 'code_exec', 'CWE-95': 'code_exec', 'CWE-917': 'code_exec', 'CWE-1336': 'code_exec',
  'CWE-918': 'ssrf',
  'CWE-22': 'file_path', 'CWE-23': 'file_path', 'CWE-36': 'file_path', 'CWE-73': 'file_path', 'CWE-59': 'file_path',
  'CWE-434': 'file_upload', 'CWE-502': 'deserialization', 'CWE-611': 'xxe', 'CWE-776': 'xxe',
  'CWE-79': 'xss', 'CWE-80': 'xss', 'CWE-601': 'redirect', 'CWE-352': 'csrf', 'CWE-942': 'cors', 'CWE-346': 'cors',
  'CWE-287': 'authn', 'CWE-290': 'authn', 'CWE-306': 'authn', 'CWE-384': 'authn',
  'CWE-284': 'access_control', 'CWE-285': 'access_control', 'CWE-639': 'access_control', 'CWE-566': 'access_control',
  'CWE-862': 'access_control', 'CWE-863': 'access_control', 'CWE-269': 'access_control', 'CWE-932': 'access_control',
  'CWE-840': 'business_logic', 'CWE-841': 'business_logic', 'CWE-837': 'business_logic', 'CWE-1284': 'business_logic', 'CWE-799': 'business_logic',
  'CWE-362': 'concurrency', 'CWE-367': 'concurrency',
  'CWE-326': 'crypto', 'CWE-327': 'crypto', 'CWE-328': 'crypto', 'CWE-330': 'crypto', 'CWE-338': 'crypto',
  'CWE-259': 'secret', 'CWE-321': 'secret', 'CWE-798': 'secret',
  'CWE-200': 'info_leak', 'CWE-209': 'info_leak', 'CWE-215': 'info_leak', 'CWE-532': 'info_leak',
  'CWE-117': 'log_injection',
  // denial of service and robustness. CWE-20 (improper input validation) is broad; labels use it for
  // crashes and unchecked inputs, so it joins this class (a finding still needs the same sink function to hit).
  'CWE-20': 'robustness', 'CWE-369': 'robustness', 'CWE-400': 'robustness', 'CWE-405': 'robustness', 'CWE-407': 'robustness',
  'CWE-476': 'robustness', 'CWE-674': 'robustness', 'CWE-770': 'robustness', 'CWE-789': 'robustness', 'CWE-834': 'robustness',
  'CWE-835': 'robustness', 'CWE-1333': 'robustness',
};

export function normCwe(cwe: string | null | undefined): string | null {
  const m = /^\s*(?:CWE-)?(\d{1,5})\s*$/i.exec(cwe ?? '');
  return m ? `CWE-${Number(m[1])}` : null;
}

export function classOfCategory(category: string): string {
  return CLASS_OF_CATEGORY[category] ?? 'other';
}

/** Classes of a finding: its category, plus its CWE when mapped. `other` never matches alone. */
export function findingClasses(category: string, cwe: string | null | undefined): Set<string> {
  const out = new Set<string>([classOfCategory(category)]);
  const c = normCwe(cwe);
  if (c && CLASS_OF_CWE[c]) out.add(CLASS_OF_CWE[c]!);
  return out;
}

export function labelClasses(category: string, cwes: readonly string[], equivalents: readonly string[] = []): Set<string> {
  const out = new Set<string>([classOfCategory(category), ...equivalents.map(classOfCategory)]);
  for (const cwe of cwes) {
    const c = normCwe(cwe);
    if (c && CLASS_OF_CWE[c]) out.add(CLASS_OF_CWE[c]!);
  }
  return out;
}

export function classesIntersect(a: Set<string>, b: Set<string>): boolean {
  for (const x of a) if (x !== 'other' && b.has(x)) return true;
  return false;
}
