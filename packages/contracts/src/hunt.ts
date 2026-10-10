// Risk hunting (hunt-risk steps; basis sources).
import { Type, type Static } from 'typebox';
import { closedSet, SEVERITIES } from './enums.js';
import { VULN_CATEGORIES } from './categories.js';
import { AUDIT_LANGUAGES, DEPENDENCY_ECOSYSTEMS } from './languages.js';
import { CodeRef, HitDraft, PendingCondition } from './submit.js';

const Str = (max = 4000) => Type.String({ minLength: 1, maxLength: max });

/** MVP implements skill / prompt / intel; report (V1.1) and ticket (V1.2) keep the shape only. */
export const HUNT_BASIS_KINDS = ['skill', 'prompt', 'intel', 'report', 'ticket'] as const;
export type HuntBasisKind = (typeof HUNT_BASIS_KINDS)[number];
export const HUNT_ECOSYSTEMS = [...DEPENDENCY_ECOSYSTEMS, 'any'] as const;
export const HUNT_API_LANGUAGES = [...AUDIT_LANGUAGES, 'any'] as const;

/**
 * The organized basis of a risk hunt: what to look for (features) and how to judge (conditions).
 * Drafted by AI from a skill, a prompt or 1Day/CVE intel; confirmed or edited by the user.
 */
export const HuntBasis = Type.Object({
  title: Str(200),
  summary: Str(3000),
  category: Type.Optional(closedSet(VULN_CATEGORIES)),
  severity: closedSet(SEVERITIES),
  features: Type.Object({
    /** Affected components: Maven `group:artifact`, Go module path, npm / PyPI / Composer (`vendor/package`) / NuGet package; versions as a range expression. */
    dependencies: Type.Array(Type.Object({
      ecosystem: closedSet(HUNT_ECOSYSTEMS), name: Str(200),
      affectedVersions: Type.String({ maxLength: 200, description: 'e.g. "<2.13.4.2", ">=1.0.0 <1.2.3", "*" (all)' }),
      fixedVersion: Type.Optional(Type.String({ maxLength: 60 })),
    }, { additionalProperties: false }), { maxItems: 20 }),
    /** Dangerous APIs as ripgrep regular expressions (RE2 syntax). */
    apis: Type.Array(Type.Object({
      pattern: Str(300), language: Type.Optional(closedSet(HUNT_API_LANGUAGES)), description: Str(300),
    }, { additionalProperties: false }), { maxItems: 30 }),
    /** Code patterns in words; `grep` (optional regex) finds candidate places. */
    codePatterns: Type.Array(Type.Object({ description: Str(600), grep: Type.Optional(Type.String({ maxLength: 300 })) }, { additionalProperties: false }), { maxItems: 20 }),
    /** Rough locations (e.g. an interface named in a report): hunting starts there. */
    locations: Type.Array(Type.Object({
      project: Type.Optional(Type.String({ maxLength: 120 })), repo: Type.Optional(Type.String({ maxLength: 120 })),
      path: Type.Optional(Type.String({ maxLength: 500 })), route: Type.Optional(Type.String({ maxLength: 300 })),
    }, { additionalProperties: false }), { maxItems: 20 }),
  }, { additionalProperties: false }),
  affectedIf: Type.Array(Str(600), { minItems: 1, maxItems: 10 }),
  notAffectedIf: Type.Array(Str(600), { minItems: 1, maxItems: 10 }),
  remediation: Str(3000),
  references: Type.Array(Type.String({ maxLength: 500 }), { maxItems: 10 }),
}, { additionalProperties: false });
export type HuntBasis = Static<typeof HuntBasis>;

const PROBE_CHARS = [...'aA1_ +-*/.,;:(){}[]<>=!&|"\'$@#\n'];
const PROBES = ['', ...PROBE_CHARS, ...PROBE_CHARS.flatMap((a) => PROBE_CHARS.map((b) => a + b))];

/**
 * Regexes in a basis that are too broad to locate anything: they match the empty string or a trivial
 * one- or two-character code fragment (e.g. `\+`, `\.`, `a*`), so every repository would get candidates
 * and an AI judgement instead of a rule verdict. Patterns that JS cannot compile are left to ripgrep.
 */
export function basisPatternIssues(basis: Pick<HuntBasis, 'features'>): string[] {
  const issues: string[] = [];
  const probe = (label: string, pattern: string) => {
    let re: RegExp;
    try { re = new RegExp(pattern); } catch { return; }
    const hit = PROBES.find((p) => re.test(p));
    if (hit !== undefined) issues.push(`${label} 过宽：能匹配“${hit === '' ? '（空字符串）' : hit.replace(/\n/g, '\\n')}”，几乎所有仓库都会产生候选；改为只匹配危险写法本身的正则（${pattern.slice(0, 80)}）`);
  };
  basis.features.apis.forEach((a, i) => probe(`features.apis[${i}].pattern`, a.pattern));
  basis.features.codePatterns.forEach((c, i) => { if (c.grep) probe(`features.codePatterns[${i}].grep`, c.grep); });
  return issues;
}

/** A candidate place found by the deterministic locate phase. */
export const RiskCandidate = Type.Object({
  id: Type.String(),
  repo: Type.String(),
  kind: closedSet(['dependency', 'api', 'pattern', 'location'] as const),
  path: Type.String(),
  line: Type.Integer({ minimum: 0 }),
  label: Type.String(),
  /** dependency: declared version and whether it is inside the affected range. */
  detail: Type.Optional(Type.String()),
}, { additionalProperties: false });
export type RiskCandidate = Static<typeof RiskCandidate>;

export const RISK_VERDICTS = ['affected', 'not_affected', 'pending'] as const;
export type RiskVerdict = (typeof RISK_VERDICTS)[number];

/** Judgement of one repository's candidates (hunt-risk judge phase). Hits use the finding shape. */
export const SubmitRiskVerdicts = Type.Object({
  hits: Type.Array(HitDraft, { maxItems: 50 }),
  ruledOut: Type.Array(Type.Object({ candidateId: Str(300), reason: Str(1000) }, { additionalProperties: false }), { maxItems: 200 }),
  repoVerdict: Type.Object({
    verdict: closedSet(RISK_VERDICTS),
    reason: Str(1000),
    /** not_affected needs at least one piece of evidence; code or the checked manifest line. */
    evidence: Type.Array(CodeRef, { maxItems: 20 }),
    pendingCondition: Type.Optional(PendingCondition),
  }, { additionalProperties: false }),
}, { additionalProperties: false });
export type SubmitRiskVerdicts = Static<typeof SubmitRiskVerdicts>;
