// Parameter schemas for the submit_* tools. Structured artifacts can only be
// produced through these tools; "no findings" must be an explicit empty submission.
import { Type, type Static } from 'typebox';
import { closedSet, SEVERITIES, THREAT_RISK_CATEGORIES, THREAT_RISK_LEVELS } from './enums.js';
import { VULN_CATEGORIES } from './categories.js';

const Str = (max = 4000) => Type.String({ minLength: 1, maxLength: max });
const Line = Type.Integer({ minimum: 1 });

export const CodeRef = Type.Object({
  repo: Type.Optional(Type.String({ description: 'Repository name; omit for the audited repository.' })),
  path: Str(1024),
  startLine: Line,
  endLine: Line,
  note: Type.Optional(Str(1000)),
}, { additionalProperties: false });
export type CodeRef = Static<typeof CodeRef>;

export const TargetRef = Type.Object({
  targetKind: closedSet(['entry', 'sink'] as const),
  targetId: Str(512),
}, { additionalProperties: false });
export type TargetRef = Static<typeof TargetRef>;

/** Legacy shape of a pending condition; still read from stored data, never submitted. */
export const MissingContext = Type.Object({
  needs: Str(1000),
  holdsIf: Str(1000),
  notHoldsIf: Str(1000),
}, { additionalProperties: false });
export type MissingContext = Static<typeof MissingContext>;

export const PENDING_MISSING_KINDS = ['repo', 'gateway_policy', 'config', 'business_rule', 'external_service'] as const;
export const PENDING_ACTIONS = ['add_repo', 'add_knowledge', 'query_connector', 'ask_user'] as const;
const Condition = Type.Object({
  statement: Str(600),
  /** How the condition can be checked once the missing piece is there (e.g. tool cross_repo_trace on gateway). */
  checkable: Type.Optional(Type.Object({ tool: Type.Optional(Str(60)), target: Type.Optional(Str(300)) }, { additionalProperties: false })),
}, { additionalProperties: false });
/**
 * "待确认": what is missing, when the vulnerability holds or is refuted, how
 * severe it is if it holds, and what the user can do. A targeted reverification checks only these.
 */
/** Missing kinds that need a clue: a common-sense rule or defence in depth is not a reason to be pending. */
export const PENDING_KINDS_NEEDING_CLUE = ['business_rule', 'config'] as const;
/** What in the code or knowledge suggests the unusual rule / configuration the verdict depends on. */
export const PendingClue = Type.Object({
  ref: Type.Optional(CodeRef),
  skill: Type.Optional(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' })),
  note: Str(500),
}, { additionalProperties: false });
export const PendingCondition = Type.Object({
  missing: Type.Array(Type.Object({ kind: closedSet(PENDING_MISSING_KINDS), ref: Str(200), hint: Type.Optional(Str(500)), clue: Type.Optional(PendingClue) }, { additionalProperties: false }), { minItems: 1, maxItems: 8 }),
  holdsIf: Type.Array(Condition, { minItems: 1, maxItems: 6 }),
  refutedIf: Type.Array(Condition, { minItems: 1, maxItems: 6 }),
  severityIfHolds: closedSet(['critical', 'high', 'medium', 'low'] as const),
  suggestedActions: Type.Array(closedSet(PENDING_ACTIONS), { minItems: 1, maxItems: 4 }),
}, { additionalProperties: false });
export type PendingCondition = Static<typeof PendingCondition>;

/** The optional `pendingCondition` of a conclusion: present means "pending". */
const PendingField = Type.Optional(Type.Object(PendingCondition.properties, {
  additionalProperties: false,
  description: 'Only when the verdict depends on a specific fact that is not visible in the code (a missing repository or gateway, a concrete configuration value, a business rule hinted at in code or knowledge). Omit the field entirely when the code evidence settles the finding; never fill placeholders such as "nothing missing". Presence of this field marks the conclusion as pending.',
}));

const PLACEHOLDER_MISSING = /^\s*(无|没有|暂无|不存在|无需|不需要|不适用|均已|已在代码|none|nothing|n\/?a|not applicable|no missing|unused|null|placeholder|-+)\s*$|^\s*(无|没有|暂无|不存在|无需|不需要|均已|已在代码|none|nothing|not applicable|no missing)|不存在(必要|任何)?(的)?缺失|无(必要)?缺失|没有缺失|无需补充/i;

/**
 * Issues for a pending condition that declares nothing missing: its presence would mark the conclusion
 * pending although the model found no unknown (seen in a calibration run).
 */
export function placeholderPendingIssues(p: PendingCondition | undefined, where: string): string[] {
  if (!p) return [];
  const empty = p.missing.filter((m) => PLACEHOLDER_MISSING.test(m.ref) || PLACEHOLDER_MISSING.test(m.hint ?? ''));
  return empty.length === p.missing.length
    ? [`${where}.pendingCondition 没有写明缺少的具体事实（${empty.map((m) => `“${m.ref}”`).join('、')}）：结论不依赖代码以外的事实时，请整个省略 pendingCondition，重新提交`]
    : [];
}

/** Read a stored pending condition in either shape (legacy MissingContext is converted). */
export function normalizePending(x: unknown): PendingCondition | null {
  if (!x || typeof x !== 'object') return null;
  const o = x as Record<string, unknown>;
  if (Array.isArray(o.missing)) return o as unknown as PendingCondition;
  if (typeof o.needs === 'string') {
    return {
      missing: [{ kind: 'config', ref: o.needs }], holdsIf: [{ statement: String(o.holdsIf ?? '') }], refutedIf: [{ statement: String(o.notHoldsIf ?? '') }],
      severityIfHolds: 'medium', suggestedActions: ['ask_user'],
    };
  }
  return null;
}

/** Fields of a submitted finding, shared by hunt findings and risk-hunt hits. */
const findingProps = {
  title: Str(200),
  category: closedSet(VULN_CATEGORIES),
  cwe: Type.Optional(Type.String({ pattern: '^CWE-\\d{1,5}$' })),
  severity: closedSet(SEVERITIES),
  confidence: Type.Number({ minimum: 0, maximum: 1, description: 'Probability the finding is a real, exploitable issue.' }),
  /** Dangerous operation location (the identity anchor). */
  location: CodeRef,
  sink: Type.Optional(Type.Object({
    sinkId: Type.Optional(Str(512)),
    symbol: Type.Optional(Str(512)),
    api: Type.Optional(Str(512)),
  }, { additionalProperties: false })),
  /** Entry point ids or keys (`METHOD /path`) reaching the sink. */
  entries: Type.Array(Str(512), { maxItems: 50 }),
  rootCause: Str(500),
  /**
   * the attack path — who controls what input, how it reaches the dangerous operation, which
   * check is missing — and the impact if exploited. Preconditions go into exploitConditions (at least one for a
   * confirmed finding; “无需特殊前置条件” when there are none). A finding that cannot state them is not confirmed.
   */
  attackPath: Str(2000),
  impact: Str(1000),
  // Layer ① evidence
  evidence: Type.Array(CodeRef, { minItems: 1, maxItems: 30 }),
  // Layer ② reasoning & chain (entry → sink)
  chain: Type.Array(CodeRef, { maxItems: 30 }),
  /**
   * for a check that is not there (authorization, authentication, CSRF, a business rule, a race):
   * where the check belongs and what it should verify. The location must have been read.
   */
  missingCheck: Type.Optional(Type.Object({ location: CodeRef, expected: Str(500) }, { additionalProperties: false })),
  reasoning: Str(8000),
  counterCheck: Str(4000),
  // Layer ③ exploit conditions
  exploitConditions: Type.Array(Type.Object({
    condition: Str(1000),
    status: closedSet(['confirmed', 'unconfirmed', 'unsatisfied'] as const),
    source: Str(500),
  }, { additionalProperties: false }), { maxItems: 20 }),
  // Layer ④ remediation
  remediation: Type.Object({
    approach: Str(4000),
    suggestion: Type.Optional(Str(8000)),
    verification: Type.Optional(Str(2000)),
  }, { additionalProperties: false }),
  pendingCondition: PendingField,
  /** Knowledge the conclusion relies on: skill names (or `name/file`) read in this session. */
  knowledgeRefs: Type.Optional(Type.Array(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}(/[^\\s]{1,200})?$' }), { maxItems: 10 })),
  /** Connector results the conclusion relies on: `call=` ids returned by connector_query in this session. */
  connectorRefs: Type.Optional(Type.Array(Type.String({ pattern: '^ccl_[0-9A-Z]{26}$' }), { maxItems: 10 })),
  /** the finding's responsibility class — own-service defect, relies on an upstream guarantee, or a cross-service risk. */
  boundary: Type.Optional(Type.Enum(['own', 'upstream', 'cross_service'] as const, { description: 'own: a defect of this service; upstream: holds only if an upstream (gateway, caller) does not do its check; cross_service: reachable only from other internal services. Omit when unsure; the engine classes it from the entry exposure.' })),
  /** enterprise facts the conclusion relies on as premises — ids returned by facts_query in this session. */
  factRefs: Type.Optional(Type.Array(Type.String({ pattern: '^fct_[0-9A-Z]{26}$' }), { maxItems: 10, description: 'Enterprise facts this conclusion relies on as premises: ids returned by facts_query in this session. When a fact changes, the finding is marked for reverification.' })),
};
/** A risk-hunt hit: the repository verdict is given separately. */
export const HitDraft = Type.Object(findingProps, { additionalProperties: false });
export type HitDraft = Static<typeof HitDraft>;
/**
 * A hunt finding. `verdict` is an explicit decision (in calibration an optional pendingCondition was
 * filled for nearly every finding): `pending` needs a pendingCondition; with `confirmed` a pendingCondition
 * given anyway is kept as unconfirmed exploit conditions.
 */
export const FindingDraft = Type.Object({
  ...findingProps,
  verdict: Type.Enum(['confirmed', 'pending'] as const, {
    description: 'confirmed: the code evidence you read establishes the issue (uncertainty goes into confidence and exploitConditions). pending: whether it holds depends on a specific fact outside the code (a missing repository or gateway, a concrete configuration value, a business rule hinted at in code or knowledge) — then give pendingCondition.',
  }),
}, { additionalProperties: false });
export type FindingDraft = Static<typeof FindingDraft>;

/**
 * Hypothesis-first review: a risk assumed from the business meaning of the code and the
 * attempt to refute it with code evidence. `refuted`: the evidence rules it out (what was checked is in
 * `attempts`); `open`: neither proven nor refuted — an "未排除的假设", never a finding. Proven hypotheses are
 * submitted as findings instead.
 */
export const HypothesisDraft = Type.Object({
  statement: Str(1000),
  category: closedSet(VULN_CATEGORIES),
  location: CodeRef,
  entry: Type.Optional(Str(300)),
  attempts: Str(2000),
  status: closedSet(['refuted', 'open'] as const),
}, { additionalProperties: false });
export type HypothesisDraft = Static<typeof HypothesisDraft>;

export const SubmitFindings = Type.Object({
  findings: Type.Array(FindingDraft, { maxItems: 50 }),
  hypotheses: Type.Optional(Type.Array(HypothesisDraft, { maxItems: 30 })),
  reviewedTargets: Type.Array(Type.Object({
    targetKind: closedSet(['entry', 'sink'] as const),
    targetId: Str(512),
    verdict: closedSet(['no_issue', 'suspicious', 'finding'] as const),
  }, { additionalProperties: false }), { maxItems: 200 }),
  ruledOut: Type.Array(Type.Object({
    targetKind: closedSet(['entry', 'sink'] as const),
    targetId: Str(512),
    reason: Str(1000),
  }, { additionalProperties: false }), { maxItems: 200 }),
  scopeReviewed: Str(2000),
}, { additionalProperties: false });
export type SubmitFindings = Static<typeof SubmitFindings>;

/**
 * A domain expert submits like a hunt, plus the directions it did not get to (`openLeads`), which a
 * further round of the same domain may take up.
 */
export const SubmitDomainFindings = Type.Object({
  ...SubmitFindings.properties,
  openLeads: Type.Optional(Type.Array(Type.Object({
    direction: Str(1000),
    files: Type.Array(Str(500), { maxItems: 10 }),
  }, { additionalProperties: false }), { maxItems: 12 })),
}, { additionalProperties: false });
export type SubmitDomainFindings = Static<typeof SubmitDomainFindings>;

/**
 * Risk-hypothesis-first: one risk the repository may face, proposed from the threat model
 * before any is verified. `basis` ties it to the threat model (asset, role, trust boundary); `entries` and
 * `files` are where verification starts (not checked here: the hypothesis is not a claim about code yet).
 */
export const ThreatHypothesisDraft = Type.Object({
  statement: Str(1000),
  category: closedSet(VULN_CATEGORIES),
  basis: Str(1000),
  entries: Type.Array(Str(300), { maxItems: 10 }),
  files: Type.Array(Str(500), { maxItems: 10 }),
  priority: Type.Integer({ minimum: 1, maximum: 5, description: '5 = most likely and most harmful; verification follows this order' }),
}, { additionalProperties: false });
export type ThreatHypothesisDraft = Static<typeof ThreatHypothesisDraft>;

/**
 * A risk domain the threat model chose for this system — what its expert looks at, the vulnerability
 * categories it covers, mechanisms to check as a whole (each starting at code the session read) and the domain's risk
 * points (leads for the expert, not verified one by one).
 */
export const RiskDomainDraft = Type.Object({
  name: Str(60),
  focus: Str(800),
  categories: Type.Array(closedSet(VULN_CATEGORIES), { minItems: 1, maxItems: VULN_CATEGORIES.length }),
  mechanisms: Type.Array(Type.Object({ name: Str(200), location: CodeRef, why: Str(600) }, { additionalProperties: false }), { maxItems: 6 }),
  leads: Type.Array(Type.Object({
    statement: Str(1000),
    entries: Type.Array(Str(300), { maxItems: 10 }),
    files: Type.Array(Str(500), { maxItems: 10 }),
  }, { additionalProperties: false }), { maxItems: 12 }),
}, { additionalProperties: false });
export type RiskDomainDraft = Static<typeof RiskDomainDraft>;

/** who should be able to call a group of entries. */
export const ACCESS_LEVELS = ['public', 'authenticated', 'role', 'owner'] as const;
export type AccessLevel = (typeof ACCESS_LEVELS)[number];
/**
 * one group of the threat model's access policy — a route prefix (`/admin/`, `/api/order/`) or a controller /
 * handler name, the level its entries should require, the role for `role`, and why. One group per call (flat object,
 * as submit_risk_domain).
 */
export const AccessPolicyDraft = Type.Object({
  scope: Str(300),
  level: closedSet(ACCESS_LEVELS),
  role: Type.Optional(Str(100)),
  reason: Str(500),
}, { additionalProperties: false });
export type AccessPolicyDraft = Static<typeof AccessPolicyDraft>;

/**
 * `threat-model` step submission; at most `limits.maxCandidates` hypotheses (checked by the step). `domains` when
 * the domain hunt is on (required then, checked by the step).
 */
export const SubmitThreatModel = Type.Object({
  hypotheses: Type.Array(ThreatHypothesisDraft, { maxItems: 500 }),
  domains: Type.Optional(Type.Array(RiskDomainDraft, { maxItems: 8 })),
  notes: Type.Optional(Str(3000)),
}, { additionalProperties: false });
export type SubmitThreatModel = Static<typeof SubmitThreatModel>;

/**
 * The verdict on one listed hypothesis. `confirmed` names the finding of the same call that proves it;
 * `refuted` / `open` give the reason (what was checked, which guard). `location` is the code the verdict rests
 * on and must have been read in this session.
 */
export const HypothesisVerdictDraft = Type.Object({
  hypothesisId: Str(64),
  status: closedSet(['confirmed', 'refuted', 'open'] as const),
  reason: Str(2000),
  location: CodeRef,
  finding: Type.Optional(Type.Integer({ minimum: 0, description: 'Index into findings of this call (confirmed without sameAs)' })),
  /** A listed earlier finding (its id, e.g. HUNT-B1-F1) that already proves this hypothesis. */
  sameAs: Type.Optional(Str(200)),
}, { additionalProperties: false });
export type HypothesisVerdictDraft = Static<typeof HypothesisVerdictDraft>;

/**
 * Submission of a hypothesis-verification batch: a hunt submission plus one verdict per listed hypothesis. Without
 * the hunt's own `hypotheses` (a real model filled both, duplicating the verdicts as new hypotheses).
 */
const { hypotheses: _hunts, ...verificationProps } = SubmitFindings.properties;
export const SubmitHypothesisVerification = Type.Object({
  ...verificationProps,
  verdicts: Type.Array(HypothesisVerdictDraft, { maxItems: 30 }),
}, { additionalProperties: false });
export type SubmitHypothesisVerification = Static<typeof SubmitHypothesisVerification>;

/**
 * a domain expert that also verifies the hypotheses of its categories — the expert submission
 * plus verdicts, without the hunt's own `hypotheses` (as in SubmitHypothesisVerification). Verdicts may be spread
 * over several calls.
 */
const { hypotheses: _domainHunts, ...domainVerificationProps } = SubmitDomainFindings.properties;
export const SubmitDomainVerification = Type.Object({
  ...domainVerificationProps,
  verdicts: Type.Optional(Type.Array(HypothesisVerdictDraft, { maxItems: 30 })),
}, { additionalProperties: false });
export type SubmitDomainVerification = Static<typeof SubmitDomainVerification>;

export const COGNITIVE_FIELDS = ['confirmedFacts', 'activeHypotheses', 'pendingQuestions', 'ruledOutDirections', 'exploredNodes', 'knowledgeNeeds'] as const;
export type CognitiveField = (typeof COGNITIVE_FIELDS)[number];

export const StateOp = Type.Object({
  op: closedSet(['add', 'update', 'retire'] as const),
  field: closedSet(COGNITIVE_FIELDS),
  id: Type.Optional(Str(128)),
  text: Type.Optional(Str(2000)),
  evidenceRefs: Type.Optional(Type.Array(CodeRef, { maxItems: 10 })),
  reason: Type.Optional(Str(1000)),
}, { additionalProperties: false });
export type StateOp = Static<typeof StateOp>;

export const SubmitStateUpdate = Type.Object({
  ops: Type.Array(StateOp, { maxItems: 50 }),
}, { additionalProperties: false });
export type SubmitStateUpdate = Static<typeof SubmitStateUpdate>;

export const SubmitChallenge = Type.Object({
  codeDefense: Str(4000),
  threatModel: Str(4000),
  affirm: Str(4000),
  /**
   * maintain: the evidence holds; pending: it depends on a specific fact outside the code (with pendingCondition);
   * refuted: code evidence you read contradicts it (a guard, an unreachable path) — the finding is
   * not deleted, it becomes “待确认” with lower confidence and both sides are kept for a person to decide.
   */
  confirmation: closedSet(['maintain', 'pending', 'refuted'] as const),
  confidenceDelta: Type.Number({ minimum: -1, maximum: 1 }),
  /** Code the verdict rests on (read in this session); required for refuted. */
  evidence: Type.Optional(Type.Array(CodeRef, { maxItems: 10 })),
  severitySuggestion: Type.Optional(closedSet(SEVERITIES)),
  pendingCondition: PendingField,
  reason: Str(2000),
  /** Knowledge the conclusion relies on: skill names (or `name/file`) read in this session. */
  knowledgeRefs: Type.Optional(Type.Array(Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}(/[^\\s]{1,200})?$' }), { maxItems: 10 })),
  /** Connector results the conclusion relies on: `call=` ids returned by connector_query in this session. */
  connectorRefs: Type.Optional(Type.Array(Type.String({ pattern: '^ccl_[0-9A-Z]{26}$' }), { maxItems: 10 })),
}, { additionalProperties: false });
export type SubmitChallenge = Static<typeof SubmitChallenge>;

export const SubmitPlan = Type.Object({
  summary: Str(4000),
  focusDirections: Type.Array(Type.Object({ direction: Str(500), reason: Str(1000) }, { additionalProperties: false }), { maxItems: 20 }),
  plannedKnowledge: Type.Array(Type.Object({ skill: Str(64), reason: Str(500) }, { additionalProperties: false }), { maxItems: 20 }),
  contextNeeded: Type.Array(Str(1000), { maxItems: 20 }),
  limitations: Type.Array(Str(1000), { maxItems: 20 }),
}, { additionalProperties: false });
export type SubmitPlan = Static<typeof SubmitPlan>;

export const SubmitTriage = Type.Object({
  scores: Type.Array(Type.Object({
    candidateId: Str(512),
    score: Type.Integer({ minimum: 1, maximum: 5 }),
    reason: Str(500),
  }, { additionalProperties: false }), { maxItems: 500 }),
}, { additionalProperties: false });
export type SubmitTriage = Static<typeof SubmitTriage>;

export const SubmitMergeGroups = Type.Object({
  groups: Type.Array(Type.Object({ labels: Type.Array(Str(16), { minItems: 1 }) }, { additionalProperties: false })),
  dropped: Type.Array(Type.Object({
    label: Str(16),
    reason: closedSet(['duplicate_of', 'out_of_scope'] as const),
    detail: Str(500),
  }, { additionalProperties: false })),
}, { additionalProperties: false });
export type SubmitMergeGroups = Static<typeof SubmitMergeGroups>;

export const AskUser = Type.Object({
  question: Str(2000),
  blocking: Type.Boolean({ description: 'True when the answer determines whether a conclusion holds.' }),
  context: Type.Optional(Str(2000)),
}, { additionalProperties: false });
export type AskUser = Static<typeof AskUser>;

/**
 * profile: project profile + threat model. Consumed as the "threat model summary" section of
 * later sessions' system prompts. Evidence is optional: this is orientation, not a
 * finding.
 */
/**
 * attack surface the structure index did not recognize, found by the profile. `entry`: a place an
 * outside party can reach (a GraphQL operation, a WebSocket handshake, a message consumer, a scheduled job, a CLI
 * command); `sink`: a dangerous operation the sink rules do not know (an ORM call that takes raw conditions, a custom
 * query builder, a reflective invocation, a template render). Each points at the code that implements it.
 */
export const SURFACE_KINDS = ['entry', 'sink'] as const;
export const SurfaceItem = Type.Object({
  kind: closedSet(SURFACE_KINDS),
  name: Str(200),
  /** entry: how it is reached, e.g. `GraphQL mutation deleteShareToken`, `WebSocket GET /api/graphql`, `cron 0 * * * *`. */
  access: Type.Optional(Str(300)),
  /** sink: the vulnerability category the operation can lead to. */
  category: Type.Optional(closedSet(VULN_CATEGORIES)),
  /** sink: the dangerous call as written, e.g. `db.Find(&album, albumID)`. */
  api: Type.Optional(Str(300)),
  location: CodeRef,
  why: Str(600),
}, { additionalProperties: false });
export type SurfaceItem = Static<typeof SurfaceItem>;

export const SubmitProfile = Type.Object({
  summary: Str(3000),
  techStack: Type.Array(Str(200), { maxItems: 30 }),
  modules: Type.Array(Type.Object({ path: Str(500), purpose: Str(500) }, { additionalProperties: false }), { maxItems: 40 }),
  authModel: Str(2000),
  trustBoundaries: Type.Array(Type.Object({ name: Str(200), description: Str(1000) }, { additionalProperties: false }), { maxItems: 20 }),
  assets: Type.Array(Type.Object({
    name: Str(200), sensitivity: closedSet(['low', 'medium', 'high'] as const), description: Str(1000),
  }, { additionalProperties: false }), { maxItems: 30 }),
  roles: Type.Array(Type.Object({ name: Str(200), description: Str(1000) }, { additionalProperties: false }), { maxItems: 20 }),
  externalDependencies: Type.Array(Type.Object({ name: Str(200), description: Str(1000) }, { additionalProperties: false }), { maxItems: 30 }),
  assumptions: Type.Array(Str(1000), { maxItems: 20 }),
  /** only when asked for (`tools.surfaceDiscovery`). */
  surface: Type.Optional(Type.Array(SurfaceItem, { maxItems: 120 })),
}, { additionalProperties: false });
export type SubmitProfile = Static<typeof SubmitProfile>;

/**
 * The system model of a multi-repository audit, written once after the per-repository profiles (which stay
 * inside their own repository): the cross-repository flows and the trust boundaries between the services.
 */
export const SubmitSystemModel = Type.Object({
  summary: Str(3000),
  flows: Type.Array(Type.Object({
    from: Str(200), to: Str(200),
    /** How the call is made, e.g. `HTTP GET /internal/users/{id}`, `MQ order.created`, `gateway route /api/orders/**`. */
    via: Str(500),
    /** Identity and data passed across: headers, tokens, user ids taken on trust. */
    carries: Str(1000),
    /** Where the receiving side checks the caller (or that it does not). */
    check: Str(1000),
    location: Type.Optional(CodeRef),
  }, { additionalProperties: false }), { maxItems: 40 }),
  trustBoundaries: Type.Array(Type.Object({
    name: Str(200), description: Str(1000), repos: Type.Array(Str(200), { maxItems: 20 }),
  }, { additionalProperties: false }), { maxItems: 20 }),
  /** Risks that only show across services (a peer trusting a forgeable header, a check done on one side only). */
  risks: Type.Array(Type.Object({
    title: Str(300), statement: Str(1500), repos: Type.Array(Str(200), { maxItems: 20 }), location: Type.Optional(CodeRef),
  }, { additionalProperties: false }), { maxItems: 20 }),
  assumptions: Type.Array(Str(1000), { maxItems: 20 }),
}, { additionalProperties: false });
export type SubmitSystemModel = Static<typeof SubmitSystemModel>;

/**
 * Suspected matching: for each unmatched finding (label F*), pick the tracked
 * vulnerability (label V*) with the same root cause among its candidates, or null. Labels only — the
 * model never sees or writes ids.
 */
export const SubmitSuspectedMatches = Type.Object({
  decisions: Type.Array(Type.Object({
    finding: Str(16),
    vulnerability: Type.Union([Str(16), Type.Null()]),
    reason: Str(1000),
  }, { additionalProperties: false }), { maxItems: 200 }),
}, { additionalProperties: false });
export type SubmitSuspectedMatches = Static<typeof SubmitSuspectedMatches>;

/**
 * verify-fix: targeted re-verification of one tracked vulnerability along
 * its original chain. "Regression" is not a model verdict: it follows from the prior lifecycle.
 */
export const REVERIFY_VERDICTS = ['fixed', 'still_present', 'partially_fixed', 'undetermined'] as const;
export type ReverifyVerdict = (typeof REVERIFY_VERDICTS)[number];
/**
 * Second-opinion review of a favourable verdict (reverify “已修复”, risk hunt “受影响”): the
 * reviewer can only keep it or doubt it; a doubt turns the verdict into “待确认” with the reviewer's condition.
 */
export const SubmitVerdictReview = Type.Object({
  decision: closedSet(['maintain', 'doubt'] as const),
  reason: Str(2000),
  evidence: Type.Array(CodeRef, { maxItems: 20 }),
  pendingCondition: Type.Optional(PendingCondition),
}, { additionalProperties: false });
export type SubmitVerdictReview = Static<typeof SubmitVerdictReview>;

/**
 * One deep-explore round: pick exactly one direction and the step to derive. No facts, no
 * findings (the evidence gate): those come only from the derived execution step.
 */
export const SubmitDecision = Type.Object({
  /** A todo / leads item id as listed; or omit it and describe a new direction in `direction`. */
  itemId: Type.Optional(Str(120)),
  direction: Type.Optional(Type.Object({
    title: Str(300),
    target: Type.Object({ repo: Type.Optional(Str(120)), path: Str(1000), line: Type.Optional(Type.Integer({ minimum: 1 })), symbol: Type.Optional(Str(300)) }, { additionalProperties: false }),
  }, { additionalProperties: false })),
  action: closedSet(['hunt', 'read', 'challenge'] as const),
  /** challenge: the finding to argue (`F-n` id as listed). */
  findingId: Type.Optional(Str(120)),
  rationale: Str(1000),
  /** Nothing worth exploring any more: end the loop. */
  stop: Type.Optional(Type.Boolean()),
}, { additionalProperties: false });
export type SubmitDecision = Static<typeof SubmitDecision>;

/** Independent review (`review`): a fresh session judges one finding without the hunt's context. */
export const SubmitReview = Type.Object({
  verdict: closedSet(['holds', 'refuted', 'insufficient'] as const),
  confidence: Type.Number({ minimum: 0, maximum: 1 }),
  reason: Str(2000),
  evidence: Type.Array(CodeRef, { maxItems: 20 }),
}, { additionalProperties: false });
export type SubmitReview = Static<typeof SubmitReview>;

export const SubmitReverify = Type.Object({
  verdict: closedSet(REVERIFY_VERDICTS),
  reasoning: Str(6000),
  /** Current-version code: the fix (fixed / partially_fixed) or the still-reachable sink (still_present). */
  evidence: Type.Array(CodeRef, { maxItems: 20 }),
  /** partially_fixed: entry keys (`METHOD /path`) that no longer reach the sink. */
  fixedEntries: Type.Array(Str(300), { maxItems: 50 }),
  pendingCondition: PendingField,
  /** Only for a vulnerability that was pending confirmation: whether its condition now holds. */
  pendingResolution: Type.Optional(closedSet(['holds', 'refuted', 'still_pending'] as const)),
  /** Connector results the conclusion relies on: `call=` ids returned by connector_query in this session. */
  connectorRefs: Type.Optional(Type.Array(Type.String({ pattern: '^ccl_[0-9A-Z]{26}$' }), { maxItems: 10 })),
}, { additionalProperties: false });
export type SubmitReverify = Static<typeof SubmitReverify>;

/** Repository role judgement (RepoRoleResult; the deterministic parts are filled by the engine). */
export const SubmitRepoRole = Type.Object({
  roles: Type.Array(Type.Object({
    role: closedSet(['gateway', 'auth', 'business', 'api_def', 'frontend', 'shared_lib'] as const),
    confidence: Type.Number({ minimum: 0, maximum: 1 }),
    evidence: Type.Array(Type.Object({
      signal: Str(200), path: Type.Optional(Str(500)), count: Type.Optional(Type.Integer({ minimum: 0 })),
    }, { additionalProperties: false }), { minItems: 1, maxItems: 8 }),
  }, { additionalProperties: false }), { maxItems: 4, description: 'Zero or more roles; a repository may play several (e.g. gateway + auth).' }),
  rationale: Str(2000),
}, { additionalProperties: false });
export type SubmitRepoRole = Static<typeof SubmitRepoRole>;

/**
 * A requirement threat model: the clarification (Markdown, six sections of the report template) and the
 * risks, each resting on source numbers (S1 …). `no` reuses an existing risk's number on regeneration. `sourceIssues`:
 * sources the model could not read in full (an online document that failed, a document read only in part).
 */
export const RequirementThreatRiskDraft = Type.Object({
  no: Type.Optional(Type.Integer({ minimum: 1 })),
  category: closedSet(THREAT_RISK_CATEGORIES),
  level: closedSet(THREAT_RISK_LEVELS),
  statement: Str(600),
  impact: Str(1500),
  mitigation: Str(3000),
  features: Type.Array(Str(200), { maxItems: 10 }),
  sources: Type.Array(Type.Integer({ minimum: 1 }), { minItems: 1, maxItems: 50 }),
}, { additionalProperties: false });
export type RequirementThreatRiskDraft = Static<typeof RequirementThreatRiskDraft>;
export const SubmitRequirementThreatModel = Type.Object({
  clarification: Str(60_000),
  risks: Type.Array(RequirementThreatRiskDraft, { maxItems: 200 }),
  sourceIssues: Type.Optional(Type.Array(Type.Object({ source: Type.Integer({ minimum: 1 }), problem: Str(500) }, { additionalProperties: false }), {
    maxItems: 100,
    description: 'Only sources you could not read in full (a connector failed, an online document is missing, pages left unread). Gaps or conflicts in what the sources say go into the clarification (待确认与冲突点), not here.',
  })),
}, { additionalProperties: false });
export type SubmitRequirementThreatModel = Static<typeof SubmitRequirementThreatModel>;
