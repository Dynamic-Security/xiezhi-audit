// Benchmark manifest, label and experiment schemas. Eval-only: nothing in
// the product reads these, so they live here and not in contracts.
import { Type, type Static } from 'typebox';
import { closedSet as lit, VULN_CATEGORIES } from '@xiezhi/contracts';

const LineRange = Type.Array(Type.Integer({ minimum: 1 }), { minItems: 2, maxItems: 2 });
const Id = Type.String({ pattern: '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' });
const Sha256 = Type.String({ pattern: '^[0-9a-f]{64}$' });
const Text = (max = 2000) => Type.String({ minLength: 1, maxLength: max });
const RelPath = Type.String({ minLength: 1, maxLength: 500, pattern: '^[^/\\\\][^\\\\]*$' });
/** Repository origin: a directory under `sources/`, or an `https://` Git URL pinned by a full `commit`. */
const Origin = Type.String({ minLength: 1, maxLength: 500, pattern: '^[^/\\\\][^\\\\]*$' });
const FullCommit = Type.String({ pattern: '^[0-9a-f]{40}$' });

export const PARTITIONS = ['dev', 'holdout'] as const;
export const SAMPLE_KINDS = ['vuln', 'fixed', 'negative', 'risk_hunt', 'reverify', 'identity', 'incremental'] as const;
export const BENCH_SCENES = ['full', 'incremental', 'risk_hunt', 'reverify'] as const;
export const LANGUAGES = ['java', 'go', 'python', 'javascript', 'typescript', 'php', 'kotlin', 'csharp', 'ruby', 'rust'] as const;
export const DEPTHS = ['single_point', 'cross_file', 'business_logic', 'cross_repo'] as const;
/**
 * Whose responsibility the problem is — `own` (a defect of the audited service whatever its
 * upstreams do), `upstream` (exploitable only when an upstream guarantee such as gateway auth does not hold),
 * `cross_service` (abuse by an internal caller: internal endpoints without service auth, trusted internal headers).
 */
export const BOUNDARIES = ['own', 'upstream', 'cross_service'] as const;
export const REVERIFY_CLASSES = ['fixed', 'still_present', 'partially_fixed', 'regressed', 'undetermined'] as const;
export const RISK_CLASSES = ['affected', 'not_affected', 'pending'] as const;
export const REASON_TYPES = ['not_imported', 'version_out_of_range', 'guarded', 'unreachable'] as const;
export const IDENTITY_CLASSES = ['same', 'suspected', 'different'] as const;
/** Cost tiers: smoke ⊂ core ⊂ full; a sample without a tier is in the full set only. */
export const TIERS = ['smoke', 'core', 'full'] as const;
/**
 * complete: every real problem in the sample is labelled (hand-built samples); an unlabelled finding on a fixed /
 * negative sample is a false positive. known_only: only the known advisories are labelled (real projects);
 * Recall counts the known ones, every other finding goes to adjudication and counts once decided.
 */
export const LABEL_POLICIES = ['complete', 'known_only'] as const;
export const REFACTORS = ['rename', 'move', 'split', 'merge', 'new_entry', 'other_sink'] as const;
export type Partition = (typeof PARTITIONS)[number];
export type SampleKind = (typeof SAMPLE_KINDS)[number];
export type ReverifyClass = (typeof REVERIFY_CLASSES)[number];
export type RiskClass = (typeof RISK_CLASSES)[number];
export type ReasonType = (typeof REASON_TYPES)[number];
export type IdentityClass = (typeof IDENTITY_CLASSES)[number];
export type Tier = (typeof TIERS)[number];
export type LabelPolicy = (typeof LABEL_POLICIES)[number];

// ---- manifest ----

export const RepoTree = Type.Object({
  name: Id,
  /** Under `sources/` (bench-relative), or an https Git URL with `commit` (checked by validate). */
  origin: Origin,
  root_hash: Sha256,
  commit: Type.Optional(FullCommit),
}, { additionalProperties: false });
export type RepoTree = Static<typeof RepoTree>;

export const SampleRepo = Type.Object({
  name: Id,
  role: lit(['auditable', 'context'] as const),
  origin: Origin,
  root_hash: Sha256,
  commit: Type.Optional(Type.String({ pattern: '^[0-9a-f]{7,64}$' })),
}, { additionalProperties: false });
export type SampleRepo = Static<typeof SampleRepo>;

export const SceneInput = Type.Object({
  /** single (default when one repository is auditable) or multi. */
  mode: Type.Optional(lit(['single', 'multi'] as const)),
  /** risk_hunt: basis text file (bench-relative, under sources/) and how the product should read it. */
  basis_ref: Type.Optional(RelPath),
  basis_kind: Type.Optional(lit(['prompt', 'intel'] as const)),
  /** reverify / identity: later versions of the repositories, applied in order after the base audit. */
  versions: Type.Optional(Type.Array(Type.Object({
    name: Id,
    repos: Type.Array(RepoTree, { minItems: 1 }),
  }, { additionalProperties: false }), { minItems: 1, maxItems: 5 })),
  /** reverify: the vulnerability label of the base version to follow. */
  target_label: Type.Optional(Id),
}, { additionalProperties: false });
export type SceneInput = Static<typeof SceneInput>;

export const SampleSource = Type.Object({
  dataset: Id,
  ref: Type.Optional(Text(500)),
  license: Text(100),
}, { additionalProperties: false });

export const Sample = Type.Object({
  sample_id: Id,
  project: Id,
  partition: lit(PARTITIONS),
  kind: lit(SAMPLE_KINDS),
  language: lit(LANGUAGES),
  source: SampleSource,
  repos: Type.Array(SampleRepo, { minItems: 1, maxItems: 8 }),
  scene: lit(BENCH_SCENES),
  scene_input: Type.Optional(SceneInput),
  labels: Type.Array(Id),
  tags: Type.Array(Id),
  tier: Type.Optional(lit(['smoke', 'core'] as const)),
  label_policy: Type.Optional(lit(LABEL_POLICIES)),
}, { additionalProperties: false });
export type Sample = Static<typeof Sample>;

export const SourceEntry = Type.Object({
  dataset: Id,
  status: lit(['active', 'planned'] as const),
  license: Text(100),
  url: Type.Optional(Text(500)),
  note: Type.Optional(Text(2000)),
}, { additionalProperties: false });
export type SourceEntry = Static<typeof SourceEntry>;

export const Manifest = Type.Object({
  bench_version: Type.String({ pattern: '^\\d+\\.\\d+\\.\\d+$' }),
  sources: Type.Array(SourceEntry, { minItems: 1 }),
  samples: Type.Array(Sample),
}, { additionalProperties: false });
export type Manifest = Static<typeof Manifest>;

// ---- labels ----

const CodeAnchor = Type.Object({
  repo: Id,
  file: RelPath,
  /** Java `Class.method`, Go `Recv.Method` / `Func`, MyBatis XML `Mapper.statementId`. */
  function: Type.Optional(Text(200)),
  api: Type.Optional(Text(200)),
  /** Reference only; matching is by function. Required when no function is given. */
  line_range: Type.Optional(LineRange),
}, { additionalProperties: false });
export type CodeAnchor = Static<typeof CodeAnchor>;

export const VulnLabel = Type.Object({
  label_id: Id,
  kind: Type.Literal('vuln'),
  category: lit(VULN_CATEGORIES),
  cwe: Type.Array(Type.String({ pattern: '^CWE-\\d{1,5}$' }), { minItems: 1 }),
  /** Further accepted categories for this label (e.g. business logic also reported as authz). */
  category_equivalents: Type.Optional(Type.Array(lit(VULN_CATEGORIES))),
  root_cause: Text(),
  sink: CodeAnchor,
  /**
   * Other functions of the same chain accepted as the sink (eval extension): for a
   * missing check (IDOR, business logic) the handler and the service method are equally valid places.
   */
  alt_sinks: Type.Optional(Type.Array(CodeAnchor, { maxItems: 4 })),
  /**
   * Affected entries. May be empty only for labels of imported public datasets, which name no HTTP route
   *; `validate` rejects an empty list on self-built / real-oss samples, and the
   * entry-hit metric skips labels without entries.
   */
  entries: Type.Array(Type.Object({ repo: Id, route: Text(300), handler: Type.Optional(Text(200)) }, { additionalProperties: false })),
  conditions: Type.Optional(Type.Object({
    holds_if: Type.Array(Text()),
    not_holds_if: Type.Array(Text()),
  }, { additionalProperties: false })),
  expected: Type.Object({
    verdict: lit(['confirmed', 'pending'] as const),
    severity: Type.Optional(Type.Array(lit(['low', 'medium', 'high', 'critical'] as const), { minItems: 1 })),
    /** pending: services/repositories the product must name as missing. */
    missing: Type.Optional(Type.Array(Text(200), { minItems: 1 })),
  }, { additionalProperties: false }),
  depth: lit(DEPTHS),
  /** Absent = `own`. */
  boundary: Type.Optional(lit(BOUNDARIES)),
}, { additionalProperties: false });
export type VulnLabel = Static<typeof VulnLabel>;

export const NegativeLabel = Type.Object({
  label_id: Id,
  kind: Type.Literal('negative'),
  expected: Type.Object({ verdict: Type.Literal('none') }, { additionalProperties: false }),
  /** Where the protection is: in the same code, upstream (gateway/other repository), or a fix. */
  guard: lit(['local', 'upstream', 'fix'] as const),
  /** The category the decoy resembles. */
  category: lit(VULN_CATEGORIES),
  decoys: Type.Array(Type.Object({
    repo: Id, file: RelPath, function: Type.Optional(Text(200)),
    line_range: Type.Optional(LineRange),
    note: Text(),
  }, { additionalProperties: false }), { minItems: 1 }),
}, { additionalProperties: false });
export type NegativeLabel = Static<typeof NegativeLabel>;

export const RiskHuntLabel = Type.Object({
  label_id: Id,
  kind: Type.Literal('risk_hunt'),
  targets: Type.Array(Type.Object({
    repo: Id,
    expected: lit(RISK_CLASSES),
    locations: Type.Optional(Type.Array(CodeAnchor)),
    reason_type: Type.Optional(lit(REASON_TYPES)),
    reason_evidence: Type.Optional(Type.Array(CodeAnchor, { minItems: 1 })),
  }, { additionalProperties: false }), { minItems: 1 }),
}, { additionalProperties: false });
export type RiskHuntLabel = Static<typeof RiskHuntLabel>;

export const ReverifyLabel = Type.Object({
  label_id: Id,
  kind: Type.Literal('reverify'),
  target_label: Id,
  /** One expected verdict per scene_input.versions entry. */
  expected: Type.Array(lit(REVERIFY_CLASSES), { minItems: 1, maxItems: 5 }),
}, { additionalProperties: false });
export type ReverifyLabel = Static<typeof ReverifyLabel>;

export const IdentityLabel = Type.Object({
  label_id: Id,
  kind: Type.Literal('identity'),
  /** Vulnerability label in the base version and in the version named by `version`. */
  a: Id,
  b: Id,
  version: Id,
  expected: lit(IDENTITY_CLASSES),
  refactor: lit(REFACTORS),
}, { additionalProperties: false });
export type IdentityLabel = Static<typeof IdentityLabel>;

export const Label = Type.Union([VulnLabel, NegativeLabel, RiskHuntLabel, ReverifyLabel, IdentityLabel]);
export type Label = VulnLabel | NegativeLabel | RiskHuntLabel | ReverifyLabel | IdentityLabel;

export const LabelFile = Type.Object({
  project: Id,
  labels: Type.Array(Label, { minItems: 1 }),
}, { additionalProperties: false });
export type LabelFile = Static<typeof LabelFile>;

// ---- adjudication decisions ----

/**
 * Human decisions on unlabelled findings of `known_only` samples, keyed by the scorer's stability key
 * (`class|repo:path:function`). They never become labels: Recall stays on the known advisories.
 */
export const AdjudicationDecision = Type.Object({
  key: Type.String({ minLength: 3, maxLength: 1000 }),
  verdict: lit(['true_positive', 'false_positive'] as const),
  note: Text(),
  /** Limit the decision to these samples (e.g. a problem fixed in a later version); default every sample of the project. */
  samples: Type.Optional(Type.Array(Id, { minItems: 1 })),
  decided_by: Type.Optional(Text(100)),
  decided_at: Type.Optional(Type.String({ pattern: '^\\d{4}-\\d{2}-\\d{2}$' })),
}, { additionalProperties: false });
export type AdjudicationDecision = Static<typeof AdjudicationDecision>;

export const AdjudicationFile = Type.Object({
  project: Id,
  decisions: Type.Array(AdjudicationDecision),
}, { additionalProperties: false });
export type AdjudicationFile = Static<typeof AdjudicationFile>;

// ---- experiment ----

export const Experiment = Type.Object({
  experiment: Id,
  bench: Type.Object({
    version: Type.String({ pattern: '^\\d+\\.\\d+\\.\\d+$' }),
    partition: lit(PARTITIONS),
    filter: Type.Optional(Type.Record(Type.String(), Type.Union([Type.String(), Type.Array(Type.String())]))),
  }, { additionalProperties: false }),
  baseline: Type.Object({
    strategy_from: Type.String({ pattern: '^scene_default:(full|incremental|risk_hunt|reverify)$' }),
    overrides: Type.Record(Type.String(), Type.Unknown()),
  }, { additionalProperties: false }),
  variants: Type.Array(Type.Object({
    name: Id,
    /** Dotted AuditStrategy field → value; exactly one field (the `models` composite counts as one). */
    patch: Type.Record(Type.String(), Type.Unknown()),
  }, { additionalProperties: false }), { minItems: 1, maxItems: 8 }),
  repeats: Type.Integer({ minimum: 1, maximum: 20 }),
  pins: Type.Optional(Type.Object({
    pi: Type.Optional(Type.String()),
    models: Type.Optional(Type.Record(Type.String(), Type.String())),
  }, { additionalProperties: false })),
  limits: Type.Optional(Type.Object({
    max_cost_usd: Type.Optional(Type.Number({ minimum: 0 })),
    max_parallel: Type.Optional(Type.Integer({ minimum: 1, maximum: 8 })),
  }, { additionalProperties: false })),
  metrics: Type.Optional(Type.Array(Type.String())),
  decision: Type.Object({
    primary: lit(['f1', 'precision', 'recall', 'recall_mixed', 'f1_mixed'] as const),
    guard: Type.Array(lit(['f1', 'precision', 'recall', 'recall_mixed', 'f1_mixed'] as const)),
    cost_metric: Type.Optional(Type.String()),
  }, { additionalProperties: false }),
  /** Bootstrap resamples and PRNG seed (fixed for reproducible intervals). */
  bootstrap: Type.Optional(Type.Object({ resamples: Type.Integer({ minimum: 100, maximum: 100_000 }), seed: Type.Integer() }, { additionalProperties: false })),
}, { additionalProperties: false });
export type Experiment = Static<typeof Experiment>;
