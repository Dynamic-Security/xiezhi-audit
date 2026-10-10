// Knowledge ingestion: what the organizing model submits for a skill or a case file, and
// the contradiction judgement over similar existing knowledge. `source` / `verified` are never chosen by
// the model — the ingestion pipeline sets them from where the content came from.
import { Type, type Static } from 'typebox';
import { closedSet, KNOWLEDGE_FRAMEWORKS, KNOWLEDGE_LANGUAGES, REPO_ROLES, SCENES, SKILL_CATEGORIES } from './enums.js';
import { VULN_CATEGORIES } from './categories.js';

const Str = (max = 4000) => Type.String({ minLength: 1, maxLength: max });
const Words = (max = 20) => Type.Array(Type.String({ minLength: 1, maxLength: 60 }), { maxItems: max });
const SKILL_NAME = '^[a-z0-9][a-z0-9-]{1,63}$';

export const KnowledgeSkillSubmit = Type.Object({
  name: Type.String({ pattern: SKILL_NAME, description: '小写字母、数字、连字符' }),
  /** 20–400 characters, no newline / link / angle brackets. */
  description: Type.String({ minLength: 20, maxLength: 400 }),
  category: closedSet(SKILL_CATEGORIES),
  load: Type.Optional(Type.String({ pattern: '^(on_demand|always|phase:[a-z,]+)$' })),
  appliesTo: Type.Optional(Type.Object({
    // Closed sets / controlled ids: the prefilter matches these exactly, a free-text value would exclude the skill.
    scenes: Type.Optional(Type.Array(closedSet(SCENES), { maxItems: 4 })),
    languages: Type.Optional(Type.Array(Type.String({ pattern: '^[a-z][a-z0-9_+-]{0,19}$' }), { maxItems: 10, description: `小写语言 id，已知：${KNOWLEDGE_LANGUAGES.join(', ')}` })),
    frameworks: Type.Optional(Type.Array(Type.String({ pattern: '^[a-z][a-z0-9_-]{0,31}$' }), { maxItems: 10, description: `小写框架 id，已知：${KNOWLEDGE_FRAMEWORKS.join(', ')}` })),
    vulnClasses: Type.Optional(Type.Array(closedSet(VULN_CATEGORIES), { maxItems: 10 })), repoRoles: Type.Optional(Type.Array(closedSet(REPO_ROLES), { maxItems: 7 })),
  }, { additionalProperties: false })),
  cwe: Type.Optional(Type.Array(Type.String({ pattern: '^CWE-\\d+$' }), { maxItems: 10 })),
  tags: Type.Optional(Type.Array(Type.String({ minLength: 1, maxLength: 32 }), { maxItems: 10 })),
  body: Str(100_000),
}, { additionalProperties: false });
export type KnowledgeSkillSubmit = Static<typeof KnowledgeSkillSubmit>;

/** One case file of a case library. */
export const KnowledgeCaseSubmit = Type.Object({
  name: Type.String({ pattern: SKILL_NAME }),
  description: Str(200),
  vulnClass: closedSet(VULN_CATEGORIES),
  cwe: Type.Optional(Type.Array(Type.String({ pattern: '^CWE-\\d+$' }), { maxItems: 5 })),
  languages: Type.Optional(Words(5)),
  frameworks: Type.Optional(Words(5)),
  appliesWhen: Str(300),
  pattern: Str(), codeTraits: Str(8000), holdsIf: Str(), notHoldsIf: Str(), fix: Str(), whenToUse: Str(),
}, { additionalProperties: false });
export type KnowledgeCaseSubmit = Static<typeof KnowledgeCaseSubmit>;

/** Contradictions between a draft and similar existing knowledge (“结论矛盾”). */
export const KnowledgeConflictSubmit = Type.Object({
  conflicts: Type.Array(Type.Object({
    candidate: Type.String({ maxLength: 20, description: '候选编号，如 c1' }),
    points: Type.Array(Str(400), { maxItems: 10, description: '相互矛盾的成立条件或事实陈述；没有矛盾时为空数组' }),
    suggestion: closedSet(['merge', 'replace', 'keep_both'] as const),
    merged: Type.Optional(Str(100_000)),
  }, { additionalProperties: false }), { maxItems: 5 }),
}, { additionalProperties: false });
export type KnowledgeConflictSubmit = Static<typeof KnowledgeConflictSubmit>;

/**
 * Architecture material → topology proposals. Names only; the
 * pipeline maps them to repositories and records every edge as `imported` / `inferred` with the statement.
 */
export const ArchitectureImportSubmit = Type.Object({
  services: Type.Array(Type.Object({
    name: Type.String({ minLength: 1, maxLength: 100 }),
    kind: closedSet(['service', 'gateway', 'external_service', 'mq_topic'] as const),
    /** Repository name of this project when the material says which repository implements it. */
    repo: Type.Optional(Type.String({ maxLength: 100 })),
    description: Type.Optional(Type.String({ maxLength: 300 })),
  }, { additionalProperties: false }), { maxItems: 100 }),
  edges: Type.Array(Type.Object({
    from: Type.String({ minLength: 1, maxLength: 100 }), to: Type.String({ minLength: 1, maxLength: 100 }),
    kind: closedSet(['contract', 'client_call', 'message', 'shared_lib', 'frontend_api'] as const),
    protocol: closedSet(['http', 'grpc', 'dubbo', 'mq', 'gateway_route', 'shared_lib'] as const),
    /** The sentence of the material that states this connection. */
    statement: Type.String({ minLength: 1, maxLength: 400 }),
  }, { additionalProperties: false }), { maxItems: 300 }),
  summary: Type.String({ maxLength: 2000 }),
}, { additionalProperties: false });
export type ArchitectureImportSubmit = Static<typeof ArchitectureImportSubmit>;

/** A connector pack drafted from an OpenAPI document: declarative operations only, never scripts. */
export const ConnectorPackSubmit = Type.Object({
  name: Type.String({ pattern: '^[a-z0-9][a-z0-9-]{1,63}$' }),
  description: Type.String({ minLength: 10, maxLength: 400 }),
  baseUrl: Type.String({ maxLength: 500 }),
  auth: Type.Object({
    type: closedSet(['none', 'header'] as const),
    header: Type.Optional(Type.String({ maxLength: 64 })),
    /** e.g. "Bearer ${secret:token}" — the secret name is declared in `secrets`. */
    value: Type.Optional(Type.String({ maxLength: 200 })),
  }, { additionalProperties: false }),
  secrets: Type.Array(Type.String({ pattern: '^[A-Za-z0-9_.-]{1,64}$' }), { maxItems: 10 }),
  operations: Type.Array(Type.Object({
    name: Type.String({ pattern: '^[a-z][a-z0-9_]{1,63}$' }),
    kind: closedSet(['read', 'write'] as const),
    description: Str(300),
    method: closedSet(['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const),
    path: Type.String({ pattern: '^/', maxLength: 500 }),
    query: Type.Optional(Type.Record(Type.String({ maxLength: 64 }), Type.String({ maxLength: 500 }))),
    body: Type.Optional(Type.Unknown()),
    params: Type.Record(Type.String({ pattern: '^[A-Za-z_][A-Za-z0-9_]*$' }), Type.Object({
      type: closedSet(['string', 'integer', 'number', 'boolean', 'array'] as const), description: Type.Optional(Type.String({ maxLength: 200 })),
      required: Type.Optional(Type.Boolean()), maxLength: Type.Optional(Type.Integer()), minimum: Type.Optional(Type.Number()), maximum: Type.Optional(Type.Number()),
      pattern: Type.Optional(Type.String({ maxLength: 200 })), enum: Type.Optional(Type.Array(Type.String({ maxLength: 100 }), { maxItems: 50 })),
    }, { additionalProperties: false })),
    extract: Type.Optional(Type.String({ maxLength: 300 })),
  }, { additionalProperties: false }), { minItems: 1, maxItems: 40 }),
  notes: Type.String({ maxLength: 4000 }),
}, { additionalProperties: false });
export type ConnectorPackSubmit = Static<typeof ConnectorPackSubmit>;
