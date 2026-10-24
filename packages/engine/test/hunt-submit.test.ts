// submit_findings consistency: a candidate concluded as `finding` must be
// backed by a finding in the same call, otherwise the vulnerability would be dropped silently.
import { describe, expect, it } from 'vitest';
import { basisPatternIssues, sameCategoryFamily, type FindingDraft } from '@xiezhi/contracts';
import { exploitConditionsOf, pendingClueIssues, validateFindings, wasRead } from '../src/steps/hunt.js';
import type { AuditRuntime } from '../src/runtime.js';

const ENTRY = 'order-service:GET /api/order/{}';
const SINK = 'inventory-service:main.go#L26:12:cmdi';
const rt = {
  targets: [{ name: 'order-service' }, { name: 'inventory-service' }],
  repoByName: () => undefined,
  views: new Map(),
  readRanges: () => [],
  indexes: new Map([
    ['order-service', { entrypoints: [{ entryId: ENTRY, entryKey: 'GET /api/order/{}', path: 'src/OrderController.java' }], sinks: [] }],
    ['inventory-service', { entrypoints: [], sinks: [{ sinkId: SINK, path: 'main.go' }] }],
  ]),
} as unknown as AuditRuntime;

const finding = (over: Partial<FindingDraft>): FindingDraft => ({
  title: 't', category: 'cmdi', severity: 'high', confidence: 0.9, location: { repo: 'inventory-service', path: 'main.go', startLine: 26, endLine: 26 },
  entries: [], rootCause: 'r', attackPath: '请求参数 host 原样拼接进 exec 的命令行，未做任何过滤', impact: '执行任意命令', evidence: [{ repo: 'inventory-service', path: 'main.go', startLine: 26, endLine: 26 }], chain: [], reasoning: 'x', counterCheck: 'y',
  exploitConditions: [{ condition: '无需特殊前置条件', status: 'confirmed', source: 'main.go' }], remediation: { approach: 'a' }, verdict: 'confirmed', ...over,
} as FindingDraft);

const consistency = (issues: string[]) => issues.filter((i) => i.includes('verdict "finding"'));

describe('submit_findings consistency', () => {
  it('rejects a finding verdict without a finding that covers the target', () => {
    const issues = validateFindings(rt, {
      findings: [finding({ sink: { sinkId: SINK } })],
      reviewedTargets: [{ targetId: SINK, verdict: 'finding' }, { targetId: ENTRY, verdict: 'finding' }], ruledOut: [],
    });
    expect(consistency(issues)).toHaveLength(1);
    expect(consistency(issues)[0]).toContain(ENTRY);
  });

  it('accepts coverage by sink id, entry id, route key or location in the target file', () => {
    for (const f of [
      finding({ category: 'authz_object', entries: [ENTRY] }),
      finding({ category: 'authz_object', entries: ['GET /api/order/{id}'] }),
      finding({ category: 'authz_object', location: { repo: 'order-service', path: 'src/OrderController.java', startLine: 3, endLine: 4 } }),
    ]) {
      expect(consistency(validateFindings(rt, { findings: [f], reviewedTargets: [{ targetId: ENTRY, verdict: 'finding' }], ruledOut: [] }))).toEqual([]);
    }
    expect(consistency(validateFindings(rt, { findings: [], reviewedTargets: [{ targetId: ENTRY, verdict: 'suspicious' }], ruledOut: [] }))).toEqual([]);
  });
});

describe('pending needs a clue for business rules and configuration', () => {
  const cond = (missing: { kind: string; ref: string; clue?: Record<string, unknown> }[]) => ({
    missing, holdsIf: [{ statement: 'a' }], refutedIf: [{ statement: 'b' }], severityIfHolds: 'high', suggestedActions: ['ask_user'],
  }) as never;
  const krt = { ...rt, knowledge: { skills: [{ name: 'order-visibility' }] } } as unknown as AuditRuntime;

  it('rejects a common-sense business rule or a defence-in-depth config without a clue', () => {
    expect(pendingClueIssues(krt, cond([{ kind: 'business_rule', ref: '订单详情访问规则' }]), 'findings[0]')[0]).toContain('没有线索');
    expect(pendingClueIssues(krt, cond([{ kind: 'config', ref: 'MySQL 运行配置' }]), 'f')).toHaveLength(1);
    // A clue that points at code never read in this audit is not a clue.
    expect(pendingClueIssues(krt, cond([{ kind: 'config', ref: 'x', clue: { ref: { repo: 'order-service', path: 'src/Nope.java', startLine: 1, endLine: 2 }, note: 'n' } }]), 'f')).toHaveLength(1);
    expect(pendingClueIssues(krt, cond([{ kind: 'business_rule', ref: 'x', clue: { skill: 'no-such-skill', note: 'n' } }]), 'f')).toHaveLength(1);
  });

  it('accepts a knowledge clue, and missing repositories / gateways need none', () => {
    expect(pendingClueIssues(krt, cond([{ kind: 'business_rule', ref: '订单可见范围', clue: { skill: 'order-visibility', note: '知识说明客服可查看全部订单' } }]), 'f')).toEqual([]);
    expect(pendingClueIssues(krt, cond([{ kind: 'gateway_policy', ref: 'edge-gateway' }, { kind: 'repo', ref: 'auth-service' }]), 'f')).toEqual([]);
    expect(pendingClueIssues(krt, undefined, 'f')).toEqual([]);
  });
});

describe('explicit verdict', () => {
  const cond = { missing: [{ kind: 'config', ref: 'DB 账号权限' }], holdsIf: [{ statement: '账号有写权限时影响扩大' }], refutedIf: [{ statement: '只读' }], severityIfHolds: 'high', suggestedActions: ['ask_user'] } as never;
  const sinkOnly = { findings: [], reviewedTargets: [], ruledOut: [] };
  it('pending needs a condition; a confirmed finding is not checked for clues', () => {
    const noCond = validateFindings(rt, { ...sinkOnly, findings: [finding({ verdict: 'pending' })] });
    expect(noCond.some((i) => i.includes('verdict "pending" needs a pendingCondition'))).toBe(true);
    const confirmed = validateFindings(rt, { ...sinkOnly, findings: [finding({ verdict: 'confirmed', pendingCondition: cond })] });
    expect(confirmed.some((i) => i.includes('pendingCondition'))).toBe(false);
  });
  it('unified threshold: a confirmed finding states the attack path, the impact and its preconditions', () => {
    const weak = validateFindings(rt, { ...sinkOnly, findings: [finding({ attackPath: '可注入', impact: '', exploitConditions: [] })] });
    expect(weak.some((i) => i.includes('a confirmed finding needs') && i.includes('attackPath') && i.includes('impact') && i.includes('exploitConditions'))).toBe(true);
    expect(validateFindings(rt, { ...sinkOnly, findings: [finding({})] }).some((i) => i.includes('a confirmed finding needs'))).toBe(false);
    // A pending finding says what is missing instead; the threshold is for confirmed ones.
    expect(validateFindings(rt, { ...sinkOnly, findings: [finding({ verdict: 'pending', pendingCondition: cond, attackPath: '可注入', exploitConditions: [] })] }).some((i) => i.includes('a confirmed finding needs'))).toBe(false);
  });
  it('a condition given with verdict confirmed is kept as unconfirmed exploit conditions', () => {
    expect(exploitConditionsOf(finding({ verdict: 'confirmed', pendingCondition: cond })).slice(1)).toEqual([
      { condition: '账号有写权限时影响扩大', status: 'unconfirmed', source: '模型列出的前提（结论已确认）：DB 账号权限' },
    ]);
    expect(exploitConditionsOf(finding({ verdict: 'pending', pendingCondition: cond, exploitConditions: [] }))).toEqual([]);
  });
});

describe('basis pattern breadth', () => {
  const basis = (apis: string[], greps: string[]) => ({
    features: { dependencies: [], locations: [], apis: apis.map((pattern) => ({ pattern, description: 'd' })), codePatterns: greps.map((grep) => ({ description: 'd', grep })) },
  }) as unknown as Parameters<typeof basisPatternIssues>[0];

  it('accepts specific patterns', () => {
    expect(basisPatternIssues(basis(['\\$\\{[^}]+\\}', '@(?:Select|Update)Provider\\b', 'exec\\.Command\\s*\\(\\s*"(?:sh|bash)"'], ['exec\\.(Command|CommandContext)\\s*\\(']))).toEqual([]);
  });

  it('rejects patterns that match empty or trivial fragments', () => {
    const issues = basisPatternIssues(basis(['.'], ['(StringBuilder|\\.append\\(|\\+)', 'a*']));
    expect(issues).toHaveLength(3);
    expect(issues[1]).toContain('“+”');
  });
});

describe('suspected-match category families', () => {
  it('groups categories a model may use interchangeably for one root cause', () => {
    expect(sameCategoryFamily('authn', 'authz_object')).toBe(true);
    expect(sameCategoryFamily('cmdi', 'code_injection')).toBe(true);
    expect(sameCategoryFamily('sqli', 'sqli')).toBe(true);
    expect(sameCategoryFamily('sqli', 'cmdi')).toBe(false);
    expect(sameCategoryFamily('xss', 'authn')).toBe(false);
  });
});

describe('evidence and chain segments count as verified only when read', () => {
  const read = { 'Dao.java': [[10, 30]] } as Record<string, [number, number][]>;
  const rrt = {
    repoByName: (n: string) => (n === 'app' ? { name: 'app' } : undefined),
    views: new Map([['app', { guard: (p: string) => { if (p.includes('..')) throw new Error('outside'); return p; } }]]),
    readRanges: (_repo: string, path: string) => read[path] ?? [],
  } as unknown as AuditRuntime;
  const ref = (path: string, s: number, e: number, repo = 'app') => ({ repo, path, startLine: s, endLine: e });

  it('a range that overlaps what the read tool returned is read; anything else is not', () => {
    expect(wasRead(rrt, ref('Dao.java', 17, 21))).toBe(true);
    expect(wasRead(rrt, ref('Dao.java', 28, 40))).toBe(true);
    expect(wasRead(rrt, ref('Dao.java', 31, 40))).toBe(false);
    expect(wasRead(rrt, ref('Ctl.java', 1, 5))).toBe(false);
    expect(wasRead(rrt, ref('Dao.java', 17, 21, 'other'))).toBe(false);
    expect(wasRead(rrt, ref('../x', 1, 2))).toBe(false);
  });
});

describe('reconcile picks a representative that meets the confidence threshold', () => {
  it('a confident high finding represents the group before an uncertain critical one', async () => {
    const { canonicalOrder } = await import('../src/steps/reconcile.js');
    const a = { id: 'a', severity: 'critical', confidence_score: 0.5 };
    const b = { id: 'b', severity: 'high', confidence_score: 0.95 };
    const order = canonicalOrder(0.6, () => 0, () => 0);
    expect([a, b].sort(order)[0]!.id).toBe('b');
    // When every member is below the threshold, severity still decides (the group is insufficient either way).
    expect([{ ...b, confidence_score: 0.4 }, a].sort(order)[0]!.id).toBe('a');
    // When both meet it, severity decides as before.
    expect([{ ...b }, { ...a, confidence_score: 0.7 }].sort(order)[0]!.id).toBe('a');
  });
});

describe('target ids written without the repository prefix or with named parameters', () => {
  it('resolve to the one listed id; stay unknown when none or several match', async () => {
    const { resolveTargetId } = await import('../src/steps/hunt.js');
    const known = ['rs-files:GET /files/{}/owner', 'rs-files:POST /login', 'rb-board:POST /login', 'rb-board:GET /posts/{}'];
    const repos = ['rs-files', 'rb-board'];
    // Seen with claude-haiku-5-5: the step failed after three refusals.
    expect(resolveTargetId(known, 'GET /files/{id}/owner', repos)).toBe('rs-files:GET /files/{}/owner');
    expect(resolveTargetId(known, 'rb-board:GET /posts/:id', repos)).toBe('rb-board:GET /posts/{}');
    expect(resolveTargetId(known, 'rs-files:POST /login', repos)).toBe('rs-files:POST /login');
    expect(resolveTargetId(known, 'POST /login', repos)).toBeNull(); // both repositories have it
    expect(resolveTargetId(known, 'GET /nope', repos)).toBeNull();
    // A route followed by a remark.
    expect(resolveTargetId(known, 'GET /posts/:id (IDOR)', repos)).toBe('rb-board:GET /posts/{}');
    expect(resolveTargetId(known, 'rs-files:POST /login 暴力破解/枚举', repos)).toBe('rs-files:POST /login');
    // A sink written as its location and API.
    const sinks = [...known, 'rs-files:src/handlers.rs#L32:24:cmdi', 'rs-files:src/handlers.rs#L14:38:sqli'];
    expect(resolveTargetId(sinks, 'rs-files:src/handlers.rs:32 Command sh -c', repos)).toBe('rs-files:src/handlers.rs#L32:24:cmdi');
    expect(resolveTargetId(sinks, 'src/handlers.rs:14', repos)).toBe('rs-files:src/handlers.rs#L14:38:sqli');
    expect(resolveTargetId(sinks, 'rs-files:src/handlers.rs:99', repos)).toBeNull();
  });
});

describe('a finding carrying sameAs repeats an earlier finding', () => {
  it('is dropped and the verdict pointing at it uses sameAs; later indexes shift', async () => {
    const { dropRepeatedFindings } = await import('../src/steps/hunt.js');
    const r = dropRepeatedFindings({
      findings: [{ title: 'a', sameAs: 'DOM-D1-R1-F1' }, { title: 'b' }],
      verdicts: [{ hypothesisId: 'h1', status: 'confirmed', finding: 0 }, { hypothesisId: 'h2', status: 'confirmed', finding: 1 }, { hypothesisId: 'h3', status: 'refuted' }],
    });
    expect(r.repeats).toEqual([{ i: 0, id: 'DOM-D1-R1-F1' }]);
    expect(r.args.findings).toEqual([{ title: 'b' }]);
    expect(r.args.verdicts).toEqual([
      { hypothesisId: 'h1', status: 'confirmed', sameAs: 'DOM-D1-R1-F1' }, { hypothesisId: 'h2', status: 'confirmed', finding: 0 }, { hypothesisId: 'h3', status: 'refuted' },
    ]);
    const plain = { findings: [{ title: 'c' }], verdicts: [] };
    expect(dropRepeatedFindings(plain).args).toBe(plain);
  });
});

describe('a canonical finding of class `other` takes its members\' specific class', () => {
  it('SSTI reported as other by one model and ssti by others is published as ssti', async () => {
    const { specificCategory } = await import('../src/steps/reconcile.js');
    const members = [{ category: 'other', cwe: null }, { category: 'ssti', cwe: 'CWE-1336' }, { category: 'ssti', cwe: null }, { category: 'code_injection', cwe: 'CWE-94' }];
    expect(specificCategory({ category: 'other' }, members)).toEqual({ category: 'ssti', cwe: 'CWE-1336' });
    expect(specificCategory({ category: 'sqli' }, members)).toEqual({});
    expect(specificCategory({ category: 'other' }, [{ category: 'other', cwe: null }])).toEqual({});
  });
});

describe('deep exploration stagnation ignores replayed rounds', () => {
  it('three replayed rounds after a resume do not stop the loop; new rounds without progress still do', async () => {
    const { nextQuiet } = await import('../src/pipeline/review.js');
    const { STAGNATION_ROUNDS } = await import('../src/explore.js');
    let quiet = 0;
    for (let i = 0; i < 5; i++) quiet = nextQuiet(quiet, true, false);
    expect(quiet).toBe(0);
    for (let i = 0; i < STAGNATION_ROUNDS; i++) quiet = nextQuiet(quiet, false, false);
    expect(quiet).toBe(STAGNATION_ROUNDS);
    expect(nextQuiet(2, false, true)).toBe(0);
  });
});

describe('dropRepeatedFindings leaves malformed lists to the schema', () => {
  it('a findings list sent as text or holding null is returned as it came, without throwing', async () => {
    const { dropRepeatedFindings } = await import('../src/steps/hunt.js');
    const text = { findings: '[{"title":"a"}]' as unknown as object[] };
    expect(dropRepeatedFindings(text)).toEqual({ args: text, repeats: [] });
    const nulls = { findings: [null as unknown as object, { title: 'b', sameAs: 'F1' }], verdicts: [null as unknown as object] };
    expect(() => dropRepeatedFindings(nulls)).not.toThrow();
    expect(dropRepeatedFindings(nulls).args.findings).toEqual([null]);
  });
});
