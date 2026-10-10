// dependencies in full audits. The engine lists the declared dependencies of the target
// repositories (the manifests and lock files the risk hunt already parses) and, only when the audit's connectors include
// an OSV connector (an operation named `osv_query`), asks it about each dependency with a version. Hits go to a domain
// expert as leads to judge whether the code uses the vulnerable part; nothing leaves the machine without that connector.
import type { ConnectorAccess, ConnectorOperation } from '@xiezhi/agent';
import type { DependencyEcosystem } from '@xiezhi/contracts';
import { declaredDependencies, type Declared } from '@xiezhi/context';
import { buildConnectorAccess } from './connector-access.js';
import type { AuditRuntime } from './runtime.js';
import { P } from '@xiezhi/knowledge';

/** OSV ecosystem names of the parsed ecosystems. */
export const OSV_ECOSYSTEM: Record<DependencyEcosystem, string> = { maven: 'Maven', go: 'Go', npm: 'npm', pypi: 'PyPI', composer: 'Packagist', nuget: 'NuGet', rubygems: 'RubyGems', cargo: 'crates.io' };
/** At most this many dependencies are looked up per audit (direct manifests first, in file order). */
export const MAX_OSV_QUERIES = 150;
/** The operation name of the OSV connector pack (connector-packs/osv). */
export const OSV_OPERATION = 'osv_query';

export interface Advisory { id: string; summary: string | null; aliases: string[]; severity: string | null }
export interface DependencyHit { repo: string; ecosystem: string; name: string; version: string; path: string; line: number; advisories: Advisory[] }
export interface DependencyRecord {
  repos: { repo: string; total: number; byEcosystem: Record<string, number>; versioned: number }[];
  /** Whether an OSV connector was available, how many were asked, how many calls failed. */
  osv: { available: boolean; queried: number; failed: number };
  hits: DependencyHit[];
}

/** The target repositories' declared dependencies, one per (ecosystem, name, version). */
export function dependencyInventory(rt: Pick<AuditRuntime, 'targets' | 'views'>): { repo: string; deps: Declared[] }[] {
  return rt.targets.map((r) => {
    const view = rt.views.get(r.name);
    const seen = new Set<string>();
    const deps = (view ? declaredDependencies(view) : []).filter((d) => {
      const k = `${d.ecosystem}:${d.name}:${d.version ?? ''}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    return { repo: r.name, deps };
  });
}

/** Parse what the pack's `extract` returned: a JSON array of advisories (or an empty / non-JSON answer). */
export function parseAdvisories(text: string): Advisory[] {
  const start = text.indexOf('[');
  if (start < 0) return [];
  try {
    // The pack's projection names a nested field by its path (`database_specific.severity`).
    const arr = JSON.parse(text.slice(start, text.lastIndexOf(']') + 1)) as ({ id?: string; summary?: string; aliases?: string[]; database_specific?: { severity?: string }; 'database_specific.severity'?: string; severity?: unknown })[];
    return arr.filter((a) => typeof a?.id === 'string').map((a) => ({
      id: a.id!, summary: a.summary ?? null, aliases: Array.isArray(a.aliases) ? a.aliases.slice(0, 5) : [],
      severity: a['database_specific.severity'] ?? a.database_specific?.severity ?? (typeof a.severity === 'string' ? a.severity : null),
    }));
  } catch {
    return [];
  }
}

const done = (rt: Pick<AuditRuntime, 'store' | 'auditId'>) => rt.store.listEvents(rt.auditId, 0, ['judgement.made']).find((e) => e.payload.kind === 'dependencies');

/** The audit's dependency record, if the check ran. */
export function dependencyRecord(rt: Pick<AuditRuntime, 'store' | 'auditId'>): DependencyRecord | null {
  return (done(rt)?.payload.record as DependencyRecord | undefined) ?? null;
}

/**
 * Run once per audit (a resumed run reuses the recorded result): list the dependencies; with an OSV connector, query
 * each versioned one (at most MAX_OSV_QUERIES, sequentially; the connector pool limits concurrency and trips its
 * breaker on failures) and keep the hits.
 */
export async function dependencyCheck(rt: AuditRuntime, signal?: AbortSignal, access?: ConnectorAccess | null): Promise<DependencyRecord> {
  const prior = dependencyRecord(rt);
  if (prior) return prior;
  const inventory = dependencyInventory(rt);
  const acc = access !== undefined ? access : rt.connectorPool && rt.strategy.connectors?.length ? buildConnectorAccess({
    store: rt.store, pool: rt.connectorPool, refs: rt.strategy.connectors, auditId: rt.auditId, stepId: 'dependencies', artifacts: rt.auditArtifacts,
    onQueried: (payload) => rt.event('connector.queried', payload, null),
  }) : null;
  const op: ConnectorOperation | undefined = acc?.operations.find((o) => o.tool === OSV_OPERATION);
  const record: DependencyRecord = {
    repos: inventory.map(({ repo, deps }) => ({
      repo, total: deps.length, versioned: deps.filter((d) => d.version).length,
      byEcosystem: deps.reduce<Record<string, number>>((m, d) => ({ ...m, [d.ecosystem]: (m[d.ecosystem] ?? 0) + 1 }), {}),
    })),
    osv: { available: !!op, queried: 0, failed: 0 }, hits: [],
  };
  if (acc && op) {
    const queue = inventory.flatMap(({ repo, deps }) => deps.filter((d) => d.version && /^[\w.+-]+$/.test(d.version)).map((d) => ({ repo, d }))).slice(0, MAX_OSV_QUERIES);
    for (const { repo, d } of queue) {
      if (signal?.aborted) break;
      record.osv.queried++;
      try {
        const r = await acc.call(op, { name: d.name, ecosystem: OSV_ECOSYSTEM[d.ecosystem as DependencyEcosystem], version: d.version! }, `依赖漏洞检查：${d.name}@${d.version}`, signal);
        if (r.isError || r.pending) { record.osv.failed++; continue; }
        const advisories = parseAdvisories(r.text);
        if (advisories.length) record.hits.push({ repo, ecosystem: d.ecosystem, name: d.name, version: d.version!, path: d.path, line: d.line, advisories: advisories.slice(0, 10) });
      } catch {
        record.osv.failed++;
      }
    }
  }
  rt.event('judgement.made', { kind: 'dependencies', record });
  return record;
}

/** The section the expert owning dependency issues gets (leads, not must-answer). */
export function dependencyLines(hits: DependencyHit[]): string[] {
  if (!hits.length) return [];
  return [
    '', P('domains.dependencies', { n: hits.length }),
    ...hits.slice(0, 40).map((h) => `- ${h.name}@${h.version}（${h.ecosystem}，${h.repo}:${h.path}:${h.line}）：${h.advisories.slice(0, 5).map((a) => `${a.id}${a.aliases.length ? `/${a.aliases[0]}` : ''}${a.summary ? ` ${a.summary.slice(0, 120)}` : ''}`).join('；')}`),
  ];
}
