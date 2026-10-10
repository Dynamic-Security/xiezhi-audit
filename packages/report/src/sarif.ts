// SARIF 2.1.0. One run per audit; one originalUriBaseId per repo so
// codeFlows can cross repositories.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { defaultCweFor, resolveCategory, sha256Hex } from '@xiezhi/contracts';
import type * as Sarif from 'sarif';
import { pendingOfDetail, STATIC_AUDIT_NOTE, type CodeLoc, type ReportFinding, type ReportModel } from './model.js';

export interface SarifOptions {
  /** Directory holding `snapshots/<rootHash>` (for snippets). */
  snapshotsDir: string;
  snippets: boolean;
  localRoots: boolean;
  /** Include fixed_verified vulnerabilities as `absent`. */
  includeFixed?: boolean;
  toolVersion: string;
}

const LEVEL: Record<string, Sarif.Result.level> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
const SECURITY_SEVERITY: Record<string, string> = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };

const baseId = (repo: string) => `REPO_${repo.replace(/[^A-Za-z0-9_]/g, '_')}`;
const uri = (p: string) => p.split('/').map(encodeURIComponent).join('/');

export function renderSarif(m: ReportModel, o: SarifOptions): string {
  const repoByName = new Map(m.repositories.map((r) => [r.name, r]));
  const snippet = (l: CodeLoc, rootHash?: string | null): string | undefined => {
    if (!o.snippets) return undefined;
    // A project-level export reads each location from the snapshot of the audit that found it.
    const root = rootHash ?? repoByName.get(l.repo)?.rootHash;
    if (!root) return undefined;
    const file = join(o.snapshotsDir, root, ...l.path.split('/'));
    if (!existsSync(file)) return undefined;
    return readFileSync(file, 'utf8').split(/\r?\n/).slice(l.startLine - 1, l.endLine).join('\n');
  };
  const physical = (l: CodeLoc, withSnippet = true, rootHash?: string | null) => {
    const text = withSnippet ? snippet(l, rootHash) : undefined;
    return {
      artifactLocation: { uri: uri(l.path), uriBaseId: baseId(l.repo) },
      region: { startLine: l.startLine, endLine: Math.max(l.endLine, l.startLine), ...(text !== undefined ? { snippet: { text } } : {}) },
    };
  };
  const all = [...m.findings];
  const categories = [...new Set(all.map((f) => f.category))].sort();
  const rules: Sarif.ReportingDescriptor[] = categories.map((c): Sarif.ReportingDescriptor => {
    const cwe = all.find((f) => f.category === c && f.cwe)?.cwe ?? defaultCweFor(resolveCategory(c));
    const sev = all.filter((f) => f.category === c).map((f) => f.severity).sort((a, b) => Number(SECURITY_SEVERITY[b]) - Number(SECURITY_SEVERITY[a]))[0] ?? 'medium';
    const cweNum = cwe?.replace('CWE-', '');
    return {
      id: c,
      name: c,
      shortDescription: { text: c },
      ...(cweNum ? { helpUri: `https://cwe.mitre.org/data/definitions/${cweNum}.html` } : {}),
      defaultConfiguration: { level: LEVEL[sev] },
      ...(cweNum ? { relationships: [{ target: { id: cweNum, toolComponent: { name: 'CWE' } }, kinds: ['relevant'] }] as Sarif.ReportingDescriptorRelationship[] } : {}),
      properties: { tags: ['security', ...(cweNum ? [`external/cwe/cwe-${cweNum}`] : [])], 'security-severity': SECURITY_SEVERITY[sev] },
    };
  });
  const cwes = [...new Set(rules.flatMap((r) => (r.relationships ?? []).map((x) => x.target.id!)))].sort((a, b) => Number(a) - Number(b));

  const result = (f: ReportFinding): Sarif.Result => {
    const baseline: Sarif.Result.baselineState = f.lifecycle === 'persisting' ? 'unchanged' : f.lifecycle === 'fixed_verified' ? 'absent' : 'new';
    const suppressions = f.confirmStatus === 'false_positive'
      ? [{ kind: 'external', status: 'accepted', justification: f.detail.challenge?.reason ?? '人工判定为误报' }] as Sarif.Suppression[]
      : f.handlingStatus === 'risk_accepted' ? [{ kind: 'external', status: 'accepted', justification: f.handlingReason ?? '接受风险' }] as Sarif.Suppression[] : undefined;
    const chain = f.detail.chain.length ? f.detail.chain : [];
    return {
      ruleId: f.category,
      ruleIndex: categories.indexOf(f.category),
      level: LEVEL[f.severity],
      message: { text: `${f.title}。${f.rootCause}` },
      locations: [{ physicalLocation: physical(f.location, true, f.origin?.rootHash), ...(f.sinkSymbol ? { logicalLocations: [{ fullyQualifiedName: f.sinkSymbol, kind: 'function' }] } : {}) }],
      ...(f.detail.evidence.length ? { relatedLocations: f.detail.evidence.map((e, i) => ({ id: i + 1, physicalLocation: physical(e, false), ...(e.note ? { message: { text: e.note } } : {}) })) } : {}),
      ...(chain.length ? {
        codeFlows: [{
          threadFlows: [{
            locations: chain.map((c) => ({ location: { physicalLocation: physical(c, false), ...(c.note ? { message: { text: c.note } } : {}) } })),
          }],
        }],
      } : {}),
      ...(f.fingerprint ? { partialFingerprints: { 'codeAuditVuln/v1': f.fingerprint } } : {}),
      ...(f.vulnId ? { correlationGuid: guidOf(f.vulnId) } : {}),
      baselineState: baseline,
      ...(suppressions ? { suppressions } : {}),
      properties: {
        'security-severity': SECURITY_SEVERITY[f.severity],
        severity: f.severity,
        confidence: f.confidence,
        confirmation: f.confirmStatus,
        handling: f.handlingStatus,
        crossAuditState: f.lifecycle,
        decisionSources: f.sources,
        ...(f.lifecycle === 'regressed' ? { regression: true } : {}),
        ...(pendingOfDetail(f.detail) ? { pendingReason: pendingOfDetail(f.detail)!.missing.map((m) => `${m.kind}:${m.ref}`).join('; ') } : {}),
        ...(f.vulnDisplayNo !== null ? { vulnerability: `V-${f.vulnDisplayNo}` } : {}),
        ...(f.vulnId ? { vulnId: f.vulnId } : {}),
        ...(!f.origin ? { finding: `F-${f.displayNo}` } : f.origin.findingNo !== null ? { finding: `F-${f.origin.findingNo}`, auditId: f.origin.auditId } : {}),
      },
    };
  };

  const results = m.findings.filter((f) => f.lifecycle !== 'fixed_verified' || o.includeFixed).map(result);
  const sarif: Sarif.Log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'xiezhi', semanticVersion: o.toolVersion, informationUri: 'https://www.npmjs.com/package/xiezhi-audit', rules,
          ...(cwes.length ? { supportedTaxonomies: [{ name: 'CWE', index: 0 }] } : {}),
        },
      },
      ...(cwes.length ? { taxonomies: [{ name: 'CWE', organization: 'MITRE', taxa: cwes.map((id) => ({ id })) }] } : {}),
      originalUriBaseIds: Object.fromEntries(m.repositories.map((r) => [baseId(r.name), o.localRoots
        ? { uri: pathToFileURL(r.locator.endsWith('/') ? r.locator : `${r.locator}/`).href, description: { text: `${r.name} (${r.roleInAudit})` } }
        : { description: { text: `${r.name} (${r.roleInAudit}); map to your local checkout` } }])),
      versionControlProvenance: m.repositories.filter((r) => r.commit).map((r) => ({
        repositoryUri: pathToFileURL(r.locator).href,
        revisionId: r.commit ?? undefined,
        ...(r.ref ? { branch: r.ref } : {}),
        mappedTo: { uriBaseId: baseId(r.name) },
        ...(r.worktree ? { properties: { workingTree: 'dirty', snapshotRootHash: r.rootHash } } : {}),
      })),
      invocations: [{
        executionSuccessful: m.audit.status === 'completed',
        ...(m.audit.partialReasons.length || m.audit.status !== 'completed' ? {
          toolExecutionNotifications: [
            ...m.audit.partialReasons.map((r): Sarif.Notification => ({ level: 'warning', message: { text: `PartialReason: ${r}` } })),
            ...(m.audit.status !== 'completed' ? [{ level: 'warning' as const, message: { text: `Audit status: ${m.audit.status}. Missing results do not mean the code is safe.` } }] : []),
          ],
        } : {}),
      }],
      results,
      properties: {
        ...(m.scope ? { scope: 'project', projectId: m.project.id, project: m.project.name, audits: m.scope.audits.map((a) => a.id) }
          : { auditId: m.audit.id, project: m.project.name, scene: m.audit.scene, status: m.audit.status }),
        notes: [STATIC_AUDIT_NOTE, ...(m.repositories.some((r) => r.worktree) ? ['Line numbers refer to the audited working-tree snapshot.'] : [])],
      },
    }],
  };
  return JSON.stringify(sarif, null, 2) + '\n';
}

/**
 * SARIF requires correlationGuid to be an RFC 4122 GUID; vulnerability ids are prefixed ULIDs. Derive
 * a stable name-based (v5-style, SHA-256 truncated) GUID from the id; the id itself is kept in
 * properties.vulnId. The seed keeps the name from before the rename, so GUIDs stay stable.
 */
export function guidOf(id: string): string {
  const h = sha256Hex(`code-audit/vuln/${id}`).split('');
  h[12] = '5';
  h[16] = ((parseInt(h[16]!, 16) & 0x3) | 0x8).toString(16);
  const x = h.join('');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20, 32)}`;
}
