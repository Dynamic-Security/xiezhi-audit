// Holdout anti-leak: before a holdout run, the knowledge visible to the product (global
// and project skills of the eval data-dir, plus the explicit knowledge set) must not contain holdout
// project names, sink function signatures or root-cause text fingerprints.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { Bench } from './bench.js';
import { byString, walkFiles } from './util.js';

export interface LeakFingerprints {
  projects: string[];
  functions: string[];
  /** Normalized root-cause n-grams → label id. */
  grams: Map<string, string>;
}

export interface LeakHit { file: string; kind: 'project' | 'function' | 'root_cause'; value: string }

/** Root-cause fingerprint length in normalized characters. */
export const GRAM = 14;

export function normalizeText(s: string): string {
  return s.toLowerCase().replace(/[\s\p{P}\p{S}]+/gu, '');
}

export function holdoutFingerprints(bench: Bench): LeakFingerprints {
  const holdProjects = new Set(bench.samples.filter((s) => s.partition === 'holdout').map((s) => s.project));
  const functions = new Set<string>();
  const grams = new Map<string, string>();
  for (const l of bench.labels.values()) {
    if (!holdProjects.has(l.project)) continue;
    const anchors = l.kind === 'vuln' ? [l.sink, ...(l.alt_sinks ?? [])] : l.kind === 'negative' ? l.decoys : l.kind === 'risk_hunt' ? l.targets.flatMap((t) => [...(t.locations ?? []), ...(t.reason_evidence ?? [])]) : [];
    for (const a of anchors) if (a.function?.includes('.')) functions.add(a.function);
    if (l.kind === 'vuln') {
      const n = normalizeText(l.root_cause);
      if (n.length <= GRAM) grams.set(n, l.label_id);
      else for (let i = 0; i + GRAM <= n.length; i++) grams.set(n.slice(i, i + GRAM), l.label_id);
    }
  }
  return { projects: [...holdProjects].sort(byString), functions: [...functions].sort(byString), grams };
}

function tokenRe(value: string): RegExp {
  const esc = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^\\w-])${esc}($|[^\\w-])`, 'i');
}

/** Skill directories of an eval data-dir: the global layer and every project layer. */
export function knowledgeDirs(dataDir: string): string[] {
  const out = [join(dataDir, 'knowledge', 'global')];
  const projects = join(dataDir, 'projects');
  if (existsSync(projects)) for (const p of readdirSync(projects).sort(byString)) out.push(join(projects, p, 'knowledge'));
  return out.filter((d) => existsSync(d) && statSync(d).isDirectory());
}

export function scanForLeaks(dirs: string[], fp: LeakFingerprints): LeakHit[] {
  const hits: LeakHit[] = [];
  const projectRes = fp.projects.map((p) => [p, tokenRe(p)] as const);
  const fnRes = fp.functions.map((f) => [f, tokenRe(f)] as const);
  for (const dir of dirs) {
    for (const rel of walkFiles(dir)) {
      const file = join(dir, rel);
      if (statSync(file).size > 2 * 1024 * 1024) continue;
      const text = readFileSync(file, 'utf8');
      for (const [p, re] of projectRes) if (re.test(text)) hits.push({ file, kind: 'project', value: p });
      for (const [f, re] of fnRes) if (re.test(text)) hits.push({ file, kind: 'function', value: f });
      const norm = normalizeText(text);
      const seen = new Set<string>();
      for (const [g, label] of fp.grams) {
        if (!seen.has(label) && norm.includes(g)) {
          seen.add(label);
          hits.push({ file, kind: 'root_cause', value: label });
        }
      }
    }
  }
  return hits;
}
