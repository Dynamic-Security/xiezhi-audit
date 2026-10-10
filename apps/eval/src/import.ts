// Public dataset import. Turns a reviewed selection of dataset records
// (CWE-Bench-Java CSV rows, OSV / Go vulndb records) into remote URL + commit sample drafts and label files
// in the benchmark's remote-sample format (`label_policy: known_only`, vuln + fixed pairs, the fix location as the decoy of the
// fixed version). Sources are fetched only through `materializeRemote` (the product's hardened Git) into the
// shared cache and are read as data: never built, run or tested. Dataset files and advisory
// text are untrusted data; they only ever become label text. The output is a draft for human review: nothing
// here writes the benchmark manifest.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Type, type Static } from 'typebox';
import { stringify } from 'yaml';
import { closedSet as lit, isTestPath as isAuditTestPath, sha256Hex, VULN_CATEGORIES } from '@xiezhi/contracts';
import { normCwe } from './categories.js';
import { functionSpans, listFunctions, type FunctionSpan } from './locate.js';
import { DEPTHS, LANGUAGES, PARTITIONS, type Sample } from './schema.js';
import { cacheDirOf, materializeRemote, type RemoteOptions, type RemoteTree } from './trees.js';
import { byString, EvalError, readYamlFile, validated, walkFiles } from './util.js';

export interface DatasetPlan {
  dataset: string;
  url: string;
  license: string;
  steps: string[];
  /** Implemented importers read `--data` and `--select`; the others only document the plan and refuse. */
  implemented: boolean;
}

export const PUBLIC_DATASETS: DatasetPlan[] = [
  {
    dataset: 'cwe-bench-java', url: 'https://github.com/iris-sast/cwe-bench-java', license: 'dataset MIT; code per upstream project', implemented: true,
    steps: [
      '下载数据集仓库固定提交的 data/project_info.csv、data/fix_info.csv 与所选条目的 advisory/<slug>.json 到 --data 目录（只作数据读取）',
      '在选择文件中列出条目（project_slug）、项目名、分区、标注前缀与许可证；需要时指定 primary（数据集列出的方法之一）',
      '导入器按 buggy_commit_id / 最后一个 fix_commit_id 拉取两棵树，按修复差异定位函数，输出样本与标注草稿，人工核对后合入基准',
    ],
  },
  {
    dataset: 'owasp-benchmark-java', url: 'https://github.com/OWASP-Benchmark/BenchmarkJava', license: 'GPL-2.0', implemented: false,
    steps: [
      '用户自行下载 BenchmarkJava 指定版本；只抽样子集用于冒烟，不作为主质量结论',
      '去掉用例中暗示答案的注释与 expectedresults-*.csv（这些文件不得进入快照），用 expectedresults 生成标注',
      '源码与标注分目录存放；GPL 源码不随仓库分发，只保存下载脚本与哈希',
    ],
  },
  {
    dataset: 'osv', url: 'https://osv.dev', license: 'CC-BY-4.0 (advisory data); code per upstream project', implemented: true,
    steps: [
      '从 api.osv.dev 下载所选 advisory 的 OSV JSON 到 --data 目录（<ID>.json）；选择文件写明生态（PyPI / npm / Packagist / NuGet / Maven / Go / RubyGems / crates.io）',
      '每个条目写明漏洞版本提交（修复提交的父提交，人工核对）、项目名、分区、标注前缀、许可证；需要时写 language（npm 的 typescript、Maven 的 kotlin）、fixed_commit、primary',
      '危险点：Go 用 ecosystem_specific.imports 的符号；其他生态取修复提交改动的该语言源码函数（评测自带的函数定位器），人工核对后合入基准',
    ],
  },
  {
    dataset: 'osv-go', url: 'https://osv.dev (Go vulnerability database)', license: 'CC-BY-4.0 (advisory data); code per upstream project', implemented: true,
    steps: [
      '从 OSV / Go 漏洞库下载所选 advisory 的 OSV JSON 到 --data 目录（<ID>.json）；只选有修复提交（GIT 范围或 FIX 提交引用）的 Web / RPC 服务',
      '在选择文件中写明漏洞版本提交（修复提交的父提交，人工核对）、项目名、分区、标注前缀、许可证；记录缺 CWE 时从 GHSA 补上',
      '导入器按 ecosystem_specific.imports 的符号与修复差异定位函数，输出样本与标注草稿，人工核对后合入基准',
    ],
  },
];

// ---- selection file (reviewed input) ----

const Id = Type.String({ pattern: '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' });
const Commit = Type.String({ pattern: '^[0-9a-f]{40}$' });

export const SelectionEntry = Type.Object({
  /** CWE-Bench-Java project_slug, or the OSV id (file `<id>.json` in --data). */
  id: Type.String({ minLength: 1, maxLength: 200 }),
  project: Id,
  partition: lit(PARTITIONS),
  /** Label ids become `<prefix>-<CATEGORY>-01` and `<prefix>-FIX`. */
  label_prefix: Type.String({ pattern: '^[A-Z][A-Z0-9]{0,15}$' }),
  license: Type.String({ minLength: 1, maxLength: 100 }),
  /** Canonical https URL when the dataset names a moved repository (file:// only where the fetch allows it: tests). */
  url: Type.Optional(Type.String({ pattern: '^(https|file)://' })),
  vuln_commit: Type.Optional(Commit),
  fixed_commit: Type.Optional(Commit),
  /** One of the functions the dataset names (`Class.method` / `Recv.Method` / `Func`), optionally in `file`. */
  primary: Type.Optional(Type.String({ minLength: 1, maxLength: 200 })),
  primary_file: Type.Optional(Type.String({ minLength: 1, maxLength: 500 })),
  category: Type.Optional(lit(VULN_CATEGORIES)),
  cwe: Type.Optional(Type.Array(Type.String({ pattern: '^CWE-\\d{1,5}$' }), { minItems: 1 })),
  root_cause: Type.Optional(Type.String({ minLength: 1, maxLength: 2000 })),
  depth: Type.Optional(lit(DEPTHS)),
  /** Disclosure date (YYYY-MM-DD) when the record's `published` is not the disclosure. */
  disclosed: Type.Optional(Type.String({ pattern: '^\\d{4}-\\d{2}-\\d{2}$' })),
  tags: Type.Optional(Type.Array(Id)),
  /** `osv`: the audited language when the ecosystem does not fix it (npm → javascript | typescript, Maven → java | kotlin). */
  language: Type.Optional(lit(LANGUAGES)),
}, { additionalProperties: false });
export type SelectionEntry = Static<typeof SelectionEntry>;

export const OSV_ECOSYSTEMS = ['Go', 'PyPI', 'npm', 'Packagist', 'NuGet', 'Maven', 'RubyGems', 'crates.io'] as const;
const DEFAULT_LANGUAGE: Record<(typeof OSV_ECOSYSTEMS)[number], (typeof LANGUAGES)[number]> = {
  Go: 'go', PyPI: 'python', npm: 'javascript', Packagist: 'php', NuGet: 'csharp', Maven: 'java', RubyGems: 'ruby', 'crates.io': 'rust',
};
/** Source file extensions per audited language. */
const EXTS: Record<(typeof LANGUAGES)[number], string[]> = {
  java: ['.java'], go: ['.go'], python: ['.py'], javascript: ['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx'], typescript: ['.ts', '.tsx', '.mts', '.cts', '.js'],
  php: ['.php'], kotlin: ['.kt'], csharp: ['.cs'], ruby: ['.rb', '.rake'], rust: ['.rs'],
};

export const Selection = Type.Object({
  dataset: lit(['cwe-bench-java', 'osv-go', 'osv'] as const),
  /** `osv`: the OSV ecosystem of the selected records. */
  ecosystem: Type.Optional(lit(OSV_ECOSYSTEMS)),
  /** Where the dataset files came from (e.g. `iris-sast/cwe-bench-java@<commit>`), written into the review report. */
  dataset_ref: Type.String({ minLength: 1, maxLength: 300 }),
  entries: Type.Array(SelectionEntry, { minItems: 1, maxItems: 200 }),
}, { additionalProperties: false });
export type Selection = Static<typeof Selection>;

// ---- dataset records ----

/** RFC 4180 CSV (quoted fields, doubled quotes, newlines inside quotes) → rows of named fields. */
export function parseCsv(text: string): Record<string, string>[] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (c === '"') quoted = false; else field += c;
    } else if (c === '"') quoted = true;
    else if (c === ',') { row.push(field); field = ''; } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.some((x) => x.length)) rows.push(row);
      row = [];
    } else field += c;
  }
  if (field.length || row.length) { row.push(field); if (row.some((x) => x.length)) rows.push(row); }
  const [head, ...body] = rows;
  if (!head) return [];
  const names = head.map((h) => h.trim());
  return body.map((r) => Object.fromEntries(names.map((n, k) => [n, (r[k] ?? '').trim()])));
}

/** The subset of an OSV record the importer reads (https://ossf.github.io/osv-schema/). */
export interface OsvRecord {
  id: string;
  published?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: { cwe_ids?: string[] };
  references?: { type: string; url: string }[];
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { type: string; repo?: string; events: Record<string, string>[] }[];
    ecosystem_specific?: { imports?: { path: string; symbols?: string[] }[] };
  }[];
}

/** A named function the dataset points at: a file (Java) or a package directory (Go). */
interface Named { fn: string; file?: string; dir?: string }

interface Candidate {
  entry: SelectionEntry;
  url: string;
  vuln: string;
  fixed: string;
  named: Named[];
  cwe: string[];
  cweName: string;
  summary: string;
  refs: string[];
  disclosed: string | null;
  /** Audited language and its source extensions. */
  language: (typeof LANGUAGES)[number];
  exts: string[];
  datasetTag: string;
}

const CATEGORY_OF_CWE: Record<string, (typeof VULN_CATEGORIES)[number]> = {
  'CWE-22': 'path_traversal', 'CWE-23': 'path_traversal', 'CWE-35': 'path_traversal', 'CWE-36': 'path_traversal', 'CWE-73': 'path_traversal', 'CWE-59': 'path_traversal',
  'CWE-77': 'cmdi', 'CWE-78': 'cmdi', 'CWE-88': 'cmdi', 'CWE-79': 'xss', 'CWE-80': 'xss', 'CWE-94': 'code_injection', 'CWE-95': 'code_injection',
  'CWE-917': 'expression_injection', 'CWE-1336': 'ssti', 'CWE-502': 'deserialization', 'CWE-611': 'xxe', 'CWE-918': 'ssrf', 'CWE-89': 'sqli',
  'CWE-601': 'open_redirect', 'CWE-352': 'csrf', 'CWE-434': 'file_upload', 'CWE-287': 'authn', 'CWE-306': 'authn', 'CWE-290': 'authn',
  'CWE-639': 'authz_object', 'CWE-862': 'authz_object', 'CWE-863': 'authz_object', 'CWE-284': 'authz_object', 'CWE-285': 'authz_function', 'CWE-269': 'authz_function',
  'CWE-200': 'info_leak', 'CWE-209': 'info_leak', 'CWE-400': 'dos', 'CWE-770': 'dos', 'CWE-476': 'dos',
};
const ABBR: Record<string, string> = {
  path_traversal: 'PATH', cmdi: 'CMDI', xss: 'XSS', code_injection: 'CODE', expression_injection: 'EXPR', ssti: 'SSTI', deserialization: 'DESER', xxe: 'XXE',
  ssrf: 'SSRF', sqli: 'SQLI', open_redirect: 'REDIR', csrf: 'CSRF', file_upload: 'UPLOAD', authn: 'AUTHN', authz_object: 'IDOR', authz_function: 'AUTHZ', info_leak: 'LEAK', dos: 'DOS',
};

const isTestPath = (f: string, ext: string) => (ext === '.go' ? /_test\.go$/.test(f) : ext === '.java' ? /(^|\/)src\/test\/|Tests?\.java$/.test(f) : isAuditTestPath(f))
  || /(^|\/)(vendor|testdata|node_modules|third_party|e2e|__mocks__)\//.test(f) || /\.min\.js$/.test(f) || /\.e2e-spec\.[cm]?[jt]sx?$/.test(f);
const normCwes = (xs: string[]) => [...new Set(xs.map((x) => normCwe(x)).filter((x): x is string => !!x))];

function readInput(path: string): string {
  if (!existsSync(path)) throw new EvalError('USAGE', `找不到输入文件 ${path}`);
  return readFileSync(path, 'utf8');
}

function readOsv(path: string): OsvRecord {
  try {
    const r = JSON.parse(readInput(path)) as OsvRecord;
    if (typeof r?.id !== 'string') throw new Error('缺少 id');
    return r;
  } catch (e) {
    if (e instanceof EvalError) throw e;
    throw new EvalError('USAGE', `无法解析 OSV 记录 ${path}：${(e as Error).message}`);
  }
}

/** `https://github.com/o/r/commit/<sha>` → [repo URL, sha]. */
function commitRef(url: string): [string, string] | null {
  const m = /^(https:\/\/[^/]+\/[^/]+\/[^/]+?)(?:\.git)?\/commit\/([0-9a-f]{40})\/?$/.exec(url.trim());
  return m ? [m[1]!, m[2]!] : null;
}

function cweBenchCandidates(sel: Selection, dataDir: string, inputs: Map<string, string>): Candidate[] {
  const pf = join(dataDir, 'data', 'project_info.csv');
  const ff = join(dataDir, 'data', 'fix_info.csv');
  const ptext = readInput(pf);
  const ftext = readInput(ff);
  inputs.set('data/project_info.csv', sha256Hex(ptext));
  inputs.set('data/fix_info.csv', sha256Hex(ftext));
  const projects = parseCsv(ptext);
  const fixes = parseCsv(ftext);
  return sel.entries.map((e) => {
    const p = projects.find((r) => r.project_slug === e.id);
    if (!p) throw new EvalError('USAGE', `project_info.csv 中没有 ${e.id}`);
    const fixIds = (p.fix_commit_ids ?? '').split(';').map((x) => x.trim()).filter(Boolean);
    const fixed = e.fixed_commit ?? fixIds[fixIds.length - 1];
    const vuln = e.vuln_commit ?? p.buggy_commit_id;
    if (!fixed || !/^[0-9a-f]{40}$/.test(fixed) || !vuln || !/^[0-9a-f]{40}$/.test(vuln)) throw new EvalError('USAGE', `${e.id}：缺少 40 位的 buggy / fix 提交`);
    // Fixed methods in CSV order; test code is never a sink.
    const named: Named[] = fixes.filter((r) => r.project_slug === e.id && r.method && r.file && !isTestPath(r.file, '.java'))
      .map((r) => ({ fn: `${r.class}.${r.method}`, file: r.file }));
    // The advisory (OSV format, GHSA) gives the disclosure date and summary.
    const advFile = join(dataDir, 'advisory', `${e.id}.json`);
    const adv = existsSync(advFile) ? readOsv(advFile) : null;
    if (adv) inputs.set(`advisory/${e.id}.json`, sha256Hex(readFileSync(advFile, 'utf8')));
    const cwe = e.cwe ?? normCwes([p.cwe_id ?? '', ...(adv?.database_specific?.cwe_ids ?? [])]);
    return {
      entry: e, url: (e.url ?? p.github_url ?? '').replace(/\/+$/, '').replace(/\.git$/, ''), vuln, fixed, named, cwe, cweName: p.cwe_name ?? '',
      summary: adv?.summary ?? '', refs: [p.cve_id, p.advisory_id || adv?.id, `cwe-bench-java ${e.id}`].filter((x): x is string => !!x),
      disclosed: e.disclosed ?? adv?.published?.slice(0, 10) ?? null, language: 'java', exts: ['.java'], datasetTag: 'cwe_bench_java',
    };
  });
}

function osvGoCandidates(sel: Selection, dataDir: string, inputs: Map<string, string>): Candidate[] {
  return sel.entries.map((e) => {
    const file = join(dataDir, `${e.id}.json`);
    const rec = readOsv(file);
    inputs.set(`${e.id}.json`, sha256Hex(readFileSync(file, 'utf8')));
    if (rec.id !== e.id) throw new EvalError('USAGE', `${file} 的 id 是 ${rec.id}，不是 ${e.id}`);
    const go = (rec.affected ?? []).filter((a) => !a.package?.ecosystem || a.package.ecosystem === 'Go');
    // Fix commit: a GIT range `fixed` event, else a FIX reference to a commit.
    const gitFixes = go.flatMap((a) => (a.ranges ?? []).filter((r) => r.type === 'GIT' && r.repo).flatMap((r) => r.events.filter((ev) => ev.fixed).map((ev) => [r.repo!, ev.fixed!] as [string, string])));
    const refFixes = (rec.references ?? []).filter((r) => r.type === 'FIX').map((r) => commitRef(r.url)).filter((x): x is [string, string] => !!x);
    const all = [...gitFixes, ...refFixes];
    const distinct = [...new Set(all.map(([, c]) => c))];
    const fixed = e.fixed_commit ?? (distinct.length === 1 ? distinct[0] : undefined);
    if (!fixed) throw new EvalError('USAGE', `${e.id}：${distinct.length ? `有 ${distinct.length} 个修复提交，需在选择文件中指定 fixed_commit` : '没有 GIT 范围或 FIX 提交引用，不能导入'}`);
    const url = (e.url ?? all.find(([, c]) => c === fixed)?.[0] ?? all[0]?.[0] ?? '').replace(/\/+$/, '').replace(/\.git$/, '');
    // The vulnerable version is the fix's parent: a depth-1 fetch cannot see it, so the reviewer states it.
    if (!e.vuln_commit) throw new EvalError('USAGE', `${e.id}：需要 vuln_commit（修复提交 ${fixed.slice(0, 12)} 的父提交，人工核对）`);
    const modules = go.map((a) => a.package?.name ?? '').filter(Boolean).sort((a, b) => b.length - a.length);
    const named: Named[] = go.flatMap((a) => (a.ecosystem_specific?.imports ?? []).flatMap((imp) => {
      const mod = modules.find((m) => imp.path === m || imp.path.startsWith(`${m}/`));
      const dir = mod ? imp.path.slice(mod.length).replace(/^\//, '') : '';
      return (imp.symbols ?? []).map((s) => ({ fn: s, dir }));
    }));
    const cwe = e.cwe ?? normCwes(rec.database_specific?.cwe_ids ?? []);
    if (!cwe.length) throw new EvalError('USAGE', `${e.id}：OSV 记录没有 CWE，需在选择文件中给出 cwe（取自别名 GHSA）`);
    return {
      entry: e, url, vuln: e.vuln_commit, fixed, named, cwe, cweName: '', summary: rec.summary ?? '',
      refs: [...(rec.aliases ?? []).filter((a) => /^(CVE|GHSA)-/.test(a)).sort(), rec.id], disclosed: e.disclosed ?? rec.published?.slice(0, 10) ?? null,
      language: 'go', exts: ['.go'], datasetTag: 'osv_go',
    };
  });
}

/**
 * OSV records of any supported ecosystem. Fix commit: a GIT range `fixed` event, a FIX reference,
 * or the only commit link among the references; the vulnerable commit is the reviewer-checked parent. Records
 * outside Go name no symbols, so the sink comes from the functions the fix changed (or the selection's `primary`).
 */
function osvCandidates(sel: Selection, dataDir: string, inputs: Map<string, string>): Candidate[] {
  const eco = sel.ecosystem as (typeof OSV_ECOSYSTEMS)[number] | undefined;
  if (!eco) throw new EvalError('USAGE', '数据集 osv 的选择文件需要 ecosystem（PyPI / npm / Packagist / NuGet / Maven / Go / RubyGems / crates.io）');
  return sel.entries.map((e) => {
    const file = join(dataDir, `${e.id}.json`);
    const rec = readOsv(file);
    inputs.set(`${e.id}.json`, sha256Hex(readFileSync(file, 'utf8')));
    if (rec.id !== e.id) throw new EvalError('USAGE', `${file} 的 id 是 ${rec.id}，不是 ${e.id}`);
    const affected = (rec.affected ?? []).filter((a) => !a.package?.ecosystem || a.package.ecosystem === eco);
    const gitFixes = affected.flatMap((a) => (a.ranges ?? []).filter((r) => r.type === 'GIT' && r.repo).flatMap((r) => r.events.filter((ev) => ev.fixed).map((ev) => [r.repo!, ev.fixed!] as [string, string])));
    const refFixes = (rec.references ?? []).filter((r) => r.type === 'FIX').map((r) => commitRef(r.url)).filter((x): x is [string, string] => !!x);
    const anyCommits = (rec.references ?? []).map((r) => commitRef(r.url)).filter((x): x is [string, string] => !!x);
    const pool = gitFixes.length ? gitFixes : refFixes.length ? refFixes : anyCommits;
    const distinct = [...new Set(pool.map(([, c]) => c))];
    const fixed = e.fixed_commit ?? (distinct.length === 1 ? distinct[0] : undefined);
    if (!fixed) throw new EvalError('USAGE', `${e.id}：${distinct.length ? `有 ${distinct.length} 个候选修复提交，需在选择文件中指定 fixed_commit` : '没有修复提交（GIT 范围、FIX 引用或提交链接），不能导入'}`);
    const url = (e.url ?? pool.find(([, c]) => c === fixed)?.[0] ?? pool[0]?.[0] ?? '').replace(/\/+$/, '').replace(/\.git$/, '');
    if (!url) throw new EvalError('USAGE', `${e.id}：无法确定仓库地址，需在选择文件中给出 url`);
    if (!e.vuln_commit) throw new EvalError('USAGE', `${e.id}：需要 vuln_commit（修复提交 ${fixed.slice(0, 12)} 的父提交，人工核对）`);
    const language = (e.language ?? DEFAULT_LANGUAGE[eco]) as (typeof LANGUAGES)[number];
    const modules = affected.map((a) => a.package?.name ?? '').filter(Boolean).sort((a, b) => b.length - a.length);
    const named: Named[] = eco !== 'Go' ? [] : affected.flatMap((a) => (a.ecosystem_specific?.imports ?? []).flatMap((imp) => {
      const mod = modules.find((m) => imp.path === m || imp.path.startsWith(`${m}/`));
      const dir = mod ? imp.path.slice(mod.length).replace(/^\//, '') : '';
      return (imp.symbols ?? []).map((s) => ({ fn: s, dir }));
    }));
    const cwe = e.cwe ?? normCwes(rec.database_specific?.cwe_ids ?? []);
    if (!cwe.length) throw new EvalError('USAGE', `${e.id}：OSV 记录没有 CWE，需在选择文件中给出 cwe`);
    return {
      entry: e, url, vuln: e.vuln_commit, fixed, named, cwe, cweName: '', summary: rec.summary ?? '',
      refs: [...(rec.aliases ?? []).filter((a) => /^(CVE|GHSA)-/.test(a)).sort(), rec.id], disclosed: e.disclosed ?? rec.published?.slice(0, 10) ?? null,
      language, exts: EXTS[language], datasetTag: `osv_${eco.toLowerCase().replace(/[^a-z0-9]+/g, '_')}`,
    };
  });
}

// ---- diff of two trees by function ----

interface Fn extends FunctionSpan { file: string; body: string }

function functionsOf(dir: string, file: string): Fn[] {
  const abs = join(dir, file);
  if (!existsSync(abs)) return [];
  const text = readFileSync(abs, 'utf8');
  const lines = text.split('\n');
  return listFunctions(text, file).map((f) => ({ ...f, file, body: lines.slice(f.start - 1, f.end).map((l) => l.trimEnd()).join('\n') }));
}

/** Functions whose text differs between the trees (by qualified name; overloads compared together), vuln-side spans. */
export function changedFunctions(vulnDir: string, fixedDir: string, file: string): { vuln: Fn[]; fixed: Fn[] } {
  const a = functionsOf(vulnDir, file);
  const b = functionsOf(fixedDir, file);
  const group = (fs: Fn[]) => {
    const m = new Map<string, string>();
    for (const f of fs) m.set(f.qualified, [m.get(f.qualified), f.body].filter((x) => x !== undefined).join('\n\u0000\n'));
    return m;
  };
  const ga = group(a);
  const gb = group(b);
  const changed = (q: string) => ga.get(q) !== gb.get(q);
  const firstOf = (fs: Fn[]) => fs.filter((f, i) => changed(f.qualified) && fs.findIndex((g) => g.qualified === f.qualified) === i);
  return { vuln: firstOf(a), fixed: firstOf(b) };
}

/** Source files of a language whose contents differ between the trees (added, removed or modified), sorted. */
export function changedFiles(vulnDir: string, fixedDir: string, ext: string | string[]): string[] {
  const exts = Array.isArray(ext) ? ext : [ext];
  const pick = (d: string) => new Set(walkFiles(d).filter((f) => exts.some((x) => f.endsWith(x)) && !isTestPath(f, exts[0]!)));
  const a = pick(vulnDir);
  const b = pick(fixedDir);
  const out: string[] = [];
  for (const f of new Set([...a, ...b])) {
    if (!a.has(f) || !b.has(f) || readFileSync(join(vulnDir, f), 'utf8') !== readFileSync(join(fixedDir, f), 'utf8')) out.push(f);
  }
  return out.sort(byString);
}

/** Where a named function lives in a tree: its file (given, or searched in the package directory). */
function locate(dir: string, n: Named, ext: string | string[], prefer: string[]): { file: string; fn: string } | null {
  const exts = Array.isArray(ext) ? ext : [ext];
  const files = n.file ? [n.file] : walkFiles(join(dir, n.dir ?? '')).filter((f) => !f.includes('/') && exts.some((x) => f.endsWith(x)) && !isTestPath(f, exts[0]!)).map((f) => (n.dir ? `${n.dir}/${f}` : f));
  const hits = files.filter((f) => existsSync(join(dir, f)) && functionSpans(readFileSync(join(dir, f), 'utf8'), f, n.fn).length);
  const best = hits.find((f) => prefer.includes(f)) ?? hits[0];
  if (!best) return null;
  // Normalise to the qualified name the scorer's locator prints (e.g. inner classes).
  const span = functionSpans(readFileSync(join(dir, best), 'utf8'), best, n.fn)[0]!;
  return { file: best, fn: span.qualified };
}

// ---- building drafts ----

export interface ImportedPair {
  samples: Sample[];
  project: string;
  labels: Record<string, unknown>[];
  review: string[];
}

export interface ImportResult {
  dataset: string;
  datasetRef: string;
  pairs: ImportedPair[];
  inputs: Map<string, string>;
}

async function buildPair(c: Candidate, sel: Selection, trees: (commit: string) => Promise<RemoteTree>): Promise<ImportedPair> {
  const e = c.entry;
  const review: string[] = [];
  const warn = (s: string) => review.push(`- 注意：${s}`);
  const vt = await trees(c.vuln);
  const ft = await trees(c.fixed);
  const files = changedFiles(vt.dir, ft.dir, c.exts);
  // Primary sink: the reviewer's choice among the named functions, else the first named function that
  // exists in the vulnerable tree (preferring ones the fix changed), else the first changed function.
  const namedHere = c.named.map((n) => locate(vt.dir, n, c.exts, files)).filter((x): x is { file: string; fn: string } => !!x);
  const missing = c.named.filter((n) => !locate(vt.dir, n, c.exts, files));
  for (const n of missing) warn(`数据集列出的 ${n.fn}（${n.file ?? n.dir ?? ''}）在漏洞版本中不存在（多为修复新增），不作为危险点`);
  const changedIn = new Map<string, Set<string>>();
  const changedSet = (f: string) => changedIn.get(f) ?? changedIn.set(f, new Set(changedFunctions(vt.dir, ft.dir, f).vuln.map((x) => x.qualified))).get(f)!;
  const didChange = (x: { file: string; fn: string }) => files.includes(x.file) && changedSet(x.file).has(x.fn);
  let primary: { file: string; fn: string } | undefined;
  if (e.primary) {
    const want = e.primary;
    const matches = (q: string) => q === want || q.endsWith(`.${want}`);
    primary = (e.primary_file ? locate(vt.dir, { fn: want, file: e.primary_file }, c.exts, files) : null) ?? namedHere.find((n) => matches(n.fn));
    if (!primary && !e.primary_file) {
      for (const f of files) {
        const hit = functionsOf(vt.dir, f).find((x) => matches(x.qualified));
        if (hit) { primary = { file: f, fn: hit.qualified }; break; }
      }
    }
    if (!primary) throw new EvalError('USAGE', `${e.id}：选择文件指定的 primary ${e.primary} 在漏洞版本中找不到`);
    if (!namedHere.some((n) => n.fn === primary!.fn && n.file === primary!.file)) warn(`primary ${primary.fn} 不是数据集列出的方法（人工指定）`);
  } else {
    // Prefer a named function the fix changed, then one in a changed file, then any named function.
    primary = namedHere.find(didChange) ?? namedHere.find((n) => files.includes(n.file)) ?? namedHere[0];
    if (!primary) {
      for (const f of files) {
        const ch = changedFunctions(vt.dir, ft.dir, f).vuln[0];
        if (ch) { primary = { file: f, fn: ch.qualified }; warn(`数据集没有给出可用的方法，危险点取修复差异中的第一个变更函数 ${ch.qualified}，需人工确认`); break; }
      }
    }
  }
  if (!primary) throw new EvalError('USAGE', `${e.id}：漏洞版本中找不到可作为危险点的函数（修复差异中没有变更的函数）`);
  const inFile = changedFunctions(vt.dir, ft.dir, primary.file);
  if (!inFile.vuln.some((f) => f.qualified === primary!.fn)) warn(`危险点 ${primary.fn} 在两个版本之间没有变化（修复在别处）`);
  // Alternative sinks (max 4): named functions the fix changed, other changed functions in the primary's
  // file, the remaining named functions; with nothing named, the changed functions of the other changed files.
  const alt: { file: string; fn: string }[] = [];
  const add = (x: { file: string; fn: string }) => {
    if (alt.length >= 4 || (x.fn === primary!.fn && x.file === primary!.file) || alt.some((a) => a.fn === x.fn && a.file === x.file)) return;
    alt.push(x);
  };
  namedHere.filter(didChange).forEach(add);
  inFile.vuln.forEach((f) => add({ file: f.file, fn: f.qualified }));
  namedHere.forEach(add);
  if (!namedHere.length) for (const f of files) changedFunctions(vt.dir, ft.dir, f).vuln.forEach((x) => add({ file: f, fn: x.qualified }));
  // Decoy of the fixed version: the fix location — the primary sink as it is after the fix, else the first
  // changed alternative that still exists, else any alternative that exists.
  const inFixed = (x: { file: string; fn: string }) => existsSync(join(ft.dir, x.file)) && functionSpans(readFileSync(join(ft.dir, x.file), 'utf8'), x.file, x.fn).length > 0;
  const decoy = [primary].find(inFixed) ?? alt.filter(didChange).find(inFixed) ?? alt.find(inFixed);
  if (!decoy) throw new EvalError('USAGE', `${e.id}：修复版本中找不到修复位置（危险点函数被删除），需人工指定`);
  if (decoy !== primary) warn(`修复版本中没有 ${primary.fn}，诱饵点改用 ${decoy.fn}`);

  const category = e.category ?? c.cwe.map((x) => CATEGORY_OF_CWE[x]).find((x) => !!x) ?? 'other';
  const vid = `${e.label_prefix}-${ABBR[category] ?? category.toUpperCase().replace(/[^A-Z0-9]/g, '')}-01`;
  const fid = `${e.label_prefix}-FIX`;
  const repo = e.project;
  const refText = c.refs.join('; ');
  const rootCause = e.root_cause ?? `${c.summary || c.cweName || category}（${refText}；修复提交 ${c.fixed.slice(0, 12)}）`.slice(0, 2000);
  const multiFile = new Set([primary.file, ...alt.map((a) => a.file)]).size > 1;
  const vuln: Record<string, unknown> = {
    label_id: vid, kind: 'vuln', category, cwe: c.cwe.length ? c.cwe : ['CWE-20'], root_cause: rootCause,
    sink: { repo, file: primary.file, function: primary.fn },
    ...(alt.length ? { alt_sinks: alt.map((a) => ({ repo, file: a.file, function: a.fn })) } : {}),
    // Public datasets name no HTTP route: no entries (the entry-hit metric skips such labels).
    entries: [],
    expected: { verdict: 'confirmed' },
    depth: e.depth ?? (multiFile ? 'cross_file' : 'single_point'),
  };
  const negative: Record<string, unknown> = {
    label_id: fid, kind: 'negative', expected: { verdict: 'none' }, guard: 'fix', category,
    decoys: [{ repo, file: decoy.file, function: decoy.fn, note: `${refText} 的修复位置（修复提交 ${c.fixed.slice(0, 12)}）` }],
  };
  const year = c.disclosed?.slice(0, 4);
  const tags = [...new Set(['public_dataset', c.datasetTag, ...(year ? [`disclosed_${year}`] : []), ...(e.tags ?? [])])];
  const source = { dataset: sel.dataset, ref: refText.slice(0, 500), license: e.license };
  const mk = (kind: 'vuln' | 'fixed', commit: string, t: RemoteTree, labels: string[]): Sample => ({
    sample_id: `${e.project}-${kind}`, project: e.project, partition: e.partition, kind, language: c.language, source,
    repos: [{ name: repo, role: 'auditable', origin: c.url, commit, root_hash: t.rootHash }], scene: 'full', labels, tags, label_policy: 'known_only',
  });
  review.unshift(
    `## ${e.project}（${sel.dataset} ${e.id}，${e.partition}）`, '',
    `- 来源：${refText}；披露 ${c.disclosed ?? '未知'}；CWE ${c.cwe.join(', ') || '无'} → ${category}`,
    `- 仓库：${c.url}；漏洞版 \`${c.vuln}\`（root_hash ${vt.rootHash.slice(0, 16)}…）→ 修复版 \`${c.fixed}\`（${ft.rootHash.slice(0, 16)}…）`,
    `- 两版之间变化的 ${c.language} 源文件（不含测试）${files.length} 个${files.length ? `：${files.slice(0, 12).join(', ')}${files.length > 12 ? ' …' : ''}` : ''}`,
    `- 危险点：\`${primary.file}\` \`${primary.fn}\`；该文件中变化的函数：${inFile.vuln.map((f) => f.qualified).join(', ') || '无'}`,
    `- 备选危险点：${alt.map((a) => `${a.fn}（${a.file}）`).join('；') || '无'}`,
    `- 修复版诱饵点：${decoy.fn}（${decoy.file}）`,
  );
  return { project: e.project, samples: [mk('vuln', c.vuln, vt, [vid]), mk('fixed', c.fixed, ft, [fid])], labels: [vuln, negative], review };
}

export interface ImportOptions {
  dataset: string;
  /** Directory with the downloaded dataset files (CWE-Bench-Java: data/*.csv, advisory/; OSV: <id>.json). */
  dataDir: string;
  /** Reviewed selection YAML (schema `Selection`). */
  selectPath: string;
  /** Cache root for fetched trees; defaults like the other commands (`XIEZHI_AUDIT_BENCH_CACHE`, `<cwd>/.cache`). */
  trees?: RemoteOptions;
}

export async function importDataset(opts: ImportOptions): Promise<ImportResult> {
  const plan = PUBLIC_DATASETS.find((d) => d.dataset === opts.dataset);
  if (!plan) throw new EvalError('USAGE', `未知数据集：${opts.dataset}（可选：${PUBLIC_DATASETS.map((d) => d.dataset).join(', ')}）`);
  if (!plan.implemented) throw new EvalError('NOT_IMPLEMENTED', `导入 ${plan.dataset} 未实现。计划步骤：`, plan.steps.map((s, i) => `${i + 1}. ${s}`));
  const sel = validated(Selection, readYamlFile(resolve(opts.selectPath)), opts.selectPath);
  if (sel.dataset !== opts.dataset) throw new EvalError('USAGE', `选择文件的 dataset 是 ${sel.dataset}，不是 ${opts.dataset}`);
  const projects = sel.entries.map((e) => e.project);
  if (new Set(projects).size !== projects.length) throw new EvalError('USAGE', '选择文件中项目重复：每个条目是一个项目（一对漏洞 / 修复样本）');
  const inputs = new Map<string, string>();
  const cands = sel.dataset === 'cwe-bench-java' ? cweBenchCandidates(sel, resolve(opts.dataDir), inputs)
    : sel.dataset === 'osv' ? osvCandidates(sel, resolve(opts.dataDir), inputs) : osvGoCandidates(sel, resolve(opts.dataDir), inputs);
  const trees = opts.trees ?? {};
  const cacheDir = cacheDirOf(process.cwd(), trees);
  const pairs: ImportedPair[] = [];
  for (const c of cands) {
    const fetch = (commit: string) => materializeRemote({ origin: c.url, commit }, cacheDir, trees)
      .catch((err: Error) => { throw new EvalError('USAGE', `${c.entry.id}：拉取 ${c.url}@${commit.slice(0, 12)} 失败：${err.message}`); });
    pairs.push(await buildPair(c, sel, fetch));
  }
  return { dataset: sel.dataset, datasetRef: sel.dataset_ref, pairs, inputs };
}

/** Deterministic draft files: samples.yaml (manifest entries), labels/<project>.yaml, IMPORT.md (review notes). */
export function writeImport(r: ImportResult, outDir: string): string[] {
  const out = resolve(outDir);
  mkdirSync(join(out, 'labels'), { recursive: true });
  const written: string[] = [];
  const put = (rel: string, text: string) => { writeFileSync(join(out, rel), text); written.push(rel); };
  const order = ['sample_id', 'project', 'partition', 'kind', 'language', 'source', 'repos', 'scene', 'labels', 'tags', 'label_policy'];
  const samples = r.pairs.flatMap((p) => p.samples).map((s) => Object.fromEntries(order.filter((k) => k in s).map((k) => [k, (s as Record<string, unknown>)[k]])));
  // No anchors / aliases: the benchmark loader refuses them (and a reviewer edits each sample on its own).
  put('samples.yaml', stringify(samples, { lineWidth: 0, aliasDuplicateObjects: false }));
  for (const p of r.pairs) put(`labels/${p.project}.yaml`, stringify({ project: p.project, labels: p.labels }, { lineWidth: 0, aliasDuplicateObjects: false }));
  put('IMPORT.md', [
    `# ${r.dataset} 导入草稿（待人工核对）`, '',
    `- 数据来源：${r.datasetRef}`,
    ...[...r.inputs.entries()].sort((a, b) => byString(a[0], b[0])).map(([f, h]) => `- 输入 \`${f}\` sha256 \`${h}\``),
    '- 源码只经产品的加固 Git 拉取到缓存并作为数据读取，从未构建、安装依赖或运行。', '',
    ...r.pairs.flatMap((p) => [...p.review, '']),
  ].join('\n'));
  return written;
}

/** `xiezhi eval import` — parse options, import, write the draft. */
export async function importCommand(dataset: string, v: { data?: string | undefined; select?: string | undefined; out?: string | undefined }, trees: RemoteOptions, print: (s: string) => void): Promise<number> {
  const plan = PUBLIC_DATASETS.find((d) => d.dataset === dataset);
  if (!plan?.implemented) return importDataset({ dataset, dataDir: '.', selectPath: '.' }).then(() => 0); // throws: unknown / not implemented
  if (!v.data || !v.select || !v.out) throw new EvalError('USAGE', 'import 需要 --data DIR（下载的数据集文件）、--select FILE（选择文件）与 --out DIR（草稿输出目录）');
  const r = await importDataset({ dataset, dataDir: v.data, selectPath: v.select, trees });
  const files = writeImport(r, v.out);
  print(`导入 ${r.pairs.length} 个项目、${r.pairs.reduce((n, p) => n + p.samples.length, 0)} 个样本（草稿）：${files.map((f) => join(resolve(v.out!), f)).join('，')}`);
  print('下一步：人工核对 IMPORT.md 与标注，把 samples.yaml 合入 manifest、labels/ 复制到基准，并把 sources 中该数据集改为 active，然后运行 validate');
  return 0;
}
