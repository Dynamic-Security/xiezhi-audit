#!/usr/bin/env node
// xiezhi eval — benchmark harness. Exit codes: 0 ok, 1 validation
// problems found, 2 usage / configuration / system error, 3 some benchmark runs did not complete.
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { stringify } from 'yaml';
import { Replayer, type ModelMode } from '@xiezhi/agent';
import { builtinSkillsDir } from '@xiezhi/knowledge';
import { checkRootHashes, loadBench, prepareTrees, staticChecks, TreeHasher } from './bench.js';
import { ablationExperiment, runExperiment } from './experiment.js';
import { gateScores, renderGate } from './gate.js';
import { importCommand } from './import.js';
import { holdoutFingerprints, scanForLeaks } from './leak.js';
import { renderReport } from './report.js';
import { parseFilter, runBench } from './runner.js';
import { scoreRunDir, type ScoreResult } from './score.js';
import { cacheDirOf, isRemoteOrigin, materializeRemote, type RemoteOptions } from './trees.js';
import { EvalError, readJson, writeJson } from './util.js';
import { existsSync } from 'node:fs';
import type { Partition } from './schema.js';

const HELP = `xiezhi eval — 评测基准工具

用法：xiezhi eval <命令> [参数]        （基准目录：--bench DIR 或环境变量 XIEZHI_AUDIT_BENCH；基准数据需自备，安装包不附带）

  validate [--bench DIR] [--json] [--offline] 校验 manifest / 标注 / 裁定 schema、root_hash、分区与防泄漏规则
  hash <目录 | https-URL@commit>...           计算源码的 root_hash（与产品快照一致），用于填写 manifest
  run --config FILE --out DIR [--partition dev|holdout] [--filter k=v[,v]]... [--repeats N]
      [--bench DIR] [--knowledge DIR] [--parallel N] [--max-cost-usd X] [--keep-data] [--allow-holdout]
      [--cache DIR] [--override JSON|FILE] [--replay FIXTURE]
                                             运行基准（每次运行使用全新的临时 data-dir；--override 为任务级策略覆盖）
  score <运行目录> [--bench DIR]               独立评分：写 score.json 与 adjudication.yaml（待裁定队列）
  report <运行目录>                           写 report.json 与 report.md（确定性渲染）
  experiment <实验.yaml> --config FILE --out DIR [--bench DIR] [--knowledge DIR] [--allow-holdout] [--cache DIR]
                                             策略对比实验（单字段变体、重复、配对 bootstrap、McNemar）
  ablation --out FILE [--bench DIR] [--scene full|incremental] [--stages id[,id]] [--repeats N] [--partition dev|holdout] [--filter k=v[,v]]...
                                             按阶段目录生成消融实验配置：每个带策略开关的阶段一个变体（默认开 → 关，默认关 → 开）；
                                             用 experiment 运行
  gate <基线运行目录> <候选运行目录> [--bench DIR] [--min-repeats N] [--out DIR]
                                             回归门禁：召回与精度配对比较、各样本命中范围、费用与上下文；
                                             写 gate.json 与 gate.md；退出码 0 不降、1 下降、3 样本不足
  import <cwe-bench-java | osv-go | osv> --data DIR --select FILE --out DIR [--sources-cache DIR] [--offline]
                                             公开数据集导入：按选择文件拉取漏洞 / 修复版本，输出样本与标注草稿

过滤键：sample、project、kind、language、scene、tag、dataset、tier（smoke ⊂ core ⊂ full）。
--cache DIR：结果缓存；被测代码有未提交改动时不缓存。
远程样本（origin 为 https Git 地址 + commit）拉取到 --sources-cache DIR（默认 XIEZHI_AUDIT_BENCH_CACHE 或 <基准>/.cache）；
--offline 只用已拉取的缓存。远程源码只作为被审数据，从不构建、运行或测试。
--config 是显式的配置文件（config.json 格式）；评测从不读取用户数据目录（~/.xiezhi-code-audit）。
留出集只在发布评测时运行，需要 --allow-holdout；运行前会扫描知识库中的留出集答案指纹。`;

const TREE_OPTIONS = { 'sources-cache': { type: 'string' }, offline: { type: 'boolean' } } as const;
function treeOptions(v: { 'sources-cache'?: string | undefined; offline?: boolean | undefined }): RemoteOptions {
  return { ...(v['sources-cache'] ? { cacheDir: resolve(v['sources-cache']) } : {}), ...(v.offline ? { offline: true } : {}), log: print };
}

const print = (s: string) => process.stdout.write(s + '\n');

/** The benchmark is a directory of its own, not shipped with the package: `--bench DIR` or `XIEZHI_AUDIT_BENCH`. */
function benchDir(v: string | undefined): string {
  const dir = v ?? process.env.XIEZHI_AUDIT_BENCH;
  if (!dir) throw new EvalError('USAGE', '需要基准目录：--bench <目录> 或环境变量 XIEZHI_AUDIT_BENCH（基准数据需自备，安装包不附带）');
  return resolve(dir);
}

async function cmdValidate(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: { bench: { type: 'string' }, json: { type: 'boolean' }, ...TREE_OPTIONS } });
  const bench = loadBench(benchDir(values.bench));
  // Remote trees are fetched first so that their label anchors and root hashes are checked too.
  const unfetched = await prepareTrees(bench, bench.samples, treeOptions(values));
  const issues = staticChecks(bench);
  const bad = await checkRootHashes(bench, bench.samples.filter((s) => !unfetched.has(s.sample_id)));
  for (const [sid, why] of [...unfetched, ...bad]) for (const w of why) issues.push({ level: 'error', where: `sample ${sid}`, message: `样本作废：${w}` });
  // The built-in skills must never carry holdout answers.
  const leaks = scanForLeaks([builtinSkillsDir()], holdoutFingerprints(bench));
  for (const l of leaks) issues.push({ level: 'error', where: l.file, message: `内置 skill 中出现留出集指纹（${l.kind}: ${l.value}）` });
  const errors = issues.filter((i) => i.level === 'error');
  const counts = {
    samples: bench.samples.length, labels: bench.labels.size, projects: new Set(bench.samples.map((s) => s.project)).size,
    dev: bench.samples.filter((s) => s.partition === 'dev').length, holdout: bench.samples.filter((s) => s.partition === 'holdout').length,
    smoke: bench.samples.filter((s) => s.tier === 'smoke').length, core: bench.samples.filter((s) => s.tier === 'smoke' || s.tier === 'core').length,
    remote: bench.samples.filter((s) => s.repos.some((r) => isRemoteOrigin(r.origin))).length,
    decisions: [...bench.decisions.values()].reduce((n, d) => n + d.length, 0),
  };
  if (values.json) {
    process.stdout.write(JSON.stringify({ bench_version: bench.manifest.bench_version, manifest_hash: bench.manifestHash, labels_hash: bench.labelsHash, ...counts, issues }, null, 2) + '\n');
  } else {
    print(`基准 ${bench.manifest.bench_version}：${counts.projects} 个项目，${counts.samples} 个样本（dev ${counts.dev} / holdout ${counts.holdout}；冒烟 ${counts.smoke} / 核心 ${counts.core}；远程 ${counts.remote}），${counts.labels} 条标注，${counts.decisions} 条裁定`);
    for (const i of issues) print(`${i.level === 'error' ? '错误' : '提示'}  ${i.where}：${i.message}`);
    print(errors.length ? `校验失败：${errors.length} 个错误` : '校验通过');
  }
  return errors.length ? 1 : 0;
}

async function cmdHash(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { bench: { type: 'string' }, ...TREE_OPTIONS } });
  if (!positionals.length) throw new EvalError('USAGE', 'hash 需要至少一个目录或 https-URL@commit');
  const h = new TreeHasher();
  try {
    for (const a of positionals) {
      if (isRemoteOrigin(a)) {
        const at = a.lastIndexOf('@');
        if (at < 0) throw new EvalError('USAGE', `远程仓库写成 URL@commit：${a}`);
        const opts = treeOptions(values);
        const t = await materializeRemote({ origin: a.slice(0, at), commit: a.slice(at + 1) }, cacheDirOf(values.bench ?? process.env.XIEZHI_AUDIT_BENCH ?? process.cwd(), opts), opts)
          .catch((e: Error) => { throw new EvalError('USAGE', e.message); });
        print(`${t.rootHash}  ${a}`);
      } else {
        print(`${await h.hash(resolve(a))}  ${a}`);
      }
    }
  } finally {
    h.dispose();
  }
  return 0;
}

function modeFrom(replay: string | undefined): ModelMode | undefined {
  return replay ? { kind: 'replay', replayer: Replayer.load(resolve(replay)) } : undefined;
}

async function cmdRun(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args, options: {
      bench: { type: 'string' }, config: { type: 'string' }, out: { type: 'string' }, partition: { type: 'string' }, filter: { type: 'string', multiple: true },
      repeats: { type: 'string' }, knowledge: { type: 'string' }, parallel: { type: 'string' }, 'max-cost-usd': { type: 'string' }, 'keep-data': { type: 'boolean' },
      'allow-holdout': { type: 'boolean' }, replay: { type: 'string' }, name: { type: 'string' }, cache: { type: 'string' }, override: { type: 'string' }, ...TREE_OPTIONS,
    },
  });
  // Task-level strategy override (same layer as an experiment arm), as inline JSON or a JSON file.
  let strategyOverride: Record<string, unknown> | undefined;
  if (values.override) {
    const raw = values.override.trim().startsWith('{') ? values.override : readFileSync(resolve(values.override), 'utf8');
    try { strategyOverride = JSON.parse(raw) as Record<string, unknown>; } catch (e) { throw new EvalError('USAGE', `--override 不是合法 JSON：${(e as Error).message}`); }
    if (!strategyOverride || typeof strategyOverride !== 'object' || Array.isArray(strategyOverride)) throw new EvalError('USAGE', '--override 必须是 JSON 对象');
  }
  if (!values.config) throw new EvalError('USAGE', 'run 需要 --config FILE（显式的模型服务配置）');
  if (!values.out) throw new EvalError('USAGE', 'run 需要 --out DIR');
  const partition = (values.partition ?? 'dev') as Partition;
  if (partition !== 'dev' && partition !== 'holdout') throw new EvalError('USAGE', '--partition 只能是 dev 或 holdout');
  const mode = modeFrom(values.replay);
  const meta = await runBench({
    bench: loadBench(benchDir(values.bench)), configPath: values.config, out: values.out, partition, filter: parseFilter(values.filter ?? []),
    repeats: values.repeats ? Number(values.repeats) : 1, ...(values.knowledge ? { knowledgeDir: values.knowledge } : {}),
    ...(values.parallel ? { maxParallel: Number(values.parallel) } : {}), ...(values['max-cost-usd'] ? { maxCostUsd: Number(values['max-cost-usd']) } : {}),
    ...(values['keep-data'] ? { keepData: true } : {}), ...(values['allow-holdout'] ? { allowHoldout: true } : {}), ...(mode ? { mode } : {}),
    ...(values.name ? { name: values.name } : {}), ...(values.cache ? { cacheDir: resolve(values.cache) } : {}), trees: treeOptions(values), log: print,
    ...(strategyOverride ? { strategyOverride } : {}),
  });
  const results = Object.entries(meta.results).sort().map(([k, v]) => `${k} ${v}`).join('，') || '无';
  const cached = meta.cache?.enabled ? `；复用缓存 ${meta.cache.hits} 次，写入 ${meta.cache.stored} 次` : '';
  print(`运行结束：${meta.selected.length} 个样本 × ${meta.repeats} 次（${results}）；作废 ${Object.keys(meta.invalid).length}；未运行 ${meta.skipped.length}${cached}。结果在 ${resolve(values.out)}`);
  print(`下一步：xiezhi eval score ${values.out} && xiezhi eval report ${values.out}`);
  // Exit 3 (like the product CLI) when any run did not complete; the records are still written.
  const done = meta.results.completed ?? 0;
  return done === Object.values(meta.results).reduce((a, b) => a + b, 0) && !meta.skipped.length && !Object.keys(meta.invalid).length ? 0 : 3;
}

async function scoreAndWrite(runDir: string, bench?: string, trees: RemoteOptions = {}): Promise<ScoreResult> {
  const score = await scoreRunDir(runDir, bench ? benchDir(bench) : undefined, { trees });
  writeJson(join(runDir, 'score.json'), score);
  writeFileSync(join(runDir, 'adjudication.yaml'), stringify({
    note: [
      '未被标注的发现（待裁定）。',
      'label_policy: complete 的样本：人工判定后回写 bench/labels 并递增 manifest 版本；留出集补标单独记录。',
      'label_policy: known_only 的样本（真实项目）：把判定按 key 写入 bench/adjudication/<project>.yaml（verdict: true_positive / false_positive），不改标注。',
    ].join('\n'),
    items: score.adjudication,
  }));
  return score;
}

async function cmdScore(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { bench: { type: 'string' }, ...TREE_OPTIONS } });
  const dir = positionals[0];
  if (!dir) throw new EvalError('USAGE', 'score 需要运行目录');
  const s = await scoreAndWrite(resolve(dir), values.bench, treeOptions(values));
  const q = s.quality;
  const pct = (x: number | null) => (x === null ? '不适用' : `${(x * 100).toFixed(1)}%`);
  const adj = q.adjudication.runs ? `（只标已知漏洞的样本已裁定 ${pct(q.adjudication.coverage)}）` : '';
  print(`完成率 ${pct(s.availability.completion_rate)}；Precision ${pct(q.precision)}${adj}，Recall ${pct(q.recall)}，F1 ${q.f1 ?? '不适用'}，Recall_mixed ${pct(q.recall_mixed)}，Recall_loose ${pct(q.recall_loose)}；待裁定 ${s.adjudication.length} 条`);
  return 0;
}

async function cmdReport(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { bench: { type: 'string' }, ...TREE_OPTIONS } });
  const dir = positionals[0];
  if (!dir) throw new EvalError('USAGE', 'report 需要运行目录');
  const abs = resolve(dir);
  const score = existsSync(join(abs, 'score.json')) ? readJson<ScoreResult>(join(abs, 'score.json')) : await scoreAndWrite(abs, values.bench, treeOptions(values));
  writeJson(join(abs, 'report.json'), score);
  writeFileSync(join(abs, 'report.md'), renderReport(score));
  print(`已写入 ${join(abs, 'report.md')}`);
  return 0;
}

async function cmdExperiment(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args, allowPositionals: true,
    options: {
      bench: { type: 'string' }, config: { type: 'string' }, out: { type: 'string' }, knowledge: { type: 'string' }, 'allow-holdout': { type: 'boolean' }, replay: { type: 'string' },
      cache: { type: 'string' }, ...TREE_OPTIONS,
    },
  });
  const file = positionals[0];
  if (!file) throw new EvalError('USAGE', 'experiment 需要实验配置文件');
  if (!values.config || !values.out) throw new EvalError('USAGE', 'experiment 需要 --config FILE 与 --out DIR');
  const mode = modeFrom(values.replay);
  const r = await runExperiment({
    experimentPath: resolve(file), benchRoot: benchDir(values.bench), configPath: values.config, out: values.out,
    ...(values.knowledge ? { knowledgeDir: values.knowledge } : {}), ...(values['allow-holdout'] ? { allowHoldout: true } : {}), ...(mode ? { mode } : {}), log: print,
    ...(values.cache ? { cacheDir: resolve(values.cache) } : {}), trees: treeOptions(values),
  });
  for (const c of r.comparisons) print(`${c.variant}：${c.primary.metric} ${c.primary.conclusion}（方向：${c.primary.direction}）— ${c.recommendation}`);
  print(`已写入 ${join(resolve(values.out), 'experiment.md')}`);
  return 0;
}

async function cmdAblation(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args, options: {
      bench: { type: 'string' }, out: { type: 'string' }, scene: { type: 'string' }, stages: { type: 'string' }, repeats: { type: 'string' },
      partition: { type: 'string' }, filter: { type: 'string', multiple: true }, name: { type: 'string' },
    },
  });
  if (!values.out) throw new EvalError('USAGE', 'ablation 需要 --out FILE（实验配置 YAML）');
  const scene = values.scene ?? 'full';
  if (scene !== 'full' && scene !== 'incremental') throw new EvalError('USAGE', '--scene 只能是 full 或 incremental');
  const partition = (values.partition ?? 'dev') as Partition;
  if (partition !== 'dev' && partition !== 'holdout') throw new EvalError('USAGE', '--partition 只能是 dev 或 holdout');
  const repeats = values.repeats ? Number(values.repeats) : undefined;
  if (repeats !== undefined && (!Number.isInteger(repeats) || repeats < 1)) throw new EvalError('USAGE', '--repeats 需要正整数');
  const exp = ablationExperiment({
    benchVersion: loadBench(benchDir(values.bench)).manifest.bench_version, scene, partition,
    ...(values.stages ? { stages: values.stages.split(',').map((x) => x.trim()).filter(Boolean) } : {}),
    ...(repeats ? { repeats } : {}), filter: parseFilter(values.filter ?? []), ...(values.name ? { name: values.name } : {}),
  });
  writeFileSync(resolve(values.out), stringify(exp));
  print(`已写入 ${resolve(values.out)}：${exp.variants.map((v) => v.name).join('、')}，每组 ${exp.repeats} 次`);
  return 0;
}

async function cmdGate(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { bench: { type: 'string' }, 'min-repeats': { type: 'string' }, out: { type: 'string' }, ...TREE_OPTIONS } });
  const [baseDir, candDir] = positionals;
  if (!baseDir || !candDir) throw new EvalError('USAGE', 'gate 需要基线运行目录与候选运行目录');
  const scoreOf = async (d: string) => (existsSync(join(resolve(d), 'score.json')) ? readJson<ScoreResult>(join(resolve(d), 'score.json')) : scoreAndWrite(resolve(d), values.bench, treeOptions(values)));
  const minRepeats = values['min-repeats'] ? Number(values['min-repeats']) : undefined;
  if (minRepeats !== undefined && (!Number.isInteger(minRepeats) || minRepeats < 1)) throw new EvalError('USAGE', '--min-repeats 需要正整数');
  const g = gateScores(await scoreOf(baseDir), await scoreOf(candDir), minRepeats ? { minRepeats } : {});
  const out = resolve(values.out ?? candDir);
  writeJson(join(out, 'gate.json'), g);
  writeFileSync(join(out, 'gate.md'), renderGate(g));
  print(`门禁：${g.verdict}${g.reasons.length ? `（${g.reasons.join('；')}）` : ''}；已写入 ${join(out, 'gate.md')}`);
  return g.verdict === '不降' ? 0 : g.verdict === '下降' ? 1 : 3;
}

async function cmdImport(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { data: { type: 'string' }, select: { type: 'string' }, out: { type: 'string' }, ...TREE_OPTIONS } });
  if (!positionals[0]) throw new EvalError('USAGE', 'import 需要数据集名（cwe-bench-java 或 osv-go）');
  return importCommand(positionals[0], values, treeOptions(values), print);
}

export async function main(argv: string[]): Promise<number> {
  const [cmd, ...args] = argv;
  switch (cmd) {
    case undefined: case 'help': case '--help': case '-h': print(HELP); return 0;
    case 'validate': return cmdValidate(args);
    case 'hash': return cmdHash(args);
    case 'run': return cmdRun(args);
    case 'score': return cmdScore(args);
    case 'report': return cmdReport(args);
    case 'experiment': return cmdExperiment(args);
    case 'ablation': return cmdAblation(args);
    case 'gate': return cmdGate(args);
    case 'import': return cmdImport(args);
    default: throw new EvalError('USAGE', `未知命令 ${cmd}；运行 xiezhi eval help 查看用法`);
  }
}

export function errorText(e: unknown): string {
  if (e instanceof EvalError) return [`错误 [${e.code}]：${e.message}`, ...e.details.map((d) => `  - ${d}`)].join('\n');
  return `错误：${(e as Error).message}`;
}

const isEntry = !!process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
if (isEntry) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (e) => {
      process.stderr.write(errorText(e) + '\n');
      process.exitCode = 2;
    },
  );
}
