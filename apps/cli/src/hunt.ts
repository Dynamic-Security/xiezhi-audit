// `xiezhi hunt …`: risk hunts from the terminal — headless (engine in
// process) or client mode (through the running service). Output is the same in both modes.
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { formatTokens } from '@xiezhi/contracts';
import type { HuntBasis, HuntBasisDto, HuntDto, HuntResultsDto } from '@xiezhi/contracts';
import { CliExit, EXIT_ERROR, EXIT_INCOMPLETE, EXIT_OK, print } from './io.js';

export interface HuntApi {
  createBasis(input: { kind: 'skill'; skill: string } | { kind: 'prompt' | 'intel'; text: string }): Promise<string>;
  getBasis(id: string): Promise<HuntBasisDto>;
  createHunt(basisId: string, scope: { all: true } | { projectIds: string[] }): Promise<HuntDto>;
  confirm(huntId: string): Promise<void>;
  getHunt(huntId: string): Promise<HuntDto>;
  results(huntId: string): Promise<HuntResultsDto>;
  promote(hitId: string): Promise<{ vulnId: string; displayNo: number; created: boolean }>;
  export(huntId: string, format: 'md' | 'html' | 'json'): Promise<string>;
  /** Returns the skill name and the knowledge draft to review. */
  saveAsSkill(basisId: string, category: 'vuln_case' | 'audit_method', name?: string): Promise<{ name: string; draftId: string }>;
}

const VERDICT: Record<string, string> = { affected: '受影响', not_affected: '不受影响', pending: '待确认' };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function printBasis(b: HuntBasisDto): void {
  print(`排查依据 ${b.id}（${b.kind}）：${b.status}${b.error ? ` — ${b.error}` : ''}`);
  const x: HuntBasis | null = b.basis;
  if (!x) return;
  print(`  ${x.title}（${x.severity}）`);
  print(`  ${x.summary}`);
  for (const d of x.features.dependencies) print(`  依赖：${d.ecosystem} ${d.name} ${d.affectedVersions}`);
  for (const a of x.features.apis) print(`  危险 API：${a.pattern}  ${a.description}`);
  for (const p of x.features.codePatterns) print(`  代码模式：${p.description}${p.grep ? `（grep ${p.grep}）` : ''}`);
  print(`  受影响：${x.affectedIf.join('；')}`);
  print(`  不受影响：${x.notAffectedIf.join('；')}`);
}

function printResults(r: HuntResultsDto): void {
  const s = r.hunt.summary;
  print(`排查 ${r.hunt.id}：${r.hunt.status} · ${s.projects} 个项目 / ${s.repositories} 个仓库：受影响 ${s.affected}，不受影响 ${s.notAffected}，待确认 ${s.pending}${s.unfinished ? `，未完成 ${s.unfinished}` : ''}`);
  for (const t of r.targets) print(`  ${t.projectName}${t.repoName ? ` / ${t.repoName}` : ''}：${t.verdict ? VERDICT[t.verdict] : '未完成'} — ${t.reason ?? ''}`);
  for (const h of r.hits) print(`  命中 ${h.id}  ${h.projectName}/${h.repoName} ${h.location.path}:${h.location.startLine} [${h.severity}] ${h.title}${h.promotedDisplayNo ? `（V-${h.promotedDisplayNo}）` : ''}`);
}

export async function huntCommand(api: HuntApi, sub: string | undefined, args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args, allowPositionals: true, strict: false,
    options: {
      prompt: { type: 'string' }, intel: { type: 'string' }, skill: { type: 'string' }, basis: { type: 'string' }, projects: { type: 'string' }, all: { type: 'boolean' },
      yes: { type: 'boolean' }, wait: { type: 'boolean' }, format: { type: 'string' }, out: { type: 'string' }, category: { type: 'string' }, name: { type: 'string' },
    },
  });
  const str = (k: string) => (typeof values[k] === 'string' ? (values[k] as string) : undefined);
  const need = (v: string | undefined, what: string) => { if (!v) throw new CliExit(EXIT_ERROR, `缺少参数：${what}`); return v; };
  if (sub === 'basis') {
    const text = (v: string) => (v.startsWith('@') ? readFileSync(resolve(v.slice(1)), 'utf8') : v);
    const input = str('skill') ? { kind: 'skill' as const, skill: str('skill')! } : str('intel') ? { kind: 'intel' as const, text: text(str('intel')!) } : str('prompt') ? { kind: 'prompt' as const, text: text(str('prompt')!) } : null;
    if (!input) throw new CliExit(EXIT_ERROR, '需要 --prompt、--intel（文本或 @文件）或 --skill 之一');
    const id = await api.createBasis(input);
    print(`正在整理排查依据 ${id}…`);
    let b = await api.getBasis(id);
    while (b.status === 'drafting') { await sleep(1000); b = await api.getBasis(id); }
    printBasis(b);
    if (b.status === 'ready') print(`确认无误后：xiezhi hunt start --basis ${id} --all --yes --wait`);
    return b.status === 'ready' ? EXIT_OK : EXIT_ERROR;
  }
  if (sub === 'start') {
    const basisId = need(str('basis'), '--basis');
    const scope = values.all ? { all: true as const } : { projectIds: need(str('projects'), '--projects 或 --all').split(',').map((x) => x.trim()).filter(Boolean) };
    let h = await api.createHunt(basisId, scope);
    print(`排查计划 ${h.id}：${h.title}`);
    if (h.plan?.estimate.precheck.status === 'running') print('  正在预检（按排查特征定位每个仓库，不调用模型）…');
    while (h.plan?.estimate.precheck.status === 'running') { await sleep(1000); h = await api.getHunt(h.id); }
    for (const p of h.plan?.projects ?? []) print(`  ${p.name}：${p.repos.filter((r) => r.auditable).map((r) => r.name).join('、') || '（没有可审计仓库）'}`);
    const e = h.plan?.estimate;
    if (e?.precheck.status === 'done') print(`  预检：${e.precheck.judged} 个仓库有候选、需要 AI 研判；${e.precheck.cleared} 个没有候选，按规则判为不受影响`);
    print(`  预计 ${e?.repositories ?? 0} 个仓库，约 ${formatTokens(e?.tokens.p50 ?? 0)}–${formatTokens(e?.tokens.p90 ?? 0)} tokens`);
    if (!values.yes) throw new CliExit(EXIT_ERROR, '确认后加 --yes 启动');
    await api.confirm(h.id);
    print('已启动');
    if (!values.wait) return EXIT_OK;
    let cur = await api.getHunt(h.id);
    while (['planned', 'running'].includes(cur.status)) { await sleep(2000); cur = await api.getHunt(h.id); }
    const r = await api.results(h.id);
    printResults(r);
    return cur.status === 'completed' ? EXIT_OK : EXIT_INCOMPLETE;
  }
  if (sub === 'show') { printResults(await api.results(need(positionals[0], 'huntId'))); return EXIT_OK; }
  if (sub === 'promote') {
    const r = await api.promote(need(positionals[0], 'hitId'));
    print(r.created ? `已转为漏洞 V-${r.displayNo}` : `与已有漏洞 V-${r.displayNo} 是同一漏洞，已关联`);
    return EXIT_OK;
  }
  if (sub === 'export') {
    const format = (str('format') ?? 'md') as 'md' | 'html' | 'json';
    if (!['md', 'html', 'json'].includes(format)) throw new CliExit(EXIT_ERROR, 'format 只能是 md、html、json');
    const out = resolve(need(str('out'), '--out'));
    writeFileSync(out, await api.export(need(positionals[0], 'huntId'), format));
    print(`已导出 ${out}`);
    return EXIT_OK;
  }
  if (sub === 'save-skill') {
    const category = (str('category') ?? 'vuln_case') as 'vuln_case' | 'audit_method';
    const r = await api.saveAsSkill(need(positionals[0], 'basisId'), category, str('name'));
    print(`已生成知识草稿 ${r.name}（${r.draftId}）；审核后启用：xiezhi knowledge approve ${r.draftId}，或在知识库页面审核`);
    return EXIT_OK;
  }
  throw new CliExit(EXIT_ERROR, `未知子命令 hunt ${sub ?? ''}`);
}
