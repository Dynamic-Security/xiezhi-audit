// knowledge import | drafts | approve | reject: imported text becomes a draft
// that is organized by AI and checked; nothing is enabled until it is approved (here or in the web page).
// The same flow runs against the local engine or, when the service is running, over its API.
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { parseArgs } from 'node:util';
import type { KnowledgeDraftDto } from '@xiezhi/contracts';
import { CliExit, EXIT_ERROR, EXIT_OK, print, printJson } from './io.js';

export interface KnowledgeApi {
  projectId(nameOrId: string): Promise<string>;
  create(body: Record<string, unknown>): Promise<KnowledgeDraftDto>;
  get(id: string): Promise<KnowledgeDraftDto>;
  list(projectId?: string): Promise<KnowledgeDraftDto[]>;
  approve(id: string, body: Record<string, unknown>): Promise<{ name: string; file: string | null }>;
  reject(id: string): Promise<KnowledgeDraftDto>;
}

const STATUS: Record<string, string> = { organizing: '整理中', ready: '待审核', failed: '失败', approved: '已启用', rejected: '已驳回' };

function describe(d: KnowledgeDraftDto): string[] {
  const c = d.checks;
  return [
    `${d.id}  ${STATUS[d.status] ?? d.status}  ${d.layer === 'global' ? '全局' : '项目'} ${d.kind === 'case' ? `案例 ${d.library}/` : ''}${d.name ?? '（未命名）'}  来源：${d.source.label}`,
    ...(d.error ? [`  失败：${d.error}`] : []),
    ...c.errors.map((e) => `  格式问题：${e}`),
    ...c.injection.map((i) => `  疑似注入（第 ${i.line} 行，${i.signal}）：${i.excerpt}`),
    ...(c.sameName ? [`  同名：${c.sameName.layer}:${c.sameName.name}${c.sameName.file ? `/${c.sameName.file}` : ''}（启用需 --replace）`] : []),
    ...(c.overridesGlobal ? ['  启用后覆盖同名全局 skill'] : []),
    ...c.similar.map((s) => `  相似：${s.layer}:${s.name}${s.file ? `/${s.file}` : ''}（${s.score}）`),
    ...c.conflicts.flatMap((x) => [`  与 ${x.layer}:${x.name}${x.file ? `/${x.file}` : ''} 矛盾（建议 ${x.suggestion}）：`, ...x.points.map((p) => `    - ${p}`)]),
  ];
}

export async function knowledgeWriteCommand(api: KnowledgeApi, sub: string, args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args, allowPositionals: true,
    options: {
      project: { type: 'string' }, case: { type: 'boolean' }, 'no-organize': { type: 'boolean' }, name: { type: 'string' }, category: { type: 'string' },
      replace: { type: 'boolean' }, 'delete-original': { type: 'boolean' }, json: { type: 'boolean' },
    },
  });
  const projectId = values.project ? await api.projectId(values.project) : undefined;
  if (sub === 'import') {
    const file = positionals[0];
    if (!file) throw new CliExit(EXIT_ERROR, '用法：knowledge import <文件|-> [--project <p>] [--case] [--no-organize] [--name n] [--category c]');
    const text = readFileSync(file === '-' ? 0 : file, 'utf8');
    let d = await api.create({
      layer: projectId ? 'project' : 'global', ...(projectId ? { projectId } : {}), kind: values.case ? 'case' : 'skill', text,
      organize: !values['no-organize'], ...(values.name ? { name: values.name } : {}), ...(values.category ? { category: values.category } : {}),
      source: { kind: values['no-organize'] ? 'manual' : 'upload', label: file === '-' ? '标准输入' : basename(file) },
    });
    for (let i = 0; d.status === 'organizing' && i < 900; i++) {
      await new Promise((r) => setTimeout(r, 1000));
      d = await api.get(d.id);
    }
    if (values.json) printJson(d); else for (const l of describe(d)) print(l);
    if (d.status === 'ready') print(`审核后启用：xiezhi knowledge approve ${d.id}${d.checks.sameName ? ' --replace' : ''}（或在知识库页面审核）`);
    return d.status === 'ready' ? EXIT_OK : EXIT_ERROR;
  }
  if (sub === 'drafts') {
    const list = await api.list(projectId);
    if (values.json) printJson(list);
    else if (!list.length) print('没有待审核的草稿');
    else for (const d of list) for (const l of describe(d)) print(l);
    return EXIT_OK;
  }
  if (sub === 'approve') {
    const id = positionals[0];
    if (!id) throw new CliExit(EXIT_ERROR, '缺少参数：draftId');
    const r = await api.approve(id, { ...(values.replace ? { replace: true } : {}), ...(values['delete-original'] ? { afterMove: 'delete' } : {}) });
    print(`已启用 ${r.name}${r.file ? `/${r.file}` : ''}`);
    return EXIT_OK;
  }
  if (sub === 'reject') {
    const id = positionals[0];
    if (!id) throw new CliExit(EXIT_ERROR, '缺少参数：draftId');
    await api.reject(id);
    print(`已驳回 ${id}（草稿保留 30 天）`);
    return EXIT_OK;
  }
  throw new CliExit(EXIT_ERROR, `未知子命令 knowledge ${sub}`);
}
