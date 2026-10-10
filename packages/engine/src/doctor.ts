// doctor: environment and security baseline checks. Only read-only
// `--version` style commands are run, through the controlled executor.
import { accessSync, constants, existsSync, statfsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Executor, GRAMMARS, grammarVersions, loadLanguage, loadRules, LSP_LANGUAGES, type GrammarLang } from '@xiezhi/context';
import { readConfig, resolveDataDir } from '@xiezhi/store';
import { defaultAppConfig, type AppConfig } from '@xiezhi/contracts';
import { lspServer, LSP_SERVER_NAMES } from './lsp.js';

export type Level = 'ok' | 'fatal' | 'block' | 'warn' | 'info';
export interface Check { name: string; level: Level; detail: string; impact?: string; fix?: string }

export async function runDoctor(dataDirArg?: string): Promise<Check[]> {
  const checks: Check[] = [];
  let appConfig: AppConfig = defaultAppConfig();
  const major = Number(process.versions.node.split('.')[0]);
  checks.push(major >= 22
    ? { name: 'node', level: 'ok', detail: process.versions.node }
    : { name: 'node', level: 'fatal', detail: process.versions.node, impact: '无法启动', fix: '安装 Node.js ≥ 22' });

  const dataDir = resolveDataDir(dataDirArg);
  if (!existsSync(dataDir)) {
    checks.push({ name: 'data-dir', level: 'info', detail: `${dataDir} 尚未创建（首次运行命令时创建）` });
  } else {
    try {
      accessSync(dataDir, constants.R_OK | constants.W_OK);
      const mode = statSync(dataDir).mode & 0o777;
      checks.push(mode & 0o077
        ? { name: 'data-dir', level: 'warn', detail: `${dataDir} 权限 ${mode.toString(8)}`, impact: '其他用户可能读取审计数据', fix: `chmod 700 ${dataDir}` }
        : { name: 'data-dir', level: 'ok', detail: dataDir });
    } catch {
      checks.push({ name: 'data-dir', level: 'fatal', detail: `${dataDir} 不可读写`, impact: '无法启动' });
    }
    const cfg = join(dataDir, 'config.json');
    if (existsSync(cfg)) {
      try { appConfig = readConfig(cfg).config; } catch { /* reported below */ }
      const mode = statSync(cfg).mode & 0o777;
      if (mode & 0o077) checks.push({ name: 'config.json', level: 'warn', detail: `权限 ${mode.toString(8)}`, fix: `chmod 600 ${cfg}` });
      try {
        const { config } = readConfig(cfg);
        const models = config.modelProviders.flatMap((p) => p.models.map((m) => `${p.id}/${m.id}`));
        const def = config.defaultModel ? `${config.defaultModel.provider}/${config.defaultModel.model}` : models[0];
        checks.push(def
          ? { name: 'models', level: 'ok', detail: `默认模型 ${def}；已配置 ${models.length} 个模型；密钥 ${config.modelProviders.filter((p) => p.apiKey).length}/${config.modelProviders.length} 已配置` }
          : { name: 'models', level: 'block', detail: '未配置模型服务', impact: '无法发起审计', fix: 'xiezhi config add-provider … 然后 config set-secret <provider>' });
        // conversations use the “对话” stage model, else the default model.
        const own = config.stageModels?.chat;
        const chat = own ? `${own.provider}/${own.model}` : def;
        checks.push(chat
          ? { name: 'conversations', level: 'ok', detail: `对话模型 ${chat}${own ? '' : '（未单独设置，跟随默认模型）'}` }
          : { name: 'conversations', level: 'warn', detail: '没有可用的对话模型', impact: 'AI 会话不可用', fix: '在“设置 › 模型”中设置默认模型或“对话”阶段的模型' });
        const env = process.env.GOFLAGS ?? '';
        if (/-toolexec|-exec|-overlay/.test(env)) checks.push({ name: 'GOFLAGS', level: 'warn', detail: '父环境的 GOFLAGS 含 -toolexec/-exec/-overlay（执行器不会继承，但请检查环境）' });
      } catch (e) {
        checks.push({ name: 'config.json', level: 'fatal', detail: (e as Error).message });
      }
    }
    try {
      const db = new DatabaseSync(join(dataDir, 'db.sqlite'), { readOnly: existsSync(join(dataDir, 'db.sqlite')) });
      const mode = (db.prepare('PRAGMA journal_mode').get() as { journal_mode: string }).journal_mode;
      db.close();
      checks.push({ name: 'sqlite', level: 'ok', detail: `journal_mode=${mode}` });
    } catch (e) {
      checks.push({ name: 'sqlite', level: 'fatal', detail: (e as Error).message, impact: '无法记录审计' });
    }
    try {
      const fs = statfsSync(dataDir);
      const free = fs.bavail * fs.bsize;
      checks.push(free >= 1024 ** 3 ? { name: 'disk', level: 'ok', detail: `${(free / 1024 ** 3).toFixed(1)} GB 可用` }
        : { name: 'disk', level: 'warn', detail: `${(free / 1024 ** 2).toFixed(0)} MB 可用`, impact: '快照与索引可能失败' });
    } catch { /* statfs unsupported */ }
  }

  const ex = new Executor({ scratchDir: join(dataDir, 'tmp', 'doctor') });
  for (const [cmd, level, impact] of [['rg', 'block', '代码搜索不可用，无法发起审计'], ['git', 'warn', 'git ref 快照与工作区版本识别不可用']] as const) {
    const r = await ex.run({ command: cmd, args: ['--version'], cwd: ex.scratchDir, timeoutMs: 10_000 });
    checks.push(r.status === 'ok'
      ? { name: cmd, level: 'ok', detail: `${ex.binaryPath(cmd)} ${r.stdout.inlinePreview.split('\n')[0]}` }
      : { name: cmd, level, detail: '不可用', impact, fix: `安装 ${cmd === 'rg' ? 'ripgrep' : 'git'}` });
  }
  try {
    for (const g of Object.keys(GRAMMARS) as GrammarLang[]) await loadLanguage(g);
    const v = grammarVersions();
    const rules = loadRules();
    checks.push(rules.errors.length
      ? { name: 'tree-sitter', level: 'warn', detail: `规则错误：${rules.errors.slice(0, 3).join('; ')}` }
      : { name: 'tree-sitter', level: 'ok', detail: `${Object.keys(GRAMMARS).map((g) => `${g} ${v[g]?.split(':')[0]}`).join(', ')}; ${rules.rules.length} 条规则` });
  } catch (e) {
    checks.push({ name: 'tree-sitter', level: 'warn', detail: (e as Error).message, impact: '结构索引与覆盖对照不可用' });
  }
  // optional; missing servers only mean definition / references fall back to tree-sitter.
  for (const lang of LSP_LANGUAGES) {
    const { server, reason } = lspServer(appConfig, lang);
    const name = LSP_SERVER_NAMES[lang];
    checks.push(server
      ? { name, level: 'ok', detail: `${server.file}${lang === 'go' ? `（go：${server.pathDirs[0]}）` : lang === 'java' ? '' : `（node：${server.pathDirs[0]}）`}` }
      : { name, level: 'info', detail: reason ?? '不可用', impact: '符号查询退化为 tree-sitter（审计中用到时记 INDEX_DEGRADED）' });
  }
  return checks;
}
