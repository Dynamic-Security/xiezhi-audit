# 獬豸 xiezhi-audit

獬豸（Xiezhi，简称 `xiezhi`）是在本机运行的代码安全审计 Agent。它对代码做静态审计（不构建、不运行、不测试被审代码），用大模型结合结构索引、规则与知识库发现漏洞，并给出证据链、复核与报告。

支持的语言：Java、Go、Python、JavaScript / TypeScript（服务端）、PHP、Kotlin、C#、Ruby、Rust。

## 能力概览

- 项目与多仓库（本地目录、Git、压缩包），AI 识别仓库角色与系统拓扑；全量 / 增量审计、风险排查、漏洞复验；单仓、关联仓库与多仓合并审计。
- 需求威胁建模：从需求文档生成威胁模型，作为审计的风险假设输入。
- Web 工作台：每个页面右侧都有 AI 面板（⌘J），按当前对象续接会话；首页输入框可以直接让 Agent 审计、排查、复验；⌘K 搜索。
- 审计默认提交即开始（可选先确认计划），过程、Agent 提问与你的介入都在审计会话里；行为轨迹按“Agent 说明 → 工具 → 结果”叙述。
- 执行跟踪：显示当前环节、并行任务数、总进度与剩余时间，以及每个并行作业（含子 Agent）在做什么、等什么；并发与预算可在运行中调整。
- 模型服务：添加时可探测可用模型，保存前测验地址、密钥与每个模型是否可用；各阶段可分别选模型，支持交叉复核。
- 结果复核带修订历史；导出 Markdown、HTML、JSON、SARIF；知识库（skill）与 MCP 连接器（内置 Jira、飞书、OSV 等连接包）。
- 内置评测工具（`xiezhi eval`）：基准样本、打分、回归门禁与消融实验。

## 安装

需要 Node.js 22.19 或更高版本，以及 [ripgrep](https://github.com/BurntSushi/ripgrep)（`rg`）；git 可选（Git 来源与增量审计用到）。

```bash
npm install -g xiezhi-audit@alpha
```

安装不编译任何原生模块。安装后先运行 `xiezhi doctor` 检查环境，缺少的工具会给出安装命令。

## 快速开始

```bash
xiezhi doctor
```

```bash
xiezhi config add-provider gw --api openai-completions --base-url https://your-gateway/v1 --models your-model
```

```bash
xiezhi config set-secret gw
```

```bash
xiezhi config set defaultModel gw/your-model
```

```bash
xiezhi project create demo
```

```bash
xiezhi project add-repo demo --path /path/to/repo
```

仓库也可以来自 Git 地址（`--git https://… | git@host:path`，可加 `--ref`）或压缩包（`--archive repo.zip`，zip / tar / tar.gz）。私有 HTTPS 仓库先配置凭证：

```bash
xiezhi config set-git-credential gitlab.example.com --username oauth2
```

```bash
xiezhi audit start --project demo --yes
```

```bash
xiezhi export <auditId> --format sarif --out report.sarif
```

### Web 工作台

```bash
xiezhi serve
```

终端会打印 `http://127.0.0.1:4820/#boot=…` 一次性登录链接（5 分钟内有效、只能用一次）；加 `--open` 自动用系统默认浏览器打开（`XIEZHI_AUDIT_BROWSER` 可指定浏览器程序的绝对路径）。链接过期或服务重启后，另开终端获取新链接：

```bash
xiezhi open
```

服务运行期间，`project`、`audit`、`export` 命令自动通过本地 API 执行（`audit start --wait` 等待结束，`audit status <id> --follow` 跟随进度，均订阅事件流）；未启动服务时在终端里运行审计，Agent 的提问可以直接在终端回答（回车跳过）；模型与默认值请在界面“设置”中修改。

- 数据目录默认为 `~/.xiezhi-code-audit`，可用 `--data-dir` 或环境变量 `XIEZHI_AUDIT_DATA_DIR` 修改。
- 静态审计：不构建、不运行、不测试目标代码。

## 开发

```bash
pnpm install && pnpm build && pnpm typecheck && pnpm lint
```

从源码运行时用 `node apps/cli/dist/main.js` 代替 `xiezhi`。`pnpm release:pack` 在 `release/` 下生成 npm 包（`release/xiezhi-audit/` 与 `xiezhi-audit-<版本>.tgz`），可用 `npm install -g ./release/xiezhi-audit-<版本>.tgz` 本地验证。

接口文档：服务运行时 `GET /api/v1/openapi.json`，快照在 `docs/api/openapi.json`。

包依赖的方向见下文“架构”，由 `pnpm lint` 强制检查。前端开发时可先 `serve`，再在 `apps/web` 运行 `pnpm dev`（Vite 代理到 4820）。

## 架构

pnpm monorepo，Node.js ≥ 22.19。

| 目录 | 作用 |
| --- | --- |
| `packages/contracts` | 共享类型、schema 与策略参数 |
| `packages/store` | SQLite 存储与迁移 |
| `packages/context` | 代码快照、结构索引（tree-sitter）、增量影响分析；唯一允许启动子进程的地方（`src/exec/`） |
| `packages/knowledge` | 知识库（skill）与提示词目录 |
| `packages/connectors` | MCP 连接器 |
| `packages/agent` | Agent 会话与工具 |
| `packages/engine` | 审计流水线、预算与调度、业务操作与查询 |
| `packages/report` | 报告生成与导出 |
| `apps/server` | 本地 HTTP API（仅监听 127.0.0.1） |
| `apps/web` | Web 工作台（React + Vite） |
| `apps/cli` | 命令行 `xiezhi` |
| `apps/eval` | 评测工具 |
| `rules/` · `skills/` · `connector-packs/` | 内置规则、知识与连接包 |

包依赖只能单向：`contracts ← store ← {context, knowledge, connectors} ← agent ← engine ← {server, eval} ← cli`；`report` 只依赖 contracts / store，由 engine 使用；`web` 只引用 contracts 的类型，通过 HTTP 访问服务。`apps/*` 不直接写 SQL 或写库，读取放在 `packages/engine/src/queries/`。这些规则由 `eslint.config.js` 检查。

## 安全说明

- 被审仓库、检索到的文档与连接器返回的内容都按不可信数据处理；被审仓库中的 AGENTS.md、SKILL.md 等控制文件不会对 Agent 可见。
- 连接器写操作的参数或会话含疑似注入指令时，调用先暂停等待用户批准。
- 模型与 Git 凭证只保存在本机数据目录；日志、轨迹与导出内容中的密钥会脱敏。

## 许可证

[MIT](LICENSE)
