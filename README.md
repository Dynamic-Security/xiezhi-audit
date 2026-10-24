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

## 使用手册

完整手册见 [docs/manual](docs/manual/README.md)，覆盖 Web 工作台和命令行的全部功能模块，每个模块都配有真实运行截图。

![Web 工作台首页](docs/manual/images/home.png)

### 典型使用流程

```text
安装并运行 xiezhi doctor
  → 启动 xiezhi serve，用一次性链接登录
  → 设置 › 模型：添加模型服务，设置默认 / 备用模型
  → 新建项目，添加仓库（本地目录 / Git / 压缩包），可选 AI 识别仓库角色
  → 新建审计（可先看计划），回答 Agent 提问，跟踪执行
  → 在结果和漏洞清单中复核：确认、误报、调整严重度
  → 修复后发起复验，或做增量审计
  → 导出报告（Markdown / HTML / JSON / SARIF），或推送到工单系统
```

### 核心概念

| 概念 | 说明 |
| --- | --- |
| 项目 | 对应一个业务系统，可以包含多个仓库。漏洞、威胁模型、企业事实、项目知识都挂在项目下。 |
| 仓库 | 本地目录、Git 地址或压缩包。每个仓库可以设为“可审计”或“只作证据”，并有 AI 识别的角色（网关、业务服务等）。 |
| 审计 | 一次审计任务。场景有全量审计、增量审计、风险排查和漏洞复验；模式有单仓库审计和多仓库合并审计。 |
| 发现 / 漏洞 | 审计中的结论叫“发现”（F-编号）。归并后进入项目的漏洞清单（V-编号），跨审计跟踪状态：新增、仍存在、已修复（经验证）、回归。 |
| 企业事实 | 代码里看不到的环境前提，例如网关鉴权、部署拓扑、网络边界。回答 Agent 提问时，答案可以存为事实，后续审计直接使用。 |
| 知识（skill） | Markdown 写成的审计方法、漏洞案例、报告规范等。Agent 先看到索引，需要时再读取正文。 |
| 预算 | 每次审计的 token 和时长上限，启动时冻结。用完后审计暂停，等你追加预算。 |

### 章节

| 章节 | 内容 |
| --- | --- |
| [1. 安装与首次配置](docs/manual/01-install-and-setup.md) | 安装、环境诊断、启动 Web 工作台、登录、配置模型服务 |
| [2. 工作台与界面导航](docs/manual/02-workspace.md) | 首页、侧栏、新建菜单、⌘K 搜索、AI 面板、主题 |
| [3. 项目与仓库](docs/manual/03-projects.md) | 新建项目、添加仓库、AI 识别仓库角色、系统拓扑、企业事实、项目知识库、项目导出 |
| [4. 代码审计](docs/manual/04-audits.md) | 新建审计、计划确认、Agent 提问、执行跟踪、行为轨迹、预算、结果、对比、导出报告 |
| [5. 漏洞管理](docs/manual/05-vulns.md) | 漏洞清单、证据链、确认 / 误报、修订建议、复验、批量操作、推送到外部系统 |
| [6. 需求威胁建模](docs/manual/06-threat-models.md) | 从需求文档生成威胁模型、功能澄清、风险研判、关联到审计 |
| [7. 风险排查](docs/manual/07-risk-hunts.md) | 针对 1Day / CVE / 特定风险跨项目快速排查 |
| [8. AI 会话](docs/manual/08-conversations.md) | 用自然语言追问漏洞、发起审计和排查 |
| [9. 知识库](docs/manual/09-knowledge.md) | skill、审计提示词、导入与 AI 整理、项目级覆盖 |
| [10. 设置](docs/manual/10-settings.md) | 模型、Git 凭证、连接器、任务创建默认值、通用、系统诊断 |
| [11. 命令行参考](docs/manual/11-cli.md) | `xiezhi` 全部命令、客户端模式、退出码、评测工具 |

## 开发

```bash
pnpm install && pnpm build && pnpm typecheck && pnpm lint
```

从源码运行时用 `node apps/cli/dist/main.js` 代替 `xiezhi`。`pnpm release:pack` 在 `release/` 下生成 npm 包（`release/xiezhi-audit/` 与 `xiezhi-audit-<版本>.tgz`），可用 `npm install -g ./release/xiezhi-audit-<版本>.tgz` 本地验证。

发版：把根目录 `package.json` 的版本改为新版本并提交，推送标签 `v<版本>`（如 `v0.1.0-alpha`）。`.github/workflows/release.yml` 会构建 npm 包，在 Linux / macOS 与 Node 22、24 上安装并运行 `scripts/smoke-package.mjs`，通过后发布到 npm（预发布版本用 `alpha` 等单独的 dist-tag）并创建 GitHub Release。手动运行该 workflow 只做构建与安装检查，不发布。

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
