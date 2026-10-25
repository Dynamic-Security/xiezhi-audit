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
- 内置评测工具（`xiezhi eval`）：基准样本、打分、回归门禁与消融实验；基准数据需自备（`--bench` 或 `XIEZHI_AUDIT_BENCH` 指向基准目录），安装包不附带。

## 安装

| 依赖 | 是否必需 | 用途 | 缺少时 |
| --- | --- | --- | --- |
| Node.js ≥ 22.19 | 必需 | 运行 CLI 与服务；内置 `node:sqlite` 存储审计数据 | 无法启动 |
| ripgrep（`rg`） | 必需 | 代码搜索 | 无法发起审计 |
| git | 推荐 | Git 仓库来源、按分支 / 提交快照、识别工作区版本 | Git 来源与 ref 快照不可用 |
| 语言服务器（见下文） | 可选 | 定义跳转、引用查找更准确 | 退化为 tree-sitter，审计照常进行 |

没有需要本机编译的原生模块（tree-sitter 以 WebAssembly 运行），不需要安装 Python、C/C++ 编译工具链。

### 1. Node.js

用版本管理器安装 Node.js 22 或更高版本（推荐 22 / 24 LTS；也可从 [nodejs.org](https://nodejs.org/) 下载安装包）：

```bash
fnm install 22 && fnm use 22
```

```bash
node --version
```

应输出 `v22.19.0` 或更高。

### 2. ripgrep 与 git

macOS（Homebrew）：

```bash
brew install ripgrep git
```

Debian / Ubuntu（其他发行版用 dnf / apk / pacman 安装同名包）：

```bash
sudo apt install ripgrep git
```

Windows：

```bash
winget install BurntSushi.ripgrep.MSVC Git.Git
```

### 3. xiezhi-audit

```bash
npm install -g xiezhi-audit@alpha
```

### 4. 语言服务器（可选）

审计对应语言的仓库时才会用到，用于定义跳转、引用查找；没有安装时符号查询退化为 tree-sitter（精度较低），并在审计中记录 `INDEX_DEGRADED`，审计照常进行。只审计某一种语言时，只装那一种即可。

Go（`gopls` 需要 Go 工具链加载包，两者都要有）：

```bash
brew install go
```

```bash
go install golang.org/x/tools/gopls@latest
```

Linux 上 Go 建议从 [go.dev/dl](https://go.dev/dl/) 安装（发行版的 `golang-go` 往往较旧）。`go install` 把 `gopls` 放在 `~/go/bin`，自动查找会覆盖这个目录。

Java（`jdtls` 需要 JDK 21 或更高，`java` 须在 `PATH` 中）：

```bash
brew install openjdk@21 jdtls
```

Linux 先安装 JDK（如 `sudo apt install openjdk-21-jdk`），再从 [Eclipse JDT LS](https://github.com/eclipse-jdtls/eclipse.jdt.ls) 下载并解压发行包，把解压目录下的 `bin/jdtls` 填到设置里；这个启动脚本需要 Python 3。

Python 与 JavaScript / TypeScript（两者都由 Node.js 运行）：

```bash
npm install -g pyright
```

```bash
npm install -g typescript-language-server typescript
```

`pyright` 包会同时装上 `pyright-langserver`。

### 5. 外部工具路径（设置 › 通用）

Web 工作台“设置 › 通用 › 外部工具路径”中的每一项对应一个配置键。留空时自动查找：先找 `PATH`，语言服务器相关的几项还会查 `~/go/bin`、`/opt/homebrew/bin`、`/usr/local/bin`、`/usr/local/go/bin`、`/usr/bin`。只有装在别处、自动查找找不到时才需要填写，填写的必须是可执行文件的绝对路径。

| 设置项 | 配置键 | 必要性 | 找不到时 |
| --- | --- | --- | --- |
| ripgrep（rg） | `tools.rgPath` | 必需 | 无法发起审计 |
| git | `tools.gitPath` | 推荐 | Git 仓库来源、按分支 / 提交快照不可用 |
| Go 语言服务器（gopls） | `tools.goplsPath` | 可选，审计 Go 时使用 | Go 符号查询退化为 tree-sitter |
| Go 工具链（go） | `tools.goPath` | 使用 gopls 时必需 | gopls 不启动，Go 退化为 tree-sitter |
| Java 语言服务器（jdtls） | `tools.jdtlsPath` | 可选，审计 Java 时使用 | Java 符号查询退化为 tree-sitter |
| Python 语言服务器（pyright-langserver） | `tools.pyrightPath` | 可选，审计 Python 时使用 | Python 符号查询退化为 tree-sitter |
| TypeScript 语言服务器（typescript-language-server） | `tools.tsLspPath` | 可选，审计 JS / TS 时使用 | JS / TS 符号查询退化为 tree-sitter |
| node（语言服务器运行需要） | `tools.nodePath` | 使用 pyright 或 typescript-language-server 时必需 | 这两个语言服务器都不启动 |

`node` 这一项只用于运行语言服务器，可以与运行 xiezhi 的 Node.js 不是同一个。`jdtls` 所用的 `java` 没有单独的设置项，须在 `PATH` 中。

查到已安装工具的绝对路径后，在设置页填写，或用命令行：

```bash
command -v gopls
```

```bash
xiezhi config set tools.goplsPath /absolute/path/to/gopls
```

设置是否生效，看“系统诊断”页或下面的 `doctor`。

### 6. 检查环境

`doctor` 逐项列出上面的依赖、数据目录、模型配置与磁盘空间，缺什么就给出对应平台的安装命令：

```bash
xiezhi doctor
```

## 快速开始

先按上一节安装并检查环境，然后配置模型服务：

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

从源码构建需要 pnpm 10.28.2，用 corepack 启用仓库指定的版本（`package.json` 的 `packageManager`；Node.js 25 起先 `npm install -g corepack`）：

```bash
corepack enable
```

```bash
pnpm install && pnpm build && pnpm typecheck && pnpm lint && pnpm test
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
