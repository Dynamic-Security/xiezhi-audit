# 11. 命令行参考

[← 返回目录](README.md)

```text
xiezhi [--data-dir DIR] <命令> [参数]
```

从源码运行时，用 `node apps/cli/dist/main.js` 代替 `xiezhi`。

## 运行模式

- **本地模式**：没有启动服务时，命令直接读写数据目录。在终端里运行审计时，Agent 的提问可以直接在终端回答（回车跳过）。
- **客户端模式**：`xiezhi serve` 运行期间，`project`、`audit`、`export` 命令自动通过本地 API 提交。`audit start` 默认确认后立即返回，加 `--wait` 等待结束；`audit status <id> --follow` 跟随进度。两者都订阅事件流，只在客户端模式下有效。
- 服务运行时，模型与默认值请在界面“设置”中修改。

## 服务与环境

| 命令 | 说明 |
| --- | --- |
| `serve [--port N] [--open]` | 启动本地服务与 Web 工作台（仅监听 127.0.0.1，默认端口 4820）；`--open` 自动打开浏览器。 |
| `open` | 服务运行中时，生成新的一次性浏览器登录链接。 |
| `doctor [--json]` | 环境诊断。 |
| `version` | 显示版本。 |

## 配置

| 命令 | 说明 |
| --- | --- |
| `config list` / `config get <key>` / `config set <key> <value>` | 读写配置。`defaultModel`、`fallbackModel` 用 `provider/model`；`stageModels.<阶段>` 用 `provider/model`、`default` 或 `none`。 |
| `config add-provider <id> --api <api> --base-url <url> --models a,b` | 添加或更新模型服务。`--api` 为 `openai-completions`、`openai-responses` 或 `anthropic-messages`。 |
| `config set-secret <providerId> [--from-env VAR]` | 设置模型服务密钥（TTY 下隐藏输入，也可以从 stdin 读取）。 |
| `config set-git-credential <host> --username <u> [--from-env VAR]` | 设置某个域名的 Git HTTPS token。 |
| `config remove-git-credential <host>` | 删除某个域名的 Git 凭证。 |

## 项目

| 命令 | 说明 |
| --- | --- |
| `project create <name>` | 新建项目。 |
| `project list` / `project show <name>` | 列出 / 查看项目。 |
| `project analyze <project>` | AI 识别仓库角色（手动触发；使用轻量模型，未设置时用默认模型）。 |
| `project add-repo <project> (--path <dir> \| --git <url> \| --archive <file>) [--ref <ref>] [--name <name>]` | 添加仓库：本地目录、Git 地址（https / ssh）或压缩包（zip / tar / tar.gz）。 |

## 审计

```text
audit start --project <p> [--scene full|incremental] [--base <ref>] [--repo <r>] [--ref <ref>]
            [--strategy <file.json>] [--title <t>] [--yes] [--wait]
            [--related <r1,r2>] | [--mode multi [--repos <r1,r2>]]
            [--threat-model <id> …]
```

| 参数 | 说明 |
| --- | --- |
| `--scene` | `full`（默认）或 `incremental`。 |
| `--base` | 增量审计的对比基线，默认对比上次审计的版本，可以指定任意分支或提交。 |
| `--repo` / `--ref` | 单仓库审计的目标仓库与版本。 |
| `--related` | 单仓库审计的关联仓库（只作证据）。 |
| `--mode multi [--repos]` | 多仓库合并审计，默认包含全部可审计仓库。 |
| `--strategy` | 用 JSON 文件覆盖本次审计的策略（预算、覆盖目标等）。 |
| `--threat-model` | 关联需求威胁模型，可以重复。 |
| `--yes` | 跳过确认，直接开始。 |
| `--wait` | 等待审计结束（客户端模式）。 |

| 命令 | 说明 |
| --- | --- |
| `audit status <auditId> [--json] [--follow]` | 查看状态与各步骤用量。 |
| `audit list [--project <p>]` | 列出审计。 |
| `audit resume <auditId> [--add-tokens N [--stage S]] [--no-stage-quotas] [--decline-budget] [--restart-filtered]` | 继续暂停的审计：追加预算（可指定阶段）、取消阶段额度、放弃追加以已有结果收尾；`--restart-filtered` 让被内容过滤拦截的步骤从头开始（不加则原样重试）。 |
| `audit cancel <auditId>` | 取消审计。 |

`audit status` 示例输出：

```text
aud_01M5JBGZJVPVB4CYPMR7FVGZFK  CEX-Demo 首次全量审计
状态：partial（BUDGET_EXHAUSTED > COVERAGE_GAP） · 阶段 done
预算：52817345/52000000 tokens
  snapshot   succeeded      attempt=1 tokens=0
  index      succeeded      attempt=1 tokens=0
  plan       succeeded      attempt=1 tokens=5543
  profile    succeeded      attempt=2 tokens=72190
  triage     succeeded      attempt=2 tokens=9623
  hunt       succeeded      attempt=1 tokens=34218
  …
```

`partial` 后的括号是未完成原因：预算耗尽（`BUDGET_EXHAUSTED`），覆盖未达标（`COVERAGE_GAP`）。此时退出码为 3。

## 导出

```text
export <auditId> --format md|html|json|sarif --out <path> [--no-snippets] [--no-local-roots]
```

- `--no-snippets`：不包含代码片段。
- `--no-local-roots`：SARIF 中不写本机绝对路径（分享给他人时使用）。

## 知识库

| 命令 | 说明 |
| --- | --- |
| `knowledge list \| show <name> \| lint [--project <p>] [--json]` | 只读查看与校验知识库（编辑请用界面或任意编辑器）。 |
| `knowledge import <文件\|-> [--project <p>] [--case] [--no-organize]` | 导入为草稿（AI 整理、校验、查重）。`--case` 导入为漏洞案例，`--no-organize` 只校验不整理。 |
| `knowledge drafts [--project <p>]` | 列出草稿。 |
| `knowledge approve <draftId> [--replace] [--delete-original]` | 审核通过草稿。 |
| `knowledge reject <draftId>` | 拒绝草稿。 |

## 风险排查

| 命令 | 说明 |
| --- | --- |
| `hunt basis (--prompt <文本\|@文件> \| --intel <文本\|@文件> \| --skill <name>)` | AI 整理风险排查依据。 |
| `hunt start --basis <id> (--projects a,b \| --all) [--yes] [--wait]` | 风险排查（每个项目一条排查审计）。 |
| `hunt show <huntId>` | 查看结果。 |
| `hunt promote <hitId>` | 把命中点转为漏洞。 |
| `hunt export <huntId> --format md\|html\|json --out <path>` | 导出。 |
| `hunt save-skill <basisId> [--category vuln_case\|audit_method] [--name n]` | 把排查依据存为 skill。 |

## 威胁模型

| 命令 | 说明 |
| --- | --- |
| `threat-model list --project <p> [--json]` | 列出项目的需求威胁模型（只读）。 |
| `threat-model export <id> [--out <path>]` | 导出为 Markdown。新建与研判请用界面。 |

## 退出码

| 退出码 | 含义 |
| --- | --- |
| 0 | 成功 |
| 2 | 参数或系统错误 |
| 3 | 审计未完成（partial / 已取消 / 已中断 / 等待预算） |

退出码不反映漏洞数量或严重度。在 CI 中按漏洞数量卡点时，请解析 `export --format json` 或 SARIF 的结果。

## 评测工具（xiezhi eval）

内置的评测工具用于衡量审计效果：基准样本、打分、回归门禁和消融实验。基准数据在独立仓库，用 `--bench DIR` 或环境变量 `XIEZHI_AUDIT_BENCH` 指定。

| 命令 | 说明 |
| --- | --- |
| `eval validate` | 校验 manifest、标注、裁定 schema、root_hash、分区与防泄漏规则。 |
| `eval hash <目录 \| https-URL@commit>…` | 计算源码的 root_hash（与产品快照一致），用于填写 manifest。 |
| `eval run --config FILE --out DIR [--partition dev\|holdout] [--filter k=v] [--repeats N] …` | 运行基准。每次运行都使用全新的临时数据目录。 |
| `eval score <运行目录>` | 独立评分：写 `score.json` 与 `adjudication.yaml`（待裁定队列）。 |
| `eval report <运行目录>` | 写 `report.json` 与 `report.md`。 |
| `eval experiment <实验.yaml> --config FILE --out DIR` | 策略对比实验（单字段变体、重复、配对 bootstrap、McNemar）。 |
| `eval ablation --out FILE [--scene] [--stages]` | 按阶段生成消融实验配置。 |
| `eval gate <基线运行目录> <候选运行目录>` | 回归门禁：召回与精度配对比较。退出码 0 不降、1 下降、3 样本不足。 |
| `eval import <cwe-bench-java \| osv-go \| osv> --data DIR --select FILE --out DIR` | 从公开数据集导入样本与标注草稿。 |

过滤键：`sample`、`project`、`kind`、`language`、`scene`、`tag`、`dataset`、`tier`（smoke ⊂ core ⊂ full）。评测从不读取用户数据目录；留出集只在发布评测时运行，需要 `--allow-holdout`。

## 接口文档

服务运行时可以访问 `GET /api/v1/openapi.json`，仓库中的快照在 [`docs/api/openapi.json`](../api/openapi.json)。

[← 返回目录](README.md)
