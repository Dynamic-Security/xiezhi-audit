---
name: lark-cli
description: 飞书 / Lark 官方命令行工具 lark-cli 的连接器包：读取云文档与知识库页面（Markdown），新建文档、整篇覆盖已有文档。使用本机已登录的 lark-cli。
program:
  name: lark-cli
  home: user
  env:
    LARKSUITE_CLI_NO_UPDATE_NOTIFIER: "1"
    LARKSUITE_CLI_NO_SKILLS_NOTIFIER: "1"
---
# lark-cli 连接器包

通过本机安装的飞书官方命令行工具 `lark-cli`（npm 包 `@larksuite/cli`）读写云文档。它不是 MCP 服务：每个操作是一条固定的 lark-cli 命令，参数按模板填入，不经过 shell。

## 前提
- 已安装并登录 lark-cli：`lark-cli auth status` 显示应用身份或用户身份为 ready。
- 命令以**你的 HOME** 运行（`home: user`），以便读取 lark-cli 自己保存的登录信息（`~/.lark-cli`）；这是本包与其他连接器的区别，首次使用和每次改动后都需要在设置中确认命令。
- 关闭 lark-cli 的更新与技能提示（环境变量 `LARKSUITE_CLI_NO_UPDATE_NOTIFIER`、`LARKSUITE_CLI_NO_SKILLS_NOTIFIER`），避免调用时触发后台下载。
- `program_path` 默认在 PATH 与常用安装目录中查找 `lark-cli`；可以在连接器中填写绝对路径（例如 npm 全局安装目录下 `@larksuite/cli/bin/lark-cli`，直接调用二进制）。

## 操作
| 操作 | 读写 | 命令 |
| --- | --- | --- |
| fetch_doc | 读 | `lark-cli docs +fetch --doc <链接或 token> --doc-format markdown` |
| create_doc | 写 | `lark-cli docs +create --doc-format markdown --title <标题> --content -`（正文从标准输入传入） |
| overwrite_doc | 写 | `lark-cli docs +update --doc <链接或 token> --command overwrite --doc-format markdown --content -` |

身份：`as` 参数取 `user`（默认，文档建在你的云空间）或 `bot`（应用身份）。读写操作默认都向 Agent 开放，不需要的可以在连接器的工具列表里关闭；用户发起的同步使用包里声明的写操作，不需要另外配置。
