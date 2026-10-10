---
name: jira-cloud
description: Jira Cloud（REST API v3）示例连接器包：按 JQL 查询工单、读取工单与可用流转（只读），创建工单、添加评论、执行流转（写入）。
base_url: https://your-domain.atlassian.net
auth:
  type: script
  script: scripts/basic-auth.mjs
interpreter: node
secrets: [email, api_token]
---
# Jira Cloud 示例连接器包

依据 Atlassian 官方 Jira Cloud REST API v3 文档编写，用于演示“连接器包”的写法。

## 配置
- **base_url**：在连接器中填写你的站点地址，例如 `https://acme.atlassian.net`（覆盖这里的占位地址）。
- **密钥**：`email`（Atlassian 账号邮箱）、`api_token`（在 https://id.atlassian.com/manage-profile/security/api-tokens 创建；建议使用只读或权限受限的账号）。
- **认证脚本** `scripts/basic-auth.mjs`：把 `email:api_token` 编码成 HTTP Basic 认证头（Jira Cloud 的基本认证方式）。它演示了“复用已有认证实现”的脚本接口：从环境变量 `CA_SECRET_<名称>` 读取密钥，在标准输出打印 `{"headers": {...}, "expiresIn": 秒}`。脚本在首次使用和每次改动后都需要在设置中确认。

## 操作
| 操作 | 读写 | 接口 |
| --- | --- | --- |
| search_issues | 读 | `GET /rest/api/3/search/jql` |
| get_issue | 读 | `GET /rest/api/3/issue/{issueIdOrKey}` |
| get_transitions | 读 | `GET /rest/api/3/issue/{issueIdOrKey}/transitions` |
| create_issue | 写 | `POST /rest/api/3/issue` |
| add_comment | 写 | `POST /rest/api/3/issue/{issueIdOrKey}/comment` |
| transition_issue | 写 | `POST /rest/api/3/issue/{issueIdOrKey}/transitions` |

读写操作默认都向 Agent 开放，按操作说明自行选择，不需要的可以在连接器的工具列表里关闭；调用参数含疑似注入指令、或会话读到过被审代码中的疑似注入指令时，这次调用先暂停等用户批准。用户发起的推送使用包里声明的写操作，不需要另外配置。

## 注意
- 描述与评论使用 Atlassian Document Format（ADF）；本包把文本放进单个段落。
- `search_issues` 使用新的 `/search/jql` 接口（旧的 `/rest/api/3/search` 已弃用）；分页使用 `nextPageToken`。
