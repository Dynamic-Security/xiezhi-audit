---
name: jira-issue-push
description: 把漏洞推送为 Jira Cloud 工单（示例推送指引）；已推送过的漏洞改为在原工单下追加评论。需要名为 jira-cloud 的连接器
category: 推送指引
tags: [jira, 工单]
push:
  connector: jira-cloud
  operation: create_issue
  external_id: $.key
  external_url: "{base_url}/browse/{external_id}"
  update_operation: add_comment
  update_key: issue
  confirm: false
---
# Jira 工单推送指引（示例）

这是随产品附带的示例，演示推送指引的写法；复制到项目知识库后按团队规范修改。

- 连接器：在“设置 → 连接器”中从示例安装 `jira-cloud` 连接器包，填入站点地址与凭证；写入能力由包里的操作声明，不需要另外打开。
- 参数由同目录的 `template.yaml`（首次推送）与 `template-update.yaml`（再次推送）确定性渲染，不消耗模型 token；删除模板后改由对话模型按本指引填写参数。
- 可用占位符：`{{display_no}}` `{{title}}` `{{severity}}` `{{severity_label}}`（中文）`{{category}}` `{{cwe}}` `{{project}}` `{{repo}}` `{{location}}` `{{entries}}` `{{entries_list}}`（数组）`{{root_cause}}` `{{remediation}}` `{{confirm_status}}` `{{fingerprint}}` `{{description}}` `{{external_id}}`。
- `confirm: true` 时每次推送都先预览再确认；默认自动执行，但内容疑似含注入指令时仍会强制预览。

## 团队约定（按需修改）

- 项目 key：SEC；工单类型：Bug。
- 标题格式：`[安全][严重程度] 漏洞编号 标题`。
- 标签至少包含 `xiezhi-audit` 与漏洞类别。
