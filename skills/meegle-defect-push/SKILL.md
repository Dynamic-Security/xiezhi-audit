---
name: meegle-defect-push
description: 把已确认或接受风险的漏洞推送为 Meegle 缺陷（示例推送指引）；再次推送时按漏洞状态追加评论、更新字段或流转状态。需要名为 Meegle 的 MCP 连接器
category: 推送指引
tags: [meegle, 缺陷, 工单]
push:
  connector: Meegle
  operation: create_workitem
  external_id: $..work_item_id
  update_operations: [add_comment, update_field, transition_state]
  update_key: work_item_id
  confirm: true
---
# Meegle 缺陷推送指引（示例）

这是随产品附带的示例。复制到项目知识库（同名即覆盖本示例）后，把“目标空间”改成团队的空间，并按团队规范调整字段。示例默认每次推送前预览（`confirm: true`）。

## 目标空间
- 空间：未指定。先用 `search_project_info` 按本项目名称查空间的 `project_key`；查不到或有多个时不要提交，在参数说明里写明原因。
- 工作项类型：缺陷（`list_workitem_types` 中名称为“缺陷”的类型）。创建前用 `list_workitem_field_config` 查该类型的字段与模板，字段 key 与选项 id 必须严格来自查询结果。

## 首次推送（create_workitem）
- 名称：`[安全][严重度] V-编号 标题`。
- 严重程度 / 优先级（按选项名称匹配）：严重 → 严重 / P0；高 → 重要 / P0；中 → 一般 / P1；低、信息 → 次要 / P2。
- 描述：漏洞的证据、推理与链路、利用条件、修复建议（标注“修复建议由 AI 生成，需人工确认”），末尾写“来源：獬豸审计”。
- 标签：空间有 `xiezhi-audit` 标签时加上；没有就只写在描述里。发现阶段等与代码审计无关的字段留空。

## 再次推送（漏洞状态有变化）
按漏洞当前的确认状态（confirm_status）、处理状态（handling_status）与跨审计状态（lifecycle）选择，可多个，按顺序：
1. `add_comment`：写明这次的变化（确认 / 误报 / 接受风险 / 已修复 / 复验回归）与理由（handling_reason）。
2. `update_field`：严重度变化时同步严重程度与优先级。
3. `transition_state`：已修复 → 已解决；误报或接受风险 → 已关闭；复验回归（lifecycle 为 regressed）→ 重新开启。目标状态先用 `get_transitable_states` 查，当前状态不能直接流转到目标状态时只追加评论说明。
