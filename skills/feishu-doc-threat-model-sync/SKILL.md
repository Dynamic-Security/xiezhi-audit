---
name: feishu-doc-threat-model-sync
description: 把需求威胁模型报告同步到飞书云文档的指引（示例）：首次新建文档，再次同步整篇覆盖同一份文档；也可以指定已有文档。需要名为 Feishu 的连接器（lark-cli 连接器包）。
category: push_guide
scope: global
tags: [feishu, lark, 飞书文档, threat-model]
push:
  target: threat_model
  connector: Feishu
  operation: create_doc
  external_id: $..document_id
  update_operations: [overwrite_doc]
  update_key: doc
  confirm: true
---
# 威胁建模报告同步到飞书文档（示例）

这是随产品附带的示例，参数由 `template.yaml`（首次新建）与 `template-update.yaml`（再次同步）确定性填写，不经过模型。复制到项目知识库（同名即覆盖本示例）后可以按团队规范修改，例如在 `template.yaml` 中加 `parent_token` 指定文件夹，或改用应用身份（`as: bot`）。

## 首次同步（create_doc）
- 标题：`<项目名> 威胁建模 · <威胁模型标题>`。
- 正文：报告 Markdown 全文。
- 默认以你的身份新建（`as: user`），文档在你的云空间；结果中的 `document_id` 记为外部 ID，`url` 为文档链接。

## 再次同步（overwrite_doc）
- 用报告 Markdown 整篇覆盖同一份文档，链接不变；文档 ID 由同步流程填写。
- 在“同步到已有文档”中填写链接时，直接覆盖那份文档（会替换其全部正文）。

## 文档规范
报告正文由同步流程按固定结构渲染：一级标题为威胁模型标题；首段为生成时间、风险数量与来源；`## 功能澄清`；`## 风险清单`（编号、等级、类别、风险、影响、规避建议、状态、研判理由、来源）；文末注明“由獬豸审计生成；风险状态以獬豸中的研判为准”。在文档中修改不会回写獬豸。
