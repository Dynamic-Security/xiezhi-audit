---
name: threat-model-report-template
description: 需求威胁模型报告的结构：来源、功能澄清（功能、角色与权限、数据与资产、信任边界、设计如此的行为、待确认与冲突点）与风险清单的字段。只在生成需求威胁模型时注入；项目层可同名覆盖以调整结构。
category: report
scope: global
load: phase:threat_model
tags: [threat-model, 报告模板]
---
# 需求威胁模型报告结构

提交时按以下结构填写；系统据此生成报告、风险表与在线文档。

## 功能澄清（clarification，Markdown）
按顺序使用以下二级标题，没有内容的写“无”：
1. `## 功能`
2. `## 角色与权限`
3. `## 数据与资产`
4. `## 信任边界与外部依赖`
5. `## 设计如此的行为`
6. `## 待确认与冲突点`（每条写明各来源的说法与出处）

每条用列表项，句末标来源编号，例如“- 买家可以对已支付订单申请退款。（S1）”。

## 风险清单（risks，结构化）
| 字段 | 说明 |
| --- | --- |
| `no` | 沿用已有编号；新风险不填，由系统分配 |
| `category` | `spoofing` / `tampering` / `repudiation` / `information_disclosure` / `denial_of_service` / `elevation_of_privilege` / `business_logic` / `abuse` |
| `level` | `high` / `medium` / `low` |
| `statement` | 一句话：谁、通过什么、能造成什么后果 |
| `impact` | 后果与影响范围 |
| `mitigation` | 可执行的规避建议，可多条 |
| `features` | 关联的功能名称（与“功能”一节中的名称一致） |
| `sources` | 来源编号数组，例如 `[1, 3]` |

## 报告（系统生成，供导出与同步）
```
# <威胁模型标题>
来源：S1 <标题>（<类型>）；S2 …
## 功能澄清
<clarification>
## 风险清单
| 编号 | 等级 | 类别 | 风险 | 规避建议 | 状态 | 研判理由 | 来源 |
```
状态用词：待研判、需规避、已规避、接受风险、误报 / 不适用。
