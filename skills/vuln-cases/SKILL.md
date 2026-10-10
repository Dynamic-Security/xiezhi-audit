---
name: vuln-cases
description: 历史漏洞与同类案例库。遇到越权、注入、SSRF 等可疑模式、需要参考先例判断成立与不成立条件时加载本库，再按索引读取具体案例。
category: vuln_case
scope: global
---
# 漏洞案例库

本库收录已确认的漏洞与典型误报先例。每个案例是本目录下的一个子文件，按下面的模板书写；从漏洞详情“沉淀为案例”会自动生成草稿，审核启用后索引自动更新。

使用方法：先看索引中与当前可疑模式同类的案例，用 `load_skill(name, file)` 读取，对照“成立条件 / 不成立条件”判断，结论中引用案例时写明文件名。

案例模板：

```markdown
---
name: idor-order-2025
description: 按订单 ID 查询未校验归属
vuln_class: authz_object
cwe: [CWE-639]
languages: [java]
frameworks: [spring-mvc]
applies_when: Spring MVC，按资源 ID 读写的接口
---
## 漏洞模式
## 代码特征
## 成立条件
## 不成立条件
## 修复方式
## 何时参考
```

<!-- BEGIN GENERATED INDEX: 以下内容由程序生成，请勿手改 -->
<!-- END GENERATED INDEX -->
