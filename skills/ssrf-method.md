---
name: ssrf-method
description: SSRF 审计方法：可控 URL、重定向跟随、DNS 重绑定、内网地址判断。审计服务端发起 HTTP 请求的代码时读取。
category: audit_method
scope: global
applies_to:
  vuln_classes: [ssrf, open_redirect]
---
# SSRF 判断要点

- URL 是否整体可控，还是只控制路径/参数（只控制查询参数通常不构成 SSRF）。
- 校验方式是否可绕过：前缀/包含匹配（`startsWith("http://trusted")` 可被 `trusted.evil.com` 绕过）、只校验主机名不校验解析结果（DNS 重绑定）、未禁止重定向。
- 内网判断应基于解析后的 IP，覆盖 127.0.0.0/8、10/8、172.16/12、192.168/16、169.254/16、::1、fc00::/7。
- 响应是否回显（影响严重度）；仅盲 SSRF 通常下调一级并在 exploitConditions 说明。
