---
name: authz-judgement-method
description: 越权（IDOR/功能级越权）判断方法：归属校验、角色校验、上游鉴权的确认路径。审计越权类问题时读取。
category: audit_method
scope: global
applies_to:
  vuln_classes: [authz_object, authz_function, authn]
---
# 越权判断步骤

1. **确定入口可达性**：入口是否需要登录（全局 Filter、中间件链、SecurityFilterChain 路径规则、注解）。未登录可达 → 按未授权访问处理。
2. **确定资源标识来源**：路径参数、查询参数、请求体中的对象 ID 是否由调用方控制。
3. **查找归属校验**：在入口到数据访问的调用链上查找以下任一形式：
   - 查询条件包含当前用户（`WHERE id = ? AND user_id = ?`、`findByIdAndOwner`）；
   - 取出对象后比较 `owner == currentUser`；
   - 统一的数据权限拦截器 / AOP / 行级安全。
4. **查找角色校验**（功能级越权）：`@PreAuthorize`、`hasRole`、中间件 `AdminOnly`、手写 `if role != admin`。
5. **跨服务**：如果鉴权在其他服务或网关完成，而当前代码库无法确认，结论为“待确认”，pendingCondition 写明缺少哪个服务或策略、成立与不成立的条件、成立时的严重度。

# 证据要求

- 入口位置、数据访问位置（危险点）、链路上每一段的代码位置。
- 明确说明“查找了哪些位置、没有找到归属校验”，作为 counterCheck。
