---
name: mybatis-injection-method
description: MyBatis SQL 注入审计方法：${} 拼接、动态 SQL、Provider 注解。审计使用 MyBatis 的 Java 项目的 SQL 注入时读取。
category: audit_method
scope: global
applies_to:
  languages: [java]
  vuln_classes: [sqli]
---
# MyBatis 注入要点

- `#{}` 是预编译参数，安全；`${}` 是字符串替换，参数可控即注入。
- 常见必须用 `${}` 的场景：`ORDER BY`、表名、列名、`IN (...)`。可接受的写法是白名单映射（枚举/Map 查表）。
- 追踪 `${x}` 对应的 Mapper 方法参数（`@Param("x")`）到 Controller 入口，确认中间是否有白名单校验。
- `@SelectProvider` 等 Provider 类中的字符串拼接同样视为 `${}`。
- XML 与接口通过 `namespace + id` 关联；注意 `<sql>` 片段与 `<include>` 的引用。
