---
name: spring-authz-method
description: Spring Security、方法注解鉴权、Filter/Interceptor 的审计方法。审计 Java Spring 项目的认证与授权时读取。
category: audit_method
scope: global
applies_to:
  languages: [java]
  frameworks: [spring]
---
# Spring 鉴权审计要点

- **SecurityFilterChain / WebSecurityConfigurerAdapter**：检查 `requestMatchers/antMatchers` 的顺序（先匹配先生效）、`permitAll` 是否过宽（如 `/api/**`）、`anyRequest()` 的兜底规则。
- **方法注解**：`@PreAuthorize` 需要 `@EnableMethodSecurity`/`@EnableGlobalMethodSecurity(prePostEnabled=true)` 才生效；注解写在接口上而实现类被直接调用时可能失效；同类内部调用不经代理，注解不生效。
- **Filter/HandlerInterceptor**：检查 `addPathPatterns/excludePathPatterns`、`shouldNotFilter`、路径匹配是否可被 `;`、`/..;/`、大小写、尾斜杠绕过。
- **路径绕过**：Spring 旧版本 `useSuffixPatternMatch`、`/api/admin/..;/` 与 Tomcat 路径规范化差异。
- 结论写法：说明入口受到哪条规则保护，或为什么不受保护，并给出规则所在位置。
