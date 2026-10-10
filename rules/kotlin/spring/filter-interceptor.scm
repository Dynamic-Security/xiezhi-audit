(class_declaration
  (delegation_specifiers
    (delegation_specifier [(constructor_invocation (user_type (identifier) @super)) (user_type (identifier) @super)]))
  (#match? @super "^(OncePerRequestFilter|Filter|GenericFilterBean|HandlerInterceptor|HandlerInterceptorAdapter|AuthenticationFilter|AbstractAuthenticationProcessingFilter|BasicAuthenticationFilter|WebFilter)$")) @class
