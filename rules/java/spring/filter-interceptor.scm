(class_declaration
  name: (identifier) @name
  [(superclass (type_identifier) @super)
   (super_interfaces (type_list (type_identifier) @super))]
  (#match? @super "^(OncePerRequestFilter|Filter|GenericFilterBean|HandlerInterceptor|HandlerInterceptorAdapter|AuthenticationFilter|AbstractAuthenticationProcessingFilter|BasicAuthenticationFilter)$")) @class
