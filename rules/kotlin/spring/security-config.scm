(call_expression
  [(identifier) @method (navigation_expression (_) (identifier) @method .)]
  (#match? @method "^(authorizeHttpRequests|authorizeRequests|authorizeExchange|requestMatchers|antMatchers|mvcMatchers|pathMatchers|securityMatcher|permitAll|authenticated|hasRole|hasAnyRole|hasAuthority|addPathPatterns|excludePathPatterns)$")) @call
