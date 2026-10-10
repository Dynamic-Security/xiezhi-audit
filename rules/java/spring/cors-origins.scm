(method_invocation
  name: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(allowedOrigins|allowedOriginPatterns|setAllowedOrigins|setAllowedOriginPatterns|addAllowedOrigin|addAllowedOriginPattern)$")) @call
