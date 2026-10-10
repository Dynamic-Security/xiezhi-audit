(module
  (expression_statement
    (assignment left: (identifier) @name right: (_) @value))
  (#match? @name "^(MIDDLEWARE|MIDDLEWARE_CLASSES|REST_FRAMEWORK)$"))
