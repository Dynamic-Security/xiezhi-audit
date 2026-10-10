(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments) @args
  (#match? @method "^(createNativeQuery|createQuery|createSQLQuery)$")) @call
