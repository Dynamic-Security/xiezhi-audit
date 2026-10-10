(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments (value_argument) (value_argument (navigation_expression) @ct)) @args
  (#match? @method "^(respondText|respondBytes)$")
  (#match? @ct "Html$")) @call
