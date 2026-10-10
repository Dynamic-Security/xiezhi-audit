(call_expression
  (navigation_expression . (_) @receiver (identifier) @method .)
  (value_arguments) @args
  (#match? @method "^(get|post|put|delete|patch|head|request|submitForm|prepareGet|preparePost)$")) @call
