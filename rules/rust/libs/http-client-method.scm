(call_expression
  function: (field_expression value: (_) @receiver field: (field_identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(get|post|put|patch|delete|head)$")) @call
