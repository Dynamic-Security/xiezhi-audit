(call_expression
  function: (selector_expression operand: (_) @router field: (field_identifier) @verb)
  arguments: (argument_list) @args
  (#match? @verb "^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any|Handle|Match)$")) @call
