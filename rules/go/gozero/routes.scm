(call_expression
  function: (selector_expression field: (field_identifier) @verb)
  arguments: (argument_list) @args
  (#match? @verb "^(AddRoutes|AddRoute)$")) @call
