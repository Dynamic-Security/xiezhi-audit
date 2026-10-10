(call_expression
  function: [(selector_expression operand: (_) @router field: (field_identifier) @verb)
             (identifier) @verb]
  arguments: (argument_list) @args
  (#match? @verb "^(HandleFunc|Handle)$")) @call
