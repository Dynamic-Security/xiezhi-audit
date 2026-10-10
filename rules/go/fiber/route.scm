(call_expression
  function: (selector_expression operand: (_) @router field: (field_identifier) @verb)
  arguments: (argument_list) @args
  (#match? @verb "^(Get|Post|Put|Delete|Patch|Head|Options|All)$")) @call
