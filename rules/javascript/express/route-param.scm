(call_expression
  function: (member_expression object: (_) @router property: (property_identifier) @verb)
  arguments: (arguments) @args
  (#match? @verb "^(get|post|put|delete|patch|options|head|all|route)$")) @call
