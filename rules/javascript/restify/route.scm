(call_expression
  function: (member_expression object: (_) @router property: (property_identifier) @verb)
  arguments: (arguments) @args
  (#match? @verb "^(get|post|put|del|delete|patch|head|opts|options|all)$")) @call
