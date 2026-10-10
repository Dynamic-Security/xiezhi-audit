(invocation_expression
  function: (member_access_expression
    expression: (_) @router
    name: (identifier) @verb)
  arguments: (argument_list) @args
  (#match? @verb "^Map(Get|Post|Put|Delete|Patch|Methods)$")) @call
