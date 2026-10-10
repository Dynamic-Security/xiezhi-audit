(call_expression
  function: (selector_expression field: (field_identifier) @verb)
  arguments: (argument_list) @args
  (#match? @verb "^(NS)?(Router|Include|AutoRouter|Get|Post|Put|Delete|Patch|Head|Options|Any)$")) @call
