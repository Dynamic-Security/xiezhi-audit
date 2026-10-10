(call_expression
  function: (selector_expression operand: (_) @receiver field: (field_identifier) @method)
  arguments: (argument_list . (_) @cond) @args
  (#match? @method "^(Where|Or|Not|Order|Group|Having|Joins)$")) @call
