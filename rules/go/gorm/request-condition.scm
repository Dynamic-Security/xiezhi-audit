(call_expression
  function: (selector_expression operand: (_) @receiver field: (field_identifier) @method)
  arguments: (argument_list . (_) . (_) @cond) @args
  (#match? @method "^(Find|First|Take|Last|Delete|FirstOrInit|FirstOrCreate)$")) @call
