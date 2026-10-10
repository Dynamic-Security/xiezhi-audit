(call_expression
  function: (selector_expression operand: (_) @receiver field: (field_identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(First|Take|Last|GetByID|GetById|FindByID|FindById|GetByIDs|DeleteByID|DeleteById|UpdateByID|UpdateById|ID|Get)$")) @call
