(call_expression
  function: (member_expression property: (property_identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(use|addHook)$")) @call
