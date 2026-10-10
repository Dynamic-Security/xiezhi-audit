(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(redirect)$")) @call
(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(away|to)$")) @call
(nullsafe_member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(away|to)$")) @call
(scoped_call_expression
  scope: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(to|away)$")) @call
