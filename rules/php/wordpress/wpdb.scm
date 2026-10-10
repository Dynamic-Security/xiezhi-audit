(member_call_expression
  object: (_) @receiver
  name: (name) @method
  arguments: (arguments) @args
  (#match? @method "^(get_results|get_row|get_var|get_col|query)$")) @call
