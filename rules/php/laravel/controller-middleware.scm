(member_call_expression
  object: (variable_name) @object
  name: (name) @method
  arguments: (arguments) @args
  (#eq? @object "$this")
  (#eq? @method "middleware")) @call
