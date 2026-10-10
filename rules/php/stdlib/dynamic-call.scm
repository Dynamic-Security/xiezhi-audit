(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(call_user_func|call_user_func_array|forward_static_call|forward_static_call_array)$")
  (#match? @args "^\\(\\s*\\$")) @call
