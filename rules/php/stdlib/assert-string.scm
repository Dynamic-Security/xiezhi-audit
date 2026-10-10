(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(assert)$")
  (#match? @args "^\\(\\s*[\"'$]")) @call
