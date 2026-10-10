(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(preg_replace)$")
  (#match? @args "^\\(\\s*['\"][^'\"]*[/#~|!@%][a-zA-Z]*e[a-zA-Z]*['\"]")) @call
