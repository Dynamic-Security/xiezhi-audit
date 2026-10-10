(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(header)$")
  (#match? @args "[Ll]ocation\\s*:")) @call
