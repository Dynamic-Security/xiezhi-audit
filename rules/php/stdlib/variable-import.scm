(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(extract)$")
  (#match? @args "\\$_(GET|POST|REQUEST|COOKIE)|->(all|input|post|get)\\(")) @call
(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(parse_str)$")
  (#not-match? @args ",")) @call
