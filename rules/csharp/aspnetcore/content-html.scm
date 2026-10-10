(invocation_expression
  function: [(identifier) @method (generic_name (identifier) @method)]
  arguments: (argument_list) @args
  (#match? @method "^Content$")
  (#match? @args "text/html")) @call
