(call_expression
  function: (identifier) @method
  arguments: (arguments) @args
  (#match? @method "^(fetch)$")) @call
