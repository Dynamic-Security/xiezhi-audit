(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(RawSQL)$")) @call
