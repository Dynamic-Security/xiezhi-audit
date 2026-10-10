(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(eval|exec|compile|execfile)$")) @call
