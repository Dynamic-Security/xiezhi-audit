(call
  function: (identifier) @fn
  arguments: (argument_list) @args
  (#match? @fn "^(Depends|Security)$")) @call
