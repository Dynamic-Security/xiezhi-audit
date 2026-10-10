(call
  function: [(identifier) (attribute)] @fn
  arguments: (argument_list) @args
  (#match? @fn "(^|\\.)(Application|add_handlers)$")) @call
