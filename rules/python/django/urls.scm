(call
  function: (identifier) @fn
  arguments: (argument_list) @args
  (#match? @fn "^(path|re_path|url)$")) @call
