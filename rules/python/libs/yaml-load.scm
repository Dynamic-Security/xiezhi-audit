(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(load|load_all|unsafe_load|unsafe_load_all|full_load)$")) @call
(call
  function: (identifier) @method
  arguments: (argument_list) @args
  (#match? @method "^(load|load_all|unsafe_load)$")) @call
