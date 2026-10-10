(call
  function: (attribute object: (_) @receiver attribute: (identifier) @method)
  arguments: (argument_list) @args
  (#match? @method "^(execute|executemany|executescript|exec_driver_sql|mogrify)$")) @call
