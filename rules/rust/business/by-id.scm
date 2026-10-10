(call_expression
  function: (scoped_identifier path: (_) @receiver name: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(find_by_id|delete_by_id)$")) @call
(call_expression
  function: (generic_function function: (scoped_identifier path: (_) @receiver name: (identifier) @method))
  arguments: (arguments) @args
  (#match? @method "^(find_by_id|delete_by_id)$")) @call
