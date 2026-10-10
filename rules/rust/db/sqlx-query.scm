(call_expression
  function: (scoped_identifier path: (_) @receiver name: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(query|query_as|query_scalar|query_with|query_as_with|query_scalar_with|raw_sql)$")) @call
(call_expression
  function: (generic_function function: (scoped_identifier path: (_) @receiver name: (identifier) @method))
  arguments: (arguments) @args
  (#match? @method "^(query|query_as|query_scalar|query_with|query_as_with|query_scalar_with|raw_sql)$")) @call
(call_expression
  function: (identifier) @method
  arguments: (arguments) @args
  (#match? @method "^(query|query_as|query_scalar|query_with|query_as_with|query_scalar_with|raw_sql)$")) @call
(call_expression
  function: (generic_function function: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(query|query_as|query_scalar|query_with|query_as_with|query_scalar_with|raw_sql)$")) @call
