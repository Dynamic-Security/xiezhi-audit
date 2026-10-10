(call_expression
  function: (scoped_identifier path: (_) @receiver name: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(to|temporary|permanent|see_other|found|moved)$")) @call
(call_expression
  function: (generic_function function: (scoped_identifier path: (_) @receiver name: (identifier) @method))
  arguments: (arguments) @args
  (#match? @method "^(to|temporary|permanent|see_other|found|moved)$")) @call
