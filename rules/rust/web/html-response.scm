(call_expression
  function: (identifier) @method
  arguments: (arguments) @args
  (#match? @method "^(Html|RawHtml)$")) @call
(call_expression
  function: (generic_function function: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(Html|RawHtml)$")) @call
(call_expression
  function: (scoped_identifier path: (_) @receiver name: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(Html|RawHtml)$")) @call
(call_expression
  function: (generic_function function: (scoped_identifier path: (_) @receiver name: (identifier) @method))
  arguments: (arguments) @args
  (#match? @method "^(Html|RawHtml)$")) @call
