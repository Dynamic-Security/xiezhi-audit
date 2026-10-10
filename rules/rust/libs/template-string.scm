(call_expression
  function: (scoped_identifier path: (_) @receiver name: (identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(one_off)$")) @call
(call_expression
  function: (generic_function function: (scoped_identifier path: (_) @receiver name: (identifier) @method))
  arguments: (arguments) @args
  (#match? @method "^(one_off)$")) @call
(call_expression
  function: (field_expression value: (_) @receiver field: (field_identifier) @method)
  arguments: (arguments) @args
  (#match? @method "^(render_str|render_template|template_from_str)$")) @call
