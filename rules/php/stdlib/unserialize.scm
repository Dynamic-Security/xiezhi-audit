(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(unserialize|igbinary_unserialize|msgpack_unpack)$")) @call
