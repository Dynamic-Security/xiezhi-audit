(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(file_get_contents|fopen|file|readfile|copy|get_headers)$")
  (#match? @args "^\\(\\s*['\"](https?|ftp)://")) @call
(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(get_headers|fsockopen|pfsockopen|stream_socket_client)$")) @call
