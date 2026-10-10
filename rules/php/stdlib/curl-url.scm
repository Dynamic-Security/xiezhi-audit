(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(curl_setopt)$")
  (#match? @args "CURLOPT_URL")) @call
