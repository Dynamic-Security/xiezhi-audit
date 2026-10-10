(function_call_expression
  function: [(name) (qualified_name)] @method
  arguments: (arguments) @args
  (#match? @method "^\\\\?(wp_remote_get|wp_remote_post|wp_remote_request|wp_remote_head|download_url|wp_safe_remote_get|wp_safe_remote_post)$")) @call
